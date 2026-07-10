from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

import pytest

import bugbounty_brain.compiler as compiler_module
from bugbounty_brain.compiler import (
    CompileValidationError,
    Fts5UnavailableError,
    compile_brain,
)


GENERATED_AT = "2026-07-10T12:00:00Z"
CARD_COLUMNS = (
    "id",
    "title",
    "summary",
    "source_url",
    "source_name",
    "published_at",
    "fetched_at",
    "content_sha256",
    "products",
    "cves",
    "techniques",
    "confidence",
    "safety",
)


def valid_card(card_id: str = "apache-struts-rce-a1b2c3d4e5f6") -> dict[str, object]:
    return {
        "id": card_id,
        "title": "Apache Struts RCE advisory",
        "summary": "Public remediation guidance for affected deployments.",
        "source_url": "https://example.com/advisories/struts-rce",
        "source_name": "Example Security Advisory",
        "published_at": "2026-07-10T08:30:00Z",
        "fetched_at": "2026-07-10T09:00:00Z",
        "content_sha256": "0" * 64,
        "products": ["Apache Struts", "Struts Core"],
        "cves": ["CVE-2024-53677"],
        "techniques": ["Input validation bypass"],
        "confidence": "high",
        "safety": "public",
    }


def write_cards(path: Path, *cards: dict[str, object]) -> None:
    path.write_text(
        "".join(
            f"{json.dumps(card, ensure_ascii=False, sort_keys=True)}\n"
            for card in cards
        ),
        encoding="utf-8",
    )


def compile_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    return (
        tmp_path / "cards.jsonl",
        tmp_path / "brain.sqlite3",
        tmp_path / "manifest.json",
    )


def test_compile_brain_writes_exact_cards_and_searches_every_fts_field(
    tmp_path: Path,
) -> None:
    # Given: two validated canonical cards with distinct searchable content.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    first = valid_card()
    second = valid_card("openssl-advisory-abcdef123456")
    second.update(
        title="OpenSSL certificate advisory",
        summary="Upgrade guidance for certificate parsing.",
        products=["OpenSSL"],
        cves=["CVE-2025-12345"],
        techniques=["Certificate parsing"],
    )
    write_cards(cards_path, first, second)

    # When: the canonical JSONL is compiled through the public API.
    compile_brain(cards_path, db_path, manifest_path, generated_at=GENERATED_AT)

    # Then: exact card rows exist and every contracted FTS field finds the right row.
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            f"SELECT {', '.join(CARD_COLUMNS)} FROM cards WHERE id = ?",
            (first["id"],),
        ).fetchone()
        searches = {
            query: connection.execute(
                "SELECT id FROM cards_fts WHERE cards_fts MATCH ? ORDER BY id",
                (query,),
            ).fetchall()
            for query in (
                "title:Struts",
                "summary:remediation",
                "products:Core",
                "cves:53677",
                "techniques:bypass",
            )
        }
    assert row == tuple(
        json.dumps(first[column], ensure_ascii=False, separators=(",", ":"))
        if column in {"products", "cves", "techniques"}
        else first[column]
        for column in CARD_COLUMNS
    )
    assert searches == {query: [(first["id"],)] for query in searches}


def test_compile_brain_creates_metadata_and_applicability_indexes(
    tmp_path: Path,
) -> None:
    # Given: one valid card with source, product, and CVE applicability data.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    write_cards(cards_path, valid_card())

    # When: the database is compiled.
    compile_brain(cards_path, db_path, manifest_path, generated_at=GENERATED_AT)

    # Then: schema metadata and member-level applicability indexes are queryable.
    with sqlite3.connect(db_path) as connection:
        card_columns = tuple(
            row[1] for row in connection.execute("PRAGMA table_info(cards)")
        )
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        product_ids = connection.execute(
            "SELECT card_id FROM card_products WHERE product = ?", ("Apache Struts",)
        ).fetchall()
        cve_ids = connection.execute(
            "SELECT card_id FROM card_cves WHERE cve = ?", ("CVE-2024-53677",)
        ).fetchall()
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'index'"
            )
        }
    assert card_columns == CARD_COLUMNS
    assert metadata == {
        "card_count": "1",
        "compatibility": "bugbounty-brain-v1",
        "generated_at": GENERATED_AT,
        "schema_version": "1",
        "source_sha256": sha256(cards_path.read_bytes()).hexdigest(),
    }
    assert product_ids == [(valid_card()["id"],)]
    assert cve_ids == [(valid_card()["id"],)]
    assert {
        "idx_cards_source",
        "idx_card_products_product",
        "idx_card_cves_cve",
    }.issubset(indexes)


def test_compile_brain_rejects_invalid_cards_without_replacing_outputs(
    tmp_path: Path,
) -> None:
    # Given: an invalid card and pre-existing database and manifest bytes.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    invalid = valid_card()
    del invalid["summary"]
    write_cards(cards_path, invalid)
    db_path.write_bytes(b"existing database")
    manifest_path.write_bytes(b"existing manifest")

    # When: compilation reaches the required validation boundary.
    with pytest.raises(CompileValidationError) as raised:
        compile_brain(cards_path, db_path, manifest_path, generated_at=GENERATED_AT)

    # Then: the typed error contains the report issues and both outputs are untouched.
    assert raised.value.issues == raised.value.report.issues
    assert [(issue.code, issue.location) for issue in raised.value.issues] == [
        ("missing_required", "line 1.summary")
    ]
    assert db_path.read_bytes() == b"existing database"
    assert manifest_path.read_bytes() == b"existing manifest"


def test_compile_brain_hashes_exact_source_and_actual_final_database_bytes(
    tmp_path: Path,
) -> None:
    # Given: valid JSONL whose exact bytes include normal json.dumps spacing.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    write_cards(cards_path, valid_card())

    # When: the artifacts are compiled.
    summary = compile_brain(
        cards_path, db_path, manifest_path, generated_at=GENERATED_AT
    )

    # Then: the canonical manifest and immutable summary carry actual byte hashes.
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source_hash = sha256(cards_path.read_bytes()).hexdigest()
    database_hash = sha256(db_path.read_bytes()).hexdigest()
    assert (
        manifest_path.read_bytes()
        == (
            json.dumps(
                manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            )
            + "\n"
        ).encode()
    )
    assert manifest == {
        "card_count": 1,
        "compatibility": "bugbounty-brain-v1",
        "database_filename": db_path.name,
        "database_sha256": database_hash,
        "generated_at": GENERATED_AT,
        "schema_version": 1,
        "source_sha256": source_hash,
    }
    assert summary == compiler_module.CompileSummary(**manifest)
    with pytest.raises(FrozenInstanceError):
        summary.card_count = 99


def test_compile_brain_is_byte_deterministic_with_fixed_generated_at(
    tmp_path: Path,
) -> None:
    # Given: fixed canonical input, output paths, and generation timestamp.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    write_cards(cards_path, valid_card())

    # When: the same compilation is performed twice.
    first = compile_brain(cards_path, db_path, manifest_path, generated_at=GENERATED_AT)
    first_db = db_path.read_bytes()
    first_manifest = manifest_path.read_bytes()
    second = compile_brain(
        cards_path, db_path, manifest_path, generated_at=GENERATED_AT
    )

    # Then: logical values and local SQLite/manifest bytes are identical.
    assert second == first
    assert db_path.read_bytes() == first_db
    assert manifest_path.read_bytes() == first_manifest


def test_compile_brain_inserts_cards_in_id_order_regardless_of_input_order(
    tmp_path: Path,
) -> None:
    # Given: valid cards written in descending ID order.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    first_id = "apache-advisory-111111111111"
    second_id = "zlib-advisory-222222222222"
    write_cards(cards_path, valid_card(second_id), valid_card(first_id))

    # When: the cards are compiled.
    compile_brain(cards_path, db_path, manifest_path, generated_at=GENERATED_AT)

    # Then: physical insertion order is ascending canonical ID order.
    with sqlite3.connect(db_path) as connection:
        ids = connection.execute("SELECT id FROM cards ORDER BY rowid").fetchall()
    assert ids == [(first_id,), (second_id,)]


def test_compile_brain_round_trips_canonical_json_arrays(tmp_path: Path) -> None:
    # Given: ordered arrays containing Unicode and punctuation.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    card = valid_card()
    card.update(
        products=["Café Gateway", "Widget/Edge"],
        cves=["CVE-2024-53677", "CVE-2025-12345"],
        techniques=["Path traversal", "Header: normalization"],
    )
    write_cards(cards_path, card)

    # When: the card is compiled.
    compile_brain(cards_path, db_path, manifest_path, generated_at=GENERATED_AT)

    # Then: each stored JSON array is canonical and decodes to the original order.
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT products, cves, techniques FROM cards"
        ).fetchone()
    assert row is not None
    for index, field in enumerate(("products", "cves", "techniques")):
        expected = card[field]
        assert row[index] == json.dumps(
            expected, ensure_ascii=False, separators=(",", ":")
        )
        assert json.loads(row[index]) == expected


def test_compile_brain_reports_actionable_typed_error_when_fts5_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a valid card and a SQLite connection that simulates a missing FTS5 module.
    cards_path, db_path, manifest_path = compile_paths(tmp_path)
    write_cards(cards_path, valid_card())
    real_connect = sqlite3.connect

    class NoFtsConnection(sqlite3.Connection):
        def execute(self, sql: str, parameters: tuple[()] = (), /) -> sqlite3.Cursor:
            if sql.startswith("CREATE VIRTUAL TABLE"):
                raise sqlite3.OperationalError("no such module: fts5")
            return super().execute(sql, parameters)

    def connect_without_fts(database: str | Path) -> sqlite3.Connection:
        return real_connect(database, factory=NoFtsConnection)

    monkeypatch.setattr(compiler_module.sqlite3, "connect", connect_without_fts)

    # When: compilation attempts to create its FTS search table.
    with pytest.raises(Fts5UnavailableError, match=r"FTS5.*SQLite"):
        compile_brain(cards_path, db_path, manifest_path, generated_at=GENERATED_AT)

    # Then: incomplete artifacts are not published.
    assert not db_path.exists()
    assert not manifest_path.exists()
