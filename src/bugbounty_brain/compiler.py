from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Final, TypedDict, assert_never

from bugbounty_brain.validator import ValidationIssue, ValidationReport
from bugbounty_brain.validator import validate_cards


SCHEMA_VERSION: Final = 1
COMPATIBILITY: Final = "bugbounty-brain-v1"
_SCHEMA_SQL: Final = (
    "PRAGMA page_size = 4096; PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA temp_store = MEMORY; PRAGMA auto_vacuum = NONE; PRAGMA foreign_keys = ON; PRAGMA user_version = 1;"
    "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;"
    "CREATE TABLE cards (id TEXT PRIMARY KEY, title TEXT NOT NULL, summary TEXT NOT NULL,"
    " source_url TEXT NOT NULL, source_name TEXT NOT NULL, published_at TEXT NOT NULL, fetched_at TEXT NOT NULL, content_sha256 TEXT NOT NULL, products TEXT NOT NULL, cves TEXT NOT NULL, techniques TEXT NOT NULL, confidence TEXT NOT NULL, safety TEXT NOT NULL); CREATE INDEX idx_cards_source ON cards(source_name, source_url);"
    "CREATE TABLE card_products (card_id TEXT NOT NULL REFERENCES cards(id), position INTEGER NOT NULL, product TEXT NOT NULL, PRIMARY KEY (card_id, position)) WITHOUT ROWID; CREATE INDEX idx_card_products_product ON card_products(product, card_id);"
    "CREATE TABLE card_cves (card_id TEXT NOT NULL REFERENCES cards(id), position INTEGER NOT NULL, cve TEXT NOT NULL, PRIMARY KEY (card_id, position)) WITHOUT ROWID; CREATE INDEX idx_card_cves_cve ON card_cves(cve, card_id);"
)
_CREATE_FTS_SQL: Final = """CREATE VIRTUAL TABLE cards_fts USING fts5(
    id UNINDEXED, title, summary, products, cves, techniques,
    tokenize = 'unicode61'
)"""
_INSERT_CARD_SQL: Final = """INSERT INTO cards VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)"""
_INSERT_FTS_SQL: Final = "INSERT INTO cards_fts VALUES (?, ?, ?, ?, ?, ?)"


@dataclass(frozen=True, slots=True)
class CompileSummary:
    schema_version: int
    generated_at: str
    card_count: int
    source_sha256: str
    database_sha256: str
    database_filename: str
    compatibility: str


@dataclass(frozen=True, slots=True)
class CompileValidationError(Exception):
    report: ValidationReport

    @property
    def issues(self) -> tuple[ValidationIssue, ...]:
        return self.report.issues

    def __str__(self) -> str:
        return f"card validation failed with {len(self.issues)} issue(s)"


@dataclass(frozen=True, slots=True)
class Fts5UnavailableError(Exception):
    reason: str

    def __str__(self) -> str:
        return f"FTS5 is required; use a SQLite build with FTS5 support: {self.reason}"


@dataclass(frozen=True, slots=True)
class _Card:
    id: str
    title: str
    summary: str
    source_url: str
    source_name: str
    published_at: str
    fetched_at: str
    content_sha256: str
    products: tuple[str, ...]
    cves: tuple[str, ...]
    techniques: tuple[str, ...]
    confidence: str
    safety: str


@dataclass(frozen=True, slots=True)
class _BuildInfo:
    generated_at: str
    source_sha256: str


class _Manifest(TypedDict):
    schema_version: int
    generated_at: str
    card_count: int
    source_sha256: str
    database_sha256: str
    database_filename: str
    compatibility: str


def compile_brain(
    cards_path: Path | str,
    db_path: Path | str,
    manifest_path: Path | str,
    *,
    generated_at: str | datetime | None = None,
) -> CompileSummary:
    source = Path(cards_path)
    report = validate_cards(source)
    if not report.ok:
        raise CompileValidationError(report=report)

    source_bytes = source.read_bytes()
    cards = sorted(_load_cards(source_bytes), key=lambda card: card.id)
    build_info = _BuildInfo(
        generated_at=_generated_at_text(generated_at),
        source_sha256=sha256(source_bytes).hexdigest(),
    )
    database = Path(db_path)
    manifest_path_value = Path(manifest_path)
    database_temp = _secure_temp(database)
    manifest_temp: Path | None = None
    try:
        _build_database(database_temp, cards, build_info)
        _sync(database_temp)
        database_sha256 = sha256(database_temp.read_bytes()).hexdigest()
        summary = CompileSummary(
            schema_version=SCHEMA_VERSION,
            generated_at=build_info.generated_at,
            card_count=len(cards),
            source_sha256=build_info.source_sha256,
            database_sha256=database_sha256,
            database_filename=database.name,
            compatibility=COMPATIBILITY,
        )
        manifest: _Manifest = {
            "schema_version": summary.schema_version,
            "generated_at": summary.generated_at,
            "card_count": summary.card_count,
            "source_sha256": summary.source_sha256,
            "database_sha256": summary.database_sha256,
            "database_filename": summary.database_filename,
            "compatibility": summary.compatibility,
        }
        manifest_temp = _secure_temp(manifest_path_value)
        manifest_temp.write_bytes(
            (
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode()
        )
        _sync(manifest_temp)
        os.replace(database_temp, database)
        os.replace(manifest_temp, manifest_path_value)
    finally:
        for temporary in (database_temp, manifest_temp):
            if temporary is not None:
                with contextlib.suppress(FileNotFoundError):
                    temporary.unlink()
    return summary


def _load_cards(source: bytes) -> list[_Card]:
    cards: list[_Card] = []
    for line in source.decode("utf-8").splitlines():
        raw = json.loads(line)
        cards.append(
            _Card(
                id=raw["id"],
                title=raw["title"],
                summary=raw["summary"],
                source_url=raw["source_url"],
                source_name=raw["source_name"],
                published_at=raw["published_at"],
                fetched_at=raw["fetched_at"],
                content_sha256=raw["content_sha256"],
                products=tuple(raw["products"]),
                cves=tuple(raw["cves"]),
                techniques=tuple(raw["techniques"]),
                confidence=raw["confidence"],
                safety=raw["safety"],
            )
        )
    return cards


def _build_database(path: Path, cards: list[_Card], info: _BuildInfo) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(_SCHEMA_SQL)
        try:
            connection.execute(_CREATE_FTS_SQL)
        except sqlite3.OperationalError as error:
            if "fts5" not in str(error).lower():
                raise
            raise Fts5UnavailableError(reason=str(error)) from error
        connection.executemany(
            "INSERT INTO metadata VALUES (?, ?)",
            (
                ("card_count", str(len(cards))),
                ("compatibility", COMPATIBILITY),
                ("generated_at", info.generated_at),
                ("schema_version", str(SCHEMA_VERSION)),
                ("source_sha256", info.source_sha256),
            ),
        )
        for card in cards:
            products = _canonical_array(card.products)
            cves = _canonical_array(card.cves)
            techniques = _canonical_array(card.techniques)
            connection.execute(
                _INSERT_CARD_SQL,
                (
                    card.id,
                    card.title,
                    card.summary,
                    card.source_url,
                    card.source_name,
                    card.published_at,
                    card.fetched_at,
                    card.content_sha256,
                    products,
                    cves,
                    techniques,
                    card.confidence,
                    card.safety,
                ),
            )
            connection.execute(
                _INSERT_FTS_SQL,
                (card.id, card.title, card.summary, products, cves, techniques),
            )
            connection.executemany(
                "INSERT INTO card_products VALUES (?, ?, ?)",
                (
                    (card.id, index, product)
                    for index, product in enumerate(card.products)
                ),
            )
            connection.executemany(
                "INSERT INTO card_cves VALUES (?, ?, ?)",
                ((card.id, index, cve) for index, cve in enumerate(card.cves)),
            )
        connection.commit()
        connection.execute("VACUUM")


def _canonical_array(values: tuple[str, ...]) -> str:
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def _secure_temp(target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    return Path(name)


def _sync(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _generated_at_text(value: str | datetime | None) -> str:
    match value:
        case None:
            stamp = datetime.now(UTC)
        case str() as text:
            return text
        case datetime() as stamp:
            pass
        case unreachable:
            assert_never(unreachable)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
