from __future__ import annotations

# allow: SIZE_OK - keep the deterministic enrichment matrix in one focused module.
import json
from pathlib import Path

import pytest

from bugbounty_brain.enricher import (
    ENRICHMENT_VERSION,
    EnrichmentError,
    enrich_cards,
)

NOW = "2026-07-12T00:00:00Z"
LATER = "2099-01-01T00:00:00Z"


def base_card(**overrides: object) -> dict[str, object]:
    card: dict[str, object] = {
        "id": "card-000000000001",
        "title": "Untitled",
        "summary": "A plain summary.",
        "source_url": "https://example.test/a",
        "source_name": "Example",
        "published_at": "2026-07-10T08:30:00Z",
        "fetched_at": "2026-07-10T09:00:00Z",
        "content_sha256": "0" * 64,
        "products": [],
        "cves": [],
        "techniques": [],
        "confidence": "medium",
        "safety": "public",
    }
    card.update(overrides)
    return card


def write_cards(path: Path, *cards: object) -> None:
    path.write_text(
        "".join(
            f"{json.dumps(card, sort_keys=True, separators=(',', ':'))}\n"
            for card in cards
        ),
        encoding="utf-8",
    )


def read_cards(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_enrich_extracts_cves_from_title_and_summary(tmp_path: Path) -> None:
    # Given: a card whose text mentions two CVEs in mixed case.
    path = tmp_path / "cards.jsonl"
    write_cards(
        path,
        base_card(
            title="Advisory for cve-2024-53677",
            summary="Also affects CVE-2021-44228 and not CVE-bad.",
        ),
    )

    # When: the cards are enriched.
    enrich_cards(path, now=NOW)

    # Then: both CVEs are normalized, sorted, and deduplicated.
    card = read_cards(path)[0]
    assert card["cves"] == ["CVE-2021-44228", "CVE-2024-53677"]
    assert card["enrichment"]["cves"] == ["CVE-2021-44228", "CVE-2024-53677"]


def test_enrich_derives_techniques_and_products_from_prose(tmp_path: Path) -> None:
    # Given: a card describing a SAML bypass in the Ruby and PHP ecosystem.
    path = tmp_path / "cards.jsonl"
    write_cards(
        path,
        base_card(
            title="Novel bypasses for SAML authentication",
            summary="A full authentication bypass in the Ruby and PHP SAML "
            "ecosystem via namespace confusion in ruby-saml.",
        ),
    )

    # When: the cards are enriched.
    enrich_cards(path, now=NOW)

    # Then: techniques and products are derived as sorted slug lists.
    card = read_cards(path)[0]
    assert card["techniques"] == ["parser-differential", "saml"]
    assert card["products"] == ["php", "ruby", "ruby-saml"]


def test_enrich_parses_ctftime_topics_and_strips_html(tmp_path: Path) -> None:
    # Given: a CTFtime-style card whose summary is HTML with a Topics list.
    path = tmp_path / "cards.jsonl"
    write_cards(
        path,
        base_card(
            title="SekaiCTF 2026 challenge",
            summary="<p>Topics: pwn,&nbsp;binary-exploitation,&nbsp;ctf,&nbsp;"
            "writeup&nbsp;</p> Rating: <span>not rated</span>",
        ),
    )

    # When: the cards are enriched.
    enrich_cards(path, now=NOW)

    # Then: recognised topics map to category slugs and noise is dropped.
    card = read_cards(path)[0]
    assert card["techniques"] == ["binary-exploitation"]


def test_enrich_respects_hyphen_aware_word_boundaries(tmp_path: Path) -> None:
    # Given: text where technique tokens appear only as substrings.
    path = tmp_path / "cards.jsonl"
    write_cards(
        path,
        base_card(
            title="Using sqlite and discourse",
            summary="No injection here, just sqlite storage and rce_helper naming.",
        ),
    )

    # When: the cards are enriched.
    enrich_cards(path, now=NOW)

    # Then: no false-positive techniques are derived from substrings.
    card = read_cards(path)[0]
    assert card["techniques"] == []


def test_enrich_is_idempotent_and_does_not_churn_timestamp(tmp_path: Path) -> None:
    # Given: a card enriched once at a fixed time.
    path = tmp_path / "cards.jsonl"
    write_cards(path, base_card(title="SAML bypass"))
    enrich_cards(path, now=NOW)
    first = path.read_text(encoding="utf-8")

    # When: enrichment runs again with a different clock.
    summary = enrich_cards(path, now=LATER)

    # Then: the output is byte-identical and nothing is reported as changed.
    assert path.read_text(encoding="utf-8") == first
    assert summary.cards_changed == 0
    assert summary.cards_unchanged == 1


def test_enrich_preserves_human_curated_entries(tmp_path: Path) -> None:
    # Given: a card a human tagged with a technique the deriver cannot infer.
    path = tmp_path / "cards.jsonl"
    write_cards(path, base_card(title="SAML bypass", techniques=["manual-insight"]))

    # When: the card is enriched.
    enrich_cards(path, now=NOW)

    # Then: the human tag survives alongside the derived one.
    card = read_cards(path)[0]
    assert card["techniques"] == ["manual-insight", "saml"]
    assert card["enrichment"]["techniques"] == ["saml"]


def test_enrich_replaces_its_own_prior_contribution(tmp_path: Path) -> None:
    # Given: a card carrying a stale enrichment-derived technique no longer implied.
    path = tmp_path / "cards.jsonl"
    write_cards(
        path,
        base_card(
            title="A neutral title",
            summary="Nothing to see here.",
            techniques=["saml", "manual-insight"],
            enrichment={
                "version": ENRICHMENT_VERSION,
                "enriched_at": NOW,
                "cves": [],
                "products": [],
                "techniques": ["saml"],
            },
        ),
    )

    # When: the card is re-enriched after its text changed.
    enrich_cards(path, now=LATER)

    # Then: the stale derived tag is dropped but the human tag remains.
    card = read_cards(path)[0]
    assert card["techniques"] == ["manual-insight"]
    assert card["enrichment"]["techniques"] == []
    assert card["enrichment"]["enriched_at"] == LATER


def test_enrich_writes_stamp_only_for_changed_cards(tmp_path: Path) -> None:
    # Given: one enriched card and one fresh card in the same file.
    path = tmp_path / "cards.jsonl"
    write_cards(path, base_card(id="card-000000000001", title="SAML bypass"))
    enrich_cards(path, now=NOW)
    existing = read_cards(path)[0]
    write_cards(
        path,
        existing,
        base_card(id="card-000000000002", title="HTTP request smuggling"),
    )

    # When: enrichment runs again at a later time.
    summary = enrich_cards(path, now=LATER)

    # Then: only the new card is changed and stamped with the later time.
    cards = {card["id"]: card for card in read_cards(path)}
    assert summary.cards_changed == 1
    assert cards["card-000000000001"]["enrichment"]["enriched_at"] == NOW
    assert cards["card-000000000002"]["enrichment"]["enriched_at"] == LATER


def test_enrich_output_is_deterministically_ordered(tmp_path: Path) -> None:
    # Given: a card whose text implies several techniques discovered out of order.
    path = tmp_path / "cards.jsonl"
    write_cards(
        path,
        base_card(
            title="WebSocket, SSRF and open redirect",
            summary="Also CORS and SAML issues.",
        ),
    )

    # When: the card is enriched.
    enrich_cards(path, now=NOW)

    # Then: derived techniques are sorted regardless of discovery order.
    card = read_cards(path)[0]
    assert card["techniques"] == sorted(card["techniques"])
    assert set(card["techniques"]) == {
        "cors-misconfiguration",
        "open-redirect",
        "saml",
        "ssrf",
        "websocket",
    }


def test_enrich_leaves_source_text_fields_untouched(tmp_path: Path) -> None:
    # Given: a card whose summary contains HTML markup.
    path = tmp_path / "cards.jsonl"
    original_summary = "<p>Topics: web,&nbsp;ctf</p>"
    write_cards(path, base_card(summary=original_summary, title="web thing"))

    # When: the card is enriched.
    enrich_cards(path, now=NOW)

    # Then: the provenance-bearing summary is preserved verbatim.
    card = read_cards(path)[0]
    assert card["summary"] == original_summary


def test_enrich_no_op_run_does_not_rewrite_file(tmp_path: Path) -> None:
    # Given: an already-enriched cards file with a known modification time.
    path = tmp_path / "cards.jsonl"
    write_cards(path, base_card(title="SAML bypass"))
    enrich_cards(path, now=NOW)
    mtime = path.stat().st_mtime_ns

    # When: a no-op enrichment runs.
    enrich_cards(path, now=LATER)

    # Then: the file is not rewritten.
    assert path.stat().st_mtime_ns == mtime


def test_enrich_bounds_derived_lists(tmp_path: Path) -> None:
    # Given: a card pre-loaded with more human CVEs than the derived cap allows.
    path = tmp_path / "cards.jsonl"
    human_cves = [f"CVE-2024-{index:04d}" for index in range(60)]
    write_cards(path, base_card(cves=human_cves))

    # When: the card is enriched.
    enrich_cards(path, now=NOW)

    # Then: the stored list is capped to the schema limit.
    card = read_cards(path)[0]
    assert len(card["cves"]) == 50


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("{not json}\n", "malformed_jsonl"),
        ('["a", "list"]\n', "card_type"),
        ('{"id": "card-1"}\n\n', "blank_line"),
    ],
)
def test_enrich_fails_closed_on_bad_input(
    tmp_path: Path, content: str, reason: str
) -> None:
    # Given: a cards file with structurally invalid content.
    path = tmp_path / "cards.jsonl"
    path.write_text(content, encoding="utf-8")

    # When/Then: enrichment refuses to run and names the failure.
    with pytest.raises(EnrichmentError) as caught:
        enrich_cards(path, now=NOW)
    assert caught.value.reason == reason


def test_enrich_handles_missing_file_as_empty(tmp_path: Path) -> None:
    # Given: no cards file on disk.
    path = tmp_path / "cards.jsonl"

    # When: enrichment runs against the missing path.
    summary = enrich_cards(path, now=NOW)

    # Then: it reports an empty corpus and writes nothing.
    assert summary.cards_total == 0
    assert not path.exists()
