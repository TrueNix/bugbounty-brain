from __future__ import annotations

# allow: SIZE_OK - required collector TDD matrix is constrained to this file.
import hashlib
import json
from pathlib import Path
import re

import pytest

from bugbounty_brain import collector
from bugbounty_brain.collector import (
    MAX_RESPONSE_BYTES,
    FetchRequest,
    FetchResponse,
    collect,
)

NOW = "2026-07-10T11:30:00Z"
RSS_URL = "https://feeds.example.test/rss.xml"
ATOM_URL = "https://feeds.example.test/atom.xml"
CARD_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,83}-[0-9a-f]{12}$")

RSS_FEED = b"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Example RSS</title>
    <item>
      <guid>rss-one</guid>
      <title>First RSS Item</title>
      <link>https://example.test/one</link>
      <description>One summary</description>
      <pubDate>Fri, 10 Jul 2026 10:00:00 GMT</pubDate>
    </item>
    <item>
      <guid>rss-two</guid>
      <title>Second RSS Item</title>
      <link>https://example.test/two</link>
      <description>Two summary</description>
      <pubDate>Fri, 10 Jul 2026 11:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

ATOM_FEED = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example Atom</title>
  <entry>
    <id>tag:example.test,2026:atom-one</id>
    <title>First Atom Item</title>
    <link href="https://example.test/atom-one" />
    <summary>Atom summary</summary>
    <updated>2026-07-10T12:30:00+02:00</updated>
  </entry>
</feed>
"""


class ScriptedFetcher:
    def __init__(self, responses: dict[str, list[FetchResponse]]) -> None:
        self._responses = {url: list(values) for url, values in responses.items()}
        self.requests: list[FetchRequest] = []

    def __call__(self, request: FetchRequest) -> FetchResponse:
        self.requests.append(request)
        responses = self._responses[request.url]
        if len(responses) == 1:
            return responses[0]
        return responses.pop(0)


class FailingIfCalledFetcher:
    requests: list[FetchRequest] = []

    def __call__(self, request: FetchRequest) -> FetchResponse:
        self.requests.append(request)
        raise AssertionError(f"unexpected fetch for {request.url}")


def write_sources(tmp_path: Path, sources: list[dict[str, str | int]]) -> Path:
    path = tmp_path / "sources.json"
    path.write_text(json.dumps(sources), encoding="utf-8")
    return path


def read_jsonl(path: Path) -> list[dict[str, str | list[str]]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    return tmp_path / "raw", tmp_path / "cards.jsonl", tmp_path / "state.json"


def test_collect_parses_rss_feed_when_source_returns_rss(tmp_path: Path) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Example RSS", "url": RSS_URL, "max_entries": 10}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher(
        {
            RSS_URL: [
                FetchResponse(
                    200,
                    {
                        "ETag": '"rss-v1"',
                        "Last-Modified": "Fri, 10 Jul 2026 11:00:00 GMT",
                    },
                    RSS_FEED,
                ),
            ],
        },
    )

    # When
    summary = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    cards = read_jsonl(cards_path)
    assert summary.sources_fetched == 1
    assert summary.cards_added == 2
    assert [card["title"] for card in cards] == ["First RSS Item", "Second RSS Item"]
    assert cards[0]["summary"] == "One summary"
    assert cards[0]["source_name"] == "Example RSS"
    assert cards[0]["source_url"] == "https://example.test/one"
    assert cards[0]["published_at"] == "2026-07-10T10:00:00Z"
    assert cards[0]["fetched_at"] == NOW
    assert cards[0]["products"] == []
    assert cards[0]["cves"] == []
    assert cards[0]["techniques"] == []
    assert cards[0]["confidence"] == "medium"
    assert cards[0]["safety"] == "public"
    assert (raw_dir / f"{hashlib.sha256(RSS_FEED).hexdigest()}.xml").exists()


def test_collect_parses_atom_feed_when_source_returns_atom(tmp_path: Path) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Example Atom", "url": ATOM_URL, "max_entries": 10}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher(
        {ATOM_URL: [FetchResponse(200, {"ETag": '"atom-v1"'}, ATOM_FEED)]},
    )

    # When
    summary = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    cards = read_jsonl(cards_path)
    assert summary.sources_fetched == 1
    assert summary.cards_added == 1
    assert cards[0]["title"] == "First Atom Item"
    assert cards[0]["summary"] == "Atom summary"
    assert cards[0]["source_url"] == "https://example.test/atom-one"
    assert cards[0]["published_at"] == "2026-07-10T10:30:00Z"


@pytest.mark.parametrize(
    "feed",
    [
        pytest.param(
            b"""<rss version="2.0"><channel><item>
              <guid>missing-rss-date</guid><title>Missing RSS date</title>
              <link>https://example.test/missing-rss-date</link>
            </item></channel></rss>""",
            id="rss-missing",
        ),
        pytest.param(
            b"""<rss version="2.0"><channel><item>
              <guid>invalid-rss-date</guid><title>Invalid RSS date</title>
              <link>https://example.test/invalid-rss-date</link>
              <pubDate>not-a-date</pubDate>
            </item></channel></rss>""",
            id="rss-invalid",
        ),
        pytest.param(
            b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry>
              <id>missing-atom-date</id><title>Missing Atom date</title>
              <link href="https://example.test/missing-atom-date" />
            </entry></feed>""",
            id="atom-missing",
        ),
        pytest.param(
            b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry>
              <id>invalid-atom-date</id><title>Invalid Atom date</title>
              <link href="https://example.test/invalid-atom-date" />
              <updated>not-a-date</updated>
            </entry></feed>""",
            id="atom-invalid",
        ),
    ],
)
def test_collect_uses_fetched_at_when_feed_date_is_missing_or_invalid(
    tmp_path: Path,
    feed: bytes,
) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Date fallback", "url": RSS_URL, "max_entries": 1}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher({RSS_URL: [FetchResponse(200, {}, feed)]})

    # When
    collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    assert read_jsonl(cards_path)[0]["published_at"] == NOW


def test_collect_truncates_card_text_and_hashes_emitted_values(tmp_path: Path) -> None:
    # Given
    title = "T" * 160
    summary = "S" * 1_200
    feed = f"""<rss version="2.0"><channel><item>
      <guid>long-entry</guid><title>{title}</title>
      <link>https://example.test/long-entry</link>
      <description>{summary}</description>
      <pubDate>Fri, 10 Jul 2026 10:00:00 GMT</pubDate>
    </item></channel></rss>""".encode()
    sources_path = write_sources(
        tmp_path,
        [{"name": "Long RSS", "url": RSS_URL, "max_entries": 1}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher({RSS_URL: [FetchResponse(200, {}, feed)]})

    # When
    collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    card = read_jsonl(cards_path)[0]
    assert card["title"] == title[:140]
    assert card["summary"] == summary[:1_000]
    canonical = {
        "entry_key": "long-entry",
        "published_at": card["published_at"],
        "source_name": "Long RSS",
        "source_url": "https://example.test/long-entry",
        "summary": card["summary"],
        "title": card["title"],
    }
    assert (
        card["content_sha256"]
        == hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()
    )


def test_collect_is_idempotent_when_same_feed_is_seen_twice(tmp_path: Path) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Example RSS", "url": RSS_URL, "max_entries": 10}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher(
        {
            RSS_URL: [
                FetchResponse(200, {"ETag": '"rss-v1"'}, RSS_FEED),
                FetchResponse(200, {"ETag": '"rss-v1"'}, RSS_FEED),
            ],
        },
    )

    # When
    first = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)
    second = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    cards = read_jsonl(cards_path)
    assert first.cards_added == 2
    assert second.cards_added == 0
    assert second.cards_skipped_existing == 2
    assert len(cards) == 2
    assert len({card["id"] for card in cards}) == 2


def test_collect_sends_conditional_headers_when_state_has_validators(
    tmp_path: Path,
) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Example RSS", "url": RSS_URL, "max_entries": 10}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher(
        {
            RSS_URL: [
                FetchResponse(
                    200,
                    {
                        "ETag": '"rss-v1"',
                        "Last-Modified": "Fri, 10 Jul 2026 11:00:00 GMT",
                    },
                    RSS_FEED,
                ),
                FetchResponse(304, {}, b""),
            ],
        },
    )

    # When
    collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)
    summary = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    second_headers = fetcher.requests[1].headers
    assert second_headers["If-None-Match"] == '"rss-v1"'
    assert second_headers["If-Modified-Since"] == "Fri, 10 Jul 2026 11:00:00 GMT"
    assert summary.sources_not_modified == 1
    assert summary.cards_added == 0


def test_collect_preserves_outputs_when_source_is_not_modified(tmp_path: Path) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Example RSS", "url": RSS_URL, "max_entries": 10}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher(
        {
            RSS_URL: [
                FetchResponse(200, {"ETag": '"rss-v1"'}, RSS_FEED),
                FetchResponse(304, {}, b""),
            ],
        },
    )
    collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)
    cards_before = cards_path.read_text(encoding="utf-8")
    state_before = state_path.read_text(encoding="utf-8")
    raw_before = sorted(path.name for path in raw_dir.iterdir())

    # When
    summary = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    assert summary.sources_not_modified == 1
    assert cards_path.read_text(encoding="utf-8") == cards_before
    assert state_path.read_text(encoding="utf-8") == state_before
    assert sorted(path.name for path in raw_dir.iterdir()) == raw_before


def test_collect_rejects_oversized_response_without_corrupting_files(
    tmp_path: Path,
) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Huge Feed", "url": RSS_URL, "max_entries": 10}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher(
        {RSS_URL: [FetchResponse(200, {}, b"x" * (MAX_RESPONSE_BYTES + 1))]},
    )

    # When
    summary = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    assert summary.sources_failed == 1
    assert summary.failures[0].reason == "response_too_large"
    assert not cards_path.exists()
    assert not state_path.exists()
    assert not raw_dir.exists() or list(raw_dir.iterdir()) == []


def test_collect_isolates_malformed_xml_to_failing_source(tmp_path: Path) -> None:
    # Given
    bad_url = "https://feeds.example.test/bad.xml"
    sources_path = write_sources(
        tmp_path,
        [
            {"name": "Bad Feed", "url": bad_url, "max_entries": 10},
            {"name": "Good Feed", "url": RSS_URL, "max_entries": 1},
        ],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = ScriptedFetcher(
        {
            bad_url: [FetchResponse(200, {}, b"<rss><channel><item>")],
            RSS_URL: [FetchResponse(200, {"ETag": '"rss-v1"'}, RSS_FEED)],
        },
    )

    # When
    summary = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    cards = read_jsonl(cards_path)
    assert summary.sources_fetched == 1
    assert summary.sources_failed == 1
    assert summary.failures[0].source_name == "Bad Feed"
    assert summary.failures[0].reason == "malformed_xml"
    assert len(cards) == 1
    assert cards[0]["source_name"] == "Good Feed"


def test_collect_rejects_non_http_sources_without_fetching(tmp_path: Path) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [
            {"name": "Local File", "url": "file:///etc/passwd", "max_entries": 10},
            {"name": "FTP Feed", "url": "ftp://example.test/feed", "max_entries": 10},
        ],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    fetcher = FailingIfCalledFetcher()

    # When
    summary = collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)

    # Then
    assert summary.sources_total == 2
    assert summary.sources_failed == 2
    assert [failure.reason for failure in summary.failures] == [
        "unsupported_url",
        "unsupported_url",
    ]
    assert fetcher.requests == []
    assert not cards_path.exists()


def test_collect_uses_deterministic_card_ids_and_content_hashes(
    tmp_path: Path,
) -> None:
    # Given
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first_sources = write_sources(
        first_dir,
        [{"name": "Example RSS", "url": RSS_URL, "max_entries": 1}],
    )
    second_sources = write_sources(
        second_dir,
        [{"name": "Example RSS", "url": RSS_URL, "max_entries": 1}],
    )
    first_raw, first_cards, first_state = paths(first_dir)
    second_raw, second_cards, second_state = paths(second_dir)

    # When
    collect(
        first_sources,
        first_raw,
        first_cards,
        first_state,
        ScriptedFetcher({RSS_URL: [FetchResponse(200, {}, RSS_FEED)]}),
        NOW,
    )
    collect(
        second_sources,
        second_raw,
        second_cards,
        second_state,
        ScriptedFetcher({RSS_URL: [FetchResponse(200, {}, RSS_FEED)]}),
        NOW,
    )

    # Then
    first_card = read_jsonl(first_cards)[0]
    second_card = read_jsonl(second_cards)[0]
    expected_id = (
        "card-" + hashlib.sha256(f"{RSS_URL}\nrss-one".encode()).hexdigest()[:12]
    )
    assert isinstance(first_card["id"], str)
    assert CARD_ID_RE.fullmatch(first_card["id"])
    assert first_card["id"] == expected_id
    assert second_card["id"] == expected_id
    assert first_card["content_sha256"] == second_card["content_sha256"]
    assert (
        first_card["content_sha256"]
        == hashlib.sha256(
            json.dumps(
                {
                    "entry_key": "rss-one",
                    "published_at": "2026-07-10T10:00:00Z",
                    "source_name": "Example RSS",
                    "source_url": "https://example.test/one",
                    "summary": "One summary",
                    "title": "First RSS Item",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        ).hexdigest()
    )


def test_collect_keeps_existing_outputs_when_atomic_card_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    sources_path = write_sources(
        tmp_path,
        [{"name": "Example RSS", "url": RSS_URL, "max_entries": 1}],
    )
    raw_dir, cards_path, state_path = paths(tmp_path)
    cards_path.write_text('{"id":"existing"}\n', encoding="utf-8")
    state_path.write_text('{"sources":{}}\n', encoding="utf-8")
    old_cards = cards_path.read_text(encoding="utf-8")
    old_state = state_path.read_text(encoding="utf-8")
    real_replace = collector.os.replace

    def fail_card_replace(source: str | bytes, destination: str | bytes) -> None:
        if Path(destination) == cards_path:
            raise OSError("forced replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(collector.os, "replace", fail_card_replace)
    fetcher = ScriptedFetcher({RSS_URL: [FetchResponse(200, {}, RSS_FEED)]})

    # When / Then
    with pytest.raises(OSError, match="forced replace failure"):
        collect(sources_path, raw_dir, cards_path, state_path, fetcher, NOW)
    assert cards_path.read_text(encoding="utf-8") == old_cards
    assert state_path.read_text(encoding="utf-8") == old_state
