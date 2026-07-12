from __future__ import annotations

import json
from pathlib import Path

from bugbounty_brain.health import (
    SourceHealth,
    load_state,
    record,
    report_payload,
    save_state,
    update_health,
)

NOW = "2026-07-12T00:00:00Z"
LATER = "2026-07-12T01:00:00Z"
URL = "https://portswigger.net/research/rss"
FAILURE = ("PortSwigger", URL, "http_500")


def write_summary(path: Path, *failures: tuple[str, str, str]) -> None:
    payload = {
        "sources_total": 3,
        "sources_failed": len(failures),
        "failures": [
            {"source_name": name, "source_url": url, "reason": reason}
            for name, url, reason in failures
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_update_health_increments_streak_and_preserves_first_failure() -> None:
    # Given: a source that already failed once.
    prior = {URL: SourceHealth("PortSwigger", URL, 1, NOW, "http_500")}

    # When: it fails again at a later time.
    state, report = update_health(prior, [FAILURE], LATER, threshold=3)

    # Then: the streak grows but the first-failure timestamp is retained.
    assert state[URL].consecutive_failures == 2
    assert state[URL].first_failed_at == NOW
    assert report.degraded and not report.unhealthy


def test_update_health_flags_unhealthy_at_threshold() -> None:
    # Given: a source that has already failed twice.
    prior = {URL: SourceHealth("PortSwigger", URL, 2, NOW, "timeout")}

    # When: it fails a third time against a threshold of three.
    _, report = update_health(prior, [FAILURE], LATER, threshold=3)

    # Then: it is reported unhealthy and the report is not ok.
    assert [health.source_url for health in report.unhealthy] == [URL]
    assert report.ok is False
    assert report.exit_code == 1


def test_update_health_resets_recovered_sources() -> None:
    # Given: a previously failing source.
    prior = {URL: SourceHealth("PortSwigger", URL, 5, NOW, "timeout")}

    # When: a run reports no failures.
    state, report = update_health(prior, [], LATER, threshold=3)

    # Then: the source is dropped and listed as recovered.
    assert state == {}
    assert report.recovered == (URL,)
    assert report.total_failing == 0


def test_update_health_is_deterministically_ordered() -> None:
    # Given: two sources failing in the same run.
    other = "https://ctftime.org/writeups/rss/"
    failures = [
        ("CTFtime", other, "fetch_error"),
        ("PortSwigger", URL, "http_500"),
    ]

    # When: health is updated with a threshold of one.
    _, report = update_health({}, failures, NOW, threshold=1)

    # Then: unhealthy sources are ordered by URL, not discovery order.
    assert [health.source_url for health in report.unhealthy] == sorted([URL, other])


def test_record_persists_state_across_runs(tmp_path: Path) -> None:
    # Given: a summary reporting one failed source and an empty state file.
    summary = tmp_path / "summary.json"
    state = tmp_path / "health.json"
    write_summary(summary, FAILURE)

    # When: two consecutive collections are recorded.
    first = record(summary, state, threshold=3, now=NOW)
    second = record(summary, state, threshold=3, now=LATER)

    # Then: the streak accumulates via the persisted state file.
    assert first.total_failing == 1
    assert not second.unhealthy and second.degraded
    stored = load_state(state)
    assert stored[URL].consecutive_failures == 2


def test_record_reaches_unhealthy_after_threshold_runs(tmp_path: Path) -> None:
    # Given: a summary that keeps failing the same source.
    summary = tmp_path / "summary.json"
    state = tmp_path / "health.json"
    write_summary(summary, FAILURE)

    # When: it is recorded three times against a threshold of three.
    reports = [record(summary, state, threshold=3, now=NOW) for _ in range(3)]

    # Then: only the third run trips the unhealthy threshold.
    assert [report.exit_code for report in reports] == [0, 0, 1]


def test_load_state_tolerates_missing_and_malformed(tmp_path: Path) -> None:
    # Given: a missing file and a malformed file.
    missing = tmp_path / "missing.json"
    malformed = tmp_path / "bad.json"
    malformed.write_text("{not json", encoding="utf-8")

    # When/Then: both degrade to an empty state rather than raising.
    assert load_state(missing) == {}
    assert load_state(malformed) == {}


def test_state_round_trips_through_disk(tmp_path: Path) -> None:
    # Given: a health state with one entry.
    state = {URL: SourceHealth("PortSwigger", URL, 4, NOW, "http_500")}
    path = tmp_path / "health.json"

    # When: it is saved and reloaded.
    save_state(path, state)
    reloaded = load_state(path)

    # Then: the entry survives the round trip intact.
    assert reloaded == state


def test_report_payload_exposes_stable_shape() -> None:
    # Given: a report with one unhealthy source.
    _, report = update_health(
        {URL: SourceHealth("PortSwigger", URL, 2, NOW, "timeout")},
        [FAILURE],
        LATER,
        threshold=3,
    )

    # When: the report is rendered for machine consumption.
    payload = report_payload(report)

    # Then: it carries the gate fields and the failing source detail.
    assert payload["ok"] is False
    assert payload["exit_code"] == 1
    assert payload["threshold"] == 3
    assert payload["unhealthy"][0]["source_url"] == URL
    assert payload["unhealthy"][0]["consecutive_failures"] == 3
