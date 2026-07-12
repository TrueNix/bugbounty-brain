from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeAlias, assert_never

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)

DEFAULT_THRESHOLD: Final = 3


@dataclass(frozen=True, slots=True)
class SourceHealth:
    source_name: str
    source_url: str
    consecutive_failures: int
    first_failed_at: str
    last_reason: str


@dataclass(frozen=True, slots=True)
class HealthReport:
    threshold: int
    total_failing: int
    unhealthy: tuple[SourceHealth, ...]
    degraded: tuple[SourceHealth, ...]
    recovered: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.unhealthy

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1


def record(
    summary_path: Path | str,
    state_path: Path | str,
    *,
    threshold: int = DEFAULT_THRESHOLD,
    now: str | dt.datetime | None = None,
) -> HealthReport:
    """Fold one collection summary into the persisted source-health streaks.

    Reads the machine-readable summary emitted by ``collect``, increments the
    consecutive-failure streak for each failed source, resets sources that
    succeeded, writes the updated state atomically, and reports which sources
    have now failed for at least ``threshold`` consecutive runs.
    """
    failures = _failures_from_summary(Path(summary_path))
    previous = load_state(Path(state_path))
    new_state, report = update_health(
        previous, failures, _now_text(now), max(1, threshold)
    )
    save_state(Path(state_path), new_state)
    return report


def update_health(
    previous: Mapping[str, SourceHealth],
    failures: Iterable[tuple[str, str, str]],
    now: str,
    threshold: int,
) -> tuple[dict[str, SourceHealth], HealthReport]:
    failed: dict[str, tuple[str, str]] = {}
    for source_name, source_url, reason in failures:
        failed[source_url] = (source_name, reason)

    new_state: dict[str, SourceHealth] = {}
    for source_url, (source_name, reason) in sorted(failed.items()):
        prior = previous.get(source_url)
        streak = (prior.consecutive_failures if prior is not None else 0) + 1
        first_failed_at = prior.first_failed_at if prior is not None else now
        new_state[source_url] = SourceHealth(
            source_name=source_name,
            source_url=source_url,
            consecutive_failures=streak,
            first_failed_at=first_failed_at,
            last_reason=reason,
        )

    recovered = tuple(sorted(url for url in previous if url not in failed))
    unhealthy = tuple(
        health
        for health in new_state.values()
        if health.consecutive_failures >= threshold
    )
    degraded = tuple(
        health
        for health in new_state.values()
        if 0 < health.consecutive_failures < threshold
    )
    report = HealthReport(
        threshold=threshold,
        total_failing=len(new_state),
        unhealthy=unhealthy,
        degraded=degraded,
        recovered=recovered,
    )
    return new_state, report


def load_state(path: Path) -> dict[str, SourceHealth]:
    if not path.exists():
        return {}
    try:
        data: JsonValue = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, Mapping):
        return {}
    sources = data.get("sources")
    if not isinstance(sources, Mapping):
        return {}
    state: dict[str, SourceHealth] = {}
    for url, raw in sources.items():
        health = _health_from_json(url, raw)
        if health is not None:
            state[url] = health
    return state


def save_state(path: Path, state: Mapping[str, SourceHealth]) -> None:
    payload = {
        "sources": {
            url: {
                "consecutive_failures": health.consecutive_failures,
                "first_failed_at": health.first_failed_at,
                "last_reason": health.last_reason,
                "source_name": health.source_name,
            }
            for url, health in sorted(state.items())
        },
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    _write_text_atomic(path, text)


def report_payload(report: HealthReport) -> dict[str, JsonValue]:
    return {
        "threshold": report.threshold,
        "total_failing": report.total_failing,
        "ok": report.ok,
        "exit_code": report.exit_code,
        "unhealthy": [_health_payload(health) for health in report.unhealthy],
        "degraded": [_health_payload(health) for health in report.degraded],
        "recovered": list(report.recovered),
    }


def _health_payload(health: SourceHealth) -> dict[str, JsonValue]:
    return {
        "source_name": health.source_name,
        "source_url": health.source_url,
        "consecutive_failures": health.consecutive_failures,
        "first_failed_at": health.first_failed_at,
        "last_reason": health.last_reason,
    }


def _failures_from_summary(path: Path) -> list[tuple[str, str, str]]:
    data: JsonValue = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        return []
    raw_failures = data.get("failures")
    if not isinstance(raw_failures, list):
        return []
    failures: list[tuple[str, str, str]] = []
    for entry in raw_failures:
        if not isinstance(entry, Mapping):
            continue
        name = entry.get("source_name")
        url = entry.get("source_url")
        reason = entry.get("reason")
        if isinstance(name, str) and isinstance(url, str) and isinstance(reason, str):
            failures.append((name, url, reason))
    return failures


def _health_from_json(url: JsonValue, raw: JsonValue) -> SourceHealth | None:
    if not isinstance(url, str) or not isinstance(raw, Mapping):
        return None
    streak = raw.get("consecutive_failures")
    first_failed_at = raw.get("first_failed_at")
    last_reason = raw.get("last_reason")
    source_name = raw.get("source_name")
    if (
        not isinstance(streak, int)
        or isinstance(streak, bool)
        or streak < 1
        or not isinstance(first_failed_at, str)
        or not isinstance(last_reason, str)
        or not isinstance(source_name, str)
    ):
        return None
    return SourceHealth(
        source_name=source_name,
        source_url=url,
        consecutive_failures=streak,
        first_failed_at=first_failed_at,
        last_reason=last_reason,
    )


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(text.encode("utf-8"))
        os.replace(temp_path, path)
    except OSError:
        temp_path.unlink(missing_ok=True)
        raise


def _now_text(now: str | dt.datetime | None) -> str:
    match now:
        case None:
            stamp = dt.datetime.now(dt.UTC)
        case str() as text:
            return text
        case dt.datetime() as stamp:
            pass
        case unreachable:
            assert_never(unreachable)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.UTC)
    return stamp.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")
