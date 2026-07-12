from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import json
from pathlib import Path
import sys
from typing import Final, TypeAlias

from bugbounty_brain import __version__
from bugbounty_brain.compiler import (
    CompileSummary,
    CompileValidationError,
    Fts5UnavailableError,
    compile_brain,
)
from bugbounty_brain.collector import CollectionSummary, collect
from bugbounty_brain.enricher import EnrichmentError, EnrichSummary, enrich_cards
from bugbounty_brain.health import DEFAULT_THRESHOLD, record, report_payload
from bugbounty_brain.validator import ValidationIssue, ValidationReport, validate_cards

PROGRAM_NAME: Final = "bugbounty-brain"
DEFAULT_SOURCES_PATH: Final = Path("sources.json")
DEFAULT_RAW_DIR: Final = Path("raw")
DEFAULT_CARDS_PATH: Final = Path("knowledge/cards.jsonl")
DEFAULT_STATE_PATH: Final = Path(".cache/collector-state.json")
DEFAULT_DATABASE_PATH: Final = Path("dist/reference_knowledge.db")
DEFAULT_MANIFEST_PATH: Final = Path("dist/brain-manifest.json")
DEFAULT_HEALTH_PATH: Final = Path(".cache/source-health.json")

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


class _Arguments(argparse.Namespace):
    sources_path: Path
    raw_dir: Path
    cards_path: Path
    state_path: Path
    database_path: Path
    manifest_path: Path
    summary_path: Path
    health_path: Path
    threshold: int
    runner: Callable[["_Arguments"], int]


def _issue_payload(issue: ValidationIssue) -> dict[str, JsonValue]:
    return {"code": issue.code, "location": issue.location}


def _validation_payload(report: ValidationReport) -> dict[str, JsonValue]:
    return {
        "path": report.path,
        "card_count": report.card_count,
        "issue_count": report.issue_count,
        "error_count": report.error_count,
        "ok": report.ok,
        "exit_code": report.exit_code,
        "issues": [_issue_payload(issue) for issue in report.issues],
    }


def _collection_payload(summary: CollectionSummary) -> dict[str, JsonValue]:
    return {
        "sources_total": summary.sources_total,
        "sources_fetched": summary.sources_fetched,
        "sources_not_modified": summary.sources_not_modified,
        "sources_failed": summary.sources_failed,
        "cards_added": summary.cards_added,
        "cards_skipped_existing": summary.cards_skipped_existing,
        "raw_snapshots_added": summary.raw_snapshots_added,
        "failures": [
            {
                "source_name": failure.source_name,
                "source_url": failure.source_url,
                "reason": failure.reason,
            }
            for failure in summary.failures
        ],
    }


def _enrich_payload(summary: EnrichSummary) -> dict[str, JsonValue]:
    return {
        "cards_total": summary.cards_total,
        "cards_changed": summary.cards_changed,
        "cards_unchanged": summary.cards_unchanged,
        "enrichment_version": summary.enrichment_version,
        "cves_total": summary.cves_total,
        "products_total": summary.products_total,
        "techniques_total": summary.techniques_total,
    }


def _compile_payload(summary: CompileSummary) -> dict[str, JsonValue]:
    return {
        "schema_version": summary.schema_version,
        "generated_at": summary.generated_at,
        "card_count": summary.card_count,
        "source_sha256": summary.source_sha256,
        "database_sha256": summary.database_sha256,
        "database_filename": summary.database_filename,
        "compatibility": summary.compatibility,
    }


def _emit_json(payload: dict[str, JsonValue], *, stderr: bool = False) -> None:
    stream = sys.stderr if stderr else sys.stdout
    stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _validate_command(arguments: _Arguments) -> int:
    report = validate_cards(arguments.cards_path)
    _emit_json(_validation_payload(report))
    return report.exit_code


def _collect_command(arguments: _Arguments) -> int:
    summary = collect(
        arguments.sources_path,
        arguments.raw_dir,
        arguments.cards_path,
        arguments.state_path,
    )
    _emit_json(_collection_payload(summary))
    all_sources_failed = (
        summary.sources_total > 0
        and summary.sources_failed == summary.sources_total
        and summary.sources_fetched == 0
        and summary.sources_not_modified == 0
    )
    return int(all_sources_failed)


def _health_command(arguments: _Arguments) -> int:
    try:
        report = record(
            arguments.summary_path,
            arguments.health_path,
            threshold=arguments.threshold,
        )
    except (OSError, json.JSONDecodeError) as error:
        _emit_json(
            {"error": "health_summary_unreadable", "message": str(error)},
            stderr=True,
        )
        return 1
    _emit_json(report_payload(report))
    return report.exit_code


def _enrich_command(arguments: _Arguments) -> int:
    try:
        summary = enrich_cards(arguments.cards_path)
    except EnrichmentError as error:
        _emit_json(
            {
                "error": "enrichment_failed",
                "reason": error.reason,
                "location": error.location,
            },
            stderr=True,
        )
        return 1
    _emit_json(_enrich_payload(summary))
    return 0


def _compile_command(arguments: _Arguments) -> int:
    try:
        summary = compile_brain(
            arguments.cards_path,
            arguments.database_path,
            arguments.manifest_path,
        )
    except CompileValidationError as error:
        _emit_json(
            {
                "error": "compile_validation_failed",
                "issue_count": len(error.issues),
                "issues": [_issue_payload(issue) for issue in error.issues],
            },
            stderr=True,
        )
        return error.report.exit_code
    except Fts5UnavailableError as error:
        _emit_json({"error": "fts5_unavailable", "message": str(error)}, stderr=True)
        return 1
    _emit_json(_compile_payload(summary))
    return 0


def _all_command(arguments: _Arguments) -> int:
    collection_exit = _collect_command(arguments)
    if collection_exit != 0:
        return collection_exit
    enrich_exit = _enrich_command(arguments)
    if enrich_exit != 0:
        return enrich_exit
    validation_exit = _validate_command(arguments)
    if validation_exit != 0:
        return validation_exit
    return _compile_command(arguments)


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sources-path",
        "--sources",
        dest="sources_path",
        type=Path,
        default=DEFAULT_SOURCES_PATH,
    )
    parser.add_argument("--raw-dir", dest="raw_dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument(
        "--state-path",
        "--state",
        dest="state_path",
        type=Path,
        default=DEFAULT_STATE_PATH,
    )


def _add_cards_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cards-path",
        "--cards",
        dest="cards_path",
        type=Path,
        default=DEFAULT_CARDS_PATH,
    )


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db-path",
        "--database",
        dest="database_path",
        type=Path,
        default=DEFAULT_DATABASE_PATH,
    )
    parser.add_argument(
        "--manifest-path",
        "--manifest",
        dest="manifest_path",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description="Build validated, searchable bug bounty knowledge.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(required=True)
    collect_parser = commands.add_parser(
        "collect", help="Collect knowledge cards from configured feeds."
    )
    _add_source_arguments(collect_parser)
    _add_cards_argument(collect_parser)
    collect_parser.set_defaults(runner=_collect_command)
    enrich_parser = commands.add_parser(
        "enrich",
        help="Deterministically derive cves, products, and techniques for cards.",
    )
    _add_cards_argument(enrich_parser)
    enrich_parser.set_defaults(runner=_enrich_command)
    validate_parser = commands.add_parser(
        "validate", help="Validate canonical knowledge cards."
    )
    _add_cards_argument(validate_parser)
    validate_parser.set_defaults(runner=_validate_command)
    compile_parser = commands.add_parser(
        "compile", help="Compile cards into SQLite and a manifest."
    )
    _add_cards_argument(compile_parser)
    _add_output_arguments(compile_parser)
    compile_parser.set_defaults(runner=_compile_command)
    health_parser = commands.add_parser(
        "health",
        help="Track and report consecutive source-fetch failure streaks.",
    )
    health_parser.add_argument(
        "--summary",
        dest="summary_path",
        type=Path,
        required=True,
    )
    health_parser.add_argument(
        "--health-path",
        dest="health_path",
        type=Path,
        default=DEFAULT_HEALTH_PATH,
    )
    health_parser.add_argument(
        "--threshold",
        dest="threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
    )
    health_parser.set_defaults(runner=_health_command)
    all_parser = commands.add_parser("all", help="Collect, validate, then compile.")
    _add_source_arguments(all_parser)
    _add_cards_argument(all_parser)
    _add_output_arguments(all_parser)
    all_parser.set_defaults(runner=_all_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv, namespace=_Arguments())
    return arguments.runner(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
