from __future__ import annotations

# noqa: SIZE_OK - the user constrained the complete CLI integration matrix here.
import json
from pathlib import Path
import sqlite3
import tomllib
from typing import TypeAlias

import pytest

from bugbounty_brain.collector import CollectionSummary, SourceFailure

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


def valid_card() -> dict[str, JsonValue]:
    return {
        "id": "apache-struts-rce-a1b2c3d4e5f6",
        "title": "Apache Struts RCE advisory",
        "summary": "Public remediation guidance for affected deployments.",
        "source_url": "https://example.com/advisories/struts-rce",
        "source_name": "Example Security Advisory",
        "published_at": "2026-07-10T08:30:00Z",
        "fetched_at": "2026-07-10T09:00:00Z",
        "content_sha256": "0" * 64,
        "products": ["Apache Struts"],
        "cves": ["CVE-2024-53677"],
        "techniques": ["Input validation bypass"],
        "confidence": "high",
        "safety": "public",
    }


def write_card(path: Path, card: dict[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{json.dumps(card, sort_keys=True)}\n", encoding="utf-8")


def pipeline_arguments(tmp_path: Path) -> tuple[list[str], Path, Path, Path]:
    cards_path = tmp_path / "cards.jsonl"
    database_path = tmp_path / "brain.db"
    manifest_path = tmp_path / "manifest.json"
    return (
        [
            "all",
            "--sources-path",
            str(tmp_path / "feeds.json"),
            "--raw-dir",
            str(tmp_path / "raw"),
            "--cards-path",
            str(cards_path),
            "--state-path",
            str(tmp_path / "state.json"),
            "--db-path",
            str(database_path),
            "--manifest-path",
            str(manifest_path),
        ],
        cards_path,
        database_path,
        manifest_path,
    )


def not_modified_collection(
    _sources_path: Path | str,
    _raw_dir: Path | str,
    _cards_path: Path | str,
    _state_path: Path | str,
) -> CollectionSummary:
    return CollectionSummary(1, 0, 1, 0, 0, 0, 0, ())


def test_main_prints_help_when_global_help_is_requested(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: the package CLI entry point.
    from bugbounty_brain.cli import main

    # When: global help is requested.
    with pytest.raises(SystemExit) as raised:
        main(["--help"])

    # Then: argparse reports every pipeline command and exits successfully.
    output = capsys.readouterr()
    assert raised.value.code == 0
    assert "usage: bugbounty-brain" in output.out
    assert all(
        command in output.out for command in ("collect", "validate", "compile", "all")
    )
    assert output.err == ""


def test_main_prints_version_when_global_version_is_requested(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: the package CLI entry point.
    from bugbounty_brain.cli import main

    # When: the global version flag is requested.
    with pytest.raises(SystemExit) as raised:
        main(["--version"])

    # Then: the distribution version is printed and argparse exits successfully.
    output = capsys.readouterr()
    assert raised.value.code == 0
    assert output.out == "bugbounty-brain 0.1.0\n"
    assert output.err == ""


def test_packaging_metadata_declares_installable_distribution_when_built() -> None:
    # Given: the project packaging configuration.
    project_file = Path(__file__).parents[1] / "pyproject.toml"

    # When: its standards-based metadata is parsed.
    configuration = tomllib.loads(project_file.read_text(encoding="utf-8"))

    # Then: the package, entry point, runtime, build backend, and dev tools are declared.
    project = configuration["project"]
    assert project["name"] == "bugbounty-brain"
    assert project["version"] == "0.1.0"
    assert project["requires-python"] == ">=3.11"
    assert project["dependencies"] == []
    assert project["scripts"] == {"bugbounty-brain": "bugbounty_brain.cli:main"}
    assert {"pytest", "ruff", "mypy", "build"}.issubset(
        {
            requirement.split(">=", maxsplit=1)[0]
            for requirement in project["optional-dependencies"]["dev"]
        }
    )
    assert configuration["build-system"]["build-backend"] == "setuptools.build_meta"
    assert configuration["tool"]["setuptools"]["package-dir"] == {"": "src"}
    assert configuration["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]
    assert "F" in configuration["tool"]["ruff"]["lint"]["select"]
    assert configuration["tool"]["mypy"]["strict"] is True


def test_validate_prints_clean_json_report_when_default_cards_are_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: one valid card at the default canonical path.
    cards_path = tmp_path / "knowledge" / "cards.jsonl"
    write_card(cards_path, valid_card())
    monkeypatch.chdir(tmp_path)
    from bugbounty_brain.cli import main

    # When: validation runs without a path override.
    exit_code = main(["validate"])

    # Then: stdout is a complete JSON report carrying its successful exit code.
    output = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(output.out) == {
        "card_count": 1,
        "error_count": 0,
        "exit_code": 0,
        "issue_count": 0,
        "issues": [],
        "ok": True,
        "path": "knowledge/cards.jsonl",
    }
    assert output.err == ""


def test_validate_prints_stable_issues_when_overridden_cards_are_invalid(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: an overridden card file missing one required field.
    cards_path = tmp_path / "invalid.jsonl"
    card = valid_card()
    del card["summary"]
    write_card(cards_path, card)
    from bugbounty_brain.cli import main

    # When: validation runs against the invalid file.
    exit_code = main(["validate", "--cards-path", str(cards_path)])

    # Then: the report exposes only stable issue fields and returns its failure code.
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert exit_code == payload["exit_code"] == 1
    assert payload["issue_count"] == payload["error_count"] == 1
    assert payload["ok"] is False
    assert payload["issues"] == [
        {"code": "missing_required", "location": "line 1.summary"}
    ]
    assert output.err == ""


def test_compile_prints_summary_and_creates_searchable_default_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: one valid card at the default canonical path.
    cards_path = tmp_path / "knowledge" / "cards.jsonl"
    write_card(cards_path, valid_card())
    monkeypatch.chdir(tmp_path)
    from bugbounty_brain.cli import main

    # When: compilation runs with all default paths.
    exit_code = main(["compile"])

    # Then: stdout matches the manifest and the real SQLite FTS index is searchable.
    output = capsys.readouterr()
    database_path = tmp_path / "dist" / "reference_knowledge.db"
    manifest_path = tmp_path / "dist" / "brain-manifest.json"
    payload = json.loads(output.out)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    with sqlite3.connect(database_path) as connection:
        matches = connection.execute(
            "SELECT id FROM cards_fts WHERE cards_fts MATCH ?", ("title:Struts",)
        ).fetchall()
    assert exit_code == 0
    assert payload == manifest
    assert payload["database_filename"] == "reference_knowledge.db"
    assert matches == [(valid_card()["id"],)]
    assert output.err == ""


def test_compile_writes_json_stderr_when_card_validation_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: an invalid card and overridden output paths.
    cards_path = tmp_path / "invalid.jsonl"
    database_path = tmp_path / "brain.db"
    manifest_path = tmp_path / "manifest.json"
    card = valid_card()
    del card["summary"]
    write_card(cards_path, card)
    from bugbounty_brain.cli import main

    # When: compilation reaches its typed validation boundary.
    exit_code = main(
        [
            "compile",
            "--cards-path",
            str(cards_path),
            "--db-path",
            str(database_path),
            "--manifest-path",
            str(manifest_path),
        ]
    )

    # Then: a concise structured error is emitted without publishing artifacts.
    output = capsys.readouterr()
    assert exit_code == 1
    assert output.out == ""
    assert json.loads(output.err) == {
        "error": "compile_validation_failed",
        "issue_count": 1,
        "issues": [{"code": "missing_required", "location": "line 1.summary"}],
    }
    assert not database_path.exists()
    assert not manifest_path.exists()


def test_compile_writes_json_stderr_when_fts5_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: valid cards and a SQLite connection whose FTS5 module is unavailable.
    import bugbounty_brain.compiler as compiler_module
    from bugbounty_brain.cli import main

    cards_path = tmp_path / "cards.jsonl"
    database_path = tmp_path / "brain.db"
    manifest_path = tmp_path / "manifest.json"
    write_card(cards_path, valid_card())
    real_connect = sqlite3.connect

    class NoFtsConnection(sqlite3.Connection):
        def execute(self, sql: str, parameters: tuple[()] = (), /) -> sqlite3.Cursor:
            if sql.startswith("CREATE VIRTUAL TABLE"):
                raise sqlite3.OperationalError("no such module: fts5")
            return super().execute(sql, parameters)

    def connect_without_fts(database: str | Path) -> sqlite3.Connection:
        return real_connect(database, factory=NoFtsConnection)

    monkeypatch.setattr(compiler_module.sqlite3, "connect", connect_without_fts)

    # When: compilation tries to create the real FTS table.
    exit_code = main(
        [
            "compile",
            "--cards-path",
            str(cards_path),
            "--db-path",
            str(database_path),
            "--manifest-path",
            str(manifest_path),
        ]
    )

    # Then: the typed FTS failure becomes concise JSON on stderr.
    output = capsys.readouterr()
    error = json.loads(output.err)
    assert exit_code == 1
    assert output.out == ""
    assert error["error"] == "fts5_unavailable"
    assert "FTS5 is required" in error["message"]
    assert not database_path.exists()
    assert not manifest_path.exists()


@pytest.mark.parametrize(
    ("summary", "expected_exit", "override_paths"),
    [
        pytest.param(
            CollectionSummary(
                2,
                1,
                0,
                1,
                3,
                4,
                1,
                (SourceFailure("failed", "https://failed.test/feed", "http_500"),),
            ),
            0,
            False,
            id="partial-fetch",
        ),
        pytest.param(
            CollectionSummary(
                2,
                0,
                1,
                1,
                0,
                0,
                0,
                (SourceFailure("failed", "https://failed.test/feed", "fetch_error"),),
            ),
            0,
            False,
            id="not-modified",
        ),
        pytest.param(
            CollectionSummary(
                2,
                0,
                0,
                2,
                0,
                0,
                0,
                (
                    SourceFailure("one", "https://one.test/feed", "http_500"),
                    SourceFailure("two", "https://two.test/feed", "fetch_error"),
                ),
            ),
            1,
            True,
            id="all-failed",
        ),
        pytest.param(CollectionSummary(0, 0, 0, 0, 0, 0, 0, ()), 0, False, id="empty"),
        pytest.param(
            CollectionSummary(
                2,
                0,
                0,
                1,
                0,
                0,
                0,
                (SourceFailure("one", "https://one.test/feed", "fetch_error"),),
            ),
            0,
            False,
            id="not-all-failed",
        ),
    ],
)
def test_collect_prints_summary_and_uses_exact_failure_exit_semantics(
    summary: CollectionSummary,
    expected_exit: int,
    override_paths: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: a collector boundary returning one configured outcome and chosen paths.
    import bugbounty_brain.cli as cli_module

    observed: list[tuple[Path | str, Path | str, Path | str, Path | str]] = []

    def collect_boundary(
        sources_path: Path | str,
        raw_dir: Path | str,
        cards_path: Path | str,
        state_path: Path | str,
    ) -> CollectionSummary:
        observed.append((sources_path, raw_dir, cards_path, state_path))
        return summary

    monkeypatch.setattr(cli_module, "collect", collect_boundary, raising=False)
    if override_paths:
        paths = (
            tmp_path / "feeds.json",
            tmp_path / "snapshots",
            tmp_path / "cards.jsonl",
            tmp_path / "state.json",
        )
        argv = [
            "collect",
            "--sources-path",
            str(paths[0]),
            "--raw-dir",
            str(paths[1]),
            "--cards-path",
            str(paths[2]),
            "--state-path",
            str(paths[3]),
        ]
    else:
        paths = (
            Path("sources.json"),
            Path("raw"),
            Path("knowledge/cards.jsonl"),
            Path(".cache/collector-state.json"),
        )
        argv = ["collect"]

    # When: collection is orchestrated through the CLI.
    exit_code = cli_module.main(argv)

    # Then: paths, JSON fields, and failure-only exit behavior match the contract.
    output = capsys.readouterr()
    assert observed == [paths]
    assert exit_code == expected_exit
    assert json.loads(output.out) == {
        "cards_added": summary.cards_added,
        "cards_skipped_existing": summary.cards_skipped_existing,
        "failures": [
            {
                "reason": failure.reason,
                "source_name": failure.source_name,
                "source_url": failure.source_url,
            }
            for failure in summary.failures
        ],
        "raw_snapshots_added": summary.raw_snapshots_added,
        "sources_failed": summary.sources_failed,
        "sources_fetched": summary.sources_fetched,
        "sources_not_modified": summary.sources_not_modified,
        "sources_total": summary.sources_total,
    }
    assert output.err == ""


def test_all_stops_after_collection_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: a collection in which every configured source failed.
    import bugbounty_brain.cli as cli_module

    argv, _cards_path, database_path, manifest_path = pipeline_arguments(tmp_path)

    def failed_collection(
        _sources: Path | str,
        _raw: Path | str,
        _cards: Path | str,
        _state: Path | str,
    ) -> CollectionSummary:
        failure = SourceFailure("feed", "https://failed.test/feed", "fetch_error")
        return CollectionSummary(1, 0, 0, 1, 0, 0, 0, (failure,))

    monkeypatch.setattr(cli_module, "collect", failed_collection)

    # When: the complete pipeline is requested.
    exit_code = cli_module.main(argv)

    # Then: only collection emits JSON and later artifacts are untouched.
    output = capsys.readouterr()
    assert exit_code == 1
    assert len(output.out.splitlines()) == 1
    assert json.loads(output.out)["sources_failed"] == 1
    assert output.err == ""
    assert not database_path.exists()
    assert not manifest_path.exists()


def test_all_stops_after_invalid_validation_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: successful collection followed by an invalid canonical card.
    import bugbounty_brain.cli as cli_module

    argv, cards_path, database_path, manifest_path = pipeline_arguments(tmp_path)
    card = valid_card()
    del card["summary"]
    write_card(cards_path, card)
    monkeypatch.setattr(cli_module, "collect", not_modified_collection)

    # When: the complete pipeline is requested.
    exit_code = cli_module.main(argv)

    # Then: collection and validation emit JSON, while compilation never starts.
    output = capsys.readouterr()
    documents = [json.loads(line) for line in output.out.splitlines()]
    assert exit_code == 1
    assert len(documents) == 2
    assert documents[0]["sources_not_modified"] == 1
    assert documents[1]["issues"] == [
        {"code": "missing_required", "location": "line 1.summary"}
    ]
    assert output.err == ""
    assert not database_path.exists()
    assert not manifest_path.exists()


def test_all_runs_real_validation_and_compilation_after_collection_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: successful collection and one valid canonical card.
    import bugbounty_brain.cli as cli_module

    argv, cards_path, database_path, manifest_path = pipeline_arguments(tmp_path)
    write_card(cards_path, valid_card())
    monkeypatch.setattr(cli_module, "collect", not_modified_collection)

    # When: the complete pipeline is requested with every path overridden.
    exit_code = cli_module.main(argv)

    # Then: all three stages emit JSON and the compiled FTS artifact is searchable.
    output = capsys.readouterr()
    documents = [json.loads(line) for line in output.out.splitlines()]
    with sqlite3.connect(database_path) as connection:
        matches = connection.execute(
            "SELECT id FROM cards_fts WHERE cards_fts MATCH ?", ("summary:remediation",)
        ).fetchall()
    assert exit_code == 0
    assert len(documents) == 3
    assert documents[0]["sources_not_modified"] == 1
    assert documents[1]["exit_code"] == 0
    assert documents[2] == json.loads(manifest_path.read_text(encoding="utf-8"))
    assert matches == [(valid_card()["id"],)]
    assert output.err == ""
