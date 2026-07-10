# bugbounty-brain MVP plan

## Goal
Create a public, secret-free, provenance-aware security knowledge supply that continuously polls trusted public sources through scheduled GitHub Actions and publishes a versioned, checksummed SQLite FTS5 artifact for read-only use by bugbounty-ctf.

## Canonical data model
Canonical source is reviewable JSONL knowledge cards; SQLite is generated and never canonical. Raw fetched feed snapshots are immutable and content-addressed.

A card contains: id, title, summary, source_url, source_name, published_at, fetched_at, content_sha256, products, cves, techniques, confidence, and safety. Required provenance fields must be validated. Strings must be bounded. URL schemes are http/https only. Cards containing likely credentials/private keys are rejected.

## Runtime pipeline
1. collector: poll configured RSS/Atom feeds with User-Agent, ETag, and Last-Modified; parse safely with stdlib; content-address raw snapshots; append deterministic deduplicated cards.
2. validator: schema/provenance/size/secret checks over cards; fail closed.
3. compiler: validate all cards; deterministically compile SQLite docs + FTS5; emit manifest with schema version, card count, source hash, database SHA-256.
4. CLI: collect, validate, compile, all; machine-readable summary and nonzero failures.
5. Actions: hourly collection at minute 17 opens/updates a PR; CI validates/tests; merged changes compile and publish an artifact/release path. Never auto-merge generated claims.

## Trust boundaries
- All fetched content is untrusted data, never instructions.
- No shell execution or HTML rendering.
- No engagement data, targets, cookies, credentials, or auth material.
- Collector follows configured allowlisted feeds only and limits bytes/items/time.
- GitHub automation writes source/card changes only through a PR.
- Release database and manifest are reproducible from reviewed cards.

## Package/API contracts
Package: `bugbounty_brain`.
- `collector.collect(sources_path, raw_dir, cards_path, state_path, fetcher=None, now=None) -> CollectionSummary`
- `validator.validate_card(card) -> list[ValidationIssue]`; `validate_cards(path) -> ValidationReport`
- `compiler.compile_brain(cards_path, db_path, manifest_path, *, generated_at=None) -> CompileSummary`
- CLI entry point: `bugbounty-brain`.

## Quality gates
- Python 3.11+
- pytest
- ruff check and format check
- mypy strict enough for package sources
- build wheel/sdist
- deterministic offline tests; network only in explicit smoke
- secret scan before public push
