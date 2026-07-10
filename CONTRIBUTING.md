# Contributing

Contributions must preserve the repository's public, secret-free, provenance-
aware boundary. A passing validator is necessary, but every source and card also
requires human review.

## Sources

Propose only allowlisted sources that are publicly accessible over HTTP(S)
without authentication. Prefer stable feeds from identifiable publishers with
clear ownership and attribution. Document why the source is useful, who
publishes it, and any license or reuse terms relevant to concise summaries.

Do not add private feeds, arbitrary URLs discovered in feed content, target
systems, engagement data, or sources that require cookies, credentials, API
keys, or tokens. Redirects or ownership changes must be reviewed as new trust
decisions.

## Knowledge cards

`knowledge/cards.jsonl` is canonical. Each card must be a concise, sanitized
summary of public material and must include the required provenance: stable card
ID, source name and URL, publication and fetch timestamps, and normalized-content
SHA-256, along with the bounded applicability and safety fields required by the
schema.

Keep attribution intact and verify that a summary accurately represents the
linked publisher. Do not copy more source text than its license permits. Never
include ScannerDB, `~/.hermes/knowledge.db`, target lists, per-target findings,
payload captures containing private data, cookies, session data, credentials,
or tokens. Examples must be unmistakably synthetic and sanitized.

Raw snapshots, `.cache/collector-state.json`, and `dist/` are not reviewable
source and must not be committed. Do not hand-edit or commit the generated
SQLite database.

## Development checks

Use Python 3.11 or newer and install the development dependencies:

```bash
python -m pip install -e '.[dev]'
```

Before opening a pull request, run the same gates as CI:

```bash
pytest
ruff check .
ruff format --check .
mypy src
python -m build
```

Run `bugbounty-brain validate` after any card change. If you compile locally,
keep `dist/reference_knowledge.db` and `dist/brain-manifest.json` uncommitted.

## Pull requests and review

Keep a pull request focused and explain changes to source trust, provenance, or
schema-relevant content. Reviewers must inspect the complete JSONL diff, follow
each new source URL, confirm attribution and licensing, compare the summary with
the public source, and check that no engagement or secret material crossed the
privacy boundary.

Automation-generated card pull requests receive the same review as handwritten
changes. Workflows never auto-merge collected claims. A maintainer's approval is
required before canonical cards become release input.

Report suspected poisoning or accidental sensitive-data exposure privately as
described in [SECURITY.md](SECURITY.md), not in a public issue or pull request.
