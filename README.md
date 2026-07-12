# bugbounty-brain

`bugbounty-brain` is a public, secret-free supply of provenance-aware security
knowledge. It collects bounded summaries from an explicit allowlist of public
feeds, keeps those summaries reviewable as JSON Lines, and compiles reviewed
cards into a versioned SQLite FTS5 database for read-only consumers.

The repository is a knowledge supply, not a target or engagement database.

## Architecture

The pipeline has five stages:

1. `collect` polls the feeds in `sources.json` with conditional HTTP requests,
   stores content-addressed raw snapshots locally, and appends deterministic,
   deduplicated knowledge cards.
2. `enrich` derives `cves`, `products`, and `techniques` for every card from its
   own title and summary using only deterministic rules (a CVE pattern, curated
   keyword dictionaries, and CTFtime topic parsing). It is idempotent, never
   mutates source-derived text, and preserves any human-curated taxonomy.
3. `validate` checks the card schema, provenance, bounds, URL schemes, the
   optional enrichment block, and likely secret material. Validation fails closed.
4. Human review decides whether generated card changes may merge.
5. `compile` validates again and builds a deterministic SQLite database with an
   FTS5 search index and a manifest describing the artifact.

`knowledge/cards.jsonl` is the canonical data source. It is line-oriented so
provenance-bearing changes can be reviewed in a pull request. The SQLite file is
generated output: it is never canonical and must not be edited or committed.
Likewise, `raw/`, collector state under `.cache/`, and `dist/` are operational or
generated data, not repository source.

The default repository paths are:

| Purpose | Path |
| --- | --- |
| Public source allowlist | `sources.json` |
| Local raw feed snapshots | `raw/` |
| Canonical knowledge cards | `knowledge/cards.jsonl` |
| Conditional-request state | `.cache/collector-state.json` |
| Generated search database | `dist/reference_knowledge.db` |
| Release manifest | `dist/brain-manifest.json` |

## Trust and provenance

Feed responses and every field derived from them are untrusted data, never
instructions. The collector follows only configured HTTP(S) sources and bounds
request time, response bytes, and item counts. It does not execute feed content
or render feed HTML. Validation rejects malformed provenance, unsafe URL shapes,
oversized fields, and likely credentials or private keys.

Every card carries its source name and URL, publication and fetch times, and a
SHA-256 digest of its normalized source-derived fields. Those fields establish
traceability; they do not make a source claim trustworthy. Reviewers must follow
the source,
compare the summary with the publisher's claim, and consider whether the source
or feed may have been compromised before merging.

GitHub automation may commit only `knowledge/cards.jsonl`, and only to the stable
automation branch used for a pull request. It never auto-merges collected
claims. The reviewed JSONL remains the boundary between network input and a
published database.

## Commands

Install Python 3.11 or newer, then install the project:

```bash
python -m pip install -e '.[dev]'
```

Run commands from the repository root to use their default paths:

```bash
# Poll sources.json; write raw/, knowledge/cards.jsonl, and collector state.
bugbounty-brain collect

# Deterministically derive cves/products/techniques in knowledge/cards.jsonl.
bugbounty-brain enrich

# Validate knowledge/cards.jsonl.
bugbounty-brain validate

# Build dist/reference_knowledge.db and dist/brain-manifest.json.
bugbounty-brain compile

# Collect, enrich, validate, then compile; stop at the first failed stage.
bugbounty-brain all
```

Each command emits a machine-readable JSON summary and returns nonzero on its
defined failure conditions. Use `bugbounty-brain COMMAND --help` for path
overrides. Collection performs network requests; validation and compilation are
local operations.

For local quality checks, run:

```bash
pytest
ruff check .
ruff format --check .
mypy src
python -m build
```

## Automation and review

CI runs the test, lint, format, type-check, and package-build gates on every push
and pull request. The collection workflow runs hourly at minute 17 and can also
be dispatched manually. Only one collection run executes at a time. It restores
collector state from the Actions cache, collects and validates cards, commits
only the canonical JSONL to `automation/knowledge-collection`, and creates or
updates a pull request with `gh`. Raw snapshots, state, and `dist/` are never
committed.

Collection pull requests require review before merge. Review source
allowlisting, attribution, accuracy, sanitization, and the complete card diff;
successful automation is not approval of an external claim.

On `v*` tags, the release workflow validates and compiles the reviewed cards,
checks the database bytes against the manifest's `database_sha256`, uploads both
artifacts, and publishes them on the matching GitHub Release. A manual dispatch
builds and uploads workflow artifacts without creating a GitHub Release.

## Consuming a release

Download `reference_knowledge.db` and `brain-manifest.json` from the same release.
Before opening the database, check the manifest's `compatibility` and
`schema_version`, require `database_filename` to be `reference_knowledge.db`, and
verify its SHA-256. For example:

```bash
python - <<'PY'
from hashlib import sha256
import json
from pathlib import Path

database = Path("reference_knowledge.db")
manifest = json.loads(Path("brain-manifest.json").read_text(encoding="utf-8"))
assert manifest["database_filename"] == database.name
assert manifest["database_sha256"] == sha256(database.read_bytes()).hexdigest()
print("verified", manifest["compatibility"], "schema", manifest["schema_version"])
PY
```

Treat a mismatch as a failed or mixed-version download. Consumers should replace
the database only after verification and should open it read-only.

## Privacy boundary

Never add, ingest, cache, or publish ScannerDB, `~/.hermes/knowledge.db`,
targets, target lists, per-target findings, cookies, session data, credentials,
API keys, or tokens. Do not add authenticated or private feeds. This ban applies to cards,
fixtures, logs, issues, pull requests, workflow artifacts, and release assets.
See [SECURITY.md](SECURITY.md) for private reporting of accidental exposure.

## Attribution and licensing

Cards retain `source_name` and `source_url` so readers can identify the original
publisher. Source publishers retain their rights in the underlying articles,
advisories, and feeds. A public URL is not permission to copy unrestricted text:
cards must be concise, sanitized summaries and contributors must follow each
source's attribution and license terms.

The repository's original code and documentation are available under the MIT
License in [LICENSE](LICENSE). That license does not relicense third-party source
material or the claims attributed to source publishers.
