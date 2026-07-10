# Security policy

## Supported version

Security fixes are applied to the current default branch and, when necessary,
to newly rebuilt release artifacts. Older generated databases should be treated
as immutable snapshots, not supported software versions.

## Report privately

Do not open a public issue for a vulnerability, knowledge-poisoning incident, or
secret exposure. Use this repository's **Security** tab and select **Report a
vulnerability** to open a private GitHub security advisory. If private
vulnerability reporting is unavailable, use a verified private contact method
from the maintainer's GitHub profile and disclose no details publicly while a
private channel is established.

Include only the minimum information needed to reproduce and assess the issue:

- the affected command, workflow, card ID, source URL, commit, or release;
- expected and observed behavior;
- safe reproduction steps and impact; and
- whether the issue is currently exploitable or still publishing bad data.

Do not paste live credentials, cookies, tokens, private targets, or engagement
data into the report. Refer to their location and type instead.

## Knowledge poisoning

Treat feed content and generated cards as untrusted. Privately report sources or
cards that contain manipulated provenance, instruction-like content, misleading
security claims, unexpected redirects, or attempts to introduce secrets.

Maintainers will assess the source and affected history, quarantine or remove it
from collection, close or correct pending automation changes, and rebuild
affected artifacts from reviewed canonical JSONL. If a published artifact is no
longer trustworthy, maintainers will identify the affected release and provide
a replacement or withdrawal notice. Reports involving an upstream compromise
may also be coordinated with the source publisher.

## Secret or private-data exposure

This public repository must never contain ScannerDB,
`~/.hermes/knowledge.db`, targets, findings, cookies, session material,
credentials, API keys, or tokens. If any such data appears:

1. Revoke or rotate the exposed secret immediately if you control it. Deletion
   from Git or a release does not make a published secret safe again.
2. Report the path, card ID, commit, workflow run, or release privately without
   repeating the sensitive value.
3. Preserve only nonsensitive evidence needed to determine scope.

Maintainers will stop further publication, remove affected pending and release
artifacts where practical, identify the exposure window, and coordinate any
necessary history cleanup. Canonical cards will be revalidated before artifacts
are rebuilt.

Public reports are appropriate for ordinary bugs that do not expose a security
weakness or sensitive data. Questions about adding or reviewing sources belong
in a normal pull request only when all discussed material is already public.
