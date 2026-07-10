from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Final, TypeAlias
from urllib.parse import urlsplit

JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    location: str


@dataclass(frozen=True, slots=True)
class ValidationReport:
    path: str
    card_count: int
    issues: tuple[ValidationIssue, ...]

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def error_count(self) -> int:
        return self.issue_count

    @property
    def ok(self) -> bool:
        return self.error_count == 0

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1


STRING_LIMITS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "id": 128,
        "title": 140,
        "summary": 1_000,
        "source_url": 2_048,
        "source_name": 120,
        "published_at": 40,
        "fetched_at": 40,
        "content_sha256": 64,
    }
)
LIST_LIMITS: Final[Mapping[str, int]] = MappingProxyType(
    {"products": 20, "cves": 50, "techniques": 30}
)
CONFIDENCE_VALUES: Final = frozenset({"low", "medium", "high"})
SAFETY_VALUES: Final = frozenset({"public", "sanitized"})
REQUIRED_FIELDS: Final = (*STRING_LIMITS, *LIST_LIMITS, "confidence", "safety")
ID_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]{2,83}-[0-9a-f]{12}$")
SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
CVE_RE: Final = re.compile(r"^CVE-\d{4}-\d{4,}$")
PRIVATE_KEY_RE: Final = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*(?P<body>.*?)"
    r"-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
BEARER_RE: Final = re.compile(r"\bbearer\s+([A-Za-z0-9._~+/=-]{8,})", re.I)
COOKIE_RE: Final = re.compile(r"\b(?:cookie|set-cookie)\s*:\s*([^;\n]+)", re.I)
ASSIGNMENT_RE: Final = re.compile(
    r"\b(?:password|passwd|pwd|api[_-]?key|secret|access[_-]?token|"
    r"refresh[_-]?token|session[_-]?id)\b\s*[:=]\s*['\"]?([^\s'\";,]+)",
    re.I,
)
PLACEHOLDER_RE: Final = re.compile(
    r"^(?:token|your_token|api_key|db_password|password|secret|changeme|dummy|"
    r"placeholder)$"
)


def validate_card(card: Mapping[str, JsonValue]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for field in REQUIRED_FIELDS:
        if field not in card:
            issues.append(_issue("missing_required", f"$.{field}"))

    for field in STRING_LIMITS:
        if field in card:
            issues.extend(_validate_string(card, field))

    if isinstance(card_id := card.get("id"), str) and not ID_RE.fullmatch(card_id):
        issues.append(_issue("invalid_id", "$.id"))
    if isinstance(source_url := card.get("source_url"), str):
        issues.extend(_validate_url(source_url))
    for field in ("published_at", "fetched_at"):
        if isinstance(timestamp := card.get(field), str):
            issues.extend(_validate_timestamp(timestamp, field))
    if isinstance(sha := card.get("content_sha256"), str) and not SHA256_RE.fullmatch(
        sha
    ):
        issues.append(_issue("invalid_sha256", "$.content_sha256"))

    for field in LIST_LIMITS:
        if field in card:
            issues.extend(_validate_string_list(card, field))

    for field, allowed in (
        ("confidence", CONFIDENCE_VALUES),
        ("safety", SAFETY_VALUES),
    ):
        if field in card:
            issues.extend(_validate_enum(card, field, allowed))

    for location, text in _walk_text(card, "$"):
        issues.extend(_secret_issues(location, text))

    return issues


def validate_cards(path: str | Path) -> ValidationReport:
    card_path = Path(path)
    issues: list[ValidationIssue] = []
    card_count = 0
    seen: dict[str, tuple[int, str]] = {}

    with card_path.open(encoding="utf-8") as lines:
        for line_no, line in enumerate(lines, start=1):
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError:
                issues.append(_issue("malformed_jsonl", f"line {line_no}"))
                continue

            if not isinstance(decoded, dict):
                issues.append(_issue("card_type", f"line {line_no}"))
                continue

            card_count += 1
            card_issues = validate_card(decoded)
            issues.extend(_line_issue(line_no, issue) for issue in card_issues)
            card_id = decoded.get("id")
            if isinstance(card_id, str):
                fingerprint = _fingerprint(decoded)
                previous = seen.get(card_id)
                if previous is None:
                    seen[card_id] = (line_no, fingerprint)
                else:
                    id_location = f"line {line_no}.id"
                    issues.append(_issue("duplicate_id", id_location))
                    if previous[1] != fingerprint:
                        issues.append(_issue("conflicting_id_content", id_location))

    return ValidationReport(
        path=str(card_path), card_count=card_count, issues=tuple(issues)
    )


def _issue(code: str, location: str) -> ValidationIssue:
    return ValidationIssue(code=code, location=location)


def _validate_string(
    card: Mapping[str, JsonValue],
    field: str,
) -> list[ValidationIssue]:
    value = card[field]
    location = f"$.{field}"
    if not isinstance(value, str):
        return [_issue("invalid_type", location)]
    if value == "":
        return [_issue("string_empty", location)]
    if len(value) > STRING_LIMITS[field]:
        return [_issue("string_too_long", location)]
    return []


def _validate_url(value: str) -> list[ValidationIssue]:
    parsed = urlsplit(value)
    issues: list[ValidationIssue] = []
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        issues.append(_issue("invalid_url_scheme", "$.source_url"))
    if parsed.username is not None or parsed.password is not None:
        issues.append(_issue("url_credentials", "$.source_url"))
    return issues


def _validate_timestamp(value: str, field: str) -> list[ValidationIssue]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return [_issue("invalid_timestamp", f"$.{field}")]
    timestamp_is_valid = "T" in value and parsed.tzinfo is not None
    return [] if timestamp_is_valid else [_issue("invalid_timestamp", f"$.{field}")]


def _validate_string_list(
    card: Mapping[str, JsonValue],
    field: str,
) -> list[ValidationIssue]:
    value = card[field]
    location = f"$.{field}"
    if not isinstance(value, list):
        return [_issue("invalid_type", location)]

    issues: list[ValidationIssue] = []
    if len(value) > LIST_LIMITS[field]:
        issues.append(_issue("list_too_long", location))
    for index, item in enumerate(value):
        item_location = f"{location}[{index}]"
        if not isinstance(item, str):
            issues.append(_issue("invalid_type", item_location))
            continue
        if not _clean_string(item):
            issues.append(_issue("unclean_string", item_location))
        elif field == "cves" and not CVE_RE.fullmatch(item):
            issues.append(_issue("invalid_cve", item_location))
    return issues


def _validate_enum(
    card: Mapping[str, JsonValue],
    field: str,
    allowed: frozenset[str],
) -> list[ValidationIssue]:
    value = card[field]
    location = f"$.{field}"
    if not isinstance(value, str):
        return [_issue("invalid_type", location)]
    if value not in allowed:
        return [_issue("invalid_enum", location)]
    return []


def _clean_string(value: str) -> bool:
    return value == value.strip() != "" and not any(ord(char) < 32 for char in value)


def _walk_text(
    value: JsonValue | Mapping[str, JsonValue], location: str
) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield location, value
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_text(item, f"{location}[{index}]")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk_text(item, f"{location}.{key}")


def _secret_issues(location: str, text: str) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for match in PRIVATE_KEY_RE.finditer(text):
        body = re.sub(r"\s+", "", match.group("body"))
        if len(body) >= 40 and not _placeholder(body):
            issues.append(_issue("secret.private_key", location))
    for match in BEARER_RE.finditer(text):
        if _secret_value(match.group(1)):
            issues.append(_issue("secret.bearer_token", location))
    for match in COOKIE_RE.finditer(text):
        cookie_value = match.group(1).split("=", maxsplit=1)[-1]
        if _secret_value(cookie_value):
            issues.append(_issue("secret.cookie", location))
    for match in ASSIGNMENT_RE.finditer(text):
        if _secret_value(match.group(1)):
            issues.append(_issue("secret.assignment", location))
    return issues


def _placeholder(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    lowered = stripped.lower()
    compact = re.sub(r"[^a-z0-9]+", "_", stripped).strip("_").lower()
    if "redacted" in lowered or "example.com" in lowered:
        return True
    return bool(PLACEHOLDER_RE.fullmatch(compact)) or bool(
        re.fullmatch(r"\$?\{?[A-Z][A-Z0-9_]{2,}\}?", stripped)
    )


def _secret_value(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    if _placeholder(stripped) or len(stripped) < 12:
        return False
    return any(char.isalpha() for char in stripped) and any(
        char.isdigit() for char in stripped
    )


def _line_issue(line_no: int, issue: ValidationIssue) -> ValidationIssue:
    suffix = "" if issue.location == "$" else issue.location[1:]
    return _issue(issue.code, f"line {line_no}{suffix}")


def _fingerprint(card: Mapping[str, JsonValue]) -> str:
    body = json.dumps(card, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return sha256(body.encode()).hexdigest()
