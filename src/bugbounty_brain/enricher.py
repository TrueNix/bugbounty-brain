from __future__ import annotations

# allow: SIZE_OK - deterministic enrichment rules are kept in one auditable file.
import datetime as dt
import html
import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeAlias, assert_never, cast

from bugbounty_brain.validator import CVE_RE, LIST_LIMITS

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)

ENRICHMENT_VERSION: Final = 1

_CVE_RE: Final = re.compile(r"(?<![\w-])CVE-(\d{4})-(\d{4,})(?![\w-])", re.IGNORECASE)
_TAG_RE: Final = re.compile(r"<[^>]+>")
_TOPICS_RE: Final = re.compile(
    r"topics:\s*(?P<topics>.*?)(?:\s+rating:|\Z)",
    re.IGNORECASE,
)

# Each technique slug maps to the phrases that, if found as whole words in a
# card's title or plain-text summary, mark the card with that technique. Phrases
# are matched case-insensitively with hyphen-aware word boundaries so "sqli"
# never matches inside "sqlite" and "saml" is found in "ruby-saml".
_TECHNIQUE_PHRASES: Final[Mapping[str, tuple[str, ...]]] = {
    "clickjacking": ("clickjacking",),
    "cookie-parsing": ("cookie", "cookie prefix", "httponly"),
    "cors-misconfiguration": ("cors", "cross-origin resource sharing"),
    "css-injection": ("css injection", "style injection", "css exfiltration"),
    "csrf": ("csrf", "cross-site request forgery"),
    "dns-rebinding": ("dns rebinding",),
    "http-request-smuggling": (
        "request smuggling",
        "request tunnelling",
        "request tunneling",
        "http desync",
        "desync",
    ),
    "idor": ("idor", "insecure direct object reference"),
    "insecure-deserialization": ("deserialization", "deserialisation"),
    "jwt": ("jwt", "json web token"),
    "oauth": ("oauth",),
    "open-redirect": ("open redirect", "open redirection"),
    "parser-differential": (
        "parser discrepanc",
        "parser-level",
        "parser differential",
        "namespace confusion",
        "attribute pollution",
    ),
    "path-traversal": (
        "path traversal",
        "directory traversal",
        "local file inclusion",
        "lfi",
    ),
    "prototype-pollution": ("prototype pollution",),
    "race-condition": ("race condition", "toctou"),
    "remote-code-execution": ("remote code execution", "rce"),
    "saml": ("saml",),
    "sql-injection": ("sql injection", "sqli"),
    "ssrf": ("ssrf", "server-side request forgery"),
    "template-injection": ("template injection", "ssti"),
    "timing-attack": ("timing attack", "web timing"),
    "unicode-normalization": (
        "unicode overflow",
        "unicode",
        "codepoint truncation",
    ),
    "url-validation-bypass": ("url validation bypass", "url parser"),
    "waf-bypass": ("waf bypass", "bypass waf", "bypassing wafs", "blocklist"),
    "web-cache-poisoning": ("cache poisoning", "web cache", "cache deception"),
    "websocket": ("websocket",),
    "xss": ("xss", "cross-site scripting", "cross site scripting"),
}

# Products and tooling. Kept deliberately conservative: only high-signal names
# that are unlikely to collide with ordinary prose in security writeups.
_PRODUCT_PHRASES: Final[Mapping[str, tuple[str, ...]]] = {
    "burp-suite": ("burp suite", "burp intruder", "turbo intruder", "burp"),
    "gitlab": ("gitlab",),
    "nuclei": ("nuclei",),
    "php": ("php",),
    "ruby": ("ruby",),
    "ruby-saml": ("ruby-saml",),
    "vs-code": ("vs code", "visual studio code"),
}

# CTFtime writeup feeds expose a "Topics:" list. Map the recognised topics to
# stable category slugs and drop everything else (event names, "ctf", "writeup",
# team names) so the taxonomy stays high-precision.
_CTF_TOPIC_CANON: Final[Mapping[str, str]] = {
    "android": "mobile",
    "binary": "binary-exploitation",
    "binary-exploitation": "binary-exploitation",
    "binaryexploitation": "binary-exploitation",
    "blockchain": "blockchain",
    "crypto": "cryptography",
    "cryptography": "cryptography",
    "forensics": "forensics",
    "game": "misc",
    "hardware": "hardware",
    "misc": "misc",
    "mobile": "mobile",
    "network": "networking",
    "networking": "networking",
    "osint": "osint",
    "pwn": "binary-exploitation",
    "rev": "reverse-engineering",
    "reverse": "reverse-engineering",
    "reverseengineering": "reverse-engineering",
    "reversing": "reverse-engineering",
    "stegano": "steganography",
    "steganography": "steganography",
    "stego": "steganography",
    "tpm2": "hardware",
    "web": "web",
}


def _compile(phrase: str) -> re.Pattern[str]:
    body = r"\s+".join(re.escape(part) for part in phrase.split())
    return re.compile(rf"(?<![\w-]){body}(?![\w-])", re.IGNORECASE)


_TECHNIQUE_MATCHERS: Final[Mapping[str, tuple[re.Pattern[str], ...]]] = {
    slug: tuple(_compile(phrase) for phrase in phrases)
    for slug, phrases in _TECHNIQUE_PHRASES.items()
}
_PRODUCT_MATCHERS: Final[Mapping[str, tuple[re.Pattern[str], ...]]] = {
    slug: tuple(_compile(phrase) for phrase in phrases)
    for slug, phrases in _PRODUCT_PHRASES.items()
}


@dataclass(frozen=True, slots=True)
class EnrichSummary:
    cards_total: int
    cards_changed: int
    cards_unchanged: int
    enrichment_version: int
    cves_total: int
    products_total: int
    techniques_total: int


@dataclass(frozen=True, slots=True)
class EnrichmentError(Exception):
    reason: str
    location: str

    def __str__(self) -> str:
        return f"{self.reason} at {self.location}"


@dataclass(frozen=True, slots=True)
class _Derived:
    cves: frozenset[str]
    products: frozenset[str]
    techniques: frozenset[str]


@dataclass(frozen=True, slots=True)
class _PriorEnrichment:
    version: int | None
    enriched_at: str | None
    cves: frozenset[str]
    products: frozenset[str]
    techniques: frozenset[str]


def enrich_cards(
    cards_path: Path | str,
    *,
    now: str | dt.datetime | None = None,
) -> EnrichSummary:
    """Deterministically populate cves/products/techniques for every card.

    The transformation is idempotent: re-running it over already-enriched cards
    produces byte-identical output and writes nothing. Enrichment only ever adds
    derived metadata; source-derived text (title, summary) is left untouched, so
    each card's provenance digest stays valid.
    """
    path = Path(cards_path)
    stamp = _now_text(now)
    original = path.read_text(encoding="utf-8") if path.exists() else ""

    lines: list[str] = []
    changed = 0
    cves_total = 0
    products_total = 0
    techniques_total = 0
    for line_no, raw in enumerate(original.splitlines(), start=1):
        if not raw.strip():
            raise EnrichmentError("blank_line", f"line {line_no}")
        card = _decode_card(raw, line_no)
        enriched, was_changed = _enrich_card(card, enriched_at=stamp)
        lines.append(_dump(enriched))
        changed += int(was_changed)
        cves_total += len(_as_str_list(enriched.get("cves")))
        products_total += len(_as_str_list(enriched.get("products")))
        techniques_total += len(_as_str_list(enriched.get("techniques")))

    output = "".join(f"{line}\n" for line in lines)
    if output != original:
        _write_text_atomic(path, output)

    return EnrichSummary(
        cards_total=len(lines),
        cards_changed=changed,
        cards_unchanged=len(lines) - changed,
        enrichment_version=ENRICHMENT_VERSION,
        cves_total=cves_total,
        products_total=products_total,
        techniques_total=techniques_total,
    )


def _enrich_card(
    card: Mapping[str, JsonValue],
    *,
    enriched_at: str,
) -> tuple[dict[str, JsonValue], bool]:
    derived = _derive(card)
    prior = _prior_enrichment(card)

    top_cves = _as_str_set(card.get("cves"))
    top_products = _as_str_set(card.get("products"))
    top_techniques = _as_str_set(card.get("techniques"))

    # Everything an earlier enrichment contributed is replaceable; anything else
    # in the field was curated by a human and must survive re-enrichment.
    human_cves = top_cves - prior.cves
    human_products = top_products - prior.products
    human_techniques = top_techniques - prior.techniques

    new_cves = _bounded(human_cves | derived.cves, LIST_LIMITS["cves"])
    new_products = _bounded(human_products | derived.products, LIST_LIMITS["products"])
    new_techniques = _bounded(
        human_techniques | derived.techniques,
        LIST_LIMITS["techniques"],
    )

    content_same = (
        prior.version == ENRICHMENT_VERSION
        and prior.enriched_at is not None
        and prior.cves == derived.cves
        and prior.products == derived.products
        and prior.techniques == derived.techniques
        and set(new_cves) == top_cves
        and set(new_products) == top_products
        and set(new_techniques) == top_techniques
    )
    stamp = prior.enriched_at if content_same and prior.enriched_at else enriched_at

    enrichment: dict[str, JsonValue] = {
        "version": ENRICHMENT_VERSION,
        "enriched_at": stamp,
        "cves": _bounded(derived.cves, LIST_LIMITS["cves"]),
        "products": _bounded(derived.products, LIST_LIMITS["products"]),
        "techniques": _bounded(derived.techniques, LIST_LIMITS["techniques"]),
    }

    result: dict[str, JsonValue] = dict(card)
    result["cves"] = new_cves
    result["products"] = new_products
    result["techniques"] = new_techniques
    result["enrichment"] = enrichment
    return result, not content_same


def _derive(card: Mapping[str, JsonValue]) -> _Derived:
    title = _text(card, "title")
    summary = _plain_text(_text(card, "summary"))
    haystack = f"{title}\n{summary}"
    techniques = _match(haystack, _TECHNIQUE_MATCHERS) | _ctf_topics(summary)
    return _Derived(
        cves=frozenset(_valid_cves(haystack)),
        products=frozenset(_match(haystack, _PRODUCT_MATCHERS)),
        techniques=frozenset(techniques),
    )


def _valid_cves(text: str) -> set[str]:
    found: set[str] = set()
    for year, number in _CVE_RE.findall(text):
        candidate = f"CVE-{year}-{number}"
        if CVE_RE.fullmatch(candidate):
            found.add(candidate)
    return found


def _match(
    haystack: str,
    matchers: Mapping[str, tuple[re.Pattern[str], ...]],
) -> set[str]:
    return {
        slug
        for slug, patterns in matchers.items()
        if any(pattern.search(haystack) for pattern in patterns)
    }


def _ctf_topics(summary: str) -> set[str]:
    match = _TOPICS_RE.search(summary)
    if match is None:
        return set()
    tokens = re.split(r"[,\s]+", match.group("topics").lower())
    return {_CTF_TOPIC_CANON[token] for token in tokens if token in _CTF_TOPIC_CANON}


def _plain_text(value: str) -> str:
    return " ".join(_TAG_RE.sub(" ", html.unescape(value)).split())


def _prior_enrichment(card: Mapping[str, JsonValue]) -> _PriorEnrichment:
    raw = card.get("enrichment")
    if not isinstance(raw, Mapping):
        return _PriorEnrichment(None, None, frozenset(), frozenset(), frozenset())
    return _PriorEnrichment(
        version=_int_or_none(raw.get("version")),
        enriched_at=_str_or_none(raw.get("enriched_at")),
        cves=frozenset(_as_str_set(raw.get("cves"))),
        products=frozenset(_as_str_set(raw.get("products"))),
        techniques=frozenset(_as_str_set(raw.get("techniques"))),
    )


def _decode_card(raw: str, line_no: int) -> dict[str, JsonValue]:
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EnrichmentError("malformed_jsonl", f"line {line_no}") from error
    if not isinstance(decoded, dict):
        raise EnrichmentError("card_type", f"line {line_no}")
    return decoded


def _text(card: Mapping[str, JsonValue], field: str) -> str:
    value = card.get(field)
    return value if isinstance(value, str) else ""


def _int_or_none(value: JsonValue) -> int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _str_or_none(value: JsonValue) -> str | None:
    return value if isinstance(value, str) else None


def _as_str_list(value: JsonValue) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _as_str_set(value: JsonValue) -> set[str]:
    return set(_as_str_list(value))


def _bounded(values: Iterable[str], limit: int) -> list[JsonValue]:
    return cast("list[JsonValue]", sorted(set(values))[:limit])


def _dump(card: Mapping[str, JsonValue]) -> str:
    return json.dumps(card, sort_keys=True, separators=(",", ":"))


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
