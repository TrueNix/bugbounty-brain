from __future__ import annotations

# allow: SIZE_OK - collector slice is constrained by the user to this file.
import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import os
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Final, Mapping, Protocol, TypeAlias, TypedDict, assert_never
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES: Final = 1_048_576
MAX_ENTRIES_PER_SOURCE: Final = 50
DEFAULT_TIMEOUT_SECONDS: Final = 15.0
USER_AGENT: Final = "bugbounty-brain-collector/0.1"
LOCAL_HOST_SUFFIXES: Final = frozenset(
    {"home", "home.arpa", "internal", "lan", "local", "localdomain", "localhost"},
)

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


@dataclass(frozen=True, slots=True)
class FetchRequest:
    url: str
    headers: Mapping[str, str]
    timeout_seconds: float
    max_bytes: int


@dataclass(frozen=True, slots=True)
class FetchResponse:
    status_code: int
    headers: Mapping[str, str]
    content: bytes


class Fetcher(Protocol):
    def __call__(self, request: FetchRequest) -> FetchResponse: ...


@dataclass(frozen=True, slots=True)
class SourceFailure:
    source_name: str
    source_url: str = field(repr=False)
    reason: str


@dataclass(frozen=True, slots=True)
class CollectionSummary:
    sources_total: int
    sources_fetched: int
    sources_not_modified: int
    sources_failed: int
    cards_added: int
    cards_skipped_existing: int
    raw_snapshots_added: int
    failures: tuple[SourceFailure, ...]


@dataclass(frozen=True, slots=True)
class Source:
    name: str
    url: str
    max_entries: int


@dataclass(frozen=True, slots=True)
class SourceState:
    etag: str | None
    last_modified: str | None
    raw_sha256: str | None
    last_fetched_at: str | None


@dataclass(frozen=True, slots=True)
class ExistingCards:
    ids: frozenset[str]
    text: str


@dataclass(frozen=True, slots=True)
class FeedEntry:
    entry_key: str
    title: str
    summary: str
    source_url: str
    published_at: str


@dataclass(frozen=True, slots=True)
class FetchError(Exception):
    url: str = field(repr=False)
    reason: str

    def __str__(self) -> str:
        return f"fetch failed: {self.reason}"


@dataclass(frozen=True, slots=True)
class RedirectTrustError(FetchError):
    def __str__(self) -> str:
        return f"response URL rejected: {self.reason}"


@dataclass(frozen=True, slots=True)
class SourceConfigError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class FeedParseError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


class CardRecord(TypedDict):
    id: str
    title: str
    summary: str
    source_url: str
    source_name: str
    published_at: str
    fetched_at: str
    content_sha256: str
    products: list[str]
    cves: list[str]
    techniques: list[str]
    confidence: str
    safety: str


def collect(
    sources_path: Path | str,
    raw_dir: Path | str,
    cards_path: Path | str,
    state_path: Path | str,
    fetcher: Fetcher | None = None,
    now: str | dt.datetime | None = None,
) -> CollectionSummary:
    sources = _load_sources(Path(sources_path))
    existing = _read_existing_cards(Path(cards_path))
    known_ids = set(existing.ids)
    state = _load_state(Path(state_path))
    active_fetcher = fetcher or UrlLibFetcher()
    fetched_at = _now_text(now)
    new_cards: list[CardRecord] = []
    failures: list[SourceFailure] = []
    fetched = 0
    not_modified = 0
    skipped_existing = 0
    raw_added = 0

    for source in sources:
        if not _valid_fetch_url(source.url):
            failures.append(_failure(source, "unsupported_url"))
            continue
        prior = state.get(source.url, SourceState(None, None, None, None))
        request = FetchRequest(
            source.url,
            _conditional_headers(prior),
            DEFAULT_TIMEOUT_SECONDS,
            MAX_RESPONSE_BYTES,
        )
        try:
            response = active_fetcher(request)
        except FetchError:
            failures.append(_failure(source, "fetch_error"))
            continue
        except OSError:
            failures.append(_failure(source, "fetch_error"))
            continue
        if response.status_code == 304:
            not_modified += 1
            continue
        if response.status_code < 200 or response.status_code > 299:
            failures.append(_failure(source, f"http_{response.status_code}"))
            continue
        if len(response.content) > MAX_RESPONSE_BYTES:
            failures.append(_failure(source, "response_too_large"))
            continue
        try:
            entries = _parse_feed(response.content, source)
        except ET.ParseError:
            failures.append(_failure(source, "malformed_xml"))
            continue
        except FeedParseError as exc:
            failures.append(_failure(source, exc.reason))
            continue
        raw_hash = hashlib.sha256(response.content).hexdigest()
        if _write_raw_snapshot(Path(raw_dir), raw_hash, response.content):
            raw_added += 1
        fetched += 1
        state[source.url] = _updated_state(response, raw_hash, fetched_at)
        for entry in entries:
            card = _card_for(source, entry, fetched_at)
            if card["id"] in known_ids:
                skipped_existing += 1
                continue
            known_ids.add(card["id"])
            new_cards.append(card)

    if new_cards:
        _write_cards(Path(cards_path), existing.text, new_cards)
    if fetched > 0:
        _write_text_atomic(Path(state_path), _state_text(state))
    return CollectionSummary(
        sources_total=len(sources),
        sources_fetched=fetched,
        sources_not_modified=not_modified,
        sources_failed=len(failures),
        cards_added=len(new_cards),
        cards_skipped_existing=skipped_existing,
        raw_snapshots_added=raw_added,
        failures=tuple(failures),
    )


class UrlLibFetcher:
    def __call__(self, request: FetchRequest) -> FetchResponse:
        headers = dict(request.headers)
        headers["User-Agent"] = USER_AGENT
        url_request = urllib.request.Request(request.url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(
                url_request,
                timeout=request.timeout_seconds,
            ) as response:
                _validate_effective_url(request.url, response.geturl())
                return FetchResponse(
                    response.getcode(),
                    dict(response.headers.items()),
                    response.read(request.max_bytes + 1),
                )
        except urllib.error.HTTPError as exc:
            with contextlib.closing(exc):
                _validate_effective_url(request.url, exc.geturl())
                if exc.code == 304:
                    return FetchResponse(304, dict(exc.headers.items()), b"")
                return FetchResponse(
                    exc.code,
                    dict(exc.headers.items()),
                    exc.read(request.max_bytes + 1),
                )
        except urllib.error.URLError as exc:
            raise FetchError(request.url, "network_error") from exc
        except TimeoutError as exc:
            raise FetchError(request.url, "timeout") from exc


def _validate_effective_url(request_url: str, effective_url: str) -> None:
    try:
        requested = urlsplit(request_url)
        effective = urlsplit(effective_url)
        requested_host = requested.hostname
        effective_host = effective.hostname
        requested_port = requested.port
        effective_port = effective.port
    except ValueError as exc:
        raise RedirectTrustError(request_url, "redirect_invalid_url") from exc
    if effective.scheme not in {"http", "https"}:
        raise RedirectTrustError(request_url, "redirect_scheme")
    if effective.username is not None or effective.password is not None:
        raise RedirectTrustError(request_url, "redirect_userinfo")
    if (
        requested_host is None
        or effective_host is None
        or requested_port == 0
        or effective_port == 0
    ):
        raise RedirectTrustError(request_url, "redirect_invalid_url")
    if requested_host.lower().rstrip(".") != effective_host.lower().rstrip("."):
        raise RedirectTrustError(request_url, "redirect_cross_host")
    if requested.scheme == "https" and effective.scheme != "https":
        raise RedirectTrustError(request_url, "redirect_downgrade")


def _load_sources(path: Path) -> list[Source]:
    data: JsonValue = json.loads(path.read_text(encoding="utf-8"))
    match data:
        case list() as items:
            return [_source_from_json(item) for item in items]
        case _:
            raise SourceConfigError("sources_json_not_list")


def _source_from_json(item: JsonValue) -> Source:
    match item:
        case dict() as raw:
            name = _required_text(raw.get("name"))
            url = _required_text(raw.get("url"))
            max_entries = _max_entries(raw.get("max_entries"))
            return Source(_bounded(name, 120), _bounded(url, 2048), max_entries)
        case _:
            raise SourceConfigError("invalid_source")


def _required_text(value: JsonValue) -> str:
    match value:
        case str() as text:
            return text
        case _:
            raise SourceConfigError("invalid_source")


def _max_entries(value: JsonValue) -> int:
    match value:
        case int() as count:
            return min(max(count, 1), MAX_ENTRIES_PER_SOURCE)
        case _:
            return MAX_ENTRIES_PER_SOURCE


def _load_state(path: Path) -> dict[str, SourceState]:
    if not path.exists():
        return {}
    data: JsonValue = json.loads(path.read_text(encoding="utf-8"))
    match data:
        case {"sources": dict() as raw_sources}:
            return {
                url: _state_from_json(raw)
                for url, raw in raw_sources.items()
                if isinstance(url, str) and isinstance(raw, dict)
            }
        case _:
            return {}


def _state_from_json(raw: dict[str, JsonValue]) -> SourceState:
    return SourceState(
        _optional_text(raw.get("etag")),
        _optional_text(raw.get("last_modified")),
        _optional_text(raw.get("raw_sha256")),
        _optional_text(raw.get("last_fetched_at")),
    )


def _state_text(state: dict[str, SourceState]) -> str:
    payload = {
        "sources": {
            url: {
                "etag": source_state.etag,
                "last_fetched_at": source_state.last_fetched_at,
                "last_modified": source_state.last_modified,
                "raw_sha256": source_state.raw_sha256,
            }
            for url, source_state in sorted(state.items())
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _read_existing_cards(path: Path) -> ExistingCards:
    if not path.exists():
        return ExistingCards(frozenset(), "")
    text = path.read_text(encoding="utf-8")
    ids: set[str] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        data: JsonValue = json.loads(line)
        match data:
            case {"id": str(card_id)}:
                ids.add(card_id)
            case _:
                continue
    return ExistingCards(frozenset(ids), text if text.endswith("\n") else f"{text}\n")


def _parse_feed(content: bytes, source: Source) -> list[FeedEntry]:
    if b"<!doctype" in content.lower():
        raise FeedParseError("malformed_xml")
    root = ET.fromstring(content)
    tag = _local_name(root.tag)
    match tag:
        case "rss":
            items = root.findall("./channel/item")[: source.max_entries]
            return [_rss_entry(item, source.url) for item in items]
        case "feed":
            entries = [
                child for child in list(root) if _local_name(child.tag) == "entry"
            ]
            return [
                _atom_entry(entry, source.url)
                for entry in entries[: source.max_entries]
            ]
        case _:
            raise FeedParseError("unsupported_feed")


def _rss_entry(item: ET.Element, fallback_url: str) -> FeedEntry:
    link = _child_text(item, ("link",))
    entry_key = _child_text(item, ("guid",)) or link or _child_text(item, ("title",))
    return FeedEntry(
        _bounded(entry_key, 500),
        _bounded(_child_text(item, ("title",)) or "(untitled)", 300),
        _bounded(_child_text(item, ("description",)), 2_000),
        _bounded(_safe_article_url(link, fallback_url), 2048),
        _bounded(_child_text(item, ("pubDate",)), 120),
    )


def _atom_entry(entry: ET.Element, fallback_url: str) -> FeedEntry:
    link = _atom_link(entry)
    entry_key = _child_text(entry, ("id",)) or link or _child_text(entry, ("title",))
    published = _child_text(entry, ("published",)) or _child_text(entry, ("updated",))
    summary = _child_text(entry, ("summary",)) or _child_text(entry, ("content",))
    return FeedEntry(
        _bounded(entry_key, 500),
        _bounded(_child_text(entry, ("title",)) or "(untitled)", 300),
        _bounded(summary, 2_000),
        _bounded(_safe_article_url(link, fallback_url), 2048),
        _bounded(published, 120),
    )


def _card_for(source: Source, entry: FeedEntry, fetched_at: str) -> CardRecord:
    title = _bounded(entry.title, 140)
    summary = _bounded(entry.summary, 1_000)
    published_at = _published_at(entry.published_at, fetched_at)
    canonical = {
        "entry_key": entry.entry_key,
        "published_at": published_at,
        "source_name": source.name,
        "source_url": entry.source_url,
        "summary": summary,
        "title": title,
    }
    content = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode(
        "utf-8",
    )
    card_id = hashlib.sha256(f"{source.url}\n{entry.entry_key}".encode("utf-8"))
    return {
        "id": f"card-{card_id.hexdigest()[:12]}",
        "title": title,
        "summary": summary,
        "source_url": entry.source_url,
        "source_name": source.name,
        "published_at": published_at,
        "fetched_at": fetched_at,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "products": [],
        "cves": [],
        "techniques": [],
        "confidence": "medium",
        "safety": "public",
    }


def _updated_state(
    response: FetchResponse,
    raw_hash: str,
    fetched_at: str,
) -> SourceState:
    return SourceState(
        _header(response.headers, "etag"),
        _header(response.headers, "last-modified"),
        raw_hash,
        fetched_at,
    )


def _write_cards(path: Path, existing_text: str, cards: list[CardRecord]) -> None:
    rows = [json.dumps(card, sort_keys=True, separators=(",", ":")) for card in cards]
    _write_text_atomic(path, f"{existing_text}{chr(10).join(rows)}\n")


def _write_raw_snapshot(raw_dir: Path, raw_hash: str, content: bytes) -> bool:
    path = raw_dir / f"{raw_hash}.xml"
    if path.exists():
        return False
    _write_bytes_atomic(path, content)
    return True


def _write_text_atomic(path: Path, text: str) -> None:
    _write_bytes_atomic(path, text.encode("utf-8"))


def _write_bytes_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        os.replace(temp_path, path)
    except OSError:
        with contextlib.suppress(FileNotFoundError):
            temp_path.unlink()
        raise


def _conditional_headers(source_state: SourceState) -> dict[str, str]:
    headers: dict[str, str] = {}
    if source_state.etag:
        headers["If-None-Match"] = source_state.etag
    if source_state.last_modified:
        headers["If-Modified-Since"] = source_state.last_modified
    return headers


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _child_text(element: ET.Element, names: tuple[str, ...]) -> str:
    for child in list(element):
        if _local_name(child.tag) in names:
            return _bounded(" ".join("".join(child.itertext()).split()), 10_000)
    return ""


def _atom_link(entry: ET.Element) -> str:
    for child in list(entry):
        if _local_name(child.tag) != "link":
            continue
        href = child.attrib.get("href")
        if href:
            return href
        text = _child_text(child, ("link",))
        if text:
            return text
    return ""


def _safe_article_url(link: str, fallback_url: str) -> str:
    if _valid_fetch_url(link):
        return link
    return fallback_url


def _valid_fetch_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
    ):
        return False

    normalized_host = hostname.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        try:
            ascii_host = normalized_host.encode("idna").decode("ascii")
        except UnicodeError:
            return False
        labels = ascii_host.split(".")
        numeric_hostname = all(
            label.isdigit()
            or (
                label.lower().startswith("0x")
                and len(label) > 2
                and all(
                    character in "0123456789abcdef" for character in label[2:].lower()
                )
            )
            for label in labels
        )
        if (
            len(labels) < 2
            or numeric_hostname
            or any(
                ascii_host == suffix or ascii_host.endswith(f".{suffix}")
                for suffix in LOCAL_HOST_SUFFIXES
            )
        ):
            return False
        return len(ascii_host) <= 253 and all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )
    return address.is_global and not address.is_multicast


def _local_name(tag: str) -> str:
    if tag.startswith("{"):
        return tag.rsplit("}", 1)[1]
    return tag


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


def _published_at(value: str, fetched_at: str) -> str:
    try:
        stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            stamp = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return fetched_at
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        return fetched_at
    return stamp.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def _optional_text(value: JsonValue) -> str | None:
    match value:
        case str() as text:
            return text
        case None:
            return None
        case _:
            return None


def _bounded(value: str, limit: int) -> str:
    return " ".join(value.split())[:limit]


def _failure(source: Source, reason: str) -> SourceFailure:
    return SourceFailure(source.name, source.url, reason)
