from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Sequence

from jwks_trust_contract import IssuerTrust, JwksSnapshot, validate_jwks_snapshot


POLICY = "BOUNDED_ETAG_304_REVALIDATION_V1"
_MAX_ETAG_CHARS = 200
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class ConditionalFetchError(ValueError):
    pass


class RefreshMode(str, Enum):
    FULL = "FULL"
    CONDITIONAL = "CONDITIONAL"


@dataclass(frozen=True)
class ConditionalCacheEntry:
    snapshot: JwksSnapshot
    etag: str | None
    revalidated_at_ms: int

    def __post_init__(self) -> None:
        if type(self.revalidated_at_ms) is not int or self.revalidated_at_ms < 0:
            raise ConditionalFetchError("JWKS_CACHE_TIME_INVALID")
        if self.revalidated_at_ms < self.snapshot.fetched_at_ms:
            raise ConditionalFetchError("JWKS_CACHE_TIME_INVALID")
        if self.etag is not None and _etag_kind(self.etag) != "strong":
            raise ConditionalFetchError("JWKS_CACHE_ETAG_INVALID")


@dataclass(frozen=True)
class RefreshPlan:
    mode: RefreshMode
    headers: Mapping[str, str]
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


def _same_trust(trust: IssuerTrust, snapshot: JwksSnapshot) -> bool:
    return (
        snapshot.issuer == trust.issuer
        and snapshot.jwks_uri == trust.jwks_uri
        and snapshot.trust_epoch == trust.trust_epoch
    )


def _validate_now(now_ms: int) -> None:
    if type(now_ms) is not int or now_ms < 0:
        raise ConditionalFetchError("JWKS_CLOCK_INVALID")


def _valid_opaque_tag(value: str) -> bool:
    if len(value) < 3 or value[0] != '"' or value[-1] != '"':
        return False
    opaque = value[1:-1]
    if not opaque or len(opaque) > _MAX_ETAG_CHARS:
        return False
    return all(ch == "!" or 0x23 <= ord(ch) <= 0x7E for ch in opaque)


def _etag_kind(value: str) -> str:
    if type(value) is not str or not value:
        return "invalid"
    if _valid_opaque_tag(value):
        return "strong"
    if value.startswith("W/") and _valid_opaque_tag(value[2:]):
        return "weak"
    return "invalid"


def _header_items(headers: object) -> list[tuple[str, str]]:
    if isinstance(headers, Mapping):
        raw_items = list(headers.items())
    elif isinstance(headers, Sequence) and not isinstance(headers, (str, bytes, bytearray)):
        raw_items = list(headers)
    else:
        raise ConditionalFetchError("JWKS_CONDITIONAL_HEADERS_INVALID")

    normalized: list[tuple[str, str]] = []
    for item in raw_items:
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes, bytearray)) or len(item) != 2:
            raise ConditionalFetchError("JWKS_CONDITIONAL_HEADERS_INVALID")
        name, value = item
        if type(name) is not str or type(value) is not str:
            raise ConditionalFetchError("JWKS_CONDITIONAL_HEADERS_INVALID")
        name = name.strip().lower()
        value = value.strip()
        if not name or _HEADER_NAME_RE.fullmatch(name) is None or "\r" in value or "\n" in value:
            raise ConditionalFetchError("JWKS_CONDITIONAL_HEADERS_INVALID")
        normalized.append((name, value))
    return normalized


def _response_etag(headers: object, *, require_strong: bool) -> str | None:
    values = [value for name, value in _header_items(headers) if name == "etag"]
    if len(values) > 1:
        raise ConditionalFetchError("JWKS_ETAG_DUPLICATE")
    if not values:
        if require_strong:
            raise ConditionalFetchError("JWKS_304_ETAG_REQUIRED")
        return None

    value = values[0]
    kind = _etag_kind(value)
    if kind == "strong":
        return value
    if kind == "weak" and not require_strong:
        return None
    if require_strong:
        raise ConditionalFetchError("JWKS_304_ETAG_INVALID")
    raise ConditionalFetchError("JWKS_ETAG_INVALID")


def plan_refresh(
    trust: IssuerTrust,
    entry: ConditionalCacheEntry | None,
    *,
    now_ms: int,
) -> RefreshPlan:
    _validate_now(now_ms)
    if entry is None:
        return RefreshPlan(RefreshMode.FULL, {}, "NO_CACHE")
    if not _same_trust(trust, entry.snapshot):
        return RefreshPlan(RefreshMode.FULL, {}, "TRUST_CHANGED")
    if now_ms >= entry.snapshot.hard_expires_at_ms:
        return RefreshPlan(RefreshMode.FULL, {}, "HARD_EXPIRED")
    if entry.etag is None:
        return RefreshPlan(RefreshMode.FULL, {}, "NO_STRONG_ETAG")
    return RefreshPlan(
        RefreshMode.CONDITIONAL,
        {"if-none-match": entry.etag},
        "STRONG_ETAG_AVAILABLE",
    )


def accept_full_200(
    trust: IssuerTrust,
    document: object,
    *,
    response_headers: object,
    fetched_at_ms: int,
    previous: ConditionalCacheEntry | None = None,
) -> ConditionalCacheEntry:
    _validate_now(fetched_at_ms)
    previous_snapshot: JwksSnapshot | None = None
    if previous is not None and _same_trust(trust, previous.snapshot):
        if fetched_at_ms < previous.revalidated_at_ms:
            raise ConditionalFetchError("JWKS_CLOCK_REWIND")
        previous_snapshot = previous.snapshot

    snapshot = validate_jwks_snapshot(
        trust,
        document,
        fetched_at_ms=fetched_at_ms,
        previous=previous_snapshot,
    )
    etag = _response_etag(response_headers, require_strong=False)
    return ConditionalCacheEntry(snapshot=snapshot, etag=etag, revalidated_at_ms=fetched_at_ms)


def apply_not_modified_304(
    trust: IssuerTrust,
    entry: ConditionalCacheEntry,
    plan: RefreshPlan,
    *,
    response_headers: object,
    body: bytes,
    now_ms: int,
) -> ConditionalCacheEntry:
    _validate_now(now_ms)
    if not _same_trust(trust, entry.snapshot):
        raise ConditionalFetchError("JWKS_304_TRUST_MISMATCH")
    if entry.etag is None:
        raise ConditionalFetchError("JWKS_304_WITHOUT_VALIDATOR")
    if plan.mode is not RefreshMode.CONDITIONAL or dict(plan.headers) != {"if-none-match": entry.etag}:
        raise ConditionalFetchError("JWKS_304_REQUEST_MISMATCH")
    if now_ms < entry.revalidated_at_ms:
        raise ConditionalFetchError("JWKS_CLOCK_REWIND")
    if now_ms >= entry.snapshot.hard_expires_at_ms:
        raise ConditionalFetchError("JWKS_304_HARD_EXPIRED")
    if type(body) is not bytes or body:
        raise ConditionalFetchError("JWKS_304_BODY_REJECTED")

    returned_etag = _response_etag(response_headers, require_strong=True)
    if returned_etag != entry.etag:
        raise ConditionalFetchError("JWKS_304_ETAG_MISMATCH")

    soft_expires_at_ms = min(now_ms + trust.soft_ttl_ms, entry.snapshot.hard_expires_at_ms)
    refreshed_snapshot = JwksSnapshot(
        issuer=entry.snapshot.issuer,
        jwks_uri=entry.snapshot.jwks_uri,
        trust_epoch=entry.snapshot.trust_epoch,
        fetched_at_ms=entry.snapshot.fetched_at_ms,
        soft_expires_at_ms=soft_expires_at_ms,
        hard_expires_at_ms=entry.snapshot.hard_expires_at_ms,
        key_set_version=entry.snapshot.key_set_version,
        keys=entry.snapshot.keys,
    )
    return ConditionalCacheEntry(
        snapshot=refreshed_snapshot,
        etag=entry.etag,
        revalidated_at_ms=now_ms,
    )
