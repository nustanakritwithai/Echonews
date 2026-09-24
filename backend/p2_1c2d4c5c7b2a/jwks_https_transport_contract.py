from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from jwks_trust_contract import IssuerTrust


POLICY = "PINNED_HTTPS_JWKS_ENVELOPE_V1"
MAX_RESPONSE_BYTES = 262_144
ALLOWED_MEDIA_TYPES = frozenset({"application/json", "application/jwk-set+json"})
_SECURITY_HEADERS = frozenset({"content-type", "content-length", "content-encoding", "location"})
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class TransportContractError(ValueError):
    pass


@dataclass(frozen=True)
class JwksHttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True)
class ParsedJwksResponse:
    media_type: str
    body_bytes: int
    document: dict


def build_pinned_jwks_request(trust: IssuerTrust) -> JwksHttpRequest:
    """Build the only request shape allowed for this issuer's JWKS endpoint.

    There is deliberately no caller-supplied URL parameter. The exact operator-pinned
    `trust.jwks_uri` is copied into the request without normalization or redirect logic.
    """
    return JwksHttpRequest(
        method="GET",
        url=trust.jwks_uri,
        headers={
            "accept": "application/jwk-set+json, application/json",
            "accept-encoding": "identity",
        },
    )


def _header_items(headers: object) -> list[tuple[str, str]]:
    if isinstance(headers, Mapping):
        raw_items = list(headers.items())
    elif isinstance(headers, Sequence) and not isinstance(headers, (str, bytes, bytearray)):
        raw_items = list(headers)
    else:
        raise TransportContractError("JWKS_HTTP_HEADERS_INVALID")

    normalized: list[tuple[str, str]] = []
    seen_security: set[str] = set()
    for item in raw_items:
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes, bytearray)) or len(item) != 2:
            raise TransportContractError("JWKS_HTTP_HEADERS_INVALID")
        name, value = item
        if type(name) is not str or type(value) is not str:
            raise TransportContractError("JWKS_HTTP_HEADERS_INVALID")
        name = name.strip().lower()
        value = value.strip()
        if not name or _HEADER_NAME_RE.fullmatch(name) is None or "\r" in value or "\n" in value:
            raise TransportContractError("JWKS_HTTP_HEADERS_INVALID")
        if name in _SECURITY_HEADERS:
            if name in seen_security:
                raise TransportContractError("JWKS_HTTP_DUPLICATE_SECURITY_HEADER")
            seen_security.add(name)
        normalized.append((name, value))
    return normalized


def _one_header(items: list[tuple[str, str]], name: str) -> str | None:
    values = [value for key, value in items if key == name]
    return values[0] if values else None


def _parse_content_type(value: str | None) -> str:
    if value is None:
        raise TransportContractError("JWKS_HTTP_CONTENT_TYPE_REQUIRED")
    parts = [part.strip() for part in value.split(";")]
    media_type = parts[0].lower()
    if media_type not in ALLOWED_MEDIA_TYPES:
        raise TransportContractError("JWKS_HTTP_CONTENT_TYPE_REJECTED")
    params: dict[str, str] = {}
    for raw in parts[1:]:
        if not raw or "=" not in raw:
            raise TransportContractError("JWKS_HTTP_CONTENT_TYPE_REJECTED")
        key, val = (piece.strip() for piece in raw.split("=", 1))
        key = key.lower()
        val = val.strip('"').lower()
        if key in params:
            raise TransportContractError("JWKS_HTTP_CONTENT_TYPE_REJECTED")
        params[key] = val
    if params and params != {"charset": "utf-8"}:
        raise TransportContractError("JWKS_HTTP_CONTENT_TYPE_REJECTED")
    return media_type


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TransportContractError("JWKS_JSON_DUPLICATE_MEMBER")
        result[key] = value
    return result


def parse_pinned_jwks_response(
    trust: IssuerTrust,
    request: JwksHttpRequest,
    *,
    status: int,
    headers: object,
    body: bytes,
) -> ParsedJwksResponse:
    """Validate one already-received HTTP response before JWKS trust validation.

    This is an envelope contract, not a socket implementation. It rejects redirects,
    compressed bodies, ambiguous security headers, oversized payloads, non-UTF-8 JSON,
    duplicate JSON object members, and any request that did not target the exact pinned URL.
    """
    if request.method != "GET" or request.url != trust.jwks_uri:
        raise TransportContractError("JWKS_HTTP_REQUEST_NOT_PINNED")
    if request.headers.get("accept-encoding") != "identity":
        raise TransportContractError("JWKS_HTTP_REQUEST_NOT_PINNED")
    if type(status) is not int:
        raise TransportContractError("JWKS_HTTP_STATUS_INVALID")
    if 300 <= status <= 399:
        raise TransportContractError("JWKS_HTTP_REDIRECT_REJECTED")
    if status != 200:
        raise TransportContractError("JWKS_HTTP_STATUS_REJECTED")
    if type(body) is not bytes:
        raise TransportContractError("JWKS_HTTP_BODY_INVALID")
    if not body or len(body) > MAX_RESPONSE_BYTES:
        raise TransportContractError("JWKS_HTTP_BODY_SIZE_REJECTED")

    items = _header_items(headers)
    media_type = _parse_content_type(_one_header(items, "content-type"))
    content_encoding = _one_header(items, "content-encoding")
    if content_encoding is not None and content_encoding.lower() != "identity":
        raise TransportContractError("JWKS_HTTP_CONTENT_ENCODING_REJECTED")
    content_length = _one_header(items, "content-length")
    if content_length is not None:
        if re.fullmatch(r"[0-9]+", content_length) is None:
            raise TransportContractError("JWKS_HTTP_CONTENT_LENGTH_INVALID")
        declared = int(content_length)
        if declared > MAX_RESPONSE_BYTES or declared != len(body):
            raise TransportContractError("JWKS_HTTP_CONTENT_LENGTH_MISMATCH")

    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise TransportContractError("JWKS_HTTP_UTF8_REQUIRED") from None
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_members)
    except TransportContractError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise TransportContractError("JWKS_HTTP_JSON_INVALID") from None
    if type(document) is not dict:
        raise TransportContractError("JWKS_HTTP_JSON_OBJECT_REQUIRED")

    return ParsedJwksResponse(
        media_type=media_type,
        body_bytes=len(body),
        document=document,
    )
