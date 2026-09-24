from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from jwks_https_transport_contract import (
    JwksHttpRequest,
    ParsedJwksResponse,
    TransportContractError,
    build_pinned_jwks_request,
    parse_pinned_jwks_response,
    MAX_RESPONSE_BYTES,
)
from jwks_egress_guard import PinnedTlsTarget
from jwks_tls_dialer import PinnedTlsConnection, open_pinned_tls_connection
from jwks_trust_contract import IssuerTrust


POLICY = "PINNED_JWKS_HTTP_OVER_TLS_V1"
MAX_HEADER_BYTES = 32_768
MAX_HEADER_LINES = 128
_STATUS_RE = re.compile(rb"^HTTP/(1\.0|1\.1) ([0-9]{3})(?: [^\r\n]*)?$")


class JwksFetchError(OSError):
    pass


@dataclass(frozen=True)
class RawHttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def _request_target(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        target = path.encode("ascii")
    except UnicodeEncodeError:
        raise JwksFetchError("JWKS_HTTP_REQUEST_TARGET_INVALID") from None
    if b"\r" in target or b"\n" in target or b" " in target:
        raise JwksFetchError("JWKS_HTTP_REQUEST_TARGET_INVALID")
    return target.decode("ascii")


def _wire_request(trust: IssuerTrust, target: PinnedTlsTarget, request: JwksHttpRequest) -> bytes:
    if request.method != "GET" or request.url != trust.jwks_uri or target.url != trust.jwks_uri:
        raise JwksFetchError("JWKS_HTTP_REQUEST_NOT_PINNED")
    parsed = urlsplit(trust.jwks_uri)
    if parsed.scheme != "https" or parsed.hostname is None or parsed.hostname.lower() != target.host:
        raise JwksFetchError("JWKS_HTTP_REQUEST_NOT_PINNED")
    if target.port != 443 or target.server_hostname != target.host:
        raise JwksFetchError("JWKS_HTTP_REQUEST_NOT_PINNED")

    lines = [
        f"GET {_request_target(request.url)} HTTP/1.1",
        f"Host: {target.host}",
        f"Accept: {request.headers.get('accept', '')}",
        f"Accept-Encoding: {request.headers.get('accept-encoding', '')}",
        "Connection: close",
        "User-Agent: EchoNews-JWKS/1",
        "",
        "",
    ]
    try:
        wire = "\r\n".join(lines).encode("ascii")
    except UnicodeEncodeError:
        raise JwksFetchError("JWKS_HTTP_REQUEST_ENCODING_INVALID") from None
    if request.headers.get("accept-encoding") != "identity":
        raise JwksFetchError("JWKS_HTTP_REQUEST_NOT_PINNED")
    return wire


def _recv(sock: object, size: int) -> bytes:
    try:
        chunk = sock.recv(size)
    except (socket.timeout, TimeoutError) as exc:
        raise JwksFetchError("JWKS_HTTP_READ_TIMEOUT") from exc
    except OSError as exc:
        raise JwksFetchError("JWKS_HTTP_READ_FAILED") from exc
    if type(chunk) is not bytes:
        raise JwksFetchError("JWKS_HTTP_READ_INVALID")
    return chunk


def _parse_head(head: bytes) -> tuple[int, tuple[tuple[str, str], ...], int | None]:
    lines = head.split(b"\r\n")
    if not lines or len(lines) > MAX_HEADER_LINES:
        raise JwksFetchError("JWKS_HTTP_HEADERS_REJECTED")
    match = _STATUS_RE.fullmatch(lines[0])
    if match is None:
        raise JwksFetchError("JWKS_HTTP_STATUS_LINE_INVALID")
    status = int(match.group(2))

    headers: list[tuple[str, str]] = []
    content_length: int | None = None
    transfer_encoding_seen = False
    for raw in lines[1:]:
        if not raw:
            continue
        if raw[:1] in (b" ", b"\t") or b":" not in raw:
            raise JwksFetchError("JWKS_HTTP_HEADERS_REJECTED")
        name_raw, value_raw = raw.split(b":", 1)
        try:
            name = name_raw.decode("ascii")
            value = value_raw.decode("latin-1").strip(" \t")
        except UnicodeDecodeError:
            raise JwksFetchError("JWKS_HTTP_HEADERS_REJECTED") from None
        if not name or any(ord(ch) < 33 or ord(ch) > 126 for ch in name):
            raise JwksFetchError("JWKS_HTTP_HEADERS_REJECTED")
        lname = name.lower()
        headers.append((lname, value))
        if lname == "transfer-encoding":
            transfer_encoding_seen = True
        elif lname == "content-length":
            if content_length is not None or re.fullmatch(r"[0-9]+", value) is None:
                raise JwksFetchError("JWKS_HTTP_CONTENT_LENGTH_INVALID")
            content_length = int(value)
            if content_length > MAX_RESPONSE_BYTES:
                raise JwksFetchError("JWKS_HTTP_BODY_SIZE_REJECTED")

    if transfer_encoding_seen:
        raise JwksFetchError("JWKS_HTTP_TRANSFER_ENCODING_REJECTED")
    return status, tuple(headers), content_length


def _read_http_response(sock: object) -> RawHttpResponse:
    buffer = bytearray()
    marker = b"\r\n\r\n"
    while marker not in buffer:
        if len(buffer) >= MAX_HEADER_BYTES:
            raise JwksFetchError("JWKS_HTTP_HEADERS_TOO_LARGE")
        chunk = _recv(sock, min(4096, MAX_HEADER_BYTES + 1 - len(buffer)))
        if not chunk:
            raise JwksFetchError("JWKS_HTTP_EOF_BEFORE_HEADERS")
        buffer.extend(chunk)
        if len(buffer) > MAX_HEADER_BYTES and marker not in buffer:
            raise JwksFetchError("JWKS_HTTP_HEADERS_TOO_LARGE")

    head, body_start = bytes(buffer).split(marker, 1)
    if len(head) + len(marker) > MAX_HEADER_BYTES:
        raise JwksFetchError("JWKS_HTTP_HEADERS_TOO_LARGE")
    status, headers, content_length = _parse_head(head)

    body = bytearray(body_start)
    if content_length is not None:
        if len(body) > content_length:
            raise JwksFetchError("JWKS_HTTP_EXTRA_BODY_BYTES")
        while len(body) < content_length:
            chunk = _recv(sock, min(4096, content_length - len(body)))
            if not chunk:
                raise JwksFetchError("JWKS_HTTP_EOF_BEFORE_BODY")
            body.extend(chunk)
        if len(body) != content_length:
            raise JwksFetchError("JWKS_HTTP_CONTENT_LENGTH_MISMATCH")
    else:
        while True:
            if len(body) > MAX_RESPONSE_BYTES:
                raise JwksFetchError("JWKS_HTTP_BODY_SIZE_REJECTED")
            chunk = _recv(sock, min(4096, MAX_RESPONSE_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise JwksFetchError("JWKS_HTTP_BODY_SIZE_REJECTED")

    return RawHttpResponse(status=status, headers=headers, body=bytes(body))


def fetch_pinned_jwks_over_tls(
    trust: IssuerTrust,
    target: PinnedTlsTarget,
    *,
    _opener: Callable[[PinnedTlsTarget], PinnedTlsConnection] = open_pinned_tls_connection,
) -> ParsedJwksResponse:
    request = build_pinned_jwks_request(trust)
    wire = _wire_request(trust, target, request)
    connection: PinnedTlsConnection | None = None
    try:
        connection = _opener(target)
        try:
            connection.tls_socket.sendall(wire)
        except (socket.timeout, TimeoutError) as exc:
            raise JwksFetchError("JWKS_HTTP_WRITE_TIMEOUT") from exc
        except OSError as exc:
            raise JwksFetchError("JWKS_HTTP_WRITE_FAILED") from exc
        raw = _read_http_response(connection.tls_socket)
        return parse_pinned_jwks_response(
            trust,
            request,
            status=raw.status,
            headers=raw.headers,
            body=raw.body,
        )
    except TransportContractError:
        raise
    finally:
        if connection is not None:
            connection.close()
