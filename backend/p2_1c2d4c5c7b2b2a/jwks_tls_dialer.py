from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from jwks_egress_guard import CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS, PinnedTlsTarget


POLICY = "PINNED_JWKS_TLS_DIALER_V1"


class TlsDialError(OSError):
    pass


@dataclass(frozen=True)
class PinnedTlsConnection:
    tls_socket: ssl.SSLSocket
    peer_address: str

    def close(self) -> None:
        self.tls_socket.close()


def _system_verified_context() -> ssl.SSLContext:
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise TlsDialError("JWKS_TLS_CONTEXT_NOT_VERIFIED")
    return context


def _validate_target(target: PinnedTlsTarget) -> tuple[tuple[str, int], ...]:
    if not isinstance(target, PinnedTlsTarget):
        raise TlsDialError("JWKS_TLS_TARGET_INVALID")
    parsed = urlsplit(target.url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or (parsed.port or 443) != 443
        or target.port != 443
        or target.host != parsed.hostname.lower()
        or target.server_hostname != target.host
        or target.allow_environment_proxy is not False
        or target.connect_timeout_ms != CONNECT_TIMEOUT_MS
        or target.read_timeout_ms != READ_TIMEOUT_MS
        or not target.addresses
    ):
        raise TlsDialError("JWKS_TLS_TARGET_INVALID")

    endpoints: list[tuple[str, int]] = []
    for raw in target.addresses:
        if type(raw) is not str or "%" in raw:
            raise TlsDialError("JWKS_TLS_TARGET_INVALID")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            raise TlsDialError("JWKS_TLS_TARGET_INVALID") from None
        if (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise TlsDialError("JWKS_TLS_TARGET_INVALID")
        endpoints.append((str(address), socket.AF_INET6 if address.version == 6 else socket.AF_INET))
    return tuple(endpoints)


def open_pinned_tls_connection(
    target: PinnedTlsTarget,
    *,
    _socket_factory: Callable[[int, int], socket.socket] = socket.socket,
    _context_factory: Callable[[], ssl.SSLContext] = _system_verified_context,
    _monotonic: Callable[[], float] = time.monotonic,
) -> PinnedTlsConnection:
    """Open verified TLS directly to one frozen approved IP.

    The function never resolves `target.host`, never consults proxy settings, and
    authenticates the TLS peer against `target.server_hostname`.
    """
    endpoints = _validate_target(target)
    context = _context_factory()
    if not getattr(context, "check_hostname", False) or getattr(context, "verify_mode", None) != ssl.CERT_REQUIRED:
        raise TlsDialError("JWKS_TLS_CONTEXT_NOT_VERIFIED")

    deadline = _monotonic() + (target.connect_timeout_ms / 1000.0)
    failures: list[BaseException] = []

    for address, family in endpoints:
        remaining = deadline - _monotonic()
        if remaining <= 0:
            break

        raw = None
        tls_sock = None
        try:
            raw = _socket_factory(family, socket.SOCK_STREAM)
            raw.settimeout(remaining)
            sockaddr = (address, target.port, 0, 0) if family == socket.AF_INET6 else (address, target.port)
            raw.connect(sockaddr)

            remaining = deadline - _monotonic()
            if remaining <= 0:
                raise TimeoutError("connect budget exhausted before TLS handshake")
            raw.settimeout(remaining)

            tls_sock = context.wrap_socket(
                raw,
                server_hostname=target.server_hostname,
                do_handshake_on_connect=True,
            )
            tls_sock.settimeout(target.read_timeout_ms / 1000.0)
            return PinnedTlsConnection(tls_socket=tls_sock, peer_address=address)
        except (OSError, ssl.SSLError) as exc:
            failures.append(exc)
            try:
                if tls_sock is not None:
                    tls_sock.close()
                elif raw is not None:
                    raw.close()
            except OSError:
                pass

    if not failures:
        raise TlsDialError("JWKS_TLS_CONNECT_TIMEOUT")
    raise TlsDialError("JWKS_TLS_CONNECT_FAILED") from failures[-1]
