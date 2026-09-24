from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

from jwks_trust_contract import IssuerTrust


POLICY = "PINNED_JWKS_EGRESS_GUARD_V1"
DEFAULT_HTTPS_PORT = 443
MAX_RESOLVED_ADDRESSES = 16
CONNECT_TIMEOUT_MS = 3_000
READ_TIMEOUT_MS = 5_000
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class EgressGuardError(ValueError):
    pass


@dataclass(frozen=True)
class PinnedTlsTarget:
    """Immutable output of the egress decision.

    A socket adapter must connect only to `addresses`, must use `server_hostname`
    for TLS SNI/certificate hostname verification, must not resolve the host again,
    and must ignore environment proxy configuration.
    """

    url: str
    host: str
    port: int
    server_hostname: str
    addresses: tuple[str, ...]
    connect_timeout_ms: int = CONNECT_TIMEOUT_MS
    read_timeout_ms: int = READ_TIMEOUT_MS
    allow_environment_proxy: bool = False


def _validated_hostname(value: str) -> str:
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise EgressGuardError("JWKS_EGRESS_HOSTNAME_REJECTED") from None
    if not value or len(value) > 253 or value.endswith("."):
        raise EgressGuardError("JWKS_EGRESS_HOSTNAME_REJECTED")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise EgressGuardError("JWKS_EGRESS_IP_LITERAL_REJECTED")
    labels = value.split(".")
    if len(labels) < 2 or any(_HOST_LABEL_RE.fullmatch(label) is None for label in labels):
        raise EgressGuardError("JWKS_EGRESS_HOSTNAME_REJECTED")
    return value.lower()


def _public_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if type(value) is not str or value.strip() != value or not value or "%" in value:
        raise EgressGuardError("JWKS_EGRESS_DNS_ANSWER_REJECTED")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise EgressGuardError("JWKS_EGRESS_DNS_ANSWER_REJECTED") from None
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise EgressGuardError("JWKS_EGRESS_NON_PUBLIC_ADDRESS")
    return address


def build_pinned_tls_target(
    trust: IssuerTrust,
    resolved_addresses: Sequence[str],
) -> PinnedTlsTarget:
    """Freeze a DNS result into a public-only TLS target for the pinned JWKS URL.

    The resolver is intentionally outside this function. Production fetch code must
    resolve once, call this guard, and then connect only to the returned IP set. A
    second hostname lookup after this decision would violate the contract.
    """
    parsed = urlsplit(trust.jwks_uri)
    if parsed.scheme != "https" or not parsed.hostname:
        raise EgressGuardError("JWKS_EGRESS_URL_INVALID")
    try:
        port = parsed.port or DEFAULT_HTTPS_PORT
    except ValueError:
        raise EgressGuardError("JWKS_EGRESS_PORT_REJECTED") from None
    if port != DEFAULT_HTTPS_PORT:
        raise EgressGuardError("JWKS_EGRESS_PORT_REJECTED")

    host = _validated_hostname(parsed.hostname)
    if isinstance(resolved_addresses, (str, bytes, bytearray)) or not isinstance(resolved_addresses, Sequence):
        raise EgressGuardError("JWKS_EGRESS_DNS_ANSWER_REJECTED")
    if not 1 <= len(resolved_addresses) <= MAX_RESOLVED_ADDRESSES:
        raise EgressGuardError("JWKS_EGRESS_DNS_ANSWER_REJECTED")

    approved: dict[tuple[int, int], str] = {}
    for raw in resolved_addresses:
        address = _public_ip(raw)
        approved[(address.version, int(address))] = str(address)
    if not approved:
        raise EgressGuardError("JWKS_EGRESS_DNS_ANSWER_REJECTED")

    addresses = tuple(approved[key] for key in sorted(approved))
    return PinnedTlsTarget(
        url=trust.jwks_uri,
        host=host,
        port=port,
        server_hostname=host,
        addresses=addresses,
    )
