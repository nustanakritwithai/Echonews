from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit


POLICY = "PINNED_ISSUER_JWKS_ROTATION_V1"
MAX_KEYS = 32
MIN_RSA_BITS = 2048
MIN_RSA_EXPONENT = 65537
KID_RE = re.compile(r"^[A-Za-z0-9._~-]{1,80}$")
PRIVATE_RSA_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})


class ContractError(ValueError):
    pass


class KeyDecision(str, Enum):
    USE_CACHED = "USE_CACHED"
    USE_CACHED_REFRESH_RECOMMENDED = "USE_CACHED_REFRESH_RECOMMENDED"
    REFRESH_REQUIRED = "REFRESH_REQUIRED"
    REJECT = "REJECT"


@dataclass(frozen=True)
class IssuerTrust:
    issuer: str
    jwks_uri: str
    audience: str
    trust_epoch: int
    algorithm: str = "RS256"
    token_type: str = "at+jwt"
    soft_ttl_ms: int = 300_000
    hard_ttl_ms: int = 900_000

    def __post_init__(self) -> None:
        _https_url(self.issuer, allow_query=False)
        _https_url(self.jwks_uri, allow_query=True)
        if self.issuer.strip() != self.issuer or self.jwks_uri.strip() != self.jwks_uri:
            raise ContractError("TRUST_CONFIG_INVALID")
        if type(self.audience) is not str or not self.audience.strip() or len(self.audience) > 256:
            raise ContractError("TRUST_CONFIG_INVALID")
        if self.algorithm != "RS256" or self.token_type != "at+jwt":
            raise ContractError("TRUST_CONFIG_INVALID")
        if type(self.trust_epoch) is not int or self.trust_epoch <= 0:
            raise ContractError("TRUST_CONFIG_INVALID")
        if not (60_000 <= self.soft_ttl_ms < self.hard_ttl_ms <= 3_600_000):
            raise ContractError("TRUST_CONFIG_INVALID")


@dataclass(frozen=True)
class TrustedJwk:
    kid: str
    fingerprint: str
    modulus_bits: int
    exponent: int


@dataclass(frozen=True)
class JwksSnapshot:
    issuer: str
    jwks_uri: str
    trust_epoch: int
    fetched_at_ms: int
    soft_expires_at_ms: int
    hard_expires_at_ms: int
    key_set_version: str
    keys: Mapping[str, TrustedJwk]

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))


@dataclass(frozen=True)
class HeaderDecision:
    decision: KeyDecision
    kid: str | None = None
    fingerprint: str | None = None
    key_set_version: str | None = None
    reason: str | None = None


def _https_url(value: str, *, allow_query: bool) -> None:
    if type(value) is not str or not value or len(value) > 2048:
        raise ContractError("TRUST_CONFIG_INVALID")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ContractError("TRUST_CONFIG_INVALID")
    if parsed.fragment or (parsed.query and not allow_query):
        raise ContractError("TRUST_CONFIG_INVALID")


def _b64u_bytes(value: object) -> bytes:
    if type(value) is not str or not value or "=" in value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ContractError("JWKS_INVALID")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ContractError("JWKS_INVALID") from exc


def _int_from_b64u(value: object) -> int:
    raw = _b64u_bytes(value)
    if not raw or (len(raw) > 1 and raw[0] == 0):
        raise ContractError("JWKS_INVALID")
    return int.from_bytes(raw, "big")


def _eligible_rsa_jwk(raw: object) -> TrustedJwk | None:
    if type(raw) is not dict:
        raise ContractError("JWKS_INVALID")
    if PRIVATE_RSA_MEMBERS.intersection(raw):
        raise ContractError("JWKS_PRIVATE_KEY_MATERIAL")
    kid = raw.get("kid")
    if type(kid) is not str or KID_RE.fullmatch(kid) is None:
        raise ContractError("JWKS_INVALID")

    # Heterogeneous JWKS documents are allowed; only the pinned verification profile is eligible.
    if raw.get("kty") != "RSA":
        return None
    if "alg" in raw and raw.get("alg") != "RS256":
        return None
    if "use" in raw and raw.get("use") != "sig":
        return None
    if "key_ops" in raw:
        ops = raw.get("key_ops")
        if type(ops) is not list or any(type(v) is not str for v in ops) or len(set(ops)) != len(ops):
            raise ContractError("JWKS_INVALID")
        if "verify" not in ops:
            return None
        if any(op in {"encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"} for op in ops):
            return None

    n = _int_from_b64u(raw.get("n"))
    e = _int_from_b64u(raw.get("e"))
    if n.bit_length() < MIN_RSA_BITS or e < MIN_RSA_EXPONENT or e % 2 == 0:
        raise ContractError("JWKS_WEAK_RSA_KEY")

    canonical = json.dumps({"e": raw["e"], "kty": "RSA", "n": raw["n"]}, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode("ascii")).hexdigest()
    return TrustedJwk(kid=kid, fingerprint=fingerprint, modulus_bits=n.bit_length(), exponent=e)


def validate_jwks_snapshot(
    trust: IssuerTrust,
    jwks: object,
    *,
    fetched_at_ms: int,
    previous: JwksSnapshot | None = None,
) -> JwksSnapshot:
    if type(fetched_at_ms) is not int or fetched_at_ms < 0:
        raise ContractError("JWKS_INVALID")
    if type(jwks) is not dict or set(jwks) != {"keys"} or type(jwks["keys"]) is not list:
        raise ContractError("JWKS_INVALID")
    raw_keys = jwks["keys"]
    if not 1 <= len(raw_keys) <= MAX_KEYS:
        raise ContractError("JWKS_INVALID")

    seen_kids: set[str] = set()
    eligible: dict[str, TrustedJwk] = {}
    for raw in raw_keys:
        if type(raw) is not dict:
            raise ContractError("JWKS_INVALID")
        kid = raw.get("kid")
        if type(kid) is not str or KID_RE.fullmatch(kid) is None or kid in seen_kids:
            raise ContractError("JWKS_DUPLICATE_OR_INVALID_KID")
        seen_kids.add(kid)
        key = _eligible_rsa_jwk(raw)
        if key is not None:
            eligible[key.kid] = key

    if not eligible:
        raise ContractError("JWKS_NO_ELIGIBLE_KEYS")

    if previous is not None:
        if (previous.issuer != trust.issuer or previous.jwks_uri != trust.jwks_uri
                or previous.trust_epoch != trust.trust_epoch):
            raise ContractError("JWKS_PREVIOUS_TRUST_MISMATCH")
        for kid, old in previous.keys.items():
            new = eligible.get(kid)
            if new is not None and new.fingerprint != old.fingerprint:
                raise ContractError("JWKS_KID_KEY_SUBSTITUTION")

    version_input = [
        POLICY,
        str(trust.trust_epoch),
        trust.issuer,
        trust.jwks_uri,
        *[f"{kid}:{eligible[kid].fingerprint}" for kid in sorted(eligible)],
    ]
    version = hashlib.sha256("\n".join(version_input).encode("utf-8")).hexdigest()
    return JwksSnapshot(
        issuer=trust.issuer,
        jwks_uri=trust.jwks_uri,
        trust_epoch=trust.trust_epoch,
        fetched_at_ms=fetched_at_ms,
        soft_expires_at_ms=fetched_at_ms + trust.soft_ttl_ms,
        hard_expires_at_ms=fetched_at_ms + trust.hard_ttl_ms,
        key_set_version=f"jwks-v1:{version}",
        keys=eligible,
    )


def decide_header_key(
    trust: IssuerTrust,
    snapshot: JwksSnapshot | None,
    header: object,
    *,
    now_ms: int,
) -> HeaderDecision:
    if type(now_ms) is not int or now_ms < 0:
        return HeaderDecision(KeyDecision.REJECT, reason="CLOCK_INVALID")
    if type(header) is not dict or set(header) != {"alg", "typ", "kid"}:
        return HeaderDecision(KeyDecision.REJECT, reason="HEADER_PROFILE_REJECTED")
    if header.get("alg") != trust.algorithm or header.get("typ") != trust.token_type:
        return HeaderDecision(KeyDecision.REJECT, reason="HEADER_PROFILE_REJECTED")
    kid = header.get("kid")
    if type(kid) is not str or KID_RE.fullmatch(kid) is None:
        return HeaderDecision(KeyDecision.REJECT, reason="HEADER_PROFILE_REJECTED")

    if snapshot is None:
        return HeaderDecision(KeyDecision.REFRESH_REQUIRED, kid=kid, reason="NO_JWKS_SNAPSHOT")
    if (snapshot.issuer != trust.issuer or snapshot.jwks_uri != trust.jwks_uri
            or snapshot.trust_epoch != trust.trust_epoch):
        return HeaderDecision(KeyDecision.REJECT, kid=kid, reason="TRUST_EPOCH_MISMATCH")
    if now_ms >= snapshot.hard_expires_at_ms:
        return HeaderDecision(KeyDecision.REFRESH_REQUIRED, kid=kid, reason="JWKS_HARD_EXPIRED")

    key = snapshot.keys.get(kid)
    if key is None:
        # Per OIDC key rollover guidance, an unfamiliar kid requires a bounded refresh.
        return HeaderDecision(KeyDecision.REFRESH_REQUIRED, kid=kid, reason="UNKNOWN_KID")
    decision = KeyDecision.USE_CACHED
    reason = None
    if now_ms >= snapshot.soft_expires_at_ms:
        decision = KeyDecision.USE_CACHED_REFRESH_RECOMMENDED
        reason = "JWKS_SOFT_EXPIRED"
    return HeaderDecision(
        decision,
        kid=kid,
        fingerprint=key.fingerprint,
        key_set_version=snapshot.key_set_version,
        reason=reason,
    )
