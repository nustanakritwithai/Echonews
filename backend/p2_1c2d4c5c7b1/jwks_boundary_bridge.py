from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa

from identity_boundary import Config
from jwks_trust_contract import IssuerTrust, JwksSnapshot, validate_jwks_snapshot


class BridgeError(ValueError):
    pass


@dataclass(frozen=True)
class BoundaryTrustBundle:
    snapshot: JwksSnapshot
    config: Config


def _b64u_int(value: object) -> int:
    if type(value) is not str or not value or "=" in value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise BridgeError("JWKS_BRIDGE_INVALID")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise BridgeError("JWKS_BRIDGE_INVALID") from exc
    if not raw or (len(raw) > 1 and raw[0] == 0):
        raise BridgeError("JWKS_BRIDGE_INVALID")
    return int.from_bytes(raw, "big")


def _fingerprint(raw: dict) -> str:
    canonical = json.dumps(
        {"e": raw["e"], "kty": "RSA", "n": raw["n"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def build_boundary_trust_bundle(
    trust: IssuerTrust,
    jwks: object,
    *,
    fetched_at_ms: int,
    now_ms: int,
    previous: JwksSnapshot | None = None,
    max_lifetime_seconds: int = 900,
) -> BoundaryTrustBundle:
    """Validate one operator-pinned JWKS snapshot and bridge it into Boundary.Config.

    This function intentionally performs no network I/O. The caller must obtain `jwks`
    from the exact preconfigured `trust.jwks_uri`; network transport/cache policy remains
    a separate gate. No unvalidated JWK material is ever exposed to identity_boundary.
    """
    if type(now_ms) is not int or now_ms < 0 or type(fetched_at_ms) is not int or fetched_at_ms < 0:
        raise BridgeError("CLOCK_INVALID")
    if now_ms < fetched_at_ms:
        raise BridgeError("CLOCK_INVALID")

    snapshot = validate_jwks_snapshot(
        trust,
        jwks,
        fetched_at_ms=fetched_at_ms,
        previous=previous,
    )
    if now_ms >= snapshot.hard_expires_at_ms:
        raise BridgeError("JWKS_HARD_EXPIRED")

    if type(jwks) is not dict or type(jwks.get("keys")) is not list:
        # validate_jwks_snapshot should already have rejected this. Keep the bridge fail-closed.
        raise BridgeError("JWKS_BRIDGE_INVALID")
    raw_by_kid = {
        raw.get("kid"): raw
        for raw in jwks["keys"]
        if type(raw) is dict and type(raw.get("kid")) is str
    }

    public_keys: dict[str, rsa.RSAPublicKey] = {}
    for kid, trusted in snapshot.keys.items():
        raw = raw_by_kid.get(kid)
        if type(raw) is not dict or raw.get("kty") != "RSA":
            raise BridgeError("JWKS_SNAPSHOT_MISMATCH")
        try:
            n = _b64u_int(raw.get("n"))
            e = _b64u_int(raw.get("e"))
            fingerprint = _fingerprint(raw)
        except (KeyError, UnicodeEncodeError):
            raise BridgeError("JWKS_BRIDGE_INVALID") from None
        if (
            fingerprint != trusted.fingerprint
            or n.bit_length() != trusted.modulus_bits
            or e != trusted.exponent
        ):
            raise BridgeError("JWKS_SNAPSHOT_MISMATCH")
        try:
            key = rsa.RSAPublicNumbers(e, n).public_key()
        except ValueError:
            raise BridgeError("JWKS_BRIDGE_INVALID") from None
        if key.key_size != trusted.modulus_bits:
            raise BridgeError("JWKS_SNAPSHOT_MISMATCH")
        public_keys[kid] = key

    if set(public_keys) != set(snapshot.keys):
        raise BridgeError("JWKS_SNAPSHOT_MISMATCH")

    try:
        config = Config(
            issuer=trust.issuer,
            audience=trust.audience,
            key_set_version=snapshot.key_set_version,
            keys=public_keys,
            max_lifetime_seconds=max_lifetime_seconds,
        )
    except ValueError:
        raise BridgeError("BOUNDARY_CONFIG_INVALID") from None
    return BoundaryTrustBundle(snapshot=snapshot, config=config)
