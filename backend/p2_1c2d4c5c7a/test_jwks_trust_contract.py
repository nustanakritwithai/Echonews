from __future__ import annotations

import base64
import unittest

from jwks_trust_contract import (
    ContractError,
    IssuerTrust,
    KeyDecision,
    decide_header_key,
    validate_jwks_snapshot,
)


NOW = 2_000_000
TRUST = IssuerTrust(
    issuer="https://issuer.example.com",
    jwks_uri="https://issuer.example.com/.well-known/jwks.json",
    audience="echo-news-api",
    trust_epoch=1,
)


def b64u_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def rsa_key(kid="k1", *, modulus=(1 << 2047) + 12345, exponent=65537, **extra):
    key = {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": b64u_int(modulus), "e": b64u_int(exponent)}
    key.update(extra)
    return key


def header(kid="k1", **extra):
    value = {"alg": "RS256", "typ": "at+jwt", "kid": kid}
    value.update(extra)
    return value


class JwksTrustContractTests(unittest.TestCase):
    def test_01_trust_requires_pinned_https_locations(self):
        bad = (
            dict(issuer="http://issuer.example.com", jwks_uri=TRUST.jwks_uri),
            dict(issuer=TRUST.issuer, jwks_uri="http://issuer.example.com/jwks"),
            dict(issuer="https://user@issuer.example.com", jwks_uri=TRUST.jwks_uri),
            dict(issuer="https://issuer.example.com?tenant=x", jwks_uri=TRUST.jwks_uri),
        )
        for overrides in bad:
            with self.subTest(overrides=overrides), self.assertRaises(ContractError):
                IssuerTrust(audience="echo-news-api", trust_epoch=1, **overrides)

    def test_02_valid_snapshot_derives_stable_key_set_version(self):
        a = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        b = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW + 1)
        self.assertEqual(a.key_set_version, b.key_set_version)
        self.assertEqual(set(a.keys), {"k1"})

    def test_03_unrelated_non_rsa_key_is_ignored_not_selected(self):
        ec = {"kty": "EC", "kid": "ec1", "alg": "ES256", "use": "sig", "crv": "P-256", "x": "a", "y": "b"}
        snap = validate_jwks_snapshot(TRUST, {"keys": [ec, rsa_key()]}, fetched_at_ms=NOW)
        self.assertEqual(set(snap.keys), {"k1"})

    def test_04_duplicate_kid_rejects_entire_snapshot(self):
        with self.assertRaisesRegex(ContractError, "JWKS_DUPLICATE_OR_INVALID_KID"):
            validate_jwks_snapshot(TRUST, {"keys": [rsa_key(), rsa_key()]}, fetched_at_ms=NOW)

    def test_05_private_rsa_material_rejects_snapshot(self):
        with self.assertRaisesRegex(ContractError, "JWKS_PRIVATE_KEY_MATERIAL"):
            validate_jwks_snapshot(TRUST, {"keys": [rsa_key(d="secret")]}, fetched_at_ms=NOW)

    def test_06_weak_rsa_modulus_rejects_snapshot(self):
        with self.assertRaisesRegex(ContractError, "JWKS_WEAK_RSA_KEY"):
            validate_jwks_snapshot(TRUST, {"keys": [rsa_key(modulus=(1 << 1023) + 3)]}, fetched_at_ms=NOW)

    def test_07_weak_or_even_exponent_rejects_snapshot(self):
        for exponent in (3, 65536):
            with self.subTest(exponent=exponent), self.assertRaisesRegex(ContractError, "JWKS_WEAK_RSA_KEY"):
                validate_jwks_snapshot(TRUST, {"keys": [rsa_key(exponent=exponent)]}, fetched_at_ms=NOW)

    def test_08_non_signing_or_wrong_algorithm_key_is_not_eligible(self):
        cases = (
            rsa_key(alg="RS512"),
            rsa_key(use="enc"),
            rsa_key(key_ops=["encrypt"]),
        )
        for key in cases:
            with self.subTest(key=key), self.assertRaisesRegex(ContractError, "JWKS_NO_ELIGIBLE_KEYS"):
                validate_jwks_snapshot(TRUST, {"keys": [key]}, fetched_at_ms=NOW)

    def test_09_same_kid_cannot_change_key_material_inside_trust_epoch(self):
        old = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        changed = rsa_key(modulus=(1 << 2047) + 99999)
        with self.assertRaisesRegex(ContractError, "JWKS_KID_KEY_SUBSTITUTION"):
            validate_jwks_snapshot(TRUST, {"keys": [changed]}, fetched_at_ms=NOW + 1, previous=old)

    def test_10_new_kid_rotation_and_old_key_overlap_are_allowed(self):
        old = validate_jwks_snapshot(TRUST, {"keys": [rsa_key("old")]}, fetched_at_ms=NOW)
        rotated = validate_jwks_snapshot(TRUST, {"keys": [rsa_key("old"), rsa_key("new", modulus=(1 << 2047) + 33333)]}, fetched_at_ms=NOW + 1, previous=old)
        self.assertEqual(set(rotated.keys), {"old", "new"})

    def test_11_old_key_may_be_removed_in_fresh_snapshot(self):
        old = validate_jwks_snapshot(TRUST, {"keys": [rsa_key("old")]}, fetched_at_ms=NOW)
        fresh = validate_jwks_snapshot(TRUST, {"keys": [rsa_key("new", modulus=(1 << 2047) + 33333)]}, fetched_at_ms=NOW + 1, previous=old)
        self.assertNotIn("old", fresh.keys)

    def test_12_exact_header_profile_rejects_jku_x5u_jwk_and_alg_confusion(self):
        snap = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        cases = (
            header(jku="https://attacker.invalid/jwks"),
            header(x5u="https://attacker.invalid/cert"),
            header(jwk={"kty": "RSA"}),
            {"alg": "HS256", "typ": "at+jwt", "kid": "k1"},
            {"alg": "RS256", "typ": "JWT", "kid": "k1"},
        )
        for h in cases:
            with self.subTest(header=h):
                self.assertEqual(decide_header_key(TRUST, snap, h, now_ms=NOW).decision, KeyDecision.REJECT)

    def test_13_no_snapshot_requires_refresh(self):
        r = decide_header_key(TRUST, None, header(), now_ms=NOW)
        self.assertEqual(r.decision, KeyDecision.REFRESH_REQUIRED)
        self.assertEqual(r.reason, "NO_JWKS_SNAPSHOT")

    def test_14_unknown_kid_requires_refresh_even_when_cache_is_fresh(self):
        snap = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        r = decide_header_key(TRUST, snap, header("new-kid"), now_ms=NOW + 10)
        self.assertEqual(r.decision, KeyDecision.REFRESH_REQUIRED)
        self.assertEqual(r.reason, "UNKNOWN_KID")

    def test_15_known_kid_uses_fresh_cache(self):
        snap = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        r = decide_header_key(TRUST, snap, header(), now_ms=NOW + 10)
        self.assertEqual(r.decision, KeyDecision.USE_CACHED)
        self.assertEqual(r.key_set_version, snap.key_set_version)
        self.assertEqual(r.fingerprint, snap.keys["k1"].fingerprint)

    def test_16_soft_expiry_allows_bounded_stale_use_but_requests_refresh(self):
        snap = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        r = decide_header_key(TRUST, snap, header(), now_ms=snap.soft_expires_at_ms)
        self.assertEqual(r.decision, KeyDecision.USE_CACHED_REFRESH_RECOMMENDED)
        self.assertEqual(r.reason, "JWKS_SOFT_EXPIRED")

    def test_17_hard_expiry_fails_closed_pending_refresh(self):
        snap = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        r = decide_header_key(TRUST, snap, header(), now_ms=snap.hard_expires_at_ms)
        self.assertEqual(r.decision, KeyDecision.REFRESH_REQUIRED)
        self.assertEqual(r.reason, "JWKS_HARD_EXPIRED")

    def test_18_trust_epoch_mismatch_rejects_cached_snapshot(self):
        snap = validate_jwks_snapshot(TRUST, {"keys": [rsa_key()]}, fetched_at_ms=NOW)
        epoch2 = IssuerTrust(TRUST.issuer, TRUST.jwks_uri, TRUST.audience, trust_epoch=2)
        r = decide_header_key(epoch2, snap, header(), now_ms=NOW + 1)
        self.assertEqual(r.decision, KeyDecision.REJECT)
        self.assertEqual(r.reason, "TRUST_EPOCH_MISMATCH")

    def test_19_removal_takes_effect_immediately_after_successful_refresh(self):
        old = validate_jwks_snapshot(TRUST, {"keys": [rsa_key("old")]}, fetched_at_ms=NOW)
        fresh = validate_jwks_snapshot(TRUST, {"keys": [rsa_key("new", modulus=(1 << 2047) + 33333)]}, fetched_at_ms=NOW + 100, previous=old)
        r = decide_header_key(TRUST, fresh, header("old"), now_ms=NOW + 101)
        self.assertEqual(r.decision, KeyDecision.REFRESH_REQUIRED)
        self.assertEqual(r.reason, "UNKNOWN_KID")

    def test_20_reordering_jwks_does_not_change_key_set_version(self):
        a = rsa_key("a", modulus=(1 << 2047) + 11111)
        b = rsa_key("b", modulus=(1 << 2047) + 22222)
        s1 = validate_jwks_snapshot(TRUST, {"keys": [a, b]}, fetched_at_ms=NOW)
        s2 = validate_jwks_snapshot(TRUST, {"keys": [b, a]}, fetched_at_ms=NOW + 1)
        self.assertEqual(s1.key_set_version, s2.key_set_version)


if __name__ == "__main__":
    unittest.main(verbosity=2)
