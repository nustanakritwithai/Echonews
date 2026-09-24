from __future__ import annotations

import base64
import copy
import json
import time
import unittest
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from identity_boundary import ActorBinding, Boundary, BoundaryError
from jwks_boundary_bridge import BridgeError, build_boundary_trust_bundle
from jwks_trust_contract import ContractError, IssuerTrust


def _b64u_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "key_ops": ["verify"],
        "n": _b64u_int(numbers.n),
        "e": _b64u_int(numbers.e),
    }


class JwksBoundaryBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.trust = IssuerTrust(
            issuer="https://issuer.example.test",
            jwks_uri="https://issuer.example.test/.well-known/jwks.json",
            audience="echo-news-api",
            trust_epoch=1,
        )
        cls.now_ms = 2_000_000

    def bundle(self, keys, *, previous=None, now_ms=None, fetched_at_ms=None):
        fetched = self.now_ms if fetched_at_ms is None else fetched_at_ms
        now = fetched if now_ms is None else now_ms
        return build_boundary_trust_bundle(
            self.trust,
            {"keys": keys},
            fetched_at_ms=fetched,
            now_ms=now,
            previous=previous,
        )

    def token(self, key, kid, *, extra_header=None, subject="subject-1") -> str:
        now = int(time.time())
        headers = {"kid": kid, "typ": "at+jwt"}
        if extra_header:
            headers.update(extra_header)
        return jwt.encode(
            {
                "iss": self.trust.issuer,
                "aud": self.trust.audience,
                "sub": subject,
                "iat": now - 1,
                "nbf": now - 1,
                "exp": now + 120,
                "jti": f"jti-{kid}-{subject}",
            },
            key,
            algorithm="RS256",
            headers=headers,
        )

    @staticmethod
    def binding(issuer: str, subject: str) -> ActorBinding:
        return ActorBinding(
            issuer=issuer,
            subject=subject,
            actor_id=UUID("00000000-0000-4000-8000-000000000011"),
            actor_kind="HUMAN",
            capabilities=frozenset({"voice:draft:create"}),
            revision=1,
            enabled=True,
        )

    def boundary(self, config) -> Boundary:
        return Boundary(
            config,
            lookup_binding=lambda issuer, subject: self.binding(issuer, subject),
            is_revoked=lambda issuer, jti: False,
        )

    @staticmethod
    def body() -> bytes:
        return json.dumps(
            {
                "request_id": "00000000-0000-4000-8000-000000000099",
                "command": "CREATE_VOICE_DRAFT",
                "payload": {"text": "bridge integration"},
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def test_validated_jwks_becomes_boundary_config(self):
        bundle = self.bundle([_jwk(self.old_key, "old")])
        self.assertEqual(set(bundle.config.keys), {"old"})
        self.assertEqual(bundle.config.issuer, self.trust.issuer)
        self.assertEqual(bundle.config.audience, self.trust.audience)
        self.assertEqual(bundle.config.key_set_version, bundle.snapshot.key_set_version)

    def test_boundary_accepts_token_signed_by_bridged_key(self):
        bundle = self.bundle([_jwk(self.old_key, "old")])
        bound = self.boundary(bundle.config).bind(
            "Bearer " + self.token(self.old_key, "old"), self.body()
        )
        self.assertEqual(bound.key_set_version, bundle.snapshot.key_set_version)
        self.assertEqual(bound.actor_id, UUID("00000000-0000-4000-8000-000000000011"))

    def test_overlap_rotation_accepts_old_and_new(self):
        first = self.bundle([_jwk(self.old_key, "old")])
        overlap = self.bundle(
            [_jwk(self.old_key, "old"), _jwk(self.new_key, "new")],
            previous=first.snapshot,
        )
        boundary = self.boundary(overlap.config)
        boundary.bind("Bearer " + self.token(self.old_key, "old"), self.body())
        boundary.bind("Bearer " + self.token(self.new_key, "new"), self.body())

    def test_removed_old_key_is_no_longer_authorized(self):
        first = self.bundle([_jwk(self.old_key, "old")])
        overlap = self.bundle(
            [_jwk(self.old_key, "old"), _jwk(self.new_key, "new")],
            previous=first.snapshot,
        )
        new_only = self.bundle([_jwk(self.new_key, "new")], previous=overlap.snapshot)
        with self.assertRaisesRegex(BoundaryError, "IDENTITY_REJECTED"):
            self.boundary(new_only.config).bind(
                "Bearer " + self.token(self.old_key, "old"), self.body()
            )

    def test_same_kid_substitution_stays_rejected(self):
        first = self.bundle([_jwk(self.old_key, "stable")])
        with self.assertRaisesRegex(ContractError, "JWKS_KID_KEY_SUBSTITUTION"):
            self.bundle([_jwk(self.other_key, "stable")], previous=first.snapshot)

    def test_token_supplied_jku_cannot_override_bridged_keys(self):
        bundle = self.bundle([_jwk(self.old_key, "old")])
        token = self.token(
            self.old_key,
            "old",
            extra_header={"jku": "https://attacker.invalid/jwks.json"},
        )
        with self.assertRaisesRegex(BoundaryError, "IDENTITY_REJECTED"):
            self.boundary(bundle.config).bind("Bearer " + token, self.body())

    def test_private_jwk_material_is_rejected_before_bridge(self):
        raw = _jwk(self.old_key, "old")
        raw["d"] = "AQAB"
        with self.assertRaisesRegex(ContractError, "JWKS_PRIVATE_KEY_MATERIAL"):
            self.bundle([raw])

    def test_bridge_rejects_hard_expired_snapshot(self):
        with self.assertRaisesRegex(BridgeError, "JWKS_HARD_EXPIRED"):
            self.bundle(
                [_jwk(self.old_key, "old")],
                fetched_at_ms=self.now_ms,
                now_ms=self.now_ms + self.trust.hard_ttl_ms,
            )

    def test_bridge_rejects_future_fetch_timestamp(self):
        with self.assertRaisesRegex(BridgeError, "CLOCK_INVALID"):
            self.bundle(
                [_jwk(self.old_key, "old")],
                fetched_at_ms=self.now_ms + 1,
                now_ms=self.now_ms,
            )

    def test_bridge_does_not_mutate_raw_jwks(self):
        raw = {"keys": [_jwk(self.old_key, "old"), _jwk(self.new_key, "new")]}
        before = copy.deepcopy(raw)
        build_boundary_trust_bundle(
            self.trust,
            raw,
            fetched_at_ms=self.now_ms,
            now_ms=self.now_ms,
        )
        self.assertEqual(raw, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
