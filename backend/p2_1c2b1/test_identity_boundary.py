"""Real RSA/JWT checks with ephemeral fixture keys and a frozen test clock.
No production keys, users, tokens, provider, network, database or web login.
"""
from __future__ import annotations

import base64
import dataclasses
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from identity_boundary import (
    ActorBinding, Boundary, BoundaryError, Config, DraftIntent, ReviewIntent,
)

NOW = 2_000_000_000
ISSUER = "https://issuer.fixture.invalid/echo"
AUD = "echo-commands-fixture"
WRITER_ID = UUID("10000000-0000-0000-0000-000000000001")
REVIEWER_ID = UUID("10000000-0000-0000-0000-000000000002")
AI_ID = UUID("10000000-0000-0000-0000-000000000003")
REQUEST_ID = "20000000-0000-0000-0000-000000000001"
ASSESSMENT_ID = "30000000-0000-0000-0000-000000000001"


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime.fromtimestamp(NOW, tz or timezone.utc)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def draft() -> dict:
    return {"request_id": REQUEST_ID, "command": "CREATE_VOICE_DRAFT",
            "payload": {"text": "ฉันเห็นน้ำบริเวณจุด A\nยังไม่ทราบจุดอื่น"}}


def review() -> dict:
    return {"request_id": REQUEST_ID, "command": "REVIEW_EVIDENCE_RELATION",
            "payload": {"assessment_id": ASSESSMENT_ID, "expected_revision": 1,
                        "decision": "ACCEPTED", "rationale": "Fixture preflight only"}}


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.time_patch = patch("jwt.api_jwt.datetime", FrozenDatetime)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        self.lookup_calls = []
        self.revoked = set()
        self.bindings = {
            (ISSUER, "writer"): ActorBinding(ISSUER, "writer", WRITER_ID, "HUMAN",
                frozenset({"voice:draft:create"}), 1, True),
            (ISSUER, "reviewer"): ActorBinding(ISSUER, "reviewer", REVIEWER_ID, "HUMAN",
                frozenset({"voice:draft:create", "assessment:review"}), 7, True),
            (ISSUER, "ai"): ActorBinding(ISSUER, "ai", AI_ID, "AI",
                frozenset({"voice:draft:create", "assessment:review"}), 2, True),
        }
        self.keys = {"fixture-key": self.key.public_key()}
        self.config = Config(ISSUER, AUD, "fixture-keyset-v1", self.keys)
        self.boundary = Boundary(self.config, self.lookup, self.check_revocation)

    def lookup(self, issuer, subject):
        self.lookup_calls.append((issuer, subject))
        return self.bindings.get((issuer, subject))

    def check_revocation(self, issuer, jti):
        return (issuer, jti) in self.revoked

    def claims(self, **overrides):
        return {"iss": ISSUER, "aud": AUD, "sub": "writer", "iat": NOW - 10,
                "nbf": NOW - 10, "exp": NOW + 200, "jti": "fixture-session", **overrides}

    def token(self, claims=None, headers=None, key=None):
        return jwt.encode(claims if claims is not None else self.claims(), key or self.key,
                          algorithm="RS256", headers={"kid": "fixture-key", "typ": "at+jwt", **(headers or {})})

    def raw_signed(self, payload: str, header: str | None = None):
        head = header or '{"kid":"fixture-key","typ":"at+jwt","alg":"RS256"}'
        signed = (b64(head.encode()) + "." + b64(payload.encode())).encode("ascii")
        signature = self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        return signed.decode() + "." + b64(signature)

    def bind(self, body=None, token=None):
        raw = json.dumps(draft() if body is None else body, ensure_ascii=False).encode()
        return self.boundary.bind("Bearer " + (token or self.token()), raw)

    def reject(self, call, code):
        with self.assertRaises(BoundaryError) as ctx:
            call()
        self.assertEqual(str(ctx.exception), code)
        self.assertEqual(ctx.exception.code, code)

    def test_writer_is_bound_from_registry_not_request(self):
        result = self.bind()
        self.assertEqual(result.actor_id, WRITER_ID)
        self.assertEqual(result.binding_revision, 1)
        self.assertIsInstance(result.payload, DraftIntent)
        self.assertFalse(result.ready_for_execution)

    def test_reviewer_capability_only_not_execution_authorization(self):
        result = self.bind(review(), self.token(self.claims(sub="reviewer")))
        self.assertEqual(result.actor_id, REVIEWER_ID)
        self.assertEqual(result.binding_revision, 7)
        self.assertIsInstance(result.payload, ReviewIntent)
        self.assertFalse(result.ready_for_execution)

    def test_signed_role_actor_email_claims_do_not_grant_privileges(self):
        t = self.token(self.claims(actor_id=str(REVIEWER_ID), role="admin",
                   email="reviewer@fixture.invalid", scope="assessment:review",
                   app_metadata={"roles": ["reviewer"]}))
        self.assertEqual(self.bind(token=t).actor_id, WRITER_ID)
        self.reject(lambda: self.bind(review(), t), "CAPABILITY_REQUIRED")

    def test_writer_cannot_request_review_capability(self):
        self.reject(lambda: self.bind(review()), "CAPABILITY_REQUIRED")

    def test_ai_cannot_be_treated_as_human_reviewer_even_with_capability(self):
        self.reject(lambda: self.bind(review(), self.token(self.claims(sub="ai"))), "HUMAN_REVIEW_REQUIRED")

    def test_disabled_binding_denies_still_valid_token(self):
        old = self.bindings[(ISSUER, "writer")]
        self.bindings[(ISSUER, "writer")] = dataclasses.replace(old, enabled=False)
        self.reject(lambda: self.bind(), "IDENTITY_REJECTED")

    def test_binding_revocation_takes_effect_on_next_call_no_local_grant_cache(self):
        self.bind()
        old = self.bindings[(ISSUER, "writer")]
        self.bindings[(ISSUER, "writer")] = dataclasses.replace(old, capabilities=frozenset(), revision=2)
        self.reject(lambda: self.bind(), "CAPABILITY_REQUIRED")
        self.assertEqual(len(self.lookup_calls), 2)

    def test_unmapped_subject_is_not_auto_provisioned(self):
        self.reject(lambda: self.bind(token=self.token(self.claims(sub="unmapped"))), "IDENTITY_REJECTED")

    def test_same_subject_on_other_issuer_is_not_same_identity(self):
        self.reject(lambda: self.bind(token=self.token(self.claims(iss="https://other.fixture.invalid"))), "IDENTITY_REJECTED")
        self.assertEqual(self.lookup_calls, [])

    def test_wrong_registry_pair_fails_closed(self):
        self.bindings[(ISSUER, "writer")] = self.bindings[(ISSUER, "reviewer")]
        self.reject(lambda: self.bind(), "IDENTITY_REJECTED")

    def test_token_cutoff_rejects_older_token(self):
        old = self.bindings[(ISSUER, "writer")]
        self.bindings[(ISSUER, "writer")] = dataclasses.replace(old, tokens_valid_from=NOW - 9)
        self.reject(lambda: self.bind(), "IDENTITY_REJECTED")

    def test_token_cutoff_is_inclusive(self):
        old = self.bindings[(ISSUER, "writer")]
        self.bindings[(ISSUER, "writer")] = dataclasses.replace(old, tokens_valid_from=NOW - 10)
        self.assertEqual(self.bind().actor_id, WRITER_ID)

    def test_jti_revocation_rechecked(self):
        t = self.token()
        self.bind(token=t)
        self.revoked.add((ISSUER, "fixture-session"))
        self.reject(lambda: self.bind(token=t), "IDENTITY_REJECTED")

    def test_registry_outage_never_defaults_to_writer(self):
        def offline(*_):
            raise RuntimeError("potential-secret-in-adapter-exception")
        self.boundary = Boundary(self.config, offline, self.check_revocation)
        self.reject(lambda: self.bind(), "IDENTITY_BACKEND_UNAVAILABLE")

    def test_revocation_outage_never_defaults_to_not_revoked(self):
        def offline(*_):
            raise TimeoutError("potential-secret")
        self.boundary = Boundary(self.config, self.lookup, offline)
        self.reject(lambda: self.bind(), "IDENTITY_BACKEND_UNAVAILABLE")
        self.assertEqual(self.lookup_calls, [])

    def test_malformed_revocation_adapter_result_denied(self):
        self.boundary = Boundary(self.config, self.lookup, lambda *_: "false")
        self.reject(lambda: self.bind(), "IDENTITY_BACKEND_UNAVAILABLE")

    def test_wrong_signature_does_not_query_identity_registry(self):
        self.reject(lambda: self.bind(token=self.token(key=self.wrong_key)), "IDENTITY_REJECTED")
        self.assertEqual(self.lookup_calls, [])

    def test_tampering_payload_breaks_signature(self):
        pieces = self.token().split(".")
        pieces[1] = b64(json.dumps(self.claims(sub="reviewer")).encode())
        self.reject(lambda: self.bind(token=".".join(pieces)), "IDENTITY_REJECTED")

    def test_hmac_rsa_confusion_rejected(self):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        key = self.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        head = {"alg": "HS256", "kid": "fixture-key", "typ": "at+jwt"}
        msg = (b64(json.dumps(head).encode()) + "." + b64(json.dumps(self.claims()).encode())).encode()
        t = msg.decode() + "." + b64(hmac.new(key, msg, hashlib.sha256).digest())
        self.reject(lambda: self.bind(token=t), "IDENTITY_REJECTED")

    def test_alg_none_rejected(self):
        t = b64(b'{"alg":"none","kid":"fixture-key","typ":"at+jwt"}') + "." + b64(json.dumps(self.claims()).encode()) + "."
        self.reject(lambda: self.bind(token=t), "IDENTITY_REJECTED")

    def test_expiration_boundary_rejected(self):
        self.reject(lambda: self.bind(token=self.token(self.claims(exp=NOW))), "IDENTITY_REJECTED")

    def test_integer_lifetime_limit_inclusive(self):
        t = self.token(self.claims(iat=NOW-10, nbf=NOW-10, exp=NOW+890))
        self.assertFalse(self.bind(token=t).ready_for_execution)

    def test_token_header_is_not_used_for_key_downloads(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
            self.bind()
            self.reject(lambda: self.bind(token=self.token(headers={"jku": "http://127.0.0.1/keys"})), "IDENTITY_REJECTED")

    def test_duplicate_subject_in_signed_payload_rejected(self):
        raw = json.dumps(self.claims())[:-1] + ',"sub":"reviewer"}'
        self.reject(lambda: self.bind(token=self.raw_signed(raw)), "IDENTITY_REJECTED")

    def test_duplicate_algorithm_header_rejected(self):
        hdr = '{"alg":"RS256","kid":"fixture-key","typ":"at+jwt","alg":"RS256"}'
        self.reject(lambda: self.bind(token=self.raw_signed(json.dumps(self.claims()), hdr)), "IDENTITY_REJECTED")

    def test_json_duplicate_command_member_rejected(self):
        raw = json.dumps(draft())[:-1] + ',"command":"REVIEW_EVIDENCE_RELATION"}'
        self.reject(lambda: self.boundary.bind("Bearer " + self.token(), raw.encode()), "INVALID_COMMAND")

    def test_unicode_escape_duplicate_identity_member_rejected(self):
        raw = json.dumps(draft())[:-1] + ',"actor_id":"x","\\u0061ctor_id":"y"}'
        self.reject(lambda: self.boundary.bind("Bearer " + self.token(), raw.encode()), "INVALID_COMMAND")

    def test_nan_even_in_unused_signed_claim_rejected(self):
        raw = json.dumps(self.claims())[:-1] + ',"ignored":NaN}'
        self.reject(lambda: self.bind(token=self.raw_signed(raw)), "IDENTITY_REJECTED")

    def test_lone_surrogate_text_rejected(self):
        body = draft()
        body["payload"]["text"] = "\ud800"
        raw = json.dumps(body, ensure_ascii=True).encode()
        self.reject(lambda: self.boundary.bind("Bearer " + self.token(), raw), "INVALID_COMMAND")

    def test_unicode_codepoint_limit_and_original_text_preserved(self):
        body = draft()
        body["payload"]["text"] = "🌊" * 2000
        self.assertEqual(self.bind(body).payload.text, body["payload"]["text"])
        body["payload"]["text"] += "!"
        self.reject(lambda: self.bind(body), "INVALID_COMMAND")

    def test_html_text_is_data_not_an_identity_instruction(self):
        body = draft()
        body["payload"]["text"] = '<script>actor_id="reviewer"</script>'
        result = self.bind(body)
        self.assertEqual(result.actor_id, WRITER_ID)
        self.assertEqual(result.payload.text, body["payload"]["text"])

    def test_bound_intent_repr_does_not_include_token_or_voice_content(self):
        token = self.token()
        result = self.bind(token=token)
        self.assertNotIn(token, repr(result))
        self.assertNotIn(draft()["payload"]["text"], repr(result))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.actor_id = REVIEWER_ID

    def test_key_configuration_copied_not_live_client_mutable(self):
        self.keys["fixture-key"] = self.wrong_key.public_key()
        self.assertEqual(self.bind().actor_id, WRITER_ID)

    def test_explicit_new_keyset_removes_old_key_no_unbounded_cache(self):
        config = Config(ISSUER, AUD, "fixture-keyset-v2", {"next": self.wrong_key.public_key()})
        self.boundary = Boundary(config, self.lookup, self.check_revocation)
        self.reject(lambda: self.bind(), "IDENTITY_REJECTED")

    def test_no_default_keys_or_accept_all_adapter(self):
        with self.assertRaises(ValueError):
            Config(ISSUER, AUD, "v1", {})
        with self.assertRaises(ValueError):
            Boundary(self.config, self.lookup, None)

    def test_hmac_and_private_keys_cannot_be_verifier_configuration(self):
        for key in ("secret", self.key, b"not-a-public-key"):
            with self.assertRaises(ValueError):
                Config(ISSUER, AUD, "v1", {"fixture-key": key})

    def test_weak_rsa_key_rejected_by_profile(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaises(ValueError):
            Config(ISSUER, AUD, "v1", {"fixture-key": key.public_key()})

    def test_same_bearer_can_repeat_preflight_not_idempotent_db_execution(self):
        t = self.token()
        self.assertEqual(self.bind(token=t), self.bind(token=t))
        self.assertFalse(self.bind(token=t).ready_for_execution)

    def test_malformed_registry_kind_is_a_denial_not_uncaught_type_error(self):
        old = self.bindings[(ISSUER, "writer")]
        self.bindings[(ISSUER, "writer")] = dataclasses.replace(old, actor_kind=["HUMAN"])
        self.reject(lambda: self.bind(), "IDENTITY_REJECTED")

    def test_malformed_registry_capability_type_is_rejected(self):
        old = self.bindings[(ISSUER, "writer")]
        self.bindings[(ISSUER, "writer")] = dataclasses.replace(old, capabilities=["voice:draft:create"])
        self.reject(lambda: self.bind(), "IDENTITY_REJECTED")

    def test_json_numeric_overflow_rejected_even_in_unused_signed_claim(self):
        raw = json.dumps(self.claims())[:-1] + ',"ignored":1e999}'
        self.reject(lambda: self.bind(token=self.raw_signed(raw)), "IDENTITY_REJECTED")

    def test_no_repository_fixture_private_keys_written(self):
        base = Path(__file__).parent
        self.assertEqual(list(base.glob("*.pem")), [])
        self.assertEqual(list(base.glob("*.key")), [])


# Each generated method is one independently counted adversarial case.
def _token_case(overrides=None, headers=None, missing=None):
    def run(self):
        claims = self.claims(**(overrides or {}))
        if missing:
            del claims[missing]
        self.reject(lambda: self.bind(token=self.token(claims, headers)), "IDENTITY_REJECTED")
    return run


TOKEN_CASES = {
    "expired": {"overrides": {"exp": NOW - 1}},
    "future_nbf": {"overrides": {"nbf": NOW + 10}},
    "future_iat": {"overrides": {"iat": NOW + 10}},
    "overlong_lifetime": {"overrides": {"exp": NOW + 891}},
    "wrong_audience": {"overrides": {"aud": "some-other-api"}},
    "multiple_audiences": {"overrides": {"aud": [AUD, "other"]}},
    "issuer_prefix": {"overrides": {"iss": ISSUER[:-1]}},
    "empty_subject": {"overrides": {"sub": ""}},
    "numeric_subject": {"overrides": {"sub": 10}},
    "empty_jti": {"overrides": {"jti": ""}},
    "float_exp": {"overrides": {"exp": float(NOW + 200)}},
    "string_exp": {"overrides": {"exp": str(NOW + 200)}},
    "boolean_iat": {"overrides": {"iat": True}},
    "inverted_iat_nbf": {"overrides": {"iat": NOW - 5, "nbf": NOW - 10}},
    "id_token_type": {"headers": {"typ": "JWT"}},
    "unknown_kid": {"headers": {"kid": "unregistered"}},
    "kid_path_injection": {"headers": {"kid": "../../keys"}},
    "embedded_key": {"headers": {"jwk": {"kty": "RSA"}}},
    "key_download_url": {"headers": {"x5u": "https://attacker.invalid/key"}},
    "critical_extension": {"headers": {"crit": ["b64"]}},
}
for claim_name in ("iss", "aud", "sub", "iat", "nbf", "exp", "jti"):
    TOKEN_CASES["missing_" + claim_name] = {"missing": claim_name}
for label, kwargs in TOKEN_CASES.items():
    setattr(BoundaryTests, "test_token_" + label, _token_case(**kwargs))


def _body_case(path, value):
    def run(self):
        body = draft()
        target = body if path == "top" else body["payload"]
        key, val = value
        target[key] = val
        self.reject(lambda: self.bind(body), "INVALID_COMMAND")
    return run


BODY_CASES = {
    "actor_id_top": ("top", ("actor_id", str(REVIEWER_ID))),
    "author_id_top": ("top", ("author_id", str(REVIEWER_ID))),
    "reviewer_id_top": ("top", ("reviewer_id", str(REVIEWER_ID))),
    "principal_top": ("top", ("principal", {"actor_id": str(REVIEWER_ID)})),
    "roles_top": ("top", ("roles", ["admin"])),
    "actor_id_nested": ("payload", ("actor_id", str(REVIEWER_ID))),
    "source_id_nested": ("payload", ("source_id", ASSESSMENT_ID)),
    "public_visibility_nested": ("payload", ("visibility", "PUBLIC")),
    "client_clock": ("payload", ("recorded_at", "2099-01-01T00:00:00Z")),
    "empty_text": ("payload", ("text", "   ")),
    "object_text": ("payload", ("text", {"actor_id": "reviewer"})),
    "nul_text": ("payload", ("text", "a\x00b")),
    "noncanonical_request_id": ("top", ("request_id", "not-a-uuid")),
    "nil_request_id": ("top", ("request_id", str(UUID(int=0)))),
    "publish_command": ("top", ("command", "PUBLISH_ROOM")),
}
for label, args in BODY_CASES.items():
    setattr(BoundaryTests, "test_request_" + label, _body_case(*args))


def _header_case(header):
    def run(self):
        self.reject(lambda: self.boundary.bind(header, json.dumps(draft()).encode()), "IDENTITY_REJECTED")
    return run


for label, value in {"none": None, "empty": "", "basic": "Basic x",
                     "raw_jwt_missing_prefix": "a.b.c", "header_injection": "Bearer x\r\nX-Actor: admin",
                     "oversize": "Bearer " + "x" * 8193, "garbage": "Bearer .."}.items():
    setattr(BoundaryTests, "test_auth_header_" + label, _header_case(value))


def _malformed_body(raw):
    def run(self):
        self.reject(lambda: self.boundary.bind("Bearer " + self.token(), raw), "INVALID_COMMAND")
    return run


for label, raw in {"array": b"[]", "null": b"null", "empty": b"", "bad_utf8": b"\xff",
                   "oversize": b" " * 16385, "already_parsed": draft(),
                   "deeply_nested": b'{"x":' + b'['*1000 + b']'*1000 + b'}'}.items():
    setattr(BoundaryTests, "test_body_" + label, _malformed_body(raw))


def _review_case(field_name, value):
    def run(self):
        body = review()
        body["payload"][field_name] = value
        self.reject(lambda: self.bind(body, self.token(self.claims(sub="reviewer"))), "INVALID_COMMAND")
    return run


for label, field_name, value in [("bool_revision", "expected_revision", True),
        ("zero_revision", "expected_revision", 0), ("text_revision", "expected_revision", "1"),
        ("fake_assessor", "assessor_id", str(REVIEWER_ID)),
        ("missing_reason", "rationale", ""), ("unknown_decision", "decision", "VERIFIED_TRUE")]:
    setattr(BoundaryTests, "test_review_" + label, _review_case(field_name, value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
