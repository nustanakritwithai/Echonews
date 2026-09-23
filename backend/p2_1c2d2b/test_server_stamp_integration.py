from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import sys
import time
import unittest
from uuid import uuid4

import jwt
import psycopg
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "p2_1c2b1"))
sys.path.insert(0, str(HERE.parent / "p2_1c2c3"))
from identity_boundary import AuthorizationStamp, Boundary, BoundaryError, Config  # noqa:E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa:E402

ISSUER = "https://issuer.fixture.invalid/echo"
AUD = "echo-commands-fixture"
REQUEST_ID = "20000000-0000-4000-8000-000000000001"
ASSESSMENT_ID = "30000000-0000-4000-8000-000000000001"


def body(command="CREATE_VOICE_DRAFT", extra_top=None, extra_payload=None):
    if command == "CREATE_VOICE_DRAFT":
        payload = {"text": "server owned stamp fixture"}
    else:
        payload = {"assessment_id": ASSESSMENT_ID, "expected_revision": 1,
                   "decision": "ACCEPTED", "rationale": "fixture review"}
    if extra_payload:
        payload.update(extra_payload)
    result = {"request_id": REQUEST_ID, "command": command, "payload": payload}
    if extra_top:
        result.update(extra_top)
    return json.dumps(result).encode()


class ServerStampIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get("ECHO_DISPOSABLE_PG") != "YES"
                or os.environ.get("PGDATABASE") != "echo_server_stamp_test"
                or os.environ.get("PGHOST") not in ("127.0.0.1", "localhost")):
            raise RuntimeError("refusing test outside disposable loopback DB")
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, "fixture-keyset-v1", {"fixture-key": cls.private_key.public_key()})
        cls.adapter = PostgresRegistryAdapter(lambda: psycopg.connect())
        cls.boundary = Boundary(cls.config, resolve_binding=cls.adapter.resolve_binding)

    def setUp(self):
        self.subject = "user-" + uuid4().hex
        self.jti = "session-" + uuid4().hex
        self.principal_id, self.actor_id, self.source_id = uuid4(), uuid4(), uuid4()
        self.now = int(time.time())
        self.iat, self.nbf, self.exp = self.now - 3, self.now - 2, self.now + 120
        self.session_exp = self.now + 90
        self.session_key = derive_session_key(ISSUER, self.jti)
        self._provision(writer=True, reviewer=False)

    def db(self, sql, params=()):
        with psycopg.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql, params)
                return cursor.fetchone() if cursor.description else None

    def _provision(self, *, writer, reviewer):
        with psycopg.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Stamp fixture',clock_timestamp())", (self.actor_id,))
                cursor.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())", (self.source_id,))
                cursor.execute("""INSERT INTO echo_identity.principals
                    (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                    VALUES(%s,%s,%s,%s,%s,true,%s,%s,1)""",
                    (self.principal_id, ISSUER, self.subject, self.actor_id, self.source_id, writer, reviewer))
                cursor.execute("""INSERT INTO echo_identity.sessions
                    (session_key,principal_id,auth_version,issued_at,expires_at)
                    VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))""",
                    (self.session_key, self.principal_id, self.iat, self.session_exp))

    def token(self, extra=None):
        claims = {"iss": ISSUER, "aud": AUD, "sub": self.subject, "iat": self.iat,
                  "nbf": self.nbf, "exp": self.exp, "jti": self.jti}
        if extra:
            claims.update(extra)
        return jwt.encode(claims, self.private_key, algorithm="RS256",
                          headers={"kid": "fixture-key", "typ": "at+jwt"})

    def bind(self, raw=None, token=None):
        return self.boundary.bind("Bearer " + (token or self.token()), raw or body())

    def assert_boundary_denied(self, raw, code="INVALID_COMMAND"):
        with self.assertRaises(BoundaryError) as ctx:
            self.bind(raw)
        self.assertEqual(ctx.exception.code, code)

    def run_fence(self, stamp: AuthorizationStamp):
        with psycopg.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET ROLE echo_private_draft_runtime")
                cursor.execute("""SELECT echo_identity.runtime_private_draft_fence(
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", stamp.private_draft_fence_args())

    def test_01_stamp_is_built_from_verified_registry_tuple(self):
        intent = self.bind()
        stamp = intent.authorization_stamp
        self.assertIsInstance(stamp, AuthorizationStamp)
        self.assertEqual(stamp.principal_id, self.principal_id)
        self.assertEqual(stamp.actor_id, self.actor_id)
        self.assertEqual(stamp.source_id, self.source_id)
        self.assertEqual(stamp.session_key, self.session_key)
        self.assertEqual(stamp.auth_version, 1)
        self.assertEqual(stamp.capability, "voice:draft:create")
        self.assertEqual(stamp.token_issued_ms, self.iat * 1000)
        self.assertEqual(stamp.token_not_before_ms, self.nbf * 1000)
        self.assertEqual(stamp.token_expires_ms, self.exp * 1000)
        self.assertFalse(intent.ready_for_execution)

    def test_02_client_cannot_supply_top_level_authorization_stamp(self):
        self.assert_boundary_denied(body(extra_top={"authorization_stamp": {"actor_id": str(uuid4())}}))

    def test_03_client_cannot_supply_nested_authority_tuple(self):
        for key, value in [("principal_id", str(uuid4())), ("session_key", "f"*64),
                           ("actor_id", str(uuid4())), ("source_id", str(uuid4())),
                           ("auth_version", 99), ("token_expires_ms", self.exp*1000)]:
            with self.subTest(key=key):
                self.assert_boundary_denied(body(extra_payload={key: value}))

    def test_04_signed_actor_role_hints_do_not_override_stamp(self):
        fake_actor, fake_source = uuid4(), uuid4()
        stamp = self.bind(token=self.token({"actor_id": str(fake_actor), "source_id": str(fake_source),
                                            "role": "admin", "scope": "*"})).authorization_stamp
        self.assertEqual(stamp.actor_id, self.actor_id)
        self.assertEqual(stamp.source_id, self.source_id)
        self.assertEqual(stamp.principal_id, self.principal_id)

    def test_05_stamp_and_bound_intent_are_frozen_and_repr_hides_lookup_identity(self):
        intent = self.bind(); stamp = intent.authorization_stamp
        with self.assertRaises(dataclasses.FrozenInstanceError): stamp.actor_id = uuid4()
        with self.assertRaises(dataclasses.FrozenInstanceError): intent.authorization_stamp = None
        rendered = repr(intent) + repr(stamp)
        self.assertNotIn(self.subject, rendered)
        self.assertNotIn(self.session_key, rendered)

    def test_06_server_stamp_tuple_calls_least_privilege_runtime_fence(self):
        self.run_fence(self.bind().authorization_stamp)

    def test_07_forged_server_tuple_is_rejected_by_final_database_fence(self):
        original = self.bind().authorization_stamp
        for field in ("principal_id", "actor_id", "source_id"):
            with self.subTest(field=field):
                forged = dataclasses.replace(original, **{field: uuid4()})
                with self.assertRaises(psycopg.errors.InsufficientPrivilege): self.run_fence(forged)
        forged_version = dataclasses.replace(original, auth_version=77)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege): self.run_fence(forged_version)

    def test_08_committed_session_revoke_invalidates_existing_stamp_at_fence(self):
        stamp = self.bind().authorization_stamp
        self.db("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s", (self.session_key,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege): self.run_fence(stamp)

    def test_09_committed_account_disable_invalidates_existing_stamp_at_fence(self):
        stamp = self.bind().authorization_stamp
        self.db("UPDATE echo_identity.principals SET enabled=false,auth_version=2 WHERE principal_id=%s", (self.principal_id,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege): self.run_fence(stamp)

    def test_10_committed_role_version_change_invalidates_existing_stamp(self):
        stamp = self.bind().authorization_stamp
        self.db("UPDATE echo_identity.principals SET writer_enabled=false,auth_version=2 WHERE principal_id=%s", (self.principal_id,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege): self.run_fence(stamp)

    def test_11_review_stamp_cannot_be_converted_to_private_draft_fence_args(self):
        self.db("UPDATE echo_identity.principals SET reviewer_enabled=true,auth_version=2 WHERE principal_id=%s", (self.principal_id,))
        review_jti = "review-" + uuid4().hex
        review_key = derive_session_key(ISSUER, review_jti)
        self.db("""INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
                   VALUES(%s,%s,2,to_timestamp(%s),to_timestamp(%s))""",
                (review_key, self.principal_id, self.iat, self.session_exp))
        old = self.jti; self.jti = review_jti
        try:
            stamp = self.bind(body("REVIEW_EVIDENCE_RELATION"), self.token()).authorization_stamp
        finally:
            self.jti = old
        self.assertEqual(stamp.capability, "assessment:review")
        with self.assertRaises(ValueError): stamp.private_draft_fence_args()

    def test_12_legacy_non_durable_binding_never_gets_db_stamp(self):
        from identity_boundary import ActorBinding
        binding = ActorBinding(ISSUER, self.subject, self.actor_id, "HUMAN",
                               frozenset({"voice:draft:create"}), 1, True)
        legacy = Boundary(self.config, lambda *_: binding, lambda *_: False)
        result = legacy.bind("Bearer " + self.token(), body())
        self.assertIsNone(result.authorization_stamp)
        self.assertFalse(result.ready_for_execution)


if __name__ == "__main__":
    unittest.main(verbosity=2)
