"""Real RS256 + real PostgreSQL integration for P2.1c.2c.3.

Ephemeral keys and synthetic users only. No production IdP, HTTP endpoint, cookie,
refresh flow, account proof, DB write command or public publication exists here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import unittest
from uuid import UUID, uuid4

import jwt
import psycopg
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "p2_1c2b1"))
from identity_boundary import Boundary, BoundaryError, Config  # noqa: E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa: E402

ISSUER = "https://issuer.fixture.invalid/echo"
AUD = "echo-commands-fixture"
REQUEST_ID = "20000000-0000-4000-8000-000000000001"
ASSESSMENT_ID = "30000000-0000-4000-8000-000000000001"


def draft(extra=None):
    body = {"request_id": REQUEST_ID, "command": "CREATE_VOICE_DRAFT",
            "payload": {"text": "synthetic signed registry observation"}}
    if extra:
        body["payload"].update(extra)
    return json.dumps(body).encode()


def review():
    return json.dumps({"request_id": REQUEST_ID, "command": "REVIEW_EVIDENCE_RELATION",
        "payload": {"assessment_id": ASSESSMENT_ID, "expected_revision": 1,
                    "decision": "ACCEPTED", "rationale": "synthetic review"}}).encode()


class SignedRegistryIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get("ECHO_DISPOSABLE_PG") != "YES"
                or os.environ.get("PGDATABASE") != "echo_signed_registry_test"
                or os.environ.get("PGHOST") not in ("127.0.0.1", "localhost")):
            raise RuntimeError("refusing integration outside isolated loopback test database")
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, "fixture-keyset-v1", {"fixture-key": cls.key.public_key()})
        cls.connection_count = 0

        def connect():
            cls.connection_count += 1
            return psycopg.connect()

        cls.adapter = PostgresRegistryAdapter(connect)
        cls.boundary = Boundary(cls.config, resolve_binding=cls.adapter.resolve_binding)

    def setUp(self):
        self.subject = "user-" + uuid4().hex
        self.jti = "session-" + uuid4().hex
        self.actor_id = uuid4()
        self.source_id = uuid4()
        self.principal_id = uuid4()
        self.now = int(time.time())
        self.iat = self.now - 5
        self.exp = self.now + 180
        self.session_exp = self.now + 90
        self._insert_principal_and_session()

    def db(self, sql, params=()):
        with psycopg.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql, params)
                return cursor.fetchone() if cursor.description else None

    def _insert_principal_and_session(self, *, writer=True, reviewer=False, enabled=True,
                                      auth_version=1, jti=None, issued=None, expires=None):
        jti = self.jti if jti is None else jti
        issued = self.iat if issued is None else issued
        expires = self.session_exp if expires is None else expires
        with psycopg.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Synthetic signed user',clock_timestamp())",
                               (self.actor_id,))
                cursor.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                               (self.source_id,))
                cursor.execute("""INSERT INTO echo_identity.principals
                    (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (self.principal_id, ISSUER, self.subject, self.actor_id, self.source_id,
                     enabled, writer, reviewer, auth_version))
                cursor.execute("""INSERT INTO echo_identity.sessions
                    (session_key,principal_id,auth_version,issued_at,expires_at)
                    VALUES(%s,%s,%s,to_timestamp(%s),to_timestamp(%s))""",
                    (derive_session_key(ISSUER, jti), self.principal_id, auth_version, issued, expires))

    def token(self, *, subject=None, jti=None, issuer=ISSUER, audience=AUD,
              iat=None, exp=None, key=None, extra=None):
        iat = self.iat if iat is None else iat
        claims = {"iss": issuer, "aud": audience, "sub": subject or self.subject,
                  "iat": iat, "nbf": iat, "exp": self.exp if exp is None else exp,
                  "jti": jti or self.jti}
        if extra:
            claims.update(extra)
        return jwt.encode(claims, key or self.key, algorithm="RS256",
                          headers={"kid": "fixture-key", "typ": "at+jwt"})

    def bind(self, body=None, token=None):
        return self.boundary.bind("Bearer " + (token or self.token()), body or draft())

    def denied(self, call, code="IDENTITY_REJECTED"):
        with self.assertRaises(BoundaryError) as ctx:
            call()
        self.assertEqual(ctx.exception.code, code)

    def authority_update(self, set_sql):
        self.db(f"UPDATE echo_identity.principals SET {set_sql},auth_version=auth_version+1 WHERE principal_id=%s",
                (self.principal_id,))

    def test_01_real_signature_and_postgres_bind_actor_and_source(self):
        result = self.bind()
        self.assertEqual(result.actor_id, self.actor_id)
        self.assertEqual(result.source_id, self.source_id)
        self.assertEqual(result.binding_revision, 1)
        self.assertFalse(result.ready_for_execution)

    def test_02_signed_actor_role_email_hints_cannot_override_database(self):
        result = self.bind(token=self.token(extra={"actor_id": str(uuid4()), "source_id": str(uuid4()),
            "role": "admin", "scope": "assessment:review", "email": "fixture@example.invalid"}))
        self.assertEqual(result.actor_id, self.actor_id)
        self.assertEqual(result.source_id, self.source_id)
        self.denied(lambda: self.bind(review(), self.token(extra={"role": "reviewer"})), "CAPABILITY_REQUIRED")

    def test_03_database_reviewer_grant_enables_only_review_preflight(self):
        self.authority_update("reviewer_enabled=true")
        new_jti = "review-" + uuid4().hex
        key = derive_session_key(ISSUER, new_jti)
        self.db("""INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
                 VALUES(%s,%s,2,to_timestamp(%s),to_timestamp(%s))""",
                (key, self.principal_id, self.iat, self.session_exp))
        result = self.bind(review(), self.token(jti=new_jti))
        self.assertEqual(result.actor_id, self.actor_id)
        self.assertFalse(result.ready_for_execution)

    def test_04_committed_session_revoke_denies_next_signed_request(self):
        self.bind()
        self.db("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",
                (derive_session_key(ISSUER, self.jti),))
        self.denied(lambda: self.bind())

    def test_05_disable_and_reenable_never_revives_old_signed_session(self):
        self.bind()
        self.authority_update("enabled=false")
        self.denied(lambda: self.bind())
        self.authority_update("enabled=true")
        self.denied(lambda: self.bind())

    def test_06_new_generation_requires_new_signed_jti_and_current_session(self):
        self.authority_update("enabled=false")
        self.authority_update("enabled=true")
        new_jti = "generation-" + uuid4().hex
        self.db("""INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
                 VALUES(%s,%s,3,to_timestamp(%s),to_timestamp(%s))""",
                (derive_session_key(ISSUER, new_jti), self.principal_id, self.iat, self.session_exp))
        result = self.bind(token=self.token(jti=new_jti))
        self.assertEqual(result.binding_revision, 3)

    def test_07_valid_signature_with_other_subject_cannot_reuse_session_jti(self):
        self.denied(lambda: self.bind(token=self.token(subject="other-" + uuid4().hex)))

    def test_08_wrong_signature_issuer_audience_expiry_never_reach_database(self):
        before = self.connection_count
        self.denied(lambda: self.bind(token=self.token(key=self.wrong_key)))
        self.denied(lambda: self.bind(token=self.token(issuer="https://other.fixture.invalid")))
        self.denied(lambda: self.bind(token=self.token(audience="other-api")))
        self.denied(lambda: self.bind(token=self.token(iat=self.now-200, exp=self.now-100)))
        self.assertEqual(self.connection_count, before)

    def test_09_database_outage_fails_closed(self):
        bad = PostgresRegistryAdapter(lambda: (_ for _ in ()).throw(RuntimeError("fixture database secret")))
        boundary = Boundary(self.config, resolve_binding=bad.resolve_binding)
        self.denied(lambda: boundary.bind("Bearer " + self.token(), draft()), "IDENTITY_BACKEND_UNAVAILABLE")

    def test_10_expired_local_session_denies_still_valid_signed_token(self):
        self.db("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",
                (derive_session_key(ISSUER, self.jti),))
        new_jti = "expired-local-" + uuid4().hex
        past = self.now - 1
        self.db("""INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
                 VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))""",
                (derive_session_key(ISSUER, new_jti), self.principal_id, self.now-100, past))
        self.denied(lambda: self.bind(token=self.token(jti=new_jti)))

    def test_11_token_issued_before_local_session_creation_is_denied(self):
        self.db("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",
                (derive_session_key(ISSUER, self.jti),))
        new_jti = "late-session-" + uuid4().hex
        issued = self.now + 1
        self.db("""INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
                 VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))""",
                (derive_session_key(ISSUER, new_jti), self.principal_id, issued, self.now+120))
        self.denied(lambda: self.bind(token=self.token(jti=new_jti, iat=self.now-5)))

    def test_12_result_expiry_is_bounded_by_shorter_database_session(self):
        result = self.bind()
        self.assertEqual(result.expires_at, self.session_exp)
        self.assertLess(result.expires_at, self.exp)

    def test_13_draft_capability_does_not_create_public_publish_input(self):
        result = self.bind()
        self.assertEqual(result.payload.text, "synthetic signed registry observation")
        self.denied(lambda: self.bind(draft({"visibility": "PUBLIC"})), "INVALID_COMMAND")

    def test_14_subject_matching_remains_exact_and_case_sensitive(self):
        self.denied(lambda: self.bind(token=self.token(subject=self.subject.upper())))
        self.denied(lambda: self.bind(token=self.token(subject=self.subject + " ")))

    def test_15_atomic_registry_resolver_rejects_legacy_adapter_mix(self):
        with self.assertRaises(ValueError):
            Boundary(self.config, lambda *_: None, lambda *_: False,
                     resolve_binding=self.adapter.resolve_binding)


if __name__ == "__main__":
    unittest.main(verbosity=2)
