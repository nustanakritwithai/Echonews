from __future__ import annotations

import os
from pathlib import Path
import secrets
import sys
import time
import unittest
from uuid import UUID, uuid4

import jwt
import psycopg
from psycopg import sql
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for path in (
    ROOT / "backend/p2_1c2b1",
    ROOT / "backend/p2_1c2c3",
    ROOT / "backend/p2_1c2d4c5b",
    HERE,
):
    sys.path.insert(0, str(path))

from identity_boundary import Config  # noqa: E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa: E402
from first_session_boundary import SignedFirstSessionBoundary, FirstSessionError  # noqa: E402
from first_session_pool import FirstSessionPool  # noqa: E402

DB = "echo_first_session_test"
ISSUER = "https://issuer.first-session.fixture.invalid/echo"
AUD = "echo-first-session-fixture"
KID = "fixture-key"
SERVICE = "echo_first_session_service"
RUNTIME = "echo_first_session_runtime"
ACTIVATION_SERVICE = "echo_activation_service"
ACTIVATION_RUNTIME = "echo_activation_runtime"
ISSUE_PROOF_SQL = "SELECT echo_identity.runtime_issue_account_link_proof(%s,%s,%s,%s,%s,%s,%s)"
PROVISION_SQL = "SELECT echo_identity.runtime_provision_signed_principal(%s,%s,%s,%s,%s,%s)"
ACTIVATE_SQL = "SELECT echo_identity.runtime_activate_provisioned_principal(%s,%s,%s)"
RAW_CREATE = "echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)"


class SignedFirstSessionTests(unittest.TestCase):
    @staticmethod
    def admin():
        return psycopg.connect(connect_timeout=3)

    @classmethod
    def setUpClass(cls):
        if (os.environ.get("ECHO_DISPOSABLE_PG") != "YES"
                or os.environ.get("PGDATABASE") != DB
                or os.environ.get("PGHOST") not in ("127.0.0.1", "localhost")):
            raise RuntimeError("refusing non-disposable first-session database")
        with cls.admin() as c:
            version = int(c.execute("SHOW server_version_num").fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError("PostgreSQL 17 required")
            required = c.execute("""SELECT
              to_regprocedure('echo_identity.runtime_bootstrap_first_session(text,text,text,bigint,bigint,bigint)') IS NOT NULL,
              to_regclass('echo_identity.activation_audit') IS NOT NULL,
              to_regrole(%s) IS NOT NULL""", (SERVICE,)).fetchone()
            if required != (True, True, True):
                raise RuntimeError("first-session migration not installed")

        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, "first-session-keyset-v1", {KID: cls.key.public_key()})
        cls.password = secrets.token_urlsafe(32)
        cls.activation_password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            c.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(SERVICE), sql.Literal(cls.password)))
            c.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                sql.Identifier(ACTIVATION_SERVICE), sql.Literal(cls.activation_password)))

        cls.pool = FirstSessionPool(
            host="127.0.0.1", port=int(os.environ.get("PGPORT", "5432")), dbname=DB,
            user=SERVICE, password=cls.password, sslmode="disable",
            allow_insecure_test_loopback=True, max_size=2,
        )
        cls.pool.open()
        cls.boundary = SignedFirstSessionBoundary(cls.config, cls.pool.connection)
        cls.addClassCleanup(cls.cleanup)

    @classmethod
    def cleanup(cls):
        if hasattr(cls, "pool"):
            cls.pool.close()
        with cls.admin() as c:
            c.execute("DROP SCHEMA IF EXISTS echo_identity CASCADE; DROP SCHEMA IF EXISTS echo_core CASCADE;")
        roles = [
            SERVICE, RUNTIME, "echo_first_session_guard",
            ACTIVATION_SERVICE, ACTIVATION_RUNTIME, "echo_activation_guard",
            "echo_principal_provision_service", "echo_principal_provision_runtime", "echo_principal_provision_guard",
            "echo_account_link_service", "echo_account_link_runtime", "echo_account_link_guard",
            "echo_identity_mutation_service", "echo_identity_mutation_runtime", "echo_identity_mutation_guard",
            "echo_identity_registry_service", "echo_identity_registry_runtime", "echo_identity_registry_guard",
        ]
        with cls.admin() as c:
            for role in roles:
                c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        print("CLEAN_FIRST_SESSION_DATABASE", flush=True)

    @classmethod
    def activation_connection(cls):
        return psycopg.connect(
            host="127.0.0.1", port=int(os.environ.get("PGPORT", "5432")), dbname=DB,
            user=ACTIVATION_SERVICE, password=cls.activation_password, connect_timeout=3,
        )

    @classmethod
    def service_connection(cls, password=None):
        return psycopg.connect(
            host="127.0.0.1", port=int(os.environ.get("PGPORT", "5432")), dbname=DB,
            user=SERVICE, password=password or cls.password, connect_timeout=3,
        )

    def db(self, query, params=()):
        with self.admin() as c:
            cur = c.execute(query, params)
            return cur.fetchone() if cur.description else None

    def token(self, subject, *, jti=None, key=None, extra=None, lifetime=180):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": AUD, "sub": subject,
            "iat": now - 5, "nbf": now - 4, "exp": now + lifetime,
            "jti": jti or ("jti-" + uuid4().hex),
        }
        if extra:
            claims.update(extra)
        encoded = jwt.encode(
            claims, key or self.key, algorithm="RS256",
            headers={"kid": KID, "typ": "at+jwt"},
        )
        return encoded, claims

    def provision(self, subject=None):
        subject = subject or ("first-session-" + uuid4().hex)
        proof_id = uuid4()
        now = int(time.time())
        iat, nbf, exp = (now - 5) * 1000, (now - 4) * 1000, (now + 180) * 1000
        proof_exp = (now + 120) * 1000
        with self.admin() as c:
            c.execute(ISSUE_PROOF_SQL, (proof_id, ISSUER, subject, iat, nbf, exp, proof_exp)).fetchone()
            result = c.execute(PROVISION_SQL, (proof_id, ISSUER, subject, iat, nbf, exp)).fetchone()[0]
        return UUID(result["principalId"]), subject

    def activate(self, principal_id):
        with self.activation_connection() as c:
            c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(ACTIVATION_RUNTIME)))
            return c.execute(ACTIVATE_SQL, (uuid4(), principal_id, 1)).fetchone()[0]

    def activated(self, subject=None):
        principal, subject = self.provision(subject)
        result = self.activate(principal)
        self.assertEqual((result["enabled"], result["authVersion"]), (True, 2))
        return principal, subject

    def assert_error(self, code, call):
        with self.assertRaises(FirstSessionError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def session_count(self, principal):
        return self.db("SELECT count(*) FROM echo_identity.sessions WHERE principal_id=%s", (principal,))[0]

    def test_01_verified_bearer_creates_one_current_generation_session(self):
        principal, subject = self.activated()
        token, claims = self.token(subject)
        receipt = self.boundary.bootstrap("Bearer " + token, b"{}")
        self.assertEqual((receipt.auth_version, receipt.replayed), (2, False))
        key = derive_session_key(ISSUER, claims["jti"])
        row = self.db("SELECT session_key,principal_id,auth_version,revoked FROM echo_identity.sessions WHERE session_key=%s", (key,))
        self.assertEqual(row, (key, principal, 2, False))

    def test_02_exact_same_token_retry_is_idempotent(self):
        principal, subject = self.activated()
        token, _ = self.token(subject)
        first = self.boundary.bootstrap("Bearer " + token, b"{}")
        second = self.boundary.bootstrap("Bearer " + token, b"{}")
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(self.session_count(principal), 1)

    def test_03_request_body_cannot_choose_identity_or_session_fields(self):
        principal, subject = self.activated()
        token, _ = self.token(subject)
        for body in (
            b'{"principal_id":"x"}', b'{"actor_id":"x"}', b'{"source_id":"x"}',
            b'{"issuer":"x"}', b'{"subject":"x"}', b'{"session_key":"x"}',
        ):
            with self.subTest(body=body):
                self.assert_error("INVALID_FIRST_SESSION_REQUEST",
                    lambda body=body: self.boundary.bootstrap("Bearer " + token, body))
        self.assertEqual(self.session_count(principal), 0)

    def test_04_wrong_signature_is_rejected_before_session_creation(self):
        principal, subject = self.activated()
        token, _ = self.token(subject, key=self.wrong_key)
        self.assert_error("IDENTITY_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token, b"{}"))
        self.assertEqual(self.session_count(principal), 0)

    def test_05_unknown_signed_subject_cannot_bootstrap(self):
        token, _ = self.token("unknown-" + uuid4().hex)
        self.assert_error("FIRST_SESSION_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token, b"{}"))

    def test_06_provisioned_but_not_activated_principal_is_rejected(self):
        principal, subject = self.provision()
        token, _ = self.token(subject)
        self.assert_error("FIRST_SESSION_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token, b"{}"))
        self.assertEqual(self.session_count(principal), 0)

    def test_07_enabled_generation_two_without_activation_audit_is_rejected(self):
        principal, subject = self.provision()
        with self.admin() as c:
            c.execute("UPDATE echo_identity.principals SET enabled=true,auth_version=auth_version+1 WHERE principal_id=%s", (principal,))
        token, _ = self.token(subject)
        self.assert_error("FIRST_SESSION_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token, b"{}"))
        self.assertEqual(self.session_count(principal), 0)

    def test_08_legacy_raw_session_create_is_revoked_from_mutation_runtime(self):
        allowed = self.db("SELECT has_function_privilege('echo_identity_mutation_runtime', %s::regprocedure, 'EXECUTE')", (RAW_CREATE,))[0]
        self.assertFalse(allowed)

    def test_09_service_login_has_no_direct_registry_table_access(self):
        with self.assertRaises(psycopg.Error):
            with self.service_connection() as c:
                c.execute("SELECT count(*) FROM echo_identity.sessions").fetchone()

    def test_10_runtime_role_without_service_login_is_rejected(self):
        principal, subject = self.activated()
        token, claims = self.token(subject)
        key = derive_session_key(ISSUER, claims["jti"])
        with self.assertRaises(psycopg.Error) as caught:
            with self.admin() as c:
                c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(RUNTIME)))
                c.execute("SELECT echo_identity.runtime_bootstrap_first_session(%s,%s,%s,%s,%s,%s)",
                    (ISSUER, subject, key, claims["iat"]*1000, claims["nbf"]*1000, claims["exp"]*1000)).fetchone()
        self.assertIn("FIRST_SESSION_SERVICE_REQUIRED", str(caught.exception))
        self.assertEqual(self.session_count(principal), 0)

    def test_11_signed_authority_hints_cannot_override_server_resolution(self):
        principal, subject = self.activated()
        token, _ = self.token(subject, extra={
            "role": "admin", "principal_id": str(uuid4()),
            "actor_id": str(uuid4()), "source_id": str(uuid4()),
        })
        receipt = self.boundary.bootstrap("Bearer " + token, b"{}")
        self.assertEqual(receipt.auth_version, 2)
        self.assertEqual(self.session_count(principal), 1)

    def test_12_second_distinct_token_is_not_a_second_first_session(self):
        principal, subject = self.activated()
        token1, _ = self.token(subject)
        token2, _ = self.token(subject)
        self.boundary.bootstrap("Bearer " + token1, b"{}")
        self.assert_error("FIRST_SESSION_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token2, b"{}"))
        self.assertEqual(self.session_count(principal), 1)

    def test_13_revoked_first_session_cannot_be_recreated_by_same_token(self):
        principal, subject = self.activated()
        token, claims = self.token(subject)
        self.boundary.bootstrap("Bearer " + token, b"{}")
        key = derive_session_key(ISSUER, claims["jti"])
        with self.admin() as c:
            c.execute("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s", (key,))
        self.assert_error("FIRST_SESSION_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token, b"{}"))
        self.assertEqual(self.session_count(principal), 1)

    def test_14_authority_change_makes_bootstrap_replay_stale(self):
        principal, subject = self.activated()
        token, _ = self.token(subject)
        self.boundary.bootstrap("Bearer " + token, b"{}")
        with self.admin() as c:
            c.execute("UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s", (principal,))
        self.assert_error("FIRST_SESSION_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token, b"{}"))

    def test_15_registry_adapter_resolves_the_new_session_without_capabilities(self):
        principal, subject = self.activated()
        token, claims = self.token(subject)
        self.boundary.bootstrap("Bearer " + token, b"{}")
        binding = PostgresRegistryAdapter(self.admin).resolve_binding(ISSUER, subject, claims["jti"])
        self.assertIsNotNone(binding)
        self.assertEqual((binding.principal_id, binding.revision, binding.capabilities),
                         (principal, 2, frozenset()))

    def test_16_same_jti_cannot_be_retargeted_to_another_subject(self):
        p1, s1 = self.activated(); p2, s2 = self.activated()
        shared = "shared-" + uuid4().hex
        token1, _ = self.token(s1, jti=shared)
        token2, _ = self.token(s2, jti=shared)
        self.boundary.bootstrap("Bearer " + token1, b"{}")
        self.assert_error("FIRST_SESSION_REJECTED", lambda: self.boundary.bootstrap("Bearer " + token2, b"{}"))
        self.assertEqual((self.session_count(p1), self.session_count(p2)), (1, 0))

    def test_17_wrong_database_password_cannot_authenticate_service(self):
        with self.assertRaises(psycopg.Error):
            with self.service_connection(password="definitely-wrong-password") as c:
                c.execute("SELECT 1")

    def test_18_pool_enforces_exact_runtime_function_allowlist(self):
        # Opening/using the pool performs catalog checks. This successful lease proves
        # current policy matches exactly one runtime function and one SET membership.
        with self.pool.connection() as c:
            self.assertEqual(c.execute("SELECT session_user,current_user").fetchone(), (SERVICE, RUNTIME))


if __name__ == "__main__":
    unittest.main(verbosity=2)
