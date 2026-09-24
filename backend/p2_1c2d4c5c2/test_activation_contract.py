from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import secrets
import time
import unittest
from uuid import UUID, uuid4

import psycopg
from psycopg import sql

DB = "echo_activation_contract_test"
SERVICE = "echo_activation_service"
RUNTIME = "echo_activation_runtime"
GUARD = "echo_activation_guard"
ISSUER = "https://issuer.activation.fixture.invalid/echo"
ACTIVATE_SQL = "SELECT echo_identity.runtime_activate_provisioned_principal(%s,%s,%s)"
ISSUE_PROOF_SQL = "SELECT echo_identity.runtime_issue_account_link_proof(%s,%s,%s,%s,%s,%s,%s)"
PROVISION_SQL = "SELECT echo_identity.runtime_provision_signed_principal(%s,%s,%s,%s,%s,%s)"


class ActivationContractTests(unittest.TestCase):
    @staticmethod
    def admin():
        return psycopg.connect(connect_timeout=3)

    @classmethod
    def setUpClass(cls):
        if (os.environ.get("ECHO_DISPOSABLE_PG") != "YES"
                or os.environ.get("PGDATABASE") != DB
                or os.environ.get("PGHOST") not in ("127.0.0.1", "localhost")):
            raise RuntimeError("refusing non-disposable activation database")
        with cls.admin() as c:
            version = int(c.execute("SHOW server_version_num").fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError("PostgreSQL 17 required")
            required = c.execute("""SELECT
              to_regprocedure('echo_identity.runtime_activate_provisioned_principal(uuid,uuid,integer)') IS NOT NULL,
              to_regclass('echo_identity.activation_audit') IS NOT NULL,
              to_regrole(%s) IS NOT NULL""", (SERVICE,)).fetchone()
            if required != (True, True, True):
                raise RuntimeError("activation migration not installed")
        cls.password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            c.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                sql.Identifier(SERVICE), sql.Literal(cls.password)))
        cls.addClassCleanup(cls.cleanup)

    @classmethod
    def cleanup(cls):
        with cls.admin() as c:
            c.execute("DROP SCHEMA IF EXISTS echo_identity CASCADE; DROP SCHEMA IF EXISTS echo_core CASCADE;")
        roles = [
            SERVICE, RUNTIME, GUARD,
            "echo_principal_provision_service", "echo_principal_provision_runtime", "echo_principal_provision_guard",
            "echo_account_link_service", "echo_account_link_runtime", "echo_account_link_guard",
            "echo_identity_mutation_service", "echo_identity_mutation_runtime", "echo_identity_mutation_guard",
            "echo_identity_registry_service", "echo_identity_registry_runtime", "echo_identity_registry_guard",
        ]
        with cls.admin() as c:
            for role in roles:
                c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        with cls.admin() as c:
            clean = c.execute("""SELECT to_regnamespace('echo_identity') IS NULL
              AND to_regnamespace('echo_core') IS NULL AND to_regrole(%s) IS NULL""", (SERVICE,)).fetchone()[0]
            if not clean:
                raise AssertionError("activation cleanup incomplete")
        print("CLEAN_ACTIVATION_CONTRACT_DATABASE", flush=True)

    @classmethod
    def service(cls, password=None):
        return psycopg.connect(
            host="127.0.0.1", port=int(os.environ.get("PGPORT", "5432")), dbname=DB,
            user=SERVICE, password=password or cls.password, connect_timeout=3,
            options="-c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=10000",
        )

    def db(self, query, params=()):
        with self.admin() as c:
            cur = c.execute(query, params)
            return cur.fetchone() if cur.description else None

    def fixture(self, subject=None):
        subject = subject or ("activation-" + uuid4().hex)
        proof_id = uuid4()
        now = int(time.time() * 1000)
        iat, nbf, exp, proof_exp = now - 2000, now - 1000, now + 180000, now + 120000
        with self.admin() as c:
            c.execute(ISSUE_PROOF_SQL, (proof_id, ISSUER, subject, iat, nbf, exp, proof_exp)).fetchone()
            result = c.execute(PROVISION_SQL, (proof_id, ISSUER, subject, iat, nbf, exp)).fetchone()[0]
        principal_id = UUID(result["principalId"])
        return principal_id, proof_id, subject

    def activate(self, principal_id, decision_id=None, expected=1):
        decision_id = decision_id or uuid4()
        with self.service() as c:
            c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(RUNTIME)))
            row = c.execute(ACTIVATE_SQL, (decision_id, principal_id, expected)).fetchone()[0]
        return row, decision_id

    def assert_db_error(self, needle, call):
        with self.assertRaises(psycopg.Error) as caught:
            call()
        self.assertIn(needle, str(caught.exception))

    def authority(self, principal_id):
        return self.db("SELECT enabled,writer_enabled,reviewer_enabled,auth_version FROM echo_identity.principals WHERE principal_id=%s", (principal_id,))

    def test_01_valid_first_activation_is_read_only_and_audited(self):
        principal, proof, _ = self.fixture()
        result, decision = self.activate(principal)
        self.assertEqual((result["principalId"], result["authVersion"], result["enabled"],
                          result["writerEnabled"], result["reviewerEnabled"], result["replayed"]),
                         (str(principal), 2, True, False, False, False))
        self.assertEqual(self.authority(principal), (True, False, False, 2))
        audit = self.db("""SELECT decision_id,principal_id,proof_id,policy_code,from_auth_version,
            to_auth_version,service_role FROM echo_identity.activation_audit WHERE decision_id=%s""", (decision,))
        self.assertEqual(audit, (decision, principal, proof, "PROVEN_ACCOUNT_ONBOARDING_V1", 1, 2, SERVICE))

    def test_02_exact_decision_retry_is_idempotent(self):
        principal, _, _ = self.fixture(); decision = uuid4()
        first, _ = self.activate(principal, decision)
        second, _ = self.activate(principal, decision)
        self.assertFalse(first["replayed"]); self.assertTrue(second["replayed"])
        self.assertEqual(self.authority(principal), (True, False, False, 2))
        self.assertEqual(self.db("SELECT count(*) FROM echo_identity.activation_audit WHERE principal_id=%s", (principal,))[0], 1)

    def test_03_decision_id_cannot_be_retargeted(self):
        p1, _, _ = self.fixture(); p2, _, _ = self.fixture(); decision = uuid4()
        self.activate(p1, decision)
        self.assert_db_error("ACTIVATION_DECISION_CONFLICT", lambda: self.activate(p2, decision))
        self.assertEqual(self.authority(p2), (False, False, False, 1))

    def test_04_second_decision_cannot_reactivate_same_principal(self):
        principal, _, _ = self.fixture(); self.activate(principal)
        self.assert_db_error("ACTIVATION_REJECTED", lambda: self.activate(principal, uuid4()))
        self.assertEqual(self.db("SELECT count(*) FROM echo_identity.activation_audit WHERE principal_id=%s", (principal,))[0], 1)

    def test_05_unknown_principal_fails_closed(self):
        before = self.db("SELECT count(*) FROM echo_identity.activation_audit")[0]
        self.assert_db_error("ACTIVATION_REJECTED", lambda: self.activate(uuid4()))
        self.assertEqual(self.db("SELECT count(*) FROM echo_identity.activation_audit")[0], before)

    def test_06_unconsumed_proof_provenance_is_required(self):
        principal, proof, _ = self.fixture()
        with self.admin() as c:
            c.execute("UPDATE echo_identity.account_link_proofs SET consumed_at=NULL,consumed_principal_id=NULL WHERE proof_id=%s", (proof,))
        self.assert_db_error("ACTIVATION_PROVENANCE_REQUIRED", lambda: self.activate(principal))
        self.assertEqual(self.authority(principal), (False, False, False, 1))

    def test_07_proof_consumption_must_still_point_to_target_principal(self):
        principal, proof, _ = self.fixture()
        other_principal, _, _ = self.fixture()
        with self.admin() as c:
            c.execute("UPDATE echo_identity.account_link_proofs SET consumed_principal_id=%s WHERE proof_id=%s",
                      (other_principal, proof))
        self.assert_db_error("ACTIVATION_PROVENANCE_REQUIRED", lambda: self.activate(principal))
        self.assertEqual(self.authority(principal), (False, False, False, 1))

    def test_08_expected_generation_is_fixed_to_first_activation(self):
        principal, _, _ = self.fixture()
        for expected in (0, 2, 99):
            with self.subTest(expected=expected):
                self.assert_db_error("INVALID_ACTIVATION_REQUEST", lambda expected=expected: self.activate(principal, expected=expected))
        self.assertEqual(self.authority(principal), (False, False, False, 1))

    def test_09_pre_enabled_or_privileged_principal_is_rejected(self):
        principal, _, _ = self.fixture()
        with self.admin() as c:
            c.execute("UPDATE echo_identity.principals SET enabled=true,auth_version=auth_version+1 WHERE principal_id=%s", (principal,))
        self.assertEqual(self.authority(principal), (True, False, False, 2))
        self.assert_db_error("ACTIVATION_REJECTED", lambda: self.activate(principal))

    def test_10_legacy_mutation_runtime_cannot_bypass_activation_audit(self):
        allowed = self.db("""SELECT has_function_privilege('echo_identity_mutation_runtime',
          'echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)'::regprocedure,'EXECUTE')""")[0]
        self.assertFalse(allowed)

    def test_11_service_has_no_direct_registry_table_access(self):
        def direct_read():
            with self.service() as c:
                c.execute("SELECT count(*) FROM echo_identity.principals").fetchone()
        self.assert_db_error("permission denied", direct_read)

    def test_12_service_must_set_exact_activation_runtime_role(self):
        principal, _, _ = self.fixture()
        def direct_call():
            with self.service() as c:
                c.execute(ACTIVATE_SQL, (uuid4(), principal, 1)).fetchone()
        self.assert_db_error("permission denied", direct_call)

    def test_13_runtime_role_is_not_enough_without_activation_service_login(self):
        principal, _, _ = self.fixture()
        def owner_impersonates_runtime():
            with self.admin() as c:
                c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(RUNTIME)))
                c.execute(ACTIVATE_SQL, (uuid4(), principal, 1)).fetchone()
        self.assert_db_error("ACTIVATION_SERVICE_REQUIRED", owner_impersonates_runtime)
        self.assertEqual(self.authority(principal), (False, False, False, 1))

    def test_14_onboarding_services_have_no_activation_role_membership(self):
        rows = self.db("""SELECT count(*) FROM pg_auth_members m
          JOIN pg_roles member ON member.oid=m.member
          JOIN pg_roles target ON target.oid=m.roleid
          WHERE target.rolname=%s AND member.rolname=ANY(%s)""",
          (RUNTIME, ["echo_account_link_service", "echo_principal_provision_service", "echo_identity_mutation_service"]))[0]
        self.assertEqual(rows, 0)

    def test_15_activation_runtime_cannot_create_sessions(self):
        allowed = self.db("""SELECT has_function_privilege(%s,
          'echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)'::regprocedure,'EXECUTE')""", (RUNTIME,))[0]
        self.assertFalse(allowed)

    def test_16_audit_is_append_only_for_all_activation_roles(self):
        oid = self.db("SELECT 'echo_identity.activation_audit'::regclass::oid")[0]
        for role in (SERVICE, RUNTIME, GUARD):
            with self.subTest(role=role):
                update_ok, delete_ok = self.db("SELECT has_table_privilege(%s,%s,'UPDATE'),has_table_privilege(%s,%s,'DELETE')",
                                               (role, oid, role, oid))
                self.assertFalse(update_ok); self.assertFalse(delete_ok)

    def test_17_audit_policy_and_proof_are_server_derived(self):
        principal, proof, _ = self.fixture(); _, decision = self.activate(principal)
        row = self.db("SELECT proof_id,policy_code,service_role FROM echo_identity.activation_audit WHERE decision_id=%s", (decision,))
        self.assertEqual(row, (proof, "PROVEN_ACCOUNT_ONBOARDING_V1", SERVICE))

    def test_18_concurrent_distinct_decisions_produce_one_activation(self):
        principal, _, _ = self.fixture(); d1, d2 = uuid4(), uuid4()
        def attempt(decision):
            try:
                return ("ok", self.activate(principal, decision)[0])
            except psycopg.Error as exc:
                return ("err", str(exc))
        with ThreadPoolExecutor(max_workers=2) as ex:
            results = list(ex.map(attempt, (d1, d2)))
        self.assertEqual([kind for kind, _ in results].count("ok"), 1)
        self.assertEqual([kind for kind, _ in results].count("err"), 1)
        self.assertEqual(self.authority(principal), (True, False, False, 2))
        self.assertEqual(self.db("SELECT count(*) FROM echo_identity.activation_audit WHERE principal_id=%s", (principal,))[0], 1)

    def test_19_real_service_password_is_required(self):
        with self.assertRaises(psycopg.Error):
            with self.service(password="definitely-wrong-password") as c:
                c.execute("SELECT 1")

    def test_20_activation_creates_no_session_or_news_rows(self):
        principal, _, _ = self.fixture(); self.activate(principal)
        sessions = self.db("SELECT count(*) FROM echo_identity.sessions WHERE principal_id=%s", (principal,))[0]
        voices = self.db("SELECT count(*) FROM echo_core.voice_revisions")[0]
        self.assertEqual((sessions, voices), (0, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
