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
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "p2_1c2b1"))
sys.path.insert(0, str(HERE.parent / "p2_1c2c3"))
from identity_boundary import Boundary, BoundaryError, Config  # noqa:E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa:E402
from private_voice_executor import (  # noqa:E402
    PrivateVoiceExecutionError, PrivateVoiceExecutor, PrivateVoiceReceipt,
)

DB_NAME = "echo_private_executor_test"
RUNTIME = "echo_private_draft_runtime"
GUARD = "echo_private_draft_guard"
ISSUER = "https://issuer.private-executor.fixture.invalid/echo"
AUD = "echo-commands-fixture"


def draft_body(text="server executor fixture", *, top=None, payload=None):
    body = {"request_id": "20000000-0000-4000-8000-000000000001",
            "command": "CREATE_VOICE_DRAFT", "payload": {"text": text}}
    if top:
        body.update(top)
    if payload:
        body["payload"].update(payload)
    return json.dumps(body).encode()


def review_body():
    return json.dumps({
        "request_id": "20000000-0000-4000-8000-000000000002",
        "command": "REVIEW_EVIDENCE_RELATION",
        "payload": {"assessment_id": "30000000-0000-4000-8000-000000000001",
                    "expected_revision": 1, "decision": "ACCEPTED",
                    "rationale": "fixture review only"},
    }).encode()


class PrivateVoiceExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get("ECHO_DISPOSABLE_PG") != "YES"
                or os.environ.get("PGDATABASE") != DB_NAME
                or os.environ.get("PGHOST") not in ("127.0.0.1", "localhost")):
            raise RuntimeError("refusing non-disposable or non-loopback database")
        with cls.connect() as c:
            version = int(c.execute("SHOW server_version_num").fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError("this gate must run on PostgreSQL 17")
            dirty = c.execute("""SELECT to_regnamespace('echo_core') IS NOT NULL
                OR to_regnamespace('echo_identity') IS NOT NULL
                OR to_regnamespace('echo_history') IS NOT NULL
                OR to_regrole(%s) IS NOT NULL OR to_regrole(%s) IS NOT NULL""",
                (RUNTIME, GUARD)).fetchone()[0]
            if dirty:
                raise RuntimeError("refusing database with pre-existing Echo objects/roles")
            for path in (
                "database/p2_1b/schema.sql",
                "database/p2_1c/001_immutable_history.sql",
                "database/p2_1c2c/001_identity_registry.sql",
                "database/p2_1c2d1/001_write_fence.sql",
                "database/p2_1c2d2/001_runtime_roles.sql",
                "database/p2_1c2d3/001_private_voice_write.sql",
            ):
                c.execute((ROOT / path).read_text())
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, "fixture-keyset-v1",
                            {"fixture-key": cls.private_key.public_key()})
        cls.adapter = PostgresRegistryAdapter(cls.connect)
        cls.boundary = Boundary(cls.config, resolve_binding=cls.adapter.resolve_binding)
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def connect():
        return psycopg.connect(
            connect_timeout=3,
            options="-c statement_timeout=8000 -c lock_timeout=4000 "
                    "-c idle_in_transaction_session_timeout=12000",
        )

    @classmethod
    def runtime_connection(cls):
        c = cls.connect()
        c.execute(f"SET SESSION AUTHORIZATION {RUNTIME}")
        c.commit()
        return c

    @classmethod
    def cleanup(cls):
        with cls.connect() as c:
            c.execute("DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_history CASCADE; "
                      "DROP SCHEMA echo_core CASCADE;")
            c.execute(f"DROP ROLE {RUNTIME}; DROP ROLE {GUARD};")
        with cls.connect() as c:
            clean = c.execute("""SELECT to_regnamespace('echo_core') IS NULL
                AND to_regnamespace('echo_identity') IS NULL
                AND to_regnamespace('echo_history') IS NULL
                AND to_regrole(%s) IS NULL AND to_regrole(%s) IS NULL""",
                (RUNTIME, GUARD)).fetchone()[0]
            if not clean:
                raise AssertionError("executor cleanup incomplete")
        print("CLEAN_PRIVATE_EXECUTOR_DATABASE", flush=True)

    def setUp(self):
        self.subject = "user-" + uuid4().hex
        self.jti = "session-" + uuid4().hex
        self.principal_id, self.actor_id, self.source_id = uuid4(), uuid4(), uuid4()
        self.now = int(time.time())
        self.iat, self.nbf, self.exp, self.session_exp = (
            self.now - 3, self.now - 2, self.now + 120, self.now + 90)
        self.session_key = derive_session_key(ISSUER, self.jti)
        self._provision()
        # The suite intentionally shares one disposable DB so successful earlier tests
        # can leave immutable history behind. Failure cases assert against THIS test's
        # starting count rather than incorrectly assuming a globally empty table.
        self.voice_count_before = self.voice_count()
        self.payloads = {}
        self.stored_calls = []
        self.discarded = []
        self.executor = PrivateVoiceExecutor(self.runtime_connection, self.store_payload,
                                             self.discard_payload)

    def _provision(self):
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Executor fixture',clock_timestamp())",
                      (self.actor_id,))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                      (self.source_id,))
            c.execute("""INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                VALUES(%s,%s,%s,%s,%s,true,true,true,1)""",
                (self.principal_id, ISSUER, self.subject, self.actor_id, self.source_id))
            c.execute("""INSERT INTO echo_identity.sessions
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
        return self.boundary.bind("Bearer " + (token or self.token()), raw or draft_body())

    def store_payload(self, voice_id, text):
        ref = "payload:private:" + voice_id.hex
        self.stored_calls.append((voice_id, text, ref))
        self.payloads[ref] = text
        return ref

    def discard_payload(self, ref):
        self.discarded.append(ref)
        self.payloads.pop(ref, None)

    def execute_error(self, intent, code):
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            self.executor.execute(intent)
        self.assertEqual(ctx.exception.code, code)

    def db_one(self, sql, params=()):
        with self.connect() as c:
            return c.execute(sql, params).fetchone()

    def voice_count(self):
        return self.db_one("SELECT count(*) FROM echo_core.voice_revisions")[0]

    def assert_no_new_voice(self):
        self.assertEqual(self.voice_count(), self.voice_count_before)

    def test_01_signed_bound_intent_executes_one_private_revision(self):
        intent = self.bind()
        receipt = self.executor.execute(intent)
        self.assertIsInstance(receipt, PrivateVoiceReceipt)
        row = self.db_one("""SELECT revision,previous_revision,author_id,source_id,payload_ref,
                            visibility,posted_at,recorded_at
                            FROM echo_core.voice_revisions WHERE voice_id=%s""", (receipt.voice_id,))
        self.assertEqual(row[:7], (1, None, self.actor_id, self.source_id,
                                  self.stored_calls[0][2], "PRIVATE", None))
        self.assertEqual(row[7], receipt.recorded_at)
        self.assertEqual(receipt.revision, 1)
        self.assertEqual(receipt.visibility, "PRIVATE")
        self.assertEqual(self.voice_count(), self.voice_count_before + 1)

    def test_02_browser_json_cannot_supply_execution_authority_or_write_fields(self):
        attempts = [
            ({"authorization_stamp": {"actor_id": str(uuid4())}}, None),
            (None, {"actor_id": str(uuid4())}),
            (None, {"source_id": str(uuid4())}),
            (None, {"principal_id": str(uuid4())}),
            (None, {"session_key": "f" * 64}),
            (None, {"auth_version": 99}),
            (None, {"payload_ref": "client:payload"}),
            (None, {"visibility": "PUBLIC"}),
            (None, {"revision": 9}),
            (None, {"recorded_at": "2099-01-01T00:00:00Z"}),
        ]
        for top, payload in attempts:
            with self.subTest(top=top, payload=payload):
                with self.assertRaises(BoundaryError) as ctx:
                    self.bind(draft_body(top=top, payload=payload))
                self.assertEqual(ctx.exception.code, "INVALID_COMMAND")
        self.assertEqual(self.stored_calls, [])
        self.assert_no_new_voice()

    def test_03_json_shaped_dict_cannot_call_executor(self):
        self.execute_error({"command": "CREATE_VOICE_DRAFT",
                            "authorization_stamp": {"actor_id": str(self.actor_id)}},
                           "INVALID_SERVER_INTENT")
        self.assertEqual(self.stored_calls, [])
        self.assert_no_new_voice()

    def test_04_voice_id_and_payload_ref_are_server_owned(self):
        intent = self.bind(draft_body("exact author text"))
        receipt = self.executor.execute(intent)
        self.assertNotEqual(receipt.voice_id, intent.request_id)
        self.assertEqual(self.stored_calls[0][0], receipt.voice_id)
        self.assertEqual(self.stored_calls[0][1], "exact author text")
        self.assertEqual(self.stored_calls[0][2], "payload:private:" + receipt.voice_id.hex)
        self.assertEqual(self.voice_count(), self.voice_count_before + 1)

    def test_05_mismatched_server_stamp_is_rejected_before_payload_store(self):
        intent = self.bind()
        forged = dataclasses.replace(intent.authorization_stamp, actor_id=uuid4())
        self.execute_error(dataclasses.replace(intent, authorization_stamp=forged),
                           "AUTHORIZATION_STAMP_MISMATCH")
        self.assertEqual(self.stored_calls, [])
        self.assert_no_new_voice()

    def test_06_non_draft_capability_cannot_enter_private_writer(self):
        intent = self.bind()
        forged = dataclasses.replace(intent.authorization_stamp, capability="assessment:review")
        self.execute_error(dataclasses.replace(intent, authorization_stamp=forged),
                           "CAPABILITY_MISMATCH")
        self.assertEqual(self.stored_calls, [])
        self.assert_no_new_voice()

    def test_07_missing_durable_stamp_is_not_executable(self):
        intent = dataclasses.replace(self.bind(), authorization_stamp=None)
        self.execute_error(intent, "AUTHORIZATION_STAMP_REQUIRED")
        self.assertEqual(self.stored_calls, [])
        self.assert_no_new_voice()

    def test_08_review_intent_is_not_a_private_voice_execution(self):
        intent = self.bind(review_body())
        self.execute_error(intent, "UNSUPPORTED_SERVER_INTENT")
        self.assertEqual(self.stored_calls, [])
        self.assert_no_new_voice()

    def test_09_revoke_after_bind_is_denied_at_db_writer_and_payload_compensated(self):
        intent = self.bind()
        with self.connect() as c:
            c.execute("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",
                      (self.session_key,))
        self.execute_error(intent, "PRIVATE_VOICE_WRITE_REJECTED")
        self.assertEqual(self.payloads, {})
        self.assertEqual(len(self.discarded), 1)
        self.assert_no_new_voice()

    def test_10_role_change_after_bind_is_denied_and_payload_compensated(self):
        intent = self.bind()
        with self.connect() as c:
            c.execute("""UPDATE echo_identity.principals
                       SET writer_enabled=false,auth_version=2 WHERE principal_id=%s""",
                      (self.principal_id,))
        self.execute_error(intent, "PRIVATE_VOICE_WRITE_REJECTED")
        self.assertEqual(self.payloads, {})
        self.assert_no_new_voice()

    def test_11_payload_store_failure_happens_before_any_database_write(self):
        def fail_store(*_):
            raise RuntimeError("synthetic payload backend detail")
        executor = PrivateVoiceExecutor(self.runtime_connection, fail_store, self.discard_payload)
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            executor.execute(self.bind())
        self.assertEqual(ctx.exception.code, "PAYLOAD_STORE_UNAVAILABLE")
        self.assert_no_new_voice()

    def test_12_invalid_payload_ref_contract_never_reaches_database_writer(self):
        executor = PrivateVoiceExecutor(self.runtime_connection, lambda *_: "   ", self.discard_payload)
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            executor.execute(self.bind())
        self.assertEqual(ctx.exception.code, "PAYLOAD_STORE_CONTRACT_VIOLATION")
        self.assert_no_new_voice()

    def test_13_executor_rejects_owner_connection_instead_of_silently_using_privilege(self):
        executor = PrivateVoiceExecutor(self.connect, self.store_payload, self.discard_payload)
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            executor.execute(self.bind())
        self.assertEqual(ctx.exception.code, "RUNTIME_ROLE_REQUIRED")
        self.assertEqual(self.payloads, {})
        self.assertEqual(len(self.discarded), 1)
        self.assert_no_new_voice()

    def test_14_signed_actor_role_hints_cannot_change_written_author_or_visibility(self):
        token = self.token({"actor_id": str(uuid4()), "source_id": str(uuid4()),
                            "role": "admin", "scope": "publish:*"})
        receipt = self.executor.execute(self.bind(token=token))
        row = self.db_one("SELECT author_id,source_id,visibility FROM echo_core.voice_revisions WHERE voice_id=%s",
                          (receipt.voice_id,))
        self.assertEqual(row, (self.actor_id, self.source_id, "PRIVATE"))
        self.assertEqual(self.voice_count(), self.voice_count_before + 1)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PrivateVoiceExecutorTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print("P2_1C2D3B_PRIVATE_EXECUTOR_SUITE_SAT", flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
