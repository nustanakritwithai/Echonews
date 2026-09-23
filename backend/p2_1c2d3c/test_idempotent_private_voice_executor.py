from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

import jwt
import psycopg
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "p2_1c2b1"))
sys.path.insert(0, str(HERE.parent / "p2_1c2c3"))
sys.path.insert(0, str(HERE.parent / "p2_1c2d3b"))

from identity_boundary import Boundary, BoundaryError, Config  # noqa:E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa:E402
from private_voice_executor import PrivateVoiceExecutor, PrivateVoiceExecutionError  # noqa:E402
import idempotent_private_voice_executor as idem_module  # noqa:E402
from idempotent_private_voice_executor import (  # noqa:E402
    IdempotentPrivateVoiceExecutor, IdempotentPrivateVoiceReceipt,
)

DB_NAME = "echo_idempotent_private_test"
RUNTIME = "echo_private_draft_runtime"
GUARD = "echo_private_draft_guard"
ISSUER = "https://issuer.idempotency.fixture.invalid/echo"
AUD = "echo-commands-fixture"
REQUEST_ID = UUID("20000000-0000-4000-8000-000000000001")


def draft_body(text="idempotent fixture", request_id=REQUEST_ID, *, top=None, payload=None):
    body = {"request_id": str(request_id), "command": "CREATE_VOICE_DRAFT",
            "payload": {"text": text}}
    if top:
        body.update(top)
    if payload:
        body["payload"].update(payload)
    return json.dumps(body, ensure_ascii=False).encode()


class IdempotentPrivateVoiceTests(unittest.TestCase):
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
                "database/p2_1c2d3c/001_idempotent_private_receipt.sql",
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
        return psycopg.connect(connect_timeout=3,
            options="-c statement_timeout=10000 -c lock_timeout=6000 "
                    "-c idle_in_transaction_session_timeout=15000")

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
                raise AssertionError("idempotency cleanup incomplete")
        print("CLEAN_IDEMPOTENT_PRIVATE_DATABASE", flush=True)

    def setUp(self):
        self.now = int(time.time())
        self.identity = self._new_identity()
        self.voice_before = self._count("echo_core.voice_revisions")
        self.receipt_before = self._count("echo_identity.private_draft_receipts")
        self.payloads: dict[str, str] = {}
        self.stored_calls = []
        self.discarded = []
        self.payload_lock = threading.Lock()
        self.executor = IdempotentPrivateVoiceExecutor(
            self.runtime_connection, self.store_payload, self.discard_payload)

    def _new_identity(self):
        identity = {
            "subject": "user-" + uuid4().hex,
            "jti": "session-" + uuid4().hex,
            "principal_id": uuid4(), "actor_id": uuid4(), "source_id": uuid4(),
        }
        identity["session_key"] = derive_session_key(ISSUER, identity["jti"])
        identity["iat"], identity["nbf"] = self.now - 3, self.now - 2
        identity["exp"], identity["session_exp"] = self.now + 180, self.now + 150
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Idempotency fixture',clock_timestamp())",
                      (identity["actor_id"],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                      (identity["source_id"],))
            c.execute("""INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                VALUES(%s,%s,%s,%s,%s,true,true,false,1)""",
                (identity["principal_id"], ISSUER, identity["subject"],
                 identity["actor_id"], identity["source_id"]))
            c.execute("""INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))""",
                (identity["session_key"], identity["principal_id"],
                 identity["iat"], identity["session_exp"]))
        return identity

    def token(self, identity=None, extra=None):
        i = identity or self.identity
        claims = {"iss": ISSUER, "aud": AUD, "sub": i["subject"], "iat": i["iat"],
                  "nbf": i["nbf"], "exp": i["exp"], "jti": i["jti"]}
        if extra:
            claims.update(extra)
        return jwt.encode(claims, self.private_key, algorithm="RS256",
                          headers={"kid": "fixture-key", "typ": "at+jwt"})

    def bind(self, text="idempotent fixture", request_id=REQUEST_ID, identity=None, raw=None, token=None):
        return self.boundary.bind(
            "Bearer " + (token or self.token(identity)),
            raw or draft_body(text, request_id),
        )

    def store_payload(self, voice_id, text):
        ref = "payload:stage:" + voice_id.hex
        with self.payload_lock:
            self.stored_calls.append((voice_id, text, ref))
            self.payloads[ref] = text
        return ref

    def discard_payload(self, ref):
        with self.payload_lock:
            self.discarded.append(ref)
            self.payloads.pop(ref, None)

    def _count(self, relation):
        with self.connect() as c:
            return c.execute(f"SELECT count(*) FROM {relation}").fetchone()[0]

    def db_one(self, sql, params=()):
        with self.connect() as c:
            return c.execute(sql, params).fetchone()

    def assert_counts(self, voices=0, receipts=0):
        self.assertEqual(self._count("echo_core.voice_revisions"), self.voice_before + voices)
        self.assertEqual(self._count("echo_identity.private_draft_receipts"), self.receipt_before + receipts)

    def execute_error(self, intent, code):
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            self.executor.execute(intent)
        self.assertEqual(ctx.exception.code, code)

    def test_01_first_request_creates_one_private_voice_and_immutable_receipt(self):
        intent = self.bind()
        receipt = self.executor.execute(intent)
        self.assertIsInstance(receipt, IdempotentPrivateVoiceReceipt)
        self.assertFalse(receipt.replayed)
        row = self.db_one("""SELECT r.request_id,r.request_hash,r.voice_id,r.revision,r.visibility,r.recorded_at,
                                    v.author_id,v.source_id,v.payload_ref
                               FROM echo_identity.private_draft_receipts r
                               JOIN echo_core.voice_revisions v USING(voice_id,revision)
                              WHERE r.principal_id=%s AND r.request_id=%s""",
                          (self.identity["principal_id"], REQUEST_ID))
        self.assertEqual(row[0], REQUEST_ID)
        self.assertEqual(len(row[1]), 64)
        self.assertEqual(row[2:6], (receipt.voice_id, 1, "PRIVATE", receipt.recorded_at))
        self.assertEqual(row[6:8], (self.identity["actor_id"], self.identity["source_id"]))
        self.assertEqual(row[8], self.stored_calls[0][2])
        self.assert_counts(1, 1)

    def test_02_exact_retry_returns_same_receipt_without_duplicate_voice(self):
        intent = self.bind()
        first = self.executor.execute(intent)
        second = self.executor.execute(intent)
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.voice_id, second.voice_id)
        self.assertEqual(first.recorded_at, second.recorded_at)
        self.assertEqual(len(self.stored_calls), 2)
        self.assertEqual(self.discarded, [self.stored_calls[1][2]])
        self.assertEqual(set(self.payloads), {self.stored_calls[0][2]})
        self.assert_counts(1, 1)

    def test_03_same_key_with_changed_text_is_conflict_and_never_duplicates(self):
        first = self.executor.execute(self.bind("original text"))
        self.execute_error(self.bind("changed text"), "IDEMPOTENCY_KEY_REUSED")
        self.assertEqual(self._count("echo_core.voice_revisions"), self.voice_before + 1)
        self.assertEqual(self._count("echo_identity.private_draft_receipts"), self.receipt_before + 1)
        self.assertEqual(self.db_one("SELECT voice_id FROM echo_identity.private_draft_receipts WHERE principal_id=%s AND request_id=%s",
                                     (self.identity["principal_id"], REQUEST_ID))[0], first.voice_id)
        self.assertEqual(len(self.discarded), 1)

    def test_04_concurrent_exact_retry_serializes_to_one_fresh_one_replay(self):
        intent = self.bind("parallel retry")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.executor.execute(intent), range(2)))
        self.assertEqual({r.voice_id for r in results}, {results[0].voice_id})
        self.assertEqual(sorted(r.replayed for r in results), [False, True])
        self.assert_counts(1, 1)
        self.assertEqual(len(self.stored_calls), 2)
        self.assertEqual(len(self.discarded), 1)
        self.assertEqual(len(self.payloads), 1)

    def test_05_same_request_id_is_scoped_by_principal_not_global(self):
        other = self._new_identity()
        a = self.executor.execute(self.bind("same key A", identity=self.identity))
        b = self.executor.execute(self.bind("same key B", identity=other))
        self.assertNotEqual(a.voice_id, b.voice_id)
        self.assertFalse(a.replayed); self.assertFalse(b.replayed)
        self.assert_counts(2, 2)

    def test_06_revoked_session_cannot_use_old_receipt_as_authorization(self):
        intent = self.bind()
        self.executor.execute(intent)
        with self.connect() as c:
            c.execute("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",
                      (self.identity["session_key"],))
        self.execute_error(intent, "PRIVATE_VOICE_WRITE_REJECTED")
        self.assert_counts(1, 1)
        self.assertEqual(len(self.discarded), 1)

    def test_07_role_version_change_after_success_denies_retry(self):
        intent = self.bind()
        self.executor.execute(intent)
        with self.connect() as c:
            c.execute("""UPDATE echo_identity.principals
                       SET writer_enabled=false,auth_version=2 WHERE principal_id=%s""",
                      (self.identity["principal_id"],))
        self.execute_error(intent, "PRIVATE_VOICE_WRITE_REJECTED")
        self.assert_counts(1, 1)

    def test_08_browser_cannot_supply_hash_voice_or_receipt_metadata(self):
        attempts = [
            ({"request_hash": "f" * 64}, None),
            (None, {"request_hash": "f" * 64}),
            (None, {"voice_id": str(uuid4())}),
            (None, {"receipt": {"replayed": True}}),
            (None, {"visibility": "PUBLIC"}),
        ]
        for top, payload in attempts:
            with self.subTest(top=top, payload=payload):
                with self.assertRaises(BoundaryError) as ctx:
                    self.bind(raw=draft_body(top=top, payload=payload))
                self.assertEqual(ctx.exception.code, "INVALID_COMMAND")
        self.assert_counts(0, 0)

    def test_09_runtime_cannot_bypass_receipt_using_old_non_idempotent_writer(self):
        old = PrivateVoiceExecutor(self.runtime_connection, self.store_payload, self.discard_payload)
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            old.execute(self.bind())
        self.assertEqual(ctx.exception.code, "PRIVATE_VOICE_WRITE_REJECTED")
        self.assertEqual(len(self.discarded), 1)
        self.assert_counts(0, 0)

    def test_10_runtime_has_no_direct_receipt_table_privileges(self):
        statements = [
            "SELECT * FROM echo_identity.private_draft_receipts",
            "INSERT INTO echo_identity.private_draft_receipts(principal_id,request_id,request_hash,voice_id,revision,visibility,recorded_at) VALUES(%s,%s,%s,%s,1,'PRIVATE',clock_timestamp())",
            "UPDATE echo_identity.private_draft_receipts SET request_hash=request_hash",
            "DELETE FROM echo_identity.private_draft_receipts",
        ]
        for index, sql in enumerate(statements):
            with self.subTest(index=index):
                c = self.runtime_connection()
                try:
                    params = () if index != 1 else (self.identity["principal_id"], REQUEST_ID, "f"*64, uuid4())
                    with self.assertRaises(psycopg.Error) as ctx:
                        c.execute(sql, params)
                    self.assertEqual(ctx.exception.sqlstate, "42501")
                finally:
                    c.close()

    def test_11_receipt_is_immutable_even_to_migration_owner_normal_dml(self):
        self.executor.execute(self.bind())
        for sql in [
            "UPDATE echo_identity.private_draft_receipts SET request_hash='f'||substr(request_hash,2)",
            "DELETE FROM echo_identity.private_draft_receipts WHERE principal_id=%s",
            "TRUNCATE echo_identity.private_draft_receipts",
        ]:
            with self.subTest(sql=sql):
                with self.connect() as c:
                    params = (self.identity["principal_id"],) if "%s" in sql else ()
                    with self.assertRaises(psycopg.Error) as ctx:
                        c.execute(sql, params)
                    self.assertEqual(ctx.exception.sqlstate, "55000")
        self.assert_counts(1, 1)

    def test_12_owner_connection_is_rejected_before_database_execution(self):
        executor = IdempotentPrivateVoiceExecutor(self.connect, self.store_payload, self.discard_payload)
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            executor.execute(self.bind())
        self.assertEqual(ctx.exception.code, "RUNTIME_ROLE_REQUIRED")
        self.assertEqual(len(self.discarded), 1)
        self.assert_counts(0, 0)

    def test_13_signed_role_hints_never_change_canonical_authority(self):
        token = self.token(extra={"actor_id": str(uuid4()), "source_id": str(uuid4()),
                                  "role": "admin", "scope": "publish:*"})
        receipt = self.executor.execute(self.bind(token=token))
        row = self.db_one("SELECT author_id,source_id,visibility FROM echo_core.voice_revisions WHERE voice_id=%s",
                          (receipt.voice_id,))
        self.assertEqual(row, (self.identity["actor_id"], self.identity["source_id"], "PRIVATE"))
        self.assert_counts(1, 1)

    def test_14_failed_voice_insert_rolls_back_receipt_reservation(self):
        collision = uuid4()
        with self.connect() as c:
            c.execute("""INSERT INTO echo_core.voice_revisions
                (voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
                VALUES(%s,1,NULL,%s,%s,'fixture:existing','PRIVATE',NULL,clock_timestamp())""",
                (collision, self.identity["actor_id"], self.identity["source_id"]))
        baseline_voices = self._count("echo_core.voice_revisions")
        with patch.object(idem_module, "uuid4", return_value=collision):
            self.execute_error(self.bind("collision request", uuid4()), "PRIVATE_VOICE_WRITE_REJECTED")
        self.assertEqual(self._count("echo_core.voice_revisions"), baseline_voices)
        self.assertEqual(self._count("echo_identity.private_draft_receipts"), self.receipt_before)
        self.assertEqual(len(self.discarded), 1)

    def test_15_different_request_ids_create_distinct_receipts_for_same_principal(self):
        first = self.executor.execute(self.bind("one", uuid4()))
        second = self.executor.execute(self.bind("two", uuid4()))
        self.assertNotEqual(first.voice_id, second.voice_id)
        self.assert_counts(2, 2)

    def test_16_request_id_is_not_voice_id_and_receipt_is_server_canonical(self):
        intent = self.bind()
        receipt = self.executor.execute(intent)
        self.assertNotEqual(receipt.voice_id, intent.request_id)
        self.assertEqual(self.db_one("SELECT voice_id FROM echo_identity.private_draft_receipts WHERE principal_id=%s AND request_id=%s",
                                     (self.identity["principal_id"], intent.request_id))[0], receipt.voice_id)
        self.assert_counts(1, 1)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(IdempotentPrivateVoiceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print("P2_1C2D3C_IDEMPOTENT_PRIVATE_SUITE_SAT", flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
