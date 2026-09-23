from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from uuid import UUID, uuid4

import jwt
import psycopg
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for rel in ("p2_1c2b1", "p2_1c2c3", "p2_1c2d3b", "p2_1c2d3c", "p2_1c2d3d"):
    sys.path.insert(0, str(HERE.parent / rel))

from identity_boundary import Boundary, Config  # noqa:E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa:E402
from private_voice_executor import PrivateVoiceExecutionError  # noqa:E402
from idempotent_private_voice_executor import IdempotentPrivateVoiceExecutor, _request_hash  # noqa:E402
from recoverable_private_voice_executor import (  # noqa:E402
    CALL_RESERVE, CALL_WRITE, PayloadRecoveryCoordinator, RecoverablePrivateVoiceExecutor,
)

DB_NAME = "echo_payload_recovery_test"
RUNTIME = "echo_private_draft_runtime"
GUARD = "echo_private_draft_guard"
ISSUER = "https://issuer.payload.fixture.invalid/echo"
AUD = "echo-commands-fixture"
REQUEST_ID = UUID("20000000-0000-4000-8000-000000000001")


def draft_body(text="durable payload fixture", request_id=REQUEST_ID):
    return json.dumps({"request_id": str(request_id), "command": "CREATE_VOICE_DRAFT",
                       "payload": {"text": text}}, ensure_ascii=False).encode()


class FilePayloadStore:
    """Test-only durable store. Stable ref; state survives object recreation."""
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.fail_stage = False
        self.fail_commit = False

    def _dir(self, attempt_id: UUID) -> Path:
        return self.root / attempt_id.hex

    def _parse(self, ref: str) -> UUID:
        prefix = "payload:v2:"
        if not ref.startswith(prefix):
            raise ValueError("bad ref")
        return UUID(hex=ref[len(prefix):])

    def _ref(self, attempt_id: UUID) -> str:
        return "payload:v2:" + attempt_id.hex

    def stage(self, attempt_id: UUID, text: str) -> str:
        if self.fail_stage:
            raise OSError("fixture stage failure")
        d = self._dir(attempt_id)
        d.mkdir(parents=False, exist_ok=False)
        (d / "payload.txt").write_text(text, encoding="utf-8")
        (d / "state").write_text("STAGED", encoding="ascii")
        return self._ref(attempt_id)

    def commit(self, ref: str) -> None:
        if self.fail_commit:
            raise OSError("fixture commit failure")
        d = self._dir(self._parse(ref))
        state = (d / "state").read_text(encoding="ascii")
        if state == "COMMITTED":
            return
        if state != "STAGED":
            raise OSError("not staged")
        (d / "state").write_text("COMMITTED", encoding="ascii")

    def discard(self, ref: str) -> None:
        d = self._dir(self._parse(ref))
        if not d.exists():
            return
        state = (d / "state").read_text(encoding="ascii")
        if state == "COMMITTED":
            raise OSError("committed payload cannot be discarded")
        shutil.rmtree(d)

    def find_staged(self, attempt_id: UUID) -> str | None:
        d = self._dir(attempt_id)
        if not d.exists():
            return None
        return self._ref(attempt_id) if (d / "state").read_text(encoding="ascii") == "STAGED" else None

    def state(self, ref: str) -> str | None:
        d = self._dir(self._parse(ref))
        return (d / "state").read_text(encoding="ascii") if d.exists() else None

    def refs(self) -> list[str]:
        return sorted(self._ref(UUID(hex=p.name)) for p in self.root.iterdir() if p.is_dir())


class PayloadRecoveryTests(unittest.TestCase):
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
                OR to_regnamespace('echo_identity') IS NOT NULL OR to_regnamespace('echo_history') IS NOT NULL
                OR to_regrole(%s) IS NOT NULL OR to_regrole(%s) IS NOT NULL""", (RUNTIME, GUARD)).fetchone()[0]
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
                "database/p2_1c2d3d/001_payload_recovery.sql",
            ):
                c.execute((ROOT / path).read_text())
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, "fixture-keyset-v1", {"fixture-key": cls.private_key.public_key()})
        cls.adapter = PostgresRegistryAdapter(cls.connect)
        cls.boundary = Boundary(cls.config, resolve_binding=cls.adapter.resolve_binding)
        cls.tmp = tempfile.TemporaryDirectory(prefix="echo-payload-recovery-")
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def connect():
        return psycopg.connect(connect_timeout=3,
            options="-c statement_timeout=10000 -c lock_timeout=6000 -c idle_in_transaction_session_timeout=15000")

    @classmethod
    def runtime_connection(cls):
        c = cls.connect()
        c.execute(f"SET SESSION AUTHORIZATION {RUNTIME}")
        c.commit()
        return c

    @classmethod
    def cleanup(cls):
        cls.tmp.cleanup()
        with cls.connect() as c:
            c.execute("DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_history CASCADE; DROP SCHEMA echo_core CASCADE;")
            c.execute(f"DROP ROLE {RUNTIME}; DROP ROLE {GUARD};")
        print("CLEAN_PAYLOAD_RECOVERY_DATABASE", flush=True)

    def setUp(self):
        self.now = int(time.time())
        self.identity = self._new_identity()
        self.store_dir = Path(self.tmp.name) / uuid4().hex
        self.store = FilePayloadStore(self.store_dir)
        self.recovery = PayloadRecoveryCoordinator(self.runtime_connection, self.store)
        self.executor = RecoverablePrivateVoiceExecutor(self.runtime_connection, self.store)
        self.voice_before = self.count("echo_core.voice_revisions")
        self.receipt_before = self.count("echo_identity.private_draft_receipts")
        self.attempt_before = self.count("echo_identity.private_payload_attempts")

    def _new_identity(self):
        i = {"subject": "user-" + uuid4().hex, "jti": "session-" + uuid4().hex,
             "principal_id": uuid4(), "actor_id": uuid4(), "source_id": uuid4()}
        i["session_key"] = derive_session_key(ISSUER, i["jti"])
        i["iat"], i["nbf"], i["exp"], i["session_exp"] = self.now-3, self.now-2, self.now+180, self.now+150
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Payload fixture',clock_timestamp())", (i["actor_id"],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())", (i["source_id"],))
            c.execute("""INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                VALUES(%s,%s,%s,%s,%s,true,true,false,1)""",
                (i["principal_id"],ISSUER,i["subject"],i["actor_id"],i["source_id"]))
            c.execute("""INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))""",
                (i["session_key"],i["principal_id"],i["iat"],i["session_exp"]))
        return i

    def token(self, identity=None):
        i = identity or self.identity
        claims = {"iss":ISSUER,"aud":AUD,"sub":i["subject"],"iat":i["iat"],"nbf":i["nbf"],"exp":i["exp"],"jti":i["jti"]}
        return jwt.encode(claims,self.private_key,algorithm="RS256",headers={"kid":"fixture-key","typ":"at+jwt"})

    def bind(self, text="durable payload fixture", request_id=REQUEST_ID):
        return self.boundary.bind("Bearer "+self.token(),draft_body(text,request_id))

    def count(self, relation):
        with self.connect() as c:
            return c.execute(f"SELECT count(*) FROM {relation}").fetchone()[0]

    def runtime_one(self, sql, params):
        with self.runtime_connection() as c:
            return c.execute(sql,params).fetchone()

    def reserve_stage_write_without_finalize(self, intent, text=None):
        text = text if text is not None else intent.payload.text
        h = _request_hash(text)
        attempt = uuid4()
        self.runtime_one(CALL_RESERVE, intent.authorization_stamp.private_draft_fence_args() + (intent.request_id,h,attempt))
        ref = self.store.stage(attempt,text)
        row = self.runtime_one(CALL_WRITE, intent.authorization_stamp.private_draft_fence_args() + (intent.request_id,h,attempt,ref))
        return attempt,ref,row

    def make_stale_reserved(self, *, with_stage: bool):
        attempt=uuid4(); h=_request_hash("stale")
        with self.connect() as c:
            c.execute("""INSERT INTO echo_identity.private_payload_attempts
                (attempt_id,principal_id,request_id,request_hash,payload_ref,state,created_at,recover_after,updated_at)
                VALUES(%s,%s,%s,%s,NULL,'RESERVED',clock_timestamp()-interval '10 minutes',
                       clock_timestamp()-interval '5 minutes',clock_timestamp()-interval '10 minutes')""",
                (attempt,self.identity["principal_id"],uuid4(),h))
        ref=self.store.stage(attempt,"stale") if with_stage else None
        return attempt,ref

    def test_01_success_returns_only_after_payload_is_committed(self):
        r=self.executor.execute(self.bind())
        self.assertFalse(r.replayed)
        row=self.runtime_one("SELECT attempt_state,attempt_payload_ref,canonical_payload_state FROM echo_identity.runtime_get_private_payload_attempt(%s)",(r.voice_id,))
        self.assertEqual((row[0],row[2]),("COMMITTED","COMMITTED"))
        self.assertEqual(self.store.state(row[1]),"COMMITTED")
        self.assertEqual(self.count("echo_core.voice_revisions"),self.voice_before+1)
        self.assertEqual(self.count("echo_identity.private_draft_receipts"),self.receipt_before+1)

    def test_02_exact_retry_keeps_one_canonical_payload_and_discards_loser(self):
        intent=self.bind("same")
        a=self.executor.execute(intent); b=self.executor.execute(intent)
        self.assertEqual(a.voice_id,b.voice_id); self.assertFalse(a.replayed); self.assertTrue(b.replayed)
        self.assertEqual(len(self.store.refs()),1)
        self.assertEqual(self.store.state(self.store.refs()[0]),"COMMITTED")
        with self.connect() as c:
            states=[x[0] for x in c.execute("SELECT state FROM echo_identity.private_payload_attempts WHERE principal_id=%s ORDER BY created_at",(self.identity["principal_id"],)).fetchall()]
        self.assertEqual(sorted(states),["COMMITTED","DISCARDED"])

    def test_03_changed_text_conflict_discards_noncanonical_stage(self):
        self.executor.execute(self.bind("original"))
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            self.executor.execute(self.bind("changed"))
        self.assertEqual(ctx.exception.code,"IDEMPOTENCY_KEY_REUSED")
        self.assertEqual(len(self.store.refs()),1)
        self.assertEqual(self.count("echo_core.voice_revisions"),self.voice_before+1)

    def test_04_recovery_finishes_db_committed_payload_after_process_crash(self):
        attempt,ref,row=self.reserve_stage_write_without_finalize(self.bind("crash after db"))
        self.assertEqual(row[7],"NEEDS_COMMIT"); self.assertEqual(self.store.state(ref),"STAGED")
        recreated=PayloadRecoveryCoordinator(self.runtime_connection,FilePayloadStore(self.store_dir))
        snap=recreated.recover_attempt(attempt)
        self.assertEqual(snap.state,"COMMITTED"); self.assertEqual(self.store.state(ref),"COMMITTED")

    def test_05_recovery_is_idempotent_if_store_commit_succeeded_but_db_ack_did_not(self):
        attempt,ref,_=self.reserve_stage_write_without_finalize(self.bind("ack crash"))
        self.store.commit(ref)
        recreated=PayloadRecoveryCoordinator(self.runtime_connection,FilePayloadStore(self.store_dir))
        snap=recreated.recover_attempt(attempt)
        self.assertEqual(snap.state,"COMMITTED"); self.assertEqual(self.store.state(ref),"COMMITTED")

    def test_06_stale_reserved_attempt_with_stage_is_claimed_and_discarded(self):
        attempt,ref=self.make_stale_reserved(with_stage=True)
        recovered,pending=self.recovery.sweep()
        self.assertGreaterEqual(recovered,1); self.assertEqual(pending,0)
        self.assertEqual(self.recovery.snapshot(attempt).state,"DISCARDED")
        self.assertIsNone(self.store.state(ref))

    def test_07_stale_reserved_attempt_without_stage_becomes_discarded_terminal(self):
        attempt,_=self.make_stale_reserved(with_stage=False)
        self.recovery.sweep()
        self.assertEqual(self.recovery.snapshot(attempt).state,"DISCARDED")

    def test_08_store_commit_failure_leaves_needs_commit_for_later_recovery(self):
        self.store.fail_commit=True
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            self.executor.execute(self.bind("commit outage"))
        self.assertEqual(ctx.exception.code,"PAYLOAD_FINALIZATION_PENDING")
        with self.connect() as c:
            row=c.execute("SELECT attempt_id,payload_ref,state FROM echo_identity.private_payload_attempts WHERE principal_id=%s ORDER BY created_at DESC LIMIT 1",(self.identity["principal_id"],)).fetchone()
        self.assertEqual(row[2],"NEEDS_COMMIT")
        self.store.fail_commit=False
        snap=self.recovery.recover_attempt(row[0])
        self.assertEqual(snap.state,"COMMITTED"); self.assertEqual(self.store.state(row[1]),"COMMITTED")

    def test_09_stage_failure_never_creates_voice_and_keeps_durable_reservation(self):
        self.store.fail_stage=True
        with self.assertRaises(PrivateVoiceExecutionError) as ctx:
            self.executor.execute(self.bind("stage outage"))
        self.assertEqual(ctx.exception.code,"PAYLOAD_STORE_UNAVAILABLE")
        self.assertEqual(self.count("echo_core.voice_revisions"),self.voice_before)
        self.assertEqual(self.count("echo_identity.private_draft_receipts"),self.receipt_before)
        with self.connect() as c:
            self.assertEqual(c.execute("SELECT state FROM echo_identity.private_payload_attempts WHERE principal_id=%s ORDER BY created_at DESC LIMIT 1",(self.identity["principal_id"],)).fetchone()[0],"RESERVED")

    def test_10_runtime_has_no_direct_attempt_table_dml_and_old_writer_is_revoked(self):
        for sql in ["SELECT * FROM echo_identity.private_payload_attempts",
                    "UPDATE echo_identity.private_payload_attempts SET state='COMMITTED'",
                    "DELETE FROM echo_identity.private_payload_attempts"]:
            with self.subTest(sql=sql):
                c=self.runtime_connection()
                try:
                    with self.assertRaises(psycopg.Error) as ctx: c.execute(sql)
                    self.assertEqual(ctx.exception.sqlstate,"42501")
                finally: c.close()
        old=IdempotentPrivateVoiceExecutor(self.runtime_connection,
            lambda vid,text:self.store.stage(vid,text),lambda ref:self.store.discard(ref))
        with self.assertRaises(PrivateVoiceExecutionError): old.execute(self.bind("old writer"))

    def test_11_terminal_payload_state_cannot_be_rewound_by_normal_dml(self):
        r=self.executor.execute(self.bind("terminal"))
        with self.connect() as c:
            with self.assertRaises(psycopg.Error) as ctx:
                c.execute("UPDATE echo_identity.private_payload_attempts SET state='ABANDONED' WHERE attempt_id=%s",(r.voice_id,))
            self.assertEqual(ctx.exception.sqlstate,"55000")

    def test_12_needs_commit_cannot_be_discarded_and_ref_mismatch_cannot_be_acked(self):
        attempt,ref,_=self.reserve_stage_write_without_finalize(self.bind("invariant"))
        c=self.runtime_connection()
        try:
            with self.assertRaises(psycopg.Error): c.execute("SELECT echo_identity.runtime_mark_private_payload_discarded(%s)",(attempt,))
            c.rollback()
            with self.assertRaises(psycopg.Error): c.execute("SELECT echo_identity.runtime_mark_private_payload_committed(%s,%s)",(attempt,"payload:v2:"+uuid4().hex))
        finally: c.close()
        self.assertEqual(self.recovery.snapshot(attempt).state,"NEEDS_COMMIT")
        self.recovery.recover_attempt(attempt)

    def test_13_recovery_list_exposes_no_principal_subject_or_request_hash(self):
        attempt,_,_=self.reserve_stage_write_without_finalize(self.bind("minimal recovery view"))
        row=self.runtime_one("SELECT * FROM echo_identity.runtime_list_private_payload_recovery(10) WHERE attempt_id=%s",(attempt,))
        self.assertEqual(len(row),4)
        self.assertEqual(row[0],attempt); self.assertEqual(row[1],"NEEDS_COMMIT")
        self.recovery.recover_attempt(attempt)

    def test_14_reservation_rechecks_current_authority_before_external_stage(self):
        intent=self.bind("revoked before stage")
        with self.connect() as c:
            c.execute("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",(self.identity["session_key"],))
        with self.assertRaises(PrivateVoiceExecutionError): self.executor.execute(intent)
        self.assertEqual(self.count("echo_identity.private_payload_attempts"),self.attempt_before)
        self.assertEqual(self.store.refs(),[])


if __name__ == "__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(PayloadRecoveryTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print("P2_1C2D3D_PAYLOAD_RECOVERY_SUITE_SAT",flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
