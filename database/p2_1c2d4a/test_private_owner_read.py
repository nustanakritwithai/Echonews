from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import time
import unittest
from uuid import UUID, uuid4

import psycopg

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DB_NAME = "echo_private_owner_read_test"
ISSUER = "https://issuer.owner-read.fixture.invalid/echo"
WRITER_RUNTIME = "echo_private_draft_runtime"
WRITER_GUARD = "echo_private_draft_guard"
READ_RUNTIME = "echo_private_owner_read_runtime"
READ_GUARD = "echo_private_owner_read_guard"
PUBLIC_READER = "echo_public_reader"

CALL_RESERVE = """SELECT * FROM echo_identity.runtime_reserve_private_payload_attempt(
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
CALL_WRITE = """SELECT * FROM echo_identity.runtime_recoverable_idempotent_append_private_voice(
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
CALL_MARK_COMMITTED = "SELECT echo_identity.runtime_mark_private_payload_committed(%s,%s)"
CALL_READ = """SELECT * FROM echo_identity.runtime_read_private_owner_voice(
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""


class PrivateOwnerReadTests(unittest.TestCase):
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
                OR to_regnamespace('echo_public') IS NOT NULL
                OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=ANY(%s))""",
                ([WRITER_RUNTIME,WRITER_GUARD,READ_RUNTIME,READ_GUARD,PUBLIC_READER],)).fetchone()[0]
            if dirty:
                raise RuntimeError("refusing database/cluster with pre-existing Echo test objects")
            for path in (
                "database/p2_1b/schema.sql",
                "database/p2_1c/001_immutable_history.sql",
                "database/p2_1c2a/001_public_voice_read.sql",
                "database/p2_1c2c/001_identity_registry.sql",
                "database/p2_1c2d1/001_write_fence.sql",
                "database/p2_1c2d2/001_runtime_roles.sql",
                "database/p2_1c2d3/001_private_voice_write.sql",
                "database/p2_1c2d3c/001_idempotent_private_receipt.sql",
                "database/p2_1c2d3d/001_payload_recovery.sql",
                "database/p2_1c2d4a/001_private_owner_read.sql",
            ):
                c.execute((ROOT / path).read_text(encoding="utf-8"))
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def connect():
        return psycopg.connect(connect_timeout=3,
            options="-c statement_timeout=10000 -c lock_timeout=6000 -c idle_in_transaction_session_timeout=15000")

    @classmethod
    def role_connection(cls, role: str):
        c = cls.connect()
        c.execute(f"SET SESSION AUTHORIZATION {role}")
        c.commit()
        return c

    @classmethod
    def cleanup(cls):
        with cls.connect() as c:
            c.execute("DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_public CASCADE; "
                      "DROP SCHEMA echo_history CASCADE; DROP SCHEMA echo_core CASCADE;")
            for role in (READ_RUNTIME,READ_GUARD,WRITER_RUNTIME,WRITER_GUARD,PUBLIC_READER):
                c.execute(f"DROP ROLE {role}")
        print("CLEAN_PRIVATE_OWNER_READ_DATABASE", flush=True)

    def setUp(self):
        self.identity = self.new_identity()

    def new_identity(self):
        now = int(time.time())
        i = {
            "subject": "owner-" + uuid4().hex,
            "session_key": hashlib.sha256(uuid4().bytes).hexdigest(),
            "principal_id": uuid4(), "actor_id": uuid4(), "source_id": uuid4(),
            "auth_version": 1,
            "session_iat": now - 30, "token_iat": now - 20,
            "token_nbf": now - 19, "token_exp": now + 180,
            "session_exp": now + 240,
        }
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Owner read fixture',clock_timestamp())",
                      (i["actor_id"],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                      (i["source_id"],))
            c.execute("""INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                VALUES(%s,%s,%s,%s,%s,true,true,false,1)""",
                (i["principal_id"],ISSUER,i["subject"],i["actor_id"],i["source_id"]))
            c.execute("""INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))""",
                (i["session_key"],i["principal_id"],i["session_iat"],i["session_exp"]))
        return i

    def auth(self, i=None):
        i = i or self.identity
        return (ISSUER,i["subject"],i["session_key"],i["principal_id"],i["actor_id"],i["source_id"],
                i["auth_version"],"voice:draft:create",i["token_iat"]*1000,
                i["token_nbf"]*1000,i["token_exp"]*1000)

    def writer_one(self, sql, params):
        with self.role_connection(WRITER_RUNTIME) as c:
            return c.execute(sql, params).fetchone()

    def read_one(self, voice_id, i=None):
        with self.role_connection(READ_RUNTIME) as c:
            return c.execute(CALL_READ, self.auth(i)+(voice_id,)).fetchone()

    def create_voice(self, i=None, *, text="private owner fixture", committed=True):
        i = i or self.identity
        attempt = uuid4(); request_id = uuid4()
        request_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        payload_ref = "payload:v2:" + attempt.hex
        self.writer_one(CALL_RESERVE, self.auth(i)+(request_id,request_hash,attempt))
        row = self.writer_one(CALL_WRITE, self.auth(i)+(request_id,request_hash,attempt,payload_ref))
        self.assertEqual(row[0], attempt)
        self.assertEqual(row[2], "PRIVATE")
        self.assertEqual(row[7], "NEEDS_COMMIT")
        if committed:
            changed = self.writer_one(CALL_MARK_COMMITTED, (attempt,payload_ref))[0]
            self.assertTrue(changed)
        return attempt,payload_ref

    def append_head(self, voice_id, visibility):
        with self.connect() as c:
            c.execute("""INSERT INTO echo_core.voice_revisions
                (voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
                SELECT voice_id,revision+1,revision,author_id,source_id,%s,%s,NULL,clock_timestamp()
                  FROM echo_core.voice_revisions
                 WHERE voice_id=%s ORDER BY revision DESC LIMIT 1""",
                (f"fixture:head:{visibility.lower()}:{uuid4().hex}",visibility,voice_id))

    def assert_auth_denied(self, params):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege) as ctx:
            with self.role_connection(READ_RUNTIME) as c:
                c.execute(CALL_READ, params).fetchone()
        self.assertEqual(ctx.exception.sqlstate,"42501")

    def test_01_roles_are_nonlogin_separated_and_runtime_has_only_narrow_execute(self):
        signature = ("echo_identity.runtime_read_private_owner_voice"
                     "(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid)")
        with self.connect() as c:
            rows = c.execute("""SELECT rolname,NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
                    AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
                FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname""", ([READ_GUARD,READ_RUNTIME],)).fetchall()
            self.assertEqual(len(rows),2); self.assertTrue(all(r[1] for r in rows))
            self.assertTrue(c.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')",(READ_RUNTIME,signature)).fetchone()[0])
            self.assertFalse(c.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')",(WRITER_RUNTIME,signature)).fetchone()[0])
            self.assertFalse(c.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')",(PUBLIC_READER,signature)).fetchone()[0])
            self.assertEqual(c.execute("""SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
                WHERE r.rolname=ANY(%s)""",([READ_GUARD,READ_RUNTIME],)).fetchone()[0],0)

    def test_02_owner_reads_only_canonical_committed_private_revision(self):
        voice,ref = self.create_voice()
        row = self.read_one(voice)
        self.assertIsNotNone(row)
        self.assertEqual((row[0],row[1],row[2],row[3],row[5]),(voice,1,ref,"PRIVATE","COMMITTED"))

    def test_03_needs_commit_is_hidden_until_durable_ack(self):
        voice,ref = self.create_voice(committed=False)
        self.assertIsNone(self.read_one(voice))
        self.writer_one(CALL_MARK_COMMITTED,(voice,ref))
        self.assertEqual(self.read_one(voice)[5],"COMMITTED")

    def test_04_other_principal_gets_empty_result_without_private_object_oracle(self):
        voice,_ = self.create_voice()
        other = self.new_identity()
        self.assertIsNone(self.read_one(voice,other))
        self.assertIsNotNone(self.read_one(voice,self.identity))

    def test_05_forged_authority_tuple_is_rejected_before_object_lookup(self):
        voice,_ = self.create_voice()
        base = list(self.auth()+ (voice,))
        mutations = {3:uuid4(),4:uuid4(),5:uuid4(),6:2}
        for index,value in mutations.items():
            with self.subTest(index=index):
                params=base.copy(); params[index]=value
                self.assert_auth_denied(tuple(params))

    def test_06_revoked_session_denies_owner_read(self):
        voice,_=self.create_voice()
        with self.connect() as c:
            c.execute("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",(self.identity["session_key"],))
        self.assert_auth_denied(self.auth()+(voice,))

    def test_07_disabled_principal_denies_owner_read(self):
        voice,_=self.create_voice()
        with self.connect() as c:
            c.execute("""UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1
                         WHERE principal_id=%s""",(self.identity["principal_id"],))
        self.assert_auth_denied(self.auth()+(voice,))

    def test_08_removed_writer_capability_denies_owner_read(self):
        voice,_=self.create_voice()
        with self.connect() as c:
            c.execute("""UPDATE echo_identity.principals SET writer_enabled=false,auth_version=auth_version+1
                         WHERE principal_id=%s""",(self.identity["principal_id"],))
        self.assert_auth_denied(self.auth()+(voice,))

    def test_09_newer_withdrawn_head_never_falls_back_to_old_private_revision(self):
        voice,_=self.create_voice()
        self.append_head(voice,"WITHDRAWN")
        self.assertIsNone(self.read_one(voice))

    def test_10_newer_public_head_is_not_private_and_public_projection_sees_only_head(self):
        voice,_=self.create_voice()
        self.append_head(voice,"PUBLIC")
        self.assertIsNone(self.read_one(voice))
        with self.role_connection(PUBLIC_READER) as c:
            row=c.execute("SELECT voice_id,revision FROM echo_public.current_public_voices WHERE voice_id=%s",(voice,)).fetchone()
        self.assertEqual(row,(voice,2))

    def test_11_public_reader_cannot_execute_private_owner_function_and_private_stays_out_of_public_view(self):
        voice,_=self.create_voice()
        with self.role_connection(PUBLIC_READER) as c:
            self.assertIsNone(c.execute("SELECT voice_id FROM echo_public.current_public_voices WHERE voice_id=%s",(voice,)).fetchone())
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.role_connection(PUBLIC_READER) as c:
                c.execute(CALL_READ,self.auth()+(voice,)).fetchone()

    def test_12_owner_read_runtime_has_no_direct_private_or_core_table_select(self):
        for statement in (
            "SELECT * FROM echo_identity.principals",
            "SELECT * FROM echo_identity.private_payload_attempts",
            "SELECT * FROM echo_identity.private_draft_receipts",
            "SELECT * FROM echo_core.voice_revisions",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with self.role_connection(READ_RUNTIME) as c:
                        c.execute(statement).fetchone()

    def test_13_owner_read_runtime_cannot_write_or_mutate_payload_state(self):
        voice,ref=self.create_voice()
        calls = [
            (CALL_MARK_COMMITTED,(voice,ref)),
            ("SELECT echo_identity.runtime_mark_private_payload_discarded(%s)",(voice,)),
            ("SELECT * FROM echo_identity.runtime_list_private_payload_recovery(10)",()),
        ]
        for sql,params in calls:
            with self.subTest(sql=sql):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with self.role_connection(READ_RUNTIME) as c:
                        c.execute(sql,params).fetchone()

    def test_14_writer_runtime_cannot_invoke_private_owner_reader(self):
        voice,_=self.create_voice()
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.role_connection(WRITER_RUNTIME) as c:
                c.execute(CALL_READ,self.auth()+(voice,)).fetchone()

    def test_15_read_runtime_cannot_set_role_to_guard(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.role_connection(READ_RUNTIME) as c:
                c.execute(f"SET ROLE {READ_GUARD}")

    def test_16_unknown_or_invalid_voice_id_does_not_leak_objects(self):
        self.assertIsNone(self.read_one(uuid4()))
        with self.assertRaises(psycopg.errors.InvalidParameterValue) as ctx:
            with self.role_connection(READ_RUNTIME) as c:
                c.execute(CALL_READ,self.auth()+(UUID(int=0),)).fetchone()
        self.assertEqual(ctx.exception.sqlstate,"22023")


if __name__ == "__main__":
    program = unittest.main(exit=False, verbosity=2)
    if program.result.wasSuccessful():
        print("P2_1C2D4A_PRIVATE_OWNER_READ_SUITE_SAT", flush=True)
    sys.exit(0 if program.result.wasSuccessful() else 1)
