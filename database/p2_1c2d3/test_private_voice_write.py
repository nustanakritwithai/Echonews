"""P2.1c.2d.3a — real PostgreSQL atomic PRIVATE Voice append + revoke race proof.

The suite uses synthetic server-owned stamp values. It does NOT claim HTTP/login or
payload-store integration. It proves the DB primitive itself fences authority and
appends immutable PRIVATE revision 1 in one transaction under the runtime role.
"""
from __future__ import annotations

import os
from pathlib import Path
import threading
import time
import unittest
from uuid import UUID, uuid4

import psycopg

ROOT = Path(__file__).resolve().parents[2]
DB_NAME = 'echo_private_voice_write_test'
RUNTIME = 'echo_private_draft_runtime'
GUARD = 'echo_private_draft_guard'
WRITER_SIG = ('echo_identity.runtime_append_private_voice('
              'text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text)')
CALL = 'SELECT * FROM echo_identity.runtime_append_private_voice(' + ','.join(['%s'] * 13) + ')'
STAMP_FIELDS = ('issuer','subject','session_key','principal_id','actor_id','source_id',
                'auth_version','capability','issued_ms','not_before_ms','expires_ms')


class PrivateVoiceWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != DB_NAME
                or os.environ.get('PGHOST') not in ('127.0.0.1', 'localhost')):
            raise RuntimeError('refusing non-disposable or non-loopback database')
        with cls.connect() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('this gate must run on PostgreSQL 17')
            dirty = c.execute("""SELECT to_regnamespace('echo_core') IS NOT NULL
                OR to_regnamespace('echo_identity') IS NOT NULL
                OR to_regnamespace('echo_history') IS NOT NULL
                OR to_regrole(%s) IS NOT NULL OR to_regrole(%s) IS NOT NULL""",
                (RUNTIME, GUARD)).fetchone()[0]
            if dirty:
                raise RuntimeError('refusing database with pre-existing Echo objects/roles')
            for path in (
                'database/p2_1b/schema.sql',
                'database/p2_1c/001_immutable_history.sql',
                'database/p2_1c2c/001_identity_registry.sql',
                'database/p2_1c2d1/001_write_fence.sql',
                'database/p2_1c2d2/001_runtime_roles.sql',
                'database/p2_1c2d3/001_private_voice_write.sql',
            ):
                c.execute((ROOT / path).read_text())
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def connect():
        return psycopg.connect(
            connect_timeout=3,
            options='-c statement_timeout=8000 -c lock_timeout=4000 '
                    '-c idle_in_transaction_session_timeout=12000',
        )

    @classmethod
    def cleanup(cls):
        with cls.connect() as c:
            c.execute('DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_history CASCADE; '
                      'DROP SCHEMA echo_core CASCADE;')
            c.execute(f'DROP ROLE {RUNTIME}; DROP ROLE {GUARD};')
        with cls.connect() as c:
            clean = c.execute("""SELECT to_regnamespace('echo_core') IS NULL
                AND to_regnamespace('echo_identity') IS NULL
                AND to_regnamespace('echo_history') IS NULL
                AND to_regrole(%s) IS NULL AND to_regrole(%s) IS NULL""",
                (RUNTIME, GUARD)).fetchone()[0]
            if not clean:
                raise AssertionError('private-voice cleanup incomplete')
        print('CLEAN_PRIVATE_VOICE_DATABASE', flush=True)

    def setUp(self):
        self.stamp = self.make_fixture()

    def make_fixture(self):
        now_ms = self.scalar('SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint')
        s = dict(
            issuer='https://issuer.private-voice.fixture.invalid/echo',
            subject='user-' + uuid4().hex,
            session_key=uuid4().hex + uuid4().hex,
            principal_id=uuid4(), actor_id=uuid4(), source_id=uuid4(),
            auth_version=1, capability='voice:draft:create',
            issued_ms=now_ms - 5000, not_before_ms=now_ms - 5000,
            expires_ms=now_ms + 120000,
        )
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Private Voice fixture',clock_timestamp())",
                      (s['actor_id'],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                      (s['source_id'],))
            c.execute("""INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled)
                VALUES(%s,%s,%s,%s,%s,true,true,false)""",
                (s['principal_id'],s['issuer'],s['subject'],s['actor_id'],s['source_id']))
            c.execute("""INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s/1000.0),to_timestamp(%s/1000.0))""",
                (s['session_key'],s['principal_id'],s['issued_ms'],s['expires_ms']))
        return s

    def scalar(self, sql, params=()):
        with self.connect() as c:
            return c.execute(sql, params).fetchone()[0]

    def stamp_values(self, stamp=None):
        s = self.stamp if stamp is None else stamp
        return tuple(s[k] for k in STAMP_FIELDS)

    def runtime_connection(self):
        c = self.connect()
        c.execute(f'SET SESSION AUTHORIZATION {RUNTIME}')
        c.commit()
        self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(), (RUNTIME,RUNTIME))
        c.commit()
        return c

    def call_values(self, stamp=None, voice_id=None, payload_ref=None):
        return self.stamp_values(stamp) + (
            voice_id if voice_id is not None else uuid4(),
            payload_ref if payload_ref is not None else ('payload:' + uuid4().hex),
        )

    def runtime_error(self, sql, params=(), state='42501'):
        c = self.runtime_connection()
        try:
            with self.assertRaises(psycopg.Error) as ctx:
                c.execute(sql, params)
            self.assertEqual(ctx.exception.sqlstate, state)
        finally:
            c.rollback(); c.close()

    def test_01_writer_is_sealed_security_definer_and_runtime_has_execute_only(self):
        row = self.scalar("""SELECT jsonb_build_object('owner',r.rolname,'definer',p.prosecdef,'config',p.proconfig)
            FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid=%s::regprocedure""",
            (WRITER_SIG,))
        self.assertEqual(row['owner'], GUARD); self.assertTrue(row['definer'])
        self.assertEqual(row['config'], ['search_path=pg_catalog, pg_temp'])
        self.assertTrue(self.scalar('SELECT has_function_privilege(%s,%s,%s)',
                                    (RUNTIME,WRITER_SIG,'EXECUTE')))
        for privilege in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE'):
            self.assertFalse(self.scalar('SELECT has_table_privilege(%s,%s,%s)',
                (RUNTIME,'echo_core.voice_revisions',privilege)))
        self.assertFalse(self.scalar("SELECT has_table_privilege(%s,'echo_core.voice_revisions','INSERT')", (GUARD,)))
        for column in ('voice_id','revision','previous_revision','author_id','source_id',
                       'payload_ref','visibility','posted_at','recorded_at'):
            self.assertTrue(self.scalar("SELECT has_column_privilege(%s,'echo_core.voice_revisions',%s,'INSERT')",
                                        (GUARD,column)))
        for privilege in ('UPDATE','DELETE','TRUNCATE','SELECT'):
            self.assertFalse(self.scalar('SELECT has_table_privilege(%s,%s,%s)',
                (GUARD,'echo_core.voice_revisions',privilege)))

    def test_02_valid_runtime_call_writes_exactly_one_private_revision_and_audit(self):
        voice_id = uuid4(); payload = 'payload:' + uuid4().hex
        with self.runtime_connection() as c:
            row = c.execute(CALL, self.call_values(voice_id=voice_id,payload_ref=payload)).fetchone()
            self.assertEqual(row[0], voice_id); self.assertEqual(row[1:3], (1,'PRIVATE'))
        with self.connect() as c:
            stored = c.execute("""SELECT revision,previous_revision,author_id,source_id,payload_ref,
                    visibility,posted_at,recorded_at IS NOT NULL
                FROM echo_core.voice_revisions WHERE voice_id=%s""", (voice_id,)).fetchone()
            self.assertEqual(stored, (1,None,self.stamp['actor_id'],self.stamp['source_id'],payload,'PRIVATE',None,True))
            audit = c.execute("""SELECT count(*) FROM echo_history.insert_audit
                WHERE object_table='echo_core.voice_revisions' AND record_key @> %s::jsonb""",
                ('{"voice_id":"'+str(voice_id)+'","revision":1}',)).fetchone()[0]
            self.assertEqual(audit,1)

    def test_03_runtime_cannot_bypass_writer_with_direct_private_or_public_insert(self):
        for visibility in ('PRIVATE','PUBLIC'):
            self.runtime_error("""INSERT INTO echo_core.voice_revisions
                (voice_id,revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
                VALUES(%s,1,%s,%s,'direct',%s,NULL,clock_timestamp())""",
                (uuid4(),self.stamp['actor_id'],self.stamp['source_id'],visibility))
        self.runtime_error('SELECT * FROM echo_core.voice_revisions')

    def test_04_writer_has_no_public_visibility_revision_or_client_clock_parameters(self):
        names = self.scalar("""SELECT proargnames FROM pg_proc WHERE oid=%s::regprocedure""", (WRITER_SIG,))
        self.assertNotIn('p_visibility', names); self.assertNotIn('p_revision', names)
        self.assertNotIn('p_posted_at', names); self.assertNotIn('p_recorded_at', names)
        voice_id=uuid4()
        with self.runtime_connection() as c:
            c.execute(CALL,self.call_values(voice_id=voice_id))
        self.assertEqual(self.scalar('SELECT visibility FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),'PRIVATE')

    def test_05_forged_actor_source_principal_or_generation_is_denied_without_row(self):
        for key,value in (('actor_id',uuid4()),('source_id',uuid4()),('principal_id',uuid4()),('auth_version',2)):
            s=dict(self.stamp);s[key]=value;voice_id=uuid4()
            with self.subTest(field=key):
                self.runtime_error(CALL,self.call_values(stamp=s,voice_id=voice_id))
                self.assertEqual(self.scalar('SELECT count(*) FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),0)

    def test_06_committed_revoke_disable_and_role_removal_each_block_write(self):
        cases=(
            ("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s", 'session_key'),
            ("UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s", 'principal_id'),
            ("UPDATE echo_identity.principals SET writer_enabled=false,auth_version=auth_version+1 WHERE principal_id=%s", 'principal_id'),
        )
        for sql,key in cases:
            s=self.make_fixture(); voice_id=uuid4()
            with self.connect() as c: c.execute(sql,(s[key],))
            with self.subTest(sql=sql):
                self.runtime_error(CALL,self.call_values(stamp=s,voice_id=voice_id))
                self.assertEqual(self.scalar('SELECT count(*) FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),0)

    def test_07_duplicate_voice_id_fails_without_overwriting_original(self):
        voice_id=uuid4(); first='payload:first'
        with self.runtime_connection() as c: c.execute(CALL,self.call_values(voice_id=voice_id,payload_ref=first))
        c=self.runtime_connection()
        try:
            with self.assertRaises(psycopg.Error) as ctx:
                c.execute(CALL,self.call_values(voice_id=voice_id,payload_ref='payload:second'))
            self.assertEqual(ctx.exception.sqlstate,'23505')
        finally:
            c.rollback();c.close()
        self.assertEqual(self.scalar('SELECT payload_ref FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),first)
        self.assertEqual(self.scalar("SELECT count(*) FROM echo_history.insert_audit WHERE object_table='echo_core.voice_revisions' AND record_key @> %s::jsonb",
                                     ('{"voice_id":"'+str(voice_id)+'"}',)),1)

    def test_08_inserted_voice_is_immutable_and_cannot_be_deleted_or_rewritten(self):
        voice_id=uuid4()
        with self.runtime_connection() as c: c.execute(CALL,self.call_values(voice_id=voice_id))
        for sql in (
            "UPDATE echo_core.voice_revisions SET visibility='PUBLIC' WHERE voice_id=%s",
            'DELETE FROM echo_core.voice_revisions WHERE voice_id=%s',
        ):
            with self.connect() as c:
                with self.assertRaises(psycopg.Error) as ctx: c.execute(sql,(voice_id,))
                self.assertEqual(ctx.exception.sqlstate,'55000')
        self.assertEqual(self.scalar('SELECT visibility FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),'PRIVATE')

    def test_09_caller_rollback_removes_voice_and_insert_audit_atomically(self):
        voice_id=uuid4(); c=self.runtime_connection()
        try:
            c.execute(CALL,self.call_values(voice_id=voice_id)); c.rollback()
        finally: c.close()
        self.assertEqual(self.scalar('SELECT count(*) FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),0)
        self.assertEqual(self.scalar("SELECT count(*) FROM echo_history.insert_audit WHERE object_table='echo_core.voice_revisions' AND record_key @> %s::jsonb",
                                     ('{"voice_id":"'+str(voice_id)+'"}',)),0)

    def test_10_invalid_voice_id_or_payload_is_rejected_before_write(self):
        bad=((UUID(int=0),'payload:x'),(uuid4(),''),(uuid4(),' '),(uuid4(),'x'*4097))
        for voice_id,payload in bad:
            with self.subTest(length=len(payload)):
                self.runtime_error(CALL,self.call_values(voice_id=voice_id,payload_ref=payload),'22023')

    def test_11_revoke_that_locks_first_commits_then_blocked_writer_is_denied(self):
        s=self.make_fixture(); voice_id=uuid4(); revoker=self.connect()
        revoker.execute('UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s',(s['session_key'],))
        started=threading.Event();done=threading.Event();result={}
        def writer():
            c=self.runtime_connection();started.set()
            try:
                c.execute(CALL,self.call_values(stamp=s,voice_id=voice_id));c.commit();result['ok']=True
            except psycopg.Error as e:
                c.rollback();result['state']=e.sqlstate
            finally:
                c.close();done.set()
        t=threading.Thread(target=writer,daemon=True);t.start();self.assertTrue(started.wait(2))
        time.sleep(0.25);self.assertFalse(done.is_set(),'writer should wait on uncommitted revoke row lock')
        revoker.commit();revoker.close();self.assertTrue(done.wait(3));t.join(1)
        self.assertEqual(result.get('state'),'42501');self.assertNotIn('ok',result)
        self.assertEqual(self.scalar('SELECT count(*) FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),0)

    def test_12_writer_that_locks_first_commits_before_revoke_can_commit(self):
        s=self.make_fixture();voice_id=uuid4();writer=self.runtime_connection()
        writer.execute(CALL,self.call_values(stamp=s,voice_id=voice_id))
        started=threading.Event();done=threading.Event();result={}
        def revoke():
            c=self.connect();started.set()
            try:
                c.execute('UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s',(s['session_key'],));c.commit();result['ok']=True
            except psycopg.Error as e:
                c.rollback();result['state']=e.sqlstate
            finally:
                c.close();done.set()
        t=threading.Thread(target=revoke,daemon=True);t.start();self.assertTrue(started.wait(2))
        time.sleep(0.25);self.assertFalse(done.is_set(),'revoke must wait for the writer fence transaction')
        writer.commit();writer.close();self.assertTrue(done.wait(3));t.join(1)
        self.assertTrue(result.get('ok'));self.assertNotIn('state',result)
        self.assertEqual(self.scalar('SELECT visibility FROM echo_core.voice_revisions WHERE voice_id=%s',(voice_id,)),'PRIVATE')
        self.assertTrue(self.scalar('SELECT revoked FROM echo_identity.sessions WHERE session_key=%s',(s['session_key'],)))


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(PrivateVoiceWriteTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful(): print('P2_1C2D3A_PRIVATE_VOICE_WRITE_SUITE_SAT',flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
