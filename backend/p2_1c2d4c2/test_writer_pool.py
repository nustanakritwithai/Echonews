from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

import jwt
import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for rel in ('p2_1c2b1','p2_1c2c3','p2_1c2d3b','p2_1c2d3c','p2_1c2d3d','p2_1c2d4c2'):
    sys.path.insert(0, str(HERE.parent / rel))

from identity_boundary import Boundary, Config  # noqa:E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa:E402
from private_voice_executor import PrivateVoiceExecutionError  # noqa:E402
from recoverable_private_voice_executor import (  # noqa:E402
    PayloadRecoveryCoordinator, RecoverablePrivateVoiceExecutor,
)
from test_recoverable_private_voice_executor import FilePayloadStore, draft_body  # noqa:E402
from writer_pool import WriterPool, WriterPoolError, SERVICE, RUNTIME  # noqa:E402

DB_NAME = 'echo_writer_pool_test'
ISSUER = 'https://issuer.writer-pool.fixture.invalid/echo'
AUD = 'echo-writer-pool-fixture'
GUARD = 'echo_private_draft_guard'
OWNER_RUNTIME = 'echo_private_owner_read_runtime'
OWNER_GUARD = 'echo_private_owner_read_guard'
OWNER_SERVICE = 'echo_private_owner_read_service'
PUBLIC_READER = 'echo_public_reader'


class WriterPoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != DB_NAME
                or os.environ.get('PGHOST') not in ('127.0.0.1','localhost')):
            raise RuntimeError('refusing non-disposable or non-loopback database')
        with cls.connect() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('this gate must run on PostgreSQL 17')
            dirty = c.execute('''SELECT to_regnamespace('echo_core') IS NOT NULL
                OR to_regnamespace('echo_identity') IS NOT NULL
                OR to_regnamespace('echo_history') IS NOT NULL
                OR to_regnamespace('echo_public') IS NOT NULL
                OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=ANY(%s))''',
                ([SERVICE,RUNTIME,GUARD,OWNER_RUNTIME,OWNER_GUARD,OWNER_SERVICE,PUBLIC_READER],)).fetchone()[0]
            if dirty:
                raise RuntimeError('refusing database/cluster with pre-existing Echo test objects')
            for path in (
                'database/p2_1b/schema.sql',
                'database/p2_1c/001_immutable_history.sql',
                'database/p2_1c2a/001_public_voice_read.sql',
                'database/p2_1c2c/001_identity_registry.sql',
                'database/p2_1c2d1/001_write_fence.sql',
                'database/p2_1c2d2/001_runtime_roles.sql',
                'database/p2_1c2d3/001_private_voice_write.sql',
                'database/p2_1c2d3c/001_idempotent_private_receipt.sql',
                'database/p2_1c2d3d/001_payload_recovery.sql',
                'database/p2_1c2d4a/001_private_owner_read.sql',
                'database/p2_1c2d4c/001_owner_read_service.sql',
                'database/p2_1c2d4c2/001_writer_service.sql',
            ):
                c.execute((ROOT / path).read_text(encoding='utf-8'))
        cls.service_password = secrets.token_urlsafe(40)
        with cls.connect() as c:
            c.execute("SET password_encryption='scram-sha-256'")
            c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(SERVICE), sql.Literal(cls.service_password)))
        try:
            conn = psycopg.connect(**cls.service_kwargs(password='deliberately-wrong-password'))
        except psycopg.OperationalError:
            pass
        else:
            conn.close()
            raise RuntimeError('Test database accepts incorrect password; LOGIN proof unavailable')
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, 'writer-pool-keyset-v1', {'fixture-key': cls.private_key.public_key()})
        cls.registry = PostgresRegistryAdapter(cls.connect)
        cls.boundary = Boundary(cls.config, resolve_binding=cls.registry.resolve_binding)
        cls.tmp = tempfile.TemporaryDirectory(prefix='echo-writer-pool-')
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def connect():
        return psycopg.connect(connect_timeout=3,
            options='-c statement_timeout=10000 -c lock_timeout=6000 -c idle_in_transaction_session_timeout=15000')

    @classmethod
    def service_kwargs(cls, **updates):
        base = dict(host='127.0.0.1', port=int(os.environ.get('PGPORT','5432')),
                    dbname=DB_NAME, user=SERVICE, password=cls.service_password,
                    sslmode='disable', connect_timeout=3)
        base.update(updates)
        return base

    @classmethod
    def cleanup(cls):
        cls.tmp.cleanup()
        with cls.connect() as c:
            for role in (SERVICE, OWNER_SERVICE):
                if c.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)',(role,)).fetchone()[0]:
                    c.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
                    c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
            c.execute('DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_public CASCADE; '
                      'DROP SCHEMA echo_history CASCADE; DROP SCHEMA echo_core CASCADE;')
            for role in (OWNER_RUNTIME, OWNER_GUARD, RUNTIME, GUARD, PUBLIC_READER):
                if c.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)',(role,)).fetchone()[0]:
                    c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
        print('CLEAN_WRITER_POOL_DATABASE', flush=True)

    def setUp(self):
        self.now = int(time.time())
        self.identity = self.new_identity()
        args = self.service_kwargs(); args.pop('connect_timeout')
        self.pool = WriterPool(**args, allow_insecure_test_loopback=True)
        self.pool.open(); self.addCleanup(self.pool.close)
        self.store_dir = Path(self.tmp.name) / uuid4().hex
        self.store = FilePayloadStore(self.store_dir)
        self.recovery = PayloadRecoveryCoordinator(self.pool.connection, self.store)
        self.executor = RecoverablePrivateVoiceExecutor(self.pool.connection, self.store)
        self.voice_before = self.count('echo_core.voice_revisions')
        self.receipt_before = self.count('echo_identity.private_draft_receipts')
        self.attempt_before = self.count('echo_identity.private_payload_attempts')

    def new_identity(self):
        i = {'subject':'writer-'+uuid4().hex, 'jti':'session-'+uuid4().hex,
             'principal_id':uuid4(), 'actor_id':uuid4(), 'source_id':uuid4(), 'auth_version':1}
        i['session_key'] = derive_session_key(ISSUER, i['jti'])
        i['iat'], i['nbf'], i['exp'], i['session_exp'] = self.now-3, self.now-2, self.now+180, self.now+150
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Writer pool fixture',clock_timestamp())",(i['actor_id'],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",(i['source_id'],))
            c.execute('''INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                VALUES(%s,%s,%s,%s,%s,true,true,false,1)''',
                (i['principal_id'],ISSUER,i['subject'],i['actor_id'],i['source_id']))
            c.execute('''INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))''',
                (i['session_key'],i['principal_id'],i['iat'],i['session_exp']))
        return i

    def token(self, identity=None):
        i = identity or self.identity
        claims = {'iss':ISSUER,'aud':AUD,'sub':i['subject'],'iat':i['iat'],'nbf':i['nbf'],
                  'exp':i['exp'],'jti':i['jti']}
        return jwt.encode(claims,self.private_key,algorithm='RS256',headers={'kid':'fixture-key','typ':'at+jwt'})

    def bind(self, text='writer pool durable fixture', request_id=None):
        return self.boundary.bind('Bearer '+self.token(), draft_body(text, request_id or uuid4()))

    def count(self, relation):
        with self.connect() as c:
            return c.execute(f'SELECT count(*) FROM {relation}').fetchone()[0]

    def assert_pool_error(self, code, call):
        with self.assertRaises(WriterPoolError) as ctx:
            call()
        self.assertEqual(ctx.exception.code, code)

    def acquire(self):
        with self.pool.connection() as c:
            return c.info.backend_pid

    def test_01_service_is_real_login_and_lease_is_exact_writer_runtime(self):
        with self.pool.connection() as c:
            self.assertEqual(c.info.user,SERVICE)
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,RUNTIME))
            self.assertEqual(c.info.transaction_status,TransactionStatus.INTRANS)
        with self.connect() as bad:
            bad.execute(sql.SQL('SET SESSION AUTHORIZATION {}').format(sql.Identifier(SERVICE)))
            bad.commit()
            self.assert_pool_error('SERVICE_LOGIN_REQUIRED',lambda:self.pool._sanitize(bad))

    def test_02_login_has_no_default_echo_table_or_function_authority(self):
        with psycopg.connect(**self.service_kwargs(),autocommit=True) as c:
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,SERVICE))
            for statement in ('SELECT * FROM echo_core.voice_revisions',
                              'SELECT * FROM echo_identity.private_payload_attempts',
                              'SELECT * FROM echo_identity.principals'):
                with self.subTest(statement=statement),self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    c.execute(statement)
            self.assertFalse(c.execute("SELECT has_function_privilege(current_user,'echo_identity.runtime_get_private_payload_attempt(uuid)','EXECUTE')").fetchone()[0])

    def test_03_runtime_cannot_switch_to_guard_reader_public_or_owner(self):
        targets=[GUARD,OWNER_GUARD,OWNER_RUNTIME,OWNER_SERVICE,PUBLIC_READER,os.environ['PGUSER']]
        for role in targets:
            with self.subTest(role=role),self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.pool.connection() as c:
                    c.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
        self.acquire()

    def test_04_same_backend_reused_clean_after_success(self):
        with self.pool.connection() as c:
            pid=c.info.backend_pid
            c.execute("SET echo.writer_marker='request-A'")
            c.execute('SET search_path=public,pg_catalog')
            c.execute('SET row_security=off')
            c.execute("SET TimeZone='Asia/Bangkok'")
            c.execute('CREATE TEMP TABLE writer_fixture_secret(x text)')
            c.execute("INSERT INTO writer_fixture_secret VALUES ('synthetic-private-A')")
            c.execute('PREPARE writer_fixture_plan AS SELECT 42')
            c.execute('LISTEN writer_fixture_channel')
            c.execute('SELECT pg_advisory_lock(28831,17)')
        with self.pool.connection() as c:
            self.assertEqual(c.info.backend_pid,pid)
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,RUNTIME))
            self.assertIn(c.execute("SELECT current_setting('echo.writer_marker',true)").fetchone()[0],(None,''))
            self.assertEqual(c.execute('SHOW search_path').fetchone()[0],'pg_catalog')
            self.assertEqual(c.execute('SHOW row_security').fetchone()[0],'on')
            self.assertEqual(c.execute('SHOW TimeZone').fetchone()[0],'UTC')
            self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.writer_fixture_secret')").fetchone()[0])
            self.assertEqual(c.execute('SELECT count(*) FROM pg_prepared_statements').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT count(*) FROM pg_listening_channels()').fetchone()[0],0)
            self.assertEqual(c.execute("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'").fetchone()[0],0)

    def test_05_exception_rolls_back_and_resets_same_connection(self):
        pid=None
        with self.assertRaisesRegex(RuntimeError,'injected-writer-error'):
            with self.pool.connection() as c:
                pid=c.info.backend_pid
                c.execute("SET echo.writer_marker='not-for-next-request'")
                raise RuntimeError('injected-writer-error')
        with self.pool.connection() as c:
            self.assertEqual(c.info.backend_pid,pid)
            self.assertIn(c.execute("SELECT current_setting('echo.writer_marker',true)").fetchone()[0],(None,''))

    def test_06_failed_sql_transaction_not_returned_poisoned(self):
        with self.assertRaises(psycopg.errors.DivisionByZero):
            with self.pool.connection() as c:
                pid=c.info.backend_pid
                c.execute('SELECT 1/0')
        with self.pool.connection() as c:
            self.assertEqual(c.info.backend_pid,pid)
            self.assertEqual(c.execute('SELECT 7').fetchone(),(7,))

    def test_07_cleanup_fault_discards_connection_without_replaying_work(self):
        original=self.pool._sanitize; count=0
        def fail_at_release(c):
            nonlocal count
            count += 1
            if count == 2:
                raise WriterPoolError('INJECTED_RESET_FAILURE')
            return original(c)
        with patch.object(self.pool,'_sanitize',fail_at_release):
            with self.assertRaises(WriterPoolError) as ctx:
                with self.pool.connection() as c:
                    old=c; pid=c.info.backend_pid
                    c.execute('SELECT 1')
            self.assertEqual(ctx.exception.code,'POOL_RESET_FAILED')
        self.assertTrue(old.closed)
        self.assertNotEqual(self.acquire(),pid)

    def test_08_dirty_idle_pool_entry_is_sanitized_before_borrower(self):
        c=self.pool._pool.getconn(); pid=c.info.backend_pid
        c.execute('SET ROLE echo_private_draft_runtime')
        c.execute("SET echo.writer_marker='leftover'")
        self.pool._pool.putconn(c)
        with self.pool.connection() as clean:
            self.assertEqual(clean.info.backend_pid,pid)
            self.assertIn(clean.execute("SELECT current_setting('echo.writer_marker',true)").fetchone()[0],(None,''))

    def test_09_two_workers_do_not_share_one_simultaneous_lease(self):
        barrier=threading.Barrier(2)
        def work(label):
            barrier.wait(timeout=3)
            with self.pool.connection() as c:
                before=c.execute("SELECT current_setting('echo.writer_marker',true)").fetchone()[0]
                c.execute("SELECT set_config('echo.writer_marker',%s,false)",(label,))
                c.execute('SELECT pg_sleep(0.03)')
                after=c.execute("SELECT current_setting('echo.writer_marker')").fetchone()[0]
                return c.info.backend_pid,before,after
        with ThreadPoolExecutor(max_workers=2) as ex:
            results=[f.result(timeout=8) for f in [ex.submit(work,'A'),ex.submit(work,'B')]]
        self.assertEqual(results[0][0],results[1][0])
        self.assertTrue(all(r[1] in (None,'') for r in results))
        self.assertEqual(sorted(r[2] for r in results),['A','B'])

    def test_10_membership_drift_fails_closed(self):
        self.acquire()
        try:
            with self.connect() as c:
                c.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(
                    sql.Identifier(OWNER_RUNTIME),sql.Identifier(SERVICE)))
            self.assert_pool_error('ROLE_MEMBERSHIP_DRIFT',self.acquire)
        finally:
            with self.connect() as c:
                c.execute(sql.SQL('REVOKE {} FROM {}').format(sql.Identifier(OWNER_RUNTIME),sql.Identifier(SERVICE)))
        self.acquire()

    def test_11_direct_table_grant_drift_is_detected(self):
        try:
            with self.connect() as c:
                c.execute(sql.SQL('GRANT SELECT(payload_ref) ON echo_core.voice_revisions TO {}').format(sql.Identifier(RUNTIME)))
            self.assert_pool_error('DIRECT_TABLE_PRIVILEGE_DRIFT',self.acquire)
        finally:
            with self.connect() as c:
                c.execute(sql.SQL('REVOKE SELECT(payload_ref) ON echo_core.voice_revisions FROM {}').format(sql.Identifier(RUNTIME)))
        self.acquire()

    def test_12_extra_function_grant_drift_is_detected(self):
        signature='echo_identity.runtime_read_private_owner_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid)'
        try:
            with self.connect() as c:
                c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {} TO {}').format(sql.SQL(signature),sql.Identifier(RUNTIME)))
            self.assert_pool_error('FUNCTION_PRIVILEGE_DRIFT',self.acquire)
        finally:
            with self.connect() as c:
                c.execute(sql.SQL('REVOKE EXECUTE ON FUNCTION {} FROM {}').format(sql.SQL(signature),sql.Identifier(RUNTIME)))
        self.acquire()

    def test_13_constructor_rejects_owner_credentials_and_unverified_tls(self):
        args=self.service_kwargs(); args.pop('connect_timeout')
        with self.assertRaises(WriterPoolError):
            WriterPool(**{**args,'user':os.environ['PGUSER']},allow_insecure_test_loopback=True)
        with self.assertRaises(WriterPoolError):
            WriterPool(**{**args,'host':'db.production.invalid'})

    def test_14_manual_role_reset_cannot_silently_survive_lease(self):
        with self.assertRaises(WriterPoolError) as ctx:
            with self.pool.connection() as c:
                c.execute('RESET ROLE')
        self.assertEqual(ctx.exception.code,'LEASE_ROLE_CHANGED')
        self.acquire()

    def test_15_recoverable_executor_succeeds_through_real_service_pool(self):
        receipt=self.executor.execute(self.bind('pooled writer success'))
        self.assertFalse(receipt.replayed)
        with self.connect() as c:
            row=c.execute('SELECT state,payload_ref FROM echo_identity.private_payload_attempts WHERE attempt_id=%s',(receipt.voice_id,)).fetchone()
        self.assertEqual(row[0],'COMMITTED')
        self.assertEqual(self.store.state(row[1]),'COMMITTED')
        self.assertEqual(self.count('echo_core.voice_revisions'),self.voice_before+1)
        self.assertEqual(self.count('echo_identity.private_draft_receipts'),self.receipt_before+1)

    def test_16_exact_retry_is_idempotent_through_reused_service_connection(self):
        intent=self.bind('pooled exact retry')
        first=self.executor.execute(intent); second=self.executor.execute(intent)
        self.assertFalse(first.replayed); self.assertTrue(second.replayed)
        self.assertEqual(first.voice_id,second.voice_id)
        self.assertEqual(self.count('echo_core.voice_revisions'),self.voice_before+1)
        self.assertEqual(self.count('echo_identity.private_draft_receipts'),self.receipt_before+1)
        self.assertEqual(len(self.store.refs()),1)

    def test_17_revocation_is_rechecked_before_external_stage_on_reused_pool(self):
        intent=self.bind('revoked pooled writer')
        pid=self.acquire()
        with self.connect() as c:
            c.execute('UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s',(self.identity['session_key'],))
        with self.assertRaises(PrivateVoiceExecutionError):
            self.executor.execute(intent)
        self.assertEqual(self.count('echo_identity.private_payload_attempts'),self.attempt_before)
        self.assertEqual(self.store.refs(),[])
        self.assertEqual(self.acquire(),pid)

    def test_18_unknown_post_commit_reset_is_not_replayed_and_retry_heals_one_voice(self):
        intent=self.bind('unknown commit pooled writer')
        original=self.pool._sanitize; calls=0
        def fail_after_write_commit(c):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise WriterPoolError('INJECTED_POST_COMMIT_RESET')
            return original(c)
        with patch.object(self.pool,'_sanitize',fail_after_write_commit):
            with self.assertRaises(PrivateVoiceExecutionError):
                self.executor.execute(intent)
        self.assertGreaterEqual(calls,4)
        self.assertEqual(self.count('echo_core.voice_revisions'),self.voice_before+1)
        self.assertEqual(self.count('echo_identity.private_draft_receipts'),self.receipt_before+1)
        healed=self.executor.execute(intent)
        self.assertTrue(healed.replayed)
        self.assertEqual(self.count('echo_core.voice_revisions'),self.voice_before+1)
        self.assertEqual(self.count('echo_identity.private_draft_receipts'),self.receipt_before+1)
        self.assertEqual(len(self.store.refs()),1)


if __name__=='__main__':
    out=Path(os.environ.get('ECHO_WRITER_POOL_RESULTS',str(HERE/'results')))
    out.mkdir(parents=True,exist_ok=True)
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs); self.records=[]
        def addSuccess(self,test):
            super().addSuccess(test); self.records.append({'test':test.id(),'status':'SAT'})
        def addFailure(self,test,err):
            super().addFailure(test,err); self.records.append({'test':test.id(),'status':'VIOL'})
        def addError(self,test,err):
            super().addError(test,err); self.records.append({'test':test.id(),'status':'ERROR'})
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(WriterPoolTests)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    passed=result.wasSuccessful() and result.testsRun==18 and not result.skipped
    import psycopg_pool
    report={'task':'P2.1c.2d.4c.2','tests':result.testsRun,'new_writer_pool_cases':18,
            'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
            'status':'SAT' if passed else 'VIOL','results':result.records,
            'python':sys.version.split()[0],'psycopg':psycopg.__version__,
            'psycopg_pool':psycopg_pool.__version__,'commit':os.environ.get('GITHUB_SHA'),
            'scope':'actual writer service password LOGIN + recoverable/idempotent PRIVATE draft pool; no HTTP/publication/production payload provider'}
    (out/'writer-pool-results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('P2_1C2D4C2_WRITER_POOL_SAT' if passed else 'P2_1C2D4C2_WRITER_POOL_VIOL',flush=True)
    raise SystemExit(0 if passed else 1)
