"""Real service password LOGIN + same-PID pool reuse on disposable PostgreSQL 17.

Inherits 14 unchanged owner adapter cases, replacing ONLY its read connection
callback with the new service pool. Fixture provisioning/writer/identity lookup are
still trusted test infrastructure, NOT production service implementations.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import unittest
from unittest.mock import patch

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent/'p2_1c2d4b'))
import test_private_owner_read_adapter as previous
from owner_read_pool import OwnerReadPool,OwnerReadPoolError,SERVICE,RUNTIME

DB_NAME='echo_owner_read_pool_test'
# Reuse the existing guarded, disposable fixture lifecycle without editing it.
previous.DB_NAME=DB_NAME


class OwnerReadPoolTests(previous.PrivateOwnerReadAdapterTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.service_password=secrets.token_urlsafe(40)
        with cls.connect() as c:
            c.execute((ROOT/'database/p2_1c2d4c/001_owner_read_service.sql').read_text())
            c.execute("SET password_encryption='scram-sha-256'")
            c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(SERVICE),sql.Literal(cls.service_password)))
        # A real password is required: an HBA trust rule would make this fail.
        try:
            conn=psycopg.connect(**cls.service_kwargs(password='deliberately-wrong-password'))
        except psycopg.OperationalError:
            pass
        else:
            conn.close()
            raise RuntimeError('Test database accepts incorrect password; LOGIN proof unavailable')

    @classmethod
    def service_kwargs(cls,**updates):
        return dict(host='127.0.0.1',port=int(os.environ.get('PGPORT','5432')),
                    dbname=DB_NAME,user=SERVICE,password=cls.service_password,
                    sslmode='disable',connect_timeout=3,**updates) if not updates else {
                    **cls.service_kwargs(),**updates}

    @classmethod
    def cleanup(cls):
        # Test-only cluster role and grants. Never operate on any real DB/schema.
        with cls.connect() as c:
            if c.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)',(SERVICE,)).fetchone()[0]:
                c.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(SERVICE)))
                c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(SERVICE)))
        super().cleanup()
        print('CLEAN_OWNER_READ_POOL_DATABASE',flush=True)

    def setUp(self):
        super().setUp()
        args=self.service_kwargs()
        args.pop('connect_timeout')
        self.pool=OwnerReadPool(**args,allow_insecure_test_loopback=True)
        self.pool.open()
        self.addCleanup(self.pool.close)

    def read_connection(self):
        return self.pool.connection()

    def assert_pool_error(self,code,call):
        with self.assertRaises(OwnerReadPoolError) as ctx:
            call()
        self.assertEqual(ctx.exception.code,code)

    def acquire(self):
        with self.pool.connection() as c:
            return c.info.backend_pid

    def test_15_service_is_real_login_not_admin_set_session_authorization(self):
        with self.pool.connection() as c:
            self.assertEqual(c.info.user,SERVICE)
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,RUNTIME))
            self.assertEqual(c.info.transaction_status,TransactionStatus.INTRANS)
        with self.connect() as bad:
            bad.execute(sql.SQL('SET SESSION AUTHORIZATION {}').format(sql.Identifier(SERVICE)))
            bad.commit()
            self.assert_pool_error('SERVICE_LOGIN_REQUIRED',lambda:self.pool._sanitize(bad))

    def test_16_login_has_no_default_echo_table_or_function_authority(self):
        with psycopg.connect(**self.service_kwargs(),autocommit=True) as c:
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,SERVICE))
            for statement in ('SELECT * FROM echo_core.voice_revisions',
                              'SELECT * FROM echo_identity.principals',
                              'SELECT * FROM echo_identity.sessions'):
                with self.subTest(statement=statement),self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    c.execute(statement)

    def test_17_runtime_cannot_switch_to_guard_writer_public_or_owner(self):
        targets=['echo_private_owner_read_guard','echo_private_draft_guard',
                 'echo_private_draft_runtime','echo_public_reader',os.environ['PGUSER']]
        for role in targets:
            with self.subTest(role=role):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with self.pool.connection() as c:
                        c.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
        self.acquire()

    def test_18_same_backend_reused_clean_after_success(self):
        with self.pool.connection() as c:
            pid=c.info.backend_pid
            c.execute("SET echo.fixture_marker='request-A'")
            c.execute("SET search_path=public,pg_catalog")
            c.execute("SET row_security=off")
            c.execute("SET TimeZone='Asia/Bangkok'")
            c.execute('CREATE TEMP TABLE echo_fixture_secret(x text)')
            c.execute("INSERT INTO echo_fixture_secret VALUES ('synthetic-private-A')")
            c.execute('PREPARE echo_fixture_plan AS SELECT 42')
            c.execute('LISTEN echo_fixture_channel')
            c.execute('SELECT pg_advisory_lock(19827,41)')
        with self.pool.connection() as c:
            self.assertEqual(c.info.backend_pid,pid)
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,RUNTIME))
            self.assertIn(c.execute("SELECT current_setting('echo.fixture_marker',true)").fetchone()[0],(None,''))
            self.assertEqual(c.execute('SHOW search_path').fetchone()[0],'pg_catalog')
            self.assertEqual(c.execute('SHOW row_security').fetchone()[0],'on')
            self.assertEqual(c.execute('SHOW TimeZone').fetchone()[0],'UTC')
            self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.echo_fixture_secret')").fetchone()[0])
            self.assertEqual(c.execute('SELECT count(*) FROM pg_prepared_statements').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT count(*) FROM pg_listening_channels()').fetchone()[0],0)
            self.assertEqual(c.execute("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'").fetchone()[0],0)

    def test_19_exception_rolls_back_and_resets_same_connection(self):
        pid=None
        with self.assertRaisesRegex(RuntimeError,'injected-caller-error'):
            with self.pool.connection() as c:
                pid=c.info.backend_pid
                c.execute("SET echo.fixture_marker='not-for-next-request'")
                raise RuntimeError('injected-caller-error')
        with self.pool.connection() as c:
            self.assertEqual(c.info.backend_pid,pid)
            self.assertIn(c.execute("SELECT current_setting('echo.fixture_marker',true)").fetchone()[0],(None,''))

    def test_20_failed_sql_transaction_not_returned_poisoned(self):
        with self.assertRaises(psycopg.errors.DivisionByZero):
            with self.pool.connection() as c:
                pid=c.info.backend_pid
                c.execute('SELECT 1/0')
        with self.pool.connection() as c:
            self.assertEqual(c.info.backend_pid,pid)
            self.assertEqual(c.execute('SELECT 7').fetchone(),(7,))

    def test_21_statement_timeout_does_not_leak_into_next_lease(self):
        with self.assertRaises(psycopg.errors.QueryCanceled):
            with self.pool.connection() as c:
                c.execute("SET LOCAL statement_timeout='20ms'")
                c.execute('SELECT pg_sleep(1)')
        with self.pool.connection() as c:
            self.assertEqual(c.execute('SHOW statement_timeout').fetchone()[0],'10s')

    def test_22_cleanup_fault_discards_connection_not_reuses_it(self):
        original=self.pool._sanitize
        count=0
        def fail_at_release(c):
            nonlocal count
            count+=1
            if count==2:
                raise OwnerReadPoolError('INJECTED_RESET_FAILURE')
            return original(c)
        with patch.object(self.pool,'_sanitize',fail_at_release):
            with self.assertRaises(OwnerReadPoolError) as ctx:
                with self.pool.connection() as c:
                    old=c
                    pid=c.info.backend_pid
            self.assertEqual(ctx.exception.code,'POOL_RESET_FAILED')
        self.assertTrue(old.closed)
        self.assertNotEqual(self.acquire(),pid)

    def test_23_closed_socket_never_reused(self):
        with self.assertRaises((OwnerReadPoolError,psycopg.Error)):
            with self.pool.connection() as c:
                pid=c.info.backend_pid
                c.close()
        self.assertNotEqual(self.acquire(),pid)

    def test_24_dirty_idle_pool_entry_sanitized_before_borrower(self):
        # Fault injection into library internals, NOT an interface exposed to client.
        c=self.pool._pool.getconn()
        pid=c.info.backend_pid
        c.execute('SET ROLE echo_private_owner_read_runtime')
        c.execute("SET echo.fixture_marker='leftover'")
        self.pool._pool.putconn(c)
        with self.pool.connection() as clean:
            self.assertEqual(clean.info.backend_pid,pid)
            self.assertIn(clean.execute("SELECT current_setting('echo.fixture_marker',true)").fetchone()[0],(None,''))

    def test_25_two_workers_cannot_share_simultaneous_lease(self):
        barrier=threading.Barrier(2)
        def work(label):
            barrier.wait(timeout=3)
            with self.pool.connection() as c:
                before=c.execute("SELECT current_setting('echo.fixture_marker',true)").fetchone()[0]
                c.execute("SELECT set_config('echo.fixture_marker',%s,false)",(label,))
                c.execute('SELECT pg_sleep(0.03)')
                after=c.execute("SELECT current_setting('echo.fixture_marker')").fetchone()[0]
                return c.info.backend_pid,before,after
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures=[executor.submit(work,label) for label in ('A','B')]
            results=[f.result(timeout=8) for f in futures]
        self.assertEqual(results[0][0],results[1][0])
        self.assertTrue(all(r[1] in (None,'') for r in results))
        self.assertEqual([r[2] for r in results],['A','B'])

    def test_26_membership_drift_fails_closed_even_on_existing_connection(self):
        self.acquire()
        try:
            with self.connect() as c:
                c.execute(sql.SQL('GRANT echo_private_draft_runtime TO {} WITH INHERIT FALSE, SET TRUE').format(sql.Identifier(SERVICE)))
            self.assert_pool_error('ROLE_MEMBERSHIP_DRIFT',self.acquire)
        finally:
            with self.connect() as c:
                c.execute(sql.SQL('REVOKE echo_private_draft_runtime FROM {}').format(sql.Identifier(SERVICE)))
        self.acquire()

    def test_27_direct_column_grant_drift_is_detected(self):
        try:
            with self.connect() as c:
                c.execute(sql.SQL('GRANT SELECT(payload_ref) ON echo_core.voice_revisions TO {}').format(sql.Identifier(RUNTIME)))
            self.assert_pool_error('DIRECT_TABLE_PRIVILEGE_DRIFT',self.acquire)
        finally:
            with self.connect() as c:
                c.execute(sql.SQL('REVOKE SELECT(payload_ref) ON echo_core.voice_revisions FROM {}').format(sql.Identifier(RUNTIME)))
        self.acquire()

    def test_28_constructor_rejects_owner_credentials_and_unverified_tls(self):
        args=self.service_kwargs()
        args.pop('connect_timeout')
        with self.assertRaises(OwnerReadPoolError):
            OwnerReadPool(**{**args,'user':os.environ['PGUSER']},allow_insecure_test_loopback=True)
        with self.assertRaises(OwnerReadPoolError):
            OwnerReadPool(**{**args,'host':'db.production.invalid'})

    def test_29_manual_role_switch_cannot_silently_survive_lease(self):
        with self.assertRaises(OwnerReadPoolError) as ctx:
            with self.pool.connection() as c:
                c.execute('RESET ROLE')
        self.assertEqual(ctx.exception.code,'LEASE_ROLE_CHANGED')
        self.acquire()

    def test_30_cross_owner_read_does_not_inherit_previous_owner(self):
        voice,_=self.create_voice(text='owner-A-synthetic-private')
        a=self.reader.read('Bearer '+self.token(),self.body(voice))
        self.assertEqual(a.text,'owner-A-synthetic-private')
        other=self.new_identity()
        self.assertIsNone(self.reader.read('Bearer '+self.token(other),self.body(voice)))
        self.assertEqual(self.reader.read('Bearer '+self.token(),self.body(voice)).text,a.text)

    def test_31_revocation_is_rechecked_with_a_reused_service_connection(self):
        voice,_=self.create_voice()
        self.reader.read('Bearer '+self.token(),self.body(voice))
        pid=self.acquire()
        with self.connect() as c:
            c.execute('UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s',(self.identity['session_key'],))
        self.assert_error('IDENTITY_REJECTED',lambda:self.reader.read('Bearer '+self.token(),self.body(voice)))
        self.assertEqual(self.acquire(),pid)

    def test_32_normal_service_cannot_set_replica_or_elevated_session_user(self):
        for statement in ("SET session_replication_role=replica",'SET SESSION AUTHORIZATION echo_private_owner_read_guard'):
            with self.subTest(statement=statement),self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.pool.connection() as c:
                    c.execute(statement)


if __name__=='__main__':
    out=Path(os.environ.get('ECHO_POOL_RESULTS',str(HERE/'results')))
    out.mkdir(parents=True,exist_ok=True)
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            self.records=[]
        def addSuccess(self,test):
            super().addSuccess(test)
            self.records.append({'test':test.id(),'status':'SAT'})
        def addFailure(self,test,err):
            super().addFailure(test,err)
            self.records.append({'test':test.id(),'status':'VIOL'})
        def addError(self,test,err):
            super().addError(test,err)
            self.records.append({'test':test.id(),'status':'ERROR'})
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(OwnerReadPoolTests)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    passed=result.wasSuccessful() and result.testsRun==32 and not result.skipped
    import psycopg_pool
    report={'task':'P2.1c.2d.4c.1','tests':result.testsRun,'new_pool_cases':18,
            'inherited_owner_adapter_cases':14,'failures':len(result.failures),
            'errors':len(result.errors),'skipped':len(result.skipped),
            'status':'SAT' if passed else 'VIOL','results':result.records,
            'python':sys.version.split()[0],'psycopg':psycopg.__version__,
            'psycopg_pool':psycopg_pool.__version__,'commit':os.environ.get('GITHUB_SHA'),
            'scope':'actual service password LOGIN and dedicated owner-read pool; no production HTTP or writer/registry service pool'}
    (out/'pool-results.json').write_text(json.dumps(report,indent=2))
    print('P2_1C2D4C1_OWNER_READ_POOL_SAT' if passed else 'P2_1C2D4C1_OWNER_READ_POOL_VIOL',flush=True)
    raise SystemExit(0 if passed else 1)
