"""Real signed token -> first-session -> current-session logout on PostgreSQL 17.
18 inherited bootstrap cases run once; 27 new logout cases. Synthetic credentials.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
from queue import Queue
import secrets
import sys
import time
import unittest
from uuid import uuid4

import psycopg
from psycopg import sql

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE),str(HERE.parent/'p2_1c2d4c5c3')]
import test_signed_first_session as base
from first_session_boundary import SignedFirstSessionBoundary, FirstSessionError, BOOTSTRAP_SQL
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key
from logout_boundary import SignedSessionLogoutBoundary, SessionLogoutError, LOGOUT_SQL, CLOCK_SQL
from logout_pool import LogoutPool, LogoutPoolError, SERVICE, RUNTIME, GUARD, FUNCTION


class SignedLogoutTests(base.SignedFirstSessionTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.logout_password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(SERVICE),sql.Literal(cls.logout_password)))
        cls.logout_pool = LogoutPool(**cls.pool_config())
        cls.logout_pool.open()
        cls.logout_boundary = SignedSessionLogoutBoundary(cls.config,cls.logout_pool.connection)

    @classmethod
    def cleanup(cls):
        if hasattr(cls,'logout_pool'):
            cls.logout_pool.close()
        try:
            super().cleanup()
        finally:
            with cls.admin() as c:
                for role in (SERVICE,RUNTIME,GUARD):
                    c.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
            with cls.admin() as c:
                clean = c.execute("SELECT to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_core') IS NULL AND to_regrole(%s) IS NULL",(SERVICE,)).fetchone()[0]
                if not clean:
                    raise AssertionError('logout fixture cleanup incomplete')
            print('CLEAN_SIGNED_LOGOUT_DATABASE',flush=True)

    @classmethod
    def pool_config(cls, **patch):
        import os
        return dict(host='127.0.0.1',port=int(os.environ.get('PGPORT','5432')),
            dbname=base.DB,user=SERVICE,password=cls.logout_password,sslmode='disable',
            max_size=2,allow_insecure_test_loopback=True) | patch

    @classmethod
    def logout_connection(cls, **patch):
        config = cls.pool_config(**patch)
        for key in ('max_size','allow_insecure_test_loopback'):
            config.pop(key)
        return psycopg.connect(**config,connect_timeout=3)

    def fixture(self, *, lifetime=180):
        principal,subject = self.activated()
        token,claims = self.token(subject,lifetime=lifetime)
        self.boundary.bootstrap('Bearer '+token,b'{}')
        return dict(principal=principal,subject=subject,token=token,claims=claims,
                    key=derive_session_key(base.ISSUER,claims['jti']))

    def logout(self,f,boundary=None,token=None):
        return (boundary or self.logout_boundary).logout('Bearer '+(token or f['token']),b'{}')

    def row(self,f):
        return self.db('SELECT principal_id,auth_version,issued_at,expires_at,revoked FROM echo_identity.sessions WHERE session_key=%s',(f['key'],))

    def authority(self,f):
        return self.db('SELECT enabled,writer_enabled,reviewer_enabled,auth_version FROM echo_identity.principals WHERE principal_id=%s',(f['principal'],))

    def denied(self,call,code='LOGOUT_REJECTED'):
        with self.assertRaises(SessionLogoutError) as caught:
            call()
        self.assertEqual(caught.exception.code,code)
        self.assertEqual(str(caught.exception),code)

    @staticmethod
    def params(f):
        c=f['claims']
        return (base.ISSUER,f['subject'],f['key'],c['iat']*1000,c['nbf']*1000,c['exp']*1000)

    def test_19_logout_revokes_durable_resolution_without_changing_account(self):
        f=self.fixture(); before=self.row(f); authority=self.authority(f)
        adapter=PostgresRegistryAdapter(self.admin)
        self.assertIsNotNone(adapter.resolve_binding(base.ISSUER,f['subject'],f['claims']['jti']))
        result=self.logout(f)
        self.assertEqual(asdict(result),{'revoked':True})
        self.assertEqual(self.row(f),before[:-1]+(True,))
        self.assertEqual(self.authority(f),authority)
        self.assertIsNone(adapter.resolve_binding(base.ISSUER,f['subject'],f['claims']['jti']))
        self.assert_error('FIRST_SESSION_REJECTED',lambda:self.boundary.bootstrap('Bearer '+f['token'],b'{}'))

    def test_20_valid_exact_logout_retry_is_idempotent(self):
        f=self.fixture(); a=self.logout(f); after=self.row(f); b=self.logout(f)
        self.assertEqual(a,b); self.assertEqual(self.row(f),after)
        self.assertEqual(self.session_count(f['principal']),1)

    def test_21_no_session_is_not_silently_created_or_reported_revoked(self):
        principal,subject=self.activated(); token,_=self.token(subject)
        self.denied(lambda:self.logout_boundary.logout('Bearer '+token,b'{}'))
        self.assertEqual(self.session_count(principal),0)

    def test_22_request_body_cannot_select_foreign_identity_or_session(self):
        f=self.fixture(); before=self.row(f)
        bodies=[b'[]',b'null',b'',b'\xff',b' '*257,b'{"x":1,"x":2}']
        for field in ('principal_id','actor_id','source_id','session_key','issuer','subject','proof_id','role','logout_all'):
            bodies.append(json.dumps({field:'untrusted'}).encode())
        for raw in bodies:
            with self.subTest(body=raw):
                self.denied(lambda:self.logout_boundary.logout('Bearer '+f['token'],raw),'INVALID_LOGOUT_REQUEST')
        self.assertEqual(self.row(f),before)

    def test_23_bad_signed_credentials_never_lease_a_connection(self):
        f=self.fixture(); calls=[]
        def forbidden():
            calls.append(True)
            raise AssertionError('verifier should deny first')
        b=SignedSessionLogoutBoundary(self.config,forbidden)
        invalid=[None,'','Basic x','Bearer junk']
        wrong,_=self.token(f['subject'],key=self.wrong_key)
        invalid.append('Bearer '+wrong)
        now=int(time.time())
        for patch in ({'iss':base.ISSUER+'/'},{'aud':'wrong'},{'exp':now-1},
                      {'nbf':now+30},{'iat':now+30,'nbf':now+30}):
            token,_=self.token(f['subject'],extra=patch)
            invalid.append('Bearer '+token)
        for auth in invalid:
            self.denied(lambda:b.logout(auth,b'{}'),'IDENTITY_REJECTED')
        self.assertEqual(calls,[]); self.assertFalse(self.row(f)[-1])

    def test_24_custom_signed_claims_cannot_redirect_logout(self):
        f=self.fixture(); other=self.fixture(); before=self.row(other)
        claims=dict(f['claims'],principal_id=str(other['principal']),session_key=other['key'],role='admin',logout_all=True)
        token,_=self.token(f['subject'],extra=claims)
        self.logout(f,token=token)
        self.assertTrue(self.row(f)[-1]); self.assertEqual(self.row(other),before)

    def test_25_another_signed_subject_cannot_use_the_same_jti(self):
        f=self.fixture(); _,other=self.activated(); before=self.row(f)
        token,_=self.token(other,extra={**f['claims'],'sub':other})
        self.denied(lambda:self.logout(f,token=token))
        self.assertEqual(self.row(f),before)

    def test_26_logout_only_one_session_not_other_sessions_of_same_account(self):
        f=self.fixture(); before_authority=self.authority(f)
        token2,claims2=self.token(f['subject'])
        key2=derive_session_key(base.ISSUER,claims2['jti'])
        # Admin fixture ONLY, not a second-login implementation or new public path.
        self.db('INSERT INTO echo_identity.sessions VALUES(%s,%s,2,to_timestamp(%s),to_timestamp(%s),false)',
                (key2,f['principal'],claims2['iat'],claims2['exp']))
        self.logout(f)
        self.assertTrue(self.row(f)[-1])
        self.assertFalse(self.db('SELECT revoked FROM echo_identity.sessions WHERE session_key=%s',(key2,))[0])
        self.assertEqual(self.authority(f),before_authority)
        self.assertEqual(self.session_count(f['principal']),2)

    def test_27_disabled_or_stale_owner_can_only_reduce_its_own_session(self):
        for setting in ('enabled=false','writer_enabled=true','reviewer_enabled=true'):
            with self.subTest(setting=setting):
                f=self.fixture()
                self.db('UPDATE echo_identity.principals SET '+setting+',auth_version=auth_version+1 WHERE principal_id=%s',(f['principal'],))
                current=self.authority(f); self.logout(f)
                self.assertEqual(self.authority(f),current)
                self.assertTrue(self.row(f)[-1]); self.assertEqual(self.row(f)[1],2)

    def test_28_new_jti_for_same_subject_cannot_revoke_the_old_session(self):
        f=self.fixture(); before=self.row(f); other,_=self.token(f['subject'])
        self.denied(lambda:self.logout(f,token=other))
        self.assertEqual(self.row(f),before)

    def test_29_same_jti_with_changed_signed_lifetime_is_not_exact_session(self):
        f=self.fixture(); before=self.row(f)
        changed=dict(f['claims'],exp=f['claims']['exp']+1)
        token,_=self.token(f['subject'],extra=changed)
        self.denied(lambda:self.logout(f,token=token)); self.assertEqual(self.row(f),before)

    def wait_queued(self,pids,futures):
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            with self.admin() as c:
                rows=c.execute("SELECT pid,wait_event_type,cardinality(pg_blocking_pids(pid)) FROM pg_stat_activity WHERE pid=ANY(%s)",(pids,)).fetchall()
            queued={pid for pid,event,count in rows if event=='Lock' and count>0}
            if queued==set(pids): return
            if any(f.done() for f in futures): self.fail('request ended before observed lock queue')
            time.sleep(0.01)
        self.fail('expected PostgreSQL lock queue not observed')

    def test_30_concurrent_logout_retries_both_succeed_once(self):
        f=self.fixture(); holder=self.admin(); pids=Queue(); executor=ThreadPoolExecutor(max_workers=2)
        @contextmanager
        def lease():
            with self.logout_pool.connection() as c:
                pids.put(c.info.backend_pid); yield c
        b=SignedSessionLogoutBoundary(self.config,lease)
        try:
            holder.execute('SELECT session_key FROM echo_identity.sessions WHERE session_key=%s FOR UPDATE',(f['key'],))
            futures=[executor.submit(self.logout,f,b) for _ in range(2)]
            borrowers=[pids.get(timeout=5) for _ in range(2)]
            self.assertEqual(len(set(borrowers)),2)
            self.wait_queued(borrowers,futures); holder.rollback()
            results=[x.result(timeout=10) for x in futures]
            self.assertEqual([asdict(r) for r in results],[{'revoked':True},{'revoked':True}])
            self.assertEqual(self.session_count(f['principal']),1)
            print('LOGOUT_LOCK_OBSERVED concurrent_retries',flush=True)
        finally:
            holder.rollback(); holder.close(); executor.shutdown(wait=True)

    def test_31_expiry_during_principal_or_session_wait_is_denied(self):
        for table,column,value_name in (('principals','principal_id','principal'),('sessions','session_key','key')):
            with self.subTest(table=table):
                f=self.fixture(lifetime=3); before=self.row(f)
                holder=self.admin(); pids=Queue(); executor=ThreadPoolExecutor(max_workers=1)
                @contextmanager
                def lease():
                    with self.logout_pool.connection() as c:
                        c.execute("SET LOCAL lock_timeout='8s'"); c.execute("SET LOCAL statement_timeout='12s'")
                        pids.put(c.info.backend_pid); yield c
                b=SignedSessionLogoutBoundary(self.config,lease)
                try:
                    holder.execute(sql.SQL('SELECT {} FROM echo_identity.{} WHERE {}=%s FOR UPDATE').format(
                        sql.Identifier(column),sql.Identifier(table),sql.Identifier(column)),(f[value_name],))
                    future=executor.submit(self.logout,f,b); pid=pids.get(timeout=5)
                    self.wait_queued([pid],[future])
                    self.db('SELECT pg_sleep(GREATEST(0,%s-extract(epoch FROM clock_timestamp())+0.05))',(f['claims']['exp'],))
                    holder.rollback(); self.denied(lambda:future.result(timeout=10))
                    self.assertEqual(self.row(f),before)
                    print('LOGOUT_LOCK_OBSERVED expiry_'+table,flush=True)
                finally:
                    holder.rollback(); holder.close(); executor.shutdown(wait=True)

    def fault_boundary(self,target,transform):
        class Cursor:
            def __init__(self,row): self.row=row
            def fetchone(self): return self.row
        class Connection:
            def __init__(self,c): self.c=c
            def execute(self,statement,params=None,**kwargs):
                cursor=self.c.execute(statement,params,**kwargs)
                if statement==target:
                    return Cursor(transform(self.c,cursor.fetchone()))
                return cursor
        @contextmanager
        def lease():
            with self.logout_pool.connection() as c: yield Connection(c)
        return SignedSessionLogoutBoundary(self.config,lease)

    def test_32_expiry_after_real_update_rolls_back_revocation(self):
        f=self.fixture(lifetime=3); before=self.row(f)
        def delayed_clock(c,row):
            c.execute('SELECT pg_sleep(GREATEST(0,%s-extract(epoch FROM clock_timestamp())+0.05))',(f['claims']['exp'],))
            return c.execute(CLOCK_SQL).fetchone()
        self.denied(lambda:self.logout(f,self.fault_boundary(CLOCK_SQL,delayed_clock)),'IDENTITY_REJECTED')
        self.assertEqual(self.row(f),before)

    def test_33_bad_receipt_after_real_revocation_rolls_back(self):
        for patch in ({'revoked':False},{'revoked':1},{'sessionKey':'f'*64}):
            with self.subTest(patch=patch):
                f=self.fixture(); before=self.row(f)
                b=self.fault_boundary(LOGOUT_SQL,lambda c,row:({**row[0],**patch},))
                self.denied(lambda:self.logout(f,b),'LOGOUT_CONTRACT_VIOLATION')
                self.assertEqual(self.row(f),before)
                self.logout(f)

    def test_34_invalid_final_clock_rolls_back(self):
        f=self.fixture(); before=self.row(f)
        self.denied(lambda:self.logout(f,self.fault_boundary(CLOCK_SQL,lambda c,row:(True,))),'LOGOUT_CONTRACT_VIOLATION')
        self.assertEqual(self.row(f),before)

    def test_35_logout_commit_blocks_then_denies_bootstrap_replay(self):
        f=self.fixture(); pids=Queue(); executor=ThreadPoolExecutor(max_workers=1)
        @contextmanager
        def bootstrap_lease():
            with self.pool.connection() as c:
                pids.put(c.info.backend_pid); yield c
        b=SignedFirstSessionBoundary(self.config,bootstrap_lease)
        try:
            with self.logout_pool.connection() as c:
                c.execute(LOGOUT_SQL,self.params(f)).fetchone()
                future=executor.submit(b.bootstrap,'Bearer '+f['token'],b'{}')
                self.wait_queued([pids.get(timeout=5)],[future])
                # This scope commits logout while bootstrap is waiting.
            self.assert_error('FIRST_SESSION_REJECTED',lambda:future.result(timeout=10))
            self.assertTrue(self.row(f)[-1])
            print('LOGOUT_LOCK_OBSERVED logout_first',flush=True)
        finally:
            executor.shutdown(wait=True)

    def test_36_bootstrap_replay_that_locked_first_finishes_before_logout(self):
        f=self.fixture(); pids=Queue(); executor=ThreadPoolExecutor(max_workers=1)
        @contextmanager
        def lease():
            with self.logout_pool.connection() as c:
                pids.put(c.info.backend_pid); yield c
        b=SignedSessionLogoutBoundary(self.config,lease)
        try:
            with self.pool.connection() as c:
                r=c.execute(BOOTSTRAP_SQL,self.params(f)).fetchone()[0]
                self.assertTrue(r['replayed'])
                future=executor.submit(self.logout,f,b)
                self.wait_queued([pids.get(timeout=5)],[future])
            self.assertTrue(future.result(timeout=10).revoked)
            self.assert_error('FIRST_SESSION_REJECTED',lambda:self.boundary.bootstrap('Bearer '+f['token'],b'{}'))
            print('LOGOUT_LOCK_OBSERVED bootstrap_first',flush=True)
        finally:
            executor.shutdown(wait=True)

    def test_37_lock_timeout_fails_closed_without_revocation(self):
        f=self.fixture(); before=self.row(f); holder=self.admin()
        @contextmanager
        def lease():
            with self.logout_pool.connection() as c:
                c.execute("SET LOCAL lock_timeout='100ms'"); yield c
        try:
            holder.execute('SELECT session_key FROM echo_identity.sessions WHERE session_key=%s FOR UPDATE',(f['key'],))
            self.denied(lambda:self.logout(f,SignedSessionLogoutBoundary(self.config,lease)),'LOGOUT_BACKEND_UNAVAILABLE')
            self.assertEqual(self.row(f),before)
        finally:
            holder.rollback(); holder.close()

    def test_38_unknown_commit_ack_is_error_then_explicit_retry_is_safe(self):
        f=self.fixture()
        @contextmanager
        def lost_ack():
            with self.logout_pool.connection() as c: yield c
            raise TimeoutError('synthetic lost acknowledgement')
        self.denied(lambda:self.logout(f,SignedSessionLogoutBoundary(self.config,lost_ack)),'LOGOUT_BACKEND_UNAVAILABLE')
        self.assertTrue(self.row(f)[-1])
        self.assertTrue(self.logout(f).revoked)
        self.assertEqual(self.session_count(f['principal']),1)

    def test_39_pool_reset_clears_state_and_aborted_transaction(self):
        p=LogoutPool(**self.pool_config(max_size=1)); p.open()
        try:
            with p.connection() as c:
                pid=c.info.backend_pid
                c.execute('CREATE TEMP TABLE logout_leak(x int)')
                c.execute("SET LOCAL application_name='dirty-logout'")
            with self.assertRaises(psycopg.Error):
                with p.connection() as c: c.execute('SELECT 1/0')
            with p.connection() as c:
                self.assertEqual(c.info.backend_pid,pid)
                self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.logout_leak')").fetchone()[0])
                self.assertNotEqual(c.execute("SHOW application_name").fetchone()[0],'dirty-logout')
            self.assertTrue(self.logout(self.fixture(),SignedSessionLogoutBoundary(self.config,p.connection)).revoked)
        finally:
            p.close()

    def test_40_service_and_runtime_have_no_raw_revoke_or_identity_bypass(self):
        f=self.fixture()
        with self.logout_connection() as c:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute(LOGOUT_SQL,self.params(f))
            c.rollback()
        for statement in ('SELECT * FROM echo_identity.sessions','UPDATE echo_identity.sessions SET revoked=false',
                          'INSERT INTO echo_identity.sessions DEFAULT VALUES','UPDATE echo_identity.principals SET enabled=true',
                          'SET ROLE echo_identity_mutation_runtime','SET ROLE echo_first_session_runtime'):
            with self.subTest(statement=statement):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with self.logout_pool.connection() as c: c.execute(statement)
        for role in (RUNTIME,'echo_identity_mutation_runtime'):
            self.assertFalse(self.db("SELECT has_function_privilege(%s,'echo_identity.runtime_revoke_session(text,uuid)'::regprocedure,'EXECUTE')",(role,))[0])
        with self.admin() as c:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute('SET LOCAL ROLE '+RUNTIME); c.execute(LOGOUT_SQL,self.params(f))
            c.rollback()
        self.assertFalse(self.row(f)[-1])

    def test_41_privilege_drift_fails_closed_then_recovers(self):
        for grant,revoke in (
            ('GRANT SELECT ON echo_identity.sessions TO '+RUNTIME,'REVOKE SELECT ON echo_identity.sessions FROM '+RUNTIME),
            ('GRANT EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) TO '+RUNTIME,
             'REVOKE EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) FROM '+RUNTIME)):
            f=self.fixture(); before=self.row(f); self.db(grant)
            try:
                self.denied(lambda:self.logout(f),'LOGOUT_BACKEND_UNAVAILABLE')
            finally:
                self.db(revoke)
            self.assertEqual(self.row(f),before); self.logout(f)

    def test_42_wrong_password_and_insecure_remote_configuration_are_denied(self):
        for patch in ({'user':'echo_test'},{'host':'remote.invalid'},{'allow_insecure_test_loopback':False}):
            with self.assertRaises(LogoutPoolError): LogoutPool(**self.pool_config(**patch))
        with self.assertRaises(psycopg.OperationalError):
            self.logout_connection(password='wrong-'+secrets.token_hex(16))

    def test_43_sql_null_and_unsupported_isolation_denied(self):
        f=self.fixture(); values=list(self.params(f)); before=self.row(f)
        for index in range(len(values)):
            params=values.copy(); params[index]=None
            with self.assertRaises(psycopg.Error):
                with self.logout_pool.connection() as c: c.execute(LOGOUT_SQL,params)
        for isolation in ('REPEATABLE READ','SERIALIZABLE'):
            with self.logout_connection() as c:
                with self.assertRaises(psycopg.errors.ActiveSqlTransaction):
                    c.execute('SET TRANSACTION ISOLATION LEVEL '+isolation)
                    c.execute('SET LOCAL ROLE '+RUNTIME); c.execute(LOGOUT_SQL,values)
                c.rollback()
        self.assertEqual(self.row(f),before)

    def test_44_logout_never_grants_capabilities_or_writes_news(self):
        f=self.fixture(); before=self.authority(f); self.logout(f)
        self.assertEqual(self.authority(f),before)
        with self.admin() as c:
            tables=c.execute("SELECT tablename FROM pg_tables WHERE schemaname='echo_core' AND tablename NOT IN ('actors','sources')").fetchall()
            self.assertGreater(len(tables),0)
            for (table,) in tables:
                count=c.execute(sql.SQL('SELECT count(*) FROM echo_core.{}').format(sql.Identifier(table))).fetchone()[0]
                self.assertEqual(count,0,table)

    def test_45_backend_outage_does_not_fabricate_logout_success(self):
        f=self.fixture(); before=self.row(f)
        def offline(): raise RuntimeError('synthetic backend secret')
        self.denied(lambda:self.logout(f,SignedSessionLogoutBoundary(self.config,offline)),'LOGOUT_BACKEND_UNAVAILABLE')
        self.assertEqual(self.row(f),before)


def load_tests(loader,standard_tests,pattern):
    return loader.loadTestsFromTestCase(SignedLogoutTests)


if __name__=='__main__':
    unittest.main(verbosity=2)
