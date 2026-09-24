"""Real PostgreSQL rotation gate: 61 unchanged inherited cases + 31 new methods.
Synthetic bearer signatures/service LOGINs only. No browser or production rollout.
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

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'p2_1c2d4c5c5a'),str(HERE.parent/'p2_1c2d4c5c5b1')]
import test_signed_repeat_login as baseline
from postgres_registry_adapter import PostgresRegistryAdapter,derive_session_key
from logout_boundary import SignedSessionLogoutBoundary,LOGOUT_SQL
from rotation_boundary import SignedSessionRotationBoundary,SessionRotationError,ROTATE_SQL,CLOCK_SQL
from rotation_pool import RotationPool,RotationPoolError,SERVICE,RUNTIME,GUARD,FUNCTION
import renewal_contract as model

ISSUER=baseline.first_base.ISSUER


class AtomicRotationTests(baseline.SignedRepeatLoginTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.rotation_password=secrets.token_urlsafe(32)
        with cls.admin() as c:
            c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(SERVICE),sql.Literal(cls.rotation_password)))
        cls.rotation_pool=RotationPool(**cls.rotation_config())
        cls.rotation_pool.open()
        cls.rotation_boundary=SignedSessionRotationBoundary(cls.config,cls.rotation_pool.connection)

    @classmethod
    def cleanup(cls):
        if hasattr(cls,'rotation_pool'):
            cls.rotation_pool.close()
        try:
            super().cleanup()
        finally:
            with cls.admin() as c:
                for role in (SERVICE,RUNTIME,GUARD):
                    c.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
            with cls.admin() as c:
                clean=c.execute("SELECT to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_core') IS NULL AND to_regrole(%s) IS NULL",(SERVICE,)).fetchone()[0]
                if not clean: raise AssertionError('rotation cleanup incomplete')
            print('CLEAN_ATOMIC_ROTATION_DATABASE',flush=True)

    @classmethod
    def rotation_config(cls,**patch):
        import os
        return dict(host='127.0.0.1',port=int(os.environ.get('PGPORT','5432')),
            dbname=baseline.first_base.DB,user=SERVICE,password=cls.rotation_password,
            sslmode='disable',max_size=2,allow_insecure_test_loopback=True)|patch

    @classmethod
    def rotation_service(cls,**patch):
        config=cls.rotation_config(**patch)
        for key in ('max_size','allow_insecure_test_loopback'): config.pop(key)
        return psycopg.connect(**config,connect_timeout=3)

    def rotation_fixture(self,lifetime=180):
        principal,subject=self.activated(); now=int(time.time())
        token,claims=self.token(subject,extra={'iat':now-30,'nbf':now-30,'exp':now+lifetime})
        self.boundary.bootstrap('Bearer '+token,b'{}')
        return dict(principal=principal,subject=subject,token=token,claims=claims,
                    key=derive_session_key(ISSUER,claims['jti']))

    def candidate(self,f,**patch):
        issued=f['claims']['iat']+1
        fields=dict(iat=issued,nbf=issued,exp=int(time.time())+180)
        fields.update(patch)
        token,claims=self.token(f['subject'],extra=fields)
        return {**f,'token':token,'claims':claims,'key':derive_session_key(ISSUER,claims['jti'])}

    def rotate(self,f,boundary=None):
        return (boundary or self.rotation_boundary).rotate('Bearer '+f['token'],b'{}')

    def rotation_denied(self,call,code='ROTATION_REJECTED'):
        with self.assertRaises(SessionRotationError) as caught: call()
        self.assertEqual(caught.exception.code,code)
        self.assertEqual(str(caught.exception),code)

    def rotation_state(self,f):
        with self.admin() as c:
            sessions=c.execute('SELECT session_key,auth_version,issued_at,expires_at,revoked FROM echo_identity.sessions WHERE principal_id=%s ORDER BY session_key',(f['principal'],)).fetchall()
            edges=c.execute('SELECT successor_key,predecessor_key,auth_version,policy_code,rotated_at FROM echo_identity.session_rotations WHERE principal_id=%s ORDER BY successor_key',(f['principal'],)).fetchall()
            authority=c.execute('SELECT enabled,writer_enabled,reviewer_enabled,auth_version FROM echo_identity.principals WHERE principal_id=%s',(f['principal'],)).fetchone()
            return sessions,edges,authority

    def rotation_edges(self,f):
        return self.rotation_state(f)[1]

    def test_62_exact_current_bearer_is_replay_without_new_history(self):
        f=self.rotation_fixture(); before=self.rotation_state(f); r=self.rotate(f)
        self.assertEqual(set(asdict(r)),{'auth_version','expires_at_ms','replayed'})
        self.assertTrue(r.replayed); self.assertEqual(r.auth_version,2)
        self.assertEqual(self.rotation_state(f),before)

    def test_63_newer_bearer_atomically_revokes_inserts_and_links(self):
        f=self.rotation_fixture(); newer=self.candidate(f); authority=self.authority(f)
        r=self.rotate(newer)
        self.assertFalse(r.replayed); self.assertTrue(self.row(f)[-1]); self.assertFalse(self.row(newer)[-1])
        self.assertEqual(self.authority(f),authority); self.assertEqual(self.current_active_count(f['principal']),1)
        edge=self.rotation_edges(f)
        self.assertEqual(len(edge),1); self.assertEqual(edge[0][:4],(newer['key'],f['key'],2,model.POLICY))
        adapter=PostgresRegistryAdapter(self.admin)
        self.assertIsNone(adapter.resolve_binding(ISSUER,f['subject'],f['claims']['jti']))
        self.assertIsNotNone(adapter.resolve_binding(ISSUER,f['subject'],newer['claims']['jti']))

    def test_64_older_and_equal_iat_candidates_cannot_rollback_current(self):
        f=self.rotation_fixture(); before=self.rotation_state(f)
        for issued in (f['claims']['iat']-1,f['claims']['iat']):
            with self.subTest(issued=issued):
                old=self.candidate(f,iat=issued,nbf=issued)
                self.rotation_denied(lambda:self.rotate(old))
                self.assertEqual(self.rotation_state(f),before)

    def test_65_revoked_predecessor_never_resurrects(self):
        f=self.rotation_fixture(); newer=self.candidate(f); self.rotate(newer); before=self.rotation_state(f)
        self.rotation_denied(lambda:self.rotate(f))
        self.repeat_denied(lambda:self.repeat(f['subject'],f['token']))
        self.assert_error('FIRST_SESSION_REJECTED',lambda:self.boundary.bootstrap('Bearer '+f['token'],b'{}'))
        self.assertEqual(self.rotation_state(f),before)

    def test_66_no_active_hands_off_to_repeat_login_without_mutation(self):
        f=self.rotation_fixture(); self.logout(f); newer=self.candidate(f); before=self.rotation_state(f)
        self.rotation_denied(lambda:self.rotate(newer),'ROTATION_NO_ACTIVE_USE_REPEAT_LOGIN')
        self.assertEqual(self.rotation_state(f),before)
        self.repeat(f['subject'],newer['token']); self.assertEqual(self.current_active_count(f['principal']),1)

    def test_67_multiple_live_sessions_fail_closed_even_for_exact_replay(self):
        f=self.rotation_fixture(); extra=self.candidate(f)
        self.db('INSERT INTO echo_identity.sessions VALUES(%s,%s,2,to_timestamp(%s),to_timestamp(%s),false)',
                (extra['key'],f['principal'],extra['claims']['iat'],extra['claims']['exp']))
        before=self.rotation_state(f)
        for candidate in (f,self.candidate(extra)):
            self.rotation_denied(lambda:self.rotate(candidate))
            self.assertEqual(self.rotation_state(f),before)

    def test_68_generation_and_disabled_checks_are_current_not_token_claims(self):
        f=self.rotation_fixture(); newer=self.candidate(f)
        self.db('UPDATE echo_identity.principals SET writer_enabled=true,auth_version=auth_version+1 WHERE principal_id=%s',(f['principal'],))
        before=self.rotation_state(f)
        self.rotation_denied(lambda:self.rotate(newer),'ROTATION_NO_ACTIVE_USE_REPEAT_LOGIN')
        self.assertEqual(self.rotation_state(f),before)
        self.repeat(f['subject'],newer['token'])
        latest=self.candidate(newer); r=self.rotate(latest); self.assertEqual(r.auth_version,3)
        self.db('UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s',(f['principal'],))
        before=self.rotation_state(f); self.rotation_denied(lambda:self.rotate(latest))
        self.assertEqual(self.rotation_state(f),before)

    def test_69_missing_provenance_and_cross_account_key_collision_deny(self):
        p,subject=self.provision()
        self.db('UPDATE echo_identity.principals SET enabled=true,auth_version=2 WHERE principal_id=%s',(p,))
        token,_=self.token(subject)
        self.rotation_denied(lambda:self.rotation_boundary.rotate('Bearer '+token,b'{}'))
        f=self.rotation_fixture(); g=self.rotation_fixture(); before=(self.rotation_state(f),self.rotation_state(g))
        collision=self.candidate(g,jti=f['claims']['jti'])
        self.rotation_denied(lambda:self.rotate(collision))
        self.assertEqual((self.rotation_state(f),self.rotation_state(g)),before)

    def test_70_body_identity_selection_and_signed_role_hints_never_grant(self):
        f=self.rotation_fixture(); before=self.rotation_state(f)
        for raw in [b'[]',b'null',b'',b'\xff',b' '*257,b'{"x":1,"x":2}']+[
                json.dumps({field:'spoof'}).encode() for field in
                ('actor_id','source_id','principal_id','session_key','predecessor','issuer','subject','policy','auth_version','refresh_token')]:
            self.rotation_denied(lambda:self.rotation_boundary.rotate('Bearer '+f['token'],raw),'INVALID_ROTATION_REQUEST')
        self.assertEqual(self.rotation_state(f),before)
        newer=self.candidate(f,actor_id=str(uuid4()),principal_id=str(uuid4()),role='admin',auth_version=999)
        self.rotate(newer); self.assertEqual(self.authority(f),(True,False,False,2))

    def test_71_invalid_signed_tokens_are_denied_before_any_lease(self):
        f=self.rotation_fixture(); calls=[]
        def forbidden(): calls.append(True); raise AssertionError('should not access DB')
        b=SignedSessionRotationBoundary(self.config,forbidden)
        wrong,_=self.token(f['subject'],key=self.wrong_key)
        invalid=[None,'','Basic x','Bearer junk','Bearer '+wrong]; now=int(time.time())
        for patch in ({'iss':ISSUER+'/'},{'aud':'wrong'},{'exp':now-1},{'nbf':now+30},
                      {'iat':now+30,'nbf':now+30}):
            token,_=self.token(f['subject'],extra=patch); invalid.append('Bearer '+token)
        for auth in invalid:
            self.rotation_denied(lambda:b.rotate(auth,b'{}'),'IDENTITY_REJECTED')
        self.assertEqual(calls,[])

    def test_72_exact_key_replay_cannot_change_signed_lifetime(self):
        f=self.rotation_fixture(); before=self.rotation_state(f)
        for patch in ({'exp':f['claims']['exp']+1},{'iat':f['claims']['iat']-1}):
            token,_=self.token(f['subject'],extra={**f['claims'],**patch})
            self.rotation_denied(lambda:self.rotation_boundary.rotate('Bearer '+token,b'{}'))
            self.assertEqual(self.rotation_state(f),before)

    def test_73_runtime_matches_locked_model_for_rotation_and_replay(self):
        f=self.rotation_fixture(); n=self.candidate(f); now=int(time.time()*1000)
        p=model.Principal(f['subject'],2)
        sessions=(model.Session(f['key'],f['subject'],2,f['claims']['iat']*1000,f['claims']['exp']*1000),)
        candidate=model.Candidate(n['key'],f['subject'],2,n['claims']['iat']*1000,n['claims']['nbf']*1000,n['claims']['exp']*1000)
        expected=model.rotate_active_session(p,sessions,candidate,now)
        self.assertEqual(expected.decision,model.Decision.ROTATED); self.assertFalse(self.rotate(n).replayed)
        self.assertEqual({s.session_key:s.revoked for s in expected.sessions},{r[0]:r[-1] for r in self.rotation_state(f)[0]})
        replay=model.rotate_active_session(p,expected.sessions,candidate,now)
        self.assertEqual(replay.decision,model.Decision.REPLAY_CURRENT); self.assertTrue(self.rotate(n).replayed)

    def fault_rotation(self,target,transform):
        class Cursor:
            def __init__(self,row): self.row=row
            def fetchone(self): return self.row
        class Connection:
            def __init__(self,c): self.c=c
            def execute(self,statement,params=None,**kwargs):
                cursor=self.c.execute(statement,params,**kwargs)
                return Cursor(transform(self.c,cursor.fetchone())) if statement==target else cursor
        @contextmanager
        def lease():
            with self.rotation_pool.connection() as c: yield Connection(c)
        return SignedSessionRotationBoundary(self.config,lease)

    def test_74_receipt_or_clock_fault_rolls_back_all_three_mutations(self):
        for target,transform in ((ROTATE_SQL,lambda c,row:({**row[0],'replayed':1},)),
                                 (ROTATE_SQL,lambda c,row:({**row[0],'sessionKey':'f'*64},)),
                                 (CLOCK_SQL,lambda c,row:(True,))):
            with self.subTest(target=target):
                f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f)
                self.rotation_denied(lambda:self.rotate(n,self.fault_rotation(target,transform)),'ROTATION_CONTRACT_VIOLATION')
                self.assertEqual(self.rotation_state(f),before)
                self.rotate(n)

    def test_75_lineage_insert_failure_rolls_back_revocation_and_successor(self):
        f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f)
        self.db('''CREATE FUNCTION echo_identity.test_rotation_fault() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic lineage failure'; END $$;
            CREATE TRIGGER test_rotation_fault BEFORE INSERT ON echo_identity.session_rotations
            FOR EACH ROW EXECUTE FUNCTION echo_identity.test_rotation_fault();''')
        try:
            self.rotation_denied(lambda:self.rotate(n),'ROTATION_BACKEND_UNAVAILABLE')
            self.assertEqual(self.rotation_state(f),before)
        finally:
            self.db('DROP TRIGGER test_rotation_fault ON echo_identity.session_rotations; DROP FUNCTION echo_identity.test_rotation_fault();')
        self.rotate(n)

    def test_76_explicit_transaction_rollback_restores_predecessor(self):
        f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f)
        with self.rotation_service() as c:
            c.execute('SET LOCAL ROLE '+RUNTIME); c.execute(ROTATE_SQL,self.params(n)).fetchone(); c.rollback()
        self.assertEqual(self.rotation_state(f),before)
        self.rotate(n)

    def test_77_unknown_commit_ack_requires_explicit_same_bearer_retry(self):
        f=self.rotation_fixture(); n=self.candidate(f)
        @contextmanager
        def lost_ack():
            with self.rotation_pool.connection() as c: yield c
            raise TimeoutError('synthetic acknowledgement loss after real commit')
        self.rotation_denied(lambda:self.rotate(n,SignedSessionRotationBoundary(self.config,lost_ack)),'ROTATION_BACKEND_UNAVAILABLE')
        committed=self.rotation_state(f)
        self.assertTrue(self.rotate(n).replayed); self.assertEqual(self.rotation_state(f),committed)
        self.assertEqual(len(self.rotation_edges(f)),1)

    def observed_rotation(self,pids):
        @contextmanager
        def lease():
            with self.rotation_pool.connection() as c:
                c.execute("SET LOCAL lock_timeout='8s'"); c.execute("SET LOCAL statement_timeout='12s'")
                pids.put(c.info.backend_pid); yield c
        return SignedSessionRotationBoundary(self.config,lease)

    def safe_rotate(self,f,b):
        try: return ('OK',self.rotate(f,b))
        except SessionRotationError as error: return ('DENIED',error.code)

    def test_78_observed_concurrent_same_and_equal_time_candidates(self):
        for identical in (True,False):
            with self.subTest(identical=identical):
                f=self.rotation_fixture(); first=self.candidate(f)
                second=first if identical else self.candidate(f)
                holder=self.admin(); pids=Queue(); ex=ThreadPoolExecutor(max_workers=2)
                try:
                    holder.execute('SELECT principal_id FROM echo_identity.principals WHERE principal_id=%s FOR UPDATE',(f['principal'],))
                    b=self.observed_rotation(pids)
                    futures=[ex.submit(self.safe_rotate,candidate,b) for candidate in (first,second)]
                    borrowers=[pids.get(timeout=5) for _ in futures]
                    self.wait_queued(borrowers,futures); holder.rollback()
                    result=[x.result(timeout=10) for x in futures]
                    if identical:
                        self.assertEqual([x[0] for x in result],['OK','OK'])
                        self.assertEqual(sorted(x[1].replayed for x in result),[False,True])
                    else:
                        self.assertEqual(sorted(x[0] for x in result),['DENIED','OK'])
                    self.assertEqual(len(self.rotation_edges(f)),1)
                    self.assertEqual(self.current_active_count(f['principal']),1)
                    print('ROTATION_LOCK_OBSERVED '+('identical' if identical else 'equal_iat'),flush=True)
                finally:
                    holder.rollback(); holder.close(); ex.shutdown(wait=True)

    def test_79_observed_competing_newer_candidates_preserve_monotonic_order(self):
        for high_first in (True,False):
            f=self.rotation_fixture(); low=self.candidate(f); high=self.candidate(low)
            first,second=(high,low) if high_first else (low,high)
            pids=Queue(); ex=ThreadPoolExecutor(max_workers=1)
            try:
                with self.rotation_pool.connection() as c:
                    c.execute(ROTATE_SQL,self.params(first)).fetchone()
                    future=ex.submit(self.safe_rotate,second,self.observed_rotation(pids))
                    self.wait_queued([pids.get(timeout=5)],[future])
                result=future.result(timeout=10)
                self.assertEqual(result[0],'DENIED' if high_first else 'OK')
                self.assertFalse(self.row(high)[-1]); self.assertTrue(self.row(f)[-1])
                self.assertEqual(len(self.rotation_edges(f)),1 if high_first else 2)
                print('ROTATION_LOCK_OBSERVED '+('higher_first' if high_first else 'lower_first'),flush=True)
            finally:
                ex.shutdown(wait=True)

    def test_80_observed_logout_rotation_order_does_not_resurrect(self):
        for logout_first in (True,False):
            f=self.rotation_fixture(); n=self.candidate(f); pids=Queue(); ex=ThreadPoolExecutor(max_workers=1)
            try:
                if logout_first:
                    with self.logout_pool.connection() as c:
                        c.execute(LOGOUT_SQL,self.params(f)).fetchone()
                        future=ex.submit(self.safe_rotate,n,self.observed_rotation(pids))
                        self.wait_queued([pids.get(timeout=5)],[future])
                    self.assertEqual(future.result(timeout=10),('DENIED','ROTATION_NO_ACTIVE_USE_REPEAT_LOGIN'))
                    self.assertEqual(len(self.rotation_edges(f)),0)
                else:
                    @contextmanager
                    def logout_lease():
                        with self.logout_pool.connection() as c:
                            pids.put(c.info.backend_pid); yield c
                    b=SignedSessionLogoutBoundary(self.config,logout_lease)
                    with self.rotation_pool.connection() as c:
                        c.execute(ROTATE_SQL,self.params(n)).fetchone()
                        future=ex.submit(self.logout,f,b)
                        self.wait_queued([pids.get(timeout=5)],[future])
                    self.assertTrue(future.result(timeout=10).revoked)
                    self.assertFalse(self.row(n)[-1]); self.assertEqual(self.current_active_count(f['principal']),1)
                self.assertTrue(self.row(f)[-1])
                print('ROTATION_LOCK_OBSERVED '+('logout_first' if logout_first else 'rotation_first'),flush=True)
            finally:
                ex.shutdown(wait=True)

    def test_81_observed_token_and_predecessor_expiry_during_wait(self):
        for predecessor_expiry in (False,True):
            f=self.rotation_fixture(lifetime=3 if predecessor_expiry else 180)
            expiry=f['claims']['exp'] if predecessor_expiry else int(time.time())+3
            n=self.candidate(f,exp=int(time.time())+180 if predecessor_expiry else expiry)
            before=self.rotation_state(f); holder=self.admin(); pids=Queue(); ex=ThreadPoolExecutor(max_workers=1)
            try:
                if predecessor_expiry:
                    holder.execute('SELECT session_key FROM echo_identity.sessions WHERE session_key=%s FOR UPDATE',(f['key'],))
                else:
                    holder.execute('SELECT principal_id FROM echo_identity.principals WHERE principal_id=%s FOR UPDATE',(f['principal'],))
                future=ex.submit(self.safe_rotate,n,self.observed_rotation(pids))
                self.wait_queued([pids.get(timeout=5)],[future])
                self.db('SELECT pg_sleep(GREATEST(0,%s-extract(epoch FROM clock_timestamp())+0.05))',(expiry,))
                holder.rollback(); result=future.result(timeout=10)
                expected='ROTATION_NO_ACTIVE_USE_REPEAT_LOGIN' if predecessor_expiry else 'ROTATION_REJECTED'
                self.assertEqual(result,('DENIED',expected)); self.assertEqual(self.rotation_state(f),before)
                print('ROTATION_LOCK_OBSERVED '+('predecessor_expired' if predecessor_expiry else 'candidate_expired'),flush=True)
            finally:
                holder.rollback(); holder.close(); ex.shutdown(wait=True)

    def test_82_predecessor_expiry_after_real_mutation_rolls_back_everything(self):
        f=self.rotation_fixture(lifetime=3); n=self.candidate(f); before=self.rotation_state(f)
        def delayed(c,row):
            c.execute('SELECT pg_sleep(GREATEST(0,%s-extract(epoch FROM clock_timestamp())+0.05))',(f['claims']['exp'],))
            return c.execute(CLOCK_SQL).fetchone()
        self.rotation_denied(lambda:self.rotate(n,self.fault_rotation(CLOCK_SQL,delayed)))
        self.assertEqual(self.rotation_state(f),before)

    def test_83_lock_timeout_does_not_revoke_or_create(self):
        f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f); holder=self.admin()
        @contextmanager
        def lease():
            with self.rotation_pool.connection() as c:
                c.execute("SET LOCAL lock_timeout='100ms'"); yield c
        try:
            holder.execute('SELECT session_key FROM echo_identity.sessions WHERE session_key=%s FOR UPDATE',(f['key'],))
            self.rotation_denied(lambda:self.rotate(n,SignedSessionRotationBoundary(self.config,lease)),'ROTATION_BACKEND_UNAVAILABLE')
            self.assertEqual(self.rotation_state(f),before)
        finally:
            holder.rollback(); holder.close()

    def test_84_authority_disable_committed_while_waiting_is_rechecked(self):
        f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f)
        holder=self.admin(); pids=Queue(); ex=ThreadPoolExecutor(max_workers=1)
        try:
            holder.execute('UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s',(f['principal'],))
            future=ex.submit(self.safe_rotate,n,self.observed_rotation(pids))
            self.wait_queued([pids.get(timeout=5)],[future]); holder.commit()
            self.assertEqual(future.result(timeout=10),('DENIED','ROTATION_REJECTED'))
            self.assertEqual(self.rotation_state(f)[:2],before[:2]); self.assertFalse(self.authority(f)[0])
            print('ROTATION_LOCK_OBSERVED disable_first',flush=True)
        finally:
            holder.rollback(); holder.close(); ex.shutdown(wait=True)

    def test_85_service_runtime_cannot_bypass_sealed_rotation(self):
        f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f)
        with self.rotation_service() as c:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege): c.execute(ROTATE_SQL,self.params(n))
            c.rollback()
        for statement in ('SELECT * FROM echo_identity.sessions','UPDATE echo_identity.sessions SET revoked=false',
            'INSERT INTO echo_identity.sessions DEFAULT VALUES','UPDATE echo_identity.principals SET enabled=true',
            'SET ROLE echo_identity_mutation_runtime','SET ROLE echo_session_logout_runtime','SET ROLE '+GUARD):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.rotation_pool.connection() as c: c.execute(statement)
        with self.admin() as c:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute('SET LOCAL ROLE '+RUNTIME); c.execute(ROTATE_SQL,self.params(n))
            c.rollback()
        self.assertEqual(self.rotation_state(f),before)

    def test_86_acl_drift_is_rejected_without_mutation(self):
        commands=[('GRANT SELECT ON echo_identity.sessions TO '+RUNTIME,'REVOKE SELECT ON echo_identity.sessions FROM '+RUNTIME),
            ('GRANT EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) TO '+RUNTIME,
             'REVOKE EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) FROM '+RUNTIME)]
        for grant,revoke in commands:
            f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f); self.db(grant)
            try:
                self.rotation_denied(lambda:self.rotate(n),'ROTATION_BACKEND_UNAVAILABLE')
            finally:
                self.db(revoke)
            self.assertEqual(self.rotation_state(f),before); self.rotate(n)

    def test_87_pool_reset_failed_transactions_and_bad_credentials(self):
        p=RotationPool(**self.rotation_config(max_size=1)); p.open()
        try:
            with p.connection() as c:
                pid=c.info.backend_pid; c.execute('CREATE TEMP TABLE rotation_leak(x int)')
                c.execute("SET LOCAL application_name='rotation-dirty'")
            with self.assertRaises(psycopg.Error):
                with p.connection() as c: c.execute('SELECT 1/0')
            with p.connection() as c:
                self.assertEqual(c.info.backend_pid,pid)
                self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.rotation_leak')").fetchone()[0])
                self.assertNotEqual(c.execute('SHOW application_name').fetchone()[0],'rotation-dirty')
            f=self.rotation_fixture(); self.rotate(self.candidate(f),SignedSessionRotationBoundary(self.config,p.connection))
        finally:
            p.close()
        with self.assertRaises(psycopg.OperationalError): self.rotation_service(password='wrong-'+secrets.token_hex(12))
        for patch in ({'user':'echo_test'},{'host':'remote.invalid'},{'allow_insecure_test_loopback':False}):
            with self.assertRaises(RotationPoolError): RotationPool(**self.rotation_config(**patch))

    def test_88_sql_nulls_and_other_isolation_levels_fail_closed(self):
        f=self.rotation_fixture(); n=self.candidate(f); params=list(self.params(n)); before=self.rotation_state(f)
        for index in range(len(params)):
            bad=params.copy(); bad[index]=None
            with self.assertRaises(psycopg.Error):
                with self.rotation_pool.connection() as c: c.execute(ROTATE_SQL,bad)
        for isolation in ('REPEATABLE READ','SERIALIZABLE'):
            with self.rotation_service() as c:
                with self.assertRaises(psycopg.errors.ActiveSqlTransaction):
                    c.execute('SET TRANSACTION ISOLATION LEVEL '+isolation)
                    c.execute('SET LOCAL ROLE '+RUNTIME); c.execute(ROTATE_SQL,params)
                c.rollback()
        self.assertEqual(self.rotation_state(f),before)

    def test_89_lineage_is_protected_and_no_news_or_permissions_are_written(self):
        f=self.rotation_fixture(); n=self.candidate(f); self.rotate(n); before=self.rotation_state(f)
        for statement in ('UPDATE echo_identity.session_rotations SET rotated_at=clock_timestamp()',
                          'DELETE FROM echo_identity.session_rotations','TRUNCATE echo_identity.session_rotations',
                          'INSERT INTO echo_identity.session_rotations DEFAULT VALUES'):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.rotation_pool.connection() as c: c.execute(statement)
        for statement in ('UPDATE echo_identity.session_rotations SET rotated_at=clock_timestamp()',
                          'DELETE FROM echo_identity.session_rotations','TRUNCATE echo_identity.session_rotations'):
            with self.assertRaises(psycopg.Error): self.db(statement)
        self.assertEqual(self.rotation_state(f),before)
        with self.admin() as c:
            tables=c.execute("SELECT tablename FROM pg_tables WHERE schemaname='echo_core' AND tablename NOT IN ('actors','sources')").fetchall()
            self.assertGreater(len(tables),0)
            for (table,) in tables:
                self.assertEqual(c.execute(sql.SQL('SELECT count(*) FROM echo_core.{}').format(sql.Identifier(table))).fetchone()[0],0)

    def test_90_distinct_principals_are_not_globally_serialized(self):
        f=self.rotation_fixture(); g=self.rotation_fixture(); n=self.candidate(f); other=self.candidate(g)
        with self.rotation_pool.connection() as c:
            c.execute(ROTATE_SQL,self.params(n)).fetchone()
            self.assertFalse(self.rotate(other).replayed)
        self.assertFalse(self.row(n)[-1]); self.assertFalse(self.row(other)[-1])

    def test_91_rotation_logout_repeat_login_never_revives_predecessors(self):
        f=self.rotation_fixture(); n=self.candidate(f); self.rotate(n); self.logout(n)
        newer=self.candidate(n); self.repeat(f['subject'],newer['token'])
        self.assertTrue(self.row(f)[-1]); self.assertTrue(self.row(n)[-1]); self.assertFalse(self.row(newer)[-1])
        self.rotation_denied(lambda:self.rotate(f))
        self.rotation_denied(lambda:self.rotate(n))
        self.assertEqual(self.current_active_count(f['principal']),1)
        self.assertEqual(len(self.rotation_edges(f)),1)

    def test_92_backend_outage_does_not_fabricate_success(self):
        f=self.rotation_fixture(); n=self.candidate(f); before=self.rotation_state(f)
        def offline(): raise RuntimeError('synthetic internal connection failure')
        self.rotation_denied(lambda:self.rotate(n,SignedSessionRotationBoundary(self.config,offline)),'ROTATION_BACKEND_UNAVAILABLE')
        self.assertEqual(self.rotation_state(f),before)


def load_tests(loader,standard_tests,pattern):
    return loader.loadTestsFromTestCase(AtomicRotationTests)


if __name__=='__main__':
    unittest.main(verbosity=2)
