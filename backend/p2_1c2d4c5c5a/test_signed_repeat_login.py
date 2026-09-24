"""c5c.5a PostgreSQL 17 integration: 45 inherited auth/logout + 16 repeat-login cases."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import sys
import time
from uuid import uuid4

import psycopg
from psycopg import sql

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent/'p2_1c2d4c5c4'), str(HERE.parent/'p2_1c2d4c5c3')]
import test_signed_logout as logout_base
import test_signed_first_session as first_base
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key
from repeat_login_boundary import SignedRepeatLoginBoundary, RepeatLoginError
from repeat_login_pool import RepeatLoginPool, RepeatLoginPoolError, SERVICE, RUNTIME, GUARD


class SignedRepeatLoginTests(logout_base.SignedLogoutTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with cls.admin() as c:
            required = c.execute("""SELECT
              to_regprocedure('echo_identity.runtime_repeat_login_session(text,text,text,bigint,bigint,bigint)') IS NOT NULL,
              to_regrole(%s) IS NOT NULL""", (SERVICE,)).fetchone()
            if required != (True, True):
                raise RuntimeError('repeat-login migration not installed')
        cls.repeat_password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(SERVICE), sql.Literal(cls.repeat_password)))
        cls.repeat_pool = RepeatLoginPool(**cls.repeat_pool_config())
        cls.repeat_pool.open()
        cls.repeat_boundary = SignedRepeatLoginBoundary(cls.config, cls.repeat_pool.connection)

    @classmethod
    def cleanup(cls):
        if hasattr(cls, 'repeat_pool'):
            cls.repeat_pool.close()
        try:
            super().cleanup()
        finally:
            with cls.admin() as c:
                for role in (SERVICE, RUNTIME, GUARD):
                    c.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
            with cls.admin() as c:
                clean = c.execute("SELECT to_regrole(%s) IS NULL AND to_regrole(%s) IS NULL AND to_regrole(%s) IS NULL",
                                  (SERVICE,RUNTIME,GUARD)).fetchone()[0]
                if not clean:
                    raise AssertionError('repeat-login roles not cleaned')
            print('CLEAN_SIGNED_REPEAT_LOGIN_DATABASE', flush=True)

    @classmethod
    def repeat_pool_config(cls, **patch):
        import os
        return dict(host='127.0.0.1', port=int(os.environ.get('PGPORT','5432')),
            dbname=first_base.DB, user=SERVICE, password=cls.repeat_password,
            sslmode='disable', max_size=2, allow_insecure_test_loopback=True) | patch

    @classmethod
    def repeat_service_connection(cls, password=None):
        import os
        return psycopg.connect(host='127.0.0.1', port=int(os.environ.get('PGPORT','5432')),
            dbname=first_base.DB, user=SERVICE, password=password or cls.repeat_password,
            connect_timeout=3)

    def repeat(self, subject, token, *, boundary=None, body=b'{}'):
        return (boundary or self.repeat_boundary).login('Bearer '+token, body)

    def repeat_denied(self, call, code='REPEAT_LOGIN_REJECTED'):
        with self.assertRaises(RepeatLoginError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def session_row_by_claims(self, principal, claims):
        key=derive_session_key(first_base.ISSUER, claims['jti'])
        row=self.db("SELECT session_key,principal_id,auth_version,revoked FROM echo_identity.sessions WHERE session_key=%s",(key,))
        return key,row

    def current_active_count(self, principal):
        return self.db("""SELECT count(*) FROM echo_identity.sessions s
          JOIN echo_identity.principals p USING(principal_id)
          WHERE s.principal_id=%s AND s.auth_version=p.auth_version
            AND NOT s.revoked AND s.expires_at>clock_timestamp()""",(principal,))[0]

    def test_46_fresh_verified_bearer_after_logout_creates_new_session(self):
        f=self.fixture(); self.logout(f)
        token2,claims2=self.token(f['subject'])
        receipt=self.repeat(f['subject'],token2)
        key2,row2=self.session_row_by_claims(f['principal'],claims2)
        self.assertEqual((receipt.auth_version,receipt.replayed),(2,False))
        self.assertEqual(row2,(key2,f['principal'],2,False))
        self.assertTrue(self.row(f)[-1])
        self.assertEqual(self.session_count(f['principal']),2)
        binding=PostgresRegistryAdapter(self.admin).resolve_binding(first_base.ISSUER,f['subject'],claims2['jti'])
        self.assertIsNotNone(binding); self.assertEqual(binding.principal_id,f['principal'])

    def test_47_exact_repeat_token_retry_is_idempotent(self):
        f=self.fixture(); self.logout(f); token2,claims2=self.token(f['subject'])
        first=self.repeat(f['subject'],token2); second=self.repeat(f['subject'],token2)
        self.assertFalse(first.replayed); self.assertTrue(second.replayed)
        self.assertEqual(self.session_count(f['principal']),2)
        _,row=self.session_row_by_claims(f['principal'],claims2); self.assertFalse(row[-1])

    def test_48_live_current_generation_session_blocks_distinct_token(self):
        f=self.fixture(); token2,_=self.token(f['subject']); before=self.session_count(f['principal'])
        self.repeat_denied(lambda:self.repeat(f['subject'],token2))
        self.assertEqual(self.session_count(f['principal']),before)
        self.assertEqual(self.current_active_count(f['principal']),1)

    def test_49_revoked_token_cannot_resurrect_its_session(self):
        f=self.fixture(); self.logout(f); before=self.row(f)
        self.repeat_denied(lambda:self.repeat(f['subject'],f['token']))
        self.assertEqual(self.row(f),before); self.assertTrue(self.row(f)[-1])

    def test_50_expired_unrevoked_session_does_not_block_fresh_login(self):
        f=self.fixture(lifetime=2)
        time.sleep(max(0.0,f['claims']['exp']-time.time()+0.08))
        token2,claims2=self.token(f['subject'])
        receipt=self.repeat(f['subject'],token2)
        self.assertFalse(receipt.replayed)
        self.assertFalse(self.row(f)[-1])
        _,row2=self.session_row_by_claims(f['principal'],claims2); self.assertFalse(row2[-1])
        self.assertEqual(self.current_active_count(f['principal']),1)

    def test_51_stale_generation_session_does_not_block_current_generation(self):
        f=self.fixture()
        self.db("UPDATE echo_identity.principals SET writer_enabled=true,auth_version=auth_version+1 WHERE principal_id=%s",(f['principal'],))
        token2,claims2=self.token(f['subject']); receipt=self.repeat(f['subject'],token2)
        self.assertEqual(receipt.auth_version,3)
        _,row2=self.session_row_by_claims(f['principal'],claims2)
        self.assertEqual(row2[2:],(3,False)); self.assertEqual(self.current_active_count(f['principal']),1)
        self.assertEqual(self.row(f)[1],2)

    def test_52_disabled_principal_cannot_repeat_login(self):
        f=self.fixture(); self.logout(f)
        self.db("UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s",(f['principal'],))
        token2,_=self.token(f['subject']); before=self.session_count(f['principal'])
        self.repeat_denied(lambda:self.repeat(f['subject'],token2))
        self.assertEqual(self.session_count(f['principal']),before)

    def test_53_enabled_principal_without_activation_audit_is_rejected(self):
        principal,subject=self.provision()
        self.db("UPDATE echo_identity.principals SET enabled=true,auth_version=auth_version+1 WHERE principal_id=%s",(principal,))
        token,_=self.token(subject)
        self.repeat_denied(lambda:self.repeat(subject,token))
        self.assertEqual(self.session_count(principal),0)

    def test_54_request_body_cannot_choose_identity_or_session_policy(self):
        principal,subject=self.activated(); token,_=self.token(subject)
        bodies=[b'[]',b'null',b'',b'\xff',b' '*257,b'{"x":1,"x":2}']
        for field in ('principal_id','actor_id','source_id','session_key','issuer','subject','auth_version','refresh_token','logout_all'):
            bodies.append(json.dumps({field:'untrusted'}).encode())
        for raw in bodies:
            with self.subTest(body=raw):
                self.repeat_denied(lambda raw=raw:self.repeat(subject,token,body=raw),'INVALID_REPEAT_LOGIN_REQUEST')
        self.assertEqual(self.session_count(principal),0)

    def test_55_invalid_signature_is_rejected_before_pool_lease(self):
        principal,subject=self.activated(); calls=[]
        def forbidden():
            calls.append(True); raise AssertionError('DB must not be touched')
        boundary=SignedRepeatLoginBoundary(self.config,forbidden)
        wrong,_=self.token(subject,key=self.wrong_key)
        invalid=[None,'','Basic x','Bearer junk','Bearer '+wrong]
        now=int(time.time())
        for patch in ({'iss':first_base.ISSUER+'/'},{'aud':'wrong'},{'exp':now-1},{'nbf':now+30},{'iat':now+30,'nbf':now+30}):
            token,_=self.token(subject,extra=patch); invalid.append('Bearer '+token)
        for auth in invalid:
            self.repeat_denied(lambda auth=auth:boundary.login(auth,b'{}'),'IDENTITY_REJECTED')
        self.assertEqual(calls,[]); self.assertEqual(self.session_count(principal),0)

    def test_56_same_jti_cannot_be_retargeted_to_another_subject(self):
        p1,s1=self.activated(); p2,s2=self.activated(); shared='repeat-'+uuid4().hex
        t1,_=self.token(s1,jti=shared); t2,_=self.token(s2,jti=shared)
        self.repeat(s1,t1); self.repeat_denied(lambda:self.repeat(s2,t2))
        self.assertEqual((self.session_count(p1),self.session_count(p2)),(1,0))

    def test_57_service_runtime_isolation_and_no_direct_registry_access(self):
        with self.assertRaises(psycopg.Error):
            with self.repeat_service_connection() as c:
                c.execute('SELECT count(*) FROM echo_identity.sessions').fetchone()
        principal,subject=self.activated(); token,claims=self.token(subject)
        key=derive_session_key(first_base.ISSUER,claims['jti'])
        with self.assertRaises(psycopg.Error) as caught:
            with self.admin() as c:
                c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(RUNTIME)))
                c.execute("SELECT echo_identity.runtime_repeat_login_session(%s,%s,%s,%s,%s,%s)",
                    (first_base.ISSUER,subject,key,claims['iat']*1000,claims['nbf']*1000,claims['exp']*1000)).fetchone()
        self.assertIn('REPEAT_LOGIN_SERVICE_REQUIRED',str(caught.exception))
        with self.repeat_pool.connection() as c:
            with self.assertRaises(psycopg.Error):
                with c.transaction():
                    c.execute("SELECT echo_identity.runtime_bootstrap_first_session(%s,%s,%s,%s,%s,%s)",
                        (first_base.ISSUER,subject,key,claims['iat']*1000,claims['nbf']*1000,claims['exp']*1000)).fetchone()
        self.assertEqual(self.session_count(principal),0)

    def test_58_concurrent_distinct_tokens_after_logout_have_one_winner(self):
        f=self.fixture(); self.logout(f); t1,_=self.token(f['subject']); t2,_=self.token(f['subject'])
        def call(token):
            try:
                return ('ok',self.repeat(f['subject'],token))
            except RepeatLoginError as exc:
                return ('err',exc.code)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results=[x.result(timeout=10) for x in [executor.submit(call,t1),executor.submit(call,t2)]]
        self.assertEqual(sorted(x[0] for x in results),['err','ok'])
        self.assertEqual([x[1] for x in results if x[0]=='err'],['REPEAT_LOGIN_REJECTED'])
        self.assertEqual(self.session_count(f['principal']),2)
        self.assertEqual(self.current_active_count(f['principal']),1)

    def test_59_unknown_post_commit_ack_requires_explicit_idempotent_retry(self):
        f=self.fixture(); self.logout(f); token2,_=self.token(f['subject'])
        @contextmanager
        def lost_ack():
            with self.repeat_pool.connection() as c:
                yield c
            raise RuntimeError('simulated acknowledgement loss after commit')
        uncertain=SignedRepeatLoginBoundary(self.config,lost_ack)
        self.repeat_denied(lambda:self.repeat(f['subject'],token2,boundary=uncertain),'REPEAT_LOGIN_BACKEND_UNAVAILABLE')
        self.assertEqual(self.session_count(f['principal']),2)
        recovered=self.repeat(f['subject'],token2); self.assertTrue(recovered.replayed)

    def test_60_token_expiry_while_waiting_for_principal_lock_rolls_back(self):
        f=self.fixture(); self.logout(f); token2,claims2=self.token(f['subject'],lifetime=2)
        holder=self.admin(); executor=ThreadPoolExecutor(max_workers=1)
        try:
            holder.execute('SELECT principal_id FROM echo_identity.principals WHERE principal_id=%s FOR UPDATE',(f['principal'],))
            future=executor.submit(self.repeat,f['subject'],token2)
            time.sleep(0.15); self.assertFalse(future.done())
            time.sleep(max(0.0,claims2['exp']-time.time()+0.08)); holder.rollback()
            with self.assertRaises(RepeatLoginError) as caught:
                future.result(timeout=10)
            self.assertEqual(caught.exception.code,'REPEAT_LOGIN_REJECTED')
            self.assertEqual(self.session_count(f['principal']),1)
        finally:
            holder.rollback(); holder.close(); executor.shutdown(wait=True)

    def test_61_password_and_exact_function_allowlist_fail_closed_on_drift(self):
        with self.assertRaises(psycopg.Error):
            with self.repeat_service_connection(password='definitely-wrong-password') as c:
                c.execute('SELECT 1')
        with self.repeat_pool.connection() as c:
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,RUNTIME))
        logout_fn='echo_identity.runtime_logout_current_session(text,text,text,bigint,bigint,bigint)'
        try:
            with self.admin() as c:
                c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {} TO {}').format(sql.SQL(logout_fn),sql.Identifier(RUNTIME)))
            with self.assertRaises(RepeatLoginPoolError) as caught:
                with self.repeat_pool.connection():
                    pass
            self.assertEqual(caught.exception.code,'FUNCTION_PRIVILEGE_DRIFT')
        finally:
            with self.admin() as c:
                c.execute(sql.SQL('REVOKE EXECUTE ON FUNCTION {} FROM {}').format(sql.SQL(logout_fn),sql.Identifier(RUNTIME)))


if __name__ == '__main__':
    import unittest
    unittest.main(verbosity=2)
