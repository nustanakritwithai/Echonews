"""Real RS256 -> c5b proof -> c5c.1 Principal, using two real service LOGINs.
Synthetic disposable PostgreSQL 17 only. Matrix subtests count as one test method.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
from queue import Queue
import secrets
import sys
import time
import unittest
from uuid import UUID, uuid4

import jwt
import psycopg
from psycopg import sql
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE),str(HERE.parent/'p2_1c2b1'),str(HERE.parent/'p2_1c2d4c5b')]
from identity_boundary import Config
from account_link_boundary import SignedAccountLinkBoundary
from account_link_pool import AccountLinkPool, SERVICE as LINK_SERVICE
from principal_boundary import SignedPrincipalBoundary, PrincipalProvisionError, PROVISION_SQL, CLOCK_SQL
from principal_pool import PrincipalPool, PrincipalPoolError, SERVICE, RUNTIME, GUARD, FUNCTION

DB = 'echo_account_link_signed_test'
ISSUER = 'https://issuer.principal.fixture.invalid/echo'
AUD = 'echo-principal-fixture'


class SignedPrincipalTests(unittest.TestCase):
    @staticmethod
    def admin():
        return psycopg.connect(connect_timeout=3)

    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES' or os.environ.get('PGDATABASE') != DB
                or os.environ.get('PGHOST') not in ('127.0.0.1','localhost')):
            raise RuntimeError('refusing non-disposable database')
        with cls.admin() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('PostgreSQL 17 required')
        cls.key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.config = Config(ISSUER,AUD,'ephemeral-principal-v1',{'fixture':cls.key.public_key()})
        cls.password = secrets.token_urlsafe(32)
        cls.link_password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            for role,password in ((SERVICE,cls.password),(LINK_SERVICE,cls.link_password)):
                c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(role),sql.Literal(password)))
        cls.pool = PrincipalPool(**cls.pool_config())
        cls.link_pool = AccountLinkPool(**cls.pool_config(user=LINK_SERVICE,password=cls.link_password))
        cls.pool.open(); cls.link_pool.open()
        cls.addClassCleanup(cls.cleanup)
        cls.link = SignedAccountLinkBoundary(cls.config,cls.link_pool.connection)
        cls.boundary = SignedPrincipalBoundary(cls.config,cls.pool.connection)

    @classmethod
    def pool_config(cls, **patch):
        return dict(host='127.0.0.1',port=int(os.environ.get('PGPORT','5432')),
            dbname=DB,user=SERVICE,password=cls.password,sslmode='disable',max_size=2,
            allow_insecure_test_loopback=True,**{}) | patch

    @classmethod
    def cleanup(cls):
        cls.pool.close(); cls.link_pool.close()
        with cls.admin() as c:
            c.execute('DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_core CASCADE;')
            for role in (SERVICE,RUNTIME,GUARD,'echo_account_link_service','echo_account_link_runtime',
                'echo_account_link_guard','echo_identity_mutation_service','echo_identity_mutation_runtime',
                'echo_identity_mutation_guard','echo_identity_registry_service','echo_identity_registry_runtime',
                'echo_identity_registry_guard'):
                c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
        with cls.admin() as c:
            if not c.execute("SELECT to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_core') IS NULL AND to_regrole(%s) IS NULL",(SERVICE,)).fetchone()[0]:
                raise AssertionError('cleanup incomplete')
        print('CLEAN_SIGNED_PRINCIPAL_DATABASE',flush=True)

    def db(self, query, params=()):
        with self.admin() as c:
            cursor = c.execute(query,params)
            return cursor.fetchone() if cursor.description else None

    def token(self, subject, **changes):
        now = int(time.time())
        claims = dict(iss=ISSUER,aud=AUD,sub=subject,iat=now-2,nbf=now-1,exp=now+180,jti=uuid4().hex)
        key = changes.pop('_key',self.key)
        headers = changes.pop('_headers',{})
        claims.update(changes)
        return 'Bearer ' + jwt.encode(claims,key,algorithm='RS256',headers={'kid':'fixture','typ':'at+jwt',**headers})

    def fixture(self, subject=None):
        subject = subject or ('subject-'+uuid4().hex)
        auth = self.token(subject)
        proof = self.link.issue(auth,b'{}')
        return subject,auth,proof

    @staticmethod
    def body(proof):
        return json.dumps({'proof_id':str(proof.proof_id)}).encode()

    def provision(self, f, boundary=None, auth=None):
        return (boundary or self.boundary).provision(auth or f[1],self.body(f[2]))

    def deny(self, call, code='PRINCIPAL_PROVISION_REJECTED'):
        with self.assertRaises(PrincipalProvisionError) as caught:
            call()
        self.assertEqual(caught.exception.code,code)
        self.assertEqual(str(caught.exception),code)

    def counts(self):
        return self.db('''SELECT (SELECT count(*) FROM echo_identity.principals),
            (SELECT count(*) FROM echo_identity.account_link_proofs WHERE consumed_at IS NOT NULL),
            (SELECT count(*) FROM echo_identity.sessions)''')

    def authority(self, principal):
        return self.db('SELECT enabled,writer_enabled,reviewer_enabled,auth_version FROM echo_identity.principals WHERE principal_id=%s',(principal,))

    def test_01_signed_proof_creates_disabled_server_owned_principal(self):
        f = self.fixture(); r = self.provision(f)
        self.assertEqual(set(asdict(r)),{'principal_id'})
        self.assertIsInstance(r.principal_id,UUID); self.assertFalse(r.ready_for_execution)
        self.assertEqual(self.authority(r.principal_id),(False,False,False,1))
        row = self.db('''SELECT p.issuer,p.subject,p.actor_id=b.actor_id,p.source_id=b.source_id,
            proof.consumed_principal_id=p.principal_id FROM echo_identity.principals p
            JOIN echo_identity.account_subject_bindings b USING(issuer,subject)
            JOIN echo_identity.account_link_proofs proof ON proof.proof_id=%s WHERE p.principal_id=%s''',
            (f[2].proof_id,r.principal_id))
        self.assertEqual(row,(ISSUER,f[0],True,True,True))

    def test_02_proof_reference_without_signed_token_is_not_authentication(self):
        f = self.fixture(); before = self.counts()
        for auth in (None,'','Basic x',str(f[2].proof_id)):
            self.deny(lambda: self.boundary.provision(auth,self.body(f[2])),'IDENTITY_REJECTED')
        self.assertEqual(self.counts(),before)

    def test_03_invalid_signature_is_denied_before_pool_lease(self):
        f = self.fixture(); calls=[]
        def forbidden():
            calls.append(True)
            raise AssertionError('must not lease')
        b = SignedPrincipalBoundary(self.config,forbidden)
        self.deny(lambda: self.provision(f,b,auth=self.token(f[0],_key=self.wrong_key)),'IDENTITY_REJECTED')
        self.assertEqual(calls,[])

    def test_04_token_profile_adversarial_matrix(self):
        f=self.fixture(); now=int(time.time()); before=self.counts()
        for patch in ({'iss':ISSUER+'/'},{'aud':'wrong'},{'exp':now-1},
            {'nbf':now+60},{'iat':now+60,'nbf':now+60},
            {'_headers':{'kid':'unknown'}},{'_headers':{'typ':'JWT'}}):
            with self.subTest(patch=patch):
                self.deny(lambda:self.provision(f,auth=self.token(f[0],**patch)),'IDENTITY_REJECTED')
        self.assertEqual(self.counts(),before)

    def test_05_client_identity_roles_and_duplicate_keys_are_rejected(self):
        f=self.fixture(); before=self.counts()
        bodies=[b'{}',b'[]',b'null',b'\xff',b' '*513,
            b'{"proof_id":null}',b'{"proof_id":"00000000-0000-0000-0000-000000000000"}',
            ('{"proof_id":"'+str(f[2].proof_id)+'","proof_id":"'+str(f[2].proof_id)+'"}').encode()]
        for key in ('issuer','subject','actor_id','source_id','principal_id','role','enabled','writer_enabled','session_key'):
            bodies.append(json.dumps({'proof_id':str(f[2].proof_id),key:'injected'}).encode())
        for raw in bodies:
            with self.subTest(raw=raw):
                self.deny(lambda:self.boundary.provision(f[1],raw),'INVALID_PRINCIPAL_REQUEST')
        self.assertEqual(self.counts(),before)

    def test_06_signed_custom_identity_and_role_claims_have_no_authority(self):
        f=self.fixture(); fake=str(uuid4())
        r=self.provision(f,auth=self.token(f[0],actor_id=fake,source_id=fake,principal_id=fake,role='admin',enabled=True))
        row=self.db('SELECT actor_id::text,source_id::text FROM echo_identity.principals WHERE principal_id=%s',(r.principal_id,))
        self.assertNotIn(fake,row); self.assertNotEqual(str(r.principal_id),fake)
        self.assertEqual(self.authority(r.principal_id),(False,False,False,1))

    def test_07_other_subject_cannot_consume_stolen_proof(self):
        f=self.fixture(); before=self.counts()
        self.deny(lambda:self.provision(f,auth=self.token('other-'+uuid4().hex)))
        self.assertEqual(self.counts(),before)
        self.assertIsNone(self.db('SELECT consumed_at FROM echo_identity.account_link_proofs WHERE proof_id=%s',(f[2].proof_id,))[0])

    def test_08_subject_case_and_trailing_space_are_distinct(self):
        f=self.fixture()
        for subject in (f[0].upper(),f[0]+' '):
            self.deny(lambda:self.provision(f,auth=self.token(subject)))

    def test_09_sql_like_subject_is_literal_not_injection(self):
        f=self.fixture("x'; SELECT 1; --"+uuid4().hex); r=self.provision(f)
        self.assertEqual(self.db('SELECT subject FROM echo_identity.principals WHERE principal_id=%s',(r.principal_id,))[0],f[0])

    def test_10_same_proof_retry_resolves_same_principal_once(self):
        f=self.fixture(); before=self.counts(); a=self.provision(f); b=self.provision(f)
        self.assertEqual(a,b)
        self.assertEqual(self.counts(),(before[0]+1,before[1]+1,before[2]))
        self.assertEqual(self.authority(a.principal_id),(False,False,False,1))

    def test_11_new_proof_for_same_subject_preserves_principal(self):
        f=self.fixture(); a=self.provision(f)
        g=self.fixture(f[0]); b=self.provision(g)
        self.assertEqual(a,b)

    def test_12_distinct_accounts_get_distinct_principals(self):
        a=self.provision(self.fixture()); b=self.provision(self.fixture())
        self.assertNotEqual(a.principal_id,b.principal_id)

    def test_13_concurrent_same_proof_creates_only_one_principal(self):
        f=self.fixture(); before=self.counts()
        with ThreadPoolExecutor(max_workers=2) as ex:
            futures=[ex.submit(self.provision,f) for _ in range(2)]
            results=[x.result(timeout=12) for x in futures]
        self.assertEqual(results[0],results[1])
        self.assertEqual(self.counts(),(before[0]+1,before[1]+1,before[2]))

    def test_14_concurrent_distinct_proofs_for_same_subject_share_principal(self):
        f=self.fixture(); g=self.fixture(f[0]); before=self.counts()
        with ThreadPoolExecutor(max_workers=2) as ex:
            futures=[ex.submit(self.provision,x) for x in (f,g)]
            results=[x.result(timeout=12) for x in futures]
        self.assertEqual(results[0],results[1])
        self.assertEqual(self.counts(),(before[0]+1,before[1]+2,before[2]))

    def test_15_retry_after_disable_cannot_reenable_or_reset_generation(self):
        f=self.fixture(); r=self.provision(f)
        self.db('UPDATE echo_identity.principals SET enabled=true,writer_enabled=true,auth_version=2 WHERE principal_id=%s',(r.principal_id,))
        self.db('UPDATE echo_identity.principals SET enabled=false,writer_enabled=false,auth_version=3 WHERE principal_id=%s',(r.principal_id,))
        self.assertEqual(self.provision(f),r)
        self.assertEqual(self.authority(r.principal_id),(False,False,False,3))

    def test_16_existing_authority_is_not_granted_removed_or_reset(self):
        f=self.fixture(); r=self.provision(f)
        self.db('UPDATE echo_identity.principals SET enabled=true,writer_enabled=true,reviewer_enabled=true,auth_version=2 WHERE principal_id=%s',(r.principal_id,))
        self.provision(self.fixture(f[0]))
        self.assertEqual(self.authority(r.principal_id),(True,True,True,2))

    def expire_proof(self,f):
        self.db("UPDATE echo_identity.account_link_proofs SET issued_at=clock_timestamp()-interval '60 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE proof_id=%s",(f[2].proof_id,))

    def test_17_expired_proof_denied_with_valid_token(self):
        f=self.fixture(); self.expire_proof(f); before=self.counts()
        self.deny(lambda:self.provision(f)); self.assertEqual(self.counts(),before)

    def test_18_consumed_expired_proof_is_not_an_authority_ticket(self):
        f=self.fixture(); self.provision(f); self.expire_proof(f); before=self.counts()
        self.deny(lambda:self.provision(f)); self.assertEqual(self.counts(),before)

    def test_19_unknown_proof_does_not_autoprovision(self):
        before=self.counts()
        self.deny(lambda:self.boundary.provision(self.token('unknown-'+uuid4().hex),json.dumps({'proof_id':str(uuid4())}).encode()))
        self.assertEqual(self.counts(),before)

    def fault_boundary(self,target,replacement):
        class Cursor:
            def fetchone(self):
                return replacement
        class Connection:
            def __init__(self,c): self.c=c
            def execute(self,statement,params=None,**kw):
                cursor=self.c.execute(statement,params,**kw)
                return Cursor() if statement==target else cursor
        @contextmanager
        def lease():
            with self.pool.connection() as c:
                yield Connection(c)
        return SignedPrincipalBoundary(self.config,lease)

    def test_20_bad_receipt_rolls_back_principal_and_proof_consumption(self):
        f=self.fixture(); before=self.counts()
        b=self.fault_boundary(PROVISION_SQL,({'principalId':str(uuid4())},))
        self.deny(lambda:self.provision(f,b),'PRINCIPAL_CONTRACT_VIOLATION')
        self.assertEqual(self.counts(),before)
        self.assertIsNone(self.db('SELECT consumed_at FROM echo_identity.account_link_proofs WHERE proof_id=%s',(f[2].proof_id,))[0])
        self.provision(f)

    def test_21_invalid_final_clock_also_rolls_back(self):
        f=self.fixture(); before=self.counts()
        self.deny(lambda:self.provision(f,self.fault_boundary(CLOCK_SQL,(True,))),'PRINCIPAL_CONTRACT_VIOLATION')
        self.assertEqual(self.counts(),before)

    def expiry_wait(self,kind):
        f=self.fixture(); before=self.counts()
        exp=int(time.time())+3
        if kind=='proof':
            self.db('UPDATE echo_identity.account_link_proofs SET expires_at=to_timestamp(%s) WHERE proof_id=%s',(exp,f[2].proof_id))
            auth=f[1]
        else:
            auth=self.token(f[0],exp=exp)
        holder=self.admin(); pids=Queue(maxsize=1); ex=ThreadPoolExecutor(max_workers=1)
        @contextmanager
        def lease():
            with self.pool.connection() as c:
                c.execute("SET LOCAL lock_timeout='8s'"); c.execute("SET LOCAL statement_timeout='12s'")
                pids.put(c.info.backend_pid)
                yield c
        try:
            if kind=='advisory':
                holder.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s || chr(31) || %s,0))',(ISSUER,f[0]))
            else:
                holder.execute('SELECT proof_id FROM echo_identity.account_link_proofs WHERE proof_id=%s FOR UPDATE',(f[2].proof_id,))
            b=SignedPrincipalBoundary(self.config,lease)
            future=ex.submit(self.provision,f,b,auth)
            waiter=pids.get(timeout=5); deadline=time.monotonic()+5; observed=False
            while time.monotonic()<deadline:
                observed=self.db('SELECT %s=ANY(pg_blocking_pids(%s))',(holder.info.backend_pid,waiter))[0]
                if observed: break
                if future.done(): self.fail('expected database lock wait was not reached')
                time.sleep(0.01)
            self.assertTrue(observed)
            self.db('SELECT pg_sleep(GREATEST(0,%s-extract(epoch FROM clock_timestamp())+0.05))',(exp,))
            holder.rollback()
            self.deny(lambda:future.result(timeout=12))
            self.assertEqual(self.counts(),before)
            print('PRINCIPAL_EXPIRY_LOCK_OBSERVED '+kind,flush=True)
        finally:
            holder.rollback(); holder.close(); ex.shutdown(wait=True)

    def test_22_token_expiry_during_advisory_wait_denied(self):
        self.expiry_wait('advisory')

    def test_23_token_expiry_during_consumer_row_wait_denied(self):
        self.expiry_wait('row')

    def test_24_proof_expiry_during_row_wait_denied(self):
        self.expiry_wait('proof')

    def test_25_lock_timeout_rolls_back_without_retry(self):
        f=self.fixture(); before=self.counts(); holder=self.admin()
        @contextmanager
        def lease():
            with self.pool.connection() as c:
                c.execute("SET LOCAL lock_timeout='100ms'")
                yield c
        try:
            holder.execute('SELECT proof_id FROM echo_identity.account_link_proofs WHERE proof_id=%s FOR UPDATE',(f[2].proof_id,))
            b=SignedPrincipalBoundary(self.config,lease)
            self.deny(lambda:self.provision(f,b),'PRINCIPAL_BACKEND_UNAVAILABLE')
            self.assertEqual(self.counts(),before)
        finally:
            holder.rollback(); holder.close()

    def test_26_real_service_and_runtime_have_no_direct_bypass(self):
        config=self.pool_config(); config={k:v for k,v in config.items() if k not in ('max_size','allow_insecure_test_loopback')}
        with psycopg.connect(**config,autocommit=True) as c:
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),(SERVICE,SERVICE))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute('SELECT * FROM echo_identity.principals')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute(PROVISION_SQL,(uuid4(),ISSUER,'x',1,1,2))
        with self.pool.connection() as c:
            allowed=c.execute('''SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='echo_identity' AND has_function_privilege(%s,p.oid,'EXECUTE') ORDER BY 1''',(RUNTIME,)).fetchall()
            self.assertEqual(allowed,[(FUNCTION,)])
        for statement in ('SELECT * FROM echo_identity.principals','UPDATE echo_identity.principals SET enabled=true',
                'INSERT INTO echo_identity.sessions DEFAULT VALUES',
                'SET ROLE echo_identity_mutation_runtime','SET ROLE echo_account_link_guard'):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.pool.connection() as c: c.execute(statement)

    def test_27_table_privilege_drift_is_detected_and_closed(self):
        f=self.fixture(); before=self.counts()
        self.db(sql.SQL('GRANT SELECT ON echo_identity.principals TO {}').format(sql.Identifier(RUNTIME)))
        try:
            self.deny(lambda:self.provision(f),'PRINCIPAL_BACKEND_UNAVAILABLE')
        finally:
            self.db(sql.SQL('REVOKE SELECT ON echo_identity.principals FROM {}').format(sql.Identifier(RUNTIME)))
        self.assertEqual(self.counts(),before); self.provision(f)

    def test_28_function_privilege_drift_is_detected(self):
        f=self.fixture(); signature='echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)'
        self.db('GRANT EXECUTE ON FUNCTION '+signature+' TO '+RUNTIME)
        try:
            self.deny(lambda:self.provision(f),'PRINCIPAL_BACKEND_UNAVAILABLE')
        finally:
            self.db('REVOKE EXECUTE ON FUNCTION '+signature+' FROM '+RUNTIME)
        self.provision(f)

    def test_29_pool_reset_and_failed_transaction_recovery(self):
        p=PrincipalPool(**self.pool_config(max_size=1)); p.open()
        try:
            with p.connection() as c:
                pid=c.info.backend_pid; c.execute('CREATE TEMP TABLE leak(x int)')
                c.execute("SET LOCAL application_name='dirty-principal'")
            with self.assertRaises(psycopg.Error):
                with p.connection() as c: c.execute('SELECT 1/0')
            with p.connection() as c:
                self.assertEqual(c.info.backend_pid,pid)
                self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.leak')").fetchone()[0])
                self.assertNotEqual(c.execute("SELECT current_setting('application_name')").fetchone()[0],'dirty-principal')
            self.provision(self.fixture(),SignedPrincipalBoundary(self.config,p.connection))
        finally:
            p.close()

    def test_30_wrong_service_credentials_and_insecure_config_denied(self):
        for patch in ({'user':'echo_test'},{'host':'example.invalid'},{'allow_insecure_test_loopback':False}):
            with self.assertRaises(PrincipalPoolError): PrincipalPool(**self.pool_config(**patch))
        config=self.pool_config(password='wrong-'+secrets.token_hex(16))
        config={k:v for k,v in config.items() if k not in ('max_size','allow_insecure_test_loopback')}
        with self.assertRaises(psycopg.OperationalError): psycopg.connect(**config,connect_timeout=2)

    def test_31_sql_nulls_and_unsupported_isolation_fail_closed(self):
        f=self.fixture(); now=int(time.time()*1000)
        params=[f[2].proof_id,ISSUER,f[0],now-2000,now-1000,now+30000]
        for i in range(len(params)):
            invalid=params.copy(); invalid[i]=None
            with self.assertRaises(psycopg.Error):
                with self.pool.connection() as c: c.execute(PROVISION_SQL,invalid)
        config=self.pool_config(); config={k:v for k,v in config.items() if k not in ('max_size','allow_insecure_test_loopback')}
        for level in ('REPEATABLE READ','SERIALIZABLE'):
            with psycopg.connect(**config,autocommit=True) as c:
                with self.assertRaises(psycopg.errors.ActiveSqlTransaction):
                    with c.transaction():
                        c.execute('SET TRANSACTION ISOLATION LEVEL '+level)
                        c.execute('SET LOCAL ROLE '+RUNTIME)
                        c.execute(PROVISION_SQL,params)

    def test_32_all_session_and_news_tables_remain_empty(self):
        self.provision(self.fixture())
        self.assertEqual(self.db('SELECT count(*) FROM echo_identity.sessions')[0],0)
        with self.admin() as c:
            tables=c.execute("SELECT tablename FROM pg_tables WHERE schemaname='echo_core' AND tablename NOT IN ('actors','sources')").fetchall()
            self.assertGreater(len(tables),0)
            for (table,) in tables:
                count=c.execute(sql.SQL('SELECT count(*) FROM echo_core.{}').format(sql.Identifier(table))).fetchone()[0]
                self.assertEqual(count,0,table)

    def test_33_commit_ack_ambiguity_is_error_and_explicit_retry_deduplicates(self):
        f=self.fixture(); before=self.counts()
        @contextmanager
        def lost_ack():
            with self.pool.connection() as c: yield c
            raise TimeoutError('synthetic-after-real-commit-no-secret-output')
        self.deny(lambda:self.provision(f,SignedPrincipalBoundary(self.config,lost_ack)),'PRINCIPAL_BACKEND_UNAVAILABLE')
        committed=self.counts()
        self.assertEqual(committed,(before[0]+1,before[1]+1,before[2]))
        self.provision(f); self.assertEqual(self.counts(),committed)

    def test_34_registry_outage_does_not_create_a_principal(self):
        f=self.fixture(); before=self.counts()
        def offline(): raise RuntimeError('synthetic database secret')
        self.deny(lambda:self.provision(f,SignedPrincipalBoundary(self.config,offline)),'PRINCIPAL_BACKEND_UNAVAILABLE')
        self.assertEqual(self.counts(),before)


if __name__=='__main__':
    unittest.main(verbosity=2)
