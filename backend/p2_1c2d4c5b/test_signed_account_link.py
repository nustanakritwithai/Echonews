from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import os
from pathlib import Path
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
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'p2_1c2b1'))

from identity_boundary import Config  # noqa: E402
from account_link_boundary import (  # noqa: E402
    SignedAccountLinkBoundary, SignedAccountLinkError,
)
from account_link_pool import (  # noqa: E402
    AccountLinkPool, AccountLinkPoolError, GUARD, RUNTIME, SERVICE,
)

DB_NAME = 'echo_account_link_signed_test'
ISSUER = 'https://issuer.account-link-signed.fixture.invalid/echo'
AUD = 'echo-account-link-signed-fixture'


class SignedAccountLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != DB_NAME
                or os.environ.get('PGHOST') not in ('127.0.0.1', 'localhost')):
            raise RuntimeError('refusing non-disposable signed account-link database')
        with cls.admin() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('signed account-link gate requires PostgreSQL 17')
            present = c.execute('''SELECT to_regrole(%s) IS NOT NULL
                AND to_regrole(%s) IS NOT NULL AND to_regrole(%s) IS NOT NULL
                AND to_regprocedure('echo_identity.runtime_issue_account_link_proof(uuid,text,text,bigint,bigint,bigint,bigint)') IS NOT NULL''',
                (SERVICE, RUNTIME, GUARD)).fetchone()[0]
            if not present:
                raise RuntimeError('signed account-link service migration not installed')

        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, 'account-link-signed-keyset-v1',
                            {'fixture-key': cls.key.public_key()})
        cls.password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(SERVICE), sql.Literal(cls.password)))

        with cls.assertRaisesStatic(psycopg.Error):
            cls.raw_service(password='wrong-' + secrets.token_hex(8))

        cls.pool = cls.make_pool(max_size=1)
        cls.pool.open()
        cls.boundary = SignedAccountLinkBoundary(cls.config, cls.pool.connection)
        cls.addClassCleanup(cls.cleanup)

    @classmethod
    def assertRaisesStatic(cls, exc):
        class _Raises:
            def __enter__(self):
                return None
            def __exit__(self, typ, value, tb):
                if typ is None:
                    raise AssertionError(f'{exc.__name__} not raised')
                if not issubclass(typ, exc):
                    return False
                return True
        return _Raises()

    @staticmethod
    def admin():
        return psycopg.connect(connect_timeout=3)

    @classmethod
    def raw_service(cls, *, password=None):
        return psycopg.connect(
            host='127.0.0.1', port=int(os.environ.get('PGPORT', '5432')),
            dbname=DB_NAME, user=SERVICE, password=password or cls.password,
            sslmode='disable', connect_timeout=3, autocommit=True,
            prepare_threshold=None,
        )

    @classmethod
    def make_pool(cls, *, max_size=1):
        return AccountLinkPool(
            host='127.0.0.1', port=int(os.environ.get('PGPORT', '5432')),
            dbname=DB_NAME, user=SERVICE, password=cls.password,
            sslmode='disable', max_size=max_size,
            allow_insecure_test_loopback=True,
        )

    @classmethod
    def cleanup(cls):
        try:
            cls.pool.close()
        except Exception:
            pass
        with cls.admin() as c:
            c.execute('DROP SCHEMA IF EXISTS echo_identity CASCADE; DROP SCHEMA IF EXISTS echo_core CASCADE;')
            for role in (
                SERVICE, RUNTIME, GUARD,
                'echo_identity_mutation_service', 'echo_identity_mutation_runtime', 'echo_identity_mutation_guard',
                'echo_identity_registry_service', 'echo_identity_registry_runtime', 'echo_identity_registry_guard',
            ):
                c.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
        print('CLEAN_SIGNED_ACCOUNT_LINK_DATABASE', flush=True)

    @staticmethod
    def subject(prefix='signed'):
        return f'{prefix}-' + uuid4().hex

    def token(self, subject: str, *, key=None, issuer=ISSUER, audience=AUD,
              lifetime=180, nbf_offset=-1, extra=None, kid='fixture-key', typ='at+jwt'):
        now = int(time.time())
        claims = {
            'iss': issuer, 'aud': audience, 'sub': subject,
            'iat': now - 2, 'nbf': now + nbf_offset, 'exp': now + lifetime,
            'jti': 'onboard-' + uuid4().hex,
        }
        if extra:
            claims.update(extra)
        return jwt.encode(claims, key or self.key, algorithm='RS256',
                          headers={'kid': kid, 'typ': typ})

    @staticmethod
    def auth(token):
        return 'Bearer ' + token

    def assert_error(self, code, call):
        with self.assertRaises(SignedAccountLinkError) as ctx:
            call()
        self.assertEqual(ctx.exception.code, code)

    def proof_count(self):
        with self.admin() as c:
            return c.execute('SELECT count(*) FROM echo_identity.account_link_proofs').fetchone()[0]

    def test_01_real_service_login_has_no_baseline_table_or_function_access(self):
        with self.raw_service() as c:
            self.assertEqual(c.info.user, SERVICE)
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(), (SERVICE, SERVICE))
            self.assertFalse(c.execute("SELECT has_table_privilege(%s,'echo_identity.account_link_proofs','SELECT')",
                                       (SERVICE,)).fetchone()[0])
            funcs = c.execute('''SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='echo_identity' AND has_function_privilege(%s,p.oid,'EXECUTE')''',
                (SERVICE,)).fetchone()[0]
            self.assertEqual(funcs, 0)

    def test_02_verified_unknown_subject_gets_server_owned_proof_without_identity_leak(self):
        subject = self.subject('first-account')
        receipt = self.boundary.issue(self.auth(self.token(subject)), b'{}')
        self.assertEqual(set(asdict(receipt)), {'proof_id', 'expires_at_ms'})
        with self.admin() as c:
            row = c.execute('''SELECT p.issuer,p.subject,p.proof_id,p.actor_id,p.source_id,
                    p.expires_at>clock_timestamp()
                FROM echo_identity.account_link_proofs p WHERE p.proof_id=%s''',
                (receipt.proof_id,)).fetchone()
        self.assertEqual(row[:3], (ISSUER, subject, receipt.proof_id))
        self.assertIsInstance(row[3], UUID); self.assertIsInstance(row[4], UUID)
        self.assertNotEqual(row[3], row[4]); self.assertTrue(row[5])

    def test_03_request_body_accepts_no_issuer_subject_actor_source_or_proof_id(self):
        token = self.auth(self.token(self.subject('body')))
        before = self.proof_count()
        bodies = (
            b'{"issuer":"https://evil.invalid"}', b'{"subject":"other"}',
            b'{"actor_id":"00000000-0000-4000-8000-000000000001"}',
            b'{"source_id":"00000000-0000-4000-8000-000000000002"}',
            b'{"proof_id":"00000000-0000-4000-8000-000000000003"}',
        )
        for body in bodies:
            with self.subTest(body=body):
                self.assert_error('INVALID_ACCOUNT_LINK_REQUEST',
                                  lambda body=body: self.boundary.issue(token, body))
        self.assertEqual(self.proof_count(), before)

    def test_04_wrong_signature_is_rejected_before_database_write(self):
        before = self.proof_count()
        token = self.token(self.subject('wrong-signature'), key=self.wrong_key)
        self.assert_error('IDENTITY_REJECTED', lambda: self.boundary.issue(self.auth(token), b'{}'))
        self.assertEqual(self.proof_count(), before)

    def test_05_wrong_issuer_or_audience_is_rejected(self):
        for token in (
            self.token(self.subject('issuer'), issuer='https://wrong.invalid/echo'),
            self.token(self.subject('audience'), audience='wrong-audience'),
        ):
            with self.subTest(token=token[:20]):
                self.assert_error('IDENTITY_REJECTED', lambda token=token: self.boundary.issue(self.auth(token), b'{}'))

    def test_06_wrong_typ_or_unknown_kid_is_rejected(self):
        for token in (
            self.token(self.subject('typ'), typ='JWT'),
            self.token(self.subject('kid'), kid='unknown-key'),
        ):
            with self.subTest(token=token[:20]):
                self.assert_error('IDENTITY_REJECTED', lambda token=token: self.boundary.issue(self.auth(token), b'{}'))

    def test_07_expired_or_future_nbf_token_is_rejected(self):
        expired = self.token(self.subject('expired'), lifetime=-1)
        future = self.token(self.subject('future'), nbf_offset=60)
        for token in (expired, future):
            with self.subTest(token=token[:20]):
                self.assert_error('IDENTITY_REJECTED', lambda token=token: self.boundary.issue(self.auth(token), b'{}'))

    def test_08_signed_actor_source_role_hints_are_ignored(self):
        subject = self.subject('signed-hints')
        fake_actor = str(uuid4()); fake_source = str(uuid4())
        token = self.token(subject, extra={
            'actor_id': fake_actor, 'source_id': fake_source,
            'role': 'admin', 'principal_id': str(uuid4()),
        })
        receipt = self.boundary.issue(self.auth(token), b'{}')
        with self.admin() as c:
            row = c.execute('SELECT subject,actor_id::text,source_id::text FROM echo_identity.account_link_proofs WHERE proof_id=%s',
                            (receipt.proof_id,)).fetchone()
        self.assertEqual(row[0], subject)
        self.assertNotEqual(row[1], fake_actor); self.assertNotEqual(row[2], fake_source)

    def test_09_same_subject_gets_distinct_proofs_but_one_actor_source_binding(self):
        subject = self.subject('stable')
        first = self.boundary.issue(self.auth(self.token(subject)), b'{}')
        second = self.boundary.issue(self.auth(self.token(subject)), b'{}')
        self.assertNotEqual(first.proof_id, second.proof_id)
        with self.admin() as c:
            rows = c.execute('''SELECT actor_id,source_id FROM echo_identity.account_link_proofs
                WHERE proof_id=ANY(%s) ORDER BY proof_id''', ([first.proof_id, second.proof_id],)).fetchall()
        self.assertEqual(rows[0], rows[1])

    def test_10_different_signed_subjects_get_distinct_bindings(self):
        a = self.boundary.issue(self.auth(self.token(self.subject('a'))), b'{}')
        b = self.boundary.issue(self.auth(self.token(self.subject('b'))), b'{}')
        with self.admin() as c:
            rows = c.execute('''SELECT actor_id,source_id FROM echo_identity.account_link_proofs
                WHERE proof_id=ANY(%s) ORDER BY proof_id''', ([a.proof_id, b.proof_id],)).fetchall()
        self.assertNotEqual(rows[0], rows[1])

    def test_11_proof_expiry_is_capped_by_short_token_expiry(self):
        subject = self.subject('short-token')
        start = int(time.time() * 1000)
        receipt = self.boundary.issue(self.auth(self.token(subject, lifetime=25)), b'{}')
        self.assertGreater(receipt.expires_at_ms, start)
        self.assertLessEqual(receipt.expires_at_ms, start + 26_000)

    def test_12_role_and_membership_policy_is_exact(self):
        with self.admin() as c:
            roles = c.execute('''SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,
                    rolcreaterole,rolreplication,rolbypassrls
                FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname''',
                ([GUARD, RUNTIME, SERVICE],)).fetchall()
            memberships = c.execute('''SELECT member.rolname,parent.rolname,m.admin_option,m.inherit_option,m.set_option
                FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
                JOIN pg_roles parent ON parent.oid=m.roleid
                WHERE member.rolname=ANY(%s) ORDER BY 1,2''', ([SERVICE, RUNTIME, GUARD],)).fetchall()
        self.assertEqual(roles, [
            (GUARD, False, False, False, False, False, False, False),
            (RUNTIME, False, False, False, False, False, False, False),
            (SERVICE, True, False, False, False, False, False, False),
        ])
        self.assertEqual(memberships, [(SERVICE, RUNTIME, False, False, True)])

    def test_13_runtime_function_allowlist_is_issue_only(self):
        with self.admin() as c:
            allowed = c.execute('''SELECT p.oid::regprocedure::text FROM pg_proc p
                JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='echo_identity' AND has_function_privilege(%s,p.oid,'EXECUTE') ORDER BY 1''',
                (RUNTIME,)).fetchall()
        self.assertEqual(allowed, [(
            'echo_identity.runtime_issue_account_link_proof(uuid,text,text,bigint,bigint,bigint,bigint)',
        )])

    def test_14_reused_backend_connection_drops_temp_and_session_state(self):
        with self.pool.connection() as c:
            pid = c.execute('SELECT pg_backend_pid()').fetchone()[0]
            c.execute('CREATE TEMP TABLE leak_me(x integer)')
            c.execute("SET LOCAL application_name='signed-link-dirty'")
        with self.pool.connection() as c:
            self.assertEqual(c.execute('SELECT pg_backend_pid()').fetchone()[0], pid)
            self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.leak_me')").fetchone()[0])
            self.assertNotEqual(c.execute("SELECT current_setting('application_name')").fetchone()[0], 'signed-link-dirty')

    def test_15_failed_transaction_is_rolled_back_and_pool_remains_usable(self):
        with self.assertRaises(psycopg.Error):
            with self.pool.connection() as c:
                c.execute('SELECT 1/0').fetchone()
        receipt = self.boundary.issue(self.auth(self.token(self.subject('after-error'))), b'{}')
        self.assertIsInstance(receipt.proof_id, UUID)

    def test_16_privilege_drift_fails_closed(self):
        with self.admin() as c:
            c.execute(sql.SQL('GRANT SELECT ON echo_identity.account_link_proofs TO {}').format(sql.Identifier(RUNTIME)))
        try:
            with self.assertRaises(AccountLinkPoolError) as ctx:
                with self.pool.connection():
                    pass
            self.assertEqual(ctx.exception.code, 'DIRECT_TABLE_PRIVILEGE_DRIFT')
        finally:
            with self.admin() as c:
                c.execute(sql.SQL('REVOKE SELECT ON echo_identity.account_link_proofs FROM {}').format(sql.Identifier(RUNTIME)))
        receipt = self.boundary.issue(self.auth(self.token(self.subject('after-drift'))), b'{}')
        self.assertIsInstance(receipt.proof_id, UUID)

    def test_17_two_concurrent_verified_subjects_remain_isolated(self):
        pool2 = self.make_pool(max_size=2); pool2.open()
        boundary2 = SignedAccountLinkBoundary(self.config, pool2.connection)
        try:
            subjects = [self.subject('parallel-a'), self.subject('parallel-b')]
            def worker(subject):
                return subject, boundary2.issue(self.auth(self.token(subject)), b'{}')
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(worker, subjects))
            with self.admin() as c:
                db_subjects = {c.execute('SELECT subject FROM echo_identity.account_link_proofs WHERE proof_id=%s',
                                         (receipt.proof_id,)).fetchone()[0]
                               for _, receipt in results}
            self.assertEqual(db_subjects, set(subjects))
        finally:
            pool2.close()

    def test_18_verified_tls_is_default_and_insecure_mode_is_test_scoped(self):
        with self.assertRaises(AccountLinkPoolError) as ctx:
            AccountLinkPool(host='127.0.0.1', port=int(os.environ.get('PGPORT', '5432')),
                            dbname=DB_NAME, user=SERVICE, password=self.password,
                            sslmode='disable', allow_insecure_test_loopback=False)
        self.assertEqual(ctx.exception.code, 'VERIFIED_TLS_REQUIRED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
