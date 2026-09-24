from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import sys
import time
import unittest
from uuid import uuid4

import jwt
import psycopg
from psycopg import sql
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'p2_1c2b1'))
sys.path.insert(0, str(HERE.parent / 'p2_1c2c3'))

from identity_boundary import Boundary, BoundaryError, Config  # noqa: E402
from postgres_registry_adapter import derive_session_key  # noqa: E402
from registry_pool import (  # noqa: E402
    GUARD, RUNTIME, SERVICE, RegistryPool, RegistryPoolError,
)
from service_registry_adapter import ServicePostgresRegistryAdapter  # noqa: E402

DB_NAME = 'echo_registry_pool_test'
ISSUER = 'https://issuer.registry-pool.fixture.invalid/echo'
AUD = 'echo-registry-pool-fixture'
REQUEST_ID = '20000000-0000-4000-8000-000000000031'
ASSESSMENT_ID = '30000000-0000-4000-8000-000000000031'


def draft() -> bytes:
    return json.dumps({
        'request_id': REQUEST_ID,
        'command': 'CREATE_VOICE_DRAFT',
        'payload': {'text': 'registry service pool fixture'},
    }, separators=(',', ':')).encode()


def review() -> bytes:
    return json.dumps({
        'request_id': REQUEST_ID,
        'command': 'REVIEW_EVIDENCE_RELATION',
        'payload': {
            'assessment_id': ASSESSMENT_ID,
            'expected_revision': 1,
            'decision': 'ACCEPTED',
            'rationale': 'registry pool fixture review',
        },
    }, separators=(',', ':')).encode()


class RegistryServicePoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != DB_NAME
                or os.environ.get('PGHOST') not in ('127.0.0.1', 'localhost')):
            raise RuntimeError('refusing non-disposable registry pool database')
        with cls.admin() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('registry pool gate requires PostgreSQL 17')
            present = c.execute('''SELECT to_regrole(%s) IS NOT NULL
                AND to_regrole(%s) IS NOT NULL AND to_regrole(%s) IS NOT NULL
                AND to_regprocedure('echo_identity.runtime_lookup_session(text,text,text)') IS NOT NULL''',
                (SERVICE, RUNTIME, GUARD)).fetchone()[0]
            if not present:
                raise RuntimeError('registry service migration not installed')

        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, 'registry-pool-keyset-v1',
                            {'fixture-key': cls.key.public_key()})
        cls.password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            statement = sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(SERVICE), sql.Literal(cls.password))
            c.execute(statement)

        # Prove the test is not accidentally using trust auth for this service.
        with cls.assertRaisesStatic(psycopg.Error):
            cls.raw_service(password='definitely-wrong-' + secrets.token_hex(8))

        cls.pool = cls.make_pool(max_size=1)
        cls.pool.open()
        cls.adapter = ServicePostgresRegistryAdapter(cls.pool.connection)
        cls.boundary = Boundary(cls.config, resolve_binding=cls.adapter.resolve_binding)
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
        return RegistryPool(
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
            for role in (SERVICE, RUNTIME, GUARD):
                c.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
        print('CLEAN_REGISTRY_POOL_DATABASE', flush=True)

    def setUp(self):
        self.identity = self.new_identity()

    def new_identity(self, *, writer=True, reviewer=False):
        now = int(time.time())
        item = {
            'subject': 'registry-owner-' + uuid4().hex,
            'jti': 'registry-session-' + uuid4().hex,
            'principal_id': uuid4(),
            'actor_id': uuid4(),
            'source_id': uuid4(),
            'auth_version': 1,
            'iat': now - 3,
            'exp': now + 180,
            'session_exp': now + 120,
        }
        item['session_key'] = derive_session_key(ISSUER, item['jti'])
        with self.admin() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Registry pool fixture',clock_timestamp())",
                      (item['actor_id'],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                      (item['source_id'],))
            c.execute('''INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                VALUES(%s,%s,%s,%s,%s,true,%s,%s,1)''',
                (item['principal_id'], ISSUER, item['subject'], item['actor_id'], item['source_id'],
                 writer, reviewer))
            c.execute('''INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))''',
                (item['session_key'], item['principal_id'], item['iat'], item['session_exp']))
        return item

    def token(self, item=None, *, key=None, subject=None, jti=None, extra=None):
        item = item or self.identity
        claims = {
            'iss': ISSUER, 'aud': AUD,
            'sub': subject if subject is not None else item['subject'],
            'iat': item['iat'], 'nbf': item['iat'], 'exp': item['exp'],
            'jti': jti if jti is not None else item['jti'],
        }
        if extra:
            claims.update(extra)
        return jwt.encode(claims, key or self.key, algorithm='RS256',
                          headers={'kid': 'fixture-key', 'typ': 'at+jwt'})

    def bind(self, item=None, *, token=None, body=None):
        return self.boundary.bind('Bearer ' + (token or self.token(item)), body or draft())

    def assert_boundary_error(self, code, call):
        with self.assertRaises(BoundaryError) as ctx:
            call()
        self.assertEqual(ctx.exception.code, code)

    def test_01_valid_signed_identity_resolves_through_real_service_pool(self):
        result = self.bind()
        self.assertEqual(result.actor_id, self.identity['actor_id'])
        self.assertEqual(result.source_id, self.identity['source_id'])
        self.assertEqual(result.binding_revision, 1)
        self.assertFalse(result.ready_for_execution)
        self.assertIsNotNone(result.authorization_stamp)

    def test_02_real_service_password_login_is_required(self):
        with self.raw_service() as c:
            self.assertEqual(c.info.user, SERVICE)
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(),
                             (SERVICE, SERVICE))
        with self.assertRaises(psycopg.Error):
            self.raw_service(password='wrong-' + secrets.token_hex(12))

    def test_03_baseline_service_has_no_registry_data_or_function_access(self):
        with self.raw_service() as c:
            for statement in (
                'SELECT count(*) FROM echo_identity.principals',
                "SELECT echo_identity.lookup_session('x','y','" + ('0' * 64) + "')",
                "SELECT echo_identity.runtime_lookup_session('x','y','" + ('0' * 64) + "')",
                'SET ROLE echo_identity_registry_guard',
            ):
                with self.subTest(statement=statement):
                    with self.assertRaises(psycopg.Error):
                        c.execute(statement)
                    c.rollback()

    def test_04_runtime_can_execute_only_sealed_wrapper_not_direct_tables(self):
        with self.pool.connection() as c:
            snapshot = c.execute('SELECT echo_identity.runtime_lookup_session(%s,%s,%s)',
                (ISSUER, self.identity['subject'], self.identity['session_key'])).fetchone()[0]
            self.assertEqual(snapshot['principal']['principalId'], str(self.identity['principal_id']))
        with self.assertRaises(psycopg.Error):
            with self.pool.connection() as c:
                c.execute('SELECT count(*) FROM echo_identity.principals')
        with self.assertRaises(psycopg.Error):
            with self.pool.connection() as c:
                c.execute('SELECT echo_identity.lookup_session(%s,%s,%s)',
                          (ISSUER, self.identity['subject'], self.identity['session_key']))

    def test_05_invalid_signature_never_borrows_registry_connection(self):
        calls = {'count': 0}
        def counted_connect():
            calls['count'] += 1
            return self.pool.connection()
        adapter = ServicePostgresRegistryAdapter(counted_connect)
        boundary = Boundary(self.config, resolve_binding=adapter.resolve_binding)
        bad = self.token(key=self.wrong_key)
        with self.assertRaises(BoundaryError) as ctx:
            boundary.bind('Bearer ' + bad, draft())
        self.assertEqual(ctx.exception.code, 'IDENTITY_REJECTED')
        self.assertEqual(calls['count'], 0)

    def test_06_committed_session_revocation_denies_next_lookup(self):
        self.bind()
        with self.admin() as c:
            c.execute('UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s',
                      (self.identity['session_key'],))
        self.assert_boundary_error('IDENTITY_REJECTED', self.bind)

    def test_07_authority_generation_change_makes_old_session_stale(self):
        with self.admin() as c:
            c.execute('''UPDATE echo_identity.principals
                         SET enabled=false,auth_version=auth_version+1
                         WHERE principal_id=%s''', (self.identity['principal_id'],))
        self.assert_boundary_error('IDENTITY_REJECTED', self.bind)

    def test_08_signed_role_actor_source_hints_cannot_override_registry(self):
        result = self.bind(token=self.token(extra={
            'role': 'admin', 'scope': 'assessment:review',
            'actor_id': str(uuid4()), 'source_id': str(uuid4()),
            'principal_id': str(uuid4()),
        }))
        self.assertEqual(result.actor_id, self.identity['actor_id'])
        self.assertEqual(result.source_id, self.identity['source_id'])
        self.assert_boundary_error('CAPABILITY_REQUIRED',
            lambda: self.bind(token=self.token(extra={'role': 'reviewer'}), body=review()))

    def test_09_current_registry_reviewer_grant_requires_fresh_generation(self):
        new_jti = 'review-' + uuid4().hex
        now = int(time.time())
        with self.admin() as c:
            c.execute('''UPDATE echo_identity.principals
                         SET reviewer_enabled=true,auth_version=auth_version+1
                         WHERE principal_id=%s''', (self.identity['principal_id'],))
            c.execute('''INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,2,to_timestamp(%s),to_timestamp(%s))''',
                (derive_session_key(ISSUER, new_jti), self.identity['principal_id'],
                 now - 1, now + 120))
        fresh = dict(self.identity)
        fresh.update({'jti': new_jti, 'iat': now - 1, 'exp': now + 180})
        result = self.bind(fresh, token=self.token(fresh), body=review())
        self.assertEqual(result.binding_revision, 2)
        self.assertFalse(result.ready_for_execution)

    def test_10_successful_lease_reuse_clears_session_state(self):
        with self.pool.connection() as c:
            pid = c.execute('SELECT pg_backend_pid()').fetchone()[0]
            c.execute("SET LOCAL application_name='registry-leak-fixture'")
            c.execute('CREATE TEMP TABLE registry_pool_leak(x integer)')
            c.execute('PREPARE registry_pool_plan AS SELECT 1')
            c.execute('LISTEN registry_pool_channel')
            c.execute('SELECT pg_advisory_lock(920031)')
        with self.pool.connection() as c:
            self.assertEqual(c.execute('SELECT pg_backend_pid()').fetchone()[0], pid)
            self.assertNotEqual(c.execute("current_setting('application_name')").fetchone()[0],
                                'registry-leak-fixture')
            self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.registry_pool_leak')").fetchone()[0])
            self.assertEqual(c.execute('SELECT count(*) FROM pg_prepared_statements').fetchone()[0], 0)
            self.assertEqual(c.execute('SELECT count(*) FROM pg_listening_channels()').fetchone()[0], 0)
        with self.admin() as c:
            got = c.execute('SELECT pg_try_advisory_lock(920031)').fetchone()[0]
            self.assertTrue(got)
            c.execute('SELECT pg_advisory_unlock(920031)')

    def test_11_failed_transaction_is_rolled_back_before_reuse(self):
        with self.assertRaises(psycopg.errors.DivisionByZero):
            with self.pool.connection() as c:
                c.execute('SELECT 1/0')
        result = self.bind()
        self.assertEqual(result.actor_id, self.identity['actor_id'])

    def test_12_lease_role_tampering_is_detected_and_connection_recovers(self):
        with self.assertRaises(RegistryPoolError) as ctx:
            with self.pool.connection() as c:
                c.execute('RESET ROLE')
        self.assertEqual(ctx.exception.code, 'LEASE_ROLE_CHANGED')
        self.assertEqual(self.bind().actor_id, self.identity['actor_id'])

    def test_13_direct_table_privilege_drift_fails_closed(self):
        with self.admin() as c:
            c.execute(sql.SQL('GRANT SELECT ON echo_identity.principals TO {}').format(sql.Identifier(RUNTIME)))
        try:
            with self.assertRaises(RegistryPoolError) as ctx:
                with self.pool.connection():
                    pass
            self.assertEqual(ctx.exception.code, 'DIRECT_TABLE_PRIVILEGE_DRIFT')
        finally:
            with self.admin() as c:
                c.execute(sql.SQL('REVOKE SELECT ON echo_identity.principals FROM {}').format(sql.Identifier(RUNTIME)))
        self.assertEqual(self.bind().actor_id, self.identity['actor_id'])

    def test_14_extra_function_privilege_drift_fails_closed(self):
        with self.admin() as c:
            c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION echo_identity.lookup_session(text,text,text) TO {}').format(sql.Identifier(RUNTIME)))
        try:
            with self.assertRaises(RegistryPoolError) as ctx:
                with self.pool.connection():
                    pass
            self.assertEqual(ctx.exception.code, 'FUNCTION_PRIVILEGE_DRIFT')
        finally:
            with self.admin() as c:
                c.execute(sql.SQL('REVOKE EXECUTE ON FUNCTION echo_identity.lookup_session(text,text,text) FROM {}').format(sql.Identifier(RUNTIME)))
        self.assertEqual(self.bind().actor_id, self.identity['actor_id'])

    def test_15_membership_drift_that_could_reach_guard_fails_closed(self):
        with self.admin() as c:
            c.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(
                sql.Identifier(GUARD), sql.Identifier(SERVICE)))
        try:
            with self.assertRaises(RegistryPoolError) as ctx:
                with self.pool.connection():
                    pass
            self.assertEqual(ctx.exception.code, 'ROLE_MEMBERSHIP_DRIFT')
        finally:
            with self.admin() as c:
                c.execute(sql.SQL('REVOKE {} FROM {}').format(sql.Identifier(GUARD), sql.Identifier(SERVICE)))
        self.assertEqual(self.bind().actor_id, self.identity['actor_id'])

    def test_16_two_concurrent_signed_lookups_are_isolated(self):
        second = self.new_identity()
        pool = self.make_pool(max_size=2)
        pool.open()
        try:
            boundary = Boundary(self.config,
                resolve_binding=ServicePostgresRegistryAdapter(pool.connection).resolve_binding)
            def run(item):
                return boundary.bind('Bearer ' + self.token(item), draft()).actor_id
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(run, [self.identity, second]))
            self.assertEqual(results, [self.identity['actor_id'], second['actor_id']])
        finally:
            pool.close()

    def test_17_config_and_unknown_identity_fail_closed(self):
        with self.assertRaises(RegistryPoolError) as ctx:
            RegistryPool(host='127.0.0.1', port=int(os.environ.get('PGPORT', '5432')),
                         dbname=DB_NAME, user=SERVICE, password=self.password,
                         sslmode='disable')
        self.assertEqual(ctx.exception.code, 'VERIFIED_TLS_REQUIRED')
        unknown = 'missing-' + uuid4().hex
        self.assert_boundary_error('IDENTITY_REJECTED',
            lambda: self.bind(token=self.token(jti=unknown)))
        self.assert_boundary_error('IDENTITY_REJECTED',
            lambda: self.bind(token=self.token(subject=self.identity['subject'].upper())))

    def test_18_closed_registry_pool_is_backend_unavailable_not_identity_denial(self):
        self.pool.close()
        self.assert_boundary_error('IDENTITY_BACKEND_UNAVAILABLE', self.bind)


if __name__ == '__main__':
    unittest.main(verbosity=2)
