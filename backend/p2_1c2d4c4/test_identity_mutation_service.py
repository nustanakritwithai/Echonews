from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import secrets
import sys
import time
import unittest
from uuid import UUID, uuid4

import psycopg
from psycopg import sql

sys.path.insert(0, os.path.dirname(__file__))

from identity_mutation_service import IdentityMutationError, IdentityMutationService
from mutation_pool import GUARD, RUNTIME, SERVICE, MutationPool, MutationPoolError

DB_NAME = 'echo_identity_mutation_test'
REGISTRY_SERVICE = 'echo_identity_registry_service'
REGISTRY_RUNTIME = 'echo_identity_registry_runtime'


class IdentityMutationServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != DB_NAME
                or os.environ.get('PGHOST') not in ('127.0.0.1', 'localhost')):
            raise RuntimeError('refusing non-disposable identity mutation database')
        with cls.admin() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('identity mutation gate requires PostgreSQL 17')
            present = c.execute('''SELECT to_regrole(%s) IS NOT NULL
                AND to_regrole(%s) IS NOT NULL AND to_regrole(%s) IS NOT NULL
                AND to_regprocedure('echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)') IS NOT NULL
                AND to_regprocedure('echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)') IS NOT NULL
                AND to_regprocedure('echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)') IS NOT NULL
                AND to_regprocedure('echo_identity.runtime_revoke_session(text,uuid)') IS NOT NULL''',
                (SERVICE, RUNTIME, GUARD)).fetchone()[0]
            if not present:
                raise RuntimeError('identity mutation service migration not installed')

        cls.password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            statement = sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(SERVICE), sql.Literal(cls.password))
            c.execute(statement)
        with cls.assertRaisesStatic(psycopg.Error):
            cls.raw_service(password='wrong-' + secrets.token_hex(12))

        cls.pool = cls.make_pool(max_size=1)
        cls.pool.open()
        cls.service = IdentityMutationService(cls.pool.connection)
        cls.addClassCleanup(cls.cleanup)

    @classmethod
    def assertRaisesStatic(cls, exc):
        class _Raises:
            def __enter__(self): return None
            def __exit__(self, typ, value, tb):
                if typ is None: raise AssertionError(f'{exc.__name__} not raised')
                return issubclass(typ, exc)
        return _Raises()

    @staticmethod
    def admin():
        return psycopg.connect(connect_timeout=3)

    @classmethod
    def raw_service(cls, *, password=None):
        return psycopg.connect(host='127.0.0.1', port=int(os.environ.get('PGPORT', '5432')),
            dbname=DB_NAME, user=SERVICE, password=password or cls.password,
            sslmode='disable', connect_timeout=3, autocommit=True, prepare_threshold=None)

    @classmethod
    def make_pool(cls, *, max_size=1):
        return MutationPool(host='127.0.0.1', port=int(os.environ.get('PGPORT', '5432')),
            dbname=DB_NAME, user=SERVICE, password=cls.password, sslmode='disable',
            max_size=max_size, allow_insecure_test_loopback=True)

    @classmethod
    def cleanup(cls):
        try: cls.pool.close()
        except Exception: pass
        with cls.admin() as c:
            c.execute('DROP SCHEMA echo_identity CASCADE')
            c.execute('DROP SCHEMA echo_core CASCADE')
            for role in (SERVICE, RUNTIME, GUARD, 'echo_identity_registry_service',
                         'echo_identity_registry_runtime', 'echo_identity_registry_guard'):
                if c.execute('SELECT to_regrole(%s) IS NOT NULL', (role,)).fetchone()[0]:
                    c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
        print('CLEAN_IDENTITY_MUTATION_DATABASE', flush=True)

    def actor_source(self):
        actor_id = uuid4(); source_id = uuid4()
        with self.admin() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN',%s,clock_timestamp())",
                      (actor_id, 'mutation fixture ' + actor_id.hex[:8]))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())", (source_id,))
        return actor_id, source_id

    def principal_fixture(self):
        actor_id, source_id = self.actor_source()
        return (uuid4(), 'https://issuer.mutation.fixture.invalid/' + uuid4().hex,
                'subject-' + uuid4().hex, actor_id, source_id)

    def provision(self):
        data = self.principal_fixture()
        result = self.service.provision_principal(principal_id=data[0], issuer=data[1], subject=data[2],
                                                  actor_id=data[3], source_id=data[4])
        return data, result

    def enable(self, *, writer=True):
        data, initial = self.provision()
        result = self.service.change_authority(principal_id=data[0], expected_auth_version=initial.auth_version,
                                               enabled=True, writer_enabled=writer)
        return data, result

    @staticmethod
    def session_key():
        return hashlib.sha256(uuid4().bytes + uuid4().bytes).hexdigest()

    @staticmethod
    def session_times():
        now = int(time.time() * 1000)
        return now - 1000, now + 120_000

    def assert_mutation_rejected(self, fn):
        with self.assertRaises(IdentityMutationError) as ctx: fn()
        self.assertEqual(ctx.exception.code, 'IDENTITY_MUTATION_REJECTED')

    def test_01_real_service_login_and_cross_service_membership_are_isolated(self):
        with self.raw_service() as c:
            self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(), (SERVICE, SERVICE))
        with self.admin() as c:
            self.assertTrue(c.execute("SELECT pg_has_role(%s,%s,'SET')", (SERVICE, RUNTIME)).fetchone()[0])
            self.assertFalse(c.execute("SELECT pg_has_role(%s,%s,'SET')", (SERVICE, REGISTRY_RUNTIME)).fetchone()[0])
            self.assertFalse(c.execute("SELECT pg_has_role(%s,%s,'SET')", (REGISTRY_SERVICE, RUNTIME)).fetchone()[0])

    def test_02_provision_principal_is_disabled_and_powerless(self):
        data, result = self.provision()
        self.assertEqual(result.principal_id, data[0])
        self.assertEqual((result.enabled, result.writer_enabled, result.reviewer_enabled, result.auth_version),
                         (False, False, False, 1))

    def test_03_exact_provision_retry_returns_same_binding_without_duplicate(self):
        data, first = self.provision()
        second = self.service.provision_principal(principal_id=data[0], issuer=data[1], subject=data[2],
                                                  actor_id=data[3], source_id=data[4])
        self.assertEqual(first, second)
        with self.admin() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM echo_identity.principals WHERE principal_id=%s',
                                       (data[0],)).fetchone()[0], 1)

    def test_04_conflicting_provision_retry_fails_closed(self):
        data, _ = self.provision(); _a, other_source = self.actor_source()
        self.assert_mutation_rejected(lambda: self.service.provision_principal(
            principal_id=data[0], issuer=data[1], subject=data[2], actor_id=data[3], source_id=other_source))

    def test_05_authority_change_and_exact_retry_advance_generation_once(self):
        data, _ = self.provision()
        first = self.service.change_authority(principal_id=data[0], expected_auth_version=1,
                                              enabled=True, writer_enabled=True)
        second = self.service.change_authority(principal_id=data[0], expected_auth_version=1,
                                               enabled=True, writer_enabled=True)
        self.assertEqual(first.auth_version, 2); self.assertEqual(first, second)
        self.assertTrue(first.enabled and first.writer_enabled); self.assertFalse(first.reviewer_enabled)

    def test_06_authority_noop_does_not_bump_generation(self):
        data, initial = self.provision()
        same = self.service.change_authority(principal_id=data[0], expected_auth_version=1,
                                             enabled=False, writer_enabled=False)
        self.assertEqual((initial.auth_version, same.auth_version), (1, 1))

    def test_07_stale_authority_generation_is_rejected(self):
        data, enabled = self.enable(writer=True); self.assertEqual(enabled.auth_version, 2)
        self.assert_mutation_rejected(lambda: self.service.change_authority(
            principal_id=data[0], expected_auth_version=1, enabled=False, writer_enabled=False))

    def test_08_reviewer_authority_remains_out_of_scope(self):
        data, _ = self.provision()
        with self.admin() as c:
            c.execute('UPDATE echo_identity.principals SET reviewer_enabled=true, auth_version=auth_version+1 WHERE principal_id=%s', (data[0],))
        self.assert_mutation_rejected(lambda: self.service.change_authority(
            principal_id=data[0], expected_auth_version=2, enabled=True, writer_enabled=False))
        self.assertNotIn('reviewer_enabled', self.service.change_authority.__annotations__)

    def test_09_create_session_only_at_current_enabled_generation(self):
        data, authority = self.enable(writer=True); issued, expires = self.session_times(); key = self.session_key()
        result = self.service.create_session(session_key=key, principal_id=data[0], auth_version=authority.auth_version,
                                             issued_at_ms=issued, expires_at_ms=expires)
        self.assertEqual((result.session_key, result.principal_id, result.auth_version, result.revoked),
                         (key, data[0], 2, False))
        self.assertEqual((result.issued_at_ms, result.expires_at_ms), (issued, expires))

    def test_10_stale_or_disabled_session_generation_is_rejected(self):
        data, _ = self.provision(); issued, expires = self.session_times(); key = self.session_key()
        self.assert_mutation_rejected(lambda: self.service.create_session(session_key=key, principal_id=data[0],
            auth_version=1, issued_at_ms=issued, expires_at_ms=expires))
        authority = self.service.change_authority(principal_id=data[0], expected_auth_version=1,
                                                  enabled=True, writer_enabled=False)
        self.assert_mutation_rejected(lambda: self.service.create_session(session_key=key, principal_id=data[0],
            auth_version=1, issued_at_ms=issued, expires_at_ms=expires))
        self.assertEqual(authority.auth_version, 2)

    def test_11_session_exact_retry_is_idempotent_but_conflict_rejects(self):
        data, authority = self.enable(writer=False); issued, expires = self.session_times(); key = self.session_key()
        first = self.service.create_session(session_key=key, principal_id=data[0], auth_version=authority.auth_version,
                                            issued_at_ms=issued, expires_at_ms=expires)
        second = self.service.create_session(session_key=key, principal_id=data[0], auth_version=authority.auth_version,
                                             issued_at_ms=issued, expires_at_ms=expires)
        self.assertEqual(first, second)
        self.assert_mutation_rejected(lambda: self.service.create_session(session_key=key, principal_id=data[0],
            auth_version=authority.auth_version, issued_at_ms=issued, expires_at_ms=expires + 1000))

    def test_12_revoke_session_is_idempotent_and_principal_bound(self):
        data, _ = self.enable(writer=False); issued, expires = self.session_times(); key = self.session_key()
        self.service.create_session(session_key=key, principal_id=data[0], auth_version=2,
                                    issued_at_ms=issued, expires_at_ms=expires)
        first = self.service.revoke_session(session_key=key, principal_id=data[0])
        second = self.service.revoke_session(session_key=key, principal_id=data[0])
        self.assertTrue(first.revoked and second.revoked)
        self.assert_mutation_rejected(lambda: self.service.revoke_session(session_key=key, principal_id=uuid4()))

    def test_13_authority_generation_change_stales_existing_session_without_retargeting(self):
        data, _ = self.enable(writer=True); issued, expires = self.session_times(); key = self.session_key()
        self.service.create_session(session_key=key, principal_id=data[0], auth_version=2,
                                    issued_at_ms=issued, expires_at_ms=expires)
        changed = self.service.change_authority(principal_id=data[0], expected_auth_version=2,
                                                enabled=True, writer_enabled=False)
        self.assertEqual(changed.auth_version, 3)
        with self.admin() as c:
            row = c.execute('SELECT p.auth_version,s.auth_version,s.revoked FROM echo_identity.principals p JOIN echo_identity.sessions s USING(principal_id) WHERE s.session_key=%s', (key,)).fetchone()
        self.assertEqual(row, (3, 2, False))

    def test_14_service_and_runtime_have_no_direct_registry_table_access(self):
        with self.raw_service() as c:
            with self.assertRaises(psycopg.Error): c.execute('SELECT * FROM echo_identity.principals')
        with self.raw_service() as c:
            c.execute('BEGIN'); c.execute('SET LOCAL ROLE echo_identity_mutation_runtime')
            with self.assertRaises(psycopg.Error): c.execute('SELECT * FROM echo_identity.sessions')
            c.rollback()

    def test_15_pool_reuse_discards_session_state(self):
        lock_key = 90210404
        with self.pool.connection() as c:
            pid = c.execute('SELECT pg_backend_pid()').fetchone()[0]
            c.execute("SET LOCAL application_name='dirty-mutation-lease'")
            c.execute('CREATE TEMP TABLE mutation_dirty(x integer)')
            c.execute('PREPARE mutation_dirty_plan AS SELECT 1')
            c.execute('LISTEN mutation_dirty_channel')
            c.execute('SELECT pg_advisory_lock(%s)', (lock_key,))
        with self.pool.connection() as c:
            self.assertEqual(c.execute('SELECT pg_backend_pid()').fetchone()[0], pid)
            self.assertIsNone(c.execute("SELECT to_regclass('pg_temp.mutation_dirty')").fetchone()[0])
            self.assertEqual(c.execute("SELECT current_setting('application_name')").fetchone()[0], '')
            self.assertEqual(c.execute('SELECT count(*) FROM pg_prepared_statements').fetchone()[0], 0)
            self.assertEqual(c.execute('SELECT count(*) FROM pg_listening_channels()').fetchone()[0], 0)
            self.assertTrue(c.execute('SELECT pg_try_advisory_lock(%s)', (lock_key,)).fetchone()[0])
            c.execute('SELECT pg_advisory_unlock(%s)', (lock_key,))

    def test_16_failed_transaction_is_rolled_back_before_reuse(self):
        with self.assertRaises(psycopg.Error):
            with self.pool.connection() as c: c.execute('SELECT 1/0')
        data, result = self.provision(); self.assertEqual((result.principal_id, result.auth_version), (data[0], 1))

    def test_17_privilege_drift_fails_closed_then_recovers_after_revoke(self):
        with self.admin() as c:
            c.execute(sql.SQL('GRANT SELECT ON echo_identity.principals TO {}').format(sql.Identifier(RUNTIME)))
        try:
            with self.assertRaises(MutationPoolError) as ctx:
                with self.pool.connection(): pass
            self.assertEqual(ctx.exception.code, 'DIRECT_TABLE_PRIVILEGE_DRIFT')
        finally:
            with self.admin() as c:
                c.execute(sql.SQL('REVOKE SELECT ON echo_identity.principals FROM {}').format(sql.Identifier(RUNTIME)))
        data, result = self.provision(); self.assertEqual(result.principal_id, data[0])

    def test_18_two_concurrent_borrowers_do_not_share_transaction_identity(self):
        pool = self.make_pool(max_size=2); pool.open(); service = IdentityMutationService(pool.connection)
        fixtures = [self.principal_fixture(), self.principal_fixture()]
        def work(data):
            return service.provision_principal(principal_id=data[0], issuer=data[1], subject=data[2],
                                               actor_id=data[3], source_id=data[4]).principal_id
        try:
            with ThreadPoolExecutor(max_workers=2) as ex: got = list(ex.map(work, fixtures))
            self.assertEqual(set(got), {fixtures[0][0], fixtures[1][0]})
        finally: pool.close()

    def test_19_unknown_postcommit_pool_reset_never_autoreplays_and_exact_retry_is_safe(self):
        data = self.principal_fixture(); original = self.pool._sanitize; calls = {'n': 0}
        def injected(c):
            calls['n'] += 1
            if calls['n'] == 2: raise MutationPoolError('INJECTED_POSTCOMMIT_RESET_FAILURE')
            return original(c)
        self.pool._sanitize = injected
        try:
            self.assert_mutation_rejected(lambda: self.service.provision_principal(
                principal_id=data[0], issuer=data[1], subject=data[2], actor_id=data[3], source_id=data[4]))
        finally: self.pool._sanitize = original
        result = self.service.provision_principal(principal_id=data[0], issuer=data[1], subject=data[2],
                                                  actor_id=data[3], source_id=data[4])
        self.assertEqual(result.principal_id, data[0])
        with self.admin() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM echo_identity.principals WHERE principal_id=%s',
                                       (data[0],)).fetchone()[0], 1)

    def test_20_adapter_rejects_invalid_shape_and_has_no_reviewer_grant_argument(self):
        with self.assertRaises(IdentityMutationError) as ctx:
            self.service.change_authority(principal_id=UUID(int=0), expected_auth_version=1,
                                          enabled=True, writer_enabled=True)
        self.assertEqual(ctx.exception.code, 'INVALID_IDENTITY_MUTATION')
        with self.assertRaises(TypeError):
            self.service.change_authority(principal_id=uuid4(), expected_auth_version=1,
                                          enabled=True, writer_enabled=True, reviewer_enabled=True)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(IdentityMutationServiceTests))
    if result.wasSuccessful(): print('P2_1C2D4C4_IDENTITY_MUTATION_SUITE_SAT', flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
