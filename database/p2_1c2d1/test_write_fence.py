"""P2.1c.2d.1: real PostgreSQL locks, commits, rollback and signed preflight.

Only a disposable PRIVATE probe table is written. This is not a news writer.
Race ordering is observed with pg_blocking_pids, not inferred from a lucky sleep.
Fixture stamp construction is trusted test code, NOT a production wire adapter.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import time
import unittest
from uuid import uuid4

import jwt
import psycopg
from psycopg import sql
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'backend/p2_1c2b1'), str(ROOT / 'backend/p2_1c2c3')]
from identity_boundary import Boundary, BoundaryError, Config
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key

ISSUER = 'https://issuer.fence.fixture.invalid/echo'
AUDIENCE = 'echo-fence-fixture'
FIELDS = ('issuer', 'subject', 'session_key', 'principal_id', 'actor_id', 'source_id',
          'auth_version', 'capability', 'issued_ms', 'not_before_ms', 'expires_ms')
FENCE_SQL = 'SELECT echo_identity.assert_private_draft_fence(' + ','.join(['%s'] * len(FIELDS)) + ')'
INSERT_SQL = ('INSERT INTO echo_fence_probe.attempts(attempt_id,' + ','.join(FIELDS) + ') '
              'VALUES (' + ','.join(['%s'] * (len(FIELDS) + 1)) + ')')
PROBE_SQL = '''
CREATE SCHEMA echo_fence_probe;
REVOKE ALL ON SCHEMA echo_fence_probe FROM PUBLIC;
CREATE TABLE echo_fence_probe.effects(effect_id uuid PRIMARY KEY);
CREATE TABLE echo_fence_probe.attempts(
  attempt_id uuid PRIMARY KEY,
  issuer text NOT NULL, subject text NOT NULL, session_key text NOT NULL,
  principal_id uuid NOT NULL, actor_id uuid NOT NULL, source_id uuid NOT NULL,
  auth_version integer NOT NULL, capability text NOT NULL,
  issued_ms bigint NOT NULL, not_before_ms bigint NOT NULL, expires_ms bigint NOT NULL,
  visibility text NOT NULL DEFAULT 'PRIVATE' CHECK (visibility = 'PRIVATE')
);
CREATE FUNCTION echo_fence_probe.check_attempt() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM echo_identity.assert_private_draft_fence(
    NEW.issuer,NEW.subject,NEW.session_key,NEW.principal_id,NEW.actor_id,NEW.source_id,
    NEW.auth_version,NEW.capability,NEW.issued_ms,NEW.not_before_ms,NEW.expires_ms);
  RETURN NEW;
END $$;
CREATE TRIGGER acquire_authority BEFORE INSERT ON echo_fence_probe.attempts
FOR EACH ROW EXECUTE FUNCTION echo_fence_probe.check_attempt();
CREATE CONSTRAINT TRIGGER recheck_authority AFTER INSERT ON echo_fence_probe.attempts
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION echo_fence_probe.check_attempt();
REVOKE ALL ON ALL TABLES IN SCHEMA echo_fence_probe FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_fence_probe FROM PUBLIC;
CREATE ROLE echo_fence_outsider NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT USAGE ON SCHEMA echo_identity TO echo_fence_outsider;
'''


class WriteFenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != 'echo_fence_test'
                or os.environ.get('PGHOST') not in ('127.0.0.1', 'localhost')):
            raise RuntimeError('refusing non-disposable or non-loopback database')
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUDIENCE, 'ephemeral-fence-v1', {'fixture': cls.key.public_key()})
        with cls.connect() as connection:
            version = int(connection.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('this gate must run on PostgreSQL 17')
            empty = connection.execute("SELECT to_regnamespace('echo_core') IS NULL AND "
                "to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_fence_probe') IS NULL").fetchone()[0]
            if not empty:
                raise RuntimeError('refusing existing schemas')
            for path in ('database/p2_1b/schema.sql', 'database/p2_1c2c/001_identity_registry.sql',
                         'database/p2_1c2d1/001_write_fence.sql'):
                connection.execute((ROOT / path).read_text())
            connection.execute(PROBE_SQL)
        cls.addClassCleanup(cls.cleanup_database)
        cls.boundary = Boundary(cls.config, resolve_binding=PostgresRegistryAdapter(cls.connect).resolve_binding)

    @staticmethod
    def connect():
        return psycopg.connect(connect_timeout=3,
            options='-c statement_timeout=12000 -c lock_timeout=8000 -c idle_in_transaction_session_timeout=20000')

    @classmethod
    def cleanup_database(cls):
        with cls.connect() as c:
            c.execute('DROP SCHEMA echo_fence_probe CASCADE; DROP SCHEMA echo_identity CASCADE; '
                      'DROP SCHEMA echo_core CASCADE; DROP ROLE echo_fence_outsider;')
        with cls.connect() as c:
            clean = c.execute("SELECT to_regnamespace('echo_core') IS NULL AND "
                "to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_fence_probe') IS NULL "
                "AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname='echo_fence_outsider')").fetchone()[0]
            if not clean:
                raise AssertionError('fixture cleanup incomplete')
        print('CLEAN_WRITE_FENCE_DATABASE', flush=True)

    def db(self, statement, parameters=()):
        with self.connect() as c:
            cursor = c.execute(statement, parameters)
            return cursor.fetchone() if cursor.description else None

    def setUp(self):
        self.fixture = self.make_fixture()
        self.stamp = self.fixture['stamp']

    def make_fixture(self):
        now_sec = int(self.db('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')[0])
        f = dict(principal_id=uuid4(), actor_id=uuid4(), source_id=uuid4(),
                 subject='user-' + uuid4().hex, jti='jti-' + uuid4().hex,
                 iat=now_sec - 5, exp=now_sec + 300)
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Fence synthetic actor',clock_timestamp())", (f['actor_id'],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())", (f['source_id'],))
            c.execute('''INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled)
                VALUES(%s,%s,%s,%s,%s,true,true,true)''',
                (f['principal_id'], ISSUER, f['subject'], f['actor_id'], f['source_id']))
            c.execute('''INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))''',
                (derive_session_key(ISSUER, f['jti']), f['principal_id'], f['iat'], f['exp']))
        f['stamp'] = self.signed_stamp(f)
        return f

    def signed_stamp(self, f, *, exp=None, jti=None):
        jti = f['jti'] if jti is None else jti
        token = jwt.encode(dict(iss=ISSUER, aud=AUDIENCE, sub=f['subject'], jti=jti,
            iat=f['iat'], nbf=f['iat'], exp=f['exp'] if exp is None else exp), self.key,
            algorithm='RS256', headers={'kid': 'fixture', 'typ': 'at+jwt'})
        body = json.dumps(dict(request_id=str(uuid4()), command='CREATE_VOICE_DRAFT',
                               payload={'text': 'synthetic fence probe'})).encode()
        intent = self.boundary.bind('Bearer ' + token, body)
        self.assertFalse(intent.ready_for_execution)
        self.assertEqual(intent.actor_id, f['actor_id'])
        self.assertEqual(intent.source_id, f['source_id'])
        # Test-owned provisioning binds the remaining tuple; NOT client JSON.
        return dict(issuer=ISSUER, subject=f['subject'], session_key=derive_session_key(ISSUER, jti),
                    principal_id=f['principal_id'], actor_id=intent.actor_id, source_id=intent.source_id,
                    auth_version=intent.binding_revision, capability='voice:draft:create',
                    issued_ms=intent.issued_at * 1000, not_before_ms=intent.issued_at * 1000,
                    expires_ms=intent.expires_at * 1000)

    def insert_probe(self, c, stamp, attempt_id):
        # Deliberate earlier side effect must also roll back on later denial.
        c.execute('INSERT INTO echo_fence_probe.effects VALUES(%s)', (attempt_id,))
        c.execute(INSERT_SQL, (attempt_id,) + tuple(stamp[k] for k in FIELDS))

    def final_check(self, c, stamp):
        c.execute(FENCE_SQL, tuple(stamp[k] for k in FIELDS))

    def attempt(self, stamp=None, connection=None):
        stamp = self.stamp if stamp is None else stamp
        c = self.connect() if connection is None else connection
        attempt_id = uuid4()
        try:
            self.insert_probe(c, stamp, attempt_id)
            self.final_check(c, stamp)
            c.commit()
            return ('COMMITTED', None, attempt_id)
        except psycopg.Error as error:
            c.rollback()
            return ('DENIED', error.sqlstate, attempt_id)
        finally:
            c.close()

    def assert_count(self, attempt_id, expected):
        for table, column in (('attempts', 'attempt_id'), ('effects', 'effect_id')):
            count = self.db(sql.SQL('SELECT count(*) FROM echo_fence_probe.{} WHERE {}=%s').format(
                sql.Identifier(table), sql.Identifier(column)), (attempt_id,))[0]
            self.assertEqual(count, expected)

    def denied_attempt(self, stamp=None, code='42501', connection=None):
        outcome = self.attempt(stamp, connection)
        self.assertEqual(outcome[:2], ('DENIED', code))
        self.assert_count(outcome[2], 0)
        return outcome

    def mutate(self, c, mode, f=None):
        f = self.fixture if f is None else f
        if mode == 'revoke':
            c.execute('UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s',
                      (f['stamp']['session_key'],))
        else:
            assignment = {'disable': 'enabled=false', 'remove_writer': 'writer_enabled=false',
                          'version': 'auth_version=auth_version'}[mode]
            # The version-only case avoids assigning auth_version twice.
            setting = 'auth_version=auth_version+1' if mode == 'version' else assignment + ',auth_version=auth_version+1'
            c.execute('UPDATE echo_identity.principals SET ' + setting + ' WHERE principal_id=%s', (f['principal_id'],))

    def committed_mutation(self, mode):
        with self.connect() as c:
            self.mutate(c, mode)

    def wait_blocked(self, waiter_pid, holder_pid):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.db('SELECT %s = ANY(pg_blocking_pids(%s))', (holder_pid, waiter_pid))[0]:
                return
            time.sleep(0.01)  # Poll observed lock state; never assume sleep establishes ordering.
        self.fail('expected database lock wait was not observed')

    def mutation_first(self, mode, rollback=False):
        holder, waiter = self.connect(), self.connect()
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            self.mutate(holder, mode)
            future = pool.submit(self.attempt, self.stamp, waiter)
            self.wait_blocked(waiter.info.backend_pid, holder.info.backend_pid)
            holder.rollback() if rollback else holder.commit()
            outcome = future.result(timeout=10)
            expected = ('COMMITTED', None) if rollback else ('DENIED', '42501')
            self.assertEqual(outcome[:2], expected)
            self.assert_count(outcome[2], int(rollback))
            print('RACE_OBSERVED mutation_first ' + mode + (' ROLLBACK' if rollback else ' COMMIT'), flush=True)
        finally:
            holder.rollback()
            holder.close()
            pool.shutdown(wait=True)
            if not waiter.closed:
                waiter.close()

    def writer_first(self, mode, rollback=False):
        writer, revoker = self.connect(), self.connect()
        attempt_id = uuid4()
        pool = ThreadPoolExecutor(max_workers=1)
        def revoke():
            try:
                self.mutate(revoker, mode)
                revoker.commit()
            finally:
                revoker.close()
        try:
            self.insert_probe(writer, self.stamp, attempt_id)
            self.assert_count(attempt_id, 0)  # uncommitted probe invisible on another connection
            future = pool.submit(revoke)
            self.wait_blocked(revoker.info.backend_pid, writer.info.backend_pid)
            if rollback:
                writer.rollback()
            else:
                self.final_check(writer, self.stamp)
                writer.commit()
            future.result(timeout=10)
            self.assert_count(attempt_id, 0 if rollback else 1)
            self.denied_attempt()  # next transaction sees committed removal
            print('RACE_OBSERVED writer_first ' + mode + (' ROLLBACK' if rollback else ' COMMIT'), flush=True)
        finally:
            writer.rollback()
            writer.close()
            pool.shutdown(wait=True)
            if not revoker.closed:
                revoker.close()

    def short_token_stamp(self):
        exp = int(self.db('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')[0]) + 3
        return self.signed_stamp(self.fixture, exp=exp)

    def wait_expired(self, expires_ms):
        self.db('SELECT pg_sleep(GREATEST(0, %s/1000.0 - extract(epoch FROM clock_timestamp()) + 0.03))', (expires_ms,))

    def test_01_valid_private_probe_commits_with_real_signed_preflight(self):
        result = self.attempt()
        self.assertEqual(result[:2], ('COMMITTED', None))
        self.assert_count(result[2], 1)
        self.assertEqual(self.db('SELECT visibility FROM echo_fence_probe.attempts WHERE attempt_id=%s', (result[2],))[0], 'PRIVATE')

    def test_02_committed_revoke_invalidates_preflight(self):
        self.committed_mutation('revoke')
        self.denied_attempt()

    def test_03_disable_invalidates_preflight(self):
        self.committed_mutation('disable')
        self.denied_attempt()

    def test_04_stale_auth_version_denied(self):
        self.committed_mutation('version')
        self.denied_attempt()

    def test_05_removed_writer_denies_old_and_current_generation(self):
        self.committed_mutation('remove_writer')
        self.denied_attempt()
        fresh_jti = 'fresh-' + uuid4().hex
        self.db('''INSERT INTO echo_identity.sessions VALUES(%s,%s,2,to_timestamp(%s),to_timestamp(%s),false)''',
            (derive_session_key(ISSUER, fresh_jti), self.fixture['principal_id'], self.fixture['iat'], self.fixture['exp']))
        with self.assertRaises(BoundaryError) as caught:
            self.signed_stamp(self.fixture, jti=fresh_jti)
        self.assertEqual(caught.exception.code, 'CAPABILITY_REQUIRED')
        self.denied_attempt({**self.stamp, 'auth_version': 2, 'session_key': derive_session_key(ISSUER, fresh_jti)})

    def test_06_identity_tuple_cannot_be_retargeted(self):
        for field, value in dict(issuer=ISSUER + '/', subject=self.stamp['subject'].upper(),
                principal_id=uuid4(), actor_id=uuid4(), source_id=uuid4(),
                session_key='f' * 64, auth_version=2).items():
            with self.subTest(field=field):
                self.denied_attempt({**self.stamp, field: value})

    def test_07_null_in_every_fence_field_denies_instead_of_strict_skip(self):
        for field in FIELDS:
            with self.subTest(field=field):
                self.denied_attempt({**self.stamp, field: None})

    def test_08_publish_and_review_capabilities_are_not_draft_authority(self):
        for capability in ('writer', 'voice:publish', 'assessment:review', ''):
            with self.subTest(capability=capability):
                self.denied_attempt({**self.stamp, 'capability': capability})
        # Reviewer flag is true in the DB; it still cannot bypass this PRIVATE-only gate.

    def test_09_invalid_or_expired_credential_windows_deny(self):
        now = int(time.time() * 1000)
        cases = [dict(expires_ms=now-1), dict(not_before_ms=now+30000),
                 dict(issued_ms=-1), dict(expires_ms=9007199254740992),
                 dict(issued_ms=self.stamp['not_before_ms']+1), dict(expires_ms=self.stamp['issued_ms'])]
        for patch in cases:
            with self.subTest(patch=patch):
                self.denied_attempt({**self.stamp, **patch})

    def test_10_local_session_expiry_before_commit_rolls_back(self):
        exp = int(self.db('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')[0]) + 3
        jti = 'short-local-' + uuid4().hex
        self.db('INSERT INTO echo_identity.sessions VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s),false)',
            (derive_session_key(ISSUER, jti), self.fixture['principal_id'], self.fixture['iat'], exp))
        stamp = self.signed_stamp(self.fixture, jti=jti)
        c, attempt_id = self.connect(), uuid4()
        try:
            self.insert_probe(c, stamp, attempt_id)
            self.wait_expired(exp * 1000)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.commit()  # default deferred recheck sees elapsed local lifetime
            c.rollback()
            self.assert_count(attempt_id, 0)
        finally:
            c.close()

    def test_11_token_expiry_after_insert_is_rechecked_at_commit(self):
        stamp = self.short_token_stamp()
        c, attempt_id = self.connect(), uuid4()
        try:
            self.insert_probe(c, stamp, attempt_id)
            self.wait_expired(stamp['expires_ms'])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.commit()
            c.rollback()
            self.assert_count(attempt_id, 0)
        finally:
            c.close()

    def test_12_expiry_while_waiting_for_lock_denies_after_wakeup(self):
        stamp = self.short_token_stamp()
        holder, waiter = self.connect(), self.connect()
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            holder.execute('SELECT principal_id FROM echo_identity.principals WHERE principal_id=%s FOR UPDATE', (self.stamp['principal_id'],))
            future = pool.submit(self.attempt, stamp, waiter)
            self.wait_blocked(waiter.info.backend_pid, holder.info.backend_pid)
            self.wait_expired(stamp['expires_ms'])
            holder.rollback()
            result = future.result(timeout=10)
            self.assertEqual(result[:2], ('DENIED', '42501'))
            self.assert_count(result[2], 0)
            print('RACE_OBSERVED token_expired_during_lock_wait', flush=True)
        finally:
            holder.rollback()
            holder.close()
            pool.shutdown(wait=True)
            if not waiter.closed:
                waiter.close()

    def test_13_revoke_first_blocks_then_denies_writer(self):
        self.mutation_first('revoke')

    def test_14_disable_first_blocks_then_denies_writer(self):
        self.mutation_first('disable')

    def test_15_role_removal_first_blocks_then_denies_writer(self):
        self.mutation_first('remove_writer')

    def test_16_writer_first_holds_session_until_commit(self):
        self.writer_first('revoke')

    def test_17_writer_first_holds_principal_until_commit(self):
        self.writer_first('disable')

    def test_18_writer_first_blocks_role_removal_until_commit(self):
        self.writer_first('remove_writer')

    def test_19_rolled_back_revoke_does_not_cancel_valid_writer(self):
        self.mutation_first('revoke', rollback=True)

    def test_20_lock_timeout_fails_closed_and_rolls_back_prior_effect(self):
        holder, waiter = self.connect(), self.connect()
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            self.mutate(holder, 'revoke')
            waiter.execute("SET lock_timeout='200ms'")
            future = pool.submit(self.attempt, self.stamp, waiter)
            result = future.result(timeout=5)
            self.assertEqual(result[:2], ('DENIED', '55P03'))
            self.assert_count(result[2], 0)
        finally:
            holder.rollback()
            holder.close()
            pool.shutdown(wait=True)
            if not waiter.closed:
                waiter.close()

    def test_21_same_transaction_revoke_fails_final_recheck(self):
        c, attempt_id = self.connect(), uuid4()
        try:
            self.insert_probe(c, self.stamp, attempt_id)
            self.mutate(c, 'revoke')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.commit()
            c.rollback()
            self.assert_count(attempt_id, 0)
            # Whole transaction rolled back: the revocation itself also vanished.
            self.assertEqual(self.attempt()[:2], ('COMMITTED', None))
        finally:
            c.close()

    def test_22_same_transaction_role_update_fails_final_recheck(self):
        c, attempt_id = self.connect(), uuid4()
        try:
            self.insert_probe(c, self.stamp, attempt_id)
            self.mutate(c, 'remove_writer')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.commit()
            c.rollback()
            self.assert_count(attempt_id, 0)
        finally:
            c.close()

    def test_23_unrelated_principal_is_not_globally_blocked(self):
        other = self.make_fixture()
        writer, modifier = self.connect(), self.connect()
        attempt_id = uuid4()
        try:
            self.insert_probe(writer, self.stamp, attempt_id)
            modifier.execute("SET lock_timeout='200ms'")
            self.mutate(modifier, 'disable', other)
            modifier.commit()
            self.final_check(writer, self.stamp)
            writer.commit()
            self.assert_count(attempt_id, 1)
        finally:
            writer.close()
            modifier.close()

    def test_24_other_isolation_levels_fail_closed(self):
        for isolation in ('REPEATABLE READ', 'SERIALIZABLE'):
            with self.subTest(isolation=isolation):
                c = self.connect()
                c.execute('SET TRANSACTION ISOLATION LEVEL ' + isolation)
                self.denied_attempt(code='25001', connection=c)

    def test_25_outsider_has_no_execute_authority(self):
        with self.connect() as c:
            c.execute('SET ROLE echo_fence_outsider')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.final_check(c, self.stamp)
            c.rollback()

    def test_26_no_news_rows_are_written_by_fence_probe(self):
        with self.connect() as c:
            tables = c.execute("SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='echo_core' AND table_type='BASE TABLE' AND table_name NOT IN ('actors','sources')").fetchall()
            self.assertGreater(len(tables), 0)
            for (table,) in tables:
                count = c.execute(sql.SQL('SELECT count(*) FROM echo_core.{}').format(sql.Identifier(table))).fetchone()[0]
                self.assertEqual(count, 0, table)

    def test_27_early_constraint_flush_does_not_replace_explicit_final_check(self):
        stamp = self.short_token_stamp()
        c, attempt_id = self.connect(), uuid4()
        try:
            self.insert_probe(c, stamp, attempt_id)
            c.execute('SET CONSTRAINTS ALL IMMEDIATE')
            self.wait_expired(stamp['expires_ms'])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.final_check(c, stamp)
            c.rollback()
            self.assert_count(attempt_id, 0)
        finally:
            c.close()

    def test_28_writer_rollback_releases_lock_without_partial_write(self):
        self.writer_first('revoke', rollback=True)

    def test_29_session_of_another_principal_is_not_reusable(self):
        other = self.make_fixture()
        self.denied_attempt({**self.stamp, 'session_key': other['stamp']['session_key']})


if __name__ == '__main__':
    unittest.main(verbosity=2)
