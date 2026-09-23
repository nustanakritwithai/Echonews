"""P2.1c.2d.2a — real PostgreSQL least-privilege / no-bypass role checks.

This suite deliberately does NOT write Echo Voice rows. It proves that the runtime
role can invoke only the narrow fence wrapper and cannot read/mutate authority or
core history directly. Fence parameters are trusted synthetic fixture values here;
server-stamp propagation is the next gate, not silently claimed by this test.
"""
from __future__ import annotations

import os
from pathlib import Path
import unittest
from uuid import uuid4

import psycopg

ROOT = Path(__file__).resolve().parents[2]
DB_NAME = 'echo_runtime_role_test'
RUNTIME = 'echo_private_draft_runtime'
GUARD = 'echo_private_draft_guard'
OUTSIDER = 'echo_private_draft_outsider'
FENCE_SIG = ('echo_identity.assert_private_draft_fence('
             'text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)')
WRAPPER_SIG = ('echo_identity.runtime_private_draft_fence('
               'text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)')
CALL = 'SELECT ' + WRAPPER_SIG.split('(')[0] + '(' + ','.join(['%s'] * 11) + ')'
FIELDS = ('issuer','subject','session_key','principal_id','actor_id','source_id',
          'auth_version','capability','issued_ms','not_before_ms','expires_ms')


class RuntimeRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != DB_NAME
                or os.environ.get('PGHOST') not in ('127.0.0.1', 'localhost')):
            raise RuntimeError('refusing non-disposable or non-loopback database')
        with cls.connect() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('this gate must run on PostgreSQL 17')
            preexisting = c.execute("""SELECT to_regnamespace('echo_core') IS NOT NULL
                OR to_regnamespace('echo_identity') IS NOT NULL
                OR to_regrole(%s) IS NOT NULL OR to_regrole(%s) IS NOT NULL""",
                (RUNTIME, GUARD)).fetchone()[0]
            if preexisting:
                raise RuntimeError('refusing database with pre-existing Echo objects/roles')
            for path in ('database/p2_1b/schema.sql',
                         'database/p2_1c2c/001_identity_registry.sql',
                         'database/p2_1c2d1/001_write_fence.sql',
                         'database/p2_1c2d2/001_runtime_roles.sql'):
                c.execute((ROOT / path).read_text())
            c.execute(f'CREATE ROLE {OUTSIDER} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                      'NOINHERIT NOREPLICATION NOBYPASSRLS')
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def connect():
        return psycopg.connect(connect_timeout=3,
            options='-c statement_timeout=8000 -c lock_timeout=4000 -c idle_in_transaction_session_timeout=12000')

    @classmethod
    def cleanup(cls):
        with cls.connect() as c:
            c.execute('DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_core CASCADE;')
            c.execute(f'DROP ROLE {OUTSIDER}; DROP ROLE {RUNTIME}; DROP ROLE {GUARD};')
        with cls.connect() as c:
            clean = c.execute("""SELECT to_regnamespace('echo_core') IS NULL
                AND to_regnamespace('echo_identity') IS NULL
                AND to_regrole(%s) IS NULL AND to_regrole(%s) IS NULL
                AND to_regrole(%s) IS NULL""", (RUNTIME,GUARD,OUTSIDER)).fetchone()[0]
            if not clean:
                raise AssertionError('runtime-role cleanup incomplete')
        print('CLEAN_RUNTIME_ROLE_DATABASE', flush=True)

    def setUp(self):
        now_ms = self.admin_scalar('SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint')
        self.stamp = dict(
            issuer='https://issuer.runtime.fixture.invalid/echo',
            subject='user-' + uuid4().hex,
            session_key=uuid4().hex + uuid4().hex,
            principal_id=uuid4(), actor_id=uuid4(), source_id=uuid4(),
            auth_version=1, capability='voice:draft:create',
            issued_ms=now_ms - 5000, not_before_ms=now_ms - 5000, expires_ms=now_ms + 120000)
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Runtime fixture',clock_timestamp())",
                      (self.stamp['actor_id'],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                      (self.stamp['source_id'],))
            c.execute("""INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled)
                VALUES(%s,%s,%s,%s,%s,true,true,false)""",
                (self.stamp['principal_id'],self.stamp['issuer'],self.stamp['subject'],
                 self.stamp['actor_id'],self.stamp['source_id']))
            c.execute("""INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s/1000.0),to_timestamp(%s/1000.0))""",
                (self.stamp['session_key'],self.stamp['principal_id'],
                 self.stamp['issued_ms'],self.stamp['expires_ms']))

    def admin_scalar(self, statement, params=()):
        with self.connect() as c:
            return c.execute(statement, params).fetchone()[0]

    def values(self, stamp=None):
        s = self.stamp if stamp is None else stamp
        return tuple(s[k] for k in FIELDS)

    def runtime_connection(self):
        c = self.connect()
        c.execute(f'SET SESSION AUTHORIZATION {RUNTIME}')
        self.assertEqual(c.execute('SELECT session_user,current_user').fetchone(), (RUNTIME,RUNTIME))
        return c

    def outsider_connection(self):
        c = self.connect()
        c.execute(f'SET SESSION AUTHORIZATION {OUTSIDER}')
        return c

    def runtime_error(self, statement, params=(), state='42501'):
        c = self.runtime_connection()
        try:
            with self.assertRaises(psycopg.Error) as ctx:
                c.execute(statement, params)
            self.assertEqual(ctx.exception.sqlstate, state)
        finally:
            c.rollback(); c.close()

    def wrapper_error(self, stamp, state='42501'):
        self.runtime_error(CALL, self.values(stamp), state)

    def test_01_roles_are_nonlogin_unprivileged_and_not_members_of_each_other(self):
        rows = self.admin_scalar("""SELECT jsonb_agg(jsonb_build_object(
              'name',rolname,'login',rolcanlogin,'super',rolsuper,'createdb',rolcreatedb,
              'createrole',rolcreaterole,'inherit',rolinherit,'replication',rolreplication,
              'bypassrls',rolbypassrls) ORDER BY rolname)
            FROM pg_roles WHERE rolname IN (%s,%s)""", (RUNTIME,GUARD))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertFalse(row['login']); self.assertFalse(row['super'])
            self.assertFalse(row['createdb']); self.assertFalse(row['createrole'])
            self.assertFalse(row['inherit']); self.assertFalse(row['replication']); self.assertFalse(row['bypassrls'])
        memberships = self.admin_scalar("""SELECT count(*) FROM pg_auth_members m
            JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
            WHERE r.rolname IN (%s,%s) OR u.rolname IN (%s,%s)""", (RUNTIME,GUARD,RUNTIME,GUARD))
        self.assertEqual(memberships, 0)

    def test_02_runtime_has_only_schema_usage_and_wrapper_execute_in_identity_surface(self):
        self.assertTrue(self.admin_scalar("SELECT has_schema_privilege(%s,'echo_identity','USAGE')", (RUNTIME,)))
        self.assertFalse(self.admin_scalar("SELECT has_schema_privilege(%s,'echo_identity','CREATE')", (RUNTIME,)))
        self.assertTrue(self.admin_scalar("SELECT has_function_privilege(%s,%s,'EXECUTE')", (RUNTIME,WRAPPER_SIG)))
        self.assertFalse(self.admin_scalar("SELECT has_function_privilege(%s,%s,'EXECUTE')", (RUNTIME,FENCE_SIG)))
        for table in ('echo_identity.principals','echo_identity.sessions'):
            for privilege in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'):
                self.assertFalse(self.admin_scalar('SELECT has_table_privilege(%s,%s,%s)',
                                                   (RUNTIME,table,privilege)))

    def test_03_guard_has_select_only_on_authority_and_no_core_history_access(self):
        self.assertTrue(self.admin_scalar("SELECT has_function_privilege(%s,%s,'EXECUTE')", (GUARD,FENCE_SIG)))
        for table in ('echo_identity.principals','echo_identity.sessions'):
            self.assertTrue(self.admin_scalar('SELECT has_table_privilege(%s,%s,\'SELECT\')', (GUARD,table)))
            for privilege in ('INSERT','UPDATE','DELETE','TRUNCATE'):
                self.assertFalse(self.admin_scalar('SELECT has_table_privilege(%s,%s,%s)', (GUARD,table,privilege)))
        for privilege in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE'):
            self.assertFalse(self.admin_scalar('SELECT has_table_privilege(%s,%s,%s)',
                (GUARD,'echo_core.voice_revisions',privilege)))

    def test_04_wrapper_is_security_definer_owned_by_guard_with_locked_path(self):
        row = self.admin_scalar("""SELECT jsonb_build_object('owner',r.rolname,'definer',p.prosecdef,'config',p.proconfig)
            FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid=%s::regprocedure""", (WRAPPER_SIG,))
        self.assertEqual(row['owner'], GUARD); self.assertTrue(row['definer'])
        self.assertEqual(row['config'], ['search_path=pg_catalog, pg_temp'])

    def test_05_runtime_can_invoke_wrapper_for_valid_current_private_draft_authority(self):
        with self.runtime_connection() as c:
            self.assertEqual(c.execute(CALL, self.values()).fetchone()[0], None)

    def test_06_runtime_cannot_read_authority_tables(self):
        self.runtime_error('SELECT * FROM echo_identity.principals')
        self.runtime_error('SELECT * FROM echo_identity.sessions')

    def test_07_runtime_cannot_mutate_authority_or_revoke_other_sessions(self):
        self.runtime_error('UPDATE echo_identity.principals SET writer_enabled=false,auth_version=auth_version+1')
        self.runtime_error('UPDATE echo_identity.sessions SET revoked=true')
        self.runtime_error("INSERT INTO echo_identity.sessions VALUES('" + 'f'*64 + "',%s,1,clock_timestamp(),clock_timestamp()+interval '1 hour',false)",
                           (self.stamp['principal_id'],))

    def test_08_runtime_cannot_read_or_write_core_voice_history_directly(self):
        self.runtime_error('SELECT * FROM echo_core.voice_revisions')
        self.runtime_error("INSERT INTO echo_core.voice_revisions(voice_id,revision,author_id,payload_ref,visibility,posted_at,recorded_at) VALUES(%s,1,%s,'x','PRIVATE',clock_timestamp(),clock_timestamp())",
                           (uuid4(),self.stamp['actor_id']))

    def test_09_runtime_cannot_call_underlying_invoker_fence_directly(self):
        direct = 'SELECT ' + FENCE_SIG.split('(')[0] + '(' + ','.join(['%s']*11) + ')'
        self.runtime_error(direct, self.values())

    def test_10_runtime_cannot_call_registry_lookup_function_directly(self):
        self.runtime_error('SELECT echo_identity.lookup_session(%s,%s,%s)',
                           (self.stamp['issuer'],self.stamp['subject'],self.stamp['session_key']))

    def test_11_runtime_cannot_set_guard_role_or_privileged_replication_mode(self):
        self.runtime_error(f'SET ROLE {GUARD}')
        self.runtime_error("SET session_replication_role='replica'")

    def test_12_runtime_cannot_create_replace_drop_or_grant_its_way_around_wrapper(self):
        self.runtime_error("CREATE FUNCTION echo_identity.evil() RETURNS int LANGUAGE sql AS 'SELECT 1'")
        self.runtime_error(f'ALTER FUNCTION {WRAPPER_SIG} SECURITY INVOKER')
        self.runtime_error(f'GRANT {GUARD} TO {RUNTIME}')

    def test_13_outsider_with_public_rights_only_cannot_use_wrapper_or_schema(self):
        c = self.outsider_connection()
        try:
            with self.assertRaises(psycopg.Error) as ctx:
                c.execute(CALL, self.values())
            self.assertEqual(ctx.exception.sqlstate, '42501')
        finally:
            c.rollback(); c.close()

    def test_14_wrapper_rejects_forged_actor_source_principal_and_generation(self):
        for key,value in (('actor_id',uuid4()),('source_id',uuid4()),('principal_id',uuid4()),('auth_version',2)):
            forged = dict(self.stamp); forged[key]=value
            with self.subTest(key=key): self.wrapper_error(forged)

    def test_15_wrapper_rejects_wrong_capability_and_unknown_session(self):
        forged = dict(self.stamp); forged['capability']='assessment:review'; self.wrapper_error(forged)
        forged = dict(self.stamp); forged['session_key']='f'*64; self.wrapper_error(forged)

    def test_16_committed_revoke_disable_or_role_removal_is_seen_through_wrapper(self):
        mutations = (
            "UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",
            "UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s",
            "UPDATE echo_identity.principals SET writer_enabled=false,auth_version=auth_version+1 WHERE principal_id=%s",
        )
        for index,statement in enumerate(mutations):
            f = self.fresh_fixture_for_subtest(index)
            with self.connect() as c:
                param = f['session_key'] if 'sessions' in statement else f['principal_id']
                c.execute(statement,(param,))
            with self.subTest(index=index): self.wrapper_error(f)

    def fresh_fixture_for_subtest(self, suffix):
        now_ms = self.admin_scalar('SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint')
        s = dict(self.stamp)
        s.update(subject=f'sub-{suffix}-'+uuid4().hex,session_key=uuid4().hex+uuid4().hex,
                 principal_id=uuid4(),actor_id=uuid4(),source_id=uuid4(),
                 issued_ms=now_ms-5000,not_before_ms=now_ms-5000,expires_ms=now_ms+120000)
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Sub fixture',clock_timestamp())",(s['actor_id'],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",(s['source_id'],))
            c.execute("""INSERT INTO echo_identity.principals(principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled)
                VALUES(%s,%s,%s,%s,%s,true,true)""",(s['principal_id'],s['issuer'],s['subject'],s['actor_id'],s['source_id']))
            c.execute("""INSERT INTO echo_identity.sessions VALUES(%s,%s,1,to_timestamp(%s/1000.0),to_timestamp(%s/1000.0),false)""",
                      (s['session_key'],s['principal_id'],s['issued_ms'],s['expires_ms']))
        return s

    def test_17_wrapper_rejects_expired_or_not_yet_valid_time(self):
        now_ms = self.admin_scalar('SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint')
        past = dict(self.stamp); past['expires_ms']=now_ms-1; self.wrapper_error(past)
        future = dict(self.stamp); future['issued_ms']=now_ms+1000; future['not_before_ms']=now_ms+1000
        self.wrapper_error(future)

    def test_18_wrapper_keeps_underlying_read_committed_only_contract(self):
        c = self.runtime_connection()
        try:
            c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            with self.assertRaises(psycopg.Error) as ctx:
                c.execute(CALL,self.values())
            self.assertEqual(ctx.exception.sqlstate,'25001')
        finally:
            c.rollback(); c.close()

    def test_19_wrapper_does_not_return_a_reusable_authorization_ticket(self):
        with self.runtime_connection() as c:
            row = c.execute(CALL,self.values()).fetchone()
            self.assertEqual(row,(None,))

    def test_20_runtime_has_no_predefined_all_data_role_membership(self):
        count = self.admin_scalar("""SELECT count(*) FROM pg_auth_members m
          JOIN pg_roles granted ON granted.oid=m.roleid JOIN pg_roles member ON member.oid=m.member
          WHERE member.rolname=%s AND granted.rolname IN ('pg_read_all_data','pg_write_all_data','pg_database_owner')""",(RUNTIME,))
        self.assertEqual(count,0)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeRoleTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print('P2_1C2D2A_RUNTIME_ROLE_SUITE_SAT', flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
