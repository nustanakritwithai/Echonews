"""P2.1c.2d.4c.4 dedicated identity/session mutation service pool.

The startup-authenticated LOGIN has no direct identity table/function access and may
SET only one fixed mutation runtime role. Every lease is one transaction. Pool reset
is synchronous and fail-closed. Business mutations are NEVER replayed by the pool;
all four sealed mutations are designed for explicit exact-parameter retry after an
unknown commit outcome.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool

SERVICE = 'echo_identity_mutation_service'
RUNTIME = 'echo_identity_mutation_runtime'
GUARD = 'echo_identity_mutation_guard'
SCHEMA = 'echo_identity'
FUNCTIONS = (
    'echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)',
    'echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)',
    'echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)',
    'echo_identity.runtime_revoke_session(text,uuid)',
)


class MutationPoolError(Exception):
    """Public-safe category; never include DSN, password or driver details."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class MutationPool:
    """Fixed-size, fixed-role service pool for durable identity mutations only."""

    def __init__(self, *, host: str, port: int, dbname: str, user: str,
                 password: str, sslmode: str = 'verify-full',
                 sslrootcert: str | None = None, max_size: int = 2,
                 allow_insecure_test_loopback: bool = False):
        if (type(host) is not str or not host or ',' in host or
                type(port) is not int or not 1 <= port <= 65535 or
                type(dbname) is not str or not dbname or user != SERVICE or
                type(password) is not str or not password or
                type(max_size) is not int or not 1 <= max_size <= 4):
            raise MutationPoolError('INVALID_SERVICE_CONFIG')
        insecure_test = (allow_insecure_test_loopback is True and
                         host == '127.0.0.1' and dbname == 'echo_identity_mutation_test')
        if sslmode != 'verify-full' and not (insecure_test and sslmode == 'disable'):
            raise MutationPoolError('VERIFIED_TLS_REQUIRED')
        self._dbname = dbname
        kwargs = dict(
            host=host, port=port, dbname=dbname, user=SERVICE, password=password,
            sslmode=sslmode, connect_timeout=3, autocommit=True,
            prepare_threshold=None, row_factory=tuple_row,
            options='-c search_path=pg_catalog -c statement_timeout=5000 '
                    '-c lock_timeout=3000 -c idle_in_transaction_session_timeout=10000',
        )
        if sslrootcert is not None:
            kwargs['sslrootcert'] = sslrootcert
        self._pool = ConnectionPool(
            conninfo='', kwargs=kwargs, min_size=0, max_size=max_size,
            max_waiting=8, timeout=3, open=False, name='echo-identity-mutation',
        )

    def open(self) -> None:
        self._pool.open()

    def close(self) -> None:
        self._pool.close(timeout=5)

    def _validate_authority(self, c: Connection) -> None:
        if c.info.user != SERVICE:
            raise MutationPoolError('SERVICE_LOGIN_REQUIRED')
        baseline = c.execute(
            'SELECT session_user,current_user,current_database()', prepare=False
        ).fetchone()
        if baseline != (SERVICE, SERVICE, self._dbname):
            raise MutationPoolError('SERVICE_BASELINE_REQUIRED')

        roles = c.execute('''SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,
                    rolcreaterole,rolreplication,rolbypassrls
             FROM pg_catalog.pg_roles
             WHERE rolname=ANY(%s) ORDER BY rolname''',
             ([GUARD, RUNTIME, SERVICE],), prepare=False).fetchall()
        expected_roles = [
            (GUARD, False, False, False, False, False, False, False),
            (RUNTIME, False, False, False, False, False, False, False),
            (SERVICE, True, False, False, False, False, False, False),
        ]
        if roles != expected_roles:
            raise MutationPoolError('ROLE_POLICY_DRIFT')

        memberships = c.execute('''SELECT member.rolname,parent.rolname,
                    m.admin_option,m.inherit_option,m.set_option
             FROM pg_catalog.pg_auth_members m
             JOIN pg_catalog.pg_roles member ON member.oid=m.member
             JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
             WHERE member.rolname=ANY(%s)
             ORDER BY member.rolname,parent.rolname''',
             ([SERVICE, RUNTIME, GUARD],), prepare=False).fetchall()
        if memberships != [(SERVICE, RUNTIME, False, False, True)]:
            raise MutationPoolError('ROLE_MEMBERSHIP_DRIFT')

        unsafe = c.execute('''SELECT EXISTS (
          SELECT 1 FROM pg_catalog.pg_class t
          JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
          CROSS JOIN unnest(%s::text[]) r(name)
          WHERE n.nspname=%s AND t.relkind IN ('r','p','v','m','f') AND (
            pg_catalog.has_table_privilege(r.name,t.oid,
              'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
            pg_catalog.has_any_column_privilege(r.name,t.oid,
              'SELECT,INSERT,UPDATE,REFERENCES'))
        )''', ([SERVICE, RUNTIME], SCHEMA), prepare=False).fetchone()[0]
        if unsafe:
            raise MutationPoolError('DIRECT_TABLE_PRIVILEGE_DRIFT')

        guard_tables = c.execute('''SELECT t.relname,
               pg_catalog.has_table_privilege(%s,t.oid,'SELECT'),
               pg_catalog.has_table_privilege(%s,t.oid,'INSERT'),
               pg_catalog.has_table_privilege(%s,t.oid,'UPDATE'),
               pg_catalog.has_table_privilege(%s,t.oid,'DELETE') OR
                 pg_catalog.has_table_privilege(%s,t.oid,'TRUNCATE')
             FROM pg_catalog.pg_class t
             JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
             WHERE n.nspname=%s AND t.relname IN ('principals','sessions')
             ORDER BY t.relname''',
             (GUARD, GUARD, GUARD, GUARD, GUARD, SCHEMA), prepare=False).fetchall()
        if guard_tables != [('principals', True, False, False, False),
                            ('sessions', True, False, False, False)]:
            raise MutationPoolError('GUARD_TABLE_POLICY_DRIFT')

        column_rows = c.execute('''SELECT t.relname,a.attname,
               pg_catalog.has_column_privilege(%s,t.oid,a.attname,'INSERT'),
               pg_catalog.has_column_privilege(%s,t.oid,a.attname,'UPDATE')
             FROM pg_catalog.pg_class t
             JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
             JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid
             WHERE n.nspname=%s AND t.relname IN ('principals','sessions')
               AND a.attnum>0 AND NOT a.attisdropped
             ORDER BY t.relname,a.attnum''',
             (GUARD, GUARD, SCHEMA), prepare=False).fetchall()
        actual = {(table, column): (insert, update)
                  for table, column, insert, update in column_rows}
        principal_cols = ('principal_id','issuer','subject','actor_id','actor_kind','source_id',
                          'enabled','writer_enabled','reviewer_enabled','auth_version')
        session_cols = ('session_key','principal_id','auth_version','issued_at','expires_at','revoked')
        expected = {('principals', col): (True, col in {'enabled','writer_enabled','auth_version'})
                    for col in principal_cols}
        expected.update({('sessions', col): (True, col == 'revoked') for col in session_cols})
        if actual != expected:
            raise MutationPoolError('GUARD_COLUMN_POLICY_DRIFT')

        allowed = c.execute('''SELECT p.oid::regprocedure::text
             FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname=%s AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE')
             ORDER BY 1''', (SCHEMA, RUNTIME), prepare=False).fetchall()
        if allowed != [(name,) for name in FUNCTIONS]:
            raise MutationPoolError('FUNCTION_PRIVILEGE_DRIFT')

        direct_service_function = c.execute('''SELECT EXISTS(
             SELECT 1 FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname=%s AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE'))''',
             (SCHEMA, SERVICE), prepare=False).fetchone()[0]
        create = c.execute('''SELECT pg_catalog.has_database_privilege(%s,current_database(),'CREATE')
             OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n
                        WHERE n.nspname=ANY(%s)
                          AND (pg_catalog.has_schema_privilege(%s,n.oid,'CREATE') OR
                               pg_catalog.has_schema_privilege(%s,n.oid,'CREATE')))''',
             (SERVICE, [SCHEMA, 'public'], SERVICE, RUNTIME), prepare=False).fetchone()[0]
        if direct_service_function or create:
            raise MutationPoolError('SERVICE_PRIVILEGE_DRIFT')

    def _sanitize(self, c: Connection) -> None:
        if c.closed or c.info.transaction_status == TransactionStatus.UNKNOWN:
            raise MutationPoolError('BROKEN_SERVICE_CONNECTION')
        if c.info.user != SERVICE:
            raise MutationPoolError('SERVICE_LOGIN_REQUIRED')
        if c.info.transaction_status != TransactionStatus.IDLE:
            c.rollback()
        c.autocommit = True
        c.prepare_threshold = None
        c.row_factory = tuple_row
        c.execute('DISCARD ALL', prepare=False)
        c.execute('SET SESSION search_path = pg_catalog', prepare=False)
        c.execute('SET SESSION row_security = on', prepare=False)
        c.execute("SET SESSION TimeZone = 'UTC'", prepare=False)
        c.execute("SET SESSION statement_timeout = '5s'", prepare=False)
        c.execute("SET SESSION lock_timeout = '3s'", prepare=False)
        c.execute("SET SESSION idle_in_transaction_session_timeout = '10s'", prepare=False)
        self._validate_authority(c)
        if c.info.transaction_status != TransactionStatus.IDLE:
            raise MutationPoolError('NONIDLE_POOL_BASELINE')

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        try:
            c = self._pool.getconn(timeout=3)
        except Exception:
            raise MutationPoolError('SERVICE_CONNECTION_UNAVAILABLE') from None
        body_failed = False
        cleanup_failed = False
        try:
            try:
                self._sanitize(c)
            except MutationPoolError:
                c.close()
                raise
            except Exception:
                c.close()
                raise MutationPoolError('POOL_RESET_FAILED') from None

            with c.transaction():
                c.execute('SET LOCAL ROLE echo_identity_mutation_runtime', prepare=False)
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE, RUNTIME):
                    raise MutationPoolError('LEASE_ROLE_REQUIRED')
                yield c
                if c.closed or c.info.transaction_status != TransactionStatus.INTRANS:
                    raise MutationPoolError('LEASE_TRANSACTION_CHANGED')
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE, RUNTIME):
                    raise MutationPoolError('LEASE_ROLE_CHANGED')
        except BaseException:
            body_failed = True
            raise
        finally:
            try:
                if not c.closed:
                    self._sanitize(c)
            except BaseException:
                cleanup_failed = True
                c.close()
            finally:
                self._pool.putconn(c)
            if cleanup_failed and not body_failed:
                raise MutationPoolError('POOL_RESET_FAILED') from None
