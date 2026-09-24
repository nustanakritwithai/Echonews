"""Dedicated synchronous durable identity-registry lookup pool.

Use ``pool.connection`` as the ServicePostgresRegistryAdapter connection callback.
The pool authenticates as one fixed database service and SET LOCAL ROLE only to the
sealed registry runtime for the lifetime of one lookup transaction. No web identity,
JWT, principal, Actor or Source is stored in PostgreSQL session settings.

This is not a provisioning pool and not a general SQL endpoint.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool

SERVICE = 'echo_identity_registry_service'
RUNTIME = 'echo_identity_registry_runtime'
GUARD = 'echo_identity_registry_guard'
LOOKUP_FUNCTION = 'echo_identity.runtime_lookup_session(text,text,text)'
SCHEMA = 'echo_identity'


class RegistryPoolError(Exception):
    """Public-safe category; never include DSN, password, token or driver text."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class RegistryPool:
    """Fixed-size service pool with fail-closed synchronous lease reset.

    The pool never retries a registry lookup. A broken/reset-failed connection is
    discarded and the caller receives a generic backend failure through Boundary.
    Raw connections are trusted-backend internals and must not escape the lease.
    PgBouncer transaction/statement pooling is outside this reference contract.
    """

    def __init__(self, *, host: str, port: int, dbname: str, user: str,
                 password: str, sslmode: str = 'verify-full',
                 sslrootcert: str | None = None, max_size: int = 2,
                 allow_insecure_test_loopback: bool = False):
        if (type(host) is not str or not host or ',' in host or
                type(port) is not int or not 1 <= port <= 65535 or
                type(dbname) is not str or not dbname or user != SERVICE or
                type(password) is not str or not password or
                type(max_size) is not int or not 1 <= max_size <= 6):
            raise RegistryPoolError('INVALID_SERVICE_CONFIG')
        insecure_test = (allow_insecure_test_loopback is True and
                         host == '127.0.0.1' and dbname == 'echo_registry_pool_test')
        if sslmode != 'verify-full' and not (insecure_test and sslmode == 'disable'):
            raise RegistryPoolError('VERIFIED_TLS_REQUIRED')
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
            max_waiting=12, timeout=3, open=False, name='echo-registry-read-only',
        )

    def open(self) -> None:
        self._pool.open()

    def close(self) -> None:
        self._pool.close(timeout=5)

    def _validate_authority(self, c: Connection) -> None:
        # info.user is the startup-authenticated role, not just current_user after
        # a privileged test connection performs SET SESSION AUTHORIZATION.
        if c.info.user != SERVICE:
            raise RegistryPoolError('SERVICE_LOGIN_REQUIRED')
        baseline = c.execute(
            'SELECT session_user,current_user,current_database()', prepare=False
        ).fetchone()
        if baseline != (SERVICE, SERVICE, self._dbname):
            raise RegistryPoolError('SERVICE_BASELINE_REQUIRED')

        roles = c.execute('''SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,
                    rolcreaterole,rolreplication,rolbypassrls
             FROM pg_catalog.pg_roles
             WHERE rolname=ANY(%s) ORDER BY rolname''',
             ([GUARD, RUNTIME, SERVICE],), prepare=False).fetchall()
        expected = [
            (GUARD, False, False, False, False, False, False, False),
            (RUNTIME, False, False, False, False, False, False, False),
            (SERVICE, True, False, False, False, False, False, False),
        ]
        if roles != expected:
            raise RegistryPoolError('ROLE_POLICY_DRIFT')

        memberships = c.execute('''SELECT member.rolname,parent.rolname,
                    m.admin_option,m.inherit_option,m.set_option
             FROM pg_catalog.pg_auth_members m
             JOIN pg_catalog.pg_roles member ON member.oid=m.member
             JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
             WHERE member.rolname=ANY(%s)
             ORDER BY member.rolname,parent.rolname''',
             ([SERVICE, RUNTIME, GUARD],), prepare=False).fetchall()
        if memberships != [(SERVICE, RUNTIME, False, False, True)]:
            raise RegistryPoolError('ROLE_MEMBERSHIP_DRIFT')

        # Service and runtime have zero direct registry table/column privileges.
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
            raise RegistryPoolError('DIRECT_TABLE_PRIVILEGE_DRIFT')

        # Guard is intentionally SELECT-only on exactly the two authority tables.
        guard_acl = c.execute('''SELECT t.relname,
               pg_catalog.has_table_privilege(%s,t.oid,'SELECT'),
               pg_catalog.has_table_privilege(%s,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
             FROM pg_catalog.pg_class t
             JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
             WHERE n.nspname=%s AND t.relname IN ('principals','sessions')
             ORDER BY t.relname''',
             (GUARD, GUARD, SCHEMA), prepare=False).fetchall()
        if guard_acl != [('principals', True, False), ('sessions', True, False)]:
            raise RegistryPoolError('GUARD_TABLE_POLICY_DRIFT')

        allowed = c.execute('''SELECT p.oid::regprocedure::text
             FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname=%s AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE')
             ORDER BY 1''', (SCHEMA, RUNTIME), prepare=False).fetchall()
        if allowed != [(LOOKUP_FUNCTION,)]:
            raise RegistryPoolError('FUNCTION_PRIVILEGE_DRIFT')

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
            raise RegistryPoolError('SERVICE_PRIVILEGE_DRIFT')

    def _sanitize(self, c: Connection) -> None:
        if c.closed or c.info.transaction_status == TransactionStatus.UNKNOWN:
            raise RegistryPoolError('BROKEN_SERVICE_CONNECTION')
        if c.info.user != SERVICE:
            raise RegistryPoolError('SERVICE_LOGIN_REQUIRED')
        if c.info.transaction_status != TransactionStatus.IDLE:
            c.rollback()  # Never commit abandoned/failed work to make it reusable.
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
            raise RegistryPoolError('NONIDLE_POOL_BASELINE')

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        try:
            c = self._pool.getconn(timeout=3)
        except Exception:
            raise RegistryPoolError('SERVICE_CONNECTION_UNAVAILABLE') from None
        body_failed = False
        cleanup_failed = False
        try:
            try:
                self._sanitize(c)
            except RegistryPoolError:
                c.close()
                raise
            except Exception:
                c.close()
                raise RegistryPoolError('POOL_RESET_FAILED') from None

            with c.transaction():
                c.execute('SET LOCAL ROLE echo_identity_registry_runtime', prepare=False)
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE, RUNTIME):
                    raise RegistryPoolError('LEASE_ROLE_REQUIRED')
                yield c
                # Callers may use cursors only. They must not end the transaction or
                # change role; doing so invalidates the lease and discards the state.
                if c.closed or c.info.transaction_status != TransactionStatus.INTRANS:
                    raise RegistryPoolError('LEASE_TRANSACTION_CHANGED')
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE, RUNTIME):
                    raise RegistryPoolError('LEASE_ROLE_CHANGED')
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
                raise RegistryPoolError('POOL_RESET_FAILED') from None
