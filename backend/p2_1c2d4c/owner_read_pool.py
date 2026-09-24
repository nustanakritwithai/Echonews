"""Dedicated synchronous PRIVATE owner-read pool, not a general SQL endpoint.

Use pool.connection as the existing PrivateOwnerReadAdapter connect_runtime callback.
No web user identity is ever kept in connection settings. One service, one runtime.
The server config/connection factory must never be derived from request JSON.
Only owner-read is in scope: writer, registry and recovery pools remain separate gates.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool

SERVICE = 'echo_private_owner_read_service'
RUNTIME = 'echo_private_owner_read_runtime'
READ_FUNCTION = 'echo_identity.runtime_read_private_owner_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid)'
SCHEMAS = ['echo_identity', 'echo_core', 'echo_history', 'echo_public']


class OwnerReadPoolError(Exception):
    """Safe category, never a DSN, password, token or driver traceback."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class OwnerReadPool:
    """Fixed-size research pool with fail-closed, synchronous lease reset.

    Does not retry business queries. An error discards/replaces a connection only;
    the caller must explicitly decide whether to retry an operation. Raw connection
    access is trusted-backend-only and must not escape a lease or cross threads.
    No PgBouncer transaction/statement pooling is supported in this reference.
    """
    def __init__(self, *, host: str, port: int, dbname: str, user: str,
                 password: str, sslmode: str = 'verify-full',
                 sslrootcert: str | None = None, max_size: int = 1,
                 allow_insecure_test_loopback: bool = False):
        if (type(host) is not str or not host or ',' in host or
                type(port) is not int or not 1 <= port <= 65535 or
                type(dbname) is not str or not dbname or user != SERVICE or
                type(password) is not str or not password or
                type(max_size) is not int or not 1 <= max_size <= 4):
            raise OwnerReadPoolError('INVALID_SERVICE_CONFIG')
        insecure_test = (allow_insecure_test_loopback is True and
                         host == '127.0.0.1' and dbname == 'echo_owner_read_pool_test')
        if sslmode != 'verify-full' and not (insecure_test and sslmode == 'disable'):
            raise OwnerReadPoolError('VERIFIED_TLS_REQUIRED')
        self._dbname = dbname
        kwargs = dict(host=host, port=port, dbname=dbname, user=SERVICE,
                      password=password, sslmode=sslmode, connect_timeout=3,
                      autocommit=True, prepare_threshold=None, row_factory=tuple_row,
                      options='-c search_path=pg_catalog -c statement_timeout=10000 -c lock_timeout=6000 -c idle_in_transaction_session_timeout=15000')
        if sslrootcert is not None:
            kwargs['sslrootcert'] = sslrootcert
        self._pool = ConnectionPool(conninfo='', kwargs=kwargs, min_size=0,
                                    max_size=max_size, max_waiting=8, timeout=3,
                                    open=False, name='echo-owner-read-only')
        # No connections are opened at import or construction time.

    def open(self) -> None:
        self._pool.open()

    def close(self) -> None:
        self._pool.close(timeout=5)

    def _validate_authority(self, c: Connection) -> None:
        # info.user is the startup-authenticated user, not the spoofable effective
        # role from an admin-created connection subsequently SET SESSION AUTHORIZED.
        if c.info.user != SERVICE:
            raise OwnerReadPoolError('SERVICE_LOGIN_REQUIRED')
        if c.execute('SELECT session_user,current_user,current_database()', prepare=False).fetchone() != (SERVICE, SERVICE, self._dbname):
            raise OwnerReadPoolError('SERVICE_BASELINE_REQUIRED')
        roles = c.execute('''SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,
                    rolcreaterole,rolreplication,rolbypassrls
                    FROM pg_catalog.pg_roles WHERE rolname=ANY(%s) ORDER BY rolname''',
                    ([RUNTIME, SERVICE],), prepare=False).fetchall()
        expected = [(RUNTIME,False,False,False,False,False,False,False),
                    (SERVICE,True,False,False,False,False,False,False)]
        if roles != expected:
            raise OwnerReadPoolError('ROLE_POLICY_DRIFT')
        memberships = c.execute('''SELECT member.rolname,parent.rolname,
                    m.admin_option,m.inherit_option,m.set_option
                    FROM pg_catalog.pg_auth_members m
                    JOIN pg_catalog.pg_roles member ON member.oid=m.member
                    JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
                    WHERE member.rolname=ANY(%s)''', ([SERVICE,RUNTIME],), prepare=False).fetchall()
        if memberships != [(SERVICE,RUNTIME,False,False,True)]:
            raise OwnerReadPoolError('ROLE_MEMBERSHIP_DRIFT')
        # No direct/base table or column grants on either service or effective role.
        unsafe = c.execute('''SELECT EXISTS (
          SELECT 1 FROM pg_catalog.pg_class t
          JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
          CROSS JOIN unnest(%s::text[]) r(name)
          WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p','v','m','f') AND (
            pg_catalog.has_table_privilege(r.name,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
            pg_catalog.has_any_column_privilege(r.name,t.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
        )''', ([SERVICE,RUNTIME],SCHEMAS), prepare=False).fetchone()[0]
        if unsafe:
            raise OwnerReadPoolError('DIRECT_TABLE_PRIVILEGE_DRIFT')
        allowed = c.execute('''SELECT p.oid::regprocedure::text
                    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                    WHERE n.nspname=ANY(%s) AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE')
                    ORDER BY 1''', (SCHEMAS,RUNTIME), prepare=False).fetchall()
        if allowed != [(READ_FUNCTION,)]:
            raise OwnerReadPoolError('FUNCTION_PRIVILEGE_DRIFT')
        direct = c.execute('''SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
                    JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                    WHERE n.nspname=ANY(%s) AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE'))''',
                    (SCHEMAS,SERVICE), prepare=False).fetchone()[0]
        create = c.execute('''SELECT pg_catalog.has_database_privilege(%s,current_database(),'CREATE')
                    OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname=ANY(%s)
                       AND (pg_catalog.has_schema_privilege(%s,n.oid,'CREATE') OR
                            pg_catalog.has_schema_privilege(%s,n.oid,'CREATE')))''',
                    (SERVICE,SCHEMAS+['public'],SERVICE,RUNTIME), prepare=False).fetchone()[0]
        if direct or create:
            raise OwnerReadPoolError('SERVICE_PRIVILEGE_DRIFT')

    def _sanitize(self, c: Connection) -> None:
        if c.closed or c.info.transaction_status == TransactionStatus.UNKNOWN:
            raise OwnerReadPoolError('BROKEN_SERVICE_CONNECTION')
        if c.info.user != SERVICE:
            raise OwnerReadPoolError('SERVICE_LOGIN_REQUIRED')
        # Roll back abandoned/failed transactions, NEVER commit to make them idle.
        if c.info.transaction_status != TransactionStatus.IDLE:
            c.rollback()
        c.autocommit = True
        c.prepare_threshold = None  # DISCARD ALL would invalidate driver plans.
        c.row_factory = tuple_row
        c.execute('DISCARD ALL', prepare=False)  # Must be outside any transaction.
        c.execute('SET SESSION search_path = pg_catalog', prepare=False)
        c.execute('SET SESSION row_security = on', prepare=False)
        c.execute("SET SESSION TimeZone = 'UTC'", prepare=False)
        c.execute("SET SESSION statement_timeout = '10s'", prepare=False)
        c.execute("SET SESSION lock_timeout = '6s'", prepare=False)
        c.execute("SET SESSION idle_in_transaction_session_timeout = '15s'", prepare=False)
        self._validate_authority(c)
        if c.info.transaction_status != TransactionStatus.IDLE:
            raise OwnerReadPoolError('NONIDLE_POOL_BASELINE')

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        # Used as a trusted callback, not passed any client role/identity argument.
        try:
            c = self._pool.getconn(timeout=3)
        except Exception:
            raise OwnerReadPoolError('SERVICE_CONNECTION_UNAVAILABLE') from None
        body_failed = False
        cleanup_failed = False
        try:
            try:
                self._sanitize(c)
            except OwnerReadPoolError:
                c.close()
                raise
            except Exception:
                c.close()
                raise OwnerReadPoolError('POOL_RESET_FAILED') from None
            with c.transaction():
                c.execute('SET LOCAL ROLE echo_private_owner_read_runtime', prepare=False)
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE,RUNTIME):
                    raise OwnerReadPoolError('LEASE_ROLE_REQUIRED')
                yield c
                # A trusted caller must not manually COMMIT/ROLLBACK/SET ROLE mid-lease.
                if c.closed or c.info.transaction_status != TransactionStatus.INTRANS:
                    raise OwnerReadPoolError('LEASE_TRANSACTION_CHANGED')
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE,RUNTIME):
                    raise OwnerReadPoolError('LEASE_ROLE_CHANGED')
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
            # Never return a dirty connection if reset fails. Do not mask an existing
            # operation error. No operation replay or success retry occurs here.
            if cleanup_failed and not body_failed:
                raise OwnerReadPoolError('POOL_RESET_FAILED') from None
