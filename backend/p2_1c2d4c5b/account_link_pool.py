"""P2.1c.2d.4c.5b fixed-role pool for signed account-link proof issuance.

The startup-authenticated service has no direct identity/core table or function
privilege and may SET LOCAL only the existing account-link runtime. Every lease is
one transaction and reset is synchronous/fail-closed. This pool never retries proof
issuance and raw connections are trusted backend internals, not an untrusted SQL API.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool

SERVICE = 'echo_account_link_service'
RUNTIME = 'echo_account_link_runtime'
GUARD = 'echo_account_link_guard'
SCHEMAS = ('echo_identity', 'echo_core')
ISSUE_FUNCTION = 'echo_identity.runtime_issue_account_link_proof(uuid,text,text,bigint,bigint,bigint,bigint)'
_TEST_DATABASES = frozenset({'echo_account_link_signed_test', 'echo_first_session_test'})


class AccountLinkPoolError(Exception):
    """Public-safe category; never include DSN, password, token or driver details."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class AccountLinkPool:
    """Fixed-size service pool for one signed account-link proof operation."""

    def __init__(self, *, host: str, port: int, dbname: str, user: str,
                 password: str, sslmode: str = 'verify-full',
                 sslrootcert: str | None = None, max_size: int = 2,
                 allow_insecure_test_loopback: bool = False):
        if (type(host) is not str or not host or ',' in host or
                type(port) is not int or not 1 <= port <= 65535 or
                type(dbname) is not str or not dbname or user != SERVICE or
                type(password) is not str or not password or
                type(max_size) is not int or not 1 <= max_size <= 4):
            raise AccountLinkPoolError('INVALID_SERVICE_CONFIG')
        insecure_test = (allow_insecure_test_loopback is True and
                         host == '127.0.0.1' and dbname in _TEST_DATABASES)
        if sslmode != 'verify-full' and not (insecure_test and sslmode == 'disable'):
            raise AccountLinkPoolError('VERIFIED_TLS_REQUIRED')
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
            max_waiting=8, timeout=3, open=False, name='echo-account-link-signed',
        )

    def open(self) -> None:
        self._pool.open()

    def close(self) -> None:
        self._pool.close(timeout=5)

    def _validate_authority(self, c: Connection) -> None:
        if c.info.user != SERVICE:
            raise AccountLinkPoolError('SERVICE_LOGIN_REQUIRED')
        baseline = c.execute(
            'SELECT session_user,current_user,current_database()', prepare=False
        ).fetchone()
        if baseline != (SERVICE, SERVICE, self._dbname):
            raise AccountLinkPoolError('SERVICE_BASELINE_REQUIRED')

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
            raise AccountLinkPoolError('ROLE_POLICY_DRIFT')

        memberships = c.execute('''SELECT member.rolname,parent.rolname,
                    m.admin_option,m.inherit_option,m.set_option
             FROM pg_catalog.pg_auth_members m
             JOIN pg_catalog.pg_roles member ON member.oid=m.member
             JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
             WHERE member.rolname=ANY(%s)
             ORDER BY member.rolname,parent.rolname''',
             ([SERVICE, RUNTIME, GUARD],), prepare=False).fetchall()
        if memberships != [(SERVICE, RUNTIME, False, False, True)]:
            raise AccountLinkPoolError('ROLE_MEMBERSHIP_DRIFT')

        unsafe = c.execute('''SELECT EXISTS (
          SELECT 1 FROM pg_catalog.pg_class t
          JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
          CROSS JOIN unnest(%s::text[]) r(name)
          WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p','v','m','f') AND (
            pg_catalog.has_table_privilege(r.name,t.oid,
              'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
            pg_catalog.has_any_column_privilege(r.name,t.oid,
              'SELECT,INSERT,UPDATE,REFERENCES'))
        )''', ([SERVICE, RUNTIME], list(SCHEMAS)), prepare=False).fetchone()[0]
        if unsafe:
            raise AccountLinkPoolError('DIRECT_TABLE_PRIVILEGE_DRIFT')

        allowed = c.execute('''SELECT p.oid::regprocedure::text
             FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname='echo_identity'
               AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE')
             ORDER BY 1''', (RUNTIME,), prepare=False).fetchall()
        if allowed != [(ISSUE_FUNCTION,)]:
            raise AccountLinkPoolError('FUNCTION_PRIVILEGE_DRIFT')

        direct_service_function = c.execute('''SELECT EXISTS(
             SELECT 1 FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname='echo_identity'
               AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE'))''',
             (SERVICE,), prepare=False).fetchone()[0]
        create = c.execute('''SELECT pg_catalog.has_database_privilege(%s,current_database(),'CREATE')
             OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n
                        WHERE n.nspname=ANY(%s)
                          AND (pg_catalog.has_schema_privilege(%s,n.oid,'CREATE')
                               OR pg_catalog.has_schema_privilege(%s,n.oid,'CREATE')))''',
             (SERVICE, list(SCHEMAS) + ['public'], SERVICE, RUNTIME), prepare=False).fetchone()[0]
        if direct_service_function or create:
            raise AccountLinkPoolError('SERVICE_PRIVILEGE_DRIFT')

    def _sanitize(self, c: Connection) -> None:
        if c.closed or c.info.transaction_status == TransactionStatus.UNKNOWN:
            raise AccountLinkPoolError('BROKEN_SERVICE_CONNECTION')
        if c.info.user != SERVICE:
            raise AccountLinkPoolError('SERVICE_LOGIN_REQUIRED')
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
            raise AccountLinkPoolError('NONIDLE_POOL_BASELINE')

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        try:
            c = self._pool.getconn(timeout=3)
        except Exception:
            raise AccountLinkPoolError('SERVICE_CONNECTION_UNAVAILABLE') from None
        body_failed = False
        cleanup_failed = False
        try:
            try:
                self._sanitize(c)
            except AccountLinkPoolError:
                c.close()
                raise
            except Exception:
                c.close()
                raise AccountLinkPoolError('POOL_RESET_FAILED') from None

            with c.transaction():
                c.execute('SET LOCAL ROLE echo_account_link_runtime', prepare=False)
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE, RUNTIME):
                    raise AccountLinkPoolError('LEASE_ROLE_REQUIRED')
                yield c
                if c.closed or c.info.transaction_status != TransactionStatus.INTRANS:
                    raise AccountLinkPoolError('LEASE_TRANSACTION_CHANGED')
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE, RUNTIME):
                    raise AccountLinkPoolError('LEASE_ROLE_CHANGED')
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
                raise AccountLinkPoolError('POOL_RESET_FAILED') from None
