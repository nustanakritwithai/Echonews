"""P2.1c.2d.4c.2 — dedicated PRIVATE draft writer/recovery service pool.

One fixed service LOGIN may SET LOCAL only to echo_private_draft_runtime for a single
transactional lease. No client identity or authorization stamp is stored in session
GUCs. The pool never retries business commands; a commit outcome that becomes unknown
is surfaced to the recoverable/idempotent executor, which must reconcile explicitly.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool

SERVICE = 'echo_private_draft_service'
RUNTIME = 'echo_private_draft_runtime'
SCHEMAS = ['echo_identity', 'echo_core', 'echo_history', 'echo_public']
ALLOWED_FUNCTIONS = sorted([
    'echo_identity.runtime_private_draft_fence(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)',
    'echo_identity.runtime_reserve_private_payload_attempt(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid)',
    'echo_identity.runtime_recoverable_idempotent_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text)',
    'echo_identity.runtime_mark_private_payload_committed(uuid,text)',
    'echo_identity.runtime_abandon_private_payload_attempt(uuid,text)',
    'echo_identity.runtime_claim_stale_private_payload_attempt(uuid)',
    'echo_identity.runtime_mark_private_payload_discarded(uuid)',
    'echo_identity.runtime_get_private_payload_attempt(uuid)',
    'echo_identity.runtime_list_private_payload_recovery(integer)',
])


class WriterPoolError(Exception):
    """Safe category only; never include DSN/password/token/driver traceback."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class WriterPool:
    """Fail-closed synchronous pool for recoverable PRIVATE draft DB calls only.

    A lease is one DB transaction. Successful exit commits once; exceptional exit
    rolls back. Neither connection creation nor reset replays SQL. If commit or reset
    becomes uncertain, the error escapes and the connection is discarded. The higher
    recoverable/idempotent layer owns reconciliation using its durable attempt ledger.
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
            raise WriterPoolError('INVALID_SERVICE_CONFIG')
        insecure_test = (allow_insecure_test_loopback is True and host == '127.0.0.1'
                         and dbname == 'echo_writer_pool_test')
        if sslmode != 'verify-full' and not (insecure_test and sslmode == 'disable'):
            raise WriterPoolError('VERIFIED_TLS_REQUIRED')
        self._dbname = dbname
        kwargs = dict(host=host, port=port, dbname=dbname, user=SERVICE,
                      password=password, sslmode=sslmode, connect_timeout=3,
                      autocommit=True, prepare_threshold=None, row_factory=tuple_row,
                      options='-c search_path=pg_catalog -c statement_timeout=10000 '
                              '-c lock_timeout=6000 -c idle_in_transaction_session_timeout=15000')
        if sslrootcert is not None:
            kwargs['sslrootcert'] = sslrootcert
        self._pool = ConnectionPool(conninfo='', kwargs=kwargs, min_size=0,
                                    max_size=max_size, max_waiting=8, timeout=3,
                                    open=False, name='echo-private-writer')

    def open(self) -> None:
        self._pool.open()

    def close(self) -> None:
        self._pool.close(timeout=5)

    def _validate_authority(self, c: Connection) -> None:
        if c.info.user != SERVICE:
            raise WriterPoolError('SERVICE_LOGIN_REQUIRED')
        if c.execute('SELECT session_user,current_user,current_database()', prepare=False).fetchone() != (SERVICE, SERVICE, self._dbname):
            raise WriterPoolError('SERVICE_BASELINE_REQUIRED')
        roles = c.execute('''SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,
                    rolcreaterole,rolreplication,rolbypassrls
                    FROM pg_catalog.pg_roles WHERE rolname=ANY(%s) ORDER BY rolname''',
                    ([RUNTIME, SERVICE],), prepare=False).fetchall()
        expected = [(RUNTIME,False,False,False,False,False,False,False),
                    (SERVICE,True,False,False,False,False,False,False)]
        if roles != expected:
            raise WriterPoolError('ROLE_POLICY_DRIFT')
        memberships = c.execute('''SELECT member.rolname,parent.rolname,
                    m.admin_option,m.inherit_option,m.set_option
                    FROM pg_catalog.pg_auth_members m
                    JOIN pg_catalog.pg_roles member ON member.oid=m.member
                    JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
                    WHERE member.rolname=ANY(%s)''', ([SERVICE,RUNTIME],), prepare=False).fetchall()
        if memberships != [(SERVICE,RUNTIME,False,False,True)]:
            raise WriterPoolError('ROLE_MEMBERSHIP_DRIFT')
        unsafe = c.execute('''SELECT EXISTS (
          SELECT 1 FROM pg_catalog.pg_class t
          JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
          CROSS JOIN unnest(%s::text[]) r(name)
          WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p','v','m','f') AND (
            pg_catalog.has_table_privilege(r.name,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
            pg_catalog.has_any_column_privilege(r.name,t.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
        )''', ([SERVICE,RUNTIME],SCHEMAS), prepare=False).fetchone()[0]
        if unsafe:
            raise WriterPoolError('DIRECT_TABLE_PRIVILEGE_DRIFT')
        allowed = [x[0] for x in c.execute('''SELECT p.oid::regprocedure::text
                    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                    WHERE n.nspname=ANY(%s) AND pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE')
                    ORDER BY 1''', (SCHEMAS,RUNTIME), prepare=False).fetchall()]
        if allowed != ALLOWED_FUNCTIONS:
            raise WriterPoolError('FUNCTION_PRIVILEGE_DRIFT')
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
            raise WriterPoolError('SERVICE_PRIVILEGE_DRIFT')

    def _sanitize(self, c: Connection) -> None:
        if c.closed or c.info.transaction_status == TransactionStatus.UNKNOWN:
            raise WriterPoolError('BROKEN_SERVICE_CONNECTION')
        if c.info.user != SERVICE:
            raise WriterPoolError('SERVICE_LOGIN_REQUIRED')
        if c.info.transaction_status != TransactionStatus.IDLE:
            c.rollback()
        c.autocommit = True
        c.prepare_threshold = None
        c.row_factory = tuple_row
        c.execute('DISCARD ALL', prepare=False)
        c.execute('SET SESSION search_path = pg_catalog', prepare=False)
        c.execute('SET SESSION row_security = on', prepare=False)
        c.execute("SET SESSION TimeZone = 'UTC'", prepare=False)
        c.execute("SET SESSION statement_timeout = '10s'", prepare=False)
        c.execute("SET SESSION lock_timeout = '6s'", prepare=False)
        c.execute("SET SESSION idle_in_transaction_session_timeout = '15s'", prepare=False)
        self._validate_authority(c)
        if c.info.transaction_status != TransactionStatus.IDLE:
            raise WriterPoolError('NONIDLE_POOL_BASELINE')

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        try:
            c = self._pool.getconn(timeout=3)
        except Exception:
            raise WriterPoolError('SERVICE_CONNECTION_UNAVAILABLE') from None
        body_failed = False
        cleanup_failed = False
        try:
            try:
                self._sanitize(c)
            except WriterPoolError:
                c.close()
                raise
            except Exception:
                c.close()
                raise WriterPoolError('POOL_RESET_FAILED') from None
            with c.transaction():
                c.execute('SET LOCAL ROLE echo_private_draft_runtime', prepare=False)
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE,RUNTIME):
                    raise WriterPoolError('LEASE_ROLE_REQUIRED')
                yield c
                if c.closed or c.info.transaction_status != TransactionStatus.INTRANS:
                    raise WriterPoolError('LEASE_TRANSACTION_CHANGED')
                if c.execute('SELECT session_user,current_user', prepare=False).fetchone() != (SERVICE,RUNTIME):
                    raise WriterPoolError('LEASE_ROLE_CHANGED')
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
                # The transaction may already have committed. Never replay here.
                raise WriterPoolError('POOL_RESET_FAILED') from None
