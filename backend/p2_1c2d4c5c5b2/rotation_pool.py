"""Fixed-role rotation pool; trusted backend only, not a general SQL endpoint.
Uses the established transaction/reset protocol without changing existing pools.
"""
from contextlib import contextmanager
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool

SERVICE = 'echo_session_rotation_service'
RUNTIME = 'echo_session_rotation_runtime'
GUARD = 'echo_session_rotation_guard'
FUNCTION = 'echo_identity.runtime_rotate_active_session(text,text,text,bigint,bigint,bigint)'


class RotationPoolError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class RotationPool:
    def __init__(self, *, host, port, dbname, user, password, sslmode='verify-full',
                 sslrootcert=None, max_size=2, allow_insecure_test_loopback=False):
        if (type(host) is not str or not host or ',' in host
                or type(port) is not int or not 1<=port<=65535
                or type(dbname) is not str or not dbname or user!=SERVICE
                or type(password) is not str or not password
                or type(max_size) is not int or not 1<=max_size<=4):
            raise RotationPoolError('INVALID_SERVICE_CONFIG')
        insecure = (allow_insecure_test_loopback is True and host=='127.0.0.1'
                    and dbname=='echo_first_session_test')
        if sslmode!='verify-full' and not (insecure and sslmode=='disable'):
            raise RotationPoolError('VERIFIED_TLS_REQUIRED')
        self._dbname = dbname
        kwargs = dict(host=host,port=port,dbname=dbname,user=SERVICE,password=password,
            sslmode=sslmode,connect_timeout=3,autocommit=True,prepare_threshold=None,row_factory=tuple_row,
            options='-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=3000 '
                    '-c idle_in_transaction_session_timeout=10000')
        if sslrootcert is not None:
            kwargs['sslrootcert'] = sslrootcert
        self._pool = ConnectionPool(conninfo='',kwargs=kwargs,min_size=0,max_size=max_size,
            max_waiting=8,timeout=3,open=False,name='echo-session-rotation')

    def open(self):
        self._pool.open()

    def close(self):
        self._pool.close(timeout=5)

    def _validate_authority(self,c):
        if c.info.user!=SERVICE or c.execute('SELECT session_user,current_user,current_database()',
                prepare=False).fetchone()!=(SERVICE,SERVICE,self._dbname):
            raise RotationPoolError('SERVICE_LOGIN_REQUIRED')
        roles=c.execute('''SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,
            rolcreaterole,rolreplication,rolbypassrls FROM pg_roles
            WHERE rolname=ANY(%s) ORDER BY rolname''',([GUARD,RUNTIME,SERVICE],),prepare=False).fetchall()
        if roles!=[(GUARD,False,False,False,False,False,False,False),
                   (RUNTIME,False,False,False,False,False,False,False),
                   (SERVICE,True,False,False,False,False,False,False)]:
            raise RotationPoolError('ROLE_POLICY_DRIFT')
        membership=c.execute('''SELECT m.rolname,p.rolname,a.admin_option,a.inherit_option,a.set_option
            FROM pg_auth_members a JOIN pg_roles m ON m.oid=a.member JOIN pg_roles p ON p.oid=a.roleid
            WHERE m.rolname=ANY(%s) OR p.rolname=ANY(%s) ORDER BY 1,2''',
            ([SERVICE,RUNTIME,GUARD],[SERVICE,RUNTIME,GUARD]),prepare=False).fetchall()
        if membership!=[(SERVICE,RUNTIME,False,False,True)]:
            raise RotationPoolError('ROLE_MEMBERSHIP_DRIFT')
        tables=c.execute('''SELECT EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
            CROSS JOIN unnest(%s::text[]) r(name)
            WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p','v','m','f') AND (
              has_table_privilege(r.name,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              OR has_any_column_privilege(r.name,t.oid,'SELECT,INSERT,UPDATE,REFERENCES')))''',
            ([SERVICE,RUNTIME],['echo_identity','echo_core']),prepare=False).fetchone()[0]
        if tables:
            raise RotationPoolError('DIRECT_TABLE_PRIVILEGE_DRIFT')
        functions=c.execute('''SELECT p.oid::regprocedure::text FROM pg_proc p
            JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='echo_identity'
            AND has_function_privilege(%s,p.oid,'EXECUTE') ORDER BY 1''',(RUNTIME,),prepare=False).fetchall()
        if functions!=[(FUNCTION,)]:
            raise RotationPoolError('FUNCTION_PRIVILEGE_DRIFT')
        direct=c.execute('''SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='echo_identity' AND has_function_privilege(%s,p.oid,'EXECUTE'))''',
            (SERVICE,),prepare=False).fetchone()[0]
        create=c.execute('''SELECT EXISTS(SELECT 1 FROM unnest(%s::text[]) r(name) WHERE
            has_database_privilege(r.name,current_database(),'CREATE') OR EXISTS(
              SELECT 1 FROM pg_namespace n WHERE n.nspname=ANY(%s)
                AND has_schema_privilege(r.name,n.oid,'CREATE')))''',
            ([SERVICE,RUNTIME],['echo_identity','echo_core','public']),prepare=False).fetchone()[0]
        sealed=c.execute('''SELECT r.rolname,p.prosecdef,p.proconfig FROM pg_proc p
            JOIN pg_roles r ON r.oid=p.proowner JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='echo_identity' AND p.oid::regprocedure::text=%s''',(FUNCTION,),prepare=False).fetchone()
        if direct or create or sealed is None or sealed[:2]!=(GUARD,True):
            raise RotationPoolError('SERVICE_PRIVILEGE_DRIFT')
        if set(sealed[2] or [])!={'search_path=pg_catalog, pg_temp','row_security=on'}:
            raise RotationPoolError('FUNCTION_CONFIG_DRIFT')

    def _sanitize(self,c):
        if c.closed or c.info.transaction_status==TransactionStatus.UNKNOWN:
            raise RotationPoolError('BROKEN_SERVICE_CONNECTION')
        if c.info.user!=SERVICE:
            raise RotationPoolError('SERVICE_LOGIN_REQUIRED')
        if c.info.transaction_status!=TransactionStatus.IDLE:
            c.rollback()
        c.autocommit=True
        c.prepare_threshold=None
        c.row_factory=tuple_row
        c.execute('DISCARD ALL',prepare=False)
        for statement in ('SET SESSION search_path=pg_catalog','SET SESSION row_security=on',
            "SET SESSION TimeZone='UTC'","SET SESSION statement_timeout='5s'",
            "SET SESSION lock_timeout='3s'","SET SESSION idle_in_transaction_session_timeout='10s'",
            "SET SESSION default_transaction_isolation='read committed'"):
            c.execute(statement,prepare=False)
        self._validate_authority(c)
        if c.info.transaction_status!=TransactionStatus.IDLE:
            raise RotationPoolError('NONIDLE_POOL_BASELINE')

    @contextmanager
    def connection(self):
        try:
            c=self._pool.getconn(timeout=3)
        except Exception:
            raise RotationPoolError('SERVICE_CONNECTION_UNAVAILABLE') from None
        body_failed=cleanup_failed=False
        try:
            try:
                self._sanitize(c)
            except RotationPoolError:
                c.close()
                raise
            except Exception:
                c.close()
                raise RotationPoolError('POOL_RESET_FAILED') from None
            with c.transaction():
                c.execute('SET LOCAL ROLE echo_session_rotation_runtime',prepare=False)
                if c.execute('SELECT session_user,current_user',prepare=False).fetchone()!=(SERVICE,RUNTIME):
                    raise RotationPoolError('LEASE_ROLE_REQUIRED')
                yield c
                if c.closed or c.info.transaction_status!=TransactionStatus.INTRANS:
                    raise RotationPoolError('LEASE_TRANSACTION_CHANGED')
                if c.execute('SELECT session_user,current_user',prepare=False).fetchone()!=(SERVICE,RUNTIME):
                    raise RotationPoolError('LEASE_ROLE_CHANGED')
        except BaseException:
            body_failed=True
            raise
        finally:
            try:
                if not c.closed:
                    self._sanitize(c)
            except BaseException:
                cleanup_failed=True
                c.close()
            finally:
                self._pool.putconn(c)
            if cleanup_failed and not body_failed:
                raise RotationPoolError('POOL_RESET_FAILED') from None
