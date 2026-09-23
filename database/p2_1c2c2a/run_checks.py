"""Real PostgreSQL registry checks through separate psql connections.
Only for a dedicated, empty, localhost CI database named echo_registry_test.
No real token, signing key, user, HTTP server or production DB is used.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unittest
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / 'results'
OUT.mkdir(exist_ok=True)
ADMIN = 'echo_identity_admin'
READER = 'echo_identity_resolver'
OWNER = 'echo_identity_owner'
ISSUER = 'https://issuer.fixture.invalid/echo'
ROLE_NAMES = (OWNER, ADMIN, READER, 'echo_public_reader')
SCHEMA_NAMES = ('echo_identity', 'echo_public', 'echo_history', 'echo_core')


def q(value):
    """Only test fixtures use SQL literals. Future production adapters MUST bind parameters."""
    if value is None:
        return 'NULL'
    return "'" + str(value).replace("'", "''") + "'"


def psql(sql, role=None, files=()):
    env = dict(os.environ)
    env['PGOPTIONS'] = '-c statement_timeout=8000 -c lock_timeout=5000 -c standard_conforming_strings=on'
    args = ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose']
    if files:
        args += ['--single-transaction']
        for path in files:
            args += ['-f', str(path)]
        raw = None
    else:
        raw = (f'SET SESSION AUTHORIZATION {role}; SET ROLE {role};\n' if role else '') + sql
    return subprocess.run(args, input=raw, text=True, capture_output=True, env=env, timeout=30)


def run(sql, role=None):
    p = psql(sql, role)
    if p.returncode:
        raise AssertionError(p.stderr)
    return p.stdout.strip()


def resolve_sql(issuer, subject, jti='fixture-jti', iat=100):
    return ("SELECT coalesce(json_agg(r),'[]'::json) FROM "
            f"echo_identity.resolve_principal({q(issuer)},{q(subject)},{q(jti)},{iat if iat is not None else 'NULL'}) r;")


def resolve(f, jti='fixture-jti', iat=100):
    return json.loads(run(resolve_sql(f['issuer'], f['subject'], jti, iat), READER))


def revise_sql(f, expected=1, enabled=True, caps=('voice:draft:create',), cutoff=0, reason='ACCESS_CHANGE'):
    ar = 'NULL' if caps is None else 'ARRAY['+','.join(q(c) for c in caps)+']::text[]'
    b = 'NULL' if enabled is None else str(enabled).lower()
    return (f"SELECT echo_identity.revise_access({q(f['principal'])},{expected},{b},{ar},"
            f"{cutoff if cutoff is not None else 'NULL'},{q(reason)});")


def fixture(enabled=True, kind='HUMAN', issuer=ISSUER, subject=None):
    actor, source = str(uuid4()), str(uuid4())
    subject = subject or 'subject-'+uuid4().hex
    run(f"INSERT INTO echo_core.actors VALUES({q(actor)},{q(kind)},'Synthetic fixture',clock_timestamp());"
        f"INSERT INTO echo_core.sources(source_id,source_kind,recorded_at) VALUES({q(source)},'ACCOUNT',clock_timestamp());")
    principal = run(f"SELECT echo_identity.provision({q(issuer)},{q(subject)},{q(actor)},{q(source)});", ADMIN)
    f = {'principal': principal, 'issuer': issuer, 'subject': subject, 'actor': actor, 'source': source}
    if enabled:
        run(revise_sql(f), ADMIN)
    return f


class RegistryTests(unittest.TestCase):
    def denied(self, sql, code, role=None):
        p = psql(sql, role)
        self.assertNotEqual(p.returncode, 0, 'unexpected SQL success')
        m = re.search(r'ERROR:\s+([0-9A-Z]{5})\b', p.stderr)
        self.assertIsNotNone(m, p.stderr)
        self.assertEqual(m.group(1), code, p.stderr)

    def test_01_new_principal_is_disabled_without_capabilities(self):
        f = fixture(False)
        self.assertEqual(resolve(f), [])
        self.assertEqual(run(f"SELECT enabled,cardinality(capabilities),revision FROM echo_identity.access_revisions WHERE principal_id={q(f['principal'])};"), 'f|0|1')

    def test_02_durable_mapping_survives_new_connections(self):
        f = fixture()
        a, b = resolve(f), resolve(f)
        self.assertEqual(a, b)
        self.assertEqual(a[0]['actor_id'], f['actor'])
        self.assertEqual(a[0]['source_id'], f['source'])
        self.assertEqual(a[0]['binding_revision'], 2)
        self.assertIs(a[0]['ready_for_execution'], False)

    def test_03_unmapped_subject_not_auto_provisioned(self):
        before = run('SELECT count(*) FROM echo_identity.principals;')
        self.assertEqual(json.loads(run(resolve_sql(ISSUER,'does-not-exist'),READER)), [])
        self.assertEqual(run('SELECT count(*) FROM echo_identity.principals;'), before)

    def test_04_same_subject_different_issuer_is_different_principal(self):
        subject = 'same-'+uuid4().hex
        a = fixture(subject=subject)
        b = fixture(issuer='https://other.fixture.invalid/echo', subject=subject)
        self.assertNotEqual(resolve(a)[0]['actor_id'], resolve(b)[0]['actor_id'])

    def test_05_subject_and_issuer_are_case_sensitive(self):
        f = fixture(subject='CaseSensitive-'+uuid4().hex)
        self.assertEqual(json.loads(run(resolve_sql(f['issuer'],f['subject'].lower()),READER)), [])
        self.assertEqual(json.loads(run(resolve_sql(f['issuer'].upper(),f['subject']),READER)), [])

    def test_06_duplicate_issuer_subject_is_not_remapped(self):
        f, other = fixture(), fixture()
        self.denied(f"SELECT echo_identity.provision({q(f['issuer'])},{q(f['subject'])},{q(other['actor'])},{q(other['source'])});",'23505',ADMIN)
        self.assertEqual(resolve(f)[0]['actor_id'], f['actor'])

    def test_07_actor_and_source_aliasing_rejected(self):
        a, b = fixture(), fixture()
        self.denied(f"SELECT echo_identity.provision({q(ISSUER)},'alias-{uuid4()}',{q(a['actor'])},{q(b['source'])});",'23505',ADMIN)

    def test_08_nonexistent_actor_denied(self):
        f = fixture()
        self.denied(f"SELECT echo_identity.provision({q(ISSUER)},'missing-actor',{q(uuid4())},{q(f['source'])});",'23503',ADMIN)

    def test_09_nonexistent_source_denied(self):
        f = fixture()
        self.denied(f"SELECT echo_identity.provision({q(ISSUER)},'missing-source',{q(f['actor'])},{q(uuid4())});",'23503',ADMIN)

    def test_10_unknown_actor_kind_denied(self):
        a,s = str(uuid4()),str(uuid4())
        run(f"INSERT INTO echo_core.actors VALUES({q(a)},'UNKNOWN','Fixture',clock_timestamp()); INSERT INTO echo_core.sources(source_id,source_kind,recorded_at) VALUES({q(s)},'ACCOUNT',clock_timestamp());")
        self.denied(f"SELECT echo_identity.provision({q(ISSUER)},'unknown-{uuid4()}',{q(a)},{q(s)});",'23514',ADMIN)

    def test_11_document_source_cannot_be_login_account(self):
        f = fixture()
        run(f"UPDATE echo_core.sources SET source_kind='DOCUMENT' WHERE source_id={q(f['source'])};")
        self.assertEqual(resolve(f), [])
        self.denied(f"SELECT echo_identity.provision({q(ISSUER)},'not-account',{q(f['actor'])},{q(f['source'])});",'23503',ADMIN)

    def test_12_actor_kind_cannot_be_rewritten_behind_binding(self):
        f = fixture()
        self.denied(f"UPDATE echo_core.actors SET actor_kind='AI' WHERE actor_id={q(f['actor'])};", '23503')

    def test_13_disable_visible_on_next_connection(self):
        f = fixture()
        self.assertEqual(len(resolve(f)), 1)
        run(revise_sql(f,2,False,(),0,'DISABLE'),ADMIN)
        self.assertEqual(resolve(f), [])

    def test_14_disable_advances_cutoff_and_reenable_does_not_revive_old_token(self):
        f = fixture()
        now = int(run('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint;'))
        run(revise_sql(f,2,False,(),0,'DISABLE'),ADMIN)
        cutoff = int(run(f"SELECT tokens_valid_from FROM echo_identity.access_revisions WHERE principal_id={q(f['principal'])} AND revision=3;"))
        self.assertGreater(cutoff,now)
        run(revise_sql(f,3,True,('voice:draft:create',),cutoff,'REENABLE'),ADMIN)
        self.assertEqual(resolve(f,iat=now), [])
        # Tests lookup cutoff only; future timestamps here are NOT verified tokens.
        self.assertEqual(len(resolve(f,iat=cutoff)),1)

    def test_15_cutoff_inclusive_and_cannot_decrease(self):
        f=fixture()
        run(revise_sql(f,2,True,('voice:draft:create',),200,'SESSION_CUTOFF'),ADMIN)
        self.assertEqual(resolve(f,iat=199),[])
        self.assertEqual(len(resolve(f,iat=200)),1)
        self.denied(revise_sql(f,3,True,('voice:draft:create',),199),'22023',ADMIN)

    def test_16_single_token_revocation_persists_across_connections(self):
        f=fixture()
        self.assertEqual(run(f"SELECT echo_identity.revoke_token({q(ISSUER)},'to-revoke');",ADMIN),'t')
        self.assertEqual(resolve(f,'to-revoke'),[])
        self.assertEqual(len(resolve(f,'not-revoked')),1)

    def test_17_revocation_is_issuer_scoped(self):
        a=fixture(issuer='https://issuer-a.fixture.invalid/echo')
        b=fixture(issuer='https://issuer-b.fixture.invalid/echo')
        run(f"SELECT echo_identity.revoke_token({q(a['issuer'])},'shared-jti');",ADMIN)
        self.assertEqual(resolve(a,'shared-jti'),[])
        self.assertEqual(len(resolve(b,'shared-jti')),1)

    def test_18_revocation_is_idempotent(self):
        f=fixture();j='revoke-'+uuid4().hex
        sql=f"SELECT echo_identity.revoke_token({q(f['issuer'])},{q(j)});"
        self.assertEqual(run(sql,ADMIN),'t');self.assertEqual(run(sql,ADMIN),'f')

    def test_19_revocation_stores_digest_not_raw_jti(self):
        f=fixture();j='fixture-sensitive-jti-'+uuid4().hex
        run(f"SELECT echo_identity.revoke_token({q(ISSUER)},{q(j)});",ADMIN)
        row=run("SELECT row_to_json(t) FROM echo_identity.token_revocations t ORDER BY revoked_at DESC LIMIT 1;")
        self.assertNotIn(j,row)
        self.assertIn(hashlib.sha256(j.encode()).hexdigest(),row)

    def test_20_capability_revocation_has_new_revision(self):
        f=fixture()
        run(revise_sql(f,2,True,(),0),ADMIN)
        result=resolve(f)[0]
        self.assertEqual(result['capabilities'],[])
        self.assertEqual(result['binding_revision'],3)
        self.assertEqual(run(f"SELECT capabilities[1] FROM echo_identity.access_revisions WHERE principal_id={q(f['principal'])} AND revision=2;"),'voice:draft:create')

    def test_21_review_capability_not_granted_to_ai(self):
        f=fixture(kind='AI')
        self.denied(revise_sql(f,2,True,('assessment:review',),0),'22023',ADMIN)
        self.assertEqual(resolve(f)[0]['actor_kind'],'AI')

    def test_22_human_review_capability_still_not_object_authorization(self):
        f=fixture()
        run(revise_sql(f,2,True,('assessment:review',),0),ADMIN)
        result=resolve(f)[0]
        self.assertEqual(result['capabilities'],['assessment:review'])
        self.assertFalse(result['ready_for_execution'])

    def test_23_stale_expected_revision_fails_without_appending(self):
        f=fixture()
        self.denied(revise_sql(f,1),'40001',ADMIN)
        self.assertEqual(resolve(f)[0]['binding_revision'],2)

    def test_24_competing_admins_one_wins_one_conflicts(self):
        f=fixture();sql=revise_sql(f,2,True,(),0)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(lambda _:psql(sql,ADMIN),range(2)))
        self.assertEqual(sum(p.returncode==0 for p in outcomes),1)
        failed=[p for p in outcomes if p.returncode][0]
        self.assertRegex(failed.stderr,r'ERROR:\s+40001\b')
        self.assertEqual(resolve(f)[0]['binding_revision'],3)

    def test_25_rollback_access_change_leaves_old_revision(self):
        f=fixture()
        run('BEGIN;'+revise_sql(f,2,False,(),0,'DISABLE')+'ROLLBACK;',ADMIN)
        self.assertEqual(resolve(f)[0]['binding_revision'],2)

    def test_26_rollback_revocation_leaves_token_usable(self):
        f=fixture();j='rollback-'+uuid4().hex
        run(f'BEGIN; SELECT echo_identity.revoke_token({q(ISSUER)},{q(j)}); ROLLBACK;',ADMIN)
        self.assertEqual(len(resolve(f,j)),1)

    def test_27_provision_and_disabled_revision_atomic(self):
        f=fixture();before=run('SELECT count(*) FROM echo_identity.principals;')
        self.denied(f"SELECT echo_identity.provision('http://untrusted','bad',{q(f['actor'])},{q(f['source'])});",'23514',ADMIN)
        self.assertEqual(run('SELECT count(*) FROM echo_identity.principals;'),before)

    def test_28_serializable_and_repeatable_read_rejected(self):
        f=fixture()
        for isolation in ('REPEATABLE READ','SERIALIZABLE'):
            self.denied('BEGIN ISOLATION LEVEL '+isolation+';'+resolve_sql(f['issuer'],f['subject']), '25001',READER)

    def test_29_admin_state_change_rejects_stale_snapshot_isolation(self):
        f=fixture()
        self.denied('BEGIN ISOLATION LEVEL REPEATABLE READ;'+revise_sql(f,2), '25001',ADMIN)

    def test_30_temp_tables_cannot_shadow_registry(self):
        f=fixture()
        result=run("CREATE TEMP TABLE principals(issuer text); SET search_path=pg_temp,public;"+resolve_sql(f['issuer'],f['subject']),READER)
        self.assertEqual(json.loads(result)[0]['actor_id'],f['actor'])

    def test_31_search_path_and_owner_not_superuser(self):
        result=run("SELECT bool_and(p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND p.prosecdef AND NOT r.rolsuper) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='echo_identity' AND p.proname IN ('provision','revise_access','revoke_token','resolve_principal');")
        self.assertEqual(result,'t')

    def test_32_roles_have_no_login_superuser_or_other_memberships(self):
        self.assertEqual(run("SELECT bool_and(NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) FROM pg_roles WHERE rolname LIKE 'echo_identity_%';"),'t')
        self.assertEqual(run("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname IN ('echo_identity_admin','echo_identity_resolver');"),'0')

    def test_33_owner_cannot_read_news_payload_tables(self):
        self.denied('SELECT * FROM echo_core.voice_revisions;','42501',OWNER)

    def test_34_reader_cannot_grant_itself_admin_role(self):
        self.denied('SET ROLE echo_identity_admin;','42501',READER)

    def test_35_reader_cannot_replace_function_or_disable_trigger(self):
        self.denied("ALTER FUNCTION echo_identity.resolve_principal(text,text,text,bigint) SECURITY INVOKER;",'42501',READER)
        self.denied('ALTER TABLE echo_identity.principals DISABLE TRIGGER reject_mutation;','42501',READER)

    def test_36_guarded_registry_rows_cannot_be_retargeted(self):
        for table in ('principals','access_revisions','token_revocations'):
            self.denied(f'DELETE FROM echo_identity.{table};','55000',OWNER)
            self.denied(f'TRUNCATE echo_identity.{table} CASCADE;','55000',OWNER)
        self.denied('UPDATE echo_identity.principals SET subject=subject WHERE false;','55000',OWNER)
        self.denied('UPDATE echo_identity.access_revisions SET enabled=true WHERE false;','55000',OWNER)

    def test_37_null_unknown_and_duplicate_capabilities_denied(self):
        f=fixture()
        for caps in (None,('admin',),('voice:draft:create','voice:draft:create'),(None,)):
            self.denied(revise_sql(f,2,True,caps,0),'22023',ADMIN)

    def test_38_disabled_record_cannot_retain_capabilities(self):
        f=fixture()
        self.denied(revise_sql(f,2,False,('voice:draft:create',),0,'DISABLE'),'23514',ADMIN)
        self.assertEqual(resolve(f)[0]['binding_revision'],2)

    def test_39_invalid_lookup_is_not_anonymous_fallback(self):
        f=fixture()
        for iss,sub,jti,iat in [(None,f['subject'],'a',100),(ISSUER,None,'a',100),(ISSUER,f['subject'],None,100),(ISSUER,f['subject'],'',100),(ISSUER,f['subject'],'a',None),(ISSUER,f['subject'],'a',-1)]:
            self.denied(resolve_sql(iss,sub,jti,iat),'22023',READER)

    def test_40_no_client_role_or_actor_parameter_on_resolver(self):
        f=fixture()
        self.denied(f"SELECT * FROM echo_identity.resolve_principal({q(ISSUER)},{q(f['subject'])},'x',100,'admin');",'42883',READER)

    def test_41_account_source_is_not_personhood_or_independence_claim(self):
        f=fixture();result=resolve(f)[0]
        self.assertNotIn('trust_score',result)
        self.assertNotIn('independent',result)
        self.assertNotIn('email',result)
        self.assertFalse(result['ready_for_execution'])

    def test_42_recorded_admin_identity_comes_from_database_role(self):
        f=fixture()
        result=run(f"SELECT active_db_role FROM echo_identity.access_revisions WHERE principal_id={q(f['principal'])} ORDER BY revision DESC LIMIT 1;")
        self.assertEqual(result,ADMIN)

    def test_43_quoted_subject_is_not_sql_instruction(self):
        f=fixture(subject="subject-' OR TRUE --")
        self.assertEqual(resolve(f)[0]['actor_id'],f['actor'])
        self.assertEqual(json.loads(run(resolve_sql(ISSUER,"' OR TRUE --"),READER)),[])

    def test_44_registry_outage_does_not_return_usable_context(self):
        f=fixture()
        # Controlled owner transaction; rollback restores ACL after probing failure.
        result=psql("BEGIN; REVOKE SELECT(source_id,source_kind) ON echo_core.sources FROM echo_identity_owner; SET LOCAL ROLE echo_identity_resolver;"+resolve_sql(f['issuer'],f['subject']))
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('"ready_for_execution":',result.stdout)
        self.assertEqual(len(resolve(f)),1)

    def test_45_no_implicit_js_writer_role_or_public_publish_capability(self):
        f=fixture();r=resolve(f)[0]
        self.assertEqual(r['capabilities'],['voice:draft:create'])
        self.assertNotIn('roles',r)
        self.assertNotIn('visibility',r)
        self.assertNotIn('writer',r['capabilities'])


def denied_table(role, table, operation):
    def test(self):
        stmt = {'select':f'SELECT * FROM echo_identity.{table};',
                'insert':f'INSERT INTO echo_identity.{table} DEFAULT VALUES;'}[operation]
        self.denied(stmt,'42501',role)
    return test

for role in (ADMIN,READER,'echo_public_reader'):
    for table in ('principals','access_revisions','token_revocations'):
        for operation in ('select','insert'):
            setattr(RegistryTests,f'test_acl_{role}_{table}_{operation}',denied_table(role,table,operation))


def denied_function(role, name):
    def test(self):
        f=fixture()
        statements={
            'provision':f"SELECT echo_identity.provision({q(ISSUER)},'x',{q(f['actor'])},{q(f['source'])});",
            'revise_access':revise_sql(f,2),
            'revoke_token':f"SELECT echo_identity.revoke_token({q(ISSUER)},'x');",
            'resolve_principal':resolve_sql(f['issuer'],f['subject']),
        }
        self.denied(statements[name],'42501',role)
    return test

for role,names in [(READER,('provision','revise_access','revoke_token')),('echo_public_reader',('provision','revise_access','revoke_token','resolve_principal'))]:
    for name in names:
        setattr(RegistryTests,f'test_acl_{role}_{name}',denied_function(role,name))


class Result(unittest.TextTestResult):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw);self.rows=[]
    def addSuccess(self,t):
        super().addSuccess(t);self.rows.append({'test':t.id(),'status':'SAT'})
    def addFailure(self,t,e):
        super().addFailure(t,e);self.rows.append({'test':t.id(),'status':'VIOL'})
    def addError(self,t,e):
        super().addError(t,e);self.rows.append({'test':t.id(),'status':'ERROR'})


def empty_space():
    schemas=','.join(q(x) for x in SCHEMA_NAMES)
    roles=','.join(q(x) for x in ROLE_NAMES)
    return run(f"SELECT NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ({schemas})) AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ({roles}));")=='t'


def cleanup():
    # Safety gate before setup established these names did not exist. Disposable only.
    run(';'.join('DROP SCHEMA IF EXISTS '+n+' CASCADE' for n in SCHEMA_NAMES)+';')
    # Remove default-privilege ownership dependencies created by the fixture owner.
    run('DROP OWNED BY echo_identity_owner;')
    run(';'.join('DROP ROLE IF EXISTS '+n for n in ROLE_NAMES)+';')
    return empty_space()


if __name__=='__main__':
    if (os.environ.get('ECHO_DISPOSABLE_REGISTRY_TEST')!='1'
        or os.environ.get('PGHOST') not in ('127.0.0.1','localhost')
        or os.environ.get('PGDATABASE')!='echo_registry_test'):
        raise SystemExit('Refusing: requires explicit dedicated localhost echo_registry_test database')
    if not empty_space():
        raise SystemExit('Refusing to modify existing Echo schemas or roles')
    stream=io.StringIO();result=None;clean=False;fatal=None
    server=run('SELECT version();')
    try:
        files=[ROOT/'database/p2_1b/schema.sql',ROOT/'database/p2_1c/001_immutable_history.sql',ROOT/'database/p2_1c2a/001_public_voice_read.sql',HERE/'001_principal_registry.sql']
        p=psql('',files=files)
        if p.returncode:
            raise AssertionError(p.stderr)
        result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(unittest.defaultTestLoader.loadTestsFromTestCase(RegistryTests))
    except Exception as exc:
        fatal=str(exc)
    finally:
        try:
            if not empty_space(): clean=cleanup()
            else: clean=True
        except Exception as exc:
            fatal=(fatal or '')+'\nCleanup failed: '+str(exc)
    text=stream.getvalue()+(('\nFATAL: '+fatal) if fatal else '')
    print(text);print('CLEAN_ISOLATED_DATABASE' if clean else 'CLEANUP_FAILED')
    (OUT/'runtime.txt').write_text(text,encoding='utf-8')
    passed=bool(result and result.wasSuccessful() and result.testsRun and not result.skipped and not fatal and clean)
    report={'task':'P2.1c.2c.2a','status':'SAT' if passed else 'VIOL','server':server,'tests':result.testsRun if result else 0,'failures':len(result.failures) if result else 0,'errors':len(result.errors) if result else 0,'skipped':len(result.skipped) if result else 0,'clean_isolated_database':clean,'fatal':fatal,'commit':os.environ.get('GITHUB_SHA'),'scope':'durable PostgreSQL registry and protected resolver only; no JWT/API/JS adapter','source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file() and p.suffix in ('.py','.sql')},'results':result.rows if result else []}
    (OUT/'registry_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('task','status','tests','failures','errors','clean_isolated_database')}))
    raise SystemExit(0 if passed else 1)
