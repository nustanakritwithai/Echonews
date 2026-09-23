// Integration tests only: psql is a test driver, NOT the production DB adapter.
// Every pg() call opens a new connection: committed mappings/revocations must persist.
import test, {before,after} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {randomUUID,createHash} from 'node:crypto';
import {createSessionResolver} from './session_boundary.mjs';
import {bindCreateVoice} from '../p2_1c2b/command_boundary.mjs';

if(process.env.ECHO_DISPOSABLE_PG!=='YES' || process.env.PGDATABASE!=='echo_session_test' ||
   !['127.0.0.1','localhost'].includes(process.env.PGHOST)) {
  throw Error('Refusing destructive integration fixture outside isolated echo_session_test on loopback');
}
function pg(sql,params={}) {
  const args=['-X','-qAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose'];
  for(const [key,value] of Object.entries(params)) args.push('-v',`${key}=${value}`);
  return execFileSync('psql',args,{input:sql,encoding:'utf8',timeout:10000,stdio:['pipe','pipe','pipe']}).trim();
}
const q=x=>"'"+String(x).replaceAll("'","''")+"'"; // Synthetic setup only; lookup uses psql quoted variables.
const N=1800000000000,ISSUER='https://identity.example.test',AUDIENCE='echo-api';
let installed=false;
before(()=>{
  assert.equal(pg('SELECT current_database();'),'echo_session_test');
  assert.equal(pg("SELECT to_regnamespace('echo_core') IS NULL AND to_regnamespace('echo_identity') IS NULL;"),'t');
  const base=readFileSync(new URL('../../database/p2_1b/schema.sql',import.meta.url),'utf8');
  const migration=readFileSync(new URL('../../database/p2_1c2c/001_identity_registry.sql',import.meta.url),'utf8');
  pg('BEGIN;\n'+base+'\n'+migration+`\nCREATE ROLE echo_session_outsider NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;\nCOMMIT;`);
  installed=true;
});
after(()=>{
  if(!installed)return;
  pg('BEGIN; DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_core CASCADE; DROP ROLE echo_session_outsider; COMMIT;');
  assert.equal(pg("SELECT to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_core') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='echo_session_outsider');"),'t');
  console.log('CLEAN_ISOLATED_IDENTITY_DATABASE');
});
function fixture({issuer=ISSUER,subject='User-'+randomUUID(),writer=true,reviewer=false}={}) {
  const f={issuer,subject,principalId:randomUUID(),actorId:randomUUID(),sourceId:randomUUID(),key:createHash('sha256').update(randomUUID()).digest('hex')};
  pg(`BEGIN;
   INSERT INTO echo_core.actors VALUES (${q(f.actorId)},'HUMAN','Synthetic account',now());
   INSERT INTO echo_core.sources VALUES (${q(f.sourceId)},'ACCOUNT',NULL,'UNKNOWN',now());
   INSERT INTO echo_identity.principals(principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled)
   VALUES (${q(f.principalId)},${q(issuer)},${q(subject)},${q(f.actorId)},${q(f.sourceId)},true,${writer},${reviewer});
   INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
   VALUES (${q(f.key)},${q(f.principalId)},1,to_timestamp(${(N-10000)/1000}),to_timestamp(${(N+60000)/1000}));
   COMMIT;`);
  f.verified={tokenUse:'ECHO_API_ACCESS',issuer,subject,audiences:[AUDIENCE],sessionKey:f.key,
    issuedAtMs:N-10000,notBeforeMs:N-10000,expiresAtMs:N+120000};
  f.resolve=createSessionResolver({issuer,audience:AUDIENCE,now:()=>N,
    verifyCredential:async()=>({...f.verified}), // Deliberate fake verifier, no real login claim.
    loadSnapshot:async lookup=>lookupSnapshot(lookup)});
  return f;
}
function lookupSnapshot({issuer,subject,sessionKey}) {
  const raw=pg("SELECT echo_identity.lookup_session(:'issuer', :'subject', :'key');",{issuer,subject,key:sessionKey});
  return raw?JSON.parse(raw):null;
}
function denied(f,role='writer',code='UNAUTHENTICATED') {return assert.rejects(()=>f.resolve('fixture-credential',role),e=>e.code===code);}
function sqlReject(sql,code) {assert.throws(()=>pg(sql),e=>String(e.stderr).includes(code));}
function change(f,sql) {pg(`UPDATE echo_identity.principals SET ${sql},auth_version=auth_version+1 WHERE principal_id=${q(f.principalId)};`);}
function newSession(f,version) {
  const key=createHash('sha256').update(randomUUID()).digest('hex');
  pg(`INSERT INTO echo_identity.sessions VALUES(${q(key)},${q(f.principalId)},${version},to_timestamp(${(N-1)/1000}),to_timestamp(${(N+60000)/1000}),false);`);
  f.verified.sessionKey=key;
  return key;
}

test('01 schema installs and current mapping survives new connections',async()=>{
  const f=fixture(),a=await f.resolve('fixture','writer'),b=await f.resolve('fixture','writer');
  assert.equal(a.actorId,f.actorId);assert.equal(b.sourceId,f.sourceId);
  assert.deepEqual(a,b);
});
test('02 same subject at different issuers is not the same identity',async()=>{
  const a=fixture({subject:'same-user',issuer:ISSUER}),b=fixture({subject:'same-user',issuer:'https://other.example.test'});
  assert.notEqual((await a.resolve('fixture','writer')).actorId,(await b.resolve('fixture','writer')).actorId);
  b.verified.sessionKey=a.key;await denied(b);
});
test('03 subject and issuer comparisons preserve case and trailing separators',()=>{
  const f=fixture({subject:'CaseSensitive'});
  for(const [issuer,subject] of [[ISSUER,'casesensitive'],[ISSUER+'/','CaseSensitive'],[ISSUER,'CaseSensitive ']])
    assert.equal(lookupSnapshot({issuer,subject,sessionKey:f.key}),null);
});
test('04 duplicate issuer+subject cannot be rebound to another actor',()=>{
  const f=fixture(),a=randomUUID(),src=randomUUID();
  pg(`INSERT INTO echo_core.actors VALUES(${q(a)},'HUMAN','Duplicate-key fixture',now());
      INSERT INTO echo_core.sources VALUES(${q(src)},'ACCOUNT',NULL,'UNKNOWN',now());`);
  sqlReject(`INSERT INTO echo_identity.principals(principal_id,issuer,subject,actor_id,source_id)
    VALUES(${q(randomUUID())},${q(f.issuer)},${q(f.subject)},${q(a)},${q(src)});`,'23505');
});
test('05 immutable account tuple rejects actor/source/subject retargeting',()=>{
  const f=fixture(),g=fixture();
  for(const field of ['actor_id','source_id','subject']) {
    const value=field==='actor_id'?g.actorId:field==='source_id'?g.sourceId:'another';
    sqlReject(`UPDATE echo_identity.principals SET ${field}=${q(value)},auth_version=2 WHERE principal_id=${q(f.principalId)};`,'55000');
  }
});
test('06 privilege or enable changes require a new auth generation',()=>{
  const f=fixture();
  for(const set of ['enabled=false','reviewer_enabled=true','auth_version=0','auth_version=3'])
    sqlReject(`UPDATE echo_identity.principals SET ${set} WHERE principal_id=${q(f.principalId)};`,'23514');
});
test('07 disabling principal blocks next fresh lookup despite an unexpired credential',async()=>{
  const f=fixture();await f.resolve('fixture','writer');change(f,'enabled=false');await denied(f);
});
test('08 re-enabling account does not resurrect sessions from prior generations',async()=>{
  const f=fixture();change(f,'enabled=false');change(f,'enabled=true');await denied(f);
  newSession(f,3);assert.equal((await f.resolve('fixture','writer')).actorId,f.actorId);
});
test('09 committed revocation stops next request on a new connection',async()=>{
  const f=fixture();await f.resolve('fixture','writer');
  pg(`UPDATE echo_identity.sessions SET revoked=true WHERE session_key=${q(f.key)};`);await denied(f);
});
test('10 revoked session cannot be restored, extended or given to a new principal',()=>{
  const f=fixture(),g=fixture();pg(`UPDATE echo_identity.sessions SET revoked=true WHERE session_key=${q(f.key)};`);
  for(const set of ['revoked=false',"expires_at=expires_at+interval '1 day'",`principal_id=${q(g.principalId)}`])
    sqlReject(`UPDATE echo_identity.sessions SET ${set} WHERE session_key=${q(f.key)};`,'55000');
});
test('11 removing reviewer permission rejects old session and keeps new writer-only session bounded',async()=>{
  const f=fixture({reviewer:true});await f.resolve('fixture','reviewer');change(f,'reviewer_enabled=false');
  await denied(f,'reviewer');newSession(f,2);await denied(f,'reviewer','FORBIDDEN');
  assert.deepEqual((await f.resolve('fixture','writer')).roles,['writer']);
});
test('12 unknown session/identity does not auto-provision',async()=>{
  const f=fixture();const beforeCount=pg('SELECT count(*) FROM echo_identity.principals;');
  f.verified.sessionKey='f'.repeat(64);await denied(f);
  assert.equal(pg('SELECT count(*) FROM echo_identity.principals;'),beforeCount);
});
test('13 subject quote is a literal lookup value, not SQL or an alias',async()=>{
  const f=fixture({subject:"x'; SELECT 1; --"});assert.equal((await f.resolve('fixture','writer')).actorId,f.actorId);
  f.verified.subject="' OR true --";await denied(f);
});
test('14 outsider cannot read mappings, call lookup or grant themselves rights',()=>{
  for(const statement of [
    'SELECT * FROM echo_identity.principals',
    `SELECT echo_identity.lookup_session('a','b','c')`,
    'UPDATE echo_identity.principals SET reviewer_enabled=true,auth_version=auth_version+1'
  ]) sqlReject(`SET ROLE echo_session_outsider; ${statement};`,'42501');
});
test('15 durable account cannot bind missing source or non-human actor',()=>{
  const actor=randomUUID(),source=randomUUID();pg(`INSERT INTO echo_core.actors VALUES(${q(actor)},'AI','Synthetic AI',now());
    INSERT INTO echo_core.sources VALUES(${q(source)},'ACCOUNT',NULL,'UNKNOWN',now());`);
  sqlReject(`INSERT INTO echo_identity.principals(principal_id,issuer,subject,actor_id,source_id)
    VALUES(${q(randomUUID())},${q(ISSUER)},'nonhuman',${q(actor)},${q(source)});`,'23503');
  const human=randomUUID();pg(`INSERT INTO echo_core.actors VALUES(${q(human)},'HUMAN','Missing-source fixture',now());`);
  sqlReject(`INSERT INTO echo_identity.principals(principal_id,issuer,subject,actor_id,source_id)
    VALUES(${q(randomUUID())},${q(ISSUER)},'missing-source',${q(human)},${q(randomUUID())});`,'23503');
});
test('16 session provisioning rejects disabled/stale authority and bad intervals',()=>{
  const f=fixture();change(f,'enabled=false');
  sqlReject(`INSERT INTO echo_identity.sessions VALUES(${q('e'.repeat(64))},${q(f.principalId)},2,now(),now()+interval '1 hour',false);`,'23514');
  change(f,'enabled=true');
  sqlReject(`INSERT INTO echo_identity.sessions VALUES(${q('e'.repeat(64))},${q(f.principalId)},1,now(),now()+interval '1 hour',false);`,'23514');
  sqlReject(`INSERT INTO echo_identity.sessions VALUES(${q('e'.repeat(64))},${q(f.principalId)},3,now(),now()-interval '1 hour',false);`,'23514');
});
test('17 delete/truncate cannot make old identifiers reusable by normal DML',()=>{
  const f=fixture();
  sqlReject(`DELETE FROM echo_identity.sessions WHERE session_key=${q(f.key)};`,'55000');
  sqlReject('TRUNCATE echo_identity.principals CASCADE;','55000');
});
test('18 failed transaction removes earlier provisioning writes as well',()=>{
  const f=fixture(),id=randomUUID(),a=randomUUID(),src=randomUUID();
  sqlReject(`BEGIN;
    INSERT INTO echo_core.actors VALUES(${q(a)},'HUMAN','Rollback fixture',now());
    INSERT INTO echo_core.sources VALUES(${q(src)},'ACCOUNT',NULL,'UNKNOWN',now());
    INSERT INTO echo_identity.principals(principal_id,issuer,subject,actor_id,source_id)
    VALUES(${q(id)},${q(f.issuer)},${q(f.subject)},${q(a)},${q(src)}); COMMIT;`,'23505');
  assert.equal(pg(`SELECT count(*) FROM echo_identity.principals WHERE principal_id=${q(id)};`),'0');
  assert.equal(pg(`SELECT count(*) FROM echo_core.actors WHERE actor_id=${q(a)};`),'0');
  assert.equal(pg(`SELECT count(*) FROM echo_core.sources WHERE source_id=${q(src)};`),'0');
});
test('19 resolver output from real DB feeds unchanged voice command contract',async()=>{
  const f=fixture(),auth=await f.resolve('fixture','writer');
  const command=bindCreateVoice({content:'synthetic post'},auth,{newUuid:()=>randomUUID(),storePayload:()=> 'fixture:payload',now:()=>new Date(N).toISOString()});
  assert.equal(command.authorId,f.actorId);assert.equal(command.sourceId,f.sourceId);assert.equal(command.visibility,'PRIVATE');
});
test('20 new principal defaults disabled and has no reviewer/writer grants',()=>{
  const a=randomUUID(),s=randomUUID(),p=randomUUID();
  pg(`INSERT INTO echo_core.actors VALUES(${q(a)},'HUMAN','Disabled fixture',now());
      INSERT INTO echo_core.sources VALUES(${q(s)},'ACCOUNT',NULL,'UNKNOWN',now());
      INSERT INTO echo_identity.principals(principal_id,issuer,subject,actor_id,source_id)
      VALUES(${q(p)},${q(ISSUER)},${q('new-'+p)},${q(a)},${q(s)});`);
  assert.equal(pg(`SELECT NOT enabled AND NOT writer_enabled AND NOT reviewer_enabled FROM echo_identity.principals WHERE principal_id=${q(p)};`),'t');
});
