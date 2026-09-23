import test from 'node:test';
import assert from 'node:assert/strict';
import { createSessionResolver, SessionBoundaryError } from './session_boundary.mjs';
import { bindCreateVoice, bindReviewAssessment } from '../p2_1c2b/command_boundary.mjs';

const N = 1800000000000;
const ISSUER = 'https://identity.example.test';
const AUDIENCE = 'echo-api';
const UUID = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  const f = { time: N, verifies: 0, reads: 0, key: 'a'.repeat(64) };
  f.verified = {tokenUse:'ECHO_API_ACCESS',issuer:ISSUER,subject:'User-A',audiences:[AUDIENCE],sessionKey:f.key,
    issuedAtMs:N-10000,notBeforeMs:N-10000,expiresAtMs:N+10000};
  f.snapshot = {
    principal: {principalId:UUID(1),issuer:ISSUER,subject:'User-A',actorId:UUID(2),sourceId:UUID(3),
      actorKind:'HUMAN',enabled:true,authVersion:3,writerEnabled:true,reviewerEnabled:false},
    session: {sessionKey:f.key,principalId:UUID(1),authVersion:3,issuedAtMs:N-10000,expiresAtMs:N+20000,revoked:false}
  };
  f.verify = async () => structuredClone(f.verified);
  f.load = async key => {f.lastLookup=key; return structuredClone(f.snapshot);};
  f.resolve = createSessionResolver({issuer:ISSUER,audience:AUDIENCE,now:()=>f.time,
    verifyCredential:async (token, policy)=>{f.verifies++;f.lastPolicy=policy;return f.verify(token,policy);},
    loadSnapshot:async key=>{f.reads++;return f.load(key);}});
  return f;
}
const rejects = (fn, code='UNAUTHENTICATED') => assert.rejects(fn, e=>e instanceof SessionBoundaryError && e.code===code);

test('valid session binds canonical actor/source rather than any claim hint', async()=>{
  const f=fixture();f.verified.actorId=UUID(99);f.verified.sourceId=UUID(98);f.verified.email='same@example.test';
  const a=await f.resolve('test-credential','writer');
  assert.equal(a.actorId,UUID(2));assert.equal(a.sourceId,UUID(3));assert.deepEqual(a.roles,['writer']);
  assert.equal(a.trusted,true);assert.equal(a.authenticated,true);
  assert.deepEqual(f.lastLookup,{issuer:ISSUER,subject:'User-A',sessionKey:f.key});
});
test('registry grants reviewer, not a token role string',async()=>{
  const f=fixture();f.verified.roles=['reviewer'];await rejects(()=>f.resolve('test','reviewer'),'FORBIDDEN');
  f.snapshot.principal.reviewerEnabled=true;const a=await f.resolve('test','reviewer');
  assert.deepEqual(a.roles,['writer','reviewer']);
});
for(const [index,token] of [null, {}, {trusted:true,authenticated:true}, '', 'test token', 'x'.repeat(16385)].entries()) {
  test(`non-credential input #${index} rejected (${typeof token},${typeof token==='string'?token.length:0})`,async()=>{
    const f=fixture();await rejects(()=>f.resolve(token,'writer'));assert.equal(f.verifies,0);assert.equal(f.reads,0);
  });
}
test('unknown capability is denied before verifier/store',async()=>{
  const f=fixture();await rejects(()=>f.resolve('test','admin'),'FORBIDDEN');assert.equal(f.verifies,0);
});
test('verifier failure is not replaced by trusted=true and does not expose token',async()=>{
  const f=fixture();f.verify=()=>{throw Error('secret test-credential decoded here');};
  await rejects(()=>f.resolve('test-credential','writer'));assert.equal(f.reads,0);
});
for(const [name,patch] of [
  ['ID token',{tokenUse:'ID_TOKEN'}],['missing token use',{tokenUse:undefined}],
  ['wrong issuer',{issuer:'https://other.example.test'}],['issuer suffix',{issuer:ISSUER+'/'}],
  ['wrong audience',{audiences:['other-api']}],['audience substring',{audiences:['echo-api-attacker']}],
  ['audience scalar',{audiences:AUDIENCE}],['empty subject',{subject:''}],['control subject',{subject:'a\n'}],
  ['missing session binding',{sessionKey:undefined}],['malformed digest',{sessionKey:'raw-token'}],
  ['expiry exact boundary',{expiresAtMs:N}],['future not-before',{notBeforeMs:N+1}],
  ['future issuance',{issuedAtMs:N+1}],['non-numeric expiry',{expiresAtMs:String(N+1000)}],
  ['invalid expiry',{expiresAtMs:Infinity}],['nonpositive interval',{expiresAtMs:N-20000}]
]) test(`verified result rejects ${name}`,async()=>{
  const f=fixture();Object.assign(f.verified,patch);await rejects(()=>f.resolve('test','writer'));assert.equal(f.reads,0);
});
test('audience array can contain the exact allowed API',async()=>{
  const f=fixture();f.verified.audiences=['other',AUDIENCE];assert.equal((await f.resolve('test','writer')).actorId,UUID(2));
});
test('unknown identity is denied without auto-provisioning',async()=>{
  const f=fixture();f.snapshot=null;await rejects(()=>f.resolve('test','writer'));assert.equal(f.reads,1);
});
for(const [name,section,patch] of [
 ['disabled principal','principal',{enabled:false}],['truthy enabled','principal',{enabled:'true'}],
 ['AI principal','principal',{actorKind:'AI'}],['unknown actor','principal',{actorId:'not-uuid'}],
 ['wrong issuer binding','principal',{issuer:ISSUER+'/'}],['subject case mismatch','principal',{subject:'user-a'}],
 ['subject padding mismatch','principal',{subject:'User-A '}],['principal version missing','principal',{authVersion:undefined}],
 ['session different principal','session',{principalId:UUID(77)}],['session wrong digest','session',{sessionKey:'b'.repeat(64)}],
 ['revoked session','session',{revoked:true}],['truthy revoke false','session',{revoked:0}],
 ['stale auth generation','session',{authVersion:2}],['session expiry boundary','session',{expiresAtMs:N}],
 ['session future start','session',{issuedAtMs:N+1}],['inverted session interval','session',{expiresAtMs:N-20000}],
 ['nonboolean role','principal',{writerEnabled:1}]
]) test(`snapshot rejects ${name}`,async()=>{
  const f=fixture();Object.assign(f.snapshot[section],patch);await rejects(()=>f.resolve('test','writer'));
});
test('writer role denied if not currently granted',async()=>{
  const f=fixture();f.snapshot.principal.writerEnabled=false;await rejects(()=>f.resolve('test','writer'),'FORBIDDEN');
});
test('logout/revocation visible on the next fresh lookup; no auth cache',async()=>{
  const f=fixture();await f.resolve('test','writer');f.snapshot.session.revoked=true;
  await rejects(()=>f.resolve('test','writer'));assert.equal(f.reads,2);assert.equal(f.verifies,2);
});
test('disable then enable with a new generation does not revive old session',async()=>{
  const f=fixture();await f.resolve('test','writer');f.snapshot.principal.enabled=false;f.snapshot.principal.authVersion++;
  await rejects(()=>f.resolve('test','writer'));
  f.snapshot.principal.enabled=true;f.snapshot.principal.authVersion++;
  await rejects(()=>f.resolve('test','writer'));
  f.verified.sessionKey='b'.repeat(64);f.snapshot.session.sessionKey='b'.repeat(64);
  f.snapshot.session.authVersion=f.snapshot.principal.authVersion;
  assert.equal((await f.resolve('test','writer')).authorizationStamp.authVersion,5);
});
test('database outage fails closed, never returns previous context',async()=>{
  const f=fixture();await f.resolve('test','writer');f.load=()=>{throw Error('connection secret');};
  await rejects(()=>f.resolve('test','writer'),'AUTHORITY_UNAVAILABLE');
});
test('slow verifier cannot return an expired credential',async()=>{
  const f=fixture();f.verify=()=>{f.time+=10000;return structuredClone(f.verified);};
  await rejects(()=>f.resolve('test','writer'));assert.equal(f.reads,0);
});
test('slow store lookup crossing token expiry is denied',async()=>{
  const f=fixture();f.load=()=>{f.time+=10000;return structuredClone(f.snapshot);};
  await rejects(()=>f.resolve('test','writer'));
});
test('clock rollback during lookup is denied',async()=>{
  const f=fixture();f.load=()=>{f.time--;return structuredClone(f.snapshot);};
  await rejects(()=>f.resolve('test','writer'),'AUTHORITY_UNAVAILABLE');
});
test('unavailable clock fails before credential verification',async()=>{
  const f=fixture();f.time=NaN;await rejects(()=>f.resolve('test','writer'),'AUTHORITY_UNAVAILABLE');assert.equal(f.verifies,0);
});
test('verifier output is copied before await; later mutation cannot retarget lookup',async()=>{
  const f=fixture();f.verify=()=>f.verified;f.load=()=>{
    f.verified.subject='User-B';f.verified.sessionKey='b'.repeat(64);
    return structuredClone(f.snapshot);
  };
  assert.equal((await f.resolve('test','writer')).actorId,UUID(2));
});
test('context and nested roles/stamp cannot be modified',async()=>{
  const f=fixture(),a=await f.resolve('test','writer');
  assert.throws(()=>{a.actorId=UUID(77);},TypeError);
  assert.throws(()=>a.roles.push('reviewer'),TypeError);
  assert.throws(()=>{a.authorizationStamp.authVersion=77;},TypeError);
});
test('stamp limits lifetime to both credential and local session',async()=>{
  const f=fixture();f.snapshot.session.expiresAtMs=N+2000;
  const a=await f.resolve('test','writer');assert.equal(a.authorizationStamp.expiresAtMs,N+2000);
  assert.equal(a.authorizationStamp.checkedAtMs,N);assert.equal(a.authorizationStamp.authVersion,3);
});
test('context contains no raw credential/email/subject from verifier',async()=>{
  const f=fixture();f.verified.email='secret@example.test';f.verified.rawToken='secret';
  const a=await f.resolve('sensitive-fixture-credential','writer');
  assert.equal(a.subject,undefined);assert.equal(a.email,undefined);
  assert.ok(!JSON.stringify(a).includes('sensitive-fixture-credential'));
});
const server={newUuid:()=>UUID(8),storePayload:()=> 'fixture:payload',now:()=>new Date(N).toISOString()};
test('resolved identity binds existing P2.1c.2b create-voice command',async()=>{
  const f=fixture(),a=await f.resolve('test','writer'),c=bindCreateVoice({content:'test'},a,server);
  assert.equal(c.authorId,UUID(2));assert.equal(c.sourceId,UUID(3));assert.equal(c.visibility,'PRIVATE');
  assert.throws(()=>bindCreateVoice({content:'test',authorId:UUID(55)},a,server));
});
test('resolved reviewer binds existing review command without retargeting',async()=>{
  const f=fixture();f.snapshot.principal.reviewerEnabled=true;const a=await f.resolve('test','reviewer');
  const existing={assessmentId:UUID(10),revision:2,reviewState:'PENDING',withdrawn:false,
    eventId:UUID(11),claimId:UUID(12),claimRevision:1,scopeKey:'scope-a',evidenceId:UUID(13),evidenceRevision:1,
    relation:'SUPPORTS',validTimeStatus:'KNOWN',validFrom:'2026-01-01T00:00:00Z',validUntil:'2026-01-02T00:00:00Z'};
  const c=bindReviewAssessment({assessmentId:existing.assessmentId,expectedRevision:2,decision:'ACCEPTED',rationale:'fixture'},a,existing,server);
  assert.equal(c.assessorId,UUID(2));assert.equal(c.eventId,existing.eventId);assert.equal(c.validUntil,existing.validUntil);
});
test('backend configuration cannot be replaced by HTTP-style callback names',()=>{
  for(const issuer of ['http://identity.example.test','https://a.test?q=1','https://a.test#x','https://u:p@a.test']) {
    assert.throws(()=>createSessionResolver({issuer,audience:AUDIENCE,verifyCredential:()=>{},loadSnapshot:()=>{},now:()=>N}));
  }
  assert.throws(()=>createSessionResolver({issuer:ISSUER,audience:AUDIENCE,verifyCredential:true,loadSnapshot:()=>{},now:()=>N}));
});
