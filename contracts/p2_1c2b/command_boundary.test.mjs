import test from 'node:test';
import assert from 'node:assert/strict';
import {bindCreateVoice, bindReviewAssessment, clientVoiceFields, clientReviewFields} from './command_boundary.mjs';

const WRITER='11111111-1111-4111-8111-111111111111';
const REVIEWER='22222222-2222-4222-8222-222222222222';
const SOURCE='33333333-3333-4333-8333-333333333333';
const VOICE='44444444-4444-4444-8444-444444444444';
const ASSESS='55555555-5555-4555-8555-555555555555';
const EVENT='66666666-6666-4666-8666-666666666666';
const CLAIM='77777777-7777-4777-8777-777777777777';
const EVIDENCE='88888888-8888-4888-8888-888888888888';
const NOW='2026-09-23T14:00:00.000Z';
const auth=(overrides={})=>({trusted:true,authenticated:true,actorId:WRITER,sourceId:SOURCE,actorKind:'HUMAN',roles:['writer'],...overrides});
const server=(overrides={})=>({newUuid:()=>VOICE,now:()=>NOW,storePayload:content=>'payload:'+content.length,reviewMethodVersion:'review-v0.1',...overrides});
const existing=(overrides={})=>({assessmentId:ASSESS,revision:3,eventId:EVENT,claimId:CLAIM,claimRevision:2,scopeKey:'scope-A',evidenceId:EVIDENCE,evidenceRevision:1,relation:'SUPPORTS',reviewState:'PENDING',withdrawn:false,validTimeStatus:'UNKNOWN',validFrom:null,validUntil:null,...overrides});
const reviewAuth=(overrides={})=>auth({actorId:REVIEWER,roles:['reviewer'],...overrides});
const reviewBody=(overrides={})=>({assessmentId:ASSESS,expectedRevision:3,decision:'ACCEPTED',rationale:'ตรวจขอบเขตและต้นทางแล้วใน fixture',...overrides});

for (const field of ['actorId','actor_id','authorId','author_id','sourceId','source_id','createdBy','created_by','recordedAt','recorded_at','voiceId','voice_id','revision','payloadRef','payload_ref']) {
  test(`voice client cannot supply trusted field ${field}`,()=>assert.throws(()=>bindCreateVoice({content:'hello',[field]:WRITER},auth(),server()),/field not allowed/));
}
for (const field of ['assessorId','assessor_id','assessorKind','assessor_kind','reviewerId','reviewer_id','methodVersion','method_version','recordedAt','recorded_at','eventId','event_id','claimId','claim_id','evidenceId','evidence_id','relation']) {
  test(`review client cannot supply trusted or retarget field ${field}`,()=>assert.throws(()=>bindReviewAssessment({...reviewBody(),[field]:REVIEWER},reviewAuth(),existing(),server()),/field not allowed/));
}
test('allowed voice body is intentionally tiny',()=>assert.deepEqual(clientVoiceFields.sort(),['content','visibility']));
test('allowed review body cannot retarget claim or evidence',()=>assert.deepEqual(clientReviewFields.sort(),['assessmentId','decision','expectedRevision','rationale']));
test('voice identity comes only from trusted auth context',()=>{const c=bindCreateVoice({content:'hello',visibility:'PUBLIC'},auth(),server());assert.equal(c.authorId,WRITER);assert.equal(c.sourceId,SOURCE);});
test('voice id, payload ref and timestamps come only from server dependencies',()=>{const c=bindCreateVoice({content:'สวัสดี'},auth(),server());assert.equal(c.voiceId,VOICE);assert.equal(c.payloadRef,'payload:6');assert.equal(c.recordedAt,NOW);assert.equal(c.postedAt,NOW);});
test('voice defaults to PRIVATE when client does not choose PUBLIC',()=>assert.equal(bindCreateVoice({content:'hello'},auth(),server()).visibility,'PRIVATE'));
test('client cannot create WITHDRAWN voice',()=>assert.throws(()=>bindCreateVoice({content:'hello',visibility:'WITHDRAWN'},auth(),server()),/visibility/));
test('client cannot use RESTRICTED before audience model exists',()=>assert.throws(()=>bindCreateVoice({content:'hello',visibility:'RESTRICTED'},auth(),server()),/visibility/));
test('writer role is required',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth({roles:[]}),server()),/writer role/));
test('AI actor cannot use human writer command',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth({actorKind:'AI'}),server()),/human writer/));
test('untrusted auth object is rejected',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth({trusted:false}),server()),/trusted authenticated/));
test('unauthenticated auth object is rejected',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth({authenticated:false}),server()),/trusted authenticated/));
test('invalid auth actor id is rejected',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth({actorId:'not-uuid'}),server()),/UUID/));
test('invalid source id is rejected',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth({sourceId:'not-uuid'}),server()),/UUID/));
test('content must be nonblank',()=>assert.throws(()=>bindCreateVoice({content:'  '},auth(),server()),/content is required/));
test('content is bounded by code points',()=>assert.throws(()=>bindCreateVoice({content:'🌊'.repeat(2001)},auth(),server()),/2000/));
test('2000 emoji code points are accepted',()=>assert.equal(bindCreateVoice({content:'🌊'.repeat(2000)},auth(),server()).payloadRef,'payload:4000'));
test('request must be a plain object',()=>assert.throws(()=>bindCreateVoice([],auth(),server()),/object/));
test('server must provide nonforgeable dependencies',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth(),{}),/server dependencies/));
test('invalid server-generated UUID fails closed',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth(),server({newUuid:()=> 'bad'})),/UUID/));
test('invalid server clock fails closed',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth(),server({now:()=> 'yesterday'})),/invalid time/));
test('invalid payload storage result fails closed',()=>assert.throws(()=>bindCreateVoice({content:'hello'},auth(),server({storePayload:()=>''})),/payload reference/));

test('reviewer identity comes only from trusted auth context',()=>{const c=bindReviewAssessment(reviewBody(),reviewAuth(),existing(),server());assert.equal(c.assessorId,REVIEWER);assert.equal(c.assessorKind,'HUMAN');});
test('review command appends exactly one revision',()=>{const c=bindReviewAssessment(reviewBody(),reviewAuth(),existing(),server());assert.equal(c.revision,4);assert.equal(c.previousRevision,3);});
test('review preserves event/claim/evidence/relation target tuple',()=>{const e=existing(),c=bindReviewAssessment(reviewBody(),reviewAuth(),e,server());for(const k of ['eventId','claimId','claimRevision','scopeKey','evidenceId','evidenceRevision','relation']) assert.equal(c[k],e[k]);});
test('review method and time come from server',()=>{const c=bindReviewAssessment(reviewBody(),reviewAuth(),existing(),server());assert.equal(c.methodVersion,'review-v0.1');assert.equal(c.assessedAt,NOW);assert.equal(c.recordedAt,NOW);});
test('reviewer role is required',()=>assert.throws(()=>bindReviewAssessment(reviewBody(),auth({roles:['writer']}),existing(),server()),/reviewer role/));
test('AI cannot approve a human-review command',()=>assert.throws(()=>bindReviewAssessment(reviewBody(),reviewAuth({actorKind:'AI'}),existing(),server()),/human reviewer/));
test('stale expected revision is rejected',()=>assert.throws(()=>bindReviewAssessment(reviewBody({expectedRevision:2}),reviewAuth(),existing(),server()),/stale/));
test('assessment id mismatch is rejected',()=>assert.throws(()=>bindReviewAssessment(reviewBody({assessmentId:CLAIM}),reviewAuth(),existing(),server()),/target mismatch/));
test('accepted assessment cannot be reviewed again through this command',()=>assert.throws(()=>bindReviewAssessment(reviewBody(),reviewAuth(),existing({reviewState:'ACCEPTED'}),server()),/not reviewable/));
test('withdrawn assessment cannot be reviewed through this command',()=>assert.throws(()=>bindReviewAssessment(reviewBody(),reviewAuth(),existing({withdrawn:true}),server()),/not reviewable/));
test('PENDING is not a terminal review decision',()=>assert.throws(()=>bindReviewAssessment(reviewBody({decision:'PENDING'}),reviewAuth(),existing(),server()),/decision/));
test('rationale is required',()=>assert.throws(()=>bindReviewAssessment(reviewBody({rationale:' '}),reviewAuth(),existing(),server()),/rationale/));
test('rationale length is bounded',()=>assert.throws(()=>bindReviewAssessment(reviewBody({rationale:'ก'.repeat(2001)}),reviewAuth(),existing(),server()),/2000/));
test('valid-time fields are preserved from existing assessment, not client supplied',()=>{const e=existing({validTimeStatus:'BOUNDED',validFrom:'2026-09-23T10:00:00Z',validUntil:'2026-09-23T11:00:00Z'});const c=bindReviewAssessment(reviewBody(),reviewAuth(),e,server());assert.equal(c.validTimeStatus,'BOUNDED');assert.equal(c.validFrom,e.validFrom);assert.equal(c.validUntil,e.validUntil);});
test('a different authenticated reviewer binds a different assessor without body changes',()=>{const other='99999999-9999-4999-8999-999999999999';const c=bindReviewAssessment(reviewBody(),reviewAuth({actorId:other}),existing(),server());assert.equal(c.assessorId,other);});
