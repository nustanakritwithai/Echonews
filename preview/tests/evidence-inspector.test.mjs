import test from 'node:test';
import assert from 'node:assert/strict';
import {rooms,voices} from '../data.mjs';
import {resolveInspection as resolve,inspectionBody as render} from '../evidence-inspector.mjs';
const roomId='canal-demo';
const at=(extra={})=>resolve(rooms,voices,{roomId,...extra});

test('claim resolves only its declared references',()=>{
 const t=at({claimId:'c1'});assert.deepEqual(t.linked.map(e=>e.id),['e1','e2']);
});
test('unknown without refs stays explicitly unknown, not false',()=>{
 const t=at({claimId:'c3'});const html=render(t,'claim');
 assert.equal(t.linked.length,0);assert.match(html,/ยังไม่มีหลักฐาน/);assert.match(html,/ไม่ได้แปลว่าข้อกล่าวอ้างเป็นเท็จ/);
 assert.equal(t.claim.state,'UNKNOWN');
});
test('rejects cross-room claim, evidence and voice',()=>{
 for(const x of [{claimId:'c4'},{evidenceId:'e4'},{voiceId:'v7'}]) assert.equal(at(x),null);
 assert.equal(resolve(rooms,voices,{roomId:'missing'}),null);
});
test('a claim cannot resolve evidence outside its refs',()=>{
 assert.equal(at({claimId:'c1',evidenceId:'e3'}),null);
});
test('evidence must resolve its exact cited voice',()=>{
 assert.equal(at({evidenceId:'e1',voiceId:'v2'}),null);
 assert.equal(at({claimId:'c1',evidenceId:'e1',voiceId:'v1'}).voice.id,'v1');
});
test('family groups repeat references without claiming independent sources',()=>{
 const t=at({evidenceId:'e3'});assert.equal(t.family.length,2);
 assert.match(render(t,'evidence'),/ไม่ใช่ 2 แหล่งอิสระ/);assert.match(render(t,'evidence'),/ยังไม่ประเมิน/);
});
test('repost preserves original writer, text and dependency',()=>{
 const t=at({evidenceId:'e3',voiceId:'v5'});const html=render(t,'source');
 assert.equal(t.voice.author,'นนท์');assert.ok(html.includes(t.voice.text));assert.match(html,/อ้างต่อจาก v1/);
});
test('source does not fabricate an external URL or fact approval',()=>{
 const html=render(at({voiceId:'v1'}),'source');assert.match(html,/ไม่มี URL/);
 assert.match(html,/การอนุมัติข้อเท็จจริง: ไม่มี/);assert.doesNotMatch(html,/href=/);
});
test('missing reference/source returns visible unknown rather than fallback',()=>{
 const fixture=structuredClone(rooms);fixture[0].claims[0].refs=['missing'];fixture[0].evidence[0].voice='missing';
 const t=resolve(fixture,voices,{roomId,claimId:'c1'});assert.deepEqual(t.linked,[null]);assert.match(render(t,'claim'),/ไม่พบหลักฐาน/);
 const e=resolve(fixture,voices,{roomId,evidenceId:'e1'});assert.equal(e.voice,null);assert.match(render(e,'evidence'),/ไม่พบเสียงต้นทาง/);
 assert.match(render(null,'source'),/ไม่พบข้อมูล/);
});
test('untrusted text is escaped in every view',()=>{
 const fixture=structuredClone(rooms), vv=structuredClone(voices);const payload='<img src=x onerror="boom">';
 fixture[0].claims[0].text=payload;fixture[0].claims[0].note=payload;
 fixture[0].evidence[0].title=payload;fixture[0].evidence[0].family=payload;vv[0].text=payload;vv[0].author=payload;
 const t=resolve(fixture,vv,{roomId,claimId:'c1',evidenceId:'e1',voiceId:'v1'});
 for(const stage of ['claim','evidence','source']){const html=render(t,stage);assert.doesNotMatch(html,/<img/);assert.match(html,/&lt;img/);}
});
test('local original text including whitespace survives without publishing',()=>{
 const local={...voices[0],id:'local-demo',local:true,text:'  ทดสอบ\nสองบรรทัด  '};
 const t=resolve(rooms,[local],{roomId,voiceId:local.id});const html=render(t,'source');
 assert.ok(html.includes(local.text));assert.match(html,/ไม่ได้ส่งให้ผู้อื่น/);
});
test('inspection never mutates voices, claims, evidence, or state labels',()=>{
 const before=JSON.stringify({rooms,voices});
 for(const room of rooms){for(const c of room.claims) render(resolve(rooms,voices,{roomId:room.id,claimId:c.id}),'claim');for(const e of room.evidence){const t=resolve(rooms,voices,{roomId:room.id,evidenceId:e.id});render(t,'evidence');render(t,'source');}}
 assert.equal(JSON.stringify({rooms,voices}),before);
});
