import test from 'node:test';
import assert from 'node:assert/strict';
import {roomSummary, renderRoomV2, ROOM_LAYERS} from '../room-v2.mjs';
import {rooms, voices} from '../data.mjs';
import {initialState, counts, roomVoices} from '../core.mjs';

const options = room => ({room,voices:roomVoices(room.id,voices,initialState()),
  counts:counts(room.id,voices,initialState()),followed:false,
  claimCard:c=>`<p data-claim="${c.id}"></p>`,voiceCard:v=>`<p data-voice="${v.id}"></p>`,
  evidenceCard:e=>`<p data-evidence="${e.id}"></p>`});

test('01 summary counts claims only, preserving explicit UNKNOWN',()=>{
  assert.deepEqual(roomSummary(rooms[0]).counts,{SUPPORTED:1,DISPUTED:1,UNKNOWN:1,COUNTERED:0});
  assert.equal(roomSummary(rooms[0]).unknown,rooms[0].claims[2].text);
});
test('02 all-unknown room remains unknown without invented support',()=>{
  const s=roomSummary(rooms[2]);assert.equal(s.total,1);assert.equal(s.counts.UNKNOWN,1);
  assert.equal(s.counts.SUPPORTED,0);
});
test('03 empty/missing source is not represented as fully known',()=>{
  for(const room of [null,{}, {claims:[],timeline:[]}]) {
    const s=roomSummary(room);assert.equal(s.total,0);assert.equal(s.unknown,null);
    assert.equal(s.freshness,'UNKNOWN');assert.equal(s.last,null);
  }
});
test('04 unrecognized claim states fail to UNKNOWN instead of support',()=>{
  const s=roomSummary({claims:[{state:'POPULAR',text:'unassessed'}]});
  assert.equal(s.counts.UNKNOWN,1);assert.equal(s.unknown,'unassessed');
});
test('05 COUNTERED is not silently merged with DISPUTED or SUPPORTED',()=>{
  const r={...rooms[0],claims:[{state:'COUNTERED',text:'countered',id:'c-new'}]};
  assert.equal(roomSummary(r).counts.COUNTERED,1);
  assert.match(renderRoomV2(options(r)),/data-state="COUNTERED"/);
});
test('06 freshness does not come from votes, text hints or client timestamps',()=>{
  const r={...rooms[0],votes:10000,updatedAt:new Date().toISOString(),freshness:'FRESH'};
  assert.equal(roomSummary(r).freshness,'UNKNOWN');
  assert.match(renderRoomV2(options(r)),/data-freshness="UNKNOWN"/);
});
test('07 last authored timeline record is labelled, not reordered as live news',()=>{
  const r={...rooms[0],timeline:[{time:'23:00',text:'first'},{time:'01:00',text:'last authored'}]};
  assert.equal(roomSummary(r).last.text,'last authored');
  assert.match(renderRoomV2(options(r)),/ไม่ใช่เวลาที่ระบบเพิ่งอัปเดต/);
});
test('08 reading a summary never changes its source fixtures',()=>{
  const r=structuredClone(rooms[0]),before=JSON.stringify(r);roomSummary(r);renderRoomV2(options(r));
  assert.equal(JSON.stringify(r),before);assert.ok(Object.isFrozen(roomSummary(r).counts));
});
test('09 local voice volume cannot change claim counts or freshness',()=>{
  const r=rooms[0],before=roomSummary(r);const html=renderRoomV2({...options(r),voices:[],counts:{voices:10000,people:10000,local:10000}});
  assert.deepEqual(roomSummary(r),before);assert.match(html,/จำนวนเสียง ≠ จำนวนหลักฐาน ≠ ความจริง/);
  assert.match(html,/data-state="SUPPORTED"/);
});
test('10 template escapes headings, location and unknown text',()=>{
  const payload='<img src=x onerror=alert(1)>';
  const r={...rooms[0],title:payload,place:payload,claims:[{id:'safe',state:'UNKNOWN',text:payload}]};
  const html=renderRoomV2(options(r));assert.ok(!html.includes(payload));assert.ok(html.includes('&lt;img'));
});
test('11 exactly three associated tabs and one initial visible panel',()=>{
  const html=renderRoomV2(options(rooms[0]));
  assert.deepEqual(ROOM_LAYERS,['reality','society','timeline']);
  assert.equal((html.match(/role="tab"/g)||[]).length,3);
  assert.equal((html.match(/role="tabpanel"/g)||[]).length,3);
  assert.equal((html.match(/aria-selected="true"/g)||[]).length,1);
  assert.equal((html.match(/tabindex="0" hidden/g)||[]).length,2);
  for(const layer of ROOM_LAYERS) assert.ok(html.includes(`aria-controls="room-panel-${layer}"`));
});
test('12 evidence grouping and local-only notices never promise independent truth',()=>{
  const html=renderRoomV2(options(rooms[0]));
  assert.match(html,/สายต้นทางต่างกันยังไม่ได้พิสูจน์ว่าเป็นหลักฐานอิสระ/);
  assert.match(html,/ไม่เผยแพร่ให้ผู้อื่น/);assert.match(html,/Current State · จำลอง/);
});
