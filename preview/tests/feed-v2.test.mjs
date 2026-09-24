import test from 'node:test';
import assert from 'node:assert/strict';
import {feedSummary,renderFeedCard} from '../feed-v2.mjs';
import {roomSummary} from '../room-v2.mjs';
import {rooms} from '../data.mjs';
const card = (room,patch={}) => renderFeedCard({room,counts:{voices:6,people:6},...patch});

test('01 feed counts equal Room counts for every fixture',()=>{
  for(const room of rooms) assert.deepEqual(feedSummary(room).counts,roomSummary(room).counts);
});
test('02 Unknown keeps its own state even when evidence is attached',()=>{
  const s=feedSummary(rooms[2]);
  assert.equal(s.counts.UNKNOWN,1); assert.equal(s.counts.SUPPORTED,0);
  assert.equal(s.unknown.id,'c6'); assert.equal(s.supported,null);
});
test('03 voices reactions and repost volume cannot change the projection',()=>{
  const r=rooms[0]; assert.deepEqual(feedSummary({...r,voices:10000,likes:99999}),feedSummary(r));
  const a=card(r),b=card(r,{counts:{voices:10000,people:999}});
  assert.equal(a.split('<section')[1].split('</section>')[0],b.split('<section')[1].split('</section>')[0]);
});
test('04 freshness remains unevaluated despite future timestamps or claims of FRESH',()=>{
  const r={...rooms[0],freshness:'FRESH',updatedAt:'2099-01-01'};
  assert.equal(feedSummary(r).freshness,'UNKNOWN');
  assert.ok(card(r).includes('ความสด: <b>ยังไม่ประเมิน</b>'));
  assert.ok(!card(r).includes('2099')); assert.ok(!card(r).includes('เมื่อสักครู่'));
});
test('05 latest is authored order not lexicographic time or wall clock',()=>{
  const r={...rooms[0],timeline:[{time:'23:59',text:'before'},{time:'00:02',text:'after'}]};
  assert.deepEqual(feedSummary(r).last,{time:'00:02',text:'after'});
  assert.ok(card(r).includes('บันทึกท้ายเรื่องสมมติ'));
});
test('06 missing data does not fabricate a supported or resolved verdict',()=>{
  const r={id:'empty',tag:'demo',title:'Empty',claims:[],evidence:[]};
  const s=feedSummary(r); assert.equal(s.total,0); assert.equal(s.supported,null); assert.equal(s.last,null);
  assert.ok(card(r).includes('ยังไม่มีข้อกล่าวอ้างให้สรุป')); assert.ok(card(r).includes('ยังไม่มีบันทึก'));
  assert.equal(feedSummary(null).total,0);
});
test('07 unrecognized states fail to Unknown while Countered stays separate',()=>{
  const r={...rooms[0],claims:[null,{id:'future',state:'NEW_STATUS',text:'pending'},
    {id:'countered',state:'COUNTERED',text:'countered'}]};
  const s=feedSummary(r); assert.equal(s.counts.UNKNOWN,1); assert.equal(s.counts.COUNTERED,1);
  assert.equal(s.counts.DISPUTED,0); assert.equal(s.unknown.id,'future');
  assert.ok(card(r).includes('data-state="COUNTERED"'));
});
test('08 immutable projection does not mutate fixture data',()=>{
  const r=structuredClone(rooms[0]),before=JSON.stringify(r),s=feedSummary(r);
  assert.throws(()=>{s.counts.UNKNOWN=0;}); assert.throws(()=>{s.unknown.text='changed';});
  card(r); assert.equal(JSON.stringify(r),before);
});
test('09 unsafe text and identifiers cannot become markup or attributes',()=>{
  const x='\"<img src=x onerror=alert(1)>';
  const r={...rooms[0],id:x,title:x,tag:x,place:x,theme:x,window:x,
    claims:[{id:x,text:x,state:'UNKNOWN'}],timeline:[{time:x,text:x}]};
  const html=card(r); assert.ok(!html.includes('<img')); assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes('#/room/'+encodeURIComponent(x)));
  assert.ok(html.includes('landscape water'));
});
test('10 Reality and Unknown precede collapsed illustration and social counts',()=>{
  const html=card(rooms[0]);
  assert.ok(html.indexOf('feed-unknown')<html.indexOf('feed-art'));
  assert.ok(html.indexOf('feed-reality')<html.indexOf('feed-society'));
  assert.ok(!html.includes('<details open')); assert.ok(!html.includes('feed-art" open'));
});
test('11 claim controls retain exact room scope and stable references',()=>{
  const html=card(rooms[1]);
  assert.ok(html.includes('data-action="feed-claim" data-room="transit-demo" data-id="c4"'));
  assert.ok(html.includes('data-id="c5"')); assert.ok(!html.includes('data-id="c1"'));
});
test('12 evidence families are not counted or labelled as independent proof',()=>{
  const html=card(rooms[0]);
  assert.ok(html.includes('3 รายการอ้างอิง · 2 สายต้นทางตัวอย่าง'));
  assert.ok(html.includes('ยังไม่ประเมินความเป็นอิสระ')); assert.ok(html.includes('จำนวนเสียง ≠ หลักฐาน'));
});
