// UX-P0.3: a presentation projection of authored claims, never crowd truth.
import {escapeHTML as esc, evidenceFamilies} from './core.mjs';
import {roomSummary} from './room-v2.mjs';

const STATES = Object.freeze({SUPPORTED:['✓','รองรับ'], DISPUTED:['≠','ขัดแย้ง'],
  UNKNOWN:['?','ยังไม่ทราบ'], COUNTERED:['⊖','คัดค้าน']});
const text = value => typeof value === 'string' ? value : '';
const snapshot = claim => claim ? Object.freeze({id:text(claim.id), text:text(claim.text)}) : null;

export function feedSummary(room) {
  const claims = Array.isArray(room?.claims) ? room.claims.filter(c=>c && typeof c==='object') : [];
  const base = roomSummary({...room, claims});
  const supported = claims.find(c=>c.state==='SUPPORTED');
  const unknown = claims.find(c=>c.state==='UNKNOWN' || !Object.hasOwn(STATES,c.state));
  // This is the last authored record, not an inferred change or wall-clock update.
  return Object.freeze({counts:base.counts, total:base.total, freshness:'UNKNOWN',
    supported:snapshot(supported), unknown:snapshot(unknown),
    last:base.last ? Object.freeze({time:text(base.last.time), text:text(base.last.text)}) : null});
}

function point(roomId, kind, claim, fallback) {
  const title = kind==='supported' ? 'มีข้อมูลรองรับ' : 'ยังไม่ทราบ';
  const content = `<span class="feed-point-label"><b>${title}</b>${claim?.id ? '<span aria-hidden="true">ดูที่มา ↗</span>' : ''}</span><span class="feed-point-text">${esc(claim?.text || fallback)}</span>`;
  const cls = `feed-point feed-${kind}`;
  return claim?.id
    ? `<button type="button" class="${cls}" data-action="feed-claim" data-room="${esc(roomId)}" data-id="${esc(claim.id)}" aria-label="${esc(title+': '+(claim.text||fallback)+' — ดูเหตุผลและต้นทาง')}">${content}</button>`
    : `<div class="${cls}">${content}</div>`;
}

export function renderFeedCard({room:r, counts:n, followed=false}) {
  const s = feedSummary(r), id = text(r.id), href = '#/room/'+encodeURIComponent(id);
  const states = ['SUPPORTED','DISPUTED','UNKNOWN',...(s.counts.COUNTERED ? ['COUNTERED'] : [])];
  const theme = ['water','transit','tech'].includes(r.theme) ? r.theme : 'water';
  const evidenceCount = Array.isArray(r.evidence) ? r.evidence.length : 0;
  const familyCount = evidenceCount ? evidenceFamilies(r) : 0;
  const unknownFallback = s.total
    ? 'ชุดตัวอย่างไม่ระบุคำถามเพิ่ม ไม่ได้แปลว่าทราบครบแล้ว'
    : 'ยังไม่มีข้อกล่าวอ้างให้สรุปในชุดตัวอย่าง';
  return `<article class="card feed-event" data-room="${esc(id)}" aria-labelledby="feed-title-${esc(id)}">
    <header class="cardhead"><span class="badge">◌ ${esc(r.tag)} · DEMO</span><span class="place">${esc(r.window)} · เวลาสมมติ</span></header>
    <a class="cardlink" href="${href}"><h2 id="feed-title-${esc(id)}">${esc(r.title)}</h2></a>
    <p class="feed-place">${esc(r.place)}</p>
    <section class="feed-reality" aria-label="สถานะจากข้อกล่าวอ้างในชุดตัวอย่าง">
      <div class="feed-state-heading"><h3>ตอนนี้รู้อะไร</h3><span>Current State · จำลอง</span></div>
      <div class="feed-state-counts" aria-label="จำนวนข้อกล่าวอ้าง ไม่ใช่คะแนนความจริง">
        ${states.map(k=>`<span class="feed-state-count ${k.toLowerCase()}" data-state="${k}"><i aria-hidden="true">${STATES[k][0]}</i><b>${s.counts[k]}</b> ${STATES[k][1]}</span>`).join('')}
      </div>
      <div class="feed-points">${point(id,'supported',s.supported,'ยังไม่มีข้อกล่าวอ้างที่มีข้อมูลรองรับในชุดนี้')}${point(id,'unknown',s.unknown,unknownFallback)}</div>
      <p class="feed-freshness" data-freshness="UNKNOWN"><span aria-hidden="true">◷</span> ความสด: <b>ยังไม่ประเมิน</b><span>ไม่มีข้อมูลอัปเดตสด</span></p>
      <div class="feed-latest"><span class="feed-latest-label">บันทึกท้ายเรื่องสมมติ${s.last?.time ? ` <b>${esc(s.last.time)}</b>` : ''}</span><p>${esc(s.last?.text || 'ยังไม่มีบันทึกในชุดตัวอย่าง')}</p></div>
    </section>
    <details class="feed-art"><summary>ดูภาพประกอบจำลอง <span>ไม่ใช่หลักฐาน</span></summary><div class="landscape ${theme}" role="img" aria-label="แผนภาพประกอบสมมติ ไม่ใช่ภาพหลักฐาน"><span class="maplabel">แผนภาพสมมติ · ไม่ใช่แผนที่จริง</span></div></details>
    <div class="feed-society"><span><b>${n.voices}</b> เสียง · ${n.people} ผู้ร่วมโพสต์ในชุดนี้</span><span>จำนวนเสียง ≠ หลักฐาน</span></div>
    <p class="feed-provenance">${evidenceCount} รายการอ้างอิง · ${familyCount} สายต้นทางตัวอย่าง<br>ยังไม่ประเมินความเป็นอิสระของแหล่ง</p>
    <footer class="cardfoot"><a class="enter" href="${href}">เข้าห้องข่าว ↗</a><button class="follow ${followed?'on':''}" data-action="follow" data-room="${esc(id)}" aria-pressed="${followed}">${followed?'✓ ติดตามแล้ว':'+ ติดตามห้อง'}</button></footer>
  </article>`;
}
