// UX-P0.1: presentation-only Room view. Never infer truth/freshness from voices.
import {escapeHTML as esc, TYPES, evidenceFamilies} from './core.mjs';

export const ROOM_LAYERS = Object.freeze(['reality', 'society', 'timeline']);
const STATUS = Object.freeze({
  SUPPORTED: {label:'มีข้อมูลรองรับ', short:'รองรับ', icon:'✓'},
  DISPUTED: {label:'มีข้อมูลขัดแย้ง', short:'ขัดแย้ง', icon:'≠'},
  UNKNOWN: {label:'ยังไม่ทราบ', short:'ยังไม่ทราบ', icon:'?'},
  COUNTERED: {label:'มีข้อมูลคัดค้าน', short:'คัดค้าน', icon:'⊖'}
});

export function roomSummary(room) {
  const claims = Array.isArray(room?.claims) ? room.claims : [];
  const counts = {SUPPORTED:0, DISPUTED:0, UNKNOWN:0, COUNTERED:0};
  for (const claim of claims) counts[Object.hasOwn(STATUS, claim.state) ? claim.state : 'UNKNOWN']++;
  const unknown = claims.find(c => !Object.hasOwn(STATUS, c.state) || c.state === 'UNKNOWN');
  const timeline = Array.isArray(room?.timeline) ? room.timeline : [];
  // Source offers authored times, not live timestamps or freshness metadata.
  return Object.freeze({counts:Object.freeze(counts), total:claims.length,
    unknown:unknown?.text ?? null, freshness:'UNKNOWN', last:timeline.at(-1) ?? null});
}

export function renderRoomV2({room:r, voices:vv, counts:n, followed, layer='reality',
                              kindFilter='all', claimCard, voiceCard, evidenceCard}) {
  const s = roomSummary(r);
  const states = ['SUPPORTED','DISPUTED','UNKNOWN', ...(s.counts.COUNTERED ? ['COUNTERED'] : [])];
  const list = kindFilter === 'all' ? vv : vv.filter(v => v.kind === kindFilter);
  const tabs = [['reality','หลักฐาน','Reality'],['society','เสียงสังคม','Society'],['timeline','เส้นเวลา','Timeline']];
  const panel = (key, html) => `<section id="room-panel-${key}" class="room-view-panel" role="tabpanel" aria-labelledby="room-tab-${key}" tabindex="0" ${layer===key?'':'hidden'}>${html}</section>`;
  return `<div class="room-v2" data-ux="room-v2">
    <a class="room-back" href="#/">← กลับฟีดห้องข่าว</a>
    <header class="room-heading" id="room-heading">
      <p class="eyebrow">ECHO VOICE ROOM <span>· ${esc(r.tag)}</span></p>
      <h1 class="roomtitle">${esc(r.title)}</h1>
      <p class="room-place">${esc(r.place)} <span>· ${esc(r.window)} ในเรื่องสมมติ</span></p>
    </header>
    <section class="event-state" aria-labelledby="state-heading">
      <div class="state-title"><h2 id="state-heading">ตอนนี้รู้อะไร</h2><span>Current State · จำลอง</span></div>
      <p class="state-explainer">สถานะของข้อกล่าวอ้าง ไม่ใช่คะแนนความจริง</p>
      <div class="state-metrics" aria-label="จำนวนข้อกล่าวอ้างแต่ละสถานะ">
        ${states.map(key=>`<div class="state-metric ${key.toLowerCase()}" data-state="${key}"><span class="metric-icon" aria-hidden="true">${STATUS[key].icon}</span><strong>${s.counts[key]}</strong><span>${STATUS[key].short}</span></div>`).join('')}
      </div>
      <p class="freshness" data-freshness="UNKNOWN"><span aria-hidden="true">◷</span> ความสด: <strong>ยังไม่ประเมิน</strong><span class="freshness-note">ไม่มีข้อมูลอัปเดตสด</span></p>
      <div class="top-unknown"><span class="unknown-sign" aria-hidden="true">?</span><div><h3>สิ่งที่ยังไม่ทราบ</h3><p>${esc(s.unknown ?? (s.total ? 'ชุดตัวอย่างไม่ได้ระบุคำถามเพิ่มเติม ไม่ได้แปลว่าทราบทุกอย่างแล้ว' : 'ยังไม่มีข้อกล่าวอ้างให้สรุปในชุดตัวอย่างนี้'))}</p></div></div>
      <details class="room-latest"><summary>บันทึกท้ายเส้นเวลา <span>${s.last ? esc(s.last.time)+' · จำลอง' : 'ยังไม่มีข้อมูล'}</span></summary><p>${esc(s.last?.text ?? 'ยังไม่มีบันทึกในชุดตัวอย่าง')}</p><p class="small muted">นี่คือเวลาในเรื่องสมมติ ไม่ใช่เวลาที่ระบบเพิ่งอัปเดต</p></details>
    </section>
    <div class="room-sticky-marker" aria-hidden="true"></div>
    <div class="room-sticky">
      <div class="room-compact" aria-hidden="true"><span>สถานะในตัวอย่าง<br><b>${s.counts.SUPPORTED} รองรับ · ${s.counts.DISPUTED} ขัดแย้ง · ${s.counts.UNKNOWN} ยังไม่ทราบ</b></span><span class="compact-freshness">ความสด<br>ยังไม่ประเมิน</span></div>
      <div class="room-segments" role="tablist" aria-label="มุมมองของเหตุการณ์">
        ${tabs.map(([key,label,en])=>`<button type="button" id="room-tab-${key}" role="tab" data-action="room-layer" data-value="${key}" aria-controls="room-panel-${key}" aria-selected="${layer===key}" tabindex="${layer===key?0:-1}"><span>${label}</span><small>${en}</small></button>`).join('')}
      </div>
    </div>
    <div id="room-body">
      ${panel('reality',`<div class="layer-heading"><span class="layer-number">01</span><div><h2>หลักฐานบอกอะไร</h2><p>ป้ายจากชุดสาธิต ไม่ได้คำนวณจากยอดเสียงหรือ AI</p></div></div><div class="room-claims">${r.claims.map(claimCard).join('') || '<p class="empty">ยังไม่มีข้อกล่าวอ้างในห้องนี้</p>'}</div><details class="room-evidence-list"><summary>หลักฐาน / ต้นทาง <span>${r.evidence.length} รายการ</span></summary><p class="evidence-context">${r.evidence.length} รายการอ้างอิง · ${evidenceFamilies(r)} สายต้นทางในตัวอย่าง<br>สายต้นทางต่างกันยังไม่ได้พิสูจน์ว่าเป็นหลักฐานอิสระ</p>${r.evidence.map(evidenceCard).join('')}</details>`)}
      ${panel('society',`<div class="layer-heading society-heading"><span class="layer-number">02</span><div><h2>ฟังเสียงที่ต่างกัน</h2><p id="room-count">${n.voices} เสียง · ${n.people} ผู้ร่วมโพสต์ในห้องนี้${n.local ? ' · '+n.local+' เสียงจากเครื่องนี้' : ''}</p></div></div><p class="society-boundary">จำนวนเสียง ≠ จำนวนหลักฐาน ≠ ความจริง<br><span>แสดงเฉพาะโพสต์ในห้องนี้ ไม่ใช่ผลสำรวจทั้งสังคม</span></p><div class="voicemap" aria-label="กรองประเภทเสียง">${Object.entries(TYPES).map(([key,label])=>`<button type="button" class="voicegroup" data-action="kind" data-value="${key}" aria-pressed="${kindFilter===key}"><b>${vv.filter(v=>v.kind===key).length}</b>${label}</button>`).join('')}</div>${kindFilter!=='all'?'<button class="textbutton clear-kind" data-action="kind" data-value="all">↶ กลับไปดูเสียงทุกประเภท</button>':''}${list.map(v=>voiceCard(v)).join('') || '<div class="empty"><h3>ยังไม่มีเสียงประเภทนี้</h3><p>เพิ่มได้โดยบันทึกเฉพาะบนเครื่อง</p></div>'}`)}
      ${panel('timeline',`<div class="layer-heading"><span class="layer-number">03</span><div><h2>เรื่องราวตามเวลา</h2><p>บันทึกในเรื่องสมมติ ไม่ใช่การอัปเดตสด</p></div></div><div class="timeline">${r.timeline.map(t=>`<div class="moment"><time>${esc(t.time)}</time><p>${esc(t.text)}</p></div>`).join('')}</div>`)}
    </div>
    <div class="roomtools room-actions-v2" aria-label="การทำงานในห้อง">
      <button class="primary" data-action="compose" data-room="${esc(r.id)}">+ เพิ่มเสียงในห้อง</button>
      <button class="secondary" data-action="follow" data-room="${esc(r.id)}" aria-pressed="${followed}">${followed?'✓ ติดตามแล้ว':'+ ติดตามห้อง'}</button>
      <button class="ghost" data-action="share" data-room="${esc(r.id)}" aria-label="คัดลอกลิงก์ห้อง">↗ ลิงก์ห้อง</button>
    </div>
    <p class="room-local-note">เพิ่มเสียงและติดตามเฉพาะในเบราว์เซอร์นี้ ไม่เผยแพร่ให้ผู้อื่น</p>
  </div>`;
}

// Mount/destroy per render: no global observer leaks, no state writes or fetches.
export function mountRoomV2(root, {onLayerChange=()=>{}} = {}) {
  const tabs = [...root.querySelectorAll('[role=tab][data-action=room-layer]')];
  const sticky = root.querySelector('.room-sticky');
  const marker = root.querySelector('.room-sticky-marker');
  if (!sticky || tabs.length!==3) return ()=>{};
  function select(key, focus=false) {
    if (!ROOM_LAYERS.includes(key)) return;
    const wasStuck = marker.getBoundingClientRect().top < 0;
    for (const tab of tabs) {
      const selected = tab.dataset.value===key;
      tab.setAttribute('aria-selected', String(selected)); tab.tabIndex=selected?0:-1;
      root.querySelector('#'+tab.getAttribute('aria-controls')).hidden=!selected;
      if (selected && focus) tab.focus({preventScroll:true});
    }
    onLayerChange(key);
    // A shorter panel must not strand keyboard/pointer users below its start.
    if (wasStuck) sticky.scrollIntoView({block:'start',behavior:'instant'});
  }
  function click(event) {
    const tab=event.target.closest('[data-action=room-layer]');
    if (tab && root.contains(tab)) select(tab.dataset.value, true);
  }
  function keydown(event) {
    const index=tabs.indexOf(event.target);
    if (index<0) return;
    const keys={ArrowRight:(index+1)%3,ArrowLeft:(index+2)%3,Home:0,End:2};
    if (Object.hasOwn(keys,event.key)) {event.preventDefault();select(tabs[keys[event.key]].dataset.value,true);}
  }
  let frame=0;
  function updateSticky() {
    frame=0; const stuck=marker.getBoundingClientRect().top<0;
    sticky.classList.toggle('is-stuck',stuck);
  }
  function scroll() {if (!frame) frame=requestAnimationFrame(updateSticky);}
  // Focused controls must not sit beneath the sticky tabs or mobile nav.
  function focusin(event) {
    const el=event.target;
    if (!el.matches('button,a,summary,[role=tabpanel]') || sticky.contains(el)) return;
    const box=el.getBoundingClientRect(), bar=sticky.getBoundingClientRect();
    const bottom=document.querySelector('.bottomnav')?.getBoundingClientRect();
    const coveredTop=sticky.classList.contains('is-stuck') && box.top<bar.bottom+8;
    const coveredBottom=bottom?.height && box.bottom>bottom.top-8;
    if (coveredTop || coveredBottom) el.scrollIntoView({block:'center',behavior:'instant'});
  }
  root.addEventListener('click',click); root.addEventListener('keydown',keydown);
  root.addEventListener('focusin',focusin); window.addEventListener('scroll',scroll,{passive:true});
  updateSticky();
  return ()=>{root.removeEventListener('click',click);root.removeEventListener('keydown',keydown);
    root.removeEventListener('focusin',focusin);window.removeEventListener('scroll',scroll);cancelAnimationFrame(frame);};
}
