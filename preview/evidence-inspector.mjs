// UX-P0.2: read-only provenance navigation; never derives truth or independence.
import {escapeHTML as esc, TYPES, STORE_KEY} from './core.mjs';
import {stateNames} from './data.mjs';

// Scoped lookups: a room cannot resolve another room's Claim/Evidence/Voice.
export function resolveInspection(rooms, voices, input) {
  const room = rooms.find(r => r.id === input.roomId);
  if (!room) return null;
  const claim = input.claimId ? room.claims.find(c => c.id === input.claimId) : null;
  if (input.claimId && !claim) return null;
  const evidence = input.evidenceId ? room.evidence.find(e => e.id === input.evidenceId) : null;
  if (input.evidenceId && (!evidence || (claim && !claim.refs.includes(evidence.id)))) return null;
  const voiceId = input.voiceId ?? evidence?.voice;
  const voice = voiceId ? (voices.find(v => v.id === voiceId && v.roomId === room.id) ?? null) : null;
  if (input.voiceId && (!voice || (evidence && evidence.voice !== voice.id))) return null;
  const linked = claim ? claim.refs.map(id => room.evidence.find(e => e.id === id) ?? null) : [];
  // Family codes are authored fixture grouping, NOT an independence verdict.
  const family = evidence ? room.evidence.filter(e => e.family === evidence.family) : [];
  return {room, claim, evidence, voice, linked, family};
}

const note = '<p class="ei-boundary">ข้อมูลจำลอง · ไม่ใช่การตรวจข่าวโดย AI · ความสดยังไม่ประเมิน</p>';
const missing = '<div class="ei-empty"><b>ยังไม่มีหลักฐานสำหรับตอบคำถามนี้</b><p>การไม่มีข้อมูลไม่ได้แปลว่าข้อกล่าวอ้างเป็นเท็จ และจำนวนเสียงไม่เติมช่องว่างนี้</p></div>';
function sourceButton(e) {
  return `<button type="button" class="ei-link" data-action="original" data-inspect="source" data-id="${esc(e.voice)}" data-evidence="${esc(e.id)}">เปิดเสียงต้นทาง ↗</button>`;
}
function evidenceTile(e) {
  if (!e) return '<div class="ei-empty">ไม่พบหลักฐานที่อ้างถึงในชุดข้อมูลนี้</div>';
  return `<article class="card evidencecard"><span class="badge">${esc(e.family)} · สายต้นทางในตัวอย่าง</span><h3>${esc(e.title)}</h3><p>${esc(e.note)}</p><p>เวลาที่บันทึก ${esc(e.when)} · จำลอง</p><div class="ei-actions"><button type="button" data-inspect="evidence" data-id="${esc(e.id)}">รายละเอียดหลักฐาน →</button>${sourceButton(e)}</div></article>`;
}
export function inspectionBody(trace, stage) {
  if (!trace) return '<div class="ei-empty"><b>ไม่พบข้อมูลที่เชื่อมโยง</b><p>ยังไม่สร้างต้นทางหรือข้อสรุปแทนข้อมูลที่หายไป</p></div>';
  const {claim:c,evidence:e,voice:v,linked,family} = trace;
  if (stage === 'claim' && c) {
    return `<span class="badge">${esc(stateNames[c.state] ?? stateNames.UNKNOWN)} · ป้ายจากข้อมูลสาธิต</span><h3 class="ei-title">${esc(c.text)}</h3><div class="ei-scope"><b>ขอบเขตของข้อกล่าวอ้าง</b><p>${esc(c.note)}</p></div><p class="ei-caption">${esc(c.fresh)} · ไม่ใช่ข้อมูลสด</p><h3 class="ei-section">หลักฐานที่อ้างถึง <span>${linked.length} รายการ</span></h3><p class="ei-caption">รายการอ้างอิงไม่ใช่จำนวนแหล่งอิสระ และไม่ได้ระบุทิศทางสนับสนุน/คัดค้านครบทุกชิ้น</p>${linked.length ? linked.map(evidenceTile).join('') : missing}`;
  }
  if (stage === 'evidence' && e) {
    return `<span class="badge">${esc(e.id)} · หลักฐานจำลอง</span><h3 class="ei-title">${esc(e.title)}</h3><p class="ei-description">${esc(e.note)}</p><dl class="ei-meta"><div><dt>เวลาในบันทึก</dt><dd>${esc(e.when)} · จำลอง</dd></div><div><dt>สายต้นทาง</dt><dd>${esc(e.family)}</dd></div><div><dt>ความเป็นอิสระ</dt><dd>ยังไม่ประเมิน</dd></div></dl><div class="ei-scope"><b>สายต้นทางเดียวกันในห้องนี้</b><p>${family.length} รายการใน ${esc(e.family)} ไม่ใช่ ${family.length} แหล่งอิสระ</p><ul>${family.map(item=>`<li>${esc(item.id)} · ${esc(item.title)}</li>`).join('')}</ul></div>${c ? `<p class="ei-caption">อ้างถึงโดยข้อกล่าวอ้าง: ${esc(c.text)}</p>` : '<p class="ei-caption">เปิดจากรายการหลักฐาน จึงยังไม่ได้เลือกข้อกล่าวอ้าง</p>'}<h3 class="ei-section">เสียงที่หลักฐานนี้อ้างถึง</h3>${v ? `<p>${esc(v.author)} · ${esc(v.time)} · บัญชีจำลอง</p>${v.repostOf?'<p class="ei-repost">เป็นการอ้างต่อ ไม่ใช่พยานต้นทางใหม่</p>':''}${sourceButton(e)}` : '<div class="ei-empty">ไม่พบเสียงต้นทางในชุดข้อมูลนี้</div>'}`;
  }
  if (stage === 'source' && v) {
    return `<p class="ei-caption">${v.local?'โพสต์ในเบราว์เซอร์นี้ ไม่ได้ส่งให้ผู้อื่น':'บัญชีและข้อความจำลอง ไม่ใช่โพสต์จากแพลตฟอร์มจริง'}</p><article class="ei-original" id="original-${esc(v.id)}"><header><span class="avatar" aria-hidden="true">${esc([...v.author][0])}</span><div><b>${esc(v.author)}</b><p>${v.local?'เจ้าของโพสต์ในเครื่อง':'@'+esc(v.handle)} · ${esc(TYPES[v.kind] ?? 'ไม่ระบุประเภท')}</p></div></header><p class="voicecontent">${esc(v.text)}</p>${v.repostOf?`<p class="ei-repost">อ้างต่อจาก ${esc(v.repostOf)} · ไม่ใช่ต้นกำเนิดใหม่</p>`:''}</article><dl class="ei-meta"><div><dt>เลขอ้างอิง</dt><dd>ต้นทาง ${esc(v.id)}</dd></div><div><dt>เวลา</dt><dd>${esc(v.local ? 'บันทึกเฉพาะเครื่อง' : v.time+' · จำลอง')}</dd></div></dl><div class="ei-scope"><b>Original Source</b><p>${v.local?'ต้นฉบับอยู่ในเสียงของฉันบนเครื่องนี้':'ต้นฉบับที่มีให้ดูคือเสียงจำลองด้านบน ไม่มี URL หรือไฟล์ต้นทางภายนอกในชุดข้อมูลนี้'}</p><p>การอนุมัติข้อเท็จจริง: ไม่มี</p></div>`;
  }
  return '<div class="ei-empty">ไม่พบข้อมูลในขั้นนี้</div>';
}

export function createEvidenceInspector({dialog, rooms, getVoices, showModal}) {
  let context=null, stage='claim', active=false;
  const remembered=new Map();
  const key=()=>`${stage}:${context?.evidenceId ?? ''}:${context?.voiceId ?? ''}`;
  function remember() {
    const scroll=dialog.querySelector('.ei-scroll');
    const focused=document.activeElement;
    remembered.set(key(),{top:scroll?.scrollTop ?? 0,action:focused?.dataset.inspect,id:focused?.dataset.id});
  }
  function render(restore=false) {
    const trace=resolveInspection(rooms,getVoices(),context);
    const steps=[['room','ห้องข่าว'],...(context.claimId?[['claim','ข้อกล่าวอ้าง']]:[]),
      ...(context.evidenceId?[['evidence','หลักฐาน']]:[]),...(stage==='source'?[['source','ต้นฉบับ']]:[])];
    const labels={claim:'เหตุผลและต้นทาง',evidence:'รายละเอียดหลักฐาน',source:'โพสต์ต้นฉบับ'};
    const trail=steps.map(([value,label])=>`<li>${value===stage ? `<span aria-current="step">${label}</span>` : `<button type="button" data-inspect="crumb" data-step="${value}">${label}</button>`}</li>`).join('');
    showModal(labels[stage],`<nav class="ei-trail" aria-label="เส้นทางหลักฐาน"><ol>${trail}</ol></nav><div class="ei-scroll" tabindex="-1"><p class="ei-context">${esc(trace?.room.title.replaceAll('\n',' ') ?? 'ไม่พบห้อง')}</p>${note}${inspectionBody(trace,stage)}</div><footer class="ei-footer"><button type="button" data-inspect="back">← ${stage==='claim'||(stage==='source'&&!context.evidenceId&&!context.claimId)?'กลับห้องข่าว':'ย้อนกลับ'}</button><span>อ่านต้นทาง ไม่ตัดสินด้วยยอดเสียง</span></footer>`);
    dialog.classList.add('evidence-inspector');
    dialog.dataset.inspectStage=stage;
    document.body.classList.add('inspector-open');
    const title=dialog.querySelector('#modal-title');
    title.setAttribute('tabindex','-1');
    title.focus({preventScroll:true});
    dialog.scrollTop=0;
    if (restore) {
      const saved=remembered.get(key());
      const target=[...dialog.querySelectorAll('[data-inspect]')].find(el=>el.dataset.inspect===saved?.action && el.dataset.id===saved?.id);
      target?.focus({preventScroll:true});
      dialog.querySelector('.ei-scroll').scrollTop=saved?.top ?? 0;
    }
  }
  function open(next, nextStage) {
    if (!resolveInspection(rooms,getVoices(),next)) return false;
    context=next;stage=nextStage;active=true;remembered.clear();render();return true;
  }
  function go(nextStage, patch={}) {
    remember();context={...context,...patch};stage=nextStage;render(true);
  }
  function close(){dialog.close();}
  function back() {
    if(stage==='source'&&context.evidenceId)go('evidence',{voiceId:null});
    else if(stage!=='claim'&&context.claimId)go('claim',{evidenceId:null,voiceId:null});
    else close();
  }
  function click(event) {
    if(!active)return;
    const button=event.target.closest('[data-inspect]');
    if(!button || !dialog.contains(button))return;
    event.stopPropagation();
    const action=button.dataset.inspect;
    if(action==='back')back();
    else if(action==='crumb') {
      const target=button.dataset.step;
      if(target==='room')close();
      else if(target==='claim')go('claim',{evidenceId:null,voiceId:null});
      else if(target==='evidence')go('evidence',{voiceId:null});
    } else if(action==='evidence')go('evidence',{evidenceId:button.dataset.id,voiceId:null});
    else if(action==='source')go('source',{evidenceId:button.dataset.evidence,voiceId:button.dataset.id});
  }
  // Native dialog keeps the page inert; explicitly wrap Tab at the modal edges
  // so keyboard navigation cannot move into browser chrome in tested Chromium.
  function keydown(event) {
    if (!active || !dialog.open || event.key !== 'Tab') return;
    const controls=[...dialog.querySelectorAll('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')]
      .filter(el=>el.getClientRects().length && !el.closest('[hidden],[inert]'));
    if (!controls.length) {event.preventDefault();dialog.querySelector('#modal-title')?.focus();return;}
    const index=controls.indexOf(document.activeElement);
    if (event.shiftKey && index<=0) {event.preventDefault();controls.at(-1).focus();}
    else if (!event.shiftKey && index===controls.length-1) {event.preventDefault();controls[0].focus();}
  }
  dialog.addEventListener('keydown',keydown);
  // A change from another tab invalidates the read snapshot. Close only this
  // inspector, never a compose form, before stale local text can remain visible.
  window.addEventListener('storage',event=>{
    if (active && (event.key===STORE_KEY || event.key===null)) close();
  });
  dialog.addEventListener('click',click);
  dialog.addEventListener('close',()=>{
    active=false;context=null;remembered.clear();dialog.classList.remove('evidence-inspector');
    delete dialog.dataset.inspectStage;document.body.classList.remove('inspector-open');
  });
  return {
    openClaim:(roomId,claimId)=>open({roomId,claimId},'claim'),
    openEvidence:(roomId,evidenceId)=>open({roomId,evidenceId},'evidence'),
    openVoice(voiceId) {
      const v=getVoices().find(item=>item.id===voiceId);
      return v ? open({roomId:v.roomId,voiceId},'source') : false;
    }
  };
}
