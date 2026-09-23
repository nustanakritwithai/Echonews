import { ROOMS, VOICES, KINDS, TOPICS } from './data.js';
export const STORAGE_KEY='echo-news-preview-v1';
export const escapeHTML=(value)=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function safeURL(value){if(!value)return '';try{const u=new URL(value);return ['http:','https:'].includes(u.protocol)?u.href:''}catch{return ''}}
const idOK=v=>typeof v==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(v);
export function emptyStore(){return {version:1,voices:[],rooms:[],following:[]}}
export function normalizeStore(raw){
 const out=emptyStore();if(!raw||raw.version!==1)return out;
 if(Array.isArray(raw.rooms))for(const r of raw.rooms.slice(0,50)){if(r&&idOK(r.id)&&r.id.startsWith('local-')&&typeof r.title==='string'&&r.title.trim()&&!out.rooms.some(x=>x.id===r.id))out.rooms.push({id:r.id,title:r.title.slice(0,140),short:r.title.slice(0,70),category:TOPICS.includes(r.category)&&r.category!=='ทั้งหมด'?r.category:'พื้นที่และชุมชน',place:'ห้องทดลองส่วนตัว · เฉพาะเครื่องนี้',theme:'water',updated:'ในเครื่อง',intro:'ห้องที่สร้างในเครื่องนี้ ยังไม่ถูกเผยแพร่ให้ผู้อื่น',quote:'ข้อมูลใหม่ยังรอการประเมิน',claims:[],local:true})}
 const roomIds=new Set([...ROOMS,...out.rooms].map(r=>r.id));
 if(Array.isArray(raw.voices))for(const v of raw.voices.slice(-200)){if(v&&idOK(v.id)&&v.id.startsWith('local-')&&roomIds.has(v.roomId)&&Object.hasOwn(KINDS,v.kind)&&typeof v.text==='string'&&v.text.trim()&&!out.voices.some(x=>x.id===v.id))out.voices.push({id:v.id,roomId:v.roomId,name:String(v.name||'คุณ').slice(0,40),kind:v.kind,text:v.text.slice(0,2000),time:typeof v.time==='string'?v.time.slice(0,25):'ไม่ระบุ',createdAt:Number.isFinite(v.createdAt)?v.createdAt:0,shared:v.shared===true,link:safeURL(v.link),local:true})}
 if(Array.isArray(raw.following))out.following=[...new Set(raw.following.filter(x=>roomIds.has(x)))];
 return out;
}
export function allRooms(store){return [...ROOMS,...store.rooms]}
export function allVoices(store){return [...VOICES,...store.voices]}
export function roomVoices(id,store){return allVoices(store).filter(v=>v.roomId===id&&(!v.local||v.shared))}
export function roomStats(id,store){const v=roomVoices(id,store);return {voices:v.length,people:new Set(v.map(x=>x.local?'local-owner':x.name)).size,families:new Set(v.filter(x=>x.evidence).map(x=>x.evidence.family)).size,pending:v.filter(x=>x.local).length}}
export function groups(id,store){const v=roomVoices(id,store);return Object.entries(KINDS).map(([kind,label])=>({kind,label,voices:v.filter(x=>x.kind===kind)}))}
export function getClaimState(claim,store){const visible=new Set(allVoices(store).filter(v=>!v.local||v.shared).map(v=>v.id));const support=(claim.support||[]).filter(id=>visible.has(id));const counter=(claim.counter||[]).filter(id=>visible.has(id));return {status:support.length?(counter.length?'DISPUTED':'SUPPORTED'):(counter.length?'COUNTERED':'UNKNOWN'),support,counter,freshness:'UNKNOWN'}}
export function filterRooms(store,{query='',topic='ทั้งหมด',following=false,latest=false}={}){const q=query.trim().toLocaleLowerCase('th');let rooms=allRooms(store).filter(r=>(topic==='ทั้งหมด'||r.category===topic)&&(!following||store.following.includes(r.id)));if(q)rooms=rooms.filter(r=>[r.title,r.category,r.place,...roomVoices(r.id,store).map(v=>v.text)].some(s=>s.toLocaleLowerCase('th').includes(q)));if(latest)rooms=[...rooms].sort((a,b)=>String(b.updated).localeCompare(String(a.updated)));return rooms}
export function makeVoice(input,store,uuid,now=Date.now()){
 const text=String(input.text||'').trim(),name=String(input.name||'คุณ').trim();
 if(!text||text.length>2000)throw new Error('เขียนข้อความ 1–2,000 ตัวอักษร');
 if(!name||name.length>40)throw new Error('ชื่อที่แสดงต้องยาว 1–40 ตัวอักษร');
 if(!Object.hasOwn(KINDS,input.kind))throw new Error('กรุณาเลือกชนิดของเสียง');
 if(!allRooms(store).some(r=>r.id===input.roomId))throw new Error('ไม่พบห้องที่เลือก');
 const link=String(input.link||'').trim();if(link&&!safeURL(link))throw new Error('ลิงก์ต้องเริ่มด้วย https:// หรือ http://');
 if(store.voices.length>=200)throw new Error('เดโมเก็บได้ 200 โพสต์ กรุณาลบโพสต์เดิมก่อน');
 const id='local-'+uuid;if(!idOK(id)||allVoices(store).some(v=>v.id===id))throw new Error('รหัสโพสต์ซ้ำหรือไม่ถูกต้อง');
 return {id,roomId:input.roomId,name,text,kind:input.kind,link:safeURL(link),time:new Date(now).toLocaleTimeString('th-TH',{hour:'2-digit',minute:'2-digit'}),createdAt:now,shared:input.shared===true,local:true};
}
export function makeRoom(title,category,uuid,store){const t=String(title||'').trim();if(!t||t.length>140)throw new Error('ชื่อห้องต้องยาว 1–140 ตัวอักษร');if(store.rooms.length>=50)throw new Error('เดโมเก็บได้ไม่เกิน 50 ห้อง');const id='local-'+uuid;if(!idOK(id)||allRooms(store).some(r=>r.id===id))throw new Error('รหัสห้องซ้ำ');return {id,title:t,short:t.slice(0,70),category:TOPICS.includes(category)&&category!=='ทั้งหมด'?category:'พื้นที่และชุมชน',place:'ห้องทดลองส่วนตัว · เฉพาะเครื่องนี้',theme:'water',updated:'ในเครื่อง',intro:'ห้องที่สร้างในเครื่องนี้ ยังไม่ถูกเผยแพร่ให้ผู้อื่น',quote:'ข้อมูลใหม่ยังรอการประเมิน',claims:[],local:true}}
export function removeVoice(store,id){return {...store,voices:store.voices.filter(v=>v.id!==id)}}
export function toggleFollow(store,id){if(!allRooms(store).some(r=>r.id===id))return store;return {...store,following:store.following.includes(id)?store.following.filter(x=>x!==id):[...store.following,id]}}
