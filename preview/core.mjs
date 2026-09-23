// Browser-local research model. No network, automatic verification or authentication.
export const VERSION = '0.1.0';
export const STORE_KEY = 'echo.preview.v1';
export const TYPES = { observation: 'รายงานสิ่งที่เห็น', question: 'ตั้งคำถาม', perspective: 'แสดงมุมมอง', correction: 'ทักท้วง / แก้ไข' };
export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const initialState = () => ({ version: 1, voices: [], follows: [] });
export function makeVoice({id, text, kind, roomId, includeInRoom, createdAt}, rooms) {
  if (typeof id !== 'string' || !/^local-[\w-]{1,74}$/.test(id)) throw Error('รหัสโพสต์ไม่ถูกต้อง');
  if (typeof text !== 'string' || !text.trim() || [...text.trim()].length > 1000) throw Error('กรุณาเขียนข้อความ 1–1,000 ตัวอักษร');
  if (!Object.hasOwn(TYPES, kind)) throw Error('เลือกประเภทของเสียง');
  if (!rooms.some(r => r.id === roomId)) throw Error('ไม่พบห้องที่เลือก');
  if (typeof includeInRoom !== 'boolean') throw Error('ระบุสิทธิ์การแสดงในห้อง');
  if (typeof createdAt !== 'string' || !Number.isFinite(Date.parse(createdAt))) throw Error('เวลาบันทึกไม่ถูกต้อง');
  return { id, text: text.trim(), kind, roomId, includeInRoom, createdAt, author: 'คุณ', handle: 'local-you', local: true };
}
export function normalizeState(raw, rooms) {
  if (!raw || raw.version !== 1 || !Array.isArray(raw.voices) || !Array.isArray(raw.follows)) throw Error('รูปแบบข้อมูลทดลองไม่รองรับ');
  if (raw.voices.length > 200) throw Error('ข้อมูลทดลองเกินขอบเขตที่รองรับ');
  const ids = new Set();
  const voices = raw.voices.map(v => {
    const clean = makeVoice(v, rooms);
    if (ids.has(clean.id)) throw Error('พบรหัสโพสต์ซ้ำ');
    ids.add(clean.id); return clean;
  });
  return { version: 1, voices, follows: [...new Set(raw.follows.filter(id => rooms.some(r => r.id === id)))] };
}
export function roomVoices(roomId, seedVoices, state) {
  return [...seedVoices, ...state.voices].filter(v => v.roomId === roomId && v.includeInRoom === true);
}
export function counts(roomId, seedVoices, state) {
  const v = roomVoices(roomId, seedVoices, state);
  return { voices: v.length, people: new Set(v.map(x => x.handle)).size, local: v.filter(x => x.local).length };
}
export function selectRooms(rooms, seed, state, {query='', filter='all'}={}) {
  const q = query.trim().toLocaleLowerCase('th');
  return rooms.filter(r => {
    if (filter === 'following' && !state.follows.includes(r.id)) return false;
    if (filter === 'community' && r.category !== 'community') return false;
    if (filter === 'tech' && r.category !== 'tech') return false;
    const haystack = [r.title, r.place, r.description, ...roomVoices(r.id, seed, state).map(v => v.text)].join(' ').toLocaleLowerCase('th');
    return !q || haystack.includes(q);
  });
}
export function toggleFollow(state, roomId, rooms) {
  if (!rooms.some(r => r.id === roomId)) throw Error('ไม่พบห้อง');
  return {...state, follows: state.follows.includes(roomId) ? state.follows.filter(x => x !== roomId) : [...state.follows, roomId]};
}
export function addVoice(state, input, rooms) {
  if (state.voices.length >= 200) throw Error('ต้นแบบจำกัด 200 โพสต์ต่อเบราว์เซอร์ กรุณาลบโพสต์เก่าก่อน');
  const voice = makeVoice(input, rooms);
  if (state.voices.some(v => v.id === voice.id)) throw Error('รหัสโพสต์ซ้ำ');
  return {...state, voices:[...state.voices, voice]};
}
export function setRoomVisibility(state, id, value) {
  if (typeof value !== 'boolean' || !state.voices.some(v => v.id === id)) throw Error('ไม่พบโพสต์ในเครื่อง');
  return {...state, voices:state.voices.map(v => v.id === id ? {...v, includeInRoom:value} : v)};
}
export function removeVoice(state, id) { return {...state, voices:state.voices.filter(v => v.id !== id)}; }
export function evidenceFamilies(room) { return new Set(room.evidence.map(e => e.family)).size; }
