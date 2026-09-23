# P2.1c.2a — Public Voice Read Boundary v0.1

## งานเดียวของรอบนี้
ปิดช่องข้อมูลเสียงสาธารณะระดับฐานข้อมูลก่อนเปิด API: บัญชีอ่านสาธารณะเห็นได้เฉพาะ **revision ล่าสุดของ Voice ที่ revision ล่าสุดเป็น PUBLIC** เท่านั้น ถ้าเจ้าของสร้าง revision ใหม่เป็น PRIVATE / RESTRICTED / WITHDRAWN ข้อมูล PUBLIC รุ่นเก่าต้องหายจาก public projection ทันที

นี่เป็นเพียง read boundary ของ Voice ไม่ใช่ระบบ Login, writer/reviewer authorization, Room publication, payload service, AI verification หรือ privacy-erasure workflow

## Decision

ใช้ `echo_public.current_public_voices` เป็น security-barrier view และกลุ่มสิทธิ์ `echo_public_reader` แบบ NOLOGIN

- กลุ่ม reader ไม่มีสิทธิ์ `echo_core` หรือ `echo_history`
- view คืนเพียง `voice_id, revision, payload_ref, posted_at, recorded_at`
- ไม่คืน `author_id`, `source_id`, `visibility`, actor/source rows, room links, claims/evidence หรือ audit
- view หา head ด้วยเลข revision ซึ่งถูก append-only/predecessor-checked แล้ว ไม่ใช้ `recorded_at`/`posted_at` จาก client เป็นตัวตัดสินรุ่นล่าสุด
- เฉพาะ head ที่เป็น PUBLIC จึงปรากฏ รุ่น PUBLIC ในอดีตไม่รั่วกลับมาเมื่อ head ถูกถอนหรือจำกัดสิทธิ์
- `payload_ref` เป็น opaque locator สำหรับ backend; ยังต้องมี content resolver ที่บังคับ access decision ซ้ำก่อนส่ง bytes/text ออกสู่ HTTP
- browser ห้ามถือ credential ฐานข้อมูล กลุ่มนี้ตั้งเป็น NOLOGIN เพื่อให้ connection role ในอนาคต inherit เท่านั้น

เหตุผลที่ไม่ใช้ `WHERE visibility='PUBLIC'` ตรง ๆ กับทุก revision คือจะทำให้ revision เก่าที่ยังมีค่า PUBLIC รั่วหลังผู้ใช้ถอน/จำกัดสิทธิ์ใน revision ใหม่

## Runtime verification

`tests_postgres.sql` ใช้ PostgreSQL 17 ฐานทดสอบแบบทิ้งได้ และตรวจ 28 ข้อ เช่น private fixture ถูกซ่อน, PUBLIC head ปรากฏหนึ่งรุ่น, RESTRICTED/WITHDRAWN head ซ่อน public history, explicit republication ต้องเป็น revision ใหม่, reader ไม่มี direct table/history/assessment/room-link access, ไม่เขียน view ได้ และ revision ไม่ใช่ client timestamp เป็นตัวเลือก head

CI ต้องรัน P2.1b 24 checks, P2.1c.1 79 checks และ suite นี้ 28 checks ก่อน task นี้จะเป็น SAT. จำนวนที่เขียนไว้เป็น expected checks ไม่ใช่ผลผ่านก่อน runtime จริง

## SAT / VIOL / UNKNOWN contract

SAT เมื่อ runtime จริงยืนยัน policy ตาม suite และ CLEAN_ROLLBACK

VIOL หาก public reader อ่าน PRIVATE/RESTRICTED/WITHDRAWN Voice, อ่าน historical PUBLIC หลัง head ไม่ PUBLIC, เข้า base/history tables ได้ หรือเขียนผ่าน projection ได้

UNKNOWN ที่ตั้งใจคงไว้: ตัวตนผู้ใช้เว็บและ reviewer, API/JWT binding, owner read, RESTRICTED audience membership, room links/claims/evidence publication, payload byte access, cache/search/CDN invalidation, deletion/backup erasure, snapshot sealing, semantic/media correctness และ multi-writer ordering

## Completed / Blocked / Next

- Concrete output: migration/view + DB role + 28-check runtime suite + isolated CI gate
- Production public read: ยัง BLOCKED เพราะ room/payload/cache visibility chain ยังไม่ครบ
- Next smallest dependent task: **P2.1c.2b — trusted writer/reviewer command boundary**: ให้ backend role เขียนผ่าน command interface ที่ผูก authenticated actor/reviewer และไม่ให้ client ระบุ actor_id เพื่อสวมสิทธิ์เอง

งานนี้ไม่เปลี่ยนหน้าเว็บ ไม่เชื่อมผู้ใช้จริง และไม่แตะฐาน production
