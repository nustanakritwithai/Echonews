# P2.1c.2d.3b — Backend PRIVATE Voice Execution Adapter

## งานเดียวของรอบนี้
เชื่อม `BoundIntent.authorization_stamp` ที่สร้างจาก signed-token + durable registry เข้ากับ PostgreSQL primitive `runtime_append_private_voice(...)` จาก P2.1c.2d.3a โดยให้ Backend เป็นผู้สร้าง `voice_id` และรับ `payload_ref` จาก trusted payload-store callback เท่านั้น

งานนี้ **ไม่เปิด HTTP route / Browser write / PUBLIC publish** และไม่เปลี่ยนหน้าเว็บ ผู้ใช้ยังส่งได้เพียงข้อความ draft ผ่าน strict Boundary เดิม

## เส้นทางที่ปิดแล้วใน task นี้

```text
raw JSON { request_id, CREATE_VOICE_DRAFT, { text } }
        ↓
Signed-token Boundary + Durable Registry
        ↓
BoundIntent + server-owned AuthorizationStamp
        ↓
PrivateVoiceExecutor
  ├─ ตรวจ exact internal type / command / capability / stamp consistency
  ├─ สร้าง voice_id ด้วย backend uuid4()
  ├─ trusted store_payload(voice_id,text) → opaque payload_ref
  └─ connection ที่ current_user = echo_private_draft_runtime เท่านั้น
        ↓
PostgreSQL runtime_append_private_voice(...)
        ↓
DB fence recheck + immutable revision 1 + PRIVATE
```

Browser ไม่มี parameter สำหรับ `actor_id`, `source_id`, `principal_id`, `session_key`, `auth_version`, `authorization_stamp`, `payload_ref`, `visibility`, `revision`, `posted_at` หรือ `recorded_at` และ field แปลกปลอมถูก Boundary ปฏิเสธก่อน executor

## กฎของ Executor
- รับ exact `BoundIntent` เท่านั้น ไม่รับ dict/JSON-shaped object
- ต้องเป็น `CREATE_VOICE_DRAFT` + `DraftIntent`
- ต้องมี `AuthorizationStamp` แบบ durable และ capability=`voice:draft:create`
- Actor/Source/auth_version/key-set/policy/token-issued จาก intent กับ stamp ต้องสอดคล้องกัน
- `voice_id` สร้างใน Backend และไม่ reuse `request_id`
- payload callback รับเพียง server-generated voice_id + author text; opaque ref ที่คืนต้อง non-empty UTF-8 ไม่มี control/NUL และยาวไม่เกิน 4096
- connection factory ต้องคืน connection ที่ `current_user` เป็น `echo_private_draft_runtime`; ถ้าเผลอส่ง owner/migration connection executor ปฏิเสธแทนการใช้สิทธิ์สูง
- SQL call มีรูปแบบคงที่และส่งเฉพาะ stamp + server voice_id + trusted payload_ref ไป sealed DB writer
- DB เป็นผู้บังคับ revision=1, previous=NULL, visibility=PRIVATE, posted_at=NULL และ recorded_at
- revoke/disable/role-version ที่ commit หลัง bind แต่ก่อน execute ถูกตรวจซ้ำโดย DB writer; ถ้าปฏิเสธ executor เรียก `discard_payload(ref)` แบบ compensation

## สิ่งที่คำว่า server-owned หมายถึงและไม่หมายถึง
มันหมายถึง request decoder ไม่มีทาง bind JSON field มาเป็น authority/write metadata โดยตรง และ executor สร้าง/อ่านค่าเหล่านี้จาก object ภายในที่มาจาก verified path

มัน **ไม่ได้** หมายถึง Python dataclass ป้องกันโค้ดอันตรายที่รันอยู่ใน process เดียวกันได้ โค้ดภายในที่ import class และสร้าง object เองยังเป็น trusted computing base การ harden process/container/supply-chain เป็นคนละ gate

## Payload contract
`store_payload(voice_id,text)` และ `discard_payload(ref)` ยังเป็น trusted callbacks ไม่ใช่ payload store production ที่ทำเสร็จแล้ว ชุดทดสอบใช้ in-memory fixture เท่านั้น

หาก DB write ล้มเหลวหลัง store สำเร็จ adapter จะเรียก discard เพื่อลด orphan แต่ callback ภายนอกไม่สามารถทำ atomic commit เดียวกับ PostgreSQL ได้ ดังนั้น crash ระหว่าง payload-store กับ DB commit, payload durability, encryption, access control, garbage collection และ recovery ยังเป็น UNKNOWN ที่ต้องปิดก่อน production

## Verification contract
CI ใหม่ต้องใช้ PostgreSQL 17 จริง, RSA/RS256 จริง, durable registry จริง, least-privilege runtime role และ sealed PRIVATE writer จริง

ทดสอบอย่างน้อย:
- signed BoundIntent → Voice revision 1 PRIVATE
- Browser authority/visibility/revision/payload_ref injection → reject
- dict lookalike → reject
- Backend-generated voice_id + trusted payload ref
- mismatched/missing/review stamp → reject
- revoke หรือ role change หลัง bind → DB deny และไม่มี Voice row
- payload store failure/invalid ref → ไม่มี Voice row
- owner connection → executor reject
- signed role/admin hints → ไม่เปลี่ยน author/source/visibility

workflow รัน regression P2.1c.2d.3a แยกฐานก่อน suite ใหม่ จำนวน PASS ให้ยึด runtime log จริง ไม่อนุมานจากไฟล์

## SAT / UNKNOWN boundary
เมื่อ suite ผ่าน เราพิสูจน์ได้เฉพาะ execution adapter path นี้ว่า Browser JSON ไม่สามารถกำหนด authority/write metadata และ Backend ใช้ runtime writer ที่ DB recheck authority อีกครั้ง

ยัง UNKNOWN/BLOCKED:
- payload store จริงและ atomicity/crash recovery
- idempotency/network retry (retry ตอนนี้อาจสร้าง Voice ใหม่อีกอัน)
- service LOGIN credential และ connection-pool role reset
- HTTP transport/cookie/CSRF/origin/rate limit
- PRIVATE owner read / RESTRICTED / RLS / privacy erasure
- revision 2 / withdraw / PUBLIC publish
- reviewer object authorization/self-review

`BoundIntent.ready_for_execution` ยังคง `False`; ไม่มี generic execute flag ถูกเปิด งานนี้เป็น narrow executor เฉพาะ PRIVATE draft เท่านั้น

## Next
หลัง gate นี้ผ่าน งานถัดไปบน P2 ต้องปิด **P2.1c.2d.3c — Idempotent PRIVATE Draft Execution Receipt** ให้ request retry เดิมไม่สร้าง Voice ซ้ำ และต้องนิยาม transaction/receipt boundary โดยไม่รับ idempotency result จาก client เป็น authority จากนั้นจึงพิจารณา payload durability coupling / service login ตาม dependency ที่เหลือ
