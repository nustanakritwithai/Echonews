# P2.1c.2d.3c — Idempotent PRIVATE Draft Execution Receipt

## งานเดียวของรอบนี้
ปิดช่อง network retry ที่อาจสร้าง PRIVATE Voice ซ้ำหลังคำขอแรก commit แล้วแต่ response หาย โดยกำหนด idempotency key เป็น `(principal_id, request_id)` และเก็บ receipt ใน PostgreSQL transaction เดียวกับ Voice revision 1

ยัง **ไม่เปิด HTTP route / Browser write / PUBLIC publish** และไม่เปลี่ยนหน้าเว็บ งานนี้ต่อจาก P2.1c.2d.3b เท่านั้น

## Contract
Browser ยังเลือก `request_id` ได้ เพราะมันเป็น request correlation/idempotency key ไม่ใช่ authority. Actor/Source/permission/session ยังคงมาจาก signed token + durable registry + DB fence

Backend คำนวณ `request_hash = SHA-256("echo/private-draft/v1\\0" + exact UTF-8 text)` เอง หาก principal เดิมใช้ request_id เดิมกับข้อความเดิมจะได้ receipt เดิม หากเปลี่ยนข้อความแต่ reuse key ระบบปฏิเสธ `IDEMPOTENCY_KEY_REUSED`

Receipt เก็บเฉพาะ principal_id, request_id, request_hash, voice_id, revision=1, visibility=PRIVATE และ recorded_at ไม่เก็บ raw token หรือเนื้อหา Voice และมี FK ไปยัง immutable Voice revision

## Concurrency
PostgreSQL ใช้ transaction-scoped advisory lock ที่ derive จาก principal_id + request_id เพื่อ serialize retry key เดียวกัน แล้วตรวจ exact composite key ใน receipt table อีกครั้ง ดังนั้น hash collision ของ advisory lock ทำได้เพียงทำให้ request ที่ไม่เกี่ยวข้องรอกัน แต่ไม่ merge identity/request เข้าด้วยกัน

ลำดับ fresh request:

```text
signed BoundIntent
→ stage payload ด้วย server voice UUID
→ DB fence recheck
→ lock principal+request key
→ ไม่มี receipt
→ immutable PRIVATE Voice insert
→ receipt insert
→ COMMIT
```

ลำดับ retry:

```text
signed BoundIntent เดิม/ใหม่ของ principal เดิม
→ stage payload ชั่วคราว
→ DB fence recheck
→ lock key
→ พบ receipt + request_hash เดิม
→ return canonical receipt
→ discard payload ที่ stage ใน retry
```

Auth ถูกตรวจใหม่แม้เป็น replay: revoked/disabled/expired caller ไม่ได้ receipt เพียงเพราะเคยสำเร็จในอดีต

## No-bypass
เมื่อ migration นี้ติดตั้ง จะ revoke `EXECUTE` ของ `runtime_append_private_voice(...)` จาก `echo_private_draft_runtime` และให้ runtime เรียกได้เฉพาะ idempotent wrapper ใหม่ Lower-level writer ยังเป็นของ NOLOGIN guard เพื่อใช้ภายใน wrapper เท่านั้น Runtime ไม่มี SELECT/INSERT/UPDATE/DELETE receipt table โดยตรง

## Payload boundary ที่ยัง UNKNOWN
Payload ถูก stage ก่อน DB transaction เช่นเดียวกับ 3b การ retry ที่แพ้ canonical receipt จะเรียก `discard_payload` ของ staged ref นั้น ดังนั้น production payload store ต้องรับรองว่า ref เป็น object เฉพาะ voice_id ที่ส่งเข้าไป และ discard ไม่ลบ shared content ของ Voice ที่ commit แล้ว

ยังไม่ atomic ข้าม payload store + PostgreSQL หาก process crash หลัง stage payload แต่ก่อน DB commit อาจมี orphan; หาก DB commit แล้ว process crash ก่อน response retry จะคืน receipt เดิม แต่ recovery/GC ของ staged object ยังเป็นงานถัดไป

## Verification gate
ชุดใหม่ต้องใช้ PostgreSQL 17 + RSA/RS256 + durable registry + runtime role + DB fence + PRIVATE writer จริง และพิสูจน์อย่างน้อย:

- first request → fresh receipt + Voice เดียว
- exact retry → canonical receipt เดิม, ไม่สร้าง Voice/receipt เพิ่ม
- concurrent exact retry → fresh 1 / replay 1, Voice เดียว
- same principal + same key + changed text → conflict, no duplicate
- same request_id คนละ principal → ไม่ชนกัน
- revoke/role removal หลัง success → replay ถูก deny
- client ส่ง request_hash/voice_id/receipt metadata → Boundary reject
- runtime เรียก lower-level non-idempotent writer ตรง ๆ ไม่ได้หลัง migration
- runtime ไม่มี direct receipt-table privilege
- receipt mutation ถูก trigger ปฏิเสธ
- DB failure rollback ไม่ทิ้ง receipt ที่ไม่มี Voice

จำนวน PASS ต้องยึด CI runtime log จริง ไม่อนุมานจากจำนวน test ที่เขียน

## SAT / UNKNOWN boundary
หาก gate ผ่าน คำว่า idempotent หมายถึง scoped PostgreSQL execution path นี้: request เดิมของ principal เดิมที่ auth ยัง valid จะไม่สร้าง Voice ซ้ำแม้ retry/concurrency

ยัง UNKNOWN/BLOCKED: production payload-store crash recovery/refcount semantics, service LOGIN/pool reset, HTTP/cookie/CSRF/origin/rate limit, PRIVATE owner read/RLS, revision 2/withdraw, PUBLIC publication, reviewer object permission และ privacy erasure

## Next
หลัง task นี้ผ่าน งาน critical dependency ถัดไปคือ **P2.1c.2d.3d — Payload Durability / Recovery Contract**: นิยาม staged→committed payload lifecycle และ recovery/garbage collection เพื่อไม่ให้ DB receipt ชี้ payload ที่สูญหรือ orphan ค้างหลัง process crash ก่อนพิจารณาเปิด HTTP write path
