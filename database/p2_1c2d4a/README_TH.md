# P2.1c.2d.4a — PRIVATE Owner Read Authorization Contract

## งานเดียวของรอบนี้
ให้ backend อ่าน metadata ของ PRIVATE Voice ของเจ้าของได้อย่างแคบที่สุด โดยต้องผ่าน authority/session ปัจจุบัน, Actor + Source ต้องตรงกับ Voice, head ปัจจุบันต้องยังเป็น PRIVATE revision 1 และ payload canonical ต้องมีสถานะ `COMMITTED` ก่อนคืน `payload_ref`

งานนี้ **ไม่ใช่ HTTP read API และไม่คืน payload bytes**. `payload_ref` เป็น locator ภายในให้ content resolver ที่เชื่อถือได้ใช้ใน gate ถัดไป Browser ไม่ได้ DB credential และห้ามเรียก function นี้โดยตรง

## Trust path

```text
server-owned authorization tuple
        ↓
echo_private_owner_read_runtime
        ↓
runtime_read_private_owner_voice(...)
        ↓
current principal/session fence + row locks
        ↓
current Voice head
        ↓
principal/Actor/Source ownership
        ↓
idempotency receipt + canonical payload attempt
        ↓
payload_state == COMMITTED
        ↓
opaque payload_ref metadata only
```

## Least privilege
สร้าง role แยกสองตัว:

- `echo_private_owner_read_guard`: `NOLOGIN`, `NOBYPASSRLS`, เป็น owner ของ sealed SECURITY DEFINER function และมี SELECT เท่าที่ต้องใช้
- `echo_private_owner_read_runtime`: `NOLOGIN`, ไม่มี table SELECT/DML และมีเพียง USAGE บน `echo_identity` + EXECUTE ของ owner-read function

ไม่มี membership ระหว่าง read runtime/guard และไม่ให้ writer runtime หรือ `echo_public_reader` เรียก owner-read function

Guard ต้องเรียก `assert_private_draft_fence` ซึ่งใช้ `SELECT ... FOR SHARE`; PostgreSQL ต้องการ SELECT และ UPDATE privilege อย่างน้อยหนึ่ง column เพื่อ lock แบบนี้ จึงให้ UPDATE เฉพาะ immutable key `principals.principal_id` และ `sessions.session_key` เช่นเดียวกับ gate P2.1c.2d.2a ไม่ให้ table-wide UPDATE/INSERT/DELETE

## Authorization semantics
รอบแรกตั้งใจ reuse capability `voice:draft:create` ที่พิสูจน์แล้ว ดังนั้น owner อ่าน draft ได้เมื่อ principal ยัง `enabled`, `writer_enabled`, session ยังไม่ revoke/expire และ `auth_version` ยังตรงกัน ถ้าถอน writer permission, disable account หรือ revoke session การอ่านถูกปฏิเสธ

ยัง **ไม่สร้าง read-only entitlement ใหม่** เพราะ registry ปัจจุบันไม่มี policy bit สำหรับสิทธิ์นั้น การเพิ่มสิทธิ์ใหม่โดยอนุมานจาก email/name/token claim จะข้าม critical dependency จึงไม่ทำใน task นี้

## Object semantics
หลัง authority ผ่านแล้ว function จะคืนแถวได้ก็ต่อเมื่อ:

- `voice_id` มี current head เป็น revision 1
- head เป็น `PRIVATE` และ `posted_at IS NULL`
- `author_id` ตรง Actor ใน server-owned authority tuple
- `source_id` ตรง Source ใน tuple เดียวกัน
- immutable execution receipt เป็นของ principal เดียวกัน
- canonical payload attempt สอดคล้องกับ receipt/request hash
- payload attempt เป็น `COMMITTED`
- payload reference ใน ledger ตรงกับ Voice revision

ถ้า voice ไม่มี, เป็นของคนอื่น, head เปลี่ยนเป็น PUBLIC/WITHDRAWN/RESTRICTED หรือ lineage ไม่ครบ จะคืน **zero rows** เหมือนกัน เพื่อลด private-object existence oracle ไม่คืน error ที่บอกว่า Voice ของคนอื่นมีอยู่จริง

ห้าม fallback ไป PRIVATE revision เก่าเมื่อมี head ใหม่แล้ว หลักการเดียวกับ public-read boundary ที่ไม่ fallback ไป PUBLIC revision เก่า

## Payload boundary
`COMMITTED` หมายถึง recovery coordinator เคยทำ external store commit สำเร็จแล้วและบันทึก acknowledgement ใน PostgreSQL ไม่ได้พิสูจน์ว่า production S3/R2/GCS/local store จะไม่มีวันสูญหาย งาน provider durability/bytes resolver ยัง UNKNOWN

Read function คืนเฉพาะ:

- voice_id
- revision
- payload_ref
- visibility
- recorded_at
- payload_state

ไม่คืน Actor/Source row, principal/session, token, email, claim/evidence หรือ payload bytes

## Verification
CI ใช้ PostgreSQL 17 disposable service และรัน:

1. P2.1c.2a public-read regression 28 checks (transaction rollback)
2. P2.1c.2d.3d payload-recovery regression 14 tests บนฐานแยก
3. P2.1c.2d.4a owner-read integration 16 tests

ชุดใหม่ตรวจ valid owner, `NEEDS_COMMIT`, other principal, forged authority tuple, revoke, disable, writer removal, current-head withdrawal/publication, public-reader isolation, direct table denial, write/recovery denial, runtime separation, guard escalation และ unknown/nil Voice IDs

จำนวน PASS จริงต้องอ่านจาก CI ของ commit/PR จริง ห้ามถือจำนวน test ที่เขียนเป็น SAT จนกว่าจะรันสำเร็จ

## SAT / VIOL / UNKNOWN contract
**SAT ได้เมื่อ:** owner-read suite และ dependency regressions ผ่านบน PostgreSQL 17 จริง และ cleanup กลับเป็นฐาน/role ว่างตามที่ test สร้าง

**VIOL:** private runtime อ่านตารางตรงได้, principal อื่นอ่าน Voice ได้, uncommitted payload ถูกคืน, old PRIVATE fallback หลัง head เปลี่ยน, public reader เรียก private function ได้ หรือ revoked/disabled/stale authority ยังอ่านผ่าน

**UNKNOWN / BLOCKED หลัง task นี้:**

- signed-token HTTP/backend read command ที่สร้าง owner-read stamp โดยเฉพาะ
- payload byte resolver และ provider durability/not-found behavior
- production service LOGIN + connection-pool role reset
- revision 2 / edit / withdraw owner-read lineage
- RESTRICTED sharing/ACL, RLS policy, list/search pagination
- privacy erasure/retention/backups
- PUBLIC publishing และ reviewer object authorization

## Next
**P2.1c.2d.4b — Backend PRIVATE Owner Read Adapter**: เพิ่ม signed backend command/read intent ที่ Browser ส่งได้แค่ `voice_id`, ให้ server สร้าง authority tuple จาก verified token + durable registry แล้วเรียก owner-read runtime; จากนั้น content resolver ต้อง fetch payload ด้วย `payload_ref` ที่อนุญาตแล้วโดยไม่เปิด locator หรือ DB metadata ให้ client โดยตรง

หยุดก่อน HTTP route หรือ PUBLIC publication
