# P2.1c.2d.3d — Payload Durability / Recovery Contract

## งานเดียวของรอบนี้
ปิด Critical UNKNOWN จาก P2.1c.2d.3c: payload bytes อยู่คนละระบบกับ PostgreSQL จึงไม่สามารถอ้าง atomic transaction ข้ามสองระบบได้

รอบนี้เพิ่ม **durable recovery ledger + state machine** เพื่อให้ crash กลายเป็นงานที่ตรวจพบและกู้คืนได้ โดยยังไม่เปิด HTTP/Browser write, PRIVATE read หรือ PUBLIC publish

## State machine

```text
RESERVED
  ├─ Voice+receipt DB transaction สำเร็จ → NEEDS_COMMIT → COMMITTED
  └─ แพ้ retry / stale timeout        → ABANDONED   → DISCARDED
```

ทุก external stage ต้องมี DB `RESERVED` ก่อน ดังนั้น object ที่ stage แล้วมี attempt_id ให้ recovery ตามกลับได้เสมอ

- `RESERVED`: Backend ผ่าน authorization fence แล้วและจอง attempt UUID แต่ยังไม่มี DB Voice
- `NEEDS_COMMIT`: Voice revision 1 + idempotency receipt commit แล้ว แต่ external store ยังต้อง finalize
- `COMMITTED`: external payload finalize สำเร็จและ DB acknowledge แล้ว
- `ABANDONED`: attempt นี้ไม่ใช่ canonical หรือหมด lease ก่อน finish
- `DISCARDED`: external staged object ของ attempt ที่ abandoned ถูกลบ/ไม่พบแล้ว

Transition ถูกจำกัดด้วย trigger; identity ของ attempt เปลี่ยนย้อนหลังไม่ได้ และ runtime ไม่มี direct table DML

## Ordering

Fresh request:

```text
signed BoundIntent + server stamp
→ DB reserve attempt (authorization recheck)
→ payload store stage(attempt_id, exact text)  [must be durable before return]
→ one DB transaction:
     authorization fence
     idempotency decision
     immutable PRIVATE Voice + receipt
     attempt -> NEEDS_COMMIT
→ payload store commit(ref)                   [must be idempotent]
→ DB attempt -> COMMITTED
→ only now may executor return success
```

Retry ที่แพ้ canonical receipt จะเปลี่ยน attempt ของตัวเองเป็น `ABANDONED`, finalize canonical payload ก่อน แล้ว discard staged payload ของตัวเอง

## Crash recovery

Recovery ใช้ DB ledger เป็น authority ไม่เดาจาก directory อย่างเดียว:

- `NEEDS_COMMIT`: เรียก `store.commit(ref)` ซ้ำได้ แล้ว ack `COMMITTED`
- `ABANDONED`: `store.discard(ref)` ซ้ำได้ แล้ว ack `DISCARDED`
- `RESERVED` ที่หมด `recover_after`: claim เป็น ABANDONED แบบ atomic ก่อนค้น staged object จาก attempt_id และ discard

การ claim stale แข่งกับ writer ด้วย row lock/state transition เดียวกัน ถ้า writer เปลี่ยน state ก่อน recovery จะ claim ไม่ได้; ถ้า recovery claim ก่อน writer จะเขียนไม่ได้ จึงไม่ควรเกิดกรณี recovery ลบ payload ที่ writer เพิ่งทำให้ canonical หลัง claim สำเร็จ

Reservation lease รอบนี้ fixed 5 นาทีใน DB contract. ค่านี้เป็น safety profile สำหรับ prototype ไม่ใช่ SLA production; production ต้องวัด stage/write latency และออกแบบ worker ownership/monitoring ก่อนใช้จริง

## Payload store contract
`DurablePayloadStore` ที่ production จะเสียบเข้ามาต้องรับรอง:

1. `stage(attempt_id,text)` เขียน bytes แบบ durable ก่อน return
2. ref คงเดิมตลอด STAGED → COMMITTED และเฉพาะ attempt นั้น
3. `commit(ref)` idempotent
4. `discard(ref)` idempotent และห้ามลบ COMMITTED object
5. `find_staged(attempt_id)` ใช้ได้หลัง process restart
6. store ห้าม dedupe shared mutable object ถ้า discard ของ losing attempt อาจลบ canonical payload

Test suite ใช้ filesystem fixture ที่ state อยู่บน disk และสร้าง store object ใหม่เพื่อจำลอง process restart แต่ **ไม่ใช่ production object store implementation และไม่พิสูจน์ disk/controller/cloud durability จริง**

## Important failure cases
- Crash หลัง reserve ก่อน stage → stale RESERVED ถูก terminalize โดย recovery
- Crash หลัง stage ก่อน DB Voice → stale RESERVED ถูก claim แล้ว stage ถูก discard
- Crash หลัง DB commit ก่อน store commit → NEEDS_COMMIT ทำให้ worker finalize ภายหลัง
- Store commit สำเร็จแต่ DB ack หาย → commit idempotent แล้ว recovery ack ซ้ำได้
- exact retry ตอน canonical ยัง NEEDS_COMMIT → retry/recovery finalize canonical ก่อนคืน receipt
- same idempotency key + different text → conflict; losing stage ไม่กลายเป็น Voice

Executor ไม่ใช้ compensation แบบ “DB exception แล้วลบ payload ทันที” อีก เพราะ commit outcome อาจ ambiguous. ต้องอ่าน durable attempt state ก่อนเสมอ

## Security boundary
Runtime ยังเป็น `echo_private_draft_runtime` และเรียกได้เฉพาะ sealed SECURITY DEFINER functions ไม่มี SELECT/INSERT/UPDATE/DELETE ตรงบน attempt ledger

Migration นี้ revoke execute ของ old `runtime_idempotent_append_private_voice(...)` จาก runtime เพื่อไม่ให้ bypass recovery ledger

Recovery API คืนเฉพาะ attempt UUID/state/ref/times ที่จำเป็น ไม่คืน subject/email/raw token และไม่ถือ recovery operation เป็น user authorization grant

## Migration boundary
Migration นี้ fail closed ถ้ามี `private_draft_receipts` อยู่ก่อนติดตั้ง เพราะ receipt เก่าไม่มี payload-attempt ledger ให้พิสูจน์ lifecycle. Prototype ปัจจุบันยังไม่มี production data migration; ถ้าวันหนึ่งมี durable receipts จริง ต้องออกแบบและ verify backfill แยก ห้ามเดาสถานะ payload เป็น COMMITTED

## Verification
CI ต้องรัน:
- P2.1c.2d.3c regression 16 cases บนฐาน isolated ของมัน
- payload recovery integration 14 cases บน PostgreSQL 17
- signed RS256 token + durable registry + least-privilege role + immutable Voice writer จริง
- filesystem fixture recreation เพื่อจำลอง recovery ข้าม process object

จำนวน PASS ยึด runtime log จริงเท่านั้น

## SAT / VIOL / UNKNOWN
ถ้า gate ผ่าน SAT หมายถึงเฉพาะ contract นี้: DB Voice/receipt ที่ executor คืน success ต้องมี canonical payload state `COMMITTED`; crash windows ที่ทดสอบทิ้ง state ที่ recovery จำแนกได้ และ stale/noncanonical stages มี terminal cleanup path

ยัง UNKNOWN/BLOCKED:
- production S3/GCS/R2/local object-store adapter, fsync/durability guarantees และ provider outage policy
- recovery worker scheduling/lease ownership/metrics/dead-letter และ long-running operation tuning
- existing production receipt backfill (ถ้ามีในอนาคต)
- service LOGIN/pool reset, HTTP/cookie/CSRF/origin/rate limit
- PRIVATE owner read/RLS, revision 2/withdraw, PUBLIC publish, reviewer object permission, privacy erasure

## Next
หลัง gate นี้ผ่าน earliest P2 dependency ถัดไปคือ **P2.1c.2d.4a — PRIVATE Owner Read Authorization Contract**: owner ต้องอ่าน draft ของตัวเองได้ผ่าน current identity/visibility authorization โดยห้าม PUBLIC reader หรือ principal อื่นเห็น payload และต้อง require payload lifecycle `COMMITTED` ก่อนคืน bytes
