# P2.1c.2d.2a — Least-Privilege / No-Bypass DB Runtime Role

## Task เดียวของรอบนี้
ปิดส่วนเล็กที่สุดของ gate หลัง P2.1c.2d.1: จำกัดบัญชี runtime ฝั่งฐานข้อมูลให้เรียกได้เฉพาะ wrapper ของ PRIVATE draft authorization fence โดย **อ่าน/แก้ authority tables ไม่ได้, เขียน Voice history ตรง ๆ ไม่ได้ และยกระดับไป guard/migration role ไม่ได้**

นี่เป็น P2.1c.2d.2a ไม่ใช่การปิด 2d.2 ทั้งก้อน เพราะการส่ง server-owned authorization stamp จาก signed-token pipeline ไป transaction ยังเป็น UNKNOWN ถัดไป

ไม่สร้าง Login จริง ไม่สร้าง HTTP route ไม่เขียน Voice ไม่เปลี่ยน frontend และไม่ deploy migration กับ production

## Concrete Output
`001_runtime_roles.sql` สร้าง role แบบ NOLOGIN สองตัว:

- `echo_private_draft_guard` — SECURITY DEFINER owner ที่มี USAGE schema + SELECT principals/sessions + EXECUTE fence เดิม และ UPDATE **เฉพาะ immutable key column** (`principal_id`, `session_key`) เพื่อให้ PostgreSQL อนุญาต `SELECT ... FOR SHARE`
- `echo_private_draft_runtime` — ไม่มี table privileges; มีเพียง USAGE schema และ EXECUTE `runtime_private_draft_fence(...)`

ไม่มี role membership ระหว่างกัน และทั้งคู่เป็น NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOINHERIT/NOREPLICATION/NOBYPASSRLS

PostgreSQL 17 กำหนดว่า `SELECT ... FOR UPDATE/FOR SHARE` ต้องมี SELECT และ UPDATE privilege อย่างน้อยหนึ่ง column. CI รอบแรกจึงตรวจพบว่าการให้ guard เพียง SELECT ทำให้ valid fence เรียกไม่ได้ เราแก้โดยให้ column-level UPDATE เฉพาะ immutable key ที่จำเป็นต่อ row-lock permission แทน table-wide UPDATE. Runtime เองยังไม่มี UPDATE ใด ๆ และไม่สามารถ SET ROLE เป็น guard ได้

wrapper ไม่มี dynamic SQL, ใช้ target แบบ schema-qualified, fixed `search_path = pg_catalog, pg_temp`, ไม่คืน token/ticket ที่ใช้ซ้ำได้ และ PUBLIC ถูก revoke ก่อนโอน ownership ไป guard role. แนวทางนี้สอดคล้องกับคำแนะนำ PostgreSQL สำหรับ SECURITY DEFINER: จำกัด search_path และถอน PUBLIC EXECUTE ก่อน grant แบบเจาะจง

## สิ่งที่ runtime ทำได้ / ทำไม่ได้

```text
future service login
      │ SET ROLE (ยังไม่ provision ในงานนี้)
      ▼
echo_private_draft_runtime
      │
      └── EXECUTE echo_identity.runtime_private_draft_fence(...)
                         │ SECURITY DEFINER
                         ▼
                echo_private_draft_guard
                         │ SELECT authority
                         │ + key-column UPDATE privilege only for row locks
                         ▼
             existing assert_private_draft_fence
```

Runtime **ทำไม่ได้**: SELECT/UPDATE principals, SELECT/UPDATE sessions, เรียก lookup_session, เรียก underlying fence ตรง ๆ, อ่าน/INSERT `echo_core.voice_revisions`, CREATE/ALTER function ใน identity schema, SET ROLE เป็น guard, SET session_replication_role, GRANT guard ให้ตนเอง

Guard ไม่มี table-wide UPDATE, ไม่มี UPDATE บน authority columns เช่น `writer_enabled` หรือ `revoked`, ไม่มี INSERT/DELETE/TRUNCATE และไม่มีสิทธิ์ core Voice history. การให้ UPDATE บน key column เป็นข้อจำเป็นของ PostgreSQL row locking ไม่ใช่สิทธิ์ของ application runtime และ guard เป็น NOLOGIN/no-membership role

## สำคัญ: ยังไม่ใช่ write path
การเรียก wrapper เดี่ยว ๆ แล้ว transaction จบจะปล่อย row locks จึงไม่เกิดสิทธิ์ที่นำไปใช้ภายหลัง Future writer ต้องเรียก wrapper **ใน transaction เดียว** กับ target write และ final check ตามสัญญา 2d.1

พารามิเตอร์ wrapper ยังถือเป็น trusted backend inputs การรู้ session digest/actor tuple ไม่ใช่ authentication. งานนี้ไม่ได้ทำให้ browser/client ส่ง stamp ได้อย่างปลอดภัย และไม่มี route ให้ browser เรียก DB

## Verification Contract
ชุดใหม่ `test_runtime_roles.py` ใช้ PostgreSQL 17 จริงในฐาน disposable `echo_runtime_role_test` และตรวจ 20 unittest methods:

- role attributes/membership
- exact schema/function/table และ key-column privileges
- valid wrapper invocation
- denial ของ direct authority/core access และ privilege escalation
- wrapper SECURITY DEFINER owner/search_path
- forged actor/source/principal/version/session/capability
- committed revoke/disable/writer removal
- time validity และ isolation mode
- ไม่มี reusable authorization ticket

ฐานถูกล้าง schema/roles หลัง suite และต้องมี marker `CLEAN_RUNTIME_ROLE_DATABASE`

CI ของงานนี้แยกเก็บ evidence; เนื่องจากไฟล์อยู่ใต้ `database/**`, gate P2.1c.2d.1 เดิมจะถูก trigger พร้อมกันและ rerun regressions/backend fence ทั้งชุดโดยอัตโนมัติด้วย จึงไม่คัดลอก regression suite ซ้ำใน workflow ใหม่

Expected test count เป็นเพียง expectation; สถานะ SAT ต้องมาจาก runtime ของ commit จริง

## SAT / VIOL / UNKNOWN boundary
- **SAT ได้เฉพาะเมื่อ** 20 runtime-role tests ผ่าน + cleanup ผ่าน + P2.1c.2d.1 regression workflow ของ PR เดียวกันผ่าน
- **VIOL** หาก runtime อ่าน/แก้ authority, เขียน core history, เรียก underlying privileged surface หรือยกระดับ role ได้
- **UNKNOWN แม้ SAT:** compromised migration/DB owner/superuser, real service-login provisioning, connection-pool role reset, server-stamp propagation, HTTP/API input binding, real Voice immutable write, reviewer object permission, RLS/privacy/erasure, idempotency/outbox/failover

## Completed / Blocked / Next
**Completed เมื่อ CI ผ่าน:** database-side least-privilege/no-bypass boundary around the existing PRIVATE draft fence

**Blocked:** browser write และ real Voice writer ยังปิดอยู่

**Next: P2.1c.2d.2b — Server-Owned Authorization Stamp Propagation** ให้ signed-token + durable-registry path สร้าง stamp ภายใน backend เอง (issuer/subject/session/principal/actor/source/version/token times) และส่งเข้า transaction adapter โดย request JSON ไม่สามารถตั้ง/แก้ stamp ได้ จากนั้นค่อยทำ P2.1c.2d.3 real immutable PRIVATE Voice write

## Primary references
- PostgreSQL 17 Privileges — `SELECT ... FOR UPDATE/FOR SHARE` ต้องมี UPDATE privilege อย่างน้อยหนึ่ง column เพิ่มจาก SELECT
  https://www.postgresql.org/docs/17/ddl-priv.html
- PostgreSQL 17 CREATE FUNCTION — SECURITY DEFINER safe search_path และการ revoke PUBLIC EXECUTE
  https://www.postgresql.org/docs/17/sql-createfunction.html
- PostgreSQL 17 role attributes / membership
  https://www.postgresql.org/docs/17/role-attributes.html
- PostgreSQL 17 GRANT
  https://www.postgresql.org/docs/17/sql-grant.html

นี่เป็น security contract ของ Echo ในฐานทดลอง ไม่ใช่การรับรอง production security หรือความจริงของเนื้อข่าว
