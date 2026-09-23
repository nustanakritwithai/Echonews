# P2.1c.2d.2 — Least-Privilege / No-Bypass Transaction Boundary

## Task
งานเดียวต่อจาก P2.1c.2d.1: ทำขอบเขต DB role/SECURITY DEFINER ที่พิสูจน์ว่า runtime writer ใช้ได้เฉพาะ server-owned transaction capsule และไม่สามารถอ่าน/แก้ authority, mint สิทธิ์เอง, เรียก raw fence หรือเขียน Voice โดยตรงเพื่อข้าม fence

นี่เป็น **research execution probe** ไม่ใช่ production writer: ไม่มี Browser/HTTP route, ไม่ migrate ฐานจริง, ไม่เขียน `echo_core.voice_revisions`, ไม่ publish และไม่เพิ่ม reviewer path

## Concrete Output
`001_least_privilege_boundary.sql` เพิ่ม schema ส่วนตัว `echo_execution` พร้อม:

- `private_draft_tickets`: capsule อายุสั้นที่ bind verified issuer/subject/session + canonical principal/Actor/Source/auth_version + `voice:draft:create` เข้ากับ command_id และ payload_ref ที่ backend ตรวจแล้ว
- `mint_private_draft_ticket(...)`: สำหรับ trusted auth/command bridge เท่านั้น เรียก P2.1c.2d.1 fence ก่อน mint และจำกัดอายุ ticket สูงสุด 30 วินาทีหรือ token expiry แล้วแต่ว่าอันไหนมาก่อน
- `execute_private_draft_probe(ticket_id)`: runtime entrypoint เดียว รับเพียง ticket id; identity, payload และ visibility ไม่ใช่ argument. Lock ticket, recheck fence, เขียน synthetic PRIVATE probe, recheck fence/time อีกครั้ง แล้ว consume ticket ใน transaction เดียว
- ทุก schema/table/function revoke PUBLIC; migration ไม่สร้าง production roles เพราะชื่อ/credential/ownership เป็น deployment concern

`test_least_privilege.py` ติดตั้ง grant matrix บน PostgreSQL service ชั่วคราวด้วย 3 principal จริงระดับ connection:

| Role | LOGIN | สิทธิ์ที่ตั้งใจให้ |
|---|---|---|
| `echo_execution_owner_test` | NOLOGIN | SELECT authority, EXECUTE raw fence, INSERT/SELECT ticket, UPDATE เฉพาะ `consumed_ms`, INSERT probe |
| `echo_auth_bridge_test` | LOGIN (test only) | EXECUTE mint เท่านั้น |
| `echo_runtime_writer_test` | LOGIN (test only) | EXECUTE consume เท่านั้น |

Function owner เป็น NOLOGIN/NOSUPERUSER/NOBYPASSRLS และไม่มี UPDATE principals/sessions, ไม่มีสิทธิ์เขียน Voice. Auth/runtime ไม่มี membership เข้า owner role

## Success Contract
1. runtime ไม่เห็น actor/source/session/payload ในตาราง และ execute function รับแค่ random ticket_id
2. runtime เรียก mint/raw fence ไม่ได้, แก้ identity/session ไม่ได้, grant ตัวเองไม่ได้, CREATE object ใน execution schema ไม่ได้ และเขียน/แก้ Voice โดยตรงไม่ได้
3. auth bridge mint ได้แต่ consume/read authority/ticket ไม่ได้; stamp ที่ผิด actor/capability ยังถูก DB fence ปฏิเสธ
4. function owner เป็น NOLOGIN least-privilege role ไม่ใช่ DB owner และตัว owner เองแก้ authority/Voice/delete ticket ไม่ได้
5. ticket bind command_id+payload_ref+PRIVATE semantics ตอน mint; runtime เปลี่ยนหลัง mintไม่ได้
6. ticket one-shot; concurrent consume สอง connection ต้องสำเร็จได้อย่างมากหนึ่งครั้ง
7. revoke/disable/writer removal หลัง mint ต้องทำให้ consume DENY และไม่มี synthetic target row/consumed marker จาก statement ที่ล้มเหลว
8. caller rollback ต้อง rollback probe+consume ทั้งคู่; ticket ใช้ใหม่ได้เพราะไม่มี commit
9. search_path/temp shadowing ไม่ hijack SECURITY DEFINER path
10. test suite ต้องยืนยันไม่มี row ใน `echo_core.voice_revisions` และ cleanup schema/roles ก่อน SAT

## Server-owned capsule ≠ client token
`ticket_id` ต้องสร้างด้วย CSPRNG ฝั่ง backend และ **ห้ามส่งให้ browser**. มันเป็น internal one-shot capability ระหว่าง verified auth/command bridge กับ restricted DB runtime—not authentication credential สำหรับผู้ใช้

Mint function ยังรับ authorization stamp fields เพราะตัวเชื่อม signed preflight → DB ต้องส่งค่าที่ตรวจแล้ว; client/runtime ไม่มี EXECUTE mint. Knowing/stealing an internal ticket may allow one bound command before expiry, therefore transport/log secrecy inside backend remains required. งานนี้ไม่ได้ป้องกัน compromised auth bridge หรือ arbitrary code execution ภายใน backend

Command data ที่ถูก bind ใน capsule รอบนี้มีเพียง `command_id` + opaque `payload_ref` และ hard-coded `PRIVATE`. ไม่มี visibility argument ใน runtime function จึงใช้ capsule นี้ publish PUBLIC ไม่ได้

## Transaction / revocation semantics
Consume reuses P2.1c.2d.1 locks: principal then session, READ COMMITTED, DB wall clock. Revoke ที่ commit ก่อน fence/recheck ต้องทำให้ DENY; writer ที่ได้ lock ก่อนอาจ finish ก่อน revoker commit ตาม serial order เดิม

SECURITY DEFINER ไม่ได้ commit ให้ caller. Runtime อาจเปิด explicit transaction และชะลอ COMMIT/ROLLBACK; นี่เป็น liveness/operational-timeout concern ไม่ใช่ authority bypass ที่พิสูจน์ในรอบนี้. Production pool ต้อง enforce transaction lifetime/statement timeout และ rollback broken sessions; ยังเป็น deployment UNKNOWN

Ticket row ใช้ `FOR UPDATE` เพื่อ serialize one-shot consume. ถ้า inner insert/final fence ล้มเหลว statement/transaction rollback จึงไม่ทิ้ง consumed marker ปลอม

## สิ่งที่ยังไม่ใช่ SAT
- real `echo_core.voice_revisions` writer
- production DB roles/credentials/pooler and secret rotation
- HTTP/cookie/JWT ingress, CSRF/origin/rate-limit
- compromised backend/auth-bridge defense หรือ ticket leakage defense นอก DB
- full idempotent response replay/outbox/event publication
- reviewer assignment/self-review/object permission
- PRIVATE owner read/RLS, RESTRICTED audience, erasure/backup privacy
- snapshot sealing และ semantic/media truth verification

## Verification
CI ใหม่ใช้ PostgreSQL 17 service ชื่อ `echo_least_priv_test`, Python/psycopg จริง และ LOGIN roles แยก connection. Test ปฏิเสธรันทันทีถ้า host/database ไม่ตรงหรือ schema/role fixture มีอยู่ก่อน

```sh
python -m pip install -r backend/p2_1c2c3/requirements.txt
ECHO_DISPOSABLE_PG=YES PGHOST=127.0.0.1 PGDATABASE=echo_least_priv_test \
  python database/p2_1c2d2/test_least_privilege.py
```

Expected source count = 26 unittest methods; ห้ามถือ expected เป็น PASS ก่อน CI จริง. Gate ต้องเห็น `Ran 26 tests`, `OK`, `CLEAN_LEAST_PRIVILEGE_DATABASE`. Existing P2.1c.2d.1/session/signed-registry workflows ถูก trigger จาก database change แยกต่างหากและต้องไม่ถูกนับซ้ำกับ 26 cases นี้

## SAT / VIOL / UNKNOWN policy
- **SAT**: เฉพาะ grant/no-bypass/capsule behavior ที่ runtime จริงพิสูจน์แล้ว
- **VIOL**: permission, ownership, replay/race หรือ rollback behavior ขัด contract ใน runtime
- **UNKNOWN**: path ที่ไม่ได้รันจริงหรือยังเป็น production integration dependency

## Completed / Blocked / Next
เมื่อ final CI ผ่าน: ปิด P2.1c.2d.2 เฉพาะ least-privilege DB execution capsule/no-direct-bypass boundary

Blocked ยังคงเป็น production writer, deployment role provisioning, ingress/session lifecycle, idempotency/outbox, read/privacy และ reviewer authorization

**Next: P2.1c.2d.3 — Immutable PRIVATE Voice Revision Writer** เปลี่ยน synthetic probe เป็น writer ของ `echo_core.voice_revisions` revision 1 แบบ PRIVATE ภายใต้ capsule เดิม พร้อม atomic payload reference/command id, duplicate/retry contract และ regression ว่า runtime ยังไม่มี direct table DML. ยังไม่เปิด PUBLIC publish หรือ browser endpoint

## Primary references
- PostgreSQL 17 `SECURITY DEFINER` safe search_path / function privilege guidance: https://www.postgresql.org/docs/17/sql-createfunction.html
- PostgreSQL role attributes and membership: https://www.postgresql.org/docs/17/role-attributes.html
- PostgreSQL GRANT/object privileges: https://www.postgresql.org/docs/17/sql-grant.html
- PostgreSQL explicit row locks: https://www.postgresql.org/docs/17/explicit-locking.html

เอกสารนี้เป็นขอบเขตที่โครงการจะพิสูจน์ ไม่ใช่คำรับรอง production security หรือความจริงของเนื้อข่าว
