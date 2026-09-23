# P2.1c.2d.2 — Least-Privilege / No-Bypass Transaction Boundary

## Task
งานเดียวต่อจาก P2.1c.2d.1: ทำขอบเขต DB role/SECURITY DEFINER ที่พิสูจน์ว่า runtime writer ใช้ได้เฉพาะ server-owned transaction capsule และไม่สามารถอ่าน/แก้ authority, mint สิทธิ์เอง, เรียก fence หรือเขียน Voice โดยตรงเพื่อข้าม authorization fence

นี่เป็น **research execution probe** ไม่ใช่ production writer: ไม่มี Browser/HTTP route, ไม่ migrate ฐานจริง, ไม่เขียน `echo_core.voice_revisions`, ไม่ publish และไม่เพิ่ม reviewer path

## Concrete Output
`001_least_privilege_boundary.sql` เพิ่ม schema ส่วนตัว `echo_execution` พร้อม:

- `private_draft_tickets`: capsule อายุสั้นที่ bind verified issuer/subject/session + canonical principal/Actor/Source/auth_version + `voice:draft:create` เข้ากับ command_id และ payload_ref ที่ backend ตรวจแล้ว
- `_assert_private_draft_fence(...)`: private SECURITY DEFINER helper ที่ใช้ semantics/lock order เดียวกับ P2.1c.2d.1 แต่ทำงานภายใต้ dedicated NOLOGIN owner; auth/runtime ไม่มี EXECUTE
- `mint_private_draft_ticket(...)`: trusted auth/command bridge เท่านั้น ตรวจ authority แล้ว mint ticket อายุสูงสุด 30 วินาทีหรือ token expiry แล้วแต่ว่าอันไหนมาก่อน
- `execute_private_draft_probe(ticket_id)`: runtime entrypoint เดียว รับเพียง ticket id; identity, payload และ visibility ไม่ใช่ argument. Lock ticket, recheck authority, เขียน synthetic PRIVATE probe, recheck อีกครั้ง แล้ว consume ticketใน transaction เดียว
- ทุก schema/table/function revoke PUBLIC; migration ไม่สร้าง production roles เพราะชื่อ/credential/ownership เป็น deployment concern

## ทำไมต้องมี private helper เพิ่มจาก P2.1c.2d.1
CI รอบแรกของ PR นี้พบ **VIOL 14 errors / 26 tests**: การออกแบบเดิมให้ SECURITY DEFINER mint/consume เรียก `echo_identity.assert_private_draft_fence` ที่เป็น SECURITY INVOKER แล้วสมมติว่ามันจะใช้ SELECT privileges ของ outer definer owner. PostgreSQL runtime แสดงว่า fence กลับถูกตรวจด้วยสิทธิ์ caller ที่ไม่มี SELECT `principals`, จึง fail ด้วย `permission denied for table principals`.

การแก้ **ไม่ใช่ grant SELECT authority ให้ auth/runtime** เพราะจะทำลาย least-privilege boundary และไม่เปลี่ยน P2.1c.2d.1 ที่ผ่าน regression ไปแล้ว. จึงเพิ่ม private SECURITY DEFINER helper ที่ถูก owned ด้วย NOLOGIN execution owner คนเดียวกับ mint/consume และให้ SELECT authority เฉพาะ owner นั้น. Auth bridge/runtime ยังไม่มี table read และไม่มี helper/raw-fence EXECUTE.

ผลรอบแรกต้องถูกบันทึกเป็น VIOL และห้ามใช้เป็นหลักฐาน PASS. SAT ได้เฉพาะ final rerun ที่ผ่านหลังแก้เท่านั้น

## Grant Matrix ที่ต้องพิสูจน์ใน CI

| Principal | LOGIN | สิทธิ์ที่ตั้งใจให้ |
|---|---|---|
| `echo_execution_owner_test` | NOLOGIN | SELECT authority, INSERT/SELECT ticket, UPDATE เฉพาะ `consumed_ms`, INSERT probe, own 3 SECURITY DEFINER functions |
| `echo_auth_bridge_test` | LOGIN (test only) | EXECUTE mint เท่านั้น |
| `echo_runtime_writer_test` | LOGIN (test only) | EXECUTE consume เท่านั้น |

Owner เป็น NOSUPERUSER/NOBYPASSRLS/NOINHERIT และไม่มี UPDATE principals/sessions, ไม่มี Voice DML, ไม่มี DELETE capsule/probe. Auth/runtime ไม่มี membership เข้า owner role

## Success Contract
1. runtime ไม่เห็น actor/source/session/payload ในตาราง และ execute function รับแค่ random ticket_id
2. runtime เรียก mint/raw/private fence ไม่ได้, แก้ identity/session ไม่ได้, grant ตัวเองไม่ได้, CREATE object ใน execution schema ไม่ได้ และเขียน/แก้ Voice โดยตรงไม่ได้
3. auth bridge mint ได้แต่ consume/read authority/ticket/private-helper ไม่ได้; stamp ที่ผิด actor/capability ยังถูก private fence ปฏิเสธ
4. function owner เป็น NOLOGIN least-privilege role ไม่ใช่ DB owner และตัว owner เองแก้ authority/Voice/delete ticket ไม่ได้
5. ticket bind command_id+payload_ref+PRIVATE semantics ตอน mint; runtime เปลี่ยนหลัง mintไม่ได้
6. ticket one-shot; concurrent consume สอง connection ต้องสำเร็จได้อย่างมากหนึ่งครั้ง
7. revoke/disable/writer removal หลัง mint ต้องทำให้ consume DENY และไม่มี synthetic target row/consumed marker จาก statement ที่ล้มเหลว
8. caller rollback ต้อง rollback probe+consume ทั้งคู่; ticket ใช้ใหม่ได้เพราะไม่มี commit
9. search_path/temp shadowing ไม่ hijack SECURITY DEFINER path
10. test suite ต้องยืนยันไม่มี row ใน `echo_core.voice_revisions` และ cleanup schema/roles ก่อน SAT

## Server-owned capsule ≠ client token
`ticket_id` ต้องสร้างด้วย CSPRNG ฝั่ง backend และ **ห้ามส่งให้ browser**. มันเป็น internal one-shot capability ระหว่าง verified auth/command bridge กับ restricted DB runtime—not authentication credential สำหรับผู้ใช้

Mint function ยังรับ authorization-stamp fields เพราะตัวเชื่อม signed preflight → DB ต้องส่งค่าที่ตรวจแล้ว; client/runtime ไม่มี EXECUTE mint. การขโมย internal ticket อาจใช้ bound command ได้หนึ่งครั้งก่อนหมดอายุ ดังนั้น transport/log secrecy ภายใน backend ยังจำเป็น งานนี้ไม่ได้ป้องกัน compromised auth bridge หรือ arbitrary server code

Command data รอบนี้ bind เพียง `command_id` + opaque `payload_ref` และ hard-coded `PRIVATE`. Runtime ไม่มี visibility argument จึงใช้ capsule นี้ publish PUBLIC ไม่ได้

## Transaction / Revocation Semantics
Private helper ใช้ lock order เดียวกับ P2.1c.2d.1: principal แล้ว session, READ COMMITTED, DB wall clock. Revoke ที่ commit ก่อน recheck ต้อง DENY; writer ที่ได้ locks ก่อนอาจ finish ก่อน revoker commit ตาม serial order เดิม

SECURITY DEFINER ไม่ได้ commit transaction ของ caller. Runtime อาจเปิด explicit transaction แล้วชะลอ COMMIT/ROLLBACK; production pool ต้อง enforce transaction lifetime/statement timeout และ rollback broken sessions ซึ่งยังเป็น deployment UNKNOWN

Ticket ใช้ `FOR UPDATE` serialize one-shot consume. ถ้า insert/final check ล้มเหลว statement/transaction rollback จึงไม่ทิ้ง consumed marker ปลอม

## สิ่งที่ยังไม่ใช่ SAT
- real `echo_core.voice_revisions` writer
- production DB roles/credentials/pooler and secret rotation
- HTTP/cookie/JWT ingress, CSRF/origin/rate-limit
- compromised backend/auth bridge หรือ ticket leakage นอก DB
- idempotent response replay/outbox/event publication
- reviewer assignment/self-review/object permission
- PRIVATE owner read/RLS, RESTRICTED audience, erasure/backup privacy
- snapshot sealing และ semantic/media truth verification

## Verification
CI ใช้ PostgreSQL 17 service ชื่อ `echo_least_priv_test`, Python/psycopg จริง และ LOGIN roles แยก connection. Test ปฏิเสธรันทันทีถ้า host/database ไม่ตรงหรือ schema/role fixture มีอยู่ก่อน

```sh
python -m pip install -r backend/p2_1c2c3/requirements.txt
ECHO_DISPOSABLE_PG=YES PGHOST=127.0.0.1 PGDATABASE=echo_least_priv_test \
  python database/p2_1c2d2/test_least_privilege.py
```

Expected source count = 26 unittest methods; ห้ามถือ expected เป็น PASS ก่อน CI จริง. Gate ต้องเห็น `Ran 26 tests`, `OK`, `CLEAN_LEAST_PRIVILEGE_DATABASE`. Existing d.1/session/signed-registry workflows ที่ trigger จาก database change เป็น regressions แยกและไม่บวกซ้ำกับ 26 cases นี้

## SAT / VIOL / UNKNOWN policy
- **SAT**: เฉพาะ grant/no-bypass/capsule behavior ที่ runtime จริงพิสูจน์แล้ว
- **VIOL**: permission, ownership, replay/race หรือ rollback behavior ขัด contract ใน runtime — รวม first-run SECURITY INVOKER assumption ที่พบจริง
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

เอกสารนี้เป็นขอบเขตที่โครงการพิสูจน์ ไม่ใช่คำรับรอง production security หรือความจริงของเนื้อข่าว
