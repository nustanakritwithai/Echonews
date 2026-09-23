# P2.1c.2c.2a — ทะเบียนตัวตนถาวรที่จำกัดสิทธิ์ v0.1

## หนึ่งงานของรอบนี้

ต่อจาก main `861074b050b3f2e653d45850b60b60dd07ca4cf8`: สร้าง **protected PostgreSQL registry + server-only resolution function** สำหรับ `(issuer, subject) → actor/source` พร้อมสิทธิ์แบบมีรุ่น และการปิดบัญชี/ถอน Token

นี่เป็นส่วนแรกของ P2.1c.2c.2 ไม่ใช่การทำ Login/API/adapter ทั้งก้อน ไม่มีการแก้หน้าเว็บ, ไม่มีการเขียน Voice จริง, ไม่มีการ deploy ฐานข้อมูล production และไม่เปลี่ยน contracts/โมดูลจาก PR #6/#7

## โครงสร้าง

- `echo_identity.principals`: tuple issuer/subject แบบ case-sensitive ที่ไม่แก้ตัวตนย้อนหลัง เชื่อม actor/type ผ่าน composite FK และ source ผ่าน FK
- `echo_identity.access_revisions`: สิทธิ์รุ่นใหม่ append-only, enabled, capabilities, cutoff ของ issued-at และ metadata ฝั่งฐานข้อมูล
- `echo_identity.token_revocations`: revoked JTI แบบ SHA-256 ภายใต้ issuer เดียวกัน ไม่เก็บ bearer token หรือ JTI ต้นฉบับ
- `provision`, `revise_access`, `revoke_token`: control-plane functions สำหรับ admin DB role เท่านั้น
- `resolve_principal`: ช่องอ่านเฉพาะ Backend ที่ผ่านด่านตรวจ Token แล้ว ยังไม่ใช่สิทธิ์ดำเนินคำสั่ง

Provision สร้าง disabled revision 1 และ capabilities ว่างในธุรกรรมเดียวกัน. ไม่มี auto-provision, email linking, การรับ role จาก JWT หรือการเพิ่มสิทธิ์โดย Browser

Actor/source อย่างละหนึ่ง principal ใน profile นี้ เพื่อไม่ให้ลิงก์บัญชีโดยไม่มีการตรวจ. การใช้หลายบัญชีต่อคน/การกู้บัญชี/ย้ายผู้ให้บริการต้องมีสเปกเพิ่ม อย่าเปิดจากการแก้ unique constraint เฉย ๆ

Source ต้องเป็น ACCOUNT ณ ตอน provision และตอน resolve. ACCOUNT เป็นชนิดข้อมูล ไม่ได้พิสูจน์ว่าเป็นคนเดียว ไม่ใช่คะแนนความน่าเชื่อถือข่าวหรือความเป็นอิสระของหลักฐาน

## สิทธิ์สามชั้น

`echo_identity_owner` เป็น NOLOGIN ไม่เป็น superuser; เป็นเจ้าของเฉพาะ schema ใหม่และได้รับเพียง column SELECT/REFERENCES ของ actors/sources ที่จำเป็น ไม่อ่าน voice payloads หรือ assessments

`echo_identity_admin` เป็น NOLOGIN ใช้แค่ control-plane functions ไม่อ่าน/เขียน base tables ตามใจ และไม่ใช่ role สำหรับผู้ใช้เว็บหรือ reviewer

`echo_identity_resolver` เป็น NOLOGIN ใช้แค่ resolve_principal ไม่ได้สิทธิ์สร้างบัญชี เพิ่มสิทธิ์ ถอน token อ่านทั้งทะเบียน หรือเขียนข่าว

ไม่ grant membership ให้ connection/account ใด ไม่สร้าง LOGIN/password. `echo_public_reader` เดิมไม่มีสิทธิ์เข้า registry

SECURITY DEFINER functions ใช้ search_path=pg_catalog,pg_temp, qualify tables, revoke PUBLIC EXECUTE และเป็นเจ้าของโดย non-superuser role. ติดตั้งในธุรกรรมเดียวเท่านั้น

## สัญญาการ resolve

Input สี่ค่า `issuer, subject, jti, issued_at` ต้องมาจาก **token ที่ upstream ตรวจลายเซ็น/issuer/audience/type/exp แล้วเท่านั้น**. SQL function ไม่ตรวจ JWT และไม่ต้าน malicious backend ที่ถือ resolver credential แล้วส่ง tuple คนอื่นเอง ห้าม expose เป็น browser RPC

คืน mapping รุ่นล่าสุดเฉพาะที่ enabled, cutoff ผ่าน และไม่อยู่ใน revocation list. Unknown principal/disabled/revoked คืนศูนย์แถว ไม่มี fallback เป็น anonymous writer. Inputs malformed หรือสิทธิ์ฐานข้อมูลหายทำให้ query fail ต้องปฏิเสธ request

Result: principal_id, actor_id, actor_kind, source_id, binding_revision, capabilities, tokens_valid_from และ **ready_for_execution=false เสมอ**. ไม่มี `roles=writer`, ไม่มี PUBLIC publishing grant และไม่แปลง `voice:draft:create` เป็น JS writer role

ทุก lookup อ่าน latest committed state ตาม Read Committed โดยไม่เก็บ cache ใน function. REPEATABLE READ/SERIALIZABLE ถูกปฏิเสธใน profile นี้เพื่อไม่ให้ backend เผลออ่านสิทธิ์จาก snapshot เก่ายาวนาน. Database statement ที่เริ่มก่อน revocation commit อาจยังเห็นสถานะเก่า จึงยังต้องตรวจซ้ำที่ transaction-time ก่อนเขียนจริง งานนี้ไม่ได้ปิด TOCTOU/write-authorization gap

## การถอนสิทธิ์

1. ปิดบัญชี: append disabled revision ใหม่ capabilities ว่าง; lookup หลัง commit ไม่คืน mapping
2. การปิดบัญชีเพิ่ม issued-at cutoff อย่างน้อย `floor(database_now_epoch)+1` เพื่อปิด Token ที่ออกในวินาทีเดียวกันด้วย. หลังเปิดบัญชีใหม่ cutoff ลดไม่ได้ Token เก่าจึงไม่กลับมาใช้ได้เอง Token ใหม่อาจต้องออกหลังขอบวินาทีถัดไป
3. ถอนบาง Token: เก็บ digest ภายใต้ issuer. ถอนซ้ำ idempotent ไม่สร้างแถวใหม่. ไม่มีฟังก์ชัน un-revoke ใน profile นี้
4. ลดสิทธิ์: append revision ใหม่ capabilities ลดลง. ยังต้องให้ caller ตรวจ capability เอง mapping ที่ enabled และ capabilities ว่างไม่ใช่การอนุญาตเขียน
5. competing admins: ล็อก principal row และตรวจ expected revision; คำสั่งแข่งใช้ revision เดียวกันสำเร็จได้หนึ่งคำสั่ง อีกคำสั่งได้ conflict

ไม่รับประกันการ revoke token ที่ขโมยไปจาก external provider, session refresh protocol, การแจกจ่ายกุญแจทุก node หรือการยับยั้งงานที่ผ่าน preflight ไปแล้ว

## ประวัติและความเป็นส่วนตัว

UPDATE/DELETE/TRUNCATE ของสามตารางถูกป้องกันจาก normal DML. Owner ที่แก้ DDL ได้ยังปิด guard ได้ ไม่ใช่ฐานข้อมูล tamper-proof

ข้อมูล issuer/subject/actor/source และแม้ JTI digest ก็เป็นข้อมูลอ่อนไหว ไม่ใช่ข้อมูลนิรนาม ห้ามเปิดใน public feed/log. Metadata session_principal/active_db_role เป็นบัญชีฐานข้อมูล ไม่ใช่ตัวตน reviewer จริง. ยังไม่มี retention/erasure/recovery workflow จึงใช้แต่ข้อมูลจำลองและห้ามเปิดรับผู้ใช้จริง

ไม่มีการรับข้อความ/URL/token ลง audit. ประวัติ rights เป็นข้อมูลที่ต้องควบคุมสิทธิ์เช่นกัน

## การทดสอบ

Runner ใช้ psql กับ PostgreSQL จริง หลาย process/connection แยกกัน รวมการแข่งสอง admin และการอ่านหลัง revoke commit. ภายใต้ test superuser ใช้ **SET SESSION AUTHORIZATION ไป non-superuser role + SET ROLE role เดียวกัน** เพื่อให้การทดสอบ escalation ไม่เผลอคง session_user เป็น superuser

```sh
# Dedicated EMPTY disposable localhost DB only; never production
export PGHOST=127.0.0.1 PGPORT=5432 PGDATABASE=echo_registry_test
# PGUSER/PGPASSWORD are CI-only or supplied by the test administrator
ECHO_DISPOSABLE_REGISTRY_TEST=1 python3 database/p2_1c2c2a/run_checks.py
```

Runner ปฏิเสธ DB ชื่ออื่นและ Echo schemas/roles ที่มีอยู่แล้ว. ในกรณีที่ผ่าน gate จึง install original schema/history/public-read + registry ใน transaction เดียว. Test fixtures commit เพื่อทดสอบข้าม connection; หลังจบล้างเฉพาะ schemas/roles ที่สร้างใน dedicated DB และตรวจ CLEAN_ISOLATED_DATABASE. ไม่ใช้ ROLLBACK ล้างทั้งชุดแล้วอ้างว่าได้ทดสอบ persistence ข้าม connection

เตรียม 70 distinct test methods: mapping/FK/case sensitivity, default disabled, capability changes, immutable rows, disable/re-enable cutoff, JTI isolation, malformed inputs, grants, role escalation, temp-table shadowing, function ownership, rollback, cross-connection persistence และ competing revisions

**จำนวนที่เตรียมไว้ไม่ใช่ผลผ่าน** อ่าน registry_results.json และ Actions ของ commit ที่ทดสอบจริง. SQL tests ไม่ได้ตรวจ signature และไม่ใช่ end-to-end integration ของ Python/JS

CI นี้ยังรัน P2.1b 24, P2.1c.1 79 และ P2.1c.2a 28 เป็น regressions แยก (131 checks) แต่ไม่รัน 104 token/68 JS command cases ใหม่. ห้ามนับผลเก่าที่ไม่ได้รันเป็นผลใหม่

## Completed / Blocked / Next

Concrete output: additive migration, PostgreSQL test runner, dedicated CI และเอกสาร. SAT ได้เฉพาะกรณีที่ CI รันผ่าน; ยังไม่ประกาศ production-ready

Blocked: provider login/key provisioning, parameterized Python registry adapter, source/UUID/DTO/capability mapping กับ JS, object authorization/reviewer assignments, transaction-time recheck, idempotent Voice write, snapshot sealing, restricted reads, privacy/backup erasure และ rate-limit/DoS

**Next: P2.1c.2c.2b — ต่อ parameterized adapter จาก verified token ไป resolver และตรวจการ mapping กับ command preflight แบบไม่ยกระดับสิทธิ์**; ผลยังต้องไม่ ready_for_execution จนกว่าจะผ่าน object authorization และ DB writer transaction

## เอกสารต้นทาง

- PostgreSQL 17 CREATE FUNCTION — SECURITY DEFINER/search_path/revoke PUBLIC ภายใน transaction: https://www.postgresql.org/docs/17/sql-createfunction.html
- PostgreSQL 17 Transaction Isolation — Read Committed statement snapshots เทียบ Repeatable Read: https://www.postgresql.org/docs/17/transaction-iso.html
- PostgreSQL 17 REVOKE — object ownership และสิทธิ์ทางอ้อม: https://www.postgresql.org/docs/17/sql-revoke.html

กติกานี้เป็น contract ของต้นแบบ Echo ไม่ใช่ข้อพิสูจน์ความถูกต้องของข่าวหรือความปลอดภัยครบระบบ
