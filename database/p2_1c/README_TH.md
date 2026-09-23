# P2.1c.1 — Immutable Revision / Mutation Contract v0.1

## งานเดียวของรอบนี้
บังคับประวัติระดับแถวใน PostgreSQL: ห้าม UPDATE / DELETE / TRUNCATE รุ่นข้อมูลและความสัมพันธ์ที่ตรึงรุ่นแล้ว การแก้ใช้ INSERT revision ถัดไป พร้อม metadata audit ในธุรกรรมเดียวกัน ไม่ทำ UI ใหม่ ไม่เชื่อม API และไม่ deploy ฐานข้อมูล production

ต่อจาก `database/p2_1b/schema.sql` โดยไม่แก้สคีมา/fixture/ชุดทดสอบเดิม หน้าเว็บหลักและ `/preview/` ไม่เปลี่ยน

## ข้อกำหนด

- คุ้มครอง 13 ตาราง: event_revisions, voice_revisions, event_voice_links, claim_revisions, claim_voice_links, evidence_revisions, evidence_voice_links, evidence_assessments, evidence_provenance_edges, policy_versions, state_snapshots, snapshot_items, snapshot_assessment_inputs
- ห้ามการเขียนทับ แม้ SET ค่าเดิมหรือ WHERE false; UPDATE arm ของ UPSERT/MERGE ไม่ใช่ช่องทางแก้ประวัติ
- INSERT revision ใหม่ยังใช้ PK/FK/previous_revision ของ P2.1b ส่วนการถอน assessment ใช้ revision ใหม่ ไม่แก้ snapshot เก่าให้ดูเหมือนรู้อยู่ก่อน
- INSERT ... ON CONFLICT DO NOTHING ที่ไม่เพิ่มแถว ไม่เพิ่ม audit และไม่ได้ยืนยันว่า payload ซ้ำตรงกัน การตรวจ idempotency key+payload อยู่ในงาน API ถัดไป
- metadata audit เก็บเฉพาะชื่อ relation, primary key, เวลาฐานข้อมูล, transaction ID และ principal/role ฐานข้อมูล ไม่สำเนาข้อความ รูป ลิงก์ proposition หรือ rationale ลง audit
- audit_id/transaction_id ไม่ใช่ global commit order; server insert time ไม่ใช่ observation time และไม่ได้พิสูจน์ received/committed ordering
- audit เริ่มเมื่อ migration ถูกติดตั้ง ไม่สร้างเรื่องย้อนหลังให้ข้อมูลก่อนติดตั้ง
- การล้มเหลวในธุรกรรมย้อนทั้งแถวใหม่และ audit; audit ไม่ใช่ security log สำหรับความพยายามที่ rollback ไปแล้ว
- function ที่เขียน audit เป็น SECURITY DEFINER มี locked search_path, qualified target และ revoke PUBLIC EXECUTE; schema/audit ไม่มี public grants
- ALWAYS triggers ป้องกันการถูกข้ามโดย replica mode ตามที่ทดสอบ แต่ไม่ใช่การต้านผู้ดูแลที่มีอำนาจปิด trigger/แก้ DDL/restore ฐานข้อมูล

## วิธีทดสอบ
ใช้ PostgreSQL 17 และฐานทดสอบเปล่าแบบทิ้งได้เท่านั้น ชุดทดสอบสร้าง role NOLOGIN เพื่อจำลอง non-owner และ ROLLBACK ทั้ง role/schema/fixture หลังจบ ต้องมีสิทธิ์ CREATE ROLE และ SET ROLE ในฐานทดสอบนี้ ห้ามให้สิทธิ์ดังกล่าวแก่ API

```sh
psql -X -v ON_ERROR_STOP=1 -f database/p2_1b/tests_postgres.sql
psql -X -v ON_ERROR_STOP=1 -f database/p2_1c/tests_postgres.sql
```

CI `.github/workflows/p2-1c-immutability.yml` รัน regression เดิม 24 กรณีและ suite ใหม่ 79 checks (40 named checks + 39 table-operation checks) บน service container พร้อมเก็บ logs/รุ่น server และตรวจ CLEAN_ROLLBACK

79 เป็นจำนวนที่ suite คาดหวัง ไม่ใช่ผลผ่านที่อ้างก่อนรัน ให้ตรวจสถานะ Actions ของ commit จริง

## Threat boundary และสิ่งที่ยังห้ามกล่าวอ้าง

นี่คุ้มครอง normal DML กับ role ที่ไม่เป็นเจ้าของ ไม่ใช่ฐานข้อมูลที่แก้ไม่ได้โดยสมบูรณ์ Owners/superusers/migration principals ยังมีอำนาจเปลี่ยน DDL. ห้ามใช้ credential เจ้าของเป็น credential แอป

บัญชีฐานข้อมูลที่บันทึกใน audit ไม่ใช่ตัวตนผู้ใช้เว็บ การอ้าง actor_id/HUMAN ในแถวไม่ใช่หลักฐานยืนยันสิทธิ์ reviewer. Test writer มี DML grants มากเกินจำเป็นเพื่อโจมตี guard ในการทดลอง ห้ามนำ grants ของ test ไปใช้ production

**Immutable rows ไม่เท่ากับ immutable sets:** ยังคงเพิ่ม child record ให้ snapshot ที่มีอยู่ได้ ต้องมี snapshot sealing/admission transaction ก่อนเผยแพร่ ไม่ถือว่างานนี้ปิด publication gate

**การถอนสู่สาธารณะไม่เท่ากับเก็บประวัติตลอดกาล:** privacy/redaction, read visibility, cache/search invalidation, backup erasure และการแยกข้อมูลอ่อนไหวออกจาก revision table ยังไม่ทำ คุ้มครองแถวไม่ได้เป็นเหตุให้เก็บข้อมูลส่วนบุคคลฝืนความยินยอม. ทดสอบด้วยข้อมูลสมมติเท่านั้น

ยังไม่ปิด UNKNOWN: authenticated API/RLS, reviewer identity, semantic assessment, current-state recomputation หลัง correction, source independence, identity/source mutation, real multi-writer ordering/throughput, snapshot admission และ privacy workflow

## Completed / Blocked / Next

- ผลงาน: additive migration, 79-check runtime suite, isolated CI gate และเอกสารขอบเขต
- Runtime status: ใช้ผล CI/PR ของ commit นี้ ไม่อ้าง PASS จากการอ่าน SQL
- Production: BLOCKED ตามรายการ UNKNOWN ด้านบน
- Next: **P2.1c.2 — authenticated writer/reviewer boundary and read-visibility contract** ก่อนเปิด API ให้ browser; snapshot sealing ยังเป็น dependent task ต้องไม่ข้าม

## แหล่งอ้างอิงทางเทคนิค

PostgreSQL 17 CREATE TRIGGER: statement triggers/zero rows/TRUNCATE และ upsert interaction
https://www.postgresql.org/docs/17/sql-createtrigger.html

PostgreSQL 17 CREATE FUNCTION: SECURITY DEFINER, safe search_path และ EXECUTE privileges
https://www.postgresql.org/docs/17/sql-createfunction.html

PostgreSQL 17 ALTER TABLE: ENABLE ALWAYS / DISABLE TRIGGER และบทบาทของ owner
https://www.postgresql.org/docs/17/sql-altertable.html

นี่เป็นกติกาของโครงการ ไม่ใช่หลักฐานว่ากติกาให้ข่าวที่จริงหรือเหมาะกับ production แล้ว
