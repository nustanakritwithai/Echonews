# c5b follow-up — Account-Link Precommit Validation

## งานเดียว
ปิดช่องว่างใน signed account-link boundary ที่ PR #27 รวมเข้า main ระหว่างการตรวจ ไม่สร้าง verifier ใหม่ ไม่เขียนทับ migration/roles/service pool เดิม และไม่เริ่ม c5c bootstrap

ฐาน: main `11d2e236e2350362aa137879a12c948ed80a1223`

## Red — พบจาก runtime จริงก่อนแก้
Test-only head `296482694e42a50269031b14f2be7badccd36f93`
CI run `35958543782`, artifact `10790793326`
SHA-256 artifact: `78cf2b85c59c0fc2441f8a966fcda03b837e60fb1198d83352d9916c1d362c73` (downloaded and matched)

รันบน PostgreSQL จริง: 18 กรณีเดิมผ่าน แต่สอง regression ใหม่ล้มเหลว:

1. ผลจาก SQL ไม่ตรง receipt contract: boundary ปฏิเสธจริง แต่ตรวจหลังออกจาก transaction แล้ว จึงเหลือ proof/binding/Actor/Source อย่างละหนึ่งแถว ค่าที่นับได้ `(12,11,11,11)` แทน baseline `(11,10,10,10)`
2. token หมดอายุระหว่างรอ advisory lock ที่ตรวจพบจริงด้วย `pg_blocking_pids`: boundary กลับคืน receipt แทน `IDENTITY_REJECTED`

Fixture กรณีแรกทำให้ receipt ผิดหลัง SQL จริงทำงานแล้ว เป็นการทดสอบ rollback contract ไม่ใช่ข้ออ้างว่ามีผู้โจมตีแก้ฐานจริงได้ ทั้งสองกรณีใช้ signed token จริง, service LOGIN จริง และ pool จริง ไม่ mock ผลตรวจลายเซ็น

## สิ่งที่แก้
- ย้าย receipt validation ทั้งหมดเข้า transaction เดียวกับ SQL issuance
- ตรวจ `clock_timestamp()` จาก DB หลัง SQL ทำงาน/รอ lock เสร็จ และก่อนออกจาก transaction
- token/proof หมดอายุ หรือ receipt ไม่ตรง contract -> exception ภายใน transaction -> rollback proof และข้อมูลผูกบัญชีใหม่ทั้งหมด
- คืน receipt หลัง pool commit/reset สำเร็จเท่านั้น
- commit acknowledgement หรือ reset ขัดข้องยังเป็น backend error/unknown outcome ไม่รับประกัน rollback และไม่ replay การออก proof อัตโนมัติ

## Gate
`test_account_link_transaction.py` สืบทอด 18 tests เดิมโดยไม่แก้ และเพิ่ม test_19/test_20; custom load_tests รันเฉพาะ subclass เพื่อไม่ได้นับชุดเดิมสองครั้ง

Expected 20 top-level tests, `OK`, `ACCOUNT_LINK_EXPIRY_LOCK_WAIT_OBSERVED`, `CLEAN_SIGNED_ACCOUNT_LINK_DATABASE` และ independent catalog cleanup check. จำนวน expected ไม่ใช่ PASS: ผล green ต้องตรวจ Actions ของ final head จริง

Workflow เดิมยังรัน c5a proof 20 และ original token boundary 104 บน final head. เมื่อทุกชุดผ่าน จำนวน unique ในขอบเขตนี้คือ 20+20+104 = 144 ไม่บวก 18 inherited tests หรือ reruns ซ้ำอีก

## ข้อจำกัด
การตรวจเวลาให้หลักฐาน ณ final DB clock sample ไม่ใช่เวลาที่ WAL ถูก flush หรือ browser ได้รับข้อความตอบ ไม่มี HTTP endpoint/production credential deployment/real onboarding rollout ในงานนี้

Raw c5a SQL function ยังเป็น trusted internal primitive ที่อ่านเวลาเริ่มต้น; ต้องใช้ paired signed boundary + transaction-owning pool สำหรับเส้นทางนี้ ห้ามเรียก raw SQL จาก client หรือถือ proof UUID เป็น bearer authorization

Production IdP/profile/TLS/HBA, session establishment/refresh/logout, reviewer/object permission, privacy/erasure และ unknown-commit proof retry policy ยังไม่ผ่านเพราะงานนี้

## Next
หลัง final gate ผ่าน: c5c signed principal provisioning/session bootstrap ต้อง consume proof สำหรับ verified issuer/subject เดียวกัน โดย backend กำหนด principal/session identity และห้ามส่ง mapping identifiers จาก client. เริ่มในงานถัดไป ไม่รวมในแพตช์นี้

## Primary references
- https://www.psycopg.org/psycopg3/docs/basic/transactions.html
- https://www.postgresql.org/docs/17/functions-datetime.html
- https://www.postgresql.org/docs/17/explicit-locking.html
