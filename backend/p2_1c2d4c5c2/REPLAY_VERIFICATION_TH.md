# c5c.2 — Activation Replay / Audit Verification Addendum

## งานเดียวและงานพร้อมกัน
ตรวจ PR #30 ซึ่งเปิดระหว่างทำ c5c.2 แล้วร่วมเพิ่ม verification ใน PR เดิม ปิด draft #31 โดยไม่ merge: ไม่ใช้ SQL/schema/นโยบายจาก draft นั้น และไม่สร้าง activation สองระบบ

นโยบาย canonical ยังคงเป็น dedicated internal `echo_activation_service` ตาม README เดิม ไม่เปลี่ยนเป็น applicant self-approval หรือ reviewer approval ไม่เพิ่ม writer/reviewer/session capability

## Red จากการรันจริง ก่อนแก้ replay
- Source head: `a172f487bb9f2e5b97b330ac9cad95c05655f2bd`
- Actions: `35962222905`
- Artifact: `10793115594`
- SHA-256 ที่ดาวน์โหลดและตรวจตรงแล้ว: `7b87c70e2c06899ca144cb5d0e50400cadc9076c088365c46fb011c15387c77f`

27 top-level methods: 20 baseline + 7 additions. Baseline20 และกรณีใหม่25–27ผ่าน ส่วน method21–24ล้มเหลว 4 methods; unittest รายงาน 6 failure records เพราะ method22มี3 subcases ไม่ใช่มี6 top-level methodsล้มเหลว. ไม่มี runtime errors และ independent cleanup ผ่าน

พบจริงว่า:
- exact retry หลัง disabled/auth_version/role เปลี่ยน ยังคืน `enabled=true, authVersion=2` จาก audit เก่า
- คำขอ decision เดียวกันที่รอ Principal lock พร้อมกัน กลับสำเร็จหนึ่งคำขอและปฏิเสธอีกหนึ่ง แทนคืนผลเดิม
- replay ข้ามการรอ transaction ที่กำลัง disable บัญชี

กรณี audit INSERT ล้มเหลว -> rollback การเปิดบัญชี, runtime audit DML denial และ explicit rollback ผ่านอยู่แล้ว ไม่อ้างว่าพบ bug ในส่วนที่ผ่าน

## Contract หลังแก้
SQL ของ PR เดิมถูกแก้ร่วมกันโดยยังคงสิทธิ์และ schema:
1. ตรวจ conflict ของ decision เดิมได้ก่อน แต่ยังไม่คืนผล
2. ล็อกและอ่าน Principal ปัจจุบันก่อนคืน replay
3. ต้องยัง enabled, ไม่มี writer/reviewer และตรง auth_version ของ audit มิฉะนั้น `ACTIVATION_REPLAY_STALE`
4. ถ้าไม่มี audit ก่อนรอ lock ให้อ่านใหม่หลังได้ lock ด้วย snapshot ใหม่ของ READ COMMITTED เพื่อรองรับ concurrent identical decision
5. ไม่แก้ audit เดิม ไม่เพิ่ม auth_version ซ้ำ และไม่เปิดบัญชีที่ถูกปิดกลับมา

README ที่กล่าวว่า exact retry คืน audit เดิมให้อ่านภายใต้เงื่อนไข current-state check นี้ ไม่ใช่ historical success ที่ใช้แทนสิทธิ์ปัจจุบัน

## Verification gate
`test_activation_replay.py` สืบทอด 20 baseline methods โดยไม่เปลี่ยน แล้วเพิ่ม 7 methods; load_tests รันเฉพาะ subclass เพื่อไม่บวก baseline ซ้ำ

Expected final result: 27 tests, OK, 2 `ACTIVATION_REPLAY_LOCK_OBSERVED` records และ cleanup. ห้ามนับ expected เป็น SAT จนตรวจ logs/Actions ของ final head;ผล green และ commit ที่ผ่านให้ดู PR #30 / artifact ของ head นั้น

## ขอบเขต
Activation receipt ยังเป็นเพียงผลของคำสั่ง ไม่ใช่ credential หรือการอนุญาตสร้าง session ครั้งถัดไป. การตรวจสถานะให้ความหมาย ณ transaction ที่อ่าน ไม่รับประกันว่าจะไม่มีการ revoke ภายหลัง

Audit ป้องกัน runtime DML ตาม ACL รวมถึง TRUNCATE; owner/superuser ยังเป็น trusted administrative boundary ไม่ใช่ระบบตรวจจับการแก้ข้อมูลโดย DBA หรือ cryptographic audit sealing

ไม่มี HTTP/user activation API, production credential rollout, operator UI, account reactivation, writer/reviewer grants, first-session bootstrap หรือ live publication ในงานนี้

Next ตาม canonical roadmap: c5c.3 Signed First-Session Bootstrap ต้องอ่าน current Principal และ auth_version ใหม่ ห้ามเชื่อ activation receipt เป็น session authority

Primary references:
- https://www.postgresql.org/docs/17/transaction-iso.html
- https://www.postgresql.org/docs/17/explicit-locking.html
