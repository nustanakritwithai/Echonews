# P2.1c.2d.4c.5c.4 — Signed Current-Session Logout

## Task / Concrete Output
หนึ่งงานต่อจาก main `631a3b30d4373dd5939cc7049b03fd42cea97c14` ซึ่งมี first-session bootstrap แล้ว: เพิ่มการถอน **Session ของ token ที่ส่งมาเท่านั้น** ไม่ทำ repeat login/refresh/logout-all/HTTP ในงานนี้

เพิ่มแบบ additive: sealed SQL function + restricted service roles, fixed-role transaction pool, signed boundary, real PostgreSQL tests และ CI. ไม่แก้ verifier, first-session implementation, activation หรือหน้าเว็บเดิม

## เส้นทาง
```text
Bearer signed access token + raw JSON {}
  -> existing strict RS256 / issuer / audience / time / jti verifier
  -> derive session_key จาก verified issuer+jti (contract เดิม)
  -> echo_session_logout_service LOGIN / pool reset / SET LOCAL ROLE
  -> exact issuer+subject resolves Principal in DB
  -> lock Principal FOR SHARE then Session FOR UPDATE
  -> verify Session owner + exact issued/expires + current DB clock
  -> existing monotonic runtime_revoke_session(...)
  -> validate receipt + final DB clock INSIDE same transaction
  -> COMMIT / pool reset
  -> LogoutReceipt(revoked=True) ไม่มี identifier หรือสิทธิ์ใหม่
```

SQL parameters ไม่ใช่หลักฐานลายเซ็นและไม่รับจาก browser ตรง ๆ. API ภายในที่รับ untrusted request คือ `SignedSessionLogoutBoundary.logout(authorization, raw_body)` เท่านั้น; body ต้องว่าง ไม่มี principal_id/actor_id/source_id/session_key หรือ logout_all

## Success Contract
- ถอน Session ที่ตรงกับ verified issuer/subject/jti เท่านั้น รู้ session digest หรือใส่ role ใน token ไม่ทำให้เลือกบัญชีอื่นได้
- บัญชีเดียวกันมีหลาย Session ใน fixture ต้องไม่ถูก logout ทั้งหมด
- Session tuple/lifetime ไม่ถูกเปลี่ยน สร้างใหม่ไม่ได้ un-revoke ไม่ได้ และไม่เพิ่มสิทธิ์หรือ auth_version
- exact retry ที่ token ยัง valid คืน success เดิม ทั้ง serial และ concurrent requests
- registry lookup หลัง logout commit ปฏิเสธ session เดิม และ first-session bootstrap เดิมไม่ทำให้ session ที่ revoked ฟื้นคืน
- receipt/clock contract ผิด หรือ token หมดอายุระหว่าง lock wait -> rollback และไม่คืน success
- commit/reset acknowledgement ขัดข้อง -> BACKEND_UNAVAILABLE ไม่อ้างว่า rollback แน่นอนและไม่ retry อัตโนมัติ; explicit retry ที่ยัง valid ทำซ้ำได้อย่างปลอดภัย
- ไม่มี raw bearer token/password/production key ลงโค้ดหรือผลทดสอบ

## นโยบาย disabled/stale session
Logout เป็นคำสั่งที่ลดสิทธิ์อย่างเดียว จึงไม่ต้องมี writer/reviewer หรือบัญชียัง enabled: token ที่ยัง valid และผูก exact owner/session สามารถ revoke session เดิมของตัวเองหลังบัญชีถูกปิด/รุ่นสิทธิ์เปลี่ยนได้

นี่ไม่ใช่การยอมให้ stale session ใช้ read/write หรือออก session ใหม่ การตรวจสิทธิ์ของคำสั่งเหล่านั้นไม่เปลี่ยน. Logout ไม่แก้ Principal หรือรุ่นสิทธิ์. Token ที่หมดอายุแล้วถูกปฏิเสธ ไม่ใช้ logout endpoint เป็น authority oracle สำหรับ credential เก่า

## Isolation / expiry / ordering
ใช้ READ COMMITTED และ lock order เดิม Principal -> Session. If logout locks first, bootstrap replay รอแล้ว DENY หลัง logout commit. If bootstrap locks first, ธุรกรรมที่ผ่านก่อนหน้านั้นเสร็จก่อน จากนั้น logout commit และคำขอใหม่ถูกปฏิเสธ. ไม่อ้างว่า logout ย้อนลบงานที่ commit ไปแล้วหรือยุติ in-flight I/O ทุกชนิดทันที

ตรวจ expiry ณ final database clock sample ไม่ใช่เวลาที่ WAL durable หรือ response ถึงมือถือ. ไม่มี user callback/network call ใน implementation ระหว่าง final check กับ transaction exit. Test-only wrappers ใช้ฉีด fault/delay หลัง SQL จริงเพื่อพิสูจน์ rollback

## Least privilege / compatibility
Service LOGIN NOINHERIT ใช้ได้เพียง SET ไป logout runtime เดียว. Runtime execute ได้เฉพาะ sealed logout function; ไม่มี table read/write หรือ principal/session selectors อื่น

NOLOGIN guard มี SELECT/lock-only immutable-key column grants และ EXECUTE revoker เดิม ไม่มี principal mutation/new session grants. Function ตรวจ exact session_user, fixed search_path, row_security และไม่เรียก dynamic SQL

ถอน EXECUTE raw `runtime_revoke_session(text,uuid)` จาก legacy mutation runtime/service โดยตั้งใจ เพื่อไม่เหลือเส้นทางเลือก Principal โดย caller. เช่นเดียวกับ raw create/activation ที่ปิดก่อนหน้านี้ legacy mutation caller ต้อง fail closed ไม่เพิ่ม grants ให้กลับมา. Admin/bulk revocation API เป็น gate อื่น; owner/superuser เป็น trusted migration authority ไม่ใช่ public runtime

Pool ทำ DISCARD ALL/reset/role-grant checks ก่อนและหลัง lease. ผิด policy หรือ reset ไม่สำเร็จ -> ทิ้ง connection. Default TLS verify-full; insecure test opt-in อนุญาตเฉพาะ 127.0.0.1 + disposable `echo_first_session_test`. Migration ไม่มีรหัสผ่านใช้งานจริง (PASSWORD NULL)

## Verification
Expected 45 top-level unittest methods: 18 first-session tests เดิมที่สืบทอดโดยไม่แก้ + 27 logout tests ใหม่. Matrix subtests และการรันซ้ำไม่บวกเป็น test เพิ่ม

ใช้ PostgreSQL 17 + ephemeral RSA + first-session และ logout service LOGIN/pools จริง. Setup ของ baseline ใช้ administrative fixture สร้าง proof/Principal และ activation service; ไม่อ้างว่ามี browser onboarding ครบวงจร. Fixture สำหรับหลาย session เป็น admin-only test ไม่ใช่ feature login ซ้ำ

Gate ต้องมี: `Ran 45 tests`, `OK`, 5 `LOGOUT_LOCK_OBSERVED` records, `CLEAN_SIGNED_LOGOUT_DATABASE`, independent catalog cleanup=t. Original strict token regression 104 ต้องผ่านด้วย. Unique scoped total เมื่อรันผ่าน = **149** (45+104) ไม่บวก inherited18 ซ้ำ

Source/runtime/artifact evidence จาก CI ของ final head เป็นเกณฑ์ SAT ไม่ถือ expected เป็นผลสำเร็จ. Workflow เก็บ scoped source archive + SHA-256 manifest และ logs โดยไม่เก็บ test credentials

## Completed / Blocked / Next
Completed เมื่อ gate ผ่าน: paired signed current-session logout, constrained DB role/pool, durable revocation + retry/rollback/isolation proofs. ตรวจหน้าเว็บ regression แยกโดยไม่เปิด browser writes

Blocked / UNKNOWN: repeat login/session renewal, logout-all, provider-wide revocation, stolen bearer defense beyond existing checks, production service-secret rotation/drain, HBA/TLS/proxy deployment, HTTP cookies/CSRF/CORS/rate limits, read/write permissions, privacy/erasure และ live publishing

**Next: c5c.5 — Signed Session Renewal / Repeat-Login Contract** ต้องกำหนดเงื่อนไขว่าคำขอใหม่ออก session ได้เมื่อใด และ token/session ที่ถูก revoke ไม่ถูกนำกลับมาใช้หรือข้าม generation check. นโยบาย session issuance/refresh ยังไม่ปิดด้วยงาน logout นี้. ห้ามเปิด public browser writes

## Primary references
- PostgreSQL 17 row locks / transaction lifetime: https://www.postgresql.org/docs/17/explicit-locking.html
- Psycopg transaction contexts: https://www.psycopg.org/psycopg3/docs/basic/transactions.html
- OWASP session lifecycle/invalidation: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
