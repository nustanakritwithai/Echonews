# P2.1c.2c.3 — Signed Preflight → Durable Registry Integration

## งานเดียวของรอบนี้
เชื่อมตัวตรวจ RS256/JWT ที่มีอยู่จาก P2.1c.2c.1 เข้ากับ PostgreSQL identity/session registry จาก P2.1c.2c.2 โดยไม่สร้าง verifier ใหม่ ไม่เปิด HTTP และไม่เปิดการเขียนข่าวจริง

เส้นทางที่ทดสอบคือ:

`Bearer JWT → existing Boundary signature/issuer/audience/time checks → atomic resolver(issuer,subject,jti) → PostgreSQL lookup_session → Actor + Source + current capabilities → BoundIntent`

`BoundIntent.ready_for_execution` ยังเป็น `False` เสมอ จึงยังไม่ใช่สิทธิ์ commit ข้อมูล

## การเปลี่ยนสำคัญ
- Boundary รองรับ `resolve_binding(issuer, subject, jti)` แบบ atomic เป็นทางเลือกใหม่ ขณะยังรักษา legacy test adapters เดิมเพื่อ regression
- ห้ามผสม atomic resolver กับ legacy lookup/revocation callbacks เพื่อไม่สร้างเส้นทางเลือก validator ที่อ่อนกว่า
- PostgreSQL adapter สร้าง `session_key = SHA-256(domain || issuer || NUL || jti)` หลัง JWT ผ่านลายเซ็นแล้วเท่านั้น ไม่ใช้ raw token และไม่รับ session key จาก client
- lookup หนึ่งคำสั่งตรวจ issuer+subject+derived session key คู่กัน จึงไม่สามารถเอา jti/session ของบัญชีหนึ่งไปจับกับ subject อีกบัญชีหนึ่งได้
- Actor/Source และ capability มาจากทะเบียนปัจจุบันเท่านั้น Claims เช่น actor_id/source_id/role/scope/email แม้ถูกเซ็นก็ไม่ยกระดับสิทธิ์
- `writer_enabled` map เฉพาะ `voice:draft:create`; ไม่แปลงเป็นสิทธิ์ PUBLIC publish
- `reviewer_enabled` map เป็น `assessment:review` preflight เท่านั้น ยังไม่ผ่าน object assignment/self-review/conflict checks
- ผลลัพธ์เพิ่ม `source_id` และลด `expires_at` ให้ไม่เกิน session ฝั่งทะเบียน
- ไม่มี authorization cache; adapter ขอ fresh DB connection ทุกครั้งใน reference นี้

## Session / token binding
ทะเบียนยังไม่สร้าง session เอง งาน provisioning ต้องคำนวณ session key ด้วยฟังก์ชันเดียวกันจาก issuer+jti ที่ออกโดย verifier/provider ที่เชื่อถือ แล้ว insert session ภายใต้ auth_version ปัจจุบัน

adapter ตรวจ session `revoked`, `auth_version`, enabled, issued/expires และ current DB clock ใน snapshot ที่อ่าน เมื่อ token ถูกออกก่อน session issued_at จะถูกปฏิเสธด้วย tokens_valid_from

การเปลี่ยน auth_version/revoke ที่ commit ก่อน lookup ถัดไปต้องเห็นผลและปฏิเสธ session เก่า แต่ยังมี TOCTOU หลัง preflight ก่อน future write commit; ไม่ได้ปิดใน task นี้

## Verification
CI ใช้ ephemeral RSA key + PyJWT verifier จริงและ PostgreSQL 17 service จริง พร้อมข้อมูล synthetic เท่านั้น

รัน:

```sh
python backend/p2_1c2b1/run_checks.py
python -m unittest -v backend/p2_1c2c3/test_signed_registry_integration.py
```

ชุดใหม่ตรวจอย่างน้อย valid token→DB Actor/Source, signed role injection, reviewer grant, revoke, disable/re-enable, new auth generation, subject/session mismatch, invalid signature/issuer/audience/expiry ก่อน DB, DB outage, local session expiry, token-before-session, effective expiry และ prohibition on PUBLIC field injection.

CI ยัง rerun P2.1c.2c session registry unit/PostgreSQL regression เดิมเพื่อรักษา dependency นี้ ผล SAT ต้องอ่านจาก run จริง ไม่ถือจำนวน expected ในเอกสารเป็น PASS

## SAT ที่งานนี้สามารถพิสูจน์ได้เมื่อ CI ผ่าน
- existing signed verifier ถูกใช้จริง ไม่ใช่ mock signature result
- verified issuer+subject+jti ถูกจับคู่กับ durable registry/session เดียวกัน
- Actor/Source/role hint ใน signed token ไม่แทน DB authority
- revoke/disable/stale auth_version ที่อ่านเห็นแล้วทำให้ request ถัดไปถูกปฏิเสธ
- draft permission ไม่กลายเป็น PUBLIC permission

## UNKNOWN / BLOCKED ต่อ
- production issuer/JWKS/key rotation และ provider-specific access-token profile
- session establishment/refresh/logout/provisioning ownership proof
- DB runtime role/pool ที่ least-privilege จริงและ primary routing
- reviewer assignment, self-review/conflict-of-interest และ object authorization
- commit-time authorization fence / revoke-vs-write race
- idempotent DB command execution, payload storage, owner/private/restricted reads
- CSRF/origin/rate limits, privacy erasure/backups, snapshot sealing และ semantic/media verification

Authenticated account ยังไม่เท่ากับ human proof หรือ independent eyewitness และไม่ทำให้ Claim จริงขึ้น

## Next
**P2.1c.2d.1 — commit-time authorization fence contract** เป็น critical UNKNOWN ถัดไป: ต้องให้ command writer recheck principal/session auth_version/revoke/expiry ใน transaction เดียวกับ write และทดสอบ revoke-vs-write race ก่อนเปิด HTTP write API
