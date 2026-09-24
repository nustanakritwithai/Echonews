# P2.1c.2d.4c.5c.5b.1 — Active-Session Renewal / Rotation Contract

## Task
ปิด critical UNKNOWN ที่เล็กที่สุดต่อจาก c5c.5a: กำหนด semantics ที่แน่นอนสำหรับการหมุน Session ขณะที่ Session เดิมยัง active โดย **ยังไม่เพิ่ม production DB function / HTTP route / refresh token**

## Decision
ใช้นโยบาย `MONOTONIC_SIGNED_BEARER_ROTATION_V1`.

### หลักการ
1. Echo News **ไม่ออก refresh token ของตัวเองใน gate นี้**. Renewal proof คือ Bearer token ใหม่จาก issuer ที่ตั้งค่าไว้ ซึ่งต้องผ่าน signature / issuer / audience / iat / nbf / exp / jti verification เหมือน boundary ก่อนหน้า
2. Request body สำหรับ renewal ต้องเป็น `{}` เท่านั้น. Caller เลือก `principal_id`, `actor_id`, `source_id`, `session_key`, predecessor หรือ policy ไม่ได้
3. Server derive candidate `session_key` จาก verified `issuer + jti`
4. Principal ต้องเป็น subject เดิม, `enabled=true`, มี activation provenance และอยู่ใน `auth_version` ปัจจุบัน
5. ต้องมี live Session อยู่แล้วใน current generation; ถ้าไม่มี ให้ใช้ repeat-login path c5c.5a แทน ไม่ silently เปลี่ยน semantics
6. ถ้า Bearer เดิมถูกส่งซ้ำและ session_key ตรงกับ current live Session ให้ตอบ idempotent replay; ไม่ rotate
7. Bearer ใหม่จะ rotate ได้ต่อเมื่อ `candidate.iat_ms > current_session.issued_at_ms` แบบ strict. Token ที่เก่ากว่า/เวลาเท่ากันห้าม rollback current Session ไปหา credential เก่า
8. Rotation ต้อง atomic ภายใต้ Principal/session lock: predecessor ถูก revoke และ successor ถูกสร้างใน transaction เดียว. หลัง commit ต้องมี live Session ของ current generation ได้สูงสุดหนึ่งตัว
9. Predecessor หลังถูกแทนที่ต้อง reject เสมอ; ห้าม resurrect และห้ามใช้ rotate กลับ
10. Unknown post-commit acknowledgement ห้าม auto-replay business mutation. Explicit retry ด้วย candidate Bearer เดิมต้อง resolve เป็น successor เดิม
11. Concurrent candidates serialize. หลัง candidate หนึ่ง commit แล้ว candidate ที่ `iat` ต่ำกว่าหรือเท่ากันต้อง reject; candidate ที่ใหม่กว่าจริงอาจ supersede ต่อได้อย่าง deterministic
12. ถ้า authority generation เปลี่ยน, candidate ต้อง resolve current generation ใหม่; Session generation เก่าไม่สามารถ authorize renewal generation ใหม่ได้
13. ไม่มี overlap/grace window หลัง DB commit. งาน HTTP/cookie ในอนาคตต้องเปลี่ยน client credential ให้ตรงกับ current Session ก่อน request ถัดไป
14. ไม่เพิ่ม refresh-token family semantics. ถ้าอนาคต Echo ออก refresh token เอง ต้องเปิด gate ใหม่และทำตาม replay defense ของ RFC 9700 (sender-constrained หรือ rotation)

## Security rationale
- OWASP Session Management แนะนำให้ renew/regenerate session identifier และทำให้ identifier เก่าใช้ต่อไม่ได้เมื่อมีการเปลี่ยน authentication/privilege state
- RFC 9700 กำหนด replay defense สำหรับ refresh tokens ของ public clients. Gate นี้หลีกเลี่ยงการสร้าง refresh token ใหม่โดยใช้ fresh issuer-signed Bearer เป็น renewal proof และเก็บ Echo Session เป็น server-side authorization state
- Strict monotonic `iat` ป้องกัน credential เก่าที่ยังไม่หมดอายุจากการ rotate ระบบย้อนกลับไปหา Session เก่า

References:
- RFC 9700, OAuth 2.0 Security Best Current Practice, §4.14: https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

## Executable contract model
`renewal_contract.py` เป็น pure deterministic state machine สำหรับ policy นี้ ไม่ใช่ production auth implementation. `test_renewal_contract.py` pin invariants ที่ implementation รอบถัดไปต้องรักษา:
- exact-token replay
- strictly newer bearer rotation
- stale/equal iat rejection
- predecessor non-resurrection
- zero/one live session invariant
- no-active-session handoff to repeat-login
- unknown-commit explicit retry
- sequential concurrency ordering
- disabled/stale-generation rejection
- token time-window validation

## SAT boundary for this task
SAT หมายถึง policy/decision ไม่มี semantic hole ภายใน executable model และ CI tests ผ่าน. **SAT ไม่ได้แปลว่า production PostgreSQL rotation ถูกพิสูจน์แล้ว** เพราะ implementation ยังไม่มีใน task นี้

## Blocked / Next
ยัง block: PostgreSQL/service-role implementation ของ atomic rotation, audit/lineage persistence, real connection-pool race tests, HTTP/cookie handoff, provider-side revocation/introspection, HBA/TLS/PgBouncer/credential rotation, logout-all, reviewer/object permissions, privacy/erasure และ PUBLIC publishing.

**Next: c5c.5b.2 — PostgreSQL Atomic Active-Session Rotation + Service Boundary.**
