# c5c.5b.2 — Atomic Active-Session Rotation + Service Boundary

Task เดียวต่อจาก main `e7cf6e962a3e92825c9e068bd663456f47ca3345`: ทำให้สัญญา `MONOTONIC_SIGNED_BEARER_ROTATION_V1` จาก c5c.5b.1 ใช้กับ PostgreSQL จริง. ยังไม่มี HTTP/browser write หรือ Echo refresh token

## Success Contract
- Request body `{}` เท่านั้น; reused signed verifier เป็นแหล่ง issuer/subject/jti/เวลา ไม่รับ predecessor/Principal/session key จาก client
- Lock Principal และ Session; ต้องมี live Session ของ current auth_version เพียงหนึ่งตัว. ไม่มี live -> คืน error ให้ไป repeat-login; มากกว่าหนึ่ง -> fail closed
- Same current Bearer/lifetime -> replay ไม่เพิ่มแถว. New Bearer ต้องมี iat มากกว่า current แบบ strict
- Revoke predecessor + INSERT successor + append immutable lineage ใน transaction เดียว; ความผิดพลาด/หมดอายุ -> rollback ทั้งชุด
- Revoked key ห้ามฟื้นคืน; collision ของบัญชีอื่นห้ามเลือก mapping ใหม่; current-generation check และ activation provenance ยังบังคับ
- Receipt validation และ DB clock หลัง lock waits อยู่ก่อน commit. Lost acknowledgement -> error ไม่ retry อัตโนมัติ; explicit same-Bearer retry ต้อง resolve successor เดิม
- Runtime แยก LOGIN/NOLOGIN roles ไม่มี direct table access หรือ raw create/revoke call. ไม่เปลี่ยนสิทธิ์บัญชี ไม่เพิ่ม writer/reviewer

## Verification plan
Real PostgreSQL 17, ephemeral RS256, existing first-session/logout/repeat-login regressions, deterministic policy model, and observed concurrent lock races. ตรวจ atomic rollback, stale/equal token, no resurrection, collision, generation changes, receipt/time faults, lineage immutability and service isolation. Expected cases ไม่ใช่ PASS จนรัน final-head CI และตรวจหลักฐานจริง

## Scope limits
Fresh issuer-signed Bearer เป็น renewal proof ไม่ใช่ proof of human presence หรือ stolen-token mitigation. Body ไม่มี credential policy ให้เลือก. Audit lineage เป็น protected DB history ไม่ใช่ cryptographic sealing/DBA tamper-proof ledger

Same-key replay บังคับทั้ง iat และ exp ให้ตรง existing session (เข้มกว่า model ที่ตรวจแค่ iat); ไม่ยืดอายุเงียบ ๆ. หาก predecessor/candidate หมดอายุระหว่าง transaction ให้ deny/rollback แทน silently เปลี่ยนเป็น repeat-login. Time guarantee คือ final DB clock sample ไม่ใช่ WAL durability/client acknowledgement

ยัง BLOCKED: production IdP/profile/revocation integration, real TLS/HBA/proxy/credential rollout, browser cookie/token handoff, rate limiting/CSRF, logout-all, object/reviewer authorization, privacy/erasure และ PUBLIC publishing. ไม่รัน migration กับฐาน production

## Next
หลัง atomic DB/service gate ผ่าน ให้ทำ bounded integration proof ของวงจร onboarding -> activation -> session -> renewal -> logout ผ่าน restricted service pools ก่อนเปิด HTTP transport. ห้ามใช้ receipt เก่าแทน current authorization

## Primary references
- https://www.postgresql.org/docs/17/explicit-locking.html
- https://www.postgresql.org/docs/17/transaction-iso.html
- https://www.psycopg.org/psycopg3/docs/basic/transactions.html
