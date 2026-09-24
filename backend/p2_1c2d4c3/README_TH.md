# P2.1c.2d.4c.3 — Durable Identity Registry Service LOGIN / Pool Separation

งานนี้ปิดเฉพาะช่องที่ signed-token boundary เคยอ่าน `principals/sessions` ผ่าน trusted owner-level connection ใน integration fixture เดิม โดยแยกเส้นทาง lookup ออกเป็น service credential ของตัวเอง

## ขอบเขตที่เพิ่ม

- `echo_identity_registry_guard` — `NOLOGIN`, ถือ `SELECT` เฉพาะ `principals/sessions` และเรียก lookup เดิมได้ แต่เขียนไม่ได้
- `echo_identity_registry_runtime` — `NOLOGIN`, ไม่มี table privilege และเรียกได้เฉพาะ `runtime_lookup_session(...)`
- `echo_identity_registry_service` — `LOGIN NOINHERIT`, ไม่มี table/function privilege โดยตรง และ SET ได้เฉพาะ runtime
- `RegistryPool` — reset connection แบบ synchronous (`ROLLBACK` ถ้าจำเป็น → `DISCARD ALL` → baseline validation), `SET LOCAL ROLE` เฉพาะใน transaction และ discard connection เมื่อ reset/authority check ล้มเหลว
- `ServicePostgresRegistryAdapter` — reuse parser/validation ของ P2.1c.2c.3 แต่เปลี่ยน SQL lookup เป็น sealed runtime wrapper เท่านั้น

ไม่มี JWT/Actor/Source/principal ใดถูกเก็บไว้ใน connection settings และไม่มี client-supplied role

## Security contract

1. signature/issuer/audience/time ต้องผ่าน `Boundary` ก่อนเรียก registry เช่นเดิม
2. service LOGIN ไม่อ่าน registry table และไม่ execute lookup function ที่ baseline role
3. runtime อ่าน table ตรง ๆ ไม่ได้; เห็นได้เฉพาะผลจาก security-definer wrapper
4. guard ไม่มี LOGIN และมี read-only data privilege
5. pool ตรวจ role flags, membership, direct ACL, function allowlist และ schema/database CREATE ก่อนทุก lease
6. successful/error lease ต้องกลับ baseline เดิมก่อน reuse; reset failure = discard ไม่ใช่ reuse
7. ไม่มี automatic application-level retry ใน pool
8. TLS default เป็น `verify-full`; `sslmode=disable` อนุญาตเฉพาะ disposable loopback test profile ที่ชื่อ DB ตายตัว

## ไม่ได้แก้ในงานนี้

- account/session provisioning หรือ revoke API
- provisioning/recovery worker service credential
- secret manager, password rotation + connection drain
- production HBA / client certificate / PgBouncer policy
- HTTP cookie/CSRF/CORS/rate limit
- independent PRIVATE read entitlement
- revision/edit/withdraw, RESTRICTED ACL, PUBLIC publication, privacy/erasure

ดังนั้น Browser/API และ PUBLIC publishing ยังต้องปิดอยู่หลัง gate นี้
