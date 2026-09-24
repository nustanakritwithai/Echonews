# P2.1c.2d.4c.4 — Identity Provisioning / Session Mutation Service Boundary

งานนี้ปิดเฉพาะช่องที่การสร้าง/เปลี่ยน durable identity และ session ยังต้องใช้ owner-level DB connection หลังจาก 4c.3 แยก read-only registry lookup แล้ว

## ขอบเขตที่เพิ่ม

มี service chain แยกใหม่:

`echo_identity_mutation_service` (LOGIN, NOINHERIT) → `SET LOCAL ROLE echo_identity_mutation_runtime` → 4 sealed SECURITY DEFINER functions owned by `echo_identity_mutation_guard` (NOLOGIN)

Service/runtime ไม่มีสิทธิ์ SELECT/INSERT/UPDATE ตาราง `principals` หรือ `sessions` โดยตรง และ service ไม่มี EXECUTE function โดยตรง Guard มีเพียง SELECT + column-level INSERT/UPDATE ที่จำเป็นต่อ 4 operations เท่านั้น ไม่มี DELETE/TRUNCATE

Operations:

1. `runtime_provision_principal(...)` — สร้าง HUMAN principal ที่ `enabled=false`, writer/reviewer=false เท่านั้น และ exact retry ได้
2. `runtime_change_principal_authority(...)` — เปลี่ยนเฉพาะ enabled + PRIVATE writer bit ด้วย expected `auth_version`; exact retry หลัง unknown commit ไม่ bump generation ซ้ำ
3. `runtime_create_session(...)` — สร้าง session เฉพาะ principal ที่ enabled และ generation ปัจจุบัน; exact retry ได้และ session ที่ revoke แล้วห้ามสร้างกลับ
4. `runtime_revoke_session(...)` — revoke session แบบ idempotent และ bind กับ principal

Reviewer authority ไม่อยู่ใน API นี้โดยตั้งใจ การเปลี่ยน reviewer principal จะ fail closed จนกว่าจะมี reviewer object-authorization gate

## Pool contract

`MutationPool` login ด้วย service account จริง, ตรวจ startup user / role flags / membership / ACL allowlist ทุก lease, rollback state ค้าง, `DISCARD ALL`, ตั้ง baseline ใหม่ แล้ว `SET LOCAL ROLE` เฉพาะ transaction เดียว การ reset ล้มเหลวจะ discard connection

Pool **ไม่ replay business mutation อัตโนมัติ** หาก commit สำเร็จแล้วแต่ cleanup/connection response ล้มเหลว ผู้เรียกอาจ retry ด้วย parameters เดิมเท่านั้น เพราะ 4 sealed operations มี idempotency contract

TLS default คือ `verify-full`; `disable` ยอมเฉพาะ disposable loopback test profile ที่ชื่อ DB ถูก pin ไว้

## สิ่งที่ยังไม่พิสูจน์

- Actor/Source ownership proof และ IdP account-link proof ก่อน provision
- reviewer grants / reviewer object authorization
- production secret issue + rotation + draining connections
- production HBA / TLS / client certificates / PgBouncer
- bulk revoke, device/session management UI, erasure
- HTTP cookie/CSRF/CORS/rate limit
- PUBLIC publication

ดังนั้นงานนี้ยังไม่เปิด Browser/API auth หรือ publishing

## Verification target

CI ต้องใช้ PostgreSQL 17 ผ่าน real password LOGIN และอย่างน้อย 20 mutation/pool cases รวม exact retry, stale generation, revoke, cross-service isolation, direct-DML denial, connection-state cleanup, privilege drift, concurrency และ unknown-postcommit reset พร้อมรักษา signed-token regression เดิม
