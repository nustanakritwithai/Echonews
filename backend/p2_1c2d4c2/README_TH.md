# P2.1c.2d.4c.2 — PRIVATE Writer Service LOGIN / Pool Integration

## Scope

งานนี้ปิดเฉพาะ service-login / connection-pool boundary ของเส้นทางเขียน PRIVATE draft ที่ผ่าน recoverable + idempotent executor แล้วเท่านั้น

ไม่เพิ่ม HTTP route, Browser write, PUBLIC publication, production object store, registry/provisioning service pool, secret rotation, PgBouncer mode, หรือ production HBA/TLS.

## Contract

- service login: `echo_private_draft_service`
- login เป็น `NOINHERIT`, ไม่ใช่ superuser/owner, ไม่มี `BYPASSRLS`
- login ไม่มี direct table/function grant ใน Echo schemas
- membership เดียวคือ SET-only ไป `echo_private_draft_runtime`
- ทุก lease ใช้ `SET LOCAL ROLE` ภายใน transaction เดียว
- ก่อนและหลังทุก lease: rollback ถ้าจำเป็น → `DISCARD ALL` → baseline settings → ตรวจ role/membership/table/function ACL ใหม่
- connection ที่ reset ไม่สำเร็จหรือ broken จะถูกทิ้ง ไม่ส่งให้ borrower ถัดไป
- pool **ไม่ retry business SQL** และไม่เดาว่า commit สำเร็จหรือไม่
- unknown commit outcome ถูกส่งกลับให้ durable attempt ledger / idempotency layer reconcile เท่านั้น

## Expected runtime function surface

`echo_private_draft_runtime` ต้องเรียกได้เฉพาะ sealed functions ที่จำเป็นกับ authorization fence + recoverable payload lifecycle ปัจจุบัน:

1. `runtime_private_draft_fence`
2. `runtime_reserve_private_payload_attempt`
3. `runtime_recoverable_idempotent_append_private_voice`
4. `runtime_mark_private_payload_committed`
5. `runtime_abandon_private_payload_attempt`
6. `runtime_claim_stale_private_payload_attempt`
7. `runtime_mark_private_payload_discarded`
8. `runtime_get_private_payload_attempt`
9. `runtime_list_private_payload_recovery`

ถ้ามี table grant, function grant หรือ role membership เพิ่มจาก allowlist นี้ pool ต้อง fail closed ก่อนส่ง connection ให้คำสั่งธุรกิจ

## Verification target

ชุดใหม่ 18 cases ตรวจ real password LOGIN, role isolation, same-backend reuse cleanup, rollback/failed transaction, cleanup fault discard, concurrent borrower serialization, ACL drift, exact retry, revoked session, recoverable payload commit และ unknown post-commit/reset outcome โดยยืนยันว่า retry ภายหลังยังได้ Voice canonical เดิมเพียงหนึ่งรายการ

CI ต้องรัน regression เดิมด้วย:

- P2.1c.2d.3d payload recovery 14 cases
- signed-token boundary 104 cases

## Remaining UNKNOWN / blocked

- production writer secret provisioning + rotation/drain
- production TLS/HBA/certificate policy
- registry/provisioning/recovery worker แยก service account/pool ตามหน้าที่จริง
- PgBouncer/proxy transaction pooling และ cross-process pool budget
- production object store durability/provider semantics
- HTTP auth/cookie/CSRF/CORS/rate limits
- revision 2/edit/withdraw, RESTRICTED ACL, independent owner-read entitlement, PUBLIC publication, privacy/erasure

งานนี้จึงยังไม่เปิด Browser/API write และยังไม่ถือว่า P2 หรือ parent 4c จบทั้งหมด
