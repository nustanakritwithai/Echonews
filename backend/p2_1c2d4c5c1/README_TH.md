# P2.1c.2d.4c.5c.1 — Signed Disabled-Principal Provisioning

## Task / Concrete Output
งานเดียวจาก main `ee84021847b4be115fc025f933bb5c14e9b59eaa`: เชื่อม proof ที่สร้างโดย c5b กับการสร้าง Principal จริง โดยตรวจ token ใหม่และห้ามเลือก Actor/Source/Principal เอง

Parent c5c คือ principal provisioning/session bootstrap แต่รอบนี้ปิดได้เฉพาะ **Principal provisioning**: สัญญา c4 กำหนด principal ใหม่เป็น disabled และไม่มี writer/reviewer grants. การ enable เพื่อสร้าง session โดยไม่มี activation policy คือการข้าม critical UNKNOWN จึงไม่ทำ

เพิ่ม SQL function/service role, fixed-role pool, signed boundary และ integration tests แบบ additive ไม่แก้ verifier, c5b precommit fix, c4/c5a functions/grants หรือ frontend

## Flow
```text
Bearer token + {"proof_id":"server-issued UUID"}
  -> strict request allowlist (proof reference only)
  -> existing c5b RS256/token-profile verifier (ตรวจใหม่ทุก request)
  -> issuer/subject จาก verified claims เท่านั้น
  -> echo_principal_provision_service LOGIN
  -> sanitized pool transaction / SET LOCAL ROLE
  -> runtime_provision_signed_principal(...)
  -> exact issuer/subject + live proof + current DB clock
  -> serialize same identity / server generates or resolves Principal ID
  -> existing c5a proof consumer -> existing c4 disabled-principal provisioner
  -> principal INSERT + proof consumed atomically
  -> receipt validation + final DB clock inside same transaction
  -> commit/reset -> PrincipalReceipt(principal_id)
```

proof_id เป็นเพียงตัวอ้างอิง proof ที่ server สร้างไว้ ไม่ใช่ bearer credential และไม่ใช่คำสั่งเลือก mapping. Client ที่รู้ proof ของคนอื่นก็ใช้ไม่ได้โดยไม่มี valid token สำหรับ exact issuer/subject นั้น. ไม่รับ issuer,subject,actor_id,source_id,principal_id,role,enabled,session_key ใน body

ผลตอบกลับไม่รวม Actor/Source, permissions, raw JWT หรือ DB receipt. principal_id เป็น identifier ไม่ใช่สิทธิ์ และ ready_for_execution=False เสมอ. ยังไม่มี HTTP route จึงยังไม่มีการเปิด onboarding บน browser

## Identity / Retry
- Principal ID ใหม่สร้างภายใน sealed SQL function ด้วย gen_random_uuid ไม่ derive จาก email/token custom claims
- Actor/Source มาจาก account_subject_bindings ที่ c5a สร้างและ proof ที่ exact-match เท่านั้น
- หนึ่ง issuer/subject มี Principal เดียว. Same proof หรือ proof ใหม่ของ subject เดิม resolve Principal เดิม
- ล็อก advisory key ตาม c5a และ consumer ล็อก proof row; race tests ยืนยันจำนวนแถว ไม่อนุมานจากลำดับ call
- Exact text matching ไม่ trim/case-fold: identity ต่างกันยังแยกกัน และข้อความคล้าย SQL ใช้ parameter binding
- Replay ต้องมี token และ proof ที่ยังไม่หมดอายุ แม้ lower-level c5a จะยอม exact retry หลัง proof หมดอายุ; paired path นี้เข้มกว่าโดยตั้งใจ
- คำขอซ้ำไม่ re-enable บัญชีที่ถูก disable ไม่เพิ่ม role ไม่ reset auth_version และไม่ออก session
- หาก commit/reset acknowledgement ไม่แน่นอนให้ BACKEND_UNAVAILABLE ไม่อ้างว่า rollback สำเร็จและไม่ retry อัตโนมัติ. Explicit verified retry ขณะ proof ยัง live จะได้ Principal เดิม ไม่เพิ่มแถวซ้ำ

## Least privilege
Service LOGIN เป็น NOINHERIT, ไม่มี table/function grant โดยตรง และ SET-only membership ไป provisioning runtime เดียว. Runtime เรียกได้เฉพาะ function นี้ ไม่มีสิทธิ์ issue proof, raw provision, activation, change role, session creation หรือ revoke

Guard NOLOGIN/NOBYPASSRLS มีเพียง SELECT principals/proofs และ EXECUTE existing c5a consumer; ไม่มี principal/session DML หรือ membership เข้า mutation guard. SECURITY DEFINER path ใช้ fixed search_path และ row_security=on. การ grant EXECUTE ไป nested sealed consumer ไม่ได้ให้สิทธิ์เปลี่ยนบัญชีทั่วไป

Pool ตรวจ service user, memberships, roles, tables/columns/functions ACL, function owner/security config ก่อนและหลังทุก lease. DISCARD ALL และคืน baseline แบบ synchronous; reset/broken/authority drift -> fail closed ทิ้ง connection. raw pool ยังเป็น trusted backend internal ไม่ใช่ sandbox ต้านโค้ด backend ที่ถูกยึด

Production default sslmode=verify-full. Insecure mode ยอมเฉพาะ opt-in loopback disposable database `echo_account_link_signed_test` เพื่อทดสอบร่วมกับ c5b pool. ไม่มี password จริงใน migration (`PASSWORD NULL`); runtime tests สร้างรหัสชั่วคราวในหน่วยความจำ

## Time / Rollback
ตรวจ DB clock หลัง advisory wait, หลัง consumer อาจรอ proof row, และก่อนออกจาก backend transaction. Token/proof หมดอายุหรือ receipt/clock contract ผิด -> rollback Principal และ proof consumed marker. Account-link proof/Actor/Source ถูกสร้างโดย c5b ในธุรกรรมก่อนหน้าและไม่ได้ถูกลบเมื่อ consumption ไม่สำเร็จ

Expiry guarantee อยู่ ณ final database clock sample ไม่ใช่เวลาที่ WAL durable หรือ client ได้รับ acknowledgement. ห้ามเติม user callbacks/network calls ระหว่าง final check และ commit ใน executor. Production distribution/clock skew/timeout policy ยังเป็นคนละ gate

## Verification
Expected 34 top-level new methods; matrix subtests ไม่นับซ้ำ. CI รัน real PostgreSQL 17, ephemeral RSA, signed proof issuer, provisioning LOGIN/pool ทั้งสองจริง:

- signed flow -> disabled/no grants; proof reference alone, wrong token/subject/issuer/audience denied
- injection/duplicate JSON/signed custom claims ไม่เลือก mapping หรือเพิ่มสิทธิ์
- same/new proof retries และ concurrency ให้หนึ่ง Principal
- disabled/active existing authority ไม่ถูกเปลี่ยน
- expiry ระหว่าง advisory/proof-row lock waits มี pg_blocking_pids proof
- receipt/clock fault AFTER real SQL -> rollback principal/consume
- service no-bypass, drift, cleanup, reset, errors and unknown-ack explicit retry
- ไม่มีแถว Session หรือข่าวจริงเกิดขึ้น

อ่านผลจริงจาก CI ของ final head ไม่ถือ expected เป็น SAT. New workflow รัน regression: c5a 20, c5b precommit 20 (รวม 18 เดิม + 2 fixes), original verifier 104 ก่อน suite ใหม่. Unique scoped total เมื่อทุกชุดผ่าน = 178; ไม่บวกการรันเดิมซ้ำจาก workflow อื่น

## Completed / Blocked / Next
Completed เมื่อ gate ผ่าน: signed proof consumption -> server-owned Principal ที่ default disabled, restricted service/pool, stable retry and concurrency, rollback/expiry proofs

Blocked/UNKNOWN: c5c parent ยังไม่จบ; activation authorization/audit, session bootstrap/refresh/logout, production provider/revocation integration and transport, service credential rollout/rotation, HTTP/CSRF/rate limits, reviewer assignments/self-review, privacy/erasure และ multi-user publication

**Next: c5c.2 — Activation Authorization Contract + Audit** ต้องกำหนดผู้อนุมัติ/นโยบายเปิดบัญชีและพิสูจน์ว่าคำขอ onboarding เพิ่มสิทธิ์ตนเองไม่ได้ ก่อนผูก first-session bootstrap. ยังไม่เปิด browser writes

Primary references: PostgreSQL 17 explicit-locking and transaction isolation; psycopg 3 transaction contexts. Provider verification reuses repository-pinned dependencies, not an unreviewed version upgrade.
- https://www.postgresql.org/docs/17/explicit-locking.html
- https://www.postgresql.org/docs/17/transaction-iso.html
- https://www.psycopg.org/psycopg3/docs/basic/transactions.html
