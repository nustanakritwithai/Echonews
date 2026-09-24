# P2.1c.2d.4c.5c.3 — Signed First-Session Bootstrap

งานนี้ปิดช่องว่างระหว่าง **Audited Activation** กับ **Session แรก** โดยยังไม่เปิด HTTP/API สาธารณะ

## Contract

Input ที่เชื่อถือไม่ได้มีเพียง:

- `Authorization: Bearer <signed access token>`
- JSON body ต้องเป็น `{}` เท่านั้น

Backend จะตรวจ signature / issuer / audience / `iat` / `nbf` / `exp` / `jti` ก่อน แล้ว derive `session_key` จาก `issuer + jti` ด้วย contract เดิมของ durable registry

Browser/Caller **ห้ามส่ง** `principal_id`, `actor_id`, `source_id`, `issuer`, `subject` หรือ `session_key`

## Database boundary

เพิ่ม role แยกสามชั้น:

- `echo_first_session_service` — LOGIN สำหรับ backend เท่านั้น
- `echo_first_session_runtime` — NOLOGIN, เรียกได้เฉพาะ sealed bootstrap function
- `echo_first_session_guard` — NOLOGIN owner ของ SECURITY DEFINER function

`runtime_bootstrap_first_session(...)` จะ resolve Principal จาก `issuer + subject` ที่ verify แล้ว และยอมสร้าง Session เฉพาะเมื่อ:

1. Principal ผ่าน audited first activation แล้ว
2. authority ปัจจุบันเป็น `enabled=true`, `auth_version=2`, `writer=false`, `reviewer=false`
3. token ยังอยู่ในช่วงเวลาใช้งาน
4. Principal ยังไม่มี Session อื่น
5. exact retry ด้วย token เดิมต้องคืน Session เดิม ไม่สร้างซ้ำ

raw c4 `runtime_create_session(...)` ถูก revoke จาก mutation runtime เพื่อปิด bypass ที่ caller ภายในอาจเลือก `principal_id` เอง

## Pool safety

`FirstSessionPool` ใช้ protocol เดียวกับ service pool ก่อนหน้า:

`ROLLBACK (ถ้าจำเป็น) → DISCARD ALL → restore baseline → verify roles/grants → BEGIN → SET LOCAL ROLE → operation → reset again`

Connection ที่ cleanup ไม่สำเร็จต้องถูกปิด ไม่ส่งต่อให้ borrower ถัดไป และไม่มี automatic business-command replay เมื่อ commit outcome ไม่ชัดเจน

## ยังไม่เปิด

- repeat login / session renewal
- cookie/session HTTP transport
- CSRF/CORS/rate-limit
- production credential rotation/drain
- HBA/TLS/PgBouncer contract
- writer/reviewer grants
- privacy/erasure
- PUBLIC publishing

ดังนั้น c5c.3 เป็นเพียง **first-session bootstrap gate** ไม่ใช่ production authentication rollout
