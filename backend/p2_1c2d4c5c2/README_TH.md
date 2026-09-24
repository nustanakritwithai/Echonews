# P2.1c.2d.4c.5c.2 — Activation Authorization Contract + Audit

งานนี้ปิดเฉพาะ critical UNKNOWN เรื่อง **ใครมีสิทธิ์เปิดใช้งาน Principal ที่เพิ่ง provision แล้ว** หลัง c5c.1

## Decision

การมี Bearer token ที่ถูกต้องและ account-link proof **ไม่เท่ากับสิทธิ์ activate บัญชี** ผู้ใช้ onboarding จึง self-activate ไม่ได้

สิทธิ์ activate ครั้งแรกถูกแยกเป็น credential ภายในเฉพาะงาน:

`echo_activation_service` → `SET LOCAL ROLE echo_activation_runtime` → sealed `runtime_activate_provisioned_principal(...)`

ฟังก์ชันยังตรวจ `session_user` ว่าต้องเป็น `echo_activation_service` จริง จึงไม่พอที่จะได้ runtime role อย่างเดียว

## Transition ที่อนุญาต

อนุญาตเพียง transition แรกเดียว:

- Principal ต้องมาจาก consumed account-link proof ที่ Actor/Source/issuer/subject ตรงกัน
- ก่อนทำ: `enabled=false`, `writer_enabled=false`, `reviewer_enabled=false`, `auth_version=1`
- หลังทำ: `enabled=true`, `writer_enabled=false`, `reviewer_enabled=false`, `auth_version=2`

งานนี้ **ไม่ grant writer**, **ไม่ grant reviewer**, **ไม่สร้าง Session**, และไม่เปิด HTTP/browser path

การ suspend/reactivate ภายหลัง หรือ writer/reviewer policy ต้องมี gate คนละตัว ไม่ reuse first-activation credential

## Audit / retry contract

ทุก activation สำเร็จ append `echo_identity.activation_audit` หนึ่งแถวต่อ Principal โดยบันทึก:

- server decision UUID
- target Principal
- consumed proof provenance
- fixed policy code `PROVEN_ACCOUNT_ONBOARDING_V1`
- authority generation 1 → 2
- service role
- DB timestamp

runtime roles ไม่มี UPDATE/DELETE บน audit table

ถ้า DB commit สำเร็จแต่ acknowledgement หาย การ retry ด้วย decision UUID เดิมคืน audit เดิมและไม่ increment auth_version ซ้ำ การใช้ decision UUID เดิมกับ Principal อื่นถูกปฏิเสธ

## Bypass closure

migration ถอน EXECUTE ของ `runtime_change_principal_authority(...)` จาก `echo_identity_mutation_runtime` และ service เดิม ดังนั้น c4 mutation credential ไม่สามารถเปิดบัญชีหรือ grant writer แบบข้าม audit ได้อีก

c4 session create/revoke ยังเก็บไว้สำหรับ gate bootstrap/logout ที่จะตามมา

## Verification scope

ชุดใหม่ตรวจ 20 methods บน PostgreSQL 17 ด้วย real password LOGIN ของ activation service รวม valid activation, exact replay, decision retarget, missing/mismatched proof provenance, stale/pre-enabled state, raw authority bypass, direct table/function denial, service/session-user isolation, role membership, audit immutability, concurrency, wrong password และการยืนยันว่าไม่มี Session/Voice ถูกสร้าง

workflow เก่าที่ path `database/**` trigger จะรัน regression ของ signed Principal และ dependency gates เพิ่มเติมด้วย

## ยัง BLOCKED

- first-session bootstrap / refresh / logout orchestration
- production activation credential provisioning + rotation/drain
- operator/policy API หรือ UI
- suspension/reactivation
- writer/reviewer authorization
- HTTP cookie/CSRF/CORS/rate limit
- privacy/erasure และ PUBLIC publishing

ดังนั้น c5c parent และ P2 ยังไม่เสร็จ

**Next:** `P2.1c.2d.4c.5c.3 — Signed First-Session Bootstrap` ให้ verified Bearer token ของ issuer/subject เดิม resolve Principal ที่เปิดใช้งานแล้ว, server สร้าง session key เอง, และผูก session กับ auth_version=2 โดย client เลือก Principal/Actor/Source ไม่ได้
