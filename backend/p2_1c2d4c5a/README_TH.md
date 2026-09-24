# P2.1c.2d.4c.5a — Account-Link Proof DB Contract

งานนี้ปิดเฉพาะ **database half** ของ Critical UNKNOWN เรื่อง IdP account → Actor/Source ownership ก่อน provision principal

## สิ่งที่เปลี่ยน

เพิ่ม durable mapping:

`(issuer, subject) -> server-generated actor_id + source_id`

Actor/Source ID ถูกสร้าง **ภายใน SECURITY DEFINER function** เท่านั้น API ของ proof issuer ไม่มี parameter `actor_id` หรือ `source_id` จึงไม่มีทางให้ request เลือก Actor/Source ของคนอื่นผ่าน path นี้

เพิ่ม short-lived proof:

`proof_id -> issuer + subject + actor_id + source_id + expires_at + consumed_principal_id`

Proof อายุได้สูงสุด 5 นาที, ต้องไม่เกิน token expiry, ใช้ provision ได้ครั้งเดียว และ exact retry ของ principal เดิมยัง idempotent หลัง unknown commit

## การปิด bypass

หลัง migration นี้ `echo_identity_mutation_runtime` ถูกถอน EXECUTE จาก

`runtime_provision_principal(principal_id, issuer, subject, actor_id, source_id)`

แล้วให้เรียกได้เฉพาะ

`runtime_provision_principal_with_link_proof(principal_id, proof_id, issuer, subject)`

ดังนั้น mutation runtime ไม่สามารถส่ง Actor/Source เองได้อีก

`echo_account_link_runtime` เป็น NOLOGIN และเรียกได้เฉพาะ `runtime_issue_account_link_proof(...)` ไม่มี table access และ provision principal ไม่ได้

## ข้อจำกัดที่ยังเป็น Critical UNKNOWN

งานนี้ **ยังไม่พิสูจน์ว่า issuer/subject มาจาก signed token จริง** เพราะยังไม่มี Service LOGIN หรือ backend signed-token adapter สำหรับ `echo_account_link_runtime`

ดังนั้นยังห้ามเปิด Browser/API onboarding และห้ามถือว่า P2.1c.2d.4c.5 จบแล้ว

งานถัดไปต้องเป็น `P2.1c.2d.4c.5b — Signed Account-Link Boundary + Service Pool` โดย request ต้องส่งได้เพียง bearer token; backend เป็นฝ่าย verify signature/issuer/audience/time แล้วสร้าง proof_id เอง ห้ามรับ issuer/subject/actor_id/source_id จาก JSON
