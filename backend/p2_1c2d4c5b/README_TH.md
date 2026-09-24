# P2.1c.2d.4c.5b — Signed Account-Link Boundary + Service Pool

งานนี้ปิด Critical UNKNOWN จาก 5a เพียงข้อเดียว: `issuer + subject` ที่ใช้ขอ account-link proof ต้องมาจาก Bearer token ที่ตรวจลายเซ็นและ token profile แล้ว ไม่ใช่ JSON จาก client

## Contract

เส้นทางใหม่คือ:

```text
Bearer access token
  -> strict RS256 / at+jwt / kid / issuer / audience / iat / nbf / exp / jti verification
  -> server generates proof_id
  -> dedicated echo_account_link_service LOGIN
  -> clean pooled transaction
  -> SET LOCAL ROLE echo_account_link_runtime
  -> runtime_issue_account_link_proof(...)
  -> DB creates/reuses issuer+subject -> Actor+Source binding
  -> caller receives only proof_id + expires_at_ms
```

Request body ต้องเป็น JSON object ว่างเท่านั้น `{}`. `issuer`, `subject`, `actor_id`, `source_id`, `principal_id`, `proof_id` หรือ role hints จาก request ถูกปฏิเสธทั้งหมด. Signed custom claims ที่ชื่อคล้ายกันไม่มีอำนาจ เพราะระบบใช้เพียง issuer/subject จาก verified token profile และ DB เป็นผู้สร้าง Actor/Source เอง

## Service boundary

`echo_account_link_service` เป็น LOGIN แบบ `NOINHERIT`, ไม่ใช่ superuser/owner, ไม่มี direct table หรือ function grant และมี SET-only membership ไป `echo_account_link_runtime` เพียง role เดียว. Pool ทำ `ROLLBACK` ถ้าจำเป็น, `DISCARD ALL`, restore baseline และตรวจ role/membership/table/function ACL ก่อนทุก lease และหลังทุก lease. Reset fail หรือ broken connection ถูกทิ้ง ไม่ส่งต่อ borrower ถัดไป และ pool ไม่ replay การออก proof อัตโนมัติ

Production ใช้ `sslmode=verify-full` โดย default. `sslmode=disable` อนุญาตเฉพาะ disposable loopback test database ที่ระบุชื่อไว้ใน code เท่านั้น

## Proof output

Backend boundary คืนเพียง `AccountLinkReceipt(proof_id, expires_at_ms)` ไม่คืน issuer/subject/Actor/Source. อายุ proof ไม่เกิน 5 นาทีและไม่เกิน token expiry. งานนี้ยังไม่ consume proof เพื่อสร้าง principal/session

## ยังไม่ใช่

- HTTP/OIDC callback หรือ browser onboarding endpoint
- principal provisioning + session bootstrap orchestration
- rate limit / CSRF / CORS / cookie policy
- production HBA/TLS certificate deployment
- service credential rotation/drain
- malicious-backend-code sandbox; raw pool object ยังเป็น trusted backend internal

Critical path ถัดไปหลัง gate นี้ผ่านคือ signed principal provisioning/session bootstrap ที่ consume proof โดยไม่ให้ client เลือก principal/issuer/subject เอง
