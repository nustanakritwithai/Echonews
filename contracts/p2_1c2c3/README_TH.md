# P2.1c.2c.3 — Signed Preflight → Durable Registry Integration

## งานเดียวของรอบนี้

เชื่อม **signed-token verifier ที่มีอยู่จริง** ใน `backend/p2_1c2b1/identity_boundary.py`
กับ **durable PostgreSQL identity/session registry** ใน `database/p2_1c2c/001_identity_registry.sql`
โดยไม่สร้าง JWT verifier ตัวที่สอง และไม่เปิด HTTP/public browser write endpoint

เส้นทางที่ทดสอบ:

```text
RS256 signed access token
→ existing Python signature / iss / aud / exp / nbf / iat verifier
→ normalized verified credential
→ issuer-bound session key derived from verified jti
→ current PostgreSQL principal + session lookup
→ Actor + Source + current roles from DB only
→ guarded existing command binder
```

## จุดเชื่อมที่เพิ่ม

### 1. Verified credential seam

`verify_credential(...)` ใน verifier เดิมคืน `VerifiedCredential` หลังตรวจ cryptographic profile แล้วเท่านั้น

ค่าที่ส่งต่อไป durable resolver มีเฉพาะ:

- tokenUse
- issuer
- subject
- audiences
- sessionKey
- issuedAtMs
- notBeforeMs
- expiresAtMs

ไม่ส่งต่อ actor/source/role/scope/email จาก token เป็น authority

`sessionKey` เป็น SHA-256 ของ versioned namespace + verified issuer + verified jti
จึงไม่รับ session key จาก client และไม่ใช้ jti จาก payload ก่อนลายเซ็นผ่าน

### 2. Cross-language bridge

`backend/p2_1c2c3/verified_credential_bridge.py` เป็น internal one-shot adapter สำหรับ
เชื่อม Python verifier เดิมเข้ากับ JavaScript resolver ใน integration/runtime gate

นี่ **ไม่ใช่** HTTP endpoint, login provider, production worker model หรือ production DB adapter

### 3. Guarded command composition

`contracts/p2_1c2c3/integrated_command_boundary.mjs`

- CREATE draft path รับเพียง `{content}`
- บังคับ `visibility='PRIVATE'`
- ไม่มี client field ที่ขอ PUBLIC ใน path นี้
- Review ต้องมี `authorizeReviewObject` callback และต้องคืน `true` ก่อนถึง binder เดิม
- reviewer role/capability อย่างเดียวจึงไม่กลายเป็น object authorization

ตัว callback ยังไม่ใช่ implementation ของ reviewer assignment/self-review policy;
งานนี้พิสูจน์เฉพาะว่า integration path **ห้าม bypass** ด่านนั้น

## Runtime gate ขั้นต่ำ

`contracts/p2_1c2c3/signed_registry_postgres.test.mjs` ใช้:

- RSA 2048-bit ephemeral key
- RS256 JWT จริง
- existing Python verifier
- PostgreSQL 17 จริงใน disposable CI service
- existing durable lookup function
- existing command binders

กรณีขั้นต่ำ:

1. valid signed token + valid DB session → PASS
2. revoked session → DENY
3. disabled account → DENY
4. stale auth_version → DENY
5. role removed → DENY
6. role escalation claims in token → ไม่มีผล
7. wrong issuer → DENY ก่อน DB lookup
8. wrong audience → DENY ก่อน DB lookup
9. expired token → DENY ก่อน DB lookup
10. DB unavailable → fail closed
11. old token/session after re-enable → DENY
12. review capability ไม่ bypass object authorization
13. draft permission ไม่กลายเป็น PUBLIC writer permission
14. Actor/Source มาจาก durable DB registry เท่านั้น

CI ใหม่ยัง rerun regression ของ signed verifier, command binder, session resolver และ real PostgreSQL mapping เดิม

## Success Contract

SAT ได้เมื่อ PR commit เดียวกันมีหลักฐานว่า:

- old verifier regression ผ่าน
- old command/session/database regressions ผ่าน
- signed-registry integration 14 cases ผ่าน
- disposable DB cleanup marker ผ่าน
- main ไม่ขยับจน branch อยู่หลัง concurrent work ตอน merge

ห้ามนับ expected tests เป็น PASS ถ้ายังไม่ได้รัน Actions จริง

## ขอบเขตที่ยัง BLOCKED / UNKNOWN หลังงานนี้

- production identity provider / JWKS distribution/rotation
- production session issue / refresh / logout
- account linking / recovery / MFA
- reviewer assignment / self-review / conflict policy implementation
- object-level read/write authorization rules
- least-privilege production DB runtime role
- commit-time authorization recheck / revoke-vs-write race
- owner/private/restricted reads + RLS
- privacy erasure
- cache/search invalidation
- snapshot sealing
- HTTP transport, cookies, CSRF, origin, rate limit
- public/multi-user publishing

ดังนั้น integration PASS **ไม่เท่ากับ production authentication หรือ production social network พร้อมใช้**

## Next

หลัง gate นี้ผ่าน งาน critical path ถัดไปคือ **Object Authorization + Commit-Time Authorization Fence**
โดยต้องเริ่มจาก smallest useful subtask และห้ามเปิด browser write endpoint ก่อน race/revocation gate ผ่าน
