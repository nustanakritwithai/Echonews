# P2.1c.2d.4c.5c.5a — Signed Repeat Login (single-active-generation policy)

## Task
ปิด UNKNOWN ที่เล็กที่สุดต่อจาก c5c.4: เมื่อ Session เดิมหมดอายุหรือถูก logout แล้ว Bearer token ใหม่จะสร้าง Session ใหม่ได้อย่างไร โดยยังไม่เปิด active-session refresh/rotation

## Decision
นโยบาย `SINGLE_ACTIVE_CURRENT_GENERATION_V1`:

1. รับเฉพาะ signed Bearer ที่ผ่าน verifier เดิม และ body `{}` เท่านั้น
2. server derive `session_key` จาก verified `issuer+jti`; caller เลือก Principal/Actor/Source/session ไม่ได้
3. Principal ต้อง `enabled`, มี proven activation audit เดิม และใช้ `auth_version` ปัจจุบัน
4. ใน authority generation ปัจจุบันมี Session ที่ `revoked=false` และยังไม่หมดอายุได้สูงสุดหนึ่ง Session
5. exact retry ของ token เดิมคืน Session เดิมได้ถ้ายัง valid และไม่ revoked
6. token/session ที่ถูก revoke ห้ามฟื้นคืน
7. Session ที่หมดอายุแล้วไม่ block login ใหม่
8. Session จาก auth_version เก่าไม่ block generation ปัจจุบัน เพราะ registry/fence ปฏิเสธ generation เก่าอยู่แล้ว
9. ไม่มี automatic retry หลัง unknown commit; caller ทำ explicit retry ด้วย token เดิมเพื่อ resolve durable result
10. **ยังไม่มี active-session renewal/refresh token rotation** ในงานนี้

เหตุผล: นี่เป็น policy ที่เล็กและ deterministic ที่สุดซึ่งทำ repeat login ได้โดยไม่สร้างช่วง overlap ของ Session สองตัวใน generation เดียวกัน. OWASP แนะนำให้กำหนด session renewal/invalidation ชัดเจนและ regenerate identity เมื่อ privilege เปลี่ยน; RFC 9700 กำหนด replay defenses เมื่อมี refresh token. เราจึงยังไม่สร้าง refresh semantics จนกว่าจะมี gate แยก

## Concrete flow
```text
fresh verified Bearer + {}
  -> strict signature/issuer/audience/time/jti verifier
  -> derive session_key(issuer,jti)
  -> echo_repeat_login_service
  -> pool reset + exact ACL check
  -> SET LOCAL ROLE echo_repeat_login_runtime
  -> lock Principal FOR UPDATE
  -> require enabled + proven activation
  -> exact-session replay check
  -> reject if another live current-generation Session exists
  -> insert Session at current auth_version
  -> final DB-clock token-window check
  -> commit
```

## Security boundary
Service LOGIN ไม่มี direct table/function privilege และ SET ได้เฉพาะ repeat-login runtime. Runtime execute ได้เฉพาะ sealed repeat-login function. Guard เป็น NOLOGIN และมีเพียง SELECT/lock/INSERT ที่จำเป็นต่อ Session issuance.

First-session service, logout service และ repeat-login service แยก role กัน. งานนี้ไม่เพิ่ม browser route, cookie, refresh token, writer/reviewer grant หรือ PUBLIC publishing.

## Verification contract
ชุดใหม่สืบทอด 45 first-session+logout tests เดิมโดยไม่แก้ และเพิ่ม repeat-login cases สำหรับ fresh login หลัง logout, exact retry, active-session denial, revoked-token non-resurrection, expired prior session, current-generation isolation, disabled/no-audit denial, request injection, same-JTI cross-subject conflict, role isolation, concurrent fresh tokens, unknown acknowledgement, expiry while waiting, wrong DB password และ exact function allowlist.

SAT ต้องมาจาก PostgreSQL 17 CI จริง; expected count ไม่ใช่ผลสำเร็จ.

## Blocked / Next
ยัง block: active-session renewal/refresh rotation, refresh replay detection, logout-all/provider revocation, production HBA/TLS/proxy/secret rotation, HTTP cookie/CSRF/CORS/rate limits, reviewer/object permissions, privacy/erasure และ PUBLIC publishing.

**Next: c5c.5b — Active-session Renewal / Rotation Contract.** ต้องเลือก proof/token family และ replay response ก่อนอนุญาต overlap/rotation; ห้ามเดาจาก repeat-login contract นี้.
