# P2.1c.2d.2b — Server-Owned Authorization Stamp Propagation

## Task เดียว
เชื่อมผลจาก signed-token + durable PostgreSQL registry ให้สร้าง authorization stamp **ภายใน Backend** และพก tuple ที่ DB fence ต้องใช้ โดย request JSON ไม่สามารถกำหนดหรือแก้ stamp ได้

งานนี้ไม่สร้าง HTTP route, service LOGIN, real Voice write, public publish หรือ reviewer object authorization และไม่เปลี่ยน `ready_for_execution=False`.

## Concrete output
`ActorBinding` จาก durable registry ส่งเพิ่ม `principal_id` และ derived `session_key` ที่ได้หลัง token ผ่าน signature/issuer/audience/type validation แล้วเท่านั้น จากนั้น `Boundary.bind()` สร้าง `AuthorizationStamp` แบบ frozen หลังตรวจ capability สำเร็จ

Stamp มีเฉพาะข้อมูลที่ DB fence ต้อง recheck:
- issuer + subject
- issuer-bound derived session_key
- principal_id / actor_id / source_id
- auth_version
- capability ที่คำสั่งนี้ต้องใช้
- signed token iat / nbf / exp แปลงเป็น integer milliseconds ฝั่ง server
- key-set/policy version เพื่อ audit/debug ภายใน

`BoundIntent.authorization_stamp` มี `repr=False`; stamp ซ่อน issuer/subject/session_key จาก repr. มันไม่ใช่ bearer token, ไม่ใช่ reusable permission ticket และไม่เปลี่ยน `ready_for_execution` เป็น true

`private_draft_fence_args()` ออก tuple ตรงกับ `echo_identity.runtime_private_draft_fence(...)` เฉพาะเมื่อ capability เป็น `voice:draft:create`; review stamp ใช้กับ private-draft fence ไม่ได้

Legacy fixture adapter ที่ไม่มี durable principal/source/session tuple ยังคง preflight ได้ แต่ไม่ได้ stamp จึงใช้ DB fence path นี้ไม่ได้

## Security boundary
Browser ยังคงส่งได้เฉพาะ request_id/command/payload ตาม allowlist เดิม การส่ง `authorization_stamp`, `principal_id`, `session_key`, actor/source หรือ authorization fields เพิ่มทำให้ INVALID_COMMAND. Signed token ที่มี actor/source/role hints ไม่ override registry

Frozen dataclass ป้องกัน accidental mutation เท่านั้น ไม่ใช่ protection จาก malicious code ภายใน backend. Compromised process/DB owner/superuser ยัง UNKNOWN และ stamp ที่เคยสร้างแล้วต้องถูก DB recheck อีกครั้งใน transaction เดียวกับ future write

เวลาถูกคูณ seconds→milliseconds เฉพาะเมื่ออยู่ใน PostgreSQL/JS safe integer range; ไม่มี float/coercion และ DB fence ยังคงตรวจเวลาปัจจุบันอีกครั้ง

## Verification gate
ชุดใหม่ใช้ ephemeral RSA จริง + PostgreSQL 17 จริง + migration เดิมถึง P2.1c.2d.2a แล้วตรวจ signed token → registry → stamp → least-privilege runtime fence โดยยังไม่มี Voice DML

ต้องพิสูจน์อย่างน้อย:
1. Actor/Source/Principal/session key/version มาจาก DB/derived server path
2. client ใส่ top-level/nested stamp หรือ principal/session fields ไม่ได้
3. signed token role/actor/source hints ไม่เปลี่ยน stamp
4. stamp frozen และ repr ไม่รั่ว subject/session key
5. tuple จาก stamp เรียก runtime fence ได้
6. forged actor/source/principal/version ถูก fence ปฏิเสธ
7. stamp เก่าหลัง committed revoke/disable/version change ถูก fence ปฏิเสธ
8. review capability ไม่สามารถใช้ private-draft fence tuple

Existing identity, signed-registry, DB fence/runtime-role workflows ถูก trigger จากไฟล์เดิมที่เปลี่ยนด้วย จึงต้องผ่าน regressions ก่อน merge

## SAT / VIOL / UNKNOWN
**SAT:** signed+registry path เป็นเจ้าของ stamp และ test runtime พิสูจน์ client injection/revocation/fence handoff ตามขอบเขต

**VIOL:** ถ้า request สามารถตั้ง stamp หรือ tuple authoritative, token claim override DB, stamp stale ผ่าน committed revoke หรือ review stamp ถูกใช้กับ draft fence

**UNKNOWN แม้ SAT:** real HTTP adapter, service LOGIN provisioning/pool reset, compromised backend, in-flight revoke-vs-write transaction, immutable PRIVATE Voice DML, idempotency, reviewer object permission, owner/private/restricted reads, RLS/privacy/erasure

## Completed / Blocked / Next
Completed เมื่อ final CI ทั้ง task + regressions ผ่านและ merge

Blocked: public/browser write ยังปิด

Next: **P2.1c.2d.3 — Real Immutable PRIVATE Voice Write** ใช้ stamp นี้กับ runtime fence ใน transaction เดียว แล้ว append Voice revision PRIVATE แบบ immutable พร้อม transaction/revoke concurrency tests; ห้ามเปิด PUBLIC publish ในงานนั้น
