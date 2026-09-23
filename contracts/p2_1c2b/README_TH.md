# P2.1c.2b — Trusted Writer / Reviewer Command Boundary v0.1

## งานเดียวของรอบนี้
ล็อก **command contract ที่ขอบ Backend** เพื่อไม่ให้ Browser/Client เป็นคนระบุ `actor_id`, `author_id`, `source_id`, `reviewer_id`, `assessor_id`, `assessor_kind`, `method_version`, `recorded_at` หรือ retarget Claim/Evidence เอง

นี่เป็น contract library + tests เท่านั้น ยังไม่ใช่ HTTP API, token verifier, DB adapter หรือ production authentication และไม่เปิด public write path

## Voice create
Client ส่งได้เพียง:

```json
{"content":"...", "visibility":"PRIVATE | PUBLIC"}
```

`visibility` ไม่ส่ง = `PRIVATE`. ยังไม่รองรับ `RESTRICTED` เพราะ audience model ยังไม่มี และ client สร้าง `WITHDRAWN` ไม่ได้

Backend ที่เชื่อถือแล้วต้อง bind:
- `authorId` และ `sourceId` จาก authenticated context
- `voiceId` จาก server UUID generator
- `payloadRef` จาก server payload store
- `postedAt` / `recordedAt` จาก server clock

Client-supplied field อื่นถูก reject แบบ fail-closed แทนการ ignore เงียบ ๆ

## Human review
Client ส่งได้เพียง:

```json
{
  "assessmentId":"...",
  "expectedRevision":3,
  "decision":"ACCEPTED | REJECTED",
  "rationale":"..."
}
```

Backend ต้องโหลด assessment ปัจจุบันเอง แล้ว command builder:
- ตรวจ optimistic expected revision
- อนุญาตเฉพาะ PENDING ที่ยังไม่ withdrawn
- preserve `eventId/claimId/claimRevision/scopeKey/evidenceId/evidenceRevision/relation/valid-time` จาก record เดิม
- bind `assessorId` จาก authenticated context และบังคับ `assessorKind=HUMAN`
- bind `methodVersion`, `assessedAt`, `recordedAt` จาก server context
- append revision ถัดไป ไม่ retarget assessment เดิม

## Trust boundary
`auth.trusted=true` ใน library เป็น **internal marker ไม่ใช่ credential และห้ามมาจาก request JSON**. HTTP adapter ในอนาคตต้องสร้าง object นี้จากผลตรวจ token/session ที่สำเร็จแล้ว โดย request parser ต้องส่งเฉพาะ body ไป command binder

Database credentials ยังอยู่หลัง Backend เท่านั้น Browser ห้ามได้รับ DB role/password. PostgreSQL `current_user`/`session_user` บอกตัวตน database principal ไม่ใช่มนุษย์ที่ login เว็บ จึงไม่ใช้สองค่านี้แทน authenticated actor. PostgreSQL เองระบุว่า `current_user` คือ effective identity สำหรับ permission checking และเปลี่ยนได้ด้วย `SET ROLE`/SECURITY DEFINER; `session_user` โดยปกติคือผู้เริ่ม connection

## Verification

```sh
node --test contracts/p2_1c2b/command_boundary.test.mjs
```

CI `.github/workflows/p2-1c2b-command-boundary.yml` ต้องผ่านก่อน merge. จำนวน test ที่แสดงโดย Node คือผลจริง; ห้ามอ้าง PASS จากการอ่าน source

## สิ่งที่ยัง UNKNOWN / BLOCKED
- ตัว token/session verifier จริงและ account→actor/source mapping ที่ durable
- HTTP endpoint, CSRF/origin/rate limit/abuse controls
- DB adapter และ transaction ที่เขียน command เหล่านี้ลง P2.1b/P2.1c
- owner/private/restricted read model, RLS และ payload authorization
- reviewer assignment/revocation, conflict-of-interest, appeal
- snapshot sealing/admission และ current-state recomputation
- privacy erasure/backups/cache/search invalidation
- semantic/media authenticity และ source independence

ดังนั้น task นี้ปิดเฉพาะ **client cannot choose trusted identity/retarget fields at the command boundary** ไม่ได้พิสูจน์ว่า authentication จริงปลอดภัยหรือ reviewer เป็นบุคคลที่ถูกต้อง

## Next
P2.1c.2c — authenticated session/token → durable actor/source mapping contract พร้อม revoke/disable behavior และ tests ก่อนสร้าง HTTP write endpoint
