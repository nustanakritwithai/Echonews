# P2.1c.2d.3a — Atomic Immutable PRIVATE Voice Write

## งานเดียวของรอบนี้

ปิด Critical UNKNOWN เรื่อง `authorization ผ่าน → revoke → Voice write commit` ที่ค้างจาก P2.1c.2d.2b ด้วย primitive ฝั่ง PostgreSQL ที่ **ตรวจ authority และ INSERT Voice revision 1 ใน transaction เดียวกัน**

นี่เป็นงานย่อยที่เล็กที่สุดของ P2.1c.2d.3 ไม่ใช่การเปิด Browser/API write. หน้าเว็บ, `/preview/`, PUBLIC publishing และ production database ไม่ถูกแก้

## Concrete contract

`echo_identity.runtime_append_private_voice(...)` รับสองกลุ่มข้อมูล:

1. server-owned AuthorizationStamp tuple เดิม: issuer, subject, session key, principal, actor, source, auth_version, capability และ token times
2. backend execution inputs: `voice_id` และ opaque `payload_ref`

ฟังก์ชัน **ไม่รับ** visibility, revision, previous_revision, author/source แยกจาก stamp, posted_at หรือ recorded_at. ค่าที่เขียนถูกตรึงเป็น:

- revision = 1
- previous_revision = NULL
- author_id = actor_id จาก stamp ที่ fence ตรวจซ้ำ
- source_id = source_id จาก stamp ที่ fence ตรวจซ้ำ
- visibility = PRIVATE เท่านั้น
- posted_at = NULL (ยังไม่ถือว่า publish)
- recorded_at = database clock หลังผ่าน fence

payload bytes ไม่เข้า history table; เก็บเพียง opaque payload_ref ตาม schema เดิม. Ownership/lifecycle ของ payload store ยังเป็น gate ถัดไป

## Transaction fence

ภายใน write statement เดียวกัน ฟังก์ชันเรียก `assert_private_draft_fence(...)` ก่อน INSERT. Fence ใช้ `FOR SHARE` กับ principal แล้ว session ตามลำดับเดิมและ lock ค้างถึง transaction end

ผล ordering ที่ต้องได้:

- revoke/disable/role change commit ก่อน writer ได้ lock → writer อ่าน state ใหม่และ DENY
- writer ได้ fence locks ก่อน → authority mutation ต้องรอ writer COMMIT/ROLLBACK; Voice write จึงอยู่ก่อน revoke ใน serialization order
- caller ROLLBACK → ทั้ง Voice row และ insert audit หายพร้อมกัน

งานนี้ไม่อ้าง SERIALIZABLE isolation; fence เดิมยังจำกัด READ COMMITTED และใช้ row-lock ordering ตาม contract P2.1c.2d.1

## Least privilege

`echo_private_draft_runtime` ได้ EXECUTE ฟังก์ชันใหม่อย่างเดียวและยังไม่มี direct table rights บน `echo_core.voice_revisions`

`echo_private_draft_guard` ได้ USAGE บน echo_core และ **column-level INSERT เฉพาะ Voice columns ที่ writer ต้องใช้**. ไม่มี SELECT/UPDATE/DELETE/TRUNCATE บน Voice history. Guard ยังคง NOLOGIN และ runtime ไม่ได้เป็น member ของ guard

ฟังก์ชันเป็น SECURITY DEFINER, owner = guard, fixed `search_path=pg_catalog, pg_temp`, ไม่มี dynamic SQL และไม่รับ visibility/role/object name จาก caller

P2.1c.1 immutable ALWAYS triggers ถูกตรวจว่า install อยู่ก่อน migration นี้จะผ่าน และทุก INSERT ยังผ่าน existing insert audit

## Verification plan

`test_private_voice_write.py` ใช้ PostgreSQL 17 จริงบนฐาน disposable loopback และทดสอบ:

- privilege/function ownership surface
- valid runtime write ได้ revision 1 PRIVATE + audit เท่านั้น
- runtime direct PRIVATE/PUBLIC INSERT และ SELECT ถูกปฏิเสธ
- ไม่มี visibility/revision/client-clock arguments
- forged actor/source/principal/auth_version ถูกปฏิเสธ
- committed revoke/disable/writer removal ถูกปฏิเสธ
- duplicate voice id ไม่ overwrite ของเดิม
- immutable row UPDATE/DELETE ไม่ได้
- transaction rollback ลบทั้ง row และ audit
- invalid voice/payload reference ถูกปฏิเสธ
- revoke-lock-first concurrency: writer รอแล้ว DENY หลัง revoke commit
- writer-lock-first concurrency: revoke รอ writer commit จากนั้น revoke จึงสำเร็จ

ชุดทดสอบใช้ synthetic stamp values จงใจ ไม่ได้อ้างว่า Browser token ถูกต่อถึง writer แล้ว. CI ยังรัน P2.1c.2d.2a runtime-role regression แยกฐานก่อน suite ใหม่ด้วย

## SAT ที่งานนี้จะปิดเมื่อ CI ผ่าน

- real immutable PRIVATE revision-1 DB append primitive
- authorization fence กับ write อยู่ใน transaction เดียวกัน
- revoke-vs-write ordering ตาม row-lock contract
- runtime ไม่มี bypass ไป PUBLIC/direct Voice DML
- rollback atomicity ระหว่าง Voice row กับ insert audit

## UNKNOWN / BLOCKED หลังงานนี้

ยังห้ามเปิด write API เพราะยังขาดอย่างน้อย:

- backend execution adapter ที่รับ `BoundIntent.authorization_stamp` + server-generated voice_id + trusted payload_ref แล้วเรียก function นี้ โดยไม่รับ stamp จาก request
- payload store ownership/rollback/orphan cleanup และ content-size/media policy
- idempotency / retry receipt เพื่อกัน network retry สร้าง Voice ซ้ำ
- service LOGIN + connection-pool reset/SET SESSION AUTHORIZATION production policy
- owner/private/restricted read authorization และ RLS/privacy erasure
- revision 2 / withdraw workflow
- PUBLIC publish command/permission แยกต่างหาก
- reviewer object authorization

ดังนั้น `BoundIntent.ready_for_execution` ยังต้องเป็น False และ Browser ยังไม่มีสิทธิ์เรียก DB

## Next

**P2.1c.2d.3b — Backend PRIVATE Voice Execution Adapter**: รับเฉพาะ BoundIntent ที่มี server-owned `voice:draft:create` stamp, สร้าง/รับ trusted payload_ref จาก backend service, เรียก runtime writer บน connection/transaction ที่ถูกจำกัด และพิสูจน์ว่า raw request ไม่สามารถส่ง authorization tuple, author/source/visibility/revision/time เข้า execution call ได้

หยุดก่อน HTTP route และ PUBLIC publishing
