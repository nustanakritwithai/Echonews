# P2.1c.2d.4b — Backend PRIVATE Owner Read Adapter

## งานเดียวของรอบนี้

เชื่อม signed-token identity boundary + durable PostgreSQL registry เข้ากับ PRIVATE owner-read primitive จาก P2.1c.2d.4a โดยให้ request ที่ไม่เชื่อถือส่งได้เพียง `voice_id` เท่านั้น

เส้นทางที่เพิ่ม:

```text
Bearer RS256 token + { voice_id }
        ↓
existing Boundary signature / issuer / audience / time checks
        ↓
PostgreSQL durable principal + session lookup
        ↓
server-owned AuthorizationStamp
        ↓
echo_private_owner_read_runtime
        ↓
runtime_read_private_owner_voice(...)
        ↓
opaque payload_ref (backend only)
        ↓
trusted payload resolver
        ↓
PrivateOwnerVoice { voice_id, revision, text, recorded_at }
```

## Security contract

- JSON body ยอมรับ field เดียวคือ `voice_id` แบบ canonical nonnil UUID
- `actor_id`, `source_id`, `principal_id`, `session_key`, `auth_version`, `payload_ref`, `visibility`, `revision` และ authorization metadata จาก browser ถูกปฏิเสธ
- Actor/Source/principal/session มาจาก signed-token Boundary + durable registry เท่านั้น
- connection ต้องมี `current_user = echo_private_owner_read_runtime` แบบ exact match
- unknown Voice, Voice ของ principal อื่น, หรือ head ที่ไม่ใช่ current PRIVATE canonical COMMITTED จะคืน `None` แบบเดียวกัน เพื่อลด private-object oracle
- payload locator ไม่อยู่ในผลลัพธ์ของ adapter และไม่ควรถูกส่งให้ browser
- payload resolver เป็น trusted backend dependency; payload ต้องเป็น UTF-8 bytes ที่สอดคล้องกับ draft text contract
- งานนี้ยังใช้ `voice:draft:create` เป็น owner-read entitlement ตาม P2.1c.2d.4a โดยตั้งใจ ยังไม่สร้างสิทธิ์ read-only ใหม่เอง

## Verification target

CI ต้องรัน PostgreSQL 17 จริงและพิสูจน์อย่างน้อย:

1. signed owner อ่าน committed PRIVATE Voice ได้
2. output ไม่มี `payload_ref`
3. request metadata injection ถูกปฏิเสธ
4. principal อื่น/unknown Voice ไม่เรียก payload resolver
5. revoked session ถูก deny
6. writer capability ถูกถอนแล้วถูก deny
7. token role/actor/source hints ไม่ override registry
8. wrong signature ถูก deny
9. DB connection role ผิดถูก deny
10. DB บอก COMMITTED แต่ payload หาย → fail closed
11. resolver contract ผิด → fail closed
12. newer PUBLIC/WITHDRAWN head ไม่ fallback ไป PRIVATE เก่า
13. malformed/duplicate/nil voice_id ถูกปฏิเสธ
14. identity backend outage → fail closed

## สิ่งที่ยัง UNKNOWN / ยังไม่เปิด

- ไม่มี HTTP route, cookie, CSRF, CORS หรือ rate limit ในงานนี้
- ยังไม่มี production object-store adapter หรือหลักฐานว่า provider จะไม่ทำ bytes หายหลัง DB บันทึก COMMITTED
- ยังไม่มี service LOGIN / connection-pool reset contract
- owner-read ยังผูกกับ writer entitlement; read-only entitlement แยกเป็นงาน schema/registry ภายหลัง
- ยังไม่มี revision 2/edit/withdraw owner read, RESTRICTED ACL, RLS/privacy erasure หรือ PUBLIC publication

ดังนั้นงานนี้เป็น backend integration primitive เท่านั้น ไม่ใช่การเปิด browser/API private read production.
