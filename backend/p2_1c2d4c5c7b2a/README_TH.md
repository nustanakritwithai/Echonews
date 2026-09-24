# P2.1c.2d.4c.5c.7b.2a — Pinned HTTPS JWKS Request/Response Envelope Contract

สถานะ: **Transport-envelope gate** — ล็อก request/response semantics ก่อนทำ socket/DNS/cache implementation จริง

## เป้าหมาย

ปิด Critical UNKNOWN ชุดแรกจาก `c5c.7b.1`: request สำหรับ JWKS ต้องออกไปยัง `IssuerTrust.jwks_uri` ที่ operator pin ไว้เท่านั้น และ response ที่ส่งต่อไปยัง trust validator ต้องเป็น HTTP envelope ที่ชัดเจนและ fail closed

```text
operator-pinned IssuerTrust.jwks_uri
        ↓
build_pinned_jwks_request()
        ↓
GET exact URL
Accept: application/jwk-set+json, application/json
Accept-Encoding: identity
        ↓
HTTP response envelope
        ↓
status/content-type/size/UTF-8/JSON checks
        ↓
ParsedJwksResponse.document
        ↓
validate_jwks_snapshot() / boundary bridge ใน gate ถัดไป
```

## Decision ที่ล็อกในงานนี้

1. **Caller เลือก JWKS URL เองไม่ได้**
   - request builder รับเฉพาะ `IssuerTrust`
   - URL ที่ออกต้องเท่ากับ `trust.jwks_uri` แบบ exact string
   - parser ตรวจซ้ำว่า request ที่ใช้รับ response ยังชี้ exact pinned URL

2. **Redirect ถูก reject ทั้งหมดใน contract นี้**
   - HTTP 3xx ทุกชนิด fail closed
   - `Location` header ไม่ถูกนำไปสร้าง request ใหม่
   - redirect policy จึงไม่สามารถถูกใช้เปลี่ยน trust root

3. **รับเฉพาะ successful full response**
   - status ต้องเป็น `200`
   - `304`/ETag conditional fetch ยังไม่ถูกเปิดในงานนี้
   - status อื่น fail closed

4. **Response body ถูกจำกัดอย่างชัดเจน**
   - body ต้องเป็น bytes และไม่ว่าง
   - สูงสุด `262144` bytes
   - `Content-Length` ถ้ามีต้องเป็นเลข, ไม่เกิน limit และต้องตรงกับ body จริง
   - compressed body (`gzip`, `br`, ฯลฯ) ถูก reject; request ขอ `identity` เท่านั้น เพื่อลด decompression ambiguity/bomb surface

5. **Content-Type ถูกจำกัด**
   - อนุญาต `application/json`
   - อนุญาต `application/jwk-set+json`
   - parameter ถ้ามีอนุญาตเฉพาะ `charset=utf-8`

6. **JSON ต้อง canonical-enough สำหรับ security parsing**
   - UTF-8 strict
   - top-level ต้องเป็น object
   - duplicate member ใน JSON object ถูก reject ทุกระดับ
   - security-relevant HTTP headers ที่ซ้ำกัน (`content-type`, `content-length`, `content-encoding`, `location`) ถูก reject
   - CR/LF header injection ถูก reject

## Verification scope

Dedicated deterministic tests 18 cases ครอบคลุม:

- exact pinned URL
- builder ไม่มี caller URL argument
- `application/json` success
- `application/jwk-set+json; charset=UTF-8` success
- tampered URL rejection
- redirect rejection
- non-200 rejection
- missing/wrong content type
- non-UTF8 content-type parameter
- compressed response rejection
- duplicate security-header rejection
- max body size
- Content-Length mismatch
- invalid UTF-8
- duplicate JSON members
- non-object JSON
- CRLF header injection

ร่วมกับ inherited c5c.7a trust contract 20 tests เพื่อให้ transport envelope ไม่ลด trust semantics เดิม

## SAT / VIOL / UNKNOWN

### SAT เมื่อ

- source compile ผ่าน
- c5c.7a trust contract ผ่าน 20/20
- transport-envelope tests ผ่าน 18/18
- request URL มาจาก operator-pinned trust เท่านั้น
- redirect/compression/oversize/ambiguous JSON fail closed

### VIOL ถ้า

- caller สามารถส่ง URL อื่นให้ request builder
- 3xx ถูก follow หรือส่งต่อเป็น success
- response ใหญ่เกิน limit ยังถูก parse
- compressed/ambiguous content ถูกยอมรับ
- duplicate JSON member หรือ duplicate security header ถูกยอมรับ

### UNKNOWN ที่จงใจคงไว้

งานนี้ **ยังไม่เปิด socket/network I/O** จึงยัง UNKNOWN เรื่อง:

- TLS certificate/hostname verification implementation
- DNS rebinding / resolver behavior / private-IP egress restrictions
- proxy/environment-variable bypass policy
- connect/read timeout และ cancellation
- ETag / `If-None-Match` / 304
- retry/backoff และ unknown-`kid` single-flight refresh
- startup warmup / cache persistence / multi-process coordination
- outage telemetry

เพราะฉะนั้น production Browser/API authentication ยังปิดอยู่ และ P2 ยังไม่จบ

## Next

`P2.1c.2d.4c.5c.7b.2b — Pinned HTTPS Fetch Adapter + TLS/Egress Guard`

ต้องทำ network fetch จริงโดยใช้ exact request contract นี้, verify TLS/hostname, ไม่ follow redirect, ไม่รับ proxy override โดยไม่ตั้งใจ, จำกัด timeout/read size และพิสูจน์ด้วย deterministic local HTTPS integration tests ก่อนเพิ่ม ETag/cache semantics
