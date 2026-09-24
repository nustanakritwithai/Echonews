# P2.1c.2d.4c.5c.7b.2b.3a — ETag / 304 Conditional Fetch Contract

งานนี้เป็น **smallest useful task** ต่อจาก HTTP-over-TLS โดยล็อก semantics ของ conditional JWKS refresh ก่อนแก้ socket fetcher จริง

## Decision: `BOUNDED_ETAG_304_REVALIDATION_V1`

1. เก็บ ETag ได้เฉพาะ **strong ETag** ที่มีรูปแบบถูกต้อง; weak ETag ถือว่าไม่มี validator และรอบถัดไปต้อง full fetch
2. ถ้า cache ไม่มี strong ETag, cache ข้าม `trust_epoch`, หรือถึง hard TTL แล้ว ต้อง full `200` fetch และ **ห้ามส่ง If-None-Match**
3. Conditional request สร้างได้เฉพาะจาก ETag ของ cache entry เดียวกัน และ header ต้องเป็น `If-None-Match: <exact cached ETag>`
4. `304 Not Modified` รับได้เฉพาะก่อน hard expiry, จาก request plan เดิม, ไม่มี body, และ response ต้องคืน strong ETag ตัวเดิมแบบ exact
5. `304` ต่ออายุได้เฉพาะ **soft freshness window**: `soft_expires_at = min(now + soft_ttl, hard_expires_at)`
6. `304` **ห้ามเปลี่ยน** `fetched_at_ms`, `hard_expires_at_ms`, `key_set_version`, key fingerprints หรือ key set
7. repeated `304` จึงต่ออายุ hard TTL ไม่ได้; เมื่อถึง hard deadline ต้อง full `200` เพื่อดาวน์โหลดและ validate JWKS body ใหม่
8. full `200` ที่ validate ผ่านจะสร้าง snapshot ใหม่และ reset soft/hard TTL; same-`kid` key substitution defense จาก trust contract เดิมยังทำงาน
9. `200` ที่ไม่มี ETag หรือมี valid weak ETag ใช้งานได้ แต่ cache จะเป็น unconditional-only
10. duplicate/malformed ETag, clock rewind, `304` ข้าม trust epoch, ETag mismatch, `304` body หรือ request-plan mismatch ถูก reject fail-closed

## Why hard TTL is not extended by 304

เป้าหมายของ ETag คือประหยัด bandwidth ไม่ใช่เปลี่ยน security lifetime ของ key material ระบบยอมให้ 304 ยืนยันความสดระยะสั้น แต่ยังบังคับให้ดาวน์โหลด JWKS body เต็มภายใน hard TTL เดิม เพื่อไม่ให้ cached key set ถูกต่ออายุแบบไม่สิ้นสุดด้วย 304

## State transition

```text
Validated 200 + strong ETag
        ↓
cache before hard TTL
        ↓
If-None-Match: exact ETag
        ↓
304 + exact same ETag + empty body
        ↓
soft TTL renewed
hard TTL unchanged
        ↓
hard deadline reached
        ↓
full 200 required
```

ถ้า full 200 ไม่มี strong ETag:

```text
Validated 200
   ↓
cache usable
   ↓
refresh is FULL only
(no conditional validator)
```

## Security boundary ที่ปิดใน task นี้

- validator ไม่ไหลข้าม issuer/JWKS URI/trust epoch
- stale cache ที่ hard-expired แล้วใช้ 304 ต่ออายุไม่ได้
- server เปลี่ยน ETag ใน 304 แล้ว reuse body เก่าไม่ได้
- client ไม่สามารถส่ง arbitrary If-None-Match ผ่าน contract นี้
- repeated 304 ไม่สามารถยืด hard key lifetime
- full refresh ยังรักษา same-kid substitution guard เดิม

## สิ่งที่ยังไม่พิสูจน์ในงานนี้

งานนี้เป็น pure deterministic contract; ยังไม่ได้ wire `If-None-Match` เข้า HTTP request บน TLS socket และยังไม่ได้ parse `304` จาก raw HTTP reader จริง จึงยังไม่ปิด retry/backoff, unknown-`kid` single-flight refresh, startup warmup, persistent/multi-process cache, outage telemetry หรือ external production IdP proof

production Browser/API authentication ยังห้ามเปิด

## Verification

`test_jwks_conditional_fetch_contract.py` มี 19 deterministic cases ครอบคลุม full/conditional planning, strong/weak/missing/duplicate/malformed ETag, trust-epoch change, bounded 304 soft revalidation, hard TTL invariance, token-header decision after revalidation, hard-expired 304, request mismatch, missing/mismatched ETag, 304 body rejection, full-200 hard reset, same-kid substitution และ clock rewind
