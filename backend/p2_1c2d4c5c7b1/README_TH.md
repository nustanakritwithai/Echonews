# P2.1c.2d.4c.5c.7b.1 — Validated JWKS Snapshot → Identity Boundary Config Bridge

สถานะ: **Narrow integration gate** — เชื่อม JWKS contract ที่ validate แล้วเข้ากับ `identity_boundary.Config` เท่านั้น ยังไม่มี network fetch, IdP จริง, HTTP/browser auth หรือ production credentials

## เป้าหมาย

ปิด Critical UNKNOWN ส่วนแรกหลัง `c5c.7a`: เปลี่ยน RSA JWK ที่ผ่าน `PINNED_ISSUER_JWKS_ROTATION_V1` แล้วให้เป็น `RSAPublicKey` ที่ boundary ใช้ verify Bearer จริง โดยห้าม raw/unvalidated JWK ข้ามเข้ามาใน Config

```text
operator-pinned IssuerTrust
        +
raw JWKS จาก transport ที่ caller รับผิดชอบ
        ↓
validate_jwks_snapshot (c5c.7a)
        ↓
hard-TTL gate
        ↓
fingerprint / modulus / exponent cross-check
        ↓
cryptography.RSAPublicKey
        ↓
identity_boundary.Config
        ↓
Boundary verifies actual RS256 Bearer
```

## Decision ที่ล็อกในงานนี้

1. **Boundary รับเฉพาะ key จาก validated snapshot**
   - bridge เรียก `validate_jwks_snapshot()` ก่อนทุกครั้ง
   - key set ที่เข้า `Config` ต้องตรงกับ eligible key set ใน snapshot แบบ exact set
   - raw JWK ที่ไม่ได้ eligible จะไม่ถูกแปลงเป็น verification key

2. **JWK → RSA conversion ต้องตรวจซ้ำกับ snapshot**
   - decode `n` / `e` แบบ strict unpadded base64url
   - recompute fingerprint ด้วย canonical form เดียวกับ c5c.7a
   - modulus bit length, exponent และ fingerprint ต้องตรงกับ `TrustedJwk`
   - `cryptography` ต้องสร้าง `RSAPublicKey` ได้จริงและ key size ต้องตรง

3. **`key_set_version` ต้องไหลถึง identity boundary โดยไม่เปลี่ยนค่า**
   - `Config.key_set_version = snapshot.key_set_version`
   - downstream `BoundIntent` จึงอ้างชุด key ที่ใช้ verify ได้แบบ deterministic

4. **Hard-expired snapshot ใช้สร้าง Config ไม่ได้**
   - ถ้า `now_ms >= hard_expires_at_ms` bridge fail closed
   - bridge ปฏิเสธ timestamp ที่ดูเหมือน fetch มาจากอนาคต

5. **Rotation semantics ของ c5c.7a ต้องคงเดิมหลัง bridge**
   - old + new overlap: token ที่เซ็นด้วยทั้งสอง key ใช้ได้
   - หลัง successful snapshot ตัด old key: token ที่เซ็นด้วย old key ถูก reject
   - same `kid` + key material เปลี่ยนใน trust epoch เดิมยังถูก reject

6. **Token ไม่มีสิทธิ์เปลี่ยน trust root**
   - `identity_boundary` ยังคง exact JOSE header profile `{alg, typ, kid}`
   - header ที่เพิ่ม `jku`, `x5u` หรือ embedded `jwk` ไม่ผ่าน แม้ signature จะใช้ trusted key จริง

## Verification scope

Gate นี้ใช้ RSA key จริง, JWS จริง และ `Boundary.bind()` จริง แต่ `jwks_boundary_bridge.py` **ไม่มี network I/O** จุดประสงค์คือพิสูจน์ conversion + integration ก่อนทำ HTTPS fetch/cache transport

Dedicated tests ตรวจ 10 cases:

- validated JWKS → Config
- actual signed Bearer ผ่าน Boundary ด้วย bridged key
- old+new overlap rotation
- removed old key หยุด authorize
- same-kid substitution ยัง fail closed
- token-supplied `jku` override ไม่ได้
- private RSA material ถูก reject ก่อน bridge
- hard-expired snapshot ถูก reject
- future fetch timestamp ถูก reject
- raw JWKS ไม่ถูก mutate

ร่วมกับ c5c.7a contract tests 20 cases จึงเป็น regression gate ของ trust semantics เดิมด้วย

## SAT / VIOL / UNKNOWN

### SAT เมื่อ

- source compile ผ่าน
- c5c.7a contract tests ผ่าน 20/20
- bridge integration tests ผ่าน 10/10
- actual RS256 token verify ผ่านเฉพาะ key ที่อยู่ใน validated Config
- removed/hard-expired/untrusted key ไม่ authorize

### VIOL ถ้า

- raw/unvalidated JWK ถูกส่งเข้า `identity_boundary.Config`
- fingerprint / `n` / `e` mismatch ถูกยอมรับ
- hard-expired snapshot ยังใช้ verify token ได้
- key ที่ถูกถอดจาก successful snapshot ยัง authorize ต่อ
- token สามารถใช้ `jku`/`x5u`/`jwk` เพื่อเปลี่ยน key source

### UNKNOWN ที่จงใจคงไว้

งานนี้ยัง **ไม่** implement production HTTPS JWKS transport/cache ดังนั้นยัง UNKNOWN เรื่อง:

- exact pinned-URL fetch และ redirect policy
- DNS / proxy / egress behavior
- response size/content-type/status policy
- ETag / If-None-Match / 304
- retry/backoff และ single-flight สำหรับ unknown `kid`
- startup warmup / cache persistence / multi-process coordination
- outage telemetry และ fail-closed behavior เมื่อ refresh ไม่สำเร็จ

เพราะฉะนั้น production Browser/API authentication ยังปิดอยู่ และ P2 ยังไม่จบ

## Next

`P2.1c.2d.4c.5c.7b.2 — Pinned HTTPS JWKS Fetch/Cache Transport`

ต้อง fetch ได้เฉพาะ `IssuerTrust.jwks_uri` ที่ operator pin, ไม่ follow unsafe redirect, จำกัด response อย่างชัดเจน, รองรับ bounded cache/ETag/unknown-kid refresh และ feed snapshot เข้า bridge นี้โดยไม่ให้ request/token เลือก URL เอง
