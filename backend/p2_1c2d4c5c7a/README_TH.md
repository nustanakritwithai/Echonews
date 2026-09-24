# P2.1c.2d.4c.5c.7a — Production Issuer / JWKS Trust + Key-Rotation Contract

สถานะ: **Contract-only gate** — ยังไม่เปิด network fetch, IdP จริง, HTTP/browser auth หรือ production credentials

## เป้าหมาย

ปิด Critical UNKNOWN หลัง `c5c.6` ว่า Echo จะเชื่อ issuer/JWKS และรับ key rotation อย่างไรโดยไม่เปิดช่องให้ token เป็นคนเลือก trust root เอง

นโยบายที่ล็อกในงานนี้คือ:

`PINNED_ISSUER_JWKS_ROTATION_V1`

```text
operator-pinned IssuerTrust
  issuer + jwks_uri + audience + trust_epoch
                  ↓
Bearer JOSE header ต้องตรง profile เท่านั้น
{ alg=RS256, typ=at+jwt, kid }
                  ↓
ไม่มี jku / x5u / jwk จาก token
                  ↓
validated JWKS snapshot
                  ↓
known kid + cache fresh     -> USE_CACHED
known kid + soft expired    -> USE_CACHED_REFRESH_RECOMMENDED
unknown kid                 -> REFRESH_REQUIRED
cache hard expired          -> REFRESH_REQUIRED
trust epoch mismatch        -> REJECT
```

## Decision ที่ล็อกแล้ว

1. **Trust root มาจาก operator config เท่านั้น**
   - `issuer` และ `jwks_uri` ต้องเป็น HTTPS ที่ pin ไว้ก่อนรับ request
   - ห้าม derive URL จาก `iss`, `kid`, `jku`, `x5u` หรือ claim/header ใดใน token
   - `issuer` ไม่มี query/fragment/userinfo
   - `jwks_uri` อาจมี query ได้ แต่ต้องตรงกับค่าที่ operator pin ไว้ทั้งหมด

2. **JOSE profile คงที่กับ boundary ปัจจุบัน**
   - `alg = RS256`
   - `typ = at+jwt`
   - `kid` ต้องมีและผ่าน profile
   - header ต้องมีแค่ `alg`, `typ`, `kid` เท่านั้น จึง reject token-supplied `jku`, `x5u`, `jwk` และ algorithm confusion ก่อน key selection

3. **JWKS validation เป็น atomic snapshot**
   - สูงสุด 32 keys ต่อ snapshot
   - duplicate/invalid `kid` ทำให้ snapshot ทั้งชุด reject
   - private RSA members (`d,p,q,dp,dq,qi,oth`) ทำให้ snapshot reject
   - RSA verification key ต้อง >= 2048 bits และ exponent odd >= 65537
   - key ที่ไม่ใช่ RSA/RS256/signature/verify profile อาจอยู่ใน JWKS ได้ แต่จะไม่ eligible สำหรับ Echo
   - snapshot ต้องมี eligible key อย่างน้อยหนึ่งตัว

4. **Rotation ใช้ new `kid` เป็นทางปกติ**
   - provider เพิ่ม key ใหม่ -> snapshot ใหม่รับได้
   - old + new อยู่พร้อมกันได้เพื่อ rollover
   - provider ถอด old key ออกจาก successful refresh -> old key หยุดอยู่ใน trusted snapshot ทันที
   - **same `kid` + key material เปลี่ยนภายใน `trust_epoch` เดียวกัน = reject (`JWKS_KID_KEY_SUBSTITUTION`)**
   - ถ้าจำเป็นต้องเปลี่ยน key material โดย reuse `kid`, ต้องเป็น explicit operator trust change / `trust_epoch` ใหม่ใน task ถัดไป ไม่รับแบบเงียบ ๆ

5. **Cache มี bounded stale window**
   - default soft TTL = 5 นาที
   - default hard TTL = 15 นาที
   - known key หลัง soft TTL ยังใช้ได้ชั่วคราว แต่ต้องขอ refresh
   - หลัง hard TTL ไม่มี cached key ใด authorize ต่อได้จนกว่าจะได้ successful refresh
   - unknown `kid` ต้อง refresh แม้ cache เดิมยัง fresh ตามแนวทาง OIDC key rollover

6. **`key_set_version` derive จาก trust epoch + eligible key fingerprints**
   - ไม่ขึ้นกับลำดับ key หรือเวลา fetch
   - ทำให้ boundary downstream อ้าง snapshot ที่ใช้ verify ได้ deterministically

## Verification scope

`jwks_trust_contract.py` เป็น deterministic policy model ไม่ทำ network fetch และไม่ verify JWS จริง จุดประสงค์คือ freeze semantics ก่อนเขียน fetch/cache adapter production

`test_jwks_trust_contract.py` ตรวจ 20 cases รวม:

- pinned HTTPS trust config
- stable key-set version
- mixed-key JWKS
- duplicate kid
- private key leakage
- weak RSA modulus/exponent
- wrong alg/use/key_ops
- same-kid key substitution
- normal add/remove rotation
- rejection of `jku`/`x5u`/embedded `jwk`
- no-cache/unknown-kid refresh
- soft/hard TTL
- trust-epoch mismatch
- key-order independence

## Standards basis

- RFC 8725 (JWT BCP): verifier ต้อง pin allowed algorithms และไม่ควร blind-follow `jku`/`x5u` จาก token เพราะ SSRF/trust-confusion risk
- RFC 7517 (JWK): `kid` ใช้สำหรับ key matching/rollover; `use`, `key_ops`, `alg` บอก intended use
- OpenID Connect Core 1.0 §10.1: signer publish keys ที่ `jwks_uri`, new `kid` signal rotation, verifier re-fetch เมื่อพบ unfamiliar `kid`, และควรมี overlap ของ decommissioned signing keysช่วงหนึ่ง
- OpenID Connect Discovery 1.0: issuer เป็น HTTPS identifier และ metadata ให้ `jwks_uri`

## SAT / VIOL / UNKNOWN

### SAT เมื่อ

- contract tests ผ่านครบ 20/20
- source compile ผ่าน
- header ที่มี remote key locator ถูก reject
- rotation/TTL/trust-epoch semantics deterministic

### VIOL ถ้า

- token สามารถกำหนด JWKS URL/key material เอง
- duplicate kid หรือ private key material ถูกยอมรับ
- same kid เปลี่ยน key เงียบ ๆ ใน trust epoch เดิม
- hard-expired cache ยัง authorize ต่อ

### UNKNOWN ที่จงใจคงไว้

งานนี้ **ยังไม่** ตอบ implementation ของ HTTPS fetch, DNS/redirect policy, HTTP cache headers/ETag, retry/backoff/single-flight, startup warmup, persistent cache, multi-process coordination, actual RSA object conversion, outage telemetry หรือ production issuer provisioning

ดังนั้น production Browser/API auth ยังปิดอยู่

## Next

`P2.1c.2d.4c.5c.7b — Pinned JWKS Fetch/Cache Adapter + Boundary Integration`

ต้อง implement network adapter ที่ fetch ได้เฉพาะ preconfigured `jwks_uri`, disable unsafe redirects, validate snapshot ด้วย contract นี้, convert eligible keys เป็น RSA public keys, feed `identity_boundary.Config`, และพิสูจน์ unknown-kid/rotation/outage behavior ด้วย integration tests
