# P2.1c.2b.1 — Token → Trusted Actor → Command Preflight

## งานเดียวของรอบนี้

ต่อจาก P2.1c.2a ที่ `main` commit `23b9a545e7252248a5204c762680ba51670bd1ba`

ทำด่านตรวจตัวตนและชนิดคำสั่งก่อนขั้นเขียนฐานข้อมูล: **Client ไม่มีช่องกำหนด actor_id, author_id, reviewer_id หรือ capabilities เอง**

งาน P2.1c.2b (trusted writer/reviewer command boundary) ยังไม่ครบทั้งก้อน รอบนี้ปิดเฉพาะส่วน 2b.1: signed-token verification + backend registry binding + strict intent schema. ไม่ได้สร้าง endpoint หรือให้สิทธิ์เขียน PostgreSQL และไม่เปลี่ยนหน้าเว็บหลักหรือ `/preview/`

## Success Contract

1. ใช้ token ที่ตรวจลายเซ็นจริงด้วยกุญแจที่ Backend กำหนดไว้ ไม่ใช้ข้อมูลใน token เลือก algorithm/URL เพื่อดาวน์โหลด key
2. ใช้ `(issuer, subject)` ที่ตรวจแล้วค้น Actor จากทะเบียนที่ Backend เชื่อถือ ไม่รับ Actor/role จาก JSON body หรือ claims ของ token โดยตรง
3. รับ command payload ตาม allowlist เท่านั้น ปฏิเสธ fields แปลกปลอมและ JSON member ที่ซ้ำ
4. ตรวจ capability จากทะเบียนทุก request; ทะเบียนหรือ revocation check ขัดข้อง = ปฏิเสธ ไม่ fallback เป็น anonymous writer
5. คืนได้เพียง `BoundIntent` ที่ `ready_for_execution == False` เสมอ จนกว่าจะผ่าน object authorization และ DB command transaction ในงานถัดไป
6. การผ่าน preflight ไม่อัปเดต Echo Voice, Review, Current State หรือ public view แม้แต่แถวเดียว

## เส้นทางข้อมูล

```text
Untrusted HTTP adapter (ยังไม่สร้าง)
  ├─ Authorization: Bearer <signed access token>
  └─ raw JSON bytes (ไม่มี actor/reviewer identity fields)
                  ↓
Boundary.bind(authorization, raw_body)
                  ↓
ตรวจ compact token / strict JSON / RS256 signature / typ / iss / aud / exp / nbf / iat / jti
                  ↓
Trusted revocation adapter + registry lookup(issuer, subject)
                  ↓
Actor UUID + actor kind + capabilities + binding revision
                  ↓
Strict command payload validation + capability preflight
                  ↓
BoundIntent (identity-and-capability precheck ONLY)
                  ↓
BLOCKED: object permissions / reviewer conflicts / atomic DB command ยังไม่ทำ
```

**ไม่มี JWT private key, token, production issuer หรือบัญชีผู้ใช้จริงอยู่ใน repository** Keys สำหรับการทดสอบสร้างในหน่วยความจำแล้วทิ้ง ไม่เขียนออกไฟล์

## Token profile ที่เลือกสำหรับ reference นี้

- Algorithm ฝั่ง server: `RS256` อย่างเดียว; กุญแจ RSA public key อย่างน้อย 2048 bits
- JOSE header ต้องมีเฉพาะ `alg`, `typ`, `kid`; `typ = at+jwt`; `kid` ต้องอยู่ใน trusted config
- ปฏิเสธ `alg=none`, HS/RS confusion, `jku`, `jwk`, `x5u`, `crit` และ URL/key แปลกปลอม ไม่มี network lookup
- บังคับ `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`; audience เป็นค่าเดียวและตรง exact; issuer exact match
- `iat`, `nbf`, `exp` เป็น integer จริง ไม่ใช่ boolean/string/float และต้องเรียง `iat <= nbf < exp`
- PyJWT ตรวจเวลาเทียบ clock ของ server ไม่รับเวลาจาก JSON command; tests เท่านั้นที่ freeze clock
- token อายุไม่เกิน 900 วินาทีโดย default, ปรับได้จาก trusted config สูงสุด 3600; **นี่เป็น profile ทดลอง ไม่ใช่ผลวิจัยว่า TTL นี้ดีที่สุด**
- token ไม่เกิน 8192 ตัวอักษร; body ไม่เกิน 16384 bytes; JSON จำกัดความลึกและปฏิเสธ duplicate members/NaN/Infinity/UTF-8 ที่ผิด

เป็น reference แบบจำกัดหนึ่ง issuer/หนึ่ง audience ต่อ Boundary ไม่ได้อ้างว่ารองรับ access token จากทุก IdP และไม่ยอมรับ ID token ที่ typ เป็น JWT. ต้องตรวจความเข้ากันได้กับ provider จริงก่อนใช้งาน

## Identity ≠ role claims ≠ ความน่าเชื่อถือข่าว

Token ลายเซ็นถูกต้องยืนยันได้เพียงว่าผู้ถือกุญแจที่กำหนดออกข้ออ้างตัวตนตาม profile ไม่ได้พิสูจน์ว่าผู้ถือ token เป็นมนุษย์เพียงคนเดียว นักข่าวที่น่าเชื่อถือ หรืออยู่ในเหตุการณ์จริง

`actor_id`, `roles`, `scope`, `email` หรือ `app_metadata` แม้อยู่ใน token ที่ลงนามแล้ว ไม่ถูกนำมาเพิ่มสิทธิ์ในด่านนี้ ใช้ข้อมูลจาก `ActorBinding` ฝั่ง Backend เท่านั้น ไม่มี auto-provisioning หรือการ link บัญชีจาก email

ทะเบียนต้องให้ tuple issuer/subject ตรงกัน, UUID Actor ที่มีอยู่จริงในระบบถัดไป, actor kind, capabilities, revision, enabled และ tokens_valid_from. ขณะนี้ใช้ **fixture registry ในหน่วยความจำใน tests** ยังไม่ได้เชื่อมทะเบียน PostgreSQL จริง การตรวจ FK กับ echo_core.actors เป็น requirement ของ adapter ถัดไป

ผล `HUMAN` เป็นสถานะในทะเบียน ไม่ใช่การทำ proof-of-personhood. AI actor แม้ถูกใส่ review capability ใน fixture ก็ไม่ผ่าน human-review preflight. แต่ human reviewer ที่ผ่าน preflight ยังไม่ได้รับสิทธิ์ตรวจ target ใดโดยอัตโนมัติ

## Command DTO ที่รับ

ตัวอย่างเขียนฉบับร่าง:

```json
{
  "request_id": "20000000-0000-0000-0000-000000000001",
  "command": "CREATE_VOICE_DRAFT",
  "payload": {"text": "เสียงต้นฉบับของฉัน"}
}
```

ต้องมี `voice:draft:create` จากทะเบียน ไม่รับ visibility/source_id/payload_ref/recorded_at/author_id จาก client ใน DTO นี้ ฟังก์ชันยังไม่สร้าง draft จริง; ข้อกำหนด writer ในอนาคตคือสร้าง PRIVATE ก่อน ไม่มี automatic publication

ตัวอย่างความประสงค์ตรวจหลักฐาน:

```json
{
  "request_id": "20000000-0000-0000-0000-000000000001",
  "command": "REVIEW_EVIDENCE_RELATION",
  "payload": {
    "assessment_id": "30000000-0000-0000-0000-000000000001",
    "expected_revision": 1,
    "decision": "ACCEPTED",
    "rationale": "เหตุผลประกอบการขอประเมิน"
  }
}
```

ต้องเป็น HUMAN ในทะเบียนและมี `assessment:review`. `decision=ACCEPTED` ใน request เป็นแค่ค่าที่ผู้ใช้ร้องขอ **ยังไม่มีการยอมรับ assessment ในฐานข้อมูล** ไม่มีการ lookup object, ตรวจความขัดแย้งส่วนได้ส่วนเสีย, ป้องกัน self-approval หรือแก้ Current State ใน task นี้

`request_id` ตรวจเพียงรูปแบบ UUID ไม่ได้ทำ idempotent write/replay protection. Bearer token ที่ยังไม่หมดอายุอาจใช้เรียก preflight ซ้ำได้ ไม่ใช่ token ใช้ครั้งเดียว

## หลักการปฏิเสธและความลับ

- `IDENTITY_REJECTED`: token/subject/binding ใช้ไม่ได้ โดยไม่คืน raw token หรือรายละเอียดผู้ใช้อื่น
- `IDENTITY_BACKEND_UNAVAILABLE`: registry/revocation adapter ขัดข้องหรือคืนชนิดผิด; fail closed
- `INVALID_COMMAND`: รูปแบบคำสั่งไม่ตรง allowlist
- `CAPABILITY_REQUIRED`: ไม่มี capability ฝั่ง registry
- `HUMAN_REVIEW_REQUIRED`: actor ไม่ใช่ HUMAN แต่ขอ review

ไม่มี token logging และ repr ของ intent ไม่แสดงข้อความต้นฉบับ/rationale แต่ actor ID และข้อมูล audit อื่นยังเป็นข้อมูลต้องควบคุมสิทธิ์ HTTP adapter ในอนาคตต้องไม่ส่ง repr/traceback หรือ Authorization header ลง log. Frozen dataclass ป้องกันความผิดพลาดโดยบังเอิญ ไม่ต้านผู้โจมตีที่รัน Python ภายใน Backend แล้ว

## รันทดสอบ

```bash
python -m pip install -r backend/p2_1c2b1/requirements.txt
python backend/p2_1c2b1/run_checks.py
```

ใช้ PyJWT 2.13.0 และ cryptography 46.0.4 ที่ทดสอบจริง พิน direct dependencies เท่านั้น ไม่ใช่ lockfile ครบทุก transitive dependency หรือการรับรอง supply-chain security

104 test cases ตรวจ real RSA/JWT signatures ด้วยกุญแจ ephemeral, signature tamper, none/HS confusion, wrong issuer/audience, expiry/not-before, duplicate JSON, identity injection, registry revocation/outage, malicious role claims, AI reviewer, unchanged author text และข้อกำหนดว่า result ยังห้าม execute

Suite นี้ **ไม่ mock ผลการตรวจลายเซ็น** แต่ freeze clock ของ library เพื่อทดสอบ expiry แบบทำซ้ำได้ ไม่มี database/HTTP/IdP จริง Test runner บันทึก test IDs, counts, รุ่น runtime และ SHA-256 source โดยไม่เก็บกุญแจหรือ token

CI gate ใหม่แยกจาก PostgreSQL gates เดิม ไม่รวมเลข 131 checks ของอดีตมาอ้างว่าได้รันฐานข้อมูลใหม่ในรอบนี้

## ขอบเขตและ gate ที่ยังเปิดอยู่

ยัง UNKNOWN/BLOCKED: production issuer+audience/key provisioning, login/account linking/MFA, JWKS rotation ทุก process, TLS/CORS/CSRF, stolen bearer token, rate limits/DoS, PostgreSQL binding adapter+FK+protected registry grants, revocation persistence/latency, object-level read/write permissions, reviewer eligibility/self-approval, transaction-time recheck, payload ownership, idempotency/command audit, database connection privilege containment, snapshot sealing และ cache/privacy invalidation

การ lookup ทุก call ใน reference ไม่ได้รับประกันว่าระบบ registry จริงไม่มี cache stale; revocation หลัง preflight แต่ก่อน transaction เป็น TOCTOU gap ที่ต้องปิดใน DB command task. ต้องตรวจ token/binding/capability/target revision ซ้ำภายในขอบเขตธุรกรรมที่นิยามก่อน execute

ไม่มี branch ที่อนุญาตให้ bypass `ready_for_execution=False`. ห้ามนำ BoundIntent กลับมารับจาก client หรือใช้แทน signed token/authorization decision. ห้ามเอากุญแจส่วนตัวไปไว้ใน Pages หรือให้ browser ถือ credential PostgreSQL

## Completed / Blocked / Next

- Concrete output: identity-bound preflight module, strict DTOs, 104-case adversarial suite, separate CI workflow, explicit scope documentation
- Runtime result: อ่าน `results/test_results.json` และ Actions ของ commit จริง ห้ามถือจำนวน expected เป็น PASS
- P2.1c.2b.1 เสร็จเมื่อ local+CI suite ผ่าน; P2.1c.2b ทั้งก้อนและ production writing **ยังไม่เสร็จ**
- **Next: P2.1c.2b.2 — protected issuer/subject → Actor registry adapter บน PostgreSQL** ตรวจ FK, grants, disabled/revocation และ principal isolation จาก runtime ก่อนต่อ writer transaction. Reviewer object authorization ยังเป็นงาน dependent ถัดไป ห้ามข้าม

## เอกสารต้นทางที่ใช้ประกอบการออกแบบ

- PyJWT 2.13.0 API: fixed algorithm, signature validation, issuer/audience and required claims.
  https://pyjwt.readthedocs.io/en/2.13.0/api.html
- RFC 8725: algorithm verification, issuer/subject/audience validation and explicit token typing.
  https://datatracker.ietf.org/doc/html/rfc8725
- OWASP Authorization Cheat Sheet: deny by default, validate permissions on every request, separate authentication from authorization.
  https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Mass Assignment Cheat Sheet: allowlist non-sensitive DTO fields instead of binding arbitrary request properties into persistence models.
  https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

นี่เป็น implementation/reference contract ของ Echo ไม่ใช่หลักฐานว่าโครงการปลอดภัยครบหรือข่าวที่ผู้ใช้รายงานเป็นจริง
