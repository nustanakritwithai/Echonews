# P2.1c.2c — Session → Durable Actor/Source Mapping Contract v0.1

## งานเดียวของรอบนี้
เพิ่มชั้นจับคู่ผลตรวจ credential กับบัญชี/session ที่บันทึกถาวร ก่อนส่ง context ให้ command binder P2.1c.2b เดิม พร้อมปฏิเสธ session เก่าหลังถอนสิทธิ์หรือเปลี่ยนรุ่นอำนาจ

**ไม่ใช่ Login ที่พร้อมใช้จริง:** ไม่มีผู้ให้บริการ auth ถูกติดตั้ง, ไม่มี JWT signature verifier, ไม่มี HTTP API และไม่เปิด Browser เขียนฐานข้อมูล งานนี้ไม่แตะหน้าเว็บหลักหรือ /preview/ และไม่เปลี่ยน schema/contract เดิม

## 1. เส้นทางความเชื่อถือ

credential ดิบ → trusted verifier adapter → issuer/subject/session lookup key ที่ตรวจแล้ว
→ PostgreSQL authoritative snapshot → ตรวจ enabled/expiry/revoke/auth_version/role
→ frozen context ของ Actor + Source → command binder เดิม

`verifyCredential` เป็น callback ของเซิร์ฟเวอร์ที่ต้องติดตั้งอย่างถูกต้อง ไม่ใช่ field ใน request และไม่ใช่แค่ decode JWT. ในชุดทดสอบ callback นี้เป็นของจำลองอย่างชัดเจน ยังไม่ได้พิสูจน์การยืนยันตัวตนกับผู้ให้บริการจริง

`loadSnapshot` ต้องอ่านฐานหลักที่ authoritative ด้วยคำสั่งเดียว ไม่ใช้ replica ล่าช้า ไม่ fallback ไป context เก่า และต้องถูกเรียกใหม่ในทุกคำสั่ง ไม่มี cache ใน resolver นี้

## 2. Identity key
ใช้ (issuer, subject) แบบ exact/case-sensitive ไม่ใช้ email, display name, ยอดผู้ติดตาม หรือ actorId ที่ token/client เสนอมา การเปลี่ยนชื่อหรืออีเมลไม่ย้ายความเป็นเจ้าของโดยอัตโนมัติ

PostgreSQL `COLLATE "C"` ใช้กับคีย์เพื่อหลีกเลี่ยงการเทียบแบบละเลยตัวพิมพ์/สำเนียง. ปัจจุบันกำหนดหนึ่ง external identity ต่อหนึ่ง Actor/Source เพื่อเริ่มอย่างจำกัด; account linking, provider migration และ recovery ต้องเป็น workflow แยก ห้าม auto-link จากอีเมลเหมือนกัน

ฐานข้อมูลใหม่ `echo_identity.principals` มี principal_id, issuer, subject, actor_id, source_id, enabled, writer_enabled, reviewer_enabled, auth_version. FK บังคับ actor_kind=HUMAN ตามข้อมูลทะเบียน แต่ไม่ได้พิสูจน์ว่าบัญชีเป็นมนุษย์จริงหรือเป็นพยานอิสระ

## 3. Local session registry
`echo_identity.sessions` เก็บ session_key, principal_id, auth_version ณ ออก session, issued_at, expires_at, revoked. session_key ต้องเป็น digest 64 hex จาก adapter ที่เชื่อถือ ไม่ใช่ bearer token และการรู้ key อย่างเดียวไม่ผ่าน authentication

ไม่เก็บ raw access token, refresh token, password, JWT หรืออีเมลในตารางเหล่านี้ แต่ issuer/subject และ mapping ก็ยังเป็นข้อมูลอ่อนไหว ต้องป้องกันและมีนโยบายการลบ ไม่มีสิทธิ์ PUBLIC และไม่มี LOGIN role ถูกสร้างจาก migration นี้

สร้างบัญชีใหม่ default disabled และไม่มี writer/reviewer grants. Provisioning ต้องถูกทำโดยบริการที่เชื่อถือหลังพิสูจน์การเป็นเจ้าของตัวตนแล้ว ไม่ได้สร้างบัญชีอัตโนมัติเมื่อ lookup ไม่พบ

## 4. Revocation rules
- หมดอายุ: now >= expiresAt หมายถึงใช้ไม่ได้ ทั้งอายุ credential และ session ต้องผ่าน
- session ถูก revoke: request ถัดไปที่อ่านสถานะหลัง revocation commit ต้องถูกปฏิเสธ
- disabled principal: ไม่ให้ context สำหรับเขียน/ตรวจ
- ทุก authority UPDATE ต้องเพิ่ม auth_version ทีละหนึ่ง; session ผูก version เก่าจึงหยุดใช้ได้ทันทีในการตรวจครั้งถัดไป
- เปิดบัญชีกลับไม่คืนชีวิตให้ session เก่า ต้องออก session ใหม่ภายใต้ version ปัจจุบัน
- เปลี่ยน role ใช้กฎเดียวกันเพื่อไม่ให้สิทธิ์เก่าหรือการยกระดับสิทธิ์ไหลเข้า session เดิมโดยเงียบ
- เปลี่ยน Actor/Source/issuer/subject ของ mapping เดิมไม่ได้ด้วย UPDATE
- session ที่ revoke แล้วย้อนเป็น active ไม่ได้; เปลี่ยนเจ้าของ/อายุ/session key ไม่ได้ ต้องออก session ใหม่
- error/ฐานข้อมูลอ่านไม่ได้: fail closed ไม่ใช้ข้อมูลเก่ามาอนุญาต

ไม่มีการคาดเวลา auth จากเวลาโพสต์ข่าว ใช้ server clock ที่ส่งเป็น integer milliseconds และตรวจอีกครั้งหลัง await เพื่อกัน credential หมดอายุระหว่าง lookup. callback clock/DB ต้องเชื่อถือ; tests ไม่พิสูจน์ NTP หรือความคลาดเคลื่อนข้ามเครื่อง

## 5. รูปแบบผลตรวจ credential ที่ adapter ต้องคืน

```js
{
  tokenUse: 'ECHO_API_ACCESS',
  issuer: 'https://identity.example.test',
  subject: 'stable-provider-subject',
  audiences: ['echo-api'],
  sessionKey: '<64 lowercase hex lookup digest>',
  issuedAtMs: 1800000000000,
  notBeforeMs: 1800000000000,
  expiresAtMs: 1800000060000
}
```

นี่คือรูปแบบ normalized หลังตรวจแล้ว ไม่ใช่ format ที่ Browser สามารถส่งมาตั้งสิทธิ์. Adapter จริงต้องตรวจ signature/key/algorithm/issuer/audience/type/expiry ตามชนิด credential และ bind session ที่ถูกต้อง. ห้ามรับ OIDC ID token มาใช้เป็น API access token เพียงเพราะ decode ได้. การเลือกผู้ให้บริการและ verifier ยังเป็นประตูที่ไม่ได้ผ่าน

ผล resolver รองรับ binder เดิม: trusted, authenticated, actorId, sourceId, actorKind, roles พร้อม `authorizationStamp` ที่มี principalId/sessionKey/authVersion/checkedAtMs/expiresAtMs/capability. ไม่คัดลอก email/roles/actor claims จาก token มาเป็นสิทธิ์

## 6. ขอบเขตสำคัญ: lookup ผ่าน ไม่เท่ากับ commit ได้เสมอ
การอ่าน snapshot หนึ่งคำสั่งมีขอบเขตเวลาของตัวเอง อาจมี revoke เกิดหลังอ่านแต่ก่อนคำสั่งเขียน commit ได้ งานนี้รับรองเพียงการตรวจหลังการเปลี่ยนแปลงที่อ่านเห็นแล้ว ไม่รับรองการหยุด in-flight transaction

DB write adapter ถัดไปต้องเก็บ authorizationStamp ควบคู่ command (binder เดิมไม่ได้ส่ง stamp ต่อใน output), ตรวจอายุและ version ซ้ำ/ใช้ transaction fence หรือ locking ที่กำหนดกับแถว authority/session ก่อน commit และทดสอบ race revoke-vs-write จริง. ห้ามนำ context ที่เคย resolve ไป cache แล้วใช้ไม่จำกัดเวลา

กรณี session ใหม่เข้าพร้อม auth_version update มี FOR SHARE ใน provisioning guard เพื่อ serialize จุดออก session ตามแถว principal แต่ไม่ได้เป็น write fence ของโพสต์ในอนาคต

## 7. ทดสอบ

```sh
node --test contracts/p2_1c2b/command_boundary.test.mjs
node --test contracts/p2_1c2c/session_boundary.test.mjs
# เฉพาะ PostgreSQL service ทดสอบเปล่าบน loopback:
ECHO_DISPOSABLE_PG=YES PGHOST=127.0.0.1 PGDATABASE=echo_session_test \
  node --test contracts/p2_1c2c/postgres_mapping.test.mjs
```

Unit tests ใช้ verifier/store จำลอง. PostgreSQL integration ใช้ DB จริงและเปิด connection ใหม่ทุก query เพื่อทดสอบ durable lookup/revoke แต่ verifier ยังเป็น fixture. psql ใน test เป็น test driver ไม่ใช่ production adapter

CI `.github/workflows/p2-1c2c-session.yml` รัน regression DB เดิม 24+79+28 และ command เดิม 68 ก่อน suite ใหม่ รักษา log ของทุกชุดและตรวจ cleanup. จำนวนผลผ่านให้อ่านจาก CI ของ commit จริง ไม่อนุมานจากจำนวน test ที่เขียน

ชุด integration ปฏิเสธเมื่อไม่ได้กำหนดฐาน disposable ชื่อ echo_session_test บน loopback และจะไม่เริ่มถ้า echo_core/echo_identity มีอยู่ก่อน. มันสร้างและลบเฉพาะ schema/role ที่ตัวเองสร้างใน service ทดสอบ ห้ามใช้กับฐานจริง

## 8. สิ่งที่ยัง UNKNOWN / BLOCKED
- ตัวตรวจ credential จริง, issuer configuration, session establishment/rotation/refresh/logout bridge และ key rollover
- durable provisioning ownership proof, role grant audit/reviewer assignment/revocation UI, account linking/recovery
- production DB pool/primary routing, API transport/cookies/CSRF/origin/rate limit
- authorization ณ commit, TOCTOU/race revoke-write และ durable command adapter
- owner/private/restricted/payload reads, RLS, snapshot sealing, cache/search invalidation, privacy erasure/backup retention
- bot/Sybil resistance: บัญชีที่ authenticated ไม่ได้พิสูจน์ว่าเป็นคนอิสระ และไม่ทำให้ข่าวจริงขึ้น

ไม่สร้าง PKI เอง ไม่เปิด HTTP ไม่เปลี่ยน fixture news labels และไม่ใช้ข้อมูลส่วนตัวจริงในการทดสอบ

## 9. Completed / Next
ผลที่จะปิดได้เมื่อ CI ผ่าน: session mapping/revocation contract + durable registry + real-DB integration ของชั้นนี้

**Next: P2.1c.2d — เลือกและทดสอบ credential verifier/session adapter จริง** เพื่อปิด dependency ที่ verifyCredential ยังเป็น fixture ก่อนเปิด write API. จากนั้นต้องปิด write-time authorization fence และสิทธิ์การอ่าน ไม่ข้ามไป deploy ระบบหลายผู้ใช้เพียงเพราะ contract tests ผ่าน

## Primary-source rationale
- OpenID Connect Core 1.0 §5.7: issuer+subject สำหรับ stable identity; email/preferred_username ไม่ใช่ unique identity guarantee
  https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
- OWASP Session Management Cheat Sheet: session expiry/invalidation ฝั่ง server และ lifecycle ไม่ใช่เฉพาะล้าง cookie ฝั่ง client
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- RFC 8725: JWT verification, issuer/audience/type validation และการไม่สับสนชนิด token
  https://www.rfc-editor.org/rfc/rfc8725.html
- PostgreSQL 17 transaction isolation: read-committed statement snapshot ไม่ใช่การตรึงสิทธิ์ถึง transaction ในอนาคต
  https://www.postgresql.org/docs/17/transaction-iso.html

แนวทางและพารามิเตอร์เฉพาะ Echo ในเอกสารนี้เป็น contract ที่เสนอและทดสอบ ไม่ใช่สิ่งที่เอกสารอ้างอิงรับรองว่าระบบ production ปลอดภัยแล้ว
