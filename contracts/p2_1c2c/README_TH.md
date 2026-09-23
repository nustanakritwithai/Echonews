# P2.1c.2c.2 — Durable Identity / Session Registry v0.1

## งานเดียวและการประสานกับงานที่เข้ามาพร้อมกัน
รอบนี้ทำทะเบียน issuer/subject → Actor/Source และ session ถาวรบน PostgreSQL พร้อม resolver ที่อ่านสิทธิ์ปัจจุบันก่อนส่งต่อ command binder P2.1c.2b เดิม

ระหว่างทำพบ PR #7 รวมเข้า main ที่ `861074b050b3f2e653d45850b60b60dd07ca4cf8` แล้ว โดยเพิ่ม Python signed-token preflight ใน `backend/p2_1c2b1/identity_boundary.py`. งานนั้นนับเป็น P2.1c.2c.1 ส่วนงานนี้นับเป็น **P2.1c.2c.2**; ชื่อโฟลเดอร์/CI `p2_1c2c` เป็นชื่อเริ่มต้น ไม่ใช่การอ้างว่า P2.1c.2c ทั้งชุดเสร็จ

ไม่เขียนทับ PR #7 ไม่สร้าง Login/HTTP/API ใหม่ ไม่แก้หน้าเว็บหลักหรือ /preview/ ไม่แก้ command builder/schema เดิม และไม่รัน migration กับฐานใช้งานจริง

## 1. ขอบเขตความเชื่อถือ
credential → trusted verifier callback → issuer/subject/session key ที่ตรวจแล้ว
→ authoritative PostgreSQL snapshot → ตรวจ enabled/expiry/revoked/auth_version/role
→ frozen Actor/Source context → command binder เดิม

`verifyCredential` ใน resolver เป็น callback ที่เซิร์ฟเวอร์ติดตั้ง ไม่ใช่ request field และไม่ใช่แค่ decode JWT. **ชุดทดสอบใหม่ใช้ verifier จำลอง** แม้ repo มี signed-token module อยู่แล้ว ทั้งสองยังไม่เชื่อมกัน และผลผ่านแยกส่วนไม่ใช่ end-to-end authentication proof

`loadSnapshot` ต้องอ่านฐานหลักด้วย query เดียวทุกคำสั่ง ไม่มี cache ใน resolver และห้าม fallback ไปสิทธิ์เก่าเมื่อฐานอ่านไม่ได้ ตัว psql ใน integration test เป็น test driver ไม่ใช่ production pool adapter

## 2. ตารางและคีย์
`echo_identity.principals`: principal_id, issuer, subject, actor_id, source_id, enabled, writer_enabled, reviewer_enabled, auth_version

ใช้ (issuer, subject) แบบ exact และ case-sensitive ด้วย COLLATE "C" ไม่รวมบัญชีจากชื่อหรืออีเมลเหมือนกัน ไม่ยอมรับ actor/role ที่ client หรือ token เสนอแทนทะเบียน คีย์เดิมห้าม UPDATE เปลี่ยนไปผูก Actor/Source อื่น

เริ่มแบบหนึ่ง external identity ต่อหนึ่ง Actor/Source; account linking, provider migration และ recovery ยังไม่ทำ FK บังคับว่ารหัส actor_kind เป็น HUMAN ตามทะเบียน ไม่ใช่การพิสูจน์ว่าเป็นมนุษย์จริงหรือพยานอิสระ

`echo_identity.sessions`: session_key, principal_id, auth_version ณ ออก session, issued_at, expires_at, revoked

session_key เป็น digest 64 hex ที่ adapter ฝั่ง server ต้องผูกกับ credential ที่ตรวจแล้ว ไม่ใช่ bearer token และรู้ key อย่างเดียวใช้ยืนยันตัวตนไม่ได้ ไม่เก็บ raw token, password หรือ refresh token ในสองตารางนี้ แต่ issuer/subject/mapping ยังเป็นข้อมูลอ่อนไหว

migration ไม่มี PUBLIC grants และไม่สร้าง LOGIN role บัญชีใหม่ default disabled และไม่มี writer/reviewer grants ไม่ auto-provision เมื่อ lookup ไม่พบ การสร้างบัญชี/ให้สิทธิ์จริงต้องผ่าน trusted provisioning และ audit ซึ่งยังไม่ทำ

## 3. การถอนสิทธิ์
- ตรวจอายุทั้ง credential และ local session; now >= expiresAt ใช้ไม่ได้
- session ถูก revoke: lookup ถัดไปที่อ่านหลัง revoke commit ต้องปฏิเสธ
- ปิดบัญชี: ไม่คืน context สำหรับเขียนหรือตรวจ
- ทุก authority UPDATE ต้องเพิ่ม auth_version ทีละหนึ่ง; session ที่ผูก version เก่าจึงหยุดใช้
- เปิดบัญชีกลับไม่ทำให้ session เก่ากลับมา ต้องออก session ใหม่ภายใต้ version ปัจจุบัน
- เปลี่ยน role ใช้กฎ version เดียวกัน ไม่ยกระดับสิทธิ์ใน session เก่าเงียบ ๆ
- session ที่ revoke แล้วเปิดคืนไม่ได้ เปลี่ยนเจ้าของ/อายุ/key ไม่ได้ด้วย UPDATE
- error/ฐานอ่านไม่ได้: fail closed ไม่คืน context ที่เคยผ่านแล้ว

server clock เป็น integer milliseconds ตรวจซ้ำหลัง await เพื่อกันหมดอายุระหว่าง lookup ไม่ใช้เวลาโพสต์ข่าวเป็นเวลาตรวจสิทธิ์ Test clock เป็น fixture ไม่ได้พิสูจน์ความคลาดเคลื่อนข้ามเครื่อง

INSERT session ล็อก principal ด้วย FOR SHARE เพื่อจัดลำดับกับ authority UPDATE ระหว่าง provisioning เท่านั้น ไม่ใช่ write fence สำหรับคำสั่งโพสต์ภายหลัง

## 4. สัญญา callback และผลลัพธ์
verifier ต้องคืน normalized fields: tokenUse='ECHO_API_ACCESS', issuer, subject, audiences, sessionKey, issuedAtMs, notBeforeMs, expiresAtMs. นี่ไม่ใช่ JSON ที่ Browser ส่งมาตั้งสิทธิ์ และ marker ไม่ใช่หลักฐานลายเซ็นด้วยตัวเอง

ผล resolver: trusted, authenticated, actorId, sourceId, actorKind, roles พร้อม authorizationStamp={principalId,sessionKey,authVersion,checkedAtMs,expiresAtMs,capability}. ไม่ส่งต่อ email/token/role claims มาเป็นสิทธิ์

## 5. ห้ามต่อ Python/JavaScript ด้วยการ cast JSON

| ส่วนจาก PR #7 | ข้อกำหนดก่อนเชื่อมทะเบียนนี้ |
|---|---|
| BoundIntent | เป็น internal preflight และ ready_for_execution=False ไม่ใช่ JS authContext หรือ credential |
| Signature validation | ต้องเรียก verified interface ที่ตรวจ RS256/key/issuer/audience/type แล้วจริง ๆ ไม่ถอดข้อมูลจาก payload ที่ยังไม่ตรวจ |
| jti และเวลา NumericDate | ต้องกำหนด issuer-bound session-key derivation/provisioning และ seconds→milliseconds อย่างชัดเจน ห้ามใช้ client-supplied key |
| ActorBinding | ต้อง load Actor/Source จากทะเบียนเดียว ไม่ใช้ Python fixture กับ PostgreSQL คนละแหล่งเป็น authority |
| voice:draft:create | ไม่เท่ากับ writer ที่อนุญาตให้ขอ PUBLIC ได้ ต้องคงข้อจำกัด draft หรือมี grant แยก ห้ามยกระดับ capability โดยตรง |
| assessment:review | เป็น precheck ไม่ได้แปลว่าผู้ตรวจมีสิทธิ์ต่อ assessment ทุกรายการ ต้องตรวจ assignment/self-review/object access |
| UUID / subject | ต้องตรวจช่วงค่าที่ทั้งสองฝั่งยอมรับ ไม่แปลง identity ให้เท่ากันเพื่อให้ผ่านง่าย ๆ |
| Revocation | ต้องใช้ session/auth_version ปัจจุบัน และทดสอบพร้อมลายเซ็นจริง ไม่ใช่ถือว่า preflight เก่าผ่านแล้วตลอดไป |

ยังไม่มี adapter เชื่อมสองโมดูล และไม่มี route ให้ client เลือก validator ที่อ่อนกว่า ห้ามเปลี่ยน ready_for_execution เป็น True จากผลชุดทดสอบนี้

## 6. Lookup ผ่านไม่เท่ากับเขียนสำเร็จได้เสมอ
อาจมี revoke หลังอ่านแต่ก่อน commit ได้ งานนี้รับรองเฉพาะการตรวจที่เห็นการเปลี่ยนแปลงซึ่ง commit แล้ว ไม่รับรองการหยุด in-flight transaction

DB writer ถัดไปต้องเก็บ authorizationStamp ควบคู่ command เพราะ binder เดิมไม่ส่ง stamp ออกมา ตรวจอายุ/version ซ้ำและกำหนด transaction fence/locking กับ authority/session พร้อมทดสอบ race revoke-vs-write จริง ห้าม cache context ที่เคย resolve แล้วมาใช้ซ้ำ

การห้าม DELETE/TRUNCATE ป้องกัน normal-DML reuse ของ identity ไม่ใช่นโยบายเก็บข้อมูลส่วนบุคคลถาวร งาน erasure/admin retention ยังเป็น gate แยก Owners/superusers ยังเปลี่ยน DDL ได้ ห้ามใช้ credential เจ้าของใน public API

## 7. การทดสอบและขอบเขต

```sh
node --test contracts/p2_1c2b/command_boundary.test.mjs
node --test contracts/p2_1c2c/session_boundary.test.mjs
# เฉพาะฐาน PostgreSQL เปล่าแบบทิ้งได้บน loopback:
ECHO_DISPOSABLE_PG=YES PGHOST=127.0.0.1 PGDATABASE=echo_session_test \
  node --test contracts/p2_1c2c/postgres_mapping.test.mjs
```

Unit tests ใช้ verifier/store จำลอง 61 กรณี ส่วน integration 20 กรณีใช้ PostgreSQL จริง เปิด connection ใหม่ทุก query และ commit การเปลี่ยนสิทธิ์ แต่ verifier ยังเป็น fixture

CI `.github/workflows/p2-1c2c-session.yml` รัน DB regression เดิม 24+79+28 และ command regression 68 ก่อนชุดใหม่ พร้อมเก็บ logs/รุ่น server และตรวจ CLEAN_ISOLATED_IDENTITY_DATABASE ผลผ่านให้อ่านจาก CI commit จริง ไม่อนุมานจากจำนวน test ที่เขียน และไม่นับการรันในเครื่องซ้ำเป็นกรณีใหม่

Integration ปฏิเสธถ้าไม่ได้กำหนดฐาน disposable ชื่อ echo_session_test บน loopback หรือ schema มีอยู่ก่อน ลบเฉพาะ schema/test role ที่ตัวเองสร้างใน service ทดสอบ ห้ามใช้กับฐานจริง

## 8. Completed / Blocked / Next
เมื่อ CI ผ่าน ปิดได้เฉพาะ durable registry + resolver/revocation contract และ real-DB integration ของชั้นนี้ ยังไม่ปิด parent gate ทั้งชุด

ยัง BLOCKED: production issuer/key provisioning/login, signed-verifier-to-registry adapter, session issuance/refresh/logout, ownership proof และ role-grant audit, real least-privilege DB adapter, API transport/cookies/CSRF/origin/rate-limit, object permissions/reviewer assignment, authorization ณ commit, privacy/read visibility และ snapshot sealing

**Next: P2.1c.2c.3 — Signed Preflight → Durable Registry Integration** เชื่อมตัวตรวจลายเซ็นที่มีอยู่กับทะเบียนนี้ภายใต้ capability mapping ที่ไม่เพิ่มสิทธิ์เอง และทดสอบ token ที่เซ็นจริงคู่กับ PostgreSQL/revocation ก่อนเปิด HTTP write path ไม่ต้องประดิษฐ์ verifier อีกตัวซ้ำงาน PR #7

## แหล่งแนวคิดต้นทาง
- OpenID Connect Core 1.0 §5.7: issuer+subject เป็น stable identity pair ไม่ใช่ email/name
  https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
- OWASP Session Management: server-side expiry/invalidation
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- RFC 8725: JWT verification และไม่สับสน issuer/audience/token type
  https://www.rfc-editor.org/rfc/rfc8725.html
- PostgreSQL 17: statement snapshot ไม่ได้ตรึงสิทธิ์ถึงคำสั่งเขียนในอนาคต
  https://www.postgresql.org/docs/17/transaction-iso.html

สัญญาเฉพาะ Echo เป็นข้อเสนอที่ทดสอบตามขอบเขต ไม่ใช่คำรับรองระบบ production หรือความถูกต้องของข่าว
