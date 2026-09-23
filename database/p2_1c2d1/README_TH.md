# P2.1c.2d.1 — PRIVATE Draft Transaction Fence Contract

## Task / Concrete Output
งานเดียว: พิสูจน์สัญญา authorization fence บน PostgreSQL 17 ด้วยธุรกรรมจริง โดยใช้ฉบับร่าง PRIVATE เป็นขอบเขตเล็กสุด ยังไม่สร้าง writer ของข่าวจริง

ต่อจาก main `e6b3d639a0628eeaebc7958aeb3cf43a03f19725` ซึ่งมี signed-registry 16-case gate แล้ว เพิ่มไฟล์แบบ additive ไม่เปลี่ยน verifier, registry schema เดิม, command binder, frontend หรือ HTTP route

- `001_write_fence.sql`: `echo_identity.assert_private_draft_fence(...)`
- `test_write_fence.py`: signed preflight + real DB + synthetic write/commit/rollback + observed concurrent locks
- `.github/workflows/p2-1c2d1-write-fence.yml`: new gate และ regression เดิม พร้อม source hashes / logs

## Success Contract
1. สิทธิ์ที่ผ่าน preflight ไม่ใช่สิทธิ์ถาวร: ตรวจ principal/session/Actor/Source/auth_version/capability/expiry ใหม่ใน transaction ที่จะเขียน
2. ถ้า revoke/disable/role removal commit ก่อน writer ได้ fence ต้อง DENY และไม่มี partial write
3. ถ้า writer ได้ locks ก่อน ให้ transaction นี้เสร็จก่อน revoke commit; เมื่อ revoke commit แล้ว request ถัดไปต้อง DENY
4. ถ้า revoke transaction rollback โดยไม่ได้ commit ไม่แกล้งถือว่าได้ถอนสิทธิ์แล้ว
5. ล็อก principal แล้ว session แบบ `FOR SHARE` ค้างถึง commit/rollback; ไม่ใช้ FOR KEY SHARE ซึ่งไม่ขวาง non-key authority update
6. ตรวจเวลา `clock_timestamp()` หลังการรอ lock และตรวจซ้ำท้าย transaction ไม่ใช้ now() ที่หยุดอยู่ที่ต้น transaction
7. NULL, tuple ไม่ตรง, stale version, timeout, unsupported isolation = ปฏิเสธ/rollback ไม่ fallback
8. reviewer และ PUBLIC publishing ยังเข้า path นี้ไม่ได้
9. การผ่านต้องอาศัย CI/runtime จริง ไม่ใช่จำนวน tests ที่เขียนไว้

## Protocol ที่ทดสอบ
```text
Real RS256 signed token
  -> existing Boundary + existing durable registry adapter
  -> BoundIntent (ready_for_execution=False)
  -> test-owned context: exact issuer/subject/principal/session + Actor/Source/version/time
  -> BEGIN READ COMMITTED
  -> lock principal FOR SHARE, then session FOR SHARE
  -> recheck current authority + database wall clock
  -> synthetic PRIVATE probe write
  -> final authority/time recheck on SAME connection
  -> COMMIT (probe also has default deferred recheck)
```

`echo_fence_probe` สร้างเฉพาะใน test database และลบทิ้งหลังรัน ไม่ใช่ schema ของ social network / staging draft จริง ไม่มี payload, raw token หรือ RSA private key ลงฐาน/ไฟล์/log จากชุดใหม่

ชุดทดสอบสร้าง side effect จำลองก่อนคำสั่งเป้าหมายด้วย เมื่อผิดสิทธิ์ต้อง rollback ทั้ง side effect และ target row และตรวจจาก connection อื่นว่าไม่เหลือข้อมูล

SQL function คืน `void` ไม่คืน ticket/authContext ที่นำกลับไปใช้ request ถัดไป ไม่ตรวจลายเซ็นเอง และไม่ใช่ object authorization grant

## Race semantics ที่ต้องไม่ตีความผิด
**Revoke-first:** transaction ถอนสิทธิ์ถือ lock อยู่ -> writer รอ -> revoke commit -> writer อ่านค่าที่เปลี่ยนแล้วและ DENY

**Writer-first:** writer ถือ fence locks แล้ว -> revoke รอ -> writer ตรวจท้าย transaction และ commit -> revoke ทำต่อและ commit -> writer ครั้งถัดไป DENY

นี่คือการจัดลำดับธุรกรรม ไม่ใช่คำรับรองว่า 'กด logout แล้วงานที่ in-flight ทุกงานจะหายทันที' การขอ revoke กับ revoke ที่ commit แล้วเป็นคนละสถานะ

Tests ใช้ `pg_blocking_pids` ยืนยันว่าเกิดการรอ lock จริง ไม่ถือว่า sleep เฉย ๆ พิสูจน์ race ได้ มี timeout bounded เพื่อไม่ค้าง และทดสอบ rollback ของทั้ง writer และ revoker รวมทั้งข้อมูลคนละ principal ที่ไม่ควรถูก global lock

## ขอบเขตเวลาและ trigger
ตรวจ expiry ณ **final database clock sample ก่อน commit** ไม่อ้างว่ามีหลักฐานว่า token ยังไม่หมดอายุ ณ เวลาที่ WAL ถูก flush หรือ client ได้รับ acknowledgement หลัง network delay

Future executor ต้องไม่มี user callback / external I/O / client-driven SQL ระหว่าง final recheck กับ commit และต้อง rollback เมื่อ timeout/deadlock/serialization failure ห้าม retry ด้วย context เก่าโดยไม่ตรวจใหม่

Deferred trigger ใน probe เป็น safety check สำหรับ protocol ที่ทดสอบ แต่ `SET CONSTRAINTS ... IMMEDIATE` สามารถสั่งให้ trigger ทำก่อนเวลาได้ จึงไม่อ้างว่า trigger อย่างเดียวเป็น non-bypassable production gate มี test ว่า explicit final check ยังปฏิเสธ token หมดอายุหลัง early flush

Locks ที่ acquire หลัง savepoint อาจถูกปล่อยเมื่อ rollback ไป savepoint นั้น Future executor ต้องไม่แยก fence กับ write คนละ transaction หรือถือผลก่อน rollback เป็นสิทธิ์ใหม่ งาน wiring/no-bypass ต้องพิสูจน์เพิ่ม

## Trust boundary / ไม่เพิ่มสิทธิ์
พารามิเตอร์ SQL เป็นข้อมูลจาก trusted backend เท่านั้น รู้ actor/session digest หรือปลอม JSON ให้เหมือน stamp ไม่ได้พิสูจน์ลายเซ็นและไม่ทำให้เป็น authenticated user

ใน tests ส่วนที่เติม issuer/subject/principal/session จาก fixture เป็น trusted test harness ไม่ใช่ production adapter จาก BoundIntent จึงไม่อ้างว่า signed-token -> real writer pipeline พร้อมแล้ว

Function เป็น SECURITY INVOKER, fixed search_path และ revoke EXECUTE จาก PUBLIC ไม่สร้าง LOGIN role ไม่ grant write permission ใดให้ browser

CI ใช้ owner ของ **ฐาน disposable เท่านั้น** เพื่อสร้าง/ลบ fixture และจำลอง race. SELECT FOR SHARE ต้องมี privilege สำหรับ locking; การทำ restricted execution API ที่ไม่จำเป็นต้องแจก authority-table UPDATE ให้ผู้เขียนยังเป็น **least-privilege gate ที่ไม่ผ่าน** ห้ามนำ CI credential หรือ owner role ไปต่อ public API

รองรับเพียง READ COMMITTED และ capability `voice:draft:create`. สิทธิ์ reviewer ใน DB ยังไม่ทำให้ใช้ fence นี้ review object ได้ การตรวจ assignment/self-review/conflict, owner/private/restricted reads และการ publish ยัง BLOCKED

## Verification
```sh
python -m pip install -r backend/p2_1c2c3/requirements.txt
# ใช้ PostgreSQL 17 เปล่า บน loopback และชื่อฐานตรงนี้เท่านั้น
ECHO_DISPOSABLE_PG=YES PGHOST=127.0.0.1 PGDATABASE=echo_fence_test \
  python database/p2_1c2d1/test_write_fence.py
```

Expected: 29 unittest methods; บาง method มี matrix subtests ไม่บวก subtests ซ้ำเป็นจำนวน tests ทั้งหมด ตรวจผลจริงจาก `fence.txt`: `Ran 29 tests`, `OK`, `CLEAN_WRITE_FENCE_DATABASE` และ `RACE_OBSERVED` records

CI rerun schema/history/public-read SQL, original signed verifier, JS command binder, durable session unit/PostgreSQL และ signed-registry integration เดิมในฐาน disposable แยกกัน ไม่บวก local/CI rerun เป็นกรณีใหม่

SAT ให้เฉพาะ PRIVATE fence contract กับ probe protocol ที่ทดสอบ. parent production-write gate ยังไม่ผ่าน. ถ้า test fail ให้ VIOL/แก้และรันใหม่; ถ้ายังไม่ได้ execute หรือหลักฐานไม่ครบให้ UNKNOWN

## Completed / Blocked / Next
**Completed เมื่อ gate ผ่าน:** SQL fence primitive, deterministic race-order tests ที่ใช้ real PostgreSQL waits/commits, fail-closed/rollback/expiry checks, regression evidence

**Blocked / UNKNOWN:** production writer integration, server-only transaction context, DB least-privilege/no-bypass path, real Voice immutable revision write, reviewer object permission/self-review, issuer/login lifecycle, RLS/privacy/erasure, idempotency/outbox, failover/cross-node clocks, absolute wall-clock expiry at durability/acknowledgement, public/multi-user publishing

**Next: P2.1c.2d.2 — Least-Privilege / No-Bypass Transaction Boundary** เริ่มจากสัญญาว่าบัญชี runtime ใช้ trusted transaction path เท่านั้น แต่แก้ principals/sessions หรือเขียน Voice โดยอ้อมเพื่อข้าม fence ไม่ได้ พร้อมกำหนดการ bind credential/session stamp ที่ไม่รับจาก client. ยังไม่เปิด browser write endpoint

## Primary references
- PostgreSQL 17 row locks, transaction lifetime, savepoints, conflict matrix:
  https://www.postgresql.org/docs/17/explicit-locking.html
- PostgreSQL 17 READ COMMITTED re-evaluation after concurrent updates:
  https://www.postgresql.org/docs/17/transaction-iso.html
- PostgreSQL 17 deferred triggers / SET CONSTRAINTS:
  https://www.postgresql.org/docs/17/sql-createtrigger.html
- PostgreSQL 17 clock_timestamp vs transaction time:
  https://www.postgresql.org/docs/17/functions-datetime.html
