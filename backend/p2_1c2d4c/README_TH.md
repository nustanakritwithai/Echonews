# P2.1c.2d.4c.1 — PRIVATE Owner-Read Service LOGIN / Pool Boundary

## งานเดียว
ทำส่วนย่อยแรกของ 4c: บัญชี service สำหรับ PRIVATE owner-read และ connection-pool reset ที่ใช้กับ adapter 4b เดิมได้ ไม่ทำ writer/registry/recovery pool ในงานนี้ ไม่เปิด HTTP/Login ผู้ใช้จริง และไม่แก้หน้าเว็บ

เริ่มจาก main 87224fa23c06910a4b158d6af8d0f1cf1038f749. หลักฐาน parent gate คือ PR #21; โค้ด parent ทั้งหมดคงเดิม รอบนี้เป็น additive migration/module/tests/workflow/document เท่านั้น

## Success contract

1. connection ต้อง login เป็น `echo_private_owner_read_service` จริง ไม่ยอมรับ admin ที่ใช้ SET SESSION AUTHORIZATION ปลอมเป็น service ตรวจ libpq startup user เพิ่มจาก session_user/current_user
2. service เป็น LOGIN/NOINHERIT/NOSUPERUSER/NOCREATEROLE/NOCREATEDB/NOREPLICATION/NOBYPASSRLS; membership เดียวไป owner-read runtime ด้วย SET TRUE, INHERIT FALSE, ADMIN FALSE. runtime ไม่มี membership ไป role อื่น
3. ค่าเริ่มต้น service ไม่มีสิทธิ์ตารางหรือฟังก์ชัน Echo; ภายในแต่ละ lease ใช้ SET LOCAL ROLE ไป `echo_private_owner_read_runtime` เท่านั้น ไม่ให้ request ระบุชื่อ role
4. ก่อนและหลังทุก lease: rollback ธุรกรรมที่ค้าง, DISCARD ALL นอก transaction, ตั้ง session baseline ใหม่, ตรวจ role/ACL อีกครั้ง. ไม่ commit ธุรกรรมเพื่อทำให้ connection ดูสะอาด
5. runtime ต้องเรียกฟังก์ชัน Echo ได้เพียง owner-read wrapper เดิม ไม่มี direct table/column grants หรือ CREATE ใน schema ที่ตรวจ
6. reset ล้มเหลว/connection เสีย: ปิดและไม่คืน connection สกปรกให้ผู้ยืมถัดไป ไม่มี fallback ไป owner หรือ replay business operation อัตโนมัติ
7. ข้อมูลตัวตนผู้ใช้เว็บยังมาจาก signed-token + durable registry ทุกคำขอ ไม่เก็บ actor/session ของเว็บไว้ใน SQL SET/GUC เพื่อใช้เป็นอำนาจ

## Concrete files

- `database/p2_1c2d4c/001_owner_read_service.sql`: additive role migration มี PASSWORD NULL, ไม่สร้าง secret
- `owner_read_pool.py`: synchronous psycopg_pool wrapper, fixed role, pinned authenticated user, explicit lease/cleanup
- `test_owner_read_pool.py`: สืบทอด 14 กรณี owner adapter เดิม เปลี่ยนเฉพาะ read connection เป็น service LOGIN จริง พร้อม 18 กรณี pool ใหม่
- `requirements.txt`: ใช้ psycopg 3.3.6 เดิม เพิ่ม psycopg_pool 3.3.0 เป็น direct dependency
- `.github/workflows/p2-1c2d4c-owner-read-pool.yml`: isolated PostgreSQL17, SCRAM host authentication, signed-token regression และ pool gate

## แบบการใช้ภายใน Backend

```python
pool = OwnerReadPool(
    host=trusted_config.host, port=5432, dbname=trusted_config.dbname,
    user='echo_private_owner_read_service',
    password=secret_provider.owner_read_password,
    sslmode='verify-full', sslrootcert=trusted_config.ca_file,
)
pool.open()
# PrivateOwnerReadAdapter(existing_boundary, pool.connection, trusted_payload_resolver)
# ปิดด้วย pool.close() ใน application lifecycle
```

นี่เป็น integration seam ไม่ใช่ production server ที่ถูกเปิดแล้ว ห้ามส่ง credential/DSN/role config ผ่าน client JSON. constructor default verify-full; ยอม sslmode=disable เฉพาะ flag ทดสอบ+host 127.0.0.1+ชื่อฐาน echo_owner_read_pool_test เท่านั้น

## Pool strategy

ใช้ psycopg_pool จริง ไม่สร้างระบบ queue ใหม่เอง ขนาด default 1 (ปรับ 1–4 สำหรับ reference) เพื่อพิสูจน์ same-backend reuse ได้ ปิด auto-prepare เนื่องจาก DISCARD ALL ล้าง prepared statements; ไม่ใช้ replay หรือกระจาย identity ผ่าน session state

ตัว wrapper ทำ synchronous sanitize ก่อนคืน connection ให้ pool และอีกครั้งก่อนให้ caller เพื่อไม่อาศัยเพียง async reset worker. DISCARD ALL ล้าง temp, prepared statements, LISTEN, session advisory locks และ session settings ตาม PostgreSQL. จากนั้นกำหนด search_path=pg_catalog, row_security=on, UTC และ timeout baseline อย่างชัดเจน

การตรวจ ACL ใช้ metadata SELECT ตรวจ role flags/membership, base-table/column grants, Echo function allowlist และ CREATE grants. นี่ไม่ใช่การรับรอง ACL ทั้ง cluster หรือป้องกัน DBA ที่แก้ privilege ระหว่าง lease. runtime ยังต้องผ่าน object/authorization fence เดิม

Connection/cursor ที่ได้จาก lease เป็น trusted-backend object ห้ามเก็บไว้ใช้หลัง context จบ ห้ามเรียก manual COMMIT/ROLLBACK เปลี่ยน role เอง หรือแชร์ให้ thread อื่น. การตรวจปลาย lease ช่วยตรวจผิด contract แต่ไม่ใช่ sandbox ป้องกันโค้ดอันตรายที่รันอยู่ใน Backend แล้ว

## Runtime verification ที่ต้องใช้ก่อน PASS

```sh
python -m pip install -r backend/p2_1c2d4c/requirements.txt
ECHO_DISPOSABLE_PG=YES PGHOST=127.0.0.1 PGDATABASE=echo_owner_read_pool_test \
  python backend/p2_1c2d4c/test_owner_read_pool.py
```

ต้องใช้ PostgreSQL17 service เปล่าแบบทิ้งได้ตาม fixture guard เดิมเท่านั้น. test provision ด้วย admin fixture แล้วสร้าง password service แบบสุ่มในหน่วยความจำ ให้ service login ผ่าน TCP จริง ไม่ใช้ SET SESSION AUTHORIZATION ใน read pool. ต้องทดสอบว่า password ผิด login ไม่ผ่านเพื่อไม่หลงทดสอบบน HBA trust

32 เป็นจำนวนที่คาดหวัง ไม่ใช่ผลสำเร็จก่อน CI: 14 inherited adapter cases + 18 new cases. Signed-token regression 104 รันแยก. ไม่บวก local run กับ CI เป็นจำนวน test ใหม่. log/JSON/source hashes และ cleanup marker อยู่ใน artifact ของ commit จริง

กรณีใหม่: real login, no default authority, guard/writer/owner escalation denial, same PID หลัง success/error, temp/GUC/search_path/role/plan/LISTEN/advisory-lock reset, timeout recovery, broken/reset-failed connection discard, dirty pool checkout, concurrent borrowers, ACL drift, service configuration denial, owner A→B→A และ revoke บน connection ที่ reuse

## Privacy / credentials / deployment boundary

- service login ไม่ใช่ผู้ใช้ Echo หรือหลักฐานความเป็นมนุษย์
- migration ไม่ตั้ง password/secret/HBA/certificate. PASSWORD NULL ไม่กัน trust/peer/certificate login ต้อง review access config จริงก่อน deploy
- CONNECT/TEMP ที่มาจาก PUBLIC ไม่ถูกลบทั้งระบบ; schema/database allowlists ต้องตรวจใน target environment
- password ทดสอบไม่อยู่ใน repo/artifact และไม่ส่งเข้า Pages
- read pool ไม่ได้รับ writer/recovery/registry privileges. ทะเบียนตัวตนและ fixture writer ใน test ยังเป็น trusted fixture setup ไม่ใช่ service deployments ที่พิสูจน์ครบ
- ไม่มีการแก้ claim labels หรือสร้าง Voice สาธารณะ

## UNKNOWN / blocked

ยังไม่ปิด parent 4c: writer service pool, registry/provisioning/recovery service roles, secret rotation/operational revocation/connection drain, multi-instance budgets, production TLS/HBA, PgBouncer/proxy transaction pooling, HTTP transport/CSRF/CORS/rate limit และ privacy erasure. actual production payload store/reviewer authorization/public publication ยังมี gate เดิม

การตรวจ expiry/revoke ของ owner read ยังมีขอบเขตตาม adapter/fence เดิม ไม่อ้างว่าดึง bytes แล้วสามารถเรียกคืนข้อมูลที่ส่งไปแล้วได้. การตรวจสิทธิ์ก่อนยืม connection ไม่ใช่การต้าน malicious DBA ที่เปลี่ยน grants ระหว่าง transaction

## Completed / Next

เมื่อ final CI ผ่าน ปิดได้เฉพาะ **P2.1c.2d.4c.1 owner-read LOGIN + pool reuse contract**.

Next: **P2.1c.2d.4c.2 — PRIVATE writer service LOGIN/pool integration** ให้ writer ใช้ service ของตัวเองและไม่ข้าม receipt/recovery/fence ด้วย pool retry; ทดสอบ unknown commit outcome และ role isolation ก่อนเปิด HTTP. ห้ามถือ read-only pool ที่ผ่านว่า writer/registry pools ผ่านแล้ว

## เอกสารหลักที่ตรวจ

PostgreSQL17 SET ROLE / role membership options:
https://www.postgresql.org/docs/17/sql-set-role.html
https://www.postgresql.org/docs/17/sql-grant.html
PostgreSQL17 DISCARD (ห้ามใช้ DISCARD ALL ใน transaction):
https://www.postgresql.org/docs/17/sql-discard.html
Psycopg pool lifecycle / getconn-putconn / configuration and reset:
https://www.psycopg.org/psycopg3/docs/advanced/pool.html

กติกา Echo เป็นการออกแบบของโครงการ ไม่ใช่เอกสารเหล่านี้รับรองว่าเป็นระบบปลอดภัยพร้อม production
