# ประสานงานกับ PR #6 — ไม่สร้าง API สองชุด

ตรวจจาก main `3f53d4fb364d471f8bfd2dd937e10bc54eb08302` ซึ่งเข้ามาระหว่างทำ PR นี้

## สถานะ roadmap ที่ใช้ร่วมกัน
- PR #6 เพิ่ม `contracts/p2_1c2b/command_boundary.mjs`: ตัวสร้างคำสั่งซึ่งรับ authenticated context จาก Backend อยู่แล้ว แต่ยังไม่มีตัวตรวจ token
- งานนี้ปิดเฉพาะ token/identity preflight ส่วนที่ขาด ไม่แทนที่หรือย้อนสถานะผลทดสอบ 68 กรณีของ PR #6
- ชื่อโฟลเดอร์และ test task `p2_1c2b1` เป็นรหัสที่เริ่มก่อน merge PR #6; ใน roadmap ใหม่ของ PR #6 งานเดียวกันนี้เทียบกับ **P2.1c.2c.1 — token verification subcomponent** ไม่ใช่หลักฐานว่า 2c ทั้งก้อนเสร็จ

## ห้ามต่อสองโมดูลโดย cast JSON ตรง ๆ

Python `BoundIntent` เป็น internal research preflight ไม่ใช่ API wire format ชุดใหม่ และไม่ใช่ JS `authContext` ของ command builder

| ประเด็น | ขอบเขตที่ยังต้องทำ |
|---|---|
| Actor/source | Python ยังไม่มี `sourceId`; ต้อง resolve จากทะเบียนที่ควบคุมสิทธิ์และ FK จริง ไม่รับจาก Client |
| Capability/role | `voice:draft:create` ไม่เท่ากับสิทธิ์ `writer` ที่สามารถขอ PUBLIC ได้ ห้ามแปลง capability เป็น role ตรง ๆ |
| Create | Python รับ `text` สำหรับ draft เท่านั้น; JS รับ `content` กับ PRIVATE/PUBLIC นี่เป็นคนละขอบเขตและยังไม่มี public endpoint |
| Actor kind | Python preflight บางคำสั่งอาจผ่าน AI ได้ แต่ JS writer บังคับ HUMAN; adapter ห้ามยกเลิกกติกาฝั่ง JS |
| Review | Python เป็น capability precheck; JS ตรวจ current assessment/revision/tuple จากข้อมูล server เพิ่ม ทั้งสองยังไม่พิสูจน์ reviewer assignment และ conflict-of-interest |
| UUID | Python ตรวจ canonical nonnil UUID; JS จำกัด version/variant ด้วย regex adapter ต้องตรวจรูปแบบที่ผ่านทั้งสอง ไม่ coercion อัตโนมัติ |
| Revocation | ต้องตรวจข้อมูลปัจจุบันอีกครั้งใน transaction ก่อนเขียน ไม่ถือ preflight เก่าเป็นสิทธิ์ถาวร |

**ไม่เปิด adapter หรือ write endpoint ในงานนี้** `ready_for_execution=False` เสมอ และไม่มีการเรียก JS command builder จาก token module

การคงโมดูลทั้งสองไว้จึงไม่ใช่การเปิดทางให้ request เลือก validator ที่อ่อนกว่า เส้นทาง HTTP ยังไม่มี การทดสอบของแต่ละโมดูลต้องไม่เรียกว่า end-to-end auth integration

## Test boundary หลังรวมงาน
CI ของ PR นี้รัน token/preflight 104 กรณี และ regression ของ command builder PR #6 บน tree ที่รวมกัน ใช้ชุดทดสอบคนละกลุ่ม ไม่บวกจำนวนการรันในเครื่องกับ CI เป็นกรณีใหม่ ไม่มีการรัน PostgreSQL ใน gate นี้

## งานถัดไปที่ตรงกันทั้งสองแผน
**P2.1c.2c.2 / planned alias P2.1c.2b.2 — durable protected principal registry + adapter contract**: issuer/subject → actor/source บน PostgreSQL พร้อม FK, read grants, disable/revoke และการตรวจ principal isolation. ต้องระบุการ mapping DTO/roles แบบชัดเจนก่อนต่อสองโมดูล

จากนั้นจึงตรวจ object authorization, reviewer assignment/self-review และ transaction ก่อนเปิด Browser API. ยังไม่เปลี่ยนหน้าเว็บ ไม่เปิด Login จริง และไม่เผยแพร่ข้อมูลผู้ใช้
