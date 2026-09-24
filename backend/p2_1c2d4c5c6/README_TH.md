# P2.1c.2d.4c.5c.6 — Bounded Identity Lifecycle Integration Proof

งานนี้ปิด Critical UNKNOWN ถัดจาก c5c.5b.2 เท่านั้น: พิสูจน์ว่า chain ที่สร้างแยกไว้ก่อนหน้าใช้งานต่อกันได้จริงผ่าน restricted service boundaries โดยไม่ข้ามกลับไปใช้ owner/admin mutation ระหว่าง business transition

## Task

พิสูจน์วงจรเดียวบน PostgreSQL จริง:

`verified Bearer -> account-link proof -> disabled Principal -> audited activation -> first Session -> atomic rotation -> current-session logout -> repeat login`

Account-link และ Principal provisioning ต้องผ่าน service pools ที่มีอยู่จริง, activation ผ่าน dedicated activation service LOGIN, และ session transitions ใช้ first-session / rotation / logout / repeat-login pools ที่พิสูจน์ไว้แล้ว

## Success Contract

- Client identity มาจาก verified Bearer เท่านั้น; Actor/Source/Principal/session key ไม่ถูกเลือกจาก request
- Account-link proof ถูก consume ไปยัง Principal เดียว, activation เปลี่ยน authority 1 -> 2 พร้อม audit หนึ่งรายการ
- First Session resolve ผ่าน durable registry ได้เฉพาะ JTI ปัจจุบัน
- Rotation revoke predecessor + สร้าง successor; registry ต้องเลิก resolve predecessor ทันที
- Logout ทำให้ successor ไม่ resolve และไม่มี live current-generation Session
- Fresh repeat-login หลัง logout สร้าง live Session ใหม่หนึ่งตัวและ resolve กลับ Principal เดิม
- Historical proof/principal receipt ยังคง idempotent ได้ แต่ต้องไม่ resurrect Session ที่ logout/revoke ไปแล้ว
- สองบัญชีที่เดิน lifecycle พร้อมกันต้องไม่ข้าม Principal/Session กัน
- ไม่มี HTTP route, browser cookie, refresh token, permission grant, production credential หรือ production migration ในงานนี้

## Verification Plan

Workflow ใหม่ติดตั้ง auth migration chain เดิมบน disposable PostgreSQL 17 แล้วรัน `BoundedIdentityLifecycleTests` ซึ่ง inherit 92 atomic-rotation/session lifecycle methods เดิมและเพิ่ม 3 end-to-end integration methods รวม expected 95 methods. รัน strict signed-token regression 104 methods และ deterministic renewal model 14 methods แยกอีกครั้ง

PASS จะอ้างได้ต่อเมื่อ final-head CI สำเร็จ, cleanup เป็นจริง และ evidence artifact ถูกตรวจแล้วเท่านั้น

## Scope / Critical Unknowns ที่ยังเหลือ

งานนี้พิสูจน์ bounded integration ของ synthetic issuer + disposable service passwords เท่านั้น ไม่ได้พิสูจน์ production IdP/JWKS rotation, provider revocation/introspection, production HBA/TLS/PgBouncer, secret rotation/drain, browser token/cookie handoff, CSRF/CORS/rate limiting, logout-all, suspension/reactivation, writer/reviewer object authorization, privacy/erasure หรือ PUBLIC publishing

Historical onboarding/activation receipts เป็น provenance ไม่ใช่ current authorization; ทุก session operation ต้องอ้าง current durable Principal/session state ใหม่เสมอ

## Next

หลัง integration gate นี้ SAT ให้ทำ smallest next critical task: **production issuer/JWKS trust + key-rotation contract** สำหรับ verified Bearer โดยยังไม่เปิด HTTP/browser surface และยังไม่ถือ receipt/proof เก่าเป็น current authorization
