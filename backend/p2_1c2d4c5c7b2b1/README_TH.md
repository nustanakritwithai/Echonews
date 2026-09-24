# P2.1c.2d.4c.5c.7b.2b.1 — Pinned JWKS DNS/Egress Guard Contract

งานนี้เป็น **smallest useful task** ต่อจาก `7b.2a` และยังไม่ทำ network fetch จริง เป้าหมายคือปิดความกำกวมก่อนเปิด socket ว่า DNS answer แบบใดอนุญาตให้นำไปใช้กับ JWKS endpoint ที่ operator pin ไว้

## Decision: `PINNED_JWKS_EGRESS_GUARD_V1`

1. ใช้เฉพาะ hostname จาก `IssuerTrust.jwks_uri`; caller ไม่มี URL/host override
2. JWKS transport production ใช้ HTTPS port `443` เท่านั้น
3. hostname ต้องเป็น ASCII DNS name แบบ canonical-useable: ไม่มี trailing dot, ไม่มี IP literal, ไม่มี Unicode/underscore/label ผิดรูป
4. resolver ต้องคืน 1–16 IP addresses และ **ทุก address ต้องเป็น public global unicast**
5. ถ้ามี private/loopback/link-local/multicast/reserved/unspecified/non-global ปะปนแม้เพียงหนึ่งตัว ให้ reject ทั้ง resolution แบบ fail-closed
6. IPv6 scope/zone id เช่น `%eth0` ถูก reject
7. output เป็น immutable `PinnedTlsTarget` ซึ่ง freeze IP set หลัง DNS decision; fetch adapter ถัดไปต้อง connect เฉพาะ IP ใน set นี้และ **ห้าม resolve hostname ซ้ำ**
8. TLS SNI และ certificate hostname verification ต้องใช้ original DNS hostname (`server_hostname`) ไม่ใช่ IP ที่ connect
9. environment proxy ถูกปิด (`allow_environment_proxy=False`)
10. transport budget ถูก freeze ที่ connect 3s / read 5s เพื่อกัน request ค้างไม่จำกัด

## เหตุผลด้าน security

Contract นี้ตัด SSRF ไปยัง localhost/VPC/metadata/link-local และทำให้ DNS rebinding มีจุดตรวจ deterministic: DNS resolve หนึ่งครั้ง → validate public-only → freeze address set → socket adapter ต้องใช้เฉพาะ set เดิม ขณะเดียวกัน TLS identity ยังผูกกับ hostname ที่ operator pin ไว้

## สิ่งที่ยังไม่พิสูจน์ในงานนี้

งานนี้ **ไม่ใช่ socket implementation** และยังไม่อ้าง SAT สำหรับ TLS handshake จริง, CA/hostname verification, connect-to-approved-IP wiring, DNS resolver behavior ของระบบจริง, proxy bypass จริง, ETag/304, retry/backoff, single-flight refresh, multi-process cache หรือ outage telemetry สิ่งเหล่านี้ต้องทำใน task ถัดไปและห้ามเปิด production Browser/API auth ก่อนผ่าน

## Verification

`test_jwks_egress_guard.py` มี 18 deterministic cases ครอบคลุม public IPv4/IPv6, deterministic dedupe/sort, empty/oversized DNS answer, private/loopback/link-local/multicast/unspecified/documentation ranges, mixed public+private fail-closed, IP-literal host, non-443 port, Unicode/trailing-dot hostname, scoped IPv6 และ frozen SNI/timeouts/proxy policy
