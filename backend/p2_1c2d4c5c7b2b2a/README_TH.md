# P2.1c.2d.4c.5c.7b.2b.2a — Pinned TLS Socket Dialer + Hostname Verification

งานนี้เป็น **smallest useful task** ต่อจาก `7b.2b.1` โดยปิดช่องว่างระหว่าง `PinnedTlsTarget` กับ TLS socket จริง แต่ยังไม่ส่ง HTTP GET และยังไม่ parse JWKS response ใน task นี้

## Decision: `PINNED_JWKS_TLS_DIALER_V1`

1. รับเฉพาะ `PinnedTlsTarget` ที่ตรงกับ contract เดิม: HTTPS/443, `host == server_hostname`, proxy disabled, timeout 3s/5s และมี frozen IP set
2. ป้องกัน fabricated target ซ้ำอีกชั้น: malformed port และทุก IP ที่ไม่ใช่ public global address ถูก reject
3. socket ถูกสร้างด้วย `AF_INET`/`AF_INET6` แล้ว `connect()` ไปยัง **numeric frozen IP โดยตรง**; ห้ามเรียก hostname resolver ซ้ำ
4. TLS context production สร้างด้วย `ssl.create_default_context(purpose=SERVER_AUTH)` จึงใช้ platform/system CA store และต้องมี `check_hostname=True` + `CERT_REQUIRED`
5. TLS handshake ใช้ `server_hostname` จาก pinned DNS hostname เพื่อบังคับ SNI + certificate hostname verification; ไม่ใช้ IP เป็น TLS identity
6. connect + TLS handshake ใช้ deadline เดียวจาก connect budget 3 วินาที และหลัง handshake เปลี่ยนเป็น read timeout 5 วินาที
7. หาก IP แรก connect/TLS ล้มเหลว สามารถ failover ได้เฉพาะ IP ถัดไปใน frozen approved set เท่านั้น; ไม่มี URL/host/proxy fallback
8. failed sockets ถูกปิดก่อนลอง candidate ถัดไป และ callers ได้ `PinnedTlsConnection(peer_address=...)` เพื่อ audit ว่า IP ใดชนะ

## Security boundary ที่ปิดใน task นี้

ก่อนหน้านี้ contract เพียงบอกว่า adapter *ต้อง* connect ไป frozen IP และ verify hostname; ตอนนี้ implementation ทำสิ่งนั้นจริง และ deterministic tests ป้องกัน second DNS lookup, disabled hostname verification, `CERT_NONE`, private-IP/malformed-port fabricated target, SNI mismatch และ environment-proxy permission

## สิ่งที่ยังไม่พิสูจน์ในงานนี้

ยังไม่ได้ส่ง HTTP request บน TLS socket, ยังไม่ได้อ่าน status/headers/body, ยังไม่ได้ integrate `parse_pinned_jwks_response()`, ETag/304, retry/backoff, unknown-`kid` single-flight, persistent/multi-process cache หรือ outage telemetry ดังนั้น production Browser/API auth ยังห้ามเปิด

## Verification

`test_jwks_tls_dialer.py` มี 16 deterministic cases ครอบคลุม system verified context, IPv4/IPv6 numeric dialing, no second DNS lookup, SNI/handshake, read timeout, frozen-IP failover, TLS-failure cleanup, all-failure fail-closed, unverified context rejection, fabricated private/malformed-port target, proxy permission rejection, SNI mismatch, deadline exhaustion และ explicit close
