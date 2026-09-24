# P2.1c.2d.4c.5c.7b.2b.2b — HTTP GET over Pinned TLS Socket + Envelope Integration

งานนี้เป็น **smallest useful task** ต่อจาก `7b.2b.2a` โดยเชื่อม `PinnedTlsConnection` เข้ากับ HTTP request/response จริง และส่งผลเข้า `parse_pinned_jwks_response()` โดยยังไม่แตะ ETag/304, retry/backoff, refresh single-flight หรือ persistent cache

## Decision: `PINNED_JWKS_HTTP_OVER_TLS_V1`

1. request สร้างจาก `build_pinned_jwks_request(trust)` เท่านั้น และ `target.url` ต้องตรง `trust.jwks_uri` แบบ exact
2. wire request เป็น HTTP/1.1 `GET` ไปยัง path+query ของ pinned JWKS URL พร้อม `Host` จาก pinned hostname, `Accept-Encoding: identity` และ `Connection: close`
3. adapter ไม่มี caller-supplied URL/Host/proxy และใช้ `open_pinned_tls_connection(target)` ที่พิสูจน์ frozen numeric IP + TLS hostname verification จาก task ก่อนหน้า
4. response header จำกัด 32 KiB และไม่เกิน 128 lines; malformed status line, obs-fold และ malformed framing ถูก reject
5. `Transfer-Encoding` ทุกชนิดถูก reject ใน task นี้เพื่อตัด chunked/framing ambiguity; รองรับเฉพาะ exact `Content-Length` หรือ body-until-EOF ภายใต้ `Connection: close`
6. body limit สืบทอดจาก envelope contract ที่ 262,144 bytes; duplicate/malformed Content-Length, short body, extra bytes และ oversize ถูก reject fail-closed
7. status/headers/body ที่อ่านได้แล้วต้องผ่าน `parse_pinned_jwks_response()` ต่อเสมอ จึงยังใช้ redirect/content-type/content-encoding/UTF-8/duplicate-JSON-member rules เดิมครบ
8. socket write/read timeout ถูกแปลงเป็น domain error และ TLS connection ถูกปิดใน `finally` ทั้ง success และ failure

## Security boundary ที่ปิดใน task นี้

ก่อนหน้านี้ระบบพิสูจน์ถึง verified TLS socket แต่ยังไม่มี request/response path จริง งานนี้ทำให้ chain เป็น:

`PinnedTlsTarget -> verified TLS -> exact pinned GET -> bounded HTTP framing -> envelope validation -> ParsedJwksResponse`

จึงปิดช่อง caller เปลี่ยน URL/Host, HTTP redirect-following, transfer-framing ambiguity, oversized headers/body และ connection leak ใน path นี้

## สิ่งที่ยังไม่พิสูจน์ในงานนี้

ยังไม่มี ETag/If-None-Match/304 semantics, retry/backoff, unknown-`kid` refresh single-flight, startup warmup, persistent/multi-process cache coordination, provider outage telemetry หรือ external production IdP handshake test ดังนั้น production Browser/API authentication ยังห้ามเปิด

## Verification

`test_jwks_http_tls_fetch.py` มี 18 deterministic cases ครอบคลุม exact pinned request, query preservation, Content-Length และ EOF framing, split reads, HTTP/1.0 compatibility, redirect rejection via inherited envelope, transfer-encoding rejection, header/body bounds, malformed status/obs-fold, duplicate/short/extra Content-Length, read/write timeout, target URL/host mismatch และ guaranteed close on envelope failure
