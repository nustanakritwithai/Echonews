from __future__ import annotations

import socket
import unittest

from jwks_egress_guard import PinnedTlsTarget
from jwks_http_tls_fetch import (
    JwksFetchError,
    MAX_HEADER_BYTES,
    fetch_pinned_jwks_over_tls,
)
from jwks_https_transport_contract import TransportContractError
from jwks_tls_dialer import PinnedTlsConnection
from jwks_trust_contract import IssuerTrust


class FakeTlsSocket:
    def __init__(self, chunks=(), *, recv_error=None, send_error=None):
        self.chunks = list(chunks)
        self.recv_error = recv_error
        self.send_error = send_error
        self.sent = b""
        self.closed = False

    def sendall(self, data: bytes) -> None:
        if self.send_error is not None:
            raise self.send_error
        self.sent += data

    def recv(self, size: int) -> bytes:
        if self.recv_error is not None:
            error = self.recv_error
            self.recv_error = None
            raise error
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


def trust() -> IssuerTrust:
    return IssuerTrust(
        issuer="https://issuer.example",
        jwks_uri="https://issuer.example/.well-known/jwks.json?tenant=echo",
        audience="echo-news",
        trust_epoch=1,
    )


def target(t: IssuerTrust | None = None) -> PinnedTlsTarget:
    t = t or trust()
    return PinnedTlsTarget(
        url=t.jwks_uri,
        host="issuer.example",
        port=443,
        server_hostname="issuer.example",
        addresses=("8.8.8.8",),
    )


def response(body=b'{"keys":[]}', *, status="200 OK", headers=()) -> bytes:
    base = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    base.extend(headers)
    lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in base]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


class FetchTests(unittest.TestCase):
    def _fetch(self, sock: FakeTlsSocket, *, t=None, tg=None):
        t = t or trust()
        tg = tg or target(t)
        seen = []
        result = fetch_pinned_jwks_over_tls(
            t,
            tg,
            _opener=lambda actual: seen.append(actual) or PinnedTlsConnection(sock, actual.addresses[0]),
        )
        return result, seen

    def test_content_length_success_and_exact_request(self):
        sock = FakeTlsSocket([response()])
        parsed, seen = self._fetch(sock)
        self.assertEqual(parsed.document, {"keys": []})
        self.assertEqual(seen, [target()])
        self.assertIn(b"GET /.well-known/jwks.json?tenant=echo HTTP/1.1\r\n", sock.sent)
        self.assertIn(b"Host: issuer.example\r\n", sock.sent)
        self.assertIn(b"Accept-Encoding: identity\r\n", sock.sent)
        self.assertIn(b"Connection: close\r\n", sock.sent)
        self.assertTrue(sock.closed)

    def test_eof_framing_without_content_length(self):
        body = b'{"keys":[]}'
        wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body
        parsed, _ = self._fetch(FakeTlsSocket([wire, b""]))
        self.assertEqual(parsed.body_bytes, len(body))

    def test_split_headers_and_body_are_supported(self):
        wire = response()
        parsed, _ = self._fetch(FakeTlsSocket([wire[:9], wire[9:25], wire[25:]]))
        self.assertEqual(parsed.document, {"keys": []})

    def test_http_10_is_accepted_for_envelope_validation(self):
        wire = response().replace(b"HTTP/1.1", b"HTTP/1.0", 1)
        parsed, _ = self._fetch(FakeTlsSocket([wire]))
        self.assertEqual(parsed.document, {"keys": []})

    def test_redirect_reaches_envelope_and_is_rejected(self):
        sock = FakeTlsSocket([response(status="302 Found", headers=[("Location", "https://evil.example/jwks")])])
        with self.assertRaises(TransportContractError):
            self._fetch(sock)
        self.assertTrue(sock.closed)

    def test_transfer_encoding_is_rejected_before_body_decode(self):
        wire = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"b\r\n{\"keys\":[]}\r\n0\r\n\r\n"
        )
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_TRANSFER_ENCODING_REJECTED"):
            self._fetch(FakeTlsSocket([wire]))

    def test_oversized_header_is_rejected(self):
        wire = b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * MAX_HEADER_BYTES
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_HEADERS_TOO_LARGE"):
            self._fetch(FakeTlsSocket([wire]))

    def test_malformed_status_line_is_rejected(self):
        wire = response().replace(b"HTTP/1.1 200 OK", b"ICY 200 OK", 1)
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_STATUS_LINE_INVALID"):
            self._fetch(FakeTlsSocket([wire]))

    def test_obs_fold_header_is_rejected(self):
        wire = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b" X-Fold: nope\r\nContent-Length: 11\r\n\r\n{\"keys\":[]}"
        )
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_HEADERS_REJECTED"):
            self._fetch(FakeTlsSocket([wire]))

    def test_duplicate_content_length_is_rejected(self):
        wire = response(headers=[("Content-Length", "11")])
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_CONTENT_LENGTH_INVALID"):
            self._fetch(FakeTlsSocket([wire]))

    def test_short_content_length_body_is_rejected(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99\r\n\r\n{}"
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_EOF_BEFORE_BODY"):
            self._fetch(FakeTlsSocket([wire]))

    def test_extra_bytes_after_content_length_are_rejected(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}EXTRA"
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_EXTRA_BODY_BYTES"):
            self._fetch(FakeTlsSocket([wire]))

    def test_declared_oversize_body_is_rejected_without_reading_it(self):
        wire = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: 262145\r\n\r\n"
        )
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_BODY_SIZE_REJECTED"):
            self._fetch(FakeTlsSocket([wire]))

    def test_read_timeout_is_domain_error_and_connection_closes(self):
        sock = FakeTlsSocket([], recv_error=socket.timeout("late"))
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_READ_TIMEOUT"):
            self._fetch(sock)
        self.assertTrue(sock.closed)

    def test_write_timeout_is_domain_error_and_connection_closes(self):
        sock = FakeTlsSocket([response()], send_error=socket.timeout("late"))
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_WRITE_TIMEOUT"):
            self._fetch(sock)
        self.assertTrue(sock.closed)

    def test_target_url_mismatch_fails_before_open(self):
        t = trust()
        bad = PinnedTlsTarget(
            url="https://issuer.example/other.json",
            host="issuer.example",
            port=443,
            server_hostname="issuer.example",
            addresses=("8.8.8.8",),
        )
        called = []
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_REQUEST_NOT_PINNED"):
            fetch_pinned_jwks_over_tls(t, bad, _opener=lambda actual: called.append(actual))
        self.assertEqual(called, [])

    def test_target_host_mismatch_fails_before_open(self):
        t = trust()
        bad = PinnedTlsTarget(
            url=t.jwks_uri,
            host="other.example",
            port=443,
            server_hostname="other.example",
            addresses=("8.8.8.8",),
        )
        with self.assertRaisesRegex(JwksFetchError, "JWKS_HTTP_REQUEST_NOT_PINNED"):
            fetch_pinned_jwks_over_tls(t, bad, _opener=lambda actual: self.fail("must not open"))

    def test_envelope_content_type_failure_still_closes_connection(self):
        body = b'{"keys":[]}'
        wire = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\n" + body
        )
        sock = FakeTlsSocket([wire])
        with self.assertRaises(TransportContractError):
            self._fetch(sock)
        self.assertTrue(sock.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
