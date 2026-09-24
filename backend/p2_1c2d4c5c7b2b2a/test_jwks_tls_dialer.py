import os
import socket
import ssl
import unittest
from unittest.mock import patch

from jwks_egress_guard import PinnedTlsTarget
from jwks_tls_dialer import (
    PinnedTlsConnection,
    TlsDialError,
    _system_verified_context,
    open_pinned_tls_connection,
)


def target(*, addresses=("8.8.8.8",), **overrides):
    values = dict(
        url="https://auth.example.com/jwks",
        host="auth.example.com",
        port=443,
        server_hostname="auth.example.com",
        addresses=tuple(addresses),
        connect_timeout_ms=3000,
        read_timeout_ms=5000,
        allow_environment_proxy=False,
    )
    values.update(overrides)
    return PinnedTlsTarget(**values)


class FakeTlsSocket:
    def __init__(self):
        self.timeouts = []
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


class FakeSocket:
    def __init__(self, family, socktype, *, connect_error=None):
        self.family = family
        self.socktype = socktype
        self.connect_error = connect_error
        self.timeouts = []
        self.connected_to = None
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, value):
        self.connected_to = value
        if self.connect_error is not None:
            raise self.connect_error

    def close(self):
        self.closed = True


class SocketFactory:
    def __init__(self, errors=()):
        self.errors = list(errors)
        self.created = []

    def __call__(self, family, socktype):
        error = self.errors.pop(0) if self.errors else None
        sock = FakeSocket(family, socktype, connect_error=error)
        self.created.append(sock)
        return sock


class FakeContext:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED

    def __init__(self, *, handshake_errors=()):
        self.handshake_errors = list(handshake_errors)
        self.wrap_calls = []
        self.tls_sockets = []

    def wrap_socket(self, raw, *, server_hostname, do_handshake_on_connect):
        self.wrap_calls.append((raw, server_hostname, do_handshake_on_connect))
        error = self.handshake_errors.pop(0) if self.handshake_errors else None
        if error is not None:
            raise error
        tls = FakeTlsSocket()
        self.tls_sockets.append(tls)
        return tls


class JwksTlsDialerTests(unittest.TestCase):
    def test_system_context_uses_server_auth_and_verification(self):
        fake = FakeContext()
        with patch("jwks_tls_dialer.ssl.create_default_context", return_value=fake) as create:
            context = _system_verified_context()
        create.assert_called_once_with(purpose=ssl.Purpose.SERVER_AUTH)
        self.assertIs(context, fake)

    def test_ipv4_dials_frozen_ip_without_dns_lookup(self):
        sockets = SocketFactory()
        context = FakeContext()
        with patch("jwks_tls_dialer.socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            connection = open_pinned_tls_connection(
                target(),
                _socket_factory=sockets,
                _context_factory=lambda: context,
                _monotonic=lambda: 0.0,
            )
        self.assertEqual(sockets.created[0].family, socket.AF_INET)
        self.assertEqual(sockets.created[0].connected_to, ("8.8.8.8", 443))
        self.assertEqual(connection.peer_address, "8.8.8.8")

    def test_ipv6_dials_frozen_ip(self):
        sockets = SocketFactory()
        context = FakeContext()
        connection = open_pinned_tls_connection(
            target(addresses=("2001:4860:4860::8888",)),
            _socket_factory=sockets,
            _context_factory=lambda: context,
            _monotonic=lambda: 0.0,
        )
        self.assertEqual(sockets.created[0].family, socket.AF_INET6)
        self.assertEqual(sockets.created[0].connected_to, ("2001:4860:4860::8888", 443, 0, 0))
        self.assertEqual(connection.peer_address, "2001:4860:4860::8888")

    def test_tls_uses_original_hostname_as_sni_and_performs_handshake(self):
        sockets = SocketFactory()
        context = FakeContext()
        open_pinned_tls_connection(
            target(),
            _socket_factory=sockets,
            _context_factory=lambda: context,
            _monotonic=lambda: 0.0,
        )
        _, server_hostname, handshake = context.wrap_calls[0]
        self.assertEqual(server_hostname, "auth.example.com")
        self.assertTrue(handshake)

    def test_read_timeout_is_applied_after_tls_handshake(self):
        sockets = SocketFactory()
        context = FakeContext()
        connection = open_pinned_tls_connection(
            target(),
            _socket_factory=sockets,
            _context_factory=lambda: context,
            _monotonic=lambda: 0.0,
        )
        self.assertEqual(connection.tls_socket.timeouts[-1], 5.0)
        self.assertLessEqual(sockets.created[0].timeouts[0], 3.0)

    def test_first_ip_failure_falls_back_only_to_next_frozen_ip(self):
        sockets = SocketFactory(errors=(OSError("first failed"),))
        context = FakeContext()
        connection = open_pinned_tls_connection(
            target(addresses=("8.8.8.8", "8.8.4.4")),
            _socket_factory=sockets,
            _context_factory=lambda: context,
            _monotonic=lambda: 0.0,
        )
        self.assertEqual([s.connected_to for s in sockets.created], [("8.8.8.8", 443), ("8.8.4.4", 443)])
        self.assertTrue(sockets.created[0].closed)
        self.assertEqual(connection.peer_address, "8.8.4.4")

    def test_tls_failure_can_fall_back_and_failed_socket_is_closed(self):
        sockets = SocketFactory()
        context = FakeContext(handshake_errors=(ssl.SSLError("bad cert"),))
        connection = open_pinned_tls_connection(
            target(addresses=("8.8.8.8", "8.8.4.4")),
            _socket_factory=sockets,
            _context_factory=lambda: context,
            _monotonic=lambda: 0.0,
        )
        self.assertTrue(sockets.created[0].closed)
        self.assertEqual(connection.peer_address, "8.8.4.4")

    def test_all_connection_failures_fail_closed(self):
        sockets = SocketFactory(errors=(OSError("one"), OSError("two")))
        context = FakeContext()
        with self.assertRaisesRegex(TlsDialError, "JWKS_TLS_CONNECT_FAILED"):
            open_pinned_tls_connection(
                target(addresses=("8.8.8.8", "8.8.4.4")),
                _socket_factory=sockets,
                _context_factory=lambda: context,
                _monotonic=lambda: 0.0,
            )
        self.assertTrue(all(s.closed for s in sockets.created))

    def test_unverified_hostname_context_is_rejected_before_socket_open(self):
        sockets = SocketFactory()
        context = FakeContext()
        context.check_hostname = False
        with self.assertRaisesRegex(TlsDialError, "JWKS_TLS_CONTEXT_NOT_VERIFIED"):
            open_pinned_tls_connection(
                target(),
                _socket_factory=sockets,
                _context_factory=lambda: context,
                _monotonic=lambda: 0.0,
            )
        self.assertEqual(sockets.created, [])

    def test_cert_none_context_is_rejected_before_socket_open(self):
        sockets = SocketFactory()
        context = FakeContext()
        context.verify_mode = ssl.CERT_NONE
        with self.assertRaisesRegex(TlsDialError, "JWKS_TLS_CONTEXT_NOT_VERIFIED"):
            open_pinned_tls_connection(
                target(),
                _socket_factory=sockets,
                _context_factory=lambda: context,
                _monotonic=lambda: 0.0,
            )
        self.assertEqual(sockets.created, [])

    def test_private_ip_in_fabricated_target_is_rejected(self):
        with self.assertRaisesRegex(TlsDialError, "JWKS_TLS_TARGET_INVALID"):
            open_pinned_tls_connection(target(addresses=("10.0.0.1",)))

    def test_environment_proxy_permission_is_rejected(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9999"}):
            with self.assertRaisesRegex(TlsDialError, "JWKS_TLS_TARGET_INVALID"):
                open_pinned_tls_connection(target(allow_environment_proxy=True))

    def test_sni_mismatch_is_rejected(self):
        with self.assertRaisesRegex(TlsDialError, "JWKS_TLS_TARGET_INVALID"):
            open_pinned_tls_connection(target(server_hostname="other.example.com"))

    def test_connect_budget_exhaustion_before_any_socket_fails_closed(self):
        readings = iter((0.0, 4.0))
        with self.assertRaisesRegex(TlsDialError, "JWKS_TLS_CONNECT_TIMEOUT"):
            open_pinned_tls_connection(
                target(),
                _socket_factory=SocketFactory(),
                _context_factory=lambda: FakeContext(),
                _monotonic=lambda: next(readings),
            )

    def test_connection_close_delegates_to_tls_socket(self):
        sockets = SocketFactory()
        context = FakeContext()
        connection = open_pinned_tls_connection(
            target(),
            _socket_factory=sockets,
            _context_factory=lambda: context,
            _monotonic=lambda: 0.0,
        )
        self.assertIsInstance(connection, PinnedTlsConnection)
        connection.close()
        self.assertTrue(connection.tls_socket.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
