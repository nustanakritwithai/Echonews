import unittest

from jwks_egress_guard import (
    CONNECT_TIMEOUT_MS,
    READ_TIMEOUT_MS,
    EgressGuardError,
    build_pinned_tls_target,
)
from jwks_trust_contract import IssuerTrust


def trust(url="https://auth.example.com/.well-known/jwks.json"):
    return IssuerTrust(
        issuer="https://auth.example.com",
        jwks_uri=url,
        audience="echo-news",
        trust_epoch=1,
    )


class JwksEgressGuardTests(unittest.TestCase):
    def test_public_ipv4_is_accepted(self):
        target = build_pinned_tls_target(trust(), ["8.8.8.8"])
        self.assertEqual(target.addresses, ("8.8.8.8",))

    def test_public_ipv6_is_accepted(self):
        target = build_pinned_tls_target(trust(), ["2001:4860:4860::8888"])
        self.assertEqual(target.addresses, ("2001:4860:4860::8888",))

    def test_answers_are_deduplicated_and_sorted(self):
        target = build_pinned_tls_target(
            trust(),
            ["8.8.4.4", "2001:4860:4860::8888", "8.8.8.8", "8.8.4.4"],
        )
        self.assertEqual(
            target.addresses,
            ("8.8.4.4", "8.8.8.8", "2001:4860:4860::8888"),
        )

    def test_empty_answer_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_DNS_ANSWER_REJECTED"):
            build_pinned_tls_target(trust(), [])

    def test_too_many_answers_are_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_DNS_ANSWER_REJECTED"):
            build_pinned_tls_target(trust(), [f"8.8.8.{i}" for i in range(1, 18)])

    def test_private_ipv4_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_NON_PUBLIC_ADDRESS"):
            build_pinned_tls_target(trust(), ["10.0.0.1"])

    def test_loopback_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_NON_PUBLIC_ADDRESS"):
            build_pinned_tls_target(trust(), ["127.0.0.1"])

    def test_link_local_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_NON_PUBLIC_ADDRESS"):
            build_pinned_tls_target(trust(), ["169.254.1.1"])

    def test_multicast_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_NON_PUBLIC_ADDRESS"):
            build_pinned_tls_target(trust(), ["224.0.0.1"])

    def test_unspecified_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_NON_PUBLIC_ADDRESS"):
            build_pinned_tls_target(trust(), ["0.0.0.0"])

    def test_non_global_documentation_range_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_NON_PUBLIC_ADDRESS"):
            build_pinned_tls_target(trust(), ["192.0.2.1"])

    def test_mixed_public_and_private_answers_fail_closed(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_NON_PUBLIC_ADDRESS"):
            build_pinned_tls_target(trust(), ["8.8.8.8", "10.0.0.1"])

    def test_ip_literal_host_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_IP_LITERAL_REJECTED"):
            build_pinned_tls_target(trust("https://8.8.8.8/jwks"), ["8.8.8.8"])

    def test_non_443_port_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_PORT_REJECTED"):
            build_pinned_tls_target(trust("https://auth.example.com:8443/jwks"), ["8.8.8.8"])

    def test_unicode_hostname_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_HOSTNAME_REJECTED"):
            build_pinned_tls_target(trust("https://éxample.com/jwks"), ["8.8.8.8"])

    def test_trailing_dot_hostname_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_HOSTNAME_REJECTED"):
            build_pinned_tls_target(trust("https://auth.example.com./jwks"), ["8.8.8.8"])

    def test_scoped_ipv6_answer_is_rejected(self):
        with self.assertRaisesRegex(EgressGuardError, "JWKS_EGRESS_DNS_ANSWER_REJECTED"):
            build_pinned_tls_target(trust(), ["fe80::1%eth0"])

    def test_target_freezes_sni_timeouts_and_disables_environment_proxy(self):
        target = build_pinned_tls_target(
            trust("https://AUTH.EXAMPLE.COM/jwks"),
            ["8.8.8.8"],
        )
        self.assertEqual(target.server_hostname, "auth.example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.connect_timeout_ms, CONNECT_TIMEOUT_MS)
        self.assertEqual(target.read_timeout_ms, READ_TIMEOUT_MS)
        self.assertFalse(target.allow_environment_proxy)


if __name__ == "__main__":
    unittest.main(verbosity=2)
