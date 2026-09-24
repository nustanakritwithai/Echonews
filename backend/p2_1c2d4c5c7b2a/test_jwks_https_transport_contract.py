from __future__ import annotations

import inspect
import json
import unittest

from jwks_https_transport_contract import (
    JwksHttpRequest,
    MAX_RESPONSE_BYTES,
    TransportContractError,
    build_pinned_jwks_request,
    parse_pinned_jwks_response,
)
from jwks_trust_contract import IssuerTrust


class PinnedHttpsJwksEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust = IssuerTrust(
            issuer="https://issuer.example",
            jwks_uri="https://keys.example/.well-known/jwks.json?tenant=echo",
            audience="echo-news",
            trust_epoch=7,
        )
        self.request = build_pinned_jwks_request(self.trust)
        self.body = json.dumps({"keys": [{"kid": "k1"}]}).encode("utf-8")

    def parse(self, *, status=200, headers=None, body=None, request=None):
        if headers is None:
            headers = [("Content-Type", "application/json"), ("Content-Length", str(len(self.body)))]
        return parse_pinned_jwks_response(
            self.trust,
            request or self.request,
            status=status,
            headers=headers,
            body=self.body if body is None else body,
        )

    def assert_error(self, code, **kwargs):
        with self.assertRaisesRegex(TransportContractError, f"^{code}$"):
            self.parse(**kwargs)

    def test_01_request_uses_exact_operator_pinned_url(self):
        self.assertEqual(self.request.method, "GET")
        self.assertEqual(self.request.url, self.trust.jwks_uri)
        self.assertEqual(self.request.headers["accept-encoding"], "identity")

    def test_02_builder_has_no_caller_url_argument(self):
        self.assertEqual(tuple(inspect.signature(build_pinned_jwks_request).parameters), ("trust",))

    def test_03_application_json_200_is_accepted(self):
        parsed = self.parse()
        self.assertEqual(parsed.media_type, "application/json")
        self.assertEqual(parsed.document, {"keys": [{"kid": "k1"}]})

    def test_04_jwk_set_json_and_utf8_charset_are_accepted(self):
        headers = [("Content-Type", "application/jwk-set+json; charset=UTF-8")]
        parsed = self.parse(headers=headers)
        self.assertEqual(parsed.media_type, "application/jwk-set+json")

    def test_05_tampered_request_url_is_rejected(self):
        evil = JwksHttpRequest(method="GET", url="https://evil.example/jwks", headers=self.request.headers)
        self.assert_error("JWKS_HTTP_REQUEST_NOT_PINNED", request=evil)

    def test_06_redirect_is_rejected_even_with_location(self):
        self.assert_error(
            "JWKS_HTTP_REDIRECT_REJECTED",
            status=302,
            headers=[("Content-Type", "application/json"), ("Location", self.trust.jwks_uri)],
        )

    def test_07_non_200_status_is_rejected(self):
        self.assert_error("JWKS_HTTP_STATUS_REJECTED", status=503)

    def test_08_missing_content_type_is_rejected(self):
        self.assert_error("JWKS_HTTP_CONTENT_TYPE_REQUIRED", headers=[])

    def test_09_wrong_content_type_is_rejected(self):
        self.assert_error("JWKS_HTTP_CONTENT_TYPE_REJECTED", headers=[("Content-Type", "text/html")])

    def test_10_non_utf8_or_extra_content_type_parameter_is_rejected(self):
        self.assert_error(
            "JWKS_HTTP_CONTENT_TYPE_REJECTED",
            headers=[("Content-Type", "application/json; charset=iso-8859-1")],
        )

    def test_11_compressed_response_is_rejected(self):
        self.assert_error(
            "JWKS_HTTP_CONTENT_ENCODING_REJECTED",
            headers=[("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
        )

    def test_12_duplicate_security_header_is_rejected(self):
        self.assert_error(
            "JWKS_HTTP_DUPLICATE_SECURITY_HEADER",
            headers=[("Content-Type", "application/json"), ("content-type", "application/jwk-set+json")],
        )

    def test_13_body_size_is_bounded(self):
        body = b"{" + b" " * MAX_RESPONSE_BYTES + b"}"
        self.assert_error("JWKS_HTTP_BODY_SIZE_REJECTED", body=body, headers=[("Content-Type", "application/json")])

    def test_14_content_length_must_match_actual_body(self):
        self.assert_error(
            "JWKS_HTTP_CONTENT_LENGTH_MISMATCH",
            headers=[("Content-Type", "application/json"), ("Content-Length", str(len(self.body) + 1))],
        )

    def test_15_invalid_utf8_is_rejected(self):
        body = b'{"keys":[]}' + b"\xff"
        self.assert_error("JWKS_HTTP_UTF8_REQUIRED", body=body, headers=[("Content-Type", "application/json")])

    def test_16_duplicate_json_members_are_rejected(self):
        body = b'{"keys":[],"keys":[]}'
        self.assert_error("JWKS_JSON_DUPLICATE_MEMBER", body=body, headers=[("Content-Type", "application/json")])

    def test_17_top_level_json_must_be_object(self):
        body = b'[]'
        self.assert_error("JWKS_HTTP_JSON_OBJECT_REQUIRED", body=body, headers=[("Content-Type", "application/json")])

    def test_18_crlf_header_value_is_rejected(self):
        self.assert_error(
            "JWKS_HTTP_HEADERS_INVALID",
            headers=[("Content-Type", "application/json\r\nX-Evil: 1")],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
