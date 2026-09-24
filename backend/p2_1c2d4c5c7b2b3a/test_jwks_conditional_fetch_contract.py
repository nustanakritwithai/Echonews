from __future__ import annotations

import base64
import unittest

from jwks_conditional_fetch_contract import (
    ConditionalFetchError,
    RefreshMode,
    accept_full_200,
    apply_not_modified_304,
    plan_refresh,
)
from jwks_trust_contract import ContractError, IssuerTrust, KeyDecision, decide_header_key


def trust(*, epoch: int = 1) -> IssuerTrust:
    return IssuerTrust(
        issuer="https://issuer.example",
        jwks_uri="https://issuer.example/.well-known/jwks.json",
        audience="echo-news",
        trust_epoch=epoch,
    )


def _b64u_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def document(*, kid: str = "k1", delta: int = 0) -> dict:
    modulus = (1 << 2047) | (0x12345 + delta)
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "alg": "RS256",
                "use": "sig",
                "n": _b64u_int(modulus),
                "e": _b64u_int(65537),
            }
        ]
    }


def cached(*, etag: str | None = '"v1"', fetched_at_ms: int = 100_000):
    headers = {} if etag is None else {"ETag": etag}
    return accept_full_200(
        trust(),
        document(),
        response_headers=headers,
        fetched_at_ms=fetched_at_ms,
    )


class ConditionalFetchContractTests(unittest.TestCase):
    def test_no_cache_requires_full_fetch(self):
        plan = plan_refresh(trust(), None, now_ms=100_000)
        self.assertIs(plan.mode, RefreshMode.FULL)
        self.assertEqual(dict(plan.headers), {})
        self.assertEqual(plan.reason, "NO_CACHE")

    def test_strong_etag_builds_exact_conditional_plan(self):
        entry = cached()
        plan = plan_refresh(trust(), entry, now_ms=200_000)
        self.assertIs(plan.mode, RefreshMode.CONDITIONAL)
        self.assertEqual(dict(plan.headers), {"if-none-match": '"v1"'})

    def test_missing_etag_keeps_refresh_unconditional(self):
        entry = cached(etag=None)
        plan = plan_refresh(trust(), entry, now_ms=200_000)
        self.assertIs(plan.mode, RefreshMode.FULL)
        self.assertEqual(plan.reason, "NO_STRONG_ETAG")

    def test_weak_etag_is_ignored_not_reused(self):
        entry = accept_full_200(
            trust(),
            document(),
            response_headers={"ETag": 'W/"v1"'},
            fetched_at_ms=100_000,
        )
        self.assertIsNone(entry.etag)
        self.assertIs(plan_refresh(trust(), entry, now_ms=200_000).mode, RefreshMode.FULL)

    def test_duplicate_etag_is_rejected(self):
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_ETAG_DUPLICATE"):
            accept_full_200(
                trust(),
                document(),
                response_headers=[("ETag", '"v1"'), ("etag", '"v2"')],
                fetched_at_ms=100_000,
            )

    def test_malformed_etag_is_rejected(self):
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_ETAG_INVALID"):
            accept_full_200(
                trust(),
                document(),
                response_headers={"ETag": "not-quoted"},
                fetched_at_ms=100_000,
            )

    def test_trust_epoch_change_forces_full_fetch_without_validator(self):
        entry = cached()
        plan = plan_refresh(trust(epoch=2), entry, now_ms=200_000)
        self.assertIs(plan.mode, RefreshMode.FULL)
        self.assertEqual(dict(plan.headers), {})
        self.assertEqual(plan.reason, "TRUST_CHANGED")

    def test_304_renews_soft_window_but_preserves_hard_deadline_and_body_identity(self):
        entry = cached()
        plan = plan_refresh(trust(), entry, now_ms=500_000)
        refreshed = apply_not_modified_304(
            trust(),
            entry,
            plan,
            response_headers={"ETag": '"v1"'},
            body=b"",
            now_ms=500_000,
        )
        self.assertEqual(refreshed.snapshot.fetched_at_ms, entry.snapshot.fetched_at_ms)
        self.assertEqual(refreshed.snapshot.hard_expires_at_ms, entry.snapshot.hard_expires_at_ms)
        self.assertEqual(refreshed.snapshot.soft_expires_at_ms, 800_000)
        self.assertEqual(refreshed.snapshot.key_set_version, entry.snapshot.key_set_version)
        self.assertEqual(dict(refreshed.snapshot.keys), dict(entry.snapshot.keys))
        self.assertEqual(refreshed.revalidated_at_ms, 500_000)

    def test_304_soft_revalidation_is_visible_to_header_decision(self):
        entry = cached()
        self.assertEqual(
            decide_header_key(
                trust(),
                entry.snapshot,
                {"alg": "RS256", "typ": "at+jwt", "kid": "k1"},
                now_ms=450_000,
            ).decision,
            KeyDecision.USE_CACHED_REFRESH_RECOMMENDED,
        )
        refreshed = apply_not_modified_304(
            trust(),
            entry,
            plan_refresh(trust(), entry, now_ms=500_000),
            response_headers={"ETag": '"v1"'},
            body=b"",
            now_ms=500_000,
        )
        self.assertEqual(
            decide_header_key(
                trust(),
                refreshed.snapshot,
                {"alg": "RS256", "typ": "at+jwt", "kid": "k1"},
                now_ms=600_000,
            ).decision,
            KeyDecision.USE_CACHED,
        )

    def test_repeated_304_never_extends_hard_deadline(self):
        entry = cached()
        first = apply_not_modified_304(
            trust(),
            entry,
            plan_refresh(trust(), entry, now_ms=500_000),
            response_headers={"ETag": '"v1"'},
            body=b"",
            now_ms=500_000,
        )
        second = apply_not_modified_304(
            trust(),
            first,
            plan_refresh(trust(), first, now_ms=850_000),
            response_headers={"ETag": '"v1"'},
            body=b"",
            now_ms=850_000,
        )
        self.assertEqual(second.snapshot.hard_expires_at_ms, 1_000_000)
        self.assertEqual(second.snapshot.soft_expires_at_ms, 1_000_000)
        self.assertEqual(plan_refresh(trust(), second, now_ms=1_000_000).reason, "HARD_EXPIRED")

    def test_304_at_hard_expiry_is_rejected(self):
        entry = cached()
        conditional = plan_refresh(trust(), entry, now_ms=900_000)
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_304_HARD_EXPIRED"):
            apply_not_modified_304(
                trust(),
                entry,
                conditional,
                response_headers={"ETag": '"v1"'},
                body=b"",
                now_ms=1_000_000,
            )

    def test_304_cannot_cross_trust_epoch(self):
        entry = cached()
        old_plan = plan_refresh(trust(), entry, now_ms=200_000)
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_304_TRUST_MISMATCH"):
            apply_not_modified_304(
                trust(epoch=2),
                entry,
                old_plan,
                response_headers={"ETag": '"v1"'},
                body=b"",
                now_ms=200_000,
            )

    def test_304_requires_the_exact_conditional_request(self):
        entry = cached()
        full_plan = plan_refresh(trust(), None, now_ms=200_000)
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_304_REQUEST_MISMATCH"):
            apply_not_modified_304(
                trust(),
                entry,
                full_plan,
                response_headers={"ETag": '"v1"'},
                body=b"",
                now_ms=200_000,
            )

    def test_304_without_etag_is_rejected(self):
        entry = cached()
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_304_ETAG_REQUIRED"):
            apply_not_modified_304(
                trust(),
                entry,
                plan_refresh(trust(), entry, now_ms=200_000),
                response_headers={},
                body=b"",
                now_ms=200_000,
            )

    def test_304_with_mismatched_etag_is_rejected(self):
        entry = cached()
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_304_ETAG_MISMATCH"):
            apply_not_modified_304(
                trust(),
                entry,
                plan_refresh(trust(), entry, now_ms=200_000),
                response_headers={"ETag": '"v2"'},
                body=b"",
                now_ms=200_000,
            )

    def test_304_with_body_is_rejected(self):
        entry = cached()
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_304_BODY_REJECTED"):
            apply_not_modified_304(
                trust(),
                entry,
                plan_refresh(trust(), entry, now_ms=200_000),
                response_headers={"ETag": '"v1"'},
                body=b"{}",
                now_ms=200_000,
            )

    def test_full_200_resets_hard_deadline_after_bounded_revalidation_period(self):
        entry = cached()
        replacement = accept_full_200(
            trust(),
            document(kid="k2"),
            response_headers={"ETag": '"v2"'},
            fetched_at_ms=1_000_000,
            previous=entry,
        )
        self.assertEqual(replacement.snapshot.fetched_at_ms, 1_000_000)
        self.assertEqual(replacement.snapshot.hard_expires_at_ms, 1_900_000)
        self.assertEqual(replacement.etag, '"v2"')

    def test_full_200_preserves_same_kid_substitution_defense(self):
        entry = cached()
        with self.assertRaisesRegex(ContractError, "JWKS_KID_KEY_SUBSTITUTION"):
            accept_full_200(
                trust(),
                document(delta=1),
                response_headers={"ETag": '"v2"'},
                fetched_at_ms=200_000,
                previous=entry,
            )

    def test_clock_rewind_is_rejected(self):
        entry = cached(fetched_at_ms=200_000)
        with self.assertRaisesRegex(ConditionalFetchError, "JWKS_CLOCK_REWIND"):
            accept_full_200(
                trust(),
                document(kid="k2"),
                response_headers={"ETag": '"v2"'},
                fetched_at_ms=199_999,
                previous=entry,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
