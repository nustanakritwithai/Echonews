from __future__ import annotations

import unittest

from renewal_contract import Candidate, Decision, Principal, Session, rotate_active_session


NOW = 2_000_000
SUB = "acct-123"
P = Principal(subject=SUB, auth_version=7)
CURRENT = Session("s-current", SUB, 7, 1_900_000, 2_500_000)


def candidate(key="s-next", *, iat=1_950_000, nbf=1_950_000, exp=2_600_000, subject=SUB, version=7):
    return Candidate(key, subject, version, iat, nbf, exp)


class RenewalContractTests(unittest.TestCase):
    def test_01_exact_current_token_replay_is_idempotent(self):
        c = candidate("s-current", iat=CURRENT.issued_at_ms, nbf=CURRENT.issued_at_ms, exp=CURRENT.expires_at_ms)
        r = rotate_active_session(P, (CURRENT,), c, NOW)
        self.assertEqual(r.decision, Decision.REPLAY_CURRENT)
        self.assertEqual(r.sessions, (CURRENT,))
        self.assertEqual(r.current_session_key, "s-current")

    def test_02_strictly_newer_bearer_rotates_atomically(self):
        r = rotate_active_session(P, (CURRENT,), candidate(), NOW)
        self.assertEqual(r.decision, Decision.ROTATED)
        live = [s for s in r.sessions if s.live(NOW, P.auth_version)]
        self.assertEqual([s.session_key for s in live], ["s-next"])
        old = next(s for s in r.sessions if s.session_key == "s-current")
        self.assertTrue(old.revoked)
        self.assertEqual(old.replaced_by, "s-next")

    def test_03_equal_iat_different_jti_cannot_roll_current(self):
        r = rotate_active_session(P, (CURRENT,), candidate(iat=CURRENT.issued_at_ms), NOW)
        self.assertEqual(r.decision, Decision.REJECT_STALE_OR_EQUAL_BEARER)

    def test_04_older_bearer_cannot_roll_current(self):
        r = rotate_active_session(P, (CURRENT,), candidate(iat=CURRENT.issued_at_ms - 1), NOW)
        self.assertEqual(r.decision, Decision.REJECT_STALE_OR_EQUAL_BEARER)

    def test_05_revoked_predecessor_never_resurrects(self):
        first = rotate_active_session(P, (CURRENT,), candidate(), NOW)
        replay_old = candidate("s-current", iat=CURRENT.issued_at_ms, nbf=CURRENT.issued_at_ms, exp=2_400_000)
        r = rotate_active_session(P, first.sessions, replay_old, NOW)
        self.assertEqual(r.decision, Decision.REJECT_REVOKED_PREDECESSOR)
        self.assertEqual(r.current_session_key, "s-next")

    def test_06_no_active_session_must_use_repeat_login_path(self):
        expired = Session("expired", SUB, 7, 1_000_000, NOW)
        r = rotate_active_session(P, (expired,), candidate(), NOW)
        self.assertEqual(r.decision, Decision.REJECT_NO_ACTIVE_USE_REPEAT_LOGIN)

    def test_07_unknown_commit_explicit_retry_resolves_successor(self):
        committed = rotate_active_session(P, (CURRENT,), candidate(), NOW)
        self.assertEqual(committed.decision, Decision.ROTATED)
        retry = rotate_active_session(P, committed.sessions, candidate(), NOW)
        self.assertEqual(retry.decision, Decision.REPLAY_CURRENT)
        self.assertEqual(retry.current_session_key, "s-next")

    def test_08_sequential_newer_candidate_can_supersede_after_serialization(self):
        first = rotate_active_session(P, (CURRENT,), candidate("s-a", iat=1_950_000), NOW)
        second = rotate_active_session(P, first.sessions, candidate("s-b", iat=1_960_000), NOW)
        self.assertEqual(second.decision, Decision.ROTATED)
        live = [s.session_key for s in second.sessions if s.live(NOW, P.auth_version)]
        self.assertEqual(live, ["s-b"])

    def test_09_late_arriving_older_concurrent_candidate_rejects(self):
        first = rotate_active_session(P, (CURRENT,), candidate("s-newer", iat=1_970_000), NOW)
        second = rotate_active_session(P, first.sessions, candidate("s-older", iat=1_960_000), NOW)
        self.assertEqual(second.decision, Decision.REJECT_STALE_OR_EQUAL_BEARER)
        self.assertEqual(second.current_session_key, "s-newer")

    def test_10_disabled_or_unactivated_principal_rejects(self):
        for principal in (
            Principal(SUB, 7, enabled=False, activated=True),
            Principal(SUB, 7, enabled=True, activated=False),
        ):
            with self.subTest(principal=principal):
                r = rotate_active_session(principal, (CURRENT,), candidate(), NOW)
                self.assertEqual(r.decision, Decision.REJECT_IDENTITY)

    def test_11_subject_and_generation_are_server_authority(self):
        wrong_subject = rotate_active_session(P, (CURRENT,), candidate(subject="other"), NOW)
        wrong_generation = rotate_active_session(P, (CURRENT,), candidate(version=8), NOW)
        self.assertEqual(wrong_subject.decision, Decision.REJECT_IDENTITY)
        self.assertEqual(wrong_generation.decision, Decision.REJECT_AUTHORITY)

    def test_12_token_must_be_current_by_db_clock(self):
        cases = (
            candidate(iat=NOW + 1, nbf=NOW + 1),
            candidate(nbf=NOW + 1),
            candidate(exp=NOW),
        )
        for c in cases:
            with self.subTest(candidate=c):
                r = rotate_active_session(P, (CURRENT,), c, NOW)
                self.assertEqual(r.decision, Decision.REJECT_TOKEN_TIME)

    def test_13_multiple_live_sessions_is_contract_violation(self):
        bad = Session("second-live", SUB, 7, 1_910_000, 2_500_000)
        r = rotate_active_session(P, (CURRENT, bad), candidate(), NOW)
        self.assertEqual(r.decision, Decision.CONTRACT_VIOLATION)

    def test_14_same_key_with_mismatched_issued_time_is_contract_violation(self):
        c = candidate("s-current", iat=CURRENT.issued_at_ms + 1)
        r = rotate_active_session(P, (CURRENT,), c, NOW)
        self.assertEqual(r.decision, Decision.CONTRACT_VIOLATION)


if __name__ == "__main__":
    unittest.main(verbosity=2)
