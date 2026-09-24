"""c5c.6 bounded identity lifecycle integration on real restricted service boundaries.

Reuses the proven c5b/c5c.1/c5c.2/c5c.3/c5c.4/c5c.5a/c5c.5b.2
components without adding HTTP, refresh tokens, or production credentials.
The inherited 92 cases stay intact; this file adds exactly 3 end-to-end methods.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import sys
import time
from uuid import uuid4

from psycopg import sql

HERE = Path(__file__).resolve().parent
sys.path[:0] = [
    str(HERE),
    str(HERE.parent / "p2_1c2d4c5b"),
    str(HERE.parent / "p2_1c2d4c5c1"),
    str(HERE.parent / "p2_1c2d4c5c5b2"),
]
import test_atomic_rotation as rotation_base
from account_link_boundary import SignedAccountLinkBoundary
from account_link_pool import AccountLinkPool, SERVICE as LINK_SERVICE
from principal_boundary import SignedPrincipalBoundary
from principal_pool import PrincipalPool, SERVICE as PRINCIPAL_SERVICE
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key

ISSUER = rotation_base.ISSUER
DB = rotation_base.baseline.first_base.DB


class BoundedIdentityLifecycleTests(rotation_base.AtomicRotationTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.lifecycle_link_password = secrets.token_urlsafe(32)
        cls.lifecycle_principal_password = secrets.token_urlsafe(32)
        with cls.admin() as c:
            for role, password in (
                (LINK_SERVICE, cls.lifecycle_link_password),
                (PRINCIPAL_SERVICE, cls.lifecycle_principal_password),
            ):
                c.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(password)
                    )
                )
        common = dict(
            host="127.0.0.1",
            port=int(os.environ.get("PGPORT", "5432")),
            dbname=DB,
            sslmode="disable",
            max_size=2,
            allow_insecure_test_loopback=True,
        )
        cls.lifecycle_link_pool = AccountLinkPool(
            **common, user=LINK_SERVICE, password=cls.lifecycle_link_password
        )
        cls.lifecycle_principal_pool = PrincipalPool(
            **common, user=PRINCIPAL_SERVICE, password=cls.lifecycle_principal_password
        )
        cls.lifecycle_link_pool.open()
        cls.lifecycle_principal_pool.open()
        cls.lifecycle_link = SignedAccountLinkBoundary(
            cls.config, cls.lifecycle_link_pool.connection
        )
        cls.lifecycle_principal = SignedPrincipalBoundary(
            cls.config, cls.lifecycle_principal_pool.connection
        )

    @classmethod
    def cleanup(cls):
        for name in ("lifecycle_principal_pool", "lifecycle_link_pool"):
            pool = getattr(cls, name, None)
            if pool is not None:
                pool.close()
        super().cleanup()
        print("CLEAN_BOUNDED_IDENTITY_LIFECYCLE_DATABASE", flush=True)

    def lifecycle_token(self, subject: str, issued_offset: int):
        now = int(time.time())
        issued = now + issued_offset
        return self.token(
            subject,
            extra={"iat": issued, "nbf": issued, "exp": now + 180},
        )

    def signed_onboard(self, subject: str | None = None):
        subject = subject or ("lifecycle-" + uuid4().hex)
        token, claims = self.lifecycle_token(subject, -30)
        authorization = "Bearer " + token
        proof = self.lifecycle_link.issue(authorization, b"{}")
        principal = self.lifecycle_principal.provision(
            authorization,
            json.dumps(
                {"proof_id": str(proof.proof_id)}, separators=(",", ":")
            ).encode(),
        )
        return {
            "subject": subject,
            "token": token,
            "claims": claims,
            "proof": proof,
            "principal": principal.principal_id,
            "key": derive_session_key(ISSUER, claims["jti"]),
        }

    def registry_binding(self, subject: str, claims: dict):
        return PostgresRegistryAdapter(self.admin).resolve_binding(
            ISSUER, subject, claims["jti"]
        )

    def principal_authority(self, principal):
        return self.db(
            """SELECT enabled,writer_enabled,reviewer_enabled,auth_version
                 FROM echo_identity.principals WHERE principal_id=%s""",
            (principal,),
        )

    def test_93_full_bounded_lifecycle_uses_current_authority_at_every_transition(self):
        f = self.signed_onboard()
        self.assertEqual(self.principal_authority(f["principal"]), (False, False, False, 1))
        self.assertEqual(
            self.db(
                """SELECT consumed_principal_id=%s
                     FROM echo_identity.account_link_proofs WHERE proof_id=%s""",
                (f["principal"], f["proof"].proof_id),
            ),
            (True,),
        )

        activated = self.activate(f["principal"])
        self.assertEqual(
            (activated["enabled"], activated["authVersion"]), (True, 2)
        )
        first = self.boundary.bootstrap("Bearer " + f["token"], b"{}")
        self.assertFalse(first.replayed)
        self.assertEqual(first.auth_version, 2)
        self.assertEqual(
            self.registry_binding(f["subject"], f["claims"]).principal_id,
            f["principal"],
        )

        token2, claims2 = self.lifecycle_token(f["subject"], -20)
        rotated = {
            **f,
            "token": token2,
            "claims": claims2,
            "key": derive_session_key(ISSUER, claims2["jti"]),
        }
        receipt = self.rotate(rotated)
        self.assertFalse(receipt.replayed)
        self.assertIsNone(self.registry_binding(f["subject"], f["claims"]))
        self.assertEqual(
            self.registry_binding(f["subject"], claims2).principal_id,
            f["principal"],
        )
        self.assertEqual(self.current_active_count(f["principal"]), 1)

        self.logout(rotated)
        self.assertIsNone(self.registry_binding(f["subject"], claims2))
        self.assertEqual(self.current_active_count(f["principal"]), 0)

        token3, claims3 = self.lifecycle_token(f["subject"], -10)
        repeat = self.repeat(f["subject"], token3)
        self.assertFalse(repeat.replayed)
        self.assertEqual(repeat.auth_version, 2)
        self.assertEqual(
            self.registry_binding(f["subject"], claims3).principal_id,
            f["principal"],
        )
        self.assertEqual(self.current_active_count(f["principal"]), 1)
        self.assertEqual(
            self.db(
                "SELECT count(*) FROM echo_identity.activation_audit WHERE principal_id=%s",
                (f["principal"],),
            ),
            (1,),
        )
        self.assertEqual(
            self.db(
                "SELECT count(*) FROM echo_identity.session_rotations WHERE principal_id=%s",
                (f["principal"],),
            ),
            (1,),
        )

    def test_94_historical_provision_receipt_never_resurrects_logged_out_session(self):
        f = self.signed_onboard()
        self.activate(f["principal"])
        self.boundary.bootstrap("Bearer " + f["token"], b"{}")
        self.logout(f)
        self.assertIsNone(self.registry_binding(f["subject"], f["claims"]))

        replayed_principal = self.lifecycle_principal.provision(
            "Bearer " + f["token"],
            json.dumps(
                {"proof_id": str(f["proof"].proof_id)}, separators=(",", ":")
            ).encode(),
        )
        self.assertEqual(replayed_principal.principal_id, f["principal"])
        self.assertEqual(self.current_active_count(f["principal"]), 0)
        self.assert_error(
            "FIRST_SESSION_REJECTED",
            lambda: self.boundary.bootstrap("Bearer " + f["token"], b"{}"),
        )
        self.repeat_denied(lambda: self.repeat(f["subject"], f["token"]))

        fresh_token, fresh_claims = self.lifecycle_token(f["subject"], -10)
        fresh = self.repeat(f["subject"], fresh_token)
        self.assertFalse(fresh.replayed)
        self.assertEqual(
            self.registry_binding(f["subject"], fresh_claims).principal_id,
            f["principal"],
        )
        self.assertEqual(self.current_active_count(f["principal"]), 1)

    def test_95_two_accounts_remain_isolated_across_rotation_logout_and_repeat_login(self):
        a = self.signed_onboard("account-a-" + uuid4().hex)
        b = self.signed_onboard("account-b-" + uuid4().hex)
        for f in (a, b):
            self.activate(f["principal"])
            self.boundary.bootstrap("Bearer " + f["token"], b"{}")
        self.assertNotEqual(a["principal"], b["principal"])

        a2_token, a2_claims = self.lifecycle_token(a["subject"], -20)
        a2 = {
            **a,
            "token": a2_token,
            "claims": a2_claims,
            "key": derive_session_key(ISSUER, a2_claims["jti"]),
        }
        self.rotate(a2)
        self.assertEqual(
            self.registry_binding(b["subject"], b["claims"]).principal_id,
            b["principal"],
        )
        self.assertEqual(self.current_active_count(b["principal"]), 1)

        self.logout(a2)
        a3_token, a3_claims = self.lifecycle_token(a["subject"], -10)
        self.repeat(a["subject"], a3_token)
        self.assertEqual(
            self.registry_binding(a["subject"], a3_claims).principal_id,
            a["principal"],
        )
        self.assertEqual(
            self.registry_binding(b["subject"], b["claims"]).principal_id,
            b["principal"],
        )
        self.assertEqual(
            (
                self.current_active_count(a["principal"]),
                self.current_active_count(b["principal"]),
            ),
            (1, 1),
        )


if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)
