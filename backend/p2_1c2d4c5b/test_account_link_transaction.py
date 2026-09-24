"""Account-link transaction gate: retain all 18 c5b cases and add two regressions.

Both new cases use the real service LOGIN/pool and PostgreSQL writes. The receipt
fault is injected only AFTER the real SQL function returns; signature checking is
never mocked. The expiry race is ordered using observed pg_blocking_pids.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from queue import Queue
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_signed_account_link as baseline
from account_link_boundary import ISSUE_SQL, SignedAccountLinkBoundary


class AccountLinkTransactionTests(baseline.SignedAccountLinkTests):
    def state_counts(self):
        with self.admin() as c:
            return c.execute('''SELECT
                (SELECT count(*) FROM echo_identity.account_link_proofs),
                (SELECT count(*) FROM echo_identity.account_subject_bindings),
                (SELECT count(*) FROM echo_core.actors),
                (SELECT count(*) FROM echo_core.sources)''').fetchone()

    def test_19_invalid_receipt_rolls_back_real_proof_and_new_binding(self):
        before = self.state_counts()

        class FaultedCursor:
            def __init__(self, cursor):
                self.cursor = cursor

            def fetchone(self):
                row = self.cursor.fetchone()
                value = dict(row[0])
                value['subject'] = 'receipt-contract-fault-not-the-signed-subject'
                return (value,)

        class FaultedConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, statement, params=None, **kwargs):
                cursor = self.connection.execute(statement, params, **kwargs)
                return FaultedCursor(cursor) if statement == ISSUE_SQL else cursor

        @contextmanager
        def faulted_lease():
            with self.pool.connection() as c:
                yield FaultedConnection(c)

        boundary = SignedAccountLinkBoundary(self.config, faulted_lease)
        token = self.auth(self.token(self.subject('receipt-rollback')))
        self.assert_error('ACCOUNT_LINK_CONTRACT_VIOLATION', lambda: boundary.issue(token, b'{}'))
        self.assertEqual(self.state_counts(), before,
                         'Denied receipt must roll back proof, binding, Actor and Source')
        # The failed lease must not poison a subsequent borrower.
        good = self.boundary.issue(self.auth(self.token(self.subject('after-contract-error'))), b'{}')
        self.assertGreater(good.expires_at_ms, int(time.time() * 1000))

    def test_20_token_expiring_during_observed_db_lock_wait_rolls_back(self):
        subject = self.subject('expiry-lock')
        before = self.state_counts()
        holder = self.admin()
        executor = ThreadPoolExecutor(max_workers=1)
        borrower_pids = Queue(maxsize=1)

        @contextmanager
        def observed_lease():
            with self.pool.connection() as c:
                # Trusted fixture-only timeout extension keeps the expiry test
                # distinct from the pool's ordinary three-second lock timeout.
                c.execute("SET LOCAL lock_timeout='8s'")
                c.execute("SET LOCAL statement_timeout='12s'")
                borrower_pids.put(c.info.backend_pid)
                yield c

        boundary = SignedAccountLinkBoundary(self.config, observed_lease)
        try:
            holder.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s || chr(31) || %s,0))',
                           (baseline.ISSUER, subject))
            # Decode with signature verification in the fixture only, to know
            # when to release the observed lock. The product verifier runs too.
            token = self.token(subject, lifetime=3)
            claims = baseline.jwt.decode(token, self.key.public_key(), algorithms=['RS256'],
                                         issuer=baseline.ISSUER, audience=baseline.AUD)
            future = executor.submit(boundary.issue, self.auth(token), b'{}')
            waiter = borrower_pids.get(timeout=5)
            deadline = time.monotonic() + 5
            observed = False
            while time.monotonic() < deadline:
                with self.admin() as observer:
                    observed = observer.execute('SELECT %s=ANY(pg_blocking_pids(%s))',
                                                (holder.info.backend_pid, waiter)).fetchone()[0]
                if observed:
                    break
                if future.done():
                    self.fail('Proof operation finished before expected DB lock wait')
                time.sleep(0.01)
            self.assertTrue(observed, 'The advisory lock wait must be observed, not guessed')
            with self.admin() as observer:
                observer.execute('SELECT pg_sleep(GREATEST(0,%s-extract(epoch FROM clock_timestamp())+0.05))',
                                 (claims['exp'],))
            holder.rollback()
            self.assert_error('IDENTITY_REJECTED', lambda: future.result(timeout=10))
            self.assertEqual(self.state_counts(), before,
                             'Expired token must leave no proof, binding, Actor or Source')
            print('ACCOUNT_LINK_EXPIRY_LOCK_WAIT_OBSERVED', flush=True)
        finally:
            holder.rollback()
            holder.close()
            executor.shutdown(wait=True)


def load_tests(loader, standard_tests, pattern):
    # Inherited original cases run once, not as a second separately counted suite.
    return loader.loadTestsFromTestCase(AccountLinkTransactionTests)


if __name__ == '__main__':
    unittest.main(verbosity=2)
