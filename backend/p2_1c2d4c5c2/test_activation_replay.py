"""c5c.2 replay hardening. Inherit the original 20 cases unchanged, run once.

The new tests use actual PostgreSQL transactions/service credentials. Waiting is
proved through pg_blocking_pids, not assumed from a sleep. No new activation policy.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import time
import unittest
from uuid import uuid4

import psycopg
from psycopg import sql

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_activation_contract import ActivationContractTests, ACTIVATE_SQL, RUNTIME


class ActivationReplayTests(ActivationContractTests):
    def audit_snapshot(self, principal):
        return self.db('SELECT decision_id,principal_id,proof_id,from_auth_version,to_auth_version,recorded_at FROM echo_identity.activation_audit WHERE principal_id=%s',(principal,))

    def test_21_exact_replay_after_disable_is_not_current_authority(self):
        principal,_,_=self.fixture(); _,decision=self.activate(principal)
        audit=self.audit_snapshot(principal)
        self.db('UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s',(principal,))
        self.assert_db_error('ACTIVATION_REPLAY_STALE',lambda:self.activate(principal,decision))
        self.assertEqual(self.authority(principal),(False,False,False,3))
        self.assertEqual(self.audit_snapshot(principal),audit)

    def test_22_exact_replay_after_generation_or_role_change_denies(self):
        for assignment in ('auth_version=auth_version+1',
                           'writer_enabled=true,auth_version=auth_version+1',
                           'reviewer_enabled=true,auth_version=auth_version+1'):
            with self.subTest(assignment=assignment):
                principal,_,_=self.fixture(); _,decision=self.activate(principal)
                audit=self.audit_snapshot(principal)
                self.db('UPDATE echo_identity.principals SET '+assignment+' WHERE principal_id=%s',(principal,))
                current=self.authority(principal)
                self.assert_db_error('ACTIVATION_REPLAY_STALE',lambda:self.activate(principal,decision))
                self.assertEqual(self.authority(principal),current)
                self.assertEqual(self.audit_snapshot(principal),audit)

    def wait_blocked(self,waiter,holder,future):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            blocked=self.db('SELECT %s=ANY(pg_blocking_pids(%s))',(holder,waiter))[0]
            if blocked:
                return
            if future.done():
                self.fail('Operation returned before required Principal lock wait')
            time.sleep(0.01)
        self.fail('Expected PostgreSQL lock wait was not observed')

    def wait_both_queued(self,pids,futures):
        """Observe both requests in PostgreSQL's waiter queue.

        The second waiter may be reported as blocked by the first waiter rather than
        by the original row-lock holder, so requiring the holder PID for both is a
        false test assumption. Non-empty pg_blocking_pids for both proves that both
        requests reached the lock queue before the holder is released.
        """
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            waiting=[self.db('SELECT cardinality(pg_blocking_pids(%s)) > 0',(pid,))[0] for pid in pids]
            if all(waiting):
                return
            if any(f.done() for f in futures):
                self.fail('Operation returned before both requests entered the Principal lock queue')
            time.sleep(0.01)
        self.fail('Both activation requests were not observed in PostgreSQL lock queues')

    def service_attempt(self,c,principal,decision):
        try:
            c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(RUNTIME)))
            result=c.execute(ACTIVATE_SQL,(decision,principal,1)).fetchone()[0]
            c.commit()
            return ('OK',result)
        except psycopg.Error as error:
            c.rollback()
            return ('DENIED',str(error))
        finally:
            c.close()

    def test_23_identical_concurrent_decisions_return_one_result_and_one_replay(self):
        principal,_,_=self.fixture(); decision=uuid4()
        holder=self.admin(); first=self.service(); second=self.service()
        first_pid,second_pid=first.info.backend_pid,second.info.backend_pid
        pool=ThreadPoolExecutor(max_workers=2)
        try:
            holder.execute('SELECT principal_id FROM echo_identity.principals WHERE principal_id=%s FOR UPDATE',(principal,))
            futures=[pool.submit(self.service_attempt,c,principal,decision) for c in (first,second)]
            self.wait_both_queued((first_pid,second_pid),futures)
            holder.rollback()
            results=[f.result(timeout=8) for f in futures]
            self.assertEqual([r[0] for r in results],['OK','OK'])
            self.assertEqual(sorted(r[1]['replayed'] for r in results),[False,True])
            self.assertEqual({r[1]['decisionId'] for r in results},{str(decision)})
            self.assertEqual(self.authority(principal),(True,False,False,2))
            self.assertEqual(self.db('SELECT count(*) FROM echo_identity.activation_audit WHERE principal_id=%s',(principal,))[0],1)
            print('ACTIVATION_REPLAY_LOCK_OBSERVED identical_decisions',flush=True)
        finally:
            holder.rollback(); holder.close(); pool.shutdown(wait=True)
            for c in (first,second):
                if not c.closed: c.close()

    def test_24_disable_committing_while_replay_waits_must_be_seen(self):
        principal,_,_=self.fixture(); _,decision=self.activate(principal)
        audit=self.audit_snapshot(principal)
        holder=self.admin(); waiter=self.service(); pid=waiter.info.backend_pid
        pool=ThreadPoolExecutor(max_workers=1)
        try:
            holder.execute('UPDATE echo_identity.principals SET enabled=false,auth_version=auth_version+1 WHERE principal_id=%s',(principal,))
            future=pool.submit(self.service_attempt,waiter,principal,decision)
            self.wait_blocked(pid,holder.info.backend_pid,future)
            holder.commit()
            result=future.result(timeout=8)
            self.assertEqual(result[0],'DENIED')
            self.assertIn('ACTIVATION_REPLAY_STALE',result[1])
            self.assertEqual(self.authority(principal),(False,False,False,3))
            self.assertEqual(self.audit_snapshot(principal),audit)
            print('ACTIVATION_REPLAY_LOCK_OBSERVED disable_first',flush=True)
        finally:
            holder.rollback(); holder.close(); pool.shutdown(wait=True)
            if not waiter.closed: waiter.close()

    def test_25_audit_insert_failure_rolls_back_authority_update(self):
        principal,_,_=self.fixture(); decision=uuid4()
        # Fault after the real UPDATE but before its paired audit INSERT completes.
        self.db('''CREATE FUNCTION echo_identity.test_fail_activation_audit() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'AUDIT_PROBE_FAILURE'; END $$;
            CREATE TRIGGER test_audit_failure BEFORE INSERT ON echo_identity.activation_audit
            FOR EACH ROW EXECUTE FUNCTION echo_identity.test_fail_activation_audit();''')
        try:
            self.assert_db_error('AUDIT_PROBE_FAILURE',lambda:self.activate(principal,decision))
            self.assertEqual(self.authority(principal),(False,False,False,1))
            self.assertIsNone(self.audit_snapshot(principal))
        finally:
            self.db('DROP TRIGGER test_audit_failure ON echo_identity.activation_audit; DROP FUNCTION echo_identity.test_fail_activation_audit();')
        self.activate(principal,decision)
        self.assertEqual(self.authority(principal),(True,False,False,2))

    def test_26_activation_runtime_cannot_truncate_or_forge_audit(self):
        principal,_,_=self.fixture(); self.activate(principal); audit=self.audit_snapshot(principal)
        for statement in ('TRUNCATE echo_identity.activation_audit',
                          'INSERT INTO echo_identity.activation_audit DEFAULT VALUES',
                          'UPDATE echo_identity.activation_audit SET recorded_at=clock_timestamp()',
                          'DELETE FROM echo_identity.activation_audit'):
            def try_statement():
                with self.service() as c:
                    c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(RUNTIME)))
                    c.execute(statement)
            with self.subTest(statement=statement):
                self.assert_db_error('permission denied',try_statement)
        self.assertEqual(self.audit_snapshot(principal),audit)

    def test_27_explicit_rollback_removes_both_activation_and_audit(self):
        principal,_,_=self.fixture(); decision=uuid4()
        with self.service() as c:
            c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(RUNTIME)))
            c.execute(ACTIVATE_SQL,(decision,principal,1)).fetchone()
            c.rollback()
        self.assertEqual(self.authority(principal),(False,False,False,1))
        self.assertIsNone(self.audit_snapshot(principal))
        result,_=self.activate(principal,decision)
        self.assertFalse(result['replayed'])


def load_tests(loader,standard_tests,pattern):
    return loader.loadTestsFromTestCase(ActivationReplayTests)


if __name__=='__main__':
    unittest.main(verbosity=2)
