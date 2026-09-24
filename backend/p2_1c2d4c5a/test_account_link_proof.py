from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import time
import unittest
from uuid import UUID, uuid4

import psycopg

DB_NAME = 'echo_account_link_proof_test'
ISSUER = 'https://issuer.account-link.fixture.invalid/echo'
LINK_RUNTIME = 'echo_account_link_runtime'
LINK_GUARD = 'echo_account_link_guard'
MUTATION_RUNTIME = 'echo_identity_mutation_runtime'
REGISTRY_RUNTIME = 'echo_identity_registry_runtime'

ISSUE = '''SELECT echo_identity.runtime_issue_account_link_proof(
    %s,%s,%s,%s,%s,%s,%s)'''
PROVISION = '''SELECT echo_identity.runtime_provision_principal_with_link_proof(
    %s,%s,%s,%s)'''
RAW_PROVISION = '''SELECT echo_identity.runtime_provision_principal(
    %s,%s,%s,%s,%s)'''


class AccountLinkProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get('ECHO_DISPOSABLE_PG') != 'YES'
                or os.environ.get('PGDATABASE') != DB_NAME
                or os.environ.get('PGHOST') not in ('127.0.0.1', 'localhost')):
            raise RuntimeError('refusing non-disposable account-link proof database')
        with cls.admin() as c:
            version = int(c.execute('SHOW server_version_num').fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError('account-link proof gate requires PostgreSQL 17')
            installed = c.execute('''SELECT
                to_regclass('echo_identity.account_subject_bindings') IS NOT NULL AND
                to_regclass('echo_identity.account_link_proofs') IS NOT NULL AND
                to_regrole(%s) IS NOT NULL AND to_regrole(%s) IS NOT NULL AND
                to_regprocedure('echo_identity.runtime_issue_account_link_proof(uuid,text,text,bigint,bigint,bigint,bigint)') IS NOT NULL AND
                to_regprocedure('echo_identity.runtime_provision_principal_with_link_proof(uuid,uuid,text,text)') IS NOT NULL''',
                (LINK_RUNTIME, LINK_GUARD)).fetchone()[0]
            if not installed:
                raise RuntimeError('account-link proof migration not installed')
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def admin():
        return psycopg.connect(connect_timeout=3)

    @classmethod
    def role(cls, role: str):
        c = cls.admin()
        c.execute(f'SET SESSION AUTHORIZATION {role}')
        c.commit()
        return c

    @classmethod
    def cleanup(cls):
        with cls.admin() as c:
            c.execute('DROP SCHEMA echo_identity CASCADE')
            c.execute('DROP SCHEMA echo_core CASCADE')
            for role in (
                LINK_RUNTIME, LINK_GUARD,
                'echo_identity_mutation_service', MUTATION_RUNTIME, 'echo_identity_mutation_guard',
                'echo_identity_registry_service', REGISTRY_RUNTIME, 'echo_identity_registry_guard',
            ):
                c.execute(f'DROP ROLE IF EXISTS {role}')
        print('CLEAN_ACCOUNT_LINK_PROOF_DATABASE', flush=True)

    @staticmethod
    def window(*, proof_ms: int = 60_000):
        now = int(time.time() * 1000)
        return now - 1000, now - 500, now + 120_000, now + proof_ms

    @classmethod
    def issue(cls, *, subject: str | None = None, proof_id: UUID | None = None,
              proof_ms: int = 60_000):
        subject = subject or ('subject-' + uuid4().hex)
        proof_id = proof_id or uuid4()
        times = cls.window(proof_ms=proof_ms)
        with cls.role(LINK_RUNTIME) as c:
            value = c.execute(ISSUE, (proof_id, ISSUER, subject, *times)).fetchone()[0]
        return value, times

    @classmethod
    def provision(cls, principal_id: UUID, proof_id: UUID, subject: str):
        with cls.role(MUTATION_RUNTIME) as c:
            return c.execute(PROVISION, (principal_id, proof_id, ISSUER, subject)).fetchone()[0]

    def test_01_link_runtime_has_no_direct_registry_or_core_table_access(self):
        with self.admin() as c:
            for role in (LINK_RUNTIME, MUTATION_RUNTIME):
                for table in ('echo_identity.account_subject_bindings',
                              'echo_identity.account_link_proofs',
                              'echo_core.actors', 'echo_core.sources'):
                    self.assertFalse(c.execute(
                        "SELECT has_table_privilege(%s,%s,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')",
                        (role, table)).fetchone()[0], (role, table))

    def test_02_issue_function_accepts_no_actor_or_source_identifier(self):
        with self.admin() as c:
            args = c.execute('''SELECT pg_get_function_identity_arguments(
                'echo_identity.runtime_issue_account_link_proof(uuid,text,text,bigint,bigint,bigint,bigint)'::regprocedure)''').fetchone()[0]
        self.assertEqual(args, 'p_proof_id uuid, p_issuer text, p_subject text, p_token_issued_ms bigint, p_token_not_before_ms bigint, p_token_expires_ms bigint, p_proof_expires_ms bigint')

    def test_03_issue_generates_new_actor_and_source_server_side(self):
        subject = 'generated-' + uuid4().hex
        value, _ = self.issue(subject=subject)
        actor = UUID(value['actorId']); source = UUID(value['sourceId'])
        self.assertNotEqual(actor, source)
        with self.admin() as c:
            row = c.execute('''SELECT b.actor_id,b.source_id,a.actor_kind,s.source_kind
                 FROM echo_identity.account_subject_bindings b
                 JOIN echo_core.actors a USING(actor_id)
                 JOIN echo_core.sources s USING(source_id)
                 WHERE b.issuer=%s AND b.subject=%s''', (ISSUER, subject)).fetchone()
        self.assertEqual(row, (actor, source, 'HUMAN', 'ACCOUNT'))

    def test_04_same_subject_reuses_binding_across_distinct_proofs(self):
        subject = 'stable-' + uuid4().hex
        first, _ = self.issue(subject=subject)
        second, _ = self.issue(subject=subject)
        self.assertNotEqual(first['proofId'], second['proofId'])
        self.assertEqual((first['actorId'], first['sourceId']),
                         (second['actorId'], second['sourceId']))

    def test_05_different_subjects_receive_distinct_actor_source_pairs(self):
        first, _ = self.issue(subject='a-' + uuid4().hex)
        second, _ = self.issue(subject='b-' + uuid4().hex)
        self.assertNotEqual(first['actorId'], second['actorId'])
        self.assertNotEqual(first['sourceId'], second['sourceId'])

    def test_06_exact_proof_issue_retry_is_idempotent(self):
        subject = 'issue-retry-' + uuid4().hex
        proof_id = uuid4(); times = self.window()
        with self.role(LINK_RUNTIME) as c:
            first = c.execute(ISSUE, (proof_id, ISSUER, subject, *times)).fetchone()[0]
        with self.role(LINK_RUNTIME) as c:
            second = c.execute(ISSUE, (proof_id, ISSUER, subject, *times)).fetchone()[0]
        self.assertEqual(first, second)

    def test_07_same_proof_id_cannot_be_retargeted(self):
        proof_id = uuid4(); first_subject = 'proof-owner-' + uuid4().hex
        self.issue(subject=first_subject, proof_id=proof_id)
        times = self.window()
        with self.assertRaises(psycopg.Error):
            with self.role(LINK_RUNTIME) as c:
                c.execute(ISSUE, (proof_id, ISSUER, 'other-' + uuid4().hex, *times)).fetchone()

    def test_08_proof_lifetime_is_capped_at_five_minutes_and_token_expiry(self):
        now = int(time.time() * 1000)
        with self.assertRaises(psycopg.Error):
            with self.role(LINK_RUNTIME) as c:
                c.execute(ISSUE, (uuid4(), ISSUER, 'ttl-' + uuid4().hex,
                                  now-1000, now-500, now+900_000, now+600_000)).fetchone()
        with self.assertRaises(psycopg.Error):
            with self.role(LINK_RUNTIME) as c:
                c.execute(ISSUE, (uuid4(), ISSUER, 'token-exp-' + uuid4().hex,
                                  now-1000, now-500, now+20_000, now+30_000)).fetchone()

    def test_09_mutation_runtime_cannot_use_raw_actor_source_provisioner_after_c5a(self):
        with self.assertRaises(psycopg.Error):
            with self.role(MUTATION_RUNTIME) as c:
                c.execute(RAW_PROVISION, (uuid4(), ISSUER, 'raw-' + uuid4().hex,
                                          uuid4(), uuid4())).fetchone()

    def test_10_link_runtime_cannot_consume_or_provision(self):
        subject = 'link-no-provision-' + uuid4().hex
        proof, _ = self.issue(subject=subject)
        with self.assertRaises(psycopg.Error):
            with self.role(LINK_RUNTIME) as c:
                c.execute(PROVISION, (uuid4(), UUID(proof['proofId']), ISSUER, subject)).fetchone()

    def test_11_mutation_runtime_cannot_issue_link_proof(self):
        now = self.window()
        with self.assertRaises(psycopg.Error):
            with self.role(MUTATION_RUNTIME) as c:
                c.execute(ISSUE, (uuid4(), ISSUER, 'mutation-no-issue-' + uuid4().hex, *now)).fetchone()

    def test_12_live_proof_provisions_principal_with_exact_bound_actor_source(self):
        subject = 'provision-' + uuid4().hex
        proof, _ = self.issue(subject=subject)
        principal = uuid4()
        result = self.provision(principal, UUID(proof['proofId']), subject)
        self.assertEqual(UUID(result['principalId']), principal)
        self.assertFalse(result['enabled'])
        with self.admin() as c:
            row = c.execute('''SELECT p.actor_id,p.source_id,l.consumed_principal_id,l.consumed_at IS NOT NULL
                 FROM echo_identity.principals p
                 JOIN echo_identity.account_link_proofs l ON l.proof_id=%s
                 WHERE p.principal_id=%s''', (UUID(proof['proofId']), principal)).fetchone()
        self.assertEqual((str(row[0]), str(row[1])), (proof['actorId'], proof['sourceId']))
        self.assertEqual((row[2], row[3]), (principal, True))

    def test_13_provision_rejects_issuer_or_subject_mismatch_without_consuming(self):
        subject = 'mismatch-' + uuid4().hex
        proof, _ = self.issue(subject=subject); proof_id = UUID(proof['proofId'])
        with self.assertRaises(psycopg.Error):
            with self.role(MUTATION_RUNTIME) as c:
                c.execute(PROVISION, (uuid4(), proof_id, ISSUER, 'wrong-' + uuid4().hex)).fetchone()
        with self.admin() as c:
            consumed = c.execute('SELECT consumed_at FROM echo_identity.account_link_proofs WHERE proof_id=%s',
                                 (proof_id,)).fetchone()[0]
        self.assertIsNone(consumed)

    def test_14_consumed_proof_exact_same_principal_retry_is_idempotent(self):
        subject = 'consume-retry-' + uuid4().hex
        proof, _ = self.issue(subject=subject); proof_id = UUID(proof['proofId']); principal = uuid4()
        first = self.provision(principal, proof_id, subject)
        second = self.provision(principal, proof_id, subject)
        self.assertEqual(first, second)
        with self.admin() as c:
            count = c.execute('SELECT count(*) FROM echo_identity.principals WHERE issuer=%s AND subject=%s',
                              (ISSUER, subject)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_15_consumed_proof_cannot_create_second_principal(self):
        subject = 'single-use-' + uuid4().hex
        proof, _ = self.issue(subject=subject); proof_id = UUID(proof['proofId'])
        self.provision(uuid4(), proof_id, subject)
        with self.assertRaises(psycopg.Error):
            self.provision(uuid4(), proof_id, subject)

    def test_16_expired_unconsumed_proof_cannot_provision(self):
        subject = 'expires-' + uuid4().hex
        proof, _ = self.issue(subject=subject, proof_ms=700)
        time.sleep(0.9)
        with self.assertRaises(psycopg.Error):
            self.provision(uuid4(), UUID(proof['proofId']), subject)

    def test_17_concurrent_first_issue_serializes_to_one_binding(self):
        subject = 'race-' + uuid4().hex
        def worker(_):
            return self.issue(subject=subject)[0]
        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = list(pool.map(worker, range(2)))
        self.assertEqual((first['actorId'], first['sourceId']),
                         (second['actorId'], second['sourceId']))
        with self.admin() as c:
            count = c.execute('SELECT count(*) FROM echo_identity.account_subject_bindings WHERE issuer=%s AND subject=%s',
                              (ISSUER, subject)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_18_mutation_runtime_allowlist_contains_wrapper_not_raw_provision(self):
        with self.admin() as c:
            allowed = c.execute('''SELECT p.oid::regprocedure::text
                FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='echo_identity' AND has_function_privilege(%s,p.oid,'EXECUTE')
                ORDER BY 1''', (MUTATION_RUNTIME,)).fetchall()
        names = {row[0] for row in allowed}
        self.assertIn('echo_identity.runtime_provision_principal_with_link_proof(uuid,uuid,text,text)', names)
        self.assertNotIn('echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)', names)
        self.assertIn('echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)', names)
        self.assertIn('echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)', names)
        self.assertIn('echo_identity.runtime_revoke_session(text,uuid)', names)

    def test_19_unrelated_registry_runtime_cannot_issue_or_consume_proof(self):
        subject = 'registry-denied-' + uuid4().hex
        times = self.window(); proof_id = uuid4()
        with self.assertRaises(psycopg.Error):
            with self.role(REGISTRY_RUNTIME) as c:
                c.execute(ISSUE, (proof_id, ISSUER, subject, *times)).fetchone()
        with self.assertRaises(psycopg.Error):
            with self.role(REGISTRY_RUNTIME) as c:
                c.execute(PROVISION, (uuid4(), proof_id, ISSUER, subject)).fetchone()

    def test_20_guard_and_runtime_roles_are_nonlogin_nonadmin_nobypassrls(self):
        with self.admin() as c:
            rows = c.execute('''SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,
                    rolcreaterole,rolreplication,rolbypassrls
                FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname''',
                ([LINK_GUARD, LINK_RUNTIME],)).fetchall()
        self.assertEqual(rows, [
            (LINK_GUARD, False, False, False, False, False, False, False),
            (LINK_RUNTIME, False, False, False, False, False, False, False),
        ])


if __name__ == '__main__':
    unittest.main(verbosity=2)
