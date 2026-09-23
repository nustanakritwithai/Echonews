#!/usr/bin/env python3
"""P2.1c.2d.2 real PostgreSQL least-privilege/no-bypass contract.

Disposable loopback database only. Synthetic LOGIN roles prove that actual
connection principals cannot bypass the server-owned execution capsule.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
import unittest
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[2]
DB = os.environ.get("PGDATABASE", "")
HOST = os.environ.get("PGHOST", "")
PORT = int(os.environ.get("PGPORT", "5432"))
ADMIN = os.environ.get("PGUSER", "echo_test")
ADMIN_PASSWORD = os.environ.get("PGPASSWORD", "")
OWNER = "echo_execution_owner_test"
AUTH = "echo_auth_bridge_test"
RUNTIME = "echo_runtime_writer_test"
AUTH_PASSWORD = "disposable_auth_bridge_only"
RUNTIME_PASSWORD = "disposable_runtime_only"
ISSUER = "https://identity.example.test"
MINT_SIG = "echo_execution.mint_private_draft_ticket(uuid,uuid,text,text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)"
EXEC_SIG = "echo_execution.execute_private_draft_probe(uuid)"
FENCE_SIG = "echo_identity.assert_private_draft_fence(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)"


def connect(user=ADMIN, password=ADMIN_PASSWORD, autocommit=True):
    return psycopg.connect(host=HOST, port=PORT, dbname=DB, user=user, password=password,
                           connect_timeout=5, autocommit=autocommit)


def scalar(conn, query, params=()):
    with conn.cursor() as cur:
        cur.execute(query, params)
        row = cur.fetchone()
        return None if row is None else row[0]


class LeastPrivilegeBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("ECHO_DISPOSABLE_PG") != "YES" or DB != "echo_least_priv_test" or HOST not in {"127.0.0.1", "localhost"}:
            raise RuntimeError("Refusing destructive auth test outside loopback echo_least_priv_test")
        cls.admin = connect()
        if scalar(cls.admin, "SELECT current_database()") != "echo_least_priv_test":
            raise RuntimeError("wrong disposable database")
        if not scalar(cls.admin, "SELECT to_regnamespace('echo_core') IS NULL AND to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_execution') IS NULL"):
            raise RuntimeError("test database is not empty")
        if scalar(cls.admin, "SELECT count(*) FROM pg_roles WHERE rolname = ANY(%s)", ([OWNER, AUTH, RUNTIME],)) != 0:
            raise RuntimeError("test roles already exist")

        for path in [
            ROOT / "database/p2_1b/schema.sql",
            ROOT / "database/p2_1c2c/001_identity_registry.sql",
            ROOT / "database/p2_1c2d1/001_write_fence.sql",
            ROOT / "database/p2_1c2d2/001_least_privilege_boundary.sql",
        ]:
            cls.admin.execute(path.read_text(encoding="utf-8"))

        cls.admin.execute(f"""
          CREATE ROLE {OWNER} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
          CREATE ROLE {AUTH} LOGIN PASSWORD '{AUTH_PASSWORD}' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
          CREATE ROLE {RUNTIME} LOGIN PASSWORD '{RUNTIME_PASSWORD}' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
          ALTER FUNCTION {MINT_SIG} OWNER TO {OWNER};
          ALTER FUNCTION {EXEC_SIG} OWNER TO {OWNER};
          GRANT USAGE ON SCHEMA echo_identity, echo_execution TO {OWNER};
          GRANT SELECT ON echo_identity.principals, echo_identity.sessions TO {OWNER};
          GRANT EXECUTE ON FUNCTION {FENCE_SIG} TO {OWNER};
          GRANT INSERT, SELECT ON echo_execution.private_draft_tickets TO {OWNER};
          GRANT UPDATE(consumed_ms) ON echo_execution.private_draft_tickets TO {OWNER};
          GRANT INSERT ON echo_execution.private_draft_probe TO {OWNER};
          GRANT USAGE ON SCHEMA echo_execution TO {AUTH}, {RUNTIME};
          GRANT EXECUTE ON FUNCTION {MINT_SIG} TO {AUTH};
          GRANT EXECUTE ON FUNCTION {EXEC_SIG} TO {RUNTIME};
        """)

    @classmethod
    def tearDownClass(cls):
        try:
            if hasattr(cls, "admin") and not cls.admin.closed:
                if scalar(cls.admin, "SELECT to_regnamespace('echo_core') IS NOT NULL"):
                    if scalar(cls.admin, "SELECT count(*) FROM echo_core.voice_revisions") != 0:
                        raise AssertionError("least-privilege suite unexpectedly wrote a Voice row")
                cls.admin.execute("DROP SCHEMA IF EXISTS echo_execution CASCADE; DROP SCHEMA IF EXISTS echo_identity CASCADE; DROP SCHEMA IF EXISTS echo_core CASCADE;")
                for role in [AUTH, RUNTIME, OWNER]:
                    if scalar(cls.admin, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)", (role,)):
                        cls.admin.execute(sql.SQL("DROP OWNED BY {};").format(sql.Identifier(role)))
                        cls.admin.execute(sql.SQL("DROP ROLE {};").format(sql.Identifier(role)))
                if not scalar(cls.admin, "SELECT to_regnamespace('echo_core') IS NULL AND to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_execution') IS NULL"):
                    raise AssertionError("schema cleanup failed")
                if scalar(cls.admin, "SELECT count(*) FROM pg_roles WHERE rolname = ANY(%s)", ([OWNER, AUTH, RUNTIME],)) != 0:
                    raise AssertionError("role cleanup failed")
                print("CLEAN_LEAST_PRIVILEGE_DATABASE")
        finally:
            if hasattr(cls, "admin"):
                cls.admin.close()

    def assert_sqlstate(self, fn, state="42501"):
        with self.assertRaises(psycopg.Error) as ctx:
            fn()
        self.assertEqual(ctx.exception.sqlstate, state, str(ctx.exception))

    def fixture(self, *, writer=True):
        now = int(time.time() * 1000)
        actor, source, principal = uuid4(), uuid4(), uuid4()
        subject = f"fixture-{uuid4()}"
        key = hashlib.sha256(uuid4().bytes).hexdigest()
        self.admin.execute("INSERT INTO echo_core.actors VALUES (%s,'HUMAN','Synthetic least-privilege actor',clock_timestamp())", (actor,))
        self.admin.execute("INSERT INTO echo_core.sources VALUES (%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())", (source,))
        self.admin.execute("""INSERT INTO echo_identity.principals
          (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled)
          VALUES(%s,%s,%s,%s,%s,true,%s,false)""", (principal, ISSUER, subject, actor, source, writer))
        self.admin.execute("""INSERT INTO echo_identity.sessions
          (session_key,principal_id,auth_version,issued_at,expires_at)
          VALUES(%s,%s,1,to_timestamp(%s/1000.0),to_timestamp(%s/1000.0))""",
          (key, principal, now - 10000, now + 300000))
        return {"actor":actor,"source":source,"principal":principal,"subject":subject,"key":key,
                "iat":now-5000,"nbf":now-5000,"exp":now+120000}

    def mint(self, f, *, ticket=None, command=None, payload=None, actor=None, capability="voice:draft:create", exp=None):
        ticket, command = ticket or uuid4(), command or uuid4()
        payload = payload or f"fixture:payload:{uuid4()}"
        with connect(AUTH, AUTH_PASSWORD) as conn:
            result = scalar(conn, "SELECT echo_execution.mint_private_draft_ticket(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
              (ticket, command, payload, ISSUER, f["subject"], f["key"], f["principal"], actor or f["actor"],
               f["source"], 1, capability, f["iat"], f["nbf"], exp or f["exp"]))
        self.assertEqual(result, ticket)
        return ticket, command, payload

    def execute(self, ticket, *, autocommit=True):
        conn = connect(RUNTIME, RUNTIME_PASSWORD, autocommit=autocommit)
        try:
            return conn, scalar(conn, "SELECT echo_execution.execute_private_draft_probe(%s)", (ticket,))
        except Exception:
            conn.close()
            raise

    def test_01_function_owner_is_nologin_and_functions_are_security_definer(self):
        rows = self.admin.execute("""SELECT p.proname,r.rolname,r.rolcanlogin,p.prosecdef,p.proconfig
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
          WHERE n.nspname='echo_execution' ORDER BY p.proname""").fetchall()
        self.assertEqual(len(rows), 2)
        for _, owner, canlogin, secdef, config in rows:
            self.assertEqual(owner, OWNER); self.assertFalse(canlogin); self.assertTrue(secdef)
            self.assertEqual(config, ["search_path=pg_catalog, pg_temp"])

    def test_02_valid_ticket_executes_only_private_probe_and_no_voice_row(self):
        f=self.fixture(); ticket,command,payload=self.mint(f)
        conn,result=self.execute(ticket); conn.close()
        self.assertEqual(result, command)
        row=self.admin.execute("SELECT actor_id,source_id,payload_ref,visibility FROM echo_execution.private_draft_probe WHERE command_id=%s",(command,)).fetchone()
        self.assertEqual(row,(f["actor"],f["source"],payload,"PRIVATE"))
        self.assertEqual(scalar(self.admin,"SELECT count(*) FROM echo_core.voice_revisions"),0)

    def test_03_runtime_cannot_mint_or_supply_identity_payload_visibility(self):
        f=self.fixture()
        with connect(RUNTIME,RUNTIME_PASSWORD) as conn:
            self.assert_sqlstate(lambda: conn.execute("SELECT echo_execution.mint_private_draft_ticket(%s,%s,%s,%s,%s,%s,%s,%s,%s,1,'voice:draft:create',%s,%s,%s)",
              (uuid4(),uuid4(),'attacker:payload',ISSUER,f['subject'],f['key'],f['principal'],f['actor'],f['source'],f['iat'],f['nbf'],f['exp'])))
        argnames=scalar(self.admin,"SELECT proargnames FROM pg_proc WHERE oid=%s::regprocedure",(EXEC_SIG,))
        self.assertEqual(argnames,["p_ticket_id"])

    def test_04_auth_bridge_cannot_execute_runtime_capsule(self):
        f=self.fixture();ticket,_,_=self.mint(f)
        with connect(AUTH,AUTH_PASSWORD) as conn:
            self.assert_sqlstate(lambda: conn.execute("SELECT echo_execution.execute_private_draft_probe(%s)",(ticket,)))

    def test_05_runtime_cannot_read_identity_ticket_or_probe_tables(self):
        with connect(RUNTIME,RUNTIME_PASSWORD) as conn:
            for statement in ["SELECT * FROM echo_identity.principals","SELECT * FROM echo_identity.sessions",
                              "SELECT * FROM echo_execution.private_draft_tickets","SELECT * FROM echo_execution.private_draft_probe"]:
                with self.subTest(statement=statement): self.assert_sqlstate(lambda s=statement: conn.execute(s))

    def test_06_runtime_cannot_mutate_authority_or_execution_tables(self):
        with connect(RUNTIME,RUNTIME_PASSWORD) as conn:
            for statement in ["UPDATE echo_identity.principals SET enabled=false",
                              "UPDATE echo_identity.sessions SET revoked=true",
                              "DELETE FROM echo_execution.private_draft_tickets",
                              "TRUNCATE echo_execution.private_draft_probe"]:
                with self.subTest(statement=statement): self.assert_sqlstate(lambda s=statement: conn.execute(s))

    def test_07_runtime_cannot_directly_write_or_rewrite_voice_history(self):
        f=self.fixture()
        with connect(RUNTIME,RUNTIME_PASSWORD) as conn:
            self.assert_sqlstate(lambda: conn.execute("""INSERT INTO echo_core.voice_revisions
              (voice_id,revision,author_id,source_id,payload_ref,visibility,recorded_at)
              VALUES(%s,1,%s,%s,'forged','PUBLIC',clock_timestamp())""",(uuid4(),f['actor'],f['source'])))
            self.assert_sqlstate(lambda: conn.execute("UPDATE echo_core.voice_revisions SET visibility='PUBLIC'"))

    def test_08_runtime_cannot_call_raw_fence_or_become_definer_owner(self):
        f=self.fixture()
        with connect(RUNTIME,RUNTIME_PASSWORD) as conn:
            self.assert_sqlstate(lambda: conn.execute("SELECT echo_identity.assert_private_draft_fence(%s,%s,%s,%s,%s,%s,1,'voice:draft:create',%s,%s,%s)",
              (ISSUER,f['subject'],f['key'],f['principal'],f['actor'],f['source'],f['iat'],f['nbf'],f['exp'])))
            self.assert_sqlstate(lambda: conn.execute(f"SET ROLE {OWNER}"))

    def test_09_runtime_cannot_grant_itself_or_create_execution_objects(self):
        with connect(RUNTIME,RUNTIME_PASSWORD) as conn:
            self.assert_sqlstate(lambda: conn.execute(f"GRANT SELECT ON echo_identity.principals TO {RUNTIME}"))
            self.assert_sqlstate(lambda: conn.execute("CREATE TABLE echo_execution.backdoor(x int)"))

    def test_10_definer_owner_itself_cannot_change_authority_or_voice(self):
        f=self.fixture(); self.admin.execute(f"SET ROLE {OWNER}")
        try:
            self.assert_sqlstate(lambda: self.admin.execute("UPDATE echo_identity.principals SET enabled=false"))
            self.assert_sqlstate(lambda: self.admin.execute("UPDATE echo_identity.sessions SET revoked=true"))
            self.assert_sqlstate(lambda: self.admin.execute("""INSERT INTO echo_core.voice_revisions
              (voice_id,revision,author_id,source_id,payload_ref,visibility,recorded_at)
              VALUES(%s,1,%s,%s,'forged','PRIVATE',clock_timestamp())""",(uuid4(),f['actor'],f['source'])))
        finally:
            self.admin.execute("RESET ROLE")

    def test_11_wrong_actor_or_capability_cannot_be_minted_even_by_auth_bridge(self):
        f=self.fixture()
        self.assert_sqlstate(lambda: self.mint(f,actor=uuid4()))
        self.assert_sqlstate(lambda: self.mint(f,capability="assessment:review"))

    def test_12_ticket_is_one_shot(self):
        f=self.fixture();ticket,command,_=self.mint(f)
        conn,result=self.execute(ticket);conn.close();self.assertEqual(result,command)
        self.assert_sqlstate(lambda: self.execute(ticket))
        self.assertEqual(scalar(self.admin,"SELECT count(*) FROM echo_execution.private_draft_probe WHERE ticket_id=%s",(ticket,)),1)

    def test_13_two_runtime_connections_cannot_consume_same_ticket_twice(self):
        f=self.fixture();ticket,command,_=self.mint(f);results=[];lock=threading.Lock()
        def worker():
            try:
                conn,value=self.execute(ticket);conn.close();item=("SAT",value)
            except psycopg.Error as e: item=(e.sqlstate,None)
            with lock: results.append(item)
        threads=[threading.Thread(target=worker) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=5)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(sorted(x[0] for x in results),["42501","SAT"])
        self.assertEqual(scalar(self.admin,"SELECT count(*) FROM echo_execution.private_draft_probe WHERE command_id=%s",(command,)),1)

    def test_14_revocation_after_mint_denies_consume_and_rolls_back_probe(self):
        f=self.fixture();ticket,command,_=self.mint(f)
        self.admin.execute("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",(f['key'],))
        self.assert_sqlstate(lambda: self.execute(ticket))
        self.assertTrue(scalar(self.admin,"SELECT consumed_ms IS NULL FROM echo_execution.private_draft_tickets WHERE ticket_id=%s",(ticket,)))
        self.assertEqual(scalar(self.admin,"SELECT count(*) FROM echo_execution.private_draft_probe WHERE command_id=%s",(command,)),0)

    def test_15_disable_or_writer_removal_after_mint_denies_ticket(self):
        for change in ["enabled=false","writer_enabled=false"]:
            with self.subTest(change=change):
                f=self.fixture();ticket,command,_=self.mint(f)
                self.admin.execute(f"UPDATE echo_identity.principals SET {change},auth_version=auth_version+1 WHERE principal_id=%s",(f['principal'],))
                self.assert_sqlstate(lambda: self.execute(ticket))
                self.assertEqual(scalar(self.admin,"SELECT count(*) FROM echo_execution.private_draft_probe WHERE command_id=%s",(command,)),0)

    def test_16_reenable_does_not_revive_old_ticket_generation(self):
        f=self.fixture();ticket,_,_=self.mint(f)
        self.admin.execute("UPDATE echo_identity.principals SET enabled=false,auth_version=2 WHERE principal_id=%s",(f['principal'],))
        self.admin.execute("UPDATE echo_identity.principals SET enabled=true,auth_version=3 WHERE principal_id=%s",(f['principal'],))
        self.assert_sqlstate(lambda: self.execute(ticket))

    def test_17_short_token_expiry_also_limits_ticket(self):
        f=self.fixture();soon=int(time.time()*1000)+1200;ticket,command,_=self.mint(f,exp=soon)
        time.sleep(1.35)
        self.assert_sqlstate(lambda: self.execute(ticket))
        self.assertEqual(scalar(self.admin,"SELECT count(*) FROM echo_execution.private_draft_probe WHERE command_id=%s",(command,)),0)

    def test_18_unknown_ticket_is_same_denial_category(self):
        self.assert_sqlstate(lambda: self.execute(uuid4()))

    def test_19_search_path_temp_shadow_does_not_hijack_definer_tables(self):
        f=self.fixture();ticket,command,_=self.mint(f)
        with connect(RUNTIME,RUNTIME_PASSWORD) as conn:
            conn.execute("CREATE TEMP TABLE private_draft_tickets(ticket_id uuid, consumed_ms bigint)")
            conn.execute("SET search_path=pg_temp,public")
            result=scalar(conn,"SELECT echo_execution.execute_private_draft_probe(%s)",(ticket,))
            self.assertEqual(result,command)
            self.assertEqual(scalar(conn,"SELECT count(*) FROM private_draft_tickets"),0)

    def test_20_failed_probe_insert_does_not_consume_ticket(self):
        f=self.fixture();ticket,command,payload=self.mint(f)
        self.admin.execute("""INSERT INTO echo_execution.private_draft_probe
          (command_id,ticket_id,actor_id,source_id,payload_ref,visibility,recorded_at)
          VALUES(%s,%s,%s,%s,%s,'PRIVATE',clock_timestamp())""",
          (command,ticket,f['actor'],f['source'],payload))
        self.assert_sqlstate(lambda: self.execute(ticket),"23505")
        self.assertTrue(scalar(self.admin,"SELECT consumed_ms IS NULL FROM echo_execution.private_draft_tickets WHERE ticket_id=%s",(ticket,)))

    def test_21_caller_rollback_does_not_consume_ticket_or_leave_probe(self):
        f=self.fixture();ticket,command,_=self.mint(f)
        conn,result=self.execute(ticket,autocommit=False);self.assertEqual(result,command);conn.rollback();conn.close()
        self.assertEqual(scalar(self.admin,"SELECT count(*) FROM echo_execution.private_draft_probe WHERE command_id=%s",(command,)),0)
        self.assertTrue(scalar(self.admin,"SELECT consumed_ms IS NULL FROM echo_execution.private_draft_tickets WHERE ticket_id=%s",(ticket,)))
        conn,result=self.execute(ticket);conn.close();self.assertEqual(result,command)

    def test_22_test_roles_have_no_admin_or_bypass_attributes_and_no_memberships(self):
        rows=self.admin.execute("SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname",([OWNER,AUTH,RUNTIME],)).fetchall()
        self.assertEqual(len(rows),3)
        for row in rows:self.assertEqual(row[1:],(False,False,False,False,False))
        self.assertEqual(scalar(self.admin,"SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname=ANY(%s)",([OWNER,AUTH,RUNTIME],)),0)

    def test_23_auth_bridge_cannot_read_or_mutate_private_tables(self):
        with connect(AUTH,AUTH_PASSWORD) as conn:
            for statement in ["SELECT * FROM echo_identity.principals","SELECT * FROM echo_execution.private_draft_tickets",
                              "UPDATE echo_identity.principals SET writer_enabled=true","DELETE FROM echo_execution.private_draft_tickets"]:
                with self.subTest(statement=statement):self.assert_sqlstate(lambda s=statement:conn.execute(s))

    def test_24_ticket_ttl_is_capped_and_command_is_bound_at_mint(self):
        f=self.fixture();ticket,command,payload=self.mint(f)
        row=self.admin.execute("SELECT command_id,payload_ref,ticket_expires_ms-minted_ms,token_expires_ms-ticket_expires_ms FROM echo_execution.private_draft_tickets WHERE ticket_id=%s",(ticket,)).fetchone()
        self.assertEqual(row[0],command);self.assertEqual(row[1],payload)
        self.assertGreater(row[2],0);self.assertLessEqual(row[2],30000);self.assertGreaterEqual(row[3],0)

    def test_25_definer_owner_cannot_delete_capsules_or_probes(self):
        f=self.fixture();ticket,_,_=self.mint(f)
        self.admin.execute(f"SET ROLE {OWNER}")
        try:
            self.assert_sqlstate(lambda:self.admin.execute("DELETE FROM echo_execution.private_draft_tickets WHERE ticket_id=%s",(ticket,)))
            self.assert_sqlstate(lambda:self.admin.execute("DELETE FROM echo_execution.private_draft_probe"))
        finally:self.admin.execute("RESET ROLE")

    def test_26_public_execute_is_revoked_and_grants_are_split(self):
        mint_acl=scalar(self.admin,"SELECT has_function_privilege(%s,%s,'EXECUTE')",(RUNTIME,MINT_SIG))
        run_acl=scalar(self.admin,"SELECT has_function_privilege(%s,%s,'EXECUTE')",(AUTH,EXEC_SIG))
        owner_login=scalar(self.admin,"SELECT rolcanlogin FROM pg_roles WHERE rolname=%s",(OWNER,))
        self.assertFalse(mint_acl);self.assertFalse(run_acl);self.assertFalse(owner_login)


if __name__ == "__main__":
    unittest.main(verbosity=2)
