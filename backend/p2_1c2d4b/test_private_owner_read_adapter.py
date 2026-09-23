from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest
from uuid import UUID, uuid4

import jwt
import psycopg
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "p2_1c2b1"))
sys.path.insert(0, str(HERE.parent / "p2_1c2c3"))

from identity_boundary import Boundary, Config  # noqa: E402
from postgres_registry_adapter import PostgresRegistryAdapter, derive_session_key  # noqa: E402
from private_owner_read_adapter import (  # noqa: E402
    PrivateOwnerReadAdapter,
    PrivateOwnerReadError,
)

DB_NAME = "echo_private_owner_read_adapter_test"
ISSUER = "https://issuer.owner-read-adapter.fixture.invalid/echo"
AUD = "echo-owner-read-adapter-fixture"
READ_RUNTIME = "echo_private_owner_read_runtime"
READ_GUARD = "echo_private_owner_read_guard"
WRITER_RUNTIME = "echo_private_draft_runtime"
WRITER_GUARD = "echo_private_draft_guard"
PUBLIC_READER = "echo_public_reader"

CALL_RESERVE = """SELECT * FROM echo_identity.runtime_reserve_private_payload_attempt(
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
CALL_WRITE = """SELECT * FROM echo_identity.runtime_recoverable_idempotent_append_private_voice(
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
CALL_MARK_COMMITTED = "SELECT echo_identity.runtime_mark_private_payload_committed(%s,%s)"


class PrivateOwnerReadAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get("ECHO_DISPOSABLE_PG") != "YES"
                or os.environ.get("PGDATABASE") != DB_NAME
                or os.environ.get("PGHOST") not in ("127.0.0.1", "localhost")):
            raise RuntimeError("refusing non-disposable or non-loopback database")
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = Config(ISSUER, AUD, "owner-read-keyset-v1", {"fixture-key": cls.key.public_key()})

        with cls.connect() as c:
            version = int(c.execute("SHOW server_version_num").fetchone()[0])
            if not 170000 <= version < 180000:
                raise RuntimeError("this gate must run on PostgreSQL 17")
            dirty = c.execute("""SELECT to_regnamespace('echo_core') IS NOT NULL
                OR to_regnamespace('echo_identity') IS NOT NULL
                OR to_regnamespace('echo_history') IS NOT NULL
                OR to_regnamespace('echo_public') IS NOT NULL
                OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=ANY(%s))""",
                ([READ_RUNTIME,READ_GUARD,WRITER_RUNTIME,WRITER_GUARD,PUBLIC_READER],)).fetchone()[0]
            if dirty:
                raise RuntimeError("refusing database/cluster with pre-existing Echo test objects")
            for path in (
                "database/p2_1b/schema.sql",
                "database/p2_1c/001_immutable_history.sql",
                "database/p2_1c2a/001_public_voice_read.sql",
                "database/p2_1c2c/001_identity_registry.sql",
                "database/p2_1c2d1/001_write_fence.sql",
                "database/p2_1c2d2/001_runtime_roles.sql",
                "database/p2_1c2d3/001_private_voice_write.sql",
                "database/p2_1c2d3c/001_idempotent_private_receipt.sql",
                "database/p2_1c2d3d/001_payload_recovery.sql",
                "database/p2_1c2d4a/001_private_owner_read.sql",
            ):
                c.execute((ROOT / path).read_text(encoding="utf-8"))
        cls.addClassCleanup(cls.cleanup)

    @staticmethod
    def connect():
        return psycopg.connect(connect_timeout=3,
            options="-c statement_timeout=10000 -c lock_timeout=6000 -c idle_in_transaction_session_timeout=15000")

    @classmethod
    def role_connection(cls, role: str):
        c = cls.connect()
        c.execute(f"SET SESSION AUTHORIZATION {role}")
        c.commit()
        return c

    @classmethod
    def cleanup(cls):
        with cls.connect() as c:
            c.execute("DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_public CASCADE; "
                      "DROP SCHEMA echo_history CASCADE; DROP SCHEMA echo_core CASCADE;")
            for role in (READ_RUNTIME,READ_GUARD,WRITER_RUNTIME,WRITER_GUARD,PUBLIC_READER):
                c.execute(f"DROP ROLE {role}")
        print("CLEAN_PRIVATE_OWNER_READ_ADAPTER_DATABASE", flush=True)

    def setUp(self):
        self.payloads: dict[str, bytes] = {}
        self.resolved_refs: list[str] = []
        self.identity = self.new_identity()
        self.registry = PostgresRegistryAdapter(self.connect)
        self.boundary = Boundary(self.config, resolve_binding=self.registry.resolve_binding)
        self.reader = PrivateOwnerReadAdapter(self.boundary, self.read_connection, self.resolve_payload)

    def new_identity(self, *, writer=True):
        now = int(time.time())
        i = {
            "subject": "owner-" + uuid4().hex,
            "jti": "session-" + uuid4().hex,
            "principal_id": uuid4(), "actor_id": uuid4(), "source_id": uuid4(),
            "auth_version": 1,
            "iat": now - 5, "exp": now + 180, "session_exp": now + 120,
        }
        i["session_key"] = derive_session_key(ISSUER, i["jti"])
        with self.connect() as c:
            c.execute("INSERT INTO echo_core.actors VALUES(%s,'HUMAN','Owner adapter fixture',clock_timestamp())",
                      (i["actor_id"],))
            c.execute("INSERT INTO echo_core.sources VALUES(%s,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp())",
                      (i["source_id"],))
            c.execute("""INSERT INTO echo_identity.principals
                (principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled,auth_version)
                VALUES(%s,%s,%s,%s,%s,true,%s,false,1)""",
                (i["principal_id"],ISSUER,i["subject"],i["actor_id"],i["source_id"],writer))
            c.execute("""INSERT INTO echo_identity.sessions
                (session_key,principal_id,auth_version,issued_at,expires_at)
                VALUES(%s,%s,1,to_timestamp(%s),to_timestamp(%s))""",
                (i["session_key"],i["principal_id"],i["iat"],i["session_exp"]))
        return i

    def token(self, i=None, *, key=None, extra=None):
        i = i or self.identity
        claims = {"iss":ISSUER,"aud":AUD,"sub":i["subject"],"iat":i["iat"],"nbf":i["iat"],
                  "exp":i["exp"],"jti":i["jti"]}
        if extra:
            claims.update(extra)
        return jwt.encode(claims, key or self.key, algorithm="RS256",
                          headers={"kid":"fixture-key","typ":"at+jwt"})

    def auth_tuple(self, i=None):
        i = i or self.identity
        return (ISSUER,i["subject"],i["session_key"],i["principal_id"],i["actor_id"],i["source_id"],
                i["auth_version"],"voice:draft:create",i["iat"]*1000,i["iat"]*1000,i["exp"]*1000)

    def body(self, voice_id, **extra):
        obj = {"voice_id":str(voice_id)}
        obj.update(extra)
        return json.dumps(obj,separators=(",",":")).encode()

    def read_connection(self):
        return self.role_connection(READ_RUNTIME)

    def resolve_payload(self, ref: str) -> bytes:
        self.resolved_refs.append(ref)
        return self.payloads[ref]

    def writer_one(self, sql, params):
        with self.role_connection(WRITER_RUNTIME) as c:
            return c.execute(sql, params).fetchone()

    def create_voice(self, i=None, *, text="private adapter fixture"):
        i = i or self.identity
        attempt = uuid4(); request_id = uuid4()
        request_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        payload_ref = "payload:adapter:" + attempt.hex
        self.writer_one(CALL_RESERVE, self.auth_tuple(i)+(request_id,request_hash,attempt))
        row = self.writer_one(CALL_WRITE, self.auth_tuple(i)+(request_id,request_hash,attempt,payload_ref))
        self.assertEqual((row[0],row[2],row[7]),(attempt,"PRIVATE","NEEDS_COMMIT"))
        self.assertTrue(self.writer_one(CALL_MARK_COMMITTED,(attempt,payload_ref))[0])
        self.payloads[payload_ref] = text.encode("utf-8")
        return attempt,payload_ref

    def append_head(self, voice_id, visibility):
        with self.connect() as c:
            c.execute("""INSERT INTO echo_core.voice_revisions
                (voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
                SELECT voice_id,revision+1,revision,author_id,source_id,%s,%s,NULL,clock_timestamp()
                  FROM echo_core.voice_revisions
                 WHERE voice_id=%s ORDER BY revision DESC LIMIT 1""",
                (f"fixture:head:{visibility.lower()}:{uuid4().hex}",visibility,voice_id))

    def assert_error(self, code, call):
        with self.assertRaises(PrivateOwnerReadError) as ctx:
            call()
        self.assertEqual(ctx.exception.code,code)

    def test_01_signed_owner_read_returns_content_without_locator(self):
        voice,ref = self.create_voice(text="signed private owner text")
        result = self.reader.read("Bearer "+self.token(),self.body(voice))
        self.assertEqual((result.voice_id,result.revision,result.text),(voice,1,"signed private owner text"))
        self.assertEqual(self.resolved_refs,[ref])
        self.assertNotIn("payload_ref",asdict(result))
        self.assertNotIn(ref,repr(result))

    def test_02_request_may_supply_only_voice_id(self):
        voice,_ = self.create_voice()
        for extra in ({"actor_id":str(self.identity["actor_id"])},
                      {"source_id":str(self.identity["source_id"])},
                      {"payload_ref":"payload:forged"},{"revision":1},{"visibility":"PRIVATE"},
                      {"authorization_stamp":{"auth_version":1}}):
            with self.subTest(extra=extra):
                self.assert_error("INVALID_READ_REQUEST",
                    lambda extra=extra:self.reader.read("Bearer "+self.token(),self.body(voice,**extra)))
        self.assertEqual(self.resolved_refs,[])

    def test_03_other_principal_gets_same_empty_result_and_no_payload_lookup(self):
        voice,_ = self.create_voice()
        other = self.new_identity()
        result = self.reader.read("Bearer "+self.token(other),self.body(voice))
        self.assertIsNone(result)
        self.assertEqual(self.resolved_refs,[])

    def test_04_unknown_voice_is_empty_and_never_calls_payload_resolver(self):
        self.assertIsNone(self.reader.read("Bearer "+self.token(),self.body(uuid4())))
        self.assertEqual(self.resolved_refs,[])

    def test_05_revoked_session_fails_closed_before_private_object_read(self):
        voice,_ = self.create_voice()
        with self.connect() as c:
            c.execute("UPDATE echo_identity.sessions SET revoked=true WHERE session_key=%s",
                      (self.identity["session_key"],))
        self.assert_error("IDENTITY_REJECTED",
            lambda:self.reader.read("Bearer "+self.token(),self.body(voice)))
        self.assertEqual(self.resolved_refs,[])

    def test_06_removed_writer_capability_fails_closed(self):
        voice,_ = self.create_voice()
        # Keep the same generation solely to isolate capability behavior; production
        # authority changes also advance auth_version and invalidate old sessions.
        with self.connect() as c:
            c.execute("UPDATE echo_identity.principals SET writer_enabled=false WHERE principal_id=%s",
                      (self.identity["principal_id"],))
        self.assert_error("CAPABILITY_REQUIRED",
            lambda:self.reader.read("Bearer "+self.token(),self.body(voice)))
        self.assertEqual(self.resolved_refs,[])

    def test_07_signed_role_actor_source_hints_cannot_override_registry(self):
        voice,_ = self.create_voice(text="registry owns identity")
        forged={"role":"admin","actor_id":str(uuid4()),"source_id":str(uuid4()),
                "principal_id":str(uuid4()),"scope":"private:read:any"}
        result=self.reader.read("Bearer "+self.token(extra=forged),self.body(voice))
        self.assertEqual(result.text,"registry owns identity")

    def test_08_wrong_signature_is_rejected_without_payload_lookup(self):
        voice,_ = self.create_voice()
        self.assert_error("IDENTITY_REJECTED",
            lambda:self.reader.read("Bearer "+self.token(key=self.wrong_key),self.body(voice)))
        self.assertEqual(self.resolved_refs,[])

    def test_09_runtime_connection_must_be_exact_owner_read_role(self):
        voice,_ = self.create_voice()
        bad = PrivateOwnerReadAdapter(self.boundary,self.connect,self.resolve_payload)
        self.assert_error("RUNTIME_ROLE_REQUIRED",
            lambda:bad.read("Bearer "+self.token(),self.body(voice)))
        self.assertEqual(self.resolved_refs,[])

    def test_10_committed_db_row_with_missing_payload_fails_closed_without_leaking_ref(self):
        voice,ref = self.create_voice()
        del self.payloads[ref]
        self.assert_error("PAYLOAD_UNAVAILABLE",
            lambda:self.reader.read("Bearer "+self.token(),self.body(voice)))
        self.assertEqual(self.resolved_refs,[ref])

    def test_11_payload_resolver_contract_rejects_non_bytes_or_invalid_text(self):
        voice,_ = self.create_voice()
        for bad_value in ("not-bytes",b"\xff",b"\x00bad",b"   "):
            with self.subTest(value=repr(bad_value)):
                reader=PrivateOwnerReadAdapter(self.boundary,self.read_connection,lambda _ref,v=bad_value:v)
                self.assert_error("PAYLOAD_CONTRACT_VIOLATION",
                    lambda reader=reader:reader.read("Bearer "+self.token(),self.body(voice)))

    def test_12_newer_public_or_withdrawn_head_never_falls_back_to_private_payload(self):
        for visibility in ("PUBLIC","WITHDRAWN"):
            with self.subTest(visibility=visibility):
                voice,_=self.create_voice(text="old private "+visibility)
                self.append_head(voice,visibility)
                self.assertIsNone(self.reader.read("Bearer "+self.token(),self.body(voice)))
        self.assertEqual(self.resolved_refs,[])

    def test_13_malformed_duplicate_or_nil_voice_id_is_rejected(self):
        bad_bodies=[b"{}",b"[]",b"{",b'{"voice_id":"00000000-0000-0000-0000-000000000000"}',
                    b'{"voice_id":"11111111-1111-4111-8111-111111111111","voice_id":"22222222-2222-4222-8222-222222222222"}']
        for raw in bad_bodies:
            with self.subTest(raw=raw):
                self.assert_error("INVALID_READ_REQUEST",lambda raw=raw:self.reader.read("Bearer "+self.token(),raw))

    def test_14_identity_backend_outage_fails_closed(self):
        voice,_=self.create_voice()
        bad_boundary=Boundary(self.config,resolve_binding=lambda *_:(_ for _ in ()).throw(RuntimeError("db down")))
        bad=PrivateOwnerReadAdapter(bad_boundary,self.read_connection,self.resolve_payload)
        self.assert_error("IDENTITY_BACKEND_UNAVAILABLE",
            lambda:bad.read("Bearer "+self.token(),self.body(voice)))
        self.assertEqual(self.resolved_refs,[])


if __name__ == "__main__":
    program=unittest.main(exit=False,verbosity=2)
    if program.result.wasSuccessful():
        print("P2_1C2D4B_PRIVATE_OWNER_READ_ADAPTER_SUITE_SAT",flush=True)
    sys.exit(0 if program.result.wasSuccessful() else 1)
