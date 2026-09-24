-- P2.1c.2d.4c.1: ONE dedicated owner-read service LOGIN.
-- Apply only in a reviewed, isolated environment after 4a. This does not provision
-- a password, pg_hba, TLS, HTTP service or production credential. Fail on collision.
DO $$
BEGIN
  IF to_regrole('echo_private_owner_read_runtime') IS NULL
     OR to_regprocedure('echo_identity.runtime_read_private_owner_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid)') IS NULL THEN
    RAISE EXCEPTION 'P2.1c.2d.4a required' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_private_owner_read_service') IS NOT NULL THEN
    RAISE EXCEPTION 'Service role already exists; do not overwrite its grants' USING ERRCODE='42710';
  END IF;
END $$;
CREATE ROLE echo_private_owner_read_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 8 PASSWORD NULL;
GRANT echo_private_owner_read_runtime TO echo_private_owner_read_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
ALTER ROLE echo_private_owner_read_service SET search_path = pg_catalog;
ALTER ROLE echo_private_owner_read_service SET row_security = on;
ALTER ROLE echo_private_owner_read_service SET statement_timeout = '10s';
ALTER ROLE echo_private_owner_read_service SET lock_timeout = '6s';
ALTER ROLE echo_private_owner_read_service SET idle_in_transaction_session_timeout = '15s';
COMMENT ON ROLE echo_private_owner_read_service IS
  'Backend-only dedicated PRIVATE owner-read login; no password provisioned by migration; SET LOCAL only to owner-read runtime. Not a web-user identity.';
-- No table grants, schema ownership, writer/recovery/guard membership or public API.
-- Password NULL blocks password auth, NOT trust/peer/certificate auth: review HBA.
-- CONNECT/TEMP can still come from PUBLIC. DB/HBA/secret/TLS provisioning remains
-- administrative work; this script intentionally does not revoke cluster-wide ACLs.
