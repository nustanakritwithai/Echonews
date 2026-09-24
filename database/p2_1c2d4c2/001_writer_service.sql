-- P2.1c.2d.4c.2: dedicated PRIVATE draft writer/recovery service LOGIN.
-- Apply only after the recoverable/idempotent PRIVATE draft chain (3d).
-- This migration provisions NO password, HBA rule, TLS secret, HTTP endpoint,
-- payload provider, or production credential. Collision is fail-closed.
DO $$
BEGIN
  IF to_regrole('echo_private_draft_runtime') IS NULL
     OR to_regprocedure('echo_identity.runtime_reserve_private_payload_attempt(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid)') IS NULL
     OR to_regprocedure('echo_identity.runtime_recoverable_idempotent_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text)') IS NULL
     OR to_regprocedure('echo_identity.runtime_get_private_payload_attempt(uuid)') IS NULL THEN
    RAISE EXCEPTION 'P2.1c.2d.3d recoverable writer chain required' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_private_draft_service') IS NOT NULL THEN
    RAISE EXCEPTION 'Writer service role already exists; do not overwrite grants' USING ERRCODE='42710';
  END IF;
END $$;

CREATE ROLE echo_private_draft_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 8 PASSWORD NULL;

GRANT echo_private_draft_runtime TO echo_private_draft_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

ALTER ROLE echo_private_draft_service SET search_path = pg_catalog;
ALTER ROLE echo_private_draft_service SET row_security = on;
ALTER ROLE echo_private_draft_service SET statement_timeout = '10s';
ALTER ROLE echo_private_draft_service SET lock_timeout = '6s';
ALTER ROLE echo_private_draft_service SET idle_in_transaction_session_timeout = '15s';

COMMENT ON ROLE echo_private_draft_service IS
  'Backend-only PRIVATE draft writer/recovery login. SET LOCAL only to echo_private_draft_runtime. Password and production transport are provisioned separately.';

-- No direct table/function grants are added to the LOGIN. The service may SET the
-- existing NOLOGIN runtime role, whose sealed function surface is verified by the
-- application pool before every lease. PASSWORD NULL blocks password auth only;
-- trust/peer/certificate and production HBA/TLS remain separate administrative gates.
