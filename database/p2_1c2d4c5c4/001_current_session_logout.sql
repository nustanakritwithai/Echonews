-- c5c.4: revoke ONLY the session selected by a newly verified signed token.
-- Paired backend required: SQL arguments are NOT cryptographic proof.
-- No HTTP endpoint, refresh, logout-all, principal changes or browser grants.
DO $$
BEGIN
  IF to_regrole('echo_first_session_service') IS NULL
     OR to_regprocedure('echo_identity.runtime_revoke_session(text,uuid)') IS NULL THEN
    RAISE EXCEPTION 'First-session and durable revocation contracts required' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_session_logout_service') IS NOT NULL
     OR to_regrole('echo_session_logout_runtime') IS NOT NULL
     OR to_regrole('echo_session_logout_guard') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_logout_current_session(text,text,text,bigint,bigint,bigint)') IS NOT NULL THEN
    RAISE EXCEPTION 'Do not overwrite logout service' USING ERRCODE='42710';
  END IF;
END $$;
CREATE ROLE echo_session_logout_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_session_logout_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_session_logout_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4 PASSWORD NULL;
REVOKE ALL ON SCHEMA echo_identity,echo_core FROM
  echo_session_logout_guard,echo_session_logout_runtime,echo_session_logout_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity,echo_core FROM
  echo_session_logout_guard,echo_session_logout_runtime,echo_session_logout_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM
  echo_session_logout_guard,echo_session_logout_runtime,echo_session_logout_service;

GRANT USAGE ON SCHEMA echo_identity TO echo_session_logout_guard;
GRANT SELECT ON echo_identity.principals,echo_identity.sessions TO echo_session_logout_guard;
-- Lock-only column grants; immutable keys remain protected by existing triggers.
GRANT UPDATE(principal_id) ON echo_identity.principals TO echo_session_logout_guard;
GRANT UPDATE(session_key) ON echo_identity.sessions TO echo_session_logout_guard;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) TO echo_session_logout_guard;
-- Do not leave the broad principal/key selector exposed to the old runtime.
REVOKE EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid)
  FROM echo_identity_mutation_runtime,echo_identity_mutation_service;

CREATE FUNCTION echo_identity.runtime_logout_current_session(
  p_issuer text,p_subject text,p_session_key text,
  p_token_issued_ms bigint,p_token_not_before_ms bigint,p_token_expires_ms bigint
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p echo_identity.principals%ROWTYPE;
DECLARE s echo_identity.sessions%ROWTYPE;
DECLARE result jsonb;
DECLARE checked_ms bigint;
BEGIN
  IF session_user::text IS DISTINCT FROM 'echo_session_logout_service' THEN
    RAISE EXCEPTION 'LOGOUT_SERVICE_REQUIRED' USING ERRCODE='42501';
  END IF;
  IF p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048 OR btrim(p_issuer)=''
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255 OR btrim(p_subject)=''
     OR p_session_key IS NULL OR p_session_key !~ '^[a-f0-9]{64}$'
     OR p_token_issued_ms IS NULL OR p_token_not_before_ms IS NULL OR p_token_expires_ms IS NULL
     OR p_token_issued_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_not_before_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_expires_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_issued_ms > p_token_not_before_ms
     OR p_token_not_before_ms >= p_token_expires_ms THEN
    RAISE EXCEPTION 'INVALID_LOGOUT_REQUEST' USING ERRCODE='22023';
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'UNSUPPORTED_LOGOUT_ISOLATION' USING ERRCODE='25001';
  END IF;
  -- Keep the established principal -> session lock order used by fenced commands.
  SELECT * INTO p FROM echo_identity.principals
    WHERE issuer=p_issuer COLLATE "C" AND subject=p_subject COLLATE "C" FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'LOGOUT_SESSION_REJECTED' USING ERRCODE='23514';
  END IF;
  SELECT * INTO s FROM echo_identity.sessions WHERE session_key=p_session_key COLLATE "C" FOR UPDATE;
  IF NOT FOUND OR s.principal_id IS DISTINCT FROM p.principal_id
     OR floor(extract(epoch FROM s.issued_at)*1000)::bigint <> p_token_issued_ms
     OR floor(extract(epoch FROM s.expires_at)*1000)::bigint <> p_token_expires_ms THEN
    RAISE EXCEPTION 'LOGOUT_SESSION_REJECTED' USING ERRCODE='23514';
  END IF;
  checked_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF checked_ms < p_token_issued_ms OR checked_ms < p_token_not_before_ms
     OR checked_ms >= p_token_expires_ms THEN
    RAISE EXCEPTION 'LOGOUT_TOKEN_WINDOW_REJECTED' USING ERRCODE='23514';
  END IF;
  -- Deliberately NO enabled/current-version/role prerequisite: a still-valid signed
  -- owner can only reduce its own old session authority, even after disable/version
  -- changes. This never authorizes a read, write, session creation or reactivation.
  -- Already-revoked rows are accepted for idempotent explicit retry, never restored.
  result := echo_identity.runtime_revoke_session(s.session_key,p.principal_id);
  IF result->>'sessionKey' IS DISTINCT FROM s.session_key
     OR result->>'principalId' IS DISTINCT FROM p.principal_id::text
     OR result->>'authVersion' IS DISTINCT FROM s.auth_version::text
     OR result->'revoked' IS DISTINCT FROM 'true'::jsonb THEN
    RAISE EXCEPTION 'LOGOUT_CONTRACT_VIOLATION' USING ERRCODE='23514';
  END IF;
  checked_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF checked_ms < p_token_issued_ms OR checked_ms < p_token_not_before_ms
     OR checked_ms >= p_token_expires_ms THEN
    RAISE EXCEPTION 'LOGOUT_TOKEN_WINDOW_REJECTED' USING ERRCODE='23514';
  END IF;
  -- Minimal receipt does not expose account ids, role/version or a reusable ticket.
  RETURN jsonb_build_object('sessionKey',s.session_key,'revoked',true);
END $$;
REVOKE ALL ON FUNCTION echo_identity.runtime_logout_current_session(text,text,text,bigint,bigint,bigint) FROM PUBLIC;
ALTER FUNCTION echo_identity.runtime_logout_current_session(text,text,text,bigint,bigint,bigint)
  OWNER TO echo_session_logout_guard;
GRANT USAGE ON SCHEMA echo_identity TO echo_session_logout_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_logout_current_session(text,text,text,bigint,bigint,bigint)
  TO echo_session_logout_runtime;
GRANT echo_session_logout_runtime TO echo_session_logout_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
ALTER ROLE echo_session_logout_service SET search_path=pg_catalog;
ALTER ROLE echo_session_logout_service SET row_security=on;
ALTER ROLE echo_session_logout_service SET statement_timeout='5s';
ALTER ROLE echo_session_logout_service SET lock_timeout='3s';
ALTER ROLE echo_session_logout_service SET idle_in_transaction_session_timeout='10s';
COMMENT ON FUNCTION echo_identity.runtime_logout_current_session(text,text,text,bigint,bigint,bigint) IS
  'c5c.4 paired signed-current-session logout only; monotonic revocation, no new authority. Expiry checked at final DB sample, not physical durability/ack time.';
