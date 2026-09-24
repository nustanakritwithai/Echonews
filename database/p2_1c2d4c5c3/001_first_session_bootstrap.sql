-- P2.1c.2d.4c.5c.3 — signed first-session bootstrap.
-- Scope: after audited first activation, create exactly one initial Session from a
-- verified bearer identity. The caller never supplies Principal/Actor/Source or a
-- session key. Later login/session renewal, HTTP cookies and public APIs are OUT.
DO $$
BEGIN
  IF to_regclass('echo_identity.activation_audit') IS NULL
     OR to_regprocedure('echo_identity.runtime_activate_provisioned_principal(uuid,uuid,integer)') IS NULL
     OR to_regprocedure('echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)') IS NULL THEN
    RAISE EXCEPTION 'c5c.2 + c4 session primitives required first' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_first_session_guard') IS NOT NULL
     OR to_regrole('echo_first_session_runtime') IS NOT NULL
     OR to_regrole('echo_first_session_service') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_bootstrap_first_session(text,text,text,bigint,bigint,bigint)') IS NOT NULL THEN
    RAISE EXCEPTION 'First-session bootstrap already exists; do not overwrite grants' USING ERRCODE='42710';
  END IF;
END $$;

CREATE ROLE echo_first_session_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_first_session_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_first_session_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4 PASSWORD NULL;

REVOKE ALL ON SCHEMA echo_identity FROM
  echo_first_session_guard,echo_first_session_runtime,echo_first_session_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM
  echo_first_session_guard,echo_first_session_runtime,echo_first_session_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM
  echo_first_session_guard,echo_first_session_runtime,echo_first_session_service;

-- The sealed guard can lock one Principal, prove audited activation and insert one
-- Session. Immutable-key UPDATE grants exist only because PostgreSQL requires an
-- UPDATE privilege for SELECT ... FOR UPDATE; no function changes these keys.
GRANT USAGE ON SCHEMA echo_identity TO echo_first_session_guard;
GRANT SELECT ON echo_identity.principals,echo_identity.sessions,echo_identity.activation_audit
  TO echo_first_session_guard;
GRANT UPDATE (principal_id) ON echo_identity.principals TO echo_first_session_guard;
GRANT UPDATE (session_key) ON echo_identity.sessions TO echo_first_session_guard;
GRANT INSERT (session_key,principal_id,auth_version,issued_at,expires_at,revoked)
  ON echo_identity.sessions TO echo_first_session_guard;

CREATE FUNCTION echo_identity.runtime_bootstrap_first_session(
  p_issuer text,
  p_subject text,
  p_session_key text,
  p_token_issued_ms bigint,
  p_token_not_before_ms bigint,
  p_token_expires_ms bigint
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p echo_identity.principals%ROWTYPE;
DECLARE s echo_identity.sessions%ROWTYPE;
DECLARE a echo_identity.activation_audit%ROWTYPE;
DECLARE now_ms bigint;
DECLARE replayed_value boolean := false;
BEGIN
  IF session_user::text IS DISTINCT FROM 'echo_first_session_service' THEN
    RAISE EXCEPTION 'FIRST_SESSION_SERVICE_REQUIRED' USING ERRCODE='42501';
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
    RAISE EXCEPTION 'INVALID_FIRST_SESSION_REQUEST' USING ERRCODE='22023';
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'UNSUPPORTED_FIRST_SESSION_ISOLATION' USING ERRCODE='25001';
  END IF;

  SELECT * INTO p FROM echo_identity.principals
   WHERE issuer=p_issuer COLLATE "C" AND subject=p_subject COLLATE "C"
   FOR UPDATE;
  IF NOT FOUND OR NOT p.enabled OR p.auth_version <> 2
     OR p.writer_enabled OR p.reviewer_enabled THEN
    RAISE EXCEPTION 'FIRST_SESSION_AUTHORITY_REJECTED' USING ERRCODE='23514';
  END IF;

  SELECT * INTO a FROM echo_identity.activation_audit WHERE principal_id=p.principal_id;
  IF NOT FOUND OR a.from_auth_version <> 1 OR a.to_auth_version <> 2
     OR a.policy_code <> 'PROVEN_ACCOUNT_ONBOARDING_V1'
     OR a.service_role <> 'echo_activation_service' THEN
    RAISE EXCEPTION 'FIRST_SESSION_ACTIVATION_PROOF_REQUIRED' USING ERRCODE='23514';
  END IF;

  now_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF now_ms < p_token_issued_ms OR now_ms < p_token_not_before_ms OR now_ms >= p_token_expires_ms THEN
    RAISE EXCEPTION 'FIRST_SESSION_TOKEN_WINDOW_REJECTED' USING ERRCODE='23514';
  END IF;

  IF EXISTS (
    SELECT 1 FROM echo_identity.sessions
     WHERE principal_id=p.principal_id AND session_key<>p_session_key COLLATE "C"
  ) THEN
    RAISE EXCEPTION 'FIRST_SESSION_ALREADY_EXISTS' USING ERRCODE='55000';
  END IF;

  SELECT * INTO s FROM echo_identity.sessions WHERE session_key=p_session_key FOR UPDATE;
  IF FOUND THEN
    IF s.principal_id IS DISTINCT FROM p.principal_id OR s.auth_version <> p.auth_version
       OR floor(extract(epoch FROM s.issued_at)*1000)::bigint <> p_token_issued_ms
       OR floor(extract(epoch FROM s.expires_at)*1000)::bigint <> p_token_expires_ms THEN
      RAISE EXCEPTION 'FIRST_SESSION_CONFLICT' USING ERRCODE='23505';
    END IF;
    IF s.revoked THEN
      RAISE EXCEPTION 'FIRST_SESSION_REVOKED' USING ERRCODE='55000';
    END IF;
    replayed_value := true;
  ELSE
    INSERT INTO echo_identity.sessions(
      session_key,principal_id,auth_version,issued_at,expires_at,revoked
    ) VALUES (
      p_session_key,p.principal_id,p.auth_version,
      to_timestamp(p_token_issued_ms::double precision/1000.0),
      to_timestamp(p_token_expires_ms::double precision/1000.0),false
    );
    SELECT * INTO s FROM echo_identity.sessions WHERE session_key=p_session_key;
  END IF;

  now_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF now_ms < p_token_issued_ms OR now_ms < p_token_not_before_ms OR now_ms >= p_token_expires_ms THEN
    RAISE EXCEPTION 'FIRST_SESSION_TOKEN_WINDOW_REJECTED' USING ERRCODE='23514';
  END IF;

  RETURN jsonb_build_object(
    'sessionKey',s.session_key,'issuer',p.issuer,'subject',p.subject,
    'authVersion',s.auth_version,
    'issuedAtMs',floor(extract(epoch FROM s.issued_at)*1000)::bigint,
    'expiresAtMs',floor(extract(epoch FROM s.expires_at)*1000)::bigint,
    'replayed',replayed_value
  );
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_bootstrap_first_session(text,text,text,bigint,bigint,bigint) FROM PUBLIC;
ALTER FUNCTION echo_identity.runtime_bootstrap_first_session(text,text,text,bigint,bigint,bigint)
  OWNER TO echo_first_session_guard;
GRANT USAGE ON SCHEMA echo_identity TO echo_first_session_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_bootstrap_first_session(text,text,text,bigint,bigint,bigint)
  TO echo_first_session_runtime;
GRANT echo_first_session_runtime TO echo_first_session_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

REVOKE EXECUTE ON FUNCTION echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)
  FROM echo_identity_mutation_runtime,echo_identity_mutation_service;

ALTER ROLE echo_first_session_service SET search_path=pg_catalog;
ALTER ROLE echo_first_session_service SET row_security=on;
ALTER ROLE echo_first_session_service SET statement_timeout='5s';
ALTER ROLE echo_first_session_service SET lock_timeout='3s';
ALTER ROLE echo_first_session_service SET idle_in_transaction_session_timeout='10s';

COMMENT ON FUNCTION echo_identity.runtime_bootstrap_first_session(text,text,text,bigint,bigint,bigint) IS
  'c5c.3 sealed first-session creation for an audited activation. Principal is resolved from verified issuer+subject and session_key is backend-derived from verified jti.';
COMMENT ON ROLE echo_first_session_service IS
  'Backend-only first-session credential. No browser identity, raw Principal selector, writer/reviewer grant or direct registry access.';

-- Still blocked: repeat-login/session renewal, production credential rotation/drain,
-- HBA/TLS/proxy behavior, HTTP cookie/CSRF/CORS/rate-limit, writer/reviewer policy,
-- privacy/erasure and PUBLIC publishing.
