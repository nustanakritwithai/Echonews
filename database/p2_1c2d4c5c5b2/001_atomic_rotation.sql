-- c5c.5b.2: implement MONOTONIC_SIGNED_BEARER_ROTATION_V1.
-- Trusted signed backend only; SQL parameters are NOT bearer authentication.
-- Disposable deployment until remaining provider/HTTP/operations gates pass.
DO $$
BEGIN
  IF to_regprocedure('echo_identity.runtime_repeat_login_session(text,text,text,bigint,bigint,bigint)') IS NULL
     OR to_regprocedure('echo_identity.runtime_revoke_session(text,uuid)') IS NULL THEN
    RAISE EXCEPTION 'repeat-login and logout dependencies required' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_session_rotation_guard') IS NOT NULL
     OR to_regrole('echo_session_rotation_runtime') IS NOT NULL
     OR to_regrole('echo_session_rotation_service') IS NOT NULL
     OR to_regclass('echo_identity.session_rotations') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_rotate_active_session(text,text,text,bigint,bigint,bigint)') IS NOT NULL THEN
    RAISE EXCEPTION 'Do not overwrite rotation objects' USING ERRCODE='42710';
  END IF;
END $$;
CREATE ROLE echo_session_rotation_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_session_rotation_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_session_rotation_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4 PASSWORD NULL;

CREATE TABLE echo_identity.session_rotations (
  successor_key text COLLATE "C" PRIMARY KEY REFERENCES echo_identity.sessions(session_key),
  predecessor_key text COLLATE "C" NOT NULL UNIQUE REFERENCES echo_identity.sessions(session_key),
  principal_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
  auth_version integer NOT NULL CHECK(auth_version>0),
  policy_code text NOT NULL CHECK(policy_code='MONOTONIC_SIGNED_BEARER_ROTATION_V1'),
  rotated_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(rotated_at)),
  CHECK(successor_key<>predecessor_key)
);
REVOKE ALL ON echo_identity.session_rotations FROM PUBLIC;
CREATE FUNCTION echo_identity.reject_rotation_history_change() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'IMMUTABLE_ROTATION_HISTORY' USING ERRCODE='55000';
END $$;
CREATE TRIGGER rotation_history_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON echo_identity.session_rotations
FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.reject_rotation_history_change();
REVOKE ALL ON FUNCTION echo_identity.reject_rotation_history_change() FROM PUBLIC;

REVOKE ALL ON SCHEMA echo_identity,echo_core FROM
  echo_session_rotation_guard,echo_session_rotation_runtime,echo_session_rotation_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity,echo_core FROM
  echo_session_rotation_guard,echo_session_rotation_runtime,echo_session_rotation_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM
  echo_session_rotation_guard,echo_session_rotation_runtime,echo_session_rotation_service;
GRANT USAGE ON SCHEMA echo_identity TO echo_session_rotation_guard;
GRANT SELECT ON echo_identity.principals,echo_identity.sessions,echo_identity.activation_audit,
  echo_identity.session_rotations TO echo_session_rotation_guard;
-- Immutable-key UPDATE column grants are for PostgreSQL row locking only.
GRANT UPDATE(principal_id) ON echo_identity.principals TO echo_session_rotation_guard;
GRANT UPDATE(session_key) ON echo_identity.sessions TO echo_session_rotation_guard;
GRANT INSERT(session_key,principal_id,auth_version,issued_at,expires_at,revoked)
  ON echo_identity.sessions TO echo_session_rotation_guard;
GRANT INSERT ON echo_identity.session_rotations TO echo_session_rotation_guard;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) TO echo_session_rotation_guard;

CREATE FUNCTION echo_identity.runtime_rotate_active_session(
  p_issuer text,p_subject text,p_session_key text,
  p_token_issued_ms bigint,p_token_not_before_ms bigint,p_token_expires_ms bigint
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p echo_identity.principals%ROWTYPE;
DECLARE current_s echo_identity.sessions%ROWTYPE;
DECLARE candidate_s echo_identity.sessions%ROWTYPE;
DECLARE a echo_identity.activation_audit%ROWTYPE;
DECLARE now_ms bigint;
DECLARE live_count bigint;
DECLARE current_key text;
DECLARE valid_until bigint;
DECLARE replayed_value boolean := false;
DECLARE revocation jsonb;
BEGIN
  IF session_user::text IS DISTINCT FROM 'echo_session_rotation_service' THEN
    RAISE EXCEPTION 'ROTATION_SERVICE_REQUIRED' USING ERRCODE='42501';
  END IF;
  IF p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048 OR btrim(p_issuer)=''
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255 OR btrim(p_subject)=''
     OR p_session_key IS NULL OR p_session_key !~ '^[a-f0-9]{64}$'
     OR p_token_issued_ms IS NULL OR p_token_not_before_ms IS NULL OR p_token_expires_ms IS NULL
     OR p_token_issued_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_not_before_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_expires_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_issued_ms>p_token_not_before_ms OR p_token_not_before_ms>=p_token_expires_ms THEN
    RAISE EXCEPTION 'INVALID_ROTATION_REQUEST' USING ERRCODE='22023';
  END IF;
  IF current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'UNSUPPORTED_ROTATION_ISOLATION' USING ERRCODE='25001';
  END IF;
  -- Same Principal-first protocol as first-session, repeat-login and logout.
  SELECT * INTO p FROM echo_identity.principals
    WHERE issuer=p_issuer COLLATE "C" AND subject=p_subject COLLATE "C" FOR UPDATE;
  IF NOT FOUND OR NOT p.enabled OR p.actor_kind<>'HUMAN' OR p.auth_version<2 THEN
    RAISE EXCEPTION 'ROTATION_AUTHORITY_REJECTED' USING ERRCODE='23514';
  END IF;
  SELECT * INTO a FROM echo_identity.activation_audit WHERE principal_id=p.principal_id;
  IF NOT FOUND OR a.from_auth_version<>1 OR a.to_auth_version<>2
     OR a.policy_code<>'PROVEN_ACCOUNT_ONBOARDING_V1' OR a.service_role<>'echo_activation_service' THEN
    RAISE EXCEPTION 'ROTATION_ACTIVATION_REQUIRED' USING ERRCODE='23514';
  END IF;

  -- Lock current live rows and any prior use of the candidate key in stable order.
  -- Principal lock serializes sanctioned issuers; schema INSERT guard also takes
  -- a Principal lock. Privileged direct DDL/DML is not a public threat boundary.
  PERFORM session_key FROM echo_identity.sessions
    WHERE (principal_id=p.principal_id AND auth_version=p.auth_version
           AND NOT revoked AND expires_at>clock_timestamp())
       OR session_key=p_session_key COLLATE "C"
    ORDER BY session_key FOR UPDATE;
  now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF now_ms<p_token_issued_ms OR now_ms<p_token_not_before_ms OR now_ms>=p_token_expires_ms THEN
    RAISE EXCEPTION 'ROTATION_TOKEN_WINDOW_REJECTED' USING ERRCODE='23514';
  END IF;
  SELECT count(*),min(session_key) INTO live_count,current_key FROM echo_identity.sessions
    WHERE principal_id=p.principal_id AND auth_version=p.auth_version AND NOT revoked
      AND expires_at>to_timestamp(now_ms::double precision/1000.0);
  IF live_count=0 THEN
    RAISE EXCEPTION 'ROTATION_NO_ACTIVE_USE_REPEAT_LOGIN' USING ERRCODE='P0002';
  END IF;
  IF live_count<>1 THEN
    RAISE EXCEPTION 'ROTATION_MULTIPLE_ACTIVE_CONTRACT' USING ERRCODE='23514';
  END IF;
  SELECT * INTO current_s FROM echo_identity.sessions WHERE session_key=current_key;
  IF ceil(extract(epoch FROM current_s.issued_at)*1000)::bigint>now_ms THEN
    RAISE EXCEPTION 'ROTATION_CURRENT_TIME_CONTRACT' USING ERRCODE='23514';
  END IF;
  valid_until:=LEAST(p_token_expires_ms,floor(extract(epoch FROM current_s.expires_at)*1000)::bigint);

  IF current_key=p_session_key THEN
    -- Exact retry must not silently rewrite/extend an existing signed lifetime.
    IF floor(extract(epoch FROM current_s.issued_at)*1000)::bigint<>p_token_issued_ms
       OR floor(extract(epoch FROM current_s.expires_at)*1000)::bigint<>p_token_expires_ms THEN
      RAISE EXCEPTION 'ROTATION_REPLAY_CONFLICT' USING ERRCODE='23505';
    END IF;
    replayed_value:=true;
  ELSE
    SELECT * INTO candidate_s FROM echo_identity.sessions WHERE session_key=p_session_key COLLATE "C";
    IF FOUND THEN
      IF candidate_s.principal_id=p.principal_id AND candidate_s.revoked THEN
        RAISE EXCEPTION 'ROTATION_REVOKED_PREDECESSOR' USING ERRCODE='55000';
      END IF;
      RAISE EXCEPTION 'ROTATION_KNOWN_KEY_CONFLICT' USING ERRCODE='23505';
    END IF;
    IF p_token_issued_ms<=floor(extract(epoch FROM current_s.issued_at)*1000)::bigint THEN
      RAISE EXCEPTION 'ROTATION_STALE_OR_EQUAL_BEARER' USING ERRCODE='23514';
    END IF;

    revocation:=echo_identity.runtime_revoke_session(current_key,p.principal_id);
    IF revocation->>'sessionKey' IS DISTINCT FROM current_key
       OR revocation->>'principalId' IS DISTINCT FROM p.principal_id::text
       OR revocation->'revoked' IS DISTINCT FROM 'true'::jsonb THEN
      RAISE EXCEPTION 'ROTATION_REVOKE_CONTRACT' USING ERRCODE='23514';
    END IF;
    INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at,revoked)
      VALUES(p_session_key,p.principal_id,p.auth_version,
             to_timestamp(p_token_issued_ms::double precision/1000.0),
             to_timestamp(p_token_expires_ms::double precision/1000.0),false);
    INSERT INTO echo_identity.session_rotations(successor_key,predecessor_key,principal_id,auth_version,policy_code)
      VALUES(p_session_key,current_key,p.principal_id,p.auth_version,'MONOTONIC_SIGNED_BEARER_ROTATION_V1');
  END IF;
  -- Revocation + new row + lineage all roll back on this or any later failure.
  now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF now_ms<p_token_issued_ms OR now_ms<p_token_not_before_ms OR now_ms>=valid_until THEN
    RAISE EXCEPTION 'ROTATION_FINAL_TIME_REJECTED' USING ERRCODE='23514';
  END IF;
  SELECT count(*),min(session_key) INTO live_count,current_key FROM echo_identity.sessions
    WHERE principal_id=p.principal_id AND auth_version=p.auth_version AND NOT revoked
      AND expires_at>to_timestamp(now_ms::double precision/1000.0);
  IF live_count<>1 OR current_key IS DISTINCT FROM p_session_key THEN
    RAISE EXCEPTION 'ROTATION_POSTCONDITION_VIOLATION' USING ERRCODE='23514';
  END IF;
  RETURN jsonb_build_object('sessionKey',p_session_key,'issuer',p.issuer,'subject',p.subject,
    'authVersion',p.auth_version,'issuedAtMs',p_token_issued_ms,'expiresAtMs',p_token_expires_ms,
    'authorizedUntilMs',valid_until,'replayed',replayed_value,'policy','MONOTONIC_SIGNED_BEARER_ROTATION_V1');
END $$;
REVOKE ALL ON FUNCTION echo_identity.runtime_rotate_active_session(text,text,text,bigint,bigint,bigint) FROM PUBLIC;
ALTER FUNCTION echo_identity.runtime_rotate_active_session(text,text,text,bigint,bigint,bigint)
  OWNER TO echo_session_rotation_guard;
GRANT USAGE ON SCHEMA echo_identity TO echo_session_rotation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_rotate_active_session(text,text,text,bigint,bigint,bigint)
  TO echo_session_rotation_runtime;
GRANT echo_session_rotation_runtime TO echo_session_rotation_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
ALTER ROLE echo_session_rotation_service SET search_path=pg_catalog;
ALTER ROLE echo_session_rotation_service SET row_security=on;
ALTER ROLE echo_session_rotation_service SET statement_timeout='5s';
ALTER ROLE echo_session_rotation_service SET lock_timeout='3s';
ALTER ROLE echo_session_rotation_service SET idle_in_transaction_session_timeout='10s';
COMMENT ON FUNCTION echo_identity.runtime_rotate_active_session(text,text,text,bigint,bigint,bigint) IS
  'c5c.5b.2 paired signed boundary: atomic monotonic active-session rotation with immutable lineage, no refresh token/HTTP. Receipt is not future authorization.';
