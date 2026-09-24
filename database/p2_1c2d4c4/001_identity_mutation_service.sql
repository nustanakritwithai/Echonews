-- P2.1c.2d.4c.4: least-privilege identity provisioning / session mutation boundary.
-- Scope: provision a disabled principal against already-proven Actor+Source rows,
-- change enabled/private-writer authority with optimistic generation checks, create
-- a session at the current generation, and revoke one session. Reviewer authority,
-- actor/source ownership proof, HTTP auth, credential rotation and erasure are OUT.
DO $$
BEGIN
  IF to_regclass('echo_identity.principals') IS NULL
     OR to_regclass('echo_identity.sessions') IS NULL
     OR to_regrole('echo_identity_registry_service') IS NULL
     OR to_regprocedure('echo_identity.runtime_lookup_session(text,text,text)') IS NULL THEN
    RAISE EXCEPTION 'P2.1c.2d.4c.3 registry service boundary required first' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_identity_mutation_guard') IS NOT NULL
     OR to_regrole('echo_identity_mutation_runtime') IS NOT NULL
     OR to_regrole('echo_identity_mutation_service') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_revoke_session(text,uuid)') IS NOT NULL THEN
    RAISE EXCEPTION 'Identity mutation service objects already exist; do not overwrite grants' USING ERRCODE='42710';
  END IF;
END $$;

CREATE ROLE echo_identity_mutation_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_identity_mutation_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_identity_mutation_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 6 PASSWORD NULL;

REVOKE ALL ON SCHEMA echo_identity FROM echo_identity_mutation_guard,
  echo_identity_mutation_runtime, echo_identity_mutation_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM echo_identity_mutation_guard,
  echo_identity_mutation_runtime, echo_identity_mutation_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM echo_identity_mutation_guard,
  echo_identity_mutation_runtime, echo_identity_mutation_service;

GRANT USAGE ON SCHEMA echo_identity TO echo_identity_mutation_guard;
GRANT SELECT ON echo_identity.principals, echo_identity.sessions TO echo_identity_mutation_guard;
GRANT INSERT (principal_id,issuer,subject,actor_id,actor_kind,source_id,
              enabled,writer_enabled,reviewer_enabled,auth_version)
  ON echo_identity.principals TO echo_identity_mutation_guard;
GRANT UPDATE (enabled,writer_enabled,auth_version)
  ON echo_identity.principals TO echo_identity_mutation_guard;
GRANT INSERT (session_key,principal_id,auth_version,issued_at,expires_at,revoked)
  ON echo_identity.sessions TO echo_identity_mutation_guard;
GRANT UPDATE (revoked) ON echo_identity.sessions TO echo_identity_mutation_guard;

CREATE FUNCTION echo_identity.runtime_provision_principal(
  p_principal_id uuid,
  p_issuer text,
  p_subject text,
  p_actor_id uuid,
  p_source_id uuid
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp
SET row_security = on AS $$
DECLARE p echo_identity.principals%ROWTYPE;
BEGIN
  IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_actor_id IS NULL OR p_actor_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_source_id IS NULL OR p_source_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048 OR btrim(p_issuer)=''
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255 OR btrim(p_subject)='' THEN
    RAISE EXCEPTION 'INVALID_IDENTITY_PROVISIONING_INPUT' USING ERRCODE='22023';
  END IF;

  INSERT INTO echo_identity.principals(
    principal_id,issuer,subject,actor_id,actor_kind,source_id,
    enabled,writer_enabled,reviewer_enabled,auth_version
  ) VALUES (
    p_principal_id,p_issuer,p_subject,p_actor_id,'HUMAN',p_source_id,
    false,false,false,1
  ) ON CONFLICT DO NOTHING;

  SELECT * INTO p FROM echo_identity.principals WHERE principal_id=p_principal_id;
  IF NOT FOUND
     OR p.issuer IS DISTINCT FROM p_issuer
     OR p.subject IS DISTINCT FROM p_subject
     OR p.actor_id IS DISTINCT FROM p_actor_id
     OR p.actor_kind <> 'HUMAN'
     OR p.source_id IS DISTINCT FROM p_source_id THEN
    RAISE EXCEPTION 'IDENTITY_PROVISIONING_CONFLICT' USING ERRCODE='23505';
  END IF;

  RETURN jsonb_build_object(
    'principalId',p.principal_id,'issuer',p.issuer,'subject',p.subject,
    'actorId',p.actor_id,'sourceId',p.source_id,'enabled',p.enabled,
    'writerEnabled',p.writer_enabled,'reviewerEnabled',p.reviewer_enabled,
    'authVersion',p.auth_version
  );
END $$;

CREATE FUNCTION echo_identity.runtime_change_principal_authority(
  p_principal_id uuid,
  p_expected_auth_version integer,
  p_enabled boolean,
  p_writer_enabled boolean
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp
SET row_security = on AS $$
DECLARE p echo_identity.principals%ROWTYPE;
BEGIN
  IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_expected_auth_version IS NULL OR p_expected_auth_version <= 0
     OR p_enabled IS NULL OR p_writer_enabled IS NULL
     OR (NOT p_enabled AND p_writer_enabled) THEN
    RAISE EXCEPTION 'INVALID_AUTHORITY_CHANGE_INPUT' USING ERRCODE='22023';
  END IF;

  SELECT * INTO p FROM echo_identity.principals
   WHERE principal_id=p_principal_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'IDENTITY_MUTATION_REJECTED' USING ERRCODE='P0002';
  END IF;
  IF p.reviewer_enabled THEN
    RAISE EXCEPTION 'REVIEWER_AUTHORITY_OUT_OF_SCOPE' USING ERRCODE='55000';
  END IF;

  IF p.auth_version = p_expected_auth_version + 1
     AND p.enabled = p_enabled AND p.writer_enabled = p_writer_enabled THEN
    RETURN jsonb_build_object(
      'principalId',p.principal_id,'enabled',p.enabled,
      'writerEnabled',p.writer_enabled,'reviewerEnabled',p.reviewer_enabled,
      'authVersion',p.auth_version,'replayed',true
    );
  END IF;
  IF p.auth_version <> p_expected_auth_version THEN
    RAISE EXCEPTION 'STALE_AUTHORITY_GENERATION' USING ERRCODE='40001';
  END IF;

  IF p.enabled = p_enabled AND p.writer_enabled = p_writer_enabled THEN
    RETURN jsonb_build_object(
      'principalId',p.principal_id,'enabled',p.enabled,
      'writerEnabled',p.writer_enabled,'reviewerEnabled',p.reviewer_enabled,
      'authVersion',p.auth_version,'replayed',true
    );
  END IF;

  UPDATE echo_identity.principals
     SET enabled=p_enabled,
         writer_enabled=p_writer_enabled,
         auth_version=auth_version+1
   WHERE principal_id=p_principal_id
   RETURNING * INTO p;

  RETURN jsonb_build_object(
    'principalId',p.principal_id,'enabled',p.enabled,
    'writerEnabled',p.writer_enabled,'reviewerEnabled',p.reviewer_enabled,
    'authVersion',p.auth_version,'replayed',false
  );
END $$;

CREATE FUNCTION echo_identity.runtime_create_session(
  p_session_key text,
  p_principal_id uuid,
  p_auth_version integer,
  p_issued_at_ms bigint,
  p_expires_at_ms bigint
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp
SET row_security = on AS $$
DECLARE p echo_identity.principals%ROWTYPE;
DECLARE s echo_identity.sessions%ROWTYPE;
DECLARE now_ms bigint;
BEGIN
  now_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF p_session_key IS NULL OR p_session_key !~ '^[a-f0-9]{64}$'
     OR p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_auth_version IS NULL OR p_auth_version <= 0
     OR p_issued_at_ms IS NULL OR p_expires_at_ms IS NULL
     OR p_issued_at_ms <= 0 OR p_expires_at_ms <= p_issued_at_ms
     OR p_expires_at_ms <= now_ms THEN
    RAISE EXCEPTION 'INVALID_SESSION_PROVISIONING_INPUT' USING ERRCODE='22023';
  END IF;

  SELECT * INTO p FROM echo_identity.principals
   WHERE principal_id=p_principal_id FOR SHARE;
  IF NOT FOUND OR NOT p.enabled OR p.auth_version <> p_auth_version THEN
    RAISE EXCEPTION 'SESSION_AUTHORITY_REJECTED' USING ERRCODE='23514';
  END IF;

  INSERT INTO echo_identity.sessions(
    session_key,principal_id,auth_version,issued_at,expires_at,revoked
  ) VALUES (
    p_session_key,p_principal_id,p_auth_version,
    to_timestamp(p_issued_at_ms::double precision/1000.0),
    to_timestamp(p_expires_at_ms::double precision/1000.0),false
  ) ON CONFLICT DO NOTHING;

  SELECT * INTO s FROM echo_identity.sessions WHERE session_key=p_session_key FOR UPDATE;
  IF NOT FOUND
     OR s.principal_id IS DISTINCT FROM p_principal_id
     OR s.auth_version <> p_auth_version
     OR floor(extract(epoch FROM s.issued_at)*1000)::bigint <> p_issued_at_ms
     OR floor(extract(epoch FROM s.expires_at)*1000)::bigint <> p_expires_at_ms THEN
    RAISE EXCEPTION 'SESSION_PROVISIONING_CONFLICT' USING ERRCODE='23505';
  END IF;
  IF s.revoked THEN
    RAISE EXCEPTION 'REVOKED_SESSION_CANNOT_BE_RECREATED' USING ERRCODE='55000';
  END IF;

  RETURN jsonb_build_object(
    'sessionKey',s.session_key,'principalId',s.principal_id,
    'authVersion',s.auth_version,
    'issuedAtMs',floor(extract(epoch FROM s.issued_at)*1000)::bigint,
    'expiresAtMs',floor(extract(epoch FROM s.expires_at)*1000)::bigint,
    'revoked',s.revoked
  );
END $$;

CREATE FUNCTION echo_identity.runtime_revoke_session(
  p_session_key text,
  p_principal_id uuid
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp
SET row_security = on AS $$
DECLARE s echo_identity.sessions%ROWTYPE;
BEGIN
  IF p_session_key IS NULL OR p_session_key !~ '^[a-f0-9]{64}$'
     OR p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
    RAISE EXCEPTION 'INVALID_SESSION_REVOCATION_INPUT' USING ERRCODE='22023';
  END IF;

  SELECT * INTO s FROM echo_identity.sessions
   WHERE session_key=p_session_key FOR UPDATE;
  IF NOT FOUND OR s.principal_id IS DISTINCT FROM p_principal_id THEN
    RAISE EXCEPTION 'IDENTITY_MUTATION_REJECTED' USING ERRCODE='P0002';
  END IF;
  IF NOT s.revoked THEN
    UPDATE echo_identity.sessions SET revoked=true
     WHERE session_key=p_session_key RETURNING * INTO s;
  END IF;

  RETURN jsonb_build_object(
    'sessionKey',s.session_key,'principalId',s.principal_id,
    'authVersion',s.auth_version,'revoked',s.revoked
  );
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) FROM PUBLIC;

GRANT USAGE ON SCHEMA echo_identity TO echo_identity_mutation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)
  TO echo_identity_mutation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)
  TO echo_identity_mutation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)
  TO echo_identity_mutation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_revoke_session(text,uuid)
  TO echo_identity_mutation_runtime;

ALTER FUNCTION echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)
  OWNER TO echo_identity_mutation_guard;
ALTER FUNCTION echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)
  OWNER TO echo_identity_mutation_guard;
ALTER FUNCTION echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint)
  OWNER TO echo_identity_mutation_guard;
ALTER FUNCTION echo_identity.runtime_revoke_session(text,uuid)
  OWNER TO echo_identity_mutation_guard;

GRANT echo_identity_mutation_runtime TO echo_identity_mutation_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

ALTER ROLE echo_identity_mutation_service SET search_path = pg_catalog;
ALTER ROLE echo_identity_mutation_service SET row_security = on;
ALTER ROLE echo_identity_mutation_service SET statement_timeout = '5s';
ALTER ROLE echo_identity_mutation_service SET lock_timeout = '3s';
ALTER ROLE echo_identity_mutation_service SET idle_in_transaction_session_timeout = '10s';

COMMENT ON ROLE echo_identity_mutation_service IS
  'Backend-only identity/session mutation login. Fixed SET LOCAL role; no direct registry table or function privilege.';
COMMENT ON FUNCTION echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid) IS
  'Create one disabled HUMAN principal for an already-proven Actor+Source; exact retry is idempotent.';
COMMENT ON FUNCTION echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean) IS
  'Optimistic enabled/private-writer authority change. Reviewer authority remains out of scope.';
COMMENT ON FUNCTION echo_identity.runtime_create_session(text,uuid,integer,bigint,bigint) IS
  'Create current-generation enabled-principal session; exact retry is idempotent.';
COMMENT ON FUNCTION echo_identity.runtime_revoke_session(text,uuid) IS
  'Idempotently revoke one session bound to the supplied principal.';

-- PASSWORD NULL blocks password authentication only. Production credential issue/
-- rotation, HBA/TLS/client certificates, Actor/Source ownership proof, reviewer grants,
-- bulk revocation, erasure and public HTTP auth remain separate blocking gates.
