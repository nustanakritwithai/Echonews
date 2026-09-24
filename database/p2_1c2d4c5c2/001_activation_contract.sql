-- P2.1c.2d.4c.5c.2 — first-activation authorization contract + immutable audit.
-- Scope: a dedicated internal activation credential may activate exactly one
-- freshly proof-provisioned Principal (auth_version=1) into enabled/read-only
-- authority (auth_version=2). It NEVER grants writer/reviewer authority and it
-- NEVER creates a Session. Browser/self-service activation remains forbidden.
DO $$
BEGIN
  IF to_regprocedure('echo_identity.runtime_provision_signed_principal(uuid,text,text,bigint,bigint,bigint)') IS NULL
     OR to_regprocedure('echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)') IS NULL
     OR to_regclass('echo_identity.account_link_proofs') IS NULL THEN
    RAISE EXCEPTION 'c5c.1 + c4 + c5a required first' USING ERRCODE='55000';
  END IF;
  IF to_regclass('echo_identity.activation_audit') IS NOT NULL
     OR to_regrole('echo_activation_guard') IS NOT NULL
     OR to_regrole('echo_activation_runtime') IS NOT NULL
     OR to_regrole('echo_activation_service') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_activate_provisioned_principal(uuid,uuid,integer)') IS NOT NULL THEN
    RAISE EXCEPTION 'Activation contract already exists; do not overwrite grants' USING ERRCODE='42710';
  END IF;
END $$;

CREATE TABLE echo_identity.activation_audit (
  decision_id uuid PRIMARY KEY CHECK (decision_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  principal_id uuid NOT NULL UNIQUE REFERENCES echo_identity.principals(principal_id),
  proof_id uuid NOT NULL REFERENCES echo_identity.account_link_proofs(proof_id),
  policy_code text COLLATE "C" NOT NULL CHECK (policy_code='PROVEN_ACCOUNT_ONBOARDING_V1'),
  from_auth_version integer NOT NULL CHECK (from_auth_version=1),
  to_auth_version integer NOT NULL CHECK (to_auth_version=2),
  service_role text COLLATE "C" NOT NULL CHECK (service_role='echo_activation_service'),
  recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at))
);
REVOKE ALL ON echo_identity.activation_audit FROM PUBLIC;

CREATE ROLE echo_activation_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_activation_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_activation_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4 PASSWORD NULL;

REVOKE ALL ON SCHEMA echo_identity FROM
  echo_activation_guard,echo_activation_runtime,echo_activation_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM
  echo_activation_guard,echo_activation_runtime,echo_activation_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM
  echo_activation_guard,echo_activation_runtime,echo_activation_service;

-- Guard receives only the columns/data required to prove first activation and
-- append an audit record. No writer/reviewer/session mutation privilege exists.
GRANT USAGE ON SCHEMA echo_identity TO echo_activation_guard;
GRANT SELECT ON echo_identity.principals,echo_identity.account_link_proofs,
                echo_identity.activation_audit TO echo_activation_guard;
GRANT UPDATE (enabled,auth_version) ON echo_identity.principals TO echo_activation_guard;
GRANT INSERT ON echo_identity.activation_audit TO echo_activation_guard;

CREATE FUNCTION echo_identity.runtime_activate_provisioned_principal(
  p_decision_id uuid,
  p_principal_id uuid,
  p_expected_auth_version integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE a echo_identity.activation_audit%ROWTYPE;
DECLARE p echo_identity.principals%ROWTYPE;
DECLARE proof_id_value uuid;
DECLARE now_value timestamptz;
BEGIN
  -- Possession of the dedicated DB service credential is the authorization for
  -- this internal policy step. A user Bearer token is intentionally NOT accepted.
  IF session_user::text IS DISTINCT FROM 'echo_activation_service' THEN
    RAISE EXCEPTION 'ACTIVATION_SERVICE_REQUIRED' USING ERRCODE='42501';
  END IF;
  IF p_decision_id IS NULL OR p_decision_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_expected_auth_version IS NULL OR p_expected_auth_version <> 1 THEN
    RAISE EXCEPTION 'INVALID_ACTIVATION_REQUEST' USING ERRCODE='22023';
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'UNSUPPORTED_ACTIVATION_ISOLATION' USING ERRCODE='25001';
  END IF;

  -- Exact decision retry is the only replay path. This covers a committed DB
  -- transaction whose acknowledgement/reset was lost without mutating twice.
  SELECT * INTO a FROM echo_identity.activation_audit WHERE decision_id=p_decision_id;
  IF FOUND THEN
    IF a.principal_id IS DISTINCT FROM p_principal_id
       OR a.from_auth_version <> p_expected_auth_version
       OR a.policy_code <> 'PROVEN_ACCOUNT_ONBOARDING_V1'
       OR a.service_role <> 'echo_activation_service' THEN
      RAISE EXCEPTION 'ACTIVATION_DECISION_CONFLICT' USING ERRCODE='23505';
    END IF;
    RETURN jsonb_build_object(
      'decisionId',a.decision_id,'principalId',a.principal_id,
      'authVersion',a.to_auth_version,'enabled',true,
      'writerEnabled',false,'reviewerEnabled',false,'replayed',true
    );
  END IF;

  SELECT * INTO p FROM echo_identity.principals
   WHERE principal_id=p_principal_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='P0002';
  END IF;

  -- This service is only for the initial disabled -> enabled/read-only transition.
  -- Any later suspension/reactivation/writer policy needs a different audited gate.
  IF p.auth_version <> 1 OR p.auth_version <> p_expected_auth_version
     OR p.enabled OR p.writer_enabled OR p.reviewer_enabled THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='23514';
  END IF;

  -- The Principal must descend from the proven account-link path. Expiry is not
  -- rechecked here: c5c.1 consumed the proof while both token and proof were live.
  SELECT alp.proof_id INTO proof_id_value
    FROM echo_identity.account_link_proofs alp
   WHERE alp.consumed_principal_id=p.principal_id
     AND alp.consumed_at IS NOT NULL
     AND alp.issuer=p.issuer COLLATE "C"
     AND alp.subject=p.subject COLLATE "C"
     AND alp.actor_id=p.actor_id
     AND alp.source_id=p.source_id
   ORDER BY alp.consumed_at,alp.proof_id
   LIMIT 1;
  IF proof_id_value IS NULL THEN
    RAISE EXCEPTION 'ACTIVATION_PROVENANCE_REQUIRED' USING ERRCODE='23514';
  END IF;

  -- A different decision may have activated the Principal while we waited.
  IF EXISTS (SELECT 1 FROM echo_identity.activation_audit WHERE principal_id=p.principal_id) THEN
    RAISE EXCEPTION 'PRINCIPAL_ALREADY_ACTIVATED' USING ERRCODE='23505';
  END IF;

  UPDATE echo_identity.principals
     SET enabled=true, auth_version=auth_version+1
   WHERE principal_id=p.principal_id
     AND auth_version=1 AND NOT enabled AND NOT writer_enabled AND NOT reviewer_enabled
   RETURNING * INTO p;
  IF NOT FOUND OR p.auth_version <> 2 OR NOT p.enabled OR p.writer_enabled OR p.reviewer_enabled THEN
    RAISE EXCEPTION 'ACTIVATION_CONTRACT_VIOLATION' USING ERRCODE='23514';
  END IF;

  now_value := clock_timestamp();
  INSERT INTO echo_identity.activation_audit(
    decision_id,principal_id,proof_id,policy_code,from_auth_version,to_auth_version,
    service_role,recorded_at
  ) VALUES(
    p_decision_id,p.principal_id,proof_id_value,'PROVEN_ACCOUNT_ONBOARDING_V1',1,2,
    'echo_activation_service',now_value
  );

  RETURN jsonb_build_object(
    'decisionId',p_decision_id,'principalId',p.principal_id,
    'authVersion',p.auth_version,'enabled',p.enabled,
    'writerEnabled',p.writer_enabled,'reviewerEnabled',p.reviewer_enabled,'replayed',false
  );
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_activate_provisioned_principal(uuid,uuid,integer) FROM PUBLIC;
ALTER FUNCTION echo_identity.runtime_activate_provisioned_principal(uuid,uuid,integer)
  OWNER TO echo_activation_guard;
GRANT USAGE ON SCHEMA echo_identity TO echo_activation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_activate_provisioned_principal(uuid,uuid,integer)
  TO echo_activation_runtime;
GRANT echo_activation_runtime TO echo_activation_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

-- Close the legacy unaudited activation bypass. The c4 mutation service keeps
-- session create/revoke for later bootstrap/logout work, but cannot enable an
-- account or grant writer authority after this migration.
REVOKE EXECUTE ON FUNCTION echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)
  FROM echo_identity_mutation_runtime,echo_identity_mutation_service;

ALTER ROLE echo_activation_service SET search_path=pg_catalog;
ALTER ROLE echo_activation_service SET row_security=on;
ALTER ROLE echo_activation_service SET statement_timeout='5s';
ALTER ROLE echo_activation_service SET lock_timeout='3s';
ALTER ROLE echo_activation_service SET idle_in_transaction_session_timeout='10s';

COMMENT ON TABLE echo_identity.activation_audit IS
  'Append-only runtime audit for first account activation. One row per Principal and one exact decision id.';
COMMENT ON FUNCTION echo_identity.runtime_activate_provisioned_principal(uuid,uuid,integer) IS
  'c5c.2 dedicated internal policy activation: proof-provisioned auth_version 1 -> enabled/read-only auth_version 2; exact decision retry only; no Session.';
COMMENT ON ROLE echo_activation_service IS
  'Dedicated internal first-activation credential. Never a browser/user identity; no writer/reviewer/session privilege.';

-- Still blocked after this gate: first-session bootstrap, activation-service
-- production credential rotation/drain, operator/policy UI/API, suspension/reactivation,
-- writer/reviewer policy, HTTP security and public publishing.
