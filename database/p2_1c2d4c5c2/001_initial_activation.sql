-- c5c.2: first activation only. No writer/reviewer grants, sessions or HTTP.
-- Paired signed backend verifies issuer/subject/session; these SQL parameters
-- are NOT bearer authentication. No LOGIN or initial approvers are provisioned.
DO $$
BEGIN
  IF to_regprocedure('echo_identity.runtime_provision_signed_principal(uuid,text,text,bigint,bigint,bigint)') IS NULL
     OR to_regrole('echo_identity_mutation_runtime') IS NULL THEN
    RAISE EXCEPTION 'c5c.1 required' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_activation_guard') IS NOT NULL OR to_regrole('echo_activation_runtime') IS NOT NULL
     OR to_regclass('echo_identity.activation_grants') IS NOT NULL
     OR to_regclass('echo_identity.activation_audit') IS NOT NULL THEN
    RAISE EXCEPTION 'Do not overwrite activation objects' USING ERRCODE='42710';
  END IF;
END $$;
CREATE ROLE echo_activation_guard NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_activation_runtime NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Only reviewed administrative provisioning may INSERT grants. There is no
-- runtime grant issuer. Each grant is scoped to one approver generation/target.
CREATE TABLE echo_identity.activation_grants (
  grant_id uuid PRIMARY KEY,
  approver_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
  target_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
  approver_auth_version integer NOT NULL CHECK(approver_auth_version > 0),
  target_auth_version integer NOT NULL DEFAULT 1 CHECK(target_auth_version = 1),
  policy_version text NOT NULL DEFAULT 'initial-enable-only-v1' CHECK(policy_version='initial-enable-only-v1'),
  authority_ref text NOT NULL CHECK(length(btrim(authority_ref)) BETWEEN 1 AND 256),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(issued_at)),
  expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
  revoked boolean NOT NULL DEFAULT false,
  CHECK(approver_id <> target_id),
  CHECK(expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes')
);
CREATE TABLE echo_identity.activation_audit (
  request_id uuid PRIMARY KEY,
  grant_id uuid NOT NULL REFERENCES echo_identity.activation_grants(grant_id),
  approver_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
  approver_actor_id uuid NOT NULL REFERENCES echo_core.actors(actor_id),
  approver_source_id uuid NOT NULL REFERENCES echo_core.sources(source_id),
  approver_auth_version integer NOT NULL CHECK(approver_auth_version > 0),
  session_key text NOT NULL CHECK(session_key ~ '^[a-f0-9]{64}$'),
  target_id uuid NOT NULL UNIQUE REFERENCES echo_identity.principals(principal_id),
  before_auth_version integer NOT NULL CHECK(before_auth_version=1),
  after_auth_version integer NOT NULL CHECK(after_auth_version=2),
  decision text NOT NULL CHECK(decision='ACTIVATED_NO_ROLES'),
  policy_version text NOT NULL CHECK(policy_version='initial-enable-only-v1'),
  authority_ref text NOT NULL,
  reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 1000),
  checked_at timestamptz NOT NULL CHECK(isfinite(checked_at)),
  CHECK(approver_id <> target_id)
);
REVOKE ALL ON echo_identity.activation_grants,echo_identity.activation_audit FROM PUBLIC;

CREATE FUNCTION echo_identity.protect_activation_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF ROW(NEW.grant_id,NEW.approver_id,NEW.target_id,NEW.approver_auth_version,
         NEW.target_auth_version,NEW.policy_version,NEW.authority_ref,NEW.issued_at,NEW.expires_at)
     IS DISTINCT FROM ROW(OLD.grant_id,OLD.approver_id,OLD.target_id,OLD.approver_auth_version,
         OLD.target_auth_version,OLD.policy_version,OLD.authority_ref,OLD.issued_at,OLD.expires_at)
     OR (OLD.revoked AND NOT NEW.revoked) THEN
    RAISE EXCEPTION 'IMMUTABLE_ACTIVATION_GRANT' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE FUNCTION echo_identity.protect_activation_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'IMMUTABLE_ACTIVATION_HISTORY' USING ERRCODE='55000';
END $$;
CREATE TRIGGER activation_grant_update BEFORE UPDATE ON echo_identity.activation_grants
FOR EACH ROW EXECUTE FUNCTION echo_identity.protect_activation_grant();
CREATE TRIGGER activation_grant_removal BEFORE DELETE OR TRUNCATE ON echo_identity.activation_grants
FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.protect_activation_history();
CREATE TRIGGER activation_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON echo_identity.activation_audit
FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.protect_activation_history();
REVOKE ALL ON FUNCTION echo_identity.protect_activation_grant(),echo_identity.protect_activation_history() FROM PUBLIC;

GRANT USAGE ON SCHEMA echo_identity TO echo_activation_guard;
GRANT SELECT ON echo_identity.principals,echo_identity.sessions,echo_identity.account_link_proofs,
  echo_identity.activation_grants,echo_identity.activation_audit TO echo_activation_guard;
-- Minimal column UPDATE grants are needed for row locks. NO runtime membership
-- permits SET ROLE to this guard; its only exposed function contains static SQL.
GRANT UPDATE(auth_version) ON echo_identity.principals TO echo_activation_guard;
GRANT UPDATE(revoked) ON echo_identity.sessions,echo_identity.activation_grants TO echo_activation_guard;
GRANT INSERT ON echo_identity.activation_audit TO echo_activation_guard;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)
  TO echo_activation_guard;
-- Intentional hardening: the former unaudited broad runtime entry is no longer
-- callable. Its owner remains a trusted NOLOGIN guard; old runtime callers DENY.
-- An audited disable/reactivation/admin interface is a separate future gate.
REVOKE EXECUTE ON FUNCTION echo_identity.runtime_change_principal_authority(uuid,integer,boolean,boolean)
  FROM echo_identity_mutation_runtime;

CREATE FUNCTION echo_identity.runtime_activate_initial_account(
  p_request_id uuid,p_grant_id uuid,p_issuer text,p_subject text,p_session_key text,
  p_issued_ms bigint,p_not_before_ms bigint,p_expires_ms bigint,p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE g echo_identity.activation_grants%ROWTYPE;
DECLARE a echo_identity.principals%ROWTYPE;
DECLARE t echo_identity.principals%ROWTYPE;
DECLARE s echo_identity.sessions%ROWTYPE;
DECLARE h echo_identity.activation_audit%ROWTYPE;
DECLARE now_ms bigint;
DECLARE valid_until bigint;
DECLARE result jsonb;
BEGIN
  IF p_request_id IS NULL OR p_request_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_grant_id IS NULL OR p_grant_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255
     OR p_session_key IS NULL OR p_session_key !~ '^[a-f0-9]{64}$'
     OR p_issued_ms IS NULL OR p_not_before_ms IS NULL OR p_expires_ms IS NULL
     OR p_issued_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_not_before_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_expires_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_issued_ms > p_not_before_ms OR p_not_before_ms >= p_expires_ms
     OR p_reason IS NULL OR length(p_reason)>1000 OR length(btrim(p_reason))<1 THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='22023';
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'UNSUPPORTED_ACTIVATION_ISOLATION' USING ERRCODE='25001';
  END IF;
  -- Lock order for this command: grant -> principals in UUID order -> session.
  SELECT * INTO g FROM echo_identity.activation_grants WHERE grant_id=p_grant_id FOR SHARE;
  IF NOT FOUND OR g.revoked OR g.approver_id=g.target_id THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='42501';
  END IF;
  PERFORM principal_id FROM echo_identity.principals
    WHERE principal_id IN(g.approver_id,g.target_id) ORDER BY principal_id FOR UPDATE;
  SELECT * INTO a FROM echo_identity.principals WHERE principal_id=g.approver_id;
  SELECT * INTO t FROM echo_identity.principals WHERE principal_id=g.target_id;
  SELECT * INTO s FROM echo_identity.sessions WHERE session_key=p_session_key COLLATE "C" FOR SHARE;
  IF NOT FOUND OR NOT a.enabled OR a.actor_kind <> 'HUMAN'
     OR a.issuer IS DISTINCT FROM p_issuer COLLATE "C" OR a.subject IS DISTINCT FROM p_subject COLLATE "C"
     OR a.auth_version <> g.approver_auth_version OR s.principal_id <> a.principal_id
     OR s.auth_version <> a.auth_version OR s.revoked
     OR t.actor_kind <> 'HUMAN' OR t.writer_enabled OR t.reviewer_enabled THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='42501';
  END IF;
  now_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  valid_until := LEAST(p_expires_ms,floor(extract(epoch FROM s.expires_at)*1000)::bigint,
                        floor(extract(epoch FROM g.expires_at)*1000)::bigint);
  IF now_ms >= valid_until OR now_ms < p_issued_ms OR now_ms < p_not_before_ms
     OR now_ms < ceil(extract(epoch FROM g.issued_at)*1000)::bigint
     OR now_ms < ceil(extract(epoch FROM s.issued_at)*1000)::bigint
     OR p_issued_ms < ceil(extract(epoch FROM s.issued_at)*1000)::bigint THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='42501';
  END IF;
  -- Require durable account-link provenance, not just a loose Actor/Source FK.
  IF NOT EXISTS(SELECT 1 FROM echo_identity.account_link_proofs p
      WHERE p.consumed_principal_id=t.principal_id AND p.consumed_at IS NOT NULL
        AND p.issuer=t.issuer COLLATE "C" AND p.subject=t.subject COLLATE "C"
        AND p.actor_id=t.actor_id AND p.source_id=t.source_id) THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='42501';
  END IF;

  SELECT * INTO h FROM echo_identity.activation_audit WHERE request_id=p_request_id;
  IF FOUND THEN
    -- Revalidate live authority before treating a retry as an acknowledgement.
    IF h.grant_id<>g.grant_id OR h.approver_id<>a.principal_id OR h.target_id<>t.principal_id
       OR h.session_key<>p_session_key OR h.reason IS DISTINCT FROM p_reason
       OR t.auth_version<>h.after_auth_version OR NOT t.enabled THEN
      RAISE EXCEPTION 'ACTIVATION_REPLAY_CONFLICT' USING ERRCODE='23505';
    END IF;
  ELSE
    IF t.enabled OR t.auth_version<>1 OR g.target_auth_version<>1 THEN
      RAISE EXCEPTION 'NOT_INITIAL_ACTIVATION' USING ERRCODE='42501';
    END IF;
    result := echo_identity.runtime_change_principal_authority(t.principal_id,1,true,false);
    IF result->>'authVersion' IS DISTINCT FROM '2' OR result->>'enabled' IS DISTINCT FROM 'true'
       OR result->>'writerEnabled' IS DISTINCT FROM 'false' OR result->>'reviewerEnabled' IS DISTINCT FROM 'false' THEN
      RAISE EXCEPTION 'ACTIVATION_CONTRACT_VIOLATION' USING ERRCODE='23514';
    END IF;
    INSERT INTO echo_identity.activation_audit VALUES(
      p_request_id,g.grant_id,a.principal_id,a.actor_id,a.source_id,a.auth_version,p_session_key,
      t.principal_id,1,2,'ACTIVATED_NO_ROLES',g.policy_version,g.authority_ref,p_reason,clock_timestamp());
  END IF;
  -- Audit INSERT can block on a concurrent request id. Check clock AFTER it.
  now_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF now_ms >= valid_until OR now_ms < p_issued_ms OR now_ms < p_not_before_ms THEN
    RAISE EXCEPTION 'ACTIVATION_REJECTED' USING ERRCODE='42501';
  END IF;
  RETURN jsonb_build_object('requestId',p_request_id,'principalId',t.principal_id,'authVersion',2,
      'enabled',true,'writerEnabled',false,'reviewerEnabled',false,
      'policyVersion',g.policy_version,'authorizedUntilMs',valid_until);
END $$;
REVOKE ALL ON FUNCTION echo_identity.runtime_activate_initial_account(uuid,uuid,text,text,text,bigint,bigint,bigint,text) FROM PUBLIC;
ALTER FUNCTION echo_identity.runtime_activate_initial_account(uuid,uuid,text,text,text,bigint,bigint,bigint,text)
  OWNER TO echo_activation_guard;
GRANT USAGE ON SCHEMA echo_identity TO echo_activation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_activate_initial_account(uuid,uuid,text,text,text,bigint,bigint,bigint,text)
  TO echo_activation_runtime;
-- No grant issuance, audit editing, session creation, reactivation or role grants
-- exposed. Denial telemetry / admin bootstrap / real activation service pool are
-- separate gates. Owners/superusers remain trusted and are NOT a public runtime.
