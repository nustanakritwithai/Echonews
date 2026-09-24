-- P2.1c.2d.4c.5a — durable account-link proof and raw-provision bypass closure.
-- Database-only gate. It creates no HTTP route or LOGIN credential for account-link
-- issuance. A later signed-token adapter must be the only caller allowed to feed
-- issuer/subject into echo_account_link_runtime.
DO $$
BEGIN
  IF to_regclass('echo_identity.principals') IS NULL
     OR to_regclass('echo_core.actors') IS NULL
     OR to_regclass('echo_core.sources') IS NULL
     OR to_regrole('echo_identity_mutation_runtime') IS NULL
     OR to_regprocedure('echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)') IS NULL THEN
    RAISE EXCEPTION 'P2.1c.2d.4c.4 identity mutation boundary required first' USING ERRCODE='55000';
  END IF;
  IF to_regclass('echo_identity.account_subject_bindings') IS NOT NULL
     OR to_regclass('echo_identity.account_link_proofs') IS NOT NULL
     OR to_regrole('echo_account_link_guard') IS NOT NULL
     OR to_regrole('echo_account_link_runtime') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_issue_account_link_proof(uuid,text,text,bigint,bigint,bigint,bigint)') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_provision_principal_with_link_proof(uuid,uuid,text,text)') IS NOT NULL THEN
    RAISE EXCEPTION 'Account-link proof objects already exist; do not overwrite grants' USING ERRCODE='42710';
  END IF;
END $$;

CREATE TABLE echo_identity.account_subject_bindings (
  issuer text COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
  subject text COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  actor_id uuid NOT NULL UNIQUE REFERENCES echo_core.actors(actor_id),
  source_id uuid NOT NULL UNIQUE REFERENCES echo_core.sources(source_id),
  recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
  PRIMARY KEY (issuer,subject),
  UNIQUE (issuer,subject,actor_id,source_id)
);

CREATE TABLE echo_identity.account_link_proofs (
  proof_id uuid PRIMARY KEY,
  issuer text COLLATE "C" NOT NULL,
  subject text COLLATE "C" NOT NULL,
  actor_id uuid NOT NULL,
  source_id uuid NOT NULL,
  issued_at timestamptz NOT NULL CHECK (isfinite(issued_at)),
  expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
  consumed_at timestamptz,
  consumed_principal_id uuid REFERENCES echo_identity.principals(principal_id),
  FOREIGN KEY (issuer,subject,actor_id,source_id)
    REFERENCES echo_identity.account_subject_bindings(issuer,subject,actor_id,source_id),
  CHECK (expires_at > issued_at),
  CHECK ((consumed_at IS NULL AND consumed_principal_id IS NULL)
      OR (consumed_at IS NOT NULL AND consumed_principal_id IS NOT NULL AND isfinite(consumed_at)))
);

REVOKE ALL ON echo_identity.account_subject_bindings, echo_identity.account_link_proofs FROM PUBLIC;

CREATE ROLE echo_account_link_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_account_link_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

REVOKE ALL ON SCHEMA echo_identity,echo_core FROM echo_account_link_guard,echo_account_link_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM echo_account_link_guard,echo_account_link_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_core FROM echo_account_link_guard,echo_account_link_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM echo_account_link_guard,echo_account_link_runtime;

GRANT USAGE ON SCHEMA echo_identity,echo_core TO echo_account_link_guard;
GRANT SELECT,INSERT ON echo_identity.account_subject_bindings TO echo_account_link_guard;
GRANT SELECT,INSERT ON echo_identity.account_link_proofs TO echo_account_link_guard;
GRANT UPDATE (consumed_at,consumed_principal_id) ON echo_identity.account_link_proofs TO echo_account_link_guard;
GRANT SELECT,INSERT ON echo_core.actors,echo_core.sources TO echo_account_link_guard;

CREATE FUNCTION echo_identity.runtime_issue_account_link_proof(
  p_proof_id uuid,
  p_issuer text,
  p_subject text,
  p_token_issued_ms bigint,
  p_token_not_before_ms bigint,
  p_token_expires_ms bigint,
  p_proof_expires_ms bigint
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp
SET row_security=on AS $$
DECLARE b echo_identity.account_subject_bindings%ROWTYPE;
DECLARE p echo_identity.account_link_proofs%ROWTYPE;
DECLARE now_ms bigint;
DECLARE new_actor uuid;
DECLARE new_source uuid;
BEGIN
  now_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF p_proof_id IS NULL OR p_proof_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048 OR btrim(p_issuer)=''
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255 OR btrim(p_subject)=''
     OR p_token_issued_ms IS NULL OR p_token_not_before_ms IS NULL
     OR p_token_expires_ms IS NULL OR p_proof_expires_ms IS NULL
     OR p_token_issued_ms <= 0 OR p_token_not_before_ms < p_token_issued_ms
     OR p_token_expires_ms <= p_token_not_before_ms
     OR p_token_issued_ms > now_ms OR p_token_not_before_ms > now_ms
     OR p_token_expires_ms <= now_ms OR p_proof_expires_ms <= now_ms
     OR p_proof_expires_ms > p_token_expires_ms
     OR p_proof_expires_ms > now_ms + 300000 THEN
    RAISE EXCEPTION 'INVALID_ACCOUNT_LINK_PROOF_INPUT' USING ERRCODE='22023';
  END IF;

  -- Serialize first-link creation for one exact issuer/subject. Actor and Source IDs
  -- are generated inside the sealed function; callers never select existing IDs.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(p_issuer || chr(31) || p_subject, 0)
  );

  SELECT * INTO b
    FROM echo_identity.account_subject_bindings
   WHERE issuer=p_issuer COLLATE "C" AND subject=p_subject COLLATE "C";

  IF NOT FOUND THEN
    new_actor := gen_random_uuid();
    new_source := gen_random_uuid();
    INSERT INTO echo_core.actors(actor_id,actor_kind,display_label,recorded_at)
      VALUES(new_actor,'HUMAN','Echo account',clock_timestamp());
    INSERT INTO echo_core.sources(source_id,source_kind,source_locator,origin_status,recorded_at)
      VALUES(new_source,'ACCOUNT',NULL,'UNKNOWN',clock_timestamp());
    INSERT INTO echo_identity.account_subject_bindings(
      issuer,subject,actor_id,source_id,recorded_at
    ) VALUES(p_issuer,p_subject,new_actor,new_source,clock_timestamp());
    SELECT * INTO b
      FROM echo_identity.account_subject_bindings
     WHERE issuer=p_issuer COLLATE "C" AND subject=p_subject COLLATE "C";
  END IF;

  INSERT INTO echo_identity.account_link_proofs(
    proof_id,issuer,subject,actor_id,source_id,issued_at,expires_at
  ) VALUES(
    p_proof_id,p_issuer,p_subject,b.actor_id,b.source_id,
    to_timestamp(p_token_issued_ms::double precision/1000.0),
    to_timestamp(p_proof_expires_ms::double precision/1000.0)
  ) ON CONFLICT DO NOTHING;

  SELECT * INTO p FROM echo_identity.account_link_proofs WHERE proof_id=p_proof_id;
  IF NOT FOUND
     OR p.issuer IS DISTINCT FROM p_issuer
     OR p.subject IS DISTINCT FROM p_subject
     OR p.actor_id IS DISTINCT FROM b.actor_id
     OR p.source_id IS DISTINCT FROM b.source_id
     OR floor(extract(epoch FROM p.issued_at)*1000)::bigint <> p_token_issued_ms
     OR floor(extract(epoch FROM p.expires_at)*1000)::bigint <> p_proof_expires_ms THEN
    RAISE EXCEPTION 'ACCOUNT_LINK_PROOF_CONFLICT' USING ERRCODE='23505';
  END IF;

  RETURN jsonb_build_object(
    'proofId',p.proof_id,'issuer',p.issuer,'subject',p.subject,
    'actorId',p.actor_id,'sourceId',p.source_id,
    'expiresAtMs',floor(extract(epoch FROM p.expires_at)*1000)::bigint,
    'consumed',p.consumed_at IS NOT NULL
  );
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_issue_account_link_proof(
  uuid,text,text,bigint,bigint,bigint,bigint
) FROM PUBLIC;
GRANT USAGE ON SCHEMA echo_identity TO echo_account_link_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_issue_account_link_proof(
  uuid,text,text,bigint,bigint,bigint,bigint
) TO echo_account_link_runtime;
ALTER FUNCTION echo_identity.runtime_issue_account_link_proof(
  uuid,text,text,bigint,bigint,bigint,bigint
) OWNER TO echo_account_link_guard;

-- The proof consumer owns no principal-table DML. It invokes only the already
-- sealed/idempotent c4 principal provisioner, then atomically consumes the proof.
GRANT EXECUTE ON FUNCTION echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)
  TO echo_account_link_guard;

CREATE FUNCTION echo_identity.runtime_provision_principal_with_link_proof(
  p_principal_id uuid,
  p_proof_id uuid,
  p_issuer text,
  p_subject text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp
SET row_security=on AS $$
DECLARE p echo_identity.account_link_proofs%ROWTYPE;
DECLARE result jsonb;
BEGIN
  IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_proof_id IS NULL OR p_proof_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048 OR btrim(p_issuer)=''
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255 OR btrim(p_subject)='' THEN
    RAISE EXCEPTION 'INVALID_LINKED_PROVISIONING_INPUT' USING ERRCODE='22023';
  END IF;

  SELECT * INTO p FROM echo_identity.account_link_proofs
   WHERE proof_id=p_proof_id FOR UPDATE;
  IF NOT FOUND OR p.issuer IS DISTINCT FROM p_issuer OR p.subject IS DISTINCT FROM p_subject THEN
    RAISE EXCEPTION 'ACCOUNT_LINK_PROOF_REJECTED' USING ERRCODE='23514';
  END IF;

  -- A committed exact retry remains safe even after expiry; a fresh consumption
  -- always requires the proof to still be live.
  IF p.consumed_at IS NOT NULL THEN
    IF p.consumed_principal_id IS DISTINCT FROM p_principal_id THEN
      RAISE EXCEPTION 'ACCOUNT_LINK_PROOF_ALREADY_CONSUMED' USING ERRCODE='55000';
    END IF;
    RETURN echo_identity.runtime_provision_principal(
      p_principal_id,p_issuer,p_subject,p.actor_id,p.source_id
    );
  END IF;

  IF p.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'ACCOUNT_LINK_PROOF_EXPIRED' USING ERRCODE='23514';
  END IF;

  result := echo_identity.runtime_provision_principal(
    p_principal_id,p_issuer,p_subject,p.actor_id,p.source_id
  );

  UPDATE echo_identity.account_link_proofs
     SET consumed_at=clock_timestamp(), consumed_principal_id=p_principal_id
   WHERE proof_id=p_proof_id;

  RETURN result;
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_provision_principal_with_link_proof(
  uuid,uuid,text,text
) FROM PUBLIC;
ALTER FUNCTION echo_identity.runtime_provision_principal_with_link_proof(
  uuid,uuid,text,text
) OWNER TO echo_account_link_guard;

-- Close the c4 bypass: mutation runtime can no longer choose Actor/Source directly.
REVOKE EXECUTE ON FUNCTION echo_identity.runtime_provision_principal(uuid,text,text,uuid,uuid)
  FROM echo_identity_mutation_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_provision_principal_with_link_proof(
  uuid,uuid,text,text
) TO echo_identity_mutation_runtime;

COMMENT ON TABLE echo_identity.account_subject_bindings IS
  'Immutable by runtime contract: issuer/subject maps to internally generated Actor+Source. Not a real-world identity claim.';
COMMENT ON TABLE echo_identity.account_link_proofs IS
  'Short-lived single-use proof binding issuer/subject to its server-owned Actor+Source mapping.';
COMMENT ON FUNCTION echo_identity.runtime_issue_account_link_proof(
  uuid,text,text,bigint,bigint,bigint,bigint
) IS 'DB half of P2.1c.2d.4c.5 ownership gate. Actor/Source generated internally; signed-token caller is a later gate.';
COMMENT ON FUNCTION echo_identity.runtime_provision_principal_with_link_proof(
  uuid,uuid,text,text
) IS 'Only mutation-runtime principal provisioning path after c5a. Consumes one live account-link proof atomically.';

-- CRITICAL UNKNOWN intentionally remains: account_link_runtime is NOLOGIN and has no
-- service membership. This migration does not prove issuer/subject came from a
-- cryptographically verified token. The next gate must wire strict signed-token
-- verification and must not accept issuer/subject, actor_id or source_id from JSON.
