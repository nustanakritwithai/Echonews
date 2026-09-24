-- c5c.1: signed principal provisioning, NOT activation or session bootstrap.
-- Apply only to disposable development databases until deployment gates pass.
-- This trusted internal function DOES NOT verify signatures: use the paired
-- backend boundary. A proof UUID alone is never authentication.
DO $$
BEGIN
  IF to_regprocedure('echo_identity.runtime_provision_principal_with_link_proof(uuid,uuid,text,text)') IS NULL
     OR to_regrole('echo_account_link_service') IS NULL THEN
    RAISE EXCEPTION 'c5a/c5b required first' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_principal_provision_guard') IS NOT NULL
     OR to_regrole('echo_principal_provision_runtime') IS NOT NULL
     OR to_regrole('echo_principal_provision_service') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_provision_signed_principal(uuid,text,text,bigint,bigint,bigint)') IS NOT NULL THEN
    RAISE EXCEPTION 'Do not overwrite existing provisioning service' USING ERRCODE='42710';
  END IF;
END $$;

CREATE ROLE echo_principal_provision_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_principal_provision_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_principal_provision_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 6 PASSWORD NULL;

REVOKE ALL ON SCHEMA echo_identity,echo_core FROM
  echo_principal_provision_guard,echo_principal_provision_runtime,echo_principal_provision_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity,echo_core FROM
  echo_principal_provision_guard,echo_principal_provision_runtime,echo_principal_provision_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM
  echo_principal_provision_guard,echo_principal_provision_runtime,echo_principal_provision_service;

GRANT USAGE ON SCHEMA echo_identity TO echo_principal_provision_guard;
GRANT SELECT ON echo_identity.principals,echo_identity.account_link_proofs
  TO echo_principal_provision_guard;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_provision_principal_with_link_proof(uuid,uuid,text,text)
  TO echo_principal_provision_guard;
-- No principal/session DML, no activation, no raw provisioning and no membership
-- in either mutation or account-link roles. The existing sealed consumer owns DML.

CREATE FUNCTION echo_identity.runtime_provision_signed_principal(
  p_proof_id uuid,p_issuer text,p_subject text,
  p_token_issued_ms bigint,p_token_not_before_ms bigint,p_token_expires_ms bigint
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE proof echo_identity.account_link_proofs%ROWTYPE;
DECLARE principal_id_value uuid;
DECLARE result jsonb;
DECLARE checked_ms bigint;
DECLARE proof_exp_ms bigint;
BEGIN
  IF p_proof_id IS NULL OR p_proof_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048 OR btrim(p_issuer)=''
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255 OR btrim(p_subject)=''
     OR p_token_issued_ms IS NULL OR p_token_not_before_ms IS NULL OR p_token_expires_ms IS NULL
     OR p_token_issued_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_not_before_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_expires_ms NOT BETWEEN 1 AND 9007199254740991
     OR p_token_issued_ms > p_token_not_before_ms
     OR p_token_not_before_ms >= p_token_expires_ms THEN
    RAISE EXCEPTION 'PRINCIPAL_PROVISION_REJECTED' USING ERRCODE='22023';
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'UNSUPPORTED_PROVISION_ISOLATION' USING ERRCODE='25001';
  END IF;

  -- Same exact identity serialization key as c5a issuance. Hash collisions can
  -- only serialize unrelated accounts; exact text comparisons still isolate them.
  PERFORM pg_advisory_xact_lock(hashtextextended(p_issuer || chr(31) || p_subject,0));
  SELECT * INTO proof FROM echo_identity.account_link_proofs WHERE proof_id=p_proof_id;
  IF NOT FOUND OR proof.issuer IS DISTINCT FROM p_issuer COLLATE "C"
     OR proof.subject IS DISTINCT FROM p_subject COLLATE "C" THEN
    RAISE EXCEPTION 'PRINCIPAL_PROVISION_REJECTED' USING ERRCODE='23514';
  END IF;
  checked_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  proof_exp_ms := floor(extract(epoch FROM proof.expires_at)*1000)::bigint;
  IF checked_ms < p_token_issued_ms OR checked_ms < p_token_not_before_ms
     OR checked_ms >= p_token_expires_ms OR checked_ms >= proof_exp_ms
     OR proof.issued_at > clock_timestamp() THEN
    RAISE EXCEPTION 'PRINCIPAL_PROVISION_REJECTED' USING ERRCODE='23514';
  END IF;

  -- Caller cannot choose a Principal, Actor or Source. Repeat requests and new
  -- proofs for the same account resolve the existing Principal, never relink it.
  SELECT principal_id INTO principal_id_value FROM echo_identity.principals
   WHERE issuer=p_issuer COLLATE "C" AND subject=p_subject COLLATE "C";
  IF NOT FOUND THEN
    principal_id_value := gen_random_uuid();
  END IF;
  result := echo_identity.runtime_provision_principal_with_link_proof(
    principal_id_value,p_proof_id,p_issuer,p_subject);
  IF result->>'principalId' IS DISTINCT FROM principal_id_value::text
     OR result->>'issuer' IS DISTINCT FROM p_issuer
     OR result->>'subject' IS DISTINCT FROM p_subject
     OR result->>'actorId' IS DISTINCT FROM proof.actor_id::text
     OR result->>'sourceId' IS DISTINCT FROM proof.source_id::text THEN
    RAISE EXCEPTION 'PRINCIPAL_PROVISION_CONTRACT' USING ERRCODE='23514';
  END IF;

  -- The consumer may wait for a proof/unique constraint lock. Do not use an old
  -- pre-wait timestamp. Exception rolls back both principal and consume marker.
  checked_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF checked_ms < p_token_issued_ms OR checked_ms < p_token_not_before_ms
     OR checked_ms >= p_token_expires_ms OR checked_ms >= proof_exp_ms THEN
    RAISE EXCEPTION 'PRINCIPAL_PROVISION_REJECTED' USING ERRCODE='23514';
  END IF;
  RETURN jsonb_build_object('principalId',principal_id_value,'proofId',p_proof_id,
    'issuer',p_issuer,'subject',p_subject,'proofExpiresAtMs',proof_exp_ms);
END $$;
REVOKE ALL ON FUNCTION echo_identity.runtime_provision_signed_principal(uuid,text,text,bigint,bigint,bigint) FROM PUBLIC;
ALTER FUNCTION echo_identity.runtime_provision_signed_principal(uuid,text,text,bigint,bigint,bigint)
  OWNER TO echo_principal_provision_guard;
GRANT USAGE ON SCHEMA echo_identity TO echo_principal_provision_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_provision_signed_principal(uuid,text,text,bigint,bigint,bigint)
  TO echo_principal_provision_runtime;
GRANT echo_principal_provision_runtime TO echo_principal_provision_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
ALTER ROLE echo_principal_provision_service SET search_path=pg_catalog;
ALTER ROLE echo_principal_provision_service SET row_security=on;
ALTER ROLE echo_principal_provision_service SET statement_timeout='5s';
ALTER ROLE echo_principal_provision_service SET lock_timeout='3s';
ALTER ROLE echo_principal_provision_service SET idle_in_transaction_session_timeout='10s';
COMMENT ON FUNCTION echo_identity.runtime_provision_signed_principal(uuid,text,text,bigint,bigint,bigint) IS
 'c5c.1 trusted signed-boundary consumer only. New principal disabled/no grants; existing authority untouched. No session issuance.';
