-- Echo News P2.1c.2d.3d: durable payload recovery ledger for PRIVATE draft writes.
-- TEST/DEVELOPMENT contract only. Requires P2.1c.2d.3c.
--
-- Goal: make the cross-system gap explicit and recoverable without pretending that
-- PostgreSQL and an external payload store participate in one atomic transaction.
-- Every payload stage is first represented by a durable DB attempt. The Voice +
-- idempotency receipt transaction then moves that attempt to NEEDS_COMMIT. External
-- payload finalization is idempotent and acknowledged separately. Recovery can safely
-- finish NEEDS_COMMIT or discard ABANDONED/stale RESERVED attempts.

DO $$
BEGIN
    IF to_regrole('echo_private_draft_guard') IS NULL
       OR to_regrole('echo_private_draft_runtime') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.2a runtime roles are required first' USING ERRCODE='55000';
    END IF;
    IF to_regclass('echo_identity.private_draft_receipts') IS NULL
       OR to_regprocedure('echo_identity.runtime_idempotent_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text)') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.3c idempotency gate is required first' USING ERRCODE='55000';
    END IF;
    IF to_regclass('echo_identity.private_payload_attempts') IS NOT NULL THEN
        RAISE EXCEPTION 'Payload recovery objects already exist' USING ERRCODE='42710';
    END IF;
    IF EXISTS (SELECT 1 FROM echo_identity.private_draft_receipts) THEN
        RAISE EXCEPTION 'Existing receipts require an explicit payload-ledger backfill before this gate' USING ERRCODE='55000';
    END IF;
END $$;

CREATE TABLE echo_identity.private_payload_attempts (
    attempt_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
    request_id uuid NOT NULL,
    request_hash text COLLATE "C" NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    payload_ref text,
    state text NOT NULL CHECK (state IN ('RESERVED','NEEDS_COMMIT','COMMITTED','ABANDONED','DISCARDED')),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    recover_after timestamptz NOT NULL CHECK (isfinite(recover_after) AND recover_after >= created_at),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    CHECK (
        (state='RESERVED' AND payload_ref IS NULL)
        OR (state IN ('NEEDS_COMMIT','COMMITTED') AND payload_ref IS NOT NULL AND length(btrim(payload_ref)) > 0)
        OR state IN ('ABANDONED','DISCARDED')
    )
);
CREATE INDEX private_payload_attempt_state_idx
    ON echo_identity.private_payload_attempts(state,recover_after,created_at);
REVOKE ALL ON echo_identity.private_payload_attempts FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON echo_identity.private_payload_attempts TO echo_private_draft_guard;

CREATE FUNCTION echo_identity.guard_private_payload_attempt_transition()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state <> 'RESERVED' OR NEW.payload_ref IS NOT NULL THEN
            RAISE EXCEPTION 'PAYLOAD_ATTEMPT_MUST_START_RESERVED' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.attempt_id,NEW.principal_id,NEW.request_id,NEW.request_hash,NEW.created_at,NEW.recover_after)
       IS DISTINCT FROM
       ROW(OLD.attempt_id,OLD.principal_id,OLD.request_id,OLD.request_hash,OLD.created_at,OLD.recover_after) THEN
        RAISE EXCEPTION 'PAYLOAD_ATTEMPT_IDENTITY_IS_IMMUTABLE' USING ERRCODE='55000';
    END IF;
    IF OLD.state='RESERVED' AND NEW.state IN ('NEEDS_COMMIT','ABANDONED') THEN
        NULL;
    ELSIF OLD.state='NEEDS_COMMIT' AND NEW.state='COMMITTED' THEN
        NULL;
    ELSIF OLD.state='ABANDONED' AND NEW.state='DISCARDED' THEN
        NULL;
    ELSIF OLD.state=NEW.state AND OLD.payload_ref IS NOT DISTINCT FROM NEW.payload_ref THEN
        NULL; -- idempotent acknowledgement only
    ELSE
        RAISE EXCEPTION 'INVALID_PAYLOAD_ATTEMPT_TRANSITION' USING ERRCODE='55000';
    END IF;
    IF OLD.payload_ref IS NOT NULL AND NEW.payload_ref IS DISTINCT FROM OLD.payload_ref THEN
        RAISE EXCEPTION 'PAYLOAD_REFERENCE_IS_IMMUTABLE_ONCE_SET' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END $$;
-- Row-level trigger validates only state transitions; removal has its own statement trigger.
CREATE TRIGGER private_payload_attempt_insert_update_guard
BEFORE INSERT OR UPDATE ON echo_identity.private_payload_attempts
FOR EACH ROW EXECUTE FUNCTION echo_identity.guard_private_payload_attempt_transition();
CREATE FUNCTION echo_identity.reject_private_payload_attempt_removal()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'PAYLOAD_ATTEMPT_HISTORY_IS_NOT_REMOVABLE' USING ERRCODE='55000';
END $$;
CREATE TRIGGER private_payload_attempt_no_remove
BEFORE DELETE OR TRUNCATE ON echo_identity.private_payload_attempts
FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.reject_private_payload_attempt_removal();
REVOKE ALL ON FUNCTION echo_identity.guard_private_payload_attempt_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.reject_private_payload_attempt_removal() FROM PUBLIC;

CREATE FUNCTION echo_identity.runtime_reserve_private_payload_attempt(
    p_issuer text,p_subject text,p_session_key text,p_principal_id uuid,p_actor_id uuid,p_source_id uuid,
    p_auth_version integer,p_capability text,p_token_issued_ms bigint,p_token_not_before_ms bigint,
    p_token_expires_ms bigint,p_request_id uuid,p_request_hash text,p_attempt_id uuid
) RETURNS TABLE(reserved_attempt_id uuid,reserved_at timestamptz,recover_after timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE t timestamptz;
BEGIN
    IF p_attempt_id IS NULL OR p_attempt_id='00000000-0000-0000-0000-000000000000'::uuid
       OR p_request_id IS NULL OR p_request_id='00000000-0000-0000-0000-000000000000'::uuid
       OR p_request_hash IS NULL OR p_request_hash !~ '^[a-f0-9]{64}$' THEN
        RAISE EXCEPTION 'INVALID_PAYLOAD_RESERVATION' USING ERRCODE='22023';
    END IF;
    PERFORM echo_identity.assert_private_draft_fence(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms);
    t := clock_timestamp();
    INSERT INTO echo_identity.private_payload_attempts(
        attempt_id,principal_id,request_id,request_hash,payload_ref,state,created_at,recover_after,updated_at)
    VALUES(p_attempt_id,p_principal_id,p_request_id,p_request_hash,NULL,'RESERVED',t,t+interval '5 minutes',t);
    RETURN QUERY SELECT p_attempt_id,t,t+interval '5 minutes';
END $$;

CREATE FUNCTION echo_identity.runtime_recoverable_idempotent_append_private_voice(
    p_issuer text,p_subject text,p_session_key text,p_principal_id uuid,p_actor_id uuid,p_source_id uuid,
    p_auth_version integer,p_capability text,p_token_issued_ms bigint,p_token_not_before_ms bigint,
    p_token_expires_ms bigint,p_request_id uuid,p_request_hash text,p_attempt_id uuid,p_payload_ref text
) RETURNS TABLE(
    written_voice_id uuid,written_revision integer,written_visibility text,written_recorded_at timestamptz,
    was_replay boolean,canonical_attempt_id uuid,canonical_payload_ref text,canonical_payload_state text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a echo_identity.private_payload_attempts%ROWTYPE;
    existing echo_identity.private_draft_receipts%ROWTYPE;
    canonical echo_identity.private_payload_attempts%ROWTYPE;
    fresh record;
    lock_key bigint;
BEGIN
    IF p_payload_ref IS NULL OR length(btrim(p_payload_ref))=0 OR length(p_payload_ref)>4096 THEN
        RAISE EXCEPTION 'INVALID_PAYLOAD_REFERENCE' USING ERRCODE='22023';
    END IF;
    PERFORM echo_identity.assert_private_draft_fence(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms);

    SELECT * INTO a FROM echo_identity.private_payload_attempts
     WHERE attempt_id=p_attempt_id FOR UPDATE;
    IF NOT FOUND OR a.state<>'RESERVED' OR a.principal_id<>p_principal_id
       OR a.request_id<>p_request_id OR a.request_hash<>p_request_hash THEN
        RAISE EXCEPTION 'INVALID_PAYLOAD_ATTEMPT' USING ERRCODE='P2002';
    END IF;

    lock_key := pg_catalog.hashtextextended(p_principal_id::text || ':' || p_request_id::text,0);
    PERFORM pg_catalog.pg_advisory_xact_lock(lock_key);
    SELECT * INTO existing FROM echo_identity.private_draft_receipts
     WHERE principal_id=p_principal_id AND request_id=p_request_id;

    IF FOUND THEN
        IF existing.request_hash<>p_request_hash THEN
            RAISE EXCEPTION 'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST' USING ERRCODE='P2001';
        END IF;
        UPDATE echo_identity.private_payload_attempts
           SET state='ABANDONED',payload_ref=p_payload_ref,updated_at=clock_timestamp()
         WHERE attempt_id=p_attempt_id;
        SELECT * INTO canonical FROM echo_identity.private_payload_attempts
         WHERE attempt_id=existing.voice_id;
        IF NOT FOUND OR canonical.state NOT IN ('NEEDS_COMMIT','COMMITTED')
           OR canonical.payload_ref IS NULL THEN
            RAISE EXCEPTION 'CANONICAL_PAYLOAD_ATTEMPT_MISSING' USING ERRCODE='55000';
        END IF;
        RETURN QUERY SELECT existing.voice_id,existing.revision,existing.visibility,
            existing.recorded_at,true,canonical.attempt_id,canonical.payload_ref,canonical.state;
        RETURN;
    END IF;

    SELECT * INTO fresh FROM echo_identity.runtime_append_private_voice(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms,
        p_attempt_id,p_payload_ref);
    INSERT INTO echo_identity.private_draft_receipts(
        principal_id,request_id,request_hash,voice_id,revision,visibility,recorded_at)
    VALUES(p_principal_id,p_request_id,p_request_hash,fresh.written_voice_id,
           fresh.written_revision,fresh.written_visibility,fresh.written_recorded_at);
    UPDATE echo_identity.private_payload_attempts
       SET state='NEEDS_COMMIT',payload_ref=p_payload_ref,updated_at=clock_timestamp()
     WHERE attempt_id=p_attempt_id;
    RETURN QUERY SELECT fresh.written_voice_id,fresh.written_revision,fresh.written_visibility,
        fresh.written_recorded_at,false,p_attempt_id,p_payload_ref,'NEEDS_COMMIT'::text;
END $$;

CREATE FUNCTION echo_identity.runtime_mark_private_payload_committed(p_attempt_id uuid,p_payload_ref text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE s text;
BEGIN
    SELECT state INTO s FROM echo_identity.private_payload_attempts
     WHERE attempt_id=p_attempt_id AND payload_ref=p_payload_ref FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PAYLOAD_ATTEMPT_NOT_FOUND' USING ERRCODE='P2002'; END IF;
    IF s='COMMITTED' THEN RETURN false; END IF;
    IF s<>'NEEDS_COMMIT' THEN RAISE EXCEPTION 'PAYLOAD_NOT_COMMITTABLE' USING ERRCODE='55000'; END IF;
    IF NOT EXISTS(
        SELECT 1 FROM echo_identity.private_draft_receipts r
        WHERE r.voice_id=p_attempt_id AND r.revision=1 AND r.visibility='PRIVATE'
    ) THEN
        RAISE EXCEPTION 'PAYLOAD_RECEIPT_MISMATCH' USING ERRCODE='55000';
    END IF;
    UPDATE echo_identity.private_payload_attempts
       SET state='COMMITTED',updated_at=clock_timestamp() WHERE attempt_id=p_attempt_id;
    RETURN true;
END $$;

CREATE FUNCTION echo_identity.runtime_abandon_private_payload_attempt(p_attempt_id uuid,p_payload_ref text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE s text;
BEGIN
    IF p_payload_ref IS NULL OR length(btrim(p_payload_ref))=0 OR length(p_payload_ref)>4096 THEN
        RAISE EXCEPTION 'INVALID_PAYLOAD_REFERENCE' USING ERRCODE='22023';
    END IF;
    SELECT state INTO s FROM echo_identity.private_payload_attempts
     WHERE attempt_id=p_attempt_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PAYLOAD_ATTEMPT_NOT_FOUND' USING ERRCODE='P2002'; END IF;
    IF s='ABANDONED' THEN RETURN false; END IF;
    IF s<>'RESERVED' THEN RAISE EXCEPTION 'PAYLOAD_NOT_ABANDONABLE' USING ERRCODE='55000'; END IF;
    UPDATE echo_identity.private_payload_attempts
       SET state='ABANDONED',payload_ref=p_payload_ref,updated_at=clock_timestamp()
     WHERE attempt_id=p_attempt_id;
    RETURN true;
END $$;

CREATE FUNCTION echo_identity.runtime_claim_stale_private_payload_attempt(p_attempt_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE echo_identity.private_payload_attempts
       SET state='ABANDONED',updated_at=clock_timestamp()
     WHERE attempt_id=p_attempt_id AND state='RESERVED' AND recover_after<=clock_timestamp();
    RETURN FOUND;
END $$;

CREATE FUNCTION echo_identity.runtime_mark_private_payload_discarded(p_attempt_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE s text;
BEGIN
    SELECT state INTO s FROM echo_identity.private_payload_attempts
     WHERE attempt_id=p_attempt_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PAYLOAD_ATTEMPT_NOT_FOUND' USING ERRCODE='P2002'; END IF;
    IF s='DISCARDED' THEN RETURN false; END IF;
    IF s<>'ABANDONED' THEN RAISE EXCEPTION 'PAYLOAD_NOT_DISCARDABLE' USING ERRCODE='55000'; END IF;
    UPDATE echo_identity.private_payload_attempts
       SET state='DISCARDED',updated_at=clock_timestamp() WHERE attempt_id=p_attempt_id;
    RETURN true;
END $$;

CREATE FUNCTION echo_identity.runtime_get_private_payload_attempt(p_attempt_id uuid)
RETURNS TABLE(
    attempt_id uuid,attempt_state text,attempt_payload_ref text,attempt_created_at timestamptz,
    attempt_recover_after timestamptz,canonical_voice_id uuid,canonical_revision integer,
    canonical_visibility text,canonical_recorded_at timestamptz,canonical_attempt_id uuid,
    canonical_payload_ref text,canonical_payload_state text
)
LANGUAGE sql STABLE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
 SELECT a.attempt_id,a.state,a.payload_ref,a.created_at,a.recover_after,
        r.voice_id,r.revision,r.visibility,r.recorded_at,
        c.attempt_id,c.payload_ref,c.state
 FROM echo_identity.private_payload_attempts a
 LEFT JOIN echo_identity.private_draft_receipts r
   ON r.principal_id=a.principal_id AND r.request_id=a.request_id AND r.request_hash=a.request_hash
 LEFT JOIN echo_identity.private_payload_attempts c ON c.attempt_id=r.voice_id
 WHERE a.attempt_id=p_attempt_id;
$$;

CREATE FUNCTION echo_identity.runtime_list_private_payload_recovery(p_limit integer DEFAULT 100)
RETURNS TABLE(attempt_id uuid,attempt_state text,payload_ref text,recover_after timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_limit IS NULL OR p_limit<1 OR p_limit>1000 THEN
        RAISE EXCEPTION 'INVALID_RECOVERY_LIMIT' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
      SELECT a.attempt_id,a.state,a.payload_ref,a.recover_after
      FROM echo_identity.private_payload_attempts a
      WHERE a.state IN ('NEEDS_COMMIT','ABANDONED')
         OR (a.state='RESERVED' AND a.recover_after<=clock_timestamp())
      ORDER BY a.created_at,a.attempt_id
      LIMIT p_limit;
END $$;

-- Seal all new functions. Runtime sees only narrow wrappers, never table DML.
REVOKE ALL ON FUNCTION echo_identity.runtime_reserve_private_payload_attempt(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_recoverable_idempotent_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_mark_private_payload_committed(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_abandon_private_payload_attempt(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_claim_stale_private_payload_attempt(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_mark_private_payload_discarded(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_get_private_payload_attempt(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_identity.runtime_list_private_payload_recovery(integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION echo_identity.runtime_reserve_private_payload_attempt(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid) TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_recoverable_idempotent_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text) TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_mark_private_payload_committed(uuid,text) TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_abandon_private_payload_attempt(uuid,text) TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_claim_stale_private_payload_attempt(uuid) TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_mark_private_payload_discarded(uuid) TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_get_private_payload_attempt(uuid) TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_list_private_payload_recovery(integer) TO echo_private_draft_runtime;

ALTER FUNCTION echo_identity.runtime_reserve_private_payload_attempt(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid) OWNER TO echo_private_draft_guard;
ALTER FUNCTION echo_identity.runtime_recoverable_idempotent_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text) OWNER TO echo_private_draft_guard;
ALTER FUNCTION echo_identity.runtime_mark_private_payload_committed(uuid,text) OWNER TO echo_private_draft_guard;
ALTER FUNCTION echo_identity.runtime_abandon_private_payload_attempt(uuid,text) OWNER TO echo_private_draft_guard;
ALTER FUNCTION echo_identity.runtime_claim_stale_private_payload_attempt(uuid) OWNER TO echo_private_draft_guard;
ALTER FUNCTION echo_identity.runtime_mark_private_payload_discarded(uuid) OWNER TO echo_private_draft_guard;
ALTER FUNCTION echo_identity.runtime_get_private_payload_attempt(uuid) OWNER TO echo_private_draft_guard;
ALTER FUNCTION echo_identity.runtime_list_private_payload_recovery(integer) OWNER TO echo_private_draft_guard;

-- After this migration, application runtime may not use the older idempotent writer
-- because it has no durable stage/finalization ledger.
REVOKE EXECUTE ON FUNCTION echo_identity.runtime_idempotent_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text
) FROM echo_private_draft_runtime;

-- IMPORTANT: external payload durability is still supplied by a trusted store.
-- The store contract must make stage durable before returning, commit/discard
-- idempotent, and allow recovery to find a staged object from attempt_id. PRIVATE
-- reads remain blocked until a later gate requires canonical payload_state=COMMITTED.
