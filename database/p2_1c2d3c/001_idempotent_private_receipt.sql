-- Echo News P2.1c.2d.3c: idempotent PRIVATE draft execution receipt.
-- Requires the complete P2.1c.2d.3b dependency chain. This migration is a
-- TEST/DEVELOPMENT contract: no LOGIN, HTTP route, PUBLIC writer or read API.
--
-- Scope: (principal_id, request_id) is the idempotency key. request_id is client
-- chosen but never authority. A server-computed request_hash binds the key to the
-- exact CREATE_VOICE_DRAFT semantic input. Actor/source/permission remain fence-owned.

DO $$
BEGIN
    IF to_regrole('echo_private_draft_guard') IS NULL
       OR to_regrole('echo_private_draft_runtime') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.2a runtime roles are required first' USING ERRCODE='55000';
    END IF;
    IF to_regprocedure('echo_identity.runtime_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text)') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.3a PRIVATE Voice writer is required first' USING ERRCODE='55000';
    END IF;
    IF to_regclass('echo_identity.private_draft_receipts') IS NOT NULL
       OR to_regprocedure('echo_identity.runtime_idempotent_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text)') IS NOT NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.3c receipt objects already exist' USING ERRCODE='42710';
    END IF;
END $$;

CREATE TABLE echo_identity.private_draft_receipts (
    principal_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
    request_id uuid NOT NULL,
    request_hash text COLLATE "C" NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    voice_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision = 1),
    visibility text NOT NULL CHECK (visibility = 'PRIVATE'),
    recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
    PRIMARY KEY (principal_id, request_id),
    UNIQUE (voice_id),
    FOREIGN KEY (voice_id, revision)
      REFERENCES echo_core.voice_revisions(voice_id, revision)
);
REVOKE ALL ON echo_identity.private_draft_receipts FROM PUBLIC;
GRANT SELECT, INSERT ON echo_identity.private_draft_receipts TO echo_private_draft_guard;

CREATE FUNCTION echo_identity.reject_private_draft_receipt_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'PRIVATE_DRAFT_RECEIPT_IS_IMMUTABLE' USING ERRCODE='55000';
END $$;
CREATE TRIGGER private_draft_receipt_no_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON echo_identity.private_draft_receipts
FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.reject_private_draft_receipt_mutation();
REVOKE ALL ON FUNCTION echo_identity.reject_private_draft_receipt_mutation() FROM PUBLIC;

CREATE FUNCTION echo_identity.runtime_idempotent_append_private_voice(
    p_issuer text,
    p_subject text,
    p_session_key text,
    p_principal_id uuid,
    p_actor_id uuid,
    p_source_id uuid,
    p_auth_version integer,
    p_capability text,
    p_token_issued_ms bigint,
    p_token_not_before_ms bigint,
    p_token_expires_ms bigint,
    p_request_id uuid,
    p_request_hash text,
    p_voice_id uuid,
    p_payload_ref text
) RETURNS TABLE(
    written_voice_id uuid,
    written_revision integer,
    written_visibility text,
    written_recorded_at timestamptz,
    was_replay boolean
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    existing echo_identity.private_draft_receipts%ROWTYPE;
    fresh record;
    lock_key bigint;
BEGIN
    IF p_request_id IS NULL
       OR p_request_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_request_hash IS NULL
       OR p_request_hash !~ '^[a-f0-9]{64}$' THEN
        RAISE EXCEPTION 'INVALID_IDEMPOTENCY_INPUT' USING ERRCODE='22023';
    END IF;

    -- Authorization is rechecked even for a replay. A revoked/disabled caller does
    -- not gain a receipt oracle merely because the request succeeded in the past.
    PERFORM echo_identity.assert_private_draft_fence(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms
    );

    -- Serialize only equal-ish keys inside this transaction. A 64-bit advisory hash
    -- collision can delay an unrelated request but cannot merge identities because
    -- the exact composite key is still checked in the table below.
    lock_key := pg_catalog.hashtextextended(p_principal_id::text || ':' || p_request_id::text, 0);
    PERFORM pg_catalog.pg_advisory_xact_lock(lock_key);

    SELECT * INTO existing
      FROM echo_identity.private_draft_receipts
     WHERE principal_id = p_principal_id AND request_id = p_request_id;
    IF FOUND THEN
        IF existing.request_hash <> p_request_hash THEN
            RAISE EXCEPTION 'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST' USING ERRCODE='P2001';
        END IF;
        RETURN QUERY SELECT existing.voice_id, existing.revision, existing.visibility,
                            existing.recorded_at, true;
        RETURN;
    END IF;

    SELECT * INTO fresh
      FROM echo_identity.runtime_append_private_voice(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms,
        p_voice_id,p_payload_ref
      );

    INSERT INTO echo_identity.private_draft_receipts(
        principal_id,request_id,request_hash,voice_id,revision,visibility,recorded_at
    ) VALUES (
        p_principal_id,p_request_id,p_request_hash,fresh.written_voice_id,
        fresh.written_revision,fresh.written_visibility,fresh.written_recorded_at
    );

    RETURN QUERY SELECT fresh.written_voice_id, fresh.written_revision,
                        fresh.written_visibility, fresh.written_recorded_at, false;
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_idempotent_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_idempotent_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text
) TO echo_private_draft_runtime;
ALTER FUNCTION echo_identity.runtime_idempotent_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text,uuid,text
) OWNER TO echo_private_draft_guard;

-- Once this gate is installed, runtime may not bypass request receipts by calling
-- the lower-level writer directly. The NOLOGIN guard owns it and the new wrapper.
REVOKE EXECUTE ON FUNCTION echo_identity.runtime_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text
) FROM echo_private_draft_runtime;

-- Receipt access remains server-internal: runtime gets no direct table SELECT/DML.
-- Payload crash atomicity is still outside PostgreSQL and remains a later gate.
