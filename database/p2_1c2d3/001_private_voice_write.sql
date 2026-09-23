-- Echo News P2.1c.2d.3a: atomic immutable PRIVATE Voice revision-1 writer.
-- TEST/DEVELOPMENT contract only. Requires P2.1b + P2.1c.1 + P2.1c.2c +
-- P2.1c.2d.1 + P2.1c.2d.2a. No LOGIN, HTTP route or PUBLIC publication path.
--
-- Security model: the application runtime can EXECUTE only this sealed wrapper.
-- Its SECURITY DEFINER owner can INSERT only the exact Voice columns needed here.
-- The existing authorization fence locks principal/session rows in the SAME
-- transaction before INSERT, so a committed revoke cannot slip between fence and
-- write. Browser/request JSON must never call PostgreSQL directly.

DO $$
DECLARE
    reject_trigger_ok boolean;
    audit_trigger_ok boolean;
BEGIN
    IF to_regrole('echo_private_draft_guard') IS NULL
       OR to_regrole('echo_private_draft_runtime') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.2a runtime roles are required first' USING ERRCODE='55000';
    END IF;
    IF to_regprocedure('echo_identity.assert_private_draft_fence(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)') IS NULL
       OR to_regprocedure('echo_identity.runtime_private_draft_fence(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.1/d.2 fence functions are required first' USING ERRCODE='55000';
    END IF;
    SELECT EXISTS(
        SELECT 1 FROM pg_trigger
        WHERE tgrelid='echo_core.voice_revisions'::regclass
          AND tgname='echo_reject_mutation' AND tgenabled='A'
    ) INTO reject_trigger_ok;
    SELECT EXISTS(
        SELECT 1 FROM pg_trigger
        WHERE tgrelid='echo_core.voice_revisions'::regclass
          AND tgname='echo_audit_insert' AND tgenabled='A'
    ) INTO audit_trigger_ok;
    IF NOT reject_trigger_ok OR NOT audit_trigger_ok THEN
        RAISE EXCEPTION 'P2.1c.1 immutable Voice triggers are required and must be ALWAYS enabled'
            USING ERRCODE='55000';
    END IF;
    IF to_regprocedure('echo_identity.runtime_append_private_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text)') IS NOT NULL THEN
        RAISE EXCEPTION 'Private Voice writer already exists' USING ERRCODE='42710';
    END IF;
END $$;

-- Guard receives no UPDATE/DELETE/TRUNCATE/SELECT on Voice history. Column-scoped
-- INSERT is enough for this one immutable append function. The runtime role itself
-- still receives zero direct echo_core table privileges.
GRANT USAGE ON SCHEMA echo_core TO echo_private_draft_guard;
GRANT INSERT (
    voice_id, revision, previous_revision, author_id, source_id,
    payload_ref, visibility, posted_at, recorded_at
) ON echo_core.voice_revisions TO echo_private_draft_guard;

CREATE FUNCTION echo_identity.runtime_append_private_voice(
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
    p_voice_id uuid,
    p_payload_ref text
) RETURNS TABLE(
    written_voice_id uuid,
    written_revision integer,
    written_visibility text,
    written_recorded_at timestamptz
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_recorded_at timestamptz;
BEGIN
    -- voice_id and payload_ref are backend execution inputs, not authority. Keep
    -- validation strict and do not accept author/source/visibility/revision/time as
    -- independent write fields. Authority tuple is rechecked by the fence below.
    IF p_voice_id IS NULL
       OR p_voice_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_payload_ref IS NULL
       OR length(btrim(p_payload_ref)) = 0
       OR length(p_payload_ref) > 4096 THEN
        RAISE EXCEPTION 'INVALID_PRIVATE_VOICE_WRITE' USING ERRCODE='22023';
    END IF;

    -- IMPORTANT: call the locking invoker fence from inside THIS write statement.
    -- Principal then session FOR SHARE locks remain held until caller COMMIT/ROLLBACK.
    PERFORM echo_identity.assert_private_draft_fence(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms
    );

    v_recorded_at := clock_timestamp();
    INSERT INTO echo_core.voice_revisions(
        voice_id, revision, previous_revision, author_id, source_id,
        payload_ref, visibility, posted_at, recorded_at
    ) VALUES (
        p_voice_id, 1, NULL, p_actor_id, p_source_id,
        p_payload_ref, 'PRIVATE', NULL, v_recorded_at
    );

    RETURN QUERY SELECT p_voice_id, 1, 'PRIVATE'::text, v_recorded_at;
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text
) TO echo_private_draft_runtime;
ALTER FUNCTION echo_identity.runtime_append_private_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid,text
) OWNER TO echo_private_draft_guard;

-- No PUBLIC/RESTRICTED writer exists. No revision-2 append exists. No payload bytes
-- are stored here. No idempotency receipt, HTTP route, service LOGIN or read grant is
-- added. A later backend adapter must feed server-owned stamp + payload reference.
