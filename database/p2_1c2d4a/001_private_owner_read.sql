-- Echo News P2.1c.2d.4a: least-privilege PRIVATE owner-read authorization contract.
-- TEST/DEVELOPMENT contract only. Requires public read + durable identity/session +
-- immutable PRIVATE write/idempotency/payload-recovery gates through P2.1c.2d.3d.
--
-- Scope is intentionally narrow: an active writer may resolve the CURRENT PRIVATE
-- revision-1 draft that belongs to the same durable Actor+Source+principal, and only
-- after the canonical payload attempt is COMMITTED. This returns an opaque payload
-- reference to trusted backend code; it does not serve payload bytes or create HTTP.

DO $$
BEGIN
    IF to_regrole('echo_public_reader') IS NULL
       OR to_regclass('echo_public.current_public_voices') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2a public read boundary is required first' USING ERRCODE='55000';
    END IF;
    IF to_regrole('echo_private_draft_guard') IS NULL
       OR to_regrole('echo_private_draft_runtime') IS NULL
       OR to_regprocedure('echo_identity.assert_private_draft_fence(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.1/d.2 authorization runtime is required first' USING ERRCODE='55000';
    END IF;
    IF to_regclass('echo_identity.private_draft_receipts') IS NULL
       OR to_regclass('echo_identity.private_payload_attempts') IS NULL
       OR to_regprocedure('echo_identity.runtime_mark_private_payload_committed(uuid,text)') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.3c/d payload durability chain is required first' USING ERRCODE='55000';
    END IF;
    IF to_regrole('echo_private_owner_read_guard') IS NOT NULL
       OR to_regrole('echo_private_owner_read_runtime') IS NOT NULL
       OR to_regprocedure('echo_identity.runtime_read_private_owner_voice(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'PRIVATE owner read objects already exist' USING ERRCODE='42710';
    END IF;
END $$;

-- Read path is separated from the draft-writer runtime. A future service LOGIN may
-- be allowed to SET only the specific runtime role needed for one operation; neither
-- runtime is a member of the guard or of the other runtime role.
CREATE ROLE echo_private_owner_read_guard
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_private_owner_read_runtime
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

REVOKE ALL ON SCHEMA echo_identity, echo_core FROM echo_private_owner_read_guard, echo_private_owner_read_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM echo_private_owner_read_guard, echo_private_owner_read_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_core FROM echo_private_owner_read_guard, echo_private_owner_read_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM echo_private_owner_read_guard, echo_private_owner_read_runtime;

-- The sealed guard needs the same authority-row lock privileges as the existing
-- fence plus read-only access to the exact canonical lineage used by this contract.
-- SELECT ... FOR SHARE in assert_private_draft_fence requires SELECT and UPDATE on
-- at least one column. UPDATE is therefore granted only on immutable key columns,
-- exactly as in P2.1c.2d.2a; no table-wide UPDATE/INSERT/DELETE is granted here.
GRANT USAGE ON SCHEMA echo_identity, echo_core TO echo_private_owner_read_guard;
GRANT SELECT ON echo_identity.principals, echo_identity.sessions,
                echo_identity.private_draft_receipts,
                echo_identity.private_payload_attempts
    TO echo_private_owner_read_guard;
GRANT UPDATE (principal_id) ON echo_identity.principals TO echo_private_owner_read_guard;
GRANT UPDATE (session_key) ON echo_identity.sessions TO echo_private_owner_read_guard;
GRANT SELECT ON echo_core.voice_revisions TO echo_private_owner_read_guard;
GRANT EXECUTE ON FUNCTION echo_identity.assert_private_draft_fence(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint
) TO echo_private_owner_read_guard;

CREATE FUNCTION echo_identity.runtime_read_private_owner_voice(
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
    p_voice_id uuid
) RETURNS TABLE(
    read_voice_id uuid,
    read_revision integer,
    read_payload_ref text,
    read_visibility text,
    read_recorded_at timestamptz,
    read_payload_state text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp
SET row_security = on AS $$
BEGIN
    IF p_voice_id IS NULL OR p_voice_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'INVALID_PRIVATE_VOICE_READ' USING ERRCODE='22023';
    END IF;

    -- Reuse the proven current-authority lock/fence. For this first read gate,
    -- owner-read intentionally requires the active voice:draft:create capability;
    -- a future independent read entitlement must get its own registry bit/fence.
    PERFORM echo_identity.assert_private_draft_fence(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms
    );

    -- Object mismatch is deliberately an empty result rather than a distinct error:
    -- a valid account must not gain an existence oracle for another principal's
    -- private Voice. Never fall back to an older PRIVATE revision when the head is
    -- PUBLIC/RESTRICTED/WITHDRAWN or otherwise lacks canonical committed payload.
    RETURN QUERY
    WITH head AS (
        SELECT v.voice_id,v.revision,v.author_id,v.source_id,v.payload_ref,
               v.visibility,v.posted_at,v.recorded_at
        FROM echo_core.voice_revisions v
        WHERE v.voice_id=p_voice_id
        ORDER BY v.revision DESC
        LIMIT 1
    )
    SELECT h.voice_id,h.revision,h.payload_ref,h.visibility,h.recorded_at,a.state
    FROM head h
    JOIN echo_identity.private_draft_receipts r
      ON r.voice_id=h.voice_id AND r.revision=h.revision
     AND r.visibility=h.visibility AND r.recorded_at=h.recorded_at
    JOIN echo_identity.private_payload_attempts a
      ON a.attempt_id=r.voice_id AND a.principal_id=r.principal_id
     AND a.request_id=r.request_id AND a.request_hash=r.request_hash
    WHERE h.revision=1
      AND h.visibility='PRIVATE'
      AND h.posted_at IS NULL
      AND h.author_id=p_actor_id
      AND h.source_id=p_source_id
      AND r.principal_id=p_principal_id
      AND a.principal_id=p_principal_id
      AND a.state='COMMITTED'
      AND a.payload_ref IS NOT DISTINCT FROM h.payload_ref;
END $$;

REVOKE ALL ON FUNCTION echo_identity.runtime_read_private_owner_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid
) FROM PUBLIC;
GRANT USAGE ON SCHEMA echo_identity TO echo_private_owner_read_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_read_private_owner_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid
) TO echo_private_owner_read_runtime;
ALTER FUNCTION echo_identity.runtime_read_private_owner_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid
) OWNER TO echo_private_owner_read_guard;

COMMENT ON FUNCTION echo_identity.runtime_read_private_owner_voice(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint,uuid
) IS 'P2.1c.2d.4a backend-only current PRIVATE revision-1 owner metadata resolver. Requires current writer authority and canonical COMMITTED payload state; object mismatch returns zero rows.';

-- NO LOGIN/service credential, browser/API route, payload bytes, list/search endpoint,
-- revision-2 owner reader, RESTRICTED reader, RLS policy or PUBLIC publication is
-- added here. COMMITTED is a DB recovery acknowledgement, not proof that a future
-- production object-store provider can never lose bytes. That remains a separate gate.
