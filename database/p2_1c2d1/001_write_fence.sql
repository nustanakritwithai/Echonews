-- P2.1c.2d.1: authorization fence primitive, NOT a production writer.
-- Additive; apply only to an isolated disposable PostgreSQL 17 test database.
-- Caller arguments MUST come from a trusted verified credential/registry context.
-- Knowing these values is not authentication. No HTTP route or grants are added.
-- Supported protocol: READ COMMITTED, principal then session locks, guarded write,
-- final recheck, COMMIT on the SAME connection. Never cache success between txns.
CREATE FUNCTION echo_identity.assert_private_draft_fence(
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
    p_token_expires_ms bigint
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    principal echo_identity.principals%ROWTYPE;
    session_row echo_identity.sessions%ROWTYPE;
    checked_ms bigint;
BEGIN
    -- Deliberately no STRICT: null input must RAISE, not silently return success.
    IF p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048
       OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255
       OR p_session_key IS NULL OR p_session_key !~ '^[a-f0-9]{64}$'
       OR p_principal_id IS NULL OR p_actor_id IS NULL OR p_source_id IS NULL
       OR p_principal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_actor_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_source_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_auth_version IS NULL OR p_auth_version < 1
       OR p_capability IS DISTINCT FROM 'voice:draft:create'
       OR p_token_issued_ms IS NULL OR p_token_not_before_ms IS NULL
       OR p_token_expires_ms IS NULL
       OR p_token_issued_ms NOT BETWEEN 0 AND 9007199254740991
       OR p_token_not_before_ms NOT BETWEEN 0 AND 9007199254740991
       OR p_token_expires_ms NOT BETWEEN 0 AND 9007199254740991
       OR p_token_issued_ms > p_token_not_before_ms
       OR p_token_not_before_ms >= p_token_expires_ms THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE = '42501';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'UNSUPPORTED_FENCE_ISOLATION' USING ERRCODE = '25001';
    END IF;

    -- FOR KEY SHARE would NOT block non-key role/revoke updates. FOR SHARE does.
    -- These are row locks, not a global/table-exclusive lock. Keep this order in
    -- future mixed principal/session mutations too; lock timeout/deadlock = abort.
    SELECT * INTO principal FROM echo_identity.principals
      WHERE principal_id = p_principal_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO session_row FROM echo_identity.sessions
      WHERE session_key = p_session_key COLLATE "C" FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE = '42501';
    END IF;

    -- MUST sample wall clock AFTER potentially blocking lock acquisition.
    -- now()/transaction_timestamp() would freeze the time at transaction start.
    checked_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF principal.issuer IS DISTINCT FROM p_issuer COLLATE "C"
       OR principal.subject IS DISTINCT FROM p_subject COLLATE "C"
       OR principal.actor_id IS DISTINCT FROM p_actor_id
       OR principal.source_id IS DISTINCT FROM p_source_id
       OR principal.actor_kind <> 'HUMAN'
       OR NOT principal.enabled OR NOT principal.writer_enabled
       OR principal.auth_version <> p_auth_version
       OR session_row.principal_id <> principal.principal_id
       OR session_row.auth_version <> principal.auth_version
       OR session_row.revoked
       OR session_row.expires_at <= session_row.issued_at
       OR checked_ms < ceil(extract(epoch FROM session_row.issued_at) * 1000)::bigint
       OR checked_ms >= floor(extract(epoch FROM session_row.expires_at) * 1000)::bigint
       OR p_token_issued_ms < ceil(extract(epoch FROM session_row.issued_at) * 1000)::bigint
       OR checked_ms < p_token_issued_ms OR checked_ms < p_token_not_before_ms
       OR checked_ms >= p_token_expires_ms THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE = '42501';
    END IF;
    -- No DML, success flag, reusable ticket, PUBLIC permission or object grant.
    -- Row locks remain until transaction end (unless rolled back to a savepoint).
END $$;
REVOKE ALL ON FUNCTION echo_identity.assert_private_draft_fence(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint
) FROM PUBLIC;
-- No table gets a trigger here. The test-only probe demonstrates early + deferred
-- checks. Wiring real immutable Voice revisions, protected execution context and
-- least-privilege writer roles remains BLOCKED. Never use DB owner in a public API.
