-- Echo News P2.1c.2d.2a: least-privilege DB runtime role for the PRIVATE draft fence.
-- Additive TEST/DEVELOPMENT contract only. Requires p2_1c2c + p2_1c2d1.
-- This does NOT create a LOGIN, HTTP endpoint, Voice writer or publication path.
-- Role creation/ownership transfer requires a migration/DBA principal. Never use
-- that migration principal as the application connection identity.

DO $$
BEGIN
    IF to_regrole('echo_private_draft_guard') IS NOT NULL
       OR to_regrole('echo_private_draft_runtime') IS NOT NULL THEN
        RAISE EXCEPTION 'Echo private draft roles already exist' USING ERRCODE='42710';
    END IF;
    IF to_regprocedure('echo_identity.assert_private_draft_fence(text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint)') IS NULL THEN
        RAISE EXCEPTION 'P2.1c.2d.1 fence is required first' USING ERRCODE='55000';
    END IF;
END $$;

CREATE ROLE echo_private_draft_guard
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_private_draft_runtime
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

-- Start from no privileges, then give the sealed guard only enough rights to run
-- the existing SECURITY INVOKER fence. SELECT ... FOR SHARE requires SELECT plus
-- UPDATE privilege on at least one column in PostgreSQL. We therefore grant UPDATE
-- only on immutable key columns used solely to satisfy the row-lock privilege
-- check, never table-wide UPDATE. The application runtime gets no table access.
REVOKE ALL ON SCHEMA echo_identity FROM echo_private_draft_guard, echo_private_draft_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM echo_private_draft_guard, echo_private_draft_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM echo_private_draft_guard, echo_private_draft_runtime;

GRANT USAGE ON SCHEMA echo_identity TO echo_private_draft_guard;
GRANT SELECT ON echo_identity.principals, echo_identity.sessions TO echo_private_draft_guard;
GRANT UPDATE (principal_id) ON echo_identity.principals TO echo_private_draft_guard;
GRANT UPDATE (session_key) ON echo_identity.sessions TO echo_private_draft_guard;
GRANT EXECUTE ON FUNCTION echo_identity.assert_private_draft_fence(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint
) TO echo_private_draft_guard;

-- SECURITY DEFINER is deliberately tiny: no dynamic SQL, no client callback, no
-- table DML, fully-qualified target, fixed search_path. It returns no reusable grant.
CREATE FUNCTION echo_identity.runtime_private_draft_fence(
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
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM echo_identity.assert_private_draft_fence(
        p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
        p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms
    );
END $$;
REVOKE ALL ON FUNCTION echo_identity.runtime_private_draft_fence(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint
) FROM PUBLIC;

GRANT USAGE ON SCHEMA echo_identity TO echo_private_draft_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_private_draft_fence(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint
) TO echo_private_draft_runtime;

-- Transfer only the narrow wrapper to the non-login guard role. The guard gets no
-- CREATE on echo_identity, no table-wide UPDATE, and no INSERT/DELETE/TRUNCATE.
-- Column UPDATE on the immutable key of each authority table exists only because
-- PostgreSQL requires it for SELECT ... FOR SHARE. Runtime has no membership in
-- guard and cannot invoke SQL as this role.
ALTER FUNCTION echo_identity.runtime_private_draft_fence(
    text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint
) OWNER TO echo_private_draft_guard;

-- No membership is granted between these roles. A future service LOGIN must be
-- provisioned separately with SET access only to echo_private_draft_runtime and
-- must not inherit migration/owner privileges.
--
-- IMPORTANT: this closes only the database privilege surface around the fence.
-- The arguments are still trusted-backend inputs. P2.1c.2d.2b must propagate an
-- unforgeable-by-request server stamp from the signed registry path; browser JSON
-- must never be accepted as these parameters. Calling this function alone outside
-- the same transaction as a future write grants nothing because the locks end.
