-- P2.1c.2d.2: least-privilege / no-bypass execution capsule.
-- ADDITIVE RESEARCH CONTRACT ONLY. No production roles, HTTP route or real Voice
-- writer are created here. Deployers must install the documented grants with a
-- dedicated NOLOGIN function owner; never leave these functions owned by DB owner.
CREATE SCHEMA echo_execution;
REVOKE ALL ON SCHEMA echo_execution FROM PUBLIC;

-- Short-lived server-internal capsule. It binds a verified authorization stamp
-- to one already-validated PRIVATE-draft command. This is NOT a browser token.
CREATE TABLE echo_execution.private_draft_tickets (
    ticket_id uuid PRIMARY KEY CHECK (ticket_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    command_id uuid NOT NULL UNIQUE CHECK (command_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    payload_ref text NOT NULL CHECK (length(payload_ref) BETWEEN 1 AND 2048),
    issuer text COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject text COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    session_key text COLLATE "C" NOT NULL CHECK (session_key ~ '^[a-f0-9]{64}$'),
    principal_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    source_id uuid NOT NULL,
    auth_version integer NOT NULL CHECK (auth_version > 0),
    capability text NOT NULL CHECK (capability = 'voice:draft:create'),
    token_issued_ms bigint NOT NULL CHECK (token_issued_ms BETWEEN 0 AND 9007199254740991),
    token_not_before_ms bigint NOT NULL CHECK (token_not_before_ms BETWEEN 0 AND 9007199254740991),
    token_expires_ms bigint NOT NULL CHECK (token_expires_ms BETWEEN 0 AND 9007199254740991),
    minted_ms bigint NOT NULL CHECK (minted_ms BETWEEN 0 AND 9007199254740991),
    ticket_expires_ms bigint NOT NULL CHECK (ticket_expires_ms BETWEEN 0 AND 9007199254740991),
    consumed_ms bigint CHECK (consumed_ms BETWEEN 0 AND 9007199254740991),
    CHECK (token_issued_ms <= token_not_before_ms AND token_not_before_ms < token_expires_ms),
    CHECK (minted_ms < ticket_expires_ms AND ticket_expires_ms <= token_expires_ms),
    CHECK (consumed_ms IS NULL OR consumed_ms >= minted_ms)
);

-- Test/research target only. The next task must wire the same boundary to the
-- immutable Voice revision table without broadening grants.
CREATE TABLE echo_execution.private_draft_probe (
    command_id uuid PRIMARY KEY,
    ticket_id uuid NOT NULL UNIQUE REFERENCES echo_execution.private_draft_tickets(ticket_id),
    actor_id uuid NOT NULL REFERENCES echo_core.actors(actor_id),
    source_id uuid NOT NULL REFERENCES echo_core.sources(source_id),
    payload_ref text NOT NULL CHECK (length(payload_ref) BETWEEN 1 AND 2048),
    visibility text NOT NULL CHECK (visibility = 'PRIVATE'),
    recorded_at timestamptz NOT NULL
);
REVOKE ALL ON ALL TABLES IN SCHEMA echo_execution FROM PUBLIC;

-- Called only by a trusted authentication/command bridge after signature,
-- registry and DTO checks. Runtime/browser code must not get EXECUTE here.
CREATE FUNCTION echo_execution.mint_private_draft_ticket(
    p_ticket_id uuid,
    p_command_id uuid,
    p_payload_ref text,
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
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE checked_ms bigint;
BEGIN
    IF p_ticket_id IS NULL OR p_ticket_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_command_id IS NULL OR p_command_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_payload_ref IS NULL OR length(p_payload_ref) NOT BETWEEN 1 AND 2048 THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE='42501';
    END IF;

    -- Existing fence locks principal then session and rechecks current DB state.
    PERFORM echo_identity.assert_private_draft_fence(
      p_issuer,p_subject,p_session_key,p_principal_id,p_actor_id,p_source_id,
      p_auth_version,p_capability,p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms);

    checked_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF checked_ms >= p_token_expires_ms THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE='42501';
    END IF;

    INSERT INTO echo_execution.private_draft_tickets(
      ticket_id,command_id,payload_ref,issuer,subject,session_key,principal_id,
      actor_id,source_id,auth_version,capability,token_issued_ms,
      token_not_before_ms,token_expires_ms,minted_ms,ticket_expires_ms)
    VALUES(
      p_ticket_id,p_command_id,p_payload_ref,p_issuer,p_subject,p_session_key,
      p_principal_id,p_actor_id,p_source_id,p_auth_version,p_capability,
      p_token_issued_ms,p_token_not_before_ms,p_token_expires_ms,checked_ms,
      LEAST(p_token_expires_ms, checked_ms + 30000));
    RETURN p_ticket_id;
END $$;

-- Runtime gets only this one-shot entrypoint and a random server-owned ticket id.
-- Actor/source/payload/visibility are read from the private capsule, not arguments.
CREATE FUNCTION echo_execution.execute_private_draft_probe(p_ticket_id uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    ticket echo_execution.private_draft_tickets%ROWTYPE;
    checked_ms bigint;
BEGIN
    IF p_ticket_id IS NULL OR p_ticket_id = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE='42501';
    END IF;

    SELECT * INTO ticket FROM echo_execution.private_draft_tickets
      WHERE ticket_id=p_ticket_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE='42501';
    END IF;
    checked_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF ticket.consumed_ms IS NOT NULL OR checked_ms >= ticket.ticket_expires_ms THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE='42501';
    END IF;

    PERFORM echo_identity.assert_private_draft_fence(
      ticket.issuer,ticket.subject,ticket.session_key,ticket.principal_id,
      ticket.actor_id,ticket.source_id,ticket.auth_version,ticket.capability,
      ticket.token_issued_ms,ticket.token_not_before_ms,ticket.token_expires_ms);

    -- Synthetic target only: no real Voice/history row is created in this task.
    INSERT INTO echo_execution.private_draft_probe(
      command_id,ticket_id,actor_id,source_id,payload_ref,visibility,recorded_at)
    VALUES(ticket.command_id,ticket.ticket_id,ticket.actor_id,ticket.source_id,
           ticket.payload_ref,'PRIVATE',clock_timestamp());

    -- Final authority + wall-clock check on the same transaction. Any failure
    -- rolls back both the probe insert and ticket consumption.
    PERFORM echo_identity.assert_private_draft_fence(
      ticket.issuer,ticket.subject,ticket.session_key,ticket.principal_id,
      ticket.actor_id,ticket.source_id,ticket.auth_version,ticket.capability,
      ticket.token_issued_ms,ticket.token_not_before_ms,ticket.token_expires_ms);
    checked_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF checked_ms >= ticket.ticket_expires_ms THEN
        RAISE EXCEPTION 'AUTHORIZATION_DENIED' USING ERRCODE='42501';
    END IF;

    UPDATE echo_execution.private_draft_tickets
      SET consumed_ms=checked_ms WHERE ticket_id=ticket.ticket_id;
    RETURN ticket.command_id;
END $$;

REVOKE ALL ON FUNCTION echo_execution.mint_private_draft_ticket(
  uuid,uuid,text,text,text,text,uuid,uuid,uuid,integer,text,bigint,bigint,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION echo_execution.execute_private_draft_probe(uuid) FROM PUBLIC;

-- Role names/grants are deployment-specific and therefore intentionally absent.
-- Required contract: dedicated NOLOGIN definer owner has only SELECT identity,
-- EXECUTE fence, INSERT/SELECT/column-UPDATE ticket, INSERT probe; auth bridge only
-- EXECUTE mint; runtime only EXECUTE consume. CI installs exactly that grant set.
