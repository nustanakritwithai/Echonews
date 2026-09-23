-- P2.1c.2c: private durable mapping for trusted auth/provisioning adapters.
-- Apply only on a disposable development database until remaining auth gates pass.
-- No public/login role or endpoint is created, and no raw credential is stored.
CREATE SCHEMA echo_identity;
REVOKE ALL ON SCHEMA echo_identity FROM PUBLIC;

CREATE TABLE echo_identity.principals (
    principal_id uuid PRIMARY KEY,
    issuer text COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject text COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    actor_id uuid NOT NULL UNIQUE,
    actor_kind text NOT NULL DEFAULT 'HUMAN' CHECK (actor_kind = 'HUMAN'),
    source_id uuid NOT NULL UNIQUE REFERENCES echo_core.sources(source_id),
    enabled boolean NOT NULL DEFAULT false,
    writer_enabled boolean NOT NULL DEFAULT false,
    reviewer_enabled boolean NOT NULL DEFAULT false,
    auth_version integer NOT NULL DEFAULT 1 CHECK (auth_version > 0),
    UNIQUE (issuer, subject),
    FOREIGN KEY (actor_id, actor_kind) REFERENCES echo_core.actors(actor_id, actor_kind)
);

-- session_key is a non-bearer lookup digest from the trusted session adapter.
-- Knowing it is NOT authentication; verifier proof of the same session is required.
CREATE TABLE echo_identity.sessions (
    session_key text COLLATE "C" PRIMARY KEY CHECK (session_key ~ '^[a-f0-9]{64}$'),
    principal_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
    auth_version integer NOT NULL CHECK (auth_version > 0),
    issued_at timestamptz NOT NULL CHECK (isfinite(issued_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    revoked boolean NOT NULL DEFAULT false,
    CHECK (expires_at > issued_at)
);
CREATE INDEX session_principal_idx ON echo_identity.sessions(principal_id);
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM PUBLIC;

CREATE FUNCTION echo_identity.guard_principal()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.auth_version <> 1 THEN
            RAISE EXCEPTION 'Initial auth_version must be 1' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.principal_id,NEW.issuer,NEW.subject,NEW.actor_id,NEW.actor_kind,NEW.source_id)
       IS DISTINCT FROM ROW(OLD.principal_id,OLD.issuer,OLD.subject,OLD.actor_id,OLD.actor_kind,OLD.source_id) THEN
        RAISE EXCEPTION 'Identity binding cannot be retargeted' USING ERRCODE='55000';
    END IF;
    IF NEW.auth_version::bigint <> OLD.auth_version::bigint + 1 THEN
        RAISE EXCEPTION 'Every authority update must advance auth_version by one' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER principal_binding_guard BEFORE INSERT OR UPDATE ON echo_identity.principals
FOR EACH ROW EXECUTE FUNCTION echo_identity.guard_principal();

CREATE FUNCTION echo_identity.guard_session()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE p echo_identity.principals%ROWTYPE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Provisioning must serialize against authority updates. No client DML.
        SELECT * INTO p FROM echo_identity.principals WHERE principal_id=NEW.principal_id FOR SHARE;
        IF NOT FOUND OR NOT p.enabled OR p.auth_version <> NEW.auth_version OR NEW.revoked THEN
            RAISE EXCEPTION 'Session requires current enabled principal/version' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.session_key,NEW.principal_id,NEW.auth_version,NEW.issued_at,NEW.expires_at)
       IS DISTINCT FROM ROW(OLD.session_key,OLD.principal_id,OLD.auth_version,OLD.issued_at,OLD.expires_at) THEN
        RAISE EXCEPTION 'Session identity/lifetime cannot be replaced' USING ERRCODE='55000';
    END IF;
    IF OLD.revoked AND NOT NEW.revoked THEN
        RAISE EXCEPTION 'Revoked session cannot be reactivated' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER session_binding_guard BEFORE INSERT OR UPDATE ON echo_identity.sessions
FOR EACH ROW EXECUTE FUNCTION echo_identity.guard_session();

CREATE FUNCTION echo_identity.reject_removal()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'Use disable/revoke; erasure requires a reviewed administrative workflow' USING ERRCODE='55000';
END $$;
CREATE TRIGGER principal_no_removal BEFORE DELETE OR TRUNCATE ON echo_identity.principals
FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.reject_removal();
CREATE TRIGGER session_no_removal BEFORE DELETE OR TRUNCATE ON echo_identity.sessions
FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.reject_removal();

-- A single SQL statement reads one MVCC snapshot. This does NOT reserve authority
-- through a future write/commit: the writer transaction MUST fence/recheck later.
-- SECURITY INVOKER; only a trusted server role with SELECT and EXECUTE may call it.
CREATE FUNCTION echo_identity.lookup_session(p_issuer text,p_subject text,p_key text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
 SELECT jsonb_build_object(
   'principal',jsonb_build_object(
     'principalId',p.principal_id,'issuer',p.issuer,'subject',p.subject,
     'actorId',p.actor_id,'sourceId',p.source_id,'actorKind',p.actor_kind,
     'enabled',p.enabled,'authVersion',p.auth_version,
     'writerEnabled',p.writer_enabled,'reviewerEnabled',p.reviewer_enabled),
   'session',jsonb_build_object(
     'sessionKey',s.session_key,'principalId',s.principal_id,'authVersion',s.auth_version,
     'issuedAtMs',floor(extract(epoch FROM s.issued_at)*1000)::bigint,
     'expiresAtMs',floor(extract(epoch FROM s.expires_at)*1000)::bigint,'revoked',s.revoked))
 FROM echo_identity.principals p JOIN echo_identity.sessions s USING(principal_id)
 WHERE p.issuer=p_issuer COLLATE "C" AND p.subject=p_subject COLLATE "C"
   AND s.session_key=p_key COLLATE "C";
$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM PUBLIC;
-- Provisioning, actor ownership proof, cryptographic verifier, audited role grants,
-- primary-pool adapter, role grants/RLS, erasure and write-time fences are NOT here.
-- Owners/migration principals can still alter DDL. Never use them in a public API.
