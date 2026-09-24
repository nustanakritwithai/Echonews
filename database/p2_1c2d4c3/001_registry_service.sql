-- P2.1c.2d.4c.3: dedicated durable identity-registry lookup service.
-- Scope is read-only signed-token -> principal/session resolution only.
-- No provisioning, session creation/revocation, HTTP auth endpoint, password secret,
-- HBA/TLS policy, reviewer object access, writer grant or public publication is added.
DO $$
BEGIN
  IF to_regclass('echo_identity.principals') IS NULL
     OR to_regclass('echo_identity.sessions') IS NULL
     OR to_regprocedure('echo_identity.lookup_session(text,text,text)') IS NULL THEN
    RAISE EXCEPTION 'P2.1c.2c durable identity registry required' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_identity_registry_guard') IS NOT NULL
     OR to_regrole('echo_identity_registry_runtime') IS NOT NULL
     OR to_regrole('echo_identity_registry_service') IS NOT NULL
     OR to_regprocedure('echo_identity.runtime_lookup_session(text,text,text)') IS NOT NULL THEN
    RAISE EXCEPTION 'Registry service objects already exist; do not overwrite grants' USING ERRCODE='42710';
  END IF;
END $$;

CREATE ROLE echo_identity_registry_guard
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_identity_registry_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_identity_registry_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 12 PASSWORD NULL;

REVOKE ALL ON SCHEMA echo_identity FROM echo_identity_registry_guard,
  echo_identity_registry_runtime, echo_identity_registry_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM echo_identity_registry_guard,
  echo_identity_registry_runtime, echo_identity_registry_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM echo_identity_registry_guard,
  echo_identity_registry_runtime, echo_identity_registry_service;

-- Only the sealed guard may inspect durable authority rows. It cannot login and has
-- no write grant. The runtime gets no table privilege at all.
GRANT USAGE ON SCHEMA echo_identity TO echo_identity_registry_guard;
GRANT SELECT ON echo_identity.principals, echo_identity.sessions TO echo_identity_registry_guard;
GRANT EXECUTE ON FUNCTION echo_identity.lookup_session(text,text,text)
  TO echo_identity_registry_guard;

CREATE FUNCTION echo_identity.runtime_lookup_session(
  p_issuer text,
  p_subject text,
  p_session_key text
) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER CALLED ON NULL INPUT
SET search_path = pg_catalog, pg_temp
SET row_security = on AS $$
  SELECT echo_identity.lookup_session(p_issuer,p_subject,p_session_key);
$$;

REVOKE ALL ON FUNCTION echo_identity.runtime_lookup_session(text,text,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA echo_identity TO echo_identity_registry_runtime;
GRANT EXECUTE ON FUNCTION echo_identity.runtime_lookup_session(text,text,text)
  TO echo_identity_registry_runtime;
ALTER FUNCTION echo_identity.runtime_lookup_session(text,text,text)
  OWNER TO echo_identity_registry_guard;

-- Service can only SET to the fixed read runtime. NOINHERIT means it receives no
-- runtime privilege while sitting at the baseline login role.
GRANT echo_identity_registry_runtime TO echo_identity_registry_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

ALTER ROLE echo_identity_registry_service SET search_path = pg_catalog;
ALTER ROLE echo_identity_registry_service SET row_security = on;
ALTER ROLE echo_identity_registry_service SET statement_timeout = '5s';
ALTER ROLE echo_identity_registry_service SET lock_timeout = '3s';
ALTER ROLE echo_identity_registry_service SET idle_in_transaction_session_timeout = '10s';

COMMENT ON ROLE echo_identity_registry_service IS
  'Backend-only durable identity lookup login. SET LOCAL only to echo_identity_registry_runtime; provisioning is deliberately separate.';
COMMENT ON FUNCTION echo_identity.runtime_lookup_session(text,text,text) IS
  'P2.1c.2d.4c.3 sealed current principal/session snapshot for verified signed-token backend lookup.';

-- PASSWORD NULL blocks password authentication only. Production secret rotation,
-- certificates/HBA, proxy behavior, connection budgets and provisioning credentials
-- remain separate gates and MUST NOT be inferred from this migration.
