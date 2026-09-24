-- P2.1c.2d.4c.5b — signed account-link service boundary.
-- This gate adds the only service LOGIN permitted to SET the account-link runtime.
-- It does not create HTTP routes, principal/session provisioning orchestration, or
-- production credentials. Bearer verification remains in trusted backend code.
DO $$
BEGIN
  IF to_regrole('echo_account_link_guard') IS NULL
     OR to_regrole('echo_account_link_runtime') IS NULL
     OR to_regprocedure('echo_identity.runtime_issue_account_link_proof(uuid,text,text,bigint,bigint,bigint,bigint)') IS NULL THEN
    RAISE EXCEPTION 'P2.1c.2d.4c.5a account-link proof gate required first' USING ERRCODE='55000';
  END IF;
  IF to_regrole('echo_account_link_service') IS NOT NULL THEN
    RAISE EXCEPTION 'Account-link service role already exists; do not overwrite grants' USING ERRCODE='42710';
  END IF;
END $$;

CREATE ROLE echo_account_link_service
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 8 PASSWORD NULL;

REVOKE ALL ON SCHEMA echo_identity,echo_core FROM echo_account_link_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM echo_account_link_service;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_core FROM echo_account_link_service;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM echo_account_link_service;

GRANT echo_account_link_runtime TO echo_account_link_service
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

ALTER ROLE echo_account_link_service SET search_path = pg_catalog;
ALTER ROLE echo_account_link_service SET row_security = on;
ALTER ROLE echo_account_link_service SET statement_timeout = '5s';
ALTER ROLE echo_account_link_service SET lock_timeout = '3s';
ALTER ROLE echo_account_link_service SET idle_in_transaction_session_timeout = '10s';

COMMENT ON ROLE echo_account_link_service IS
  'Backend-only signed account-link issuer. SET LOCAL only to echo_account_link_runtime; request identity fields are forbidden by the paired backend boundary.';

-- PASSWORD NULL blocks password authentication only. Production HBA/TLS,
-- credential rotation/drain, proxy behavior, HTTP rate limits and principal/session
-- bootstrap remain later gates. A raw pool connection is trusted backend internals,
-- not an untrusted SQL or browser interface.
