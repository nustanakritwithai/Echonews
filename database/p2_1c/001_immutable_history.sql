-- Echo News P2.1c.1: append-only history under NORMAL non-owner DML.
-- Requires P2.1b schema. Apply with psql -X -v ON_ERROR_STOP=1 --single-transaction.
-- Test/development only until authentication, RLS, redaction and snapshot sealing pass.
-- Does not defend against owners/superusers changing DDL, disabling triggers or restores.
-- No IF NOT EXISTS / OR REPLACE: an existing install fails rather than being overwritten.
CREATE SCHEMA echo_history;
REVOKE ALL ON SCHEMA echo_history FROM PUBLIC;

-- Metadata only: never copy payloads, URLs, proposition text or rationales here.
-- IDs and database principals are still sensitive metadata, not anonymous data.
-- Audit starts at installation; existing rows are NOT backfilled as past observations.
CREATE TABLE echo_history.insert_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    object_table text NOT NULL,
    record_key jsonb NOT NULL CHECK (jsonb_typeof(record_key) = 'object'),
    inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
    session_principal name NOT NULL,
    active_db_role name NOT NULL,
    UNIQUE (object_table, record_key)
);
REVOKE ALL ON TABLE echo_history.insert_audit FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA echo_history FROM PUBLIC;

CREATE FUNCTION echo_history.reject_history_mutation()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = format('ECHO_APPEND_ONLY: %I.%I rejects %s',
                         TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP),
        HINT = 'Insert a successor revision/new immutable record. Privacy erasure needs a separately reviewed workflow.';
END;
$$;
REVOKE ALL ON FUNCTION echo_history.reject_history_mutation() FROM PUBLIC;

-- SECURITY DEFINER is limited to this closed trigger path. It cannot receive
-- arbitrary SQL/identifiers from an application argument. No public EXECUTE.
CREATE FUNCTION echo_history.audit_history_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    row_value jsonb := to_jsonb(NEW);
    key_value jsonb := '{}'::jsonb;
    key_name text;
BEGIN
    IF TG_OP <> 'INSERT' OR TG_TABLE_SCHEMA <> 'echo_core' OR TG_NARGS < 1 THEN
        RAISE EXCEPTION 'Unexpected audit invocation' USING ERRCODE = '55000';
    END IF;
    FOREACH key_name IN ARRAY TG_ARGV LOOP
        IF NOT row_value ? key_name OR row_value -> key_name = 'null'::jsonb THEN
            RAISE EXCEPTION 'Missing audit key' USING ERRCODE = '55000';
        END IF;
        key_value := key_value || jsonb_build_object(key_name, row_value -> key_name);
    END LOOP;
    INSERT INTO echo_history.insert_audit
        (object_table, record_key, session_principal, active_db_role)
    VALUES
        (TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, key_value, session_user,
         COALESCE(NULLIF(current_setting('role'), 'none'), session_user)::name);
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION echo_history.audit_history_insert() FROM PUBLIC;

DO $$
DECLARE
    table_name text;
    key_args text;
    targets constant text[] := ARRAY[
        'event_revisions','voice_revisions','event_voice_links',
        'claim_revisions','claim_voice_links','evidence_revisions',
        'evidence_voice_links','evidence_assessments','evidence_provenance_edges',
        'policy_versions','state_snapshots','snapshot_items','snapshot_assessment_inputs'
    ];
BEGIN
    FOREACH table_name IN ARRAY targets LOOP
        -- Catalog-derived PKs, not application-supplied JSON pointers.
        SELECT string_agg(quote_literal(a.attname), ', ' ORDER BY k.ordinality)
          INTO key_args
          FROM pg_index i
          CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality)
          JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
         WHERE i.indrelid = to_regclass(format('echo_core.%I', table_name))
           AND i.indisprimary;
        IF key_args IS NULL THEN
            RAISE EXCEPTION 'Missing expected P2.1b primary key: %', table_name;
        END IF;
        -- Statement-level also blocks zero-row UPDATE/DELETE and upsert UPDATE.
        EXECUTE format('CREATE TRIGGER echo_reject_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON echo_core.%I FOR EACH STATEMENT EXECUTE FUNCTION echo_history.reject_history_mutation()', table_name);
        EXECUTE format('CREATE TRIGGER echo_audit_insert AFTER INSERT ON echo_core.%I FOR EACH ROW EXECUTE FUNCTION echo_history.audit_history_insert(%s)', table_name, key_args);
        EXECUTE format('ALTER TABLE echo_core.%I ENABLE ALWAYS TRIGGER echo_reject_mutation', table_name);
        EXECUTE format('ALTER TABLE echo_core.%I ENABLE ALWAYS TRIGGER echo_audit_insert', table_name);
    END LOOP;
END;
$$;

CREATE TRIGGER echo_reject_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON echo_history.insert_audit
FOR EACH STATEMENT EXECUTE FUNCTION echo_history.reject_history_mutation();
ALTER TABLE echo_history.insert_audit ENABLE ALWAYS TRIGGER echo_reject_mutation;

-- No API/public role is created or granted here. Owner and migration credentials
-- MUST NOT become application credentials. Actor/source identity rows are outside
-- this row-history task. So are immutable *sets* (late snapshot children), authentic
-- reviewer identity, commit ordering, state recomputation, and privacy erasure.
