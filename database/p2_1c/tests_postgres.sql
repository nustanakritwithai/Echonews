\set ON_ERROR_STOP on
-- DISPOSABLE test database only. Role, schema and fixtures roll back together.
BEGIN;
\ir ../p2_1b/schema.sql
\ir 001_immutable_history.sql
\ir ../p2_1b/fixtures.sql
CREATE TEMP TABLE checks (label text PRIMARY KEY, result text NOT NULL) ON COMMIT DROP;
CREATE FUNCTION pg_temp.ok(label text, condition boolean)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF condition IS DISTINCT FROM true THEN RAISE EXCEPTION 'FAIL: %', label; END IF;
    INSERT INTO checks VALUES (label, 'SAT');
END $$;
CREATE FUNCTION pg_temp.err(label text, statement text, expected text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE actual text;
BEGIN
    BEGIN
        EXECUTE statement;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS actual = RETURNED_SQLSTATE;
    END;
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'FAIL %: expected %, got %', label, expected, coalesce(actual, 'SUCCESS');
    END IF;
    INSERT INTO checks VALUES (label, 'SAT');
END $$;

-- Populate the three optional relation tables as well as the supplied fixtures.
INSERT INTO echo_core.claim_voice_links
SELECT claim_id, revision, event_id, primary_voice_link_id,
       primary_voice_link_revision, derived_by, recorded_at
FROM echo_core.claim_revisions;
INSERT INTO echo_core.evidence_voice_links
SELECT evidence_id, revision, introduced_by_voice_id,
       introduced_by_voice_revision, 'ATTACHED', recorded_at
FROM echo_core.evidence_revisions;
INSERT INTO echo_core.evidence_provenance_edges
(edge_id, revision, child_evidence_id, child_evidence_revision,
 parent_evidence_id, parent_evidence_revision, edge_kind, basis,
 asserted_by, method_version, rationale, recorded_at)
VALUES ('90000000-0000-0000-0000-000000000001',1,
'f6dd6ad2-33f6-55af-a874-8853fe84dcc3',1,'5d765272-41a7-5a94-ae74-0c9b7809c35f',1,
'REFERENCES','DECLARED','272a37fa-9e4f-50fc-bd3b-38625412fe19',
'fixture','Synthetic reference, not source independence',clock_timestamp());

CREATE TEMP TABLE targets (table_name text PRIMARY KEY, key_column text, row_count bigint);
INSERT INTO targets
SELECT c.relname, a.attname, 0
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
JOIN pg_index i ON i.indrelid=c.oid AND i.indisprimary
JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0]
WHERE n.nspname='echo_core' AND c.relkind='r'
AND c.relname NOT IN ('actors','sources');
SELECT pg_temp.ok('01_exactly_thirteen_history_tables', (SELECT count(*)=13 FROM targets));
DO $$ DECLARE t record; n bigint; before_n bigint;
BEGIN
    FOR t IN SELECT * FROM targets LOOP
        EXECUTE format('SELECT count(*) FROM echo_core.%I',t.table_name) INTO n;
        UPDATE targets SET row_count=n WHERE table_name=t.table_name;
        before_n := n;
        IF n=0 THEN RAISE EXCEPTION 'Test table empty: %',t.table_name; END IF;
        PERFORM pg_temp.err('guard_update_'||t.table_name,
            format('UPDATE echo_core.%I SET %I=%I',t.table_name,t.key_column,t.key_column),'55000');
        PERFORM pg_temp.err('guard_delete_'||t.table_name,
            format('DELETE FROM echo_core.%I',t.table_name),'55000');
        PERFORM pg_temp.err('guard_truncate_'||t.table_name,
            format('TRUNCATE echo_core.%I CASCADE',t.table_name),'55000');
        EXECUTE format('SELECT count(*) FROM echo_core.%I',t.table_name) INTO n;
        IF n<>before_n THEN RAISE EXCEPTION 'Rows changed'; END IF;
    END LOOP;
END $$;
SELECT pg_temp.ok('02_exactly_once_metadata_for_initial_inserts',
    (SELECT sum(row_count) FROM targets)=(SELECT count(*) FROM echo_history.insert_audit));
SELECT pg_temp.ok('03_all_guard_and_audit_triggers_enabled_always',
    (SELECT count(*)=26 FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid
     JOIN targets t ON t.table_name=c.relname
     WHERE c.relnamespace='echo_core'::regnamespace
     AND g.tgname IN ('echo_reject_mutation','echo_audit_insert') AND g.tgenabled='A'));
SELECT pg_temp.ok('04_audit_contains_only_primary_key_fields',
    NOT EXISTS (SELECT 1 FROM echo_history.insert_audit a,
                LATERAL jsonb_object_keys(a.record_key) k(name)
                WHERE k.name IN ('proposition','payload_ref','rationale','asset_ref','title','config','source_locator')));
SELECT pg_temp.ok('05_server_generated_time_not_client_recorded_at',
    (SELECT bool_and(inserted_at>=transaction_timestamp()) FROM echo_history.insert_audit));
SELECT pg_temp.ok('06_audit_has_actual_transaction',
    (SELECT bool_and(transaction_id=pg_current_xact_id()) FROM echo_history.insert_audit));
SELECT pg_temp.err('07_audit_update_blocked','UPDATE echo_history.insert_audit SET object_table=object_table','55000');
SELECT pg_temp.err('08_audit_delete_blocked','DELETE FROM echo_history.insert_audit','55000');
SELECT pg_temp.err('09_audit_truncate_blocked','TRUNCATE echo_history.insert_audit','55000');
SELECT pg_temp.err('10_even_zero_row_update_blocked','UPDATE echo_core.voice_revisions SET visibility=''PUBLIC'' WHERE false','55000');
SELECT pg_temp.err('11_even_zero_row_delete_blocked','DELETE FROM echo_core.voice_revisions WHERE false','55000');

-- New versions are allowed. Existing references remain pinned to version 1.
INSERT INTO echo_core.voice_revisions
(voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
SELECT voice_id,2,1,author_id,source_id,'fixture:voice-a-corrected','WITHDRAWN',posted_at,clock_timestamp()
FROM echo_core.voice_revisions WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=1;
SELECT pg_temp.ok('12_successor_voice_insert_allowed',
    (SELECT count(*)=2 FROM echo_core.voice_revisions WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d'));
SELECT pg_temp.ok('13_previous_voice_payload_and_visibility_unchanged',
    (SELECT payload_ref='fixture:voice-a-r1' AND visibility='PRIVATE'
     FROM echo_core.voice_revisions WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=1));
SELECT pg_temp.ok('14_existing_room_link_still_pins_voice_revision_one',
    (SELECT voice_revision=1 FROM echo_core.event_voice_links WHERE link_id='084c6466-d2ed-5032-9ef8-742d3b77dce0' AND revision=1));
INSERT INTO echo_core.evidence_assessments
SELECT (jsonb_populate_record(NULL::echo_core.evidence_assessments,
 to_jsonb(a)||jsonb_build_object('revision',2,'previous_revision',1,
 'withdrawn',true,'rationale','Corrected by appending, not overwriting',
 'recorded_at',clock_timestamp()))).* FROM echo_core.evidence_assessments a
WHERE assessment_id='012dc1a7-deed-5997-bd1d-bb647837f6d9' AND revision=1;
SELECT pg_temp.ok('15_withdrawal_is_new_assessment_revision',
    (SELECT withdrawn FROM echo_core.evidence_assessments WHERE assessment_id='012dc1a7-deed-5997-bd1d-bb647837f6d9' AND revision=2));
SELECT pg_temp.ok('16_previous_assessment_not_rewritten',
    (SELECT NOT withdrawn FROM echo_core.evidence_assessments WHERE assessment_id='012dc1a7-deed-5997-bd1d-bb647837f6d9' AND revision=1));
SELECT pg_temp.ok('17_old_snapshot_keeps_exact_assessment_version',
    (SELECT assessment_revision=1 FROM echo_core.snapshot_assessment_inputs WHERE snapshot_id='8c637c17-0de5-5421-b79e-1442c9b5f0f6'));
SELECT pg_temp.err('18_upsert_cannot_update_existing_history',
 'INSERT INTO echo_core.voice_revisions SELECT * FROM echo_core.voice_revisions WHERE voice_id=''4b34744b-b12e-5e4e-9404-a94d4b084f1d'' AND revision=1 ON CONFLICT (voice_id,revision) DO UPDATE SET payload_ref=excluded.payload_ref','55000');
CREATE TEMP TABLE audit_count AS SELECT count(*) AS n FROM echo_history.insert_audit;
INSERT INTO echo_core.voice_revisions SELECT * FROM echo_core.voice_revisions
WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=1 ON CONFLICT DO NOTHING;
SELECT pg_temp.ok('19_conflict_do_nothing_does_not_duplicate_audit',
 (SELECT n FROM audit_count)=(SELECT count(*) FROM echo_history.insert_audit));
SELECT pg_temp.err('20_merge_cannot_update_history',
 'MERGE INTO echo_core.voice_revisions v USING (SELECT ''4b34744b-b12e-5e4e-9404-a94d4b084f1d''::uuid AS id) s ON v.voice_id=s.id WHEN MATCHED THEN UPDATE SET payload_ref=v.payload_ref','55000');

-- Transaction failure must roll back audit and row, not leave a phantom commit.
DO $$ BEGIN
  BEGIN
    INSERT INTO echo_core.event_revisions (event_id,revision,title,created_by,recorded_at)
    VALUES ('90000000-0000-0000-0000-000000000002',1,'Rollback-only fixture',
            '272a37fa-9e4f-50fc-bd3b-38625412fe19',clock_timestamp());
    RAISE EXCEPTION 'injected rollback' USING ERRCODE='P0001';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN NULL;
  END;
END $$;
SELECT pg_temp.ok('21_rollback_removes_candidate_row',
 NOT EXISTS(SELECT 1 FROM echo_core.event_revisions WHERE event_id='90000000-0000-0000-0000-000000000002'));
SELECT pg_temp.ok('22_rollback_removes_candidate_audit',
 NOT EXISTS(SELECT 1 FROM echo_history.insert_audit WHERE record_key->>'event_id'='90000000-0000-0000-0000-000000000002'));
SELECT pg_temp.ok('23_failed_operations_add_no_committed_audit',
 (SELECT n FROM audit_count)=(SELECT count(*) FROM echo_history.insert_audit));

-- Test a regular non-owner database role. It is NOT a real user authentication model.
-- Intentionally grant UPDATE/DELETE/TRUNCATE to prove triggers enforce the policy
-- even with excessive DML grants. Do not use these grants as an API role template.
CREATE ROLE echo_p21c_test_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA echo_core,echo_history TO echo_p21c_test_writer;
GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON ALL TABLES IN SCHEMA echo_core TO echo_p21c_test_writer;
GRANT SELECT ON echo_history.insert_audit TO echo_p21c_test_writer;
GRANT SELECT,INSERT ON checks TO echo_p21c_test_writer;
SET LOCAL ROLE echo_p21c_test_writer;
SELECT pg_temp.err('24_nonowner_cannot_disable_guard',
 'ALTER TABLE echo_core.voice_revisions DISABLE TRIGGER echo_reject_mutation','42501');
SELECT pg_temp.err('25_nonowner_cannot_drop_guard',
 'DROP TRIGGER echo_reject_mutation ON echo_core.voice_revisions','42501');
SELECT pg_temp.err('26_nonowner_cannot_set_replication_role','SET LOCAL session_replication_role=replica','42501');
SELECT pg_temp.err('27_nonowner_cannot_replace_audit_function',
 'CREATE OR REPLACE FUNCTION echo_history.audit_history_insert() RETURNS trigger LANGUAGE plpgsql AS ''BEGIN RETURN NEW; END''','42501');
SELECT pg_temp.err('28_nonowner_cannot_forge_audit',
 'INSERT INTO echo_history.insert_audit(object_table,record_key,session_principal,active_db_role) VALUES (''fake'',''{}'',''fake'',''fake'')','42501');
SELECT pg_temp.err('29_nonowner_cannot_call_audit_function','SELECT echo_history.audit_history_insert()','42501');
SELECT pg_temp.err('30_nonowner_update_blocked_despite_grant',
 'UPDATE echo_core.voice_revisions SET payload_ref=''forged''','55000');
SELECT pg_temp.err('31_nonowner_delete_blocked_despite_grant','DELETE FROM echo_core.snapshot_items','55000');
SELECT pg_temp.err('32_nonowner_truncate_blocked_despite_grant','TRUNCATE echo_core.snapshot_items CASCADE','55000');
INSERT INTO echo_core.event_revisions (event_id,revision,title,created_by,recorded_at)
VALUES ('90000000-0000-0000-0000-000000000003',1,'Regular writer fixture',
        '272a37fa-9e4f-50fc-bd3b-38625412fe19',clock_timestamp());
SELECT pg_temp.ok('33_nonowner_valid_insert_audited_with_real_db_role',
 (SELECT active_db_role='echo_p21c_test_writer' AND session_principal=session_user
  FROM echo_history.insert_audit WHERE record_key->>'event_id'='90000000-0000-0000-0000-000000000003'));
RESET ROLE;

-- Even replica mode cannot accidentally suppress these ALWAYS triggers.
-- Owner can still explicitly disable/drop them; this is not a superuser defense.
SET LOCAL session_replication_role=replica;
SELECT pg_temp.err('34_always_guard_runs_in_replica_mode','DELETE FROM echo_core.voice_revisions','55000');
INSERT INTO echo_core.event_revisions (event_id,revision,title,created_by,recorded_at)
VALUES ('90000000-0000-0000-0000-000000000004',1,'Replica fixture',
        '272a37fa-9e4f-50fc-bd3b-38625412fe19',clock_timestamp());
SELECT pg_temp.ok('35_always_insert_audit_runs_in_replica_mode',
 EXISTS(SELECT 1 FROM echo_history.insert_audit WHERE record_key->>'event_id'='90000000-0000-0000-0000-000000000004'));
SET LOCAL session_replication_role=origin;

-- COPY must produce the same audit as INSERT.
COPY echo_core.event_revisions (event_id,revision,title,created_by,recorded_at) FROM STDIN WITH (FORMAT csv);
90000000-0000-0000-0000-000000000005,1,Copy fixture,272a37fa-9e4f-50fc-bd3b-38625412fe19,2026-09-23T09:00:00Z
\.
SELECT pg_temp.ok('36_copy_is_audited',
 EXISTS(SELECT 1 FROM echo_history.insert_audit WHERE record_key->>'event_id'='90000000-0000-0000-0000-000000000005'));

-- Attempt search-path shadowing; definer path and schema qualification must win.
CREATE TEMP TABLE insert_audit (unexpected text);
SET LOCAL search_path=pg_temp, public, echo_history;
INSERT INTO echo_core.event_revisions (event_id,revision,title,created_by,recorded_at)
VALUES ('90000000-0000-0000-0000-000000000006',1,'Search path fixture',
        '272a37fa-9e4f-50fc-bd3b-38625412fe19',clock_timestamp());
SELECT pg_temp.ok('37_temp_audit_table_cannot_hijack_insert',
 (SELECT count(*)=0 FROM pg_temp.insert_audit)
 AND EXISTS(SELECT 1 FROM echo_history.insert_audit WHERE record_key->>'event_id'='90000000-0000-0000-0000-000000000006'));
SET LOCAL search_path=public;
SELECT pg_temp.ok('38_audit_function_has_locked_search_path',
 (SELECT proconfig=ARRAY['search_path=pg_catalog, pg_temp'] FROM pg_proc
  WHERE oid='echo_history.audit_history_insert()'::regprocedure));
SELECT pg_temp.ok('39_no_public_execute_or_audit_insert_grant',
 NOT has_function_privilege('echo_p21c_test_writer','echo_history.audit_history_insert()','EXECUTE')
 AND NOT has_table_privilege('echo_p21c_test_writer','echo_history.insert_audit','INSERT'));
SELECT pg_temp.ok('40_guard_does_not_delete_old_provenance',
 (SELECT count(*)=1 FROM echo_core.evidence_provenance_edges));

DO $$ BEGIN
 IF (SELECT count(*) FROM checks) <> 79 THEN RAISE EXCEPTION 'Incomplete check suite'; END IF;
END $$;
SELECT label, result FROM checks ORDER BY label;
SELECT count(*) AS passed_checks FROM checks;
\echo P2.1C IMMUTABLE HISTORY SUITE FINISHED
ROLLBACK;
SELECT CASE WHEN to_regnamespace('echo_core') IS NULL
             AND to_regnamespace('echo_history') IS NULL
             AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='echo_p21c_test_writer')
            THEN 'CLEAN_ROLLBACK' ELSE 'ROLLBACK_LEFT_OBJECTS' END AS cleanup;
