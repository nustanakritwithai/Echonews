\set ON_ERROR_STOP on
-- Disposable PostgreSQL 17 test database only. Everything rolls back.
BEGIN;
\ir ../p2_1b/schema.sql
\ir ../p2_1c/001_immutable_history.sql
\ir 001_public_voice_read.sql
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
    BEGIN EXECUTE statement;
    EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS actual = RETURNED_SQLSTATE;
    END;
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'FAIL %: expected %, got %', label, expected, coalesce(actual,'SUCCESS');
    END IF;
    INSERT INTO checks VALUES (label, 'SAT');
END $$;
CREATE FUNCTION pg_temp.err_any(label text, statement text, expected text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE actual text;
BEGIN
    BEGIN EXECUTE statement;
    EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS actual = RETURNED_SQLSTATE;
    END;
    IF actual IS NULL OR NOT (actual = ANY(expected)) THEN
        RAISE EXCEPTION 'FAIL %: expected one of %, got %', label, expected, coalesce(actual,'SUCCESS');
    END IF;
    INSERT INTO checks VALUES (label, 'SAT');
END $$;
-- The probe role needs only to let the test helpers record their SAT rows in
-- this transaction-local temp table. This is not an application grant.
GRANT INSERT ON checks TO echo_public_reader;

SELECT pg_temp.ok('01_reader_is_nonlogin_nonprivileged',
 (SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
         AND NOT rolreplication AND NOT rolbypassrls
    FROM pg_roles WHERE rolname='echo_public_reader'));
SELECT pg_temp.ok('02_reader_has_public_schema_usage', has_schema_privilege('echo_public_reader','echo_public','USAGE'));
SELECT pg_temp.ok('03_public_pseudorole_has_no_schema_usage', NOT has_schema_privilege('public','echo_public','USAGE'));
SELECT pg_temp.ok('04_reader_has_view_select_only',
 has_table_privilege('echo_public_reader','echo_public.current_public_voices','SELECT')
 AND NOT has_table_privilege('echo_public_reader','echo_public.current_public_voices','INSERT')
 AND NOT has_table_privilege('echo_public_reader','echo_public.current_public_voices','UPDATE')
 AND NOT has_table_privilege('echo_public_reader','echo_public.current_public_voices','DELETE'));
SELECT pg_temp.ok('05_reader_has_no_echo_core_schema_usage', NOT has_schema_privilege('echo_public_reader','echo_core','USAGE'));
SELECT pg_temp.ok('06_reader_cannot_select_voice_table', NOT has_table_privilege('echo_public_reader','echo_core.voice_revisions','SELECT'));
SELECT pg_temp.ok('07_reader_cannot_select_actor_or_source_tables',
 NOT has_table_privilege('echo_public_reader','echo_core.actors','SELECT')
 AND NOT has_table_privilege('echo_public_reader','echo_core.sources','SELECT'));
SELECT pg_temp.ok('08_reader_cannot_read_history_audit',
 NOT has_schema_privilege('echo_public_reader','echo_history','USAGE')
 AND NOT has_table_privilege('echo_public_reader','echo_history.insert_audit','SELECT'));
SELECT pg_temp.ok('09_view_is_security_barrier',
 EXISTS(SELECT 1 FROM pg_class WHERE oid='echo_public.current_public_voices'::regclass
        AND reloptions @> ARRAY['security_barrier=true']));
SELECT pg_temp.ok('10_view_exposes_only_minimum_columns',
 (SELECT array_agg(column_name::text ORDER BY ordinal_position)=ARRAY['voice_id','revision','payload_ref','posted_at','recorded_at']::text[]
  FROM information_schema.columns WHERE table_schema='echo_public' AND table_name='current_public_voices'));
SELECT pg_temp.ok('11_private_fixtures_are_not_public',
 (SELECT count(*)=0 FROM echo_public.current_public_voices));

-- Append a PUBLIC successor. Never mutate revision 1.
INSERT INTO echo_core.voice_revisions
(voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
SELECT voice_id,2,1,author_id,source_id,'fixture:voice-a-public-r2','PUBLIC',
       '2026-09-23T09:01:00Z','2026-09-23T09:02:00Z'
FROM echo_core.voice_revisions
WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=1;
SELECT pg_temp.ok('12_public_head_appears_once',
 (SELECT count(*)=1 FROM echo_public.current_public_voices));
SELECT pg_temp.ok('13_public_projection_returns_only_latest_revision',
 (SELECT revision=2 AND payload_ref='fixture:voice-a-public-r2'
    FROM echo_public.current_public_voices
   WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d'));
SELECT pg_temp.ok('14_other_private_voice_stays_hidden',
 NOT EXISTS(SELECT 1 FROM echo_public.current_public_voices
            WHERE voice_id='11020f0b-d8a6-52f7-9d0c-b01b52709215'));

SET LOCAL ROLE echo_public_reader;
SELECT pg_temp.ok('15_reader_role_can_read_projection',
 (SELECT count(*)=1 FROM echo_public.current_public_voices));
SELECT pg_temp.err('16_reader_role_cannot_read_core_directly',
 'SELECT * FROM echo_core.voice_revisions','42501');
-- PostgreSQL may reject DML first as insufficient privilege (42501) or because
-- this security-barrier projection is intrinsically non-updatable (55000).
-- Either is a fail-closed result; test 04 independently proves no DML grant.
SELECT pg_temp.err_any('17_reader_cannot_insert_projection',
 'INSERT INTO echo_public.current_public_voices(voice_id,revision,payload_ref,recorded_at) VALUES (gen_random_uuid(),1,''x'',clock_timestamp())',ARRAY['42501','55000']);
SELECT pg_temp.err_any('18_reader_cannot_update_projection',
 'UPDATE echo_public.current_public_voices SET payload_ref=''forged''',ARRAY['42501','55000']);
SELECT pg_temp.err_any('19_reader_cannot_delete_projection',
 'DELETE FROM echo_public.current_public_voices',ARRAY['42501','55000']);
SELECT pg_temp.err('20_reader_cannot_create_in_public_schema',
 'CREATE VIEW echo_public.forged AS SELECT 1 AS x','42501');
RESET ROLE;

-- A newer RESTRICTED head must suppress the older PUBLIC revision entirely.
INSERT INTO echo_core.voice_revisions
(voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
SELECT voice_id,3,2,author_id,source_id,'fixture:voice-a-restricted-r3','RESTRICTED',
       '2026-09-23T09:03:00Z','2026-09-23T09:04:00Z'
FROM echo_core.voice_revisions
WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=2;
SELECT pg_temp.ok('21_restricted_head_hides_older_public_revision',
 (SELECT count(*)=0 FROM echo_public.current_public_voices));

-- Re-publication is a new explicit revision; then withdrawal hides history again.
INSERT INTO echo_core.voice_revisions
(voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
SELECT voice_id,4,3,author_id,source_id,'fixture:voice-a-public-r4','PUBLIC',
       '2026-09-23T09:05:00Z','2026-09-23T09:06:00Z'
FROM echo_core.voice_revisions
WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=3;
SELECT pg_temp.ok('22_explicit_republication_reappears',
 (SELECT revision=4 FROM echo_public.current_public_voices
  WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d'));
INSERT INTO echo_core.voice_revisions
(voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
SELECT voice_id,5,4,author_id,source_id,'fixture:voice-a-withdrawn-r5','WITHDRAWN',
       '2026-09-23T09:07:00Z','2026-09-23T09:08:00Z'
FROM echo_core.voice_revisions
WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=4;
SELECT pg_temp.ok('23_withdrawal_hides_all_older_public_revisions',
 (SELECT count(*)=0 FROM echo_public.current_public_voices));

-- Head selection is revision-based, never client time based.
INSERT INTO echo_core.voice_revisions
(voice_id,revision,previous_revision,author_id,source_id,payload_ref,visibility,posted_at,recorded_at)
SELECT voice_id,6,5,author_id,source_id,'fixture:voice-a-public-r6-old-time','PUBLIC',
       '2026-09-22T01:00:00Z','2026-09-22T01:01:00Z'
FROM echo_core.voice_revisions
WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d' AND revision=5;
SELECT pg_temp.ok('24_revision_not_timestamp_selects_head',
 (SELECT revision=6 AND recorded_at='2026-09-22T01:01:00Z'::timestamptz
    FROM echo_public.current_public_voices
   WHERE voice_id='4b34744b-b12e-5e4e-9404-a94d4b084f1d'));
SELECT pg_temp.ok('25_projection_never_exposes_author_source_or_visibility_columns',
 NOT EXISTS(SELECT 1 FROM information_schema.columns
            WHERE table_schema='echo_public' AND table_name='current_public_voices'
              AND column_name IN ('author_id','source_id','visibility')));
SELECT pg_temp.ok('26_reader_has_no_assessment_or_room_link_access',
 NOT has_table_privilege('echo_public_reader','echo_core.evidence_assessments','SELECT')
 AND NOT has_table_privilege('echo_public_reader','echo_core.event_voice_links','SELECT'));
SELECT pg_temp.ok('27_no_public_grant_on_projection',
 NOT has_table_privilege('public','echo_public.current_public_voices','SELECT'));
SELECT pg_temp.ok('28_public_reader_role_has_no_role_memberships',
 NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
            WHERE r.rolname='echo_public_reader'));

DO $$ BEGIN
 IF (SELECT count(*) FROM checks) <> 28 THEN RAISE EXCEPTION 'Incomplete public-read suite'; END IF;
END $$;
SELECT label,result FROM checks ORDER BY label;
SELECT count(*) AS passed_checks FROM checks;
\echo P2.1C2A PUBLIC VOICE READ SUITE FINISHED
ROLLBACK;
SELECT CASE WHEN to_regnamespace('echo_core') IS NULL
             AND to_regnamespace('echo_history') IS NULL
             AND to_regnamespace('echo_public') IS NULL
             AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('echo_public_reader'))
            THEN 'CLEAN_ROLLBACK' ELSE 'ROLLBACK_LEFT_OBJECTS' END AS cleanup;
