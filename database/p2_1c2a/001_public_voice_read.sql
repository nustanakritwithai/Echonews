-- Echo News P2.1c.2a — Public Voice Read Boundary v0.1
-- Smallest public-read task only. This does NOT authenticate writers/reviewers,
-- publish room membership, expose claims/evidence, or resolve payload contents.
-- Apply after P2.1b + P2.1c.1 with owner/migration credentials, never API credentials.

CREATE ROLE echo_public_reader
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

CREATE SCHEMA echo_public;
REVOKE ALL ON SCHEMA echo_public FROM PUBLIC;
GRANT USAGE ON SCHEMA echo_public TO echo_public_reader;

-- A historical PUBLIC revision must disappear if the newest revision becomes
-- PRIVATE, RESTRICTED, or WITHDRAWN. Revision number, not client timestamps,
-- defines the head because revisions are append-only and predecessor-checked.
-- payload_ref is intentionally visible only to the backend DB role; it is an
-- opaque content locator, not permission to serve the payload without the same
-- access decision in the content resolver.
CREATE VIEW echo_public.current_public_voices
WITH (security_barrier = true)
AS
SELECT voice_id, revision, payload_ref, posted_at, recorded_at
FROM (
    SELECT DISTINCT ON (voice_id)
           voice_id, revision, payload_ref, posted_at, recorded_at, visibility
    FROM echo_core.voice_revisions
    ORDER BY voice_id, revision DESC
) AS head
WHERE visibility = 'PUBLIC';

REVOKE ALL ON TABLE echo_public.current_public_voices FROM PUBLIC;
GRANT SELECT ON TABLE echo_public.current_public_voices TO echo_public_reader;

COMMENT ON VIEW echo_public.current_public_voices IS
'Current-head PUBLIC voice metadata for a backend public-read role. No historical revisions, author/source rows, room links, claims, evidence, or payload bytes. A newer non-PUBLIC revision hides all older PUBLIC revisions.';

-- Intentionally NO grants on echo_core, echo_history, actors, sources, room links,
-- assessments, sequences, or functions. A future connection role may inherit
-- echo_public_reader, but browser clients must never receive database credentials.
