-- Echo News Center — P2.1b Core Entity Schema v0.1
-- DESIGN CANDIDATE. PostgreSQL runtime verification is still REQUIRED.
-- Run only in an isolated development/test database. No production deployment.
-- This file deliberately does NOT create an API role, RLS policy, publication
-- service, general event log, family matcher, or mutation/audit triggers.
-- Execute atomically using psql -X -v ON_ERROR_STOP=1 --single-transaction -f schema.sql.
-- CREATE SCHEMA deliberately fails if echo_core already exists. No DROP/CASCADE.
CREATE SCHEMA echo_core;
REVOKE ALL ON SCHEMA echo_core FROM PUBLIC;

CREATE TABLE echo_core.actors (
    actor_id uuid PRIMARY KEY,
    actor_kind text NOT NULL CHECK (actor_kind IN ('HUMAN','AI','SYSTEM','TEST_FIXTURE','UNKNOWN')),
    display_label text NOT NULL CHECK (length(btrim(display_label)) > 0),
    recorded_at timestamptz NOT NULL,
    UNIQUE (actor_id, actor_kind)
);

-- Source is not the same thing as uploader, verified identity, or independence.
CREATE TABLE echo_core.sources (
    source_id uuid PRIMARY KEY,
    source_kind text NOT NULL CHECK (source_kind IN ('ACCOUNT','ORGANIZATION','DEVICE','DOCUMENT','WEBSITE','UNKNOWN')),
    source_locator text,
    origin_status text NOT NULL DEFAULT 'UNKNOWN' CHECK (origin_status IN ('UNKNOWN','DECLARED','ASSESSED')),
    recorded_at timestamptz NOT NULL
);

CREATE TABLE echo_core.event_revisions (
    event_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    previous_revision integer,
    title text NOT NULL CHECK (length(btrim(title)) > 0),
    activity_state text NOT NULL DEFAULT 'CANDIDATE'
        CHECK (activity_state IN ('CANDIDATE','ACTIVE','STABILIZING','INACTIVE','ARCHIVED')),
    created_by uuid NOT NULL REFERENCES echo_core.actors (actor_id),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (event_id, revision),
    FOREIGN KEY (event_id, previous_revision) REFERENCES echo_core.event_revisions (event_id, revision),
    CHECK ((revision = 1 AND previous_revision IS NULL) OR
           (revision > 1 AND previous_revision IS NOT NULL AND previous_revision = revision - 1))
);

-- Exact content revision is referred to by an opaque payload key, not embedded
-- in a permanent audit log. Visibility enforcement/redaction are BLOCKING TODOs.
CREATE TABLE echo_core.voice_revisions (
    voice_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    previous_revision integer,
    author_id uuid NOT NULL REFERENCES echo_core.actors (actor_id),
    source_id uuid NOT NULL REFERENCES echo_core.sources (source_id),
    payload_ref text NOT NULL CHECK (length(btrim(payload_ref)) > 0),
    visibility text NOT NULL DEFAULT 'PRIVATE'
        CHECK (visibility IN ('PRIVATE','RESTRICTED','PUBLIC','WITHDRAWN')),
    posted_at timestamptz,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (voice_id, revision),
    UNIQUE (voice_id, revision, author_id),
    FOREIGN KEY (voice_id, previous_revision, author_id)
        REFERENCES echo_core.voice_revisions (voice_id, revision, author_id),
    CHECK ((revision = 1 AND previous_revision IS NULL) OR
           (revision > 1 AND previous_revision IS NOT NULL AND previous_revision = revision - 1))
);

-- A voice may be linked to several rooms. Link an exact revision and optional
-- Unicode-code-point span [start,end), NOT a JS UTF-16 offset. Media spans are TODO.
CREATE TABLE echo_core.event_voice_links (
    link_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    previous_revision integer,
    event_id uuid NOT NULL,
    event_revision integer NOT NULL,
    voice_id uuid NOT NULL,
    voice_revision integer NOT NULL,
    span_start integer,
    span_end integer,
    link_state text NOT NULL DEFAULT 'PROPOSED' CHECK (link_state IN ('PROPOSED','ACTIVE','RETRACTED')),
    proposed_by uuid NOT NULL REFERENCES echo_core.actors (actor_id),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (link_id, revision),
    UNIQUE (link_id, revision, event_id),
    UNIQUE (link_id, revision, event_id, voice_id),
    FOREIGN KEY (event_id, event_revision) REFERENCES echo_core.event_revisions (event_id, revision),
    FOREIGN KEY (voice_id, voice_revision) REFERENCES echo_core.voice_revisions (voice_id, revision),
    FOREIGN KEY (link_id, previous_revision, event_id, voice_id)
        REFERENCES echo_core.event_voice_links (link_id, revision, event_id, voice_id),
    CHECK ((revision = 1 AND previous_revision IS NULL) OR
           (revision > 1 AND previous_revision IS NOT NULL AND previous_revision = revision - 1)),
    CHECK ((span_start IS NULL AND span_end IS NULL) OR
           (span_start IS NOT NULL AND span_end IS NOT NULL AND span_start >= 0 AND span_end > span_start))
);

CREATE TABLE echo_core.claim_revisions (
    claim_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    previous_revision integer,
    event_id uuid NOT NULL,
    event_revision integer NOT NULL,
    scope_key text NOT NULL CHECK (length(btrim(scope_key)) > 0),
    proposition text NOT NULL CHECK (length(btrim(proposition)) > 0),
    claim_kind text NOT NULL CHECK (claim_kind IN ('FACTUAL','CAUSAL','UNKNOWN')),
    risk text NOT NULL DEFAULT 'HIGH' CHECK (risk IN ('LOW','HIGH')),
    primary_voice_link_id uuid NOT NULL,
    primary_voice_link_revision integer NOT NULL,
    derived_by uuid NOT NULL REFERENCES echo_core.actors (actor_id),
    derivation_version text NOT NULL CHECK (length(btrim(derivation_version)) > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (claim_id, revision),
    UNIQUE (claim_id, revision, event_id),
    UNIQUE (claim_id, revision, event_id, scope_key),
    FOREIGN KEY (event_id, event_revision) REFERENCES echo_core.event_revisions (event_id, revision),
    FOREIGN KEY (primary_voice_link_id, primary_voice_link_revision, event_id)
        REFERENCES echo_core.event_voice_links (link_id, revision, event_id),
    FOREIGN KEY (claim_id, previous_revision, event_id, scope_key)
        REFERENCES echo_core.claim_revisions (claim_id, revision, event_id, scope_key),
    CHECK ((revision = 1 AND previous_revision IS NULL) OR
           (revision > 1 AND previous_revision IS NOT NULL AND previous_revision = revision - 1))
);

-- Optional additional voices behind one claim. The same-event check is a
-- composite foreign key; two independently valid IDs alone are insufficient.
CREATE TABLE echo_core.claim_voice_links (
    claim_id uuid NOT NULL,
    claim_revision integer NOT NULL,
    event_id uuid NOT NULL,
    voice_link_id uuid NOT NULL,
    voice_link_revision integer NOT NULL,
    linked_by uuid NOT NULL REFERENCES echo_core.actors (actor_id),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (claim_id, claim_revision, voice_link_id, voice_link_revision),
    FOREIGN KEY (claim_id, claim_revision, event_id)
        REFERENCES echo_core.claim_revisions (claim_id, revision, event_id),
    FOREIGN KEY (voice_link_id, voice_link_revision, event_id)
        REFERENCES echo_core.event_voice_links (link_id, revision, event_id)
);

CREATE TABLE echo_core.evidence_revisions (
    evidence_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    previous_revision integer,
    evidence_type text NOT NULL CHECK (evidence_type IN ('MEDIA','OBSERVATION','DOCUMENT','SENSOR','EXTERNAL','DERIVED')),
    source_id uuid NOT NULL REFERENCES echo_core.sources (source_id),
    introduced_by_voice_id uuid NOT NULL,
    introduced_by_voice_revision integer NOT NULL,
    asset_ref text NOT NULL CHECK (length(btrim(asset_ref)) > 0),
    observed_at timestamptz,
    claimed_location text,
    location_precision text NOT NULL DEFAULT 'UNKNOWN',
    origin_status text NOT NULL DEFAULT 'UNKNOWN' CHECK (origin_status IN ('UNKNOWN','DECLARED','ASSESSED')),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (evidence_id, revision),
    FOREIGN KEY (introduced_by_voice_id, introduced_by_voice_revision)
        REFERENCES echo_core.voice_revisions (voice_id, revision),
    FOREIGN KEY (evidence_id, previous_revision) REFERENCES echo_core.evidence_revisions (evidence_id, revision),
    CHECK ((revision = 1 AND previous_revision IS NULL) OR
           (revision > 1 AND previous_revision IS NOT NULL AND previous_revision = revision - 1))
);

CREATE TABLE echo_core.evidence_voice_links (
    evidence_id uuid NOT NULL,
    evidence_revision integer NOT NULL,
    voice_id uuid NOT NULL,
    voice_revision integer NOT NULL,
    use_kind text NOT NULL CHECK (use_kind IN ('ATTACHED','SHARED','OBSERVATION')),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (evidence_id, evidence_revision, voice_id, voice_revision),
    FOREIGN KEY (evidence_id, evidence_revision) REFERENCES echo_core.evidence_revisions (evidence_id, revision),
    FOREIGN KEY (voice_id, voice_revision) REFERENCES echo_core.voice_revisions (voice_id, revision)
);

-- An assessment points to ONE exact claim/evidence pair. Retargeting that pair
-- or its scope requires a new assessment_id. Review changes use a new revision.
CREATE TABLE echo_core.evidence_assessments (
    assessment_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    previous_revision integer,
    event_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    claim_revision integer NOT NULL,
    scope_key text NOT NULL,
    evidence_id uuid NOT NULL,
    evidence_revision integer NOT NULL,
    relation text NOT NULL CHECK (relation IN ('SUPPORTS','CONTRADICTS','CONTEXTUALIZES','UNKNOWN')),
    review_state text NOT NULL DEFAULT 'PENDING' CHECK (review_state IN ('PENDING','ACCEPTED','REJECTED')),
    withdrawn boolean NOT NULL DEFAULT false,
    assessor_id uuid NOT NULL,
    assessor_kind text NOT NULL,
    method_version text NOT NULL CHECK (length(btrim(method_version)) > 0),
    rationale text NOT NULL CHECK (length(btrim(rationale)) > 0),
    valid_time_status text NOT NULL DEFAULT 'UNKNOWN' CHECK (valid_time_status IN ('UNKNOWN','BOUNDED')),
    valid_from timestamptz,
    valid_until timestamptz,
    assessed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (assessment_id, revision),
    UNIQUE (assessment_id, revision, claim_id, claim_revision, relation),
    UNIQUE (assessment_id, revision, event_id, claim_id, claim_revision, scope_key, evidence_id, evidence_revision),
    FOREIGN KEY (claim_id, claim_revision, event_id, scope_key)
        REFERENCES echo_core.claim_revisions (claim_id, revision, event_id, scope_key),
    FOREIGN KEY (evidence_id, evidence_revision) REFERENCES echo_core.evidence_revisions (evidence_id, revision),
    FOREIGN KEY (assessor_id, assessor_kind) REFERENCES echo_core.actors (actor_id, actor_kind),
    FOREIGN KEY (assessment_id, previous_revision, event_id, claim_id, claim_revision, scope_key, evidence_id, evidence_revision)
        REFERENCES echo_core.evidence_assessments (assessment_id, revision, event_id, claim_id, claim_revision, scope_key, evidence_id, evidence_revision),
    CHECK ((revision = 1 AND previous_revision IS NULL) OR
           (revision > 1 AND previous_revision IS NOT NULL AND previous_revision = revision - 1)),
    CHECK (review_state <> 'ACCEPTED' OR assessor_kind IN ('HUMAN','TEST_FIXTURE')),
    CHECK ((valid_time_status = 'UNKNOWN' AND valid_from IS NULL AND valid_until IS NULL) OR
           (valid_time_status = 'BOUNDED' AND valid_from IS NOT NULL AND valid_until IS NOT NULL
            AND isfinite(valid_from) AND isfinite(valid_until) AND valid_from < valid_until)),
    CHECK (assessed_at <= recorded_at)
);

-- A provenance edge is itself a VERSIONED ASSERTION, not guaranteed fact.
-- Minimum typed graph: evidence-to-evidence lineage; actor/source/voice edges
-- already have typed FKs. No untyped target_type + target_id escape hatch.
CREATE TABLE echo_core.evidence_provenance_edges (
    edge_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    previous_revision integer,
    child_evidence_id uuid NOT NULL,
    child_evidence_revision integer NOT NULL,
    parent_evidence_id uuid NOT NULL,
    parent_evidence_revision integer NOT NULL,
    edge_kind text NOT NULL CHECK (edge_kind IN ('COPIED_FROM','DERIVED_FROM','REFERENCES')),
    basis text NOT NULL CHECK (basis IN ('DECLARED','INFERRED','ASSESSED')),
    review_state text NOT NULL DEFAULT 'PENDING' CHECK (review_state IN ('PENDING','ACCEPTED','REJECTED')),
    withdrawn boolean NOT NULL DEFAULT false,
    asserted_by uuid NOT NULL REFERENCES echo_core.actors (actor_id),
    method_version text NOT NULL CHECK (length(btrim(method_version)) > 0),
    rationale text NOT NULL CHECK (length(btrim(rationale)) > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (edge_id, revision),
    UNIQUE (edge_id, revision, child_evidence_id, child_evidence_revision, parent_evidence_id, parent_evidence_revision, edge_kind),
    FOREIGN KEY (child_evidence_id, child_evidence_revision) REFERENCES echo_core.evidence_revisions (evidence_id, revision),
    FOREIGN KEY (parent_evidence_id, parent_evidence_revision) REFERENCES echo_core.evidence_revisions (evidence_id, revision),
    FOREIGN KEY (edge_id, previous_revision, child_evidence_id, child_evidence_revision, parent_evidence_id, parent_evidence_revision, edge_kind)
        REFERENCES echo_core.evidence_provenance_edges (edge_id, revision, child_evidence_id, child_evidence_revision, parent_evidence_id, parent_evidence_revision, edge_kind),
    CHECK ((revision = 1 AND previous_revision IS NULL) OR
           (revision > 1 AND previous_revision IS NOT NULL AND previous_revision = revision - 1)),
    CHECK (child_evidence_id <> parent_evidence_id OR child_evidence_revision <> parent_evidence_revision)
);

CREATE TABLE echo_core.policy_versions (
    policy_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    config jsonb NOT NULL CHECK (jsonb_typeof(config) = 'object'),
    reducer_version text NOT NULL CHECK (length(btrim(reducer_version)) > 0),
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (policy_id, revision)
);

-- Reconstruction output only, NOT permission to publish. input_manifest_ref
-- must resolve to the exact complete event-log/trace catalog in the later adapter.
CREATE TABLE echo_core.state_snapshots (
    snapshot_id uuid PRIMARY KEY,
    event_id uuid NOT NULL,
    event_revision integer NOT NULL,
    previous_snapshot_id uuid,
    policy_id uuid NOT NULL,
    policy_revision integer NOT NULL,
    valid_at timestamptz NOT NULL,
    known_at timestamptz NOT NULL,
    computed_at timestamptz NOT NULL,
    log_revision bigint NOT NULL CHECK (log_revision >= 0),
    trace_catalog_revision bigint NOT NULL CHECK (trace_catalog_revision >= 0),
    input_manifest_ref text NOT NULL CHECK (length(btrim(input_manifest_ref)) > 0),
    input_sha256 text NOT NULL CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
    renderer_version text NOT NULL CHECK (length(btrim(renderer_version)) > 0),
    publication_decision text NOT NULL DEFAULT 'REVIEW_REQUIRED'
        CHECK (publication_decision IN ('LABELED_ASSESSMENT','CAUTION','REVIEW_REQUIRED')),
    UNIQUE (snapshot_id, event_id),
    FOREIGN KEY (event_id, event_revision) REFERENCES echo_core.event_revisions (event_id, revision),
    FOREIGN KEY (policy_id, policy_revision) REFERENCES echo_core.policy_versions (policy_id, revision),
    FOREIGN KEY (previous_snapshot_id, event_id) REFERENCES echo_core.state_snapshots (snapshot_id, event_id),
    CHECK (previous_snapshot_id IS NULL OR previous_snapshot_id <> snapshot_id),
    CHECK (known_at <= computed_at AND valid_at <= computed_at)
);

CREATE TABLE echo_core.snapshot_items (
    snapshot_id uuid NOT NULL,
    event_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    claim_revision integer NOT NULL,
    evidence_state text NOT NULL CHECK (evidence_state IN ('UNKNOWN','SUPPORTED','COUNTERED','DISPUTED')),
    freshness text NOT NULL CHECK (freshness IN ('UNKNOWN','FRESH','STALE','MIXED')),
    reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(reason_codes) = 'array'),
    independence_status text NOT NULL DEFAULT 'NOT_ESTIMATED' CHECK (independence_status = 'NOT_ESTIMATED'),
    PRIMARY KEY (snapshot_id, claim_id, claim_revision),
    UNIQUE (snapshot_id, claim_id),
    FOREIGN KEY (snapshot_id, event_id) REFERENCES echo_core.state_snapshots (snapshot_id, event_id),
    FOREIGN KEY (claim_id, claim_revision, event_id) REFERENCES echo_core.claim_revisions (claim_id, revision, event_id)
);

-- Store both used and excluded assessment revisions. Complete evidence selection,
-- accepted-review/valid-time/admission checks and minimum trace cardinality MUST
-- be enforced by the future transactional snapshot writer, not assumed from FKs.
CREATE TABLE echo_core.snapshot_assessment_inputs (
    snapshot_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    claim_revision integer NOT NULL,
    assessment_id uuid NOT NULL,
    assessment_revision integer NOT NULL,
    relation text NOT NULL,
    use_role text NOT NULL CHECK (use_role IN ('SUPPORT','COUNTER','EXCLUDED')),
    exclusion_reason text,
    PRIMARY KEY (snapshot_id, claim_id, assessment_id),
    FOREIGN KEY (snapshot_id, claim_id, claim_revision)
        REFERENCES echo_core.snapshot_items (snapshot_id, claim_id, claim_revision),
    FOREIGN KEY (assessment_id, assessment_revision, claim_id, claim_revision, relation)
        REFERENCES echo_core.evidence_assessments (assessment_id, revision, claim_id, claim_revision, relation),
    CHECK ((use_role = 'SUPPORT' AND relation = 'SUPPORTS' AND exclusion_reason IS NULL) OR
           (use_role = 'COUNTER' AND relation = 'CONTRADICTS' AND exclusion_reason IS NULL) OR
           (use_role = 'EXCLUDED' AND exclusion_reason IS NOT NULL AND length(btrim(exclusion_reason)) > 0))
);

CREATE INDEX event_voice_room_idx ON echo_core.event_voice_links (event_id, link_state, recorded_at DESC);
CREATE INDEX event_voice_original_idx ON echo_core.event_voice_links (voice_id, voice_revision);
CREATE INDEX claim_event_idx ON echo_core.claim_revisions (event_id, recorded_at DESC);
CREATE INDEX evidence_source_idx ON echo_core.evidence_revisions (source_id);
CREATE INDEX assessment_claim_idx ON echo_core.evidence_assessments (claim_id, claim_revision, recorded_at);
CREATE INDEX provenance_child_idx ON echo_core.evidence_provenance_edges (child_evidence_id, child_evidence_revision);
CREATE INDEX provenance_parent_idx ON echo_core.evidence_provenance_edges (parent_evidence_id, parent_evidence_revision);
CREATE INDEX snapshot_event_idx ON echo_core.state_snapshots (event_id, computed_at DESC);
REVOKE ALL ON ALL TABLES IN SCHEMA echo_core FROM PUBLIC;
