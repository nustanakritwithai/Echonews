-- P2.1c.2c.2a: protected durable registry, NOT JWT verification or write permission.
-- Requires echo_core. Run only with --single-transaction on an isolated DB.
-- All role/schema names intentionally fail on collision. No production grants/login.
CREATE ROLE echo_identity_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_identity_admin NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE echo_identity_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA echo_identity AUTHORIZATION echo_identity_owner;
REVOKE ALL ON SCHEMA echo_identity FROM PUBLIC;
GRANT USAGE ON SCHEMA echo_core TO echo_identity_owner;
GRANT SELECT(actor_id,actor_kind), REFERENCES(actor_id,actor_kind) ON echo_core.actors TO echo_identity_owner;
GRANT SELECT(source_id,source_kind), REFERENCES(source_id) ON echo_core.sources TO echo_identity_owner;
SET LOCAL ROLE echo_identity_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- No email linking/automatic provisioning. One principal per actor/source in this
-- research profile. Future account linking needs a separately reviewed migration.
CREATE TABLE echo_identity.principals (
    principal_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text COLLATE "C" NOT NULL CHECK (issuer LIKE 'https://%' AND length(issuer) BETWEEN 9 AND 2048 AND issuer=btrim(issuer)),
    subject text COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 256 AND length(btrim(subject))>0),
    actor_id uuid NOT NULL UNIQUE CHECK (actor_id<>'00000000-0000-0000-0000-000000000000'),
    actor_kind text NOT NULL CHECK (actor_kind IN ('HUMAN','AI','SYSTEM')),
    source_id uuid NOT NULL UNIQUE REFERENCES echo_core.sources(source_id) CHECK (source_id<>'00000000-0000-0000-0000-000000000000'),
    provisioned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(issuer,subject),
    FOREIGN KEY(actor_id,actor_kind) REFERENCES echo_core.actors(actor_id,actor_kind)
);
CREATE FUNCTION echo_identity.valid_caps(value text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT value IS NOT NULL AND COALESCE(array_ndims(value),1)=1
 AND array_position(value,NULL) IS NULL
 AND value <@ ARRAY['voice:draft:create','assessment:review']::text[]
 AND cardinality(value)=(SELECT count(DISTINCT x) FROM unnest(value) AS u(x));
$$;
CREATE TABLE echo_identity.access_revisions (
    principal_id uuid NOT NULL REFERENCES echo_identity.principals(principal_id),
    revision integer NOT NULL CHECK(revision>0),
    previous_revision integer,
    enabled boolean NOT NULL DEFAULT false,
    capabilities text[] NOT NULL DEFAULT '{}' CHECK(echo_identity.valid_caps(capabilities)),
    tokens_valid_from bigint NOT NULL DEFAULT 0 CHECK(tokens_valid_from>=0 AND tokens_valid_from<9007199254740992),
    reason_code text NOT NULL CHECK(reason_code IN ('PROVISIONED','ACCESS_CHANGE','DISABLE','REENABLE','SESSION_CUTOFF')),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    session_principal name NOT NULL DEFAULT session_user,
    active_db_role name NOT NULL DEFAULT current_setting('role'),
    PRIMARY KEY(principal_id,revision),
    FOREIGN KEY(principal_id,previous_revision) REFERENCES echo_identity.access_revisions(principal_id,revision),
    CHECK((revision=1 AND previous_revision IS NULL) OR (revision>1 AND previous_revision IS NOT NULL AND previous_revision=revision-1)),
    CHECK(enabled OR cardinality(capabilities)=0)
);
CREATE TABLE echo_identity.token_revocations (
    issuer text COLLATE "C" NOT NULL,
    jti_digest bytea NOT NULL CHECK(octet_length(jti_digest)=32),
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    session_principal name NOT NULL DEFAULT session_user,
    active_db_role name NOT NULL DEFAULT current_setting('role'),
    PRIMARY KEY(issuer,jti_digest)
);
CREATE FUNCTION echo_identity.reject_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'ECHO_IDENTITY_APPEND_ONLY' USING ERRCODE='55000';
END;
$$;
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['principals','access_revisions','token_revocations'] LOOP
  EXECUTE format('CREATE TRIGGER reject_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON echo_identity.%I FOR EACH STATEMENT EXECUTE FUNCTION echo_identity.reject_mutation()',n);
  EXECUTE format('ALTER TABLE echo_identity.%I ENABLE ALWAYS TRIGGER reject_mutation',n);
 END LOOP;
END $$;

CREATE FUNCTION echo_identity.provision(p_issuer text,p_subject text,p_actor uuid,p_source uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result uuid; kind text;
BEGIN
 SELECT a.actor_kind INTO kind FROM echo_core.actors a WHERE a.actor_id=p_actor;
 IF kind IS NULL OR NOT EXISTS(SELECT 1 FROM echo_core.sources s WHERE s.source_id=p_source AND s.source_kind='ACCOUNT') THEN
  RAISE EXCEPTION 'ECHO_PRINCIPAL_REFERENCE_INVALID' USING ERRCODE='23503';
 END IF;
 INSERT INTO echo_identity.principals(issuer,subject,actor_id,actor_kind,source_id)
 VALUES(p_issuer,p_subject,p_actor,kind,p_source) RETURNING principal_id INTO result;
 INSERT INTO echo_identity.access_revisions(principal_id,revision,reason_code)
 VALUES(result,1,'PROVISIONED');
 RETURN result;
END;
$$;
-- Owner/admin control plane only, never a public endpoint. Expected revision is
-- optimistic concurrency; the principal row lock serializes competing admins.
CREATE FUNCTION echo_identity.revise_access(p_principal uuid,p_expected integer,p_enabled boolean,p_caps text[],p_cutoff bigint,p_reason text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE old echo_identity.access_revisions%ROWTYPE; cutoff bigint;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'ECHO_READ_COMMITTED_REQUIRED' USING ERRCODE='25001';
 END IF;
 IF p_expected IS NULL OR p_expected<1 OR p_enabled IS NULL OR p_cutoff IS NULL
    OR p_cutoff<0 OR p_cutoff>=9007199254740992 OR NOT echo_identity.valid_caps(p_caps)
    OR p_reason IS NULL OR p_reason NOT IN ('ACCESS_CHANGE','DISABLE','REENABLE','SESSION_CUTOFF') THEN
  RAISE EXCEPTION 'ECHO_ACCESS_INPUT_INVALID' USING ERRCODE='22023';
 END IF;
 PERFORM 1 FROM echo_identity.principals p WHERE p.principal_id=p_principal FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ECHO_PRINCIPAL_NOT_FOUND' USING ERRCODE='22023'; END IF;
 SELECT r.* INTO old FROM echo_identity.access_revisions r WHERE r.principal_id=p_principal ORDER BY r.revision DESC LIMIT 1;
 IF NOT FOUND OR old.revision<>p_expected THEN
  RAISE EXCEPTION 'ECHO_ACCESS_REVISION_CONFLICT' USING ERRCODE='40001';
 END IF;
 IF p_cutoff<old.tokens_valid_from THEN
  RAISE EXCEPTION 'ECHO_TOKEN_CUTOFF_CANNOT_DECREASE' USING ERRCODE='22023';
 END IF;
 IF 'assessment:review'=ANY(p_caps) AND NOT EXISTS(
      SELECT 1 FROM echo_identity.principals p WHERE p.principal_id=p_principal AND p.actor_kind='HUMAN') THEN
  RAISE EXCEPTION 'ECHO_HUMAN_REVIEW_REQUIRED' USING ERRCODE='22023';
 END IF;
 cutoff:=p_cutoff;
 IF NOT p_enabled THEN
  -- Integer JWT issued-at granularity: invalidate tokens issued in this second
  -- too. A newly issued token may need to wait until the next whole second.
  cutoff:=greatest(cutoff,floor(extract(epoch FROM clock_timestamp()))::bigint+1);
 END IF;
 INSERT INTO echo_identity.access_revisions(principal_id,revision,previous_revision,enabled,capabilities,tokens_valid_from,reason_code)
 VALUES(p_principal,old.revision+1,old.revision,p_enabled,p_caps,cutoff,p_reason);
 RETURN old.revision+1;
END;
$$;
CREATE FUNCTION echo_identity.revoke_token(p_issuer text,p_jti text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE affected integer;
BEGIN
 IF p_jti IS NULL OR length(p_jti) NOT BETWEEN 1 AND 256 OR length(btrim(p_jti))=0
    OR NOT EXISTS(SELECT 1 FROM echo_identity.principals p WHERE p.issuer=p_issuer COLLATE "C") THEN
  RAISE EXCEPTION 'ECHO_REVOCATION_INPUT_INVALID' USING ERRCODE='22023';
 END IF;
 INSERT INTO echo_identity.token_revocations(issuer,jti_digest)
 VALUES(p_issuer,sha256(convert_to(p_jti,'UTF8'))) ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS affected=ROW_COUNT;
 RETURN affected=1;
END;
$$;

-- This function DOES NOT validate a JWT. Its DB role is a trusted backend
-- capability, never a browser/anonymous RPC grant. Verified token claims only.
-- No result deliberately conflates unmapped/disabled/revoked/cutoff identities.
CREATE FUNCTION echo_identity.resolve_principal(p_issuer text,p_subject text,p_jti text,p_issued_at bigint)
RETURNS TABLE(principal_id uuid,actor_id uuid,actor_kind text,source_id uuid,binding_revision integer,capabilities text[],tokens_valid_from bigint,ready_for_execution boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'ECHO_READ_COMMITTED_REQUIRED' USING ERRCODE='25001';
 END IF;
 IF p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 9 AND 2048
    OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(btrim(p_subject))=0
    OR p_jti IS NULL OR length(p_jti) NOT BETWEEN 1 AND 256 OR length(btrim(p_jti))=0
    OR p_issued_at IS NULL OR p_issued_at<0 OR p_issued_at>=9007199254740992 THEN
  RAISE EXCEPTION 'ECHO_RESOLUTION_INPUT_INVALID' USING ERRCODE='22023';
 END IF;
 RETURN QUERY
 SELECT p.principal_id,p.actor_id,p.actor_kind,p.source_id,r.revision,r.capabilities,r.tokens_valid_from,false
 FROM echo_identity.principals p
 JOIN echo_core.sources s ON s.source_id=p.source_id AND s.source_kind='ACCOUNT'
 CROSS JOIN LATERAL (SELECT a.* FROM echo_identity.access_revisions a
   WHERE a.principal_id=p.principal_id ORDER BY a.revision DESC LIMIT 1) r
 WHERE p.issuer=p_issuer COLLATE "C" AND p.subject=p_subject COLLATE "C"
   AND r.enabled AND p_issued_at>=r.tokens_valid_from
   AND NOT EXISTS(SELECT 1 FROM echo_identity.token_revocations t
     WHERE t.issuer=p_issuer COLLATE "C" AND t.jti_digest=sha256(convert_to(p_jti,'UTF8')));
END;
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA echo_identity FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA echo_identity FROM PUBLIC;
GRANT USAGE ON SCHEMA echo_identity TO echo_identity_admin,echo_identity_resolver;
GRANT EXECUTE ON FUNCTION echo_identity.provision(text,text,uuid,uuid),
 echo_identity.revise_access(uuid,integer,boolean,text[],bigint,text),
 echo_identity.revoke_token(text,text) TO echo_identity_admin;
GRANT EXECUTE ON FUNCTION echo_identity.resolve_principal(text,text,text,bigint) TO echo_identity_resolver;
RESET ROLE;
-- No role memberships, LOGIN credentials, HTTP adapter, automatic author/source
-- provisioning, capability->JS-role conversion or actual Voice writes are added.
