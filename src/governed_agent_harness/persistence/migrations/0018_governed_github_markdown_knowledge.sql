-- Phase 5.2: one actor-scoped, pinned GitHub Markdown knowledge source.
--
-- This is intentionally not a general connector framework.  Callers can import
-- exactly one Markdown file at a full immutable commit SHA, retain immutable
-- revisions, retrieve cited untrusted context, and logically revoke a source.
-- Credentials, HTTP, background sync, memory promotion, and MCP transport are
-- outside this migration.

LOCK TABLE public.gah_runtime_principals IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.gah_run_heads IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.gah_evidence_events IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION public.gah_github_markdown_path_valid(p_path text) RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $function$
DECLARE
    segment text;
BEGIN
    IF octet_length(p_path) NOT BETWEEN 3 AND 1024
       OR p_path !~ '\.(md|markdown)$'
    THEN
        RETURN false;
    END IF;
    FOR segment IN SELECT pg_catalog.regexp_split_to_table(p_path, '/') LOOP
        IF segment !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END
$function$;

CREATE FUNCTION public.gah_github_markdown_source_identity_valid(p_source_identity text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $function$
DECLARE
    parts text[];
    repository text;
    source_path text;
BEGIN
    IF p_source_identity !~ '^github://' THEN
        RETURN false;
    END IF;
    parts := pg_catalog.string_to_array(substr(p_source_identity, length('github://') + 1), '/');
    IF pg_catalog.cardinality(parts) < 3
       OR parts[1] !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,98}$'
       OR parts[2] !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,98}$'
    THEN
        RETURN false;
    END IF;
    repository := parts[1] || '/' || parts[2];
    source_path := pg_catalog.array_to_string(parts[3:pg_catalog.cardinality(parts)], '/');
    RETURN p_source_identity = 'github://' || repository || '/' || source_path
       AND public.gah_github_markdown_path_valid(source_path);
END
$function$;

CREATE TABLE public.gah_github_markdown_sources (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    source_identity text NOT NULL,
    repository text NOT NULL,
    source_path text NOT NULL,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_operation_id text,
    revocation_operation_digest text,
    revocation_evidence_json jsonb,
    PRIMARY KEY (tenant_id, actor_id, source_identity),
    CHECK (source_identity = 'github://' || repository || '/' || source_path),
    CHECK (repository ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,98}/[A-Za-z0-9][A-Za-z0-9_.-]{0,98}$'),
    CHECK (public.gah_github_markdown_path_valid(source_path)),
    CHECK ((revoked_at IS NULL) = (revocation_operation_id IS NULL)),
    CHECK ((revoked_at IS NULL) = (revocation_operation_digest IS NULL)),
    CHECK ((revoked_at IS NULL) = (revocation_evidence_json IS NULL)),
    CHECK (revocation_operation_digest IS NULL OR revocation_operation_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (revocation_evidence_json IS NULL OR revocation_evidence_json ->> 'record_type' = 'evidence_envelope')
);

CREATE TABLE public.gah_github_markdown_revisions (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    source_identity text NOT NULL,
    commit_sha text NOT NULL,
    content_digest text NOT NULL,
    import_binding_digest text NOT NULL,
    revision_uri text NOT NULL,
    media_type text NOT NULL,
    content text NOT NULL,
    classification text NOT NULL,
    retention_expires_at timestamptz NOT NULL,
    evidence_json jsonb NOT NULL,
    evidence_event_id text NOT NULL,
    evidence_payload_digest text NOT NULL,
    imported_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, actor_id, source_identity, commit_sha),
    FOREIGN KEY (tenant_id, actor_id, source_identity)
        REFERENCES public.gah_github_markdown_sources (tenant_id, actor_id, source_identity),
    CHECK (commit_sha ~ '^[0-9a-f]{40}$'),
    CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (import_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (media_type = 'text/markdown'),
    CHECK (octet_length(content) BETWEEN 1 AND 65536),
    CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
    CHECK (evidence_json ->> 'record_type' = 'evidence_envelope'),
    CHECK (evidence_json #>> '{draft,event_id}' = evidence_event_id),
    CHECK (evidence_json ->> 'payload_digest' = evidence_payload_digest),
    CHECK (revision_uri ~ '^https://github\.com/')
);

CREATE TABLE public.gah_github_markdown_operations (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    operation_id text NOT NULL,
    operation_kind text NOT NULL,
    operation_digest text NOT NULL,
    binding_digest text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, actor_id, operation_id),
    CHECK (operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK (operation_kind IN ('import', 'revoke')),
    CHECK (operation_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (binding_digest ~ '^sha256:[0-9a-f]{64}$')
);

ALTER TABLE public.gah_github_markdown_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gah_github_markdown_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE public.gah_github_markdown_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gah_github_markdown_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.gah_github_markdown_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gah_github_markdown_operations FORCE ROW LEVEL SECURITY;

CREATE POLICY gah_github_markdown_sources_scope ON public.gah_github_markdown_sources
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

CREATE POLICY gah_github_markdown_revisions_scope ON public.gah_github_markdown_revisions
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

CREATE POLICY gah_github_markdown_operations_scope ON public.gah_github_markdown_operations
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

ALTER TABLE public.gah_github_markdown_sources OWNER TO gah_schema_owner;
ALTER TABLE public.gah_github_markdown_revisions OWNER TO gah_schema_owner;
ALTER TABLE public.gah_github_markdown_operations OWNER TO gah_schema_owner;
REVOKE ALL ON public.gah_github_markdown_sources FROM PUBLIC, gah_runtime, gah_authority_writer;
REVOKE ALL ON public.gah_github_markdown_revisions FROM PUBLIC, gah_runtime, gah_authority_writer;
REVOKE ALL ON public.gah_github_markdown_operations FROM PUBLIC, gah_runtime, gah_authority_writer;

CREATE FUNCTION public.gah_github_markdown_assert_policy(
    p_actor jsonb, p_operation_id text, p_operation_digest text, p_policy jsonb
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    rule_refs jsonb;
BEGIN
    IF pg_catalog.jsonb_typeof(p_policy) IS DISTINCT FROM 'object'
       OR NOT (p_policy ?& ARRAY[
           'schema_version','record_type','tenant_id','decision_id','request_id',
           'request_digest','decision','rule_refs','constraints','isolation_profile',
           'decided_at','decision_digest'
       ])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(p_policy) AS keys(key)
            WHERE key <> ALL(ARRAY[
                'schema_version','record_type','tenant_id','decision_id','request_id',
                'request_digest','decision','rule_refs','constraints','isolation_profile',
                'decided_at','decision_digest'
            ])
       )
       OR p_policy ->> 'schema_version' IS DISTINCT FROM '1.0'
       OR p_policy ->> 'record_type' IS DISTINCT FROM 'policy_decision'
       OR p_policy ->> 'tenant_id' IS DISTINCT FROM p_actor ->> 'tenant_id'
       OR pg_catalog.jsonb_typeof(p_policy -> 'decision_id') IS DISTINCT FROM 'string'
       OR p_policy ->> 'decision_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR pg_catalog.jsonb_typeof(p_policy -> 'request_id') IS DISTINCT FROM 'string'
       OR p_policy ->> 'request_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_policy ->> 'request_id' IS DISTINCT FROM p_operation_id
       OR pg_catalog.jsonb_typeof(p_policy -> 'request_digest') IS DISTINCT FROM 'string'
       OR p_policy ->> 'request_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_policy ->> 'request_digest' IS DISTINCT FROM p_operation_digest
       OR p_policy ->> 'decision' IS DISTINCT FROM 'authorize'
       OR p_policy ->> 'isolation_profile' IS DISTINCT FROM 'no_effect'
       OR p_policy -> 'constraints' IS DISTINCT FROM '[]'::jsonb
       OR pg_catalog.jsonb_typeof(p_policy -> 'decision_digest') IS DISTINCT FROM 'string'
       OR p_policy ->> 'decision_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_policy ->> 'decision_digest' IS DISTINCT FROM public.gah_canonical_sha256(
            p_policy - 'decision_digest'
       )
       OR pg_catalog.jsonb_typeof(p_policy -> 'decided_at') IS DISTINCT FROM 'string'
       OR p_policy ->> 'decided_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR NOT pg_catalog.pg_input_is_valid(p_policy ->> 'decided_at', 'timestamp with time zone')
       OR (p_policy ->> 'decided_at')::timestamptz > pg_catalog.clock_timestamp()
    THEN
        RAISE EXCEPTION 'GitHub Markdown policy is not an exact bounded authorization';
    END IF;
    rule_refs := p_policy -> 'rule_refs';
    IF pg_catalog.jsonb_typeof(rule_refs) IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(rule_refs) NOT BETWEEN 1 AND 128
       OR (
           SELECT count(*) <> count(DISTINCT value)
             FROM pg_catalog.jsonb_array_elements(rule_refs) AS elements(value)
       )
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_array_elements(rule_refs) AS elements(value)
            WHERE pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string'
               OR pg_catalog.char_length(value #>> '{}') NOT BETWEEN 1 AND 128
               OR value #>> '{}' !~ '^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$'
       )
    THEN
        RAISE EXCEPTION 'GitHub Markdown policy is not an exact bounded authorization';
    END IF;
END
$function$;

CREATE FUNCTION public.gah_github_markdown_assert_source(p_source jsonb) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF pg_catalog.jsonb_typeof(p_source) IS DISTINCT FROM 'object'
       OR NOT (p_source ?& ARRAY[
           'source_identity','repository','commit_sha','path','revision_uri',
           'media_type','content','content_digest','classification','retention_expires_at'
       ])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(p_source) AS keys(key)
            WHERE key <> ALL(ARRAY[
                'source_identity','repository','commit_sha','path','revision_uri',
                'media_type','content','content_digest','classification','retention_expires_at'
            ])
       )
       OR pg_catalog.jsonb_typeof(p_source -> 'repository') IS DISTINCT FROM 'string'
       OR p_source ->> 'repository'
            !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,98}/[A-Za-z0-9][A-Za-z0-9_.-]{0,98}$'
       OR pg_catalog.jsonb_typeof(p_source -> 'commit_sha') IS DISTINCT FROM 'string'
       OR p_source ->> 'commit_sha' !~ '^[0-9a-f]{40}$'
       OR pg_catalog.jsonb_typeof(p_source -> 'path') IS DISTINCT FROM 'string'
       OR NOT public.gah_github_markdown_path_valid(p_source ->> 'path')
       OR pg_catalog.jsonb_typeof(p_source -> 'source_identity') IS DISTINCT FROM 'string'
       OR p_source ->> 'source_identity' IS DISTINCT FROM
            'github://' || (p_source ->> 'repository') || '/' || (p_source ->> 'path')
       OR pg_catalog.jsonb_typeof(p_source -> 'revision_uri') IS DISTINCT FROM 'string'
       OR p_source ->> 'revision_uri' IS DISTINCT FROM
            'https://github.com/' || (p_source ->> 'repository') || '/blob/'
            || (p_source ->> 'commit_sha') || '/' || (p_source ->> 'path')
       OR p_source ->> 'media_type' IS DISTINCT FROM 'text/markdown'
       OR pg_catalog.jsonb_typeof(p_source -> 'content') IS DISTINCT FROM 'string'
       OR octet_length(p_source ->> 'content') NOT BETWEEN 1 AND 65536
       OR p_source ->> 'content' ~ 'gh[pousr]_[A-Za-z0-9_]{36,}'
       OR p_source ->> 'content' ~ 'github_pat_[A-Za-z0-9_]{82,}'
       OR p_source ->> 'content' ~ 'AKIA[0-9A-Z]{16}'
       OR p_source ->> 'content' ~ '-----BEGIN [A-Z ]+PRIVATE KEY-----'
       OR pg_catalog.jsonb_typeof(p_source -> 'content_digest') IS DISTINCT FROM 'string'
       OR p_source ->> 'content_digest' IS DISTINCT FROM public.gah_canonical_sha256(
            pg_catalog.jsonb_build_object(
                'content', p_source -> 'content', 'media_type', p_source -> 'media_type'
            )
       )
       OR p_source ->> 'classification' NOT IN ('public', 'internal', 'confidential', 'restricted')
       OR pg_catalog.jsonb_typeof(p_source -> 'retention_expires_at') IS DISTINCT FROM 'string'
       OR p_source ->> 'retention_expires_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR NOT pg_catalog.pg_input_is_valid(
            p_source ->> 'retention_expires_at', 'timestamp with time zone'
       )
       OR (p_source ->> 'retention_expires_at')::timestamptz <= pg_catalog.clock_timestamp()
    THEN
        RAISE EXCEPTION 'GitHub Markdown source is invalid';
    END IF;
END
$function$;

CREATE FUNCTION public.gah_github_markdown_assert_evidence(
    p_actor jsonb,
    p_run_id text,
    p_event_kind text,
    p_policy jsonb,
    p_expected_payload jsonb,
    p_evidence jsonb
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    expected_policy_ref jsonb := pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
        'record_type', 'policy_decision',
        'record_id', p_policy ->> 'decision_id',
        'record_digest', p_policy ->> 'decision_digest'
    ));
    draft jsonb;
    idempotency jsonb;
BEGIN
    IF pg_catalog.jsonb_typeof(p_evidence) IS DISTINCT FROM 'object'
       OR NOT (p_evidence ?& ARRAY[
           'schema_version','record_type','tenant_id','envelope_id','draft','draft_digest',
           'recorded_at','sequence_number','payload_digest','prior_event_digest',
           'event_digest','policy_refs','storage_writer_id'
       ])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(p_evidence) AS keys(key)
            WHERE key <> ALL(ARRAY[
                'schema_version','record_type','tenant_id','envelope_id','draft','draft_digest',
                'recorded_at','sequence_number','payload_digest','prior_event_digest',
                'event_digest','policy_refs','storage_writer_id'
            ])
       )
       OR p_evidence ->> 'schema_version' IS DISTINCT FROM '1.0'
       OR p_evidence ->> 'record_type' IS DISTINCT FROM 'evidence_envelope'
       OR p_evidence ->> 'tenant_id' IS DISTINCT FROM p_actor ->> 'tenant_id'
       OR pg_catalog.jsonb_typeof(p_evidence -> 'envelope_id') IS DISTINCT FROM 'string'
       OR p_evidence ->> 'envelope_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR pg_catalog.jsonb_typeof(p_evidence -> 'draft_digest') IS DISTINCT FROM 'string'
       OR p_evidence ->> 'draft_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_evidence ->> 'draft_digest' IS DISTINCT FROM public.gah_canonical_sha256(
            p_evidence -> 'draft'
       )
       OR pg_catalog.jsonb_typeof(p_evidence -> 'payload_digest') IS DISTINCT FROM 'string'
       OR p_evidence ->> 'payload_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_evidence ->> 'payload_digest' IS DISTINCT FROM public.gah_canonical_sha256(
            p_evidence #> '{draft,inline_payload}'
       )
       OR pg_catalog.jsonb_typeof(p_evidence -> 'event_digest') IS DISTINCT FROM 'string'
       OR p_evidence ->> 'event_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_evidence ->> 'event_digest' IS DISTINCT FROM public.gah_canonical_sha256(
            p_evidence - 'event_digest'
       )
       OR p_evidence -> 'policy_refs' IS DISTINCT FROM expected_policy_ref
       OR p_evidence ->> 'storage_writer_id' IS DISTINCT FROM 'kernel.postgresql.v1'
       OR pg_catalog.jsonb_typeof(p_evidence -> 'sequence_number') IS DISTINCT FROM 'number'
       OR (p_evidence ->> 'sequence_number') !~ '^[0-9]+$'
       OR (p_evidence ->> 'sequence_number')::numeric > 9007199254740991
       OR NOT (
           pg_catalog.jsonb_typeof(p_evidence -> 'prior_event_digest') = 'null'
           OR (
               pg_catalog.jsonb_typeof(p_evidence -> 'prior_event_digest') = 'string'
               AND p_evidence ->> 'prior_event_digest' ~ '^sha256:[0-9a-f]{64}$'
           )
       )
    THEN
        RAISE EXCEPTION 'GitHub Markdown evidence is invalid';
    END IF;
    draft := p_evidence -> 'draft';
    IF pg_catalog.jsonb_typeof(draft) IS DISTINCT FROM 'object'
       OR NOT (draft ?& ARRAY[
           'schema_version','record_type','tenant_id','event_id','run_id','event_kind',
           'occurred_at','idempotency','classification','redaction_status','inline_payload'
       ])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(draft) AS keys(key)
            WHERE key <> ALL(ARRAY[
                'schema_version','record_type','tenant_id','event_id','run_id','event_kind',
                'occurred_at','idempotency','classification','redaction_status','inline_payload'
            ])
       )
       OR draft ->> 'schema_version' IS DISTINCT FROM '1.0'
       OR draft ->> 'record_type' IS DISTINCT FROM 'evidence_draft'
       OR draft ->> 'tenant_id' IS DISTINCT FROM p_actor ->> 'tenant_id'
       OR pg_catalog.jsonb_typeof(draft -> 'event_id') IS DISTINCT FROM 'string'
       OR draft ->> 'event_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR draft ->> 'run_id' IS DISTINCT FROM p_run_id
       OR draft ->> 'event_kind' IS DISTINCT FROM p_event_kind
       OR draft ->> 'classification' IS DISTINCT FROM 'internal'
       OR draft ->> 'redaction_status' IS DISTINCT FROM 'redacted'
       OR draft -> 'inline_payload' IS DISTINCT FROM p_expected_payload
       OR pg_catalog.jsonb_typeof(draft -> 'occurred_at') IS DISTINCT FROM 'string'
       OR draft ->> 'occurred_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR NOT pg_catalog.pg_input_is_valid(
            draft ->> 'occurred_at', 'timestamp with time zone'
       )
       OR pg_catalog.jsonb_typeof(p_evidence -> 'recorded_at') IS DISTINCT FROM 'string'
       OR p_evidence ->> 'recorded_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR NOT pg_catalog.pg_input_is_valid(
            p_evidence ->> 'recorded_at', 'timestamp with time zone'
       )
       OR draft ->> 'occurred_at' IS DISTINCT FROM p_evidence ->> 'recorded_at'
       OR (p_evidence ->> 'recorded_at')::timestamptz > pg_catalog.clock_timestamp()
       OR (p_policy ->> 'decided_at')::timestamptz
            > (p_evidence ->> 'recorded_at')::timestamptz
       OR (p_actor ->> 'issued_at')::timestamptz
            > (p_evidence ->> 'recorded_at')::timestamptz
       OR (p_actor #>> '{auth,verified_at}')::timestamptz
            > (p_evidence ->> 'recorded_at')::timestamptz
    THEN
        RAISE EXCEPTION 'GitHub Markdown evidence is invalid';
    END IF;
    idempotency := draft -> 'idempotency';
    IF pg_catalog.jsonb_typeof(idempotency) IS DISTINCT FROM 'object'
       OR NOT (idempotency ?& ARRAY['tenant_id','idempotency_key','operation_digest'])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(idempotency) AS keys(key)
            WHERE key <> ALL(ARRAY['tenant_id','idempotency_key','operation_digest'])
       )
       OR idempotency ->> 'tenant_id' IS DISTINCT FROM p_actor ->> 'tenant_id'
       OR idempotency ->> 'idempotency_key' IS DISTINCT FROM
            ('kernel.' || p_event_kind || '.' || p_run_id || '.'
             || (p_evidence ->> 'sequence_number'))
       OR idempotency ->> 'operation_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_expected_payload)
    THEN
        RAISE EXCEPTION 'GitHub Markdown evidence is invalid';
    END IF;
END
$function$;

CREATE FUNCTION public.gah_github_markdown_commit_evidence(
    p_actor jsonb, p_run_id text, p_evidence jsonb
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    head public.gah_run_heads%ROWTYPE;
    changed bigint;
BEGIN
    INSERT INTO public.gah_run_heads (tenant_id, actor_id, run_id)
    VALUES (p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_run_id)
    ON CONFLICT (tenant_id, run_id) DO NOTHING;
    SELECT * INTO head FROM public.gah_run_heads
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND run_id = p_run_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub Markdown run belongs to another actor';
    END IF;
    IF (p_evidence ->> 'sequence_number')::bigint <> head.next_sequence
       OR p_evidence ->> 'prior_event_digest' IS DISTINCT FROM head.last_event_digest
       OR (head.last_recorded_at IS NOT NULL
           AND (p_evidence ->> 'recorded_at')::timestamptz < head.last_recorded_at)
    THEN
        RAISE EXCEPTION 'GitHub Markdown evidence sequence conflicts with run head';
    END IF;
    INSERT INTO public.gah_evidence_events (
        tenant_id, actor_id, run_id, sequence_number, envelope_id, event_digest,
        prior_event_digest, envelope_json, recorded_at
    ) VALUES (
        p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_run_id,
        (p_evidence ->> 'sequence_number')::bigint, p_evidence ->> 'envelope_id',
        p_evidence ->> 'event_digest', p_evidence ->> 'prior_event_digest', p_evidence,
        (p_evidence ->> 'recorded_at')::timestamptz
    );
    UPDATE public.gah_run_heads
       SET next_sequence = head.next_sequence + 1,
           last_event_digest = p_evidence ->> 'event_digest',
           last_recorded_at = (p_evidence ->> 'recorded_at')::timestamptz,
           version = head.version + 1
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND run_id = p_run_id
       AND version = head.version;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'GitHub Markdown run head changed concurrently';
    END IF;
END
$function$;

CREATE FUNCTION public.gah_github_markdown_reserve_operation(
    p_actor jsonb,
    p_operation_id text,
    p_operation_kind text,
    p_operation_digest text,
    p_binding_digest text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    existing public.gah_github_markdown_operations%ROWTYPE;
    inserted bigint;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF p_operation_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_operation_kind NOT IN ('import', 'revoke')
       OR p_operation_digest !~ '^sha256:[0-9a-f]{64}$'
       OR p_binding_digest !~ '^sha256:[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION 'GitHub Markdown operation reservation is malformed';
    END IF;
    INSERT INTO public.gah_github_markdown_operations (
        tenant_id, actor_id, operation_id, operation_kind, operation_digest, binding_digest, created_at
    ) VALUES (
        p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_operation_id,
        p_operation_kind, p_operation_digest, p_binding_digest, pg_catalog.clock_timestamp()
    ) ON CONFLICT (tenant_id, actor_id, operation_id) DO NOTHING;
    GET DIAGNOSTICS inserted = ROW_COUNT;
    IF inserted = 1 THEN
        RETURN;
    END IF;
    SELECT * INTO existing
      FROM public.gah_github_markdown_operations
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND operation_id = p_operation_id
     FOR KEY SHARE;
    IF NOT FOUND
       OR existing.operation_kind IS DISTINCT FROM p_operation_kind
       OR existing.operation_digest IS DISTINCT FROM p_operation_digest
       OR existing.binding_digest IS DISTINCT FROM p_binding_digest
    THEN
        RAISE EXCEPTION 'GitHub Markdown operation conflicts with stored operation';
    END IF;
END
$function$;

CREATE FUNCTION public.gah_lookup_github_markdown_revision(
    p_actor jsonb, p_source_identity text, p_commit_sha text, p_content_digest text,
    p_import_binding_digest text
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    revision public.gah_github_markdown_revisions%ROWTYPE;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF p_source_identity IS NULL OR p_commit_sha !~ '^[0-9a-f]{40}$'
       OR p_content_digest !~ '^sha256:[0-9a-f]{64}$'
       OR p_import_binding_digest !~ '^sha256:[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION 'GitHub Markdown replay lookup is malformed';
    END IF;
    SELECT revisions.* INTO revision
      FROM public.gah_github_markdown_revisions AS revisions
      JOIN public.gah_github_markdown_sources AS sources
        ON sources.tenant_id = revisions.tenant_id
       AND sources.actor_id = revisions.actor_id
       AND sources.source_identity = revisions.source_identity
     WHERE revisions.tenant_id = p_actor ->> 'tenant_id'
       AND revisions.actor_id = p_actor ->> 'actor_id'
       AND revisions.source_identity = p_source_identity
       AND revisions.commit_sha = p_commit_sha
       AND revisions.content_digest = p_content_digest
       AND revisions.import_binding_digest = p_import_binding_digest
       AND revisions.retention_expires_at > pg_catalog.clock_timestamp()
       AND sources.revoked_at IS NULL;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'source_identity', revision.source_identity,
        'revision_uri', revision.revision_uri,
        'repository', split_part(revision.source_identity, '/', 3) || '/' || split_part(revision.source_identity, '/', 4),
        'commit_sha', revision.commit_sha,
        'path', substr(revision.source_identity, length('github://' || split_part(revision.source_identity, '/', 3) || '/' || split_part(revision.source_identity, '/', 4) || '/') + 1),
        'content', revision.content,
        'content_digest', revision.content_digest,
        'classification', revision.classification,
        'citation', pg_catalog.jsonb_build_object(
            'evidence_id', revision.evidence_event_id,
            'payload_digest', revision.evidence_payload_digest
        )
    );
END
$function$;

CREATE FUNCTION public.gah_import_github_markdown(
    p_actor jsonb, p_payload jsonb, p_evidence jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    source jsonb := p_payload -> 'source';
    policy jsonb := p_payload -> 'policy_decision';
    expected_payload jsonb;
    existing public.gah_github_markdown_revisions%ROWTYPE;
    import_binding_digest text;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF pg_catalog.jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
       OR NOT (p_payload ?& ARRAY[
           'operation_id','operation_digest','run_id','source','policy_decision'
       ])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(p_payload) AS keys(key)
            WHERE key <> ALL(ARRAY[
                'operation_id','operation_digest','run_id','source','policy_decision'
            ])
       )
       OR p_payload ->> 'operation_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_payload ->> 'run_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_payload ->> 'operation_digest' IS DISTINCT FROM public.gah_canonical_sha256(
            pg_catalog.jsonb_build_object(
                'operation_id', p_payload -> 'operation_id', 'source', source
            )
       )
    THEN
        RAISE EXCEPTION 'GitHub Markdown import payload is invalid';
    END IF;
    PERFORM public.gah_github_markdown_assert_source(source);
    PERFORM public.gah_github_markdown_assert_policy(
        p_actor, p_payload ->> 'operation_id', p_payload ->> 'operation_digest', policy
    );
    expected_payload := pg_catalog.jsonb_build_object(
        'actor_id', p_actor ->> 'actor_id',
        'operation_id', p_payload ->> 'operation_id',
        'operation_digest', p_payload ->> 'operation_digest',
        'source', source - 'content',
        'policy_decision_digest', policy ->> 'decision_digest'
    );
    PERFORM public.gah_github_markdown_assert_evidence(
        p_actor, p_payload ->> 'run_id', 'knowledge.github_markdown_imported',
        policy, expected_payload, p_evidence
    );
    import_binding_digest := public.gah_canonical_sha256(p_payload);
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'github-source:' || (p_actor ->> 'tenant_id') || ':' || (p_actor ->> 'actor_id')
        || ':' || (source ->> 'source_identity'), 0
    ));
    PERFORM public.gah_github_markdown_reserve_operation(
        p_actor, p_payload ->> 'operation_id', 'import', p_payload ->> 'operation_digest',
        import_binding_digest
    );
    IF EXISTS (
        SELECT 1 FROM public.gah_github_markdown_sources
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND source_identity = source ->> 'source_identity'
           AND revoked_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'GitHub Markdown source is revoked';
    END IF;
    SELECT * INTO existing
      FROM public.gah_github_markdown_revisions
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND source_identity = source ->> 'source_identity'
       AND commit_sha = source ->> 'commit_sha'
     FOR UPDATE;
    IF FOUND THEN
        IF existing.content_digest IS DISTINCT FROM source ->> 'content_digest' THEN
            RAISE EXCEPTION 'GitHub Markdown commit conflicts with stored content';
        END IF;
        IF existing.import_binding_digest IS DISTINCT FROM import_binding_digest THEN
            RAISE EXCEPTION 'GitHub Markdown revision binding conflicts with stored import';
        END IF;
        RAISE EXCEPTION 'GitHub Markdown revision already exists';
    END IF;
    INSERT INTO public.gah_github_markdown_sources (
        tenant_id, actor_id, source_identity, repository, source_path, created_at
    ) VALUES (
        p_actor ->> 'tenant_id', p_actor ->> 'actor_id', source ->> 'source_identity',
        source ->> 'repository', source ->> 'path', pg_catalog.clock_timestamp()
    ) ON CONFLICT (tenant_id, actor_id, source_identity) DO NOTHING;
    PERFORM public.gah_github_markdown_commit_evidence(
        p_actor, p_payload ->> 'run_id', p_evidence
    );
    INSERT INTO public.gah_github_markdown_revisions (
        tenant_id, actor_id, source_identity, commit_sha, content_digest, import_binding_digest, revision_uri,
        media_type, content, classification, retention_expires_at, evidence_json,
        evidence_event_id, evidence_payload_digest, imported_at
    ) VALUES (
        p_actor ->> 'tenant_id', p_actor ->> 'actor_id', source ->> 'source_identity',
        source ->> 'commit_sha', source ->> 'content_digest', import_binding_digest,
        source ->> 'revision_uri',
        source ->> 'media_type', source ->> 'content', source ->> 'classification',
        (source ->> 'retention_expires_at')::timestamptz, p_evidence,
        p_evidence #>> '{draft,event_id}', p_evidence ->> 'payload_digest',
        pg_catalog.clock_timestamp()
    );
    RETURN public.gah_lookup_github_markdown_revision(
        p_actor, source ->> 'source_identity', source ->> 'commit_sha',
        source ->> 'content_digest', import_binding_digest
    );
END
$function$;

CREATE FUNCTION public.gah_revoke_github_markdown_source(
    p_actor jsonb, p_payload jsonb, p_evidence jsonb
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    policy jsonb := p_payload -> 'policy_decision';
    expected_payload jsonb;
    source public.gah_github_markdown_sources%ROWTYPE;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF pg_catalog.jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
       OR NOT (p_payload ?& ARRAY[
           'operation_id','operation_digest','run_id','source_identity','policy_decision'
       ])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(p_payload) AS keys(key)
            WHERE key <> ALL(ARRAY[
                'operation_id','operation_digest','run_id','source_identity','policy_decision'
            ])
       )
       OR p_payload ->> 'operation_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_payload ->> 'run_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR NOT public.gah_github_markdown_source_identity_valid(p_payload ->> 'source_identity')
       OR p_payload ->> 'operation_digest' IS DISTINCT FROM public.gah_canonical_sha256(
            pg_catalog.jsonb_build_object(
                'operation_id', p_payload -> 'operation_id',
                'source_identity', p_payload -> 'source_identity'
            )
       )
    THEN
        RAISE EXCEPTION 'GitHub Markdown revocation payload is invalid';
    END IF;
    PERFORM public.gah_github_markdown_assert_policy(
        p_actor, p_payload ->> 'operation_id', p_payload ->> 'operation_digest', policy
    );
    expected_payload := pg_catalog.jsonb_build_object(
        'actor_id', p_actor ->> 'actor_id',
        'operation_id', p_payload ->> 'operation_id',
        'operation_digest', p_payload ->> 'operation_digest',
        'source_identity', p_payload ->> 'source_identity',
        'policy_decision_digest', policy ->> 'decision_digest'
    );
    PERFORM public.gah_github_markdown_assert_evidence(
        p_actor, p_payload ->> 'run_id', 'knowledge.github_markdown_revoked',
        policy, expected_payload, p_evidence
    );
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'github-source:' || (p_actor ->> 'tenant_id') || ':' || (p_actor ->> 'actor_id')
        || ':' || (p_payload ->> 'source_identity'), 0
    ));
    PERFORM public.gah_github_markdown_reserve_operation(
        p_actor, p_payload ->> 'operation_id', 'revoke', p_payload ->> 'operation_digest',
        public.gah_canonical_sha256(p_payload)
    );
    SELECT * INTO source FROM public.gah_github_markdown_sources
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND source_identity = p_payload ->> 'source_identity'
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub Markdown source does not exist';
    END IF;
    IF source.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'GitHub Markdown source is already revoked';
    END IF;
    PERFORM public.gah_github_markdown_commit_evidence(
        p_actor, p_payload ->> 'run_id', p_evidence
    );
    UPDATE public.gah_github_markdown_sources
       SET revoked_at = pg_catalog.clock_timestamp(),
           revocation_operation_id = p_payload ->> 'operation_id',
           revocation_operation_digest = p_payload ->> 'operation_digest',
           revocation_evidence_json = p_evidence
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND source_identity = p_payload ->> 'source_identity'
       AND revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub Markdown source revocation lost its race';
    END IF;
    RETURN true;
END
$function$;

CREATE FUNCTION public.gah_retrieve_github_markdown(
    p_actor jsonb, p_query text, p_max_results integer
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    result jsonb;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF p_query IS NULL OR btrim(p_query) = '' OR length(p_query) > 256
       OR p_max_results IS NULL OR p_max_results NOT BETWEEN 1 AND 10
    THEN
        RAISE EXCEPTION 'GitHub Markdown retrieval request is invalid';
    END IF;
    WITH eligible AS (
        SELECT revisions.*,
               position(lower(p_query) IN lower(revisions.content)) AS relevance
          FROM public.gah_github_markdown_revisions AS revisions
          JOIN public.gah_github_markdown_sources AS sources
            ON sources.tenant_id = revisions.tenant_id
           AND sources.actor_id = revisions.actor_id
           AND sources.source_identity = revisions.source_identity
         WHERE revisions.tenant_id = p_actor ->> 'tenant_id'
           AND revisions.actor_id = p_actor ->> 'actor_id'
           AND sources.revoked_at IS NULL
           AND revisions.retention_expires_at > pg_catalog.clock_timestamp()
    )
    SELECT coalesce(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'source_identity', source_identity,
            'revision_uri', revision_uri,
            'repository', split_part(source_identity, '/', 3) || '/' || split_part(source_identity, '/', 4),
            'commit_sha', commit_sha,
            'path', substr(source_identity, length('github://' || split_part(source_identity, '/', 3) || '/' || split_part(source_identity, '/', 4) || '/') + 1),
            'content', content,
            'content_digest', content_digest,
            'classification', classification,
            'citation', pg_catalog.jsonb_build_object(
                'evidence_id', evidence_event_id, 'payload_digest', evidence_payload_digest
            )
        ) ORDER BY relevance, imported_at DESC, source_identity, commit_sha
    ), '[]'::jsonb)
      INTO result
      FROM (
          SELECT * FROM eligible
           WHERE relevance > 0
           ORDER BY relevance, imported_at DESC, source_identity, commit_sha
           LIMIT p_max_results
      ) AS selected;
    RETURN result;
END
$function$;

ALTER FUNCTION public.gah_github_markdown_assert_policy(jsonb,text,text,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_github_markdown_path_valid(text) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_github_markdown_source_identity_valid(text) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_github_markdown_assert_source(jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_github_markdown_assert_evidence(jsonb,text,text,jsonb,jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_github_markdown_commit_evidence(jsonb,text,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_github_markdown_reserve_operation(jsonb,text,text,text,text) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_lookup_github_markdown_revision(jsonb,text,text,text,text) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_import_github_markdown(jsonb,jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_revoke_github_markdown_source(jsonb,jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_retrieve_github_markdown(jsonb,text,integer) OWNER TO gah_schema_owner;

REVOKE ALL ON FUNCTION public.gah_github_markdown_assert_policy(jsonb,text,text,jsonb) FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_github_markdown_path_valid(text) FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_github_markdown_source_identity_valid(text) FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_github_markdown_assert_source(jsonb) FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_github_markdown_assert_evidence(jsonb,text,text,jsonb,jsonb,jsonb) FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_github_markdown_commit_evidence(jsonb,text,jsonb) FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_github_markdown_reserve_operation(jsonb,text,text,text,text) FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_lookup_github_markdown_revision(jsonb,text,text,text,text) FROM PUBLIC, gah_runtime, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_import_github_markdown(jsonb,jsonb,jsonb) FROM PUBLIC, gah_runtime, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_revoke_github_markdown_source(jsonb,jsonb,jsonb) FROM PUBLIC, gah_runtime, gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_retrieve_github_markdown(jsonb,text,integer) FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION public.gah_lookup_github_markdown_revision(jsonb,text,text,text,text) TO gah_authority_writer;
GRANT EXECUTE ON FUNCTION public.gah_import_github_markdown(jsonb,jsonb,jsonb) TO gah_authority_writer;
GRANT EXECUTE ON FUNCTION public.gah_revoke_github_markdown_source(jsonb,jsonb,jsonb) TO gah_authority_writer;
GRANT EXECUTE ON FUNCTION public.gah_retrieve_github_markdown(jsonb,text,integer) TO gah_runtime;
