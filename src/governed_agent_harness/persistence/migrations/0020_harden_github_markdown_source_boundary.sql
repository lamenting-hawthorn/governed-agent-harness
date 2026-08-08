-- Preserve the Phase 5.2 migration checksum while tightening its bounded source
-- validation and making one import's expiry decision stable for that statement.

LOCK TABLE public.gah_github_markdown_sources,
    public.gah_github_markdown_revisions,
    public.gah_github_markdown_operations IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION public.gah_github_markdown_content_has_credential(p_content text) RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $function$
    SELECT p_content ~ 'gh[pousr]_[A-Za-z0-9_]{36,}'
        OR p_content ~ 'github_pat_[A-Za-z0-9_]{82,}'
        OR p_content ~ 'AKIA[0-9A-Z]{16}'
        OR p_content ~ '-----BEGIN [A-Z ]+PRIVATE KEY-----'
        OR p_content ~ 'xox[abprs]-[A-Za-z0-9-]{10,}'
        OR p_content ~ '(sk|rk)_(live|test)_[A-Za-z0-9]{16,}'
        OR p_content ~ 'AIza[A-Za-z0-9_-]{35}'
        OR p_content ~ 'sk-(proj-)?[A-Za-z0-9_-]{20,}'
        OR p_content ~ 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        OR p_content ~* '(^|[^[:alnum:]_])["'']?(password|passwd|secret|api[_-]?key|access[_-]?token|authorization|token)["'']?[[:space:]]*[:=][[:space:]]*["'']?(bearer[[:space:]]+)?[^[:space:]''"]{8,}'
$function$;

ALTER FUNCTION public.gah_github_markdown_content_has_credential(text) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION public.gah_github_markdown_content_has_credential(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gah_github_markdown_content_has_credential(text)
    TO gah_schema_owner;

DO $preflight$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.gah_github_markdown_revisions AS revisions
          JOIN public.gah_github_markdown_sources AS sources
            ON sources.tenant_id = revisions.tenant_id
           AND sources.actor_id = revisions.actor_id
           AND sources.source_identity = revisions.source_identity
         WHERE revisions.retention_expires_at > pg_catalog.clock_timestamp()
           AND sources.revoked_at IS NULL
           AND public.gah_github_markdown_content_has_credential(revisions.content)
    ) THEN
        RAISE EXCEPTION 'existing GitHub Markdown revision contains credential material';
    END IF;
END
$preflight$;

CREATE OR REPLACE FUNCTION public.gah_github_markdown_assert_source(p_source jsonb) RETURNS void
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
       OR public.gah_github_markdown_content_has_credential(p_source ->> 'content')
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
       OR (p_source ->> 'retention_expires_at')::timestamptz <= pg_catalog.statement_timestamp()
    THEN
        RAISE EXCEPTION 'GitHub Markdown source is invalid';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION public.gah_lookup_github_markdown_revision(
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
       AND revisions.retention_expires_at > pg_catalog.statement_timestamp()
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
