-- Phase 5.3: local stdio MCP can enumerate and read only actor/project-bound,
-- cited GitHub Markdown resources.  This is a runtime-only read boundary.
-- No MCP request can select an actor, tenant, database role, or source scope.

LOCK TABLE public.gah_runtime_principals IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.gah_github_markdown_sources IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.gah_github_markdown_revisions IN ACCESS EXCLUSIVE MODE;

CREATE INDEX gah_github_markdown_revisions_mcp_list_idx
    ON public.gah_github_markdown_revisions (
        tenant_id, actor_id, imported_at, source_identity, commit_sha
    );

CREATE UNIQUE INDEX gah_github_markdown_revisions_mcp_uri_idx
    ON public.gah_github_markdown_revisions (tenant_id, actor_id, revision_uri);

CREATE FUNCTION public.gah_mcp_assert_local_actor(p_actor jsonb, p_project_id text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF p_project_id IS NULL
       OR p_project_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR NOT coalesce((p_actor -> 'scope_authority' -> 'allowed_levels') ? 'project', false)
       OR NOT coalesce((p_actor -> 'scope_authority' -> 'project_ids') ? p_project_id, false)
    THEN
        RAISE EXCEPTION 'local MCP actor is outside project scope';
    END IF;
END
$function$;

CREATE FUNCTION public.gah_list_github_markdown_mcp_resources(
    p_actor jsonb,
    p_project_id text,
    p_after_imported_at timestamptz,
    p_after_source_identity text,
    p_after_commit_sha text,
    p_max_results integer
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    result jsonb;
BEGIN
    PERFORM public.gah_mcp_assert_local_actor(p_actor, p_project_id);
    IF p_max_results IS NULL OR p_max_results NOT BETWEEN 1 AND 50
       OR ((p_after_imported_at IS NULL) <> (p_after_source_identity IS NULL))
       OR ((p_after_imported_at IS NULL) <> (p_after_commit_sha IS NULL))
       OR (p_after_source_identity IS NOT NULL
           AND NOT public.gah_github_markdown_source_identity_valid(p_after_source_identity))
       OR (p_after_commit_sha IS NOT NULL AND p_after_commit_sha !~ '^[0-9a-f]{40}$')
    THEN
        RAISE EXCEPTION 'local MCP resource list request is invalid';
    END IF;
    WITH evaluation AS (
        SELECT pg_catalog.clock_timestamp() AS checked_at
    ), eligible AS (
        SELECT revisions.*, sources.repository, sources.source_path, evaluation.checked_at
          FROM public.gah_github_markdown_revisions AS revisions
          JOIN public.gah_github_markdown_sources AS sources
            ON sources.tenant_id = revisions.tenant_id
           AND sources.actor_id = revisions.actor_id
           AND sources.source_identity = revisions.source_identity
          CROSS JOIN evaluation
         WHERE revisions.tenant_id = p_actor ->> 'tenant_id'
           AND revisions.actor_id = p_actor ->> 'actor_id'
           AND sources.revoked_at IS NULL
           AND revisions.retention_expires_at > evaluation.checked_at
           AND (
               p_after_imported_at IS NULL
               OR (pg_catalog.date_trunc('milliseconds', revisions.imported_at),
                   revisions.source_identity, revisions.commit_sha)
                    > (p_after_imported_at, p_after_source_identity, p_after_commit_sha)
           )
         ORDER BY pg_catalog.date_trunc('milliseconds', revisions.imported_at),
                  revisions.source_identity, revisions.commit_sha
         LIMIT p_max_results + 1
    )
    SELECT coalesce(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'source_identity', source_identity,
            'revision_uri', revision_uri,
            'repository', repository,
            'commit_sha', commit_sha,
            'path', source_path,
            'content_digest', content_digest,
            'classification', classification,
            'citation', pg_catalog.jsonb_build_object(
                'evidence_id', evidence_event_id,
                'payload_digest', evidence_payload_digest
            ),
            'imported_at', pg_catalog.to_char(
                imported_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ),
            'retention_expires_at', pg_catalog.to_char(
                retention_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ),
            'freshness_checked_at', pg_catalog.to_char(
                checked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            )
        ) ORDER BY pg_catalog.date_trunc('milliseconds', imported_at),
                 source_identity, commit_sha
    ), '[]'::jsonb)
      INTO result
      FROM eligible;
    RETURN result;
END
$function$;

CREATE FUNCTION public.gah_read_github_markdown_mcp_resource(
    p_actor jsonb, p_project_id text, p_revision_uri text
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    result jsonb;
BEGIN
    PERFORM public.gah_mcp_assert_local_actor(p_actor, p_project_id);
    IF p_revision_uri IS NULL OR octet_length(p_revision_uri) NOT BETWEEN 1 AND 2048 THEN
        RETURN NULL;
    END IF;
    WITH evaluation AS (
        SELECT pg_catalog.clock_timestamp() AS checked_at
    )
    SELECT pg_catalog.jsonb_build_object(
        'source_identity', revisions.source_identity,
        'revision_uri', revisions.revision_uri,
        'repository', sources.repository,
        'commit_sha', revisions.commit_sha,
        'path', sources.source_path,
        'content', revisions.content,
        'content_digest', revisions.content_digest,
        'classification', revisions.classification,
        'citation', pg_catalog.jsonb_build_object(
            'evidence_id', revisions.evidence_event_id,
            'payload_digest', revisions.evidence_payload_digest
        ),
        'imported_at', pg_catalog.to_char(
            revisions.imported_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
        ),
        'retention_expires_at', pg_catalog.to_char(
            revisions.retention_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
        ),
        'freshness_checked_at', pg_catalog.to_char(
            evaluation.checked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
        )
    ) INTO result
      FROM public.gah_github_markdown_revisions AS revisions
      JOIN public.gah_github_markdown_sources AS sources
        ON sources.tenant_id = revisions.tenant_id
       AND sources.actor_id = revisions.actor_id
       AND sources.source_identity = revisions.source_identity
      CROSS JOIN evaluation
     WHERE revisions.tenant_id = p_actor ->> 'tenant_id'
       AND revisions.actor_id = p_actor ->> 'actor_id'
       AND revisions.revision_uri = p_revision_uri
       AND sources.revoked_at IS NULL
       AND revisions.retention_expires_at > evaluation.checked_at;
    RETURN result;
END
$function$;

ALTER FUNCTION public.gah_mcp_assert_local_actor(jsonb,text) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_list_github_markdown_mcp_resources(
    jsonb,text,timestamptz,text,text,integer
) OWNER TO gah_schema_owner;
ALTER FUNCTION public.gah_read_github_markdown_mcp_resource(jsonb,text,text)
    OWNER TO gah_schema_owner;

REVOKE ALL ON FUNCTION public.gah_mcp_assert_local_actor(jsonb,text)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_list_github_markdown_mcp_resources(
    jsonb,text,timestamptz,text,text,integer
) FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
REVOKE ALL ON FUNCTION public.gah_read_github_markdown_mcp_resource(jsonb,text,text)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION public.gah_mcp_assert_local_actor(jsonb,text) TO gah_runtime;
GRANT EXECUTE ON FUNCTION public.gah_list_github_markdown_mcp_resources(
    jsonb,text,timestamptz,text,text,integer
) TO gah_runtime;
GRANT EXECUTE ON FUNCTION public.gah_read_github_markdown_mcp_resource(jsonb,text,text)
    TO gah_runtime;
