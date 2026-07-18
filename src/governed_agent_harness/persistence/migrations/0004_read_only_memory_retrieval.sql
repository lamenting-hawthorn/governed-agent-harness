CREATE TABLE gah_memory_records (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    memory_id text NOT NULL,
    revision integer NOT NULL CHECK (revision >= 1),
    record_digest text NOT NULL CHECK (record_digest LIKE 'sha256:%'),
    record_json jsonb NOT NULL,
    scope_json jsonb NOT NULL,
    proposition_json jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    effective_from timestamptz NOT NULL,
    effective_until timestamptz,
    expires_at timestamptz,
    lifecycle_state text NOT NULL,
    PRIMARY KEY (tenant_id, memory_id, revision),
    CHECK (actor_id <> ''),
    CHECK (record_json ->> 'record_type' = 'memory_record'),
    CHECK (record_json ->> 'tenant_id' = tenant_id),
    CHECK (record_json ->> 'memory_id' = memory_id),
    CHECK ((record_json ->> 'revision')::integer = revision),
    CHECK (record_json ->> 'record_digest' = record_digest),
    CHECK (scope_json = record_json -> 'scope'),
    CHECK (scope_json ->> 'tenant_id' = tenant_id),
    CHECK (scope_json ->> 'actor_id' = actor_id),
    CHECK (proposition_json = record_json -> 'proposition'),
    CHECK (lifecycle_state = record_json ->> 'lifecycle_state'),
    CHECK (effective_until IS NULL OR effective_from <= effective_until),
    CHECK (expires_at IS NULL OR effective_from <= expires_at)
);

ALTER TABLE gah_memory_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_memory_records FORCE ROW LEVEL SECURITY;

CREATE POLICY gah_memory_records_scope ON gah_memory_records
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

ALTER TABLE gah_memory_records OWNER TO gah_schema_owner;
REVOKE ALL ON gah_memory_records FROM PUBLIC, gah_runtime, gah_authority_writer;

CREATE FUNCTION gah_retrieve_memory(p_actor jsonb, p_query jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    result jsonb;
    query_text text;
    max_records integer;
BEGIN
    IF p_actor ->> 'record_type' <> 'actor_context'
        OR nullif(p_actor ->> 'tenant_id', '') IS NULL
        OR nullif(p_actor ->> 'actor_id', '') IS NULL THEN
        RAISE EXCEPTION 'validated actor context is required';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.gah_runtime_principals
         WHERE database_role = session_user
           AND tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
    ) THEN
        RAISE EXCEPTION 'runtime database principal is outside actor scope';
    END IF;
    IF p_query ->> 'record_type' <> 'memory_query'
        OR p_query ->> 'tenant_id' <> p_actor ->> 'tenant_id'
        OR p_query #>> '{scope,record_type}' <> 'memory_scope'
        OR p_query #>> '{scope,tenant_id}' <> p_actor ->> 'tenant_id'
        OR p_query #>> '{scope,actor_id}' <> p_actor ->> 'actor_id'
        OR p_query #>> '{scope,selection,level}' <> 'actor' THEN
        RAISE EXCEPTION 'memory query scope is invalid';
    END IF;
    query_text := nullif(p_query ->> 'query', '');
    max_records := (p_query #>> '{budget,max_records}')::integer;
    IF query_text IS NULL OR max_records IS NULL OR max_records < 1 OR max_records > 256 THEN
        RAISE EXCEPTION 'memory query budget is invalid';
    END IF;
    PERFORM set_config('gah.tenant_id', p_actor ->> 'tenant_id', true);
    PERFORM set_config('gah.actor_id', p_actor ->> 'actor_id', true);

    WITH latest AS (
        SELECT DISTINCT ON (memory_id) *
          FROM public.gah_memory_records
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
         ORDER BY memory_id, revision DESC
    ), eligible AS (
        SELECT *,
               CASE
                   WHEN lower(proposition_json ->> 'subject') = lower(query_text) THEN 3
                   WHEN lower(proposition_json::text) LIKE '%' || lower(query_text) || '%' THEN 1
                   ELSE 0
               END AS relevance_score
          FROM latest
         WHERE lifecycle_state = 'active'
           AND scope_json -> 'selection' = p_query #> '{scope,selection}'
           AND effective_from <= clock_timestamp()
           AND (effective_until IS NULL OR effective_until > clock_timestamp())
           AND (expires_at IS NULL OR expires_at > clock_timestamp())
           AND proposition_json ->> 'kind' IN (
               SELECT jsonb_array_elements_text(p_query -> 'allowed_categories')
           )
           AND (p_query #>> '{temporal_bound,from}' IS NULL
                OR observed_at >= (p_query #>> '{temporal_bound,from}')::timestamptz)
           AND (p_query #>> '{temporal_bound,until}' IS NULL
                OR observed_at <= (p_query #>> '{temporal_bound,until}')::timestamptz)
    )
    SELECT coalesce(
               jsonb_agg(
                   record_json || jsonb_build_object('_relevance_score', relevance_score)
                   ORDER BY relevance_score DESC, observed_at DESC, memory_id, revision
               ),
               '[]'::jsonb
           )
      INTO result
      FROM (
          SELECT * FROM eligible
           WHERE relevance_score > 0
           ORDER BY relevance_score DESC, observed_at DESC, memory_id, revision
           LIMIT max_records
      ) AS selected;
    RETURN result;
END
$function$;

ALTER FUNCTION gah_retrieve_memory(jsonb, jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_retrieve_memory(jsonb, jsonb) FROM PUBLIC, gah_authority_writer;
GRANT EXECUTE ON FUNCTION gah_retrieve_memory(jsonb, jsonb) TO gah_runtime;
