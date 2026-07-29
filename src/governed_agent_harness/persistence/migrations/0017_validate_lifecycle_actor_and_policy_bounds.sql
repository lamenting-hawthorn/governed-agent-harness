-- Phase 5.1 lifecycle boundary repair: canonical actor admission and the
-- intentionally empty lifecycle-constraint set.  This is append-only: it
-- narrows SECURITY DEFINER entrypoints without rewriting accepted evidence.

LOCK TABLE public.gah_runtime_principals IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.gah_skill_lifecycle_transitions IN ACCESS EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION gah_skill_assert_actor(p_actor jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    scope jsonb;
    auth jsonb;
BEGIN
    IF pg_catalog.jsonb_typeof(p_actor) IS DISTINCT FROM 'object'
       OR NOT (p_actor ?& ARRAY[
           'schema_version','record_type','tenant_id','actor_id','session_id',
           'auth','roles','capabilities','trust_level','scope_authority',
           'issued_at','expires_at','correlation_id'
       ])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(p_actor) AS fields(field)
           WHERE field <> ALL(ARRAY[
               'schema_version','record_type','tenant_id','actor_id','session_id',
               'auth','roles','capabilities','trust_level','scope_authority',
               'issued_at','expires_at','correlation_id','extensions'
           ])
       )
       OR p_actor->>'schema_version' IS DISTINCT FROM '1.0'
       OR p_actor->>'record_type' IS DISTINCT FROM 'actor_context'
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_each(p_actor) AS values(field,value)
           WHERE field = ANY(ARRAY[
               'schema_version','record_type','tenant_id','actor_id','session_id',
               'trust_level','issued_at','expires_at','correlation_id'
           ]) AND pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string'
       )
       OR p_actor->>'tenant_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_actor->>'actor_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_actor->>'session_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_actor->>'correlation_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR p_actor->>'trust_level' NOT IN (
           'verified_human','verified_service','delegated_service','restricted_automation'
       )
       OR pg_catalog.jsonb_typeof(p_actor->'roles') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(p_actor->'capabilities') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(p_actor->'auth') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_actor->'scope_authority') IS DISTINCT FROM 'object'
       OR (p_actor ? 'extensions' AND pg_catalog.jsonb_typeof(p_actor->'extensions') IS DISTINCT FROM 'object')
    THEN
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_actor->'roles') AS value
        WHERE pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string'
           OR value #>> '{}' !~ '^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_actor->'capabilities') AS value
        WHERE pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string'
           OR value #>> '{}' !~ '^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$'
    ) THEN
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    auth := p_actor->'auth';
    scope := p_actor->'scope_authority';
    IF NOT (auth ?& ARRAY['issuer','method','assurance_level','verified_at'])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(auth) AS fields(field)
           WHERE field <> ALL(ARRAY['issuer','method','assurance_level','verified_at'])
       )
       OR pg_catalog.jsonb_typeof(auth->'issuer') IS DISTINCT FROM 'string'
       OR auth->>'issuer' !~ '^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$'
       OR pg_catalog.jsonb_typeof(auth->'method') IS DISTINCT FROM 'string'
       OR auth->>'method' NOT IN (
           'federated','service_credential','session_credential','hardware_assertion'
       )
       OR pg_catalog.jsonb_typeof(auth->'assurance_level') IS DISTINCT FROM 'number'
       OR (auth->>'assurance_level') !~ '^[1-4]$'
       OR pg_catalog.jsonb_typeof(auth->'verified_at') IS DISTINCT FROM 'string'
       OR auth->>'verified_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR NOT pg_catalog.pg_input_is_valid(auth->>'verified_at', 'timestamp with time zone')
       OR NOT (scope ?& ARRAY['allowed_levels','public_allowed'])
       OR EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_object_keys(scope) AS fields(field)
           WHERE field <> ALL(ARRAY[
               'allowed_levels','public_allowed','user_id','team_ids','organization_ids',
               'project_ids','workspace_ids'
           ])
       )
       OR pg_catalog.jsonb_typeof(scope->'allowed_levels') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(scope->'allowed_levels') = 0
       OR pg_catalog.jsonb_typeof(scope->'public_allowed') IS DISTINCT FROM 'boolean'
       OR (scope ? 'user_id' AND (
           pg_catalog.jsonb_typeof(scope->'user_id') IS DISTINCT FROM 'string'
           OR scope->>'user_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       ))
    THEN
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(scope->'allowed_levels') AS value
        WHERE pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string'
           OR value #>> '{}' NOT IN ('actor','user','session','workspace','project','team','organization')
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_each(scope) AS entries(key,value)
        WHERE key = ANY(ARRAY['team_ids','organization_ids','project_ids','workspace_ids'])
          AND (
              pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'array'
              OR pg_catalog.jsonb_array_length(value) = 0
              OR EXISTS (
                  SELECT 1 FROM pg_catalog.jsonb_array_elements(value) AS item
                  WHERE pg_catalog.jsonb_typeof(item) IS DISTINCT FROM 'string'
                     OR item #>> '{}' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
              )
          )
    ) THEN
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    IF p_actor->>'issued_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR p_actor->>'expires_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR NOT pg_catalog.pg_input_is_valid(p_actor->>'issued_at', 'timestamp with time zone')
       OR NOT pg_catalog.pg_input_is_valid(p_actor->>'expires_at', 'timestamp with time zone')
       OR (p_actor->>'issued_at')::timestamptz > (p_actor->>'expires_at')::timestamptz
       OR (p_actor->>'issued_at')::timestamptz > pg_catalog.clock_timestamp()
       OR (p_actor->>'expires_at')::timestamptz <= pg_catalog.clock_timestamp()
    THEN
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.gah_runtime_principals
        WHERE database_role = session_user
          AND tenant_id = p_actor->>'tenant_id'
          AND actor_id = p_actor->>'actor_id'
    ) THEN
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    PERFORM pg_catalog.set_config('gah.tenant_id', p_actor->>'tenant_id', true);
    PERFORM pg_catalog.set_config('gah.actor_id', p_actor->>'actor_id', true);
END
$function$;
ALTER FUNCTION gah_skill_assert_actor(jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_skill_assert_actor(jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer, gah_execution_admission_authority;

ALTER FUNCTION gah_verify_lifecycle_approvals(jsonb,timestamptz,boolean)
    RENAME TO gah_verify_lifecycle_approvals_0016;
ALTER FUNCTION gah_verify_lifecycle_approvals_0016(jsonb,timestamptz,boolean)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_verify_lifecycle_approvals_0016(jsonb,timestamptz,boolean)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_verify_lifecycle_approvals(
    p_command jsonb, p_accepted_at timestamptz, p_historical boolean
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    policy jsonb := p_command->'policy_decision';
    policy_decided_at timestamptz;
BEGIN
    IF pg_catalog.jsonb_typeof(policy) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(policy->'constraints') IS DISTINCT FROM 'array'
       OR policy->'constraints' IS DISTINCT FROM '[]'::jsonb
       OR pg_catalog.jsonb_typeof(policy->'decided_at') IS DISTINCT FROM 'string'
       OR policy->>'decided_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR NOT pg_catalog.pg_input_is_valid(
           policy->>'decided_at', 'timestamp with time zone'
       )
    THEN
        RAISE EXCEPTION 'lifecycle policy authority shape is invalid';
    END IF;
    policy_decided_at := (policy->>'decided_at')::timestamptz;
    IF policy_decided_at > p_accepted_at THEN
        RAISE EXCEPTION 'lifecycle policy decision is after its acceptance time';
    END IF;
    PERFORM public.gah_verify_lifecycle_approvals_0016(
        p_command, p_accepted_at, p_historical
    );
END
$function$;
ALTER FUNCTION gah_verify_lifecycle_approvals(jsonb,timestamptz,boolean)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_verify_lifecycle_approvals(jsonb,timestamptz,boolean)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

DO $preflight_lifecycle_policy_bounds$
DECLARE
    transition_row record;
BEGIN
    FOR transition_row IN
        SELECT command_json, (evidence_json->>'recorded_at')::timestamptz AS recorded_at
          FROM public.gah_skill_lifecycle_transitions
         ORDER BY tenant_id, actor_id, skill_id, transition_sequence
    LOOP
        IF pg_catalog.jsonb_typeof(transition_row.command_json) IS DISTINCT FROM 'object'
        THEN
            RAISE EXCEPTION 'persisted lifecycle authority row is invalid';
        END IF;
        PERFORM public.gah_verify_lifecycle_approvals(
            transition_row.command_json, transition_row.recorded_at, true
        );
    END LOOP;
END
$preflight_lifecycle_policy_bounds$;
