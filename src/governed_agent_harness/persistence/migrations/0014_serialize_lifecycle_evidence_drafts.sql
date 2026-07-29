-- A lifecycle transition drafts evidence from an authoritative run head and
-- subsequently commits that same head.  Serialize that draft/apply interval
-- in the one global order used by lifecycle rebuilds: operation, actor/skill,
-- then the authoritative actor/session run reservation.
-- This helper is deliberately narrower than a lifecycle entrypoint: it cannot
-- rebuild or append evidence.  It performs no DML before full-wire and live
-- writer-authorization validation.  A missing run head remains a read-only
-- canonical zero snapshot until the paired lifecycle apply commits evidence.
-- The forced-RLS head table previously exposed only actor-filtered rows even
-- to its NOLOGIN owner, making a read-only foreign-actor collision check
-- impossible.  Owner visibility is confined to SECURITY DEFINER functions
-- whose execute ACLs remain explicitly narrow.
CREATE POLICY gah_run_heads_schema_owner ON gah_run_heads
    TO gah_schema_owner USING (true) WITH CHECK (true);

CREATE FUNCTION gah_lock_skill_lifecycle_draft(
    p_actor jsonb, p_command jsonb, p_expected_operation text,
    p_writer_authorization jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    v_tenant text;
    v_actor text;
    v_skill text;
    v_run_id text;
    v_scope jsonb;
    v_head jsonb;
    v_replay jsonb;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF NOT pg_catalog.pg_has_role(
           session_user, 'gah_skill_lifecycle_authority', 'MEMBER'
       )
       OR pg_catalog.pg_has_role(session_user, 'gah_authority_writer', 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, 'gah_runtime', 'MEMBER')
       OR pg_catalog.pg_has_role(
           session_user, 'gah_execution_admission_authority', 'MEMBER'
       )
    THEN
        RAISE EXCEPTION 'lifecycle evidence draft lock requires lifecycle authority';
    END IF;
    IF p_expected_operation NOT IN ('install', 'activate', 'rollback', 'deactivate')
       OR pg_catalog.jsonb_typeof(p_command) IS DISTINCT FROM 'object'
       OR p_command ? 'transition_evidence'
       OR p_command->>'operation' IS DISTINCT FROM p_expected_operation
       OR p_command->>'operation_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_command - 'operation_digest')
       OR pg_catalog.jsonb_typeof(p_command->'operation_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_command->'skill_proposal') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(
            p_command #> '{skill_proposal,artifact_id}'
          ) IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(
            p_command #> '{skill_proposal,target_scope}'
          ) IS DISTINCT FROM 'object'
       OR coalesce(
            (SELECT array_agg(key ORDER BY key)
               FROM pg_catalog.jsonb_object_keys(p_command) AS keys(key)),
            ARRAY[]::text[]
          ) IS DISTINCT FROM ARRAY[
              'activation_receipt', 'approvals', 'artifact', 'delivery_envelope',
              'expected_revision', 'gate_decision', 'operation', 'operation_digest',
              'operation_id', 'policy_decision', 'retention', 'rollback_receipt',
              'skill_proposal', 'source_evidence', 'validity'
          ]
       OR pg_catalog.jsonb_typeof(p_command->'artifact') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_command->'gate_decision') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_command->'delivery_envelope') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_command->'policy_decision') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_command->'approvals') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(p_command->'source_evidence') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(p_command->'retention') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_command->'validity') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_command->'expected_revision') NOT IN ('null', 'number')
       OR pg_catalog.jsonb_typeof(p_command->'activation_receipt') NOT IN ('null', 'object')
       OR pg_catalog.jsonb_typeof(p_command->'rollback_receipt') NOT IN ('null', 'object')
    THEN
        RAISE EXCEPTION 'lifecycle evidence draft lock command is malformed';
    END IF;
    v_tenant := p_actor->>'tenant_id';
    v_actor := p_actor->>'actor_id';
    v_skill := p_command #>> '{skill_proposal,artifact_id}';
    v_run_id := p_actor->>'session_id';
    v_scope := p_command #> '{skill_proposal,target_scope}';
    IF pg_catalog.btrim(v_tenant) = '' OR pg_catalog.btrim(v_actor) = ''
       OR pg_catalog.btrim(v_skill) = ''
       OR pg_catalog.btrim(v_run_id) = ''
       OR pg_catalog.btrim(p_command->>'operation_id') = ''
       OR p_command #>> '{skill_proposal,tenant_id}' IS DISTINCT FROM v_tenant
       OR v_scope->>'actor_id' IS DISTINCT FROM v_actor
       OR v_scope->'selection' IS DISTINCT FROM '{"level":"actor"}'::jsonb
       OR v_scope->>'parent_digest' IS DISTINCT FROM public.gah_canonical_sha256(p_actor)
       OR p_command #>> '{skill_proposal,artifact_revision}' !~ '^[1-9][0-9]{0,8}$'
       OR p_command #>> '{delivery_envelope,artifact_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR public.gah_skill_lifecycle_sink_command_valid(
            v_tenant,
            v_actor,
            v_skill,
            (p_command #>> '{skill_proposal,artifact_revision}')::integer,
            p_command #>> '{delivery_envelope,artifact_digest}',
            p_command
          ) IS NOT TRUE
    THEN
        RAISE EXCEPTION 'lifecycle evidence draft lock binding is invalid';
    END IF;
    -- This exact actor-scoped operation key is acquired first by projection
    -- rebuilds and by lifecycle replay lookup.  Taking it here before S keeps
    -- same-operation mutation/rebuild contention out of an inverse cycle.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill-operation:' || v_tenant || ':' || v_actor || ':' ||
            (p_command->>'operation_id'), 0
    ));
    -- Fail a pre-existing cross-actor run collision before stale-state replay
    -- handling can return.  The same check is repeated under R below to close
    -- the read/lock race.
    IF EXISTS (
        SELECT 1
          FROM public.gah_run_heads AS collision
         WHERE collision.tenant_id = v_tenant
           AND collision.run_id = v_run_id
           AND collision.actor_id IS DISTINCT FROM v_actor
    ) THEN
        RAISE EXCEPTION 'run scope conflicts with an existing actor';
    END IF;
    -- The writer has already acquired its canonical cross-session commitment
    -- locks.  Assert that exact live authorization only after O, so this
    -- helper's reentrant S acquisition remains O -> S rather than S -> O.
    BEGIN
        PERFORM public.gah_skill_assert_writer_authorization(
            p_actor, p_command, p_writer_authorization
        );
    EXCEPTION WHEN raise_exception THEN
        -- Two exact callers can have independently live writer commitments
        -- from the same pre-transition state.  Once the O holder commits,
        -- only the exact immutable replay is allowed to bypass the now-stale
        -- state snapshot; malformed, changed, missing, or dead authorizations
        -- still re-raise without touching the run head.
        IF SQLERRM <> 'skill lifecycle authorized state is stale' THEN
            RAISE;
        END IF;
        v_replay := public.gah_lookup_skill_replay(p_actor, p_command);
        IF v_replay IS NULL
           OR pg_catalog.jsonb_typeof(v_replay) IS DISTINCT FROM 'object'
        THEN
            RAISE;
        END IF;
        RETURN NULL;
    END;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill:' || v_tenant || ':' || v_actor || ':' || v_skill, 0
    ));
    -- Reserve this exact actor/session before reading its authoritative head.
    -- The writer-only public head and evidence entrypoints take the identical
    -- lock, so neither can race this draft with a missing-head insert or append.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'lifecycle-run:' || v_tenant || ':' || v_actor || ':' || v_run_id, 0
    ));
    SELECT pg_catalog.jsonb_build_object(
               'next_sequence', head.next_sequence,
               'last_event_digest', head.last_event_digest,
               'last_recorded_at', head.last_recorded_at,
               'version', head.version
           )
      INTO v_head
      FROM public.gah_run_heads AS head
     WHERE head.tenant_id = v_tenant
       AND head.run_id = v_run_id
       AND head.actor_id = v_actor;
    IF v_head IS NULL THEN
        IF EXISTS (
            SELECT 1
              FROM public.gah_run_heads AS collision
             WHERE collision.tenant_id = v_tenant
               AND collision.run_id = v_run_id
        ) THEN
            RAISE EXCEPTION 'run scope conflicts with an existing actor';
        END IF;
        v_head := pg_catalog.jsonb_build_object(
            'next_sequence', 0,
            'last_event_digest', NULL,
            'last_recorded_at', NULL,
            'version', 0
        );
    END IF;
    IF v_head IS NULL
       OR pg_catalog.jsonb_typeof(v_head) IS DISTINCT FROM 'object'
       OR coalesce(
            (SELECT array_agg(key ORDER BY key)
               FROM pg_catalog.jsonb_object_keys(v_head) AS keys(key)),
            ARRAY[]::text[]
          ) IS DISTINCT FROM ARRAY[
              'last_event_digest', 'last_recorded_at', 'next_sequence', 'version'
          ]
       OR v_head->>'next_sequence' !~ '^[0-9]+$'
       OR v_head->>'version' !~ '^[0-9]+$'
       OR pg_catalog.jsonb_typeof(v_head->'last_event_digest') NOT IN ('null', 'string')
       OR pg_catalog.jsonb_typeof(v_head->'last_recorded_at') NOT IN ('null', 'string')
       OR (
            pg_catalog.jsonb_typeof(v_head->'last_event_digest') = 'string'
            AND v_head->>'last_event_digest' !~ '^sha256:[0-9a-f]{64}$'
          )
    THEN
        RAISE EXCEPTION 'lifecycle evidence draft run head is malformed';
    END IF;
    RETURN NULL;
END
$function$;

ALTER FUNCTION gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb)
    TO gah_skill_lifecycle_authority;

-- Generic evidence writers must join the exact lifecycle run reservation.
-- Keep this lock out of the broad internal writer because specialized atomic
-- authority paths own distinct lock graphs.
CREATE OR REPLACE FUNCTION gah_lock_run(p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    v_run_id text;
BEGIN
    IF pg_catalog.jsonb_typeof(p_actor) IS DISTINCT FROM 'object'
       OR (
            p_actor ? 'record_type'
            AND p_actor->>'record_type' IS DISTINCT FROM 'actor_context'
          )
       OR pg_catalog.jsonb_typeof(p_actor->'tenant_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_actor->'actor_id') IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(p_actor->>'tenant_id') = ''
       OR pg_catalog.btrim(p_actor->>'actor_id') = ''
       OR pg_catalog.jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
       OR coalesce(
            (SELECT array_agg(key ORDER BY key)
               FROM pg_catalog.jsonb_object_keys(p_payload) AS keys(key)),
            ARRAY[]::text[]
          ) IS DISTINCT FROM ARRAY['run_id']
       OR pg_catalog.jsonb_typeof(p_payload->'run_id') IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(p_payload->>'run_id') = ''
    THEN
        RAISE EXCEPTION 'run lock binding is invalid';
    END IF;
    v_run_id := p_payload->>'run_id';
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'lifecycle-run:' || (p_actor->>'tenant_id') || ':' ||
            (p_actor->>'actor_id') || ':' || v_run_id, 0
    ));
    RETURN public.gah_authority_write_internal('lock_run', p_actor, p_payload);
END
$function$;

ALTER FUNCTION gah_lock_run(jsonb,jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_lock_run(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_lock_run(jsonb,jsonb) TO gah_authority_writer;

-- Commit can be called without a preceding public head lock, so it validates
-- and acquires the same reservation independently and reentrantly.
CREATE OR REPLACE FUNCTION gah_commit_evidence(p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    v_envelope jsonb := p_payload->'envelope';
    v_run_id text;
BEGIN
    IF pg_catalog.jsonb_typeof(p_actor) IS DISTINCT FROM 'object'
       OR (
            p_actor ? 'record_type'
            AND p_actor->>'record_type' IS DISTINCT FROM 'actor_context'
          )
       OR pg_catalog.jsonb_typeof(p_actor->'tenant_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_actor->'actor_id') IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(p_actor->>'tenant_id') = ''
       OR pg_catalog.btrim(p_actor->>'actor_id') = ''
       OR pg_catalog.jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
       OR coalesce(
            (SELECT array_agg(key ORDER BY key)
               FROM pg_catalog.jsonb_object_keys(p_payload) AS keys(key)),
            ARRAY[]::text[]
          ) IS DISTINCT FROM ARRAY['envelope', 'expected_version', 'run_id']
       OR pg_catalog.jsonb_typeof(p_payload->'envelope') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_payload->'run_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_payload->'expected_version') IS DISTINCT FROM 'number'
       OR p_payload->>'expected_version' !~ '^[0-9]+$'
       OR pg_catalog.btrim(p_payload->>'run_id') = ''
       OR v_envelope->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR v_envelope #>> '{draft,run_id}' IS DISTINCT FROM p_payload->>'run_id'
       OR v_envelope #>> '{draft,inline_payload,actor_id}'
            IS DISTINCT FROM p_actor->>'actor_id'
    THEN
        RAISE EXCEPTION 'evidence commit binding is invalid';
    END IF;
    IF v_envelope #>> '{draft,event_kind}' IN (
        'skill.lifecycle_transition',
        'execution.authorization_issued',
        'execution.intent',
        'execution.outcome'
    ) THEN
        RAISE EXCEPTION 'reserved evidence event kind requires its specialized writer';
    END IF;
    v_run_id := p_payload->>'run_id';
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'lifecycle-run:' || (p_actor->>'tenant_id') || ':' ||
            (p_actor->>'actor_id') || ':' || v_run_id, 0
    ));
    RETURN public.gah_authority_write_internal('commit_evidence', p_actor, p_payload);
END
$function$;

ALTER FUNCTION gah_commit_evidence(jsonb,jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_commit_evidence(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_commit_evidence(jsonb,jsonb) TO gah_authority_writer;

-- Consumption must not lock the active projection before joining the
-- operation lock already held by issuance.  Preserve the fully validating
-- implementation privately; this wrapper establishes E -> S and the old body
-- then takes E reentrantly before state -> active projection -> evidence head.
ALTER FUNCTION gah_begin_builtin_execution(
    jsonb, jsonb, jsonb, double precision
) RENAME TO gah_begin_builtin_execution_validated;

ALTER FUNCTION gah_begin_builtin_execution_validated(
    jsonb, jsonb, jsonb, double precision
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_begin_builtin_execution_validated(
    jsonb, jsonb, jsonb, double precision
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_begin_builtin_execution(
    p_actor jsonb, p_authorization jsonb, p_intent jsonb,
    p_lease_seconds double precision
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    v_tenant text;
    v_actor text;
    v_operation text;
    v_skill text;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    IF NOT pg_catalog.pg_has_role(session_user, 'gah_runtime', 'MEMBER')
       OR pg_catalog.jsonb_typeof(p_authorization) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_authorization->'operation_id')
            IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_authorization->'command')
            IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_authorization#>'{command,skill_id}')
            IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION 'execution consume lock inputs are malformed';
    END IF;
    v_tenant := p_actor->>'tenant_id';
    v_actor := p_actor->>'actor_id';
    v_operation := p_authorization->>'operation_id';
    v_skill := p_authorization#>>'{command,skill_id}';
    IF pg_catalog.btrim(v_tenant) = ''
       OR pg_catalog.btrim(v_actor) = ''
       OR pg_catalog.btrim(v_operation) = ''
       OR pg_catalog.btrim(v_skill) = ''
       OR p_authorization#>>'{command,operation_id}' IS DISTINCT FROM v_operation
    THEN
        RAISE EXCEPTION 'execution consume lock inputs are malformed';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'execution:operation:' || v_tenant || ':' || v_operation, 0
    ));
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill:' || v_tenant || ':' || v_actor || ':' || v_skill, 0
    ));
    RETURN public.gah_begin_builtin_execution_validated(
        p_actor, p_authorization, p_intent, p_lease_seconds
    );
END
$function$;

ALTER FUNCTION gah_begin_builtin_execution(
    jsonb, jsonb, jsonb, double precision
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_begin_builtin_execution(
    jsonb, jsonb, jsonb, double precision
) FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
    gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_begin_builtin_execution(
    jsonb, jsonb, jsonb, double precision
) TO gah_runtime;
