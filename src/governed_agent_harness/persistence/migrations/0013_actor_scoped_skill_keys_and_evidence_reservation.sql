-- Phase 5.1 review hardening: lifecycle state is actor-scoped even when
-- multiple actors in one tenant select the same preinstalled built-in skill.
-- Existing keys prevented such rows from coexisting.  The old shape therefore
-- cannot contain an ambiguous cross-actor collision; nonetheless, reject any
-- row whose durable command no longer agrees with its actor before changing
-- the authoritative ledger schema.
DO $migration_guard$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.gah_skill_artifact_revisions
         WHERE actor_id IS NULL
            OR command_json #>> '{skill_proposal,target_scope,actor_id}'
                   IS DISTINCT FROM actor_id
    ) OR EXISTS (
        SELECT 1
          FROM public.gah_skill_lifecycle_transitions
         WHERE actor_id IS NULL
            OR command_json #>> '{skill_proposal,target_scope,actor_id}'
                   IS DISTINCT FROM actor_id
    ) THEN
        RAISE EXCEPTION 'cannot migrate ambiguous skill lifecycle actor bindings';
    END IF;
END
$migration_guard$;

-- Drop only key constraints.  Foreign keys must go first; their replacement
-- includes actor_id so a transition and projection can reference only that
-- actor's immutable artifact revision.
DO $keys$
DECLARE constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_catalog.pg_constraint
         WHERE conrelid = 'public.gah_active_skill_projection'::regclass
           AND contype = 'f'
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER TABLE public.gah_active_skill_projection DROP CONSTRAINT %I', constraint_name);
    END LOOP;
    FOR constraint_name IN
        SELECT conname FROM pg_catalog.pg_constraint
         WHERE conrelid = 'public.gah_skill_lifecycle_transitions'::regclass
           AND contype = 'f'
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER TABLE public.gah_skill_lifecycle_transitions DROP CONSTRAINT %I', constraint_name);
    END LOOP;
    FOR constraint_name IN
        SELECT conname FROM pg_catalog.pg_constraint
         WHERE conrelid IN (
             'public.gah_skill_artifact_revisions'::regclass,
             'public.gah_skill_lifecycle_transitions'::regclass,
             'public.gah_active_skill_projection'::regclass,
             'public.gah_skill_projection_rebuilds'::regclass
         ) AND contype IN ('p', 'u')
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER TABLE %s DROP CONSTRAINT %I',
            (SELECT conrelid::regclass FROM pg_catalog.pg_constraint WHERE conname = constraint_name LIMIT 1),
            constraint_name);
    END LOOP;
END
$keys$;

ALTER TABLE public.gah_skill_artifact_revisions
    ADD CONSTRAINT gah_skill_artifact_revisions_actor_pkey
        PRIMARY KEY (tenant_id, actor_id, skill_id, revision),
    ADD CONSTRAINT gah_skill_artifact_revisions_actor_proposal_key
        UNIQUE (tenant_id, actor_id, proposal_id);

ALTER TABLE public.gah_skill_lifecycle_transitions
    ADD CONSTRAINT gah_skill_lifecycle_transitions_actor_pkey
        PRIMARY KEY (tenant_id, actor_id, skill_id, transition_sequence),
    ADD CONSTRAINT gah_skill_lifecycle_transitions_actor_operation_id_key
        UNIQUE (tenant_id, actor_id, operation_id),
    ADD CONSTRAINT gah_skill_lifecycle_transitions_actor_operation_digest_key
        UNIQUE (tenant_id, actor_id, operation_digest),
    ADD CONSTRAINT gah_skill_lifecycle_transitions_actor_artifact_fkey
        FOREIGN KEY (tenant_id, actor_id, skill_id, target_revision)
        REFERENCES public.gah_skill_artifact_revisions
            (tenant_id, actor_id, skill_id, revision);

ALTER TABLE public.gah_active_skill_projection
    ADD CONSTRAINT gah_active_skill_projection_actor_pkey
        PRIMARY KEY (tenant_id, actor_id, skill_id),
    ADD CONSTRAINT gah_active_skill_projection_actor_artifact_fkey
        FOREIGN KEY (tenant_id, actor_id, skill_id, revision)
        REFERENCES public.gah_skill_artifact_revisions
            (tenant_id, actor_id, skill_id, revision);

ALTER TABLE public.gah_skill_projection_rebuilds
    ADD CONSTRAINT gah_skill_projection_rebuilds_actor_pkey
        PRIMARY KEY (tenant_id, actor_id, operation_id),
    ADD CONSTRAINT gah_skill_projection_rebuilds_actor_operation_digest_key
        UNIQUE (tenant_id, actor_id, operation_digest);

-- All lifecycle entrypoints call gah_skill_assert_actor before they query one
-- of these tables.  Rebuild their SQL definitions with actor-qualified keys
-- and lock names.  The guards make this append-only migration fail closed if a
-- preceding migration has changed a source shape unexpectedly.
DO $rewrite_lookup$
DECLARE definition text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_lookup_skill_replay(jsonb,jsonb)'::regprocedure
    ) INTO definition;
    IF position('''skill-operation:'' || (p_actor ->> ''tenant_id'') || '':'' || (p_command ->> ''operation_id'')' IN definition) = 0
       OR position('WHERE tenant_id=p_actor->>''tenant_id'' AND operation_id=p_command->>''operation_id''' IN definition) = 0
       OR position('WHERE tenant_id=p_actor->>''tenant_id'' AND skill_id=v_existing.skill_id' IN definition) = 0 THEN
        RAISE EXCEPTION 'cannot actor-scope lifecycle replay function';
    END IF;
    definition := replace(definition,
        '''skill-operation:'' || (p_actor ->> ''tenant_id'') || '':'' || (p_command ->> ''operation_id'')',
        '''skill-operation:'' || (p_actor ->> ''tenant_id'') || '':'' || (p_actor ->> ''actor_id'') || '':'' || (p_command ->> ''operation_id'')');
    definition := replace(definition,
        'WHERE tenant_id=p_actor->>''tenant_id'' AND operation_id=p_command->>''operation_id''',
        'WHERE tenant_id=p_actor->>''tenant_id'' AND actor_id=p_actor->>''actor_id'' AND operation_id=p_command->>''operation_id''');
    definition := replace(definition,
        'WHERE tenant_id=p_actor->>''tenant_id'' AND skill_id=v_existing.skill_id',
        'WHERE tenant_id=p_actor->>''tenant_id'' AND actor_id=p_actor->>''actor_id'' AND skill_id=v_existing.skill_id');
    EXECUTE definition;
END
$rewrite_lookup$;

DO $rewrite_validated_apply$
DECLARE definition text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_apply_skill_lifecycle_validated(jsonb,jsonb,text)'::regprocedure
    ) INTO definition;
    IF position('''skill:'' || v_tenant || '':'' || v_skill' IN definition) = 0
       OR position('WHERE tenant_id = v_tenant AND operation_id = v_operation_id' IN definition) = 0
       OR position('ON CONFLICT (tenant_id,skill_id)' IN definition) = 0 THEN
        RAISE EXCEPTION 'cannot actor-scope validated lifecycle apply function';
    END IF;
    definition := replace(definition,
        '''skill:'' || v_tenant || '':'' || v_skill',
        '''skill:'' || v_tenant || '':'' || v_actor || '':'' || v_skill');
    definition := replace(definition,
        'WHERE tenant_id = v_tenant AND operation_id = v_operation_id',
        'WHERE tenant_id = v_tenant AND actor_id = v_actor AND operation_id = v_operation_id');
    definition := replace(definition,
        'WHERE tenant_id=v_tenant AND skill_id=v_skill',
        'WHERE tenant_id=v_tenant AND actor_id=v_actor AND skill_id=v_skill');
    definition := replace(definition,
        'ON CONFLICT (tenant_id,skill_id)',
        'ON CONFLICT (tenant_id,actor_id,skill_id)');
    EXECUTE definition;
END
$rewrite_validated_apply$;

DO $rewrite_validated_rebuild$
DECLARE definition text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_rebuild_skill_projection_validated(jsonb,jsonb)'::regprocedure
    ) INTO definition;
    IF position('''skill-operation:'' || v_tenant || '':'' || (p_command->>''operation_id'')' IN definition) = 0
       OR position('WHERE tenant_id=v_tenant AND operation_id=p_command->>''operation_id''' IN definition) = 0
       OR position('''skill:'' || v_tenant || '':'' || v_skill' IN definition) = 0 THEN
        RAISE EXCEPTION 'cannot actor-scope validated lifecycle rebuild function';
    END IF;
    definition := replace(definition,
        '''skill-operation:'' || v_tenant || '':'' || (p_command->>''operation_id'')',
        '''skill-operation:'' || v_tenant || '':'' || v_actor || '':'' || (p_command->>''operation_id'')');
    definition := replace(definition,
        'WHERE tenant_id=v_tenant AND operation_id=p_command->>''operation_id''',
        'WHERE tenant_id=v_tenant AND actor_id=v_actor AND operation_id=p_command->>''operation_id''');
    definition := replace(definition,
        '''skill:'' || v_tenant || '':'' || v_skill',
        '''skill:'' || v_tenant || '':'' || v_actor || '':'' || v_skill');
    definition := replace(definition,
        'WHERE tenant_id=v_tenant AND skill_id=v_skill',
        'WHERE tenant_id=v_tenant AND actor_id=v_actor AND skill_id=v_skill');
    EXECUTE definition;
END
$rewrite_validated_rebuild$;

DO $rewrite_authorize$
DECLARE definition text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_authorize_skill_lifecycle(jsonb,jsonb)'::regprocedure
    ) INTO definition;
    IF position('WHERE tenant_id = p_actor->>''tenant_id''' IN definition) = 0 THEN
        RAISE EXCEPTION 'cannot actor-scope lifecycle writer authorization function';
    END IF;
    definition := replace(definition,
        'WHERE tenant_id = p_actor->>''tenant_id''' || chr(10)
            || '       AND skill_id = p_command #>> ''{skill_proposal,artifact_id}''',
        'WHERE tenant_id = p_actor->>''tenant_id''' || chr(10)
            || '       AND actor_id = p_actor->>''actor_id''' || chr(10)
            || '       AND skill_id = p_command #>> ''{skill_proposal,artifact_id}''');
    IF position('WHERE tenant_id = p_actor->>''tenant_id''' || chr(10)
                    || '       AND actor_id = p_actor->>''actor_id''' || chr(10)
                    || '       AND skill_id = p_command #>> ''{skill_proposal,artifact_id}''' IN definition) = 0 THEN
        RAISE EXCEPTION 'lifecycle writer authorization query did not become actor-scoped';
    END IF;
    EXECUTE definition;
END
$rewrite_authorize$;

DO $rewrite_writer_assertion$
DECLARE definition text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_skill_assert_writer_authorization(jsonb,jsonb,jsonb)'::regprocedure
    ) INTO definition;
    IF position('''skill:'' || (p_actor->>''tenant_id'') || '':'' || (p_command #>> ''{skill_proposal,artifact_id}'')' IN definition) = 0
       OR position('WHERE tenant_id = p_actor->>''tenant_id''' IN definition) = 0 THEN
        RAISE EXCEPTION 'cannot actor-scope lifecycle writer assertion function';
    END IF;
    definition := replace(definition,
        '''skill:'' || (p_actor->>''tenant_id'') || '':'' || (p_command #>> ''{skill_proposal,artifact_id}'')',
        '''skill:'' || (p_actor->>''tenant_id'') || '':'' || (p_actor->>''actor_id'') || '':'' || (p_command #>> ''{skill_proposal,artifact_id}'')');
    definition := replace(definition,
        'WHERE tenant_id = p_actor->>''tenant_id''' || chr(10)
            || '       AND skill_id = p_command #>> ''{skill_proposal,artifact_id}''',
        'WHERE tenant_id = p_actor->>''tenant_id''' || chr(10)
            || '       AND actor_id = p_actor->>''actor_id''' || chr(10)
            || '       AND skill_id = p_command #>> ''{skill_proposal,artifact_id}''');
    IF position('WHERE tenant_id = p_actor->>''tenant_id''' || chr(10)
                    || '       AND actor_id = p_actor->>''actor_id''' || chr(10)
                    || '       AND skill_id = p_command #>> ''{skill_proposal,artifact_id}''' IN definition) = 0 THEN
        RAISE EXCEPTION 'lifecycle writer assertion query did not become actor-scoped';
    END IF;
    EXECUTE definition;
END
$rewrite_writer_assertion$;

DO $rewrite_apply_entrypoint$
DECLARE definition text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_apply_skill_lifecycle(jsonb,jsonb,text)'::regprocedure
    ) INTO definition;
    IF position('WHERE tenant_id = p_actor ->> ''tenant_id''' IN definition) = 0 THEN
        RAISE EXCEPTION 'cannot actor-scope lifecycle apply entrypoint';
    END IF;
    definition := replace(definition,
        'WHERE tenant_id = p_actor ->> ''tenant_id''' || chr(10)
            || '           AND operation_id = p_command ->> ''operation_id''',
        'WHERE tenant_id = p_actor ->> ''tenant_id''' || chr(10)
            || '           AND actor_id = p_actor ->> ''actor_id''' || chr(10)
            || '           AND operation_id = p_command ->> ''operation_id''');
    IF position('WHERE tenant_id = p_actor ->> ''tenant_id''' || chr(10)
                    || '           AND actor_id = p_actor ->> ''actor_id''' || chr(10)
                    || '           AND operation_id = p_command ->> ''operation_id''' IN definition) = 0 THEN
        RAISE EXCEPTION 'lifecycle apply replay query did not become actor-scoped';
    END IF;
    EXECUTE definition;
END
$rewrite_apply_entrypoint$;

-- Lifecycle mutation and execution issuance acquire the same actor-scoped
-- skill lock before either can lock the active projection.  The original
-- issuer is preserved as a private implementation so its validation body does
-- not have to be duplicated in this migration.
ALTER FUNCTION gah_issue_builtin_execution_authorization(
    jsonb, jsonb, jsonb, jsonb, jsonb
) RENAME TO gah_issue_builtin_execution_authorization_locked;

ALTER FUNCTION gah_issue_builtin_execution_authorization_locked(
    jsonb, jsonb, jsonb, jsonb, jsonb
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_issue_builtin_execution_authorization_locked(
    jsonb, jsonb, jsonb, jsonb, jsonb
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_issue_builtin_execution_authorization(
    p_actor jsonb, p_command jsonb, p_grant jsonb, p_evidence jsonb,
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
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    IF NOT pg_catalog.pg_has_role(
           session_user, 'gah_execution_admission_authority', 'MEMBER'
       ) THEN
        RAISE EXCEPTION 'execution authorization requires admission authority';
    END IF;
    IF pg_catalog.jsonb_typeof(p_command) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_actor->'tenant_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_actor->'actor_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_command->'skill_id') IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION 'execution authorization skill lock inputs are malformed';
    END IF;
    v_tenant := p_actor->>'tenant_id';
    v_actor := p_actor->>'actor_id';
    v_skill := p_command->>'skill_id';
    IF pg_catalog.btrim(v_tenant) = '' OR pg_catalog.btrim(v_actor) = ''
       OR pg_catalog.btrim(v_skill) = '' THEN
        RAISE EXCEPTION 'execution authorization skill lock inputs are malformed';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill:' || v_tenant || ':' || v_actor || ':' || v_skill, 0
    ));
    RETURN public.gah_issue_builtin_execution_authorization_locked(
        p_actor, p_command, p_grant, p_evidence, p_writer_authorization
    );
END
$function$;

ALTER FUNCTION gah_issue_builtin_execution_authorization(
    jsonb, jsonb, jsonb, jsonb, jsonb
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_issue_builtin_execution_authorization(
    jsonb, jsonb, jsonb, jsonb, jsonb
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_issue_builtin_execution_authorization(
    jsonb, jsonb, jsonb, jsonb, jsonb
) TO gah_execution_admission_authority;

-- Only the lifecycle authority's private, command-bound sink may append this
-- event kind.  The generic authority writer remains available for unrelated
-- evidence kinds.
CREATE OR REPLACE FUNCTION gah_commit_evidence(p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    IF p_payload #>> '{envelope,draft,event_kind}' IN (
        'skill.lifecycle_transition',
        'execution.authorization_issued',
        'execution.intent',
        'execution.outcome'
    ) THEN
        RAISE EXCEPTION 'reserved evidence event kind requires its specialized writer';
    END IF;
    RETURN public.gah_authority_write_internal('commit_evidence', p_actor, p_payload);
END
$function$;

ALTER FUNCTION gah_commit_evidence(jsonb,jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_commit_evidence(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_commit_evidence(jsonb,jsonb) TO gah_authority_writer;
