-- Phase 5.1 post-review hardening.
--
-- Caller-selected execution identities are actor-scoped.  grant_id remains
-- tenant-global because it is the authority-issued bearer identity and must
-- never be reusable by a second actor.

LOCK TABLE public.gah_runtime_principals IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.gah_skill_lifecycle_transitions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.gah_builtin_execution_state IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION gah_builtin_execution_state_actor_binding_valid(
    p_tenant text, p_actor text, p_run text, p_operation text,
    p_operation_digest text, p_request text, p_request_digest text,
    p_grant text, p_grant_digest text, p_skill text, p_revision integer,
    p_artifact_digest text, p_command jsonb, p_grant_json jsonb,
    p_issuance jsonb
) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $function$
BEGIN
    RETURN CASE
        WHEN pg_catalog.jsonb_typeof(p_command) IS DISTINCT FROM 'object'
          OR pg_catalog.jsonb_typeof(p_grant_json) IS DISTINCT FROM 'object'
          OR pg_catalog.jsonb_typeof(p_issuance) IS DISTINCT FROM 'object'
          OR p_command#>>'{tool_request,tenant_id}' IS DISTINCT FROM p_tenant
          OR p_command#>>'{tool_request,actor_id}' IS DISTINCT FROM p_actor
          OR p_command#>>'{tool_request,run_id}' IS DISTINCT FROM p_run
          OR p_command->>'operation_id' IS DISTINCT FROM p_operation
          OR p_command->>'operation_digest' IS DISTINCT FROM p_operation_digest
          OR p_command#>>'{tool_request,request_id}' IS DISTINCT FROM p_request
          OR p_command#>>'{tool_request,request_digest}'
                IS DISTINCT FROM p_request_digest
          OR p_command->>'skill_id' IS DISTINCT FROM p_skill
          OR pg_catalog.jsonb_typeof(p_command->'revision')
                IS DISTINCT FROM 'number'
          OR p_command->>'revision' !~ '^[1-9][0-9]{0,8}$'
          OR (p_command->>'revision')::integer IS DISTINCT FROM p_revision
          OR p_command->>'artifact_digest' IS DISTINCT FROM p_artifact_digest
          OR p_command#>'{tool_request,arguments,input}' IS DISTINCT FROM
                '{"message":"gah.builtin.echo.v1"}'::jsonb
          OR p_grant_json->>'tenant_id' IS DISTINCT FROM p_tenant
          OR p_grant_json->>'actor_id' IS DISTINCT FROM p_actor
          OR p_grant_json->>'run_id' IS DISTINCT FROM p_run
          OR p_grant_json->>'request_id' IS DISTINCT FROM p_request
          OR p_grant_json->>'request_digest' IS DISTINCT FROM p_request_digest
          OR p_grant_json->>'grant_id' IS DISTINCT FROM p_grant
          OR public.gah_canonical_sha256(p_grant_json)
                IS DISTINCT FROM p_grant_digest
          OR p_issuance->>'tenant_id' IS DISTINCT FROM p_tenant
          OR p_issuance#>>'{draft,tenant_id}' IS DISTINCT FROM p_tenant
          OR p_issuance#>>'{draft,run_id}' IS DISTINCT FROM p_run
          OR p_issuance#>>'{draft,inline_payload,actor_id}'
                IS DISTINCT FROM p_actor
          OR p_issuance#>>'{draft,inline_payload,operation_id}'
                IS DISTINCT FROM p_operation
          OR p_issuance#>>'{draft,inline_payload,operation_digest}'
                IS DISTINCT FROM p_operation_digest
          OR p_issuance#>'{draft,inline_payload,command}'
                IS DISTINCT FROM p_command
          OR p_issuance#>'{draft,inline_payload,authorization_grant}'
                IS DISTINCT FROM p_grant_json
          OR p_issuance#>>'{draft,inline_payload,authorization_grant_digest}'
                IS DISTINCT FROM p_grant_digest
        THEN false
        ELSE true
    END;
END
$function$;
ALTER FUNCTION gah_builtin_execution_state_actor_binding_valid(
    text,text,text,text,text,text,text,text,text,text,integer,text,jsonb,jsonb,jsonb
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_builtin_execution_state_actor_binding_valid(
    text,text,text,text,text,text,text,text,text,text,integer,text,jsonb,jsonb,jsonb
) FROM PUBLIC, gah_runtime, gah_authority_writer,
       gah_skill_lifecycle_authority, gah_execution_admission_authority;

DO $execution_state_preflight$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.gah_builtin_execution_state
         WHERE public.gah_builtin_execution_state_actor_binding_valid(
                   tenant_id,actor_id,run_id,operation_id,operation_digest,
                   request_id,request_digest,grant_id,grant_digest,skill_id,
                   revision,artifact_digest,command_json,grant_json,
                   issuance_evidence_json
               ) IS NOT TRUE
    ) THEN
        RAISE EXCEPTION 'cannot migrate ambiguous execution actor bindings';
    END IF;
END
$execution_state_preflight$;

ALTER TABLE public.gah_builtin_execution_state
    DROP CONSTRAINT gah_builtin_execution_state_pkey,
    DROP CONSTRAINT gah_builtin_execution_state_tenant_id_operation_digest_key,
    DROP CONSTRAINT gah_builtin_execution_state_tenant_id_request_id_key;

ALTER TABLE public.gah_builtin_execution_state
    ADD CONSTRAINT gah_builtin_execution_state_actor_pkey
        PRIMARY KEY (tenant_id, actor_id, operation_id),
    ADD CONSTRAINT gah_builtin_execution_state_actor_operation_digest_key
        UNIQUE (tenant_id, actor_id, operation_digest),
    ADD CONSTRAINT gah_builtin_execution_state_actor_request_id_key
        UNIQUE (tenant_id, actor_id, request_id),
    ADD CONSTRAINT gah_builtin_execution_state_actor_binding_guard
        CHECK (public.gah_builtin_execution_state_actor_binding_valid(
            tenant_id,actor_id,run_id,operation_id,operation_digest,
            request_id,request_digest,grant_id,grant_digest,skill_id,revision,
            artifact_digest,command_json,grant_json,issuance_evidence_json
        ) IS TRUE);

-- Rebuild the current function bodies with actor-qualified identities.  Every
-- guard is exact and aborts the atomic migration if an earlier definition has
-- drifted.
DO $actor_scope_execution_functions$
DECLARE
    definition text;
    original text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_authorize_builtin_execution(jsonb,jsonb)'::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_binding->>''operation_id'')',
        '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_actor->>''actor_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_binding->>''operation_id'')'
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10) || '            (p_binding->>''operation_id'')'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10) || '            (p_actor->>''actor_id'')||'':''||'
                || pg_catalog.chr(10) || '            (p_binding->>''operation_id'')'
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope execution writer operation lock';
    END IF;
    EXECUTE definition;

    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_lookup_builtin_execution_authorization_approval_validated'
        '(jsonb,jsonb)'::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND (operation_id=p_command->>''operation_id''',
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND actor_id=p_actor->>''actor_id''' || pg_catalog.chr(10)
            || '       AND (operation_id=p_command->>''operation_id'''
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
                || '       AND (operation_id=p_command->>''operation_id'''
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
                || '       AND actor_id=p_actor->>''actor_id''' || pg_catalog.chr(10)
                || '       AND (operation_id=p_command->>''operation_id'''
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope execution authorization lookup';
    END IF;
    EXECUTE definition;

    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_issue_builtin_execution_authorization_locked'
        '(jsonb,jsonb,jsonb,jsonb,jsonb)'::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND (operation_id=p_command->>''operation_id''' || pg_catalog.chr(10)
            || '            OR operation_digest=p_command->>''operation_digest''' || pg_catalog.chr(10)
            || '            OR request_id=p_command#>>''{tool_request,request_id}''' || pg_catalog.chr(10)
            || '            OR grant_id=p_grant->>''grant_id'')',
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND ((actor_id=p_actor->>''actor_id'' AND (' || pg_catalog.chr(10)
            || '                operation_id=p_command->>''operation_id''' || pg_catalog.chr(10)
            || '                OR operation_digest=p_command->>''operation_digest''' || pg_catalog.chr(10)
            || '                OR request_id=p_command#>>''{tool_request,request_id}''))' || pg_catalog.chr(10)
            || '            OR grant_id=p_grant->>''grant_id'')'
    );
    definition := pg_catalog.replace(
        definition,
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND (operation_id=p_command->>''operation_id''',
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND actor_id=p_actor->>''actor_id''' || pg_catalog.chr(10)
            || '       AND (operation_id=p_command->>''operation_id'''
    );
    definition := pg_catalog.replace(
        definition,
        '''execution:request:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '                (p_command#>>''{tool_request,request_id}'')',
        '''execution:request:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '                (p_actor->>''actor_id'')||'':''||'
            || pg_catalog.chr(10) || '                (p_command#>>''{tool_request,request_id}'')'
    );
    definition := pg_catalog.replace(
        definition,
        '''skill:''||(p_actor->>''tenant_id'')||'':''||(p_command->>''skill_id'')',
        '''skill:''||(p_actor->>''tenant_id'')||'':''||'
            || '(p_actor->>''actor_id'')||'':''||(p_command->>''skill_id'')'
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
                || '       AND (operation_id=p_command->>''operation_id'''
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            '''execution:request:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10) || '                (p_command#>>''{tool_request,request_id}'')'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            '''skill:''||(p_actor->>''tenant_id'')||'':''||(p_command->>''skill_id'')'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            'AND ((actor_id=p_actor->>''actor_id'' AND ('
          ) = 0
       OR pg_catalog.strpos(
            definition,
            'AND actor_id=p_actor->>''actor_id'''
          ) = 0
       OR pg_catalog.strpos(
            definition,
            '''execution:request:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10) || '                (p_actor->>''actor_id'')||'':''||'
                || pg_catalog.chr(10) || '                (p_command#>>''{tool_request,request_id}'')'
          ) = 0
       OR pg_catalog.strpos(
            definition,
            '''skill:''||(p_actor->>''tenant_id'')||'':''||'
                || '(p_actor->>''actor_id'')||'':''||(p_command->>''skill_id'')'
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope execution issuance';
    END IF;
    EXECUTE definition;

    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_begin_builtin_execution(jsonb,jsonb,jsonb,double precision)'
            ::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        '''execution:operation:'' || v_tenant || '':'' || v_operation',
        '''execution:operation:'' || v_tenant || '':'' || v_actor || '':'' || v_operation'
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:'' || v_tenant || '':'' || v_operation'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:'' || v_tenant || '':'' || v_actor || '':'' || v_operation'
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope public execution begin lock';
    END IF;
    EXECUTE definition;

    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_begin_builtin_execution_validated'
        '(jsonb,jsonb,jsonb,double precision)'::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_authorization->>''operation_id'')',
        '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_actor->>''actor_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_authorization->>''operation_id'')'
    );
    definition := pg_catalog.replace(
        definition,
        'WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id'
            || pg_catalog.chr(10) || '     RETURNING * INTO stored;',
        'WHERE tenant_id=stored.tenant_id AND actor_id=stored.actor_id'
            || pg_catalog.chr(10) || '       AND operation_id=stored.operation_id'
            || pg_catalog.chr(10) || '     RETURNING * INTO stored;'
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10)
                || '            (p_authorization->>''operation_id'')'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10)
                || '            (p_actor->>''actor_id'')||'':''||'
                || pg_catalog.chr(10)
                || '            (p_authorization->>''operation_id'')'
          ) = 0
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=stored.tenant_id AND actor_id=stored.actor_id'
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope validated execution begin';
    END IF;
    EXECUTE definition;

    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)'::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        'WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id'
            || pg_catalog.chr(10) || '     RETURNING * INTO stored;',
        'WHERE tenant_id=stored.tenant_id AND actor_id=stored.actor_id'
            || pg_catalog.chr(10) || '       AND operation_id=stored.operation_id'
            || pg_catalog.chr(10) || '     RETURNING * INTO stored;'
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=stored.tenant_id AND actor_id=stored.actor_id'
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope execution completion';
    END IF;
    EXECUTE definition;

    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_recover_builtin_execution_validated'
        '(jsonb,jsonb,jsonb,jsonb)'::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        'WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id'
            || pg_catalog.chr(10) || '     RETURNING * INTO stored;',
        'WHERE tenant_id=stored.tenant_id AND actor_id=stored.actor_id'
            || pg_catalog.chr(10) || '       AND operation_id=stored.operation_id'
            || pg_catalog.chr(10) || '     RETURNING * INTO stored;'
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=stored.tenant_id AND actor_id=stored.actor_id'
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope execution recovery';
    END IF;
    EXECUTE definition;

    SELECT pg_catalog.pg_get_functiondef(
        'public.gah_rebuild_builtin_execution(jsonb,jsonb)'::regprocedure
    ) INTO definition;
    original := definition;
    definition := pg_catalog.replace(
        definition,
        '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_query->>''operation_id'')',
        '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_actor->>''actor_id'')||'':''||'
            || pg_catalog.chr(10) || '            (p_query->>''operation_id'')'
    );
    definition := pg_catalog.replace(
        definition,
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND (operation_id=p_query->>''operation_id''',
        'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
            || '       AND actor_id=p_actor->>''actor_id''' || pg_catalog.chr(10)
            || '       AND (operation_id=p_query->>''operation_id'''
    );
    IF definition = original
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10) || '            (p_query->>''operation_id'')'
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
                || '       AND (operation_id=p_query->>''operation_id'''
          ) <> 0
       OR pg_catalog.strpos(
            definition,
            '''execution:operation:''||(p_actor->>''tenant_id'')||'':''||'
                || pg_catalog.chr(10)
                || '            (p_actor->>''actor_id'')||'':''||'
                || pg_catalog.chr(10) || '            (p_query->>''operation_id'')'
          ) = 0
       OR pg_catalog.strpos(
            definition,
            'WHERE tenant_id=p_actor->>''tenant_id''' || pg_catalog.chr(10)
                || '       AND actor_id=p_actor->>''actor_id''' || pg_catalog.chr(10)
                || '       AND (operation_id=p_query->>''operation_id'''
          ) = 0
    THEN
        RAISE EXCEPTION 'cannot actor-scope execution rebuild';
    END IF;
    EXECUTE definition;
END
$actor_scope_execution_functions$;

CREATE FUNCTION gah_verify_lifecycle_approvals(
    p_command jsonb, p_accepted_at timestamptz, p_historical boolean
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    approval jsonb;
    approval_refs jsonb;
    policy jsonb := p_command->'policy_decision';
    proposal jsonb := p_command->'skill_proposal';
    actor_id text := proposal#>>'{target_scope,actor_id}';
    policy_decided_at timestamptz;
    approval_issued_at timestamptz;
    approval_expires_at timestamptz;
BEGIN
    IF pg_catalog.jsonb_typeof(policy) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(proposal) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(policy->'decision_id') IS DISTINCT FROM 'string'
       OR policy->>'decision_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR pg_catalog.jsonb_typeof(policy->'decision_digest') IS DISTINCT FROM 'string'
       OR policy->>'decision_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR pg_catalog.jsonb_typeof(policy->'request_id') IS DISTINCT FROM 'string'
       OR policy->>'request_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR pg_catalog.jsonb_typeof(policy->'request_digest') IS DISTINCT FROM 'string'
       OR policy->>'request_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR pg_catalog.jsonb_typeof(policy->'decision') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(policy->'constraints') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(policy->'decided_at') IS DISTINCT FROM 'string'
       OR policy->>'decided_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR pg_catalog.jsonb_typeof(proposal->'tenant_id') IS DISTINCT FROM 'string'
       OR proposal->>'tenant_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR pg_catalog.jsonb_typeof(proposal->'proposal_id') IS DISTINCT FROM 'string'
       OR proposal->>'proposal_id'
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR pg_catalog.jsonb_typeof(proposal->'proposal_digest') IS DISTINCT FROM 'string'
       OR proposal->>'proposal_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR pg_catalog.jsonb_typeof(
            proposal#>'{target_scope,actor_id}'
          ) IS DISTINCT FROM 'string'
       OR actor_id
            !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR policy->>'request_id' IS DISTINCT FROM proposal->>'proposal_id'
       OR policy->>'request_digest' IS DISTINCT FROM proposal->>'proposal_digest'
    THEN
        RAISE EXCEPTION 'lifecycle policy and proposal authority shape is invalid';
    END IF;
    IF NOT pg_catalog.pg_input_is_valid(
               policy->>'decided_at', 'timestamp with time zone'
           )
    THEN
        RAISE EXCEPTION 'lifecycle policy and proposal authority shape is invalid';
    END IF;
    policy_decided_at := (policy->>'decided_at')::timestamptz;
    IF policy->>'decision' = 'authorize' THEN
        IF pg_catalog.jsonb_typeof(p_command->'approvals') IS DISTINCT FROM 'array'
           OR pg_catalog.jsonb_array_length(p_command->'approvals') <> 0
        THEN
            RAISE EXCEPTION 'lifecycle authorize decision cannot carry approvals';
        END IF;
        RETURN;
    END IF;
    IF policy->>'decision' IS DISTINCT FROM 'require_approval'
       OR pg_catalog.jsonb_typeof(p_command->'approvals') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(p_command->'approvals') = 0
    THEN
        RAISE EXCEPTION 'lifecycle approval authority shape is invalid';
    END IF;
    SELECT coalesce(
               pg_catalog.jsonb_agg(
                   pg_catalog.jsonb_build_object(
                       'record_type','approval_record',
                       'record_id',item->>'approval_id',
                       'record_digest',item->>'approval_digest'
                   ) ORDER BY ordinal
               ),
               '[]'::jsonb
           )
      INTO approval_refs
      FROM pg_catalog.jsonb_array_elements(p_command->'approvals')
           WITH ORDINALITY AS approvals(item, ordinal);
    IF p_command#>'{delivery_envelope,reviewer_refs}'
            IS DISTINCT FROM approval_refs
    THEN
        RAISE EXCEPTION 'lifecycle approval reviewer binding is invalid';
    END IF;
    FOR approval IN
        SELECT value
          FROM pg_catalog.jsonb_array_elements(p_command->'approvals')
    LOOP
        IF pg_catalog.jsonb_typeof(approval->'issued_at')
                IS DISTINCT FROM 'string'
           OR pg_catalog.jsonb_typeof(approval->'expires_at')
                IS DISTINCT FROM 'string'
           OR approval->>'issued_at'
                !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
           OR approval->>'expires_at'
                !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
        THEN
            RAISE EXCEPTION 'lifecycle approval authority binding is invalid';
        END IF;
        IF NOT pg_catalog.pg_input_is_valid(
                   approval->>'issued_at', 'timestamp with time zone'
               )
           OR NOT pg_catalog.pg_input_is_valid(
                   approval->>'expires_at', 'timestamp with time zone'
               )
        THEN
            RAISE EXCEPTION 'lifecycle approval authority binding is invalid';
        END IF;
        approval_issued_at := (approval->>'issued_at')::timestamptz;
        approval_expires_at := (approval->>'expires_at')::timestamptz;
        IF pg_catalog.jsonb_typeof(approval) IS DISTINCT FROM 'object'
           OR NOT (approval ?& ARRAY[
               'schema_version','record_type','tenant_id','approval_id',
               'approver_actor_id','approver_context_digest','request_id',
               'request_digest','policy_decision_id','policy_decision_digest',
               'disposition','constraints','separation_of_duties','issued_at',
               'expires_at','approval_digest','proof'
           ])
           OR EXISTS (
               SELECT 1
                 FROM pg_catalog.jsonb_object_keys(approval) AS fields(field)
                WHERE field <> ALL(ARRAY[
                    'schema_version','record_type','tenant_id','approval_id',
                    'approver_actor_id','approver_context_digest','request_id',
                    'request_digest','policy_decision_id','policy_decision_digest',
                    'disposition','constraints','separation_of_duties','issued_at',
                    'expires_at','approval_digest','proof','extensions'
                ])
           )
           OR approval ? 'revoked_at'
           OR approval->>'schema_version' IS DISTINCT FROM '1.0'
           OR approval->>'record_type' IS DISTINCT FROM 'approval_record'
           OR EXISTS (
               SELECT 1
                 FROM pg_catalog.jsonb_each(approval)
                      AS scalar_values(field,value)
                WHERE field = ANY(ARRAY[
                    'schema_version','record_type','tenant_id','approval_id',
                    'approver_actor_id','approver_context_digest','request_id',
                    'request_digest','policy_decision_id',
                    'policy_decision_digest','disposition','issued_at',
                    'expires_at','approval_digest'
                ])
                  AND pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string'
           )
           OR approval->>'tenant_id'
                !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
           OR approval->>'approval_id'
                !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
           OR approval->>'approver_actor_id'
                !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
           OR approval->>'request_id'
                !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
           OR approval->>'policy_decision_id'
                !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
           OR approval->>'approver_context_digest' !~ '^sha256:[0-9a-f]{64}$'
           OR approval->>'request_digest' !~ '^sha256:[0-9a-f]{64}$'
           OR approval->>'policy_decision_digest' !~ '^sha256:[0-9a-f]{64}$'
           OR approval->>'approval_digest' !~ '^sha256:[0-9a-f]{64}$'
           OR pg_catalog.jsonb_typeof(approval->'constraints')
                IS DISTINCT FROM 'array'
           OR (
                approval ? 'extensions'
                AND pg_catalog.jsonb_typeof(approval->'extensions')
                    IS DISTINCT FROM 'object'
              )
           OR pg_catalog.jsonb_typeof(approval->'proof') IS DISTINCT FROM 'object'
           OR NOT (approval->'proof' ?& ARRAY[
                'issuer','key_id','algorithm','proof_domain','object_digest',
                'nonce','detached_proof'
              ])
           OR EXISTS (
               SELECT 1
                 FROM pg_catalog.jsonb_object_keys(approval->'proof')
                      AS proof_fields(field)
                WHERE field <> ALL(ARRAY[
                    'issuer','key_id','algorithm','proof_domain','object_digest',
                    'nonce','detached_proof'
                ])
           )
           OR EXISTS (
               SELECT 1
                 FROM pg_catalog.jsonb_each(approval->'proof')
                      AS proof_values(field,value)
                WHERE pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string'
           )
           OR approval#>>'{proof,issuer}' IS DISTINCT FROM 'policy.authority'
           OR approval#>>'{proof,algorithm}'
                IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
           OR approval#>>'{proof,proof_domain}'
                IS DISTINCT FROM 'approval_record.v1'
           OR approval->>'tenant_id' IS DISTINCT FROM proposal->>'tenant_id'
           OR approval->>'request_id' IS DISTINCT FROM proposal->>'proposal_id'
           OR approval->>'request_digest' IS DISTINCT FROM proposal->>'proposal_digest'
           OR approval->>'policy_decision_id'
                IS DISTINCT FROM policy->>'decision_id'
           OR approval->>'policy_decision_digest'
                IS DISTINCT FROM policy->>'decision_digest'
           OR approval->>'disposition' IS DISTINCT FROM 'approved'
           OR approval->'constraints' IS DISTINCT FROM policy->'constraints'
           OR pg_catalog.jsonb_typeof(approval->'separation_of_duties')
                IS DISTINCT FROM 'object'
           OR NOT (approval->'separation_of_duties' ?& ARRAY[
                'required','satisfied','policy_id'
              ])
           OR EXISTS (
               SELECT 1
                 FROM pg_catalog.jsonb_object_keys(
                      approval->'separation_of_duties'
                 ) AS duty_fields(field)
                WHERE field <> ALL(ARRAY['required','satisfied','policy_id'])
           )
           OR pg_catalog.jsonb_typeof(
                approval#>'{separation_of_duties,required}'
              ) IS DISTINCT FROM 'boolean'
           OR pg_catalog.jsonb_typeof(
                approval#>'{separation_of_duties,satisfied}'
              ) IS DISTINCT FROM 'boolean'
           OR pg_catalog.jsonb_typeof(
                approval#>'{separation_of_duties,policy_id}'
              ) IS DISTINCT FROM 'string'
           OR approval#>>'{separation_of_duties,policy_id}'
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR (
                (approval#>>'{separation_of_duties,required}')::boolean
                AND (
                    NOT (approval#>>'{separation_of_duties,satisfied}')::boolean
                    OR approval->>'approver_actor_id' IS NOT DISTINCT FROM actor_id
                )
              )
           OR approval->>'approval_digest' IS DISTINCT FROM
                public.gah_canonical_sha256(
                    (approval-'proof')-'approval_digest'
                )
           OR approval#>>'{proof,object_digest}' IS DISTINCT FROM
                public.gah_canonical_sha256(
                    (approval-'proof')-'approval_digest'
                )
           OR approval_issued_at < policy_decided_at
           OR approval_issued_at > p_accepted_at
           OR p_accepted_at >= approval_expires_at
        THEN
            RAISE EXCEPTION 'lifecycle approval authority binding is invalid';
        END IF;
        PERFORM public.gah_verify_execution_signed_record(
            approval, 'approval_digest', p_accepted_at, p_historical
        );
    END LOOP;
END
$function$;
ALTER FUNCTION gah_verify_lifecycle_approvals(jsonb,timestamptz,boolean)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_verify_lifecycle_approvals(jsonb,timestamptz,boolean)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

DO $preflight_lifecycle_approvals$
DECLARE
    transition_row record;
BEGIN
    FOR transition_row IN
        SELECT tenant_id, actor_id, skill_id, operation_id, operation,
               operation_digest, target_revision, command_json, evidence_json,
               (evidence_json->>'recorded_at')::timestamptz AS recorded_at
          FROM public.gah_skill_lifecycle_transitions
         ORDER BY tenant_id, actor_id, skill_id, transition_sequence
    LOOP
        IF pg_catalog.jsonb_typeof(
               transition_row.evidence_json->'recorded_at'
           ) IS DISTINCT FROM 'string'
           OR transition_row.command_json#>>'{skill_proposal,tenant_id}'
                IS DISTINCT FROM transition_row.tenant_id
           OR transition_row.command_json#>>'{skill_proposal,target_scope,actor_id}'
                IS DISTINCT FROM transition_row.actor_id
           OR transition_row.command_json#>>'{skill_proposal,artifact_id}'
                IS DISTINCT FROM transition_row.skill_id
           OR transition_row.command_json->>'operation_id'
                IS DISTINCT FROM transition_row.operation_id
           OR transition_row.command_json->>'operation'
                IS DISTINCT FROM transition_row.operation
           OR transition_row.command_json->>'operation_digest'
                IS DISTINCT FROM transition_row.operation_digest
           OR transition_row.command_json#>>'{delivery_envelope,artifact_revision}'
                IS DISTINCT FROM transition_row.target_revision::text
           OR public.gah_skill_lifecycle_sink_command_valid(
                transition_row.tenant_id,
                transition_row.actor_id,
                transition_row.skill_id,
                transition_row.target_revision,
                transition_row.command_json#>>'{delivery_envelope,artifact_digest}',
                transition_row.command_json
              ) IS NOT TRUE
        THEN
            RAISE EXCEPTION 'persisted lifecycle approval row binding is invalid';
        END IF;
        -- Stored rows are admissible only under their immutable ledger time;
        -- current wall-clock authority cannot retroactively invalidate them.
        PERFORM public.gah_verify_lifecycle_approvals(
            transition_row.command_json,
            transition_row.recorded_at,
            true
        );
    END LOOP;
END
$preflight_lifecycle_approvals$;

ALTER FUNCTION gah_lookup_skill_replay(jsonb,jsonb)
    RENAME TO gah_lookup_skill_replay_approval_validated;
ALTER FUNCTION gah_lookup_skill_replay_approval_validated(jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_lookup_skill_replay_approval_validated(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_lookup_skill_replay(p_actor jsonb, p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    replay jsonb;
    rebuild_terminal_digest text;
    persisted record;
    transition_row record;
    rebuild_terminal_found boolean := false;
BEGIN
    replay := public.gah_lookup_skill_replay_approval_validated(
        p_actor, p_command
    );
    IF replay IS NULL THEN
        RETURN replay;
    END IF;
    IF p_command->>'operation' = 'rebuild' THEN
        PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
            'skill:' || (p_actor->>'tenant_id') || ':' ||
            (p_actor->>'actor_id') || ':' || (p_command->>'skill_id'), 0
        ));
        SELECT transition_digest
          INTO rebuild_terminal_digest
          FROM public.gah_skill_projection_rebuilds
         WHERE tenant_id=p_actor->>'tenant_id'
           AND actor_id=p_actor->>'actor_id'
           AND operation_id=p_command->>'operation_id'
           AND operation_digest=p_command->>'operation_digest'
           AND skill_id=p_command->>'skill_id'
         FOR UPDATE;
        IF NOT FOUND
           OR rebuild_terminal_digest !~ '^sha256:[0-9a-f]{64}$'
           OR rebuild_terminal_digest
                IS DISTINCT FROM replay->>'transition_digest'
        THEN
            RAISE EXCEPTION
                'persisted lifecycle rebuild replay terminal binding is invalid';
        END IF;
        FOR transition_row IN
            SELECT tenant_id,actor_id,skill_id,target_revision,command_json,
                   evidence_json,evidence_event_digest
              FROM public.gah_skill_lifecycle_transitions
             WHERE tenant_id=p_actor->>'tenant_id'
               AND actor_id=p_actor->>'actor_id'
               AND skill_id=p_command->>'skill_id'
             ORDER BY transition_sequence
        LOOP
            IF pg_catalog.jsonb_typeof(
                   transition_row.evidence_json->'recorded_at'
               ) IS DISTINCT FROM 'string'
               OR public.gah_skill_lifecycle_sink_command_valid(
                    transition_row.tenant_id,
                    transition_row.actor_id,
                    transition_row.skill_id,
                    transition_row.target_revision,
                    transition_row.command_json
                        #>>'{delivery_envelope,artifact_digest}',
                    transition_row.command_json
                  ) IS NOT TRUE
            THEN
                RAISE EXCEPTION 'persisted lifecycle rebuild approval replay is invalid';
            END IF;
            PERFORM public.gah_verify_lifecycle_approvals(
                transition_row.command_json,
                (transition_row.evidence_json->>'recorded_at')::timestamptz,
                true
            );
            IF transition_row.evidence_event_digest =
                   rebuild_terminal_digest
            THEN
                rebuild_terminal_found := true;
                EXIT;
            END IF;
        END LOOP;
        IF NOT rebuild_terminal_found THEN
            RAISE EXCEPTION
                'persisted lifecycle rebuild replay terminal transition is invalid';
        END IF;
        RETURN replay;
    END IF;
    SELECT command_json, evidence_json
      INTO persisted
      FROM public.gah_skill_lifecycle_transitions
     WHERE tenant_id=p_actor->>'tenant_id'
       AND actor_id=p_actor->>'actor_id'
       AND operation_id=p_command->>'operation_id';
    IF NOT FOUND
       OR pg_catalog.jsonb_typeof(persisted.evidence_json->'recorded_at')
            IS DISTINCT FROM 'string'
       OR (CASE
            WHEN (persisted.command_json
                    #>>'{delivery_envelope,artifact_revision}') ~ '^[1-9][0-9]{0,8}$'
            THEN public.gah_skill_lifecycle_sink_command_valid(
                p_actor->>'tenant_id',
                p_actor->>'actor_id',
                persisted.command_json#>>'{skill_proposal,artifact_id}',
                (persisted.command_json
                    #>>'{delivery_envelope,artifact_revision}')::integer,
                persisted.command_json#>>'{delivery_envelope,artifact_digest}',
                persisted.command_json
            )
            ELSE false
          END) IS NOT TRUE
    THEN
        RAISE EXCEPTION 'persisted lifecycle approval replay is invalid';
    END IF;
    PERFORM public.gah_verify_lifecycle_approvals(
        persisted.command_json,
        (persisted.evidence_json->>'recorded_at')::timestamptz,
        true
    );
    RETURN replay;
END
$function$;
ALTER FUNCTION gah_lookup_skill_replay(jsonb,jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_lookup_skill_replay(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_lookup_skill_replay(jsonb,jsonb)
    TO gah_skill_lifecycle_authority;

ALTER FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    RENAME TO gah_apply_skill_lifecycle_approval_validated;
ALTER FUNCTION gah_apply_skill_lifecycle_approval_validated(jsonb,jsonb,text)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_apply_skill_lifecycle_approval_validated(jsonb,jsonb,text)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_apply_skill_lifecycle(
    p_actor jsonb, p_command jsonb, p_expected_operation text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    replay jsonb;
    recorded_at timestamptz;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF pg_catalog.jsonb_typeof(p_actor->'actor_id') IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(p_actor->>'actor_id') = ''
       OR p_expected_operation NOT IN ('install','activate','rollback','deactivate')
       OR p_command->>'operation' IS DISTINCT FROM p_expected_operation
    THEN
        RAISE EXCEPTION 'skill lifecycle approval verification binding is invalid';
    END IF;
    replay := public.gah_lookup_skill_replay(p_actor, p_command);
    IF replay IS NOT NULL THEN
        RETURN replay;
    END IF;
    IF pg_catalog.jsonb_typeof(
           p_command#>'{transition_evidence,recorded_at}'
       ) IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION 'skill lifecycle approval ledger time is invalid';
    END IF;
    recorded_at :=
        (p_command#>>'{transition_evidence,recorded_at}')::timestamptz;
    PERFORM public.gah_verify_lifecycle_approvals(
        p_command, pg_catalog.transaction_timestamp(), false
    );
    PERFORM public.gah_verify_lifecycle_approvals(
        p_command, recorded_at, true
    );
    RETURN public.gah_apply_skill_lifecycle_approval_validated(
        p_actor, p_command, p_expected_operation
    );
END
$function$;
ALTER FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    TO gah_skill_lifecycle_authority;

ALTER FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    RENAME TO gah_rebuild_skill_projection_approval_validated;
ALTER FUNCTION gah_rebuild_skill_projection_approval_validated(jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_rebuild_skill_projection_approval_validated(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_rebuild_skill_projection(p_actor jsonb, p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    replay jsonb;
    transition_row record;
    v_tenant text;
    v_actor text;
    v_operation text;
    v_skill text;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF p_command->>'operation' IS DISTINCT FROM 'rebuild'
       OR pg_catalog.jsonb_typeof(p_command->'operation_id')
            IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_command->'skill_id')
            IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(p_command->>'operation_id') = ''
       OR pg_catalog.btrim(p_command->>'skill_id') = ''
    THEN
        RAISE EXCEPTION 'skill projection rebuild approval binding is invalid';
    END IF;
    v_tenant := p_actor->>'tenant_id';
    v_actor := p_actor->>'actor_id';
    v_operation := p_command->>'operation_id';
    v_skill := p_command->>'skill_id';
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill-operation:' || v_tenant || ':' || v_actor || ':' || v_operation, 0
    ));
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill:' || v_tenant || ':' || v_actor || ':' || v_skill, 0
    ));
    replay := public.gah_lookup_skill_replay(p_actor, p_command);
    IF replay IS NOT NULL THEN
        RETURN replay;
    END IF;
    FOR transition_row IN
        SELECT tenant_id,actor_id,skill_id,target_revision,command_json,
               (evidence_json->>'recorded_at')::timestamptz AS recorded_at
          FROM public.gah_skill_lifecycle_transitions
         WHERE tenant_id=v_tenant
           AND actor_id=v_actor
           AND skill_id=v_skill
         ORDER BY transition_sequence
    LOOP
        IF public.gah_skill_lifecycle_sink_command_valid(
               transition_row.tenant_id,
               transition_row.actor_id,
               transition_row.skill_id,
               transition_row.target_revision,
               transition_row.command_json#>>'{delivery_envelope,artifact_digest}',
               transition_row.command_json
           ) IS NOT TRUE
        THEN
            RAISE EXCEPTION 'persisted lifecycle rebuild approval binding is invalid';
        END IF;
        PERFORM public.gah_verify_lifecycle_approvals(
            transition_row.command_json,
            transition_row.recorded_at,
            true
        );
    END LOOP;
    RETURN public.gah_rebuild_skill_projection_approval_validated(
        p_actor, p_command
    );
END
$function$;
ALTER FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    TO gah_skill_lifecycle_authority;
