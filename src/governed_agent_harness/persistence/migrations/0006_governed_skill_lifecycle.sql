-- Phase 4.4: immutable, inert skill artifacts and explicit lifecycle transitions.
-- Artifact bytes are stored only as JSON data.  No SQL function executes or
-- returns them to the runtime role.
CREATE TABLE gah_skill_artifact_revisions (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    skill_id text NOT NULL,
    revision integer NOT NULL CHECK (revision >= 1),
    proposal_id text NOT NULL,
    proposal_digest text NOT NULL CHECK (proposal_digest ~ '^sha256:[0-9a-f]{64}$'),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    artifact_json jsonb NOT NULL,
    command_json jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, skill_id, revision),
    UNIQUE (tenant_id, proposal_id),
    CHECK (command_json ->> 'operation' = 'install'),
    CHECK (command_json ->> 'operation_digest' ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (command_json #>> '{skill_proposal,proposal_id}' = proposal_id),
    CHECK (command_json #>> '{skill_proposal,proposal_digest}' = proposal_digest),
    CHECK (command_json #>> '{skill_proposal,target_scope,actor_id}' = actor_id),
    CHECK ((command_json #>> '{delivery_envelope,artifact_revision}')::integer = revision),
    CHECK (command_json #>> '{delivery_envelope,artifact_digest}' = artifact_digest)
);

CREATE TABLE gah_skill_lifecycle_transitions (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    skill_id text NOT NULL,
    transition_sequence integer NOT NULL CHECK (transition_sequence >= 1),
    operation_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('install', 'activate', 'rollback', 'deactivate')),
    operation_digest text NOT NULL CHECK (operation_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_revision integer,
    target_revision integer NOT NULL CHECK (target_revision >= 1),
    from_state text,
    to_state text NOT NULL CHECK (to_state IN ('installed', 'active', 'inactive')),
    command_json jsonb NOT NULL,
    evidence_json jsonb NOT NULL,
    evidence_event_digest text NOT NULL CHECK (evidence_event_digest ~ '^sha256:[0-9a-f]{64}$'),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, skill_id, transition_sequence),
    UNIQUE (tenant_id, operation_id),
    UNIQUE (tenant_id, operation_digest),
    FOREIGN KEY (tenant_id, skill_id, target_revision)
        REFERENCES gah_skill_artifact_revisions (tenant_id, skill_id, revision),
    CHECK (command_json ->> 'operation' = operation),
    CHECK (command_json ->> 'operation_id' = operation_id),
    CHECK (command_json ->> 'operation_digest' = operation_digest),
    CHECK (evidence_json ->> 'record_type' = 'evidence_envelope'),
    CHECK (evidence_json ->> 'event_digest' = evidence_event_digest)
);

CREATE TABLE gah_active_skill_projection (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    skill_id text NOT NULL,
    revision integer NOT NULL CHECK (revision >= 1),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    lifecycle_state text NOT NULL CHECK (lifecycle_state = 'active'),
    transition_sequence integer NOT NULL,
    rebuilt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, skill_id),
    FOREIGN KEY (tenant_id, skill_id, revision)
        REFERENCES gah_skill_artifact_revisions (tenant_id, skill_id, revision)
);

-- Rebuild is a projection repair operation, not a lifecycle transition.  Its
-- own immutable journal gives the operation the same exact replay contract
-- without manufacturing lifecycle evidence or changing the lifecycle history.
CREATE TABLE gah_skill_projection_rebuilds (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    operation_id text NOT NULL,
    operation_digest text NOT NULL CHECK (operation_digest ~ '^sha256:[0-9a-f]{64}$'),
    skill_id text NOT NULL,
    expected_revision integer NOT NULL CHECK (expected_revision >= 1),
    result_revision integer NOT NULL CHECK (result_revision >= 1),
    lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('installed', 'active', 'inactive')),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    transition_digest text NOT NULL CHECK (transition_digest ~ '^sha256:[0-9a-f]{64}$'),
    command_json jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, operation_digest),
    CHECK (command_json ->> 'operation' = 'rebuild'),
    CHECK (command_json ->> 'operation_id' = operation_id),
    CHECK (command_json ->> 'operation_digest' = operation_digest),
    CHECK (command_json ->> 'skill_id' = skill_id),
    CHECK ((command_json ->> 'expected_revision')::integer = expected_revision)
);

ALTER TABLE gah_skill_artifact_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_skill_artifact_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE gah_skill_lifecycle_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_skill_lifecycle_transitions FORCE ROW LEVEL SECURITY;
ALTER TABLE gah_active_skill_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_active_skill_projection FORCE ROW LEVEL SECURITY;
ALTER TABLE gah_skill_projection_rebuilds ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_skill_projection_rebuilds FORCE ROW LEVEL SECURITY;
CREATE POLICY gah_skill_artifact_revisions_scope ON gah_skill_artifact_revisions USING (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), ''));
CREATE POLICY gah_skill_lifecycle_transitions_scope ON gah_skill_lifecycle_transitions USING (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), ''));
CREATE POLICY gah_active_skill_projection_scope ON gah_active_skill_projection USING (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), ''));
CREATE POLICY gah_skill_projection_rebuilds_scope ON gah_skill_projection_rebuilds USING (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('gah.tenant_id', true), '') AND actor_id = nullif(current_setting('gah.actor_id', true), ''));
ALTER TABLE gah_skill_artifact_revisions OWNER TO gah_schema_owner;
ALTER TABLE gah_skill_lifecycle_transitions OWNER TO gah_schema_owner;
ALTER TABLE gah_active_skill_projection OWNER TO gah_schema_owner;
ALTER TABLE gah_skill_projection_rebuilds OWNER TO gah_schema_owner;
REVOKE ALL ON gah_skill_artifact_revisions, gah_skill_lifecycle_transitions, gah_active_skill_projection, gah_skill_projection_rebuilds FROM PUBLIC, gah_runtime, gah_authority_writer;

CREATE FUNCTION gah_skill_result(p_operation_id text, p_operation_digest text, p_skill_id text,
    p_revision integer, p_state text, p_artifact_digest text, p_transition_digest text, p_replayed boolean)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS $$
    SELECT jsonb_build_object('operation_id', p_operation_id, 'operation_digest', p_operation_digest,
        'skill_id', p_skill_id, 'revision', p_revision, 'lifecycle_state', p_state,
        'artifact_digest', p_artifact_digest, 'transition_digest', p_transition_digest,
        'replayed', p_replayed)
$$;

CREATE FUNCTION gah_skill_assert_actor(p_actor jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    IF p_actor ->> 'record_type' <> 'actor_context' OR nullif(p_actor ->> 'tenant_id', '') IS NULL
       OR nullif(p_actor ->> 'actor_id', '') IS NULL OR (p_actor ->> 'issued_at')::timestamptz > clock_timestamp()
       OR (p_actor ->> 'expires_at')::timestamptz <= clock_timestamp() OR NOT EXISTS (
           SELECT 1 FROM public.gah_runtime_principals WHERE database_role = session_user
             AND tenant_id = p_actor ->> 'tenant_id' AND actor_id = p_actor ->> 'actor_id'
       ) THEN RAISE EXCEPTION 'authority database principal is outside actor scope'; END IF;
    PERFORM set_config('gah.tenant_id', p_actor ->> 'tenant_id', true);
    PERFORM set_config('gah.actor_id', p_actor ->> 'actor_id', true);
END $function$;

CREATE FUNCTION gah_lookup_skill_replay(p_actor jsonb, p_command jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE v_existing record; v_rebuild record; v_digest text; v_normalized jsonb := p_command - 'transition_evidence';
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF nullif(p_command ->> 'operation_id', '') IS NULL THEN
        RAISE EXCEPTION 'skill lifecycle operation_id is required';
    END IF;
    -- Hold this key across lookup, ledger append, and lifecycle apply.  A replay
    -- therefore returns before a second evidence event can be appended.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill-operation:' || p_actor ->> 'tenant_id' || ':' || p_command ->> 'operation_id', 0));
    IF p_command ->> 'operation' = 'rebuild' THEN
        SELECT * INTO v_rebuild FROM public.gah_skill_projection_rebuilds
         WHERE tenant_id=p_actor->>'tenant_id' AND operation_id=p_command->>'operation_id' FOR UPDATE;
        IF NOT FOUND THEN RETURN NULL; END IF;
        IF v_rebuild.operation_digest <> p_command->>'operation_digest'
           OR v_rebuild.command_json IS DISTINCT FROM p_command THEN
            RAISE EXCEPTION 'skill projection rebuild replay conflicts with stored authority';
        END IF;
        RETURN gah_skill_result(v_rebuild.operation_id,v_rebuild.operation_digest,v_rebuild.skill_id,
            v_rebuild.result_revision,v_rebuild.lifecycle_state,v_rebuild.artifact_digest,
            v_rebuild.transition_digest,true);
    END IF;
    SELECT * INTO v_existing FROM public.gah_skill_lifecycle_transitions
     WHERE tenant_id=p_actor->>'tenant_id' AND operation_id=p_command->>'operation_id' FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF v_existing.operation_digest <> p_command->>'operation_digest'
       OR v_existing.command_json IS DISTINCT FROM v_normalized THEN
        RAISE EXCEPTION 'skill lifecycle replay conflicts with stored authority';
    END IF;
    SELECT artifact_digest INTO v_digest FROM public.gah_skill_artifact_revisions
     WHERE tenant_id=p_actor->>'tenant_id' AND skill_id=v_existing.skill_id
       AND revision=v_existing.target_revision;
    RETURN gah_skill_result(v_existing.operation_id,v_existing.operation_digest,v_existing.skill_id,
        v_existing.target_revision,v_existing.to_state,v_digest,v_existing.evidence_event_digest,true);
END $function$;

CREATE FUNCTION gah_apply_skill_lifecycle(p_actor jsonb, p_command jsonb, p_expected_operation text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_tenant text := p_actor ->> 'tenant_id'; v_actor text := p_actor ->> 'actor_id';
    v_operation text := p_command ->> 'operation'; v_operation_id text := p_command ->> 'operation_id';
    v_operation_digest text := p_command ->> 'operation_digest'; v_skill text := p_command #>> '{skill_proposal,artifact_id}';
    v_expected integer := nullif(p_command ->> 'expected_revision', '')::integer;
    v_target integer := nullif(p_command #>> '{delivery_envelope,artifact_revision}', '')::integer;
    v_artifact_digest text := p_command #>> '{delivery_envelope,artifact_digest}';
    v_max_revision integer; v_sequence integer; v_active record; v_existing record; v_artifact record;
    v_from text; v_to text; v_evidence jsonb := p_command -> 'transition_evidence';
    v_source_refs jsonb; v_approval_refs jsonb; v_policy_ref jsonb; v_receipt_reviewer_refs jsonb;
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    SELECT coalesce(jsonb_agg(jsonb_build_object('record_type','evidence_envelope',
        'record_id',source->>'envelope_id','record_digest',source->>'event_digest') ORDER BY ordinal), '[]'::jsonb)
      INTO v_source_refs
      FROM jsonb_array_elements(coalesce(p_command->'source_evidence','[]'::jsonb)) WITH ORDINALITY AS sources(source, ordinal);
    SELECT coalesce(jsonb_agg(jsonb_build_object('record_type','approval_record',
        'record_id',approval->>'approval_id','record_digest',approval->>'approval_digest') ORDER BY ordinal), '[]'::jsonb)
      INTO v_approval_refs
      FROM jsonb_array_elements(coalesce(p_command->'approvals','[]'::jsonb)) WITH ORDINALITY AS approvals(approval, ordinal);
    v_policy_ref := jsonb_build_object('record_type','policy_decision',
        'record_id',p_command #>> '{policy_decision,decision_id}',
        'record_digest',p_command #>> '{policy_decision,decision_digest}');
    v_receipt_reviewer_refs := CASE WHEN p_command #>> '{policy_decision,decision}' = 'require_approval'
        THEN v_approval_refs ELSE p_command #> '{delivery_envelope,reviewer_refs}' END;
    IF v_operation <> p_expected_operation OR v_operation NOT IN ('install','activate','rollback','deactivate') OR v_operation_id IS NULL
       OR v_operation_digest !~ '^sha256:[0-9a-f]{64}$' OR v_skill IS NULL OR v_target IS NULL
       OR p_command #>> '{skill_proposal,tenant_id}' <> v_tenant
       OR p_command #>> '{skill_proposal,target_scope,actor_id}' <> v_actor
       OR p_command #>> '{skill_proposal,target_scope,selection,level}' <> 'actor'
       OR p_command #>> '{delivery_envelope,artifact_type}' <> 'skill'
       OR p_command #>> '{skill_proposal,record_type}' <> 'skill_proposal'
       OR p_command #>> '{gate_decision,record_type}' <> 'gate_decision'
       OR p_command #>> '{delivery_envelope,record_type}' <> 'delivery_envelope'
       OR p_command #>> '{policy_decision,record_type}' <> 'policy_decision'
       OR p_command #>> '{skill_proposal,proposal_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR p_command #>> '{gate_decision,decision_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR p_command #>> '{delivery_envelope,envelope_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR p_command #>> '{policy_decision,decision_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR p_command->'artifact' IS DISTINCT FROM p_command #> '{skill_proposal,artifact}'
       OR p_command #>> '{skill_proposal,artifact_revision}' <> v_target::text
       OR p_command #> '{gate_decision,proposal_refs}' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object('record_type','skill_proposal',
                'record_id',p_command #>> '{skill_proposal,proposal_id}',
                'record_digest',p_command #>> '{skill_proposal,proposal_digest}'))
       OR p_command #> '{delivery_envelope,gate_decision_ref}' IS DISTINCT FROM jsonb_build_object(
            'record_type','gate_decision','record_id',p_command #>> '{gate_decision,gate_id}',
            'record_digest',p_command #>> '{gate_decision,decision_digest}')
       OR p_command #> '{delivery_envelope,policy_refs}' IS DISTINCT FROM jsonb_build_array(v_policy_ref)
       OR p_command #> '{skill_proposal,evidence_refs}' IS DISTINCT FROM v_source_refs
       OR p_command #> '{delivery_envelope,evidence_refs}' IS DISTINCT FROM v_source_refs
       OR p_command #>> '{policy_decision,request_id}' <> p_command #>> '{skill_proposal,proposal_id}'
       OR p_command #>> '{policy_decision,request_digest}' <> p_command #>> '{skill_proposal,proposal_digest}'
       OR p_command #>> '{policy_decision,decision}' NOT IN ('authorize','require_approval')
       OR p_command #>> '{policy_decision,isolation_profile}' <> 'no_effect'
       OR jsonb_typeof(p_command -> 'approvals') <> 'array'
       OR (p_command #>> '{policy_decision,decision}' = 'authorize' AND jsonb_array_length(p_command -> 'approvals') <> 0)
       OR (p_command #>> '{policy_decision,decision}' = 'require_approval' AND jsonb_array_length(p_command -> 'approvals') = 0)
       OR (p_command #>> '{policy_decision,decision}' = 'require_approval'
           AND p_command #> '{delivery_envelope,reviewer_refs}' IS DISTINCT FROM v_approval_refs)
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(p_command->'approvals','[]'::jsonb)) approval
                  WHERE approval->>'record_type' <> 'approval_record'
                     OR approval->>'tenant_id' <> v_tenant
                     OR approval->>'request_id' <> p_command #>> '{skill_proposal,proposal_id}'
                     OR approval->>'request_digest' <> p_command #>> '{skill_proposal,proposal_digest}'
                     OR approval->>'policy_decision_id' <> p_command #>> '{policy_decision,decision_id}'
                     OR approval->>'policy_decision_digest' <> p_command #>> '{policy_decision,decision_digest}'
                     OR approval->>'disposition' <> 'approved'
                     OR approval->'constraints' IS DISTINCT FROM p_command #> '{policy_decision,constraints}'
                     OR (approval #>> '{separation_of_duties,required}')::boolean
                        AND (NOT coalesce((approval #>> '{separation_of_duties,satisfied}')::boolean,false)
                             OR approval->>'approver_actor_id'=v_actor))
       OR (v_operation='activate' AND (
              p_command #>> '{activation_receipt,record_type}' <> 'activation_receipt'
              OR p_command #>> '{activation_receipt,issuer_role}' <> 'runtime_authority'
              OR p_command #>> '{activation_receipt,delivery_id}' <> p_command #>> '{delivery_envelope,delivery_id}'
              OR p_command #>> '{activation_receipt,delivery_digest}' <> p_command #>> '{delivery_envelope,envelope_digest}'
              OR p_command #> '{activation_receipt,target_scope}' IS DISTINCT FROM p_command #> '{delivery_envelope,target_scope}'
              OR p_command #>> '{activation_receipt,artifact_type}' <> 'skill'
              OR p_command #>> '{activation_receipt,artifact_id}' <> v_skill
              OR p_command #>> '{activation_receipt,artifact_revision}' <> v_target::text
              OR p_command #>> '{activation_receipt,artifact_digest}' <> v_artifact_digest
              OR p_command #> '{activation_receipt,policy_refs}' IS DISTINCT FROM jsonb_build_array(v_policy_ref)
              OR p_command #> '{activation_receipt,reviewer_refs}' IS DISTINCT FROM v_receipt_reviewer_refs))
       OR (v_operation='rollback' AND (
              p_command #>> '{activation_receipt,record_type}' <> 'activation_receipt'
              OR p_command #>> '{rollback_receipt,record_type}' <> 'rollback_receipt'
              OR p_command #>> '{rollback_receipt,issuer_role}' <> 'runtime_authority'
              OR p_command #> '{rollback_receipt,activation_receipt_ref}' IS DISTINCT FROM jsonb_build_object(
                    'record_type','activation_receipt','record_id',p_command #>> '{activation_receipt,receipt_id}',
                    'record_digest',p_command #>> '{activation_receipt,receipt_digest}')
              OR p_command #> '{rollback_receipt,target_scope}' IS DISTINCT FROM p_command #> '{activation_receipt,target_scope}'
              OR p_command #>> '{rollback_receipt,artifact_type}' <> 'skill'
              OR p_command #>> '{rollback_receipt,artifact_id}' <> v_skill
              OR p_command #>> '{rollback_receipt,artifact_revision}' <> v_target::text
              OR p_command #>> '{rollback_receipt,artifact_digest}' <> v_artifact_digest
              OR p_command #> '{rollback_receipt,policy_refs}' IS DISTINCT FROM jsonb_build_array(v_policy_ref)
              OR p_command #> '{rollback_receipt,reviewer_refs}' IS DISTINCT FROM v_receipt_reviewer_refs))
       OR jsonb_typeof(p_command -> 'source_evidence') <> 'array'
       OR jsonb_array_length(p_command -> 'source_evidence') = 0
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(p_command -> 'source_evidence') AS source
                  WHERE source ->> 'record_type' <> 'evidence_envelope'
                     OR source ->> 'tenant_id' <> v_tenant
                     OR source ->> 'event_digest' !~ '^sha256:[0-9a-f]{64}$')
       OR p_command #>> '{validity,expires_at}' IS NULL OR p_command #>> '{retention,expires_at}' IS NULL
       OR (p_command #>> '{validity,expires_at}')::timestamptz <= clock_timestamp()
       OR (p_command #>> '{retention,expires_at}')::timestamptz <= clock_timestamp()
       OR v_evidence ->> 'record_type' <> 'evidence_envelope'
       OR v_evidence ->> 'tenant_id' <> v_tenant
       OR v_evidence #>> '{draft,event_kind}' <> 'skill.lifecycle_transition'
       OR v_evidence #>> '{draft,inline_payload,operation_digest}' <> v_operation_digest
       OR v_evidence #> '{draft,inline_payload,command}' <> (p_command - 'transition_evidence')
       OR NOT EXISTS (SELECT 1 FROM public.gah_evidence_events transition_event
                      WHERE transition_event.tenant_id=v_tenant AND transition_event.actor_id=v_actor
                        AND transition_event.envelope_id=v_evidence->>'envelope_id'
                        AND transition_event.event_digest=v_evidence->>'event_digest'
                        AND transition_event.envelope_json=v_evidence)
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(p_command -> 'source_evidence') source
                  WHERE NOT EXISTS (SELECT 1 FROM public.gah_evidence_events source_event
                                    WHERE source_event.tenant_id=v_tenant AND source_event.actor_id=v_actor
                                      AND source_event.envelope_id=source->>'envelope_id'
                                      AND source_event.event_digest=source->>'event_digest'
                                      AND source_event.envelope_json=source))
    THEN RAISE EXCEPTION 'skill canonical wire command is invalid'; END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('skill:' || v_tenant || ':' || v_skill, 0));
    SELECT * INTO v_existing FROM public.gah_skill_lifecycle_transitions
      WHERE tenant_id = v_tenant AND operation_id = v_operation_id FOR UPDATE;
    IF FOUND THEN
        IF v_existing.operation_digest <> v_operation_digest OR v_existing.command_json IS DISTINCT FROM (p_command - 'transition_evidence') THEN
            RAISE EXCEPTION 'skill lifecycle replay conflicts with stored authority';
        END IF;
        SELECT artifact_digest INTO v_artifact_digest FROM public.gah_skill_artifact_revisions
          WHERE tenant_id=v_tenant AND skill_id=v_skill AND revision=v_existing.target_revision;
        RETURN gah_skill_result(v_operation_id, v_operation_digest, v_skill, v_existing.target_revision,
            v_existing.to_state, v_artifact_digest, v_existing.evidence_event_digest, true);
    END IF;
    SELECT revision INTO v_max_revision FROM public.gah_skill_artifact_revisions
      WHERE tenant_id=v_tenant AND skill_id=v_skill ORDER BY revision DESC LIMIT 1 FOR UPDATE;
    SELECT * INTO v_active FROM public.gah_active_skill_projection
      WHERE tenant_id=v_tenant AND skill_id=v_skill FOR UPDATE;
    IF v_operation = 'install' THEN
        IF v_expected IS DISTINCT FROM v_max_revision OR v_target <> coalesce(v_max_revision, 0) + 1 THEN
            RAISE EXCEPTION 'skill install revision is stale';
        END IF;
        IF p_command #>> '{skill_proposal,artifact_revision}' <> v_target::text
           OR p_command -> 'artifact' IS NULL
        THEN RAISE EXCEPTION 'skill install artifact binding is invalid'; END IF;
        INSERT INTO public.gah_skill_artifact_revisions (tenant_id,actor_id,skill_id,revision,proposal_id,proposal_digest,artifact_digest,artifact_json,command_json)
        VALUES (v_tenant,v_actor,v_skill,v_target,p_command #>> '{skill_proposal,proposal_id}',p_command #>> '{skill_proposal,proposal_digest}',v_artifact_digest,p_command -> 'artifact',p_command);
        v_from := CASE WHEN v_active IS NULL THEN NULL ELSE 'active' END; v_to := 'installed';
    ELSE
        IF v_max_revision IS NULL OR v_expected IS DISTINCT FROM v_max_revision THEN
            RAISE EXCEPTION 'skill transition revision is stale'; END IF;
        SELECT * INTO v_artifact FROM public.gah_skill_artifact_revisions WHERE tenant_id=v_tenant AND skill_id=v_skill AND revision=v_target;
        IF NOT FOUND OR v_artifact.artifact_digest <> v_artifact_digest THEN RAISE EXCEPTION 'skill target revision is missing or digest-mismatched'; END IF;
        IF v_operation='activate' THEN
            IF p_command #>> '{activation_receipt,record_type}' <> 'activation_receipt' OR p_command -> 'rollback_receipt' IS NOT NULL THEN RAISE EXCEPTION 'activation receipt is required'; END IF;
            v_from := CASE WHEN v_active IS NULL THEN 'inactive' ELSE 'active' END; v_to := 'active';
        ELSIF v_operation='rollback' THEN
            IF v_active IS NULL OR p_command #>> '{activation_receipt,record_type}' <> 'activation_receipt' OR p_command #>> '{rollback_receipt,record_type}' <> 'rollback_receipt' THEN RAISE EXCEPTION 'rollback requires an active bound receipt'; END IF;
            IF p_command #>> '{rollback_receipt,restored_revision_ref,record_type}' <> 'skill_proposal'
               OR p_command #>> '{rollback_receipt,restored_revision_ref,record_id}' <> v_skill
               OR p_command #>> '{rollback_receipt,restored_revision_ref,record_digest}' <> v_artifact_digest
            THEN RAISE EXCEPTION 'rollback restored revision does not bind target artifact'; END IF;
            v_from := 'active'; v_to := 'active';
        ELSE
            IF v_active IS NULL OR v_active.revision <> v_target OR p_command -> 'activation_receipt' IS NOT NULL OR p_command -> 'rollback_receipt' IS NOT NULL THEN RAISE EXCEPTION 'deactivate requires the active revision only'; END IF;
            v_from := 'active'; v_to := 'inactive';
        END IF;
    END IF;
    SELECT coalesce(transition_sequence, 0) + 1 INTO v_sequence FROM public.gah_skill_lifecycle_transitions
      WHERE tenant_id=v_tenant AND skill_id=v_skill ORDER BY transition_sequence DESC LIMIT 1 FOR UPDATE;
    v_sequence := coalesce(v_sequence, 1);
    INSERT INTO public.gah_skill_lifecycle_transitions (tenant_id,actor_id,skill_id,transition_sequence,operation_id,operation,operation_digest,expected_revision,target_revision,from_state,to_state,command_json,evidence_json,evidence_event_digest)
    VALUES (v_tenant,v_actor,v_skill,v_sequence,v_operation_id,v_operation,v_operation_digest,v_expected,v_target,v_from,v_to,p_command - 'transition_evidence',v_evidence,v_evidence->>'event_digest');
    IF v_to='active' THEN
        INSERT INTO public.gah_active_skill_projection (tenant_id,actor_id,skill_id,revision,artifact_digest,lifecycle_state,transition_sequence)
        VALUES (v_tenant,v_actor,v_skill,v_target,v_artifact_digest,'active',v_sequence)
        ON CONFLICT (tenant_id,skill_id) DO UPDATE SET actor_id=excluded.actor_id,revision=excluded.revision,artifact_digest=excluded.artifact_digest,transition_sequence=excluded.transition_sequence,rebuilt_at=clock_timestamp();
    ELSIF v_operation <> 'install' THEN
        DELETE FROM public.gah_active_skill_projection WHERE tenant_id=v_tenant AND skill_id=v_skill;
    END IF;
    RETURN gah_skill_result(v_operation_id,v_operation_digest,v_skill,v_target,v_to,v_artifact_digest,v_evidence->>'event_digest',false);
END $function$;

CREATE FUNCTION gah_rebuild_skill_projection(p_actor jsonb, p_command jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_tenant text:=p_actor->>'tenant_id'; v_actor text:=p_actor->>'actor_id';
    v_skill text:=p_command->>'skill_id'; v_expected integer:=nullif(p_command->>'expected_revision','')::integer;
    v_event record; v_artifact record; v_active_artifact record;
    v_max_revision integer; v_active_revision integer; v_active_sequence integer;
    v_last_operation text; v_last_event_digest text; v_history_count integer;
    v_ledger_count integer; v_valid_count integer; v_expected_sequence integer := 0;
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF p_command <> jsonb_build_object(
        'operation', 'rebuild',
        'operation_id', p_command->>'operation_id',
        'operation_digest', p_command->>'operation_digest',
        'expected_revision', v_expected,
        'skill_id', v_skill
    ) OR p_command->>'operation_id' IS NULL
       OR p_command->>'operation_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR v_skill IS NULL OR v_expected IS NULL THEN
        RAISE EXCEPTION 'skill rebuild canonical wire command is invalid';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill-operation:' || v_tenant || ':' || p_command->>'operation_id', 0));
    SELECT * INTO v_event FROM public.gah_skill_projection_rebuilds
     WHERE tenant_id=v_tenant AND operation_id=p_command->>'operation_id' FOR UPDATE;
    IF FOUND THEN
        IF v_event.operation_digest <> p_command->>'operation_digest'
           OR v_event.command_json IS DISTINCT FROM p_command THEN
            RAISE EXCEPTION 'skill projection rebuild replay conflicts with stored authority';
        END IF;
        RETURN gah_skill_result(v_event.operation_id,v_event.operation_digest,v_event.skill_id,
            v_event.result_revision,v_event.lifecycle_state,v_event.artifact_digest,
            v_event.transition_digest,true);
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('skill:' || v_tenant || ':' || v_skill, 0));
    SELECT max(revision) INTO v_max_revision FROM public.gah_skill_artifact_revisions
     WHERE tenant_id=v_tenant AND actor_id=v_actor AND skill_id=v_skill;
    IF v_max_revision IS DISTINCT FROM v_expected THEN
        RAISE EXCEPTION 'skill projection rebuild revision is stale';
    END IF;
    SELECT * INTO v_artifact FROM public.gah_skill_artifact_revisions WHERE tenant_id=v_tenant AND skill_id=v_skill AND revision=v_expected;
    IF NOT FOUND THEN RAISE EXCEPTION 'skill projection rebuild has no artifact revision'; END IF;
    -- Every ledger event must have one immutable transition and every
    -- transition must have its exact ledger event.  Projection deletion only
    -- happens after this complete-history proof succeeds.
    SELECT count(*) INTO v_history_count
      FROM public.gah_skill_lifecycle_transitions
     WHERE tenant_id=v_tenant AND actor_id=v_actor AND skill_id=v_skill;
    SELECT count(*) INTO v_ledger_count
      FROM public.gah_evidence_events
     WHERE tenant_id=v_tenant AND actor_id=v_actor
       AND envelope_json #>> '{draft,event_kind}'='skill.lifecycle_transition'
       AND envelope_json #>> '{draft,inline_payload,skill_id}'=v_skill;
    SELECT count(*) INTO v_valid_count
      FROM public.gah_skill_lifecycle_transitions transition
      JOIN public.gah_evidence_events transition_event
        ON transition_event.tenant_id=transition.tenant_id
       AND transition_event.actor_id=transition.actor_id
       AND transition_event.event_digest=transition.evidence_event_digest
       AND transition_event.envelope_json=transition.evidence_json
     WHERE transition.tenant_id=v_tenant AND transition.actor_id=v_actor AND transition.skill_id=v_skill
       AND transition_event.envelope_json #>> '{draft,event_kind}'='skill.lifecycle_transition'
       AND transition_event.envelope_json #>> '{draft,inline_payload,skill_id}'=v_skill
       AND transition_event.envelope_json #> '{draft,inline_payload,command}'=transition.command_json;
    IF v_history_count = 0 OR v_history_count <> v_ledger_count OR v_history_count <> v_valid_count THEN
        RAISE EXCEPTION 'skill projection rebuild canonical evidence is missing or corrupt';
    END IF;
    -- transition_sequence is a skill-scoped total order.  It supersedes
    -- run-local evidence sequence_number, which starts over in every run.
    FOR v_event IN
        SELECT transition.transition_sequence, transition.operation, transition.target_revision,
               transition.evidence_event_digest, transition_event.envelope_json
          FROM public.gah_skill_lifecycle_transitions transition
          JOIN public.gah_evidence_events transition_event
            ON transition_event.tenant_id=transition.tenant_id
           AND transition_event.actor_id=transition.actor_id
           AND transition_event.event_digest=transition.evidence_event_digest
           AND transition_event.envelope_json=transition.evidence_json
         WHERE transition.tenant_id=v_tenant AND transition.actor_id=v_actor AND transition.skill_id=v_skill
           AND transition_event.envelope_json #>> '{draft,event_kind}'='skill.lifecycle_transition'
           AND transition_event.envelope_json #>> '{draft,inline_payload,skill_id}'=v_skill
         ORDER BY transition.transition_sequence
    LOOP
        v_expected_sequence := v_expected_sequence + 1;
        IF v_event.transition_sequence <> v_expected_sequence THEN
            RAISE EXCEPTION 'skill projection rebuild lifecycle history is not contiguous';
        END IF;
        v_last_operation := v_event.operation;
        v_last_event_digest := v_event.evidence_event_digest;
        IF v_event.operation IN ('activate','rollback') THEN
            v_active_revision := v_event.target_revision;
            v_active_sequence := v_event.transition_sequence;
        ELSIF v_event.operation='deactivate' THEN
            v_active_revision := NULL;
            v_active_sequence := NULL;
        END IF;
    END LOOP;
    IF v_last_operation IS NULL THEN RAISE EXCEPTION 'skill projection rebuild has no canonical lifecycle evidence'; END IF;
    DELETE FROM public.gah_active_skill_projection WHERE tenant_id=v_tenant AND skill_id=v_skill;
    IF v_active_revision IS NOT NULL THEN
        SELECT * INTO v_active_artifact FROM public.gah_skill_artifact_revisions
         WHERE tenant_id=v_tenant AND skill_id=v_skill AND revision=v_active_revision;
        IF NOT FOUND THEN RAISE EXCEPTION 'canonical active lifecycle evidence references no artifact'; END IF;
        INSERT INTO public.gah_active_skill_projection (tenant_id,actor_id,skill_id,revision,artifact_digest,lifecycle_state,transition_sequence)
        VALUES (v_tenant,v_actor,v_skill,v_active_revision,v_active_artifact.artifact_digest,'active',v_active_sequence);
        INSERT INTO public.gah_skill_projection_rebuilds (
            tenant_id,actor_id,operation_id,operation_digest,skill_id,expected_revision,
            result_revision,lifecycle_state,artifact_digest,transition_digest,command_json
        ) VALUES (
            v_tenant,v_actor,p_command->>'operation_id',p_command->>'operation_digest',v_skill,v_expected,
            v_active_revision,'active',v_active_artifact.artifact_digest,v_last_event_digest,p_command
        );
        RETURN gah_skill_result(p_command->>'operation_id',p_command->>'operation_digest',v_skill,
            v_active_revision,'active',v_active_artifact.artifact_digest,v_last_event_digest,false);
    END IF;
    INSERT INTO public.gah_skill_projection_rebuilds (
        tenant_id,actor_id,operation_id,operation_digest,skill_id,expected_revision,
        result_revision,lifecycle_state,artifact_digest,transition_digest,command_json
    ) VALUES (
        v_tenant,v_actor,p_command->>'operation_id',p_command->>'operation_digest',v_skill,v_expected,
        v_expected,CASE WHEN v_last_operation='install' THEN 'installed' ELSE 'inactive' END,
        v_artifact.artifact_digest,v_last_event_digest,p_command
    );
    RETURN gah_skill_result(p_command->>'operation_id',p_command->>'operation_digest',v_skill,v_expected,
        CASE WHEN v_last_operation='install' THEN 'installed' ELSE 'inactive' END,
        v_artifact.artifact_digest,v_last_event_digest,false);
END $function$;

CREATE FUNCTION gah_install_skill(jsonb,jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''install'')';
CREATE FUNCTION gah_activate_skill(jsonb,jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''activate'')';
CREATE FUNCTION gah_rollback_skill(jsonb,jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''rollback'')';
CREATE FUNCTION gah_deactivate_skill(jsonb,jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''deactivate'')';

CREATE FUNCTION gah_resolve_active_skill(p_actor jsonb, p_query jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE v_row record;
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF nullif(p_query->>'skill_id','') IS NULL THEN RAISE EXCEPTION 'one exact skill_id is required'; END IF;
    SELECT * INTO v_row FROM public.gah_active_skill_projection WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id' AND skill_id=p_query->>'skill_id';
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN jsonb_build_object('skill_id',v_row.skill_id,'revision',v_row.revision,'artifact_digest',v_row.artifact_digest);
END $function$;

ALTER FUNCTION gah_skill_result(text,text,text,integer,text,text,text,boolean) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_skill_assert_actor(jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_lookup_skill_replay(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_rebuild_skill_projection(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_install_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_activate_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_rollback_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_deactivate_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_resolve_active_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_skill_result(text,text,text,integer,text,text,text,boolean), gah_skill_assert_actor(jsonb), gah_lookup_skill_replay(jsonb,jsonb), gah_apply_skill_lifecycle(jsonb,jsonb,text), gah_rebuild_skill_projection(jsonb,jsonb), gah_install_skill(jsonb,jsonb), gah_activate_skill(jsonb,jsonb), gah_rollback_skill(jsonb,jsonb), gah_deactivate_skill(jsonb,jsonb), gah_resolve_active_skill(jsonb,jsonb) FROM PUBLIC, gah_runtime;
GRANT EXECUTE ON FUNCTION gah_lookup_skill_replay(jsonb,jsonb) TO gah_authority_writer;
GRANT EXECUTE ON FUNCTION gah_install_skill(jsonb,jsonb), gah_activate_skill(jsonb,jsonb), gah_rollback_skill(jsonb,jsonb), gah_deactivate_skill(jsonb,jsonb), gah_rebuild_skill_projection(jsonb,jsonb) TO gah_authority_writer;
GRANT EXECUTE ON FUNCTION gah_resolve_active_skill(jsonb,jsonb) TO gah_runtime;
