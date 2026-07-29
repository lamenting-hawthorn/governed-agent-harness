-- Fix operator precedence in the lifecycle replay lock expression.  Without
-- explicit parentheses PostgreSQL treats the text prefix as JSON input.
CREATE OR REPLACE FUNCTION gah_lookup_skill_replay(p_actor jsonb, p_command jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE v_existing record; v_rebuild record; v_digest text; v_normalized jsonb := p_command - 'transition_evidence';
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF nullif(p_command ->> 'operation_id', '') IS NULL THEN
        RAISE EXCEPTION 'skill lifecycle operation_id is required';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill-operation:' || (p_actor ->> 'tenant_id') || ':' || (p_command ->> 'operation_id'), 0));
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

ALTER FUNCTION gah_lookup_skill_replay(jsonb,jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_lookup_skill_replay(jsonb,jsonb) FROM PUBLIC, gah_runtime, gah_authority_writer;
GRANT EXECUTE ON FUNCTION gah_lookup_skill_replay(jsonb,jsonb) TO gah_skill_lifecycle_authority;
