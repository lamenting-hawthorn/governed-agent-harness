-- Phase 5.1 review hardening: repeat inert lifecycle bindings at the durable
-- SQL sink and bind execution state access and leases to exact actor authority.

CREATE FUNCTION gah_skill_lifecycle_sink_command_valid(
    p_tenant text,
    p_actor text,
    p_skill text,
    p_revision integer,
    p_artifact_digest text,
    p_command jsonb
) RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
RETURN COALESCE((
    jsonb_typeof(p_command) = 'object'
    AND jsonb_typeof(p_command -> 'artifact') = 'object'
    AND p_command #>> '{skill_proposal,tenant_id}' = p_tenant
    AND p_command #>> '{gate_decision,tenant_id}' = p_tenant
    AND p_command #>> '{delivery_envelope,tenant_id}' = p_tenant
    AND p_command #>> '{policy_decision,tenant_id}' = p_tenant
    AND p_command #>> '{skill_proposal,target_scope,actor_id}' = p_actor
    AND p_command #> '{skill_proposal,target_scope,selection}'
        = jsonb_build_object('level', 'actor')
    AND p_command #> '{gate_decision,target_scope}'
        = p_command #> '{skill_proposal,target_scope}'
    AND p_command #> '{delivery_envelope,target_scope}'
        = p_command #> '{skill_proposal,target_scope}'
    AND p_command #>> '{skill_proposal,artifact_id}' = p_skill
    AND p_command #>> '{delivery_envelope,artifact_id}' = p_skill
    AND (p_command #>> '{skill_proposal,artifact_revision}')::integer = p_revision
    AND (p_command #>> '{delivery_envelope,artifact_revision}')::integer = p_revision
    AND p_command #>> '{delivery_envelope,artifact_type}' = 'skill'
    AND p_command #>> '{delivery_envelope,lifecycle_state}' = 'delivered'
    AND p_command -> 'artifact' = p_command #> '{skill_proposal,artifact}'
    AND NOT ((p_command -> 'artifact') ?| ARRAY[
        'archive', 'protected_payload', 'remote_uri', 'entrypoint'
    ])
    AND octet_length(convert_to(gah_canonical_json(p_command -> 'artifact'), 'UTF8'))
        <= 65536
    AND gah_canonical_sha256(p_command -> 'artifact') = p_artifact_digest
    AND p_command #>> '{delivery_envelope,artifact_digest}' = p_artifact_digest
), false);

ALTER FUNCTION gah_skill_lifecycle_sink_command_valid(
    text, text, text, integer, text, jsonb
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_skill_lifecycle_sink_command_valid(
    text, text, text, integer, text, jsonb
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

ALTER TABLE gah_skill_artifact_revisions
    ADD CONSTRAINT gah_skill_artifact_command_sink_guard
    CHECK (gah_skill_lifecycle_sink_command_valid(
        tenant_id,
        actor_id,
        skill_id,
        revision,
        artifact_digest,
        command_json
    ) IS TRUE);

ALTER TABLE gah_skill_lifecycle_transitions
    ADD CONSTRAINT gah_skill_transition_command_sink_guard
    CHECK (gah_skill_lifecycle_sink_command_valid(
        tenant_id,
        actor_id,
        skill_id,
        target_revision,
        command_json #>> '{delivery_envelope,artifact_digest}',
        command_json
    ) IS TRUE);

CREATE OR REPLACE FUNCTION gah_builtin_execution_assert_actor(p_actor jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    PERFORM set_config('gah.session_id', p_actor ->> 'session_id', true);
    PERFORM set_config(
        'gah.actor_context_digest',
        public.gah_canonical_sha256(p_actor),
        true
    );
END
$function$;

ALTER FUNCTION gah_builtin_execution_assert_actor(jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_builtin_execution_assert_actor(jsonb)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority;
GRANT EXECUTE ON FUNCTION gah_builtin_execution_assert_actor(jsonb)
    TO gah_runtime, gah_execution_admission_authority;

DROP POLICY gah_builtin_execution_state_scope ON gah_builtin_execution_state;
CREATE POLICY gah_builtin_execution_state_scope ON gah_builtin_execution_state
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
        AND run_id = nullif(current_setting('gah.session_id', true), '')
        AND command_json #>> '{tool_request,actor_context_digest}'
            = nullif(current_setting('gah.actor_context_digest', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
        AND run_id = nullif(current_setting('gah.session_id', true), '')
        AND command_json #>> '{tool_request,actor_context_digest}'
            = nullif(current_setting('gah.actor_context_digest', true), '')
    );

CREATE FUNCTION gah_builtin_execution_lease_within_authority()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF NEW.state = 'executing'
       AND (
           OLD.state IS DISTINCT FROM 'executing'
           OR OLD.lease_expires_at IS DISTINCT FROM NEW.lease_expires_at
       )
       AND (
           NEW.lease_expires_at IS NULL
           OR NEW.lease_expires_at >= (NEW.grant_json ->> 'expires_at')::timestamptz
       )
    THEN
        RAISE EXCEPTION 'execution lease exceeds the exact authority window';
    END IF;
    RETURN NEW;
END
$function$;

ALTER FUNCTION gah_builtin_execution_lease_within_authority()
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_builtin_execution_lease_within_authority()
    FROM PUBLIC, gah_runtime, gah_authority_writer,
        gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE TRIGGER gah_builtin_execution_lease_authority_guard
BEFORE UPDATE ON gah_builtin_execution_state
FOR EACH ROW
EXECUTE FUNCTION gah_builtin_execution_lease_within_authority();
