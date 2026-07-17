ALTER TABLE gah_effect_executions
    DROP CONSTRAINT IF EXISTS gah_effect_executions_check13;

CREATE TABLE gah_runtime_principals (
    database_role name PRIMARY KEY,
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    CHECK (length(tenant_id) > 0),
    CHECK (length(actor_id) > 0)
);
ALTER TABLE gah_runtime_principals OWNER TO gah_schema_owner;
REVOKE ALL ON gah_runtime_principals FROM PUBLIC, gah_runtime;

CREATE FUNCTION gah_runtime_read(p_operation text, p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    result jsonb;
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
    PERFORM set_config('gah.tenant_id', p_actor ->> 'tenant_id', true);
    PERFORM set_config('gah.actor_id', p_actor ->> 'actor_id', true);

    IF p_operation = 'effect_by_request' THEN
        SELECT to_jsonb(e) || jsonb_build_object(
                   '_lease_expired', lease_expires_at <= clock_timestamp()
               ) INTO result
          FROM public.gah_effect_executions AS e
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id';
    ELSIF p_operation = 'effect_by_binding' THEN
        SELECT coalesce(jsonb_agg(to_jsonb(e)), '[]'::jsonb) INTO result
          FROM public.gah_effect_executions AS e
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND (idempotency_key = p_payload ->> 'idempotency_key'
                OR grant_id = p_payload ->> 'grant_id'
                OR request_id = p_payload ->> 'request_id');
    ELSIF p_operation = 'events' THEN
        SELECT coalesce(jsonb_agg(envelope_json ORDER BY run_id, sequence_number), '[]'::jsonb)
          INTO result
          FROM public.gah_evidence_events
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND (p_payload ->> 'run_id' IS NULL OR run_id = p_payload ->> 'run_id');
    ELSIF p_operation = 'lifecycle_by_id' THEN
        SELECT to_jsonb(l) INTO result
          FROM public.gah_request_lifecycle AS l
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id';
    ELSIF p_operation = 'lifecycle_by_idempotency' THEN
        SELECT jsonb_build_object('request_id', request_id, 'request_json', request_json)
          INTO result
          FROM public.gah_request_lifecycle
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND idempotency_key = p_payload ->> 'idempotency_key';
    ELSIF p_operation = 'lifecycle_events' THEN
        SELECT coalesce(jsonb_agg(envelope_json ORDER BY run_id, sequence_number), '[]'::jsonb)
          INTO result
          FROM public.gah_evidence_events
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND (
                envelope_json #>> '{draft,inline_payload,request,request_id}' =
                    p_payload ->> 'request_id'
                OR envelope_json #>> '{draft,inline_payload,request_id}' =
                    p_payload ->> 'request_id'
           );
    ELSE
        RAISE EXCEPTION 'runtime read operation is not allowed';
    END IF;
    RETURN result;
END
$function$;

CREATE FUNCTION gah_authority_write_internal(p_operation text, p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    result jsonb;
    changed bigint;
    envelope jsonb;
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
    PERFORM set_config('gah.tenant_id', p_actor ->> 'tenant_id', true);
    PERFORM set_config('gah.actor_id', p_actor ->> 'actor_id', true);

    IF p_operation = 'lock_run' THEN
        INSERT INTO public.gah_run_heads (tenant_id, actor_id, run_id)
        VALUES (p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_payload ->> 'run_id')
        ON CONFLICT (tenant_id, run_id) DO NOTHING;
        SELECT jsonb_build_object(
                   'next_sequence', next_sequence,
                   'last_event_digest', last_event_digest,
                   'last_recorded_at', last_recorded_at,
                   'version', version
               ) INTO result
          FROM public.gah_run_heads
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND run_id = p_payload ->> 'run_id'
         FOR UPDATE;
        IF result IS NULL THEN
            RAISE EXCEPTION 'run scope conflicts with an existing actor';
        END IF;
    ELSIF p_operation = 'commit_evidence' THEN
        envelope := p_payload -> 'envelope';
        IF envelope ->> 'tenant_id' <> p_actor ->> 'tenant_id'
            OR envelope #>> '{draft,inline_payload,actor_id}' <> p_actor ->> 'actor_id'
            OR envelope #>> '{draft,run_id}' <> p_payload ->> 'run_id' THEN
            RAISE EXCEPTION 'evidence scope is invalid';
        END IF;
        INSERT INTO public.gah_evidence_events (
            tenant_id, actor_id, run_id, sequence_number, envelope_id,
            event_digest, prior_event_digest, envelope_json, recorded_at
        ) VALUES (
            p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_payload ->> 'run_id',
            (envelope ->> 'sequence_number')::bigint, envelope ->> 'envelope_id',
            envelope ->> 'event_digest', envelope ->> 'prior_event_digest', envelope,
            (envelope ->> 'recorded_at')::timestamptz
        );
        UPDATE public.gah_run_heads
           SET next_sequence = (envelope ->> 'sequence_number')::bigint + 1,
               last_event_digest = envelope ->> 'event_digest',
               last_recorded_at = (envelope ->> 'recorded_at')::timestamptz,
               version = version + 1
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND run_id = p_payload ->> 'run_id'
           AND version = (p_payload ->> 'expected_version')::bigint;
        GET DIAGNOSTICS changed = ROW_COUNT;
        result := jsonb_build_object('changed', changed);
    ELSIF p_operation = 'insert_lifecycle' THEN
        INSERT INTO public.gah_request_lifecycle (
            tenant_id, actor_id, run_id, request_id, request_digest,
            idempotency_key, operation_digest, policy_decision_digest,
            actor_context_json, request_json, policy_json, state, version,
            last_evidence_sequence, last_evidence_digest
        ) VALUES (
            p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_payload ->> 'run_id',
            p_payload ->> 'request_id', p_payload ->> 'request_digest',
            p_payload ->> 'idempotency_key', p_payload ->> 'operation_digest',
            p_payload ->> 'policy_decision_digest', p_actor, p_payload -> 'request',
            p_payload -> 'policy', p_payload ->> 'state', 1,
            (p_payload ->> 'last_evidence_sequence')::bigint,
            p_payload ->> 'last_evidence_digest'
        );
        result := '{"changed":1}'::jsonb;
    ELSIF p_operation = 'approve_lifecycle' THEN
        UPDATE public.gah_request_lifecycle
           SET approvals_json = jsonb_build_array(p_payload -> 'approval'),
               state = 'approved', version = version + 1,
               last_evidence_sequence = (p_payload ->> 'last_evidence_sequence')::bigint,
               last_evidence_digest = p_payload ->> 'last_evidence_digest'
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id'
           AND state = 'approval_required'
           AND version = (p_payload ->> 'expected_version')::bigint;
        GET DIAGNOSTICS changed = ROW_COUNT;
        result := jsonb_build_object('changed', changed);
    ELSIF p_operation = 'grant_lifecycle' THEN
        UPDATE public.gah_request_lifecycle
           SET grant_json = p_payload -> 'grant', state = 'grant_issued',
               version = version + 1,
               last_evidence_sequence = (p_payload ->> 'last_evidence_sequence')::bigint,
               last_evidence_digest = p_payload ->> 'last_evidence_digest'
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id'
           AND state IN ('policy_authorized', 'approved')
           AND version = (p_payload ->> 'expected_version')::bigint;
        GET DIAGNOSTICS changed = ROW_COUNT;
        result := jsonb_build_object('changed', changed);
    ELSIF p_operation = 'rebuild_lifecycle' THEN
        INSERT INTO public.gah_request_lifecycle (
            tenant_id, actor_id, run_id, request_id, request_digest,
            idempotency_key, operation_digest, policy_decision_digest,
            actor_context_json, request_json, policy_json, approvals_json,
            grant_json, state, version, last_evidence_sequence, last_evidence_digest
        ) VALUES (
            p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_payload ->> 'run_id',
            p_payload ->> 'request_id', p_payload ->> 'request_digest',
            p_payload ->> 'idempotency_key', p_payload ->> 'operation_digest',
            p_payload ->> 'policy_decision_digest', p_actor, p_payload -> 'request',
            p_payload -> 'policy', coalesce(p_payload -> 'approvals', '[]'::jsonb),
            nullif(p_payload -> 'grant', 'null'::jsonb), p_payload ->> 'state',
            (p_payload ->> 'version')::bigint,
            (p_payload ->> 'last_evidence_sequence')::bigint,
            p_payload ->> 'last_evidence_digest'
        )
        ON CONFLICT (tenant_id, request_id) DO UPDATE
           SET actor_context_json = excluded.actor_context_json,
               request_json = excluded.request_json, policy_json = excluded.policy_json,
               approvals_json = excluded.approvals_json, grant_json = excluded.grant_json,
               state = excluded.state, version = excluded.version,
               last_evidence_sequence = excluded.last_evidence_sequence,
               last_evidence_digest = excluded.last_evidence_digest
         WHERE public.gah_request_lifecycle.actor_id = excluded.actor_id;
        GET DIAGNOSTICS changed = ROW_COUNT;
        result := jsonb_build_object('changed', changed);
    ELSIF p_operation = 'insert_effect' THEN
        INSERT INTO public.gah_effect_executions (
            tenant_id, actor_id, run_id, request_id, idempotency_key,
            operation_digest, binding_digest, grant_id, grant_digest, state,
            version, actor_context_json, request_json, policy_json, approvals_json,
            grant_json, intent_envelope_json, prepared_at, execution_attempt_id,
            owner_generation, lease_expires_at, last_renewed_at
        ) VALUES (
            p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_payload ->> 'run_id',
            p_payload ->> 'request_id', p_payload ->> 'idempotency_key',
            p_payload ->> 'operation_digest', p_payload ->> 'binding_digest',
            p_payload ->> 'grant_id', p_payload ->> 'grant_digest', 'prepared', 1,
            p_actor, p_payload -> 'request', p_payload -> 'policy', p_payload -> 'approvals',
            p_payload -> 'grant', p_payload -> 'intent',
            (p_payload ->> 'prepared_at')::timestamptz, p_payload ->> 'attempt_id', 1,
            clock_timestamp() + ((p_payload ->> 'lease_seconds')::double precision * interval '1 second'),
            clock_timestamp()
        );
        INSERT INTO public.gah_grant_consumptions (
            tenant_id, actor_id, grant_id, grant_digest, request_id, consumed_at
        ) VALUES (
            p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_payload ->> 'grant_id',
            p_payload ->> 'grant_digest', p_payload ->> 'request_id',
            (p_payload ->> 'prepared_at')::timestamptz
        );
        SELECT jsonb_build_object(
                   'lease_expires_at', lease_expires_at,
                   'last_renewed_at', last_renewed_at
               ) INTO result
          FROM public.gah_effect_executions
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id';
    ELSIF p_operation = 'renew_effect' THEN
        UPDATE public.gah_effect_executions AS effect
           SET lease_expires_at = clock_timestamp()
                    + ((p_payload ->> 'lease_seconds')::double precision * interval '1 second'),
               last_renewed_at = clock_timestamp(), state = 'executing'
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id'
           AND state IN ('prepared', 'executing')
           AND execution_attempt_id = p_payload ->> 'attempt_id'
           AND owner_generation = (p_payload ->> 'owner_generation')::bigint
           AND lease_expires_at > clock_timestamp()
        RETURNING to_jsonb(effect) INTO result;
    ELSIF p_operation = 'complete_effect' THEN
        UPDATE public.gah_effect_executions
           SET state = p_payload ->> 'state', version = version + 1,
               outcome_json = p_payload -> 'outcome',
               outcome_envelope_json = p_payload -> 'evidence',
               completed_at = (p_payload ->> 'completed_at')::timestamptz
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id'
           AND state IN ('prepared', 'executing')
           AND version = (p_payload ->> 'expected_version')::bigint
           AND execution_attempt_id = p_payload ->> 'attempt_id'
           AND owner_generation = (p_payload ->> 'owner_generation')::bigint
           AND lease_expires_at > clock_timestamp();
        GET DIAGNOSTICS changed = ROW_COUNT;
        result := jsonb_build_object('changed', changed);
    ELSIF p_operation = 'recover_effect' THEN
        UPDATE public.gah_effect_executions
           SET state = 'indeterminate', version = version + 1,
               owner_generation = owner_generation + 1,
               outcome_json = p_payload -> 'outcome',
               outcome_envelope_json = p_payload -> 'evidence',
               completed_at = clock_timestamp()
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND request_id = p_payload ->> 'request_id'
           AND state IN ('prepared', 'executing')
           AND execution_attempt_id = p_payload ->> 'attempt_id'
           AND owner_generation = (p_payload ->> 'owner_generation')::bigint
           AND lease_expires_at <= clock_timestamp();
        GET DIAGNOSTICS changed = ROW_COUNT;
        result := jsonb_build_object('changed', changed);
    ELSE
        RAISE EXCEPTION 'runtime write operation is not allowed';
    END IF;
    RETURN result;
END
$function$;

ALTER FUNCTION gah_runtime_read(text, jsonb, jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_authority_write_internal(text, jsonb, jsonb) OWNER TO gah_schema_owner;
GRANT USAGE ON SCHEMA public TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_runtime_read(text, jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION gah_authority_write_internal(text, jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gah_runtime_read(text, jsonb, jsonb) TO gah_runtime;

CREATE FUNCTION gah_lock_run(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('lock_run', p_actor, p_payload);
CREATE FUNCTION gah_commit_evidence(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('commit_evidence', p_actor, p_payload);
CREATE FUNCTION gah_submit_lifecycle(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('insert_lifecycle', p_actor, p_payload);
CREATE FUNCTION gah_accept_approval(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('approve_lifecycle', p_actor, p_payload);
CREATE FUNCTION gah_issue_grant(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('grant_lifecycle', p_actor, p_payload);
CREATE FUNCTION gah_rebuild_lifecycle(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('rebuild_lifecycle', p_actor, p_payload);
CREATE FUNCTION gah_prepare_effect(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('insert_effect', p_actor, p_payload);
CREATE FUNCTION gah_renew_effect(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('renew_effect', p_actor, p_payload);
CREATE FUNCTION gah_complete_effect(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('complete_effect', p_actor, p_payload);
CREATE FUNCTION gah_recover_effect(p_actor jsonb, p_payload jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
RETURN public.gah_authority_write_internal('recover_effect', p_actor, p_payload);

DO $entrypoints$
DECLARE
    function_name text;
BEGIN
    FOREACH function_name IN ARRAY ARRAY[
        'gah_lock_run', 'gah_commit_evidence', 'gah_submit_lifecycle',
        'gah_accept_approval', 'gah_issue_grant', 'gah_rebuild_lifecycle',
        'gah_prepare_effect', 'gah_renew_effect', 'gah_complete_effect',
        'gah_recover_effect'
    ] LOOP
        EXECUTE format(
            'ALTER FUNCTION %I(jsonb,jsonb) OWNER TO gah_schema_owner', function_name
        );
        EXECUTE format(
            'REVOKE ALL ON FUNCTION %I(jsonb,jsonb) FROM PUBLIC, gah_runtime', function_name
        );
        EXECUTE format(
            'GRANT EXECUTE ON FUNCTION %I(jsonb,jsonb) TO gah_authority_writer', function_name
        );
    END LOOP;
END
$entrypoints$;
GRANT EXECUTE ON FUNCTION gah_runtime_read(text, jsonb, jsonb) TO gah_authority_writer;
GRANT USAGE ON SCHEMA public TO gah_authority_writer;
