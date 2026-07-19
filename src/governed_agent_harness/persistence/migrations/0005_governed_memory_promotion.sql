DO $roles$
DECLARE
    role_record record;
BEGIN
    SELECT * INTO role_record FROM pg_roles WHERE rolname = 'gah_schema_owner';
    IF NOT FOUND OR role_record.rolcanlogin OR role_record.rolsuper
        OR role_record.rolcreatedb OR role_record.rolcreaterole OR role_record.rolinherit
        OR role_record.rolreplication OR role_record.rolbypassrls THEN
        RAISE EXCEPTION 'gah_schema_owner is not a safe non-login owner';
    END IF;
END
$roles$;

CREATE TABLE gah_memory_transitions (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    memory_id text NOT NULL,
    revision integer NOT NULL CHECK (revision >= 1),
    proposal_id text NOT NULL,
    proposal_digest text NOT NULL CHECK (proposal_digest LIKE 'sha256:%'),
    binding_digest text NOT NULL CHECK (binding_digest LIKE 'sha256:%'),
    operation text NOT NULL CHECK (operation IN ('create', 'revise', 'supersede', 'delete')),
    expected_revision integer,
    actor_context_json jsonb NOT NULL,
    proposal_json jsonb NOT NULL,
    memory_decision_json jsonb NOT NULL,
    policy_decision_json jsonb NOT NULL,
    approvals_json jsonb NOT NULL,
    record_json jsonb NOT NULL,
    evidence_json jsonb NOT NULL,
    evidence_sequence bigint NOT NULL CHECK (evidence_sequence >= 0),
    evidence_event_digest text NOT NULL CHECK (evidence_event_digest LIKE 'sha256:%'),
    committed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, memory_id, revision),
    UNIQUE (tenant_id, proposal_id),
    UNIQUE (tenant_id, binding_digest),
    FOREIGN KEY (tenant_id, memory_id, revision)
        REFERENCES gah_memory_records (tenant_id, memory_id, revision),
    CHECK (jsonb_typeof(approvals_json) = 'array'),
    CHECK (actor_context_json ->> 'tenant_id' = tenant_id),
    CHECK (actor_context_json ->> 'actor_id' = actor_id),
    CHECK (proposal_json ->> 'record_type' = 'memory_proposal'),
    CHECK (proposal_json ->> 'tenant_id' = tenant_id),
    CHECK (proposal_json ->> 'proposal_id' = proposal_id),
    CHECK (proposal_json ->> 'proposal_digest' = proposal_digest),
    CHECK (memory_decision_json ->> 'record_type' = 'memory_decision'),
    CHECK (memory_decision_json ->> 'tenant_id' = tenant_id),
    CHECK (policy_decision_json ->> 'record_type' = 'policy_decision'),
    CHECK (policy_decision_json ->> 'tenant_id' = tenant_id),
    CHECK (record_json ->> 'record_type' = 'memory_record'),
    CHECK (record_json ->> 'tenant_id' = tenant_id),
    CHECK (record_json ->> 'memory_id' = memory_id),
    CHECK ((record_json ->> 'revision')::integer = revision),
    CHECK (record_json ->> 'record_digest' = record_json #>> '{record_digest}'),
    CHECK (record_json ->> 'lifecycle_state' = CASE WHEN operation = 'delete' THEN 'deleted' ELSE 'active' END),
    CHECK (evidence_json ->> 'record_type' = 'evidence_envelope'),
    CHECK (evidence_json ->> 'event_digest' = evidence_event_digest),
    CHECK ((evidence_json ->> 'sequence_number')::bigint = evidence_sequence),
    CHECK (evidence_json #>> '{draft,inline_payload,binding_digest}' = binding_digest),
    CHECK (expected_revision IS NULL OR expected_revision >= 1)
);

ALTER TABLE gah_memory_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_memory_transitions FORCE ROW LEVEL SECURITY;
CREATE POLICY gah_memory_transitions_scope ON gah_memory_transitions
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

ALTER TABLE gah_memory_transitions OWNER TO gah_schema_owner;
REVOKE ALL ON gah_memory_transitions FROM PUBLIC, gah_runtime, gah_authority_writer;

CREATE FUNCTION gah_commit_memory_transition(p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    existing record;
    transition jsonb := p_payload -> 'transition';
    evidence jsonb := p_payload -> 'evidence';
    record_json jsonb := transition -> 'committed_record';
    proposal jsonb := transition -> 'proposal';
    m_id text := record_json ->> 'memory_id';
    revision integer := (record_json ->> 'revision')::integer;
    expected_revision integer := nullif(p_payload ->> 'expected_revision', '')::integer;
    p_run_id text := proposal #>> '{producer,run_id}';
    head record;
    changed bigint;
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
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    IF (p_actor ->> 'issued_at')::timestamptz > clock_timestamp()
        OR (p_actor ->> 'expires_at')::timestamptz <= clock_timestamp() THEN
        RAISE EXCEPTION 'actor authority is not currently valid';
    END IF;
    PERFORM set_config('gah.tenant_id', p_actor ->> 'tenant_id', true);
    PERFORM set_config('gah.actor_id', p_actor ->> 'actor_id', true);

    -- Every caller uses the same deterministic order: memory, then proposal.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'memory:' || (p_actor ->> 'tenant_id') || ':' || m_id, 0
        )
    );
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'proposal:' || (p_actor ->> 'tenant_id') || ':' || (p_payload ->> 'proposal_id'), 0
        )
    );

    SELECT * INTO existing
      FROM public.gah_memory_transitions
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND proposal_id = p_payload ->> 'proposal_id'
     FOR UPDATE;
    IF FOUND THEN
        IF existing.binding_digest <> p_payload ->> 'binding_digest'
            OR existing.proposal_json <> proposal THEN
            RAISE EXCEPTION 'memory proposal replay conflicts with stored authority';
        END IF;
        RETURN jsonb_build_object(
            'replayed', true,
            'transition', jsonb_build_object(
                'proposal', existing.proposal_json,
                'memory_decision', existing.memory_decision_json,
                'policy_decision', existing.policy_decision_json,
                'approvals', existing.approvals_json,
                'committed_record', existing.record_json,
                'operation', existing.operation,
                'expected_revision', existing.expected_revision,
                'binding_digest', existing.binding_digest
            ),
            'evidence', existing.evidence_json
        );
    END IF;
    IF evidence IS NULL OR evidence = 'null'::jsonb THEN
        RETURN jsonb_build_object('replayed', false);
    END IF;
    IF p_payload ->> 'binding_digest' IS NULL
        OR transition ->> 'binding_digest' <> p_payload ->> 'binding_digest'
        OR transition ->> 'actor_id' <> p_actor ->> 'actor_id'
        OR transition -> 'actor_context' IS DISTINCT FROM p_actor
        OR proposal ->> 'tenant_id' <> p_actor ->> 'tenant_id'
        OR proposal #>> '{target_scope,tenant_id}' <> p_actor ->> 'tenant_id'
        OR proposal #>> '{target_scope,actor_id}' <> p_actor ->> 'actor_id'
        OR proposal #>> '{target_scope,selection,level}' <> 'actor'
        OR proposal ->> 'change_kind' <> transition ->> 'operation'
        OR proposal #>> '{proposed_record,memory_id}' <> m_id
        OR proposal #> '{proposed_record,scope}' IS DISTINCT FROM (record_json -> 'scope')
        OR (proposal -> 'proposed_record') - 'lifecycle_state' - 'record_digest'
            IS DISTINCT FROM record_json - 'lifecycle_state' - 'record_digest'
        OR transition #>> '{memory_decision,disposition}' <> 'accept'
        OR transition #>> '{memory_decision,proposal_ref,record_id}' <>
            proposal ->> 'proposal_id'
        OR transition #>> '{memory_decision,proposal_ref,record_digest}' <>
            proposal ->> 'proposal_digest'
        OR transition #>> '{memory_decision,actor_context_digest}' <>
            transition ->> 'actor_context_digest'
        OR transition #>> '{policy_decision,request_id}' <> proposal ->> 'proposal_id'
        OR transition #>> '{policy_decision,request_digest}' <>
            proposal ->> 'proposal_digest'
        OR transition #>> '{policy_decision,decision}' NOT IN ('authorize', 'require_approval')
        OR transition #>> '{policy_decision,isolation_profile}' <> 'no_effect'
        OR transition #> '{memory_decision,policy_refs}' IS DISTINCT FROM
            jsonb_build_array(jsonb_build_object(
                'record_type', 'policy_decision',
                'record_id', transition #>> '{policy_decision,decision_id}',
                'record_digest', transition #>> '{policy_decision,decision_digest}'
            ))
        OR record_json ->> 'tenant_id' <> p_actor ->> 'tenant_id'
        OR record_json #>> '{scope,actor_id}' <> p_actor ->> 'actor_id'
        OR record_json #>> '{scope,selection,level}' <> 'actor'
        OR record_json #>> '{retention,deletion_mode}' <> 'retain_non_sensitive_tombstone'
        OR evidence ->> 'tenant_id' <> p_actor ->> 'tenant_id'
        OR evidence #>> '{draft,inline_payload,actor_id}' <> p_actor ->> 'actor_id'
        OR evidence #>> '{draft,run_id}' <> p_run_id
        OR evidence #>> '{draft,event_kind}' <> 'memory.promoted'
        OR evidence #> '{draft,inline_payload}' <> transition THEN
        RAISE EXCEPTION 'memory transition binding or evidence scope is invalid';
    END IF;
    IF (proposal ->> 'expires_at')::timestamptz <= clock_timestamp()
        OR (proposal #>> '{target_scope,valid_until}')::timestamptz <= clock_timestamp()
        OR (record_json #>> '{retention,expires_at}')::timestamptz <= clock_timestamp()
        OR (record_json ->> 'expires_at')::timestamptz <= clock_timestamp()
        OR (record_json ->> 'effective_until')::timestamptz <= clock_timestamp() THEN
        RAISE EXCEPTION 'memory transition authority or validity is expired';
    END IF;
    IF transition #>> '{policy_decision,decision}' = 'require_approval'
        AND jsonb_array_length(transition -> 'approvals') = 0 THEN
        RAISE EXCEPTION 'approval-required memory promotion has no approval';
    END IF;
    IF transition #>> '{policy_decision,decision}' = 'authorize'
        AND jsonb_array_length(transition -> 'approvals') <> 0 THEN
        RAISE EXCEPTION 'authorize memory promotion cannot use alternate approval authority';
    END IF;

    INSERT INTO public.gah_run_heads (tenant_id, actor_id, run_id)
    VALUES (p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_run_id)
    ON CONFLICT (tenant_id, run_id) DO NOTHING;
    SELECT * INTO head FROM public.gah_run_heads
     WHERE tenant_id = p_actor ->> 'tenant_id' AND actor_id = p_actor ->> 'actor_id'
       AND gah_run_heads.run_id = p_run_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'promotion run belongs to another actor';
    END IF;
    IF (evidence ->> 'sequence_number')::bigint <> head.next_sequence
        OR evidence ->> 'event_digest' IS NULL THEN
        RAISE EXCEPTION 'promotion evidence sequence conflicts with run head';
    END IF;
    IF head.last_recorded_at IS NOT NULL
        AND (evidence ->> 'recorded_at')::timestamptz < head.last_recorded_at THEN
        RAISE EXCEPTION 'promotion evidence chronology regressed';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM jsonb_array_elements(proposal -> 'evidence_spans') AS span
         WHERE NOT EXISTS (
             SELECT 1 FROM public.gah_evidence_events AS source
              WHERE source.tenant_id = p_actor ->> 'tenant_id'
                AND source.actor_id = p_actor ->> 'actor_id'
                AND (source.envelope_id = span ->> 'evidence_id'
                     OR source.envelope_json #>> '{draft,event_id}' = span ->> 'evidence_id')
                AND source.envelope_json ->> 'payload_digest' = span ->> 'payload_digest'
         )
    ) THEN
        RAISE EXCEPTION 'promotion source evidence is missing or digest-mismatched';
    END IF;

    SELECT gah_memory_records.revision INTO changed FROM public.gah_memory_records
     WHERE gah_memory_records.tenant_id = p_actor ->> 'tenant_id'
       AND gah_memory_records.memory_id = m_id
     ORDER BY gah_memory_records.revision DESC LIMIT 1 FOR UPDATE;
    IF transition ->> 'operation' = 'create' THEN
        IF changed IS NOT NULL OR expected_revision IS NOT NULL OR revision <> 1 THEN
            RAISE EXCEPTION 'memory create conflicts with an existing memory';
        END IF;
    ELSIF changed IS NULL OR changed <> expected_revision THEN
        RAISE EXCEPTION 'memory expected revision is stale';
    END IF;
    IF transition ->> 'operation' <> 'create' AND revision <> expected_revision + 1 THEN
        RAISE EXCEPTION 'memory revision does not follow expected revision';
    END IF;

    INSERT INTO public.gah_evidence_events (
        tenant_id, actor_id, run_id, sequence_number, envelope_id,
        event_digest, prior_event_digest, envelope_json, recorded_at
    ) VALUES (
        p_actor ->> 'tenant_id', p_actor ->> 'actor_id', p_run_id,
        (evidence ->> 'sequence_number')::bigint, evidence ->> 'envelope_id',
        evidence ->> 'event_digest', evidence ->> 'prior_event_digest', evidence,
        (evidence ->> 'recorded_at')::timestamptz
    );
    UPDATE public.gah_run_heads
     SET next_sequence = head.next_sequence + 1,
         last_event_digest = evidence ->> 'event_digest',
         last_recorded_at = (evidence ->> 'recorded_at')::timestamptz,
         version = head.version + 1
     WHERE tenant_id = p_actor ->> 'tenant_id' AND actor_id = p_actor ->> 'actor_id'
     AND gah_run_heads.run_id = p_run_id AND version = head.version;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'promotion run head changed concurrently';
    END IF;

    INSERT INTO public.gah_memory_records (
        tenant_id, actor_id, memory_id, revision, record_digest, record_json,
        scope_json, proposition_json, observed_at, effective_from, effective_until,
        expires_at, lifecycle_state
    ) VALUES (
        p_actor ->> 'tenant_id', p_actor ->> 'actor_id', m_id, revision,
        record_json ->> 'record_digest', record_json, record_json -> 'scope',
        record_json -> 'proposition', (record_json ->> 'observed_at')::timestamptz,
        (record_json ->> 'effective_from')::timestamptz,
        nullif(record_json ->> 'effective_until', '')::timestamptz,
        nullif(record_json ->> 'expires_at', '')::timestamptz,
        record_json ->> 'lifecycle_state'
    );
    INSERT INTO public.gah_memory_transitions (
        tenant_id, actor_id, memory_id, revision, proposal_id, proposal_digest,
        binding_digest, operation, expected_revision, actor_context_json,
        proposal_json, memory_decision_json, policy_decision_json, approvals_json,
        record_json, evidence_json, evidence_sequence, evidence_event_digest, committed_at
    ) VALUES (
        p_actor ->> 'tenant_id', p_actor ->> 'actor_id', m_id, revision,
        p_payload ->> 'proposal_id', proposal ->> 'proposal_digest',
        p_payload ->> 'binding_digest', transition ->> 'operation', expected_revision,
        transition -> 'actor_context', proposal,
        transition -> 'memory_decision', transition -> 'policy_decision',
        transition -> 'approvals', record_json, evidence,
        (evidence ->> 'sequence_number')::bigint, evidence ->> 'event_digest', clock_timestamp()
    );
    RETURN jsonb_build_object('replayed', false, 'transition', transition, 'evidence', evidence);
END
$function$;

CREATE FUNCTION gah_rebuild_memory_projection(p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    event record;
    payload jsonb;
    transition jsonb;
    record_json jsonb;
    last_transition jsonb;
    last_evidence jsonb;
    wanted text := nullif(p_payload ->> 'memory_id', '');
    rebuilt integer := 0;
    rebuilt_revision integer := 0;
BEGIN
    IF p_actor ->> 'record_type' <> 'actor_context'
        OR NOT EXISTS (
            SELECT 1 FROM public.gah_runtime_principals
             WHERE database_role = session_user
               AND tenant_id = p_actor ->> 'tenant_id'
               AND actor_id = p_actor ->> 'actor_id'
        ) THEN
        RAISE EXCEPTION 'authority database principal is outside actor scope';
    END IF;
    IF (p_actor ->> 'issued_at')::timestamptz > clock_timestamp()
        OR (p_actor ->> 'expires_at')::timestamptz <= clock_timestamp() THEN
        RAISE EXCEPTION 'actor authority is not currently valid';
    END IF;
    PERFORM set_config('gah.tenant_id', p_actor ->> 'tenant_id', true);
    PERFORM set_config('gah.actor_id', p_actor ->> 'actor_id', true);
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'memory:' || (p_actor ->> 'tenant_id') || ':' || coalesce(wanted, '*'), 0
        )
    );
    IF wanted IS NULL THEN
        RAISE EXCEPTION 'one exact memory_id is required for projection rebuild';
    END IF;
    DELETE FROM public.gah_memory_transitions
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND memory_id = wanted;
    DELETE FROM public.gah_memory_records
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND memory_id = wanted;
    FOR event IN
        SELECT envelope_json
          FROM public.gah_evidence_events
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND actor_id = p_actor ->> 'actor_id'
           AND envelope_json #>> '{draft,event_kind}' = 'memory.promoted'
           AND envelope_json #>> '{draft,inline_payload,committed_record,memory_id}' = wanted
         ORDER BY (envelope_json #>> '{draft,inline_payload,committed_record,revision}')::integer,
                  recorded_at, run_id, sequence_number
    LOOP
        payload := event.envelope_json #> '{draft,inline_payload}';
        transition := payload;
        record_json := transition -> 'committed_record';
        IF (record_json ->> 'revision')::integer <> rebuilt_revision + 1 THEN
            RAISE EXCEPTION 'canonical memory promotion revisions are not contiguous';
        END IF;
        IF record_json ->> 'memory_id' = wanted THEN
            INSERT INTO public.gah_memory_records (
                tenant_id, actor_id, memory_id, revision, record_digest, record_json,
                scope_json, proposition_json, observed_at, effective_from, effective_until,
                expires_at, lifecycle_state
            ) VALUES (
                p_actor ->> 'tenant_id', p_actor ->> 'actor_id', record_json ->> 'memory_id',
                (record_json ->> 'revision')::integer, record_json ->> 'record_digest', record_json,
                record_json -> 'scope', record_json -> 'proposition',
                (record_json ->> 'observed_at')::timestamptz,
                (record_json ->> 'effective_from')::timestamptz,
                nullif(record_json ->> 'effective_until', '')::timestamptz,
                nullif(record_json ->> 'expires_at', '')::timestamptz,
                record_json ->> 'lifecycle_state'
            ) ON CONFLICT (tenant_id, memory_id, revision) DO UPDATE SET
                actor_id = excluded.actor_id, record_digest = excluded.record_digest,
                record_json = excluded.record_json, scope_json = excluded.scope_json,
                proposition_json = excluded.proposition_json, observed_at = excluded.observed_at,
                effective_from = excluded.effective_from, effective_until = excluded.effective_until,
                expires_at = excluded.expires_at, lifecycle_state = excluded.lifecycle_state;
            INSERT INTO public.gah_memory_transitions (
                tenant_id, actor_id, memory_id, revision, proposal_id, proposal_digest,
                binding_digest, operation, expected_revision, actor_context_json,
                proposal_json, memory_decision_json, policy_decision_json, approvals_json,
                record_json, evidence_json, evidence_sequence, evidence_event_digest, committed_at
            ) VALUES (
                p_actor ->> 'tenant_id', p_actor ->> 'actor_id', record_json ->> 'memory_id',
                (record_json ->> 'revision')::integer, transition -> 'proposal' ->> 'proposal_id',
                transition -> 'proposal' ->> 'proposal_digest', transition ->> 'binding_digest',
                transition ->> 'operation', nullif(transition ->> 'expected_revision', '')::integer,
                transition -> 'actor_context', transition -> 'proposal',
                transition -> 'memory_decision',
                transition -> 'policy_decision', transition -> 'approvals', record_json,
                event.envelope_json, (event.envelope_json ->> 'sequence_number')::bigint,
                event.envelope_json ->> 'event_digest', (event.envelope_json ->> 'recorded_at')::timestamptz
            ) ON CONFLICT (tenant_id, memory_id, revision) DO UPDATE SET
                actor_id = excluded.actor_id, proposal_id = excluded.proposal_id,
                proposal_digest = excluded.proposal_digest, binding_digest = excluded.binding_digest,
                operation = excluded.operation, expected_revision = excluded.expected_revision,
                actor_context_json = excluded.actor_context_json, proposal_json = excluded.proposal_json,
                memory_decision_json = excluded.memory_decision_json,
                policy_decision_json = excluded.policy_decision_json, approvals_json = excluded.approvals_json,
                record_json = excluded.record_json, evidence_json = excluded.evidence_json,
                evidence_sequence = excluded.evidence_sequence,
                evidence_event_digest = excluded.evidence_event_digest, committed_at = excluded.committed_at;
            rebuilt := rebuilt + 1;
            rebuilt_revision := (record_json ->> 'revision')::integer;
            last_transition := transition;
            last_evidence := event.envelope_json;
        END IF;
    END LOOP;
    IF rebuilt = 0 THEN
        RAISE EXCEPTION 'canonical memory promotion evidence was not found';
    END IF;
    RETURN jsonb_build_object(
        'rebuilt', rebuilt, 'transition', last_transition, 'evidence', last_evidence
    );
END
$function$;

ALTER FUNCTION gah_commit_memory_transition(jsonb, jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_rebuild_memory_projection(jsonb, jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_commit_memory_transition(jsonb, jsonb) FROM PUBLIC, gah_runtime;
REVOKE ALL ON FUNCTION gah_rebuild_memory_projection(jsonb, jsonb) FROM PUBLIC, gah_runtime;
GRANT EXECUTE ON FUNCTION gah_commit_memory_transition(jsonb, jsonb) TO gah_authority_writer;
GRANT EXECUTE ON FUNCTION gah_rebuild_memory_projection(jsonb, jsonb) TO gah_authority_writer;

-- Phase 4.3 makes the retention horizon an authoritative retrieval ceiling.
CREATE OR REPLACE FUNCTION gah_retrieve_memory(p_actor jsonb, p_query jsonb)
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
           AND (record_json #>> '{retention,expires_at}')::timestamptz > clock_timestamp()
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
