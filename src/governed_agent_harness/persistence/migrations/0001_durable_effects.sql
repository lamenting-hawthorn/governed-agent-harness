CREATE TABLE IF NOT EXISTS gah_run_heads (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    run_id text NOT NULL,
    next_sequence bigint NOT NULL DEFAULT 0 CHECK (next_sequence >= 0),
    last_event_digest text,
    last_recorded_at timestamptz,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, actor_id, run_id)
);

CREATE TABLE IF NOT EXISTS gah_evidence_events (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    run_id text NOT NULL,
    sequence_number bigint NOT NULL CHECK (sequence_number >= 0),
    envelope_id text NOT NULL,
    event_digest text NOT NULL,
    prior_event_digest text,
    envelope_json jsonb NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, sequence_number),
    UNIQUE (tenant_id, envelope_id),
    FOREIGN KEY (tenant_id, actor_id, run_id)
        REFERENCES gah_run_heads (tenant_id, actor_id, run_id),
    CHECK (envelope_json ->> 'tenant_id' = tenant_id),
    CHECK (envelope_json ->> 'envelope_id' = envelope_id),
    CHECK (envelope_json ->> 'event_digest' = event_digest),
    CHECK ((envelope_json ->> 'sequence_number')::bigint = sequence_number),
    CHECK (envelope_json #>> '{draft,run_id}' = run_id),
    CHECK ((envelope_json ->> 'recorded_at')::timestamptz = recorded_at),
    CHECK (envelope_json #>> '{draft,inline_payload,actor_id}' = actor_id)
);

CREATE TABLE IF NOT EXISTS gah_effect_executions (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    run_id text NOT NULL,
    request_id text NOT NULL,
    idempotency_key text NOT NULL,
    operation_digest text NOT NULL,
    binding_digest text NOT NULL,
    grant_id text NOT NULL,
    grant_digest text NOT NULL,
    state text NOT NULL CHECK (state IN ('prepared', 'completed', 'indeterminate')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    actor_context_json jsonb NOT NULL,
    request_json jsonb NOT NULL,
    policy_json jsonb NOT NULL,
    approvals_json jsonb NOT NULL,
    grant_json jsonb NOT NULL,
    intent_envelope_json jsonb NOT NULL,
    outcome_json jsonb,
    outcome_envelope_json jsonb,
    prepared_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, request_id),
    UNIQUE (tenant_id, idempotency_key),
    UNIQUE (tenant_id, grant_id),
    UNIQUE (tenant_id, actor_id, request_id, grant_id, grant_digest),
    FOREIGN KEY (tenant_id, actor_id, run_id)
        REFERENCES gah_run_heads (tenant_id, actor_id, run_id),
    CHECK (actor_context_json ->> 'tenant_id' = tenant_id),
    CHECK (actor_context_json ->> 'actor_id' = actor_id),
    CHECK (request_json ->> 'tenant_id' = tenant_id),
    CHECK (request_json ->> 'actor_id' = actor_id),
    CHECK (request_json ->> 'run_id' = run_id),
    CHECK (request_json ->> 'request_id' = request_id),
    CHECK (request_json #>> '{idempotency,idempotency_key}' = idempotency_key),
    CHECK (request_json #>> '{idempotency,operation_digest}' = operation_digest),
    CHECK (grant_json ->> 'tenant_id' = tenant_id),
    CHECK (grant_json ->> 'actor_id' = actor_id),
    CHECK (grant_json ->> 'run_id' = run_id),
    CHECK (grant_json ->> 'request_id' = request_id),
    CHECK (grant_json ->> 'grant_id' = grant_id),
    CHECK (
        (state = 'prepared' AND outcome_json IS NULL AND outcome_envelope_json IS NULL
            AND completed_at IS NULL)
        OR
        (state IN ('completed', 'indeterminate') AND outcome_json IS NOT NULL
            AND outcome_envelope_json IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS gah_grant_consumptions (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    grant_id text NOT NULL,
    grant_digest text NOT NULL,
    request_id text NOT NULL,
    consumed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, grant_id),
    FOREIGN KEY (tenant_id, actor_id, request_id, grant_id, grant_digest)
        REFERENCES gah_effect_executions (tenant_id, actor_id, request_id, grant_id, grant_digest),
    CHECK (grant_digest LIKE 'sha256:%')
);

ALTER TABLE gah_run_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_run_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE gah_evidence_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_evidence_events FORCE ROW LEVEL SECURITY;
ALTER TABLE gah_effect_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_effect_executions FORCE ROW LEVEL SECURITY;
ALTER TABLE gah_grant_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_grant_consumptions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS gah_run_heads_scope ON gah_run_heads;
CREATE POLICY gah_run_heads_scope ON gah_run_heads
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

DROP POLICY IF EXISTS gah_evidence_events_scope ON gah_evidence_events;
CREATE POLICY gah_evidence_events_scope ON gah_evidence_events
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

DROP POLICY IF EXISTS gah_effect_executions_scope ON gah_effect_executions;
CREATE POLICY gah_effect_executions_scope ON gah_effect_executions
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

DROP POLICY IF EXISTS gah_grant_consumptions_scope ON gah_grant_consumptions;
CREATE POLICY gah_grant_consumptions_scope ON gah_grant_consumptions
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

REVOKE DELETE, TRUNCATE ON gah_run_heads, gah_evidence_events,
    gah_effect_executions, gah_grant_consumptions FROM PUBLIC;
REVOKE UPDATE ON gah_evidence_events, gah_grant_consumptions FROM PUBLIC;
