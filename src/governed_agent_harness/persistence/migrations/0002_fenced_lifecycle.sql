DO $roles$
DECLARE
    role_record record;
BEGIN
    SELECT * INTO role_record FROM pg_roles WHERE rolname = 'gah_schema_owner';
    IF NOT FOUND THEN
        CREATE ROLE gah_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    ELSIF role_record.rolcanlogin OR role_record.rolsuper OR role_record.rolcreatedb
        OR role_record.rolcreaterole OR role_record.rolinherit OR role_record.rolreplication
        OR role_record.rolbypassrls THEN
        RAISE EXCEPTION 'existing gah_schema_owner role has unsafe attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
         WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'gah_schema_owner')
            OR roleid = (SELECT oid FROM pg_roles WHERE rolname = 'gah_schema_owner')
    ) THEN
        RAISE EXCEPTION 'existing gah_schema_owner role has unsafe memberships';
    END IF;

    SELECT * INTO role_record FROM pg_roles WHERE rolname = 'gah_runtime';
    IF NOT FOUND THEN
        CREATE ROLE gah_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    ELSIF role_record.rolcanlogin OR role_record.rolsuper OR role_record.rolcreatedb
        OR role_record.rolcreaterole OR role_record.rolinherit OR role_record.rolreplication
        OR role_record.rolbypassrls THEN
        RAISE EXCEPTION 'existing gah_runtime role has unsafe attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
         WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'gah_runtime')
    ) THEN
        RAISE EXCEPTION 'existing gah_runtime role has unsafe memberships';
    END IF;

    SELECT * INTO role_record FROM pg_roles WHERE rolname = 'gah_authority_writer';
    IF NOT FOUND THEN
        CREATE ROLE gah_authority_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    ELSIF role_record.rolcanlogin OR role_record.rolsuper OR role_record.rolcreatedb
        OR role_record.rolcreaterole OR role_record.rolinherit OR role_record.rolreplication
        OR role_record.rolbypassrls THEN
        RAISE EXCEPTION 'existing gah_authority_writer role has unsafe attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
         WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'gah_authority_writer')
    ) THEN
        RAISE EXCEPTION 'existing gah_authority_writer role has unsafe memberships';
    END IF;
END
$roles$;

ALTER TABLE gah_effect_executions
    DROP CONSTRAINT gah_effect_executions_state_check,
    DROP CONSTRAINT gah_effect_executions_check,
    ADD COLUMN execution_attempt_id text,
    ADD COLUMN owner_generation bigint,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN last_renewed_at timestamptz;

UPDATE gah_effect_executions
   SET execution_attempt_id = 'legacy:' || request_id,
       owner_generation = 1,
       lease_expires_at = coalesce(completed_at, prepared_at),
       last_renewed_at = prepared_at;

ALTER TABLE gah_effect_executions
    ALTER COLUMN execution_attempt_id SET NOT NULL,
    ALTER COLUMN owner_generation SET NOT NULL,
    ALTER COLUMN lease_expires_at SET NOT NULL,
    ALTER COLUMN last_renewed_at SET NOT NULL,
    ADD CONSTRAINT gah_effect_executions_owner_generation_check
        CHECK (owner_generation >= 1),
    ADD CONSTRAINT gah_effect_executions_attempt_id_check
        CHECK (length(execution_attempt_id) > 0),
    ADD CONSTRAINT gah_effect_executions_lease_chronology_check
        CHECK (last_renewed_at <= lease_expires_at),
    ADD CONSTRAINT gah_effect_executions_state_check
        CHECK (state IN ('prepared', 'executing', 'completed', 'failed', 'indeterminate')),
    ADD CONSTRAINT gah_effect_executions_terminal_state_check CHECK (
        (state IN ('prepared', 'executing') AND outcome_json IS NULL
            AND outcome_envelope_json IS NULL AND completed_at IS NULL)
        OR
        (state IN ('completed', 'failed', 'indeterminate') AND outcome_json IS NOT NULL
            AND outcome_envelope_json IS NOT NULL AND completed_at IS NOT NULL)
    );

CREATE TABLE gah_request_lifecycle (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    run_id text NOT NULL,
    request_id text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest LIKE 'sha256:%'),
    idempotency_key text NOT NULL,
    operation_digest text NOT NULL CHECK (operation_digest LIKE 'sha256:%'),
    policy_decision_digest text NOT NULL CHECK (policy_decision_digest LIKE 'sha256:%'),
    state text NOT NULL CHECK (
        state IN (
            'denied',
            'approval_required',
            'policy_authorized',
            'approved',
            'grant_issued'
        )
    ),
    version bigint NOT NULL CHECK (version > 0),
    last_evidence_sequence bigint NOT NULL CHECK (last_evidence_sequence >= 0),
    last_evidence_digest text NOT NULL CHECK (last_evidence_digest LIKE 'sha256:%'),
    actor_context_json jsonb NOT NULL,
    request_json jsonb NOT NULL,
    policy_json jsonb NOT NULL,
    approvals_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    grant_json jsonb,
    PRIMARY KEY (tenant_id, request_id),
    UNIQUE (tenant_id, idempotency_key),
    UNIQUE (tenant_id, actor_id, request_id),
    FOREIGN KEY (tenant_id, actor_id, run_id)
        REFERENCES gah_run_heads (tenant_id, actor_id, run_id),
    CHECK (jsonb_typeof(approvals_json) = 'array'),
    CHECK (actor_context_json ->> 'tenant_id' = tenant_id),
    CHECK (actor_context_json ->> 'actor_id' = actor_id),
    CHECK (request_json ->> 'tenant_id' = tenant_id),
    CHECK (request_json ->> 'actor_id' = actor_id),
    CHECK (request_json ->> 'run_id' = run_id),
    CHECK (request_json ->> 'request_id' = request_id),
    CHECK (request_json ->> 'request_digest' = request_digest),
    CHECK (request_json #>> '{idempotency,idempotency_key}' = idempotency_key),
    CHECK (request_json #>> '{idempotency,operation_digest}' = operation_digest),
    CHECK (policy_json ->> 'tenant_id' = tenant_id),
    CHECK (policy_json ->> 'request_id' = request_id),
    CHECK (policy_json ->> 'request_digest' = request_digest),
    CHECK (policy_json ->> 'decision_digest' = policy_decision_digest),
    CHECK (
        (state = 'grant_issued' AND grant_json IS NOT NULL)
        OR (state <> 'grant_issued' AND grant_json IS NULL)
    ),
    CHECK (
        grant_json IS NULL
        OR (
            grant_json ->> 'tenant_id' = tenant_id
            AND grant_json ->> 'actor_id' = actor_id
            AND grant_json ->> 'run_id' = run_id
            AND grant_json ->> 'request_id' = request_id
            AND grant_json ->> 'request_digest' = request_digest
            AND grant_json ->> 'policy_decision_digest' = policy_decision_digest
            AND grant_json #>> '{idempotency,idempotency_key}' = idempotency_key
            AND grant_json #>> '{idempotency,operation_digest}' = operation_digest
        )
    )
);

ALTER TABLE gah_request_lifecycle ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_request_lifecycle FORCE ROW LEVEL SECURITY;

CREATE POLICY gah_request_lifecycle_scope ON gah_request_lifecycle
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );

ALTER TABLE gah_schema_migrations OWNER TO gah_schema_owner;
ALTER TABLE gah_run_heads OWNER TO gah_schema_owner;
ALTER TABLE gah_evidence_events OWNER TO gah_schema_owner;
ALTER TABLE gah_effect_executions OWNER TO gah_schema_owner;
ALTER TABLE gah_grant_consumptions OWNER TO gah_schema_owner;
ALTER TABLE gah_request_lifecycle OWNER TO gah_schema_owner;

DO $privileges$
DECLARE
    target_schema name := current_schema();
BEGIN
    EXECUTE format(
        'REVOKE ALL ON SCHEMA %I FROM PUBLIC, gah_runtime, gah_authority_writer',
        target_schema
    );
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO gah_runtime', target_schema);
    EXECUTE format(
        'REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC, gah_runtime, gah_authority_writer',
        target_schema
    );
END
$privileges$;
