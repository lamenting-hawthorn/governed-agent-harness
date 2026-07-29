-- Phase 5.1: one digest-bound, preinstalled, deterministic built-in execution path.
-- Stored artifact JSON remains inert and is never returned to the runtime.

DO $roles$
DECLARE
    role_record record;
BEGIN
    SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit,
           rolreplication, rolbypassrls
      INTO role_record
      FROM pg_catalog.pg_roles
     WHERE rolname = 'gah_execution_admission_authority';
    IF NOT FOUND THEN
        CREATE ROLE gah_execution_admission_authority
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
            NOREPLICATION NOBYPASSRLS;
    ELSIF role_record.rolcanlogin OR role_record.rolsuper OR role_record.rolcreatedb
       OR role_record.rolcreaterole OR role_record.rolinherit
       OR role_record.rolreplication OR role_record.rolbypassrls THEN
        RAISE EXCEPTION 'existing execution admission authority role has unsafe attributes';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_auth_members
         WHERE member = (
             SELECT oid FROM pg_catalog.pg_roles
              WHERE rolname = 'gah_execution_admission_authority'
         )
    ) THEN
        RAISE EXCEPTION 'execution admission authority role has unsafe memberships';
    END IF;
    IF EXISTS (
        SELECT 1
         FROM pg_catalog.pg_roles AS login_role
         WHERE login_role.rolcanlogin
           AND NOT login_role.rolsuper
           AND pg_catalog.pg_has_role(
               login_role.oid, 'gah_execution_admission_authority', 'MEMBER')
           AND (
               pg_catalog.pg_has_role(login_role.oid, 'gah_runtime', 'MEMBER')
               OR pg_catalog.pg_has_role(
                   login_role.oid, 'gah_authority_writer', 'MEMBER')
               OR pg_catalog.pg_has_role(
                   login_role.oid, 'gah_skill_lifecycle_authority', 'MEMBER')
           )
    ) THEN
        RAISE EXCEPTION 'execution admission and other GAH credentials must be distinct';
    END IF;
END
$roles$;

-- This is deliberately a repository-owned, verify-only extension.  Migration
-- application must fail closed if the server has not installed its exact 1.0
-- artifact; Python is never a fallback for direct SQL admission.
CREATE EXTENSION IF NOT EXISTS gah_ed25519;

DO $extension_identity$
DECLARE
    extension_row record;
    function_row record;
    schema_row record;
    installing_admin oid;
BEGIN
    SELECT role.oid INTO installing_admin
      FROM pg_catalog.pg_roles AS role WHERE role.rolname = current_user;
    SELECT extension.oid, extension.extnamespace, extension.extowner,
           extension.extversion
      INTO extension_row
      FROM pg_catalog.pg_extension AS extension
     WHERE extension.extname = 'gah_ed25519';
    SELECT procedure.oid, procedure.pronamespace, procedure.proowner,
           language.lanname, procedure.probin, procedure.prosrc,
           procedure.proisstrict, procedure.provolatile, procedure.proparallel
      INTO function_row
      FROM pg_catalog.pg_proc AS procedure
      JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
     WHERE procedure.oid = to_regprocedure(
         'gah_crypto.ed25519_verify_detached(bytea,bytea,bytea)'
     );
    SELECT namespace.oid, namespace.nspowner
      INTO schema_row
      FROM pg_catalog.pg_namespace AS namespace
     WHERE namespace.nspname = 'gah_crypto';
    IF extension_row IS NULL
       OR extension_row.extversion <> '1.0'
       OR extension_row.extnamespace IS DISTINCT FROM schema_row.oid
       OR extension_row.extowner IS DISTINCT FROM installing_admin
       OR function_row IS NULL
       OR function_row.pronamespace IS DISTINCT FROM extension_row.extnamespace
       OR function_row.proowner IS DISTINCT FROM extension_row.extowner
       OR function_row.lanname IS DISTINCT FROM 'c'
       OR function_row.probin IS DISTINCT FROM '$libdir/gah_ed25519'
       OR function_row.prosrc IS DISTINCT FROM 'gah_ed25519_verify_detached'
       OR function_row.proisstrict IS NOT TRUE
       OR function_row.provolatile IS DISTINCT FROM 'i'
       OR function_row.proparallel IS DISTINCT FROM 's'
       OR NOT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_depend AS dependency
            WHERE dependency.classid = 'pg_proc'::regclass
              AND dependency.objid = function_row.oid
              AND dependency.refclassid = 'pg_extension'::regclass
              AND dependency.refobjid = extension_row.oid
              AND dependency.deptype = 'e'
       )
       OR schema_row.nspowner IS DISTINCT FROM extension_row.extowner
    THEN
        RAISE EXCEPTION 'gah_ed25519 extension identity is unavailable or unsafe';
    END IF;
END
$extension_identity$;

ALTER FUNCTION gah_crypto.ed25519_verify_detached(bytea,bytea,bytea)
    OWNER TO gah_schema_owner;
REVOKE ALL ON SCHEMA gah_crypto FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_crypto.ed25519_verify_detached(bytea,bytea,bytea)
    FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
GRANT USAGE ON SCHEMA gah_crypto TO gah_schema_owner;
GRANT EXECUTE ON FUNCTION gah_crypto.ed25519_verify_detached(bytea,bytea,bytea)
    TO gah_schema_owner;

DO $extension_access$
DECLARE
    extension_row record;
    function_row record;
    installing_admin oid;
BEGIN
    SELECT role.oid INTO installing_admin
      FROM pg_catalog.pg_roles AS role WHERE role.rolname = current_user;
    SELECT extension.oid, extension.extowner
      INTO extension_row
      FROM pg_catalog.pg_extension AS extension
     WHERE extension.extname = 'gah_ed25519';
    SELECT procedure.oid, procedure.proowner
      INTO function_row
      FROM pg_catalog.pg_proc AS procedure
     WHERE procedure.oid = to_regprocedure(
         'gah_crypto.ed25519_verify_detached(bytea,bytea,bytea)'
     );
    IF extension_row IS NULL
       OR extension_row.extowner IS DISTINCT FROM installing_admin
       OR function_row IS NULL
       OR function_row.proowner IS DISTINCT FROM 'gah_schema_owner'::regrole::oid
       OR has_schema_privilege('public', 'gah_crypto', 'USAGE')
       OR has_schema_privilege('gah_runtime', 'gah_crypto', 'USAGE')
       OR has_schema_privilege('gah_authority_writer', 'gah_crypto', 'USAGE')
       OR has_schema_privilege('gah_skill_lifecycle_authority', 'gah_crypto', 'USAGE')
       OR has_schema_privilege('gah_execution_admission_authority', 'gah_crypto', 'USAGE')
       OR NOT has_schema_privilege('gah_schema_owner', 'gah_crypto', 'USAGE')
       OR has_function_privilege('public', function_row.oid, 'EXECUTE')
       OR has_function_privilege('gah_runtime', function_row.oid, 'EXECUTE')
       OR has_function_privilege('gah_authority_writer', function_row.oid, 'EXECUTE')
       OR has_function_privilege(
           'gah_skill_lifecycle_authority', function_row.oid, 'EXECUTE'
       )
       OR has_function_privilege(
           'gah_execution_admission_authority', function_row.oid, 'EXECUTE'
       )
       OR NOT has_function_privilege('gah_schema_owner', function_row.oid, 'EXECUTE')
    THEN
        RAISE EXCEPTION 'gah_ed25519 extension access boundary is unsafe';
    END IF;
END
$extension_access$;

CREATE TABLE gah_execution_proof_keys (
    issuer text NOT NULL,
    key_id text NOT NULL,
    algorithm text NOT NULL,
    proof_domain text NOT NULL,
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    public_key_fingerprint text NOT NULL CHECK (
        public_key_fingerprint = 'sha256:' || encode(digest(public_key, 'sha256'), 'hex')
    ),
    trust_policy_version text NOT NULL,
    trust_policy_digest text NOT NULL CHECK (trust_policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (issuer, key_id, algorithm, proof_domain),
    CHECK (valid_until IS NULL OR valid_until >= valid_from)
);
ALTER TABLE gah_execution_proof_keys OWNER TO gah_schema_owner;
ALTER TABLE gah_execution_proof_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_execution_proof_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY gah_execution_proof_keys_schema_owner ON gah_execution_proof_keys
    TO gah_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON gah_execution_proof_keys FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_execution_proof_keys_append_only()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    RAISE EXCEPTION 'execution proof-key registry is append-only';
END
$function$;
CREATE TRIGGER gah_execution_proof_keys_no_mutation
    BEFORE UPDATE OR DELETE OR TRUNCATE ON gah_execution_proof_keys
    FOR EACH STATEMENT EXECUTE FUNCTION gah_execution_proof_keys_append_only();

CREATE FUNCTION gah_verify_execution_signed_record(
    p_record jsonb, p_digest_field text, p_accepted_at timestamptz,
    p_historical boolean DEFAULT false
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    proof jsonb := p_record->'proof';
    key_row public.gah_execution_proof_keys%ROWTYPE;
    signature bytea;
    message bytea;
    unsigned_record jsonb;
    snapshot jsonb;
BEGIN
    IF p_accepted_at IS NULL
       OR jsonb_typeof(proof) IS DISTINCT FROM 'object'
       OR proof->>'algorithm' IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
       OR proof->>'issuer' IS NULL OR proof->>'key_id' IS NULL
       OR proof->>'proof_domain' IS NULL OR proof->>'object_digest' IS NULL
       OR proof->>'nonce' !~ '^[A-Za-z0-9_-]{22,128}$'
       OR proof->>'detached_proof' !~ '^[A-Za-z0-9_-]{86}$'
    THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END IF;
    IF NOT p_historical
       AND date_trunc('milliseconds', p_accepted_at)
            IS DISTINCT FROM date_trunc('milliseconds', transaction_timestamp())
    THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END IF;
    unsigned_record := (p_record - 'proof') - p_digest_field;
    IF proof->>'object_digest' IS DISTINCT FROM public.gah_canonical_sha256(unsigned_record) THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END IF;
    SELECT * INTO key_row FROM public.gah_execution_proof_keys
     WHERE issuer=proof->>'issuer' AND key_id=proof->>'key_id'
       AND algorithm=proof->>'algorithm' AND proof_domain=proof->>'proof_domain'
       AND valid_from <= p_accepted_at
       AND (valid_until IS NULL OR valid_until >= p_accepted_at)
       AND (revoked_at IS NULL OR revoked_at > p_accepted_at);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END IF;
    IF (p_record->>'issued_at')::timestamptz > p_accepted_at
       OR p_accepted_at > (p_record->>'expires_at')::timestamptz
       OR (p_record->>'issued_at')::timestamptz < key_row.valid_from
       OR (key_row.valid_until IS NOT NULL
           AND (p_record->>'issued_at')::timestamptz > key_row.valid_until)
    THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END IF;
    BEGIN
        signature := decode(translate(proof->>'detached_proof', '-_', '+/') || '==', 'base64');
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END;
    IF octet_length(signature) <> 64 THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END IF;
    message := convert_to(public.gah_canonical_json(jsonb_build_object(
        'protocol','gah.detached-proof.v1',
        'issuer',proof->>'issuer',
        'key_id',proof->>'key_id',
        'algorithm',proof->>'algorithm',
        'proof_domain',proof->>'proof_domain',
        'object_digest',proof->>'object_digest',
        'nonce',proof->>'nonce',
        'unsigned_record',unsigned_record
    )), 'UTF8');
    IF NOT gah_crypto.ed25519_verify_detached(signature, message, key_row.public_key) THEN
        RAISE EXCEPTION 'detached proof verification failed';
    END IF;
    snapshot := jsonb_build_object(
        'record_digest', public.gah_canonical_sha256(p_record),
        'accepted_at', to_char(p_accepted_at AT TIME ZONE 'UTC',
                               'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'proof', jsonb_build_object(
            'issuer', proof->>'issuer', 'key_id', proof->>'key_id',
            'algorithm', proof->>'algorithm', 'proof_domain', proof->>'proof_domain',
            'object_digest', proof->>'object_digest', 'nonce', proof->>'nonce',
            'detached_proof', proof->>'detached_proof'
        ),
        'trust', jsonb_build_object(
            'policy_version', key_row.trust_policy_version,
            'policy_digest', key_row.trust_policy_digest,
            'key_fingerprint', key_row.public_key_fingerprint,
            'public_key', regexp_replace(
                translate(encode(key_row.public_key, 'base64'), '+/', '-_'), '=+$', ''
            ),
            'valid_from', to_char(key_row.valid_from AT TIME ZONE 'UTC',
                                  'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
            'valid_until', CASE WHEN key_row.valid_until IS NULL THEN NULL
                ELSE to_char(key_row.valid_until AT TIME ZONE 'UTC',
                             'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
            'revoked_at', CASE WHEN key_row.revoked_at IS NULL THEN NULL
                ELSE to_char(key_row.revoked_at AT TIME ZONE 'UTC',
                             'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END
        )
    );
    RETURN snapshot;
END
$function$;
ALTER FUNCTION gah_verify_execution_signed_record(jsonb,text,timestamptz,boolean)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_verify_execution_signed_record(jsonb,text,timestamptz,boolean)
    FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_verify_execution_signed_record(jsonb,text,timestamptz,boolean)
    TO gah_execution_admission_authority;

CREATE OR REPLACE FUNCTION gah_commit_evidence(p_actor jsonb, p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    IF p_payload #>> '{envelope,draft,event_kind}' IN (
        'execution.authorization_issued',
        'execution.intent',
        'execution.outcome'
    ) THEN
        RAISE EXCEPTION 'execution event kind is reserved for its specialized writer';
    END IF;
    RETURN public.gah_authority_write_internal('commit_evidence', p_actor, p_payload);
END
$function$;

CREATE FUNCTION gah_builtin_execution_assert_object(
    p_value jsonb, p_required text[], p_allowed text[], p_label text
) RETURNS void
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $function$
BEGIN
    IF pg_catalog.jsonb_typeof(p_value) IS DISTINCT FROM 'object'
       OR NOT (p_value ?& p_required)
       OR EXISTS (
           SELECT 1
             FROM pg_catalog.jsonb_object_keys(p_value) AS keys(key)
            WHERE NOT (key = ANY (p_allowed))
       )
    THEN
        RAISE EXCEPTION '% has missing, null-container, or extra fields', p_label;
    END IF;
END
$function$;

CREATE FUNCTION gah_builtin_execution_assert_field_types(
    p_value jsonb, p_strings text[], p_objects text[], p_arrays text[], p_label text
) RETURNS void
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $function$
DECLARE
    field_name text;
BEGIN
    FOREACH field_name IN ARRAY p_strings LOOP
        IF pg_catalog.jsonb_typeof(p_value->field_name) IS DISTINCT FROM 'string'
           OR nullif(p_value->>field_name, '') IS NULL
        THEN RAISE EXCEPTION '% field % must be a non-empty string', p_label, field_name;
        END IF;
    END LOOP;
    FOREACH field_name IN ARRAY p_objects LOOP
        IF pg_catalog.jsonb_typeof(p_value->field_name) IS DISTINCT FROM 'object'
        THEN RAISE EXCEPTION '% field % must be an object', p_label, field_name;
        END IF;
    END LOOP;
    FOREACH field_name IN ARRAY p_arrays LOOP
        IF pg_catalog.jsonb_typeof(p_value->field_name) IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION '% field % must be an array', p_label, field_name;
        END IF;
    END LOOP;
END
$function$;

CREATE TABLE gah_builtin_execution_state (
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    run_id text NOT NULL,
    operation_id text NOT NULL,
    operation_digest text NOT NULL CHECK (operation_digest ~ '^sha256:[0-9a-f]{64}$'),
    request_id text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    grant_id text NOT NULL,
    grant_digest text NOT NULL CHECK (grant_digest ~ '^sha256:[0-9a-f]{64}$'),
    skill_id text NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    command_json jsonb NOT NULL,
    grant_json jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('authorized','executing','completed','indeterminate')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    issuance_evidence_json jsonb NOT NULL,
    intent_evidence_json jsonb,
    outcome_json jsonb,
    outcome_evidence_json jsonb,
    execution_attempt_id text,
    owner_generation bigint,
    lease_expires_at timestamptz,
    issued_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, operation_digest),
    UNIQUE (tenant_id, request_id),
    UNIQUE (tenant_id, grant_id),
    CHECK (command_json ->> 'operation_id' = operation_id),
    CHECK (command_json ->> 'operation_digest' = operation_digest),
    CHECK (command_json #>> '{tool_request,request_id}' = request_id),
    CHECK (command_json #>> '{tool_request,request_digest}' = request_digest),
    CHECK (command_json ->> 'skill_id' = skill_id),
    CHECK ((command_json ->> 'revision')::integer = revision),
    CHECK (command_json ->> 'artifact_digest' = artifact_digest),
    CHECK (grant_json ->> 'grant_id' = grant_id),
    CHECK (grant_json ->> 'request_id' = request_id),
    CHECK (
        (state = 'authorized' AND intent_evidence_json IS NULL AND outcome_json IS NULL
            AND outcome_evidence_json IS NULL AND execution_attempt_id IS NULL
            AND owner_generation IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL)
        OR
        (state = 'executing' AND intent_evidence_json IS NOT NULL AND outcome_json IS NULL
            AND outcome_evidence_json IS NULL AND execution_attempt_id IS NOT NULL
            AND owner_generation IS NOT NULL AND lease_expires_at IS NOT NULL
            AND completed_at IS NULL)
        OR
        (state IN ('completed','indeterminate') AND intent_evidence_json IS NOT NULL
            AND outcome_json IS NOT NULL AND outcome_evidence_json IS NOT NULL
            AND execution_attempt_id IS NOT NULL AND owner_generation IS NOT NULL
            AND lease_expires_at IS NOT NULL AND completed_at IS NOT NULL)
    )
);

ALTER TABLE gah_builtin_execution_state OWNER TO gah_schema_owner;
ALTER TABLE gah_builtin_execution_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE gah_builtin_execution_state FORCE ROW LEVEL SECURITY;
CREATE POLICY gah_builtin_execution_state_scope ON gah_builtin_execution_state
    USING (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('gah.tenant_id', true), '')
        AND actor_id = nullif(current_setting('gah.actor_id', true), '')
    );
REVOKE ALL ON gah_builtin_execution_state FROM PUBLIC, gah_runtime,
    gah_authority_writer, gah_skill_lifecycle_authority,
    gah_execution_admission_authority;

CREATE FUNCTION gah_builtin_execution_result(p_row gah_builtin_execution_state, p_replayed boolean)
RETURNS jsonb
LANGUAGE sql
SET search_path = pg_catalog, public
RETURN jsonb_build_object(
    'command', p_row.command_json,
    'grant', p_row.grant_json,
    'issuance_evidence', p_row.issuance_evidence_json,
    'replayed', p_replayed
);

CREATE FUNCTION gah_builtin_execution_terminal_result(
    p_row gah_builtin_execution_state, p_replayed boolean
) RETURNS jsonb
LANGUAGE sql
SET search_path = pg_catalog, public
RETURN jsonb_build_object(
    'state', p_row.state,
    'intent_evidence', p_row.intent_evidence_json,
    'outcome', p_row.outcome_json,
    'outcome_evidence', p_row.outcome_evidence_json,
    'attempt_id', p_row.execution_attempt_id,
    'owner_generation', p_row.owner_generation,
    'replayed', p_replayed
);

CREATE FUNCTION gah_builtin_execution_assert_actor(p_actor jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
END
$function$;

CREATE FUNCTION gah_builtin_execution_evidence_head(p_actor jsonb, p_run_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE head public.gah_run_heads%ROWTYPE;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    IF p_run_id IS NULL OR p_run_id <> p_actor->>'session_id' THEN
        RAISE EXCEPTION 'execution run is outside the actor session';
    END IF;
    SELECT * INTO head FROM public.gah_run_heads
     WHERE tenant_id=p_actor->>'tenant_id' AND run_id=p_run_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'next_sequence', 0, 'last_event_digest', NULL,
            'last_recorded_at', NULL, 'version', 0
        );
    END IF;
    IF head.actor_id IS DISTINCT FROM p_actor->>'actor_id' THEN
        RAISE EXCEPTION 'execution evidence run conflicts with actor';
    END IF;
    RETURN jsonb_build_object(
        'next_sequence', head.next_sequence,
        'last_event_digest', head.last_event_digest,
        'last_recorded_at', head.last_recorded_at,
        'version', head.version
    );
END
$function$;

CREATE FUNCTION gah_builtin_execution_commit_evidence(
    p_actor jsonb, p_envelope jsonb, p_event_kind text, p_payload jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE head public.gah_run_heads%ROWTYPE; changed bigint;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    PERFORM public.gah_builtin_execution_assert_object(
        p_envelope,
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
              'draft_digest','recorded_at','sequence_number','payload_digest',
              'prior_event_digest','event_digest','policy_refs','storage_writer_id'],
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
              'draft_digest','recorded_at','sequence_number','payload_digest',
              'prior_event_digest','event_digest','policy_refs','storage_writer_id',
              'extensions'],
        'execution evidence envelope'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_envelope,
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft_digest',
              'recorded_at','payload_digest','event_digest','storage_writer_id'],
        ARRAY['draft'], ARRAY['policy_refs'], 'execution evidence envelope'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_envelope->'draft',
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','idempotency','classification','redaction_status',
              'inline_payload'],
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','idempotency','classification','redaction_status',
              'inline_payload','protected_payload','extensions'],
        'execution evidence draft'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_envelope->'draft',
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','classification','redaction_status'],
        ARRAY['idempotency','inline_payload'], ARRAY[]::text[], 'execution evidence draft'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_envelope#>'{draft,idempotency}',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        'execution evidence idempotency'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_envelope#>'{draft,idempotency}',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution evidence idempotency'
    );
    IF p_event_kind NOT IN (
           'execution.authorization_issued','execution.intent','execution.outcome')
       OR pg_catalog.jsonb_typeof(p_envelope->'sequence_number') IS DISTINCT FROM 'number'
       OR p_envelope->>'sequence_number' !~ '^[0-9]+$'
       OR NOT (
           p_envelope->'prior_event_digest' = 'null'::jsonb
           OR pg_catalog.jsonb_typeof(p_envelope->'prior_event_digest') = 'string')
       OR p_envelope->>'schema_version' IS DISTINCT FROM '1.0'
       OR p_envelope->>'record_type' IS DISTINCT FROM 'evidence_envelope'
       OR p_envelope#>>'{draft,schema_version}' IS DISTINCT FROM '1.0'
       OR p_envelope#>>'{draft,record_type}' IS DISTINCT FROM 'evidence_draft'
    THEN RAISE EXCEPTION 'execution evidence envelope shape is invalid'; END IF;
    -- A run head is created only as part of the specialized evidence commit:
    -- callers that merely inspect a new run must not create or lock state.
    INSERT INTO public.gah_run_heads (tenant_id, actor_id, run_id)
    VALUES (p_actor->>'tenant_id', p_actor->>'actor_id',
            p_envelope#>>'{draft,run_id}')
    ON CONFLICT (tenant_id, run_id) DO NOTHING;
    SELECT * INTO head FROM public.gah_run_heads
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND run_id=p_envelope#>>'{draft,run_id}'
     FOR UPDATE;
    IF NOT FOUND
       OR p_envelope->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_envelope#>>'{draft,tenant_id}' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_envelope#>>'{draft,event_kind}' IS DISTINCT FROM p_event_kind
       OR p_envelope#>'{draft,inline_payload}' IS DISTINCT FROM p_payload
       OR p_envelope#>>'{draft,inline_payload,actor_id}'
            IS DISTINCT FROM p_actor->>'actor_id'
       OR p_envelope#>>'{draft,idempotency,operation_digest}'
            IS DISTINCT FROM p_payload->>'operation_digest'
       OR (p_envelope->>'sequence_number')::bigint IS DISTINCT FROM head.next_sequence
       OR p_envelope->>'prior_event_digest' IS DISTINCT FROM head.last_event_digest
       OR p_envelope->>'draft_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_envelope->>'payload_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_envelope->>'event_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_envelope->>'draft_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_envelope->'draft')
       OR p_envelope->>'payload_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(
                p_envelope#>'{draft,inline_payload}')
       OR p_envelope->>'event_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_envelope-'event_digest')
       OR p_envelope->>'storage_writer_id'
            IS DISTINCT FROM 'execution.postgresql.v1'
       OR (head.last_recorded_at IS NOT NULL
           AND (p_envelope->>'recorded_at')::timestamptz < head.last_recorded_at)
       OR (p_envelope->>'recorded_at')::timestamptz
            > clock_timestamp() + interval '1 minute'
    THEN RAISE EXCEPTION 'execution evidence envelope is not canonical or current'; END IF;
    INSERT INTO public.gah_evidence_events (
        tenant_id, actor_id, run_id, sequence_number, envelope_id,
        event_digest, prior_event_digest, envelope_json, recorded_at
    ) VALUES (
        p_actor->>'tenant_id', p_actor->>'actor_id', p_envelope#>>'{draft,run_id}',
        (p_envelope->>'sequence_number')::bigint, p_envelope->>'envelope_id',
        p_envelope->>'event_digest', p_envelope->>'prior_event_digest', p_envelope,
        (p_envelope->>'recorded_at')::timestamptz
    );
    UPDATE public.gah_run_heads
       SET next_sequence=next_sequence+1,
           last_event_digest=p_envelope->>'event_digest',
           last_recorded_at=(p_envelope->>'recorded_at')::timestamptz,
           version=version+1
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND run_id=p_envelope#>>'{draft,run_id}' AND version=head.version;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN RAISE EXCEPTION 'execution evidence sequence lost its race'; END IF;
END
$function$;

CREATE FUNCTION gah_builtin_execution_writer_lock_keys(p_actor jsonb, p_binding jsonb)
RETURNS TABLE (lock_a integer, lock_b integer, lock_c integer, lock_d integer)
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, public AS
    'WITH commitment AS (
         SELECT public.digest(pg_catalog.convert_to(public.gah_canonical_json(
             jsonb_build_object(
                 ''tenant_id'', $1->>''tenant_id'', ''actor_id'', $1->>''actor_id'',
                 ''session_id'', $1->>''session_id'', ''purpose'', $2->>''purpose'',
                 ''operation_id'', $2->>''operation_id'',
                 ''operation_digest'', $2->>''operation_digest'',
                 ''command_digest'', $2->>''command_digest'',
                 ''grant_digest'', $2->>''grant_digest'',
                 ''request_id'', $2->>''request_id'',
                 ''request_digest'', $2->>''request_digest''
             )), ''UTF8''), ''sha256'') AS value
     ), halves AS (
         SELECT ((get_byte(value, 0)::bigint << 24)
                   + (get_byte(value, 1)::bigint << 16)
                   + (get_byte(value, 2)::bigint << 8)
                   + get_byte(value, 3)::bigint) AS first_half,
                ((get_byte(value, 4)::bigint << 24)
                   + (get_byte(value, 5)::bigint << 16)
                   + (get_byte(value, 6)::bigint << 8)
                   + get_byte(value, 7)::bigint) AS second_half,
                ((get_byte(value, 8)::bigint << 24)
                   + (get_byte(value, 9)::bigint << 16)
                   + (get_byte(value, 10)::bigint << 8)
                   + get_byte(value, 11)::bigint) AS third_half,
                ((get_byte(value, 12)::bigint << 24)
                   + (get_byte(value, 13)::bigint << 16)
                   + (get_byte(value, 14)::bigint << 8)
                   + get_byte(value, 15)::bigint) AS fourth_half
           FROM commitment
     )
     SELECT CASE WHEN first_half > 2147483647
                     THEN (first_half - 4294967296)::integer
                     ELSE first_half::integer END,
            CASE WHEN second_half > 2147483647
                     THEN (second_half - 4294967296)::integer
                     ELSE second_half::integer END,
            CASE WHEN third_half > 2147483647
                     THEN (third_half - 4294967296)::integer
                     ELSE third_half::integer END,
            CASE WHEN fourth_half > 2147483647
                     THEN (fourth_half - 4294967296)::integer
                     ELSE fourth_half::integer END
       FROM halves';

CREATE FUNCTION gah_authorize_builtin_execution(p_actor jsonb, p_binding jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    first_a integer; first_b integer; second_a integer; second_b integer;
    raw_a integer; raw_b integer; raw_c integer; raw_d integer;
    issued_at timestamptz := clock_timestamp();
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    IF NOT pg_catalog.pg_has_role(session_user, 'gah_authority_writer', 'MEMBER')
       OR pg_catalog.pg_has_role(
           session_user, 'gah_execution_admission_authority', 'MEMBER')
    THEN
        RAISE EXCEPTION 'execution writer authorization requires its distinct writer role';
    END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        p_binding,
        ARRAY['purpose','operation_id','operation_digest','command_digest',
              'grant_digest','request_id','request_digest'],
        ARRAY['purpose','operation_id','operation_digest','command_digest',
              'grant_digest','request_id','request_digest'],
        'execution writer binding'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_binding,
        ARRAY['purpose','operation_id','operation_digest','command_digest',
              'grant_digest','request_id','request_digest'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution writer binding'
    );
    IF p_binding->>'purpose' IS DISTINCT FROM 'issue'
       OR p_binding->>'operation_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_binding->>'command_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_binding->>'grant_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_binding->>'request_digest' !~ '^sha256:[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION 'execution writer binding is malformed';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'execution:operation:'||(p_actor->>'tenant_id')||':'||
            (p_binding->>'operation_id'), 0
    ));
    SELECT lock_a, lock_b, lock_c, lock_d
      INTO raw_a, raw_b, raw_c, raw_d
      FROM public.gah_builtin_execution_writer_lock_keys(p_actor, p_binding);
    SELECT CASE WHEN (raw_a,raw_b) <= (raw_c,raw_d) THEN raw_a ELSE raw_c END,
           CASE WHEN (raw_a,raw_b) <= (raw_c,raw_d) THEN raw_b ELSE raw_d END,
           CASE WHEN (raw_a,raw_b) <= (raw_c,raw_d) THEN raw_c ELSE raw_a END,
           CASE WHEN (raw_a,raw_b) <= (raw_c,raw_d) THEN raw_d ELSE raw_b END
      INTO first_a, first_b, second_a, second_b;
    PERFORM pg_catalog.pg_advisory_xact_lock(first_a, first_b);
    PERFORM pg_catalog.pg_advisory_xact_lock(second_a, second_b);
    RETURN jsonb_build_object(
        'writer_pid',pg_catalog.pg_backend_pid(),
        'tenant_id',p_actor->>'tenant_id','actor_id',p_actor->>'actor_id',
        'session_id',p_actor->>'session_id','purpose',p_binding->>'purpose',
        'operation_id',p_binding->>'operation_id',
        'operation_digest',p_binding->>'operation_digest',
        'command_digest',p_binding->>'command_digest',
        'grant_digest',p_binding->>'grant_digest',
        'request_id',p_binding->>'request_id',
        'request_digest',p_binding->>'request_digest',
        'nonce',pg_catalog.encode(public.gen_random_bytes(16),'hex'),
        'issued_at',to_char(issued_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'expires_at',to_char(
            (issued_at + interval '30 seconds') AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    );
END
$function$;

CREATE FUNCTION gah_builtin_execution_assert_writer_authorization(
    p_actor jsonb, p_command jsonb, p_grant jsonb, p_authorization jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    lock_a integer; lock_b integer; lock_c integer; lock_d integer;
    writer_pid integer;
    binding jsonb;
BEGIN
    IF NOT pg_catalog.pg_has_role(
           session_user, 'gah_execution_admission_authority', 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, 'gah_authority_writer', 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, 'gah_runtime', 'MEMBER')
       OR pg_catalog.pg_has_role(
           session_user, 'gah_skill_lifecycle_authority', 'MEMBER')
    THEN
        RAISE EXCEPTION 'execution issuance requires its distinct admission credential';
    END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        p_authorization,
        ARRAY['writer_pid','tenant_id','actor_id','session_id','purpose',
              'operation_id','operation_digest','command_digest','grant_digest',
              'request_id','request_digest','nonce','issued_at','expires_at'],
        ARRAY['writer_pid','tenant_id','actor_id','session_id','purpose',
              'operation_id','operation_digest','command_digest','grant_digest',
              'request_id','request_digest','nonce','issued_at','expires_at'],
        'execution writer authorization'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_authorization,
        ARRAY['tenant_id','actor_id','session_id','purpose','operation_id',
              'operation_digest','command_digest','grant_digest','request_id',
              'request_digest','nonce','issued_at','expires_at'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution writer authorization'
    );
    IF pg_catalog.jsonb_typeof(p_authorization->'writer_pid') IS DISTINCT FROM 'number'
       OR p_authorization->>'writer_pid' !~ '^[1-9][0-9]*$'
       OR p_authorization->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_authorization->>'actor_id' IS DISTINCT FROM p_actor->>'actor_id'
       OR p_authorization->>'session_id' IS DISTINCT FROM p_actor->>'session_id'
       OR p_authorization->>'purpose' IS DISTINCT FROM 'issue'
       OR p_authorization->>'operation_id' IS DISTINCT FROM p_command->>'operation_id'
       OR p_authorization->>'operation_digest'
            IS DISTINCT FROM p_command->>'operation_digest'
       OR p_authorization->>'command_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_command)
       OR p_authorization->>'grant_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_grant)
       OR p_authorization->>'request_id'
            IS DISTINCT FROM p_command#>>'{tool_request,request_id}'
       OR p_authorization->>'request_digest'
            IS DISTINCT FROM p_command#>>'{tool_request,request_digest}'
       OR p_authorization->>'nonce' !~ '^[0-9a-f]{32}$'
       OR (p_authorization->>'issued_at')::timestamptz
            > clock_timestamp() + interval '1 minute'
       OR (p_authorization->>'expires_at')::timestamptz
            <= clock_timestamp()
       OR (p_authorization->>'expires_at')::timestamptz
            > (p_authorization->>'issued_at')::timestamptz + interval '30 seconds'
    THEN
        RAISE EXCEPTION 'execution writer authorization is invalid or expired';
    END IF;
    writer_pid := (p_authorization->>'writer_pid')::integer;
    IF writer_pid = pg_catalog.pg_backend_pid() THEN
        RAISE EXCEPTION 'execution writer authorization must use a distinct session';
    END IF;
    binding := jsonb_build_object(
        'purpose',p_authorization->>'purpose',
        'operation_id',p_authorization->>'operation_id',
        'operation_digest',p_authorization->>'operation_digest',
        'command_digest',p_authorization->>'command_digest',
        'grant_digest',p_authorization->>'grant_digest',
        'request_id',p_authorization->>'request_id',
        'request_digest',p_authorization->>'request_digest'
    );
    SELECT keys.lock_a, keys.lock_b, keys.lock_c, keys.lock_d
      INTO lock_a, lock_b, lock_c, lock_d
      FROM public.gah_builtin_execution_writer_lock_keys(
          p_actor, binding) AS keys;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_locks AS locks
          JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid=locks.pid
          JOIN pg_catalog.pg_roles AS role_record ON role_record.rolname=activity.usename
         WHERE locks.locktype='advisory' AND locks.granted AND locks.pid=writer_pid
           AND locks.objsubid=2
           AND locks.classid::bigint = CASE WHEN lock_a < 0
               THEN lock_a::bigint + 4294967296 ELSE lock_a::bigint END
           AND locks.objid::bigint = CASE WHEN lock_b < 0
               THEN lock_b::bigint + 4294967296 ELSE lock_b::bigint END
           AND pg_catalog.pg_has_role(
               role_record.oid,'gah_authority_writer','MEMBER')
           AND NOT pg_catalog.pg_has_role(
               role_record.oid,'gah_execution_admission_authority','MEMBER')
    ) OR NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_locks AS locks
          JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid=locks.pid
          JOIN pg_catalog.pg_roles AS role_record ON role_record.rolname=activity.usename
         WHERE locks.locktype='advisory' AND locks.granted AND locks.pid=writer_pid
           AND locks.objsubid=2
           AND locks.classid::bigint = CASE WHEN lock_c < 0
               THEN lock_c::bigint + 4294967296 ELSE lock_c::bigint END
           AND locks.objid::bigint = CASE WHEN lock_d < 0
               THEN lock_d::bigint + 4294967296 ELSE lock_d::bigint END
           AND pg_catalog.pg_has_role(
               role_record.oid,'gah_authority_writer','MEMBER')
           AND NOT pg_catalog.pg_has_role(
               role_record.oid,'gah_execution_admission_authority','MEMBER')
    ) THEN
        RAISE EXCEPTION 'execution writer authorization is not live';
    END IF;
END
$function$;

CREATE FUNCTION gah_lookup_builtin_execution_authorization(p_actor jsonb, p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE stored public.gah_builtin_execution_state%ROWTYPE;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id'
       AND (operation_id=p_command->>'operation_id'
            OR operation_digest=p_command->>'operation_digest');
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF stored.actor_id <> p_actor->>'actor_id'
       OR stored.operation_id <> p_command->>'operation_id'
       OR stored.operation_digest <> p_command->>'operation_digest'
       OR stored.command_json IS DISTINCT FROM p_command
       OR stored.command_json#>>'{tool_request,actor_context_digest}'
            IS DISTINCT FROM public.gah_canonical_sha256(p_actor)
    THEN RAISE EXCEPTION 'execution authorization replay conflicts with stored authority'; END IF;
    RETURN public.gah_builtin_execution_result(stored, true);
END
$function$;

CREATE FUNCTION gah_builtin_execution_validate_authority(
    p_actor jsonb, p_command jsonb, p_grant jsonb, p_evidence jsonb,
    p_require_current boolean
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    active public.gah_active_skill_projection%ROWTYPE;
    artifact public.gah_skill_artifact_revisions%ROWTYPE;
    request jsonb := p_command->'tool_request';
    policy jsonb := p_command->'policy_decision';
    gate jsonb := p_command->'gate_decision';
    approval jsonb := p_command#>'{approvals,0}';
    proof jsonb;
    envelope jsonb;
    draft jsonb := p_evidence->'draft';
    payload jsonb := p_evidence#>'{draft,inline_payload}';
    writer_authorization jsonb;
    approval_acceptance jsonb;
    grant_acceptance jsonb;
BEGIN
    PERFORM public.gah_builtin_execution_assert_object(
        p_actor,
        ARRAY['schema_version','record_type','tenant_id','actor_id','session_id','auth',
              'roles','capabilities','trust_level','scope_authority','issued_at',
              'expires_at','correlation_id'],
        ARRAY['schema_version','record_type','tenant_id','actor_id','session_id','auth',
              'roles','capabilities','trust_level','scope_authority','issued_at',
              'expires_at','correlation_id','extensions'],
        'execution actor'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_actor,
        ARRAY['schema_version','record_type','tenant_id','actor_id','session_id',
              'trust_level','issued_at','expires_at','correlation_id'],
        ARRAY['auth','scope_authority'], ARRAY['roles','capabilities'], 'execution actor'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_command,
        ARRAY['operation_id','operation_digest','skill_id','revision','artifact_digest',
              'tool_request','policy_decision','gate_decision','approvals',
              'source_evidence','validity','retention'],
        ARRAY['operation_id','operation_digest','skill_id','revision','artifact_digest',
              'tool_request','policy_decision','gate_decision','approvals',
              'source_evidence','validity','retention'],
        'execution command'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_command,
        ARRAY['operation_id','operation_digest','skill_id','artifact_digest'],
        ARRAY['tool_request','policy_decision','gate_decision','validity','retention'],
        ARRAY['approvals','source_evidence'], 'execution command'
    );
    IF pg_catalog.jsonb_typeof(p_command->'revision') IS DISTINCT FROM 'number'
       OR p_command->>'revision' !~ '^[1-9][0-9]*$'
    THEN RAISE EXCEPTION 'execution command revision is malformed'; END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        request,
        ARRAY['schema_version','record_type','tenant_id','actor_id',
              'actor_context_digest','run_id','request_id','tool_id','tool_version',
              'arguments','effect_classes','request_digest','idempotency','requested_at'],
        ARRAY['schema_version','record_type','tenant_id','actor_id',
              'actor_context_digest','run_id','request_id','tool_id','tool_version',
              'arguments','effect_classes','request_digest','idempotency','requested_at',
              'extensions'],
        'execution tool request'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        request,
        ARRAY['schema_version','record_type','tenant_id','actor_id',
              'actor_context_digest','run_id','request_id','tool_id','tool_version',
              'request_digest','requested_at'],
        ARRAY['arguments','idempotency'], ARRAY['effect_classes'],
        'execution tool request'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        request->'arguments',
        ARRAY['skill_id','revision','artifact_digest','input'],
        ARRAY['skill_id','revision','artifact_digest','input'],
        'execution arguments'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        request->'arguments', ARRAY['skill_id','artifact_digest'], ARRAY['input'],
        ARRAY[]::text[], 'execution arguments'
    );
    IF pg_catalog.jsonb_typeof(request#>'{arguments,revision}') IS DISTINCT FROM 'number'
       OR request#>>'{arguments,revision}' !~ '^[1-9][0-9]*$'
       OR pg_catalog.octet_length(
            public.gah_canonical_json(request#>'{arguments,input}')) > 16384
       OR request#>'{arguments,input}' IS DISTINCT FROM
            '{"message":"gah.builtin.echo.v1"}'::jsonb
    THEN RAISE EXCEPTION 'execution arguments are malformed or oversized'; END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        request->'idempotency',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        'execution request idempotency'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        request->'idempotency',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution request idempotency'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        policy,
        ARRAY['schema_version','record_type','tenant_id','decision_id','request_id',
              'request_digest','decision','rule_refs','constraints','isolation_profile',
              'decided_at','decision_digest'],
        ARRAY['schema_version','record_type','tenant_id','decision_id','request_id',
              'request_digest','decision','rule_refs','constraints','isolation_profile',
              'decided_at','decision_digest','transformed_request_ref','extensions'],
        'execution policy decision'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        policy,
        ARRAY['schema_version','record_type','tenant_id','decision_id','request_id',
              'request_digest','decision','isolation_profile','decided_at',
              'decision_digest'],
        ARRAY[]::text[], ARRAY['rule_refs','constraints'], 'execution policy decision'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        gate,
        ARRAY['schema_version','record_type','tenant_id','gate_id','target_scope',
              'proposal_refs','evaluation_refs','provenance_digest','producer_version',
              'runtime_version','decision','eligibility_checks','policy_refs',
              'reviewer_refs','compatibility','issued_at','decision_digest'],
        ARRAY['schema_version','record_type','tenant_id','gate_id','target_scope',
              'proposal_refs','evaluation_refs','provenance_digest','producer_version',
              'runtime_version','decision','eligibility_checks','policy_refs',
              'reviewer_refs','compatibility','issued_at','decision_digest',
              'task_quality','extensions'],
        'execution gate decision'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        gate,
        ARRAY['schema_version','record_type','tenant_id','gate_id','provenance_digest',
              'producer_version','runtime_version','decision','issued_at',
              'decision_digest'],
        ARRAY['target_scope','eligibility_checks','compatibility'],
        ARRAY['proposal_refs','evaluation_refs','policy_refs','reviewer_refs'],
        'execution gate decision'
    );
    IF pg_catalog.jsonb_array_length(p_command->'approvals') IS DISTINCT FROM 1
    THEN RAISE EXCEPTION 'execution requires exactly one approval'; END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        approval,
        ARRAY['schema_version','record_type','tenant_id','approval_id',
              'approver_actor_id','approver_context_digest','request_id','request_digest',
              'policy_decision_id','policy_decision_digest','disposition','constraints',
              'separation_of_duties','issued_at','expires_at','approval_digest','proof'],
        ARRAY['schema_version','record_type','tenant_id','approval_id',
              'approver_actor_id','approver_context_digest','request_id','request_digest',
              'policy_decision_id','policy_decision_digest','disposition','constraints',
              'separation_of_duties','issued_at','expires_at','approval_digest','proof',
              'revoked_at','extensions'],
        'execution approval'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        approval,
        ARRAY['schema_version','record_type','tenant_id','approval_id',
              'approver_actor_id','approver_context_digest','request_id','request_digest',
              'policy_decision_id','policy_decision_digest','disposition','issued_at',
              'expires_at','approval_digest'],
        ARRAY['separation_of_duties','proof'], ARRAY['constraints'], 'execution approval'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        approval->'separation_of_duties',
        ARRAY['required','satisfied','policy_id'],
        ARRAY['required','satisfied','policy_id'],
        'execution approval separation of duties'
    );
    IF pg_catalog.jsonb_typeof(approval#>'{separation_of_duties,required}')
            IS DISTINCT FROM 'boolean'
       OR pg_catalog.jsonb_typeof(approval#>'{separation_of_duties,satisfied}')
            IS DISTINCT FROM 'boolean'
       OR pg_catalog.jsonb_typeof(approval#>'{separation_of_duties,policy_id}')
            IS DISTINCT FROM 'string'
    THEN RAISE EXCEPTION 'execution approval separation of duties is malformed'; END IF;
    proof := approval->'proof';
    PERFORM public.gah_builtin_execution_assert_object(
        proof,
        ARRAY['issuer','key_id','algorithm','proof_domain','object_digest','nonce',
              'detached_proof'],
        ARRAY['issuer','key_id','algorithm','proof_domain','object_digest','nonce',
              'detached_proof'],
        'execution approval proof'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        proof,
        ARRAY['issuer','key_id','algorithm','proof_domain','object_digest','nonce',
              'detached_proof'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution approval proof'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_grant,
        ARRAY['schema_version','record_type','tenant_id','grant_id','actor_id','run_id',
              'request_id','request_digest','tool_id','tool_version',
              'policy_decision_id','policy_decision_digest','approval_refs',
              'constraints','isolation_profile','issued_at','expires_at','grant_nonce',
              'idempotency','proof'],
        ARRAY['schema_version','record_type','tenant_id','grant_id','actor_id','run_id',
              'request_id','request_digest','tool_id','tool_version',
              'policy_decision_id','policy_decision_digest','approval_refs',
              'constraints','isolation_profile','issued_at','expires_at','grant_nonce',
              'idempotency','proof','extensions'],
        'execution grant'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_grant,
        ARRAY['schema_version','record_type','tenant_id','grant_id','actor_id','run_id',
              'request_id','request_digest','tool_id','tool_version',
              'policy_decision_id','policy_decision_digest','isolation_profile',
              'issued_at','expires_at','grant_nonce'],
        ARRAY['idempotency','proof'], ARRAY['approval_refs','constraints'],
        'execution grant'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_grant->'idempotency',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        'execution grant idempotency'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_grant->'idempotency',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution grant idempotency'
    );
    proof := p_grant->'proof';
    PERFORM public.gah_builtin_execution_assert_object(
        proof,
        ARRAY['issuer','key_id','algorithm','proof_domain','object_digest','nonce',
              'detached_proof'],
        ARRAY['issuer','key_id','algorithm','proof_domain','object_digest','nonce',
              'detached_proof'],
        'execution grant proof'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        proof,
        ARRAY['issuer','key_id','algorithm','proof_domain','object_digest','nonce',
              'detached_proof'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution grant proof'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_command->'validity', ARRAY['expires_at'], ARRAY['expires_at'],
        'execution validity'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_command->'retention', ARRAY['expires_at'], ARRAY['expires_at'],
        'execution retention'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_command->'validity', ARRAY['expires_at'], ARRAY[]::text[],
        ARRAY[]::text[], 'execution validity'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_command->'retention', ARRAY['expires_at'], ARRAY[]::text[],
        ARRAY[]::text[], 'execution retention'
    );
    IF pg_catalog.jsonb_array_length(p_command->'source_evidence') < 1
    THEN RAISE EXCEPTION 'execution source evidence is empty'; END IF;
    FOR envelope IN SELECT value FROM jsonb_array_elements(
        p_command->'source_evidence') AS sources(value)
    LOOP
        PERFORM public.gah_builtin_execution_assert_object(
            envelope,
            ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
                  'draft_digest','recorded_at','sequence_number','payload_digest',
                  'prior_event_digest','event_digest','policy_refs','storage_writer_id'],
            ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
                  'draft_digest','recorded_at','sequence_number','payload_digest',
                  'prior_event_digest','event_digest','policy_refs','storage_writer_id',
                  'extensions'],
            'execution source evidence'
        );
        IF envelope->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
           OR envelope->>'draft_digest'
                IS DISTINCT FROM public.gah_canonical_sha256(envelope->'draft')
           OR envelope->>'payload_digest'
                IS DISTINCT FROM public.gah_canonical_sha256(
                    envelope#>'{draft,inline_payload}')
           OR envelope->>'event_digest'
                IS DISTINCT FROM public.gah_canonical_sha256(envelope-'event_digest')
        THEN RAISE EXCEPTION 'execution source evidence is not canonical'; END IF;
    END LOOP;
    PERFORM public.gah_builtin_execution_assert_object(
        p_evidence,
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
              'draft_digest','recorded_at','sequence_number','payload_digest',
              'prior_event_digest','event_digest','policy_refs','storage_writer_id'],
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
              'draft_digest','recorded_at','sequence_number','payload_digest',
              'prior_event_digest','event_digest','policy_refs','storage_writer_id',
              'extensions'],
        'execution issuance evidence'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_evidence,
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft_digest',
              'recorded_at','payload_digest','event_digest','storage_writer_id'],
        ARRAY['draft'], ARRAY['policy_refs'], 'execution issuance evidence'
    );
    IF pg_catalog.jsonb_typeof(p_evidence->'sequence_number') IS DISTINCT FROM 'number'
       OR p_evidence->>'sequence_number' !~ '^[0-9]+$'
       OR NOT (
           p_evidence->'prior_event_digest' = 'null'::jsonb
           OR pg_catalog.jsonb_typeof(p_evidence->'prior_event_digest') = 'string')
    THEN RAISE EXCEPTION 'execution issuance evidence position is malformed'; END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        draft,
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','idempotency','classification','redaction_status',
              'inline_payload'],
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','idempotency','classification','redaction_status',
              'inline_payload','protected_payload','extensions'],
        'execution issuance evidence draft'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        draft,
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','classification','redaction_status'],
        ARRAY['idempotency','inline_payload'], ARRAY[]::text[],
        'execution issuance evidence draft'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        payload,
        ARRAY['actor_id','operation_id','operation_digest','command',
              'authorization_grant','authorization_grant_digest',
              'proof_acceptances','writer_authorization','state'],
        ARRAY['actor_id','operation_id','operation_digest','command',
              'authorization_grant','authorization_grant_digest',
              'proof_acceptances','writer_authorization','state'],
        'execution issuance evidence payload'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        payload,
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','state'],
        ARRAY['command','authorization_grant','proof_acceptances','writer_authorization'],
        ARRAY[]::text[], 'execution issuance evidence payload'
    );
    writer_authorization := payload->'writer_authorization';
    PERFORM public.gah_builtin_execution_assert_object(
        writer_authorization,
        ARRAY['writer_pid','tenant_id','actor_id','session_id','purpose',
              'operation_id','operation_digest','command_digest','grant_digest',
              'request_id','request_digest','nonce','issued_at','expires_at'],
        ARRAY['writer_pid','tenant_id','actor_id','session_id','purpose',
              'operation_id','operation_digest','command_digest','grant_digest',
              'request_id','request_digest','nonce','issued_at','expires_at'],
        'execution evidence writer authorization'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        writer_authorization,
        ARRAY['tenant_id','actor_id','session_id','purpose','operation_id',
              'operation_digest','command_digest','grant_digest','request_id',
              'request_digest','nonce','issued_at','expires_at'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution evidence writer authorization'
    );
    IF pg_catalog.jsonb_typeof(writer_authorization->'writer_pid')
            IS DISTINCT FROM 'number'
       OR writer_authorization->>'writer_pid' !~ '^[1-9][0-9]*$'
       OR writer_authorization->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR writer_authorization->>'actor_id' IS DISTINCT FROM p_actor->>'actor_id'
       OR writer_authorization->>'session_id' IS DISTINCT FROM p_actor->>'session_id'
       OR writer_authorization->>'purpose' IS DISTINCT FROM 'issue'
       OR writer_authorization->>'operation_id'
            IS DISTINCT FROM p_command->>'operation_id'
       OR writer_authorization->>'operation_digest'
            IS DISTINCT FROM p_command->>'operation_digest'
       OR writer_authorization->>'command_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_command)
       OR writer_authorization->>'grant_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_grant)
       OR writer_authorization->>'request_id'
            IS DISTINCT FROM p_command#>>'{tool_request,request_id}'
       OR writer_authorization->>'request_digest'
            IS DISTINCT FROM p_command#>>'{tool_request,request_digest}'
       OR writer_authorization->>'nonce' !~ '^[0-9a-f]{32}$'
       OR (writer_authorization->>'expires_at')::timestamptz
            <= (writer_authorization->>'issued_at')::timestamptz
       OR (writer_authorization->>'expires_at')::timestamptz
            > (writer_authorization->>'issued_at')::timestamptz + interval '30 seconds'
       OR (writer_authorization->>'issued_at')::timestamptz
            > (p_evidence->>'recorded_at')::timestamptz + interval '1 minute'
    THEN
        RAISE EXCEPTION 'execution evidence writer authorization is malformed or unbound';
    END IF;
    SELECT * INTO artifact FROM public.gah_skill_artifact_revisions
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND skill_id=p_command->>'skill_id'
       AND revision=(p_command->>'revision')::integer;
    IF NOT FOUND
       OR artifact.artifact_digest IS DISTINCT FROM p_command->>'artifact_digest'
       OR artifact.command_json->'gate_decision' IS DISTINCT FROM gate
       OR artifact.command_json->'source_evidence'
            IS DISTINCT FROM p_command->'source_evidence'
       OR artifact.command_json->'validity' IS DISTINCT FROM p_command->'validity'
       OR artifact.command_json->'retention' IS DISTINCT FROM p_command->'retention'
    THEN RAISE EXCEPTION 'execution authorization is not bound to lifecycle authority'; END IF;
    IF p_require_current THEN
        SELECT * INTO active FROM public.gah_active_skill_projection
         WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
           AND skill_id=p_command->>'skill_id' FOR UPDATE;
        IF NOT FOUND OR active.lifecycle_state IS DISTINCT FROM 'active'
           OR active.revision IS DISTINCT FROM (p_command->>'revision')::integer
           OR active.artifact_digest IS DISTINCT FROM p_command->>'artifact_digest'
        THEN
            RAISE EXCEPTION 'execution authorization active skill binding is stale';
        END IF;
    ELSE
        active.skill_id := p_command->>'skill_id';
        active.revision := (p_command->>'revision')::integer;
        active.artifact_digest := p_command->>'artifact_digest';
    END IF;
    IF p_actor->>'schema_version' IS DISTINCT FROM '1.0'
       OR p_actor->>'record_type' IS DISTINCT FROM 'actor_context'
       OR p_command->>'operation_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_command-'operation_digest')
       OR p_command->>'operation_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_command->>'artifact_digest'
            IS DISTINCT FROM
               'sha256:be4c49fbd64577c93908f9c49d3a4625e52c216bac4703be737fc2e080f4c9a7'
       OR request->>'schema_version' IS DISTINCT FROM '1.0'
       OR request->>'record_type' IS DISTINCT FROM 'tool_request'
       OR request->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR request->>'actor_id' IS DISTINCT FROM p_actor->>'actor_id'
       OR request->>'actor_context_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_actor)
       OR request->>'run_id' IS DISTINCT FROM p_actor->>'session_id'
       OR request->>'tool_id' IS DISTINCT FROM 'gah.builtin.echo'
       OR request->>'tool_version' IS DISTINCT FROM '1.0.0'
       OR request->'effect_classes' IS DISTINCT FROM '["execute_code"]'::jsonb
       OR request#>>'{arguments,skill_id}' IS DISTINCT FROM active.skill_id
       OR (request#>>'{arguments,revision}')::integer IS DISTINCT FROM active.revision
       OR request#>>'{arguments,artifact_digest}'
            IS DISTINCT FROM active.artifact_digest
       OR request->>'request_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(request-'request_digest')
       OR request#>>'{idempotency,tenant_id}' IS DISTINCT FROM p_actor->>'tenant_id'
       OR request#>>'{idempotency,operation_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR policy->>'schema_version' IS DISTINCT FROM '1.0'
       OR policy->>'record_type' IS DISTINCT FROM 'policy_decision'
       OR policy->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR policy->>'request_id' IS DISTINCT FROM request->>'request_id'
       OR policy->>'request_digest' IS DISTINCT FROM request->>'request_digest'
       OR policy->>'decision' IS DISTINCT FROM 'require_approval'
       OR policy->>'isolation_profile' IS DISTINCT FROM 'none'
       OR policy->'constraints' IS DISTINCT FROM '[]'::jsonb
       OR policy->>'decision_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(policy-'decision_digest')
       OR gate->>'schema_version' IS DISTINCT FROM '1.0'
       OR gate->>'record_type' IS DISTINCT FROM 'gate_decision'
       OR gate->>'decision' IS DISTINCT FROM 'approve'
       OR gate->>'decision_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(gate-'decision_digest')
       OR approval->>'schema_version' IS DISTINCT FROM '1.0'
       OR approval->>'record_type' IS DISTINCT FROM 'approval_record'
       OR approval->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR approval->>'request_id' IS DISTINCT FROM request->>'request_id'
       OR approval->>'request_digest' IS DISTINCT FROM request->>'request_digest'
       OR approval->>'policy_decision_id' IS DISTINCT FROM policy->>'decision_id'
       OR approval->>'policy_decision_digest'
            IS DISTINCT FROM policy->>'decision_digest'
       OR approval->>'disposition' IS DISTINCT FROM 'approved'
       OR approval->'constraints' IS DISTINCT FROM '[]'::jsonb
       OR (approval#>>'{separation_of_duties,required}')::boolean IS NOT TRUE
       OR (approval#>>'{separation_of_duties,satisfied}')::boolean IS NOT TRUE
       OR approval->>'approver_actor_id' IS NOT DISTINCT FROM p_actor->>'actor_id'
       OR approval->>'approval_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(
                (approval-'approval_digest')-'proof')
       OR approval#>>'{proof,proof_domain}' IS DISTINCT FROM 'approval_record.v1'
       OR approval#>>'{proof,object_digest}'
            IS DISTINCT FROM public.gah_canonical_sha256(
                (approval-'approval_digest')-'proof')
       OR approval#>>'{proof,object_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR approval#>>'{proof,nonce}' !~ '^[A-Za-z0-9_-]{22,128}$'
       OR approval#>>'{proof,detached_proof}' !~ '^[A-Za-z0-9_-]+$'
       OR pg_catalog.length(approval#>>'{proof,detached_proof}') NOT BETWEEN 43 AND 2048
       OR p_grant->>'schema_version' IS DISTINCT FROM '1.0'
       OR p_grant->>'record_type' IS DISTINCT FROM 'authorization_grant'
       OR p_grant->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_grant->>'actor_id' IS DISTINCT FROM p_actor->>'actor_id'
       OR p_grant->>'run_id' IS DISTINCT FROM p_actor->>'session_id'
       OR p_grant->>'request_id' IS DISTINCT FROM request->>'request_id'
       OR p_grant->>'request_digest' IS DISTINCT FROM request->>'request_digest'
       OR p_grant->>'tool_id' IS DISTINCT FROM 'gah.builtin.echo'
       OR p_grant->>'tool_version' IS DISTINCT FROM '1.0.0'
       OR p_grant->>'policy_decision_id' IS DISTINCT FROM policy->>'decision_id'
       OR p_grant->>'policy_decision_digest'
            IS DISTINCT FROM policy->>'decision_digest'
       OR p_grant->'approval_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','approval_record',
                'record_id',approval->>'approval_id',
                'record_digest',approval->>'approval_digest'))
       OR p_grant->'constraints' IS DISTINCT FROM '[]'::jsonb
       OR p_grant->>'isolation_profile' IS DISTINCT FROM 'none'
       OR p_grant->'idempotency' IS DISTINCT FROM request->'idempotency'
       OR p_grant#>>'{proof,proof_domain}'
            IS DISTINCT FROM 'authorization_grant.v1'
       OR p_grant#>>'{proof,object_digest}'
            IS DISTINCT FROM public.gah_canonical_sha256(p_grant-'proof')
       OR p_grant#>>'{proof,object_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR p_grant#>>'{proof,nonce}' !~ '^[A-Za-z0-9_-]{22,128}$'
       OR p_grant#>>'{proof,detached_proof}' !~ '^[A-Za-z0-9_-]+$'
       OR pg_catalog.length(p_grant#>>'{proof,detached_proof}') NOT BETWEEN 43 AND 2048
       OR (p_grant->>'issued_at')::timestamptz
            < (approval->>'issued_at')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            <= (p_grant->>'issued_at')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            > (p_grant->>'issued_at')::timestamptz + interval '5 minutes'
       OR (p_grant->>'expires_at')::timestamptz
            > (p_actor->>'expires_at')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            > (approval->>'expires_at')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            > (p_command#>>'{validity,expires_at}')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            > (p_command#>>'{retention,expires_at}')::timestamptz
       OR p_evidence->>'schema_version' IS DISTINCT FROM '1.0'
       OR p_evidence->>'record_type' IS DISTINCT FROM 'evidence_envelope'
       OR p_evidence->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_evidence->>'draft_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(draft)
       OR p_evidence->>'payload_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(payload)
       OR p_evidence->>'event_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_evidence-'event_digest')
       OR p_evidence->>'storage_writer_id'
            IS DISTINCT FROM 'execution.postgresql.v1'
       OR p_evidence->'policy_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','policy_decision',
                'record_id',policy->>'decision_id',
                'record_digest',policy->>'decision_digest'))
       OR draft->>'schema_version' IS DISTINCT FROM '1.0'
       OR draft->>'record_type' IS DISTINCT FROM 'evidence_draft'
       OR draft->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR draft->>'run_id' IS DISTINCT FROM p_actor->>'session_id'
       OR draft->>'event_kind'
            IS DISTINCT FROM 'execution.authorization_issued'
       OR draft->>'occurred_at' IS DISTINCT FROM p_evidence->>'recorded_at'
       OR draft->>'classification' IS DISTINCT FROM 'internal'
       OR draft->>'redaction_status' IS DISTINCT FROM 'redacted'
       OR draft#>>'{idempotency,tenant_id}' IS DISTINCT FROM p_actor->>'tenant_id'
       OR draft#>>'{idempotency,operation_digest}'
            IS DISTINCT FROM p_command->>'operation_digest'
       OR payload->>'actor_id' IS DISTINCT FROM p_actor->>'actor_id'
       OR payload->>'operation_id' IS DISTINCT FROM p_command->>'operation_id'
       OR payload->>'operation_digest' IS DISTINCT FROM p_command->>'operation_digest'
       OR payload->'command' IS DISTINCT FROM p_command
       OR payload->'authorization_grant' IS DISTINCT FROM p_grant
       OR payload->>'authorization_grant_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_grant)
       OR payload->>'state' IS DISTINCT FROM 'authorized'
    THEN
        RAISE EXCEPTION 'execution authority binding is malformed, changed, or unsigned';
    END IF;
    IF (p_actor->>'issued_at')::timestamptz > (p_grant->>'issued_at')::timestamptz
       OR (approval->>'issued_at')::timestamptz > (p_grant->>'issued_at')::timestamptz
    THEN RAISE EXCEPTION 'execution authority chronology is invalid'; END IF;
    IF p_require_current AND (
           (p_actor->>'issued_at')::timestamptz > clock_timestamp()
           OR (p_actor->>'expires_at')::timestamptz <= clock_timestamp()
           OR (approval->>'issued_at')::timestamptz > clock_timestamp()
           OR (approval->>'expires_at')::timestamptz <= clock_timestamp()
           OR (p_command#>>'{validity,expires_at}')::timestamptz <= clock_timestamp()
           OR (p_command#>>'{retention,expires_at}')::timestamptz <= clock_timestamp()
           OR (p_grant->>'issued_at')::timestamptz > clock_timestamp()
           OR (p_grant->>'expires_at')::timestamptz <= clock_timestamp()
       )
    THEN RAISE EXCEPTION 'execution authority is expired or not yet valid'; END IF;
    approval_acceptance := public.gah_verify_execution_signed_record(
        approval, 'approval_digest', (p_evidence->>'recorded_at')::timestamptz,
        NOT p_require_current
    );
    grant_acceptance := public.gah_verify_execution_signed_record(
        p_grant, 'grant_digest', (p_evidence->>'recorded_at')::timestamptz,
        NOT p_require_current
    );
    IF payload->'proof_acceptances' IS DISTINCT FROM jsonb_build_object(
        'accepted_at', p_evidence->>'recorded_at',
        'approval', approval_acceptance,
        'grant', grant_acceptance
    ) THEN
        RAISE EXCEPTION 'execution proof acceptance snapshot is missing or mismatched';
    END IF;
END
$function$;

CREATE FUNCTION gah_issue_builtin_execution_authorization(
    p_actor jsonb, p_command jsonb, p_grant jsonb, p_evidence jsonb,
    p_writer_authorization jsonb
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    active public.gah_active_skill_projection%ROWTYPE;
    artifact public.gah_skill_artifact_revisions%ROWTYPE;
    stored public.gah_builtin_execution_state%ROWTYPE;
    approval jsonb := p_command#>'{approvals,0}';
    payload jsonb := p_evidence#>'{draft,inline_payload}';
    lock_key text;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    IF NOT pg_catalog.pg_has_role(
           session_user, 'gah_execution_admission_authority', 'MEMBER') THEN
        RAISE EXCEPTION 'execution authorization requires admission authority';
    END IF;
    -- An exact durable replay is valid even after the original grant expires.
    -- It must be indistinguishable from the stored actor, command, grant, and
    -- ledger-bound acceptance snapshot; anything else is a conflict.
    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id'
       AND (operation_id=p_command->>'operation_id'
            OR operation_digest=p_command->>'operation_digest');
    IF FOUND THEN
        IF stored.actor_id IS DISTINCT FROM p_actor->>'actor_id'
           OR stored.run_id IS DISTINCT FROM p_actor->>'session_id'
           OR stored.command_json IS DISTINCT FROM p_command
           OR stored.command_json#>>'{tool_request,actor_context_digest}'
                IS DISTINCT FROM public.gah_canonical_sha256(p_actor)
           OR stored.grant_json IS DISTINCT FROM p_grant
           OR stored.issuance_evidence_json IS DISTINCT FROM p_evidence
           OR stored.issuance_evidence_json#>'{draft,inline_payload,writer_authorization}'
                IS DISTINCT FROM p_writer_authorization
        THEN RAISE EXCEPTION 'execution authorization conflicts with stored authority'; END IF;
        RETURN public.gah_builtin_execution_result(stored,true);
    END IF;
    PERFORM public.gah_builtin_execution_validate_authority(
        p_actor,p_command,p_grant,p_evidence,true);
    PERFORM public.gah_builtin_execution_assert_writer_authorization(
        p_actor,p_command,p_grant,p_writer_authorization);
    IF payload->'writer_authorization' IS DISTINCT FROM p_writer_authorization
    THEN RAISE EXCEPTION 'execution evidence lacks its exact writer authorization'; END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(p_command)) <> 12
       OR NOT (p_command ?& ARRAY[
           'operation_id','operation_digest','skill_id','revision','artifact_digest',
           'tool_request','policy_decision','gate_decision','approvals','source_evidence',
           'validity','retention'])
       OR p_command->>'operation_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR p_command->>'operation_digest'
            <> public.gah_canonical_sha256(p_command-'operation_digest')
       OR jsonb_array_length(p_command->'approvals') <> 1
       OR jsonb_array_length(p_command#>'{tool_request,effect_classes}') <> 1
       OR p_command#>>'{tool_request,effect_classes,0}' <> 'execute_code'
       OR p_command#>>'{tool_request,tool_id}' <> 'gah.builtin.echo'
       OR p_command#>>'{tool_request,tool_version}' <> '1.0.0'
       OR p_command->>'artifact_digest'
            <> 'sha256:be4c49fbd64577c93908f9c49d3a4625e52c216bac4703be737fc2e080f4c9a7'
    THEN RAISE EXCEPTION 'execution authorization command is outside the built-in boundary'; END IF;

    FOREACH lock_key IN ARRAY (
        SELECT array_agg(value ORDER BY value) FROM unnest(ARRAY[
            'execution:request:'||(p_actor->>'tenant_id')||':'||
                (p_command#>>'{tool_request,request_id}'),
            'execution:grant:'||(p_actor->>'tenant_id')||':'||(p_grant->>'grant_id'),
            'skill:'||(p_actor->>'tenant_id')||':'||(p_command->>'skill_id')
        ]) AS value
    ) LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended(lock_key, 0));
    END LOOP;

    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id'
       AND (operation_id=p_command->>'operation_id'
            OR operation_digest=p_command->>'operation_digest'
            OR request_id=p_command#>>'{tool_request,request_id}'
            OR grant_id=p_grant->>'grant_id');
    IF FOUND THEN
        IF stored.actor_id <> p_actor->>'actor_id'
           OR stored.command_json IS DISTINCT FROM p_command
           OR stored.command_json#>>'{tool_request,actor_context_digest}'
                IS DISTINCT FROM public.gah_canonical_sha256(p_actor)
           OR stored.grant_json IS DISTINCT FROM p_grant
           OR stored.issuance_evidence_json IS DISTINCT FROM p_evidence
           OR stored.issuance_evidence_json#>'{draft,inline_payload,writer_authorization}'
                IS DISTINCT FROM p_writer_authorization
        THEN RAISE EXCEPTION 'execution authorization conflicts with stored authority'; END IF;
        RETURN public.gah_builtin_execution_result(stored, true);
    END IF;

    SELECT * INTO active FROM public.gah_active_skill_projection
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND skill_id=p_command->>'skill_id' FOR UPDATE;
    IF NOT FOUND OR active.lifecycle_state <> 'active'
       OR active.revision <> (p_command->>'revision')::integer
       OR active.artifact_digest <> p_command->>'artifact_digest'
    THEN RAISE EXCEPTION 'execution authorization active skill binding is stale'; END IF;
    SELECT * INTO artifact FROM public.gah_skill_artifact_revisions
     WHERE tenant_id=active.tenant_id AND actor_id=active.actor_id
       AND skill_id=active.skill_id AND revision=active.revision;
    IF NOT FOUND OR artifact.artifact_digest <> active.artifact_digest
       OR artifact.command_json->'gate_decision' IS DISTINCT FROM p_command->'gate_decision'
       OR artifact.command_json->'source_evidence' IS DISTINCT FROM p_command->'source_evidence'
       OR artifact.command_json->'validity' IS DISTINCT FROM p_command->'validity'
       OR artifact.command_json->'retention' IS DISTINCT FROM p_command->'retention'
    THEN RAISE EXCEPTION 'execution authorization is not bound to lifecycle authority'; END IF;

    IF p_command#>>'{tool_request,tenant_id}' <> p_actor->>'tenant_id'
       OR p_command#>>'{tool_request,actor_id}' <> p_actor->>'actor_id'
       OR p_command#>>'{tool_request,actor_context_digest}'
            <> public.gah_canonical_sha256(p_actor)
       OR p_command#>>'{tool_request,run_id}' <> p_actor->>'session_id'
       OR p_command#>>'{tool_request,arguments,skill_id}' <> active.skill_id
       OR (p_command#>>'{tool_request,arguments,revision}')::integer <> active.revision
       OR p_command#>>'{tool_request,arguments,artifact_digest}' <> active.artifact_digest
       OR (SELECT count(*) FROM jsonb_object_keys(p_command#>'{tool_request,arguments}')) <> 4
       OR p_command#>>'{policy_decision,request_id}'
            <> p_command#>>'{tool_request,request_id}'
       OR p_command#>>'{policy_decision,request_digest}'
            <> p_command#>>'{tool_request,request_digest}'
       OR p_command#>>'{policy_decision,decision}' <> 'require_approval'
       OR p_command#>>'{policy_decision,isolation_profile}' <> 'none'
       OR approval->>'request_id' <> p_command#>>'{tool_request,request_id}'
       OR approval->>'request_digest' <> p_command#>>'{tool_request,request_digest}'
       OR approval->>'policy_decision_id' <> p_command#>>'{policy_decision,decision_id}'
       OR approval->>'policy_decision_digest' <> p_command#>>'{policy_decision,decision_digest}'
       OR approval->>'disposition' <> 'approved'
       OR (approval#>>'{separation_of_duties,required}')::boolean IS NOT TRUE
       OR (approval#>>'{separation_of_duties,satisfied}')::boolean IS NOT TRUE
       OR approval->>'approver_actor_id' = p_actor->>'actor_id'
       OR p_command#>>'{gate_decision,decision}' <> 'approve'
       OR p_command#>>'{tool_request,request_digest}'
            <> public.gah_canonical_sha256(
                (p_command#>'{tool_request}')-'request_digest')
       OR p_command#>>'{policy_decision,decision_digest}'
            <> public.gah_canonical_sha256(
                (p_command#>'{policy_decision}')-'decision_digest')
       OR p_command#>>'{gate_decision,decision_digest}'
            <> public.gah_canonical_sha256(
                (p_command#>'{gate_decision}')-'decision_digest')
       OR approval->>'approval_digest'
            <> public.gah_canonical_sha256((approval-'approval_digest')-'proof')
       OR approval#>>'{proof,object_digest}'
            <> public.gah_canonical_sha256((approval-'approval_digest')-'proof')
       OR (p_actor->>'issued_at')::timestamptz > clock_timestamp()
       OR (p_actor->>'expires_at')::timestamptz <= clock_timestamp()
       OR (approval->>'issued_at')::timestamptz > clock_timestamp()
       OR (approval->>'expires_at')::timestamptz <= clock_timestamp()
       OR (p_command#>>'{validity,expires_at}')::timestamptz <= clock_timestamp()
       OR (p_command#>>'{retention,expires_at}')::timestamptz <= clock_timestamp()
    THEN RAISE EXCEPTION 'execution request policy gate or approval binding is invalid'; END IF;

    IF p_grant->>'tenant_id' <> p_actor->>'tenant_id'
       OR p_grant->>'actor_id' <> p_actor->>'actor_id'
       OR p_grant->>'run_id' <> p_actor->>'session_id'
       OR p_grant->>'request_id' <> p_command#>>'{tool_request,request_id}'
       OR p_grant->>'request_digest' <> p_command#>>'{tool_request,request_digest}'
       OR p_grant->>'tool_id' <> 'gah.builtin.echo'
       OR p_grant->>'tool_version' <> '1.0.0'
       OR p_grant->>'policy_decision_id' <> p_command#>>'{policy_decision,decision_id}'
       OR p_grant->>'policy_decision_digest' <> p_command#>>'{policy_decision,decision_digest}'
       OR p_grant->'approval_refs' IS DISTINCT FROM jsonb_build_array(jsonb_build_object(
           'record_type','approval_record','record_id',approval->>'approval_id',
           'record_digest',approval->>'approval_digest'))
       OR p_grant->'constraints' IS DISTINCT FROM p_command#>'{policy_decision,constraints}'
       OR p_grant->>'isolation_profile' <> 'none'
       OR p_grant->'idempotency' IS DISTINCT FROM p_command#>'{tool_request,idempotency}'
       OR (p_grant->>'issued_at')::timestamptz < (approval->>'issued_at')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz <= (p_grant->>'issued_at')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            > (p_grant->>'issued_at')::timestamptz + interval '5 minutes'
       OR (p_grant->>'expires_at')::timestamptz > (approval->>'expires_at')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            > (p_command#>>'{validity,expires_at}')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz
            > (p_command#>>'{retention,expires_at}')::timestamptz
       OR (p_grant->>'expires_at')::timestamptz > (p_actor->>'expires_at')::timestamptz
       OR p_grant#>>'{proof,object_digest}'
            <> public.gah_canonical_sha256(p_grant-'proof')
       OR payload->>'authorization_grant_digest'
            <> public.gah_canonical_sha256(p_grant)
       OR (p_grant->>'issued_at')::timestamptz > clock_timestamp()
       OR (p_grant->>'expires_at')::timestamptz <= clock_timestamp()
    THEN RAISE EXCEPTION 'execution authorization grant binding is invalid'; END IF;

    IF payload->>'actor_id' <> p_actor->>'actor_id'
       OR payload->>'operation_id' <> p_command->>'operation_id'
       OR payload->>'operation_digest' <> p_command->>'operation_digest'
       OR payload->'command' IS DISTINCT FROM p_command
       OR payload->'authorization_grant' IS DISTINCT FROM p_grant
       OR payload->>'authorization_grant_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR payload->>'state' <> 'authorized'
    THEN RAISE EXCEPTION 'execution issuance evidence binding is invalid'; END IF;
    PERFORM public.gah_builtin_execution_commit_evidence(
        p_actor, p_evidence, 'execution.authorization_issued', payload
    );
    INSERT INTO public.gah_builtin_execution_state (
        tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,request_digest,
        grant_id,grant_digest,skill_id,revision,artifact_digest,command_json,grant_json,
        state,issuance_evidence_json,issued_at
    ) VALUES (
        p_actor->>'tenant_id',p_actor->>'actor_id',p_actor->>'session_id',
        p_command->>'operation_id',p_command->>'operation_digest',
        p_command#>>'{tool_request,request_id}',p_command#>>'{tool_request,request_digest}',
        p_grant->>'grant_id',payload->>'authorization_grant_digest',
        active.skill_id,active.revision,active.artifact_digest,p_command,p_grant,
        'authorized',p_evidence,(p_grant->>'issued_at')::timestamptz
    ) RETURNING * INTO stored;
    RETURN public.gah_builtin_execution_result(stored, false);
END
$function$;

CREATE FUNCTION gah_lookup_builtin_execution(p_actor jsonb, p_query jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE stored public.gah_builtin_execution_state%ROWTYPE;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    PERFORM public.gah_builtin_execution_assert_object(
        p_query, ARRAY['operation_id','operation_digest','grant_digest'],
        ARRAY['operation_id','operation_digest','grant_digest'], 'execution lookup query'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_query, ARRAY['operation_id','operation_digest','grant_digest'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution lookup query'
    );
    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND operation_id=p_query->>'operation_id';
    IF NOT FOUND OR stored.run_id <> p_actor->>'session_id'
       OR stored.command_json#>>'{tool_request,actor_context_digest}'
            <> public.gah_canonical_sha256(p_actor)
       OR stored.operation_digest <> p_query->>'operation_digest'
       OR stored.grant_digest <> p_query->>'grant_digest'
    THEN RAISE EXCEPTION 'execution state is missing or digest-mismatched'; END IF;
    RETURN jsonb_build_object(
        'state',stored.state,'intent_evidence',stored.intent_evidence_json,
        'outcome',stored.outcome_json,'outcome_evidence',stored.outcome_evidence_json
    );
END
$function$;

CREATE FUNCTION gah_begin_builtin_execution(
    p_actor jsonb, p_authorization jsonb, p_intent jsonb, p_lease_seconds double precision
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    stored public.gah_builtin_execution_state%ROWTYPE;
    active public.gah_active_skill_projection%ROWTYPE;
    payload jsonb := p_intent#>'{draft,inline_payload}';
    lease_now timestamptz;
    lease_deadline timestamptz;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    PERFORM public.gah_builtin_execution_assert_object(
        p_authorization,
        ARRAY['operation_id','operation_digest','command','grant'],
        ARRAY['operation_id','operation_digest','command','grant'],
        'execution consume authorization'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_authorization, ARRAY['operation_id','operation_digest'], ARRAY['command','grant'],
        ARRAY[]::text[], 'execution consume authorization'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        payload,
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','skill_id','revision','artifact_digest','state'],
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','skill_id','revision','artifact_digest','state'],
        'execution intent payload'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        payload,
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','skill_id','artifact_digest','state'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution intent payload'
    );
    IF pg_catalog.jsonb_typeof(payload->'revision') IS DISTINCT FROM 'number'
       OR payload->>'revision' !~ '^[1-9][0-9]*$'
    THEN RAISE EXCEPTION 'execution intent revision is malformed'; END IF;
    IF NOT pg_has_role(session_user, 'gah_runtime', 'MEMBER')
       OR p_lease_seconds <= 0 OR p_lease_seconds > 300
    THEN RAISE EXCEPTION 'execution consume requires the bounded runtime path'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'execution:operation:'||(p_actor->>'tenant_id')||':'||
            (p_authorization->>'operation_id'),0));
    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND operation_id=p_authorization->>'operation_id' FOR UPDATE;
    IF NOT FOUND
       OR stored.run_id <> p_actor->>'session_id'
       OR stored.command_json#>>'{tool_request,actor_context_digest}'
            <> public.gah_canonical_sha256(p_actor)
       OR stored.operation_digest <> p_authorization->>'operation_digest'
       OR stored.command_json IS DISTINCT FROM p_authorization->'command'
       OR stored.grant_json IS DISTINCT FROM p_authorization->'grant'
    THEN RAISE EXCEPTION 'execution consume authorization is missing or changed'; END IF;
    IF stored.state IN ('completed','indeterminate') THEN
        RETURN public.gah_builtin_execution_terminal_result(stored, true);
    END IF;
    IF stored.state='executing' THEN
        RAISE EXCEPTION 'execution authorization is already consumed';
    END IF;
    SELECT * INTO active FROM public.gah_active_skill_projection
     WHERE tenant_id=stored.tenant_id AND actor_id=stored.actor_id
       AND skill_id=stored.skill_id FOR UPDATE;
    IF NOT FOUND OR active.lifecycle_state <> 'active'
       OR active.revision <> stored.revision
       OR active.artifact_digest <> stored.artifact_digest
       OR (stored.grant_json->>'expires_at')::timestamptz <= clock_timestamp()
       OR (stored.command_json#>>'{validity,expires_at}')::timestamptz <= clock_timestamp()
       OR (stored.command_json#>>'{retention,expires_at}')::timestamptz
            <= clock_timestamp()
    THEN RAISE EXCEPTION 'execution consume binding is stale or expired'; END IF;
    lease_now := clock_timestamp();
    lease_deadline := LEAST(
        lease_now+(p_lease_seconds*interval '1 second'),
        (stored.grant_json->>'expires_at')::timestamptz - interval '1 millisecond'
    );
    IF lease_deadline <= lease_now
    THEN RAISE EXCEPTION 'execution consume has no positive fenced lease window'; END IF;
    IF payload <> jsonb_build_object(
        'actor_id',stored.actor_id,'operation_id',stored.operation_id,
        'operation_digest',stored.operation_digest,
        'authorization_grant_digest',stored.grant_digest,
        'skill_id',stored.skill_id,'revision',stored.revision,
        'artifact_digest',stored.artifact_digest,'state','executing')
    THEN RAISE EXCEPTION 'execution intent binding is invalid'; END IF;
    PERFORM public.gah_builtin_execution_commit_evidence(
        p_actor,p_intent,'execution.intent',payload
    );
    UPDATE public.gah_builtin_execution_state
       SET state='executing',version=version+1,intent_evidence_json=p_intent,
           execution_attempt_id=p_intent->>'envelope_id',owner_generation=1,
           lease_expires_at=lease_deadline
     WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id
     RETURNING * INTO stored;
    RETURN jsonb_build_object(
        'state',stored.state,'intent_evidence',stored.intent_evidence_json,
        'attempt_id',stored.execution_attempt_id,'owner_generation',stored.owner_generation,
        'replayed',false
    );
END
$function$;

CREATE FUNCTION gah_builtin_execution_validate_ledger_envelope(
    p_actor jsonb, p_envelope jsonb, p_event_kind text, p_payload jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    draft jsonb := p_envelope->'draft';
BEGIN
    PERFORM public.gah_builtin_execution_assert_object(
        p_envelope,
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
              'draft_digest','recorded_at','sequence_number','payload_digest',
              'prior_event_digest','event_digest','policy_refs','storage_writer_id'],
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft',
              'draft_digest','recorded_at','sequence_number','payload_digest',
              'prior_event_digest','event_digest','policy_refs','storage_writer_id',
              'extensions'],
        'execution ledger envelope'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_envelope,
        ARRAY['schema_version','record_type','tenant_id','envelope_id','draft_digest',
              'recorded_at','payload_digest','event_digest','storage_writer_id'],
        ARRAY['draft'], ARRAY['policy_refs'], 'execution ledger envelope'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        draft,
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','idempotency','classification','redaction_status',
              'inline_payload'],
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','idempotency','classification','redaction_status',
              'inline_payload','protected_payload','extensions'],
        'execution ledger draft'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        draft,
        ARRAY['schema_version','record_type','tenant_id','event_id','run_id','event_kind',
              'occurred_at','classification','redaction_status'],
        ARRAY['idempotency','inline_payload'], ARRAY[]::text[], 'execution ledger draft'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        draft->'idempotency',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        'execution ledger idempotency'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        draft->'idempotency',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution ledger idempotency'
    );
    IF p_event_kind NOT IN (
           'execution.authorization_issued','execution.intent','execution.outcome')
       OR pg_catalog.jsonb_typeof(p_envelope->'sequence_number') IS DISTINCT FROM 'number'
       OR p_envelope->>'sequence_number' !~ '^[0-9]+$'
       OR NOT (
           p_envelope->'prior_event_digest' = 'null'::jsonb
           OR pg_catalog.jsonb_typeof(p_envelope->'prior_event_digest') = 'string')
       OR p_envelope->>'schema_version' IS DISTINCT FROM '1.0'
       OR p_envelope->>'record_type' IS DISTINCT FROM 'evidence_envelope'
       OR p_envelope->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_envelope->>'draft_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(draft)
       OR p_envelope->>'payload_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_payload)
       OR p_envelope->>'event_digest'
            IS DISTINCT FROM public.gah_canonical_sha256(p_envelope-'event_digest')
       OR p_envelope->>'storage_writer_id'
            IS DISTINCT FROM 'execution.postgresql.v1'
       OR draft->>'schema_version' IS DISTINCT FROM '1.0'
       OR draft->>'record_type' IS DISTINCT FROM 'evidence_draft'
       OR draft->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR draft->>'run_id' IS DISTINCT FROM p_actor->>'session_id'
       OR draft->>'event_kind' IS DISTINCT FROM p_event_kind
       OR draft->>'occurred_at' IS DISTINCT FROM p_envelope->>'recorded_at'
       OR draft->>'classification' IS DISTINCT FROM 'internal'
       OR draft->>'redaction_status' IS DISTINCT FROM 'redacted'
       OR draft->'inline_payload' IS DISTINCT FROM p_payload
       OR draft#>>'{inline_payload,actor_id}' IS DISTINCT FROM p_actor->>'actor_id'
       OR draft#>>'{idempotency,tenant_id}' IS DISTINCT FROM p_actor->>'tenant_id'
       OR draft#>>'{idempotency,operation_digest}'
            IS DISTINCT FROM p_payload->>'operation_digest'
       OR (p_envelope->>'recorded_at')::timestamptz
            > clock_timestamp() + interval '1 minute'
    THEN RAISE EXCEPTION 'execution ledger envelope is malformed or non-canonical'; END IF;
END
$function$;

CREATE FUNCTION gah_builtin_execution_validate_outcome(
    p_actor jsonb, p_command jsonb, p_grant jsonb, p_intent jsonb,
    p_outcome jsonb, p_state text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    expected_status text := CASE p_state
        WHEN 'completed' THEN 'succeeded'
        WHEN 'indeterminate' THEN 'indeterminate'
        ELSE NULL
    END;
    expected_result jsonb := CASE p_state
        WHEN 'completed' THEN jsonb_build_object(
            'echo',p_command#>'{tool_request,arguments,input}')
        WHEN 'indeterminate' THEN '{"error":"execution_outcome_unknown"}'::jsonb
        ELSE NULL
    END;
    scope jsonb := p_outcome->'target_scope';
BEGIN
    IF expected_status IS NULL THEN
        RAISE EXCEPTION 'execution outcome state is unsupported';
    END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        p_outcome,
        ARRAY['schema_version','record_type','tenant_id','outcome_id','target_scope',
              'run_id','request_ref','status','effect_state','evidence_refs',
              'provenance_digest','result_payload','producer_version','runtime_version',
              'policy_refs','reviewer_refs','compatibility','idempotency','occurred_at',
              'outcome_digest'],
        ARRAY['schema_version','record_type','tenant_id','outcome_id','target_scope',
              'run_id','request_ref','status','effect_state','evidence_refs',
              'provenance_digest','result_payload','producer_version','runtime_version',
              'policy_refs','reviewer_refs','compatibility','idempotency','occurred_at',
              'outcome_digest','extensions'],
        'execution outcome'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_outcome,
        ARRAY['schema_version','record_type','tenant_id','outcome_id','run_id','status',
              'effect_state','provenance_digest','producer_version','runtime_version',
              'occurred_at','outcome_digest'],
        ARRAY['target_scope','request_ref','result_payload','compatibility','idempotency'],
        ARRAY['evidence_refs','policy_refs','reviewer_refs'], 'execution outcome'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        scope,
        ARRAY['schema_version','record_type','scope_id','tenant_id','actor_id',
              'parent_record_type','parent_digest','selection','derived_at','valid_until'],
        ARRAY['schema_version','record_type','scope_id','tenant_id','actor_id',
              'parent_record_type','parent_digest','selection','derived_at','valid_until',
              'extensions'],
        'execution outcome scope'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        scope,
        ARRAY['schema_version','record_type','scope_id','tenant_id','actor_id',
              'parent_record_type','parent_digest','derived_at','valid_until'],
        ARRAY['selection'], ARRAY[]::text[], 'execution outcome scope'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        scope->'selection', ARRAY['level'], ARRAY['level'],
        'execution outcome scope selection'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_outcome->'request_ref',
        ARRAY['record_type','record_id','record_digest'],
        ARRAY['record_type','record_id','record_digest'],
        'execution outcome request reference'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        p_outcome->'idempotency',
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        ARRAY['tenant_id','idempotency_key','operation_digest'],
        'execution outcome idempotency'
    );
    IF p_outcome->>'schema_version' IS DISTINCT FROM '1.0'
       OR p_outcome->>'record_type' IS DISTINCT FROM 'action_outcome'
       OR p_outcome->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_outcome->>'run_id' IS DISTINCT FROM p_actor->>'session_id'
       OR p_outcome->>'status' IS DISTINCT FROM expected_status
       OR p_outcome->>'effect_state' IS DISTINCT FROM expected_status
       OR p_outcome->'result_payload' IS DISTINCT FROM expected_result
       OR p_outcome->>'producer_version' IS DISTINCT FROM 'builtin_execution.v1'
       OR p_outcome->>'runtime_version' IS DISTINCT FROM 'phase5.1.local.v1'
       OR p_outcome->'request_ref' IS DISTINCT FROM jsonb_build_object(
            'record_type','tool_request',
            'record_id',p_command#>>'{tool_request,request_id}',
            'record_digest',p_command#>>'{tool_request,request_digest}')
       OR p_outcome->'evidence_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','evidence_envelope','record_id',p_intent->>'envelope_id',
                'record_digest',p_intent->>'event_digest'))
       OR p_outcome->'policy_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','policy_decision',
                'record_id',p_command#>>'{policy_decision,decision_id}',
                'record_digest',p_command#>>'{policy_decision,decision_digest}'))
       OR p_outcome->'reviewer_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','approval_record',
                'record_id',p_command#>>'{approvals,0,approval_id}',
                'record_digest',p_command#>>'{approvals,0,approval_digest}'))
       OR p_outcome->'compatibility' IS DISTINCT FROM jsonb_build_object(
            'contract_versions',jsonb_build_array('action_outcome=1.0'),
            'runtime_version_range','>=0.1')
       OR p_outcome->'idempotency' IS DISTINCT FROM
            p_command#>'{tool_request,idempotency}'
       OR p_outcome->>'provenance_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(jsonb_build_object(
                'authorization_grant_digest',public.gah_canonical_sha256(p_grant),
                'intent_evidence_digest',p_intent->>'event_digest',
                'result_payload',p_outcome->'result_payload'))
       OR p_outcome->>'outcome_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_outcome-'outcome_digest')
       OR scope->>'schema_version' IS DISTINCT FROM '1.0'
       OR scope->>'record_type' IS DISTINCT FROM 'memory_scope'
       OR scope->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR scope->>'actor_id' IS DISTINCT FROM p_actor->>'actor_id'
       OR scope->>'parent_record_type' IS DISTINCT FROM 'actor_context'
       OR scope->>'parent_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_actor)
       OR scope->'selection' IS DISTINCT FROM '{"level":"actor"}'::jsonb
       OR scope->>'derived_at' IS DISTINCT FROM p_outcome->>'occurred_at'
       OR scope->>'valid_until' IS DISTINCT FROM p_actor->>'expires_at'
       OR (p_outcome->>'occurred_at')::timestamptz
            > clock_timestamp() + interval '1 minute'
    THEN RAISE EXCEPTION 'execution outcome is malformed or unbound'; END IF;
END
$function$;

CREATE FUNCTION gah_complete_builtin_execution(
    p_actor jsonb, p_completion jsonb, p_outcome jsonb, p_evidence jsonb
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE stored public.gah_builtin_execution_state%ROWTYPE;
    payload jsonb := p_evidence#>'{draft,inline_payload}';
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    PERFORM public.gah_builtin_execution_assert_object(
        p_completion,
        ARRAY['operation_id','operation_digest','attempt_id','owner_generation'],
        ARRAY['operation_id','operation_digest','attempt_id','owner_generation'],
        'execution completion'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_completion, ARRAY['operation_id','operation_digest','attempt_id'],
        ARRAY[]::text[], ARRAY[]::text[], 'execution completion'
    );
    IF pg_catalog.jsonb_typeof(p_completion->'owner_generation')
            IS DISTINCT FROM 'number'
       OR p_completion->>'owner_generation' !~ '^[1-9][0-9]*$'
    THEN RAISE EXCEPTION 'execution completion generation is malformed'; END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        payload,
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','outcome_digest','status','state','outcome'],
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','outcome_digest','status','state','outcome'],
        'execution completion payload'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        payload,
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','outcome_digest','status','state'],
        ARRAY['outcome'], ARRAY[]::text[], 'execution completion payload'
    );
    IF NOT pg_has_role(session_user, 'gah_runtime', 'MEMBER')
    THEN RAISE EXCEPTION 'execution completion requires runtime'; END IF;
    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND operation_id=p_completion->>'operation_id' FOR UPDATE;
    IF NOT FOUND OR stored.run_id <> p_actor->>'session_id'
       OR stored.command_json#>>'{tool_request,actor_context_digest}'
            <> public.gah_canonical_sha256(p_actor)
       OR stored.operation_digest <> p_completion->>'operation_digest'
    THEN RAISE EXCEPTION 'execution completion is missing or digest-mismatched'; END IF;
    IF stored.state='completed' THEN
        IF stored.outcome_json IS DISTINCT FROM p_outcome
        THEN RAISE EXCEPTION 'execution completion replay changed outcome'; END IF;
        RETURN public.gah_builtin_execution_terminal_result(stored,true);
    END IF;
    PERFORM public.gah_builtin_execution_validate_outcome(
        p_actor,stored.command_json,stored.grant_json,stored.intent_evidence_json,
        p_outcome,'completed');
    IF stored.state <> 'executing'
       OR stored.execution_attempt_id <> p_completion->>'attempt_id'
       OR stored.owner_generation <> (p_completion->>'owner_generation')::bigint
       OR stored.lease_expires_at <= clock_timestamp()
       OR p_outcome->>'status' <> 'succeeded'
       OR p_outcome->>'effect_state' <> 'succeeded'
       OR p_outcome->>'tenant_id' <> stored.tenant_id
       OR p_outcome->>'run_id' <> stored.run_id
       OR p_outcome#>>'{request_ref,record_id}' <> stored.request_id
       OR p_outcome#>>'{request_ref,record_digest}' <> stored.request_digest
       OR p_outcome->>'outcome_digest'
            <> public.gah_canonical_sha256(p_outcome-'outcome_digest')
       OR p_outcome#>'{result_payload}' IS DISTINCT FROM jsonb_build_object(
            'echo',stored.command_json#>'{tool_request,arguments,input}')
       OR p_outcome->'evidence_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','evidence_envelope',
                'record_id',stored.intent_evidence_json->>'envelope_id',
                'record_digest',stored.intent_evidence_json->>'event_digest'))
       OR p_outcome->'policy_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','policy_decision',
                'record_id',stored.command_json#>>'{policy_decision,decision_id}',
                'record_digest',stored.command_json#>>'{policy_decision,decision_digest}'))
       OR p_outcome->'reviewer_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','approval_record',
                'record_id',stored.command_json#>>'{approvals,0,approval_id}',
                'record_digest',stored.command_json#>>'{approvals,0,approval_digest}'))
       OR p_outcome->'idempotency'
            IS DISTINCT FROM stored.command_json#>'{tool_request,idempotency}'
       OR p_outcome->>'provenance_digest' <> public.gah_canonical_sha256(
            jsonb_build_object(
                'authorization_grant_digest',stored.grant_digest,
                'intent_evidence_digest',stored.intent_evidence_json->>'event_digest',
                'result_payload',p_outcome->'result_payload'))
       OR payload <> jsonb_build_object(
           'actor_id',stored.actor_id,'operation_id',stored.operation_id,
           'operation_digest',stored.operation_digest,
           'authorization_grant_digest',stored.grant_digest,
           'outcome_digest',p_outcome->>'outcome_digest',
           'status','succeeded','state','completed','outcome',p_outcome)
    THEN RAISE EXCEPTION 'execution completion binding is invalid or stale'; END IF;
    PERFORM public.gah_builtin_execution_commit_evidence(
        p_actor,p_evidence,'execution.outcome',payload
    );
    UPDATE public.gah_builtin_execution_state
       SET state='completed',version=version+1,outcome_json=p_outcome,
           outcome_evidence_json=p_evidence,completed_at=clock_timestamp()
     WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id
     RETURNING * INTO stored;
    RETURN public.gah_builtin_execution_terminal_result(stored,false);
END
$function$;

CREATE FUNCTION gah_recover_builtin_execution(
    p_actor jsonb, p_query jsonb, p_outcome jsonb, p_evidence jsonb
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE stored public.gah_builtin_execution_state%ROWTYPE;
    payload jsonb := p_evidence#>'{draft,inline_payload}';
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    PERFORM public.gah_builtin_execution_assert_object(
        p_query, ARRAY['operation_id','operation_digest'],
        ARRAY['operation_id','operation_digest'], 'execution recovery query'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_query, ARRAY['operation_id','operation_digest'], ARRAY[]::text[],
        ARRAY[]::text[], 'execution recovery query'
    );
    PERFORM public.gah_builtin_execution_assert_object(
        payload,
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','outcome_digest','status','state','outcome'],
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','outcome_digest','status','state','outcome'],
        'execution recovery payload'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        payload,
        ARRAY['actor_id','operation_id','operation_digest',
              'authorization_grant_digest','outcome_digest','status','state'],
        ARRAY['outcome'], ARRAY[]::text[], 'execution recovery payload'
    );
    IF NOT pg_has_role(session_user, 'gah_runtime', 'MEMBER')
    THEN RAISE EXCEPTION 'execution recovery requires runtime'; END IF;
    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND operation_id=p_query->>'operation_id' FOR UPDATE;
    IF NOT FOUND OR stored.run_id <> p_actor->>'session_id'
       OR stored.command_json#>>'{tool_request,actor_context_digest}'
            <> public.gah_canonical_sha256(p_actor)
       OR stored.operation_digest <> p_query->>'operation_digest'
    THEN RAISE EXCEPTION 'execution recovery is missing or digest-mismatched'; END IF;
    IF stored.state IN ('completed','indeterminate') THEN
        RETURN public.gah_builtin_execution_terminal_result(stored,true);
    END IF;
    PERFORM public.gah_builtin_execution_validate_outcome(
        p_actor,stored.command_json,stored.grant_json,stored.intent_evidence_json,
        p_outcome,'indeterminate');
    IF stored.state <> 'executing' OR stored.lease_expires_at > clock_timestamp()
       OR p_outcome->>'status' <> 'indeterminate'
       OR p_outcome->>'effect_state' <> 'indeterminate'
       OR p_outcome->>'tenant_id' <> stored.tenant_id
       OR p_outcome->>'run_id' <> stored.run_id
       OR p_outcome#>>'{request_ref,record_id}' <> stored.request_id
       OR p_outcome#>>'{request_ref,record_digest}' <> stored.request_digest
       OR p_outcome->>'outcome_digest'
            <> public.gah_canonical_sha256(p_outcome-'outcome_digest')
       OR p_outcome#>'{result_payload}' IS DISTINCT FROM
            '{"error":"execution_outcome_unknown"}'::jsonb
       OR p_outcome->'evidence_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','evidence_envelope',
                'record_id',stored.intent_evidence_json->>'envelope_id',
                'record_digest',stored.intent_evidence_json->>'event_digest'))
       OR p_outcome->'policy_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','policy_decision',
                'record_id',stored.command_json#>>'{policy_decision,decision_id}',
                'record_digest',stored.command_json#>>'{policy_decision,decision_digest}'))
       OR p_outcome->'reviewer_refs' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object(
                'record_type','approval_record',
                'record_id',stored.command_json#>>'{approvals,0,approval_id}',
                'record_digest',stored.command_json#>>'{approvals,0,approval_digest}'))
       OR p_outcome->'idempotency'
            IS DISTINCT FROM stored.command_json#>'{tool_request,idempotency}'
       OR p_outcome->>'provenance_digest' <> public.gah_canonical_sha256(
            jsonb_build_object(
                'authorization_grant_digest',stored.grant_digest,
                'intent_evidence_digest',stored.intent_evidence_json->>'event_digest',
                'result_payload',p_outcome->'result_payload'))
       OR payload <> jsonb_build_object(
           'actor_id',stored.actor_id,'operation_id',stored.operation_id,
           'operation_digest',stored.operation_digest,
           'authorization_grant_digest',stored.grant_digest,
           'outcome_digest',p_outcome->>'outcome_digest',
           'status','indeterminate','state','indeterminate','outcome',p_outcome)
    THEN RAISE EXCEPTION 'execution recovery is not authorized by an expired lease'; END IF;
    PERFORM public.gah_builtin_execution_commit_evidence(
        p_actor,p_evidence,'execution.outcome',payload
    );
    UPDATE public.gah_builtin_execution_state
       SET state='indeterminate',version=version+1,owner_generation=owner_generation+1,
           outcome_json=p_outcome,outcome_evidence_json=p_evidence,
           completed_at=clock_timestamp()
     WHERE tenant_id=stored.tenant_id AND operation_id=stored.operation_id
     RETURNING * INTO stored;
    RETURN public.gah_builtin_execution_terminal_result(stored,false);
END
$function$;

CREATE FUNCTION gah_builtin_execution_assert_authoritative_run_chain(
    p_actor jsonb, p_run_id text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    head public.gah_run_heads%ROWTYPE;
    event_row public.gah_evidence_events%ROWTYPE;
    final_row public.gah_evidence_events%ROWTYPE;
    event_count bigint;
BEGIN
    SELECT * INTO head FROM public.gah_run_heads
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND run_id=p_run_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'execution rebuild authoritative run head is missing';
    END IF;
    FOR event_row IN
        SELECT * FROM public.gah_evidence_events
         WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
           AND run_id=p_run_id ORDER BY sequence_number
    LOOP
        IF event_row.envelope_json->>'tenant_id' IS DISTINCT FROM event_row.tenant_id
           OR event_row.envelope_json#>>'{draft,inline_payload,actor_id}'
                IS DISTINCT FROM event_row.actor_id
           OR event_row.envelope_json#>>'{draft,run_id}' IS DISTINCT FROM event_row.run_id
           OR event_row.envelope_json->>'envelope_id' IS DISTINCT FROM event_row.envelope_id
           OR event_row.envelope_json->>'event_digest' IS DISTINCT FROM event_row.event_digest
           OR (event_row.envelope_json->>'sequence_number')::bigint
                IS DISTINCT FROM event_row.sequence_number
           OR event_row.envelope_json->>'prior_event_digest'
                IS DISTINCT FROM event_row.prior_event_digest
           OR (event_row.envelope_json->>'recorded_at')::timestamptz
                IS DISTINCT FROM event_row.recorded_at
        THEN RAISE EXCEPTION 'execution rebuild envelope disagrees with authoritative row'; END IF;
    END LOOP;
    SELECT count(*) INTO event_count FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND run_id=p_run_id;
    SELECT * INTO final_row FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND run_id=p_run_id ORDER BY sequence_number DESC LIMIT 1;
    IF event_count = 0 OR final_row IS NULL
       OR head.next_sequence IS DISTINCT FROM event_count
       OR head.version IS DISTINCT FROM event_count
       OR head.last_event_digest IS DISTINCT FROM final_row.event_digest
       OR head.last_recorded_at IS DISTINCT FROM final_row.recorded_at
    THEN RAISE EXCEPTION 'execution rebuild authoritative run head disagrees with evidence'; END IF;
END
$function$;

CREATE FUNCTION gah_rebuild_builtin_execution(p_actor jsonb, p_query jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    issuance jsonb; intent jsonb; terminal jsonb; payload jsonb;
    intent_payload jsonb; terminal_payload jsonb; outcome jsonb;
    stored public.gah_builtin_execution_state%ROWTYPE; rebuilt_state text;
    issuance_count bigint; intent_count bigint; terminal_count bigint;
    target_run_id text;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    IF NOT pg_catalog.pg_has_role(
           session_user, 'gah_execution_admission_authority', 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, 'gah_authority_writer', 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, 'gah_runtime', 'MEMBER')
       OR pg_catalog.pg_has_role(
           session_user, 'gah_skill_lifecycle_authority', 'MEMBER')
    THEN RAISE EXCEPTION 'execution rebuild requires its distinct admission role'; END IF;
    PERFORM public.gah_builtin_execution_assert_object(
        p_query, ARRAY['operation_id','operation_digest'],
        ARRAY['operation_id','operation_digest'], 'execution rebuild query'
    );
    PERFORM public.gah_builtin_execution_assert_field_types(
        p_query, ARRAY['operation_id','operation_digest'], ARRAY[]::text[],
        ARRAY[]::text[], 'execution rebuild query'
    );
    IF p_query->>'operation_digest' !~ '^sha256:[0-9a-f]{64}$'
    THEN RAISE EXCEPTION 'execution rebuild query digest is malformed'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'execution:operation:'||(p_actor->>'tenant_id')||':'||
            (p_query->>'operation_id'),0));
    SELECT * INTO stored FROM public.gah_builtin_execution_state
     WHERE tenant_id=p_actor->>'tenant_id'
       AND (operation_id=p_query->>'operation_id'
            OR operation_digest=p_query->>'operation_digest')
     FOR UPDATE;
    IF FOUND THEN
        IF stored.actor_id IS DISTINCT FROM p_actor->>'actor_id'
           OR stored.operation_id IS DISTINCT FROM p_query->>'operation_id'
           OR stored.operation_digest IS DISTINCT FROM p_query->>'operation_digest'
        THEN RAISE EXCEPTION 'execution rebuild conflicts with stored state'; END IF;
        RETURN public.gah_builtin_execution_result(stored,true);
    END IF;
    PERFORM public.gah_builtin_execution_assert_authoritative_run_chain(
        p_actor, p_actor->>'session_id'
    );
    SELECT count(*) INTO issuance_count FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND envelope_json#>>'{draft,event_kind}'='execution.authorization_issued'
       AND envelope_json#>>'{draft,inline_payload,operation_id}'=p_query->>'operation_id';
    SELECT count(*) INTO intent_count FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND envelope_json#>>'{draft,event_kind}'='execution.intent'
       AND envelope_json#>>'{draft,inline_payload,operation_id}'=p_query->>'operation_id';
    SELECT count(*) INTO terminal_count FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND envelope_json#>>'{draft,event_kind}'='execution.outcome'
       AND envelope_json#>>'{draft,inline_payload,operation_id}'=p_query->>'operation_id';
    IF issuance_count IS DISTINCT FROM 1 OR intent_count > 1 OR terminal_count > 1
       OR (terminal_count = 1 AND intent_count IS DISTINCT FROM 1)
    THEN RAISE EXCEPTION 'execution rebuild evidence cardinality is invalid'; END IF;
    SELECT envelope_json INTO STRICT issuance FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND envelope_json#>>'{draft,event_kind}'='execution.authorization_issued'
       AND envelope_json#>>'{draft,inline_payload,operation_id}'=p_query->>'operation_id';
    IF issuance#>>'{draft,inline_payload,operation_digest}'
            IS DISTINCT FROM p_query->>'operation_digest'
    THEN RAISE EXCEPTION 'execution rebuild has no exact issuance evidence'; END IF;
    payload := issuance#>'{draft,inline_payload}';
    target_run_id := payload#>>'{command,tool_request,run_id}';
    SELECT envelope_json INTO intent FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND envelope_json#>>'{draft,event_kind}'='execution.intent'
       AND envelope_json#>>'{draft,inline_payload,operation_id}'=p_query->>'operation_id';
    SELECT envelope_json INTO terminal FROM public.gah_evidence_events
     WHERE tenant_id=p_actor->>'tenant_id' AND actor_id=p_actor->>'actor_id'
       AND envelope_json#>>'{draft,event_kind}'='execution.outcome'
       AND envelope_json#>>'{draft,inline_payload,operation_id}'=p_query->>'operation_id';
    rebuilt_state := CASE
        WHEN terminal#>>'{draft,inline_payload,state}' IN ('completed','indeterminate')
            THEN terminal#>>'{draft,inline_payload,state}'
        WHEN intent IS NOT NULL THEN 'executing'
        ELSE 'authorized'
    END;
    IF target_run_id IS DISTINCT FROM p_actor->>'session_id'
       OR EXISTS (
           SELECT 1
             FROM (
                 SELECT sequence_number,event_digest,prior_event_digest,recorded_at,
                        row_number() OVER (ORDER BY sequence_number)-1 AS expected_sequence,
                        lag(event_digest) OVER (ORDER BY sequence_number) AS expected_prior,
                        lag(recorded_at) OVER (ORDER BY sequence_number) AS prior_time
                   FROM public.gah_evidence_events AS events
                  WHERE events.tenant_id=p_actor->>'tenant_id'
                    AND events.actor_id=p_actor->>'actor_id'
                    AND events.run_id=target_run_id
             ) AS chain
            WHERE chain.sequence_number IS DISTINCT FROM chain.expected_sequence
               OR chain.prior_event_digest IS DISTINCT FROM chain.expected_prior
               OR (chain.prior_time IS NOT NULL
                   AND chain.recorded_at < chain.prior_time)
       )
    THEN RAISE EXCEPTION 'execution rebuild authoritative run chain is invalid'; END IF;
    PERFORM public.gah_builtin_execution_validate_ledger_envelope(
        p_actor,issuance,'execution.authorization_issued',payload);
    PERFORM public.gah_builtin_execution_validate_authority(
        p_actor,payload->'command',payload->'authorization_grant',issuance,
        false);
    IF issuance->'policy_refs' IS DISTINCT FROM jsonb_build_array(
           jsonb_build_object(
               'record_type','policy_decision',
               'record_id',payload#>>'{command,policy_decision,decision_id}',
               'record_digest',payload#>>'{command,policy_decision,decision_digest}'))
    THEN RAISE EXCEPTION 'execution issuance policy reference is invalid'; END IF;
    IF intent IS NOT NULL THEN
        intent_payload := intent#>'{draft,inline_payload}';
        PERFORM public.gah_builtin_execution_assert_object(
            intent_payload,
            ARRAY['actor_id','operation_id','operation_digest',
                  'authorization_grant_digest','skill_id','revision',
                  'artifact_digest','state'],
            ARRAY['actor_id','operation_id','operation_digest',
                  'authorization_grant_digest','skill_id','revision',
                  'artifact_digest','state'],
            'execution rebuilt intent payload'
        );
        PERFORM public.gah_builtin_execution_validate_ledger_envelope(
            p_actor,intent,'execution.intent',intent_payload);
        IF intent_payload IS DISTINCT FROM jsonb_build_object(
               'actor_id',p_actor->>'actor_id',
               'operation_id',p_query->>'operation_id',
               'operation_digest',p_query->>'operation_digest',
               'authorization_grant_digest',
                   payload->>'authorization_grant_digest',
               'skill_id',payload#>>'{command,skill_id}',
               'revision',(payload#>>'{command,revision}')::integer,
               'artifact_digest',payload#>>'{command,artifact_digest}',
               'state','executing')
           OR intent->'policy_refs' IS DISTINCT FROM issuance->'policy_refs'
           OR (intent->>'sequence_number')::bigint
                <= (issuance->>'sequence_number')::bigint
        THEN RAISE EXCEPTION 'execution rebuilt intent is unbound'; END IF;
    END IF;
    IF terminal IS NOT NULL THEN
        terminal_payload := terminal#>'{draft,inline_payload}';
        PERFORM public.gah_builtin_execution_assert_object(
            terminal_payload,
            ARRAY['actor_id','operation_id','operation_digest',
                  'authorization_grant_digest','outcome_digest','status',
                  'state','outcome'],
            ARRAY['actor_id','operation_id','operation_digest',
                  'authorization_grant_digest','outcome_digest','status',
                  'state','outcome'],
            'execution rebuilt outcome payload'
        );
        PERFORM public.gah_builtin_execution_validate_ledger_envelope(
            p_actor,terminal,'execution.outcome',terminal_payload);
        outcome := terminal_payload->'outcome';
        PERFORM public.gah_builtin_execution_validate_outcome(
            p_actor,payload->'command',payload->'authorization_grant',
            intent,outcome,rebuilt_state);
        IF terminal_payload IS DISTINCT FROM jsonb_build_object(
               'actor_id',p_actor->>'actor_id',
               'operation_id',p_query->>'operation_id',
               'operation_digest',p_query->>'operation_digest',
               'authorization_grant_digest',
                   payload->>'authorization_grant_digest',
               'outcome_digest',outcome->>'outcome_digest',
               'status',outcome->>'status','state',rebuilt_state,'outcome',outcome)
           OR terminal->'policy_refs' IS DISTINCT FROM issuance->'policy_refs'
           OR (terminal->>'sequence_number')::bigint
                <= (intent->>'sequence_number')::bigint
        THEN RAISE EXCEPTION 'execution rebuilt outcome is unbound'; END IF;
    END IF;
    INSERT INTO public.gah_builtin_execution_state (
        tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,request_digest,
        grant_id,grant_digest,skill_id,revision,artifact_digest,command_json,grant_json,
        state,version,issuance_evidence_json,intent_evidence_json,outcome_json,
        outcome_evidence_json,execution_attempt_id,owner_generation,lease_expires_at,
        issued_at,completed_at
    ) VALUES (
        p_actor->>'tenant_id',p_actor->>'actor_id',p_actor->>'session_id',
        p_query->>'operation_id',p_query->>'operation_digest',
        payload#>>'{command,tool_request,request_id}',
        payload#>>'{command,tool_request,request_digest}',
        payload#>>'{authorization_grant,grant_id}',
        payload->>'authorization_grant_digest',payload#>>'{command,skill_id}',
        (payload#>>'{command,revision}')::integer,payload#>>'{command,artifact_digest}',
        payload->'command',payload->'authorization_grant',rebuilt_state,
        CASE rebuilt_state WHEN 'authorized' THEN 1 WHEN 'executing' THEN 2 ELSE 3 END,
        issuance,intent,
        outcome,
        terminal,
        CASE WHEN intent IS NULL THEN NULL ELSE intent->>'envelope_id' END,
        CASE WHEN intent IS NULL THEN NULL ELSE
            CASE WHEN rebuilt_state='indeterminate' THEN 2 ELSE 1 END END,
        CASE WHEN intent IS NULL THEN NULL ELSE clock_timestamp()-interval '1 second' END,
        (payload#>>'{authorization_grant,issued_at}')::timestamptz,
        CASE WHEN terminal IS NULL THEN NULL ELSE
            (terminal->>'recorded_at')::timestamptz END
    ) RETURNING * INTO stored;
    RETURN public.gah_builtin_execution_result(stored,true);
END
$function$;

ALTER FUNCTION gah_builtin_execution_result(gah_builtin_execution_state,boolean)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_terminal_result(gah_builtin_execution_state,boolean)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_commit_evidence(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_assert_object(jsonb,text[],text[],text)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_assert_field_types(
    jsonb,text[],text[],text[],text) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_assert_actor(jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_evidence_head(jsonb,text) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_commit_evidence(jsonb,jsonb,text,jsonb)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_writer_lock_keys(jsonb,jsonb)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_authorize_builtin_execution(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_assert_writer_authorization(
    jsonb,jsonb,jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_lookup_builtin_execution_authorization(jsonb,jsonb)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_validate_authority(
    jsonb,jsonb,jsonb,jsonb,boolean) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_validate_ledger_envelope(
    jsonb,jsonb,text,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_validate_outcome(
    jsonb,jsonb,jsonb,jsonb,jsonb,text) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_issue_builtin_execution_authorization(
    jsonb,jsonb,jsonb,jsonb,jsonb)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_lookup_builtin_execution(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_begin_builtin_execution(jsonb,jsonb,jsonb,double precision)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_builtin_execution_assert_authoritative_run_chain(jsonb,text)
    OWNER TO gah_schema_owner;
ALTER FUNCTION gah_rebuild_builtin_execution(jsonb,jsonb) OWNER TO gah_schema_owner;

REVOKE ALL ON FUNCTION gah_builtin_execution_result(gah_builtin_execution_state,boolean)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_builtin_execution_terminal_result(
    gah_builtin_execution_state,boolean)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_builtin_execution_assert_object(jsonb,text[],text[],text),
    gah_builtin_execution_assert_field_types(jsonb,text[],text[],text[],text),
    gah_builtin_execution_assert_actor(jsonb),
    gah_builtin_execution_writer_lock_keys(jsonb,jsonb),
    gah_builtin_execution_assert_writer_authorization(jsonb,jsonb,jsonb,jsonb),
    gah_builtin_execution_validate_authority(jsonb,jsonb,jsonb,jsonb,boolean),
    gah_builtin_execution_validate_ledger_envelope(jsonb,jsonb,text,jsonb),
    gah_builtin_execution_validate_outcome(jsonb,jsonb,jsonb,jsonb,jsonb,text),
    gah_builtin_execution_assert_authoritative_run_chain(jsonb,text)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_builtin_execution_commit_evidence(jsonb,jsonb,text,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_builtin_execution_evidence_head(jsonb,text),
    gah_lookup_builtin_execution_authorization(jsonb,jsonb),
    gah_authorize_builtin_execution(jsonb,jsonb),
    gah_issue_builtin_execution_authorization(jsonb,jsonb,jsonb,jsonb,jsonb),
    gah_rebuild_builtin_execution(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_lookup_builtin_execution(jsonb,jsonb)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_begin_builtin_execution(jsonb,jsonb,jsonb,double precision)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
REVOKE ALL ON FUNCTION gah_commit_evidence(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;

GRANT EXECUTE ON FUNCTION gah_builtin_execution_evidence_head(jsonb,text)
    TO gah_runtime, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_lookup_builtin_execution_authorization(jsonb,jsonb)
    TO gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_authorize_builtin_execution(jsonb,jsonb)
    TO gah_authority_writer;
GRANT EXECUTE ON FUNCTION gah_issue_builtin_execution_authorization(
    jsonb,jsonb,jsonb,jsonb,jsonb) TO gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_lookup_builtin_execution(jsonb,jsonb) TO gah_runtime;
GRANT EXECUTE ON FUNCTION gah_begin_builtin_execution(jsonb,jsonb,jsonb,double precision)
    TO gah_runtime;
GRANT EXECUTE ON FUNCTION gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    TO gah_runtime;
GRANT EXECUTE ON FUNCTION gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    TO gah_runtime;
GRANT EXECUTE ON FUNCTION gah_rebuild_builtin_execution(jsonb,jsonb)
    TO gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_commit_evidence(jsonb,jsonb) TO gah_authority_writer;
GRANT USAGE ON SCHEMA public TO gah_execution_admission_authority;
