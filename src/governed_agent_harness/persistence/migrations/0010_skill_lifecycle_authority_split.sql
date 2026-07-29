-- Phase 4.4 authority hardening: a lifecycle credential may commit only the
-- exact evidence envelope bound to its lifecycle transition.  It is not a
-- generic evidence writer.
DO $roles$
DECLARE
    role_record record;
BEGIN
    -- Repair the former installer shape, where a lifecycle login was a member
    -- of both authority groups.  A remaining indirect overlap is unsafe and
    -- requires an explicit credential split before this migration can apply.
    FOR role_record IN
        SELECT member_role.rolname
          FROM pg_auth_members AS writer_membership
          JOIN pg_auth_members AS lifecycle_membership
            ON lifecycle_membership.member = writer_membership.member
          JOIN pg_roles AS member_role ON member_role.oid = writer_membership.member
         WHERE writer_membership.roleid = (
                   SELECT oid FROM pg_roles WHERE rolname = 'gah_authority_writer'
               )
           AND lifecycle_membership.roleid = (
                   SELECT oid FROM pg_roles WHERE rolname = 'gah_skill_lifecycle_authority'
               )
    LOOP
        EXECUTE format('REVOKE gah_authority_writer FROM %I', role_record.rolname);
    END LOOP;

    IF EXISTS (
        SELECT 1
         FROM pg_roles AS login_role
         WHERE login_role.rolcanlogin
           AND NOT login_role.rolsuper
           AND pg_has_role(login_role.oid, 'gah_authority_writer', 'MEMBER')
           AND pg_has_role(login_role.oid, 'gah_skill_lifecycle_authority', 'MEMBER')
    ) THEN
        RAISE EXCEPTION 'lifecycle and generic evidence authority credentials must be distinct';
    END IF;
END
$roles$;

-- PostgreSQL has no built-in SHA-256 function.  pgcrypto is required here to
-- re-check the RFC 8785 subset digests that the Python contract validator
-- emits, preventing a direct lifecycle SQL caller from substituting merely
-- self-consistent JSON.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE FUNCTION gah_utf16be_sort_key(p_value text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $function$
DECLARE
    v_position integer;
    v_codepoint integer;
    v_utf8 bytea;
    v_first integer;
    v_units text := '';
BEGIN
    FOR v_position IN 1..char_length(p_value) LOOP
        v_utf8 := convert_to(substr(p_value, v_position, 1), 'UTF8');
        v_first := get_byte(v_utf8, 0);
        IF v_first < 128 THEN
            v_codepoint := v_first;
        ELSIF v_first < 224 THEN
            v_codepoint := ((v_first & 31) << 6) + (get_byte(v_utf8, 1) & 63);
        ELSIF v_first < 240 THEN
            v_codepoint := ((v_first & 15) << 12) + ((get_byte(v_utf8, 1) & 63) << 6)
                + (get_byte(v_utf8, 2) & 63);
        ELSE
            v_codepoint := ((v_first & 7) << 18) + ((get_byte(v_utf8, 1) & 63) << 12)
                + ((get_byte(v_utf8, 2) & 63) << 6) + (get_byte(v_utf8, 3) & 63);
        END IF;
        IF v_codepoint = 65533 OR v_codepoint BETWEEN 55296 AND 57343 THEN
            RAISE EXCEPTION 'canonical JSON object key contains a forbidden Unicode codepoint';
        ELSIF v_codepoint <= 65535 THEN
            v_units := v_units || lpad(to_hex(v_codepoint), 4, '0');
        ELSE
            v_codepoint := v_codepoint - 65536;
            v_units := v_units || lpad(to_hex(55296 + (v_codepoint >> 10)), 4, '0');
            v_units := v_units || lpad(to_hex(56320 + (v_codepoint & 1023)), 4, '0');
        END IF;
    END LOOP;
    RETURN decode(v_units, 'hex');
END $function$;

CREATE FUNCTION gah_canonical_json(p_value jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $function$
DECLARE
    v_type text := jsonb_typeof(p_value);
    v_result text;
BEGIN
    IF v_type = 'null' THEN
        RETURN 'null';
    ELSIF v_type = 'boolean' THEN
        RETURN p_value::text;
    ELSIF v_type = 'number' THEN
        IF p_value #>> '{}' !~ '^-?(0|[1-9][0-9]*)$'
           OR abs((p_value #>> '{}')::numeric) > 9007199254740991 THEN
            RAISE EXCEPTION 'canonical JSON number is not a safe integer';
        END IF;
        RETURN p_value::text;
    ELSIF v_type = 'string' THEN
        IF position(chr(65533) IN (p_value #>> '{}')) > 0 THEN
            RAISE EXCEPTION 'canonical JSON string contains replacement character';
        END IF;
        RETURN to_json(p_value #>> '{}')::text;
    ELSIF v_type = 'array' THEN
        SELECT '[' || coalesce(string_agg(public.gah_canonical_json(value), ',' ORDER BY ordinal), '') || ']'
          INTO v_result
          FROM jsonb_array_elements(p_value) WITH ORDINALITY AS elements(value, ordinal);
        RETURN v_result;
    ELSIF v_type = 'object' THEN
        SELECT '{' || coalesce(
                   string_agg(pg_catalog.to_json(key)::text || ':' || public.gah_canonical_json(value), ','
                       ORDER BY public.gah_utf16be_sort_key(key)),
                   ''
               ) || '}'
          INTO v_result
          FROM jsonb_each(p_value);
        IF EXISTS (
            SELECT 1 FROM jsonb_object_keys(p_value) AS keys(key)
             WHERE position(chr(65533) IN key) > 0
        ) THEN
            RAISE EXCEPTION 'canonical JSON object key contains replacement character';
        END IF;
        RETURN v_result;
    END IF;
    RAISE EXCEPTION 'unsupported canonical JSON value';
END $function$;

CREATE FUNCTION gah_canonical_sha256(p_value jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, public AS
    'SELECT ''sha256:'' || pg_catalog.encode(public.digest(pg_catalog.convert_to(public.gah_canonical_json($1), ''UTF8''), ''sha256''), ''hex'')';

-- Preserve the prior complete validation body behind a private helper.  The
-- new public entrypoint commits the command-bound evidence before invoking it,
-- so a transition cannot exist without that exact ledger event.
ALTER FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    RENAME TO gah_apply_skill_lifecycle_validated;
ALTER FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    RENAME TO gah_rebuild_skill_projection_validated;

CREATE FUNCTION gah_skill_lifecycle_evidence_head(p_actor jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_run_id text := p_actor ->> 'session_id';
    v_head record;
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF nullif(v_run_id, '') IS NULL THEN
        RAISE EXCEPTION 'skill lifecycle actor session is required';
    END IF;
    SELECT next_sequence, last_event_digest, last_recorded_at, version INTO v_head
      FROM public.gah_run_heads
     WHERE tenant_id = p_actor ->> 'tenant_id'
       AND actor_id = p_actor ->> 'actor_id'
       AND run_id = v_run_id;
    RETURN jsonb_build_object(
        'next_sequence', coalesce(v_head.next_sequence, 0),
        'last_event_digest', v_head.last_event_digest,
        'last_recorded_at', v_head.last_recorded_at,
        'version', coalesce(v_head.version, 0)
    );
END $function$;

CREATE FUNCTION gah_skill_authorization_lock_keys(p_actor jsonb, p_command jsonb)
RETURNS TABLE (lock_a integer, lock_b integer, lock_c integer, lock_d integer)
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, public AS
    'WITH commitment AS (
         SELECT public.digest(pg_catalog.convert_to(public.gah_canonical_json(
             jsonb_build_object(
                 ''tenant_id'', $1->>''tenant_id'', ''actor_id'', $1->>''actor_id'',
                 ''session_id'', $1->>''session_id'', ''operation_id'', $2->>''operation_id'',
                 ''operation_digest'', $2->>''operation_digest'',
                 ''expected_transition_sequence'', $2->>''expected_transition_sequence'',
                 ''expected_lifecycle_state'', $2->>''expected_lifecycle_state''
             )), ''UTF8''), ''sha256'') AS value
     ), halves AS (
         SELECT ((get_byte(value, 0)::bigint << 24) + (get_byte(value, 1)::bigint << 16)
                   + (get_byte(value, 2)::bigint << 8) + get_byte(value, 3)::bigint) AS first_half,
                ((get_byte(value, 4)::bigint << 24) + (get_byte(value, 5)::bigint << 16)
                   + (get_byte(value, 6)::bigint << 8) + get_byte(value, 7)::bigint) AS second_half,
                ((get_byte(value, 8)::bigint << 24) + (get_byte(value, 9)::bigint << 16)
                   + (get_byte(value, 10)::bigint << 8) + get_byte(value, 11)::bigint) AS third_half,
                ((get_byte(value, 12)::bigint << 24) + (get_byte(value, 13)::bigint << 16)
                   + (get_byte(value, 14)::bigint << 8) + get_byte(value, 15)::bigint) AS fourth_half
           FROM commitment
     )
     SELECT CASE WHEN first_half > 2147483647 THEN (first_half - 4294967296)::integer ELSE first_half::integer END,
            CASE WHEN second_half > 2147483647 THEN (second_half - 4294967296)::integer ELSE second_half::integer END,
            CASE WHEN third_half > 2147483647 THEN (third_half - 4294967296)::integer ELSE third_half::integer END,
            CASE WHEN fourth_half > 2147483647 THEN (fourth_half - 4294967296)::integer ELSE fourth_half::integer END
       FROM halves';

CREATE FUNCTION gah_skill_authorization_ordered_locks(p_actor jsonb, p_command jsonb)
RETURNS TABLE (first_a integer, first_b integer, second_a integer, second_b integer)
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, public AS
    'SELECT CASE WHEN (lock_a, lock_b) <= (lock_c, lock_d) THEN lock_a ELSE lock_c END,
            CASE WHEN (lock_a, lock_b) <= (lock_c, lock_d) THEN lock_b ELSE lock_d END,
            CASE WHEN (lock_a, lock_b) <= (lock_c, lock_d) THEN lock_c ELSE lock_a END,
            CASE WHEN (lock_a, lock_b) <= (lock_c, lock_d) THEN lock_d ELSE lock_b END
       FROM public.gah_skill_authorization_lock_keys($1, $2)';

CREATE FUNCTION gah_authorize_skill_lifecycle(p_actor jsonb, p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_lock_a integer;
    v_lock_b integer;
    v_lock_c integer;
    v_lock_d integer;
    v_run_id text := p_actor ->> 'session_id';
    v_sequence integer;
    v_state text;
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF p_command ->> 'operation_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_command - 'operation_digest') THEN
        RAISE EXCEPTION 'skill lifecycle writer authorization binding is invalid';
    END IF;
    SELECT coalesce(transition_sequence, 0), to_state
      INTO v_sequence, v_state
      FROM public.gah_skill_lifecycle_transitions
     WHERE tenant_id = p_actor->>'tenant_id'
       AND skill_id = p_command #>> '{skill_proposal,artifact_id}'
     ORDER BY transition_sequence DESC
     LIMIT 1;
    v_sequence := coalesce(v_sequence, 0);
    v_state := coalesce(v_state, 'none');
    SELECT first_a, first_b, second_a, second_b INTO v_lock_a, v_lock_b, v_lock_c, v_lock_d
      FROM public.gah_skill_authorization_ordered_locks(
          p_actor,
          p_command || jsonb_build_object(
              'expected_transition_sequence', v_sequence,
              'expected_lifecycle_state', v_state
          )
      );
    -- Every writer takes the two SHA-256 lock pairs in one global tuple order.
    PERFORM pg_catalog.pg_advisory_xact_lock(v_lock_a, v_lock_b);
    PERFORM pg_catalog.pg_advisory_xact_lock(v_lock_c, v_lock_d);
    RETURN jsonb_build_object(
        'writer_pid', pg_catalog.pg_backend_pid(),
        'tenant_id', p_actor->>'tenant_id', 'actor_id', p_actor->>'actor_id',
        'session_id', v_run_id, 'operation_id', p_command->>'operation_id',
        'operation_digest', p_command->>'operation_digest',
        'expected_transition_sequence', v_sequence,
        'expected_lifecycle_state', v_state
    );
END $function$;

CREATE FUNCTION gah_skill_assert_writer_authorization(
    p_actor jsonb, p_command jsonb, p_authorization jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_lock_a integer;
    v_lock_b integer;
    v_lock_c integer;
    v_lock_d integer;
    v_pid integer;
    v_expected_sequence integer;
    v_expected_state text;
    v_current_sequence integer;
    v_current_state text;
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF p_authorization IS NULL OR jsonb_typeof(p_authorization) IS DISTINCT FROM 'object'
       OR coalesce((SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(p_authorization) AS keys(key)), ARRAY[]::text[])
            IS DISTINCT FROM ARRAY['actor_id','expected_lifecycle_state','expected_transition_sequence',
                                   'operation_digest','operation_id','session_id','tenant_id','writer_pid']
       OR jsonb_typeof(p_authorization->'writer_pid') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p_authorization->'expected_transition_sequence') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p_authorization->'expected_lifecycle_state') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p_authorization->'tenant_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p_authorization->'actor_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p_authorization->'session_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p_authorization->'operation_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p_authorization->'operation_digest') IS DISTINCT FROM 'string'
       OR p_authorization->>'tenant_id' IS DISTINCT FROM p_actor->>'tenant_id'
       OR p_authorization->>'actor_id' IS DISTINCT FROM p_actor->>'actor_id'
       OR p_authorization->>'session_id' IS DISTINCT FROM p_actor->>'session_id'
       OR p_authorization->>'operation_id' IS DISTINCT FROM p_command->>'operation_id'
       OR p_authorization->>'operation_digest' IS DISTINCT FROM p_command->>'operation_digest'
       OR p_authorization->>'writer_pid' !~ '^[1-9][0-9]*$'
       OR p_authorization->>'expected_transition_sequence' !~ '^[0-9]+$'
       OR p_authorization->>'expected_lifecycle_state' NOT IN ('none','installed','active','inactive') THEN
        RAISE EXCEPTION 'skill lifecycle writer authorization is invalid';
    END IF;
    v_pid := (p_authorization->>'writer_pid')::integer;
    v_expected_sequence := (p_authorization->>'expected_transition_sequence')::integer;
    v_expected_state := p_authorization->>'expected_lifecycle_state';
    IF v_pid = pg_catalog.pg_backend_pid() THEN
        RAISE EXCEPTION 'skill lifecycle writer authorization must use a distinct session';
    END IF;
    SELECT lock_a, lock_b, lock_c, lock_d INTO v_lock_a, v_lock_b, v_lock_c, v_lock_d
      FROM public.gah_skill_authorization_lock_keys(
          p_actor,
          p_command || jsonb_build_object(
              'expected_transition_sequence', v_expected_sequence,
              'expected_lifecycle_state', v_expected_state
          )
      );
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_locks AS locks
          JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid = locks.pid
          JOIN pg_catalog.pg_roles AS role_record ON role_record.rolname = activity.usename
         WHERE locks.locktype = 'advisory' AND locks.granted AND locks.pid = v_pid
           AND locks.objsubid = 2
           AND locks.classid::bigint = CASE WHEN v_lock_a < 0 THEN v_lock_a::bigint + 4294967296 ELSE v_lock_a::bigint END
           AND locks.objid::bigint = CASE WHEN v_lock_b < 0 THEN v_lock_b::bigint + 4294967296 ELSE v_lock_b::bigint END
           AND pg_catalog.pg_has_role(role_record.oid, 'gah_authority_writer', 'MEMBER')
    ) THEN
        RAISE EXCEPTION 'skill lifecycle writer authorization is not live';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_locks AS locks
          JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid = locks.pid
          JOIN pg_catalog.pg_roles AS role_record ON role_record.rolname = activity.usename
         WHERE locks.locktype = 'advisory' AND locks.granted AND locks.pid = v_pid
           AND locks.objsubid = 2
           AND locks.classid::bigint = CASE WHEN v_lock_c < 0 THEN v_lock_c::bigint + 4294967296 ELSE v_lock_c::bigint END
           AND locks.objid::bigint = CASE WHEN v_lock_d < 0 THEN v_lock_d::bigint + 4294967296 ELSE v_lock_d::bigint END
           AND pg_catalog.pg_has_role(role_record.oid, 'gah_authority_writer', 'MEMBER')
    ) THEN
        RAISE EXCEPTION 'skill lifecycle writer authorization is not live';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill:' || (p_actor->>'tenant_id') || ':' || (p_command #>> '{skill_proposal,artifact_id}'), 0
    ));
    SELECT coalesce(transition_sequence, 0), to_state
      INTO v_current_sequence, v_current_state
      FROM public.gah_skill_lifecycle_transitions
     WHERE tenant_id = p_actor->>'tenant_id'
       AND skill_id = p_command #>> '{skill_proposal,artifact_id}'
     ORDER BY transition_sequence DESC
     LIMIT 1;
    v_current_sequence := coalesce(v_current_sequence, 0);
    v_current_state := coalesce(v_current_state, 'none');
    IF v_expected_sequence IS DISTINCT FROM v_current_sequence
       OR v_expected_state IS DISTINCT FROM v_current_state THEN
        RAISE EXCEPTION 'skill lifecycle authorized state is stale';
    END IF;
END $function$;

CREATE FUNCTION gah_apply_skill_lifecycle(p_actor jsonb, p_command jsonb, p_expected_operation text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_evidence jsonb := p_command -> 'transition_evidence';
    v_head jsonb;
    v_committed jsonb;
    v_existing boolean;
    v_run_id text := p_actor ->> 'session_id';
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF p_command #>> '{gate_decision,decision}' <> 'approve' THEN
        RAISE EXCEPTION 'skill lifecycle gate decision must approve';
    END IF;
    IF p_command ->> 'operation_digest' IS DISTINCT FROM
            public.gah_canonical_sha256((p_command - 'transition_evidence') - 'operation_digest') THEN
        RAISE EXCEPTION 'skill lifecycle command digest binding is invalid';
    END IF;
    IF p_command #>> '{skill_proposal,proposal_digest}' IS DISTINCT FROM
            public.gah_canonical_sha256(((p_command -> 'skill_proposal') - 'proof') - 'proposal_digest')
       OR p_command #>> '{gate_decision,decision_digest}' IS DISTINCT FROM
            public.gah_canonical_sha256(((p_command -> 'gate_decision') - 'proof') - 'decision_digest')
       OR p_command #>> '{delivery_envelope,envelope_digest}' IS DISTINCT FROM
            public.gah_canonical_sha256(((p_command -> 'delivery_envelope') - 'proof') - 'envelope_digest')
       OR p_command #>> '{policy_decision,decision_digest}' IS DISTINCT FROM
            public.gah_canonical_sha256(((p_command -> 'policy_decision') - 'proof') - 'decision_digest')
       OR p_command #>> '{delivery_envelope,artifact_digest}' IS DISTINCT FROM
            public.gah_canonical_sha256(p_command -> 'artifact') THEN
        RAISE EXCEPTION 'skill lifecycle record digest binding is invalid';
    END IF;
    IF (p_command -> 'skill_proposal' ? 'proof'
            AND p_command #>> '{skill_proposal,proof,object_digest}' IS DISTINCT FROM
                public.gah_canonical_sha256(((p_command -> 'skill_proposal') - 'proof') - 'proposal_digest'))
       OR (p_command -> 'gate_decision' ? 'proof'
            AND p_command #>> '{gate_decision,proof,object_digest}' IS DISTINCT FROM
                public.gah_canonical_sha256(((p_command -> 'gate_decision') - 'proof') - 'decision_digest'))
       OR (p_command -> 'delivery_envelope' ? 'proof'
            AND p_command #>> '{delivery_envelope,proof,object_digest}' IS DISTINCT FROM
                public.gah_canonical_sha256(((p_command -> 'delivery_envelope') - 'proof') - 'envelope_digest'))
       OR (p_command -> 'policy_decision' ? 'proof'
            AND p_command #>> '{policy_decision,proof,object_digest}' IS DISTINCT FROM
                public.gah_canonical_sha256(((p_command -> 'policy_decision') - 'proof') - 'decision_digest'))
       OR EXISTS (
            SELECT 1 FROM jsonb_array_elements(p_command -> 'approvals') AS approval
             WHERE approval ->> 'approval_digest' IS DISTINCT FROM
                       public.gah_canonical_sha256((approval - 'proof') - 'approval_digest')
                OR (approval ? 'proof' AND approval #>> '{proof,object_digest}' IS DISTINCT FROM
                       public.gah_canonical_sha256((approval - 'proof') - 'approval_digest'))
       )
       OR (jsonb_typeof(p_command -> 'activation_receipt') = 'object' AND (
            p_command #>> '{activation_receipt,receipt_digest}' IS DISTINCT FROM
                public.gah_canonical_sha256(((p_command -> 'activation_receipt') - 'proof') - 'receipt_digest')
            OR (p_command -> 'activation_receipt' ? 'proof'
                AND p_command #>> '{activation_receipt,proof,object_digest}' IS DISTINCT FROM
                    public.gah_canonical_sha256(((p_command -> 'activation_receipt') - 'proof') - 'receipt_digest')
       )))
       OR (jsonb_typeof(p_command -> 'rollback_receipt') = 'object' AND (
            p_command #>> '{rollback_receipt,receipt_digest}' IS DISTINCT FROM
                public.gah_canonical_sha256(((p_command -> 'rollback_receipt') - 'proof') - 'receipt_digest')
            OR (p_command -> 'rollback_receipt' ? 'proof'
                AND p_command #>> '{rollback_receipt,proof,object_digest}' IS DISTINCT FROM
                    public.gah_canonical_sha256(((p_command -> 'rollback_receipt') - 'proof') - 'receipt_digest')
       ))) THEN
        RAISE EXCEPTION 'skill lifecycle record digest binding is invalid';
    END IF;
    IF v_evidence IS NULL OR nullif(v_run_id, '') IS NULL
       OR v_evidence #>> '{draft,run_id}' <> v_run_id THEN
        RAISE EXCEPTION 'skill lifecycle transition evidence is invalid';
    END IF;
    IF v_evidence ->> 'draft_digest' IS DISTINCT FROM public.gah_canonical_sha256(v_evidence -> 'draft')
       OR v_evidence ->> 'payload_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(v_evidence #> '{draft,inline_payload}')
       OR v_evidence #>> '{draft,idempotency,operation_digest}' IS DISTINCT FROM
            public.gah_canonical_sha256(v_evidence #> '{draft,inline_payload}')
       OR v_evidence ->> 'event_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(v_evidence - 'event_digest') THEN
        RAISE EXCEPTION 'skill lifecycle transition evidence digest binding is invalid';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM public.gah_skill_lifecycle_transitions
         WHERE tenant_id = p_actor ->> 'tenant_id'
           AND operation_id = p_command ->> 'operation_id'
    ) INTO v_existing;
    IF v_existing THEN
        RETURN public.gah_lookup_skill_replay(p_actor, p_command - 'transition_evidence');
    END IF;

    PERFORM public.gah_skill_assert_writer_authorization(
        p_actor, p_command - 'transition_evidence',
        v_evidence #> '{draft,inline_payload,writer_authorization}'
    );

    v_head := public.gah_authority_write_internal(
        'lock_run', p_actor, jsonb_build_object('run_id', v_run_id)
    );
    IF v_evidence -> 'sequence_number' IS DISTINCT FROM v_head -> 'next_sequence'
       OR v_evidence -> 'prior_event_digest' IS DISTINCT FROM v_head -> 'last_event_digest'
       OR v_evidence -> 'recorded_at' IS NULL
       OR v_evidence ->> 'event_digest' !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'skill lifecycle evidence head is stale or malformed';
    END IF;
    v_committed := public.gah_authority_write_internal(
        'commit_evidence', p_actor,
        jsonb_build_object(
            'run_id', v_run_id,
            'expected_version', v_head -> 'version',
            'envelope', v_evidence
        )
    );
    IF (v_committed ->> 'changed')::integer <> 1 THEN
        RAISE EXCEPTION 'skill lifecycle evidence sequence lost its race';
    END IF;
    RETURN public.gah_apply_skill_lifecycle_validated(p_actor, p_command, p_expected_operation);
END $function$;

CREATE FUNCTION gah_rebuild_skill_projection(p_actor jsonb, p_command jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    PERFORM gah_skill_assert_actor(p_actor);
    IF p_command ->> 'operation_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_command - 'operation_digest') THEN
        RAISE EXCEPTION 'skill projection rebuild command digest binding is invalid';
    END IF;
    RETURN public.gah_rebuild_skill_projection_validated(p_actor, p_command);
END $function$;

CREATE OR REPLACE FUNCTION gah_install_skill(jsonb,jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''install'')';
CREATE OR REPLACE FUNCTION gah_activate_skill(jsonb,jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''activate'')';
CREATE OR REPLACE FUNCTION gah_rollback_skill(jsonb,jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''rollback'')';
CREATE OR REPLACE FUNCTION gah_deactivate_skill(jsonb,jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS 'SELECT public.gah_apply_skill_lifecycle($1,$2,''deactivate'')';

ALTER FUNCTION gah_apply_skill_lifecycle_validated(jsonb,jsonb,text) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_rebuild_skill_projection_validated(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_rebuild_skill_projection(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_skill_lifecycle_evidence_head(jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_skill_authorization_lock_keys(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_skill_authorization_ordered_locks(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_authorize_skill_lifecycle(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_skill_assert_writer_authorization(jsonb,jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_utf16be_sort_key(text) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_canonical_json(jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_canonical_sha256(jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_install_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_activate_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_rollback_skill(jsonb,jsonb) OWNER TO gah_schema_owner;
ALTER FUNCTION gah_deactivate_skill(jsonb,jsonb) OWNER TO gah_schema_owner;

REVOKE ALL ON FUNCTION gah_apply_skill_lifecycle_validated(jsonb,jsonb,text),
    gah_apply_skill_lifecycle(jsonb,jsonb,text),
    gah_rebuild_skill_projection_validated(jsonb,jsonb),
    gah_skill_lifecycle_evidence_head(jsonb),
    gah_skill_authorization_lock_keys(jsonb,jsonb),
    gah_skill_authorization_ordered_locks(jsonb,jsonb),
    gah_authorize_skill_lifecycle(jsonb,jsonb),
    gah_skill_assert_writer_authorization(jsonb,jsonb,jsonb),
    gah_utf16be_sort_key(text),
    gah_canonical_json(jsonb), gah_canonical_sha256(jsonb),
    gah_lookup_skill_replay(jsonb,jsonb),
    gah_install_skill(jsonb,jsonb), gah_activate_skill(jsonb,jsonb),
    gah_rollback_skill(jsonb,jsonb), gah_deactivate_skill(jsonb,jsonb),
    gah_rebuild_skill_projection(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer, gah_skill_lifecycle_authority;
GRANT EXECUTE ON FUNCTION gah_skill_lifecycle_evidence_head(jsonb),
    gah_lookup_skill_replay(jsonb,jsonb),
    gah_install_skill(jsonb,jsonb), gah_activate_skill(jsonb,jsonb),
    gah_rollback_skill(jsonb,jsonb), gah_deactivate_skill(jsonb,jsonb),
    gah_rebuild_skill_projection(jsonb,jsonb)
    TO gah_skill_lifecycle_authority;
GRANT EXECUTE ON FUNCTION gah_authorize_skill_lifecycle(jsonb,jsonb) TO gah_authority_writer;
