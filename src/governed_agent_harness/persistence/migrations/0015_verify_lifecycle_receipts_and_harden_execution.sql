-- Re-attest legacy lifecycle receipts against current database trust during
-- upgrade, then verify them historically during rebuild.  The migration does
-- not claim to recover a pre-0015 database acceptance timestamp.

CREATE FUNCTION gah_assert_lifecycle_receipt_binding(
    p_command jsonb, p_operation text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    activation jsonb := p_command->'activation_receipt';
    rollback jsonb := p_command->'rollback_receipt';
    delivery jsonb := p_command->'delivery_envelope';
    proposal jsonb := p_command->'skill_proposal';
    policy jsonb := p_command->'policy_decision';
    policy_ref jsonb;
    proposal_ref jsonb;
BEGIN
    IF p_operation NOT IN ('activate','rollback') THEN
        RETURN;
    END IF;
    IF pg_catalog.jsonb_typeof(proposal) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(delivery) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_command->'artifact') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(proposal->'tenant_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(proposal->'target_scope') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(proposal->'artifact_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(proposal->'artifact_revision')
            IS DISTINCT FROM 'number'
       OR pg_catalog.jsonb_typeof(proposal->'artifact') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(delivery->'tenant_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(delivery->'target_scope') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(delivery->'artifact_type') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(delivery->'artifact_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(delivery->'artifact_revision')
            IS DISTINCT FROM 'number'
       OR pg_catalog.jsonb_typeof(delivery->'artifact_digest') IS DISTINCT FROM 'string'
       OR delivery->>'tenant_id' IS DISTINCT FROM proposal->>'tenant_id'
       OR delivery->'target_scope' IS DISTINCT FROM proposal->'target_scope'
       OR delivery#>>'{target_scope,tenant_id}'
            IS DISTINCT FROM proposal->>'tenant_id'
       OR pg_catalog.jsonb_typeof(delivery#>'{target_scope,actor_id}')
            IS DISTINCT FROM 'string'
       OR delivery->>'artifact_type' IS DISTINCT FROM 'skill'
       OR delivery->>'artifact_id' IS DISTINCT FROM proposal->>'artifact_id'
       OR delivery->'artifact_revision' IS DISTINCT FROM proposal->'artifact_revision'
       OR proposal->'artifact' IS DISTINCT FROM p_command->'artifact'
       OR delivery->>'artifact_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_command->'artifact')
    THEN
        RAISE EXCEPTION 'lifecycle proposal and delivery composition is invalid';
    END IF;
    IF pg_catalog.jsonb_typeof(activation) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(activation->'tenant_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'receipt_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'target_scope') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(activation->'delivery_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'delivery_digest') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'artifact_type') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'artifact_id') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'artifact_revision')
            IS DISTINCT FROM 'number'
       OR pg_catalog.jsonb_typeof(activation->'artifact_digest') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'activated_revision')
            IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(activation->'evidence_refs') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(activation->'policy_refs') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(activation->'reviewer_refs') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_typeof(activation->'issued_at') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(activation->'expires_at') IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(activation->>'issued_at') = ''
       OR pg_catalog.btrim(activation->>'expires_at') = ''
    THEN
        RAISE EXCEPTION 'activation receipt binding shape is invalid';
    END IF;
    IF p_operation = 'rollback'
       AND (
           pg_catalog.jsonb_typeof(rollback) IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(rollback->'tenant_id') IS DISTINCT FROM 'string'
           OR pg_catalog.jsonb_typeof(rollback->'target_scope') IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(rollback->'activation_receipt_ref')
                IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(rollback->'artifact_type') IS DISTINCT FROM 'string'
           OR pg_catalog.jsonb_typeof(rollback->'artifact_id') IS DISTINCT FROM 'string'
           OR pg_catalog.jsonb_typeof(rollback->'artifact_revision')
                IS DISTINCT FROM 'number'
           OR pg_catalog.jsonb_typeof(rollback->'artifact_digest') IS DISTINCT FROM 'string'
           OR pg_catalog.jsonb_typeof(rollback->'restored_revision_ref')
                IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(rollback->'evidence_refs') IS DISTINCT FROM 'array'
           OR pg_catalog.jsonb_typeof(rollback->'policy_refs') IS DISTINCT FROM 'array'
           OR pg_catalog.jsonb_typeof(rollback->'reviewer_refs') IS DISTINCT FROM 'array'
           OR pg_catalog.jsonb_typeof(rollback->'issued_at') IS DISTINCT FROM 'string'
           OR pg_catalog.jsonb_typeof(rollback->'expires_at') IS DISTINCT FROM 'string'
           OR pg_catalog.btrim(rollback->>'issued_at') = ''
           OR pg_catalog.btrim(rollback->>'expires_at') = ''
       )
    THEN
        RAISE EXCEPTION 'rollback receipt binding shape is invalid';
    END IF;
    policy_ref := pg_catalog.jsonb_build_object(
        'record_type','policy_decision',
        'record_id',policy->>'decision_id',
        'record_digest',policy->>'decision_digest'
    );
    proposal_ref := pg_catalog.jsonb_build_object(
        'record_type','skill_proposal',
        'record_id',proposal->>'artifact_id',
        'record_digest',delivery->>'artifact_digest'
    );
    IF activation->>'tenant_id' IS DISTINCT FROM proposal->>'tenant_id'
       OR activation->'target_scope' IS DISTINCT FROM delivery->'target_scope'
       OR activation->>'delivery_id' IS DISTINCT FROM delivery->>'delivery_id'
       OR activation->>'delivery_digest' IS DISTINCT FROM delivery->>'envelope_digest'
       OR activation->>'artifact_type' IS DISTINCT FROM delivery->>'artifact_type'
       OR activation->>'artifact_id' IS DISTINCT FROM delivery->>'artifact_id'
       OR activation->'artifact_revision' IS DISTINCT FROM delivery->'artifact_revision'
       OR activation->>'artifact_digest' IS DISTINCT FROM delivery->>'artifact_digest'
       OR delivery->>'lifecycle_state' IS DISTINCT FROM 'delivered'
       OR (activation->>'issued_at')::timestamptz
            < (delivery->>'issued_at')::timestamptz
       OR (activation->>'issued_at')::timestamptz
            > (delivery->>'expires_at')::timestamptz
       OR activation->'evidence_refs' IS DISTINCT FROM delivery->'evidence_refs'
       OR activation->'policy_refs'
            IS DISTINCT FROM pg_catalog.jsonb_build_array(policy_ref)
       OR activation->'reviewer_refs' IS DISTINCT FROM delivery->'reviewer_refs'
       OR activation->'activated_revision' IS DISTINCT FROM proposal_ref
    THEN
        RAISE EXCEPTION 'activation receipt is not bound to its lifecycle command';
    END IF;
    IF p_operation = 'rollback' THEN
        IF rollback->>'tenant_id' IS DISTINCT FROM activation->>'tenant_id'
           OR rollback->'target_scope' IS DISTINCT FROM activation->'target_scope'
           OR rollback->>'artifact_type' IS DISTINCT FROM activation->>'artifact_type'
           OR rollback->>'artifact_id' IS DISTINCT FROM activation->>'artifact_id'
           OR rollback->'artifact_revision'
                IS DISTINCT FROM activation->'artifact_revision'
           OR rollback->>'artifact_digest'
                IS DISTINCT FROM activation->>'artifact_digest'
           OR rollback#>>'{activation_receipt_ref,record_type}'
                IS DISTINCT FROM 'activation_receipt'
           OR rollback#>>'{activation_receipt_ref,record_id}'
                IS DISTINCT FROM activation->>'receipt_id'
           OR rollback#>>'{activation_receipt_ref,record_digest}'
                IS DISTINCT FROM activation->>'receipt_digest'
           OR (rollback->>'issued_at')::timestamptz
                < (activation->>'issued_at')::timestamptz
           OR rollback->'evidence_refs' IS DISTINCT FROM delivery->'evidence_refs'
           OR rollback->'policy_refs'
                IS DISTINCT FROM pg_catalog.jsonb_build_array(policy_ref)
           OR rollback->'reviewer_refs' IS DISTINCT FROM delivery->'reviewer_refs'
           OR rollback->'restored_revision_ref' IS DISTINCT FROM proposal_ref
        THEN
            RAISE EXCEPTION 'rollback receipt is not bound to its lifecycle command';
        END IF;
    END IF;
END
$function$;
ALTER FUNCTION gah_assert_lifecycle_receipt_binding(jsonb,text)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_assert_lifecycle_receipt_binding(jsonb,text)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_verify_persisted_lifecycle_receipts(
    p_command jsonb, p_operation text, p_accepted_at timestamptz,
    p_historical boolean, p_tenant text, p_actor text, p_skill text,
    p_target_revision integer
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_activation jsonb := p_command->'activation_receipt';
    v_rollback jsonb := p_command->'rollback_receipt';
BEGIN
    PERFORM public.gah_assert_lifecycle_receipt_binding(p_command, p_operation);
    IF p_operation = 'activate' THEN
        IF pg_catalog.jsonb_typeof(v_activation) IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(v_rollback) IS DISTINCT FROM 'null'
           OR v_activation->>'record_type' IS DISTINCT FROM 'activation_receipt'
           OR v_activation->>'issuer_role' IS DISTINCT FROM 'runtime_authority'
           OR pg_catalog.jsonb_typeof(v_activation->'proof') IS DISTINCT FROM 'object'
           OR v_activation#>>'{proof,issuer}' IS DISTINCT FROM 'runtime.authority'
           OR v_activation#>>'{proof,key_id}' IS NULL
           OR v_activation#>>'{proof,algorithm}'
                IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
           OR v_activation#>>'{proof,proof_domain}'
                IS DISTINCT FROM 'activation_receipt.v1'
           OR coalesce(v_activation#>>'{proof,nonce}','')
                !~ '^[A-Za-z0-9_-]{22,128}$'
           OR coalesce(v_activation#>>'{proof,detached_proof}','')
                !~ '^[A-Za-z0-9_-]{86}$'
           OR v_activation->>'receipt_digest' IS DISTINCT FROM
                public.gah_canonical_sha256((v_activation-'proof')-'receipt_digest')
        THEN
            RAISE EXCEPTION 'persisted activation receipt is untrusted';
        END IF;
        PERFORM public.gah_verify_execution_signed_record(
            v_activation, 'receipt_digest', p_accepted_at, p_historical
        );
    ELSIF p_operation = 'rollback' THEN
        IF pg_catalog.jsonb_typeof(v_activation) IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(v_rollback) IS DISTINCT FROM 'object'
           OR v_activation->>'record_type' IS DISTINCT FROM 'activation_receipt'
           OR v_rollback->>'record_type' IS DISTINCT FROM 'rollback_receipt'
           OR v_activation->>'issuer_role' IS DISTINCT FROM 'runtime_authority'
           OR v_rollback->>'issuer_role' IS DISTINCT FROM 'runtime_authority'
           OR pg_catalog.jsonb_typeof(v_activation->'proof') IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(v_rollback->'proof') IS DISTINCT FROM 'object'
           OR v_activation#>>'{proof,issuer}' IS DISTINCT FROM 'runtime.authority'
           OR v_rollback#>>'{proof,issuer}' IS DISTINCT FROM 'runtime.authority'
           OR v_activation#>>'{proof,key_id}' IS NULL
           OR v_rollback#>>'{proof,key_id}' IS NULL
           OR v_activation#>>'{proof,algorithm}'
                IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
           OR v_rollback#>>'{proof,algorithm}'
                IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
           OR v_activation#>>'{proof,proof_domain}'
                IS DISTINCT FROM 'activation_receipt.v1'
           OR v_rollback#>>'{proof,proof_domain}'
                IS DISTINCT FROM 'rollback_receipt.v1'
           OR coalesce(v_activation#>>'{proof,nonce}','')
                !~ '^[A-Za-z0-9_-]{22,128}$'
           OR coalesce(v_rollback#>>'{proof,nonce}','')
                !~ '^[A-Za-z0-9_-]{22,128}$'
           OR coalesce(v_activation#>>'{proof,detached_proof}','')
                !~ '^[A-Za-z0-9_-]{86}$'
           OR coalesce(v_rollback#>>'{proof,detached_proof}','')
                !~ '^[A-Za-z0-9_-]{86}$'
           OR v_activation->>'receipt_digest' IS DISTINCT FROM
                public.gah_canonical_sha256((v_activation-'proof')-'receipt_digest')
           OR v_rollback->>'receipt_digest' IS DISTINCT FROM
                public.gah_canonical_sha256((v_rollback-'proof')-'receipt_digest')
        THEN
            RAISE EXCEPTION 'persisted rollback receipts are untrusted';
        END IF;
        PERFORM public.gah_verify_execution_signed_record(
            v_activation, 'receipt_digest', p_accepted_at, p_historical
        );
        PERFORM public.gah_verify_execution_signed_record(
            v_rollback, 'receipt_digest', p_accepted_at, p_historical
        );
    END IF;
    IF p_historical
       AND public.gah_skill_lifecycle_sink_command_valid(
               p_tenant,
               p_actor,
               p_skill,
               p_target_revision,
               p_command#>>'{delivery_envelope,artifact_digest}',
               p_command
           ) IS NOT TRUE
    THEN
        RAISE EXCEPTION 'persisted lifecycle row and command binding is invalid';
    END IF;
END
$function$;
ALTER FUNCTION gah_verify_persisted_lifecycle_receipts(
    jsonb,text,timestamptz,boolean,text,text,text,integer
)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_verify_persisted_lifecycle_receipts(
    jsonb,text,timestamptz,boolean,text,text,text,integer
)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

-- Freeze both pre-0015 authority journals in this global table order before
-- preflight.  SHARE ROW EXCLUSIVE conflicts with their INSERT/UPDATE writers:
-- a writer either commits before these locks and is scanned, or starts only
-- after this atomic migration installs the hardened public wrappers.
LOCK TABLE public.gah_skill_lifecycle_transitions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.gah_builtin_execution_state IN SHARE ROW EXCLUSIVE MODE;

DO $preflight_persisted_phase51_authority$
DECLARE
    transition_row record;
    execution_row record;
BEGIN
    FOR transition_row IN
        SELECT command_json, operation, tenant_id, actor_id, skill_id,
               target_revision,
               (evidence_json->>'recorded_at')::timestamptz AS recorded_at
          FROM public.gah_skill_lifecycle_transitions
         WHERE operation IN ('activate','rollback')
         ORDER BY tenant_id, actor_id, skill_id, transition_sequence
    LOOP
        PERFORM public.gah_verify_persisted_lifecycle_receipts(
            transition_row.command_json,
            transition_row.operation,
            pg_catalog.transaction_timestamp(),
            false,
            transition_row.tenant_id,
            transition_row.actor_id,
            transition_row.skill_id,
            transition_row.target_revision
        );
        -- Separately establish that the upgraded row is replayable under the
        -- immutable ledger timestamp used by deterministic rebuild.  This is
        -- compatibility proof, not proof of its original DB acceptance time.
        PERFORM public.gah_verify_persisted_lifecycle_receipts(
            transition_row.command_json,
            transition_row.operation,
            transition_row.recorded_at,
            true,
            transition_row.tenant_id,
            transition_row.actor_id,
            transition_row.skill_id,
            transition_row.target_revision
        );
    END LOOP;
    IF EXISTS (
        SELECT 1
          FROM public.gah_builtin_execution_state AS execution_state
         WHERE CASE
            WHEN pg_catalog.jsonb_typeof(
                    execution_state.command_json->'approvals')
                    IS DISTINCT FROM 'array' THEN true
            WHEN pg_catalog.jsonb_array_length(
                    execution_state.command_json->'approvals') <> 1 THEN true
            ELSE pg_catalog.jsonb_typeof(
                    execution_state.command_json#>'{approvals,0}')
                    IS DISTINCT FROM 'object'
                 OR execution_state.command_json#>'{approvals,0}' ? 'revoked_at'
         END
    ) THEN
        RAISE EXCEPTION 'persisted execution approval is revoked or malformed';
    END IF;
    FOR execution_row IN
        SELECT intent_evidence_json, outcome_json
          FROM public.gah_builtin_execution_state
         WHERE state IN ('completed','indeterminate')
         ORDER BY tenant_id, actor_id, operation_id
    LOOP
        IF pg_catalog.jsonb_typeof(execution_row.intent_evidence_json)
                IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(
                execution_row.intent_evidence_json->'recorded_at'
              ) IS DISTINCT FROM 'string'
           OR pg_catalog.jsonb_typeof(execution_row.outcome_json)
                IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(execution_row.outcome_json->'occurred_at')
                IS DISTINCT FROM 'string'
        THEN
            RAISE EXCEPTION 'persisted terminal execution chronology is malformed';
        END IF;
        IF (execution_row.outcome_json->>'occurred_at')::timestamptz
                < (execution_row.intent_evidence_json->>'recorded_at')::timestamptz
        THEN
            RAISE EXCEPTION 'persisted terminal execution predates its intent';
        END IF;
    END LOOP;
END
$preflight_persisted_phase51_authority$;

ALTER FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    RENAME TO gah_apply_skill_lifecycle_digest_validated;
ALTER FUNCTION gah_apply_skill_lifecycle_digest_validated(jsonb,jsonb,text)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_apply_skill_lifecycle_digest_validated(jsonb,jsonb,text)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_apply_skill_lifecycle(
    p_actor jsonb, p_command jsonb, p_expected_operation text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_activation jsonb := p_command->'activation_receipt';
    v_rollback jsonb := p_command->'rollback_receipt';
    v_accepted_at timestamptz := pg_catalog.transaction_timestamp();
BEGIN
    -- Keep actor scope explicit at the sole public apply boundary.  The
    -- private digest-validated body repeats this assertion before mutation.
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF pg_catalog.jsonb_typeof(p_actor->'actor_id') IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(p_actor->>'actor_id') = ''
       OR p_expected_operation NOT IN ('install','activate','rollback','deactivate')
       OR p_command->>'operation' IS DISTINCT FROM p_expected_operation
       OR pg_catalog.jsonb_typeof(p_command#>'{transition_evidence,recorded_at}')
            IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION 'skill lifecycle receipt verification binding is invalid';
    END IF;
    IF p_expected_operation IN ('install','deactivate') THEN
        IF pg_catalog.jsonb_typeof(v_activation) IS DISTINCT FROM 'null'
           OR pg_catalog.jsonb_typeof(v_rollback) IS DISTINCT FROM 'null'
        THEN
            RAISE EXCEPTION 'skill lifecycle operation must not carry runtime receipts';
        END IF;
    ELSIF p_expected_operation = 'activate' THEN
        IF pg_catalog.jsonb_typeof(v_activation) IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(v_rollback) IS DISTINCT FROM 'null'
           OR v_activation->>'record_type' IS DISTINCT FROM 'activation_receipt'
           OR v_activation->>'issuer_role' IS DISTINCT FROM 'runtime_authority'
           OR pg_catalog.jsonb_typeof(v_activation->'proof') IS DISTINCT FROM 'object'
           OR v_activation#>>'{proof,issuer}' IS DISTINCT FROM 'runtime.authority'
           OR v_activation#>>'{proof,key_id}' IS NULL
           OR v_activation#>>'{proof,algorithm}'
                IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
           OR v_activation#>>'{proof,proof_domain}'
                IS DISTINCT FROM 'activation_receipt.v1'
           OR coalesce(v_activation#>>'{proof,nonce}','')
                !~ '^[A-Za-z0-9_-]{22,128}$'
           OR coalesce(v_activation#>>'{proof,detached_proof}','')
                !~ '^[A-Za-z0-9_-]{86}$'
           OR v_activation->>'receipt_digest' IS DISTINCT FROM
                public.gah_canonical_sha256(
                    (v_activation-'proof')-'receipt_digest')
        THEN
            RAISE EXCEPTION 'activation receipt is missing or untrusted';
        END IF;
        PERFORM public.gah_assert_lifecycle_receipt_binding(
            p_command, p_expected_operation
        );
        PERFORM public.gah_verify_execution_signed_record(
            v_activation, 'receipt_digest', v_accepted_at, false
        );
        PERFORM public.gah_verify_execution_signed_record(
            v_activation,
            'receipt_digest',
            (p_command#>>'{transition_evidence,recorded_at}')::timestamptz,
            true
        );
    ELSE
        IF pg_catalog.jsonb_typeof(v_activation) IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(v_rollback) IS DISTINCT FROM 'object'
           OR v_activation->>'record_type' IS DISTINCT FROM 'activation_receipt'
           OR v_rollback->>'record_type' IS DISTINCT FROM 'rollback_receipt'
           OR v_activation->>'issuer_role' IS DISTINCT FROM 'runtime_authority'
           OR v_rollback->>'issuer_role' IS DISTINCT FROM 'runtime_authority'
           OR pg_catalog.jsonb_typeof(v_activation->'proof') IS DISTINCT FROM 'object'
           OR pg_catalog.jsonb_typeof(v_rollback->'proof') IS DISTINCT FROM 'object'
           OR v_activation#>>'{proof,issuer}' IS DISTINCT FROM 'runtime.authority'
           OR v_rollback#>>'{proof,issuer}' IS DISTINCT FROM 'runtime.authority'
           OR v_activation#>>'{proof,key_id}' IS NULL
           OR v_rollback#>>'{proof,key_id}' IS NULL
           OR v_activation#>>'{proof,algorithm}'
                IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
           OR v_rollback#>>'{proof,algorithm}'
                IS DISTINCT FROM 'ed25519-rfc8032-gah-cjson-v1'
           OR v_activation#>>'{proof,proof_domain}'
                IS DISTINCT FROM 'activation_receipt.v1'
           OR v_rollback#>>'{proof,proof_domain}'
                IS DISTINCT FROM 'rollback_receipt.v1'
           OR coalesce(v_activation#>>'{proof,nonce}','')
                !~ '^[A-Za-z0-9_-]{22,128}$'
           OR coalesce(v_rollback#>>'{proof,nonce}','')
                !~ '^[A-Za-z0-9_-]{22,128}$'
           OR coalesce(v_activation#>>'{proof,detached_proof}','')
                !~ '^[A-Za-z0-9_-]{86}$'
           OR coalesce(v_rollback#>>'{proof,detached_proof}','')
                !~ '^[A-Za-z0-9_-]{86}$'
           OR v_activation->>'receipt_digest' IS DISTINCT FROM
                public.gah_canonical_sha256(
                    (v_activation-'proof')-'receipt_digest')
           OR v_rollback->>'receipt_digest' IS DISTINCT FROM
                public.gah_canonical_sha256(
                    (v_rollback-'proof')-'receipt_digest')
        THEN
            RAISE EXCEPTION 'rollback receipts are missing or untrusted';
        END IF;
        PERFORM public.gah_assert_lifecycle_receipt_binding(
            p_command, p_expected_operation
        );
        PERFORM public.gah_verify_execution_signed_record(
            v_activation, 'receipt_digest', v_accepted_at, false
        );
        PERFORM public.gah_verify_execution_signed_record(
            v_rollback, 'receipt_digest', v_accepted_at, false
        );
        PERFORM public.gah_verify_execution_signed_record(
            v_activation,
            'receipt_digest',
            (p_command#>>'{transition_evidence,recorded_at}')::timestamptz,
            true
        );
        PERFORM public.gah_verify_execution_signed_record(
            v_rollback,
            'receipt_digest',
            (p_command#>>'{transition_evidence,recorded_at}')::timestamptz,
            true
        );
    END IF;
    RETURN public.gah_apply_skill_lifecycle_digest_validated(
        p_actor, p_command, p_expected_operation
    );
END
$function$;
ALTER FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_apply_skill_lifecycle(jsonb,jsonb,text)
    TO gah_skill_lifecycle_authority;

ALTER FUNCTION gah_builtin_execution_validate_authority(
    jsonb,jsonb,jsonb,jsonb,boolean
) RENAME TO gah_builtin_execution_validate_authority_validated;
ALTER FUNCTION gah_builtin_execution_validate_authority_validated(
    jsonb,jsonb,jsonb,jsonb,boolean
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_builtin_execution_validate_authority_validated(
    jsonb,jsonb,jsonb,jsonb,boolean
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_builtin_execution_validate_authority(
    p_actor jsonb, p_command jsonb, p_grant jsonb, p_evidence jsonb,
    p_require_current boolean
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    IF pg_catalog.jsonb_typeof(p_command#>'{approvals,0}') IS DISTINCT FROM 'object'
       OR p_command#>'{approvals,0}' ? 'revoked_at'
    THEN
        RAISE EXCEPTION 'execution approval is revoked or malformed';
    END IF;
    PERFORM public.gah_builtin_execution_validate_authority_validated(
        p_actor, p_command, p_grant, p_evidence, p_require_current
    );
END
$function$;
ALTER FUNCTION gah_builtin_execution_validate_authority(
    jsonb,jsonb,jsonb,jsonb,boolean
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_builtin_execution_validate_authority(
    jsonb,jsonb,jsonb,jsonb,boolean
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

ALTER FUNCTION gah_builtin_execution_validate_outcome(
    jsonb,jsonb,jsonb,jsonb,jsonb,text
) RENAME TO gah_builtin_execution_validate_outcome_validated;
ALTER FUNCTION gah_builtin_execution_validate_outcome_validated(
    jsonb,jsonb,jsonb,jsonb,jsonb,text
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_builtin_execution_validate_outcome_validated(
    jsonb,jsonb,jsonb,jsonb,jsonb,text
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_builtin_execution_validate_outcome(
    p_actor jsonb, p_command jsonb, p_grant jsonb, p_intent jsonb,
    p_outcome jsonb, p_state text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
BEGIN
    IF pg_catalog.jsonb_typeof(p_intent) IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_intent->'recorded_at') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_outcome->'occurred_at') IS DISTINCT FROM 'string'
       OR (p_outcome->>'occurred_at')::timestamptz
            < (p_intent->>'recorded_at')::timestamptz
    THEN
        RAISE EXCEPTION 'execution outcome predates its persisted intent';
    END IF;
    PERFORM public.gah_builtin_execution_validate_outcome_validated(
        p_actor, p_command, p_grant, p_intent, p_outcome, p_state
    );
END
$function$;
ALTER FUNCTION gah_builtin_execution_validate_outcome(
    jsonb,jsonb,jsonb,jsonb,jsonb,text
) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_builtin_execution_validate_outcome(
    jsonb,jsonb,jsonb,jsonb,jsonb,text
) FROM PUBLIC, gah_runtime, gah_authority_writer,
    gah_skill_lifecycle_authority, gah_execution_admission_authority;

ALTER FUNCTION gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    RENAME TO gah_recover_builtin_execution_validated;
ALTER FUNCTION gah_recover_builtin_execution_validated(jsonb,jsonb,jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_recover_builtin_execution_validated(jsonb,jsonb,jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_recover_builtin_execution(
    p_actor jsonb, p_query jsonb, p_outcome jsonb, p_evidence jsonb
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    v_intent jsonb;
BEGIN
    PERFORM public.gah_builtin_execution_assert_actor(p_actor);
    SELECT state_row.intent_evidence_json
      INTO v_intent
      FROM public.gah_builtin_execution_state AS state_row
     WHERE state_row.tenant_id = p_actor->>'tenant_id'
       AND state_row.actor_id = p_actor->>'actor_id'
       AND state_row.operation_id = p_query->>'operation_id';
    IF v_intent IS NULL THEN
        RAISE EXCEPTION 'execution recovery requires a persisted intent';
    END IF;
    RETURN public.gah_recover_builtin_execution_validated(
        p_actor, p_query, p_outcome, p_evidence
    );
END
$function$;
ALTER FUNCTION gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    FROM PUBLIC, gah_authority_writer, gah_skill_lifecycle_authority,
         gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)
    TO gah_runtime;

-- Rebuild is projection mutation from immutable lifecycle authority.  Verify
-- every activation/rollback receipt in the selected canonical history before
-- the private rebuild body can replay or change a projection.
ALTER FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    RENAME TO gah_rebuild_skill_projection_receipt_validated;
ALTER FUNCTION gah_rebuild_skill_projection_receipt_validated(jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_rebuild_skill_projection_receipt_validated(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_rebuild_skill_projection(p_actor jsonb, p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    transition_row record;
    v_tenant text;
    v_actor text;
    v_operation_id text;
    v_skill text;
BEGIN
    PERFORM public.gah_skill_assert_actor(p_actor);
    IF pg_catalog.jsonb_typeof(p_command) IS DISTINCT FROM 'object'
       OR p_command->>'operation' IS DISTINCT FROM 'rebuild'
       OR pg_catalog.jsonb_typeof(p_command->'operation_id')
            IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_command->'operation_digest')
            IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(p_command->'skill_id')
            IS DISTINCT FROM 'string'
       OR pg_catalog.btrim(p_command->>'operation_id') = ''
       OR pg_catalog.btrim(p_command->>'skill_id') = ''
       OR p_command->>'operation_digest' !~ '^sha256:[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION 'skill projection rebuild receipt binding is invalid';
    END IF;
    IF p_command->>'operation_digest' IS DISTINCT FROM
            public.gah_canonical_sha256(p_command - 'operation_digest')
    THEN
        RAISE EXCEPTION 'skill projection rebuild command digest binding is invalid';
    END IF;
    v_tenant := p_actor->>'tenant_id';
    v_actor := p_actor->>'actor_id';
    v_operation_id := p_command->>'operation_id';
    v_skill := p_command->>'skill_id';
    -- Match every lifecycle/rebuild path's canonical O -> actor-scoped S
    -- ordering.  The private body takes both reentrantly after verification.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill-operation:' || v_tenant || ':' || v_actor || ':' ||
            v_operation_id, 0
    ));
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'skill:' || v_tenant || ':' || v_actor || ':' || v_skill, 0
    ));
    FOR transition_row IN
        SELECT command_json, operation, tenant_id, actor_id, skill_id,
               target_revision,
               (evidence_json->>'recorded_at')::timestamptz AS recorded_at
          FROM public.gah_skill_lifecycle_transitions
         WHERE tenant_id=v_tenant
           AND actor_id=v_actor
           AND skill_id=v_skill
           AND operation IN ('activate','rollback')
         ORDER BY transition_sequence
    LOOP
        PERFORM public.gah_verify_persisted_lifecycle_receipts(
            transition_row.command_json,
            transition_row.operation,
            transition_row.recorded_at,
            true,
            transition_row.tenant_id,
            transition_row.actor_id,
            transition_row.skill_id,
            transition_row.target_revision
        );
    END LOOP;
    RETURN public.gah_rebuild_skill_projection_receipt_validated(
        p_actor, p_command
    );
END
$function$;
ALTER FUNCTION gah_rebuild_skill_projection(jsonb,jsonb) OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_rebuild_skill_projection(jsonb,jsonb)
    TO gah_skill_lifecycle_authority;

-- Exact authorization replay is durable but cannot preserve a revoked or
-- malformed approval imported from a pre-0015 database.
ALTER FUNCTION gah_lookup_builtin_execution_authorization(jsonb,jsonb)
    RENAME TO gah_lookup_builtin_execution_authorization_approval_validated;
ALTER FUNCTION gah_lookup_builtin_execution_authorization_approval_validated(jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION
    gah_lookup_builtin_execution_authorization_approval_validated(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;

CREATE FUNCTION gah_lookup_builtin_execution_authorization(
    p_actor jsonb, p_command jsonb
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $function$
DECLARE
    result jsonb;
    stored_command jsonb;
BEGIN
    result := public.gah_lookup_builtin_execution_authorization_approval_validated(
        p_actor, p_command
    );
    IF result IS NULL THEN
        RETURN NULL;
    END IF;
    stored_command := result->'command';
    IF (CASE
        WHEN pg_catalog.jsonb_typeof(stored_command->'approvals')
                IS DISTINCT FROM 'array' THEN true
        WHEN pg_catalog.jsonb_array_length(stored_command->'approvals') <> 1 THEN true
        ELSE pg_catalog.jsonb_typeof(stored_command#>'{approvals,0}')
                IS DISTINCT FROM 'object'
             OR stored_command#>'{approvals,0}' ? 'revoked_at'
    END) THEN
        RAISE EXCEPTION 'persisted execution approval is revoked or malformed';
    END IF;
    RETURN result;
END
$function$;
ALTER FUNCTION gah_lookup_builtin_execution_authorization(jsonb,jsonb)
    OWNER TO gah_schema_owner;
REVOKE ALL ON FUNCTION gah_lookup_builtin_execution_authorization(jsonb,jsonb)
    FROM PUBLIC, gah_runtime, gah_authority_writer,
         gah_skill_lifecycle_authority, gah_execution_admission_authority;
GRANT EXECUTE ON FUNCTION gah_lookup_builtin_execution_authorization(jsonb,jsonb)
    TO gah_execution_admission_authority;
