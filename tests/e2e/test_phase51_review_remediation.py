"""Independent real-PostgreSQL acceptance checks for the Phase 5.1 P1 repair.

These deliberately exercise the public SECURITY DEFINER sinks rather than the
Python preflight.  They pin the two review findings: actor-scoped execution
identities and cryptographically verified lifecycle approvals.
"""

from __future__ import annotations

import copy
import json
from hashlib import sha256

import pytest
from nacl.signing import SigningKey

from governed_agent_harness.contracts import apply_object_digest
from governed_agent_harness.persistence.skills import (
    build_skill_lifecycle_wire_command,
    skill_lifecycle_operation_digest,
)

import test_governed_skill_lifecycle as lifecycle


@pytest.mark.parametrize("window", ("valid", "expired", "revoked"))
def test_phase51_lifecycle_sql_uses_inserted_policy_approval_trust_window(
    postgres_connections, window
):
    """A lifecycle SQL sink evaluates the trusted DB key at acceptance time."""

    actor, command = lifecycle._approval_required_command(postgres_connections)
    key_id = f"policy.0016.{window}.v1"
    approval = lifecycle._sign_policy_approval(command["approvals"][0], key_id=key_id)
    command["approvals"] = [approval]
    command["delivery_envelope"]["reviewer_refs"] = [
        lifecycle.ref("approval_record", approval["approval_id"], approval["approval_digest"])
    ]
    apply_object_digest(command["delivery_envelope"])
    public_key = SigningKey(lifecycle._TEST_SIGNING_SEED).verify_key.encode()
    if window == "valid":
        valid_from, valid_until, revoked_at = (
            "2020-01-01T00:00:00.000Z",
            "2030-01-01T00:00:00.000Z",
            None,
        )
    elif window == "expired":
        valid_from, valid_until, revoked_at = (
            "2020-01-01T00:00:00.000Z",
            "2025-01-01T00:00:00.000Z",
            None,
        )
    else:
        valid_from, valid_until, revoked_at = (
            "2020-01-01T00:00:00.000Z",
            "2030-01-01T00:00:00.000Z",
            "2025-01-01T00:00:00.000Z",
        )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_execution_proof_keys ("
            "issuer,key_id,algorithm,proof_domain,public_key,public_key_fingerprint,"
            "trust_policy_version,trust_policy_digest,valid_from,valid_until,revoked_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz,%s::timestamptz)",
            (
                "policy.authority",
                key_id,
                lifecycle._TEST_ALGORITHM,
                "approval_record.v1",
                public_key,
                "sha256:" + sha256(public_key).hexdigest(),
                "phase51.0016.window.v1",
                "sha256:" + "1" * 64,
                valid_from,
                valid_until,
                revoked_at,
            ),
        )
    wire = build_skill_lifecycle_wire_command("install", command)
    before = lifecycle._skill_authority_snapshot(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        authorization = lifecycle._authorize_lifecycle(writer_connection, actor, "install", command)
        wire = lifecycle._direct_lifecycle_wire(
            postgres_connections,
            actor,
            command,
            writer_authorization=authorization,
        )
        if window == "valid":
            installed = lifecycle._direct_apply(
                postgres_connections, actor, "gah_install_skill", wire
            )
            assert installed["lifecycle_state"] == "installed"
        else:
            with pytest.raises(Exception):
                lifecycle._direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    if window != "valid":
        assert lifecycle._skill_authority_snapshot(postgres_connections) == before


def _catalog_functions(postgres_connections):
    """Return owner/config/ACL/body of the 0016 security-sensitive functions."""

    signatures = (
        "gah_verify_lifecycle_approvals(jsonb,timestamptz,boolean)",
        "gah_lookup_skill_replay(jsonb,jsonb)",
        "gah_apply_skill_lifecycle(jsonb,jsonb,text)",
        "gah_rebuild_skill_projection(jsonb,jsonb)",
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT p.oid::regprocedure::text, r.rolname, p.proconfig, "
            "has_function_privilege('public', p.oid, 'EXECUTE'), "
            "pg_get_functiondef(p.oid) "
            "FROM pg_proc AS p JOIN pg_roles AS r ON r.oid=p.proowner "
            "WHERE p.oid = ANY(%s::regprocedure[]) "
            "ORDER BY p.oid::regprocedure::text",
            (list(signatures),),
        )
        rows = cursor.fetchall()
    assert len(rows) == len(signatures)
    return {row[0]: row[1:] for row in rows}


def _function_acl(postgres_connections, signatures):
    """Return four role execute bits and the stored function body."""

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT p.oid::regprocedure::text, "
            "has_function_privilege('gah_runtime', p.oid, 'EXECUTE'), "
            "has_function_privilege('gah_authority_writer', p.oid, 'EXECUTE'), "
            "has_function_privilege('gah_skill_lifecycle_authority', p.oid, 'EXECUTE'), "
            "has_function_privilege('gah_execution_admission_authority', p.oid, 'EXECUTE'), "
            "pg_get_functiondef(p.oid) FROM pg_proc AS p "
            "WHERE p.oid = ANY(%s::regprocedure[]) "
            "ORDER BY p.oid::regprocedure::text",
            (list(signatures),),
        )
        return {row[0]: row[1:] for row in cursor.fetchall()}


def test_phase51_0016_actor_scope_and_lifecycle_sink_catalog_contract(postgres_connections):
    """0016 must leave actor scope and hardened functions observable in the DB."""

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='gah_builtin_execution_state'::regclass "
            "AND conname IN ("
            "'gah_builtin_execution_state_actor_pkey',"
            "'gah_builtin_execution_state_actor_operation_digest_key',"
            "'gah_builtin_execution_state_actor_request_id_key',"
            "'gah_builtin_execution_state_actor_binding_guard') "
            "ORDER BY conname"
        )
        constraints = dict(cursor.fetchall())
        cursor.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='gah_builtin_execution_state'::regclass "
            "AND contype='u' AND pg_get_constraintdef(oid) "
            "LIKE 'UNIQUE (tenant_id, grant_id)%'"
        )
        grant_constraint = cursor.fetchone()

    assert (
        "PRIMARY KEY (tenant_id, actor_id, operation_id)"
        in constraints["gah_builtin_execution_state_actor_pkey"]
    )
    assert (
        "UNIQUE (tenant_id, actor_id, operation_digest)"
        in constraints["gah_builtin_execution_state_actor_operation_digest_key"]
    )
    assert (
        "UNIQUE (tenant_id, actor_id, request_id)"
        in constraints["gah_builtin_execution_state_actor_request_id_key"]
    )
    assert (
        "gah_builtin_execution_state_actor_binding_valid"
        in constraints["gah_builtin_execution_state_actor_binding_guard"]
    )
    assert grant_constraint is not None

    functions = _catalog_functions(postgres_connections)
    for owner, proconfig, public_execute, body in functions.values():
        assert owner == "gah_schema_owner"
        assert public_execute is False
        assert proconfig is not None and "search_path=pg_catalog, public" in proconfig
        assert "SECURITY DEFINER" in body
    verifier = functions["gah_verify_lifecycle_approvals(jsonb,timestamp with time zone,boolean)"][
        3
    ]
    assert "gah_verify_execution_signed_record" in verifier
    assert "approval_record.v1" in verifier
    assert "revoked_at" in verifier
    for signature in (
        "gah_lookup_skill_replay(jsonb,jsonb)",
        "gah_apply_skill_lifecycle(jsonb,jsonb,text)",
        "gah_rebuild_skill_projection(jsonb,jsonb)",
    ):
        assert "gah_verify_lifecycle_approvals" in functions[signature][3]

    lifecycle_acl = _function_acl(
        postgres_connections,
        (
            "gah_lookup_skill_replay(jsonb,jsonb)",
            "gah_apply_skill_lifecycle(jsonb,jsonb,text)",
            "gah_rebuild_skill_projection(jsonb,jsonb)",
            "gah_lookup_skill_replay_approval_validated(jsonb,jsonb)",
            "gah_apply_skill_lifecycle_approval_validated(jsonb,jsonb,text)",
            "gah_rebuild_skill_projection_approval_validated(jsonb,jsonb)",
        ),
    )
    for signature in (
        "gah_lookup_skill_replay(jsonb,jsonb)",
        "gah_apply_skill_lifecycle(jsonb,jsonb,text)",
        "gah_rebuild_skill_projection(jsonb,jsonb)",
    ):
        assert lifecycle_acl[signature][:4] == (False, False, True, False)
    for signature in (
        "gah_lookup_skill_replay_approval_validated(jsonb,jsonb)",
        "gah_apply_skill_lifecycle_approval_validated(jsonb,jsonb,text)",
        "gah_rebuild_skill_projection_approval_validated(jsonb,jsonb)",
    ):
        assert lifecycle_acl[signature][:4] == (False, False, False, False)

    execution_acl = _function_acl(
        postgres_connections,
        (
            "gah_authorize_builtin_execution(jsonb,jsonb)",
            "gah_lookup_builtin_execution_authorization(jsonb,jsonb)",
            "gah_lookup_builtin_execution_authorization_approval_validated(jsonb,jsonb)",
            "gah_issue_builtin_execution_authorization_locked(jsonb,jsonb,jsonb,jsonb,jsonb)",
            "gah_begin_builtin_execution(jsonb,jsonb,jsonb,double precision)",
            "gah_begin_builtin_execution_validated(jsonb,jsonb,jsonb,double precision)",
            "gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)",
            "gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)",
            "gah_recover_builtin_execution_validated(jsonb,jsonb,jsonb,jsonb)",
            "gah_rebuild_builtin_execution(jsonb,jsonb)",
        ),
    )
    expected_public_acl = {
        "gah_authorize_builtin_execution(jsonb,jsonb)": (False, True, False, False),
        "gah_lookup_builtin_execution_authorization(jsonb,jsonb)": (
            False,
            False,
            False,
            True,
        ),
        "gah_begin_builtin_execution(jsonb,jsonb,jsonb,double precision)": (
            True,
            False,
            False,
            False,
        ),
        "gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)": (
            True,
            False,
            False,
            False,
        ),
        "gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)": (
            True,
            False,
            False,
            False,
        ),
        "gah_rebuild_builtin_execution(jsonb,jsonb)": (False, False, False, True),
    }
    for signature, expected_acl in expected_public_acl.items():
        assert execution_acl[signature][:4] == expected_acl
    for signature in (
        "gah_lookup_builtin_execution_authorization_approval_validated(jsonb,jsonb)",
        "gah_begin_builtin_execution_validated(jsonb,jsonb,jsonb,double precision)",
        "gah_recover_builtin_execution_validated(jsonb,jsonb,jsonb,jsonb)",
    ):
        assert execution_acl[signature][:4] == (False, False, False, False)
    for signature in (
        "gah_lookup_builtin_execution_authorization_approval_validated(jsonb,jsonb)",
        "gah_issue_builtin_execution_authorization_locked(jsonb,jsonb,jsonb,jsonb,jsonb)",
        "gah_begin_builtin_execution_validated(jsonb,jsonb,jsonb,double precision)",
        "gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)",
        "gah_recover_builtin_execution_validated(jsonb,jsonb,jsonb,jsonb)",
    ):
        assert "actor_id=p_actor->>'actor_id'" in execution_acl[signature][4], signature
    authorize_body = execution_acl["gah_authorize_builtin_execution(jsonb,jsonb)"][4]
    assert "execution:operation:" in authorize_body
    assert "(p_actor->>'actor_id')||':'||" in authorize_body
    issue_body = execution_acl[
        "gah_issue_builtin_execution_authorization_locked(jsonb,jsonb,jsonb,jsonb,jsonb)"
    ][4]
    assert "execution:request:" in issue_body
    assert "'skill:'||(p_actor->>'tenant_id')||':'||" in issue_body
    rebuild_body = execution_acl["gah_rebuild_builtin_execution(jsonb,jsonb)"][4]
    assert "stored.actor_id IS DISTINCT FROM p_actor->>'actor_id'" in rebuild_body


@pytest.mark.parametrize(
    "attack",
    ("missing_issued_at", "null_expires_at", "evidence_before_issued_at"),
)
def test_phase51_direct_lifecycle_sink_rejects_scalar_time_attacks_without_mutation(
    postgres_connections, attack
):
    """Python cannot be the only lifecycle-approval validator."""

    actor, command = lifecycle._approval_required_command(postgres_connections)
    evidence_template = lifecycle._direct_lifecycle_wire(postgres_connections, actor, command)[
        "transition_evidence"
    ]
    approval = command["approvals"][0]
    if attack == "missing_issued_at":
        approval.pop("issued_at")
    elif attack == "null_expires_at":
        approval["expires_at"] = None
    else:
        # A valid signature over an approval issued after ledger recording is
        # still rejected by the SQL sink.
        approval["issued_at"] = "2030-01-01T00:00:00.000Z"
    command["approvals"][0] = lifecycle._sign_policy_approval(approval)
    command["delivery_envelope"]["reviewer_refs"] = [
        lifecycle.ref(
            "approval_record",
            command["approvals"][0]["approval_id"],
            command["approvals"][0]["approval_digest"],
        )
    ]
    apply_object_digest(command["delivery_envelope"])
    wire = build_skill_lifecycle_wire_command("install", command)
    before = lifecycle._skill_authority_snapshot(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        writer_authorization = lifecycle._authorize_lifecycle(
            writer_connection, actor, "install", command
        )
        evidence = lifecycle._rebind_direct_lifecycle_evidence(
            evidence_template,
            actor=actor,
            wire=wire,
            writer_authorization=writer_authorization,
        )
        wire = {**wire, "transition_evidence": evidence}
        with pytest.raises(Exception):
            lifecycle._direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


def test_phase51_direct_lifecycle_sink_rejects_approval_before_bound_policy(
    postgres_connections,
):
    """A valid signature cannot authorize an approval predating its policy decision."""

    actor, command = lifecycle._approval_required_command(postgres_connections)
    policy = command["policy_decision"]
    policy["decided_at"] = "2026-01-02T00:00:00.000Z"
    apply_object_digest(policy)
    approval = command["approvals"][0]
    approval["policy_decision_digest"] = policy["decision_digest"]
    approval = lifecycle._sign_policy_approval(approval)
    command["approvals"] = [approval]
    command["delivery_envelope"]["policy_refs"] = [
        lifecycle.ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    ]
    command["delivery_envelope"]["reviewer_refs"] = [
        lifecycle.ref("approval_record", approval["approval_id"], approval["approval_digest"])
    ]
    apply_object_digest(command["delivery_envelope"])
    before = lifecycle._skill_authority_snapshot(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        authorization = lifecycle._authorize_lifecycle(writer_connection, actor, "install", command)
        wire = lifecycle._direct_lifecycle_wire(
            postgres_connections,
            actor,
            command,
            writer_authorization=authorization,
        )
        with pytest.raises(
            Exception,
            match="approval.*policy|policy.*approval|lifecycle approval authority binding",
        ):
            lifecycle._direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


def test_phase51_lifecycle_replay_and_rebuild_stop_on_poisoned_approval(postgres_connections):
    """Persisted bad approval data cannot be replayed or rebuilt past atomically."""

    actor, command = lifecycle._approval_required_command(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        writer_authorization = lifecycle._authorize_lifecycle(
            writer_connection, actor, "install", command
        )
        wire = lifecycle._direct_lifecycle_wire(
            postgres_connections,
            actor,
            command,
            writer_authorization=writer_authorization,
        )
        installed = lifecycle._direct_apply(
            postgres_connections,
            actor,
            "gah_install_skill",
            wire,
        )
    assert installed["lifecycle_state"] == "installed"
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT command_json FROM gah_skill_lifecycle_transitions "
            "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
            (actor["tenant_id"], actor["actor_id"], command["operation_id"]),
        )
        poisoned_command = copy.deepcopy(cursor.fetchone()[0])
        proof = poisoned_command["approvals"][0]["proof"]
        proof["detached_proof"] = ("A" if proof["detached_proof"][0] != "A" else "B") + proof[
            "detached_proof"
        ][1:]
        cursor.execute(
            "UPDATE gah_skill_lifecycle_transitions SET command_json=%s::jsonb "
            "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
            (
                json.dumps(poisoned_command),
                actor["tenant_id"],
                actor["actor_id"],
                command["operation_id"],
            ),
        )
    before = lifecycle._skill_authority_snapshot(postgres_connections)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception):
            cursor.execute(
                "SELECT gah_lookup_skill_replay(%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(poisoned_command)),
            )
    rebuild = build_skill_lifecycle_wire_command(
        "rebuild",
        {
            "operation_id": "phase51-poisoned-approval-rebuild",
            "expected_revision": 1,
            "skill_id": command["skill_proposal"]["artifact_id"],
        },
    )
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception):
            cursor.execute(
                "SELECT gah_rebuild_skill_projection(%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(rebuild)),
            )
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


def test_phase51_persisted_replay_rejects_approval_before_bound_policy(
    postgres_connections,
):
    """Historical replay repeats approval/policy chronology validation at the sink."""

    actor, command = lifecycle._approval_required_command(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        authorization = lifecycle._authorize_lifecycle(writer_connection, actor, "install", command)
        wire = lifecycle._direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=authorization
        )
        lifecycle._direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT command_json FROM gah_skill_lifecycle_transitions "
            "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
            (actor["tenant_id"], actor["actor_id"], command["operation_id"]),
        )
        poisoned = copy.deepcopy(cursor.fetchone()[0])
        policy = poisoned["policy_decision"]
        policy["decided_at"] = "2026-01-02T00:00:00.000Z"
        apply_object_digest(policy)
        approval = poisoned["approvals"][0]
        approval["policy_decision_digest"] = policy["decision_digest"]
        approval = lifecycle._sign_policy_approval(approval)
        poisoned["approvals"] = [approval]
        poisoned["delivery_envelope"]["policy_refs"] = [
            lifecycle.ref("policy_decision", policy["decision_id"], policy["decision_digest"])
        ]
        poisoned["delivery_envelope"]["reviewer_refs"] = [
            lifecycle.ref("approval_record", approval["approval_id"], approval["approval_digest"])
        ]
        apply_object_digest(poisoned["delivery_envelope"])
        unsigned = dict(poisoned)
        unsigned.pop("operation_digest")
        poisoned["operation_digest"] = skill_lifecycle_operation_digest(unsigned)
        cursor.execute(
            "UPDATE gah_skill_lifecycle_transitions SET operation_digest=%s,command_json=%s::jsonb "
            "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
            (
                poisoned["operation_digest"],
                json.dumps(poisoned),
                actor["tenant_id"],
                actor["actor_id"],
                command["operation_id"],
            ),
        )
    before = lifecycle._skill_authority_snapshot(postgres_connections)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(
            Exception,
            match="approval.*policy|policy.*approval|lifecycle approval authority binding",
        ):
            cursor.execute(
                "SELECT gah_lookup_skill_replay(%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(poisoned)),
            )
        connection.rollback()
        rebuild = build_skill_lifecycle_wire_command(
            "rebuild",
            {
                "operation_id": "phase51-pre-policy-rebuild",
                "expected_revision": 1,
                "skill_id": command["skill_proposal"]["artifact_id"],
            },
        )
        with pytest.raises(
            Exception,
            match="approval.*policy|policy.*approval|lifecycle approval authority binding",
        ):
            cursor.execute(
                "SELECT gah_rebuild_skill_projection(%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(rebuild)),
            )
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


def test_phase51_rebuild_replay_stops_at_stored_terminal_before_later_admin_poison(
    postgres_connections,
):
    """A rebuild replay is bounded by its stored terminal, not later corrupt rows."""

    actor, command = lifecycle._approval_required_command(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        authorization = lifecycle._authorize_lifecycle(writer_connection, actor, "install", command)
        install_wire = lifecycle._direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=authorization
        )
        lifecycle._direct_apply(postgres_connections, actor, "gah_install_skill", install_wire)
    rebuild = build_skill_lifecycle_wire_command(
        "rebuild",
        {
            "operation_id": "phase51-prefix-rebuild",
            "expected_revision": 1,
            "skill_id": command["skill_proposal"]["artifact_id"],
        },
    )
    first = lifecycle._direct_apply(
        postgres_connections, actor, "gah_rebuild_skill_projection", rebuild
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_skill_lifecycle_transitions "
            "(tenant_id,actor_id,skill_id,transition_sequence,operation_id,operation,"
            "operation_digest,expected_revision,target_revision,from_state,to_state,"
            "command_json,evidence_json,evidence_event_digest) "
            "SELECT tenant_id,actor_id,skill_id,transition_sequence+1,%s,operation,%s,"
            "expected_revision,target_revision,from_state,to_state,"
            "jsonb_set(jsonb_set(jsonb_set(command_json,'{operation_id}',to_jsonb(%s::text)),"
            "'{operation_digest}',to_jsonb(%s::text)),'{approvals,0,proof,detached_proof}',"
            "to_jsonb(%s::text)),jsonb_set(evidence_json,'{event_digest}',to_jsonb(%s::text)),%s "
            "FROM gah_skill_lifecycle_transitions "
            "WHERE tenant_id=%s AND actor_id=%s AND skill_id=%s "
            "ORDER BY transition_sequence DESC LIMIT 1",
            (
                "phase51-later-admin-poison",
                "sha256:" + "f" * 64,
                "phase51-later-admin-poison",
                "sha256:" + "f" * 64,
                "A" * 86,
                "sha256:" + "e" * 64,
                "sha256:" + "e" * 64,
                actor["tenant_id"],
                actor["actor_id"],
                command["skill_proposal"]["artifact_id"],
            ),
        )
    replay = lifecycle._direct_apply(
        postgres_connections, actor, "gah_rebuild_skill_projection", rebuild
    )
    assert replay["replayed"] is True
    assert replay["transition_digest"] == first["transition_digest"]
