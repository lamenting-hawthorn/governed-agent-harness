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

from governed_agent_harness.contracts import (
    ActorContext,
    apply_object_digest,
    validate_skill_lifecycle_command,
)
from governed_agent_harness.contracts.errors import SemanticError
from governed_agent_harness.persistence.skills import (
    build_skill_lifecycle_wire_command,
    skill_lifecycle_operation_digest,
)

import test_governed_skill_lifecycle as lifecycle


_ACTOR_BOUND_ATTACKS = (
    "roles_limit",
    "roles_unique",
    "capabilities_limit",
    "capabilities_unique",
    "allowed_levels_limit",
    "allowed_levels_unique",
    "team_ids_limit",
    "team_ids_unique",
    "organization_ids_limit",
    "organization_ids_unique",
    "project_ids_limit",
    "project_ids_unique",
    "workspace_ids_limit",
    "workspace_ids_unique",
    "extensions_property_limit",
    "extensions_property_name",
    "extensions_property_name_length",
    "extensions_string_length",
    "extensions_integer_range",
    "extensions_number_type",
    "extensions_array_limit",
    "extensions_array_item_shape",
    "extensions_object_limit",
    "extensions_object_key",
    "extensions_object_key_length",
    "extensions_object_value_shape",
    "extensions_canonical_size",
    "verified_after_issued",
)


def _actor_bound_poison(actor, attack):
    poisoned = copy.deepcopy(actor)
    memberships = {
        "team_ids",
        "organization_ids",
        "project_ids",
        "workspace_ids",
    }
    if attack == "roles_limit":
        poisoned["roles"] = [f"role.{index}" for index in range(65)]
    elif attack == "roles_unique":
        poisoned["roles"] = ["operator", "operator"]
    elif attack == "capabilities_limit":
        poisoned["capabilities"] = [f"capability.{index}" for index in range(129)]
    elif attack == "capabilities_unique":
        poisoned["capabilities"] = ["memory.read", "memory.read"]
    elif attack == "allowed_levels_limit":
        poisoned["scope_authority"]["allowed_levels"].append("actor")
    elif attack == "allowed_levels_unique":
        poisoned["scope_authority"]["allowed_levels"] = ["actor", "actor"]
    elif attack.removesuffix("_limit") in memberships:
        field = attack.removesuffix("_limit")
        poisoned["scope_authority"][field] = [
            f"018f0000-0000-7000-8000-{index:012x}" for index in range(65)
        ]
    elif attack.removesuffix("_unique") in memberships:
        field = attack.removesuffix("_unique")
        value = poisoned["scope_authority"][field][0]
        poisoned["scope_authority"][field] = [value, value]
    elif attack == "extensions_property_limit":
        poisoned["extensions"] = {f"example{index}.org/key": index for index in range(17)}
    elif attack == "extensions_property_name":
        poisoned["extensions"] = {"not_namespaced": True}
    elif attack == "extensions_property_name_length":
        poisoned["extensions"] = {f"{'a.' * 94}a/key": True}
    elif attack == "extensions_string_length":
        poisoned["extensions"] = {"example.org/key": "x" * 257}
    elif attack == "extensions_integer_range":
        poisoned["extensions"] = {"example.org/key": 9_007_199_254_740_992}
    elif attack == "extensions_number_type":
        poisoned["extensions"] = {"example.org/key": 1.5}
    elif attack == "extensions_array_limit":
        poisoned["extensions"] = {"example.org/key": [1, 2, 3, 4, 5]}
    elif attack == "extensions_array_item_shape":
        poisoned["extensions"] = {"example.org/key": [{"nested": True}]}
    elif attack == "extensions_object_limit":
        poisoned["extensions"] = {"example.org/key": {f"key_{index}": index for index in range(5)}}
    elif attack == "extensions_object_key":
        poisoned["extensions"] = {"example.org/key": {"Not_Snake": True}}
    elif attack == "extensions_object_key_length":
        poisoned["extensions"] = {"example.org/key": {"a" * 33: True}}
    elif attack == "extensions_object_value_shape":
        poisoned["extensions"] = {"example.org/key": {"nested": [True]}}
    elif attack == "extensions_canonical_size":
        poisoned["extensions"] = {
            f"example{index}.org/key": {f"value_{child}": "x" * 256 for child in range(4)}
            for index in range(16)
        }
    elif attack == "verified_after_issued":
        poisoned["auth"]["verified_at"] = "2026-01-01T00:00:01.000Z"
        poisoned["issued_at"] = "2026-01-01T00:00:00.000Z"
    else:
        raise AssertionError(f"unknown actor attack: {attack}")
    return poisoned


@pytest.mark.parametrize(
    "field,value", (("retention", None), ("retention", []), ("validity", "bad"))
)
def test_phase51_lifecycle_rejects_non_mapping_validity_before_dereference(
    postgres_connections, field, value
):
    """Malformed expiry containers are contract errors, never AttributeError."""

    actor, command = lifecycle._persisted_command(postgres_connections)
    command[field] = value
    wire = build_skill_lifecycle_wire_command("install", command)
    with pytest.raises(SemanticError, match="retention and validity must be JSON objects"):
        validate_skill_lifecycle_command(actor_context=actor, command=wire)


@pytest.mark.parametrize("removed", ("session_id", "auth", "scope_authority"))
def test_phase51_partial_actor_cannot_replay_through_python_or_sql(postgres_connections, removed):
    """A schema-invalid actor cannot take either replay fast path."""

    actor, command = lifecycle._persisted_command(postgres_connections)
    authority = lifecycle.PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: lifecycle.NOW,
        ids=lifecycle._ids(),
    )
    authority.install_skill(actor_context=actor, **command)
    partial = copy.deepcopy(actor)
    partial.pop(removed)
    before = lifecycle._skill_authority_snapshot(postgres_connections)
    with pytest.raises(Exception):
        authority.install_skill(actor_context=partial, **command)
    wire = build_skill_lifecycle_wire_command("install", command)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception):
            cursor.execute(
                "SELECT gah_lookup_skill_replay(%s::jsonb,%s::jsonb)",
                (json.dumps(partial), json.dumps(wire)),
            )
    rebuild = {
        "operation_id": f"phase51-partial-actor-rebuild-{removed}",
        "expected_revision": 1,
        "skill_id": command["skill_proposal"]["artifact_id"],
    }
    with pytest.raises(Exception):
        authority.rebuild_skill_projection(actor_context=partial, **rebuild)
    rebuild_wire = build_skill_lifecycle_wire_command("rebuild", rebuild)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception):
            cursor.execute(
                "SELECT gah_rebuild_skill_projection(%s::jsonb,%s::jsonb)",
                (json.dumps(partial), json.dumps(rebuild_wire)),
            )
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


@pytest.mark.parametrize("attack", _ACTOR_BOUND_ATTACKS)
def test_phase51_actor_contract_bounds_cannot_replay_or_rebuild_through_sql(
    postgres_connections, attack
):
    """Every missing ActorContext invariant fails before durable SQL effects."""

    actor, command = lifecycle._persisted_command(postgres_connections)
    authority = lifecycle.PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: lifecycle.NOW,
        ids=lifecycle._ids(),
    )
    authority.install_skill(actor_context=actor, **command)
    poisoned = _actor_bound_poison(actor, attack)
    with pytest.raises(Exception):
        ActorContext(poisoned)

    before = lifecycle._skill_authority_snapshot(postgres_connections)
    wire = build_skill_lifecycle_wire_command("install", command)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="actor scope"):
            cursor.execute(
                "SELECT gah_lookup_skill_replay(%s::jsonb,%s::jsonb)",
                (json.dumps(poisoned), json.dumps(wire)),
            )
        connection.rollback()
        rebuild = build_skill_lifecycle_wire_command(
            "rebuild",
            {
                "operation_id": f"phase51-actor-bound-{attack}-rebuild",
                "expected_revision": 1,
                "skill_id": command["skill_proposal"]["artifact_id"],
            },
        )
        with pytest.raises(Exception, match="actor scope"):
            cursor.execute(
                "SELECT gah_rebuild_skill_projection(%s::jsonb,%s::jsonb)",
                (json.dumps(poisoned), json.dumps(rebuild)),
            )
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


def test_phase51_actor_contract_maxima_can_replay_through_sql(postgres_connections):
    """Canonical upper bounds remain usable while the bypasses fail closed."""

    actor, command = lifecycle._persisted_command(postgres_connections)
    authority = lifecycle.PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: lifecycle.NOW,
        ids=lifecycle._ids(),
    )
    authority.install_skill(actor_context=actor, **command)
    bounded = copy.deepcopy(actor)
    bounded["roles"] = [f"role.{index}" for index in range(64)]
    bounded["capabilities"] = [f"capability.{index}" for index in range(128)]
    for field in ("team_ids", "organization_ids", "project_ids", "workspace_ids"):
        bounded["scope_authority"][field] = [
            f"018f0000-0000-7000-8000-{index:012x}" for index in range(64)
        ]
    bounded["extensions"] = {
        f"example{index}.org/key": (
            [None, True, 9_007_199_254_740_991, "x" * 256]
            if index % 2 == 0
            else {"first": None, "second": False, "third": -9_007_199_254_740_991, "fourth": "x"}
        )
        for index in range(16)
    }
    ActorContext(bounded)

    before = lifecycle._skill_authority_snapshot(postgres_connections)
    wire = build_skill_lifecycle_wire_command("install", command)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT gah_lookup_skill_replay(%s::jsonb,%s::jsonb)",
            (json.dumps(bounded), json.dumps(wire)),
        )
        assert cursor.fetchone()[0]["replayed"] is True
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


def _unsupported_constraint():
    return {
        "constraint_id": "example.invalid/unsupported",
        "constraint_version": "v1",
        "parameters": {"mode": "opaque"},
        "parameters_digest": lifecycle.sha256_digest({"mode": "opaque"}),
    }


@pytest.mark.parametrize(
    ("attack", "requires_approval"),
    (
        ("constraints", False),
        ("constraints", True),
        ("future_policy", False),
        ("future_policy", True),
    ),
)
def test_phase51_direct_lifecycle_sink_rejects_unsupported_or_future_policy_without_mutation(
    postgres_connections, attack, requires_approval
):
    """The SECURITY DEFINER sink enforces the common policy checks itself."""

    actor, command = (
        lifecycle._approval_required_command(postgres_connections)
        if requires_approval
        else lifecycle._persisted_command(postgres_connections)
    )
    policy = command["policy_decision"]
    if attack == "constraints":
        policy["constraints"] = [_unsupported_constraint()]
    else:
        policy["decided_at"] = "2030-01-01T00:00:00.000Z"
    apply_object_digest(policy)
    if requires_approval:
        approval = command["approvals"][0]
        approval["policy_decision_digest"] = policy["decision_digest"]
        approval["constraints"] = copy.deepcopy(policy["constraints"])
        approval = lifecycle._sign_policy_approval(approval)
        command["approvals"] = [approval]
        command["delivery_envelope"]["reviewer_refs"] = [
            lifecycle.ref("approval_record", approval["approval_id"], approval["approval_digest"])
        ]
    command["delivery_envelope"]["policy_refs"] = [
        lifecycle.ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    ]
    apply_object_digest(command["delivery_envelope"])
    before = lifecycle._skill_authority_snapshot(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        authorization = lifecycle._authorize_lifecycle(writer_connection, actor, "install", command)
        wire = lifecycle._direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=authorization
        )
        with pytest.raises(Exception, match="policy"):
            lifecycle._direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


@pytest.mark.parametrize("attack", ("constraints", "future_policy"))
def test_phase51_persisted_replay_and_rebuild_reject_policy_poison_without_mutation(
    postgres_connections, attack
):
    """Stored authorization poison cannot be replayed or rebuilt through 0017."""

    actor, command = lifecycle._persisted_command(postgres_connections)
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
        if attack == "constraints":
            policy["constraints"] = [_unsupported_constraint()]
        else:
            policy["decided_at"] = "2030-01-01T00:00:00.000Z"
        apply_object_digest(policy)
        poisoned["delivery_envelope"]["policy_refs"] = [
            lifecycle.ref("policy_decision", policy["decision_id"], policy["decision_digest"])
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
        with pytest.raises(Exception, match="policy"):
            cursor.execute(
                "SELECT gah_lookup_skill_replay(%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(poisoned)),
            )
        connection.rollback()
        rebuild = build_skill_lifecycle_wire_command(
            "rebuild",
            {
                "operation_id": f"phase51-{attack}-poison-rebuild",
                "expected_revision": 1,
                "skill_id": command["skill_proposal"]["artifact_id"],
            },
        )
        with pytest.raises(Exception, match="policy"):
            cursor.execute(
                "SELECT gah_rebuild_skill_projection(%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(rebuild)),
            )
    assert lifecycle._skill_authority_snapshot(postgres_connections) == before


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


def test_phase51_0017_actor_scope_and_lifecycle_sink_catalog_contract(postgres_connections):
    """0017 must leave actor scope and hardened functions observable in the DB."""

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
    assert "gah_verify_lifecycle_approvals_0016" in verifier
    assert "constraints" in verifier
    assert "policy_decided_at > p_accepted_at" in verifier
    for signature in (
        "gah_lookup_skill_replay(jsonb,jsonb)",
        "gah_apply_skill_lifecycle(jsonb,jsonb,text)",
        "gah_rebuild_skill_projection(jsonb,jsonb)",
    ):
        assert "gah_verify_lifecycle_approvals" in functions[signature][3]

    actor_helpers = (
        "gah_skill_assert_actor(jsonb)",
        "gah_actor_extension_scalar_valid(jsonb)",
        "gah_actor_extension_value_valid(jsonb)",
        "gah_actor_extensions_valid(jsonb)",
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT p.oid::regprocedure::text, r.rolname, p.proconfig, "
            "p.prosecdef, p.provolatile, "
            "has_function_privilege('public', p.oid, 'EXECUTE'), "
            "has_function_privilege('gah_runtime', p.oid, 'EXECUTE'), "
            "has_function_privilege('gah_authority_writer', p.oid, 'EXECUTE'), "
            "has_function_privilege('gah_skill_lifecycle_authority', p.oid, 'EXECUTE'), "
            "has_function_privilege('gah_execution_admission_authority', p.oid, 'EXECUTE') "
            "FROM pg_proc AS p JOIN pg_roles AS r ON r.oid=p.proowner "
            "WHERE p.oid = ANY(%s::regprocedure[]) ORDER BY p.oid::regprocedure::text",
            (list(actor_helpers),),
        )
        actor_catalog = {row[0]: row[1:] for row in cursor.fetchall()}
    assert set(actor_catalog) == set(actor_helpers)
    actor_assert = actor_catalog["gah_skill_assert_actor(jsonb)"]
    assert actor_assert[:5] == (
        "gah_schema_owner",
        ["search_path=pg_catalog, public"],
        True,
        "v",
        False,
    )
    assert actor_assert[5:] == (False, False, False, False)
    for signature in actor_helpers[1:]:
        helper = actor_catalog[signature]
        assert helper[:5] == (
            "gah_schema_owner",
            ["search_path=pg_catalog, public"],
            False,
            "i",
            False,
        )
        assert helper[5:] == (False, False, False, False)

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
            match="approval.*policy|policy.*approval|lifecycle approval authority binding|policy decision",
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
            match="approval.*policy|policy.*approval|lifecycle approval authority binding|policy decision",
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
            match="approval.*policy|policy.*approval|lifecycle approval authority binding|policy decision",
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
