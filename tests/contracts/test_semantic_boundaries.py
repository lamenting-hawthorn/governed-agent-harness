"""Cross-record authority, scope, constraint, and lifecycle tests."""

from __future__ import annotations

import copy
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest

from governed_agent_harness.contracts import (
    DEFAULT_SCHEMA_STORE,
    MODEL_BY_RECORD_TYPE,
    ConstraintRegistry,
    IdempotencyConflictError,
    IdempotencyResult,
    SchemaError,
    SemanticError,
    apply_object_digest,
    compare_idempotency_bindings,
    learning_artifact_is_active,
    sha256_digest,
    validate_approval_binding,
    validate_constraint_support,
    validate_grant_binding,
    validate_policy_request_binding,
    validate_record,
    validate_scope_narrowing,
)

OTHER_UUID = "018f0000-0000-7000-8000-000000000999"
OTHER_TENANT = "018f0000-0000-7000-8000-000000000998"
GRANT_ACCEPTANCE_TIME = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)

ACTION_STATUSES = ("succeeded", "failed", "indeterminate", "cancelled")
ACTION_EFFECT_STATES = (
    "proposed",
    "decided",
    "approved",
    "grant_issued",
    "prepared",
    "dispatched",
    "succeeded",
    "failed",
    "indeterminate",
)
VALID_ACTION_COMBINATIONS = {
    ("succeeded", "succeeded"),
    ("failed", "failed"),
    ("indeterminate", "indeterminate"),
    ("cancelled", "proposed"),
    ("cancelled", "decided"),
    ("cancelled", "approved"),
    ("cancelled", "grant_issued"),
    ("cancelled", "prepared"),
}
INVALID_ACTION_COMBINATIONS = tuple(
    (status, effect)
    for status in ACTION_STATUSES
    for effect in ACTION_EFFECT_STATES
    if (status, effect) not in VALID_ACTION_COMBINATIONS
)

DELETION_MODES = ("preview", "confirmed")
DELETION_STATUSES = ("previewed", "deleted", "duplicate_replayed", "rejected")
VALID_DELETION_COMBINATIONS = {
    ("preview", "previewed", False),
    ("preview", "rejected", False),
    ("confirmed", "deleted", True),
    ("confirmed", "duplicate_replayed", True),
    ("confirmed", "rejected", False),
}
INVALID_DELETION_COMBINATIONS = tuple(
    (mode, status, has_tombstones)
    for mode in DELETION_MODES
    for status in DELETION_STATUSES
    for has_tombstones in (False, True)
    if (mode, status, has_tombstones) not in VALID_DELETION_COMBINATIONS
)


def _validate_fixture_grant(
    grant: dict[str, Any],
    request: dict[str, Any],
    policy: dict[str, Any],
    approvals: list[dict[str, Any]],
    *,
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    validate_grant_binding(
        grant,
        request,
        policy,
        approvals,
        constraint_registry=constraint_registry,
        verifier=verifier,
        trust=trust_factory(now=GRANT_ACCEPTANCE_TIME),
    )


def test_mutated_tool_request_after_policy_decision_fails_binding(
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    request = records["tool_request"]
    policy = records["policy_decision"]
    original_policy_digest = policy["request_digest"]
    request["arguments"]["input"] = "mutated-after-decision"
    redigest(request)

    MODEL_BY_RECORD_TYPE["tool_request"](request)
    assert request["request_digest"] != original_policy_digest
    with pytest.raises(SemanticError, match="request_digest"):
        validate_policy_request_binding(policy, request)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("actor_id", OTHER_UUID),
        ("run_id", OTHER_UUID),
        ("request_id", OTHER_UUID),
        ("request_digest", "sha256:" + "9" * 64),
        ("tool_id", "other.tool"),
        ("tool_version", "2.0"),
    ],
)
def test_grant_request_tool_and_version_mismatches_fail_closed(
    field: str,
    replacement: str,
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    grant = records["authorization_grant"]
    grant[field] = replacement
    redigest(grant)

    MODEL_BY_RECORD_TYPE["authorization_grant"](grant)
    with pytest.raises(SemanticError, match=field):
        _validate_fixture_grant(
            grant,
            records["tool_request"],
            records["policy_decision"],
            [records["approval_record"]],
            constraint_registry=constraint_registry,
            verifier=verifier,
            trust_factory=trust_factory,
        )


def test_cross_tenant_grant_fails_closed(
    records: dict[str, dict[str, Any]],
    rebind_tenant: Callable[[dict[str, Any], str], dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    grant = rebind_tenant(records["authorization_grant"], OTHER_TENANT)
    MODEL_BY_RECORD_TYPE["authorization_grant"](grant, expected_tenant=OTHER_TENANT)

    with pytest.raises(SemanticError, match="tenant_id"):
        _validate_fixture_grant(
            grant,
            records["tool_request"],
            records["policy_decision"],
            [records["approval_record"]],
            constraint_registry=constraint_registry,
            verifier=verifier,
            trust_factory=trust_factory,
        )


def test_grant_binding_verifies_approval_and_grant_authority(
    records: dict[str, dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    _validate_fixture_grant(
        records["authorization_grant"],
        records["tool_request"],
        records["policy_decision"],
        [records["approval_record"]],
        constraint_registry=constraint_registry,
        verifier=verifier,
        trust_factory=trust_factory,
    )

    assert [call["proof_domain"] for call in verifier.calls] == [
        "approval_record.v1",
        "authorization_grant.v1",
    ]


def test_approval_binding_rejects_policy_and_request_confusion(
    records: dict[str, dict[str, Any]],
) -> None:
    approval = records["approval_record"]
    approval["policy_decision_id"] = OTHER_UUID
    with pytest.raises(SemanticError, match="policy_decision_id"):
        validate_approval_binding(
            approval,
            records["policy_decision"],
            records["tool_request"],
        )


@pytest.mark.parametrize("record_type", ["approval_record", "authorization_grant"])
def test_approval_and_grant_reject_non_forward_expiry(
    record_type: str,
    record_copy: Any,
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    record = record_copy(record_type)
    record["expires_at"] = record["issued_at"]
    redigest(record)
    with pytest.raises(SemanticError, match="issued_at must be before expires_at"):
        MODEL_BY_RECORD_TYPE[record_type](record)


@pytest.mark.parametrize("record_type", ["approval_record", "authorization_grant"])
def test_approval_and_grant_reject_malformed_expiry(
    record_type: str,
    record_copy: Any,
) -> None:
    record = record_copy(record_type)
    record["expires_at"] = "not-a-timestamp"
    with pytest.raises(SchemaError, match="expires_at"):
        MODEL_BY_RECORD_TYPE[record_type](record, verify_self_digests=False)


def test_grant_cannot_be_issued_after_approval_expiry(
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    approval = records["approval_record"]
    grant = records["authorization_grant"]
    approval["expires_at"] = "2026-01-01T00:10:30.000Z"
    redigest(approval)
    grant["approval_refs"][0]["record_digest"] = approval["approval_digest"]
    redigest(grant)

    with pytest.raises(SemanticError, match="issued after its approval expired"):
        _validate_fixture_grant(
            grant,
            records["tool_request"],
            records["policy_decision"],
            [approval],
            constraint_registry=constraint_registry,
            verifier=verifier,
            trust_factory=trust_factory,
        )


def test_grant_cannot_outlive_approval(
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    approval = records["approval_record"]
    grant = records["authorization_grant"]
    approval["expires_at"] = "2026-01-01T00:15:00.000Z"
    redigest(approval)
    grant["approval_refs"][0]["record_digest"] = approval["approval_digest"]
    redigest(grant)

    with pytest.raises(SemanticError, match="outlives its approval"):
        _validate_fixture_grant(
            grant,
            records["tool_request"],
            records["policy_decision"],
            [approval],
            constraint_registry=constraint_registry,
            verifier=verifier,
            trust_factory=trust_factory,
        )


def test_grant_expired_before_policy_decision_cannot_bind(
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    grant = records["authorization_grant"]
    grant["issued_at"] = "2026-01-01T00:08:30.000Z"
    grant["expires_at"] = "2026-01-01T00:08:45.000Z"
    redigest(grant)
    MODEL_BY_RECORD_TYPE["authorization_grant"](grant)

    with pytest.raises(SemanticError, match="grant predates its policy decision"):
        _validate_fixture_grant(
            grant,
            records["tool_request"],
            records["policy_decision"],
            [records["approval_record"]],
            constraint_registry=constraint_registry,
            verifier=verifier,
            trust_factory=trust_factory,
        )


def test_grant_isolation_must_exactly_match_policy(
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    grant = records["authorization_grant"]
    grant["isolation_profile"] = "microvm"
    redigest(grant)
    MODEL_BY_RECORD_TYPE["authorization_grant"](grant)

    with pytest.raises(SemanticError, match="isolation_profile.*exactly match"):
        _validate_fixture_grant(
            grant,
            records["tool_request"],
            records["policy_decision"],
            [records["approval_record"]],
            constraint_registry=constraint_registry,
            verifier=verifier,
            trust_factory=trust_factory,
        )
    assert verifier.calls == []


@pytest.mark.parametrize(
    ("decision", "isolation_profile", "error"),
    [
        ("deny", "container", "policy disposition"),
        ("transform", "container", "policy disposition"),
        ("authorize", "no_effect", "no-effect policy"),
    ],
)
def test_non_authorizing_policy_dispositions_cannot_grant(
    decision: str,
    isolation_profile: str,
    error: str,
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    constraint_registry: ConstraintRegistry,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    policy = records["policy_decision"]
    grant = records["authorization_grant"]
    approval = records["approval_record"]
    policy["decision"] = decision
    policy["isolation_profile"] = isolation_profile
    if decision == "transform":
        policy["transformed_request_ref"] = {
            "record_type": "tool_request",
            "record_id": records["tool_request"]["request_id"],
            "record_digest": records["tool_request"]["request_digest"],
        }
    redigest(policy)
    approval["policy_decision_digest"] = policy["decision_digest"]
    redigest(approval)
    grant["policy_decision_digest"] = policy["decision_digest"]
    grant["approval_refs"][0]["record_digest"] = approval["approval_digest"]
    if isolation_profile != "no_effect":
        grant["isolation_profile"] = isolation_profile
    redigest(grant)
    MODEL_BY_RECORD_TYPE["policy_decision"](policy)
    MODEL_BY_RECORD_TYPE["authorization_grant"](grant)

    with pytest.raises(SemanticError, match=error):
        _validate_fixture_grant(
            grant,
            records["tool_request"],
            policy,
            [approval],
            constraint_registry=constraint_registry,
            verifier=verifier,
            trust_factory=trust_factory,
        )
    assert verifier.calls == []


def test_unknown_constraint_id_and_version_fail_closed(
    record_copy: Any,
) -> None:
    policy = record_copy("policy_decision")
    unsupported = ConstraintRegistry({})
    wrong_version = ConstraintRegistry({"example.org/max_actions": frozenset({"2.0"})})

    with pytest.raises(SemanticError, match="unsupported constraint"):
        validate_constraint_support(policy, unsupported)
    with pytest.raises(SemanticError, match="unsupported constraint"):
        validate_constraint_support(policy, wrong_version)


def test_constraint_parameter_mutation_without_digest_is_rejected(record_copy: Any) -> None:
    policy = record_copy("policy_decision")
    policy["constraints"][0]["parameters"]["maximum"] = 2
    apply_object_digest(policy)
    with pytest.raises(SemanticError, match="parameters_digest"):
        validate_record(policy)


def test_conflicting_idempotency_reuse_fails_but_exact_replay_succeeds(
    record_copy: Any,
) -> None:
    binding = record_copy("tool_request")["idempotency"]
    conflict = copy.deepcopy(binding)
    conflict["operation_digest"] = sha256_digest({"different": "operation"})

    assert compare_idempotency_bindings(None, binding) is IdempotencyResult.NEW
    assert compare_idempotency_bindings(binding, copy.deepcopy(binding)) is IdempotencyResult.REPLAY
    with pytest.raises(IdempotencyConflictError, match="already bound"):
        compare_idempotency_bindings(binding, conflict)


def test_idempotency_key_is_tenant_scoped(record_copy: Any) -> None:
    binding = record_copy("tool_request")["idempotency"]
    other_tenant = copy.deepcopy(binding)
    other_tenant["tenant_id"] = OTHER_TENANT
    assert compare_idempotency_bindings(binding, other_tenant) is IdempotencyResult.NEW


def _scope_derived_from_actor(
    actor: dict[str, Any],
    template: dict[str, Any],
    selection: dict[str, Any],
) -> dict[str, Any]:
    scope = copy.deepcopy(template)
    scope["tenant_id"] = actor["tenant_id"]
    scope["actor_id"] = actor["actor_id"]
    scope["parent_record_type"] = "actor_context"
    scope["parent_digest"] = sha256_digest(actor)
    scope["selection"] = selection
    return scope


def _scope_derived_from_scope(
    parent: dict[str, Any],
    *,
    derived_at: str,
    valid_until: str,
) -> dict[str, Any]:
    child = copy.deepcopy(parent)
    child["scope_id"] = OTHER_UUID
    child["parent_record_type"] = "memory_scope"
    child["parent_digest"] = sha256_digest(parent)
    child["derived_at"] = derived_at
    child["valid_until"] = valid_until
    return child


def test_memory_scope_record_rejects_derivation_after_validity(record_copy: Any) -> None:
    scope = record_copy("memory_scope")
    scope["derived_at"] = "2026-01-01T01:00:00.001Z"

    with pytest.raises(SemanticError, match="derived_at must be not after valid_until"):
        MODEL_BY_RECORD_TYPE["memory_scope"](scope)


@pytest.mark.parametrize(
    ("derived_at", "valid_until"),
    [
        ("2026-01-01T00:00:00.999Z", "2026-01-01T00:30:00.000Z"),
        ("2026-01-01T01:00:00.001Z", "2026-01-01T01:00:00.002Z"),
        ("2026-01-01T00:30:00.000Z", "2026-01-01T01:00:00.001Z"),
    ],
    ids=("before-actor-issue", "after-actor-expiry", "outlives-actor"),
)
def test_actor_scope_validity_must_be_bounded_by_actor_context(
    derived_at: str,
    valid_until: str,
    record_copy: Any,
) -> None:
    actor = record_copy("actor_context")
    scope = _scope_derived_from_actor(actor, record_copy("memory_scope"), {"level": "actor"})
    scope["derived_at"] = derived_at
    scope["valid_until"] = valid_until

    with pytest.raises(SemanticError, match="bounded by its ActorContext"):
        validate_scope_narrowing(scope, actor)


def test_actor_scope_accepts_valid_bounded_window(record_copy: Any) -> None:
    actor = record_copy("actor_context")
    scope = _scope_derived_from_actor(actor, record_copy("memory_scope"), {"level": "actor"})
    scope["derived_at"] = actor["issued_at"]
    scope["valid_until"] = actor["expires_at"]

    MODEL_BY_RECORD_TYPE["memory_scope"](scope)
    validate_scope_narrowing(scope, actor)


@pytest.mark.parametrize(
    ("derived_at", "valid_until"),
    [
        ("2026-01-01T00:00:01.999Z", "2026-01-01T00:30:00.000Z"),
        ("2026-01-01T01:00:00.001Z", "2026-01-01T01:00:00.002Z"),
        ("2026-01-01T00:30:00.000Z", "2026-01-01T01:00:00.001Z"),
    ],
    ids=("before-parent-window", "after-parent-window", "outlives-parent"),
)
def test_child_scope_validity_must_be_bounded_by_parent_scope(
    derived_at: str,
    valid_until: str,
    record_copy: Any,
) -> None:
    parent = record_copy("memory_scope")
    child = _scope_derived_from_scope(
        parent,
        derived_at=derived_at,
        valid_until=valid_until,
    )

    with pytest.raises(SemanticError, match="bounded by its parent scope"):
        validate_scope_narrowing(child, parent)


def test_child_scope_accepts_valid_bounded_window(record_copy: Any) -> None:
    parent = record_copy("memory_scope")
    child = _scope_derived_from_scope(
        parent,
        derived_at="2026-01-01T00:15:00.000Z",
        valid_until="2026-01-01T00:45:00.000Z",
    )

    MODEL_BY_RECORD_TYPE["memory_scope"](child)
    validate_scope_narrowing(child, parent)


@pytest.mark.parametrize(
    "level",
    ["actor", "session", "user", "team", "organization", "project", "workspace", "public"],
)
def test_actor_context_allows_every_authorized_scope_selection(
    level: str,
    record_copy: Any,
) -> None:
    actor = record_copy("actor_context")
    authority = actor["scope_authority"]
    selections = {
        "actor": {"level": "actor"},
        "session": {"level": "session", "session_id": actor["session_id"]},
        "user": {"level": "user", "user_id": authority["user_id"]},
        "team": {"level": "team", "team_id": authority["team_ids"][0]},
        "organization": {
            "level": "organization",
            "organization_id": authority["organization_ids"][0],
        },
        "project": {"level": "project", "project_id": authority["project_ids"][0]},
        "workspace": {
            "level": "workspace",
            "workspace_id": authority["workspace_ids"][0],
        },
        "public": {"level": "public"},
    }
    scope = _scope_derived_from_actor(actor, record_copy("memory_scope"), selections[level])

    MODEL_BY_RECORD_TYPE["memory_scope"](scope)
    validate_scope_narrowing(scope, actor)


def test_actor_context_rejects_scope_level_not_explicitly_authorized(record_copy: Any) -> None:
    actor = record_copy("actor_context")
    actor["scope_authority"]["allowed_levels"].remove("project")
    scope = _scope_derived_from_actor(
        actor,
        record_copy("memory_scope"),
        {"level": "project", "project_id": actor["scope_authority"]["project_ids"][0]},
    )

    with pytest.raises(SemanticError, match="not explicitly authorized"):
        validate_scope_narrowing(scope, actor)


@pytest.mark.parametrize(
    ("level", "id_field"),
    [
        ("session", "session_id"),
        ("user", "user_id"),
        ("team", "team_id"),
        ("organization", "organization_id"),
        ("project", "project_id"),
        ("workspace", "workspace_id"),
    ],
)
def test_actor_context_rejects_unauthorized_scope_identifier(
    level: str,
    id_field: str,
    record_copy: Any,
) -> None:
    actor = record_copy("actor_context")
    scope = _scope_derived_from_actor(
        actor,
        record_copy("memory_scope"),
        {"level": level, id_field: OTHER_UUID},
    )

    with pytest.raises(SemanticError, match=id_field):
        validate_scope_narrowing(scope, actor)


def test_actor_context_rejects_unauthorized_public_scope(record_copy: Any) -> None:
    actor = record_copy("actor_context")
    actor["scope_authority"]["public_allowed"] = False
    scope = _scope_derived_from_actor(
        actor,
        record_copy("memory_scope"),
        {"level": "public"},
    )

    with pytest.raises(SemanticError, match="public scope selection is not authorized"):
        validate_scope_narrowing(scope, actor)


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("parent_record_type", "memory_scope", "immediate parent"),
        ("parent_digest", "sha256:" + "9" * 64, "parent_digest"),
    ],
)
def test_scope_rejects_wrong_immediate_parent_type_or_digest(
    field: str,
    replacement: str,
    error: str,
    record_copy: Any,
) -> None:
    actor = record_copy("actor_context")
    scope = _scope_derived_from_actor(
        actor,
        record_copy("memory_scope"),
        {"level": "actor"},
    )
    scope[field] = replacement

    with pytest.raises(SemanticError, match=error):
        validate_scope_narrowing(scope, actor)


def test_child_scope_must_preserve_parent_selection(record_copy: Any) -> None:
    parent = record_copy("memory_scope")
    child = copy.deepcopy(parent)
    child["parent_record_type"] = "memory_scope"
    child["parent_digest"] = sha256_digest(parent)
    child["selection"] = {
        "level": "team",
        "team_id": "018f0000-0000-7000-8000-00000000002c",
    }

    with pytest.raises(SemanticError, match="exactly equal parent selection"):
        validate_scope_narrowing(child, parent)


def test_scope_actor_binding_is_mandatory(record_copy: Any) -> None:
    actor = record_copy("actor_context")
    scope = _scope_derived_from_actor(
        actor,
        record_copy("memory_scope"),
        {"level": "actor"},
    )
    scope["actor_id"] = OTHER_UUID

    with pytest.raises(SemanticError, match="scope actor"):
        validate_scope_narrowing(scope, actor)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("payload_digest", "sha256:ABC", "pattern"),
        ("uri", "relative/payload", "absolute"),
        ("uri", "blob://tenant/bad%2", "percent encoding"),
        ("uri", "blob://tenant/has space", "whitespace"),
        ("size_bytes", -1, "below minimum"),
    ],
)
def test_malformed_protected_payload_reference_fields_fail_closed(
    field: str,
    value: Any,
    error: str,
    record_copy: Any,
) -> None:
    draft = record_copy("evidence_draft")
    del draft["inline_payload"]
    draft["protected_payload"] = {
        "tenant_id": draft["tenant_id"],
        "uri": "blob://tenant/payload",
        "payload_digest": "sha256:" + "0" * 64,
        "size_bytes": 128,
        "media_type": "application/json",
        "encryption_key_id": "fixture.key.v1",
        "retention_until": "2027-01-01T00:00:00.000Z",
    }
    draft["protected_payload"][field] = value
    with pytest.raises(SchemaError, match=error):
        MODEL_BY_RECORD_TYPE["evidence_draft"](draft, verify_self_digests=False)


def test_protected_payload_reference_is_tenant_bound(record_copy: Any) -> None:
    draft = record_copy("evidence_draft")
    del draft["inline_payload"]
    draft["protected_payload"] = {
        "tenant_id": OTHER_TENANT,
        "uri": "blob://tenant/payload",
        "payload_digest": "sha256:" + "0" * 64,
        "size_bytes": 128,
        "media_type": "application/json",
        "encryption_key_id": "fixture.key.v1",
        "retention_until": "2027-01-01T00:00:00.000Z",
    }
    DEFAULT_SCHEMA_STORE.validate_record(draft)
    with pytest.raises(SemanticError, match="nested tenant"):
        MODEL_BY_RECORD_TYPE["evidence_draft"](draft)


def test_extension_key_count_and_exact_byte_limit_fail_closed(record_copy: Any) -> None:
    too_many = record_copy("actor_context")
    too_many["extensions"] = {f"example.org/key_{index}": index for index in range(17)}
    with pytest.raises(SchemaError, match="more than maxProperties"):
        MODEL_BY_RECORD_TYPE["actor_context"](too_many)

    too_large = record_copy("actor_context")
    value = {f"part_{index}": "x" * 256 for index in range(4)}
    too_large["extensions"] = {
        f"example.org/key_{index}": copy.deepcopy(value) for index in range(16)
    }
    DEFAULT_SCHEMA_STORE.validate_record(too_large)
    with pytest.raises(SemanticError, match="8192 bytes"):
        MODEL_BY_RECORD_TYPE["actor_context"](too_large)


def test_memory_record_visibility_must_equal_scope_selection(
    record_copy: Any,
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    record = record_copy("memory_record")
    record["visibility"] = "team"
    redigest(record)

    with pytest.raises(SemanticError, match="visibility.*scope selection level"):
        MODEL_BY_RECORD_TYPE["memory_record"](record)


def test_memory_proposal_target_scope_must_equal_proposed_record_scope(
    record_copy: Any,
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    proposal = record_copy("memory_proposal")
    proposal["target_scope"]["scope_id"] = OTHER_UUID
    redigest(proposal)

    with pytest.raises(SemanticError, match="target_scope.*exactly equal"):
        MODEL_BY_RECORD_TYPE["memory_proposal"](proposal)


def test_memory_proposal_nested_record_must_remain_candidate(
    record_copy: Any,
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    proposal = record_copy("memory_proposal")
    proposal["proposed_record"]["lifecycle_state"] = "active"
    redigest(proposal)

    with pytest.raises(SchemaError, match="constant"):
        DEFAULT_SCHEMA_STORE.validate_record(proposal, "memory_proposal")
    with pytest.raises(SchemaError, match="constant"):
        MODEL_BY_RECORD_TYPE["memory_proposal"](proposal)


def test_invalid_state_combination_matrices_are_exhaustive() -> None:
    assert len(VALID_ACTION_COMBINATIONS) + len(INVALID_ACTION_COMBINATIONS) == 36
    assert len(INVALID_ACTION_COMBINATIONS) == 28
    assert len(VALID_DELETION_COMBINATIONS) + len(INVALID_DELETION_COMBINATIONS) == 16
    assert len(INVALID_DELETION_COMBINATIONS) == 11


@pytest.mark.parametrize(
    ("status", "effect_state"),
    INVALID_ACTION_COMBINATIONS,
    ids=lambda values: str(values),
)
def test_every_invalid_action_outcome_status_effect_combination_fails_schema_and_model(
    status: str,
    effect_state: str,
    record_copy: Any,
) -> None:
    outcome = record_copy("action_outcome")
    outcome["status"] = status
    outcome["effect_state"] = effect_state

    with pytest.raises(SchemaError, match="oneOf"):
        DEFAULT_SCHEMA_STORE.validate_record(outcome, "action_outcome")
    with pytest.raises(SchemaError, match="oneOf"):
        MODEL_BY_RECORD_TYPE["action_outcome"](outcome, verify_self_digests=False)


@pytest.mark.parametrize(
    ("mode", "status", "has_tombstones"),
    INVALID_DELETION_COMBINATIONS,
    ids=lambda values: str(values),
)
def test_every_invalid_deletion_receipt_combination_fails_schema_and_model(
    mode: str,
    status: str,
    has_tombstones: bool,
    record_copy: Any,
) -> None:
    receipt = record_copy("deletion_receipt")
    receipt["mode"] = mode
    receipt["status"] = status
    if has_tombstones:
        receipt["tombstone_refs"] = copy.deepcopy(receipt["target_refs"])
    else:
        receipt.pop("tombstone_refs", None)

    with pytest.raises(SchemaError, match="oneOf"):
        DEFAULT_SCHEMA_STORE.validate_record(receipt, "deletion_receipt")
    with pytest.raises(SchemaError, match="oneOf"):
        MODEL_BY_RECORD_TYPE["deletion_receipt"](receipt, verify_self_digests=False)


def test_truth_confidence_is_distinct_from_task_quality(record_copy: Any) -> None:
    proposal = record_copy("memory_proposal")
    assert (
        proposal["truth_confidence"]["value_millionths"]
        != proposal["task_quality"]["score_millionths"]
    )
    MODEL_BY_RECORD_TYPE["memory_proposal"](proposal)

    for field in ("truth_confidence", "task_quality"):
        incomplete = record_copy("memory_proposal")
        del incomplete[field]
        with pytest.raises(SchemaError, match=field):
            MODEL_BY_RECORD_TYPE["memory_proposal"](incomplete, verify_self_digests=False)

    swapped = record_copy("memory_proposal")
    swapped["truth_confidence"] = copy.deepcopy(swapped["task_quality"])
    with pytest.raises(SchemaError):
        MODEL_BY_RECORD_TYPE["memory_proposal"](swapped, verify_self_digests=False)


@pytest.mark.parametrize("record_type", ["skill_proposal", "policy_proposal"])
def test_legacy_applied_is_not_a_v1_lifecycle_state(
    record_type: str,
    record_copy: Any,
) -> None:
    proposal = record_copy(record_type)
    proposal["lifecycle_state"] = "applied"
    with pytest.raises(SchemaError, match="enum"):
        MODEL_BY_RECORD_TYPE[record_type](proposal, verify_self_digests=False)


def test_legacy_exported_delivery_never_activates(
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery = records["delivery_envelope"]
    delivery["lifecycle_state"] = "legacy_exported"
    redigest(delivery)
    assert not learning_artifact_is_active(
        delivery,
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(),
        expected_tenant=delivery["tenant_id"],
    )
    assert verifier.calls == []
