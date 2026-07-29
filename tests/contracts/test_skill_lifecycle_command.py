"""Adversarial proof for the canonical inert-skill authority command."""

from __future__ import annotations

import copy
import json

import pytest

from governed_agent_harness.contracts import apply_object_digest, sha256_digest
from governed_agent_harness.contracts.errors import SemanticError
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.contracts.validation import validate_skill_lifecycle_command
from governed_agent_harness.persistence.skills import (
    PostgresSkillLifecycleAuthority,
    SkillLifecycleState,
    _result,
    build_skill_lifecycle_wire_command,
)


def _ref(record_type: str, record_id: str, digest: str) -> dict[str, str]:
    return {"record_type": record_type, "record_id": record_id, "record_digest": digest}


def _command() -> tuple[dict[str, object], dict[str, object]]:
    records = build_positive_records()
    actor = copy.deepcopy(records["actor_context"])
    proposal = copy.deepcopy(records["skill_proposal"])
    gate = copy.deepcopy(records["gate_decision"])
    delivery = copy.deepcopy(records["delivery_envelope"])
    policy = copy.deepcopy(records["policy_decision"])
    evidence = copy.deepcopy(records["evidence_envelope"])
    proposal["target_scope"]["selection"] = {"level": "actor"}
    gate["target_scope"] = copy.deepcopy(proposal["target_scope"])
    delivery["target_scope"] = copy.deepcopy(proposal["target_scope"])
    apply_object_digest(proposal)
    policy.update(
        {
            "request_id": proposal["proposal_id"],
            "request_digest": proposal["proposal_digest"],
            "decision": "authorize",
            "constraints": [],
            "isolation_profile": "no_effect",
        }
    )
    apply_object_digest(policy)
    policy_ref = _ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    gate["proposal_refs"] = [
        _ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
    ]
    apply_object_digest(gate)
    delivery.update(
        {
            "artifact_digest": sha256_digest(proposal["artifact"]),
            "gate_decision_ref": _ref("gate_decision", gate["gate_id"], gate["decision_digest"]),
            "policy_refs": [policy_ref],
            "reviewer_refs": copy.deepcopy(proposal["reviewer_refs"]),
        }
    )
    apply_object_digest(delivery)
    command: dict[str, object] = {
        "operation_id": "skill-install-1",
        "expected_revision": None,
        "skill_proposal": proposal,
        "artifact": copy.deepcopy(proposal["artifact"]),
        "gate_decision": gate,
        "delivery_envelope": delivery,
        "policy_decision": policy,
        "approvals": [],
        "source_evidence": [evidence],
        "retention": {"expires_at": "2030-01-01T00:00:00.000Z"},
        "validity": {"expires_at": "2030-01-01T00:00:00.000Z"},
        "activation_receipt": None,
        "rollback_receipt": None,
    }
    return actor, command


def test_canonical_wire_command_binds_every_mutable_lifecycle_input() -> None:
    actor, command = _command()
    wire = build_skill_lifecycle_wire_command("install", command)
    digest = validate_skill_lifecycle_command(actor_context=actor, command=wire)
    assert digest == wire["operation_digest"]

    changed = copy.deepcopy(wire)
    changed["retention"]["expires_at"] = "2031-01-01T00:00:00.000Z"
    with pytest.raises(SemanticError, match="operation_digest"):
        validate_skill_lifecycle_command(actor_context=actor, command=changed)


@pytest.mark.parametrize("invalid_operation", (["install"], {"operation": "install"}))
def test_lifecycle_operation_shape_is_normalized_to_semantic_error(
    invalid_operation: object,
) -> None:
    actor, command = _command()
    wire = build_skill_lifecycle_wire_command("install", command)
    wire["operation"] = invalid_operation
    with pytest.raises(SemanticError, match="unknown skill lifecycle operation"):
        validate_skill_lifecycle_command(actor_context=actor, command=wire)


def test_missing_lifecycle_operation_is_normalized_to_semantic_error() -> None:
    actor, command = _command()
    wire = build_skill_lifecycle_wire_command("install", command)
    del wire["operation"]
    with pytest.raises(SemanticError, match="unknown skill lifecycle operation"):
        validate_skill_lifecycle_command(actor_context=actor, command=wire)


def test_rejects_noncanonical_source_evidence_and_invented_artifact_fields() -> None:
    actor, command = _command()
    wire = build_skill_lifecycle_wire_command("install", command)
    wire["source_evidence"] = []
    wire["operation_digest"] = sha256_digest(
        {key: value for key, value in wire.items() if key != "operation_digest"}
    )
    with pytest.raises(SemanticError, match="source evidence"):
        validate_skill_lifecycle_command(actor_context=actor, command=wire)

    actor, command = _command()
    command["artifact"]["entrypoint"] = "unsafe.py"
    wire = build_skill_lifecycle_wire_command("install", command)
    with pytest.raises(SemanticError, match="inert"):
        validate_skill_lifecycle_command(actor_context=actor, command=wire)


def test_rejects_non_actor_skill_lifecycle_scope() -> None:
    actor, command = _command()
    proposal = command["skill_proposal"]
    proposal["target_scope"]["selection"] = {
        "level": "project",
        "project_id": actor["scope_authority"]["project_ids"][0],
    }
    apply_object_digest(proposal)

    policy = command["policy_decision"]
    policy["request_digest"] = proposal["proposal_digest"]
    apply_object_digest(policy)
    policy_ref = _ref("policy_decision", policy["decision_id"], policy["decision_digest"])

    gate = command["gate_decision"]
    gate["target_scope"] = copy.deepcopy(proposal["target_scope"])
    gate["proposal_refs"] = [
        _ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
    ]
    apply_object_digest(gate)

    delivery = command["delivery_envelope"]
    delivery["target_scope"] = copy.deepcopy(proposal["target_scope"])
    delivery["policy_refs"] = [policy_ref]
    delivery["gate_decision_ref"] = _ref("gate_decision", gate["gate_id"], gate["decision_digest"])
    apply_object_digest(delivery)

    with pytest.raises(SemanticError, match="actor-only"):
        validate_skill_lifecycle_command(
            actor_context=actor,
            command=build_skill_lifecycle_wire_command("install", command),
        )


def test_approval_constraints_and_separation_are_bound_to_skill_authority() -> None:
    actor, command = _command()
    records = build_positive_records()
    approval = copy.deepcopy(records["approval_record"])
    policy = command["policy_decision"]
    policy["decision"] = "require_approval"
    policy["constraints"] = []
    apply_object_digest(policy)
    approval.update(
        {
            "request_id": command["skill_proposal"]["proposal_id"],
            "request_digest": command["skill_proposal"]["proposal_digest"],
            "policy_decision_id": policy["decision_id"],
            "policy_decision_digest": policy["decision_digest"],
            "constraints": [],
        }
    )
    apply_object_digest(approval)
    approval_ref = _ref("approval_record", approval["approval_id"], approval["approval_digest"])
    delivery = command["delivery_envelope"]
    delivery["policy_refs"] = [
        _ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    ]
    delivery["reviewer_refs"] = [approval_ref]
    apply_object_digest(delivery)
    command["approvals"] = [approval]

    wire = build_skill_lifecycle_wire_command("install", command)
    validate_skill_lifecycle_command(actor_context=actor, command=wire)

    changed = copy.deepcopy(command)
    changed["approvals"][0]["separation_of_duties"]["satisfied"] = False
    apply_object_digest(changed["approvals"][0])
    changed["delivery_envelope"]["reviewer_refs"] = [
        _ref(
            "approval_record",
            changed["approvals"][0]["approval_id"],
            changed["approvals"][0]["approval_digest"],
        )
    ]
    apply_object_digest(changed["delivery_envelope"])
    with pytest.raises(SemanticError, match="separation"):
        validate_skill_lifecycle_command(
            actor_context=actor,
            command=build_skill_lifecycle_wire_command("install", changed),
        )

    unsupported = copy.deepcopy(command)
    unsupported_policy = unsupported["policy_decision"]
    unsupported_policy["constraints"] = copy.deepcopy(records["approval_record"]["constraints"])
    apply_object_digest(unsupported_policy)
    unsupported_approval = unsupported["approvals"][0]
    unsupported_approval["policy_decision_digest"] = unsupported_policy["decision_digest"]
    unsupported_approval["constraints"] = copy.deepcopy(unsupported_policy["constraints"])
    apply_object_digest(unsupported_approval)
    unsupported_delivery = unsupported["delivery_envelope"]
    unsupported_delivery["policy_refs"] = [
        _ref(
            "policy_decision",
            unsupported_policy["decision_id"],
            unsupported_policy["decision_digest"],
        )
    ]
    unsupported_delivery["reviewer_refs"] = [
        _ref(
            "approval_record",
            unsupported_approval["approval_id"],
            unsupported_approval["approval_digest"],
        )
    ]
    apply_object_digest(unsupported_delivery)
    with pytest.raises(SemanticError, match="constraints must be exactly empty"):
        validate_skill_lifecycle_command(
            actor_context=actor,
            command=build_skill_lifecycle_wire_command("install", unsupported),
        )


def test_wrapper_and_sql_receive_one_complete_wire_shape() -> None:
    actor, command = _command()
    captured: dict[str, object] = {}

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def execute(self, query, parameters):
            captured["query"] = str(query)
            captured["parameters"] = parameters
            if "gah_install_skill" in captured["query"]:
                captured["wire"] = json.loads(parameters[1])

        def fetchone(self):
            query = captured["query"]
            if "gah_lock_skill_lifecycle_draft" in query:
                return (None,)
            if "gah_lookup_skill_replay" in query:
                return (None,)
            if "gah_authorize_skill_lifecycle" in query:
                return (
                    {
                        "writer_pid": 12345,
                        "tenant_id": actor["tenant_id"],
                        "actor_id": actor["actor_id"],
                        "session_id": actor["session_id"],
                        "operation_id": command["operation_id"],
                        "operation_digest": "sha256:" + "a" * 64,
                        "expected_transition_sequence": 0,
                        "expected_lifecycle_state": "none",
                    },
                )
            if "gah_skill_lifecycle_evidence_head" in query:
                return (
                    {
                        "next_sequence": 1,
                        "last_event_digest": "sha256:" + "a" * 64,
                        "last_recorded_at": "2026-01-01T00:00:00.000Z",
                        "version": 1,
                    },
                )
            if "gah_lock_run" in query:
                return (
                    {
                        "next_sequence": 0,
                        "last_event_digest": None,
                        "last_recorded_at": None,
                        "version": 0,
                    },
                )
            if "gah_commit_evidence" in query:
                return ({"changed": 1},)
            wire = captured["wire"]
            return (
                {
                    "operation_id": wire["operation_id"],
                    "operation_digest": wire["operation_digest"],
                    "skill_id": wire["skill_proposal"]["artifact_id"],
                    "revision": 1,
                    "lifecycle_state": "installed",
                    "artifact_digest": wire["delivery_envelope"]["artifact_digest"],
                    "transition_digest": wire["transition_evidence"]["event_digest"],
                    "replayed": False,
                },
            )

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def cursor(self):
            return Cursor()

    result = PostgresSkillLifecycleAuthority(
        privileged_connect=Connection,
        evidence_writer_connect=lambda: Connection(),
    ).install_skill(actor_context=actor, **command)
    assert captured["query"] == "SELECT gah_install_skill(%s::jsonb, %s::jsonb)"
    assert set(captured["wire"]) == {
        "operation",
        "operation_id",
        "operation_digest",
        "expected_revision",
        "skill_proposal",
        "artifact",
        "gate_decision",
        "delivery_envelope",
        "policy_decision",
        "approvals",
        "source_evidence",
        "retention",
        "validity",
        "activation_receipt",
        "rollback_receipt",
        "transition_evidence",
    }
    assert result.operation_digest == captured["wire"]["operation_digest"]


def test_rebuild_uses_the_same_result_shape_and_wire_digest() -> None:
    actor, _ = _command()
    command = {"operation_id": "skill-rebuild-1", "expected_revision": 1, "skill_id": "skill-a"}
    wire = build_skill_lifecycle_wire_command("rebuild", command)
    assert (
        validate_skill_lifecycle_command(actor_context=actor, command=wire)
        == wire["operation_digest"]
    )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("revision", 2, "revision"),
        ("lifecycle_state", "active", "state"),
        ("artifact_digest", "sha256:" + "b" * 64, "artifact"),
    ),
)
def test_lifecycle_result_binds_revision_state_and_artifact(field, replacement, message) -> None:
    value = {
        "operation_id": "skill-operation",
        "operation_digest": "sha256:" + "a" * 64,
        "skill_id": "skill-a",
        "revision": 1,
        "lifecycle_state": "installed",
        "artifact_digest": "sha256:" + "c" * 64,
        "transition_digest": "sha256:" + "d" * 64,
        "replayed": False,
    }
    value[field] = replacement
    with pytest.raises(RuntimeError, match=f"unbound {message}"):
        _result(
            value,
            expected_operation_id="skill-operation",
            expected_digest="sha256:" + "a" * 64,
            expected_skill_id="skill-a",
            expected_revision=1,
            expected_state=SkillLifecycleState.INSTALLED,
            expected_artifact_digest="sha256:" + "c" * 64,
            expected_transition_digest="sha256:" + "d" * 64,
        )
