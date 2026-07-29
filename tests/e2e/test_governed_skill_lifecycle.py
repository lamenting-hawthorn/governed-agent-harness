"""PostgreSQL-only public-port proof for inert governed skill installation."""

from __future__ import annotations

import copy
import dataclasses
from datetime import datetime, timedelta, timezone
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from governed_agent_harness.contracts import (
    TrustContext,
    TrustedKey,
    apply_object_digest,
    sha256_digest,
    verify_runtime_receipt,
)
from governed_agent_harness.contracts.errors import SemanticError
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import (
    PostgresActiveSkillResolver,
    PostgresSkillLifecycleAuthority,
)
from governed_agent_harness.persistence.skills import build_skill_lifecycle_wire_command
from skill_lifecycle_support import command as build_command, ref


NOW = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)
RECEIPT_NOW = datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)


def _ids():
    # Keep lifecycle-owned evidence identifiers disjoint from the shared
    # fixture store's small monotonic sequence.
    sequence = 0xA000

    def next_id() -> str:
        nonlocal sequence
        sequence += 1
        return f"018f0000-0000-7000-8000-{sequence:012x}"

    return next_id


def _persisted_command(postgres_connections):
    actor, command = build_command()
    actor["issued_at"] = "2025-01-01T00:00:00.000Z"
    actor["expires_at"] = "2030-01-01T00:00:00.000Z"
    target_scope = command["skill_proposal"]["target_scope"]
    target_scope["parent_digest"] = sha256_digest(actor)
    command["gate_decision"]["target_scope"] = copy.deepcopy(target_scope)
    command["delivery_envelope"]["target_scope"] = copy.deepcopy(target_scope)
    source = postgres_connections["store_at"](NOW).append(
        tenant_id=actor["tenant_id"],
        run_id="018f0000-0000-7000-8000-0000000000b0",
        event_kind="kernel.policy_decided",
        policy_ref={
            "record_type": "policy_decision",
            "record_id": command["policy_decision"]["decision_id"],
            "record_digest": command["policy_decision"]["decision_digest"],
        },
        payload={
            "actor_id": actor["actor_id"],
            "policy_decision_digest": command["policy_decision"]["decision_digest"],
        },
    )
    evidence_ref = ref("evidence_envelope", source["envelope_id"], source["event_digest"])
    command["source_evidence"] = [source]
    proposal = command["skill_proposal"]
    proposal["evidence_refs"] = [evidence_ref]
    apply_object_digest(proposal)
    policy = command["policy_decision"]
    policy["request_digest"] = proposal["proposal_digest"]
    apply_object_digest(policy)
    gate = command["gate_decision"]
    gate["proposal_refs"] = [
        ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
    ]
    apply_object_digest(gate)
    delivery = command["delivery_envelope"]
    delivery.update(
        {
            "evidence_refs": [evidence_ref],
            "policy_refs": [
                ref("policy_decision", policy["decision_id"], policy["decision_digest"])
            ],
            "gate_decision_ref": ref("gate_decision", gate["gate_id"], gate["decision_digest"]),
        }
    )
    apply_object_digest(delivery)
    return actor, command


def _rebind_lifecycle_command(command):
    """Recompute digests without repairing deliberately changed semantics."""

    proposal = command["skill_proposal"]
    apply_object_digest(proposal)
    policy = command["policy_decision"]
    policy["request_digest"] = proposal["proposal_digest"]
    apply_object_digest(policy)
    gate = command["gate_decision"]
    gate["proposal_refs"] = [
        ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
    ]
    apply_object_digest(gate)
    delivery = command["delivery_envelope"]
    delivery["artifact_digest"] = sha256_digest(command["artifact"])
    delivery["gate_decision_ref"] = ref("gate_decision", gate["gate_id"], gate["decision_digest"])
    delivery["policy_refs"] = [
        ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    ]
    apply_object_digest(delivery)


def _mutate_lifecycle_sink_field(command, path, *, missing):
    container = command
    for key in path[:-1]:
        container = container[key]
    if missing:
        container.pop(path[-1], None)
    else:
        container[path[-1]] = None

    root = path[0]
    proposal = command["skill_proposal"]
    policy = command["policy_decision"]
    gate = command["gate_decision"]
    delivery = command["delivery_envelope"]
    if root == "skill_proposal":
        apply_object_digest(proposal)
        policy["request_digest"] = proposal["proposal_digest"]
        apply_object_digest(policy)
        gate["proposal_refs"] = [
            ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
        ]
        apply_object_digest(gate)
        delivery["gate_decision_ref"] = ref(
            "gate_decision", gate["gate_id"], gate["decision_digest"]
        )
        delivery["policy_refs"] = [
            ref("policy_decision", policy["decision_id"], policy["decision_digest"])
        ]
        apply_object_digest(delivery)
    elif root == "gate_decision":
        apply_object_digest(gate)
        delivery["gate_decision_ref"] = ref(
            "gate_decision", gate["gate_id"], gate["decision_digest"]
        )
        apply_object_digest(delivery)
    elif root == "policy_decision":
        apply_object_digest(policy)
        delivery["policy_refs"] = [
            ref("policy_decision", policy["decision_id"], policy["decision_digest"])
        ]
        apply_object_digest(delivery)
    elif root == "delivery_envelope":
        apply_object_digest(delivery)
    elif root == "artifact":
        delivery["artifact_digest"] = sha256_digest(command.get("artifact"))
        apply_object_digest(delivery)


class _AcceptingVerifier:
    def verify(self, **values: object) -> bool:
        return True


def _receipt_trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="runtime.authority",
                key_id="runtime.key.v1",
                algorithms=frozenset({"fixture-proof-v1"}),
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
            ),
        ),
        allowed_algorithms=frozenset({"fixture-proof-v1"}),
        allowed_proof_domains=frozenset({"activation_receipt.v1", "rollback_receipt.v1"}),
        expected_issuers=frozenset({"runtime.authority"}),
        allowed_domain_issuers=frozenset(
            {
                ("activation_receipt.v1", "runtime.authority"),
                ("rollback_receipt.v1", "runtime.authority"),
            }
        ),
        trust_policy_version="skill-lifecycle.test.v1",
    )


def _approval_trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="policy.authority",
                key_id="policy.key.v1",
                algorithms=frozenset({"fixture-proof-v1"}),
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
            ),
        ),
        allowed_algorithms=frozenset({"fixture-proof-v1"}),
        allowed_proof_domains=frozenset({"approval_record.v1"}),
        expected_issuers=frozenset({"policy.authority"}),
        allowed_domain_issuers=frozenset({("approval_record.v1", "policy.authority")}),
        trust_policy_version="skill-lifecycle.approval-test.v1",
    )


def _activation_receipt(command):
    receipt = copy.deepcopy(build_positive_records()["activation_receipt"])
    delivery = command["delivery_envelope"]
    proposal = command["skill_proposal"]
    receipt.update(
        {
            "target_scope": copy.deepcopy(delivery["target_scope"]),
            "delivery_id": delivery["delivery_id"],
            "delivery_digest": delivery["envelope_digest"],
            "artifact_type": delivery["artifact_type"],
            "artifact_id": delivery["artifact_id"],
            "artifact_revision": delivery["artifact_revision"],
            "artifact_digest": delivery["artifact_digest"],
            "activated_revision": ref(
                "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
            ),
            "evidence_refs": copy.deepcopy(delivery["evidence_refs"]),
            "policy_refs": copy.deepcopy(delivery["policy_refs"]),
            "reviewer_refs": copy.deepcopy(delivery["reviewer_refs"]),
        }
    )
    return apply_object_digest(receipt)


def _rollback_receipt(command, activation):
    receipt = copy.deepcopy(build_positive_records()["rollback_receipt"])
    delivery = command["delivery_envelope"]
    proposal = command["skill_proposal"]
    receipt.update(
        {
            "target_scope": copy.deepcopy(activation["target_scope"]),
            "activation_receipt_ref": ref(
                "activation_receipt", activation["receipt_id"], activation["receipt_digest"]
            ),
            "artifact_type": delivery["artifact_type"],
            "artifact_id": delivery["artifact_id"],
            "artifact_revision": delivery["artifact_revision"],
            "artifact_digest": delivery["artifact_digest"],
            "rollback_revision": ref(
                "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
            ),
            "restored_revision_ref": ref(
                "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
            ),
            "evidence_refs": copy.deepcopy(delivery["evidence_refs"]),
            "policy_refs": copy.deepcopy(delivery["policy_refs"]),
            "reviewer_refs": copy.deepcopy(delivery["reviewer_refs"]),
        }
    )
    return apply_object_digest(receipt)


def _rollback_receipt_trust(now, activation, rollback):
    trust = _receipt_trust(now)
    verifier = _AcceptingVerifier()
    activation_history = verify_runtime_receipt(
        activation, verifier=verifier, trust=trust, expected_tenant=activation["tenant_id"]
    )
    rollback_history = verify_runtime_receipt(
        rollback, verifier=verifier, trust=trust, expected_tenant=rollback["tenant_id"]
    )
    return dataclasses.replace(
        trust,
        historical_acceptances=(
            dataclasses.replace(activation_history, ledger_position=1),
            dataclasses.replace(rollback_history, ledger_position=2),
        ),
    )


def test_public_authority_installs_only_schema_valid_evidence_bound_command(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    assert command["skill_proposal"]["target_scope"]["selection"] == {"level": "actor"}
    result = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: NOW,
        ids=_ids(),
    ).install_skill(actor_context=actor, **command)
    assert result.lifecycle_state.value == "installed"
    assert result.replayed is False


def test_replay_is_resolved_before_a_second_lifecycle_evidence_append(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: NOW,
        ids=_ids(),
    )
    first = authority.install_skill(actor_context=actor, **command)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_evidence_events")
        evidence_count = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM gah_skill_lifecycle_transitions")
        transition_count = cursor.fetchone()[0]

    replay = authority.install_skill(actor_context=actor, **command)

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_evidence_events")
        assert cursor.fetchone()[0] == evidence_count
        cursor.execute("SELECT count(*) FROM gah_skill_lifecycle_transitions")
        assert cursor.fetchone()[0] == transition_count
    assert replay.replayed is True
    assert replay.transition_digest == first.transition_digest


def test_exact_lifecycle_replay_precedes_current_validity_validation(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    clock = [RECEIPT_NOW]
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: clock[0],
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **install)
    receipt = _activation_receipt(install)
    receipt["expires_at"] = "2027-01-01T00:00:00.000Z"
    apply_object_digest(receipt)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "skill-expiring-activation-replay",
            "expected_revision": 1,
            "activation_receipt": receipt,
        }
    )
    first = authority.activate_skill(actor_context=actor, **activate)
    clock[0] = datetime(2028, 1, 1, tzinfo=timezone.utc)
    before = _skill_authority_snapshot(postgres_connections)

    replay = authority.activate_skill(actor_context=actor, **activate)

    assert replay.replayed is True
    assert replay.transition_digest == first.transition_digest
    assert _skill_authority_snapshot(postgres_connections) == before

    changed_actor = copy.deepcopy(actor)
    changed_actor["correlation_id"] = "018f0000-0000-7000-8000-00000000ffef"
    with pytest.raises(Exception):
        authority.activate_skill(actor_context=changed_actor, **activate)
    assert _skill_authority_snapshot(postgres_connections) == before


def test_exact_approval_required_replay_survives_approval_expiry(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    policy = command["policy_decision"]
    policy["decision"] = "require_approval"
    apply_object_digest(policy)
    approval = copy.deepcopy(build_positive_records()["approval_record"])
    approval.update(
        {
            "tenant_id": actor["tenant_id"],
            "request_id": command["skill_proposal"]["proposal_id"],
            "request_digest": command["skill_proposal"]["proposal_digest"],
            "policy_decision_id": policy["decision_id"],
            "policy_decision_digest": policy["decision_digest"],
            "constraints": copy.deepcopy(policy["constraints"]),
            "expires_at": "2027-01-01T00:00:00.000Z",
        }
    )
    apply_object_digest(approval)
    command["approvals"] = [approval]
    delivery = command["delivery_envelope"]
    delivery["policy_refs"] = [
        ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    ]
    delivery["reviewer_refs"] = [
        ref("approval_record", approval["approval_id"], approval["approval_digest"])
    ]
    apply_object_digest(delivery)
    clock = [NOW]
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: clock[0],
        ids=_ids(),
        approval_verifier=_AcceptingVerifier(),
        approval_trust=_approval_trust,
    )
    first = authority.install_skill(actor_context=actor, **command)
    clock[0] = datetime(2028, 1, 1, tzinfo=timezone.utc)
    before = _skill_authority_snapshot(postgres_connections)

    replay = authority.install_skill(actor_context=actor, **command)

    assert replay.replayed is True
    assert replay.transition_digest == first.transition_digest
    assert _skill_authority_snapshot(postgres_connections) == before

    changed = copy.deepcopy(command)
    changed["retention"]["expires_at"] = "2027-06-01T00:00:00.000Z"
    with pytest.raises(Exception, match="replay conflicts"):
        authority.install_skill(actor_context=actor, **changed)
    assert _skill_authority_snapshot(postgres_connections) == before


def test_current_approval_rejects_backdated_trust_context_without_mutation(
    postgres_connections,
):
    actor, command = _persisted_command(postgres_connections)
    policy = command["policy_decision"]
    policy["decision"] = "require_approval"
    apply_object_digest(policy)
    approval = copy.deepcopy(build_positive_records()["approval_record"])
    approval.update(
        {
            "tenant_id": actor["tenant_id"],
            "request_id": command["skill_proposal"]["proposal_id"],
            "request_digest": command["skill_proposal"]["proposal_digest"],
            "policy_decision_id": policy["decision_id"],
            "policy_decision_digest": policy["decision_digest"],
            "constraints": copy.deepcopy(policy["constraints"]),
            "expires_at": "2027-01-01T00:00:00.000Z",
        }
    )
    apply_object_digest(approval)
    command["approvals"] = [approval]
    delivery = command["delivery_envelope"]
    delivery["policy_refs"] = [
        ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    ]
    delivery["reviewer_refs"] = [
        ref("approval_record", approval["approval_id"], approval["approval_digest"])
    ]
    apply_object_digest(delivery)
    before = _skill_authority_snapshot(postgres_connections)

    with pytest.raises(SemanticError, match="requested time"):
        PostgresSkillLifecycleAuthority(
            privileged_connect=postgres_connections["skill_authority"],
            evidence_writer_connect=postgres_connections["writer"],
            clock=lambda: NOW,
            ids=_ids(),
            approval_verifier=_AcceptingVerifier(),
            approval_trust=lambda _now: _approval_trust(NOW - timedelta(milliseconds=1)),
        ).install_skill(actor_context=actor, **command)

    assert _skill_authority_snapshot(postgres_connections) == before


def test_current_receipt_rejects_backdated_trust_context_without_mutation(
    postgres_connections,
):
    actor, install = _persisted_command(postgres_connections)
    PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
    ).install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "stale-receipt-trust-context",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install),
        }
    )
    before = _skill_authority_snapshot(postgres_connections)

    with pytest.raises(SemanticError, match="requested time"):
        PostgresSkillLifecycleAuthority(
            privileged_connect=postgres_connections["skill_authority"],
            evidence_writer_connect=postgres_connections["writer"],
            clock=lambda: RECEIPT_NOW,
            ids=_ids(),
            receipt_verifier=_AcceptingVerifier(),
            receipt_trust=lambda _now: _receipt_trust(RECEIPT_NOW - timedelta(milliseconds=1)),
        ).activate_skill(actor_context=actor, **activate)

    assert _skill_authority_snapshot(postgres_connections) == before


def test_e2e_lifecycle_matrix_accepts_canonical_null_optional_receipts(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    installed = authority.install_skill(actor_context=actor, **install)
    assert installed.lifecycle_state.value == "installed"

    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "skill-activate-1",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install),
        }
    )
    active = authority.activate_skill(actor_context=actor, **activate)
    assert active.lifecycle_state.value == "active"
    assert (
        PostgresActiveSkillResolver(
            runtime_connect=postgres_connections["app"]
        ).resolve_active_skill(actor_context=actor, skill_id=active.skill_id)
        is not None
    )

    deactivate = copy.deepcopy(install)
    deactivate.update(
        {
            "operation_id": "skill-deactivate-1",
            "expected_revision": 1,
        }
    )
    inactive = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
    ).deactivate_skill(actor_context=actor, **deactivate)
    assert inactive.lifecycle_state.value == "inactive"
    assert (
        PostgresActiveSkillResolver(
            runtime_connect=postgres_connections["app"]
        ).resolve_active_skill(actor_context=actor, skill_id=inactive.skill_id)
        is None
    )

    rebuilt = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
    ).rebuild_skill_projection(
        actor_context=actor,
        operation_id="skill-rebuild-1",
        expected_revision=1,
        skill_id=inactive.skill_id,
    )
    assert rebuilt.lifecycle_state.value == "inactive"
    replay = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
    ).rebuild_skill_projection(
        actor_context=actor,
        operation_id="skill-rebuild-1",
        expected_revision=1,
        skill_id=inactive.skill_id,
    )
    assert replay.replayed is True
    assert replay.transition_digest == rebuilt.transition_digest
    with pytest.raises(Exception, match="rebuild replay conflicts"):
        PostgresSkillLifecycleAuthority(
            privileged_connect=postgres_connections["skill_authority"],
            evidence_writer_connect=postgres_connections["writer"],
            clock=lambda: RECEIPT_NOW,
        ).rebuild_skill_projection(
            actor_context=actor,
            operation_id="skill-rebuild-1",
            expected_revision=1,
            skill_id="018f0000-0000-7000-8000-0000000000ff",
        )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_skill_projection_rebuilds")
        assert cursor.fetchone()[0] == 1


def test_e2e_rollback_returns_the_selected_artifact_digest(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    activation = _activation_receipt(install)
    rollback = _rollback_receipt(install, activation)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=lambda now: _rollback_receipt_trust(now, activation, rollback),
    )
    authority.install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "skill-activate-rollback-1",
            "expected_revision": 1,
            "activation_receipt": activation,
        }
    )
    authority.activate_skill(actor_context=actor, **activate)
    rollback_command = copy.deepcopy(install)
    rollback_command.update(
        {
            "operation_id": "skill-rollback-selected-digest-1",
            "expected_revision": 1,
            "activation_receipt": activation,
            "rollback_receipt": rollback,
        }
    )
    selected = authority.rollback_skill(actor_context=actor, **rollback_command)
    assert selected.lifecycle_state.value == "active"
    assert selected.artifact_digest == install["delivery_envelope"]["artifact_digest"]
    resolved = PostgresActiveSkillResolver(
        runtime_connect=postgres_connections["app"]
    ).resolve_active_skill(actor_context=actor, skill_id=selected.skill_id)
    assert resolved is not None
    assert resolved.artifact_digest == selected.artifact_digest


def test_rebuild_restores_a_corrupt_projection_only_from_complete_history(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "skill-activate-1",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install),
        }
    )
    active = authority.activate_skill(actor_context=actor, **activate)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM gah_active_skill_projection WHERE tenant_id = %s AND skill_id = %s",
            (actor["tenant_id"], active.skill_id),
        )
    rebuilt = authority.rebuild_skill_projection(
        actor_context=actor,
        operation_id="skill-rebuild-corrupt-projection",
        expected_revision=1,
        skill_id=active.skill_id,
    )
    assert rebuilt.lifecycle_state.value == "active"
    assert rebuilt.artifact_digest == active.artifact_digest

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_evidence_events SET envelope_json = jsonb_set("
            "envelope_json, '{draft,inline_payload,skill_id}', '\"forged\"'::jsonb) "
            "WHERE event_digest = %s",
            (active.transition_digest,),
        )
        cursor.execute(
            "SELECT revision, artifact_digest, transition_sequence FROM gah_active_skill_projection "
            "WHERE tenant_id = %s AND skill_id = %s",
            (actor["tenant_id"], active.skill_id),
        )
        before = cursor.fetchone()
    with pytest.raises(Exception, match="canonical evidence is missing or corrupt"):
        authority.rebuild_skill_projection(
            actor_context=actor,
            operation_id="skill-rebuild-corrupt-evidence",
            expected_revision=1,
            skill_id=active.skill_id,
        )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT revision, artifact_digest, transition_sequence FROM gah_active_skill_projection "
            "WHERE tenant_id = %s AND skill_id = %s",
            (actor["tenant_id"], active.skill_id),
        )
        assert cursor.fetchone() == before
        cursor.execute(
            "DELETE FROM gah_evidence_events WHERE event_digest = %s", (active.transition_digest,)
        )
        cursor.execute(
            "SELECT revision, artifact_digest, transition_sequence FROM gah_active_skill_projection "
            "WHERE tenant_id = %s AND skill_id = %s",
            (actor["tenant_id"], active.skill_id),
        )
        assert cursor.fetchone() == before
    with pytest.raises(Exception, match="canonical evidence is missing or corrupt"):
        authority.rebuild_skill_projection(
            actor_context=actor,
            operation_id="skill-rebuild-partial-evidence",
            expected_revision=1,
            skill_id=active.skill_id,
        )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT revision, artifact_digest, transition_sequence FROM gah_active_skill_projection "
            "WHERE tenant_id = %s AND skill_id = %s",
            (actor["tenant_id"], active.skill_id),
        )
        assert cursor.fetchone() == before


def test_runtime_sql_cannot_forge_or_invoke_skill_authority(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps({"operation": "install", **command})),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_skill_lifecycle_transitions")
        assert cursor.fetchone()[0] == 0


def test_generic_writer_cannot_invoke_any_skill_lifecycle_entrypoint(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    wire = build_skill_lifecycle_wire_command("install", command)
    rebuild = build_skill_lifecycle_wire_command(
        "rebuild",
        {"operation_id": "writer-rebuild", "expected_revision": 1, "skill_id": "skill-a"},
    )
    calls = (
        ("gah_skill_lifecycle_evidence_head(%s::jsonb)", (json.dumps(actor),)),
        (
            "gah_lookup_skill_replay(%s::jsonb, %s::jsonb)",
            (json.dumps(actor), json.dumps(wire)),
        ),
        ("gah_install_skill(%s::jsonb, %s::jsonb)", (json.dumps(actor), json.dumps(wire))),
        ("gah_activate_skill(%s::jsonb, %s::jsonb)", (json.dumps(actor), json.dumps(wire))),
        ("gah_rollback_skill(%s::jsonb, %s::jsonb)", (json.dumps(actor), json.dumps(wire))),
        ("gah_deactivate_skill(%s::jsonb, %s::jsonb)", (json.dumps(actor), json.dumps(wire))),
        (
            "gah_rebuild_skill_projection(%s::jsonb, %s::jsonb)",
            (json.dumps(actor), json.dumps(rebuild)),
        ),
        (
            "gah_apply_skill_lifecycle(%s::jsonb, %s::jsonb, 'install')",
            (json.dumps(actor), json.dumps(wire)),
        ),
    )
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        for statement, parameters in calls:
            with pytest.raises(Exception, match="permission denied"):
                cursor.execute(f"SELECT {statement}", parameters)
            connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (1, 0, 0)


def test_lifecycle_credential_cannot_directly_commit_evidence(postgres_connections):
    actor = build_positive_records()["actor_context"]
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute(
                "SELECT gah_commit_evidence(%s::jsonb, '{}'::jsonb)",
                (json.dumps(actor),),
            )
        connection.rollback()


def _direct_lifecycle_wire(
    postgres_connections,
    actor,
    command,
    operation="install",
    now=NOW,
    writer_authorization=None,
):
    wire = build_skill_lifecycle_wire_command(operation, command)
    payload = {
        "actor_id": actor["actor_id"],
        "operation_id": wire["operation_id"],
        "operation_digest": wire["operation_digest"],
        "skill_id": wire["skill_proposal"]["artifact_id"],
        "command": wire,
    }
    if writer_authorization is not None:
        payload["writer_authorization"] = writer_authorization
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT gah_skill_lifecycle_evidence_head(%s::jsonb)", (json.dumps(actor),))
        head = cursor.fetchone()[0]
    store = postgres_connections["store_at"](now)
    evidence, _version = store._build_evidence_from_head(
        actor=actor,
        run_id=actor["session_id"],
        event_kind="skill.lifecycle_transition",
        policy_ref={
            "record_type": "policy_decision",
            "record_id": wire["policy_decision"]["decision_id"],
            "record_digest": wire["policy_decision"]["decision_digest"],
        },
        payload=payload,
        head=head,
    )
    return {**wire, "transition_evidence": evidence}


def _authorize_lifecycle(writer_connection, actor, operation, command):
    wire = build_skill_lifecycle_wire_command(operation, command)
    with writer_connection.cursor() as cursor:
        cursor.execute(
            "SELECT gah_authorize_skill_lifecycle(%s::jsonb, %s::jsonb)",
            (json.dumps(actor), json.dumps(wire)),
        )
        return cursor.fetchone()[0]


def _rebind_direct_lifecycle_evidence(evidence, *, actor, wire, writer_authorization):
    rebound = copy.deepcopy(evidence)
    payload = rebound["draft"]["inline_payload"]
    payload.update(
        {
            "actor_id": actor["actor_id"],
            "operation_id": wire["operation_id"],
            "operation_digest": wire["operation_digest"],
            "skill_id": wire["skill_proposal"]["artifact_id"],
            "command": wire,
            "writer_authorization": writer_authorization,
        }
    )
    rebound["payload_digest"] = sha256_digest(payload)
    rebound["draft"]["idempotency"]["operation_digest"] = rebound["payload_digest"]
    rebound["draft_digest"] = sha256_digest(rebound["draft"])
    unsigned_envelope = copy.deepcopy(rebound)
    unsigned_envelope.pop("event_digest")
    rebound["event_digest"] = sha256_digest(unsigned_envelope)
    return rebound


def _direct_apply(postgres_connections, actor, function, wire, barrier=None):
    if barrier is not None:
        barrier.wait(timeout=5)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            f"SELECT {function}(%s::jsonb, %s::jsonb)",
            (json.dumps(actor), json.dumps(wire)),
        )
        return cursor.fetchone()[0]


def _skill_authority_snapshot(postgres_connections):
    """Capture every lifecycle-owned durable surface before a rejected call."""

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT "
            "coalesce((SELECT jsonb_agg(jsonb_build_object("
            "'tenant_id', tenant_id, 'actor_id', actor_id, 'run_id', run_id, "
            "'next_sequence', next_sequence, 'last_event_digest', last_event_digest, "
            "'version', version) ORDER BY tenant_id, actor_id, run_id) "
            "FROM gah_run_heads), '[]'::jsonb), "
            "coalesce((SELECT jsonb_agg(jsonb_build_object("
            "'tenant_id', tenant_id, 'actor_id', actor_id, 'skill_id', skill_id, "
            "'revision', revision, 'artifact_digest', artifact_digest) "
            "ORDER BY tenant_id, actor_id, skill_id, revision) "
            "FROM gah_skill_artifact_revisions), '[]'::jsonb), "
            "coalesce((SELECT jsonb_agg(jsonb_build_object("
            "'tenant_id', tenant_id, 'actor_id', actor_id, 'skill_id', skill_id, "
            "'transition_sequence', transition_sequence, 'operation_id', operation_id, "
            "'evidence_event_digest', evidence_event_digest) "
            "ORDER BY tenant_id, actor_id, skill_id, transition_sequence) "
            "FROM gah_skill_lifecycle_transitions), '[]'::jsonb), "
            "coalesce((SELECT jsonb_agg(jsonb_build_object("
            "'tenant_id', tenant_id, 'actor_id', actor_id, 'skill_id', skill_id, "
            "'revision', revision, 'lifecycle_state', lifecycle_state, "
            "'transition_sequence', transition_sequence) "
            "ORDER BY tenant_id, actor_id, skill_id) "
            "FROM gah_active_skill_projection), '[]'::jsonb)"
        )
        return cursor.fetchone()


def _replace_source_evidence(command, source):
    """Rebind the signed command records to an existing alternate source event."""

    rebound = copy.deepcopy(command)
    source_ref = ref("evidence_envelope", source["envelope_id"], source["event_digest"])
    rebound["source_evidence"] = [source]
    proposal = rebound["skill_proposal"]
    proposal["evidence_refs"] = [source_ref]
    apply_object_digest(proposal)
    policy = rebound["policy_decision"]
    policy["request_digest"] = proposal["proposal_digest"]
    apply_object_digest(policy)
    gate = rebound["gate_decision"]
    gate["proposal_refs"] = [
        ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
    ]
    apply_object_digest(gate)
    delivery = rebound["delivery_envelope"]
    delivery.update(
        {
            "evidence_refs": [source_ref],
            "policy_refs": [
                ref("policy_decision", policy["decision_id"], policy["decision_digest"])
            ],
            "gate_decision_ref": ref("gate_decision", gate["gate_id"], gate["decision_digest"]),
        }
    )
    apply_object_digest(delivery)
    return rebound


@pytest.mark.parametrize(
    ("field", "foreign_value"),
    (
        ("tenant_id", "018f0000-0000-7000-8000-0000000000fa"),
        ("actor_id", "018f0000-0000-7000-8000-0000000000fb"),
    ),
)
def test_direct_lifecycle_rejects_foreign_actor_scope_without_durable_mutation(
    postgres_connections, field, foreign_value
):
    actor, command = _persisted_command(postgres_connections)
    wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    foreign_actor = copy.deepcopy(actor)
    foreign_actor[field] = foreign_value
    apply_object_digest(foreign_actor)
    before = _skill_authority_snapshot(postgres_connections)

    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="authority database principal is outside actor scope"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(foreign_actor), json.dumps(wire)),
            )
        connection.rollback()

    assert _skill_authority_snapshot(postgres_connections) == before


def test_direct_lifecycle_rejects_cross_actor_source_evidence_without_durable_mutation(
    postgres_connections,
):
    actor, command = _persisted_command(postgres_connections)
    foreign_actor = copy.deepcopy(actor)
    foreign_actor.update(
        {
            "actor_id": "018f0000-0000-7000-8000-0000000000fa",
            "session_id": "018f0000-0000-7000-8000-0000000000fb",
        }
    )
    apply_object_digest(foreign_actor)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_runtime_principals SET tenant_id = %s, actor_id = %s "
            "WHERE database_role = 'gah_writer'",
            (foreign_actor["tenant_id"], foreign_actor["actor_id"]),
        )
    try:
        with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
            foreign_source = postgres_connections["store_at"](NOW)._append_evidence(
                cursor=cursor,
                actor=foreign_actor,
                run_id=foreign_actor["session_id"],
                event_kind="kernel.policy_decided",
                policy_ref={
                    "record_type": "policy_decision",
                    "record_id": command["policy_decision"]["decision_id"],
                    "record_digest": command["policy_decision"]["decision_digest"],
                },
                payload={
                    "actor_id": foreign_actor["actor_id"],
                    "policy_decision_digest": command["policy_decision"]["decision_digest"],
                },
            )
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE gah_runtime_principals SET tenant_id = %s, actor_id = %s "
                "WHERE database_role = 'gah_writer'",
                (actor["tenant_id"], actor["actor_id"]),
            )

    cross_actor_command = _replace_source_evidence(command, foreign_source)
    with postgres_connections["writer"]() as writer_connection:
        authorization = _authorize_lifecycle(
            writer_connection, actor, "install", cross_actor_command
        )
        wire = _direct_lifecycle_wire(
            postgres_connections,
            actor,
            cross_actor_command,
            writer_authorization=authorization,
        )
        before = _skill_authority_snapshot(postgres_connections)
        with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
            with pytest.raises(Exception, match="skill canonical wire command is invalid"):
                cursor.execute(
                    "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                    (json.dumps(actor), json.dumps(wire)),
                )
            connection.rollback()

    assert _skill_authority_snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    ("mutate", "rebind_operation_digest", "message"),
    (
        (lambda wire: wire.__setitem__("operation_digest", "sha256:" + "0" * 64), False, "command"),
        (
            lambda wire: wire["skill_proposal"].__setitem__(
                "proposal_digest", "sha256:" + "0" * 64
            ),
            True,
            "record",
        ),
        (
            lambda wire: wire["gate_decision"].__setitem__("decision_digest", "sha256:" + "0" * 64),
            True,
            "record",
        ),
        (
            lambda wire: wire["delivery_envelope"].__setitem__(
                "envelope_digest", "sha256:" + "0" * 64
            ),
            True,
            "record",
        ),
        (
            lambda wire: wire["policy_decision"].__setitem__(
                "decision_digest", "sha256:" + "0" * 64
            ),
            True,
            "record",
        ),
    ),
)
def test_direct_lifecycle_sql_rejects_corrupted_digest_without_mutation(
    postgres_connections, mutate, rebind_operation_digest, message
):
    actor, command = _persisted_command(postgres_connections)
    wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    mutate(wire)
    if rebind_operation_digest:
        unsigned = dict(wire)
        unsigned.pop("transition_evidence")
        unsigned.pop("operation_digest")
        wire["operation_digest"] = sha256_digest(unsigned)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match=f"{message} digest binding is invalid"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (1, 0, 0)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda command: command["gate_decision"].__setitem__("tenant_id", "tenant-cross"),
        lambda command: command["delivery_envelope"].__setitem__("tenant_id", "tenant-cross"),
        lambda command: command["policy_decision"].__setitem__("tenant_id", "tenant-cross"),
        lambda command: command["gate_decision"]["target_scope"].__setitem__(
            "actor_id", "actor-cross"
        ),
        lambda command: command["delivery_envelope"]["target_scope"].__setitem__(
            "actor_id", "actor-cross"
        ),
        lambda command: command["delivery_envelope"].__setitem__("artifact_id", "skill-cross"),
        lambda command: command["delivery_envelope"].__setitem__("lifecycle_state", "activated"),
    ),
)
def test_direct_lifecycle_sql_rejects_cross_record_binding_attacks_without_mutation(
    postgres_connections,
    mutate,
):
    actor, command = _persisted_command(postgres_connections)
    valid_wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    mutate(command)
    _rebind_lifecycle_command(command)
    with postgres_connections["writer"]() as writer_connection:
        authorization = _authorize_lifecycle(writer_connection, actor, "install", command)
        command_wire = build_skill_lifecycle_wire_command("install", command)
        wire = {
            **command_wire,
            "transition_evidence": _rebind_direct_lifecycle_evidence(
                valid_wire["transition_evidence"],
                actor=actor,
                wire=command_wire,
                writer_authorization=authorization,
            ),
        }
        before = _skill_authority_snapshot(postgres_connections)
        with pytest.raises(Exception, match="gah_skill_artifact_command_sink_guard"):
            _direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    assert _skill_authority_snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    "path",
    (
        ("policy_decision", "tenant_id"),
        ("gate_decision", "target_scope"),
        ("artifact",),
        ("skill_proposal", "artifact_revision"),
        ("delivery_envelope", "lifecycle_state"),
        ("delivery_envelope", "artifact_digest"),
    ),
)
@pytest.mark.parametrize("missing", (True, False), ids=("missing", "json-null"))
def test_direct_lifecycle_sink_rejects_missing_or_null_bindings_without_mutation(
    postgres_connections,
    path,
    missing,
):
    actor, command = _persisted_command(postgres_connections)
    valid_wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    _mutate_lifecycle_sink_field(command, path, missing=missing)
    with postgres_connections["writer"]() as writer_connection:
        authorization = _authorize_lifecycle(writer_connection, actor, "install", command)
        command_wire = build_skill_lifecycle_wire_command("install", command)
        wire = {
            **command_wire,
            "transition_evidence": _rebind_direct_lifecycle_evidence(
                valid_wire["transition_evidence"],
                actor=actor,
                wire=command_wire,
                writer_authorization=authorization,
            ),
        }
        before = _skill_authority_snapshot(postgres_connections)
        with pytest.raises(Exception):
            _direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    assert _skill_authority_snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("archive", {"format": "zip", "bytes": "AA=="}),
        ("protected_payload", {"ciphertext": "AA=="}),
        ("remote_uri", "https://example.invalid/skill.json"),
        ("entrypoint", "unsafe.py"),
        ("payload", "x" * (64 * 1024)),
    ),
)
def test_direct_lifecycle_sql_rejects_non_inert_or_oversized_artifacts_without_mutation(
    postgres_connections,
    field,
    value,
):
    actor, command = _persisted_command(postgres_connections)
    valid_wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    command["artifact"][field] = value
    command["skill_proposal"]["artifact"] = copy.deepcopy(command["artifact"])
    _rebind_lifecycle_command(command)
    with postgres_connections["writer"]() as writer_connection:
        authorization = _authorize_lifecycle(writer_connection, actor, "install", command)
        command_wire = build_skill_lifecycle_wire_command("install", command)
        wire = {
            **command_wire,
            "transition_evidence": _rebind_direct_lifecycle_evidence(
                valid_wire["transition_evidence"],
                actor=actor,
                wire=command_wire,
                writer_authorization=authorization,
            ),
        }
        before = _skill_authority_snapshot(postgres_connections)
        with pytest.raises(Exception, match="gah_skill_artifact_command_sink_guard"):
            _direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    assert _skill_authority_snapshot(postgres_connections) == before


def test_transition_sink_rechecks_cross_record_bindings_without_mutation(
    postgres_connections,
):
    actor, install = _persisted_command(postgres_connections)
    PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
    ).install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "skill-transition-sink-guard",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install),
        }
    )
    valid_wire = _direct_lifecycle_wire(
        postgres_connections,
        actor,
        activate,
        operation="activate",
        now=RECEIPT_NOW,
    )
    activate["gate_decision"]["target_scope"]["actor_id"] = "actor-cross"
    _rebind_lifecycle_command(activate)
    activate["activation_receipt"] = _activation_receipt(activate)
    with postgres_connections["writer"]() as writer_connection:
        authorization = _authorize_lifecycle(writer_connection, actor, "activate", activate)
        command_wire = build_skill_lifecycle_wire_command("activate", activate)
        wire = {
            **command_wire,
            "transition_evidence": _rebind_direct_lifecycle_evidence(
                valid_wire["transition_evidence"],
                actor=actor,
                wire=command_wire,
                writer_authorization=authorization,
            ),
        }
        before = _skill_authority_snapshot(postgres_connections)
        with pytest.raises(Exception, match="gah_skill_transition_command_sink_guard"):
            _direct_apply(postgres_connections, actor, "gah_activate_skill", wire)
    assert _skill_authority_snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    "path",
    (
        ("policy_decision", "tenant_id"),
        ("gate_decision", "target_scope"),
        ("artifact",),
        ("skill_proposal", "artifact_revision"),
        ("delivery_envelope", "lifecycle_state"),
        ("delivery_envelope", "artifact_digest"),
    ),
)
@pytest.mark.parametrize("missing", (True, False), ids=("missing", "json-null"))
def test_transition_table_sink_rejects_missing_or_null_bindings_without_mutation(
    postgres_connections,
    path,
    missing,
):
    actor, install = _persisted_command(postgres_connections)
    PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
    ).install_skill(actor_context=actor, **install)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT command_json,evidence_json,evidence_event_digest "
            "FROM gah_skill_lifecycle_transitions "
            "WHERE tenant_id=%s AND operation_id=%s",
            (actor["tenant_id"], install["operation_id"]),
        )
        stored_command, evidence, evidence_digest = cursor.fetchone()

    command = copy.deepcopy(stored_command)
    command["operation_id"] = (
        f"transition-null-guard-{'missing' if missing else 'null'}-{'-'.join(path)}"
    )
    command.pop("operation_digest")
    _mutate_lifecycle_sink_field(command, path, missing=missing)
    command_without_wire = copy.deepcopy(command)
    command_without_wire.pop("operation")
    wire = build_skill_lifecycle_wire_command("install", command_without_wire)
    before = _skill_authority_snapshot(postgres_connections)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="gah_skill_transition_command_sink_guard"):
            cursor.execute(
                "INSERT INTO gah_skill_lifecycle_transitions "
                "(tenant_id,actor_id,skill_id,transition_sequence,operation_id,"
                "operation,operation_digest,expected_revision,target_revision,"
                "from_state,to_state,command_json,evidence_json,evidence_event_digest) "
                "VALUES (%s,%s,%s,2,%s,'install',%s,NULL,1,'installed','installed',"
                "%s::jsonb,%s::jsonb,%s)",
                (
                    actor["tenant_id"],
                    actor["actor_id"],
                    install["skill_proposal"]["artifact_id"],
                    wire["operation_id"],
                    wire["operation_digest"],
                    json.dumps(wire),
                    json.dumps(evidence),
                    evidence_digest,
                ),
            )
        connection.rollback()
    assert _skill_authority_snapshot(postgres_connections) == before


def test_non_approving_gate_is_rejected_without_mutation(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    wire["gate_decision"]["decision"] = "reject"
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="gate decision must approve"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (1, 0, 0)


def test_direct_lifecycle_sql_requires_live_writer_authorization_without_mutation(
    postgres_connections,
):
    actor, command = _persisted_command(postgres_connections)
    wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="writer authorization is invalid"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions)"
        )
        assert cursor.fetchone() == (1, 0)


def test_dropped_writer_authorization_cannot_mutate_lifecycle(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    wire = build_skill_lifecycle_wire_command("install", command)
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT gah_authorize_skill_lifecycle(%s::jsonb, %s::jsonb)",
            (json.dumps(actor), json.dumps(wire)),
        )
        authorization = cursor.fetchone()[0]
    expired_wire = _direct_lifecycle_wire(
        postgres_connections, actor, command, writer_authorization=authorization
    )
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="writer authorization is not live"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(expired_wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions)"
        )
        assert cursor.fetchone() == (1, 0)


def test_forged_writer_pid_cannot_mutate_lifecycle(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    wire = build_skill_lifecycle_wire_command("install", command)
    with (
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as writer_cursor,
    ):
        writer_cursor.execute(
            "SELECT gah_authorize_skill_lifecycle(%s::jsonb, %s::jsonb)",
            (json.dumps(actor), json.dumps(wire)),
        )
        authorization = dict(writer_cursor.fetchone()[0])
        authorization["writer_pid"] += 1
        forged_wire = _direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=authorization
        )
        with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
            with pytest.raises(Exception, match="writer authorization is not live"):
                cursor.execute(
                    "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                    (json.dumps(actor), json.dumps(forged_wire)),
                )
            connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions)"
        )
        assert cursor.fetchone() == (1, 0)


def test_writer_authorization_requires_exact_shape_and_commitment(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    other = copy.deepcopy(command)
    other["operation_id"] = "wrong-command-live-pid"
    with postgres_connections["writer"]() as writer_connection:
        authorization = _authorize_lifecycle(writer_connection, actor, "install", command)
        truncated = {"writer_pid": authorization["writer_pid"]}
        truncated_wire = _direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=truncated
        )
        wrong_sequence = dict(authorization)
        wrong_sequence["expected_transition_sequence"] += 1
        wrong_sequence_wire = _direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=wrong_sequence
        )
        wrong_command = dict(authorization)
        other_wire = build_skill_lifecycle_wire_command("install", other)
        wrong_command["operation_id"] = other_wire["operation_id"]
        wrong_command["operation_digest"] = other_wire["operation_digest"]
        wrong_command_wire = _direct_lifecycle_wire(
            postgres_connections, actor, other, writer_authorization=wrong_command
        )
        for candidate, message in (
            (truncated_wire, "writer authorization is invalid"),
            (wrong_sequence_wire, "writer authorization is not live"),
            (wrong_command_wire, "writer authorization is not live"),
        ):
            with (
                postgres_connections["skill_authority"]() as connection,
                connection.cursor() as cursor,
            ):
                with pytest.raises(Exception, match=message):
                    cursor.execute(
                        "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                        (json.dumps(actor), json.dumps(candidate)),
                    )
                connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_skill_artifact_revisions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (1, 0, 0, 0)


def test_one_live_writer_lock_is_insufficient_for_lifecycle_authorization(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    wire = build_skill_lifecycle_wire_command("install", command)
    committed = {
        **wire,
        "expected_transition_sequence": 0,
        "expected_lifecycle_state": "none",
    }
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT lock_a, lock_b, lock_c, lock_d "
            "FROM gah_skill_authorization_lock_keys(%s::jsonb, %s::jsonb)",
            (json.dumps(actor), json.dumps(committed)),
        )
        lock_a, lock_b, _lock_c, _lock_d = cursor.fetchone()
    with (
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as cursor,
    ):
        cursor.execute("SELECT pg_backend_pid()")
        writer_pid = cursor.fetchone()[0]
        cursor.execute("SELECT pg_advisory_xact_lock(%s, %s)", (lock_a, lock_b))
        authorization = {
            "writer_pid": writer_pid,
            "tenant_id": actor["tenant_id"],
            "actor_id": actor["actor_id"],
            "session_id": actor["session_id"],
            "operation_id": wire["operation_id"],
            "operation_digest": wire["operation_digest"],
            "expected_transition_sequence": 0,
            "expected_lifecycle_state": "none",
        }
        partial_wire = _direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=authorization
        )
        with (
            postgres_connections["skill_authority"]() as connection,
            connection.cursor() as lifecycle_cursor,
        ):
            with pytest.raises(Exception, match="writer authorization is not live"):
                lifecycle_cursor.execute(
                    "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                    (json.dumps(actor), json.dumps(partial_wire)),
                )
            connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_skill_artifact_revisions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (1, 0, 0, 0)
    result = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: NOW,
        ids=_ids(),
    ).install_skill(actor_context=actor, **command)
    assert result.replayed is False


def test_exact_lifecycle_replay_is_mutation_free_after_authorization_consumption(
    postgres_connections,
):
    actor, command = _persisted_command(postgres_connections)
    with postgres_connections["writer"]() as writer_connection:
        authorization = _authorize_lifecycle(writer_connection, actor, "install", command)
        wire = _direct_lifecycle_wire(
            postgres_connections, actor, command, writer_authorization=authorization
        )
        first = _direct_apply(postgres_connections, actor, "gah_install_skill", wire)
        second = _direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    replay = _direct_apply(postgres_connections, actor, "gah_install_skill", wire)
    assert first["replayed"] is False
    assert second["replayed"] is True
    assert replay["replayed"] is True
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_skill_artifact_revisions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (2, 1, 1, 0)


def test_changed_command_changes_the_full_128_bit_authorization_lock_tuple(postgres_connections):
    actor, command = _persisted_command(postgres_connections)
    first = build_skill_lifecycle_wire_command("install", command)
    changed = copy.deepcopy(command)
    changed["operation_id"] = "changed-lock-commitment"
    second = build_skill_lifecycle_wire_command("install", changed)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT lock_a, lock_b, lock_c, lock_d "
            "FROM gah_skill_authorization_lock_keys(%s::jsonb, %s::jsonb)",
            (
                json.dumps(actor),
                json.dumps(
                    {**first, "expected_transition_sequence": 0, "expected_lifecycle_state": "none"}
                ),
            ),
        )
        first_keys = cursor.fetchone()
        cursor.execute(
            "SELECT lock_a, lock_b, lock_c, lock_d "
            "FROM gah_skill_authorization_lock_keys(%s::jsonb, %s::jsonb)",
            (
                json.dumps(actor),
                json.dumps(
                    {
                        **second,
                        "expected_transition_sequence": 0,
                        "expected_lifecycle_state": "none",
                    }
                ),
            ),
        )
        assert cursor.fetchone() != first_keys


def test_reversed_sha_lock_pairs_are_normalized_to_one_global_order(postgres_connections):
    actor, _command = _persisted_command(postgres_connections)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            WITH candidates AS (
                SELECT jsonb_build_object(
                    'operation_id', 'ordered-lock-' || number::text,
                    'operation_digest', 'sha256:' || repeat('a', 64),
                    'expected_transition_sequence', 0,
                    'expected_lifecycle_state', 'none'
                ) AS command
                  FROM generate_series(1, 64) AS series(number)
            )
            SELECT raw.lock_a, raw.lock_b, raw.lock_c, raw.lock_d,
                   ordered.first_a, ordered.first_b, ordered.second_a, ordered.second_b
              FROM candidates
             CROSS JOIN LATERAL gah_skill_authorization_lock_keys(%s::jsonb, command) AS raw
             CROSS JOIN LATERAL gah_skill_authorization_ordered_locks(%s::jsonb, command) AS ordered
             WHERE (raw.lock_a, raw.lock_b) > (raw.lock_c, raw.lock_d)
             LIMIT 1
            """,
            (json.dumps(actor), json.dumps(actor)),
        )
        row = cursor.fetchone()
    assert row is not None
    lock_a, lock_b, lock_c, lock_d, first_a, first_b, second_a, second_b = row
    assert (first_a, first_b, second_a, second_b) == (lock_c, lock_d, lock_a, lock_b)
    assert (first_a, first_b) <= (second_a, second_b)


def test_direct_rebuild_sql_rejects_changed_digest_before_replay_or_mutation(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "rebuild-digest-activate",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install),
        }
    )
    active = authority.activate_skill(actor_context=actor, **activate)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM gah_active_skill_projection WHERE tenant_id = %s AND skill_id = %s",
            (actor["tenant_id"], active.skill_id),
        )
    rebuild = {
        "operation_id": "rebuild-digest",
        "expected_revision": 1,
        "skill_id": active.skill_id,
    }
    authority.rebuild_skill_projection(actor_context=actor, **rebuild)
    wire = build_skill_lifecycle_wire_command("rebuild", rebuild)
    wire["operation_digest"] = "sha256:" + "0" * 64
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="rebuild command digest binding is invalid"):
            cursor.execute(
                "SELECT gah_rebuild_skill_projection(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_skill_projection_rebuilds")
        assert cursor.fetchone()[0] == 1


def test_direct_lifecycle_sql_rejects_tampered_transition_envelope_without_mutation(
    postgres_connections,
):
    actor, command = _persisted_command(postgres_connections)
    wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    wire["transition_evidence"]["event_digest"] = "sha256:" + "0" * 64
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="transition evidence digest binding is invalid"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (1, 0, 0)


def test_direct_lifecycle_sql_rejects_tampered_runtime_receipt_digest_without_mutation(
    postgres_connections,
):
    actor, install = _persisted_command(postgres_connections)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "receipt-digest-tamper",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install),
        }
    )
    wire = _direct_lifecycle_wire(
        postgres_connections, actor, activate, "activate", now=RECEIPT_NOW
    )
    wire["activation_receipt"]["receipt_digest"] = "sha256:" + "0" * 64
    unsigned = dict(wire)
    unsigned.pop("transition_evidence")
    unsigned.pop("operation_digest")
    wire["operation_digest"] = sha256_digest(unsigned)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="record digest binding is invalid"):
            cursor.execute(
                "SELECT gah_activate_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (2, 1, 0)


def test_direct_lifecycle_sql_rejects_tampered_approval_digest_without_mutation(
    postgres_connections,
):
    actor, command = _persisted_command(postgres_connections)
    command = copy.deepcopy(command)
    command["approvals"] = [copy.deepcopy(build_positive_records()["approval_record"])]
    wire = _direct_lifecycle_wire(postgres_connections, actor, command)
    wire["approvals"][0]["approval_digest"] = "sha256:" + "0" * 64
    unsigned = dict(wire)
    unsigned.pop("transition_evidence")
    unsigned.pop("operation_digest")
    wire["operation_digest"] = sha256_digest(unsigned)
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="record digest binding is invalid"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (1, 0, 0)


def test_forged_authority_sql_is_rejected_without_ledger_or_projection_mutation(
    postgres_connections,
):
    """A generic writer can neither forge lifecycle evidence nor lifecycle state."""

    actor, command = _persisted_command(postgres_connections)
    wire = build_skill_lifecycle_wire_command("install", command)
    ledger_payload = {
        "actor_id": actor["actor_id"],
        "operation_id": wire["operation_id"],
        "operation_digest": wire["operation_digest"],
        "skill_id": wire["skill_proposal"]["artifact_id"],
        "command": wire,
    }
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        before = cursor.fetchone()
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="reserved evidence event kind"):
            postgres_connections["store_at"](NOW)._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=actor["session_id"],
                event_kind="skill.lifecycle_transition",
                policy_ref={
                    "record_type": "policy_decision",
                    "record_id": command["policy_decision"]["decision_id"],
                    "record_digest": command["policy_decision"]["decision_digest"],
                },
                payload=ledger_payload,
            )
        connection.rollback()
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute(
                "SELECT gah_install_skill(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(wire)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == before


def test_concurrent_lifecycle_apply_replays_without_extra_evidence(
    postgres_connections,
):
    actor, command = _persisted_command(postgres_connections)

    def install_once():
        return PostgresSkillLifecycleAuthority(
            privileged_connect=postgres_connections["skill_authority"],
            evidence_writer_connect=postgres_connections["writer"],
            clock=lambda: NOW,
        ).install_skill(actor_context=actor, **command)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result() for future in (pool.submit(install_once), pool.submit(install_once))
        ]
    assert sorted(result.replayed for result in results) == [False, True]
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_skill_artifact_revisions)"
        )
        assert cursor.fetchone() == (2, 1, 1)


def _active_skill_for_cas_race(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    activation = _activation_receipt(install)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "cas-baseline-activate",
            "expected_revision": 1,
            "activation_receipt": activation,
        }
    )
    authority.activate_skill(actor_context=actor, **activate)
    return actor, install, activation


def _run_authorized_cas_race(postgres_connections, actor, first, second):
    first_operation, first_command, first_function = first
    second_operation, second_command, second_function = second
    with (
        postgres_connections["writer"]() as first_writer,
        postgres_connections["writer"]() as second_writer,
    ):
        first_authorization = _authorize_lifecycle(
            first_writer, actor, first_operation, first_command
        )
        second_authorization = _authorize_lifecycle(
            second_writer, actor, second_operation, second_command
        )
        assert first_authorization["expected_transition_sequence"] == 2
        assert second_authorization["expected_transition_sequence"] == 2
        assert first_authorization["expected_lifecycle_state"] == "active"
        assert second_authorization["expected_lifecycle_state"] == "active"
        first_wire = _direct_lifecycle_wire(
            postgres_connections,
            actor,
            first_command,
            first_operation,
            now=RECEIPT_NOW,
            writer_authorization=first_authorization,
        )
        second_wire = _direct_lifecycle_wire(
            postgres_connections,
            actor,
            second_command,
            second_operation,
            now=RECEIPT_NOW,
            writer_authorization=second_authorization,
        )
        barrier = Barrier(2)

        def apply(function, wire):
            try:
                return ("ok", _direct_apply(postgres_connections, actor, function, wire, barrier))
            except Exception as error:
                return ("error", str(error))

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [
                future.result()
                for future in (
                    pool.submit(apply, first_function, first_wire),
                    pool.submit(apply, second_function, second_wire),
                )
            ]
    assert sum(result[0] == "ok" for result in results) == 1
    assert (
        sum("authorized state is stale" in result[1] for result in results if result[0] == "error")
        == 1
    )
    return results


@pytest.mark.parametrize("_iteration", range(10))
def test_authorized_activate_and_rollback_race_has_one_atomic_winner(
    postgres_connections, _iteration
):
    actor, install, activation = _active_skill_for_cas_race(postgres_connections)
    rollback = _rollback_receipt(install, activation)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "cas-race-activate",
            "expected_revision": 1,
            "activation_receipt": activation,
        }
    )
    rollback_command = copy.deepcopy(install)
    rollback_command.update(
        {
            "operation_id": "cas-race-rollback",
            "expected_revision": 1,
            "activation_receipt": activation,
            "rollback_receipt": rollback,
        }
    )
    results = _run_authorized_cas_race(
        postgres_connections,
        actor,
        ("activate", activate, "gah_activate_skill"),
        ("rollback", rollback_command, "gah_rollback_skill"),
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_skill_artifact_revisions), "
            "(SELECT lifecycle_state FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == (4, 3, 1, "active")
    assert next(result[1]["lifecycle_state"] for result in results if result[0] == "ok") == "active"
    fresh = copy.deepcopy(install)
    fresh.update({"operation_id": "cas-fresh-deactivate", "expected_revision": 1})
    result = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
    ).deactivate_skill(actor_context=actor, **fresh)
    assert result.lifecycle_state.value == "inactive"


@pytest.mark.parametrize("_iteration", range(10))
def test_authorized_activate_and_deactivate_race_has_one_atomic_winner(
    postgres_connections, _iteration
):
    actor, install, activation = _active_skill_for_cas_race(postgres_connections)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "cas-race-activate-2",
            "expected_revision": 1,
            "activation_receipt": activation,
        }
    )
    deactivate = copy.deepcopy(install)
    deactivate.update({"operation_id": "cas-race-deactivate", "expected_revision": 1})
    results = _run_authorized_cas_race(
        postgres_connections,
        actor,
        ("activate", activate, "gah_activate_skill"),
        ("deactivate", deactivate, "gah_deactivate_skill"),
    )
    winning_state = next(result[1]["lifecycle_state"] for result in results if result[0] == "ok")
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_skill_artifact_revisions), "
            "(SELECT lifecycle_state FROM gah_active_skill_projection)"
        )
        evidence, transitions, revisions, projected_state = cursor.fetchone()
        assert (evidence, transitions, revisions) == (4, 3, 1)
        assert projected_state == ("active" if winning_state == "active" else None)


def test_concurrent_rebuild_replays_once_and_rejects_conflicts(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **install)
    activate = copy.deepcopy(install)
    activate.update(
        {
            "operation_id": "skill-activate-concurrent-rebuild",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install),
        }
    )
    active = authority.activate_skill(actor_context=actor, **activate)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM gah_active_skill_projection WHERE tenant_id = %s AND skill_id = %s",
            (actor["tenant_id"], active.skill_id),
        )

    rebuild = {
        "operation_id": "skill-rebuild-concurrent",
        "expected_revision": 1,
        "skill_id": active.skill_id,
    }

    def rebuild_once():
        return PostgresSkillLifecycleAuthority(
            privileged_connect=postgres_connections["skill_authority"],
            evidence_writer_connect=postgres_connections["writer"],
            clock=lambda: RECEIPT_NOW,
        ).rebuild_skill_projection(actor_context=actor, **rebuild)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result() for future in (pool.submit(rebuild_once), pool.submit(rebuild_once))
        ]
    assert sorted(result.replayed for result in results) == [False, True]
    with pytest.raises(Exception, match="rebuild replay conflicts"):
        PostgresSkillLifecycleAuthority(
            privileged_connect=postgres_connections["skill_authority"],
            evidence_writer_connect=postgres_connections["writer"],
            clock=lambda: RECEIPT_NOW,
        ).rebuild_skill_projection(
            actor_context=actor,
            operation_id=rebuild["operation_id"],
            expected_revision=1,
            skill_id="018f0000-0000-7000-8000-0000000000ff",
        )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_skill_projection_rebuilds")
        assert cursor.fetchone()[0] == 1


def test_stale_lifecycle_revision_rolls_back_evidence_and_state(postgres_connections):
    actor, install = _persisted_command(postgres_connections)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **install)
    stale = copy.deepcopy(install)
    stale.update(
        {
            "operation_id": "skill-activate-stale-revision",
            "expected_revision": 2,
            "activation_receipt": _activation_receipt(install),
        }
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        before = cursor.fetchone()
    with pytest.raises(Exception, match="revision is stale"):
        authority.activate_skill(actor_context=actor, **stale)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == before
    with pytest.raises(Exception, match="revision is stale"):
        authority.activate_skill(actor_context=actor, **stale)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_skill_lifecycle_transitions), "
            "(SELECT count(*) FROM gah_active_skill_projection)"
        )
        assert cursor.fetchone() == before


@pytest.mark.parametrize(
    "function_name",
    ("gah_install_skill", "gah_activate_skill", "gah_rollback_skill", "gah_deactivate_skill"),
)
def test_sql_wrapper_operation_mismatch_is_zero_mutation(postgres_connections, function_name):
    actor, command = _persisted_command(postgres_connections)
    before = postgres_connections["admin"]()
    with before.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_skill_lifecycle_transitions")
        count = cursor.fetchone()[0]
    before.close()
    command = copy.deepcopy(command)
    command["operation"] = "install" if function_name != "gah_install_skill" else "activate"
    command["operation_digest"] = "sha256:" + "a" * 64
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute(
                f"SELECT {function_name}(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(command)),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_skill_lifecycle_transitions")
        assert cursor.fetchone()[0] == count
