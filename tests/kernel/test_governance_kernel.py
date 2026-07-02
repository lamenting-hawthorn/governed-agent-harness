"""Public-flow, negative-path, and adversarial coverage for the Phase 2 kernel."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import pytest

from governed_agent_harness.contracts import (
    ConstraintRegistry,
    IdempotencyConflictError,
    ProofVerificationError,
    SemanticError,
    apply_object_digest,
    sha256_digest,
)
from governed_agent_harness.kernel import (
    GovernanceKernel,
    IdentityError,
    KernelLifecycle,
    LifecycleError,
    PolicyConfigurationError,
    PolicyRule,
    PolicySet,
)


NOW = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)


class RecordingIdentityVerifier:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.calls: list[dict[str, Any]] = []

    def verify(self, *, actor_context: dict[str, Any]) -> bool:
        self.calls.append(actor_context)
        return self.accepted


def _approval_policy() -> PolicySet:
    return PolicySet(
        rules=(
            PolicyRule(
                rule_id="effects.approval.v1",
                decision="require_approval",
                effect_classes=frozenset({"write_external"}),
                isolation_profile="container",
            ),
        )
    )


def _kernel(
    verifier: Any, trust_factory: Any, identity_verifier: RecordingIdentityVerifier | None = None
) -> GovernanceKernel:
    return GovernanceKernel(
        policy=_approval_policy(),
        identity_verifier=identity_verifier or RecordingIdentityVerifier(),
        approval_verifier=verifier,
        approval_trust=lambda now: trust_factory(now=now),
        clock=lambda: NOW,
    )


def _bound_approval(
    approval: dict[str, Any], *, policy: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    approval["tenant_id"] = request["tenant_id"]
    approval["request_id"] = request["request_id"]
    approval["request_digest"] = request["request_digest"]
    approval["policy_decision_id"] = policy["decision_id"]
    approval["policy_decision_digest"] = policy["decision_digest"]
    return apply_object_digest(approval)


def _other_tenant(record: dict[str, Any]) -> dict[str, Any]:
    tenant_id = "018f0000-0000-7000-8000-000000000999"

    def rebind(value: Any) -> None:
        if isinstance(value, dict):
            if "tenant_id" in value:
                value["tenant_id"] = tenant_id
            for child in value.values():
                rebind(child)
        elif isinstance(value, list):
            for child in value:
                rebind(child)

    rebind(record)
    return apply_object_digest(record)


def test_public_kernel_flow_is_evidence_first_and_never_executes_an_effect(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)

    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    assert awaiting.state is KernelLifecycle.APPROVAL_REQUIRED
    assert len(awaiting.evidence) == 1
    assert awaiting.evidence[0]["draft"]["event_kind"] == "kernel.policy_decided"

    approval = _bound_approval(
        records["approval_record"], policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    approved = kernel.accept_approval(
        tenant_id=awaiting.request["tenant_id"],
        request_id=awaiting.request["request_id"],
        approval=approval,
    )

    assert approved.state is KernelLifecycle.APPROVED
    assert approved.approval is not None
    assert [event["draft"]["event_kind"] for event in approved.evidence] == [
        "kernel.policy_decided",
        "kernel.approval_accepted",
    ]
    assert [event["sequence_number"] for event in approved.evidence] == [0, 1]
    assert approved.evidence[1]["prior_event_digest"] == approved.evidence[0]["event_digest"]
    assert len(kernel.events(actor_context=records["actor_context"])) == 2


def test_submit_is_idempotent_without_appending_duplicate_evidence(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    first = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    replay = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )

    assert replay.to_dict() == first.to_dict()
    assert len(kernel.events(actor_context=records["actor_context"])) == 1


def test_public_lifecycle_snapshot_cannot_mutate_kernel_owned_state(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    snapshot = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    assert isinstance(snapshot.request, dict)
    snapshot.request["request_digest"] = "sha256:" + "0" * 64

    stored = kernel.get(
        actor_context=records["actor_context"],
        request_id=records["tool_request"]["request_id"],
    )
    assert stored.request["request_digest"] != snapshot.request["request_digest"]


def test_identity_context_mutation_fails_before_a_policy_decision(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    records["tool_request"]["actor_id"] = "018f0000-0000-7000-8000-000000000999"
    apply_object_digest(records["tool_request"])

    with pytest.raises(IdentityError, match="tenant and actor"):
        kernel.submit(actor_context=records["actor_context"], tool_request=records["tool_request"])
    assert kernel.events(actor_context=records["actor_context"]) == ()


def test_untrusted_identity_fails_closed_before_a_policy_decision(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    identity = RecordingIdentityVerifier(accepted=False)
    kernel = _kernel(verifier, trust_factory, identity)

    with pytest.raises(IdentityError, match="not trusted"):
        kernel.submit(actor_context=records["actor_context"], tool_request=records["tool_request"])
    assert len(identity.calls) == 1
    with pytest.raises(IdentityError, match="not trusted"):
        kernel.events(actor_context=records["actor_context"])


def test_expired_identity_fails_closed(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    records["actor_context"]["expires_at"] = "2026-01-01T00:11:00.000Z"
    records["tool_request"]["actor_context_digest"] = sha256_digest(records["actor_context"])
    apply_object_digest(records["tool_request"])

    with pytest.raises(IdentityError, match="expired"):
        kernel.submit(actor_context=records["actor_context"], tool_request=records["tool_request"])


def test_mismatched_or_replayed_approval_never_advances_lifecycle(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    approval = _bound_approval(
        records["approval_record"], policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    approval["request_digest"] = "sha256:" + "9" * 64
    apply_object_digest(approval)
    with pytest.raises(SemanticError, match="request_digest"):
        kernel.accept_approval(
            tenant_id=awaiting.request["tenant_id"],
            request_id=awaiting.request["request_id"],
            approval=approval,
        )

    approval = _bound_approval(
        approval, policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    approved = kernel.accept_approval(
        tenant_id=awaiting.request["tenant_id"],
        request_id=awaiting.request["request_id"],
        approval=approval,
    )
    assert approved.state is KernelLifecycle.APPROVED
    with pytest.raises(LifecycleError, match="current lifecycle state"):
        kernel.accept_approval(
            tenant_id=awaiting.request["tenant_id"],
            request_id=awaiting.request["request_id"],
            approval=approval,
        )


def test_expired_approval_is_rejected_before_evidence_or_state_change(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    approval = _bound_approval(
        records["approval_record"], policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    approval["expires_at"] = "2026-01-01T00:11:00.000Z"
    apply_object_digest(approval)

    with pytest.raises(LifecycleError, match="not currently valid"):
        kernel.accept_approval(
            tenant_id=awaiting.request["tenant_id"],
            request_id=awaiting.request["request_id"],
            approval=approval,
        )
    assert (
        kernel.get(
            actor_context=records["actor_context"], request_id=awaiting.request["request_id"]
        ).state
        is KernelLifecycle.APPROVAL_REQUIRED
    )
    assert len(kernel.events(actor_context=records["actor_context"])) == 1


def test_untrusted_approval_proof_is_rejected_before_evidence_or_state_change(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    approval = _bound_approval(
        records["approval_record"], policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    verifier.accepted = False

    with pytest.raises(ProofVerificationError, match="detached proof"):
        kernel.accept_approval(
            tenant_id=awaiting.request["tenant_id"],
            request_id=awaiting.request["request_id"],
            approval=approval,
        )
    assert (
        kernel.get(
            actor_context=records["actor_context"], request_id=awaiting.request["request_id"]
        ).state
        is KernelLifecycle.APPROVAL_REQUIRED
    )
    assert len(kernel.events(actor_context=records["actor_context"])) == 1


def test_unsatisfied_separation_of_duties_cannot_advance_lifecycle(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    approval = _bound_approval(
        records["approval_record"], policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    approval["separation_of_duties"]["satisfied"] = False
    apply_object_digest(approval)

    with pytest.raises(LifecycleError, match="separation of duties"):
        kernel.accept_approval(
            tenant_id=awaiting.request["tenant_id"],
            request_id=awaiting.request["request_id"],
            approval=approval,
        )
    assert len(kernel.events(actor_context=records["actor_context"])) == 1


def test_unmatched_request_is_denied_with_evidence(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    records["tool_request"]["effect_classes"] = ["financial"]
    apply_object_digest(records["tool_request"])
    denied = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )

    assert denied.state is KernelLifecycle.DENIED
    assert denied.policy["decision"] == "deny"


def test_authorize_policy_records_non_executable_policy_authorization(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = GovernanceKernel(
        policy=PolicySet(
            rules=(
                PolicyRule(
                    rule_id="effects.local_allow.v1",
                    decision="authorize",
                    effect_classes=frozenset({"write_external"}),
                    isolation_profile="process",
                ),
            )
        ),
        identity_verifier=RecordingIdentityVerifier(),
        approval_verifier=verifier,
        approval_trust=lambda now: trust_factory(now=now),
        clock=lambda: NOW,
    )

    result = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    assert result.state is KernelLifecycle.POLICY_AUTHORIZED
    assert result.approval is None


@pytest.mark.parametrize("decision", ["authorize", "require_approval"])
def test_executable_policy_dispositions_require_a_grant_compatible_profile(decision: str) -> None:
    with pytest.raises(PolicyConfigurationError, match="executable isolation profile"):
        PolicyRule(
            rule_id="effects.invalid_profile.v1",
            decision=decision,
            effect_classes=frozenset({"write_external"}),
        )
    with pytest.raises(PolicyConfigurationError, match="deny rules"):
        PolicyRule(
            rule_id="effects.invalid_deny.v1",
            decision="deny",
            effect_classes=frozenset({"write_external"}),
            isolation_profile="container",
        )


def test_policy_authorization_and_approval_preserve_grant_binding_isolation_profiles(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    for decision, expected_state in (
        ("authorize", KernelLifecycle.POLICY_AUTHORIZED),
        ("require_approval", KernelLifecycle.APPROVAL_REQUIRED),
    ):
        kernel = GovernanceKernel(
            policy=PolicySet(
                rules=(
                    PolicyRule(
                        rule_id=f"effects.{decision}.v1",
                        decision=decision,
                        effect_classes=frozenset({"write_external"}),
                        isolation_profile="container",
                    ),
                )
            ),
            identity_verifier=RecordingIdentityVerifier(),
            approval_verifier=verifier,
            approval_trust=lambda now: trust_factory(now=now),
            clock=lambda: NOW,
        )
        result = kernel.submit(
            actor_context=records["actor_context"], tool_request=records["tool_request"]
        )
        assert result.state is expected_state
        assert result.policy["isolation_profile"] == "container"


def test_constraints_fail_closed_before_authorized_or_approval_lifecycle_state(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    constraint = copy.deepcopy(records["policy_decision"]["constraints"][0])
    for decision in ("authorize", "require_approval"):
        kernel = GovernanceKernel(
            policy=PolicySet(
                rules=(
                    PolicyRule(
                        rule_id=f"effects.constrained.{decision}.v1",
                        decision=decision,
                        effect_classes=frozenset({"write_external"}),
                        isolation_profile="container",
                        constraints=(constraint,),
                    ),
                )
            ),
            identity_verifier=RecordingIdentityVerifier(),
            approval_verifier=verifier,
            approval_trust=lambda now: trust_factory(now=now),
            clock=lambda: NOW,
        )
        with pytest.raises(SemanticError, match="unsupported constraint"):
            kernel.submit(
                actor_context=records["actor_context"], tool_request=records["tool_request"]
            )
        assert kernel.events(actor_context=records["actor_context"]) == ()


@pytest.mark.parametrize(
    ("constraint_id", "constraint_version"),
    [("unsupported.example/rule", "1.0"), ("example.org/max_actions", "2.0")],
)
def test_unsupported_constraint_id_and_version_fail_closed(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Any,
    constraint_id: str,
    constraint_version: str,
) -> None:
    constraint = copy.deepcopy(records["policy_decision"]["constraints"][0])
    constraint["constraint_id"] = constraint_id
    constraint["constraint_version"] = constraint_version
    kernel = GovernanceKernel(
        policy=PolicySet(
            rules=(
                PolicyRule(
                    rule_id="effects.unsupported_constraint.v1",
                    decision="authorize",
                    effect_classes=frozenset({"write_external"}),
                    isolation_profile="container",
                    constraints=(constraint,),
                ),
            )
        ),
        identity_verifier=RecordingIdentityVerifier(),
        approval_verifier=verifier,
        approval_trust=lambda now: trust_factory(now=now),
        clock=lambda: NOW,
        constraint_registry=ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
    )
    with pytest.raises(SemanticError, match="unsupported constraint"):
        kernel.submit(actor_context=records["actor_context"], tool_request=records["tool_request"])
    assert kernel.events(actor_context=records["actor_context"]) == ()


def test_supported_and_unconstrained_policy_rules_are_accepted(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    constraint = copy.deepcopy(records["policy_decision"]["constraints"][0])
    supported = GovernanceKernel(
        policy=PolicySet(
            rules=(
                PolicyRule(
                    rule_id="effects.supported_constraint.v1",
                    decision="authorize",
                    effect_classes=frozenset({"write_external"}),
                    isolation_profile="container",
                    constraints=(constraint,),
                ),
            )
        ),
        identity_verifier=RecordingIdentityVerifier(),
        approval_verifier=verifier,
        approval_trust=lambda now: trust_factory(now=now),
        clock=lambda: NOW,
        constraint_registry=ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
    )
    assert (
        supported.submit(
            actor_context=records["actor_context"], tool_request=records["tool_request"]
        ).state
        is KernelLifecycle.POLICY_AUTHORIZED
    )
    unconstrained = _kernel(verifier, trust_factory)
    assert (
        unconstrained.submit(
            actor_context=records["actor_context"], tool_request=records["tool_request"]
        ).state
        is KernelLifecycle.APPROVAL_REQUIRED
    )


def test_tenant_and_actor_scoped_reads_require_current_trusted_identity(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    submitted = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    assert (
        kernel.get(
            actor_context=records["actor_context"], request_id=submitted.request["request_id"]
        ).state
        is KernelLifecycle.APPROVAL_REQUIRED
    )
    other_actor = copy.deepcopy(records["actor_context"])
    other_actor["actor_id"] = "018f0000-0000-7000-8000-000000000777"
    with pytest.raises(IdentityError, match="another actor"):
        kernel.get(actor_context=other_actor, request_id=submitted.request["request_id"])
    assert kernel.events(actor_context=other_actor) == ()
    other_tenant = _other_tenant(copy.deepcopy(records["actor_context"]))
    with pytest.raises(LifecycleError, match="unknown tenant"):
        kernel.get(actor_context=other_tenant, request_id=submitted.request["request_id"])
    expired = copy.deepcopy(records["actor_context"])
    expired["expires_at"] = "2026-01-01T00:11:00.000Z"
    with pytest.raises(IdentityError, match="expired"):
        kernel.events(actor_context=expired)
    untrusted = RecordingIdentityVerifier(accepted=False)
    blocked = _kernel(verifier, trust_factory, untrusted)
    with pytest.raises(IdentityError, match="not trusted"):
        blocked.events(actor_context=records["actor_context"])


def test_replay_requires_the_exact_canonical_request_and_never_appends_evidence(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    first = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    original_evidence = kernel.events(actor_context=records["actor_context"])
    same_key_changed_request_id = copy.deepcopy(records["tool_request"])
    same_key_changed_request_id["request_id"] = "018f0000-0000-7000-8000-000000000777"
    apply_object_digest(same_key_changed_request_id)
    changed_digest = copy.deepcopy(records["tool_request"])
    changed_digest["effect_classes"] = ["read_external"]
    apply_object_digest(changed_digest)
    changed_operation = copy.deepcopy(records["tool_request"])
    changed_operation["idempotency"]["operation_digest"] = "sha256:" + "a" * 64
    apply_object_digest(changed_operation)
    for changed in (same_key_changed_request_id, changed_digest, changed_operation):
        with pytest.raises(IdempotencyConflictError):
            kernel.submit(actor_context=records["actor_context"], tool_request=changed)
    assert (
        kernel.submit(
            actor_context=records["actor_context"], tool_request=records["tool_request"]
        ).to_dict()
        == first.to_dict()
    )
    assert kernel.events(actor_context=records["actor_context"]) == original_evidence


def test_cross_tenant_idempotency_key_reuse_is_independent(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    kernel.submit(actor_context=records["actor_context"], tool_request=records["tool_request"])
    other_actor = _other_tenant(copy.deepcopy(records["actor_context"]))
    other_request = _other_tenant(copy.deepcopy(records["tool_request"]))
    other_request["actor_context_digest"] = sha256_digest(other_actor)
    apply_object_digest(other_request)
    assert (
        kernel.submit(actor_context=other_actor, tool_request=other_request).state
        is KernelLifecycle.APPROVAL_REQUIRED
    )


def test_concurrent_duplicate_submission_has_one_evidence_event(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: kernel.submit(
                    actor_context=records["actor_context"], tool_request=records["tool_request"]
                ),
                range(8),
            )
        )
    assert all(result.to_dict() == results[0].to_dict() for result in results)
    assert len(kernel.events(actor_context=records["actor_context"])) == 1
