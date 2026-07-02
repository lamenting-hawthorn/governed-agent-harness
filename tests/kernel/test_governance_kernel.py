"""Public-flow, negative-path, and adversarial coverage for the Phase 2 kernel."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import pytest

from governed_agent_harness.contracts import (
    AuthorizationGrant,
    ConstraintRegistry,
    IdempotencyConflictError,
    ProofVerificationError,
    SemanticError,
    apply_object_digest,
    sha256_digest,
    validate_grant_binding,
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
    verifier: Any,
    trust_factory: Any,
    identity_verifier: RecordingIdentityVerifier | None = None,
    constraint_registry: ConstraintRegistry | None = None,
) -> GovernanceKernel:
    registry = (
        constraint_registry
        if constraint_registry is not None
        else ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})})
    )
    return GovernanceKernel(
        policy=_approval_policy(),
        identity_verifier=identity_verifier or RecordingIdentityVerifier(),
        approval_verifier=verifier,
        approval_trust=lambda now: trust_factory(now=now),
        constraint_registry=registry,
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


def _grant_for_result(
    grant: dict[str, Any],
    result: Any,
    *,
    approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request = result.request
    policy = result.policy
    for field in ("tenant_id", "actor_id", "run_id", "request_id", "request_digest"):
        grant[field] = request[field]
    grant["tool_id"] = request["tool_id"]
    grant["tool_version"] = request["tool_version"]
    grant["policy_decision_id"] = policy["decision_id"]
    grant["policy_decision_digest"] = policy["decision_digest"]
    grant["constraints"] = copy.deepcopy(policy["constraints"])
    grant["isolation_profile"] = policy["isolation_profile"]
    grant["issued_at"] = policy["decided_at"]
    grant["approval_refs"] = []
    if approval is not None:
        grant["approval_refs"] = [
            {
                "record_type": "approval_record",
                "record_id": approval["approval_id"],
                "record_digest": approval["approval_digest"],
            }
        ]
        grant["constraints"].extend(copy.deepcopy(approval["constraints"]))
    return apply_object_digest(grant)


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
    grant = _grant_for_result(
        records["authorization_grant"], approved, approval=dict(approved.approval)
    )
    AuthorizationGrant(grant, expected_tenant=approved.request["tenant_id"])
    validate_grant_binding(
        grant,
        approved.request,
        approved.policy,
        [approved.approval],
        constraint_registry=ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
        verifier=verifier,
        trust=trust_factory(now=NOW),
    )


@pytest.mark.parametrize(
    ("registry", "constraint_id", "constraint_version"),
    [
        (None, "example.org/max_actions", "1.0"),
        (ConstraintRegistry({}), "example.org/max_actions", "1.0"),
        (
            ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
            "unsupported.example/rule",
            "1.0",
        ),
        (
            ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
            "example.org/max_actions",
            "2.0",
        ),
    ],
)
def test_unsupported_approval_constraints_fail_before_evidence_or_state_change(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Any,
    registry: ConstraintRegistry | None,
    constraint_id: str,
    constraint_version: str,
) -> None:
    if registry is None:
        kernel = GovernanceKernel(
            policy=_approval_policy(),
            identity_verifier=RecordingIdentityVerifier(),
            approval_verifier=verifier,
            approval_trust=lambda now: trust_factory(now=now),
            clock=lambda: NOW,
        )
    else:
        kernel = _kernel(verifier, trust_factory, constraint_registry=registry)
    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    approval = _bound_approval(
        records["approval_record"], policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    approval["constraints"][0]["constraint_id"] = constraint_id
    approval["constraints"][0]["constraint_version"] = constraint_version
    apply_object_digest(approval)

    with pytest.raises(SemanticError, match="unsupported constraint"):
        kernel.accept_approval(
            tenant_id=awaiting.request["tenant_id"],
            request_id=awaiting.request["request_id"],
            approval=approval,
        )
    stored = kernel.get(
        actor_context=records["actor_context"], request_id=awaiting.request["request_id"]
    )
    assert stored.state is KernelLifecycle.APPROVAL_REQUIRED
    assert stored.approval is None
    assert len(kernel.events(actor_context=records["actor_context"])) == 1


def test_unconstrained_approval_remains_valid_with_empty_registry(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory, constraint_registry=ConstraintRegistry({}))
    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    approval = _bound_approval(
        records["approval_record"], policy=dict(awaiting.policy), request=dict(awaiting.request)
    )
    approval["constraints"] = []
    apply_object_digest(approval)

    assert (
        kernel.accept_approval(
            tenant_id=awaiting.request["tenant_id"],
            request_id=awaiting.request["request_id"],
            approval=approval,
        ).state
        is KernelLifecycle.APPROVED
    )


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


def test_future_request_fails_before_policy_evidence_or_state(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    records["tool_request"]["requested_at"] = "2026-01-01T00:12:00.001Z"
    apply_object_digest(records["tool_request"])

    with pytest.raises(IdentityError, match="future"):
        kernel.submit(actor_context=records["actor_context"], tool_request=records["tool_request"])
    assert kernel.events(actor_context=records["actor_context"]) == ()
    with pytest.raises(LifecycleError):
        kernel.get(
            actor_context=records["actor_context"],
            request_id=records["tool_request"]["request_id"],
        )


@pytest.mark.parametrize("requested_at", ["2026-01-01T00:12:00.000Z", "2026-01-01T00:08:00.000Z"])
@pytest.mark.parametrize(
    ("decision", "expected_state"),
    [
        ("authorize", KernelLifecycle.POLICY_AUTHORIZED),
        ("require_approval", KernelLifecycle.APPROVAL_REQUIRED),
    ],
)
def test_current_and_past_requests_produce_non_predating_policy_decisions(
    requested_at: str,
    decision: str,
    expected_state: KernelLifecycle,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Any,
) -> None:
    records["tool_request"]["requested_at"] = requested_at
    apply_object_digest(records["tool_request"])
    kernel = GovernanceKernel(
        policy=PolicySet(
            rules=(
                PolicyRule(
                    rule_id=f"effects.chronology.{decision}.v1",
                    decision=decision,
                    effect_classes=frozenset({"write_external"}),
                    isolation_profile="none",
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
    assert result.policy["decided_at"] == "2026-01-01T00:12:00.000Z"
    assert result.policy["decided_at"] >= result.request["requested_at"]


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
    for isolation_profile in ("no_effect", "unsupported"):
        with pytest.raises(PolicyConfigurationError, match="executable isolation profile"):
            PolicyRule(
                rule_id="effects.invalid_profile.v1",
                decision=decision,
                effect_classes=frozenset({"write_external"}),
                isolation_profile=isolation_profile,
            )
    with pytest.raises(PolicyConfigurationError, match="deny rules"):
        PolicyRule(
            rule_id="effects.invalid_deny.v1",
            decision="deny",
            effect_classes=frozenset({"write_external"}),
            isolation_profile="container",
        )


@pytest.mark.parametrize(
    ("decision", "expected_state"),
    [
        ("authorize", KernelLifecycle.POLICY_AUTHORIZED),
        ("require_approval", KernelLifecycle.APPROVAL_REQUIRED),
    ],
)
def test_none_isolation_profile_is_schema_and_grant_compatible(
    decision: str,
    expected_state: KernelLifecycle,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Any,
) -> None:
    kernel = GovernanceKernel(
        policy=PolicySet(
            rules=(
                PolicyRule(
                    rule_id=f"effects.none.{decision}.v1",
                    decision=decision,
                    effect_classes=frozenset({"write_external"}),
                    isolation_profile="none",
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
    assert result.policy["isolation_profile"] == "none"
    assert result.policy["decided_at"] >= result.request["requested_at"]

    approvals: list[dict[str, Any]] = []
    approval = None
    if decision == "require_approval":
        approval = _bound_approval(
            records["approval_record"],
            policy=dict(result.policy),
            request=dict(result.request),
        )
        approval["constraints"] = []
        apply_object_digest(approval)
        approvals.append(approval)
    grant = _grant_for_result(records["authorization_grant"], result, approval=approval)
    AuthorizationGrant(grant, expected_tenant=result.request["tenant_id"])
    validate_grant_binding(
        grant,
        result.request,
        result.policy,
        approvals,
        constraint_registry=ConstraintRegistry({}),
        verifier=verifier,
        trust=trust_factory(now=NOW),
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
    errors = []
    for scoped_actor, request_id in (
        (other_actor, submitted.request["request_id"]),
        (records["actor_context"], "018f0000-0000-7000-8000-000000000778"),
    ):
        with pytest.raises(LifecycleError) as exc_info:
            kernel.get(actor_context=scoped_actor, request_id=request_id)
        errors.append((type(exc_info.value), str(exc_info.value)))
    assert errors[0] == errors[1]
    assert kernel.events(actor_context=other_actor) == ()
    other_tenant = _other_tenant(copy.deepcopy(records["actor_context"]))
    with pytest.raises(LifecycleError, match="actor-scoped request not found"):
        kernel.get(actor_context=other_tenant, request_id=submitted.request["request_id"])
    expired = copy.deepcopy(records["actor_context"])
    expired["expires_at"] = "2026-01-01T00:11:00.000Z"
    with pytest.raises(IdentityError, match="expired"):
        kernel.events(actor_context=expired)
    future_issued = copy.deepcopy(records["actor_context"])
    future_issued["issued_at"] = "2026-01-01T00:12:00.001Z"
    apply_object_digest(future_issued)
    with pytest.raises(IdentityError, match="not currently valid"):
        kernel.get(actor_context=future_issued, request_id=submitted.request["request_id"])
    untrusted = RecordingIdentityVerifier(accepted=False)
    blocked = _kernel(verifier, trust_factory, untrusted)
    with pytest.raises(IdentityError, match="not trusted"):
        blocked.events(actor_context=records["actor_context"])


def test_actor_event_partition_hides_other_actor_evidence_content(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    first_actor = records["actor_context"]
    first_request = records["tool_request"]
    kernel.submit(actor_context=first_actor, tool_request=first_request)

    second_actor = copy.deepcopy(first_actor)
    second_actor["actor_id"] = "018f0000-0000-7000-8000-000000000777"
    apply_object_digest(second_actor)
    second_request = copy.deepcopy(first_request)
    second_request["actor_id"] = second_actor["actor_id"]
    second_request["actor_context_digest"] = sha256_digest(second_actor)
    second_request["request_id"] = "018f0000-0000-7000-8000-000000000778"
    second_request["idempotency"]["idempotency_key"] = "fixture.operation.actor2"
    apply_object_digest(second_request)
    kernel.submit(actor_context=second_actor, tool_request=second_request)

    first_events = kernel.events(actor_context=first_actor)
    second_events = kernel.events(actor_context=second_actor)
    assert len(first_events) == len(second_events) == 1
    assert {event["draft"]["inline_payload"]["actor_id"] for event in first_events} == {
        first_actor["actor_id"]
    }
    assert {event["draft"]["inline_payload"]["actor_id"] for event in second_events} == {
        second_actor["actor_id"]
    }


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


def test_concurrent_conflicting_replay_has_one_winner_and_one_evidence_event(
    records: dict[str, dict[str, Any]], verifier: Any, trust_factory: Any
) -> None:
    kernel = _kernel(verifier, trust_factory)
    original = records["tool_request"]
    conflicting = copy.deepcopy(original)
    conflicting["request_id"] = "018f0000-0000-7000-8000-000000000777"
    conflicting["effect_classes"] = ["read_external"]
    apply_object_digest(conflicting)

    def submit(request: dict[str, Any]) -> tuple[str, str]:
        try:
            result = kernel.submit(actor_context=records["actor_context"], tool_request=request)
        except IdempotencyConflictError as exc:
            return "conflict", str(exc)
        return "accepted", result.request["request_digest"]

    submissions = [original, conflicting] * 4
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(submit, submissions))

    accepted_digests = {value for status, value in outcomes if status == "accepted"}
    assert len(accepted_digests) == 1
    assert {status for status, _ in outcomes} == {"accepted", "conflict"}
    assert len(kernel.events(actor_context=records["actor_context"])) == 1
