"""Focused negative, adversarial, isolation, chronology, and concurrency proofs."""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable, Mapping
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
    EffectConfigurationError,
    ExecutorCapabilities,
    GovernanceKernel,
    InMemoryEvidenceLedger,
    KernelLifecycle,
    LifecycleError,
    PolicyRule,
    PolicySet,
)


NOW = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)
OTHER_ACTOR = "018f0000-0000-7000-8000-000000000998"
OTHER_TENANT = "018f0000-0000-7000-8000-000000000999"


class AcceptingIdentityVerifier:
    def verify(self, *, actor_context: Mapping[str, Any]) -> bool:
        return True


class RecordingVerifier:
    def __init__(self, *, accepted: bool = True) -> None:
        self.accepted = accepted
        self.calls: list[dict[str, Any]] = []

    def verify(self, **values: Any) -> bool:
        self.calls.append(copy.deepcopy(values))
        return self.accepted


class ExactGrantIssuer:
    def __init__(self, mutator: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.mutator = mutator
        self.calls: list[dict[str, Any]] = []

    def issue(self, *, unsigned_grant: Mapping[str, Any]) -> Mapping[str, Any]:
        grant = copy.deepcopy(dict(unsigned_grant))
        self.calls.append(copy.deepcopy(grant))
        if self.mutator is not None:
            self.mutator(grant)
        grant["proof"] = {
            "issuer": "policy.authority",
            "key_id": "policy.key.v1",
            "algorithm": "fixture-proof-v1",
            "proof_domain": "authorization_grant.v1",
            "object_digest": "sha256:" + "0" * 64,
            "nonce": "N" * 22,
            "detached_proof": "P" * 43,
        }
        return apply_object_digest(grant)


class RecordingExecutor:
    def __init__(
        self,
        *,
        effect_classes: frozenset[str] = frozenset({"write_external"}),
        isolation_profiles: frozenset[str] = frozenset({"none"}),
        constraints: ConstraintRegistry | None = None,
        raw_result: Any | None = None,
        on_execute: Callable[[], None] | None = None,
    ) -> None:
        self.capabilities = ExecutorCapabilities(
            effect_classes=effect_classes,
            isolation_profiles=isolation_profiles,
            constraints=constraints
            if constraints is not None
            else ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
        )
        self.calls: list[dict[str, Any]] = []
        self.reverted_grants: list[str] = []
        self.raw_result = raw_result
        self.on_execute = on_execute
        self._lock = threading.Lock()

    def execute(
        self, *, request: Mapping[str, Any], authorization_grant: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        effect = {
            "request_digest": request["request_digest"],
            "grant_id": authorization_grant["grant_id"],
            "arguments": copy.deepcopy(request["arguments"]),
        }
        with self._lock:
            self.calls.append(effect)
            effect_number = len(self.calls)
        if self.on_execute is not None:
            self.on_execute()
        if self.raw_result is not None:
            return self.raw_result
        return {"result": "synthetic", "effect_number": effect_number}

    def revert(
        self,
        *,
        request: Mapping[str, Any],
        authorization_grant: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        with self._lock:
            for index in range(len(self.calls) - 1, -1, -1):
                if self.calls[index]["grant_id"] == authorization_grant["grant_id"]:
                    self.calls.pop(index)
                    self.reverted_grants.append(authorization_grant["grant_id"])
                    return


class MutableClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class SequentialIds:
    def __init__(self) -> None:
        self._value = 2000
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            self._value += 1
            return f"018f0000-0000-7000-8000-{self._value:012x}"


class FailingEvidenceLedger(InMemoryEvidenceLedger):
    def __init__(self, *, fail_event: str, clock: Callable[[], datetime]) -> None:
        super().__init__(clock=clock, ids=SequentialIds())
        self.fail_event = fail_event

    def append(self, **values: Any) -> dict[str, Any]:
        if values["event_kind"] == self.fail_event:
            raise SemanticError(f"injected evidence failure for {self.fail_event}")
        return super().append(**values)


def _constraint(records: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return copy.deepcopy(records["policy_decision"]["constraints"][0])


def _policy(
    records: Mapping[str, Mapping[str, Any]],
    *,
    decision: str = "require_approval",
    constraints: tuple[Mapping[str, Any], ...] | None = None,
) -> PolicySet:
    return PolicySet(
        rules=(
            PolicyRule(
                rule_id=f"effects.phase3.{decision}.v1",
                decision=decision,
                effect_classes=frozenset({"write_external"}),
                isolation_profile="none" if decision != "deny" else "no_effect",
                constraints=constraints
                if constraints is not None
                else ((_constraint(records),) if decision != "deny" else ()),
            ),
        )
    )


def _kernel(
    records: Mapping[str, Mapping[str, Any]],
    trust_factory: Callable[..., Any],
    *,
    decision: str = "require_approval",
    issuer: ExactGrantIssuer | None = None,
    executor: RecordingExecutor | None = None,
    grant_verifier: RecordingVerifier | None = None,
    clock: MutableClock | None = None,
    evidence_ledger: InMemoryEvidenceLedger | None = None,
    policy: PolicySet | None = None,
) -> tuple[GovernanceKernel, ExactGrantIssuer, RecordingExecutor, MutableClock]:
    active_clock = clock or MutableClock()
    active_issuer = issuer or ExactGrantIssuer()
    active_executor = executor or RecordingExecutor()
    approval_verifier = RecordingVerifier()
    active_grant_verifier = grant_verifier or RecordingVerifier()
    kernel = GovernanceKernel(
        policy=policy or _policy(records, decision=decision),
        identity_verifier=AcceptingIdentityVerifier(),
        approval_verifier=approval_verifier,
        approval_trust=lambda now: trust_factory(now=now),
        grant_issuer=active_issuer,
        grant_verifier=active_grant_verifier,
        grant_trust=lambda now: trust_factory(now=now),
        executor=active_executor,
        constraint_registry=ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
        clock=active_clock,
        nonce_factory=lambda: "G" * 22,
        evidence_ledger=evidence_ledger,
    )
    return kernel, active_issuer, active_executor, active_clock


def _submit(kernel: GovernanceKernel, records: Mapping[str, Mapping[str, Any]]) -> Any:
    return kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )


def _approve(
    kernel: GovernanceKernel,
    records: Mapping[str, Mapping[str, Any]],
    awaiting: Any,
) -> Any:
    approval = copy.deepcopy(records["approval_record"])
    approval["tenant_id"] = awaiting.request["tenant_id"]
    approval["request_id"] = awaiting.request["request_id"]
    approval["request_digest"] = awaiting.request["request_digest"]
    approval["policy_decision_id"] = awaiting.policy["decision_id"]
    approval["policy_decision_digest"] = awaiting.policy["decision_digest"]
    approval["constraints"] = copy.deepcopy(awaiting.policy["constraints"])
    apply_object_digest(approval)
    return kernel.accept_approval(
        tenant_id=awaiting.request["tenant_id"],
        request_id=awaiting.request["request_id"],
        approval=approval,
    )


def _approved_kernel(
    records: Mapping[str, Mapping[str, Any]], trust_factory: Callable[..., Any], **values: Any
) -> tuple[GovernanceKernel, ExactGrantIssuer, RecordingExecutor, MutableClock, Any]:
    kernel, issuer, executor, clock = _kernel(records, trust_factory, **values)
    approved = _approve(kernel, records, _submit(kernel, records))
    return kernel, issuer, executor, clock, approved


@pytest.mark.parametrize("decision", ["require_approval", "deny"])
def test_grant_cannot_be_issued_before_authorized_or_approved_state(
    decision: str, records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    kernel, issuer, executor, _ = _kernel(records, trust_factory, decision=decision)
    result = _submit(kernel, records)

    with pytest.raises(LifecycleError, match="current lifecycle state"):
        kernel.issue_grant(
            actor_context=records["actor_context"], request_id=result.request["request_id"]
        )

    assert issuer.calls == []
    assert executor.calls == []
    assert len(kernel.events(actor_context=records["actor_context"])) == 1


def test_policy_authorized_state_issues_one_short_lived_exact_grant(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    kernel, issuer, executor, _ = _kernel(records, trust_factory, decision="authorize")
    authorized = _submit(kernel, records)

    granted = kernel.issue_grant(
        actor_context=records["actor_context"], request_id=authorized.request["request_id"]
    )
    replay = kernel.issue_grant(
        actor_context=records["actor_context"], request_id=authorized.request["request_id"]
    )

    assert granted.state is KernelLifecycle.GRANT_ISSUED
    assert granted.grant is not None
    assert granted.grant["issued_at"] == "2026-01-01T00:12:00.000Z"
    assert granted.grant["expires_at"] == "2026-01-01T00:17:00.000Z"
    assert granted.grant["approval_refs"] == []
    assert granted.grant["idempotency"] == granted.request["idempotency"]
    assert replay.to_dict() == granted.to_dict()
    assert len(issuer.calls) == 1
    assert executor.calls == []
    assert len(kernel.events(actor_context=records["actor_context"])) == 2


def test_approved_grant_binds_request_policy_approval_constraints_and_expiry(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    kernel, issuer, executor, _, approved = _approved_kernel(records, trust_factory)

    granted = kernel.issue_grant(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    grant = granted.grant
    assert grant is not None

    for field in (
        "tenant_id",
        "actor_id",
        "run_id",
        "request_id",
        "request_digest",
        "tool_id",
        "tool_version",
    ):
        assert grant[field] == granted.request[field]
    assert grant["policy_decision_id"] == granted.policy["decision_id"]
    assert grant["policy_decision_digest"] == granted.policy["decision_digest"]
    assert grant["approval_refs"] == [
        {
            "record_type": "approval_record",
            "record_id": granted.approval["approval_id"],
            "record_digest": granted.approval["approval_digest"],
        }
    ]
    assert grant["constraints"] == granted.policy["constraints"]
    assert grant["idempotency"] == granted.request["idempotency"]
    assert grant["isolation_profile"] == "none"
    assert grant["expires_at"] == "2026-01-01T00:17:00.000Z"
    assert len(issuer.calls) == 1
    assert executor.calls == []


@pytest.mark.parametrize("limiting_authority", ["actor", "approval"])
def test_grant_expiry_is_bounded_by_actor_or_approval_authority(
    limiting_authority: str,
    records: dict[str, dict[str, Any]],
    trust_factory: Callable[..., Any],
) -> None:
    if limiting_authority == "actor":
        records["actor_context"]["expires_at"] = "2026-01-01T00:14:00.000Z"
        records["tool_request"]["actor_context_digest"] = sha256_digest(records["actor_context"])
        apply_object_digest(records["tool_request"])
    else:
        records["approval_record"]["expires_at"] = "2026-01-01T00:14:00.000Z"
        apply_object_digest(records["approval_record"])
    kernel, _, _, _, approved = _approved_kernel(records, trust_factory)

    granted = kernel.issue_grant(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )

    assert granted.grant is not None
    assert granted.grant["expires_at"] == "2026-01-01T00:14:00.000Z"


def _mutate_actor(grant: dict[str, Any]) -> None:
    grant["actor_id"] = OTHER_ACTOR


def _mutate_run(grant: dict[str, Any]) -> None:
    grant["run_id"] = "018f0000-0000-7000-8000-000000000997"


def _mutate_request_digest(grant: dict[str, Any]) -> None:
    grant["request_digest"] = "sha256:" + "1" * 64


def _mutate_policy_digest(grant: dict[str, Any]) -> None:
    grant["policy_decision_digest"] = "sha256:" + "2" * 64


def _mutate_approvals(grant: dict[str, Any]) -> None:
    grant["approval_refs"] = []


def _mutate_constraints(grant: dict[str, Any]) -> None:
    grant["constraints"] = []


def _mutate_isolation(grant: dict[str, Any]) -> None:
    grant["isolation_profile"] = "process"


def _mutate_expiry(grant: dict[str, Any]) -> None:
    grant["expires_at"] = "2026-01-01T00:16:00.000Z"


def _mutate_idempotency(grant: dict[str, Any]) -> None:
    grant["idempotency"]["idempotency_key"] = "conflicting.effect.0001"


@pytest.mark.parametrize(
    "mutator",
    [
        _mutate_actor,
        _mutate_run,
        _mutate_request_digest,
        _mutate_policy_digest,
        _mutate_approvals,
        _mutate_constraints,
        _mutate_isolation,
        _mutate_expiry,
        _mutate_idempotency,
    ],
)
def test_grant_issuer_cannot_change_any_kernel_authored_binding(
    mutator: Callable[[dict[str, Any]], None],
    records: dict[str, dict[str, Any]],
    trust_factory: Callable[..., Any],
) -> None:
    issuer = ExactGrantIssuer(mutator)
    kernel, _, executor, _, approved = _approved_kernel(records, trust_factory, issuer=issuer)

    with pytest.raises(EffectConfigurationError, match="changed the kernel-authored"):
        kernel.issue_grant(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    stored = kernel.get(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    assert stored.state is KernelLifecycle.APPROVED
    assert stored.grant is None
    assert executor.calls == []
    assert len(kernel.events(actor_context=records["actor_context"])) == 2


def test_untrusted_grant_proof_fails_before_evidence_or_state_change(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    verifier = RecordingVerifier(accepted=False)
    kernel, _, executor, _, approved = _approved_kernel(
        records, trust_factory, grant_verifier=verifier
    )

    with pytest.raises(ProofVerificationError, match="detached proof"):
        kernel.issue_grant(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    assert len(verifier.calls) == 1
    assert executor.calls == []
    assert (
        kernel.get(
            actor_context=records["actor_context"], request_id=approved.request["request_id"]
        ).state
        is KernelLifecycle.APPROVED
    )
    assert len(kernel.events(actor_context=records["actor_context"])) == 2


def test_missing_broker_configuration_fails_before_grant_or_effect(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    issuer = ExactGrantIssuer()
    kernel = GovernanceKernel(
        policy=_policy(records),
        identity_verifier=AcceptingIdentityVerifier(),
        approval_verifier=RecordingVerifier(),
        approval_trust=lambda now: trust_factory(now=now),
        grant_issuer=issuer,
        grant_verifier=RecordingVerifier(),
        grant_trust=lambda now: trust_factory(now=now),
        constraint_registry=ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
        clock=lambda: NOW,
    )
    approved = _approve(kernel, records, _submit(kernel, records))

    with pytest.raises(EffectConfigurationError, match="effect broker requires"):
        kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    stored = kernel.get(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    assert stored.state is KernelLifecycle.APPROVED
    assert stored.grant is None
    assert issuer.calls == []
    assert len(kernel.events(actor_context=records["actor_context"])) == 2


@pytest.mark.parametrize(
    "actor_change",
    [
        lambda actor: actor.update(actor_id=OTHER_ACTOR),
        lambda actor: actor.update(tenant_id=OTHER_TENANT),
    ],
)
def test_other_actor_or_tenant_cannot_issue_or_dispatch(
    actor_change: Callable[[dict[str, Any]], None],
    records: dict[str, dict[str, Any]],
    trust_factory: Callable[..., Any],
) -> None:
    kernel, issuer, executor, _, approved = _approved_kernel(records, trust_factory)
    attacker = copy.deepcopy(records["actor_context"])
    actor_change(attacker)

    with pytest.raises(LifecycleError, match="actor-scoped request not found"):
        kernel.execute_effect(actor_context=attacker, request_id=approved.request["request_id"])

    assert issuer.calls == []
    assert executor.calls == []
    assert len(kernel.events(actor_context=records["actor_context"])) == 2


@pytest.mark.parametrize(
    "executor",
    [
        RecordingExecutor(effect_classes=frozenset()),
        RecordingExecutor(isolation_profiles=frozenset()),
        RecordingExecutor(constraints=ConstraintRegistry({})),
    ],
)
def test_unsupported_effect_isolation_or_constraint_fails_before_intent_and_effect(
    executor: RecordingExecutor,
    records: dict[str, dict[str, Any]],
    trust_factory: Callable[..., Any],
) -> None:
    kernel, _, _, _, approved = _approved_kernel(records, trust_factory, executor=executor)

    with pytest.raises(EffectConfigurationError, match="executor does not support"):
        kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    stored = kernel.get(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    assert stored.state is KernelLifecycle.APPROVED
    assert stored.grant is None
    assert stored.outcome is None
    assert executor.calls == []
    assert len(kernel.events(actor_context=records["actor_context"])) == 2


def test_expired_grant_fails_before_intent_effect_or_outcome(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    kernel, _, executor, clock, approved = _approved_kernel(records, trust_factory)
    granted = kernel.issue_grant(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    clock.now = datetime(2026, 1, 1, 0, 17, tzinfo=timezone.utc)

    with pytest.raises(EffectConfigurationError, match="grant is not currently valid"):
        kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    assert executor.calls == []
    assert (
        kernel.get(
            actor_context=records["actor_context"], request_id=approved.request["request_id"]
        ).to_dict()
        == granted.to_dict()
    )
    assert len(kernel.events(actor_context=records["actor_context"])) == 3


@pytest.mark.parametrize(
    "fail_event",
    ["kernel.authorization_grant_issued", "kernel.effect_execution_intent"],
)
def test_pre_execution_evidence_failure_creates_no_effect_or_invalid_transition(
    fail_event: str,
    records: dict[str, dict[str, Any]],
    trust_factory: Callable[..., Any],
) -> None:
    clock = MutableClock()
    ledger = FailingEvidenceLedger(fail_event=fail_event, clock=clock)
    kernel, _, executor, _, approved = _approved_kernel(
        records, trust_factory, clock=clock, evidence_ledger=ledger
    )

    with pytest.raises(SemanticError, match="injected evidence failure"):
        kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    stored = kernel.get(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    expected_state = (
        KernelLifecycle.APPROVED
        if fail_event == "kernel.authorization_grant_issued"
        else KernelLifecycle.GRANT_ISSUED
    )
    assert stored.state is expected_state
    assert stored.outcome is None
    assert executor.calls == []


def test_outcome_evidence_failure_reverts_the_only_allowed_synthetic_effect(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    clock = MutableClock()
    ledger = FailingEvidenceLedger(fail_event="kernel.effect_execution_outcome", clock=clock)
    kernel, _, executor, _, approved = _approved_kernel(
        records, trust_factory, clock=clock, evidence_ledger=ledger
    )

    with pytest.raises(SemanticError, match="injected evidence failure"):
        kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    stored = kernel.get(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    assert stored.state is KernelLifecycle.GRANT_ISSUED
    assert stored.outcome is None
    assert executor.calls == []
    assert len(executor.reverted_grants) == 1
    assert [
        event["draft"]["event_kind"]
        for event in kernel.events(actor_context=records["actor_context"])
    ] == [
        "kernel.policy_decided",
        "kernel.approval_accepted",
        "kernel.authorization_grant_issued",
        "kernel.effect_execution_intent",
    ]
    ledger.fail_event = "disabled"
    with pytest.raises(IdempotencyConflictError, match="consumed without"):
        kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )
    assert executor.calls == []


def test_malformed_executor_result_is_reverted_and_recorded_as_indeterminate(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    executor = RecordingExecutor(raw_result={"invalid": b"not-json"})
    kernel, _, _, _, approved = _approved_kernel(records, trust_factory, executor=executor)

    completed = kernel.execute_effect(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )

    assert completed.state is KernelLifecycle.EFFECT_INDETERMINATE
    assert completed.outcome is not None
    assert completed.outcome["status"] == "indeterminate"
    assert completed.outcome["result_payload"] == {"error": "executor_result_indeterminate"}
    assert executor.calls == []
    assert len(executor.reverted_grants) == 1


def test_clock_rollback_after_intent_reverts_effect_and_blocks_outcome_transition(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    clock = MutableClock()
    executor = RecordingExecutor(
        on_execute=lambda: setattr(clock, "now", datetime(2026, 1, 1, 0, 11, tzinfo=timezone.utc))
    )
    kernel, _, _, _, approved = _approved_kernel(
        records, trust_factory, executor=executor, clock=clock
    )

    with pytest.raises(LifecycleError, match="evidence time cannot precede"):
        kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        )

    clock.now = NOW
    stored = kernel.get(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    assert stored.state is KernelLifecycle.GRANT_ISSUED
    assert stored.outcome is None
    assert executor.calls == []
    assert len(executor.reverted_grants) == 1


def test_outcome_exactly_binds_actor_request_policy_approval_and_idempotency(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    kernel, _, executor, _, approved = _approved_kernel(records, trust_factory)
    completed = kernel.execute_effect(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    outcome = completed.outcome
    assert outcome is not None

    assert outcome["tenant_id"] == records["actor_context"]["tenant_id"]
    assert outcome["run_id"] == completed.request["run_id"]
    assert outcome["request_ref"] == {
        "record_type": "tool_request",
        "record_id": completed.request["request_id"],
        "record_digest": completed.request["request_digest"],
    }
    assert outcome["target_scope"]["actor_id"] == records["actor_context"]["actor_id"]
    assert outcome["target_scope"]["parent_digest"] == sha256_digest(records["actor_context"])
    assert outcome["target_scope"]["selection"] == {"level": "actor"}
    assert outcome["policy_refs"][0]["record_digest"] == completed.policy["decision_digest"]
    assert outcome["reviewer_refs"][0]["record_digest"] == completed.approval["approval_digest"]
    assert outcome["idempotency"] == completed.request["idempotency"]
    assert len(executor.calls) == 1


def test_concurrent_exact_replay_consumes_grant_once_and_returns_one_result(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    kernel, _, executor, _, approved = _approved_kernel(records, trust_factory)

    def execute(_: int) -> dict[str, Any]:
        return kernel.execute_effect(
            actor_context=records["actor_context"],
            request_id=approved.request["request_id"],
        ).to_dict()

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(execute, range(32)))

    assert all(result == results[0] for result in results)
    assert len(executor.calls) == 1
    assert len(kernel.events(actor_context=records["actor_context"])) == 5


def test_broker_rejects_conflicting_grant_replay_without_another_effect(
    records: dict[str, dict[str, Any]], trust_factory: Callable[..., Any]
) -> None:
    kernel, _, executor, _, approved = _approved_kernel(records, trust_factory)
    completed = kernel.execute_effect(
        actor_context=records["actor_context"], request_id=approved.request["request_id"]
    )
    conflicting_grant = copy.deepcopy(completed.grant)
    assert conflicting_grant is not None
    conflicting_grant["grant_id"] = "018f0000-0000-7000-8000-000000000996"
    conflicting_grant["grant_nonce"] = "Z" * 22
    apply_object_digest(conflicting_grant)
    broker = kernel._broker
    assert broker is not None

    with pytest.raises(IdempotencyConflictError, match="original governed bindings"):
        broker.dispatch(
            actor_context=records["actor_context"],
            request=completed.request,
            policy=completed.policy,
            approvals=(completed.approval,),
            authorization_grant=conflicting_grant,
        )

    assert len(executor.calls) == 1
    assert len(kernel.events(actor_context=records["actor_context"])) == 5
