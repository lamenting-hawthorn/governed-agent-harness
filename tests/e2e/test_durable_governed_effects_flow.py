from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

import pytest

from governed_agent_harness.contracts import (
    ConstraintRegistry,
    TrustContext,
    TrustedKey,
    apply_object_digest,
    sha256_digest,
)
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.kernel import (
    ExecutorCapabilities,
    GovernanceKernel,
    KernelLifecycle,
    PolicyRule,
    PolicySet,
    PreparedExecutionError,
)


NOW = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)


class AcceptingIdentityVerifier:
    def verify(self, *, actor_context: Mapping[str, Any]) -> bool:
        return True


class AcceptingVerifier:
    def verify(self, **values: object) -> bool:
        return True


class DeterministicGrantIssuer:
    def issue(self, *, unsigned_grant: Mapping[str, Any]) -> Mapping[str, Any]:
        grant = copy.deepcopy(dict(unsigned_grant))
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


class DeterministicExecutor:
    capabilities = ExecutorCapabilities(
        effect_classes=frozenset({"write_external"}),
        isolation_profiles=frozenset({"none"}),
        constraints=ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
    )

    def __init__(self) -> None:
        self.calls = 0

    def execute(
        self, *, request: Mapping[str, Any], authorization_grant: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self.calls += 1
        return {"result": "synthetic", "call": self.calls}

    def revert(
        self,
        *,
        request: Mapping[str, Any],
        authorization_grant: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        self.calls = max(0, self.calls - 1)


def _trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="policy.authority",
                key_id="policy.key.v1",
                algorithms=frozenset({"fixture-proof-v1"}),
                valid_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
                valid_until=datetime(2027, 1, 1, tzinfo=timezone.utc),
            ),
        ),
        allowed_algorithms=frozenset({"fixture-proof-v1"}),
        allowed_proof_domains=frozenset({"approval_record.v1", "authorization_grant.v1"}),
        expected_issuers=frozenset({"policy.authority"}),
        allowed_domain_issuers=frozenset(
            {
                ("approval_record.v1", "policy.authority"),
                ("authorization_grant.v1", "policy.authority"),
            }
        ),
        trust_policy_version="phase4.test.v1",
        clock_skew=timedelta(seconds=30),
    )


def _approve(kernel: GovernanceKernel, records: dict[str, dict[str, Any]], awaiting: Any) -> None:
    approval = copy.deepcopy(records["approval_record"])
    approval.update(
        {
            "tenant_id": awaiting.request["tenant_id"],
            "request_id": awaiting.request["request_id"],
            "request_digest": awaiting.request["request_digest"],
            "policy_decision_id": awaiting.policy["decision_id"],
            "policy_decision_digest": awaiting.policy["decision_digest"],
            "constraints": copy.deepcopy(awaiting.policy["constraints"]),
            "issued_at": "2026-01-01T00:12:00.000Z",
            "expires_at": "2026-01-01T01:00:00.000Z",
        }
    )
    apply_object_digest(approval)
    kernel.accept_approval(
        tenant_id=awaiting.request["tenant_id"],
        request_id=awaiting.request["request_id"],
        approval=approval,
    )


def _kernel(
    records: dict[str, dict[str, Any]], store: Any, executor: DeterministicExecutor
) -> GovernanceKernel:
    constraint = copy.deepcopy(records["policy_decision"]["constraints"][0])
    return GovernanceKernel(
        policy=PolicySet(
            rules=(
                PolicyRule(
                    rule_id="effects.phase4.approval.v1",
                    decision="require_approval",
                    effect_classes=frozenset({"write_external"}),
                    isolation_profile="none",
                    constraints=(constraint,),
                ),
            )
        ),
        identity_verifier=AcceptingIdentityVerifier(),
        approval_verifier=AcceptingVerifier(),
        approval_trust=_trust,
        grant_issuer=DeterministicGrantIssuer(),
        grant_verifier=AcceptingVerifier(),
        grant_trust=_trust,
        executor=executor,
        constraint_registry=ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})}),
        clock=lambda: NOW,
        durable_store=store,
    )


def test_public_durable_flow_replays_after_kernel_restart(postgres_connections):
    records = build_positive_records()
    first_executor = DeterministicExecutor()
    first = _kernel(records, postgres_connections["store"](), first_executor)
    awaiting = first.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    _approve(first, records, awaiting)
    completed = first.execute_effect(
        actor_context=records["actor_context"], request_id=awaiting.request["request_id"]
    )
    assert completed.state is KernelLifecycle.EFFECT_SUCCEEDED
    assert first_executor.calls == 1
    assert tuple(event["draft"]["event_kind"] for event in completed.evidence) == (
        "kernel.policy_decided",
        "kernel.approval_accepted",
        "kernel.authorization_grant_issued",
        "kernel.effect_execution_intent",
        "kernel.effect_execution_outcome",
    )

    restarted_executor = DeterministicExecutor()
    restarted = _kernel(records, postgres_connections["store"](), restarted_executor)
    replay = restarted.execute_effect(
        actor_context=records["actor_context"], request_id=awaiting.request["request_id"]
    )
    assert replay.outcome == completed.outcome
    assert replay.state is KernelLifecycle.EFFECT_SUCCEEDED
    assert tuple(
        event["draft"]["event_kind"]
        for event in restarted.events(actor_context=records["actor_context"])
    ) == tuple(event["draft"]["event_kind"] for event in completed.evidence)
    assert restarted_executor.calls == 0


def test_prepared_restart_requires_explicit_recovery_and_never_executes(postgres_connections):
    records = build_positive_records()
    store = postgres_connections["store"]()
    actor = records["actor_context"]
    request = records["tool_request"]
    policy = records["policy_decision"]
    approval = copy.deepcopy(records["approval_record"])
    approval["constraints"] = copy.deepcopy(policy["constraints"])
    grant = copy.deepcopy(records["authorization_grant"])
    grant["idempotency"] = copy.deepcopy(request["idempotency"])
    apply_object_digest(grant)
    prepared = store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=(approval,),
        grant=grant,
        policy_ref={
            "record_type": "policy_decision",
            "record_id": policy["decision_id"],
            "record_digest": policy["decision_digest"],
        },
        intent_payload={
            "actor_id": actor["actor_id"],
            "request_digest": request["request_digest"],
            "policy_decision_digest": policy["decision_digest"],
            "authorization_grant_digest": sha256_digest(grant),
            "effect_classes": copy.deepcopy(request["effect_classes"]),
            "isolation_profile": grant["isolation_profile"],
        },
    )
    restarted = _kernel(records, postgres_connections["store"](), DeterministicExecutor())
    with pytest.raises(PreparedExecutionError):
        restarted.execute_effect(actor_context=actor, request_id=request["request_id"])
    recovered = restarted.recover_effect(
        actor_context=actor,
        request_id=request["request_id"],
        confirm_dispatch_owner_abandoned=True,
    )
    assert recovered.state is KernelLifecycle.EFFECT_INDETERMINATE
    assert recovered.outcome is not None
    assert recovered.outcome["status"] == "indeterminate"
    assert (
        prepared.version
        < store.lookup(actor_context=actor, request_id=request["request_id"]).version
    )
