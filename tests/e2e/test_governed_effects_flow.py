"""Public end-to-end proof for the bounded Phase 3 governed-effects flow."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from governed_agent_harness.contracts import (
    ConstraintRegistry,
    TrustContext,
    TrustedKey,
    apply_object_digest,
)
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.kernel import (
    ExecutorCapabilities,
    GovernanceKernel,
    KernelLifecycle,
    PolicyRule,
    PolicySet,
)


NOW = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)


class AcceptingVerifier:
    def verify(self, **values: object) -> bool:
        return True


class AcceptingIdentityVerifier:
    def verify(self, *, actor_context: Mapping[str, Any]) -> bool:
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
        self.calls: list[dict[str, Any]] = []
        self.evidence_probe: Callable[[], tuple[dict[str, Any], ...]] | None = None
        self.evidence_kinds_at_call: tuple[str, ...] = ()

    def execute(
        self, *, request: Mapping[str, Any], authorization_grant: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        assert self.evidence_probe is not None
        self.evidence_kinds_at_call = tuple(
            event["draft"]["event_kind"] for event in self.evidence_probe()
        )
        effect = {
            "tool_id": request["tool_id"],
            "arguments": copy.deepcopy(request["arguments"]),
            "grant_id": authorization_grant["grant_id"],
        }
        self.calls.append(effect)
        return {"result": "synthetic", "effect_number": len(self.calls)}

    def revert(
        self,
        *,
        request: Mapping[str, Any],
        authorization_grant: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        if self.calls and self.calls[-1]["grant_id"] == authorization_grant["grant_id"]:
            self.calls.pop()


def _trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="policy.authority",
                key_id="policy.key.v1",
                algorithms=frozenset({"fixture-proof-v1"}),
                valid_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
                valid_until=datetime(2026, 1, 2, tzinfo=timezone.utc),
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
        trust_policy_version="phase3.test.v1",
        clock_skew=timedelta(seconds=30),
    )


def test_public_approval_to_effect_flow_is_evidence_first_and_replay_safe() -> None:
    records = build_positive_records()
    constraint = copy.deepcopy(records["policy_decision"]["constraints"][0])
    executor = DeterministicExecutor()
    kernel = GovernanceKernel(
        policy=PolicySet(
            rules=(
                PolicyRule(
                    rule_id="effects.phase3.approval.v1",
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
    )

    awaiting = kernel.submit(
        actor_context=records["actor_context"], tool_request=records["tool_request"]
    )
    approval = records["approval_record"]
    approval["tenant_id"] = awaiting.request["tenant_id"]
    approval["request_id"] = awaiting.request["request_id"]
    approval["request_digest"] = awaiting.request["request_digest"]
    approval["policy_decision_id"] = awaiting.policy["decision_id"]
    approval["policy_decision_digest"] = awaiting.policy["decision_digest"]
    apply_object_digest(approval)
    approved = kernel.accept_approval(
        tenant_id=awaiting.request["tenant_id"],
        request_id=awaiting.request["request_id"],
        approval=approval,
    )
    assert approved.state is KernelLifecycle.APPROVED

    executor.evidence_probe = lambda: kernel.events(actor_context=records["actor_context"])
    completed = kernel.execute_effect(
        actor_context=records["actor_context"], request_id=awaiting.request["request_id"]
    )

    assert completed.state is KernelLifecycle.EFFECT_SUCCEEDED
    assert completed.grant is not None
    assert completed.grant["isolation_profile"] == "none"
    assert completed.outcome is not None
    assert completed.outcome["status"] == "succeeded"
    assert completed.outcome["result_payload"] == {
        "result": "synthetic",
        "effect_number": 1,
    }
    assert executor.evidence_kinds_at_call == (
        "kernel.policy_decided",
        "kernel.approval_accepted",
        "kernel.authorization_grant_issued",
        "kernel.effect_execution_intent",
    )
    assert tuple(event["draft"]["event_kind"] for event in completed.evidence) == (
        *executor.evidence_kinds_at_call,
        "kernel.effect_execution_outcome",
    )

    replay = kernel.execute_effect(
        actor_context=records["actor_context"], request_id=awaiting.request["request_id"]
    )
    assert replay.to_dict() == completed.to_dict()
    assert len(executor.calls) == 1
    assert len(kernel.events(actor_context=records["actor_context"])) == 5
