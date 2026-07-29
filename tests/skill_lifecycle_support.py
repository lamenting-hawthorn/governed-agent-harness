"""Schema-valid fixture assembly shared by skill lifecycle database tests."""

from __future__ import annotations

import copy

from governed_agent_harness.contracts import apply_object_digest, sha256_digest
from governed_agent_harness.contracts.positive_fixtures import build_positive_records


def ref(record_type: str, record_id: str, digest: str) -> dict[str, str]:
    return {"record_type": record_type, "record_id": record_id, "record_digest": digest}


def command() -> tuple[dict[str, object], dict[str, object]]:
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
    policy_ref = ref("policy_decision", policy["decision_id"], policy["decision_digest"])
    gate["proposal_refs"] = [
        ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
    ]
    apply_object_digest(gate)
    delivery.update(
        {
            "artifact_digest": sha256_digest(proposal["artifact"]),
            "gate_decision_ref": ref("gate_decision", gate["gate_id"], gate["decision_digest"]),
            "policy_refs": [policy_ref],
            "reviewer_refs": copy.deepcopy(proposal["reviewer_refs"]),
        }
    )
    apply_object_digest(delivery)
    return actor, {
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
