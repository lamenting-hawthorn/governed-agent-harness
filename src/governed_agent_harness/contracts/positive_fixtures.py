"""Deterministic synthetic positive fixtures and canonicalization vectors."""

from __future__ import annotations

import copy
import json
from typing import Any

from .canonical import canonical_bytes, sha256_digest
from .validation import SELF_DIGEST_FIELDS, apply_object_digest

TENANT_ID = "018f0000-0000-7000-8000-000000000001"


def _uuid(index: int) -> str:
    return f"018f0000-0000-7000-8000-{index:012x}"


def _digest(label: str) -> str:
    return sha256_digest({"fixture": label})


def _idempotency(index: int) -> dict[str, Any]:
    return {
        "tenant_id": TENANT_ID,
        "idempotency_key": f"fixture.operation.{index:04d}",
        "operation_digest": _digest(f"operation-{index}"),
    }


def _record_ref(record_type: str, record_id: str, digest: str) -> dict[str, Any]:
    return {"record_type": record_type, "record_id": record_id, "record_digest": digest}


def _ref(record: dict[str, Any], id_field: str) -> dict[str, Any]:
    digest_field = SELF_DIGEST_FIELDS.get(record["record_type"])
    digest = record[digest_field] if digest_field else sha256_digest(record)
    return _record_ref(record["record_type"], record[id_field], digest)


def _compatibility(*record_types: str) -> dict[str, Any]:
    return {
        "contract_versions": [f"{record_type}=1.0" for record_type in record_types],
        "runtime_version_range": ">=1.0",
    }


def _retention() -> dict[str, Any]:
    return {
        "policy_id": "retention.standard.v1",
        "expires_at": "2028-01-01T00:00:00.000Z",
        "deletion_mode": "retain_non_sensitive_tombstone",
    }


def _evidence_span(evidence_id: str) -> dict[str, Any]:
    return {"evidence_id": evidence_id, "payload_digest": _digest(f"payload-{evidence_id}")}


def _truth_confidence(evidence_id: str) -> dict[str, Any]:
    return {
        "value_millionths": 900000,
        "basis": "observed",
        "evidence_ids": [evidence_id],
    }


def _task_quality() -> dict[str, Any]:
    return {
        "score_millionths": 850000,
        "metric": "fixture.quality",
        "evaluator_version": "evaluator.v1",
    }


def _proof(domain: str) -> dict[str, Any]:
    if domain in {"approval_record.v1", "authorization_grant.v1"}:
        issuer, key_id = "policy.authority", "policy.key.v1"
    elif domain == "delivery_envelope.v1":
        issuer, key_id = "learning.authority", "learning.key.v1"
    else:
        issuer, key_id = "runtime.authority", "runtime.key.v1"
    return {
        "issuer": issuer,
        "key_id": key_id,
        "algorithm": "fixture-proof-v1",
        "proof_domain": domain,
        "object_digest": _digest("pending-proof-object"),
        "nonce": "N" * 22,
        "detached_proof": "P" * 43,
    }


def _constraint() -> dict[str, Any]:
    parameters: dict[str, Any] = {"maximum": 1}
    return {
        "constraint_id": "example.org/max_actions",
        "constraint_version": "1.0",
        "parameters": parameters,
        "parameters_digest": sha256_digest(parameters),
    }


def _finalize(record: dict[str, Any]) -> dict[str, Any]:
    for value in record.values():
        if isinstance(value, dict) and "schema_version" in value and "record_type" in value:
            _finalize(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "schema_version" in item and "record_type" in item:
                    _finalize(item)
    if record.get("record_type") == "evidence_envelope":
        record["draft_digest"] = sha256_digest(record["draft"])
        draft = record["draft"]
        record["payload_digest"] = (
            sha256_digest(draft["inline_payload"])
            if "inline_payload" in draft
            else draft["protected_payload"]["payload_digest"]
        )
    return apply_object_digest(record)


def build_positive_records() -> dict[str, dict[str, Any]]:
    """Build one coherent positive fixture for each catalog record type."""

    records: dict[str, dict[str, Any]] = {}
    actor = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "actor_context",
            "tenant_id": TENANT_ID,
            "actor_id": _uuid(2),
            "session_id": _uuid(3),
            "auth": {
                "issuer": "fixture.identity",
                "method": "federated",
                "assurance_level": 2,
                "verified_at": "2026-01-01T00:00:00.000Z",
            },
            "roles": ["operator"],
            "capabilities": ["memory.read"],
            "trust_level": "verified_human",
            "scope_authority": {
                "allowed_levels": [
                    "actor",
                    "user",
                    "session",
                    "workspace",
                    "project",
                    "team",
                    "organization",
                ],
                "user_id": _uuid(43),
                "team_ids": [_uuid(44)],
                "organization_ids": [_uuid(45)],
                "project_ids": [_uuid(46)],
                "workspace_ids": [_uuid(47)],
                "public_allowed": True,
            },
            "issued_at": "2026-01-01T00:00:01.000Z",
            "expires_at": "2026-01-01T01:00:00.000Z",
            "correlation_id": _uuid(4),
            "extensions": {"example.org/fixture": {"deterministic": True}},
        }
    )
    records["actor_context"] = actor

    scope = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "memory_scope",
            "scope_id": _uuid(5),
            "tenant_id": TENANT_ID,
            "actor_id": actor["actor_id"],
            "parent_record_type": "actor_context",
            "parent_digest": sha256_digest(actor),
            "selection": {
                "level": "project",
                "project_id": actor["scope_authority"]["project_ids"][0],
            },
            "derived_at": "2026-01-01T00:00:02.000Z",
            "valid_until": "2026-01-01T01:00:00.000Z",
        }
    )
    records["memory_scope"] = scope

    evidence_draft = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "evidence_draft",
            "tenant_id": TENANT_ID,
            "event_id": _uuid(6),
            "run_id": _uuid(7),
            "event_kind": "fixture.observed",
            "occurred_at": "2026-01-01T00:01:00.000Z",
            "idempotency": _idempotency(1),
            "classification": "internal",
            "redaction_status": "redacted",
            "inline_payload": {"message": "synthetic fixture"},
        }
    )
    records["evidence_draft"] = evidence_draft

    policy_ref = _record_ref("policy_proposal", _uuid(90), _digest("policy-ref"))
    evidence_envelope = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "evidence_envelope",
            "tenant_id": TENANT_ID,
            "envelope_id": _uuid(8),
            "draft": copy.deepcopy(evidence_draft),
            "draft_digest": _digest("pending-draft"),
            "recorded_at": "2026-01-01T00:02:00.000Z",
            "sequence_number": 1,
            "payload_digest": _digest("pending-payload"),
            "prior_event_digest": None,
            "event_digest": _digest("pending-event"),
            "policy_refs": [policy_ref],
            "storage_writer_id": "evidence.writer.v1",
        }
    )
    records["evidence_envelope"] = evidence_envelope
    evidence_ref = _ref(evidence_envelope, "envelope_id")

    trace = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "learning_trace_envelope",
            "tenant_id": TENANT_ID,
            "trace_id": _uuid(9),
            "run_id": evidence_draft["run_id"],
            "scope": copy.deepcopy(scope),
            "completion_state": "completed",
            "evidence_refs": [evidence_ref],
            "tool_evidence_refs": [],
            "versions": {"runtime": "runtime.v1", "adapter": "adapter.v1", "contract_set": "1.0"},
            "source_digest": _digest("trace-source"),
            "normalized_digest": _digest("trace-normalized"),
            "redaction": {"policy_id": "redaction.v1", "status": "redacted"},
            "retention": _retention(),
            "exported_at": "2026-01-01T00:03:00.000Z",
            "export_digest": _digest("pending-export"),
            "idempotency": _idempotency(2),
        }
    )
    records["learning_trace_envelope"] = trace

    query = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "memory_query",
            "tenant_id": TENANT_ID,
            "query_id": _uuid(10),
            "scope": copy.deepcopy(scope),
            "query": "synthetic fixture query",
            "retrieval_profile": "fast",
            "budget": {"max_records": 10, "timeout_ms": 1000},
            "allowed_categories": ["fact"],
            "temporal_bound": {
                "from": "2025-01-01T00:00:00.000Z",
                "until": "2026-01-01T00:00:00.000Z",
            },
            "correlation_id": actor["correlation_id"],
            "idempotency": _idempotency(3),
        }
    )
    records["memory_query"] = query

    memory = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "memory_record",
            "tenant_id": TENANT_ID,
            "memory_id": _uuid(11),
            "revision": 1,
            "proposition": {
                "kind": "fact",
                "subject": "fixture subject",
                "predicate": "has.value",
                "value": "synthetic",
            },
            "entity_ids": [_uuid(12)],
            "scope": copy.deepcopy(scope),
            "visibility": "project",
            "observed_at": "2026-01-01T00:01:00.000Z",
            "effective_from": "2026-01-01T00:01:00.000Z",
            "effective_until": None,
            "expires_at": "2027-01-01T00:00:00.000Z",
            "truth_confidence": _truth_confidence(evidence_draft["event_id"]),
            "provenance": [_evidence_span(evidence_draft["event_id"])],
            "sensitivity": "internal",
            "retention": _retention(),
            "lifecycle_state": "candidate",
            "embedding_space_version": "embedding.v1",
            "record_digest": _digest("pending-memory"),
        }
    )
    records["memory_record"] = memory

    memory_proposal = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "memory_proposal",
            "tenant_id": TENANT_ID,
            "proposal_id": _uuid(13),
            "target_scope": copy.deepcopy(scope),
            "change_kind": "create",
            "proposed_record": copy.deepcopy(memory),
            "evidence_spans": [_evidence_span(evidence_draft["event_id"])],
            "producer": {
                "producer_id": "learner.v1",
                "producer_version": "1.0",
                "run_id": _uuid(14),
            },
            "truth_confidence": _truth_confidence(evidence_draft["event_id"]),
            "task_quality": _task_quality(),
            "compatibility": _compatibility("memory_proposal", "memory_record"),
            "expires_at": "2027-01-01T00:00:00.000Z",
            "lifecycle_state": "pending",
            "proposal_digest": _digest("pending-memory-proposal"),
        }
    )
    records["memory_proposal"] = memory_proposal

    memory_decision = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "memory_decision",
            "tenant_id": TENANT_ID,
            "decision_id": _uuid(15),
            "proposal_ref": _ref(memory_proposal, "proposal_id"),
            "disposition": "accept",
            "policy_refs": [policy_ref],
            "rule_refs": ["memory.accept.v1"],
            "constraints": [_constraint()],
            "reason_code": "fixture.accepted",
            "actor_context_digest": sha256_digest(actor),
            "decided_at": "2026-01-01T00:04:00.000Z",
            "decision_digest": _digest("pending-memory-decision"),
        }
    )
    records["memory_decision"] = memory_decision

    context_bundle = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "context_bundle",
            "tenant_id": TENANT_ID,
            "bundle_id": _uuid(16),
            "query_id": query["query_id"],
            "scope_digest": sha256_digest(scope),
            "records": [
                {
                    "memory_id": memory["memory_id"],
                    "revision": memory["revision"],
                    "memory_type": "fact",
                    "citation": _evidence_span(evidence_draft["event_id"]),
                    "component_scores": {
                        "relevance": 900000,
                        "recency": 800000,
                        "confidence": 900000,
                    },
                }
            ],
            "retrieval_profile": "fast",
            "timeout_state": "within_budget",
            "degradation_state": "none",
            "generated_at": "2026-01-01T00:05:00.000Z",
            "bundle_digest": _digest("pending-context-bundle"),
        }
    )
    records["context_bundle"] = context_bundle

    write_receipt = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "write_receipt",
            "tenant_id": TENANT_ID,
            "receipt_id": _uuid(17),
            "request_id": _uuid(18),
            "source_event_id": evidence_draft["event_id"],
            "resulting_revisions": [_ref(memory, "memory_id")],
            "evidence_ids": [evidence_draft["event_id"]],
            "status": "committed",
            "idempotency": _idempotency(4),
            "issued_at": "2026-01-01T00:06:00.000Z",
            "receipt_digest": _digest("pending-write-receipt"),
        }
    )
    records["write_receipt"] = write_receipt

    deletion_receipt = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "deletion_receipt",
            "tenant_id": TENANT_ID,
            "receipt_id": _uuid(19),
            "request_id": _uuid(20),
            "mode": "preview",
            "target_refs": [_ref(memory, "memory_id")],
            "evidence_ids": [evidence_draft["event_id"]],
            "status": "previewed",
            "idempotency": _idempotency(5),
            "issued_at": "2026-01-01T00:07:00.000Z",
            "receipt_digest": _digest("pending-deletion-receipt"),
        }
    )
    records["deletion_receipt"] = deletion_receipt

    tool_request = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "tool_request",
            "tenant_id": TENANT_ID,
            "actor_id": actor["actor_id"],
            "actor_context_digest": sha256_digest(actor),
            "run_id": evidence_draft["run_id"],
            "request_id": _uuid(21),
            "tool_id": "fixture.tool",
            "tool_version": "1.0",
            "arguments": {"input": "synthetic"},
            "effect_classes": ["write_external"],
            "request_digest": _digest("pending-tool-request"),
            "idempotency": _idempotency(6),
            "requested_at": "2026-01-01T00:08:00.000Z",
        }
    )
    records["tool_request"] = tool_request

    policy_decision = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "policy_decision",
            "tenant_id": TENANT_ID,
            "decision_id": _uuid(22),
            "request_id": tool_request["request_id"],
            "request_digest": tool_request["request_digest"],
            "decision": "require_approval",
            "rule_refs": ["effects.approval.v1"],
            "constraints": [_constraint()],
            "isolation_profile": "container",
            "decided_at": "2026-01-01T00:09:00.000Z",
            "decision_digest": _digest("pending-policy-decision"),
        }
    )
    records["policy_decision"] = policy_decision

    approval = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "approval_record",
            "tenant_id": TENANT_ID,
            "approval_id": _uuid(23),
            "approver_actor_id": _uuid(24),
            "approver_context_digest": _digest("approver-context"),
            "request_id": tool_request["request_id"],
            "request_digest": tool_request["request_digest"],
            "policy_decision_id": policy_decision["decision_id"],
            "policy_decision_digest": policy_decision["decision_digest"],
            "disposition": "approved",
            "constraints": [_constraint()],
            "separation_of_duties": {"required": True, "satisfied": True, "policy_id": "sod.v1"},
            "issued_at": "2026-01-01T00:10:00.000Z",
            "expires_at": "2026-01-01T01:00:00.000Z",
            "approval_digest": _digest("pending-approval"),
            "proof": _proof("approval_record.v1"),
        }
    )
    records["approval_record"] = approval

    grant = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "authorization_grant",
            "tenant_id": TENANT_ID,
            "grant_id": _uuid(25),
            "actor_id": tool_request["actor_id"],
            "run_id": tool_request["run_id"],
            "request_id": tool_request["request_id"],
            "request_digest": tool_request["request_digest"],
            "tool_id": tool_request["tool_id"],
            "tool_version": tool_request["tool_version"],
            "policy_decision_id": policy_decision["decision_id"],
            "policy_decision_digest": policy_decision["decision_digest"],
            "approval_refs": [_ref(approval, "approval_id")],
            "constraints": [_constraint()],
            "isolation_profile": "container",
            "issued_at": "2026-01-01T00:11:00.000Z",
            "expires_at": "2026-01-01T00:16:00.000Z",
            "grant_nonce": "G" * 22,
            "idempotency": _idempotency(7),
            "proof": _proof("authorization_grant.v1"),
        }
    )
    records["authorization_grant"] = grant

    manifest = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "capability_manifest",
            "tenant_id": TENANT_ID,
            "manifest_id": _uuid(26),
            "adapter_id": "fixture.adapter",
            "adapter_version": "1.0",
            "effect_classes": ["write_external"],
            "capability_level": "gate",
            "limitations": ["Synthetic fixture only"],
            "proof_suite": {
                "suite_id": "fixture.suite",
                "revision": "1.0",
                "result_digest": _digest("suite"),
            },
            "verified_at": "2026-01-01T00:12:00.000Z",
            "manifest_digest": _digest("pending-manifest"),
        }
    )
    records["capability_manifest"] = manifest

    outcome = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "action_outcome",
            "tenant_id": TENANT_ID,
            "outcome_id": _uuid(27),
            "target_scope": copy.deepcopy(scope),
            "run_id": tool_request["run_id"],
            "request_ref": _ref(tool_request, "request_id"),
            "status": "succeeded",
            "effect_state": "succeeded",
            "evidence_refs": [evidence_ref],
            "provenance_digest": _digest("outcome-provenance"),
            "result_payload": {"result": "synthetic"},
            "producer_version": "producer.v1",
            "runtime_version": "runtime.v1",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("action_outcome"),
            "idempotency": _idempotency(8),
            "occurred_at": "2026-01-01T00:13:00.000Z",
            "outcome_digest": _digest("pending-outcome"),
        }
    )
    records["action_outcome"] = outcome

    feedback = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "feedback_event",
            "tenant_id": TENANT_ID,
            "feedback_id": _uuid(28),
            "target_scope": copy.deepcopy(scope),
            "outcome_ref": _ref(outcome, "outcome_id"),
            "source": {"source_type": "reviewer", "source_id": "reviewer.fixture"},
            "feedback_type": "rating",
            "feedback": {"rating": 5},
            "evidence_refs": [evidence_ref],
            "provenance_digest": _digest("feedback-provenance"),
            "classification": "internal",
            "redaction_status": "redacted",
            "consent_policy_id": "consent.v1",
            "producer_version": "producer.v1",
            "runtime_version": "runtime.v1",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("feedback_event"),
            "idempotency": _idempotency(9),
            "occurred_at": "2026-01-01T00:14:00.000Z",
            "feedback_digest": _digest("pending-feedback"),
        }
    )
    records["feedback_event"] = feedback

    dataset = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "dataset_version",
            "tenant_id": TENANT_ID,
            "dataset_id": _uuid(29),
            "revision": 1,
            "target_scope": copy.deepcopy(scope),
            "lifecycle_state": "published",
            "source_revisions": [_ref(trace, "trace_id")],
            "consent_policy_id": "consent.v1",
            "redaction_policy_id": "redaction.v1",
            "split_assignments": {
                "train": [_uuid(30)],
                "validation": [_uuid(31)],
                "test": [_uuid(32)],
            },
            "exclusions": [],
            "producer_version": "producer.v1",
            "runtime_version": "runtime.v1",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("dataset_version"),
            "created_at": "2026-01-01T00:15:00.000Z",
            "published_at": "2026-01-01T00:16:00.000Z",
            "manifest_digest": _digest("pending-dataset"),
        }
    )
    records["dataset_version"] = dataset

    evaluation = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "evaluation_run",
            "tenant_id": TENANT_ID,
            "evaluation_id": _uuid(33),
            "target_scope": copy.deepcopy(scope),
            "dataset_ref": _ref(dataset, "dataset_id"),
            "evaluator_id": "fixture.evaluator",
            "evaluator_version": "1.0",
            "configuration_digest": _digest("evaluation-config"),
            "environment_digest": _digest("evaluation-environment"),
            "versions": {
                "runtime": "runtime.v1",
                "toolset": "toolset.v1",
                "model": "model.v1",
                "skillset": "skillset.v1",
                "policy": "policy.v1",
            },
            "seed": 7,
            "lifecycle_state": "completed",
            "checkpoint_refs": [],
            "result_refs": [_ref(outcome, "outcome_id")],
            "mandatory_artifact_refs": [_ref(outcome, "outcome_id")],
            "task_quality": _task_quality(),
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("evaluation_run", "dataset_version"),
            "created_at": "2026-01-01T00:17:00.000Z",
            "started_at": "2026-01-01T00:18:00.000Z",
            "completed_at": "2026-01-01T00:19:00.000Z",
            "idempotency": _idempotency(10),
            "run_digest": _digest("pending-evaluation"),
        }
    )
    records["evaluation_run"] = evaluation

    skill = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "skill_proposal",
            "tenant_id": TENANT_ID,
            "proposal_id": _uuid(34),
            "artifact_id": _uuid(35),
            "artifact_revision": 1,
            "target_scope": copy.deepcopy(scope),
            "artifact": {"kind": "synthetic", "version": 1},
            "evidence_refs": [evidence_ref],
            "provenance_digest": _digest("skill-provenance"),
            "producer_version": "producer.v1",
            "runtime_version": "runtime.v1",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("skill_proposal"),
            "created_at": "2026-01-01T00:20:00.000Z",
            "expires_at": "2027-01-01T00:00:00.000Z",
            "lifecycle_state": "approved",
            "proposal_digest": _digest("pending-skill"),
        }
    )
    records["skill_proposal"] = skill

    policy_proposal = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "policy_proposal",
            "tenant_id": TENANT_ID,
            "proposal_id": _uuid(36),
            "artifact_id": _uuid(37),
            "artifact_revision": 1,
            "target_scope": copy.deepcopy(scope),
            "policy_domain": "evaluation",
            "artifact": {"rule": "synthetic"},
            "evidence_refs": [evidence_ref],
            "provenance_digest": _digest("policy-provenance"),
            "producer_version": "producer.v1",
            "runtime_version": "runtime.v1",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("policy_proposal"),
            "created_at": "2026-01-01T00:21:00.000Z",
            "expires_at": "2027-01-01T00:00:00.000Z",
            "lifecycle_state": "approved",
            "proposal_digest": _digest("pending-policy-proposal"),
        }
    )
    records["policy_proposal"] = policy_proposal

    gate = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "gate_decision",
            "tenant_id": TENANT_ID,
            "gate_id": _uuid(38),
            "target_scope": copy.deepcopy(scope),
            "proposal_refs": [_ref(skill, "proposal_id")],
            "evaluation_refs": [_ref(evaluation, "evaluation_id")],
            "provenance_digest": _digest("gate-provenance"),
            "producer_version": "producer.v1",
            "runtime_version": "runtime.v1",
            "decision": "approve",
            "eligibility_checks": {
                "reproducible_evaluation": True,
                "mandatory_artifacts_present": True,
                "policy_current": True,
                "review_complete": True,
            },
            "task_quality": _task_quality(),
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("gate_decision", "evaluation_run"),
            "issued_at": "2026-01-01T00:22:00.000Z",
            "decision_digest": _digest("pending-gate"),
        }
    )
    records["gate_decision"] = gate

    artifact_digest = sha256_digest(skill["artifact"])
    delivery = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "delivery_envelope",
            "tenant_id": TENANT_ID,
            "delivery_id": _uuid(39),
            "target_scope": copy.deepcopy(scope),
            "artifact_type": "skill",
            "artifact_id": skill["artifact_id"],
            "artifact_revision": skill["artifact_revision"],
            "artifact_digest": artifact_digest,
            "gate_decision_ref": _ref(gate, "gate_id"),
            "evidence_refs": [evidence_ref],
            "provenance_digest": _digest("delivery-provenance"),
            "producer_version": "producer.v1",
            "runtime_version": "runtime.v1",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("delivery_envelope", "skill_proposal"),
            "rollback_metadata": {"strategy": "deactivate_revision", "previous_active_ref": None},
            "lifecycle_state": "delivered",
            "idempotency": _idempotency(11),
            "issued_at": "2026-01-01T00:23:00.000Z",
            "expires_at": "2026-01-02T00:23:00.000Z",
            "envelope_digest": _digest("pending-delivery"),
            "proof": _proof("delivery_envelope.v1"),
        }
    )
    records["delivery_envelope"] = delivery

    activation = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "activation_receipt",
            "tenant_id": TENANT_ID,
            "receipt_id": _uuid(40),
            "issuer_role": "runtime_authority",
            "target_scope": copy.deepcopy(scope),
            "delivery_id": delivery["delivery_id"],
            "delivery_digest": delivery["envelope_digest"],
            "artifact_type": delivery["artifact_type"],
            "artifact_id": delivery["artifact_id"],
            "artifact_revision": delivery["artifact_revision"],
            "artifact_digest": delivery["artifact_digest"],
            "activated_revision": _record_ref(
                "skill_proposal", skill["artifact_id"], artifact_digest
            ),
            "previous_active_ref": None,
            "evidence_refs": [evidence_ref],
            "provenance_digest": _digest("activation-provenance"),
            "producer_version": "runtime.authority.v1",
            "runtime_version": "runtime.v1",
            "status": "activated",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("activation_receipt", "delivery_envelope"),
            "idempotency": _idempotency(12),
            "issued_at": "2026-01-01T00:24:00.000Z",
            "expires_at": "2026-01-02T00:24:00.000Z",
            "receipt_digest": _digest("pending-activation"),
            "proof": _proof("activation_receipt.v1"),
        }
    )
    records["activation_receipt"] = activation

    rollback = _finalize(
        {
            "schema_version": "1.0",
            "record_type": "rollback_receipt",
            "tenant_id": TENANT_ID,
            "receipt_id": _uuid(41),
            "issuer_role": "runtime_authority",
            "target_scope": copy.deepcopy(scope),
            "activation_receipt_ref": _ref(activation, "receipt_id"),
            "artifact_type": activation["artifact_type"],
            "artifact_id": activation["artifact_id"],
            "artifact_revision": activation["artifact_revision"],
            "artifact_digest": activation["artifact_digest"],
            "rollback_revision": _record_ref(
                "skill_proposal", _uuid(42), _digest("rollback-revision")
            ),
            "restored_revision_ref": None,
            "evidence_refs": [evidence_ref],
            "provenance_digest": _digest("rollback-provenance"),
            "producer_version": "runtime.authority.v1",
            "runtime_version": "runtime.v1",
            "status": "rolled_back",
            "reason_code": "fixture.rollback",
            "policy_refs": [policy_ref],
            "reviewer_refs": [_ref(approval, "approval_id")],
            "compatibility": _compatibility("rollback_receipt", "activation_receipt"),
            "idempotency": _idempotency(13),
            "issued_at": "2026-01-01T00:25:00.000Z",
            "expires_at": "2026-01-02T00:25:00.000Z",
            "receipt_digest": _digest("pending-rollback"),
            "proof": _proof("rollback_receipt.v1"),
        }
    )
    records["rollback_receipt"] = rollback
    return records


def _serialized(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def build_positive_fixture_files() -> dict[str, bytes]:
    records = build_positive_records()
    files = {f"{record_type}.json": _serialized(record) for record_type, record in records.items()}
    canonical_inputs = [
        {"name": "utf16_property_order", "input": {"😀": 1, "\ue000": 2, "a": 3}},
        {"name": "string_escaping", "input": {"text": 'line\nquote"slash\\control\u000f'}},
        {"name": "integer_domain", "input": {"max": 9007199254740991, "min": -9007199254740991}},
    ]
    canonical_vectors = [
        {**vector, "canonical": canonical_bytes(vector["input"]).decode("utf-8")}
        for vector in canonical_inputs
    ]
    digest_vectors = [
        {
            "name": vector["name"],
            "input": vector["input"],
            "canonical": vector["canonical"],
            "digest": sha256_digest(vector["input"]),
        }
        for vector in canonical_vectors
    ]
    files["canonicalization_vectors.json"] = _serialized(canonical_vectors)
    files["digest_vectors.json"] = _serialized(digest_vectors)
    return files
