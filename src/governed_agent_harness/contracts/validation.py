"""Semantic, cross-record, proof, scope, and idempotency validation."""

from __future__ import annotations

import copy
import hmac
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol

from .canonical import MAX_SAFE_INTEGER, canonical_bytes, require_sha256_digest, sha256_digest
from .errors import ContractError, IdempotencyConflictError, ProofVerificationError, SemanticError
from .schema import DEFAULT_SCHEMA_STORE, SchemaStore

EXTENSIONS_CANONICAL_BYTE_LIMIT = 8 * 1024

SELF_DIGEST_FIELDS: Mapping[str, str] = {
    "evidence_envelope": "event_digest",
    "learning_trace_envelope": "export_digest",
    "memory_record": "record_digest",
    "memory_proposal": "proposal_digest",
    "memory_decision": "decision_digest",
    "context_bundle": "bundle_digest",
    "write_receipt": "receipt_digest",
    "deletion_receipt": "receipt_digest",
    "tool_request": "request_digest",
    "policy_decision": "decision_digest",
    "approval_record": "approval_digest",
    "capability_manifest": "manifest_digest",
    "action_outcome": "outcome_digest",
    "feedback_event": "feedback_digest",
    "evaluation_run": "run_digest",
    "dataset_version": "manifest_digest",
    "skill_proposal": "proposal_digest",
    "policy_proposal": "proposal_digest",
    "gate_decision": "decision_digest",
    "delivery_envelope": "envelope_digest",
    "activation_receipt": "receipt_digest",
    "rollback_receipt": "receipt_digest",
}

SIGNED_PROOF_DOMAINS: Mapping[str, str] = {
    "approval_record": "approval_record.v1",
    "authorization_grant": "authorization_grant.v1",
    "delivery_envelope": "delivery_envelope.v1",
    "activation_receipt": "activation_receipt.v1",
    "rollback_receipt": "rollback_receipt.v1",
}


def _as_record(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    data = getattr(value, "to_dict", None)
    if callable(data):
        result = data()
        if isinstance(result, dict):
            return result
    raise TypeError("expected a record mapping or contract model")


def _parse_timestamp(value: str, path: str) -> datetime:
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise SemanticError(f"{path}: invalid UTC millisecond timestamp") from exc
    return result


def _require_order(
    record: Mapping[str, Any], first: str, second: str, *, strict: bool = False
) -> None:
    if (
        first not in record
        or second not in record
        or record[first] is None
        or record[second] is None
    ):
        return
    left = _parse_timestamp(record[first], first)
    right = _parse_timestamp(record[second], second)
    valid = left < right if strict else left <= right
    if not valid:
        operator = "before" if strict else "not after"
        raise SemanticError(f"{first} must be {operator} {second}")


def unsigned_body(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the explicitly unsigned body used by self digests and proofs."""

    result = copy.deepcopy(dict(record))
    result.pop("proof", None)
    digest_field = SELF_DIGEST_FIELDS.get(str(result.get("record_type")))
    if digest_field is not None:
        result.pop(digest_field, None)
    return result


def expected_object_digest(record: Mapping[str, Any]) -> str:
    """Digest the record's defined unsigned body."""

    return sha256_digest(unsigned_body(record))


def apply_object_digest(record: dict[str, Any]) -> dict[str, Any]:
    """Populate a record's self-digest and proof object digest in place."""

    record_type = record.get("record_type")
    digest = expected_object_digest(record)
    digest_field = SELF_DIGEST_FIELDS.get(str(record_type))
    if digest_field is not None:
        record[digest_field] = digest
    proof = record.get("proof")
    if isinstance(proof, dict):
        proof["object_digest"] = digest
    return record


def _walk(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    yield path or "/", value
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}/{key}" if path else f"/{key}"
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}/{index}" if path else f"/{index}"
            yield from _walk(child, child_path)


def validate_extensions(record: Mapping[str, Any]) -> None:
    """Enforce the exact canonical 8 KiB cap on every nested extensions object."""

    for path, value in _walk(record):
        if isinstance(value, dict) and "extensions" in value:
            size = len(canonical_bytes(value["extensions"]))
            if size > EXTENSIONS_CANONICAL_BYTE_LIMIT:
                raise SemanticError(
                    f"{path}/extensions: canonical size {size} exceeds "
                    f"{EXTENSIONS_CANONICAL_BYTE_LIMIT} bytes"
                )


def validate_tenant_consistency(
    record: Mapping[str, Any], expected_tenant: str | None = None
) -> str:
    """Require every nested tenant binding to equal the top-level tenant."""

    tenant = record.get("tenant_id")
    if not isinstance(tenant, str):
        raise SemanticError("/tenant_id: tenant binding is required")
    if expected_tenant is not None and not hmac.compare_digest(tenant, expected_tenant):
        raise SemanticError("/tenant_id: record does not match the expected tenant")
    for path, value in _walk(record):
        if path == "/" or not isinstance(value, dict) or "tenant_id" not in value:
            continue
        nested = value["tenant_id"]
        if not isinstance(nested, str) or not hmac.compare_digest(nested, tenant):
            raise SemanticError(f"{path}/tenant_id: nested tenant does not match top-level tenant")
    return tenant


def validate_self_digests(record: Mapping[str, Any]) -> None:
    """Validate self-digest/proof equality for this record and nested records."""

    for path, value in _walk(record):
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != "1.0"
            or not isinstance(value.get("record_type"), str)
        ):
            continue
        record_type = value["record_type"]
        digest_field = SELF_DIGEST_FIELDS.get(record_type)
        proof = value.get("proof")
        if digest_field is None and record_type not in SIGNED_PROOF_DOMAINS:
            continue
        expected = expected_object_digest(value)
        if digest_field is not None and value.get(digest_field) != expected:
            raise SemanticError(f"{path}/{digest_field}: self-digest does not match unsigned body")
        if record_type in SIGNED_PROOF_DOMAINS:
            if not isinstance(proof, dict):
                raise SemanticError(f"{path}/proof: signed record requires a proof")
            if proof.get("object_digest") != expected:
                raise SemanticError(f"{path}/proof/object_digest: does not match unsigned body")
            if proof.get("proof_domain") != SIGNED_PROOF_DOMAINS[record_type]:
                raise SemanticError(f"{path}/proof/proof_domain: incorrect proof domain")


def validate_derived_digests(record: Mapping[str, Any]) -> None:
    """Validate digests whose source value is present in the same record."""

    for path, value in _walk(record):
        if not isinstance(value, dict):
            continue
        if {"parameters", "parameters_digest"} <= value.keys():
            if value["parameters_digest"] != sha256_digest(value["parameters"]):
                raise SemanticError(f"{path}/parameters_digest: does not match parameters")
        if value.get("schema_version") == "1.0" and value.get("record_type") == "evidence_envelope":
            if value.get("draft_digest") != sha256_digest(value["draft"]):
                raise SemanticError(f"{path}/draft_digest: does not match draft")
            draft = value["draft"]
            if "inline_payload" in draft:
                expected_payload = sha256_digest(draft["inline_payload"])
            else:
                expected_payload = draft["protected_payload"]["payload_digest"]
            if value.get("payload_digest") != expected_payload:
                raise SemanticError(f"{path}/payload_digest: does not match draft payload")


@dataclass(frozen=True, slots=True)
class ConstraintRegistry:
    """Deployment-owned allowlist of understood constraint IDs and versions."""

    supported: Mapping[str, frozenset[str]]

    def accepts(self, constraint_id: str, constraint_version: str) -> bool:
        return constraint_version in self.supported.get(constraint_id, frozenset())


def validate_constraint_support(record: Mapping[str, Any], registry: ConstraintRegistry) -> None:
    """Fail closed when a record names an unimplemented constraint."""

    for path, value in _walk(record):
        if not isinstance(value, dict):
            continue
        if {"constraint_id", "constraint_version", "parameters", "parameters_digest"} != set(value):
            continue
        if not registry.accepts(value["constraint_id"], value["constraint_version"]):
            raise SemanticError(
                f"{path}: unsupported constraint {value['constraint_id']}@{value['constraint_version']}"
            )


def validate_chronology(record: Mapping[str, Any]) -> None:
    """Enforce chronology that is unambiguous from canonical field semantics."""

    for _, value in _walk(record):
        if isinstance(value, dict) and value.get("record_type") == "memory_scope":
            _require_order(value, "derived_at", "valid_until")

    record_type = record.get("record_type")
    if record_type == "actor_context":
        auth = record["auth"]
        if _parse_timestamp(auth["verified_at"], "auth.verified_at") > _parse_timestamp(
            record["issued_at"], "issued_at"
        ):
            raise SemanticError("auth.verified_at must not be after issued_at")
        _require_order(record, "issued_at", "expires_at", strict=True)
    elif record_type == "evidence_envelope":
        occurred = _parse_timestamp(record["draft"]["occurred_at"], "draft.occurred_at")
        recorded = _parse_timestamp(record["recorded_at"], "recorded_at")
        if occurred > recorded:
            raise SemanticError("draft.occurred_at must not be after recorded_at")
    elif record_type == "memory_query" and "temporal_bound" in record:
        _require_order(record["temporal_bound"], "from", "until")
    elif record_type == "memory_record":
        _require_order(record, "effective_from", "effective_until")
        _require_order(record, "effective_from", "expires_at")
    elif record_type == "approval_record":
        _require_order(record, "issued_at", "expires_at", strict=True)
        _require_order(record, "issued_at", "revoked_at")
    elif record_type in {
        "authorization_grant",
        "delivery_envelope",
        "activation_receipt",
        "rollback_receipt",
    }:
        _require_order(record, "issued_at", "expires_at", strict=True)
    elif record_type in {"memory_proposal", "skill_proposal", "policy_proposal"}:
        _require_order(record, "created_at", "expires_at", strict=True)
    elif record_type == "evaluation_run":
        _require_order(record, "created_at", "started_at")
        _require_order(record, "started_at", "completed_at")
    elif record_type == "dataset_version":
        _require_order(record, "created_at", "published_at")


def validate_memory_bindings(record: Mapping[str, Any]) -> None:
    """Keep memory visibility and proposal payloads bound to one exact scope."""

    for path, value in _walk(record):
        if not isinstance(value, dict) or value.get("schema_version") != "1.0":
            continue
        record_type = value.get("record_type")
        if record_type == "memory_record":
            selection = value.get("scope", {}).get("selection", {})
            if value.get("visibility") != selection.get("level"):
                raise SemanticError(
                    f"{path}/visibility: must equal the memory scope selection level"
                )
        elif record_type == "memory_proposal":
            proposed_record = value.get("proposed_record", {})
            if value.get("target_scope") != proposed_record.get("scope"):
                raise SemanticError(
                    f"{path}/target_scope: must exactly equal proposed_record scope"
                )
            if proposed_record.get("lifecycle_state") != "candidate":
                raise SemanticError(
                    f"{path}/proposed_record/lifecycle_state: proposal payload must remain candidate"
                )


def validate_record(
    record: Mapping[str, Any],
    *,
    expected_tenant: str | None = None,
    schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
    verify_self_digests: bool = True,
) -> None:
    """Validate one already-decoded record against schema and semantic duties."""

    value = _as_record(record)
    canonical_bytes(value)
    schema_store.validate_record(value)
    validate_tenant_consistency(value, expected_tenant)
    validate_extensions(value)
    validate_chronology(value)
    validate_memory_bindings(value)
    validate_derived_digests(value)
    if verify_self_digests:
        validate_self_digests(value)


def validate_scope_narrowing(scope: Any, parent: Any) -> None:
    """Require a MemoryScope to be no broader than an ActorContext or parent scope."""

    child = _as_record(scope)
    authority = _as_record(parent)
    if child.get("record_type") != "memory_scope":
        raise SemanticError("child must be a memory_scope")
    if child.get("tenant_id") != authority.get("tenant_id"):
        raise SemanticError("scope tenant does not match parent authority")
    if child.get("actor_id") != authority.get("actor_id"):
        raise SemanticError("scope actor does not match parent authority")

    parent_record_type = authority.get("record_type")
    if parent_record_type not in {"actor_context", "memory_scope"}:
        raise SemanticError("parent must be actor_context or memory_scope")
    if child.get("parent_record_type") != parent_record_type:
        raise SemanticError("scope parent_record_type does not identify its immediate parent")
    if child.get("parent_digest") != sha256_digest(authority):
        raise SemanticError("scope parent_digest does not match its immediate parent")

    child_derived = _parse_timestamp(child["derived_at"], "scope.derived_at")
    child_valid_until = _parse_timestamp(child["valid_until"], "scope.valid_until")
    if child_derived > child_valid_until:
        raise SemanticError("scope derived_at must not be after valid_until")

    selection = child["selection"]
    if parent_record_type == "memory_scope":
        parent_derived = _parse_timestamp(authority["derived_at"], "parent.derived_at")
        parent_valid_until = _parse_timestamp(authority["valid_until"], "parent.valid_until")
        if not parent_derived <= child_derived <= child_valid_until <= parent_valid_until:
            raise SemanticError("child scope validity must be bounded by its parent scope")
        if selection != authority.get("selection"):
            raise SemanticError(
                "child selection must exactly equal parent selection without a topology resolver"
            )
        return

    actor_issued = _parse_timestamp(authority["issued_at"], "actor.issued_at")
    actor_expires = _parse_timestamp(authority["expires_at"], "actor.expires_at")
    if not actor_issued <= child_derived <= child_valid_until <= actor_expires:
        raise SemanticError("scope validity must be bounded by its ActorContext")

    level = selection["level"]
    scope_authority = authority["scope_authority"]
    if level == "public":
        if scope_authority["public_allowed"] is not True:
            raise SemanticError("public scope selection is not authorized")
        return
    if level not in scope_authority["allowed_levels"]:
        raise SemanticError(f"scope selection level {level!r} is not explicitly authorized")
    if level == "actor":
        return
    if level == "session":
        if selection["session_id"] != authority["session_id"]:
            raise SemanticError("scope session_id does not match ActorContext session")
        return

    membership_fields = {
        "user": ("user_id", "user_id"),
        "team": ("team_id", "team_ids"),
        "organization": ("organization_id", "organization_ids"),
        "project": ("project_id", "project_ids"),
        "workspace": ("workspace_id", "workspace_ids"),
    }
    selected_field, authority_field = membership_fields[level]
    memberships = scope_authority.get(authority_field)
    selected_id = selection[selected_field]
    if isinstance(memberships, list):
        authorized = selected_id in memberships
    else:
        authorized = selected_id == memberships
    if not authorized:
        raise SemanticError(
            f"scope {selected_field} is not present in ActorContext {authority_field}"
        )


def _require_same(left: Mapping[str, Any], right: Mapping[str, Any], fields: Iterable[str]) -> None:
    for field in fields:
        if left.get(field) != right.get(field):
            raise SemanticError(f"cross-record binding mismatch for {field}")


def validate_policy_request_binding(policy: Any, request: Any) -> None:
    policy_record, request_record = _as_record(policy), _as_record(request)
    _require_same(policy_record, request_record, ("tenant_id", "request_id", "request_digest"))


def validate_approval_binding(approval: Any, policy: Any, request: Any) -> None:
    approval_record, policy_record, request_record = (
        _as_record(approval),
        _as_record(policy),
        _as_record(request),
    )
    validate_policy_request_binding(policy_record, request_record)
    _require_same(approval_record, request_record, ("tenant_id", "request_id", "request_digest"))
    if approval_record.get("policy_decision_id") != policy_record.get("decision_id"):
        raise SemanticError("approval policy_decision_id does not bind the decision")
    if approval_record.get("policy_decision_digest") != policy_record.get("decision_digest"):
        raise SemanticError("approval policy_decision_digest does not bind the decision")


def validate_grant_binding(
    grant: Any,
    request: Any,
    policy: Any,
    approvals: Iterable[Any] = (),
    *,
    constraint_registry: ConstraintRegistry,
    verifier: DetachedProofVerifier,
    trust: TrustContext,
) -> None:
    grant_record, request_record, policy_record = (
        _as_record(grant),
        _as_record(request),
        _as_record(policy),
    )
    validate_policy_request_binding(policy_record, request_record)
    validate_constraint_support(policy_record, constraint_registry)
    validate_constraint_support(grant_record, constraint_registry)
    _require_same(
        grant_record,
        request_record,
        (
            "tenant_id",
            "actor_id",
            "run_id",
            "request_id",
            "request_digest",
            "tool_id",
            "tool_version",
        ),
    )
    if grant_record.get("policy_decision_id") != policy_record.get("decision_id"):
        raise SemanticError("grant policy_decision_id does not bind the decision")
    if grant_record.get("policy_decision_digest") != policy_record.get("decision_digest"):
        raise SemanticError("grant policy_decision_digest does not bind the decision")
    if policy_record.get("decision") not in {"authorize", "require_approval"}:
        raise SemanticError("grant cannot be issued for this policy disposition")
    if policy_record.get("isolation_profile") == "no_effect":
        raise SemanticError("no-effect policy cannot issue a grant")
    if grant_record.get("isolation_profile") != policy_record.get("isolation_profile"):
        raise SemanticError("grant isolation_profile does not exactly match policy decision")
    if _parse_timestamp(request_record["requested_at"], "request.requested_at") > _parse_timestamp(
        policy_record["decided_at"], "policy.decided_at"
    ):
        raise SemanticError("policy decision predates its request")
    if _parse_timestamp(policy_record["decided_at"], "policy.decided_at") > _parse_timestamp(
        grant_record["issued_at"], "grant.issued_at"
    ):
        raise SemanticError("grant predates its policy decision")

    def constraint_bindings(source: Mapping[str, Any]) -> dict[tuple[str, str], str]:
        bindings: dict[tuple[str, str], str] = {}
        for constraint in source.get("constraints", []):
            key = (constraint["constraint_id"], constraint["constraint_version"])
            if key in bindings:
                raise SemanticError(f"duplicate constraint binding {key[0]}@{key[1]}")
            bindings[key] = constraint["parameters_digest"]
        return bindings

    grant_constraints = constraint_bindings(grant_record)
    for key, digest in constraint_bindings(policy_record).items():
        if grant_constraints.get(key) != digest:
            raise SemanticError(f"grant omits or changes policy constraint {key[0]}@{key[1]}")
    supplied: dict[str, dict[str, Any]] = {}
    for value in approvals:
        approval = _as_record(value)
        approval_id = approval["approval_id"]
        if approval_id in supplied:
            raise SemanticError("duplicate supplied approval ID")
        supplied[approval_id] = approval
    if policy_record.get("decision") == "require_approval" and not grant_record.get(
        "approval_refs"
    ):
        raise SemanticError("approval-required policy needs at least one bound approval")
    for reference in grant_record.get("approval_refs", []):
        approval = supplied.get(reference["record_id"])
        if approval is None:
            raise SemanticError("grant approval reference has no supplied approval")
        validate_approval_binding(approval, policy_record, request_record)
        validate_constraint_support(approval, constraint_registry)
        if approval.get("approval_digest") != reference["record_digest"]:
            raise SemanticError("grant approval reference digest mismatch")
        if approval.get("disposition") != "approved":
            raise SemanticError("grant references a non-approved approval")
        duties = approval.get("separation_of_duties", {})
        if duties.get("required") and not duties.get("satisfied"):
            raise SemanticError("grant references an approval that failed separation of duties")
        if _parse_timestamp(grant_record["issued_at"], "grant.issued_at") > _parse_timestamp(
            approval["expires_at"], "approval.expires_at"
        ):
            raise SemanticError("grant was issued after its approval expired")
        if _parse_timestamp(approval["issued_at"], "approval.issued_at") > _parse_timestamp(
            grant_record["issued_at"], "grant.issued_at"
        ):
            raise SemanticError("grant predates its approval")
        if _parse_timestamp(grant_record["expires_at"], "grant.expires_at") > _parse_timestamp(
            approval["expires_at"], "approval.expires_at"
        ):
            raise SemanticError("grant outlives its approval")
        for key, digest in constraint_bindings(approval).items():
            if grant_constraints.get(key) != digest:
                raise SemanticError(f"grant omits or changes approval constraint {key[0]}@{key[1]}")
        verify_signed_record(
            approval,
            verifier=verifier,
            trust=trust,
            expected_tenant=grant_record["tenant_id"],
        )
    verify_signed_record(
        grant_record,
        verifier=verifier,
        trust=trust,
        expected_tenant=grant_record["tenant_id"],
    )


def validate_activation_delivery_binding(receipt: Any, delivery: Any) -> None:
    receipt_record, delivery_record = _as_record(receipt), _as_record(delivery)
    _require_same(
        receipt_record,
        delivery_record,
        ("tenant_id", "artifact_type", "artifact_id", "artifact_revision", "artifact_digest"),
    )
    if receipt_record.get("delivery_id") != delivery_record.get("delivery_id"):
        raise SemanticError("activation receipt delivery_id mismatch")
    if receipt_record.get("delivery_digest") != delivery_record.get("envelope_digest"):
        raise SemanticError("activation receipt delivery_digest mismatch")
    if receipt_record.get("target_scope") != delivery_record.get("target_scope"):
        raise SemanticError("activation receipt target_scope mismatch")
    if delivery_record.get("lifecycle_state") != "delivered":
        raise SemanticError("activation requires a delivered delivery envelope")
    activation_issued = _parse_timestamp(receipt_record["issued_at"], "activation.issued_at")
    delivery_issued = _parse_timestamp(delivery_record["issued_at"], "delivery.issued_at")
    delivery_expires = _parse_timestamp(delivery_record["expires_at"], "delivery.expires_at")
    if not delivery_issued <= activation_issued <= delivery_expires:
        raise SemanticError("activation issue time is outside the delivery validity window")


def validate_rollback_activation_binding(rollback: Any, activation: Any) -> None:
    rollback_record, activation_record = _as_record(rollback), _as_record(activation)
    _require_same(
        rollback_record,
        activation_record,
        ("tenant_id", "artifact_type", "artifact_id", "artifact_revision", "artifact_digest"),
    )
    reference = rollback_record.get("activation_receipt_ref", {})
    if reference.get("record_id") != activation_record.get("receipt_id"):
        raise SemanticError("rollback activation receipt ID mismatch")
    if reference.get("record_digest") != activation_record.get("receipt_digest"):
        raise SemanticError("rollback activation receipt digest mismatch")
    if rollback_record.get("target_scope") != activation_record.get("target_scope"):
        raise SemanticError("rollback receipt target_scope mismatch")
    rollback_issued = _parse_timestamp(rollback_record["issued_at"], "rollback.issued_at")
    activation_issued = _parse_timestamp(activation_record["issued_at"], "activation.issued_at")
    if rollback_issued < activation_issued:
        raise SemanticError("rollback issue time cannot be before activation")


class IdempotencyResult(str, Enum):
    NEW = "new"
    REPLAY = "replay"


def _validate_idempotency_binding(binding: Mapping[str, Any]) -> None:
    expected = {"tenant_id", "idempotency_key", "operation_digest"}
    if set(binding) != expected:
        raise SemanticError("idempotency binding must contain exactly the canonical fields")
    tenant = binding["tenant_id"]
    if (
        not isinstance(tenant, str)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", tenant
        )
        is None
    ):
        raise SemanticError("idempotency tenant_id is not a lowercase UUIDv7")
    key = binding["idempotency_key"]
    if (
        not isinstance(key, str)
        or not 16 <= len(key) <= 128
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]+", key) is None
    ):
        raise SemanticError("idempotency_key is malformed")
    require_sha256_digest(binding["operation_digest"], "idempotency.operation_digest")


def compare_idempotency_bindings(
    existing: Mapping[str, Any] | None, incoming: Mapping[str, Any]
) -> IdempotencyResult:
    """Classify a new binding or exact replay; conflicting reuse raises."""

    _validate_idempotency_binding(incoming)
    if existing is None:
        return IdempotencyResult.NEW
    _validate_idempotency_binding(existing)
    existing_key = (existing.get("tenant_id"), existing.get("idempotency_key"))
    incoming_key = (incoming.get("tenant_id"), incoming.get("idempotency_key"))
    if existing_key != incoming_key:
        return IdempotencyResult.NEW
    if existing.get("operation_digest") != incoming.get("operation_digest"):
        raise IdempotencyConflictError("idempotency key is already bound to another operation")
    if dict(existing) != dict(incoming):
        raise IdempotencyConflictError("idempotency binding changed outside operation digest")
    return IdempotencyResult.REPLAY


@dataclass(frozen=True, slots=True)
class TrustedKey:
    issuer: str
    key_id: str
    algorithms: frozenset[str]
    valid_from: datetime
    valid_until: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RetroactiveKeyInvalidation:
    """Current compromise boundary, independent of the active trusted-key set."""

    issuer: str
    key_id: str
    invalid_from: datetime


@dataclass(frozen=True, slots=True)
class AcceptedTrustSnapshot:
    """Canonical issuance-time trust facts frozen at first acceptance."""

    trust_policy_version: str
    issuer: str
    key_id: str
    algorithm: str
    proof_domain: str
    allowed_algorithms: tuple[str, ...]
    allowed_proof_domains: tuple[str, ...]
    expected_issuers: tuple[str, ...]
    allowed_domain_issuers: tuple[tuple[str, str], ...]
    key_algorithms: tuple[str, ...]
    key_valid_from: datetime
    key_valid_until: datetime | None
    key_revoked_at: datetime | None
    clock_skew_microseconds: int


@dataclass(frozen=True, slots=True)
class HistoricalAcceptance:
    canonical_record_digest: str
    issued_at: datetime
    accepted_at: datetime
    accepted_trust: AcceptedTrustSnapshot
    accepted_trust_digest: str
    ledger_position: int


@dataclass(frozen=True, slots=True)
class TrustContext:
    now: datetime
    trusted_keys: tuple[TrustedKey, ...]
    allowed_algorithms: frozenset[str]
    allowed_proof_domains: frozenset[str]
    expected_issuers: frozenset[str]
    allowed_domain_issuers: frozenset[tuple[str, str]]
    trust_policy_version: str
    clock_skew: timedelta = timedelta(seconds=30)
    historical_acceptances: tuple[HistoricalAcceptance, ...] = ()
    retroactive_invalidations: tuple[RetroactiveKeyInvalidation, ...] = ()


class DetachedProofVerifier(Protocol):
    """Injected cryptographic boundary; Phase 0 provides no implementation."""

    def verify(
        self,
        *,
        issuer: str,
        key_id: str,
        algorithm: str,
        proof_domain: str,
        object_digest: str,
        nonce: str,
        detached_proof: str,
        unsigned_bytes: bytes,
    ) -> bool:
        """Return whether the detached proof verifies under the named key."""


def _aware(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ProofVerificationError(f"{label} must be timezone-aware")
    return value


def _canonical_timestamp(value: datetime | None, label: str) -> str | None:
    if value is None:
        return None
    return (
        _aware(value, label)
        .astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _snapshot_payload(snapshot: AcceptedTrustSnapshot) -> dict[str, Any]:
    return {
        "trust_policy_version": snapshot.trust_policy_version,
        "proof": {
            "issuer": snapshot.issuer,
            "key_id": snapshot.key_id,
            "algorithm": snapshot.algorithm,
            "proof_domain": snapshot.proof_domain,
        },
        "policy": {
            "allowed_algorithms": snapshot.allowed_algorithms,
            "allowed_proof_domains": snapshot.allowed_proof_domains,
            "expected_issuers": snapshot.expected_issuers,
            "allowed_domain_issuers": snapshot.allowed_domain_issuers,
            "clock_skew_microseconds": snapshot.clock_skew_microseconds,
        },
        "key": {
            "algorithms": snapshot.key_algorithms,
            "valid_from": _canonical_timestamp(snapshot.key_valid_from, "key_valid_from"),
            "valid_until": _canonical_timestamp(snapshot.key_valid_until, "key_valid_until"),
            "revoked_at": _canonical_timestamp(snapshot.key_revoked_at, "key_revoked_at"),
        },
    }


def accepted_trust_snapshot_digest(snapshot: AcceptedTrustSnapshot) -> str:
    """Return the canonical digest committed by a historical acceptance."""

    if not isinstance(snapshot, AcceptedTrustSnapshot):
        raise ProofVerificationError("accepted trust snapshot has an invalid type")
    return sha256_digest(_snapshot_payload(snapshot))


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _clock_skew_microseconds(value: timedelta, label: str) -> int:
    if not isinstance(value, timedelta) or value < timedelta(0):
        raise ProofVerificationError(f"{label} clock skew is invalid")
    microseconds = _timedelta_microseconds(value)
    if microseconds > MAX_SAFE_INTEGER:
        raise ProofVerificationError(f"{label} clock skew exceeds canonical integer range")
    return microseconds


def _require_normalized_strings(values: tuple[str, ...], label: str) -> None:
    if (
        not isinstance(values, tuple)
        or any(not isinstance(value, str) or not value for value in values)
        or values != tuple(sorted(set(values)))
    ):
        raise ProofVerificationError(f"accepted trust snapshot {label} is not canonical")


def _require_normalized_domain_issuers(
    values: tuple[tuple[str, str], ...],
) -> None:
    if (
        not isinstance(values, tuple)
        or any(
            not isinstance(value, tuple)
            or len(value) != 2
            or any(not isinstance(item, str) or not item for item in value)
            for value in values
        )
        or values != tuple(sorted(set(values)))
    ):
        raise ProofVerificationError(
            "accepted trust snapshot allowed_domain_issuers is not canonical"
        )


def _enforce_retroactive_invalidation(
    proof: Mapping[str, Any],
    issued_at: datetime,
    trust: TrustContext,
    signed_record_label: str,
) -> None:
    matches = [
        invalidation
        for invalidation in trust.retroactive_invalidations
        if invalidation.issuer == proof["issuer"] and invalidation.key_id == proof["key_id"]
    ]
    if len(matches) > 1:
        raise ProofVerificationError("proof key has duplicate retroactive invalidations")
    if matches and issued_at >= _aware(matches[0].invalid_from, "retroactive invalid_from"):
        raise ProofVerificationError(
            f"{signed_record_label} falls within a retroactive key revocation boundary"
        )


def _accepted_trust_snapshot(
    proof: Mapping[str, Any], trust: TrustContext, key: TrustedKey
) -> AcceptedTrustSnapshot:
    return AcceptedTrustSnapshot(
        trust_policy_version=trust.trust_policy_version,
        issuer=proof["issuer"],
        key_id=proof["key_id"],
        algorithm=proof["algorithm"],
        proof_domain=proof["proof_domain"],
        allowed_algorithms=tuple(sorted(trust.allowed_algorithms)),
        allowed_proof_domains=tuple(sorted(trust.allowed_proof_domains)),
        expected_issuers=tuple(sorted(trust.expected_issuers)),
        allowed_domain_issuers=tuple(sorted(trust.allowed_domain_issuers)),
        key_algorithms=tuple(sorted(key.algorithms)),
        key_valid_from=_aware(key.valid_from, "key valid_from"),
        key_valid_until=(
            _aware(key.valid_until, "key valid_until") if key.valid_until is not None else None
        ),
        key_revoked_at=(
            _aware(key.revoked_at, "key revoked_at") if key.revoked_at is not None else None
        ),
        clock_skew_microseconds=_clock_skew_microseconds(trust.clock_skew, "current trust policy"),
    )


def _validate_historical_acceptance(
    historical: HistoricalAcceptance,
    *,
    canonical_record_digest: str,
    proof: Mapping[str, Any],
    issued_at: datetime,
    expires_at: datetime,
) -> None:
    if (
        not isinstance(historical.ledger_position, int)
        or isinstance(historical.ledger_position, bool)
        or historical.ledger_position < 0
    ):
        raise ProofVerificationError("historical acceptance metadata is incomplete")
    if historical.canonical_record_digest != canonical_record_digest:
        raise ProofVerificationError("historical acceptance does not exactly match the record")
    if historical.issued_at != issued_at:
        raise ProofVerificationError("historical acceptance does not exactly match issuance time")
    accepted_at = _aware(historical.accepted_at, "historical accepted_at")
    snapshot = historical.accepted_trust
    if not isinstance(snapshot, AcceptedTrustSnapshot):
        raise ProofVerificationError("historical acceptance trust snapshot is missing")
    if historical.accepted_trust_digest != accepted_trust_snapshot_digest(snapshot):
        raise ProofVerificationError("historical acceptance trust snapshot digest is invalid")
    if not snapshot.trust_policy_version:
        raise ProofVerificationError("historical acceptance trust policy is missing")
    _require_normalized_strings(snapshot.allowed_algorithms, "allowed_algorithms")
    _require_normalized_strings(snapshot.allowed_proof_domains, "allowed_proof_domains")
    _require_normalized_strings(snapshot.expected_issuers, "expected_issuers")
    _require_normalized_domain_issuers(snapshot.allowed_domain_issuers)
    _require_normalized_strings(snapshot.key_algorithms, "key_algorithms")
    if (
        snapshot.issuer,
        snapshot.key_id,
        snapshot.algorithm,
        snapshot.proof_domain,
    ) != (
        proof["issuer"],
        proof["key_id"],
        proof["algorithm"],
        proof["proof_domain"],
    ):
        raise ProofVerificationError("historical acceptance does not exactly match proof trust")
    if snapshot.algorithm not in snapshot.allowed_algorithms:
        raise ProofVerificationError("historical trust snapshot disallows the proof algorithm")
    if snapshot.proof_domain not in snapshot.allowed_proof_domains:
        raise ProofVerificationError("historical trust snapshot disallows the proof domain")
    if snapshot.issuer not in snapshot.expected_issuers:
        raise ProofVerificationError("historical trust snapshot disallows the proof issuer")
    if (snapshot.proof_domain, snapshot.issuer) not in snapshot.allowed_domain_issuers:
        raise ProofVerificationError("historical trust snapshot disallows the domain issuer")
    if snapshot.algorithm not in snapshot.key_algorithms:
        raise ProofVerificationError("historical trust snapshot disallows the key algorithm")
    if (
        not isinstance(snapshot.clock_skew_microseconds, int)
        or isinstance(snapshot.clock_skew_microseconds, bool)
        or snapshot.clock_skew_microseconds < 0
        or snapshot.clock_skew_microseconds > MAX_SAFE_INTEGER
    ):
        raise ProofVerificationError("historical trust snapshot clock skew is invalid")
    skew = timedelta(microseconds=snapshot.clock_skew_microseconds)
    valid_from = _aware(snapshot.key_valid_from, "historical key_valid_from")
    valid_until = (
        _aware(snapshot.key_valid_until, "historical key_valid_until")
        if snapshot.key_valid_until is not None
        else None
    )
    revoked_at = (
        _aware(snapshot.key_revoked_at, "historical key_revoked_at")
        if snapshot.key_revoked_at is not None
        else None
    )
    if issued_at > accepted_at + skew or accepted_at > expires_at + skew:
        raise ProofVerificationError(
            "historical first-acceptance time is outside signed-record validity"
        )
    if issued_at < valid_from - skew:
        raise ProofVerificationError("historical signed record predates accepted key validity")
    if valid_until is not None and valid_until < valid_from:
        raise ProofVerificationError("historical trust snapshot key validity is inverted")
    if valid_until is not None and issued_at > valid_until + skew:
        raise ProofVerificationError("historical signed record postdates accepted key validity")
    if revoked_at is not None and revoked_at <= accepted_at:
        raise ProofVerificationError("historical trust snapshot records a revoked key")


def _trusted_key(proof: Mapping[str, Any], trust: TrustContext) -> TrustedKey:
    matches = [
        key
        for key in trust.trusted_keys
        if key.issuer == proof["issuer"] and key.key_id == proof["key_id"]
    ]
    if len(matches) != 1:
        raise ProofVerificationError("proof key is not uniquely trusted")
    return matches[0]


def _verify_signed_record(
    signed_record: Any,
    *,
    verifier: DetachedProofVerifier,
    trust: TrustContext,
    expected_tenant: str | None = None,
    schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
    allow_historical_acceptance: bool,
) -> HistoricalAcceptance:
    """Verify one signed record with first-acceptance or recorded-history semantics."""

    record = _as_record(signed_record)
    _aware(trust.now, "trust context time")
    record_type = record.get("record_type")
    if record_type not in SIGNED_PROOF_DOMAINS:
        raise ProofVerificationError("record type does not define a signed proof domain")
    validate_record(record, expected_tenant=expected_tenant, schema_store=schema_store)
    proof = record["proof"]
    domain = SIGNED_PROOF_DOMAINS[record_type]
    if proof["proof_domain"] != domain:
        raise ProofVerificationError("proof domain does not match the signed record type")
    issued_at = _parse_timestamp(record["issued_at"], "issued_at")
    expires_at = _parse_timestamp(record["expires_at"], "expires_at")
    signed_record_label = (
        "receipt" if record_type in {"activation_receipt", "rollback_receipt"} else "signed record"
    )
    _enforce_retroactive_invalidation(proof, issued_at, trust, signed_record_label)
    canonical_record_digest = sha256_digest(record)
    historical_matches = (
        [
            acceptance
            for acceptance in trust.historical_acceptances
            if acceptance.canonical_record_digest == canonical_record_digest
        ]
        if allow_historical_acceptance
        else []
    )
    if len(historical_matches) > 1:
        raise ProofVerificationError("signed record has duplicate historical acceptances")
    historical = historical_matches[0] if historical_matches else None
    if historical is None:
        if not isinstance(trust.trust_policy_version, str) or not trust.trust_policy_version:
            raise ProofVerificationError("current trust policy version is missing")
        _clock_skew_microseconds(trust.clock_skew, "current trust policy")
        if domain not in trust.allowed_proof_domains:
            raise ProofVerificationError("proof domain is not allowed")
        if proof["issuer"] not in trust.expected_issuers:
            raise ProofVerificationError("proof issuer is not allowed")
        if (domain, proof["issuer"]) not in trust.allowed_domain_issuers:
            raise ProofVerificationError("proof issuer is not allowed for the proof domain")
        if proof["algorithm"] not in trust.allowed_algorithms:
            raise ProofVerificationError("proof algorithm is not allowed")
        key = _trusted_key(proof, trust)
        if proof["algorithm"] not in key.algorithms:
            raise ProofVerificationError("proof algorithm is not allowed for the key")
        key_valid_from = _aware(key.valid_from, "key valid_from")
        key_valid_until = (
            _aware(key.valid_until, "key valid_until") if key.valid_until is not None else None
        )
        key_revoked_at = (
            _aware(key.revoked_at, "key revoked_at") if key.revoked_at is not None else None
        )
        if key_valid_until is not None and key_valid_until < key_valid_from:
            raise ProofVerificationError("key validity window is inverted")
        if trust.now > expires_at + trust.clock_skew:
            raise ProofVerificationError(f"{signed_record_label} expired before first acceptance")
        if issued_at > trust.now + trust.clock_skew:
            raise ProofVerificationError(f"{signed_record_label} issuance time is in the future")
        if issued_at < key_valid_from - trust.clock_skew:
            raise ProofVerificationError(f"{signed_record_label} predates key validity")
        if key_valid_until is not None and issued_at > key_valid_until + trust.clock_skew:
            raise ProofVerificationError(f"{signed_record_label} postdates key validity")
        if key_revoked_at is not None and key_revoked_at <= trust.now:
            raise ProofVerificationError("key is revoked for first acceptance")
        accepted_trust = _accepted_trust_snapshot(proof, trust, key)
    else:
        _validate_historical_acceptance(
            historical,
            canonical_record_digest=canonical_record_digest,
            proof=proof,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    verified = verifier.verify(
        issuer=proof["issuer"],
        key_id=proof["key_id"],
        algorithm=proof["algorithm"],
        proof_domain=proof["proof_domain"],
        object_digest=proof["object_digest"],
        nonce=proof["nonce"],
        detached_proof=proof["detached_proof"],
        unsigned_bytes=canonical_bytes(unsigned_body(record)),
    )
    if verified is not True:
        raise ProofVerificationError("detached proof verification failed")

    if historical is not None:
        return historical
    return HistoricalAcceptance(
        canonical_record_digest=canonical_record_digest,
        issued_at=issued_at,
        accepted_at=trust.now,
        accepted_trust=accepted_trust,
        accepted_trust_digest=accepted_trust_snapshot_digest(accepted_trust),
        ledger_position=-1,
    )


def verify_signed_record(
    signed_record: Any,
    *,
    verifier: DetachedProofVerifier,
    trust: TrustContext,
    expected_tenant: str | None = None,
    schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
    allow_historical_acceptance: bool = False,
) -> HistoricalAcceptance:
    """Verify a signed record, optionally honoring its exact recorded acceptance."""

    return _verify_signed_record(
        signed_record,
        verifier=verifier,
        trust=trust,
        expected_tenant=expected_tenant,
        schema_store=schema_store,
        allow_historical_acceptance=allow_historical_acceptance,
    )


def verify_runtime_receipt(
    receipt: Any,
    *,
    verifier: DetachedProofVerifier,
    trust: TrustContext,
    expected_tenant: str | None = None,
    schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
) -> HistoricalAcceptance:
    """Verify activation/rollback proof while preserving historical acceptance."""

    record = _as_record(receipt)
    if record.get("record_type") not in {"activation_receipt", "rollback_receipt"}:
        raise ProofVerificationError("only runtime activation/rollback receipts are accepted")
    if record.get("issuer_role") != "runtime_authority":
        raise ProofVerificationError("receipt issuer_role is not runtime_authority")
    return _verify_signed_record(
        record,
        verifier=verifier,
        trust=trust,
        expected_tenant=expected_tenant,
        schema_store=schema_store,
        allow_historical_acceptance=True,
    )


def validate_rollback_lifecycle(
    rollback: Any,
    activation: Any,
    *,
    verifier: DetachedProofVerifier,
    trust: TrustContext,
    expected_tenant: str | None = None,
    schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
) -> None:
    """Require a bound activation acceptance to precede rollback acceptance."""

    rollback_record, activation_record = _as_record(rollback), _as_record(activation)
    if rollback_record.get("record_type") != "rollback_receipt":
        raise ProofVerificationError("rollback lifecycle requires a rollback receipt")
    if activation_record.get("record_type") != "activation_receipt":
        raise ProofVerificationError("rollback lifecycle requires an activation receipt")

    if not isinstance(trust.historical_acceptances, tuple):
        raise ProofVerificationError("historical acceptances must be an immutable tuple")
    for acceptance in trust.historical_acceptances:
        if not isinstance(acceptance, HistoricalAcceptance):
            raise ProofVerificationError("historical acceptance record is malformed")

    activation_digest = sha256_digest(activation_record)
    rollback_digest = sha256_digest(rollback_record)
    activation_matches = tuple(
        acceptance
        for acceptance in trust.historical_acceptances
        if acceptance.canonical_record_digest == activation_digest
    )
    rollback_matches = tuple(
        acceptance
        for acceptance in trust.historical_acceptances
        if acceptance.canonical_record_digest == rollback_digest
    )
    if len(activation_matches) != 1:
        raise ProofVerificationError(
            "rollback lifecycle requires exactly one historical activation acceptance"
        )
    if len(rollback_matches) != 1:
        raise ProofVerificationError(
            "rollback lifecycle requires exactly one historical rollback acceptance"
        )

    activation_acceptance = verify_runtime_receipt(
        activation_record,
        verifier=verifier,
        trust=trust,
        expected_tenant=expected_tenant,
        schema_store=schema_store,
    )
    rollback_acceptance = verify_runtime_receipt(
        rollback_record,
        verifier=verifier,
        trust=trust,
        expected_tenant=expected_tenant,
        schema_store=schema_store,
    )
    validate_rollback_activation_binding(rollback_record, activation_record)
    positions = (
        activation_acceptance.ledger_position,
        rollback_acceptance.ledger_position,
    )
    if any(
        not isinstance(position, int) or isinstance(position, bool) or position < 0
        for position in positions
    ):
        raise ProofVerificationError("rollback lifecycle ledger positions are malformed")
    if activation_acceptance.ledger_position >= rollback_acceptance.ledger_position:
        raise ProofVerificationError(
            "historical activation acceptance must precede rollback acceptance"
        )


def learning_artifact_is_active(
    delivery: Any,
    receipt: Any | None,
    *,
    verifier: DetachedProofVerifier,
    trust: TrustContext,
    expected_tenant: str | None = None,
) -> bool:
    """Require recorded delivery and activation acceptance plus their full binding."""

    if receipt is None:
        return False
    try:
        delivery_record, receipt_record = _as_record(delivery), _as_record(receipt)
        if delivery_record.get("record_type") != "delivery_envelope":
            return False
        if delivery_record.get("lifecycle_state") != "delivered":
            return False
        if receipt_record.get("record_type") != "activation_receipt":
            return False
        delivery_acceptance = verify_signed_record(
            delivery_record,
            verifier=verifier,
            trust=trust,
            expected_tenant=expected_tenant,
            allow_historical_acceptance=True,
        )
        activation_acceptance = verify_runtime_receipt(
            receipt_record,
            verifier=verifier,
            trust=trust,
            expected_tenant=expected_tenant,
        )
        if any(
            not isinstance(position, int) or isinstance(position, bool)
            for position in (
                delivery_acceptance.ledger_position,
                activation_acceptance.ledger_position,
            )
        ):
            return False
        if not (0 <= delivery_acceptance.ledger_position < activation_acceptance.ledger_position):
            return False
        validate_activation_delivery_binding(receipt_record, delivery_record)
    except (ContractError, TypeError):
        return False
    return True
