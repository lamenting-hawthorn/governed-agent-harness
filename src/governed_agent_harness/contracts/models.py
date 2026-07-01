"""Static Python model classes backed by canonical JSON Schema validation."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any, ClassVar, TypeVar

from .canonical import canonical_bytes, sha256_digest
from .errors import SemanticError
from .json_codec import strict_json_loads
from .schema import DEFAULT_SCHEMA_STORE, SchemaStore
from .validation import validate_record

ModelT = TypeVar("ModelT", bound="ContractModel")


class ContractModel:
    """Validated immutable-by-copy representation of one canonical wire record."""

    RECORD_TYPE: ClassVar[str]
    SCHEMA_FILE: ClassVar[str]
    __slots__ = ("_data",)

    def __init__(
        self,
        data: Mapping[str, Any],
        *,
        expected_tenant: str | None = None,
        schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
        verify_self_digests: bool = True,
    ) -> None:
        value = copy.deepcopy(dict(data))
        if value.get("record_type") != self.RECORD_TYPE:
            raise SemanticError(
                f"record_type must be {self.RECORD_TYPE!r} for {type(self).__name__}"
            )
        validate_record(
            value,
            expected_tenant=expected_tenant,
            schema_store=schema_store,
            verify_self_digests=verify_self_digests,
        )
        self._data = value

    @classmethod
    def from_bytes(
        cls: type[ModelT],
        payload: bytes | bytearray | memoryview,
        *,
        expected_tenant: str | None = None,
        schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
        verify_self_digests: bool = True,
    ) -> ModelT:
        value = strict_json_loads(payload)
        if not isinstance(value, dict):
            raise SemanticError("wire record must decode to an object")
        return cls(
            value,
            expected_tenant=expected_tenant,
            schema_store=schema_store,
            verify_self_digests=verify_self_digests,
        )

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self._data)

    def canonical_digest(self) -> str:
        return sha256_digest(self._data)

    def __getitem__(self, key: str) -> Any:
        return copy.deepcopy(self._data[key])

    def __repr__(self) -> str:
        return f"{type(self).__name__}(record_type={self.RECORD_TYPE!r})"


class ActorContext(ContractModel):
    RECORD_TYPE = "actor_context"
    SCHEMA_FILE = "actor_context.schema.json"


class MemoryScope(ContractModel):
    RECORD_TYPE = "memory_scope"
    SCHEMA_FILE = "memory_scope.schema.json"


class EvidenceDraft(ContractModel):
    RECORD_TYPE = "evidence_draft"
    SCHEMA_FILE = "evidence_draft.schema.json"


class EvidenceEnvelope(ContractModel):
    RECORD_TYPE = "evidence_envelope"
    SCHEMA_FILE = "evidence_envelope.schema.json"


class LearningTraceEnvelope(ContractModel):
    RECORD_TYPE = "learning_trace_envelope"
    SCHEMA_FILE = "learning_trace_envelope.schema.json"


class MemoryQuery(ContractModel):
    RECORD_TYPE = "memory_query"
    SCHEMA_FILE = "memory_query.schema.json"


class MemoryRecord(ContractModel):
    RECORD_TYPE = "memory_record"
    SCHEMA_FILE = "memory_record.schema.json"


class MemoryProposal(ContractModel):
    RECORD_TYPE = "memory_proposal"
    SCHEMA_FILE = "memory_proposal.schema.json"


class MemoryDecision(ContractModel):
    RECORD_TYPE = "memory_decision"
    SCHEMA_FILE = "memory_decision.schema.json"


class ContextBundle(ContractModel):
    RECORD_TYPE = "context_bundle"
    SCHEMA_FILE = "context_bundle.schema.json"


class WriteReceipt(ContractModel):
    RECORD_TYPE = "write_receipt"
    SCHEMA_FILE = "write_receipt.schema.json"


class DeletionReceipt(ContractModel):
    RECORD_TYPE = "deletion_receipt"
    SCHEMA_FILE = "deletion_receipt.schema.json"


class ToolRequest(ContractModel):
    RECORD_TYPE = "tool_request"
    SCHEMA_FILE = "tool_request.schema.json"


class PolicyDecision(ContractModel):
    RECORD_TYPE = "policy_decision"
    SCHEMA_FILE = "policy_decision.schema.json"


class ApprovalRecord(ContractModel):
    RECORD_TYPE = "approval_record"
    SCHEMA_FILE = "approval_record.schema.json"


class AuthorizationGrant(ContractModel):
    RECORD_TYPE = "authorization_grant"
    SCHEMA_FILE = "authorization_grant.schema.json"


class CapabilityManifest(ContractModel):
    RECORD_TYPE = "capability_manifest"
    SCHEMA_FILE = "capability_manifest.schema.json"


class ActionOutcome(ContractModel):
    RECORD_TYPE = "action_outcome"
    SCHEMA_FILE = "action_outcome.schema.json"


class FeedbackEvent(ContractModel):
    RECORD_TYPE = "feedback_event"
    SCHEMA_FILE = "feedback_event.schema.json"


class EvaluationRun(ContractModel):
    RECORD_TYPE = "evaluation_run"
    SCHEMA_FILE = "evaluation_run.schema.json"


class DatasetVersion(ContractModel):
    RECORD_TYPE = "dataset_version"
    SCHEMA_FILE = "dataset_version.schema.json"


class SkillProposal(ContractModel):
    RECORD_TYPE = "skill_proposal"
    SCHEMA_FILE = "skill_proposal.schema.json"


class PolicyProposal(ContractModel):
    RECORD_TYPE = "policy_proposal"
    SCHEMA_FILE = "policy_proposal.schema.json"


class GateDecision(ContractModel):
    RECORD_TYPE = "gate_decision"
    SCHEMA_FILE = "gate_decision.schema.json"


class DeliveryEnvelope(ContractModel):
    RECORD_TYPE = "delivery_envelope"
    SCHEMA_FILE = "delivery_envelope.schema.json"


class ActivationReceipt(ContractModel):
    RECORD_TYPE = "activation_receipt"
    SCHEMA_FILE = "activation_receipt.schema.json"


class RollbackReceipt(ContractModel):
    RECORD_TYPE = "rollback_receipt"
    SCHEMA_FILE = "rollback_receipt.schema.json"


MODEL_CLASSES = (
    ActorContext,
    MemoryScope,
    EvidenceDraft,
    EvidenceEnvelope,
    LearningTraceEnvelope,
    MemoryQuery,
    MemoryRecord,
    MemoryProposal,
    MemoryDecision,
    ContextBundle,
    WriteReceipt,
    DeletionReceipt,
    ToolRequest,
    PolicyDecision,
    ApprovalRecord,
    AuthorizationGrant,
    CapabilityManifest,
    ActionOutcome,
    FeedbackEvent,
    EvaluationRun,
    DatasetVersion,
    SkillProposal,
    PolicyProposal,
    GateDecision,
    DeliveryEnvelope,
    ActivationReceipt,
    RollbackReceipt,
)

MODEL_BY_RECORD_TYPE = {model.RECORD_TYPE: model for model in MODEL_CLASSES}


def model_for(record_type: str) -> type[ContractModel]:
    try:
        return MODEL_BY_RECORD_TYPE[record_type]
    except KeyError as exc:
        raise SemanticError(f"unsupported record_type {record_type!r}") from exc


def parse_model(
    payload: bytes | bytearray | memoryview,
    *,
    expected_tenant: str | None = None,
    schema_store: SchemaStore = DEFAULT_SCHEMA_STORE,
    verify_self_digests: bool = True,
) -> ContractModel:
    value = strict_json_loads(payload)
    if not isinstance(value, dict) or not isinstance(value.get("record_type"), str):
        raise SemanticError("wire record requires a string record_type")
    return model_for(value["record_type"])(
        value,
        expected_tenant=expected_tenant,
        schema_store=schema_store,
        verify_self_digests=verify_self_digests,
    )
