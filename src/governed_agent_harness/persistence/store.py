"""PostgreSQL-backed authority and evidence store for durable governed effects."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from governed_agent_harness.contracts import (
    ActionOutcome,
    ActorContext,
    ApprovalRecord,
    AuthorizationGrant,
    EvidenceEnvelope,
    ConstraintRegistry,
    DetachedProofVerifier,
    IdempotencyConflictError,
    MemoryDecision,
    MemoryProposal,
    PolicyDecision,
    MemoryQuery,
    MemoryRecord,
    SemanticError,
    ToolRequest,
    TrustContext,
    apply_object_digest,
    sha256_digest,
    validate_constraint_support,
    validate_memory_promotion_bindings,
    validate_scope_narrowing,
    verify_signed_record,
)


class DurableStoreError(SemanticError):
    """Raised when durable authority state cannot transition safely."""


class OptimisticConcurrencyError(DurableStoreError):
    """Raised when a caller attempts a stale execution transition."""


class PreparedExecutionError(DurableStoreError):
    """Raised when explicit recovery is required for an existing preparation."""


@dataclass(frozen=True, slots=True)
class StoredLifecycle:
    """Validated, rebuildable pre-effect lifecycle snapshot."""

    actor_context: Mapping[str, Any]
    request: Mapping[str, Any]
    policy: Mapping[str, Any]
    state: str
    version: int
    evidence: tuple[Mapping[str, Any], ...]
    approval: Mapping[str, Any] | None = None
    grant: Mapping[str, Any] | None = None

    def snapshot(self) -> StoredLifecycle:
        return StoredLifecycle(
            actor_context=copy.deepcopy(dict(self.actor_context)),
            request=copy.deepcopy(dict(self.request)),
            policy=copy.deepcopy(dict(self.policy)),
            state=self.state,
            version=self.version,
            evidence=tuple(copy.deepcopy(dict(value)) for value in self.evidence),
            approval=copy.deepcopy(dict(self.approval)) if self.approval is not None else None,
            grant=copy.deepcopy(dict(self.grant)) if self.grant is not None else None,
        )


@dataclass(frozen=True, slots=True)
class RetrievedMemory:
    """One validated read-only memory result with deterministic relevance."""

    record: Mapping[str, Any]
    relevance_score: int

    def snapshot(self) -> RetrievedMemory:
        return RetrievedMemory(
            record=copy.deepcopy(dict(self.record)), relevance_score=self.relevance_score
        )


@dataclass(frozen=True, slots=True)
class StoredMemoryTransition:
    """Immutable result of one authority-only governed memory transition."""

    proposal: Mapping[str, Any]
    memory_decision: Mapping[str, Any]
    policy_decision: Mapping[str, Any]
    approvals: tuple[Mapping[str, Any], ...]
    record: Mapping[str, Any]
    evidence: Mapping[str, Any]
    binding_digest: str
    operation: str
    expected_revision: int | None
    replayed: bool = False

    @property
    def committed_record(self) -> Mapping[str, Any]:
        return copy.deepcopy(dict(self.record))

    @property
    def canonical_evidence(self) -> Mapping[str, Any]:
        return copy.deepcopy(dict(self.evidence))

    @property
    def previous_revision(self) -> int | None:
        return self.expected_revision

    @property
    def revision(self) -> int:
        return int(self.record["revision"])

    def snapshot(self, *, replayed: bool | None = None) -> StoredMemoryTransition:
        return StoredMemoryTransition(
            proposal=copy.deepcopy(dict(self.proposal)),
            memory_decision=copy.deepcopy(dict(self.memory_decision)),
            policy_decision=copy.deepcopy(dict(self.policy_decision)),
            approvals=tuple(copy.deepcopy(dict(value)) for value in self.approvals),
            record=copy.deepcopy(dict(self.record)),
            evidence=copy.deepcopy(dict(self.evidence)),
            binding_digest=self.binding_digest,
            operation=self.operation,
            expected_revision=self.expected_revision,
            replayed=self.replayed if replayed is None else replayed,
        )


@dataclass(frozen=True, slots=True)
class StoredEffectExecution:
    """Immutable snapshot of one durable effect execution."""

    actor_context: Mapping[str, Any]
    request: Mapping[str, Any]
    policy: Mapping[str, Any]
    approvals: tuple[Mapping[str, Any], ...]
    grant: Mapping[str, Any]
    binding_digest: str
    state: str
    version: int
    intent_evidence: Mapping[str, Any]
    outcome: Mapping[str, Any] | None = None
    outcome_evidence: Mapping[str, Any] | None = None
    execution_attempt_id: str | None = None
    owner_generation: int | None = None
    lease_expires_at: datetime | None = None
    last_renewed_at: datetime | None = None
    created: bool = False

    def snapshot(self, *, created: bool | None = None) -> StoredEffectExecution:
        return StoredEffectExecution(
            actor_context=copy.deepcopy(dict(self.actor_context)),
            request=copy.deepcopy(dict(self.request)),
            policy=copy.deepcopy(dict(self.policy)),
            approvals=tuple(copy.deepcopy(dict(value)) for value in self.approvals),
            grant=copy.deepcopy(dict(self.grant)),
            binding_digest=self.binding_digest,
            state=self.state,
            version=self.version,
            intent_evidence=copy.deepcopy(dict(self.intent_evidence)),
            outcome=copy.deepcopy(dict(self.outcome)) if self.outcome is not None else None,
            outcome_evidence=(
                copy.deepcopy(dict(self.outcome_evidence))
                if self.outcome_evidence is not None
                else None
            ),
            execution_attempt_id=self.execution_attempt_id,
            owner_generation=self.owner_generation,
            lease_expires_at=self.lease_expires_at,
            last_renewed_at=self.last_renewed_at,
            created=self.created if created is None else created,
        )


class DurableEffectStore(Protocol):
    """Narrow durable boundary used only by the sole effect broker."""

    def lookup(
        self, *, actor_context: Mapping[str, Any], request_id: str
    ) -> StoredEffectExecution | None: ...

    def prepare(
        self,
        *,
        actor_context: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...],
        grant: Mapping[str, Any],
        policy_ref: Mapping[str, str],
        intent_payload: Mapping[str, Any],
    ) -> StoredEffectExecution: ...

    def complete(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        expected_version: int,
        outcome: Mapping[str, Any],
        policy_ref: Mapping[str, str],
        outcome_payload: Mapping[str, Any],
        state: str,
        execution_attempt_id: str,
        owner_generation: int,
    ) -> StoredEffectExecution: ...

    def renew_lease(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        execution_attempt_id: str,
        owner_generation: int,
    ) -> StoredEffectExecution: ...

    def recover_expired(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        outcome: Mapping[str, Any],
        policy_ref: Mapping[str, str],
        outcome_payload: Mapping[str, Any],
    ) -> StoredEffectExecution: ...

    def load_lifecycle(
        self, *, actor_context: Mapping[str, Any], request_id: str
    ) -> StoredLifecycle | None: ...

    def persist_submission(
        self,
        *,
        actor_context: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        state: str,
        policy_ref: Mapping[str, str],
    ) -> StoredLifecycle: ...

    def persist_approval(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        expected_version: int,
        approval: Mapping[str, Any],
        policy_ref: Mapping[str, str],
    ) -> StoredLifecycle: ...

    def persist_grant(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        expected_version: int,
        grant: Mapping[str, Any],
        policy_ref: Mapping[str, str],
    ) -> StoredLifecycle: ...


class MemoryRetriever(Protocol):
    """Read-only, actor-scoped governed memory boundary."""

    def retrieve_memory(
        self,
        *,
        actor_context: Mapping[str, Any],
        memory_query: Mapping[str, Any],
    ) -> tuple[RetrievedMemory, ...]: ...


class MemoryPromotionAuthority(Protocol):
    """Authority-only boundary; it is deliberately absent from runtime/kernel ports."""

    def promote_memory(
        self,
        *,
        actor_context: Mapping[str, Any],
        proposal: Mapping[str, Any],
        memory_decision: Mapping[str, Any],
        policy_decision: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...] = (),
        expected_revision: int | None = None,
    ) -> StoredMemoryTransition: ...


class _Connection(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(self, *values: object) -> None: ...

    def cursor(self) -> Any: ...


def execution_binding_digest(
    *,
    actor_context: Mapping[str, Any],
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    approvals: tuple[Mapping[str, Any], ...],
    grant: Mapping[str, Any],
) -> str:
    """Bind every authority input whose drift could change effect authorization."""

    return sha256_digest(
        {
            "actor_context_digest": sha256_digest(actor_context),
            "request_digest": request["request_digest"],
            "policy_decision_digest": policy["decision_digest"],
            "approval_digests": [value["approval_digest"] for value in approvals],
            "constraints": grant["constraints"],
            "isolation_profile": grant["isolation_profile"],
            "grant_digest": sha256_digest(grant),
            "tenant_id": request["tenant_id"],
            "actor_id": request["actor_id"],
            "run_id": request["run_id"],
            "idempotency": request["idempotency"],
            "expires_at": grant["expires_at"],
        }
    )


def memory_transition_binding_digest(
    *,
    actor_context: Mapping[str, Any],
    proposal: Mapping[str, Any],
    memory_decision: Mapping[str, Any],
    policy_decision: Mapping[str, Any],
    approvals: tuple[Mapping[str, Any], ...],
    committed_record: Mapping[str, Any],
    expected_revision: int | None,
) -> str:
    """Bind every authority input whose drift could change memory state."""

    return sha256_digest(
        {
            "tenant_id": actor_context["tenant_id"],
            "actor_id": actor_context["actor_id"],
            "actor_context_digest": sha256_digest(actor_context),
            "scope_digest": sha256_digest(proposal["target_scope"]),
            "proposal_id": proposal["proposal_id"],
            "proposal_digest": proposal["proposal_digest"],
            "operation": proposal["change_kind"],
            "memory_id": committed_record["memory_id"],
            "expected_revision": expected_revision,
            "evidence_spans": proposal["evidence_spans"],
            "memory_decision_digest": memory_decision["decision_digest"],
            "policy_decision_digest": policy_decision["decision_digest"],
            "approval_digests": [value["approval_digest"] for value in approvals],
            "retention": committed_record["retention"],
            "effective_from": committed_record["effective_from"],
            "effective_until": committed_record.get("effective_until"),
            "expires_at": committed_record.get("expires_at"),
            "committed_record_digest": committed_record["record_digest"],
        }
    )


class PostgresDurableEffectStore:
    """Real PostgreSQL implementation with forced RLS and transactional authority use."""

    def __init__(
        self,
        *,
        connect: Callable[[], _Connection],
        privileged_connect: Callable[[], _Connection],
        clock: Callable[[], datetime],
        ids: Callable[[], str],
        lease_duration: timedelta = timedelta(seconds=30),
        constraint_registry: ConstraintRegistry | None = None,
        approval_verifier: DetachedProofVerifier | None = None,
        approval_trust: Callable[[datetime], TrustContext] | None = None,
    ) -> None:
        self._runtime_connect = connect
        self._connect = privileged_connect
        self._clock = clock
        self._ids = ids
        self._constraint_registry = constraint_registry or ConstraintRegistry({})
        self._approval_verifier = approval_verifier
        self._approval_trust = approval_trust
        if lease_duration <= timedelta(0):
            raise DurableStoreError("lease duration must be positive")
        self._lease_duration = lease_duration

    @property
    def heartbeat_interval_seconds(self) -> float:
        return max(0.01, self._lease_duration.total_seconds() / 3)

    @staticmethod
    def install_schema(
        *,
        admin_connect: Callable[[], _Connection],
        application_role: str | None = None,
        authority_role: str | None = None,
    ) -> None:
        """Apply immutable migrations and grant only runtime-function membership."""

        if (
            application_role is not None
            and authority_role is not None
            and application_role == authority_role
        ):
            raise DurableStoreError("runtime and authority database roles must be distinct")
        reserved_roles = {"gah_schema_owner", "gah_runtime", "gah_authority_writer"}
        for role_name in (application_role, authority_role):
            if role_name is None:
                continue
            if not role_name or not role_name.replace("_", "a").isalnum():
                raise DurableStoreError("database role name is malformed")
            if role_name in reserved_roles:
                raise DurableStoreError("service login cannot be a reserved GAH group role")

        from governed_agent_harness.persistence.migration import apply_migrations

        apply_migrations(admin_connect=admin_connect)
        from psycopg import sql

        with admin_connect() as connection, connection.cursor() as cursor:
            for role_name in (application_role, authority_role):
                if role_name is None:
                    continue
                cursor.execute(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = %s",
                    (role_name,),
                )
                attributes = cursor.fetchone()
                if attributes is None:
                    raise DurableStoreError("service database login does not exist")
                if attributes != (True, False, False, False, False, False):
                    raise DurableStoreError("service database login has unsafe attributes")
            membership_paths: list[tuple[str, str]] = []
            if application_role is not None:
                membership_paths.extend(
                    (
                        (application_role, "gah_schema_owner"),
                        (application_role, "gah_authority_writer"),
                    )
                )
            if authority_role is not None:
                membership_paths.extend(
                    (
                        (authority_role, "gah_schema_owner"),
                        (authority_role, "gah_runtime"),
                    )
                )
            if application_role is not None and authority_role is not None:
                membership_paths.extend(
                    (
                        (application_role, authority_role),
                        (authority_role, application_role),
                        ("gah_runtime", "gah_authority_writer"),
                    )
                )
            for member, group in membership_paths:
                cursor.execute("SELECT pg_has_role(%s, %s, 'MEMBER')", (member, group))
                if cursor.fetchone()[0]:
                    raise DurableStoreError(
                        "runtime and authority roles have an unsafe membership path"
                    )
            for role_name, membership in (
                (application_role, "gah_runtime"),
                (authority_role, "gah_authority_writer"),
            ):
                if role_name is None:
                    continue
                cursor.execute(
                    sql.SQL("GRANT {} TO {}").format(
                        sql.Identifier(membership), sql.Identifier(role_name)
                    )
                )

    @staticmethod
    def provision_principal(
        *,
        admin_connect: Callable[[], _Connection],
        database_roles: tuple[str, ...],
        actor_context: Mapping[str, Any],
    ) -> None:
        """Privileged, explicit binding of database logins to one verified actor."""

        actor = ActorContext(actor_context).to_dict()
        if not database_roles:
            raise DurableStoreError("at least one database role is required")
        with admin_connect() as connection, connection.cursor() as cursor:
            for role_name in database_roles:
                if not role_name or not role_name.replace("_", "a").isalnum():
                    raise DurableStoreError("database role name is malformed")
                cursor.execute(
                    "INSERT INTO gah_runtime_principals "
                    "(database_role, tenant_id, actor_id) VALUES (%s, %s, %s) "
                    "ON CONFLICT (database_role) DO UPDATE SET "
                    "tenant_id = excluded.tenant_id, actor_id = excluded.actor_id",
                    (role_name, actor["tenant_id"], actor["actor_id"]),
                )

    def lookup(
        self, *, actor_context: Mapping[str, Any], request_id: str
    ) -> StoredEffectExecution | None:
        actor = ActorContext(actor_context).to_dict()
        with self._runtime_connect() as connection, connection.cursor() as cursor:
            row = _runtime_read(cursor, actor, "effect_by_request", {"request_id": request_id})
        return self._row(_effect_row(row)) if row is not None else None

    def retrieve_memory(
        self, *, actor_context: Mapping[str, Any], memory_query: Mapping[str, Any]
    ) -> tuple[RetrievedMemory, ...]:
        """Return only active actor-scoped records through the restricted read role."""

        actor = ActorContext(actor_context).to_dict()
        query = MemoryQuery(memory_query, expected_tenant=actor["tenant_id"]).to_dict()
        try:
            validate_scope_narrowing(query["scope"], actor)
        except SemanticError as error:
            raise DurableStoreError(
                "memory query scope is not derived from actor authority"
            ) from error
        if query["scope"]["selection"] != {"level": "actor"}:
            raise DurableStoreError("read-only retrieval currently requires actor scope")
        if _parse_time(query["scope"]["valid_until"]) < _aware_utc(self._clock()):
            raise DurableStoreError("memory query scope is expired")
        with self._runtime_connect() as connection, connection.cursor() as cursor:
            rows = _retrieve_memory(cursor, actor, query)
        matches: list[RetrievedMemory] = []
        for row in rows:
            score = row.pop("_relevance_score", None)
            if not isinstance(score, int) or score < 1:
                raise DurableStoreError("memory retrieval returned an invalid relevance score")
            record = MemoryRecord(row, expected_tenant=actor["tenant_id"]).to_dict()
            try:
                validate_scope_narrowing(record["scope"], actor)
            except SemanticError as error:
                raise DurableStoreError(
                    "memory record scope is not derived from actor authority"
                ) from error
            if (
                record["scope"]["selection"] != query["scope"]["selection"]
                or record["visibility"] != "actor"
                or record["lifecycle_state"] != "active"
            ):
                raise DurableStoreError("memory retrieval returned an out-of-scope record")
            matches.append(RetrievedMemory(record=record, relevance_score=score))
        return tuple(match.snapshot() for match in matches)

    def _promote_memory(
        self,
        *,
        actor_context: Mapping[str, Any],
        proposal: Mapping[str, Any],
        memory_decision: Mapping[str, Any],
        policy_decision: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...] = (),
        expected_revision: int | None = None,
    ) -> StoredMemoryTransition:
        """Atomically append promotion evidence and persist its rebuildable projection."""

        now = _aware_utc(self._clock())
        actor = ActorContext(actor_context).to_dict()
        parsed_proposal = MemoryProposal(proposal, expected_tenant=actor["tenant_id"]).to_dict()
        parsed_decision = MemoryDecision(
            memory_decision, expected_tenant=actor["tenant_id"]
        ).to_dict()
        parsed_policy = PolicyDecision(
            policy_decision, expected_tenant=actor["tenant_id"]
        ).to_dict()
        parsed_approvals = tuple(
            ApprovalRecord(value, expected_tenant=actor["tenant_id"]).to_dict()
            for value in approvals
        )
        committed = _validate_memory_transition_authority(
            actor=actor,
            proposal=parsed_proposal,
            memory_decision=parsed_decision,
            policy=parsed_policy,
            approvals=parsed_approvals,
            expected_revision=expected_revision,
            now=now,
            constraint_registry=self._constraint_registry,
            approval_verifier=self._approval_verifier,
            approval_trust=self._approval_trust,
        )
        binding_digest = memory_transition_binding_digest(
            actor_context=actor,
            proposal=parsed_proposal,
            memory_decision=parsed_decision,
            policy_decision=parsed_policy,
            approvals=parsed_approvals,
            committed_record=committed,
            expected_revision=expected_revision,
        )
        policy_ref = {
            "record_type": "policy_decision",
            "record_id": parsed_policy["decision_id"],
            "record_digest": parsed_policy["decision_digest"],
        }
        transition_payload = {
            "actor_id": actor["actor_id"],
            "actor_context": actor,
            "actor_context_digest": sha256_digest(actor),
            "proposal": parsed_proposal,
            "memory_decision": parsed_decision,
            "policy_decision": parsed_policy,
            "approvals": list(parsed_approvals),
            "committed_record": committed,
            "operation": parsed_proposal["change_kind"],
            "expected_revision": expected_revision,
            "binding_digest": binding_digest,
            "policy_decision_digest": parsed_policy["decision_digest"],
        }
        with self._connect() as connection, connection.cursor() as cursor:
            for lock_key in sorted(
                (
                    f"memory:{actor['tenant_id']}:{committed['memory_id']}",
                    f"proposal:{actor['tenant_id']}:{parsed_proposal['proposal_id']}",
                )
            ):
                cursor.execute(
                    "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s, 0))",
                    (lock_key,),
                )
            existing = _commit_memory_transition(
                cursor,
                actor,
                {
                    "proposal_id": parsed_proposal["proposal_id"],
                    "binding_digest": binding_digest,
                    "transition": transition_payload,
                },
            )
            if existing.get("replayed"):
                return _stored_memory_transition(
                    existing, expected_binding=binding_digest, replayed=True
                )
            evidence = self._prepare_evidence(
                cursor=cursor,
                actor=actor,
                run_id=parsed_proposal["producer"]["run_id"],
                event_kind="memory.promoted",
                policy_ref=policy_ref,
                payload=transition_payload,
            )
            stored = _commit_memory_transition(
                cursor,
                actor,
                {
                    "proposal_id": parsed_proposal["proposal_id"],
                    "binding_digest": binding_digest,
                    "expected_revision": expected_revision,
                    "evidence": evidence,
                    "transition": transition_payload,
                },
            )
        return _stored_memory_transition(stored, expected_binding=binding_digest)

    def _rebuild_memory_projection(
        self, *, actor_context: Mapping[str, Any], memory_id: str
    ) -> StoredMemoryTransition:
        """Rebuild one memory projection exclusively from canonical ledger evidence."""

        now = _aware_utc(self._clock())
        actor = ActorContext(actor_context).to_dict()
        if not _parse_time(actor["issued_at"]) <= now < _parse_time(actor["expires_at"]):
            raise DurableStoreError("actor authority is not currently valid")
        with self._connect() as connection, connection.cursor() as cursor:
            stored = _rebuild_memory_projection(cursor, actor, {"memory_id": memory_id})
        return _stored_memory_transition(stored)

    def append(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_kind: str,
        policy_ref: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Append kernel transition evidence into the same authoritative run chain."""

        actor_id = payload.get("actor_id")
        if not isinstance(actor_id, str):
            raise DurableStoreError("evidence payload must carry the verified actor scope")
        if (
            policy_ref.get("record_type") != "policy_decision"
            or not isinstance(policy_ref.get("record_id"), str)
            or not isinstance(policy_ref.get("record_digest"), str)
        ):
            raise DurableStoreError("evidence policy reference is malformed")
        if (
            event_kind != "kernel.policy_decided"
            and payload.get("policy_decision_digest") != policy_ref["record_digest"]
        ):
            raise DurableStoreError("evidence policy reference does not match payload")
        actor = {"tenant_id": tenant_id, "actor_id": actor_id}
        with self._connect() as connection, connection.cursor() as cursor:
            return self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=run_id,
                event_kind=event_kind,
                policy_ref=policy_ref,
                payload=payload,
            )

    def persist_submission(
        self,
        *,
        actor_context: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        state: str,
        policy_ref: Mapping[str, str],
    ) -> StoredLifecycle:
        """Atomically append canonical request/policy evidence and create its projection."""

        actor = ActorContext(actor_context).to_dict()
        parsed_request = ToolRequest(request, expected_tenant=actor["tenant_id"]).to_dict()
        parsed_policy = PolicyDecision(policy, expected_tenant=actor["tenant_id"]).to_dict()
        _validate_lifecycle_authority(actor, parsed_request, parsed_policy)
        expected_state = {
            "deny": "denied",
            "require_approval": "approval_required",
            "allow": "policy_authorized",
        }.get(parsed_policy["decision"])
        if state != expected_state:
            raise DurableStoreError("lifecycle state does not match the policy decision")
        _require_policy_ref(policy_ref, parsed_policy)
        payload = {
            "actor_id": actor["actor_id"],
            "actor_context": actor,
            "request": parsed_request,
            "policy": parsed_policy,
            "request_digest": parsed_request["request_digest"],
            "policy_decision_digest": parsed_policy["decision_digest"],
            "next_state": state,
        }
        with self._connect() as connection, connection.cursor() as cursor:
            replay = _runtime_read(
                cursor,
                actor,
                "lifecycle_by_idempotency",
                {"idempotency_key": parsed_request["idempotency"]["idempotency_key"]},
            )
            if replay is not None:
                if (
                    replay["request_id"] == parsed_request["request_id"]
                    and replay["request_json"]["request_digest"] == parsed_request["request_digest"]
                ):
                    return self._load_lifecycle_with_cursor(cursor, actor, replay["request_id"])
                raise IdempotencyConflictError("durable lifecycle idempotency binding conflicts")
            evidence = self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=parsed_request["run_id"],
                event_kind="kernel.policy_decided",
                policy_ref=policy_ref,
                payload=payload,
            )
            _runtime_write(
                cursor,
                actor,
                "insert_lifecycle",
                {
                    "run_id": parsed_request["run_id"],
                    "request_id": parsed_request["request_id"],
                    "request_digest": parsed_request["request_digest"],
                    "idempotency_key": parsed_request["idempotency"]["idempotency_key"],
                    "operation_digest": parsed_request["idempotency"]["operation_digest"],
                    "policy_decision_digest": parsed_policy["decision_digest"],
                    "request": parsed_request,
                    "policy": parsed_policy,
                    "state": state,
                    "last_evidence_sequence": evidence["sequence_number"],
                    "last_evidence_digest": evidence["event_digest"],
                },
            )
        return StoredLifecycle(
            actor, parsed_request, parsed_policy, state, 1, (evidence,)
        ).snapshot()

    def persist_approval(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        expected_version: int,
        approval: Mapping[str, Any],
        policy_ref: Mapping[str, str],
    ) -> StoredLifecycle:
        """Atomically append an exact approval and advance the projection once."""

        actor = ActorContext(actor_context).to_dict()
        parsed = ApprovalRecord(approval, expected_tenant=actor["tenant_id"]).to_dict()
        with self._connect() as connection, connection.cursor() as cursor:
            current = self._load_lifecycle_with_cursor(cursor, actor, request_id, for_update=True)
            if current.state == "approved":
                if current.approval == parsed:
                    return current
                raise IdempotencyConflictError("durable approval replay conflicts")
            if current.state != "approval_required" or current.version != expected_version:
                raise OptimisticConcurrencyError("durable approval transition is stale")
            _validate_lifecycle_authority(actor, current.request, current.policy, approval=parsed)
            _require_policy_ref(policy_ref, current.policy)
            payload = {
                "actor_id": actor["actor_id"],
                "request_id": current.request["request_id"],
                "request_digest": current.request["request_digest"],
                "policy_decision_digest": current.policy["decision_digest"],
                "approval": parsed,
                "approval_digest": parsed["approval_digest"],
                "next_state": "approved",
            }
            evidence = self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=current.request["run_id"],
                event_kind="kernel.approval_accepted",
                policy_ref=policy_ref,
                payload=payload,
            )
            changed = _runtime_write(
                cursor,
                actor,
                "approve_lifecycle",
                {
                    "request_id": request_id,
                    "expected_version": expected_version,
                    "approval": parsed,
                    "last_evidence_sequence": evidence["sequence_number"],
                    "last_evidence_digest": evidence["event_digest"],
                },
            )
            if changed["changed"] != 1:
                raise OptimisticConcurrencyError("durable approval transition lost its race")
        return StoredLifecycle(
            actor,
            current.request,
            current.policy,
            "approved",
            expected_version + 1,
            (*current.evidence, evidence),
            approval=parsed,
        ).snapshot()

    def persist_grant(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        expected_version: int,
        grant: Mapping[str, Any],
        policy_ref: Mapping[str, str],
    ) -> StoredLifecycle:
        """Atomically append a canonical grant and advance its rebuildable projection."""

        actor = ActorContext(actor_context).to_dict()
        parsed = AuthorizationGrant(grant, expected_tenant=actor["tenant_id"]).to_dict()
        with self._connect() as connection, connection.cursor() as cursor:
            current = self._load_lifecycle_with_cursor(cursor, actor, request_id, for_update=True)
            if current.state == "grant_issued":
                if current.grant == parsed:
                    return current
                raise IdempotencyConflictError("durable grant replay conflicts")
            if current.state not in {"policy_authorized", "approved"}:
                raise OptimisticConcurrencyError("durable grant state is not issuable")
            if current.version != expected_version:
                raise OptimisticConcurrencyError("durable grant transition is stale")
            _validate_lifecycle_authority(
                actor,
                current.request,
                current.policy,
                approval=current.approval,
                grant=parsed,
            )
            _require_policy_ref(policy_ref, current.policy)
            payload = {
                "actor_id": actor["actor_id"],
                "request_id": current.request["request_id"],
                "request_digest": current.request["request_digest"],
                "policy_decision_digest": current.policy["decision_digest"],
                "grant": parsed,
                "authorization_grant_digest": sha256_digest(parsed),
                "next_state": "grant_issued",
            }
            evidence = self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=current.request["run_id"],
                event_kind="kernel.authorization_grant_issued",
                policy_ref=policy_ref,
                payload=payload,
            )
            changed = _runtime_write(
                cursor,
                actor,
                "grant_lifecycle",
                {
                    "request_id": request_id,
                    "expected_version": expected_version,
                    "grant": parsed,
                    "last_evidence_sequence": evidence["sequence_number"],
                    "last_evidence_digest": evidence["event_digest"],
                },
            )
            if changed["changed"] != 1:
                raise OptimisticConcurrencyError("durable grant transition lost its race")
        return StoredLifecycle(
            actor,
            current.request,
            current.policy,
            "grant_issued",
            expected_version + 1,
            (*current.evidence, evidence),
            approval=current.approval,
            grant=parsed,
        ).snapshot()

    def load_lifecycle(
        self, *, actor_context: Mapping[str, Any], request_id: str
    ) -> StoredLifecycle | None:
        actor = ActorContext(actor_context).to_dict()
        with self._runtime_connect() as connection, connection.cursor() as cursor:
            return self._load_lifecycle_with_cursor(cursor, actor, request_id, missing_ok=True)

    def rebuild_lifecycle(
        self, *, actor_context: Mapping[str, Any], request_id: str
    ) -> StoredLifecycle:
        """Rebuild and repair only the projection from authoritative canonical evidence."""

        actor = ActorContext(actor_context).to_dict()
        with self._connect() as connection, connection.cursor() as cursor:
            candidate_rows = _runtime_read(
                cursor, actor, "lifecycle_events", {"request_id": request_id}
            )
            candidates = tuple(
                EvidenceEnvelope(row, expected_tenant=actor["tenant_id"]).to_dict()
                for row in candidate_rows
            )
            run_ids = {event["draft"]["run_id"] for event in candidates}
            if len(run_ids) != 1:
                raise DurableStoreError("canonical lifecycle run authority is missing")
            _runtime_write(cursor, actor, "lock_run", {"run_id": next(iter(run_ids))})
            rebuilt = self._replay_lifecycle(cursor, actor, request_id)
            last = rebuilt.evidence[-1]
            changed = _runtime_write(
                cursor,
                actor,
                "rebuild_lifecycle",
                {
                    "request_id": request_id,
                    "run_id": rebuilt.request["run_id"],
                    "request_digest": rebuilt.request["request_digest"],
                    "idempotency_key": rebuilt.request["idempotency"]["idempotency_key"],
                    "operation_digest": rebuilt.request["idempotency"]["operation_digest"],
                    "policy_decision_digest": rebuilt.policy["decision_digest"],
                    "request": rebuilt.request,
                    "policy": rebuilt.policy,
                    "approvals": [rebuilt.approval] if rebuilt.approval else [],
                    "grant": rebuilt.grant,
                    "state": rebuilt.state,
                    "version": rebuilt.version,
                    "last_evidence_sequence": last["sequence_number"],
                    "last_evidence_digest": last["event_digest"],
                },
            )
            if changed["changed"] != 1:
                raise DurableStoreError("lifecycle projection rebuild lost its actor scope")
        return rebuilt.snapshot()

    def prepare(
        self,
        *,
        actor_context: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...],
        grant: Mapping[str, Any],
        policy_ref: Mapping[str, str],
        intent_payload: Mapping[str, Any],
    ) -> StoredEffectExecution:
        actor, parsed_request, parsed_policy, parsed_approvals, parsed_grant = _parse_inputs(
            actor_context, request, policy, approvals, grant
        )
        binding_digest = execution_binding_digest(
            actor_context=actor,
            request=parsed_request,
            policy=parsed_policy,
            approvals=parsed_approvals,
            grant=parsed_grant,
        )
        expected_intent_payload = {
            "actor_id": actor["actor_id"],
            "request_digest": parsed_request["request_digest"],
            "policy_decision_digest": parsed_policy["decision_digest"],
            "authorization_grant_digest": sha256_digest(parsed_grant),
            "effect_classes": parsed_request["effect_classes"],
            "isolation_profile": parsed_grant["isolation_profile"],
        }
        if dict(intent_payload) != expected_intent_payload:
            raise DurableStoreError("durable intent payload is not exactly bound to authority")
        lock_values = sorted(
            (
                _lock_key(
                    f"idem:{actor['tenant_id']}:{parsed_request['idempotency']['idempotency_key']}"
                ),
                _lock_key(f"grant:{actor['tenant_id']}:{parsed_grant['grant_id']}"),
            )
        )
        with self._connect() as connection, connection.cursor() as cursor:
            for value in lock_values:
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", (value,))
            existing = self._select_for_binding(cursor, actor, parsed_request, parsed_grant)
            if existing is not None:
                _require_exact(existing, binding_digest, parsed_request, parsed_grant)
                return existing.snapshot(created=False)

            intent = self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=parsed_request["run_id"],
                event_kind="kernel.effect_execution_intent",
                policy_ref=policy_ref,
                payload=intent_payload,
            )
            now = _aware_utc(self._clock())
            attempt_id = self._ids()
            inserted = _runtime_write(
                cursor,
                actor,
                "insert_effect",
                {
                    "run_id": parsed_request["run_id"],
                    "request_id": parsed_request["request_id"],
                    "idempotency_key": parsed_request["idempotency"]["idempotency_key"],
                    "operation_digest": parsed_request["idempotency"]["operation_digest"],
                    "binding_digest": binding_digest,
                    "grant_id": parsed_grant["grant_id"],
                    "grant_digest": sha256_digest(parsed_grant),
                    "request": parsed_request,
                    "policy": parsed_policy,
                    "approvals": list(parsed_approvals),
                    "grant": parsed_grant,
                    "intent": intent,
                    "prepared_at": _utc_millis(now),
                    "attempt_id": attempt_id,
                    "lease_seconds": self._lease_duration.total_seconds(),
                },
            )
            lease_expires_at = _parse_time(inserted["lease_expires_at"])
            last_renewed_at = _parse_time(inserted["last_renewed_at"])
        return StoredEffectExecution(
            actor,
            parsed_request,
            parsed_policy,
            parsed_approvals,
            parsed_grant,
            binding_digest,
            "prepared",
            1,
            intent,
            execution_attempt_id=attempt_id,
            owner_generation=1,
            lease_expires_at=lease_expires_at,
            last_renewed_at=last_renewed_at,
            created=True,
        ).snapshot()

    def complete(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        expected_version: int,
        outcome: Mapping[str, Any],
        policy_ref: Mapping[str, str],
        outcome_payload: Mapping[str, Any],
        state: str,
        execution_attempt_id: str,
        owner_generation: int,
    ) -> StoredEffectExecution:
        actor = ActorContext(actor_context).to_dict()
        if state not in {"completed", "indeterminate"}:
            raise DurableStoreError("durable terminal state is unsupported")
        parsed_outcome = ActionOutcome(outcome, expected_tenant=actor["tenant_id"]).to_dict()
        expected_status = "succeeded" if state == "completed" else "indeterminate"
        if parsed_outcome["status"] != expected_status:
            raise DurableStoreError("outcome status does not match the durable terminal state")

        with self._connect() as connection, connection.cursor() as cursor:
            row = _runtime_read(cursor, actor, "effect_by_request", {"request_id": request_id})
            if row is None:
                raise DurableStoreError("durable execution was not found")
            stored = self._row(_effect_row(row))
            if (
                stored.state not in {"prepared", "executing"}
                or stored.version != expected_version
                or stored.execution_attempt_id != execution_attempt_id
                or stored.owner_generation != owner_generation
            ):
                if (
                    stored.state == state
                    and stored.version == expected_version + 1
                    and stored.outcome == parsed_outcome
                    and stored.outcome_evidence is not None
                ):
                    return stored.snapshot()
                raise OptimisticConcurrencyError("durable execution version or state changed")
            expected_policy_ref = {
                "record_type": "policy_decision",
                "record_id": stored.policy["decision_id"],
                "record_digest": stored.policy["decision_digest"],
            }
            if dict(policy_ref) != expected_policy_ref:
                raise DurableStoreError("outcome evidence policy reference is invalid")
            if (
                outcome_payload.get("request_digest") != stored.request["request_digest"]
                or outcome_payload.get("authorization_grant_digest") != sha256_digest(stored.grant)
                or outcome_payload.get("outcome_digest") != parsed_outcome["outcome_digest"]
                or outcome_payload.get("status") != parsed_outcome["status"]
            ):
                raise DurableStoreError("outcome evidence payload is not bound to the outcome")
            _validate_outcome_binding(stored, parsed_outcome)
            evidence = self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=stored.request["run_id"],
                event_kind="kernel.effect_execution_outcome",
                policy_ref=policy_ref,
                payload=outcome_payload,
            )
            now = _aware_utc(self._clock())
            changed = _runtime_write(
                cursor,
                actor,
                "complete_effect",
                {
                    "request_id": request_id,
                    "state": state,
                    "expected_version": expected_version,
                    "attempt_id": execution_attempt_id,
                    "owner_generation": owner_generation,
                    "outcome": parsed_outcome,
                    "evidence": evidence,
                    "completed_at": _utc_millis(now),
                },
            )
            if changed["changed"] != 1:
                raise OptimisticConcurrencyError("durable execution transition lost its race")
        return StoredEffectExecution(
            actor_context=stored.actor_context,
            request=stored.request,
            policy=stored.policy,
            approvals=stored.approvals,
            grant=stored.grant,
            binding_digest=stored.binding_digest,
            state=state,
            version=expected_version + 1,
            intent_evidence=stored.intent_evidence,
            outcome=parsed_outcome,
            outcome_evidence=evidence,
            execution_attempt_id=stored.execution_attempt_id,
            owner_generation=stored.owner_generation,
            lease_expires_at=stored.lease_expires_at,
            last_renewed_at=stored.last_renewed_at,
        ).snapshot()

    def renew_lease(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        execution_attempt_id: str,
        owner_generation: int,
    ) -> StoredEffectExecution:
        """Renew only the live fenced owner using the database clock."""

        actor = ActorContext(actor_context).to_dict()
        with self._connect() as connection, connection.cursor() as cursor:
            row = _runtime_write(
                cursor,
                actor,
                "renew_effect",
                {
                    "request_id": request_id,
                    "attempt_id": execution_attempt_id,
                    "owner_generation": owner_generation,
                    "lease_seconds": self._lease_duration.total_seconds(),
                },
            )
            if row is None:
                raise OptimisticConcurrencyError("execution lease is expired or fenced")
        return self._row(_effect_row(row))

    def recover_expired(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        outcome: Mapping[str, Any],
        policy_ref: Mapping[str, str],
        outcome_payload: Mapping[str, Any],
    ) -> StoredEffectExecution:
        """Atomically fence an expired owner and record an indeterminate outcome."""

        actor = ActorContext(actor_context).to_dict()
        parsed_outcome = ActionOutcome(outcome, expected_tenant=actor["tenant_id"]).to_dict()
        if parsed_outcome["status"] != "indeterminate":
            raise DurableStoreError("expired recovery requires an indeterminate outcome")
        with self._connect() as connection, connection.cursor() as cursor:
            row = _runtime_read(cursor, actor, "effect_by_request", {"request_id": request_id})
            if row is None:
                raise DurableStoreError("durable execution was not found")
            stored = self._row(_effect_row(row))
            if stored.state in {"completed", "failed", "indeterminate"}:
                return stored.snapshot()
            if not row["_lease_expired"]:
                raise PreparedExecutionError("execution lease has not expired")
            expected_policy_ref = {
                "record_type": "policy_decision",
                "record_id": stored.policy["decision_id"],
                "record_digest": stored.policy["decision_digest"],
            }
            if dict(policy_ref) != expected_policy_ref:
                raise DurableStoreError("recovery policy reference is invalid")
            if (
                outcome_payload.get("request_digest") != stored.request["request_digest"]
                or outcome_payload.get("authorization_grant_digest") != sha256_digest(stored.grant)
                or outcome_payload.get("outcome_digest") != parsed_outcome["outcome_digest"]
                or outcome_payload.get("status") != "indeterminate"
            ):
                raise DurableStoreError("recovery evidence payload is not bound to authority")
            _validate_outcome_binding(stored, parsed_outcome)
            evidence = self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=stored.request["run_id"],
                event_kind="kernel.effect_execution_outcome",
                policy_ref=policy_ref,
                payload=outcome_payload,
            )
            changed = _runtime_write(
                cursor,
                actor,
                "recover_effect",
                {
                    "request_id": request_id,
                    "attempt_id": stored.execution_attempt_id,
                    "owner_generation": stored.owner_generation,
                    "outcome": parsed_outcome,
                    "evidence": evidence,
                },
            )
            if changed["changed"] != 1:
                raise OptimisticConcurrencyError("expired recovery lost its fence race")
        return StoredEffectExecution(
            actor_context=stored.actor_context,
            request=stored.request,
            policy=stored.policy,
            approvals=stored.approvals,
            grant=stored.grant,
            binding_digest=stored.binding_digest,
            state="indeterminate",
            version=stored.version + 1,
            intent_evidence=stored.intent_evidence,
            outcome=parsed_outcome,
            outcome_evidence=evidence,
            execution_attempt_id=stored.execution_attempt_id,
            owner_generation=(stored.owner_generation or 0) + 1,
            lease_expires_at=stored.lease_expires_at,
            last_renewed_at=stored.last_renewed_at,
        ).snapshot()

    def events(
        self, *, actor_context: Mapping[str, Any], run_id: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        actor = ActorContext(actor_context).to_dict()
        with self._runtime_connect() as connection, connection.cursor() as cursor:
            rows = _runtime_read(cursor, actor, "events", {"run_id": run_id})
            return tuple(copy.deepcopy(row) for row in rows)

    def _load_lifecycle_with_cursor(
        self,
        cursor: Any,
        actor: Mapping[str, Any],
        request_id: str,
        *,
        for_update: bool = False,
        missing_ok: bool = False,
    ) -> StoredLifecycle | None:
        value = _runtime_read(cursor, actor, "lifecycle_by_id", {"request_id": request_id})
        if value is None:
            if missing_ok:
                return None
            raise DurableStoreError("durable lifecycle was not found")
        approvals = value["approvals_json"]
        row = (
            value["actor_context_json"],
            value["request_json"],
            value["policy_json"],
            approvals[0] if approvals else None,
            value.get("grant_json"),
            value["state"],
            value["version"],
            value["last_evidence_sequence"],
            value["last_evidence_digest"],
        )
        rebuilt = self._replay_lifecycle(cursor, actor, request_id)
        expected = (
            rebuilt.actor_context,
            rebuilt.request,
            rebuilt.policy,
            rebuilt.approval,
            rebuilt.grant,
            rebuilt.state,
            rebuilt.version,
            rebuilt.evidence[-1]["sequence_number"],
            rebuilt.evidence[-1]["event_digest"],
        )
        if tuple(row) != expected:
            raise DurableStoreError(
                "lifecycle projection diverged from authoritative evidence; rebuild required"
            )
        return rebuilt.snapshot()

    def _replay_lifecycle(
        self, cursor: Any, actor: Mapping[str, Any], request_id: str
    ) -> StoredLifecycle:
        candidate_rows = _runtime_read(
            cursor, actor, "lifecycle_events", {"request_id": request_id}
        )
        candidates = tuple(
            EvidenceEnvelope(row, expected_tenant=actor["tenant_id"]).to_dict()
            for row in candidate_rows
        )
        if not candidates:
            raise DurableStoreError("canonical lifecycle authority evidence is missing")
        run_ids = {event["draft"]["run_id"] for event in candidates}
        if len(run_ids) != 1:
            raise DurableStoreError("lifecycle evidence spans multiple runs")
        run_id = next(iter(run_ids))
        all_rows = _runtime_read(cursor, actor, "events", {"run_id": run_id})
        events = tuple(
            EvidenceEnvelope(row, expected_tenant=actor["tenant_id"]).to_dict() for row in all_rows
        )
        prior_digest = None
        prior_time = None
        for sequence, event in enumerate(events):
            recorded_at = _parse_time(event["recorded_at"])
            if (
                event["sequence_number"] != sequence
                or event["prior_event_digest"] != prior_digest
                or (prior_time is not None and recorded_at < prior_time)
            ):
                raise DurableStoreError("authoritative evidence run chain is invalid")
            prior_digest = event["event_digest"]
            prior_time = recorded_at
        lifecycle_events = tuple(
            event
            for event in events
            if (
                event["draft"]["inline_payload"].get("request_id") == request_id
                or event["draft"]["inline_payload"].get("request", {}).get("request_id")
                == request_id
            )
            and event["draft"]["event_kind"]
            in {
                "kernel.policy_decided",
                "kernel.approval_accepted",
                "kernel.authorization_grant_issued",
            }
        )
        if (
            not lifecycle_events
            or lifecycle_events[0]["draft"]["event_kind"] != "kernel.policy_decided"
        ):
            raise DurableStoreError("canonical lifecycle authority evidence is missing")
        first_payload = lifecycle_events[0]["draft"]["inline_payload"]
        stored_actor = ActorContext(first_payload["actor_context"]).to_dict()
        if stored_actor != actor:
            raise DurableStoreError("lifecycle evidence actor context does not exactly match")
        request = ToolRequest(
            first_payload["request"], expected_tenant=actor["tenant_id"]
        ).to_dict()
        policy = PolicyDecision(
            first_payload["policy"], expected_tenant=actor["tenant_id"]
        ).to_dict()
        if request["request_id"] != request_id:
            raise DurableStoreError("lifecycle evidence request binding is invalid")
        expected_policy_ref = {
            "record_type": "policy_decision",
            "record_id": policy["decision_id"],
            "record_digest": policy["decision_digest"],
        }
        expected_initial_state = {
            "deny": "denied",
            "require_approval": "approval_required",
            "allow": "policy_authorized",
        }.get(policy["decision"])
        if (
            first_payload.get("actor_id") != actor["actor_id"]
            or first_payload.get("request_digest") != request["request_digest"]
            or first_payload.get("policy_decision_digest") != policy["decision_digest"]
            or first_payload.get("next_state") != expected_initial_state
            or lifecycle_events[0]["policy_refs"] != [expected_policy_ref]
        ):
            raise DurableStoreError("policy evidence bindings or state are invalid")
        approval = None
        grant = None
        state = first_payload["next_state"]
        for event in lifecycle_events[1:]:
            payload = event["draft"]["inline_payload"]
            kind = event["draft"]["event_kind"]
            if kind == "kernel.approval_accepted":
                if approval is not None or grant is not None:
                    raise DurableStoreError("lifecycle approval chronology is invalid")
                approval = ApprovalRecord(
                    payload["approval"], expected_tenant=actor["tenant_id"]
                ).to_dict()
                if (
                    payload.get("actor_id") != actor["actor_id"]
                    or payload.get("request_id") != request_id
                    or payload.get("request_digest") != request["request_digest"]
                    or payload.get("policy_decision_digest") != policy["decision_digest"]
                    or payload.get("approval_digest") != approval["approval_digest"]
                    or payload.get("next_state") != "approved"
                ):
                    raise DurableStoreError("approval evidence binding is invalid")
            elif kind == "kernel.authorization_grant_issued":
                if grant is not None:
                    raise DurableStoreError("lifecycle grant evidence is duplicated")
                grant = AuthorizationGrant(
                    payload["grant"], expected_tenant=actor["tenant_id"]
                ).to_dict()
                if (
                    payload.get("actor_id") != actor["actor_id"]
                    or payload.get("request_id") != request_id
                    or payload.get("request_digest") != request["request_digest"]
                    or payload.get("policy_decision_digest") != policy["decision_digest"]
                    or payload.get("authorization_grant_digest") != sha256_digest(grant)
                    or payload.get("next_state") != "grant_issued"
                ):
                    raise DurableStoreError("grant evidence binding is invalid")
            if event["policy_refs"] != [expected_policy_ref]:
                raise DurableStoreError("lifecycle evidence policy reference is invalid")
            state = payload["next_state"]
        _validate_lifecycle_authority(actor, request, policy, approval=approval, grant=grant)
        return StoredLifecycle(
            actor_context=actor,
            request=request,
            policy=policy,
            state=state,
            version=len(lifecycle_events),
            evidence=lifecycle_events,
            approval=approval,
            grant=grant,
        ).snapshot()

    def _select_for_binding(
        self,
        cursor: Any,
        actor: Mapping[str, Any],
        request: Mapping[str, Any],
        grant: Mapping[str, Any],
    ) -> StoredEffectExecution | None:
        rows = _runtime_read(
            cursor,
            actor,
            "effect_by_binding",
            {
                "idempotency_key": request["idempotency"]["idempotency_key"],
                "grant_id": grant["grant_id"],
                "request_id": request["request_id"],
            },
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise IdempotencyConflictError("durable authority bindings reference different rows")
        return self._row(_effect_row(rows[0]))

    def _append_evidence(
        self,
        *,
        cursor: Any,
        actor: Mapping[str, Any],
        run_id: str,
        event_kind: str,
        policy_ref: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        parsed, version = self._build_evidence(
            cursor=cursor,
            actor=actor,
            run_id=run_id,
            event_kind=event_kind,
            policy_ref=policy_ref,
            payload=payload,
        )
        changed = _runtime_write(
            cursor,
            actor,
            "commit_evidence",
            {"run_id": run_id, "expected_version": version, "envelope": parsed},
        )
        if changed["changed"] != 1:
            raise OptimisticConcurrencyError("run evidence sequence lost its race")
        return parsed

    def _prepare_evidence(
        self,
        *,
        cursor: Any,
        actor: Mapping[str, Any],
        run_id: str,
        event_kind: str,
        policy_ref: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        parsed, _version = self._build_evidence(
            cursor=cursor,
            actor=actor,
            run_id=run_id,
            event_kind=event_kind,
            policy_ref=policy_ref,
            payload=payload,
        )
        return parsed

    def _build_evidence(
        self,
        *,
        cursor: Any,
        actor: Mapping[str, Any],
        run_id: str,
        event_kind: str,
        policy_ref: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> tuple[dict[str, Any], int]:
        head = _runtime_write(cursor, actor, "lock_run", {"run_id": run_id})
        if head is None:
            raise DurableStoreError("run scope conflicts with an existing actor")
        sequence = head["next_sequence"]
        prior_digest = head["last_event_digest"]
        prior_recorded_at = (
            _parse_time(head["last_recorded_at"]) if head["last_recorded_at"] is not None else None
        )
        version = head["version"]
        now_dt = _aware_utc(self._clock())
        if prior_recorded_at is not None and now_dt < prior_recorded_at:
            raise DurableStoreError("evidence chronology regressed within a run")
        now = _utc_millis(now_dt)
        draft = {
            "schema_version": "1.0",
            "record_type": "evidence_draft",
            "tenant_id": actor["tenant_id"],
            "event_id": self._ids(),
            "run_id": run_id,
            "event_kind": event_kind,
            "occurred_at": now,
            "idempotency": {
                "tenant_id": actor["tenant_id"],
                "idempotency_key": f"kernel.{event_kind}.{run_id}.{sequence}",
                "operation_digest": sha256_digest(payload),
            },
            "classification": "internal",
            "redaction_status": "redacted",
            "inline_payload": copy.deepcopy(dict(payload)),
        }
        envelope = {
            "schema_version": "1.0",
            "record_type": "evidence_envelope",
            "tenant_id": actor["tenant_id"],
            "envelope_id": self._ids(),
            "draft": draft,
            "draft_digest": sha256_digest(draft),
            "recorded_at": now,
            "sequence_number": sequence,
            "payload_digest": sha256_digest(draft["inline_payload"]),
            "prior_event_digest": prior_digest,
            "policy_refs": [copy.deepcopy(dict(policy_ref))],
            "storage_writer_id": "kernel.postgresql.v1",
        }
        apply_object_digest(envelope)
        parsed = EvidenceEnvelope(envelope, expected_tenant=actor["tenant_id"]).to_dict()
        return parsed, version

    @staticmethod
    def _row(row: Any) -> StoredEffectExecution:
        actor, request, policy, approvals, grant = _parse_inputs(
            row[0], row[1], row[2], tuple(row[3]), row[4]
        )
        _validate_stored_inputs(actor, request, policy, approvals, grant)
        intent = EvidenceEnvelope(row[8], expected_tenant=actor["tenant_id"]).to_dict()
        stored = StoredEffectExecution(
            actor_context=actor,
            request=request,
            policy=policy,
            approvals=approvals,
            grant=grant,
            binding_digest=row[5],
            state=row[6],
            version=row[7],
            intent_evidence=intent,
            outcome=row[9],
            outcome_evidence=row[10],
            execution_attempt_id=row[11],
            owner_generation=row[12],
            lease_expires_at=row[13],
            last_renewed_at=row[14],
        ).snapshot()
        _validate_intent_evidence(stored)
        if stored.version < 1 or stored.binding_digest != execution_binding_digest(
            actor_context=actor,
            request=request,
            policy=policy,
            approvals=approvals,
            grant=grant,
        ):
            raise DurableStoreError("durable execution binding digest is invalid")
        if (
            not stored.execution_attempt_id
            or not stored.owner_generation
            or stored.owner_generation < 1
            or stored.lease_expires_at is None
            or stored.last_renewed_at is None
        ):
            raise DurableStoreError("durable execution fence metadata is invalid")
        if stored.state in {"prepared", "executing"} and (
            stored.outcome is not None or stored.outcome_evidence is not None
        ):
            raise DurableStoreError("live execution contains terminal evidence")
        if stored.state in {"completed", "failed", "indeterminate"}:
            if stored.outcome is None or stored.outcome_evidence is None:
                raise DurableStoreError("terminal execution is missing outcome evidence")
            parsed_outcome = ActionOutcome(
                stored.outcome, expected_tenant=actor["tenant_id"]
            ).to_dict()
            parsed_evidence = EvidenceEnvelope(
                stored.outcome_evidence, expected_tenant=actor["tenant_id"]
            ).to_dict()
            _validate_outcome_binding(stored, parsed_outcome)
            _validate_outcome_evidence(stored, parsed_outcome, parsed_evidence)
            stored = StoredEffectExecution(
                actor_context=actor,
                request=request,
                policy=policy,
                approvals=approvals,
                grant=grant,
                binding_digest=stored.binding_digest,
                state=stored.state,
                version=stored.version,
                intent_evidence=intent,
                outcome=parsed_outcome,
                outcome_evidence=parsed_evidence,
                execution_attempt_id=stored.execution_attempt_id,
                owner_generation=stored.owner_generation,
                lease_expires_at=stored.lease_expires_at,
                last_renewed_at=stored.last_renewed_at,
            ).snapshot()
        return stored


def _parse_inputs(
    actor_context: Mapping[str, Any],
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    approvals: tuple[Mapping[str, Any], ...],
    grant: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    tuple[dict[str, Any], ...],
    dict[str, Any],
]:
    actor = ActorContext(actor_context).to_dict()
    parsed_request = ToolRequest(request, expected_tenant=actor["tenant_id"]).to_dict()
    parsed_policy = PolicyDecision(policy, expected_tenant=actor["tenant_id"]).to_dict()
    parsed_approvals = tuple(
        ApprovalRecord(value, expected_tenant=actor["tenant_id"]).to_dict() for value in approvals
    )
    parsed_grant = AuthorizationGrant(grant, expected_tenant=actor["tenant_id"]).to_dict()
    return actor, parsed_request, parsed_policy, parsed_approvals, parsed_grant


def _validate_lifecycle_authority(
    actor: Mapping[str, Any],
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    approval: Mapping[str, Any] | None = None,
    grant: Mapping[str, Any] | None = None,
) -> None:
    if (
        request["actor_context_digest"] != sha256_digest(actor)
        or request["tenant_id"] != actor["tenant_id"]
        or request["actor_id"] != actor["actor_id"]
        or policy["tenant_id"] != actor["tenant_id"]
        or policy["request_id"] != request["request_id"]
        or policy["request_digest"] != request["request_digest"]
    ):
        raise DurableStoreError("lifecycle identity, request, or policy binding is invalid")
    if approval is not None:
        if (
            policy["decision"] != "require_approval"
            or approval["request_id"] != request["request_id"]
            or approval["request_digest"] != request["request_digest"]
            or approval["policy_decision_id"] != policy["decision_id"]
            or approval["policy_decision_digest"] != policy["decision_digest"]
            or approval["disposition"] != "approved"
            or not approval["separation_of_duties"]["satisfied"]
            or approval["constraints"] != policy["constraints"]
            or _parse_time(approval["issued_at"]) < _parse_time(policy["decided_at"])
            or _parse_time(approval["expires_at"]) <= _parse_time(approval["issued_at"])
        ):
            raise DurableStoreError("lifecycle approval binding or chronology is invalid")
    if grant is not None:
        expected_refs = (
            [
                {
                    "record_type": "approval_record",
                    "record_id": approval["approval_id"],
                    "record_digest": approval["approval_digest"],
                }
            ]
            if approval is not None
            else []
        )
        authority_time = (
            _parse_time(approval["issued_at"])
            if approval is not None
            else _parse_time(policy["decided_at"])
        )
        if (
            grant["tenant_id"] != actor["tenant_id"]
            or grant["actor_id"] != actor["actor_id"]
            or grant["run_id"] != request["run_id"]
            or grant["request_id"] != request["request_id"]
            or grant["request_digest"] != request["request_digest"]
            or grant["policy_decision_id"] != policy["decision_id"]
            or grant["policy_decision_digest"] != policy["decision_digest"]
            or grant["approval_refs"] != expected_refs
            or grant["constraints"] != policy["constraints"]
            or grant["isolation_profile"] != policy["isolation_profile"]
            or grant["idempotency"] != request["idempotency"]
            or grant["tool_id"] != request["tool_id"]
            or grant["tool_version"] != request["tool_version"]
            or _parse_time(grant["issued_at"]) < authority_time
            or _parse_time(grant["expires_at"]) <= _parse_time(grant["issued_at"])
        ):
            raise DurableStoreError("lifecycle grant binding or chronology is invalid")


def _require_policy_ref(policy_ref: Mapping[str, str], policy: Mapping[str, Any]) -> None:
    expected = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }
    if dict(policy_ref) != expected:
        raise DurableStoreError("evidence policy reference is not exactly bound")


def _require_exact(
    stored: StoredEffectExecution,
    binding_digest: str,
    request: Mapping[str, Any],
    grant: Mapping[str, Any],
) -> None:
    if stored.binding_digest != binding_digest:
        raise IdempotencyConflictError("durable execution binding conflicts with stored authority")
    if stored.request["idempotency"] != request["idempotency"]:
        raise IdempotencyConflictError("durable idempotency binding conflicts with stored request")
    if stored.request["request_digest"] != request["request_digest"]:
        raise IdempotencyConflictError("durable replay request digest conflicts")
    if stored.grant["grant_id"] != grant["grant_id"] or sha256_digest(
        stored.grant
    ) != sha256_digest(grant):
        raise IdempotencyConflictError("durable replay grant authority conflicts")


def _validate_stored_inputs(
    actor: Mapping[str, Any],
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    approvals: tuple[Mapping[str, Any], ...],
    grant: Mapping[str, Any],
) -> None:
    if request["actor_context_digest"] != sha256_digest(actor):
        raise DurableStoreError("stored request does not bind actor context")
    if (
        request["actor_id"] != actor["actor_id"]
        or request["tenant_id"] != actor["tenant_id"]
        or policy["request_id"] != request["request_id"]
        or policy["request_digest"] != request["request_digest"]
    ):
        raise DurableStoreError("stored request and policy bindings are invalid")
    if (
        policy["decision"] != "require_approval"
        or policy["constraints"] != grant["constraints"]
        or policy["isolation_profile"] != grant["isolation_profile"]
        or grant["tool_id"] != request["tool_id"]
        or grant["tool_version"] != request["tool_version"]
        or grant["tenant_id"] != actor["tenant_id"]
    ):
        raise DurableStoreError("stored policy, grant, and request constraints are invalid")
    expected_approval_refs = []
    for approval in approvals:
        if (
            approval["request_id"] != request["request_id"]
            or approval["request_digest"] != request["request_digest"]
            or approval["policy_decision_id"] != policy["decision_id"]
            or approval["policy_decision_digest"] != policy["decision_digest"]
            or approval["disposition"] != "approved"
            or not approval["separation_of_duties"]["satisfied"]
            or approval["constraints"] != policy["constraints"]
        ):
            raise DurableStoreError("stored approval binding is invalid")
        expected_approval_refs.append(
            {
                "record_type": "approval_record",
                "record_id": approval["approval_id"],
                "record_digest": approval["approval_digest"],
            }
        )
    if (
        grant["request_id"] != request["request_id"]
        or grant["request_digest"] != request["request_digest"]
        or grant["policy_decision_id"] != policy["decision_id"]
        or grant["policy_decision_digest"] != policy["decision_digest"]
        or grant["approval_refs"] != expected_approval_refs
        or grant["idempotency"] != request["idempotency"]
        or grant["actor_id"] != actor["actor_id"]
        or grant["run_id"] != request["run_id"]
    ):
        raise DurableStoreError("stored authorization grant binding is invalid")
    chronology = [
        _parse_time(policy["decided_at"]),
        *(_parse_time(approval["issued_at"]) for approval in approvals),
        _parse_time(grant["issued_at"]),
    ]
    if chronology != sorted(chronology) or any(
        _parse_time(value["expires_at"]) < chronology[-1] for value in (grant, *approvals)
    ):
        raise DurableStoreError("stored authority chronology or expiry is invalid")


def _validate_intent_evidence(
    stored: StoredEffectExecution,
) -> None:
    envelope = stored.intent_evidence
    draft = envelope.get("draft", {})
    payload = draft.get("inline_payload", {})
    expected_payload = {
        "actor_id": stored.actor_context["actor_id"],
        "request_digest": stored.request["request_digest"],
        "policy_decision_digest": stored.policy["decision_digest"],
        "authorization_grant_digest": sha256_digest(stored.grant),
        "effect_classes": stored.request["effect_classes"],
        "isolation_profile": stored.grant["isolation_profile"],
    }
    if (
        draft.get("event_kind") != "kernel.effect_execution_intent"
        or draft.get("run_id") != stored.request["run_id"]
        or payload != expected_payload
    ):
        raise DurableStoreError("durable intent evidence binding is invalid")


def _validate_outcome_binding(stored: StoredEffectExecution, outcome: Mapping[str, Any]) -> None:
    expected_request_ref = {
        "record_type": "tool_request",
        "record_id": stored.request["request_id"],
        "record_digest": stored.request["request_digest"],
    }
    expected_policy_ref = {
        "record_type": "policy_decision",
        "record_id": stored.policy["decision_id"],
        "record_digest": stored.policy["decision_digest"],
    }
    if outcome["request_ref"] != expected_request_ref:
        raise DurableStoreError("outcome request authority binding is invalid")
    if outcome["policy_refs"] != [expected_policy_ref]:
        raise DurableStoreError("outcome policy authority binding is invalid")
    expected_intent_ref = {
        "record_type": "evidence_envelope",
        "record_id": stored.intent_evidence["envelope_id"],
        "record_digest": stored.intent_evidence["event_digest"],
    }
    if outcome["evidence_refs"] != [expected_intent_ref]:
        raise DurableStoreError("outcome intent evidence binding is invalid")
    expected_reviewers = [
        {
            "record_type": "approval_record",
            "record_id": approval["approval_id"],
            "record_digest": approval["approval_digest"],
        }
        for approval in stored.approvals
    ]
    if outcome["reviewer_refs"] != expected_reviewers:
        raise DurableStoreError("outcome approval binding is invalid")
    scope = outcome["target_scope"]
    if (
        scope["tenant_id"] != stored.actor_context["tenant_id"]
        or scope["actor_id"] != stored.actor_context["actor_id"]
        or scope["parent_digest"] != sha256_digest(stored.actor_context)
    ):
        raise DurableStoreError("outcome isolation scope binding is invalid")
    expected_provenance = sha256_digest(
        {
            "authorization_grant_digest": sha256_digest(stored.grant),
            "intent_evidence_digest": stored.intent_evidence["event_digest"],
            "result_payload": outcome["result_payload"],
        }
    )
    if outcome["provenance_digest"] != expected_provenance:
        raise DurableStoreError("outcome provenance binding is invalid")
    if outcome["idempotency"] != stored.request["idempotency"]:
        raise IdempotencyConflictError("outcome idempotency binding is invalid")
    if outcome["run_id"] != stored.request["run_id"]:
        raise DurableStoreError("outcome run binding is invalid")


def _validate_outcome_evidence(
    stored: StoredEffectExecution,
    outcome: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> None:
    draft = evidence.get("draft", {})
    expected_payload = {
        "actor_id": stored.actor_context["actor_id"],
        "request_digest": stored.request["request_digest"],
        "authorization_grant_digest": sha256_digest(stored.grant),
        "outcome_digest": outcome["outcome_digest"],
        "status": outcome["status"],
    }
    actual_payload = draft.get("inline_payload")
    if isinstance(actual_payload, Mapping) and "recovery" in actual_payload:
        expected_payload["recovery"] = "lease_expired"
    if (
        draft.get("event_kind") != "kernel.effect_execution_outcome"
        or draft.get("run_id") != stored.request["run_id"]
        or draft.get("inline_payload") != expected_payload
        or outcome["status"] != ("succeeded" if stored.state == "completed" else "indeterminate")
    ):
        raise DurableStoreError("durable outcome evidence binding is invalid")


def _validate_memory_transition_authority(
    *,
    actor: Mapping[str, Any],
    proposal: Mapping[str, Any],
    memory_decision: Mapping[str, Any],
    policy: Mapping[str, Any],
    approvals: tuple[Mapping[str, Any], ...],
    expected_revision: int | None,
    now: datetime,
    constraint_registry: ConstraintRegistry,
    approval_verifier: DetachedProofVerifier | None,
    approval_trust: Callable[[datetime], TrustContext] | None,
) -> dict[str, Any]:
    """Validate exact proposal authority and produce the committed record revision."""

    validate_memory_promotion_bindings(actor, proposal, memory_decision, policy, approvals)
    if not _parse_time(actor["issued_at"]) <= now < _parse_time(actor["expires_at"]):
        raise DurableStoreError("actor authority is not currently valid")
    try:
        validate_scope_narrowing(proposal["target_scope"], actor)
    except SemanticError as error:
        raise DurableStoreError("proposal scope is not derived from actor authority") from error
    scope = proposal["target_scope"]
    if scope["selection"] != {"level": "actor"}:
        raise DurableStoreError("memory promotion currently requires actor scope")
    if not _parse_time(scope["derived_at"]) <= now < _parse_time(scope["valid_until"]):
        raise DurableStoreError("proposal scope is not currently valid")
    if proposal["lifecycle_state"] != "pending":
        raise DurableStoreError("memory proposal is not pending")
    if now >= _parse_time(proposal["expires_at"]):
        raise DurableStoreError("memory proposal is expired")
    if proposal["change_kind"] == "dispute":
        raise DurableStoreError("memory dispute transitions are outside Phase 4.3")
    if any("json_pointer" in span or "span_digest" in span for span in proposal["evidence_spans"]):
        raise DurableStoreError("partial evidence spans are not implemented for promotion")

    candidate = proposal["proposed_record"]
    if candidate["provenance"] != proposal["evidence_spans"]:
        raise DurableStoreError("proposed record provenance must exactly match proposal evidence")
    if candidate["truth_confidence"] != proposal["truth_confidence"]:
        raise DurableStoreError("proposed record confidence must exactly match proposal confidence")
    if proposal["truth_confidence"]["evidence_ids"] != [
        span["evidence_id"] for span in proposal["evidence_spans"]
    ]:
        raise DurableStoreError("truth confidence must bind every exact proposal evidence span")
    if candidate["retention"]["deletion_mode"] != "retain_non_sensitive_tombstone":
        raise DurableStoreError("physical and cryptographic memory erasure are not implemented")
    if now >= _parse_time(candidate["retention"]["expires_at"]):
        raise DurableStoreError("memory retention authority is expired")
    if candidate.get("expires_at") is not None and now >= _parse_time(candidate["expires_at"]):
        raise DurableStoreError("proposed memory is already expired")
    if candidate.get("effective_until") is not None and now >= _parse_time(
        candidate["effective_until"]
    ):
        raise DurableStoreError("proposed memory validity is already expired")

    if _parse_time(policy["decided_at"]) > now:
        raise DurableStoreError("policy decision is from the future")
    if not _parse_time(policy["decided_at"]) <= _parse_time(memory_decision["decided_at"]) <= now:
        raise DurableStoreError("memory decision chronology is invalid")
    validate_constraint_support(policy, constraint_registry)
    validate_constraint_support(memory_decision, constraint_registry)
    if approvals and (approval_verifier is None or approval_trust is None):
        raise DurableStoreError("approval verification is not configured")
    seen_approvals: set[str] = set()
    for approval in approvals:
        if approval["approval_id"] in seen_approvals:
            raise DurableStoreError("duplicate memory approval")
        seen_approvals.add(approval["approval_id"])
        if not _parse_time(approval["issued_at"]) <= now < _parse_time(approval["expires_at"]):
            raise DurableStoreError("memory approval is not currently valid")
        if _parse_time(approval["issued_at"]) < _parse_time(policy["decided_at"]):
            raise DurableStoreError("memory approval predates its policy decision")
        validate_constraint_support(approval, constraint_registry)
        assert approval_verifier is not None and approval_trust is not None
        verify_signed_record(
            approval,
            verifier=approval_verifier,
            trust=approval_trust(now),
            expected_tenant=actor["tenant_id"],
        )

    operation = proposal["change_kind"]
    revision = candidate["revision"]
    if operation == "create":
        if expected_revision is not None or revision != 1 or "supersedes_revision" in candidate:
            raise DurableStoreError("create requires revision one and no predecessor")
    else:
        if expected_revision is None or expected_revision < 1:
            raise DurableStoreError("memory transition requires a positive expected revision")
        if revision != expected_revision + 1:
            raise DurableStoreError("proposed revision does not follow expected revision")
        if candidate.get("supersedes_revision") != expected_revision:
            raise DurableStoreError("memory transition does not bind its predecessor")

    committed = copy.deepcopy(candidate)
    committed["lifecycle_state"] = "deleted" if operation == "delete" else "active"
    apply_object_digest(committed)
    return MemoryRecord(committed, expected_tenant=actor["tenant_id"]).to_dict()


def _stored_memory_transition(
    value: Mapping[str, Any],
    *,
    expected_binding: str | None = None,
    replayed: bool = False,
) -> StoredMemoryTransition:
    transition = value["transition"]
    binding = transition["binding_digest"]
    if expected_binding is not None and binding != expected_binding:
        raise IdempotencyConflictError("memory proposal replay conflicts with original bindings")
    evidence = EvidenceEnvelope(value["evidence"]).to_dict()
    record = MemoryRecord(transition["committed_record"]).to_dict()
    return StoredMemoryTransition(
        proposal=transition["proposal"],
        memory_decision=transition["memory_decision"],
        policy_decision=transition["policy_decision"],
        approvals=tuple(transition["approvals"]),
        record=record,
        evidence=evidence,
        binding_digest=binding,
        operation=transition["operation"],
        expected_revision=transition.get("expected_revision"),
        replayed=replayed,
    ).snapshot()


def _commit_memory_transition(
    cursor: Any, actor: Mapping[str, Any], payload: Mapping[str, Any]
) -> Mapping[str, Any]:
    cursor.execute(
        "SELECT gah_commit_memory_transition(%s::jsonb, %s::jsonb)",
        (_json(actor), _json(payload)),
    )
    row = cursor.fetchone()
    if row is None or not isinstance(row[0], dict):
        raise DurableStoreError("memory transition returned a malformed result")
    return row[0]


def _rebuild_memory_projection(
    cursor: Any, actor: Mapping[str, Any], payload: Mapping[str, Any]
) -> Mapping[str, Any]:
    cursor.execute(
        "SELECT gah_rebuild_memory_projection(%s::jsonb, %s::jsonb)",
        (_json(actor), _json(payload)),
    )
    row = cursor.fetchone()
    if row is None or not isinstance(row[0], dict):
        raise DurableStoreError("memory projection rebuild returned a malformed result")
    return row[0]


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _runtime_read(
    cursor: Any, actor: Mapping[str, Any], operation: str, payload: Mapping[str, Any]
) -> Any:
    cursor.execute(
        "SELECT gah_runtime_read(%s, %s::jsonb, %s::jsonb)",
        (operation, _json(actor), _json(payload)),
    )
    row = cursor.fetchone()
    return row[0] if row is not None else None


def _retrieve_memory(
    cursor: Any, actor: Mapping[str, Any], query: Mapping[str, Any]
) -> list[dict[str, Any]]:
    cursor.execute(
        "SELECT gah_retrieve_memory(%s::jsonb, %s::jsonb)",
        (_json(actor), _json(query)),
    )
    row = cursor.fetchone()
    value = row[0] if row is not None else []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise DurableStoreError("memory retrieval returned malformed rows")
    return value


def _runtime_write(
    cursor: Any, actor: Mapping[str, Any], operation: str, payload: Mapping[str, Any]
) -> Any:
    functions = {
        "lock_run": "gah_lock_run",
        "commit_evidence": "gah_commit_evidence",
        "insert_lifecycle": "gah_submit_lifecycle",
        "approve_lifecycle": "gah_accept_approval",
        "grant_lifecycle": "gah_issue_grant",
        "rebuild_lifecycle": "gah_rebuild_lifecycle",
        "insert_effect": "gah_prepare_effect",
        "renew_effect": "gah_renew_effect",
        "complete_effect": "gah_complete_effect",
        "recover_effect": "gah_recover_effect",
    }
    function_name = functions.get(operation)
    if function_name is None:
        raise DurableStoreError("authority write operation is not supported")
    from psycopg import sql

    cursor.execute(
        sql.SQL("SELECT {}(%s::jsonb, %s::jsonb)").format(sql.Identifier(function_name)),
        (_json(actor), _json(payload)),
    )
    row = cursor.fetchone()
    return row[0] if row is not None else None


def _effect_row(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        value["actor_context_json"],
        value["request_json"],
        value["policy_json"],
        value["approvals_json"],
        value["grant_json"],
        value["binding_digest"],
        value["state"],
        value["version"],
        value["intent_envelope_json"],
        value.get("outcome_json"),
        value.get("outcome_envelope_json"),
        value["execution_attempt_id"],
        value["owner_generation"],
        _parse_time(value["lease_expires_at"]),
        _parse_time(value["last_renewed_at"]),
    )


def _lock_key(value: str) -> int:
    unsigned = int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big")
    return unsigned if unsigned < 2**63 else unsigned - 2**64


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DurableStoreError("durable store clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _utc_millis(value: datetime) -> str:
    return _aware_utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise DurableStoreError("authority timestamp is malformed") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DurableStoreError("authority timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)
