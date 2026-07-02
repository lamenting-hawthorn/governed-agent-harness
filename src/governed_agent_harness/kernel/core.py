"""Bounded Phase 2 orchestration for identity, policy, approval, and evidence.

This module deliberately has no executor, transport, provider, persistence, or
authorization-grant issuer. A successful approval is recorded as lifecycle
state only; it cannot cause an external effect.
"""

from __future__ import annotations

import copy
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from governed_agent_harness.contracts import (
    ActorContext,
    ApprovalRecord,
    ConstraintRegistry,
    DetachedProofVerifier,
    EvidenceEnvelope,
    IdempotencyConflictError,
    IdempotencyResult,
    PolicyDecision,
    SemanticError,
    ToolRequest,
    TrustContext,
    apply_object_digest,
    compare_idempotency_bindings,
    sha256_digest,
    validate_approval_binding,
    validate_constraint_support,
    verify_signed_record,
)


class IdentityError(SemanticError):
    """Raised when a request is not bound to currently valid identity."""


class LifecycleError(SemanticError):
    """Raised when a lifecycle or authority transition is invalid."""


class PolicyConfigurationError(SemanticError):
    """Raised when the local policy configuration cannot make a safe decision."""


class IdentityVerifier(Protocol):
    """Injected boundary that accepts only an authenticated ActorContext."""

    def verify(self, *, actor_context: Mapping[str, Any]) -> bool:
        """Return whether this exact, schema-validated context is trusted."""


class KernelLifecycle(str, Enum):
    """States reachable by the bounded kernel; none authorizes an effect."""

    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    POLICY_AUTHORIZED = "policy_authorized"
    APPROVED = "approved"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """Deterministic local rule for a complete set of requested effect classes."""

    rule_id: str
    decision: str
    effect_classes: frozenset[str]
    tool_ids: frozenset[str] = frozenset()
    isolation_profile: str = "no_effect"
    constraints: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{2,127}", self.rule_id) is None:
            raise PolicyConfigurationError("policy rule_id is malformed")
        if self.decision not in {"authorize", "deny", "require_approval"}:
            raise PolicyConfigurationError("policy rule decision is unsupported")
        if not self.effect_classes:
            raise PolicyConfigurationError("policy rule must cover at least one effect class")
        executable_profiles = {"process", "container", "microvm", "network_restricted"}
        if self.decision in {"authorize", "require_approval"} and (
            self.isolation_profile not in executable_profiles
        ):
            raise PolicyConfigurationError(
                "authorize and require_approval rules need a supported executable isolation profile"
            )
        if self.decision == "deny" and self.isolation_profile != "no_effect":
            raise PolicyConfigurationError("deny rules must use no_effect isolation")
        for constraint in self.constraints:
            if not isinstance(constraint, Mapping):
                raise PolicyConfigurationError("policy constraint must be a mapping")

    def matches(self, request: Mapping[str, Any]) -> bool:
        requested = frozenset(request["effect_classes"])
        return requested <= self.effect_classes and (
            not self.tool_ids or request["tool_id"] in self.tool_ids
        )


@dataclass(frozen=True, slots=True)
class PolicySet:
    """Ordered, deterministic policy rules with a mandatory deny fallback."""

    rules: tuple[PolicyRule, ...]
    version: str = "local.v1"

    def __post_init__(self) -> None:
        if not self.rules:
            raise PolicyConfigurationError("policy set requires at least one rule")
        if re.fullmatch(r"[a-z][a-z0-9_.-]{2,127}", self.version) is None:
            raise PolicyConfigurationError("policy version is malformed")
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise PolicyConfigurationError("policy rule IDs must be unique")

    def evaluate(self, request: Mapping[str, Any]) -> PolicyRule:
        for rule in self.rules:
            if rule.matches(request):
                return rule
        return PolicyRule(
            rule_id=f"{self.version}.default_deny",
            decision="deny",
            effect_classes=frozenset(request["effect_classes"]),
        )


class IdFactory(Protocol):
    def __call__(self) -> str:
        """Return one lowercase UUIDv7."""


def _utc_millis(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("kernel clock must return a timezone-aware timestamp")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class _Uuid7Factory:
    """Small monotonic UUIDv7 generator for local in-process records."""

    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_ms = -1
        self._sequence = 0

    def __call__(self) -> str:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("kernel clock must return a timezone-aware timestamp")
        timestamp_ms = int(now.timestamp() * 1000)
        with self._lock:
            if timestamp_ms == self._last_ms:
                self._sequence = (self._sequence + 1) & 0x0FFF
            else:
                self._last_ms, self._sequence = timestamp_ms, secrets.randbits(12)
            random_tail = secrets.randbits(62)
            value = (
                (timestamp_ms << 80)
                | (0x7 << 76)
                | (self._sequence << 64)
                | (0x2 << 62)
                | random_tail
            )
        hexadecimal = f"{value:032x}"
        return "-".join(
            (
                hexadecimal[:8],
                hexadecimal[8:12],
                hexadecimal[12:16],
                hexadecimal[16:20],
                hexadecimal[20:],
            )
        )


@dataclass(frozen=True, slots=True)
class LifecycleRecord:
    request: Mapping[str, Any]
    policy: Mapping[str, Any]
    state: KernelLifecycle
    evidence: tuple[Mapping[str, Any], ...]
    approval: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": copy.deepcopy(dict(self.request)),
            "policy": copy.deepcopy(dict(self.policy)),
            "state": self.state.value,
            "evidence": copy.deepcopy(list(self.evidence)),
            "approval": copy.deepcopy(dict(self.approval)) if self.approval else None,
        }


class InMemoryEvidenceLedger:
    """Validating append-only evidence chain for one process lifetime only."""

    def __init__(self, *, clock: Callable[[], datetime], ids: IdFactory) -> None:
        self._clock = clock
        self._ids = ids
        self._lock = threading.RLock()
        self._by_tenant: dict[str, list[dict[str, Any]]] = {}

    def append(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_kind: str,
        policy_ref: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Append and validate one redacted, policy-bound evidence envelope."""

        with self._lock:
            events = self._by_tenant.setdefault(tenant_id, [])
            now = _utc_millis(self._clock())
            draft = {
                "schema_version": "1.0",
                "record_type": "evidence_draft",
                "tenant_id": tenant_id,
                "event_id": self._ids(),
                "run_id": run_id,
                "event_kind": event_kind,
                "occurred_at": now,
                "idempotency": {
                    "tenant_id": tenant_id,
                    "idempotency_key": f"kernel.{event_kind}.{len(events) + 1}",
                    "operation_digest": sha256_digest(payload),
                },
                "classification": "internal",
                "redaction_status": "redacted",
                "inline_payload": copy.deepcopy(dict(payload)),
            }
            envelope = {
                "schema_version": "1.0",
                "record_type": "evidence_envelope",
                "tenant_id": tenant_id,
                "envelope_id": self._ids(),
                "draft": draft,
                "draft_digest": sha256_digest(draft),
                "recorded_at": now,
                "sequence_number": len(events),
                "payload_digest": sha256_digest(draft["inline_payload"]),
                "prior_event_digest": events[-1]["event_digest"] if events else None,
                "policy_refs": [copy.deepcopy(dict(policy_ref))],
                "storage_writer_id": "kernel.in_memory.v1",
            }
            apply_object_digest(envelope)
            parsed = EvidenceEnvelope(envelope, expected_tenant=tenant_id).to_dict()
            events.append(parsed)
            return copy.deepcopy(parsed)

    def _events_for_actor(self, tenant_id: str, actor_id: str) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(
                copy.deepcopy(event)
                for event in self._by_tenant.get(tenant_id, [])
                if event["draft"]["inline_payload"].get("actor_id") == actor_id
            )


class GovernanceKernel:
    """A synchronous, no-effect orchestration boundary for Phase 2."""

    def __init__(
        self,
        *,
        policy: PolicySet,
        identity_verifier: IdentityVerifier,
        approval_verifier: DetachedProofVerifier,
        approval_trust: Callable[[datetime], TrustContext],
        constraint_registry: ConstraintRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
        ids: IdFactory | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ids = ids or _Uuid7Factory(self._clock)
        self._policy = policy
        self._identity_verifier = identity_verifier
        self._approval_verifier = approval_verifier
        self._approval_trust_factory = approval_trust
        self._constraint_registry = constraint_registry or ConstraintRegistry({})
        self._ledger = InMemoryEvidenceLedger(clock=self._clock, ids=self._ids)
        self._lock = threading.RLock()
        self._idempotency: dict[tuple[str, str], tuple[dict[str, Any], str, str]] = {}
        self._records: dict[tuple[str, str], LifecycleRecord] = {}
        self._consumed_approvals: set[tuple[str, str, str]] = set()

    def submit(
        self, *, actor_context: Mapping[str, Any], tool_request: Mapping[str, Any]
    ) -> LifecycleRecord:
        """Validate identity, decide policy, append evidence, then set lifecycle state."""

        actor = ActorContext(actor_context).to_dict()
        request = ToolRequest(tool_request, expected_tenant=actor["tenant_id"]).to_dict()
        self._validate_identity(actor, request)
        key = (request["tenant_id"], request["request_id"])
        binding_key = (request["tenant_id"], request["idempotency"]["idempotency_key"])

        with self._lock:
            existing_binding = self._idempotency.get(binding_key)
            replay = compare_idempotency_bindings(
                existing_binding[0] if existing_binding is not None else None,
                request["idempotency"],
            )
            existing = self._records.get(key)
            if replay is IdempotencyResult.REPLAY:
                if existing_binding is None:
                    raise LifecycleError("idempotency replay has no stored binding")
                _, original_request_id, original_request_digest = existing_binding
                if original_request_digest != request["request_digest"]:
                    raise IdempotencyConflictError(
                        "idempotency replay request does not match the original request digest"
                    )
                original = self._records.get((request["tenant_id"], original_request_id))
                if original is None:
                    raise LifecycleError("idempotency replay has no lifecycle record")
                return _snapshot(original)
            if existing is not None:
                raise LifecycleError(
                    "request_id is already present with another idempotency binding"
                )

            rule = self._policy.evaluate(request)
            now = _utc_millis(self._clock())
            decision = {
                "schema_version": "1.0",
                "record_type": "policy_decision",
                "tenant_id": request["tenant_id"],
                "decision_id": self._ids(),
                "request_id": request["request_id"],
                "request_digest": request["request_digest"],
                "decision": rule.decision,
                "rule_refs": [rule.rule_id],
                "constraints": [copy.deepcopy(dict(value)) for value in rule.constraints],
                "isolation_profile": rule.isolation_profile,
                "decided_at": now,
            }
            apply_object_digest(decision)
            decision = PolicyDecision(decision, expected_tenant=request["tenant_id"]).to_dict()
            validate_constraint_support(decision, self._constraint_registry)
            policy_ref = {
                "record_type": "policy_decision",
                "record_id": decision["decision_id"],
                "record_digest": decision["decision_digest"],
            }
            next_state = {
                "authorize": KernelLifecycle.POLICY_AUTHORIZED,
                "deny": KernelLifecycle.DENIED,
                "require_approval": KernelLifecycle.APPROVAL_REQUIRED,
            }[rule.decision]
            evidence = self._ledger.append(
                tenant_id=request["tenant_id"],
                run_id=request["run_id"],
                event_kind="kernel.policy_decided",
                policy_ref=policy_ref,
                payload={
                    "actor_id": request["actor_id"],
                    "request_digest": request["request_digest"],
                    "policy_decision_digest": decision["decision_digest"],
                    "next_state": next_state.value,
                },
            )
            record = LifecycleRecord(request, decision, next_state, (evidence,))
            self._idempotency[binding_key] = (
                copy.deepcopy(request["idempotency"]),
                request["request_id"],
                request["request_digest"],
            )
            self._records[key] = record
            return _snapshot(record)

    def accept_approval(
        self, *, tenant_id: str, request_id: str, approval: Mapping[str, Any]
    ) -> LifecycleRecord:
        """Verify and consume one exact approval after policy requires it."""

        with self._lock:
            key = (tenant_id, request_id)
            current = self._records.get(key)
            if current is None:
                raise LifecycleError("approval references an unknown request")
            if current.state is not KernelLifecycle.APPROVAL_REQUIRED:
                raise LifecycleError("approval is not valid in the current lifecycle state")

            parsed = ApprovalRecord(approval, expected_tenant=tenant_id).to_dict()
            validate_approval_binding(parsed, current.policy, current.request)
            if parsed["disposition"] != "approved":
                raise LifecycleError("only an approved approval record may advance lifecycle")
            duties = parsed["separation_of_duties"]
            if duties["required"] and not duties["satisfied"]:
                raise LifecycleError("approval separation of duties is not satisfied")
            now = self._clock()
            if now.tzinfo is None or now.utcoffset() is None:
                raise LifecycleError("kernel clock must return a timezone-aware timestamp")
            issued = _parse_contract_time(parsed["issued_at"])
            expires = _parse_contract_time(parsed["expires_at"])
            normalized_now = now.astimezone(timezone.utc)
            if issued > normalized_now or expires <= normalized_now:
                raise LifecycleError("approval is not currently valid")
            trust = self._approval_trust_factory(normalized_now)
            if not isinstance(trust, TrustContext) or trust.now != normalized_now:
                raise LifecycleError("approval trust factory must return the current trust context")
            verify_signed_record(
                parsed,
                verifier=self._approval_verifier,
                trust=trust,
                expected_tenant=tenant_id,
            )
            approval_key = (tenant_id, parsed["approval_id"], parsed["approval_digest"])
            if approval_key in self._consumed_approvals:
                raise LifecycleError("approval authority has already been consumed")
            policy_ref = {
                "record_type": "policy_decision",
                "record_id": current.policy["decision_id"],
                "record_digest": current.policy["decision_digest"],
            }
            evidence = self._ledger.append(
                tenant_id=tenant_id,
                run_id=current.request["run_id"],
                event_kind="kernel.approval_accepted",
                policy_ref=policy_ref,
                payload={
                    "actor_id": current.request["actor_id"],
                    "request_digest": current.request["request_digest"],
                    "approval_digest": parsed["approval_digest"],
                    "next_state": KernelLifecycle.APPROVED.value,
                },
            )
            # The evidence append succeeds before either authority consumption or state mutation.
            self._consumed_approvals.add(approval_key)
            advanced = LifecycleRecord(
                current.request,
                current.policy,
                KernelLifecycle.APPROVED,
                (*current.evidence, evidence),
                parsed,
            )
            self._records[key] = advanced
            return _snapshot(advanced)

    def get(self, *, actor_context: Mapping[str, Any], request_id: str) -> LifecycleRecord:
        """Read one lifecycle record using current, verified actor scope."""

        actor = self._validated_actor(actor_context)
        with self._lock:
            try:
                record = self._records[(actor["tenant_id"], request_id)]
            except KeyError as exc:
                raise LifecycleError("unknown tenant-scoped request") from exc
            if record.request["actor_id"] != actor["actor_id"]:
                raise IdentityError("actor context cannot read another actor's request")
            return _snapshot(record)

    def events(self, *, actor_context: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
        """Read actor-scoped tenant evidence only after trusted identity verification."""

        actor = self._validated_actor(actor_context)
        return self._ledger._events_for_actor(actor["tenant_id"], actor["actor_id"])

    def _validate_identity(self, actor: Mapping[str, Any], request: Mapping[str, Any]) -> None:
        self._validate_actor(actor)
        if actor["tenant_id"] != request["tenant_id"] or actor["actor_id"] != request["actor_id"]:
            raise IdentityError("request tenant and actor must match authenticated actor context")
        if request["actor_context_digest"] != sha256_digest(actor):
            raise IdentityError("request does not bind the exact actor context")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise IdentityError("kernel clock must return a timezone-aware timestamp")
        issued = _parse_contract_time(actor["issued_at"])
        expires = _parse_contract_time(actor["expires_at"])
        requested = _parse_contract_time(request["requested_at"])
        normalized_now = now.astimezone(timezone.utc)
        if not issued <= requested <= expires:
            raise IdentityError("request time is outside the actor context validity window")
        if normalized_now >= expires:
            raise IdentityError("actor context is expired")

    def _validated_actor(self, actor_context: Mapping[str, Any]) -> dict[str, Any]:
        actor = ActorContext(actor_context).to_dict()
        self._validate_actor(actor)
        return actor

    def _validate_actor(self, actor: Mapping[str, Any]) -> None:
        if self._identity_verifier.verify(actor_context=copy.deepcopy(dict(actor))) is not True:
            raise IdentityError("actor context is not trusted by the identity boundary")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise IdentityError("kernel clock must return a timezone-aware timestamp")
        normalized_now = now.astimezone(timezone.utc)
        if normalized_now < _parse_contract_time(actor["issued_at"]):
            raise IdentityError("actor context is not currently valid")
        if normalized_now >= _parse_contract_time(actor["expires_at"]):
            raise IdentityError("actor context is expired")


def _parse_contract_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise LifecycleError("contract timestamp is invalid") from exc


def _snapshot(record: LifecycleRecord) -> LifecycleRecord:
    """Return a deep copy so public callers cannot mutate kernel-owned state."""

    return LifecycleRecord(
        request=copy.deepcopy(dict(record.request)),
        policy=copy.deepcopy(dict(record.policy)),
        state=record.state,
        evidence=tuple(copy.deepcopy(dict(value)) for value in record.evidence),
        approval=copy.deepcopy(dict(record.approval)) if record.approval is not None else None,
    )
