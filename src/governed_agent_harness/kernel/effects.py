"""Narrow in-process authorization, broker, and executor boundaries for Phase 3."""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from governed_agent_harness.contracts import (
    ActionOutcome,
    ActorContext,
    ApprovalRecord,
    AuthorizationGrant,
    ConstraintRegistry,
    DetachedProofVerifier,
    IdempotencyConflictError,
    IdempotencyResult,
    PolicyDecision,
    SemanticError,
    ToolRequest,
    TrustContext,
    apply_object_digest,
    canonical_bytes,
    compare_idempotency_bindings,
    sha256_digest,
    validate_grant_binding,
    validate_scope_narrowing,
)
from governed_agent_harness.persistence import (
    DurableEffectStore,
    PreparedExecutionError,
    StoredEffectExecution,
    execution_binding_digest,
)


class EffectConfigurationError(SemanticError):
    """Raised when the injected execution boundary cannot enforce a declared effect."""


class AuthorizationGrantIssuer(Protocol):
    """Injected signing boundary for one exact kernel-authored grant body."""

    def issue(self, *, unsigned_grant: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return the exact body plus a detached authorization-grant proof."""


@dataclass(frozen=True, slots=True)
class ExecutorCapabilities:
    """Explicit effect, isolation, and constraint support declared by an executor."""

    effect_classes: frozenset[str]
    isolation_profiles: frozenset[str]
    constraints: ConstraintRegistry

    def validate(
        self, *, request: Mapping[str, Any], authorization_grant: Mapping[str, Any]
    ) -> None:
        requested_effects = frozenset(request["effect_classes"])
        unsupported_effects = requested_effects - self.effect_classes
        if unsupported_effects:
            raise EffectConfigurationError(
                f"executor does not support effect classes {sorted(unsupported_effects)!r}"
            )
        isolation_profile = authorization_grant["isolation_profile"]
        if isolation_profile not in self.isolation_profiles:
            raise EffectConfigurationError(
                f"executor does not support isolation profile {isolation_profile!r}"
            )
        for constraint in authorization_grant["constraints"]:
            constraint_id = constraint["constraint_id"]
            constraint_version = constraint["constraint_version"]
            if not self.constraints.accepts(constraint_id, constraint_version):
                raise EffectConfigurationError(
                    f"executor does not support constraint {constraint_id}@{constraint_version}"
                )


class EffectExecutor(Protocol):
    """Injected effect port; no provider-specific object crosses this boundary."""

    capabilities: ExecutorCapabilities

    def execute(
        self, *, request: Mapping[str, Any], authorization_grant: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Perform one effect and return a JSON-compatible synthetic result."""

    def revert(
        self,
        *,
        request: Mapping[str, Any],
        authorization_grant: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        """Remove the in-process synthetic effect if outcome evidence cannot append."""


class EvidenceAppender(Protocol):
    def append(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_kind: str,
        policy_ref: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class BrokerExecution:
    outcome: Mapping[str, Any]
    intent_evidence: Mapping[str, Any]
    outcome_evidence: Mapping[str, Any]
    replayed: bool = False

    def snapshot(self, *, replayed: bool | None = None) -> BrokerExecution:
        return BrokerExecution(
            outcome=copy.deepcopy(dict(self.outcome)),
            intent_evidence=copy.deepcopy(dict(self.intent_evidence)),
            outcome_evidence=copy.deepcopy(dict(self.outcome_evidence)),
            replayed=self.replayed if replayed is None else replayed,
        )


@dataclass(frozen=True, slots=True)
class _StoredExecution:
    idempotency: Mapping[str, Any]
    request_digest: str
    policy_digest: str
    grant_digest: str
    execution: BrokerExecution


class EffectBroker:
    """The sole dispatch path for the bounded Phase 3 in-process effect slice."""

    def __init__(
        self,
        *,
        executor: EffectExecutor,
        constraint_registry: ConstraintRegistry,
        grant_verifier: DetachedProofVerifier,
        grant_trust: Callable[[datetime], TrustContext],
        evidence: EvidenceAppender,
        clock: Callable[[], datetime],
        ids: Callable[[], str],
        durable_store: DurableEffectStore | None = None,
    ) -> None:
        self._executor = executor
        self._constraint_registry = constraint_registry
        self._grant_verifier = grant_verifier
        self._grant_trust_factory = grant_trust
        self._evidence = evidence
        self._clock = clock
        self._ids = ids
        self._durable_store = durable_store
        self._lock = threading.RLock()
        self._consumed_grants: set[tuple[str, str, str]] = set()
        self._results: dict[tuple[str, str], _StoredExecution] = {}

    @property
    def durable_store(self) -> DurableEffectStore | None:
        """Expose the narrow persistence port for kernel recovery only."""

        return self._durable_store

    def validate_capabilities(
        self,
        *,
        request: Mapping[str, Any],
        isolation_profile: str,
        constraints: list[dict[str, Any]],
    ) -> None:
        """Fail before grant issuance when this executor cannot enforce the request."""

        self._executor.capabilities.validate(
            request=request,
            authorization_grant={
                "isolation_profile": isolation_profile,
                "constraints": constraints,
            },
        )

    def dispatch(
        self,
        *,
        actor_context: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...],
        authorization_grant: Mapping[str, Any],
    ) -> BrokerExecution:
        """Authorize, record intent, consume authority, execute, then record outcome."""

        actor = ActorContext(actor_context).to_dict()
        parsed_request = ToolRequest(request, expected_tenant=actor["tenant_id"]).to_dict()
        parsed_policy = PolicyDecision(policy, expected_tenant=actor["tenant_id"]).to_dict()
        parsed_approvals = tuple(
            ApprovalRecord(value, expected_tenant=actor["tenant_id"]).to_dict()
            for value in approvals
        )
        grant = AuthorizationGrant(
            authorization_grant, expected_tenant=actor["tenant_id"]
        ).to_dict()
        if self._durable_store is not None:
            return self._dispatch_durable(
                actor=actor,
                request=parsed_request,
                policy=parsed_policy,
                approvals=parsed_approvals,
                grant=grant,
            )
        self._validate_authority(
            actor=actor,
            request=parsed_request,
            policy=parsed_policy,
            approvals=parsed_approvals,
            grant=grant,
        )
        self._executor.capabilities.validate(request=parsed_request, authorization_grant=grant)

        binding = parsed_request["idempotency"]
        binding_key = (binding["tenant_id"], binding["idempotency_key"])
        grant_digest = sha256_digest(grant)
        grant_key = (grant["tenant_id"], grant["grant_id"], grant_digest)
        policy_ref = _record_ref(
            "policy_decision",
            parsed_policy["decision_id"],
            parsed_policy["decision_digest"],
        )

        with self._lock:
            stored = self._results.get(binding_key)
            replay = compare_idempotency_bindings(
                stored.idempotency if stored is not None else None, binding
            )
            if replay is IdempotencyResult.REPLAY:
                if stored is None:
                    raise EffectConfigurationError("effect replay has no stored execution")
                if (
                    stored.request_digest != parsed_request["request_digest"]
                    or stored.policy_digest != parsed_policy["decision_digest"]
                    or stored.grant_digest != grant_digest
                ):
                    raise IdempotencyConflictError(
                        "effect replay does not match the original governed bindings"
                    )
                return stored.execution.snapshot(replayed=True)
            if grant_key in self._consumed_grants:
                raise IdempotencyConflictError(
                    "authorization grant was consumed without a replayable stored result"
                )

            intent = self._evidence.append(
                tenant_id=grant["tenant_id"],
                run_id=grant["run_id"],
                event_kind="kernel.effect_execution_intent",
                policy_ref=policy_ref,
                payload={
                    "actor_id": grant["actor_id"],
                    "request_digest": grant["request_digest"],
                    "policy_decision_digest": grant["policy_decision_digest"],
                    "authorization_grant_digest": grant_digest,
                    "effect_classes": copy.deepcopy(parsed_request["effect_classes"]),
                    "isolation_profile": grant["isolation_profile"],
                },
            )
            # Once intent is durable in this in-memory ledger, authority is consumed before
            # the executor can observe it. The broker lock makes this one atomic dispatch gate.
            self._consumed_grants.add(grant_key)
            status, result_payload, effect_active = self._invoke_executor(parsed_request, grant)
            try:
                outcome = self._build_outcome(
                    actor=actor,
                    request=parsed_request,
                    policy=parsed_policy,
                    approvals=parsed_approvals,
                    grant=grant,
                    intent=intent,
                    status=status,
                    result_payload=result_payload,
                )
            except Exception:
                if effect_active:
                    self._revert_synthetic(parsed_request, grant, result_payload)
                raise
            try:
                outcome_evidence = self._evidence.append(
                    tenant_id=grant["tenant_id"],
                    run_id=grant["run_id"],
                    event_kind="kernel.effect_execution_outcome",
                    policy_ref=policy_ref,
                    payload={
                        "actor_id": grant["actor_id"],
                        "request_digest": grant["request_digest"],
                        "authorization_grant_digest": grant_digest,
                        "outcome_digest": outcome["outcome_digest"],
                        "status": outcome["status"],
                    },
                )
            except Exception:
                # Phase 3 permits only a reversible in-process synthetic effect. Provider
                # effects are deliberately deferred until durable outcome recording exists.
                if effect_active:
                    self._revert_synthetic(parsed_request, grant, result_payload)
                raise
            execution = BrokerExecution(outcome, intent, outcome_evidence)
            self._results[binding_key] = _StoredExecution(
                idempotency=copy.deepcopy(binding),
                request_digest=parsed_request["request_digest"],
                policy_digest=parsed_policy["decision_digest"],
                grant_digest=grant_digest,
                execution=execution,
            )
            return execution.snapshot()

    def recover(
        self,
        *,
        actor_context: Mapping[str, Any],
        request_id: str,
        confirm_dispatch_owner_abandoned: bool = False,
    ) -> BrokerExecution:
        """Explicitly reconcile one committed preparation without invoking an executor."""

        if self._durable_store is None:
            raise EffectConfigurationError("durable effect recovery requires a durable store")
        if not confirm_dispatch_owner_abandoned:
            raise PreparedExecutionError(
                "recovery requires an explicit dispatch-owner-abandoned confirmation"
            )
        actor = ActorContext(actor_context).to_dict()
        stored = self._durable_store.lookup(actor_context=actor, request_id=request_id)
        if stored is None:
            raise EffectConfigurationError("durable execution was not found for recovery")
        self._validate_stored_scope(actor, stored)
        if stored.state in {"completed", "indeterminate"}:
            return self._stored_execution(stored, replayed=True)
        outcome = self._build_outcome(
            actor=stored.actor_context,
            request=stored.request,
            policy=stored.policy,
            approvals=stored.approvals,
            grant=stored.grant,
            intent=stored.intent_evidence,
            status="indeterminate",
            result_payload={"error": "prepared_execution_outcome_unknown"},
        )
        policy_ref = _record_ref(
            "policy_decision", stored.policy["decision_id"], stored.policy["decision_digest"]
        )
        completed = self._durable_store.complete(
            actor_context=actor,
            request_id=request_id,
            expected_version=stored.version,
            outcome=outcome,
            policy_ref=policy_ref,
            outcome_payload={
                "actor_id": actor["actor_id"],
                "request_digest": stored.request["request_digest"],
                "authorization_grant_digest": sha256_digest(stored.grant),
                "outcome_digest": outcome["outcome_digest"],
                "status": "indeterminate",
                "recovery": "explicit",
            },
            state="indeterminate",
        )
        return self._stored_execution(completed, replayed=True)

    def _dispatch_durable(
        self,
        *,
        actor: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...],
        grant: Mapping[str, Any],
    ) -> BrokerExecution:
        existing = self._durable_store.lookup(actor_context=actor, request_id=request["request_id"])
        if existing is not None:
            expected_binding = execution_binding_digest(
                actor_context=actor,
                request=request,
                policy=policy,
                approvals=approvals,
                grant=grant,
            )
            if existing.binding_digest != expected_binding:
                raise IdempotencyConflictError(
                    "durable replay does not match the original governed bindings"
                )
            if existing.state in {"completed", "indeterminate"}:
                return self._stored_execution(existing, replayed=True)
            raise PreparedExecutionError(
                "effect preparation exists without an outcome; explicit recovery is required"
            )

        self._validate_authority(
            actor=actor,
            request=request,
            policy=policy,
            approvals=approvals,
            grant=grant,
        )
        self._executor.capabilities.validate(request=request, authorization_grant=grant)
        policy_ref = _record_ref(
            "policy_decision", policy["decision_id"], policy["decision_digest"]
        )
        prepared = self._durable_store.prepare(
            actor_context=actor,
            request=request,
            policy=policy,
            approvals=approvals,
            grant=grant,
            policy_ref=policy_ref,
            intent_payload={
                "actor_id": grant["actor_id"],
                "request_digest": grant["request_digest"],
                "policy_decision_digest": grant["policy_decision_digest"],
                "authorization_grant_digest": sha256_digest(grant),
                "effect_classes": copy.deepcopy(request["effect_classes"]),
                "isolation_profile": grant["isolation_profile"],
            },
        )
        if not prepared.created:
            if prepared.state in {"completed", "indeterminate"}:
                return self._stored_execution(prepared, replayed=True)
            raise PreparedExecutionError(
                "effect preparation exists without an outcome; explicit recovery is required"
            )
        status, result_payload, effect_active = self._invoke_executor(request, grant)
        outcome: dict[str, Any] | None = None
        try:
            outcome = self._build_outcome(
                actor=actor,
                request=request,
                policy=policy,
                approvals=approvals,
                grant=grant,
                intent=prepared.intent_evidence,
                status=status,
                result_payload=result_payload,
            )
            completed = self._durable_store.complete(
                actor_context=actor,
                request_id=request["request_id"],
                expected_version=prepared.version,
                outcome=outcome,
                policy_ref=policy_ref,
                outcome_payload={
                    "actor_id": grant["actor_id"],
                    "request_digest": grant["request_digest"],
                    "authorization_grant_digest": sha256_digest(grant),
                    "outcome_digest": outcome["outcome_digest"],
                    "status": outcome["status"],
                },
                state="completed" if status == "succeeded" else "indeterminate",
            )
        except Exception:
            if outcome is None:
                if effect_active:
                    self._revert_synthetic(request, grant, result_payload)
                raise
            try:
                reconciled = self._durable_store.lookup(
                    actor_context=actor, request_id=request["request_id"]
                )
            except Exception as reconcile_error:
                raise EffectConfigurationError(
                    "durable outcome acknowledgement is uncertain; effect must not be retried"
                ) from reconcile_error
            if reconciled is not None and reconciled.state in {"completed", "indeterminate"}:
                if reconciled.outcome != outcome:
                    raise EffectConfigurationError(
                        "durable outcome acknowledgement conflicts with stored terminal result"
                    )
                return self._stored_execution(reconciled, replayed=True)
            if effect_active:
                self._revert_synthetic(request, grant, result_payload)
            raise
        return self._stored_execution(completed)

    @staticmethod
    def _validate_stored_scope(actor: Mapping[str, Any], stored: StoredEffectExecution) -> None:
        if actor != stored.actor_context:
            raise EffectConfigurationError(
                "recovery actor context does not exactly match preparation"
            )
        if stored.request["actor_context_digest"] != sha256_digest(actor):
            raise EffectConfigurationError("stored preparation does not bind actor context")
        if (
            stored.request["tenant_id"] != actor["tenant_id"]
            or stored.request["actor_id"] != actor["actor_id"]
            or stored.grant["tenant_id"] != actor["tenant_id"]
            or stored.grant["actor_id"] != actor["actor_id"]
        ):
            raise EffectConfigurationError("stored preparation scope is invalid")

    @staticmethod
    def _stored_execution(
        stored: StoredEffectExecution, *, replayed: bool = False
    ) -> BrokerExecution:
        if stored.outcome is None or stored.outcome_evidence is None:
            raise PreparedExecutionError("durable execution has no terminal outcome")
        return BrokerExecution(
            stored.outcome,
            stored.intent_evidence,
            stored.outcome_evidence,
            replayed=replayed,
        ).snapshot()

    def _validate_authority(
        self,
        *,
        actor: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...],
        grant: Mapping[str, Any],
    ) -> None:
        if actor["tenant_id"] != request["tenant_id"] or actor["actor_id"] != request["actor_id"]:
            raise EffectConfigurationError(
                "broker request scope does not match the verified actor context"
            )
        if request["actor_context_digest"] != sha256_digest(actor):
            raise EffectConfigurationError(
                "broker request does not bind the verified actor context"
            )
        if grant["idempotency"] != request["idempotency"]:
            raise IdempotencyConflictError(
                "authorization grant idempotency must exactly match the request"
            )
        now = _aware_utc(self._clock())
        if now >= _contract_time(actor["expires_at"]):
            raise EffectConfigurationError("verified actor context expired before dispatch")
        if not _contract_time(grant["issued_at"]) <= now < _contract_time(grant["expires_at"]):
            raise EffectConfigurationError("authorization grant is not currently valid")
        trust = self._grant_trust_factory(now)
        if not isinstance(trust, TrustContext) or trust.now != now:
            raise EffectConfigurationError(
                "grant trust factory must return the current trust context"
            )
        validate_grant_binding(
            grant,
            request,
            policy,
            approvals,
            constraint_registry=self._constraint_registry,
            verifier=self._grant_verifier,
            trust=trust,
        )

    def _invoke_executor(
        self, request: Mapping[str, Any], grant: Mapping[str, Any]
    ) -> tuple[str, dict[str, Any], bool]:
        try:
            raw_result = self._executor.execute(
                request=copy.deepcopy(dict(request)),
                authorization_grant=copy.deepcopy(dict(grant)),
            )
        except Exception:
            result = {"error": "executor_result_indeterminate"}
            self._revert_synthetic(request, grant, result)
            return "indeterminate", result, False
        try:
            if not isinstance(raw_result, Mapping):
                raise TypeError("executor result must be a mapping")
            result = copy.deepcopy(dict(raw_result))
            canonical_bytes(result)
        except Exception:
            # Error text is intentionally not persisted because it may contain sensitive
            # executor data. This slice reverts its only allowed synthetic effect.
            result = {"error": "executor_result_indeterminate"}
            self._revert_synthetic(request, grant, result)
            return "indeterminate", result, False
        return "succeeded", result, True

    def _revert_synthetic(
        self,
        request: Mapping[str, Any],
        grant: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        try:
            self._executor.revert(
                request=copy.deepcopy(dict(request)),
                authorization_grant=copy.deepcopy(dict(grant)),
                result=copy.deepcopy(dict(result)),
            )
        except Exception as exc:
            raise EffectConfigurationError(
                "synthetic executor could not revert an unrecordable effect"
            ) from exc

    def _build_outcome(
        self,
        *,
        actor: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...],
        grant: Mapping[str, Any],
        intent: Mapping[str, Any],
        status: str,
        result_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = _aware_utc(self._clock())
        occurred_at = _utc_millis(now)
        scope = {
            "schema_version": "1.0",
            "record_type": "memory_scope",
            "scope_id": self._ids(),
            "tenant_id": actor["tenant_id"],
            "actor_id": actor["actor_id"],
            "parent_record_type": "actor_context",
            "parent_digest": sha256_digest(actor),
            "selection": {"level": "actor"},
            "derived_at": occurred_at,
            "valid_until": actor["expires_at"],
        }
        validate_scope_narrowing(scope, actor)
        outcome = {
            "schema_version": "1.0",
            "record_type": "action_outcome",
            "tenant_id": request["tenant_id"],
            "outcome_id": self._ids(),
            "target_scope": scope,
            "run_id": request["run_id"],
            "request_ref": _record_ref(
                "tool_request", request["request_id"], request["request_digest"]
            ),
            "status": status,
            "effect_state": status,
            "evidence_refs": [
                _record_ref(
                    "evidence_envelope",
                    intent["envelope_id"],
                    intent["event_digest"],
                )
            ],
            "provenance_digest": sha256_digest(
                {
                    "authorization_grant_digest": sha256_digest(grant),
                    "intent_evidence_digest": intent["event_digest"],
                    "result_payload": result_payload,
                }
            ),
            "result_payload": copy.deepcopy(dict(result_payload)),
            "producer_version": "governed_effects.v1",
            "runtime_version": "phase3.in_process.v1",
            "policy_refs": [
                _record_ref(
                    "policy_decision",
                    policy["decision_id"],
                    policy["decision_digest"],
                )
            ],
            "reviewer_refs": [
                _record_ref(
                    "approval_record",
                    approval["approval_id"],
                    approval["approval_digest"],
                )
                for approval in approvals
            ],
            "compatibility": {
                "contract_versions": ["action_outcome=1.0"],
                "runtime_version_range": ">=0.1",
            },
            "idempotency": copy.deepcopy(request["idempotency"]),
            "occurred_at": occurred_at,
            "outcome_digest": "sha256:" + "0" * 64,
        }
        apply_object_digest(outcome)
        return ActionOutcome(outcome, expected_tenant=request["tenant_id"]).to_dict()


def _record_ref(record_type: str, record_id: str, record_digest: str) -> dict[str, str]:
    return {
        "record_type": record_type,
        "record_id": record_id,
        "record_digest": record_digest,
    }


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EffectConfigurationError("effect clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _utc_millis(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _contract_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise EffectConfigurationError("effect contract timestamp is invalid") from exc
