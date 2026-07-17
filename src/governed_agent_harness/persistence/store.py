"""PostgreSQL-backed authority and evidence store for durable governed effects."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Protocol

from governed_agent_harness.contracts import (
    ActionOutcome,
    ActorContext,
    ApprovalRecord,
    AuthorizationGrant,
    EvidenceEnvelope,
    IdempotencyConflictError,
    PolicyDecision,
    SemanticError,
    ToolRequest,
    apply_object_digest,
    sha256_digest,
)


class DurableStoreError(SemanticError):
    """Raised when durable authority state cannot transition safely."""


class OptimisticConcurrencyError(DurableStoreError):
    """Raised when a caller attempts a stale execution transition."""


class PreparedExecutionError(DurableStoreError):
    """Raised when explicit recovery is required for an existing preparation."""


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
    ) -> StoredEffectExecution: ...


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


class PostgresDurableEffectStore:
    """Real PostgreSQL implementation with forced RLS and transactional authority use."""

    def __init__(
        self,
        *,
        connect: Callable[[], _Connection],
        clock: Callable[[], datetime],
        ids: Callable[[], str],
        privileged_connect: Callable[[], _Connection] | None = None,
    ) -> None:
        self._connect = connect
        # The application role is read-only.  All authoritative transitions use
        # a backend-only owner connection that is never exposed to transports.
        self._privileged_connect = privileged_connect or connect
        self._clock = clock
        self._ids = ids

    @staticmethod
    def install_schema(
        *, admin_connect: Callable[[], _Connection], application_role: str | None = None
    ) -> None:
        """Install the packaged migration and optionally grant a restricted runtime role."""

        sql_text = (
            files("governed_agent_harness.persistence.migrations")
            .joinpath("0001_durable_effects.sql")
            .read_text(encoding="utf-8")
        )
        with admin_connect() as connection, connection.cursor() as cursor:
            cursor.execute(sql_text)
            if application_role is not None:
                if not application_role or not application_role.replace("_", "a").isalnum():
                    raise DurableStoreError("application role name is malformed")
                from psycopg import sql

                role = sql.Identifier(application_role)
                cursor.execute(
                    sql.SQL(
                        "REVOKE ALL ON gah_run_heads, gah_evidence_events, "
                        "gah_effect_executions, gah_grant_consumptions FROM {}"
                    ).format(role)
                )

    def lookup(
        self, *, actor_context: Mapping[str, Any], request_id: str
    ) -> StoredEffectExecution | None:
        actor = ActorContext(actor_context).to_dict()
        with self._privileged_connect() as connection, connection.cursor() as cursor:
            self._set_scope(cursor, actor)
            cursor.execute(
                """
                SELECT actor_context_json, request_json, policy_json, approvals_json,
                       grant_json, binding_digest, state, version, intent_envelope_json,
                       outcome_json, outcome_envelope_json
                  FROM gah_effect_executions
                 WHERE tenant_id = %s AND actor_id = %s AND request_id = %s
                """,
                (actor["tenant_id"], actor["actor_id"], request_id),
            )
            row = cursor.fetchone()
        return self._row(row) if row is not None else None

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
        with self._privileged_connect() as connection, connection.cursor() as cursor:
            self._set_scope(cursor, actor)
            return self._append_evidence(
                cursor=cursor,
                actor=actor,
                run_id=run_id,
                event_kind=event_kind,
                policy_ref=policy_ref,
                payload=payload,
            )

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
        with self._privileged_connect() as connection, connection.cursor() as cursor:
            self._set_scope(cursor, actor)
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
            cursor.execute(
                """
                INSERT INTO gah_effect_executions (
                    tenant_id, actor_id, run_id, request_id, idempotency_key,
                    operation_digest, binding_digest, grant_id, grant_digest, state,
                    version, actor_context_json, request_json, policy_json, approvals_json,
                    grant_json, intent_envelope_json, prepared_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, 'prepared', 1,
                    %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s
                )
                """,
                (
                    actor["tenant_id"],
                    actor["actor_id"],
                    parsed_request["run_id"],
                    parsed_request["request_id"],
                    parsed_request["idempotency"]["idempotency_key"],
                    parsed_request["idempotency"]["operation_digest"],
                    binding_digest,
                    parsed_grant["grant_id"],
                    sha256_digest(parsed_grant),
                    _json(actor),
                    _json(parsed_request),
                    _json(parsed_policy),
                    _json(list(parsed_approvals)),
                    _json(parsed_grant),
                    _json(intent),
                    now,
                ),
            )
            cursor.execute(
                """
                INSERT INTO gah_grant_consumptions (
                    tenant_id, actor_id, grant_id, grant_digest, request_id, consumed_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    actor["tenant_id"],
                    actor["actor_id"],
                    parsed_grant["grant_id"],
                    sha256_digest(parsed_grant),
                    parsed_request["request_id"],
                    now,
                ),
            )
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
    ) -> StoredEffectExecution:
        actor = ActorContext(actor_context).to_dict()
        if state not in {"completed", "indeterminate"}:
            raise DurableStoreError("durable terminal state is unsupported")
        parsed_outcome = ActionOutcome(outcome, expected_tenant=actor["tenant_id"]).to_dict()
        expected_status = "succeeded" if state == "completed" else "indeterminate"
        if parsed_outcome["status"] != expected_status:
            raise DurableStoreError("outcome status does not match the durable terminal state")

        with self._privileged_connect() as connection, connection.cursor() as cursor:
            self._set_scope(cursor, actor)
            cursor.execute(
                """
                SELECT actor_context_json, request_json, policy_json, approvals_json,
                       grant_json, binding_digest, state, version, intent_envelope_json,
                       outcome_json, outcome_envelope_json
                  FROM gah_effect_executions
                 WHERE tenant_id = %s AND actor_id = %s AND request_id = %s
                 FOR UPDATE
                """,
                (actor["tenant_id"], actor["actor_id"], request_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise DurableStoreError("durable execution was not found")
            stored = self._row(row)
            if stored.state != "prepared" or stored.version != expected_version:
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
            cursor.execute(
                """
                UPDATE gah_effect_executions
                   SET state = %s, version = version + 1, outcome_json = %s::jsonb,
                       outcome_envelope_json = %s::jsonb, completed_at = %s
                 WHERE tenant_id = %s AND actor_id = %s AND request_id = %s
                   AND state = 'prepared' AND version = %s
                """,
                (
                    state,
                    _json(parsed_outcome),
                    _json(evidence),
                    now,
                    actor["tenant_id"],
                    actor["actor_id"],
                    request_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
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
        ).snapshot()

    def events(
        self, *, actor_context: Mapping[str, Any], run_id: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        actor = ActorContext(actor_context).to_dict()
        with self._privileged_connect() as connection, connection.cursor() as cursor:
            self._set_scope(cursor, actor)
            if run_id is None:
                cursor.execute(
                    """
                    SELECT envelope_json FROM gah_evidence_events
                     WHERE tenant_id = %s AND actor_id = %s
                     ORDER BY run_id, sequence_number
                    """,
                    (actor["tenant_id"], actor["actor_id"]),
                )
            else:
                cursor.execute(
                    """
                    SELECT envelope_json FROM gah_evidence_events
                     WHERE tenant_id = %s AND actor_id = %s AND run_id = %s
                     ORDER BY sequence_number
                    """,
                    (actor["tenant_id"], actor["actor_id"], run_id),
                )
            return tuple(copy.deepcopy(row[0]) for row in cursor.fetchall())

    def _select_for_binding(
        self,
        cursor: Any,
        actor: Mapping[str, Any],
        request: Mapping[str, Any],
        grant: Mapping[str, Any],
    ) -> StoredEffectExecution | None:
        cursor.execute(
            """
            SELECT actor_context_json, request_json, policy_json, approvals_json,
                   grant_json, binding_digest, state, version, intent_envelope_json,
                   outcome_json, outcome_envelope_json
              FROM gah_effect_executions
             WHERE tenant_id = %s AND actor_id = %s
               AND (idempotency_key = %s OR grant_id = %s OR request_id = %s)
             FOR UPDATE
            """,
            (
                actor["tenant_id"],
                actor["actor_id"],
                request["idempotency"]["idempotency_key"],
                grant["grant_id"],
                request["request_id"],
            ),
        )
        rows = cursor.fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise IdempotencyConflictError("durable authority bindings reference different rows")
        return self._row(rows[0])

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
        cursor.execute(
            """
            INSERT INTO gah_run_heads (tenant_id, actor_id, run_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (tenant_id, run_id) DO NOTHING
            """,
            (actor["tenant_id"], actor["actor_id"], run_id),
        )
        cursor.execute(
            """
                SELECT next_sequence, last_event_digest, last_recorded_at, version
              FROM gah_run_heads
             WHERE tenant_id = %s AND actor_id = %s AND run_id = %s
             FOR UPDATE
            """,
            (actor["tenant_id"], actor["actor_id"], run_id),
        )
        head = cursor.fetchone()
        if head is None:
            raise DurableStoreError("run scope conflicts with an existing actor")
        sequence, prior_digest, prior_recorded_at, version = head
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
        cursor.execute(
            """
            INSERT INTO gah_evidence_events (
                tenant_id, actor_id, run_id, sequence_number, envelope_id,
                event_digest, prior_event_digest, envelope_json, recorded_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
            """,
            (
                actor["tenant_id"],
                actor["actor_id"],
                run_id,
                sequence,
                parsed["envelope_id"],
                parsed["event_digest"],
                parsed["prior_event_digest"],
                _json(parsed),
                now_dt,
            ),
        )
        cursor.execute(
            """
            UPDATE gah_run_heads
               SET next_sequence = %s, last_event_digest = %s,
                   last_recorded_at = %s, version = version + 1
             WHERE tenant_id = %s AND actor_id = %s AND run_id = %s AND version = %s
            """,
            (
                sequence + 1,
                parsed["event_digest"],
                now_dt,
                actor["tenant_id"],
                actor["actor_id"],
                run_id,
                version,
            ),
        )
        if cursor.rowcount != 1:
            raise OptimisticConcurrencyError("run evidence sequence lost its race")
        return parsed

    @staticmethod
    def _set_scope(cursor: Any, actor: Mapping[str, Any]) -> None:
        cursor.execute("SELECT set_config('gah.tenant_id', %s, true)", (actor["tenant_id"],))
        cursor.execute("SELECT set_config('gah.actor_id', %s, true)", (actor["actor_id"],))

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
        if stored.state == "prepared" and (
            stored.outcome is not None or stored.outcome_evidence is not None
        ):
            raise DurableStoreError("prepared execution contains terminal evidence")
        if stored.state in {"completed", "indeterminate"}:
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
    if outcome["status"] == "indeterminate":
        expected_payload["recovery"] = "explicit"
    if (
        draft.get("event_kind") != "kernel.effect_execution_outcome"
        or draft.get("run_id") != stored.request["run_id"]
        or draft.get("inline_payload") != expected_payload
        or outcome["status"] != ("succeeded" if stored.state == "completed" else "indeterminate")
    ):
        raise DurableStoreError("durable outcome evidence binding is invalid")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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
