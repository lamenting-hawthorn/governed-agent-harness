"""Bounded execution admission for one preinstalled deterministic built-in.

Stored skill artifacts remain inert.  The host selects code exclusively from
this static registry after PostgreSQL binds an active artifact digest to one
short-lived, single-use authorization.
"""

from __future__ import annotations

import copy
import json
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from governed_agent_harness.contracts import (
    ActionOutcome,
    ActorContext,
    ApprovalRecord,
    AuthorizationGrant,
    ConstraintRegistry,
    DetachedProofVerifier,
    EvidenceEnvelope,
    GateDecision,
    PolicyDecision,
    SemanticError,
    ToolRequest,
    TrustContext,
    apply_object_digest,
    canonical_bytes,
    sha256_digest,
    unsigned_body,
    validate_approval_binding,
    validate_grant_binding,
    validate_policy_request_binding,
    validate_scope_narrowing,
    verify_signed_record,
)
from .skills import ActiveSkillDigest, ActiveSkillResolver


BUILTIN_ECHO_TOOL_ID = "gah.builtin.echo"
BUILTIN_ECHO_TOOL_VERSION = "1.0.0"
BUILTIN_ECHO_ARTIFACT = {"kind": "synthetic", "version": 1}
BUILTIN_ECHO_ARTIFACT_DIGEST = (
    "sha256:be4c49fbd64577c93908f9c49d3a4625e52c216bac4703be737fc2e080f4c9a7"
)
_GRANT_TTL = timedelta(minutes=5)
_INPUT_LIMIT = 16_384


class ExecutionAdmissionError(SemanticError):
    """Fail-closed execution-admission error."""


class _Connection(Protocol):
    def __enter__(self) -> _Connection: ...
    def __exit__(self, *args: object) -> None: ...
    def cursor(self) -> Any: ...


class AuthorizationGrantIssuer(Protocol):
    def issue(self, *, unsigned_grant: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    command: Mapping[str, Any]
    grant: Mapping[str, Any]
    issuance_evidence: Mapping[str, Any]
    replayed: bool = False

    def snapshot(self, *, replayed: bool | None = None) -> ExecutionAuthorization:
        return ExecutionAuthorization(
            copy.deepcopy(dict(self.command)),
            copy.deepcopy(dict(self.grant)),
            copy.deepcopy(dict(self.issuance_evidence)),
            self.replayed if replayed is None else replayed,
        )


@dataclass(frozen=True, slots=True)
class BuiltinExecution:
    outcome: Mapping[str, Any]
    intent_evidence: Mapping[str, Any]
    outcome_evidence: Mapping[str, Any]
    replayed: bool = False

    def snapshot(self, *, replayed: bool | None = None) -> BuiltinExecution:
        return BuiltinExecution(
            copy.deepcopy(dict(self.outcome)),
            copy.deepcopy(dict(self.intent_evidence)),
            copy.deepcopy(dict(self.outcome_evidence)),
            self.replayed if replayed is None else replayed,
        )


class BuiltinHandlerRegistry:
    """Immutable host registry; no stored artifact text is read or interpreted."""

    def validate(self, *, active: ActiveSkillDigest, request: Mapping[str, Any]) -> None:
        arguments = request["arguments"]
        if set(arguments) != {"skill_id", "revision", "artifact_digest", "input"}:
            raise ExecutionAdmissionError("built-in request arguments are not exact")
        if (
            request["tool_id"] != BUILTIN_ECHO_TOOL_ID
            or request["tool_version"] != BUILTIN_ECHO_TOOL_VERSION
            or request["effect_classes"] != ["execute_code"]
            or active.artifact_digest != BUILTIN_ECHO_ARTIFACT_DIGEST
            or arguments["skill_id"] != active.skill_id
            or arguments["revision"] != active.revision
            or arguments["artifact_digest"] != active.artifact_digest
        ):
            raise ExecutionAdmissionError("request is not bound to the active built-in handler")
        value = arguments["input"]
        if not isinstance(value, Mapping):
            raise ExecutionAdmissionError("built-in echo input must be an object")
        if len(canonical_bytes(value)) > _INPUT_LIMIT:
            raise ExecutionAdmissionError("built-in echo input exceeds the bounded size limit")

    def invoke(self, *, request: Mapping[str, Any]) -> dict[str, Any]:
        """Invoke exactly one pure preinstalled handler."""

        return {"echo": copy.deepcopy(dict(request["arguments"]["input"]))}


_STATIC_BUILTIN_REGISTRY = BuiltinHandlerRegistry()


def execution_operation_digest(command: Mapping[str, Any]) -> str:
    return sha256_digest(dict(command))


def build_execution_admission_command(command: Mapping[str, Any]) -> dict[str, Any]:
    if "operation_digest" in command:
        raise ValueError("callers must not supply operation_digest")
    wire = copy.deepcopy(dict(command))
    wire["operation_digest"] = execution_operation_digest(wire)
    return wire


def _runtime_command(command: Mapping[str, Any]) -> dict[str, Any]:
    """Reject a caller-held authorization whose command no longer has its issued digest."""

    wire = copy.deepcopy(dict(command))
    if "operation_digest" not in wire:
        raise ExecutionAdmissionError("runtime authorization command lacks its operation digest")
    supplied = wire.pop("operation_digest")
    expected = execution_operation_digest(wire)
    wire["operation_digest"] = supplied
    if not isinstance(supplied, str) or not secrets.compare_digest(supplied, expected):
        raise ExecutionAdmissionError("runtime authorization command is missing or changed")
    return wire


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExecutionAdmissionError("execution timestamp must include an offset")
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ExecutionAdmissionError("execution clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ref(record_type: str, record_id: str, record_digest: str) -> dict[str, str]:
    return {
        "record_type": record_type,
        "record_id": record_id,
        "record_digest": record_digest,
    }


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class _Ids:
    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_ms = -1
        self._sequence = 0

    def __call__(self) -> str:
        timestamp_ms = int(self._clock().astimezone(timezone.utc).timestamp() * 1000)
        with self._lock:
            if timestamp_ms == self._last_ms:
                self._sequence = (self._sequence + 1) & 0x0FFF
            else:
                self._last_ms, self._sequence = timestamp_ms, secrets.randbits(12)
            value = (
                (timestamp_ms << 80)
                | (0x7 << 76)
                | (self._sequence << 64)
                | (0x2 << 62)
                | secrets.randbits(62)
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


def _parse_command(
    *,
    actor_context: Mapping[str, Any],
    command: Mapping[str, Any],
    active: ActiveSkillDigest,
    now: datetime,
    approval_verifier: DetachedProofVerifier,
    approval_trust: Callable[[datetime], TrustContext],
    registry: BuiltinHandlerRegistry,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    tuple[dict[str, Any], ...],
]:
    required = {
        "operation_id",
        "operation_digest",
        "skill_id",
        "revision",
        "artifact_digest",
        "tool_request",
        "policy_decision",
        "gate_decision",
        "approvals",
        "source_evidence",
        "validity",
        "retention",
    }
    wire = copy.deepcopy(dict(command))
    if set(wire) != required:
        raise ExecutionAdmissionError("execution command keys do not match the canonical contract")
    supplied = wire.pop("operation_digest")
    expected = execution_operation_digest(wire)
    wire["operation_digest"] = supplied
    if not isinstance(supplied, str) or not secrets.compare_digest(supplied, expected):
        raise ExecutionAdmissionError("execution operation digest does not bind the exact command")
    if not isinstance(wire["operation_id"], str) or not wire["operation_id"]:
        raise ExecutionAdmissionError("execution operation_id is required")

    actor = ActorContext(actor_context).to_dict()
    request = ToolRequest(wire["tool_request"], expected_tenant=actor["tenant_id"]).to_dict()
    policy = PolicyDecision(wire["policy_decision"], expected_tenant=actor["tenant_id"]).to_dict()
    gate = GateDecision(wire["gate_decision"], expected_tenant=actor["tenant_id"]).to_dict()
    if any(not isinstance(value, Mapping) or "revoked_at" in value for value in wire["approvals"]):
        raise ExecutionAdmissionError("execution approval is revoked or malformed")
    approvals = tuple(
        ApprovalRecord(value, expected_tenant=actor["tenant_id"]).to_dict()
        for value in wire["approvals"]
    )
    evidence = tuple(
        EvidenceEnvelope(value, expected_tenant=actor["tenant_id"]).to_dict()
        for value in wire["source_evidence"]
    )
    if (
        request["actor_id"] != actor["actor_id"]
        or request["actor_context_digest"] != sha256_digest(actor)
        or request["run_id"] != actor["session_id"]
        or wire["skill_id"] != active.skill_id
        or wire["revision"] != active.revision
        or wire["artifact_digest"] != active.artifact_digest
    ):
        raise ExecutionAdmissionError("execution command is outside the resolved actor binding")
    registry.validate(active=active, request=request)
    validate_policy_request_binding(policy, request)
    if (
        policy["decision"] != "require_approval"
        or policy["isolation_profile"] != "none"
        or len(approvals) != 1
    ):
        raise ExecutionAdmissionError(
            "built-in execution requires one approval and isolation_profile none"
        )
    approval = approvals[0]
    validate_approval_binding(approval, policy, request)
    if (
        approval["disposition"] != "approved"
        or not approval["separation_of_duties"]["required"]
        or not approval["separation_of_duties"]["satisfied"]
        or approval["approver_actor_id"] == actor["actor_id"]
    ):
        raise ExecutionAdmissionError("execution approval violates separation of duties")
    trust = approval_trust(now)
    if not isinstance(trust, TrustContext) or trust.now != now:
        raise ExecutionAdmissionError("approval trust must be evaluated at the current time")
    verify_signed_record(
        approval,
        verifier=approval_verifier,
        trust=trust,
        expected_tenant=actor["tenant_id"],
    )
    if gate["decision"] != "approve" or not evidence:
        raise ExecutionAdmissionError("execution requires an approved gate and source evidence")
    if any(value["tenant_id"] != actor["tenant_id"] for value in evidence):
        raise ExecutionAdmissionError("execution source evidence is cross-tenant")
    validity_expiry = _parse_time(wire["validity"].get("expires_at", ""))
    retention_expiry = _parse_time(wire["retention"].get("expires_at", ""))
    if not (
        _parse_time(actor["issued_at"])
        <= now
        < min(
            _parse_time(actor["expires_at"]),
            _parse_time(approval["expires_at"]),
            validity_expiry,
            retention_expiry,
        )
    ):
        raise ExecutionAdmissionError("execution authority is not currently valid")
    return actor, request, policy, approvals


def _grant(
    *,
    actor: Mapping[str, Any],
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    approvals: tuple[Mapping[str, Any], ...],
    now: datetime,
    ids: Callable[[], str],
    nonce: Callable[[], str],
    issuer: AuthorizationGrantIssuer,
    verifier: DetachedProofVerifier,
    trust_factory: Callable[[datetime], TrustContext],
    validity_expires_at: str,
    retention_expires_at: str,
) -> dict[str, Any]:
    value = nonce()
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{22,128}", value) is None:
        raise ExecutionAdmissionError("grant nonce source returned an invalid value")
    expiry = min(
        now + _GRANT_TTL,
        _parse_time(actor["expires_at"]),
        _parse_time(approvals[0]["expires_at"]),
        _parse_time(validity_expires_at),
        _parse_time(retention_expires_at),
    )
    unsigned = {
        "schema_version": "1.0",
        "record_type": "authorization_grant",
        "tenant_id": actor["tenant_id"],
        "grant_id": ids(),
        "actor_id": actor["actor_id"],
        "run_id": request["run_id"],
        "request_id": request["request_id"],
        "request_digest": request["request_digest"],
        "tool_id": request["tool_id"],
        "tool_version": request["tool_version"],
        "policy_decision_id": policy["decision_id"],
        "policy_decision_digest": policy["decision_digest"],
        "approval_refs": [
            _ref("approval_record", value["approval_id"], value["approval_digest"])
            for value in approvals
        ],
        "constraints": copy.deepcopy(policy["constraints"]),
        "isolation_profile": policy["isolation_profile"],
        "issued_at": _utc(now),
        "expires_at": _utc(expiry),
        "grant_nonce": value,
        "idempotency": copy.deepcopy(request["idempotency"]),
    }
    issued = AuthorizationGrant(
        issuer.issue(unsigned_grant=copy.deepcopy(unsigned)),
        expected_tenant=actor["tenant_id"],
    ).to_dict()
    if unsigned_body(issued) != unsigned:
        raise ExecutionAdmissionError("grant issuer changed the authority-authored body")
    trust = trust_factory(now)
    if not isinstance(trust, TrustContext) or trust.now != now:
        raise ExecutionAdmissionError("grant trust must be evaluated at the current time")
    validate_grant_binding(
        issued,
        request,
        policy,
        approvals,
        constraint_registry=ConstraintRegistry({}),
        verifier=verifier,
        trust=trust,
    )
    return issued


def _build_evidence(
    *,
    actor: Mapping[str, Any],
    run_id: str,
    event_kind: str,
    policy: Mapping[str, Any],
    payload: Mapping[str, Any],
    head: Mapping[str, Any],
    clock: Callable[[], datetime],
    ids: Callable[[], str],
) -> dict[str, Any]:
    now = clock().astimezone(timezone.utc)
    if head["last_recorded_at"] is not None and now < _parse_time(head["last_recorded_at"]):
        # A newly admitted authorization is timestamped by the database
        # transaction.  A caller clock can lag it, but must never move the
        # evidence chain backwards.
        now = _parse_time(head["last_recorded_at"])
    timestamp = _utc(now)
    draft = {
        "schema_version": "1.0",
        "record_type": "evidence_draft",
        "tenant_id": actor["tenant_id"],
        "event_id": ids(),
        "run_id": run_id,
        "event_kind": event_kind,
        "occurred_at": timestamp,
        "idempotency": {
            "tenant_id": actor["tenant_id"],
            "idempotency_key": (
                f"execution.{event_kind}.{payload['operation_id']}.{head['next_sequence']}"
            ),
            "operation_digest": payload["operation_digest"],
        },
        "classification": "internal",
        "redaction_status": "redacted",
        "inline_payload": copy.deepcopy(dict(payload)),
    }
    envelope = {
        "schema_version": "1.0",
        "record_type": "evidence_envelope",
        "tenant_id": actor["tenant_id"],
        "envelope_id": ids(),
        "draft": draft,
        "draft_digest": sha256_digest(draft),
        "recorded_at": timestamp,
        "sequence_number": head["next_sequence"],
        "payload_digest": sha256_digest(payload),
        "prior_event_digest": head["last_event_digest"],
        "policy_refs": [_ref("policy_decision", policy["decision_id"], policy["decision_digest"])],
        "storage_writer_id": "execution.postgresql.v1",
    }
    apply_object_digest(envelope)
    return EvidenceEnvelope(envelope, expected_tenant=actor["tenant_id"]).to_dict()


def _head(cursor: Any, actor: Mapping[str, Any], run_id: str) -> Mapping[str, Any]:
    cursor.execute(
        "SELECT gah_builtin_execution_evidence_head(%s::jsonb, %s)",
        (_json(actor), run_id),
    )
    row = cursor.fetchone()
    if row is None or row[0] is None:
        raise ExecutionAdmissionError("execution evidence head is unavailable")
    return row[0]


def _authorization(value: Any) -> ExecutionAuthorization:
    if not isinstance(value, Mapping) or set(value) != {
        "command",
        "grant",
        "issuance_evidence",
        "replayed",
    }:
        raise ExecutionAdmissionError("execution authority returned a malformed result")
    return ExecutionAuthorization(
        copy.deepcopy(value["command"]),
        copy.deepcopy(value["grant"]),
        copy.deepcopy(value["issuance_evidence"]),
        bool(value["replayed"]),
    )


class PostgresExecutionAdmissionAuthority:
    """Authority-only issuer for one exact active built-in skill digest."""

    def __init__(
        self,
        *,
        authority_connect: Callable[[], _Connection],
        evidence_writer_connect: Callable[[], _Connection],
        resolver: ActiveSkillResolver,
        grant_issuer: AuthorizationGrantIssuer,
        grant_verifier: DetachedProofVerifier,
        grant_trust: Callable[[datetime], TrustContext],
        approval_verifier: DetachedProofVerifier,
        approval_trust: Callable[[datetime], TrustContext],
        clock: Callable[[], datetime] | None = None,
        ids: Callable[[], str] | None = None,
        nonce: Callable[[], str] | None = None,
    ) -> None:
        if evidence_writer_connect is authority_connect:
            raise ValueError(
                "execution authority and evidence-writer connection factories must be distinct"
            )
        self._authority_connect = authority_connect
        self._evidence_writer_connect = evidence_writer_connect
        self._resolver = resolver
        self._grant_issuer = grant_issuer
        self._grant_verifier = grant_verifier
        self._grant_trust = grant_trust
        self._approval_verifier = approval_verifier
        self._approval_trust = approval_trust
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ids = ids or _Ids(self._clock)
        self._nonce = nonce or (lambda: secrets.token_urlsafe(24))

    def issue(
        self, *, actor_context: Mapping[str, Any], command: Mapping[str, Any]
    ) -> ExecutionAuthorization:
        wire = build_execution_admission_command(command)
        actor = ActorContext(actor_context).to_dict()
        # Exact persisted replays are durable facts, not a new authorization.
        # Resolve them before current active-skill, proof, or expiry checks.
        with self._authority_connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_lookup_builtin_execution_authorization(%s::jsonb, %s::jsonb)",
                (_json(actor), _json(wire)),
            )
            row = cursor.fetchone()
            if row is not None and row[0] is not None:
                return _authorization(row[0]).snapshot(replayed=True)
        skill_id = wire["skill_id"]
        active = self._resolver.resolve_active_skill(actor_context=actor, skill_id=skill_id)
        if active is None:
            raise ExecutionAdmissionError("execution skill is not active")
        now = self._clock().astimezone(timezone.utc)
        actor, request, policy, approvals = _parse_command(
            actor_context=actor,
            command=wire,
            active=active,
            now=now,
            approval_verifier=self._approval_verifier,
            approval_trust=self._approval_trust,
            registry=_STATIC_BUILTIN_REGISTRY,
        )
        with self._authority_connect() as connection, connection.cursor() as cursor:
            grant = _grant(
                actor=actor,
                request=request,
                policy=policy,
                approvals=approvals,
                now=now,
                ids=self._ids,
                nonce=self._nonce,
                issuer=self._grant_issuer,
                verifier=self._grant_verifier,
                trust_factory=self._grant_trust,
                validity_expires_at=wire["validity"]["expires_at"],
                retention_expires_at=wire["retention"]["expires_at"],
            )
            grant_digest = sha256_digest(grant)
            writer_binding = {
                "purpose": "issue",
                "operation_id": wire["operation_id"],
                "operation_digest": wire["operation_digest"],
                "command_digest": sha256_digest(wire),
                "grant_digest": grant_digest,
                "request_id": request["request_id"],
                "request_digest": request["request_digest"],
            }
        with (
            self._evidence_writer_connect() as writer_connection,
            writer_connection.cursor() as writer_cursor,
        ):
            writer_cursor.execute(
                "SELECT gah_authorize_builtin_execution(%s::jsonb, %s::jsonb)",
                (_json(actor), _json(writer_binding)),
            )
            writer_row = writer_cursor.fetchone()
            if writer_row is None or writer_row[0] is None:
                raise ExecutionAdmissionError("execution writer authorization is unavailable")
            writer_authorization = writer_row[0]
            with (
                self._authority_connect() as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute(
                    "SELECT gah_lookup_builtin_execution_authorization(%s::jsonb, %s::jsonb)",
                    (_json(actor), _json(wire)),
                )
                replay = cursor.fetchone()
                if replay is not None and replay[0] is not None:
                    return _authorization(replay[0]).snapshot(replayed=True)
                cursor.execute(
                    "SELECT to_char(date_trunc('milliseconds', transaction_timestamp()) "
                    "AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')"
                )
                accepted_row = cursor.fetchone()
                if accepted_row is None or not isinstance(accepted_row[0], str):
                    raise ExecutionAdmissionError("execution acceptance time is unavailable")
                accepted_at = accepted_row[0]

                def proof_acceptance(
                    record: Mapping[str, Any], digest_field: str
                ) -> Mapping[str, Any]:
                    cursor.execute(
                        "SELECT gah_verify_execution_signed_record(%s::jsonb, %s, %s::timestamptz)",
                        (_json(record), digest_field, accepted_at),
                    )
                    row = cursor.fetchone()
                    if row is None or not isinstance(row[0], Mapping):
                        raise ExecutionAdmissionError("execution proof acceptance is unavailable")
                    return copy.deepcopy(dict(row[0]))

                proof_acceptances = {
                    "accepted_at": accepted_at,
                    "approval": proof_acceptance(approvals[0], "approval_digest"),
                    "grant": proof_acceptance(grant, "grant_digest"),
                }
                payload = {
                    "actor_id": actor["actor_id"],
                    "operation_id": wire["operation_id"],
                    "operation_digest": wire["operation_digest"],
                    "command": wire,
                    "authorization_grant": grant,
                    "authorization_grant_digest": grant_digest,
                    "proof_acceptances": proof_acceptances,
                    "writer_authorization": writer_authorization,
                    "state": "authorized",
                }
                evidence = _build_evidence(
                    actor=actor,
                    run_id=request["run_id"],
                    event_kind="execution.authorization_issued",
                    policy=policy,
                    payload=payload,
                    head=_head(cursor, actor, request["run_id"]),
                    clock=lambda: _parse_time(accepted_at),
                    ids=self._ids,
                )
                cursor.execute(
                    "SELECT gah_issue_builtin_execution_authorization"
                    "(%s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)",
                    (
                        _json(actor),
                        _json(wire),
                        _json(grant),
                        _json(evidence),
                        _json(writer_authorization),
                    ),
                )
                row = cursor.fetchone()
        return _authorization(row[0] if row is not None else None)

    def rebuild(
        self, *, actor_context: Mapping[str, Any], operation_id: str, operation_digest: str
    ) -> ExecutionAuthorization:
        actor = ActorContext(actor_context).to_dict()
        with self._authority_connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_rebuild_builtin_execution(%s::jsonb, %s::jsonb)",
                (
                    _json(actor),
                    _json(
                        {
                            "operation_id": operation_id,
                            "operation_digest": operation_digest,
                        }
                    ),
                ),
            )
            row = cursor.fetchone()
        return _authorization(row[0] if row is not None else None)


class PostgresBuiltinExecutionRuntime:
    """Runtime port exposing only exact begin, complete, replay, and recovery."""

    def __init__(
        self,
        *,
        runtime_connect: Callable[[], _Connection],
        clock: Callable[[], datetime] | None = None,
        ids: Callable[[], str] | None = None,
        lease_duration: timedelta = timedelta(seconds=30),
    ) -> None:
        if lease_duration <= timedelta(0):
            raise ValueError("execution lease duration must be positive")
        self._connect = runtime_connect
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ids = ids or _Ids(self._clock)
        self._lease_duration = lease_duration

    def invoke(
        self, *, actor_context: Mapping[str, Any], authorization: ExecutionAuthorization
    ) -> BuiltinExecution:
        actor = ActorContext(actor_context).to_dict()
        command = _runtime_command(authorization.command)
        request = ToolRequest(command["tool_request"], expected_tenant=actor["tenant_id"]).to_dict()
        policy = PolicyDecision(
            command["policy_decision"], expected_tenant=actor["tenant_id"]
        ).to_dict()
        active = ActiveSkillDigest(
            command["skill_id"], command["revision"], command["artifact_digest"]
        )
        _STATIC_BUILTIN_REGISTRY.validate(active=active, request=request)
        start_payload = {
            "actor_id": actor["actor_id"],
            "operation_id": command["operation_id"],
            "operation_digest": command["operation_digest"],
            "authorization_grant_digest": sha256_digest(authorization.grant),
            "skill_id": active.skill_id,
            "revision": active.revision,
            "artifact_digest": active.artifact_digest,
            "state": "executing",
        }
        with self._connect() as connection, connection.cursor() as cursor:
            head = _head(cursor, actor, request["run_id"])
            intent = _build_evidence(
                actor=actor,
                run_id=request["run_id"],
                event_kind="execution.intent",
                policy=policy,
                payload=start_payload,
                head=head,
                clock=self._clock,
                ids=self._ids,
            )
            cursor.execute(
                "SELECT gah_begin_builtin_execution(%s::jsonb, %s::jsonb, %s::jsonb, %s)",
                (
                    _json(actor),
                    _json(
                        {
                            "operation_id": command["operation_id"],
                            "operation_digest": command["operation_digest"],
                            "command": command,
                            "grant": authorization.grant,
                        }
                    ),
                    _json(intent),
                    self._lease_duration.total_seconds(),
                ),
            )
            started = cursor.fetchone()[0]
        if started["replayed"]:
            return BuiltinExecution(
                started["outcome"],
                started["intent_evidence"],
                started["outcome_evidence"],
                True,
            ).snapshot()
        result_payload = _STATIC_BUILTIN_REGISTRY.invoke(request=request)
        outcome = self._outcome(
            actor=actor,
            request=request,
            policy=policy,
            approvals=tuple(command["approvals"]),
            grant=authorization.grant,
            intent=started["intent_evidence"],
            result_payload=result_payload,
            status="succeeded",
        )
        outcome_payload = {
            "actor_id": actor["actor_id"],
            "operation_id": command["operation_id"],
            "operation_digest": command["operation_digest"],
            "authorization_grant_digest": sha256_digest(authorization.grant),
            "outcome_digest": outcome["outcome_digest"],
            "status": "succeeded",
            "state": "completed",
            "outcome": outcome,
        }
        with self._connect() as connection, connection.cursor() as cursor:
            evidence = _build_evidence(
                actor=actor,
                run_id=request["run_id"],
                event_kind="execution.outcome",
                policy=policy,
                payload=outcome_payload,
                head=_head(cursor, actor, request["run_id"]),
                clock=self._clock,
                ids=self._ids,
            )
            cursor.execute(
                "SELECT gah_complete_builtin_execution(%s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)",
                (
                    _json(actor),
                    _json(
                        {
                            "operation_id": command["operation_id"],
                            "operation_digest": command["operation_digest"],
                            "attempt_id": started["attempt_id"],
                            "owner_generation": started["owner_generation"],
                        }
                    ),
                    _json(outcome),
                    _json(evidence),
                ),
            )
            completed = cursor.fetchone()[0]
        return BuiltinExecution(
            completed["outcome"],
            completed["intent_evidence"],
            completed["outcome_evidence"],
            bool(completed["replayed"]),
        ).snapshot()

    def recover(
        self, *, actor_context: Mapping[str, Any], authorization: ExecutionAuthorization
    ) -> BuiltinExecution:
        actor = ActorContext(actor_context).to_dict()
        command = _runtime_command(authorization.command)
        request = ToolRequest(command["tool_request"], expected_tenant=actor["tenant_id"]).to_dict()
        policy = PolicyDecision(
            command["policy_decision"], expected_tenant=actor["tenant_id"]
        ).to_dict()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_lookup_builtin_execution(%s::jsonb, %s::jsonb)",
                (
                    _json(actor),
                    _json(
                        {
                            "operation_id": command["operation_id"],
                            "operation_digest": command["operation_digest"],
                            "grant_digest": sha256_digest(authorization.grant),
                        }
                    ),
                ),
            )
            stored = cursor.fetchone()[0]
            if stored["state"] in {"completed", "indeterminate"}:
                return BuiltinExecution(
                    stored["outcome"],
                    stored["intent_evidence"],
                    stored["outcome_evidence"],
                    True,
                ).snapshot()
            if not isinstance(stored["intent_evidence"], Mapping):
                raise ExecutionAdmissionError("execution recovery requires a persisted intent")
            outcome = self._outcome(
                actor=actor,
                request=request,
                policy=policy,
                approvals=tuple(command["approvals"]),
                grant=authorization.grant,
                intent=stored["intent_evidence"],
                result_payload={"error": "execution_outcome_unknown"},
                status="indeterminate",
            )
            payload = {
                "actor_id": actor["actor_id"],
                "operation_id": command["operation_id"],
                "operation_digest": command["operation_digest"],
                "authorization_grant_digest": sha256_digest(authorization.grant),
                "outcome_digest": outcome["outcome_digest"],
                "status": "indeterminate",
                "state": "indeterminate",
                "outcome": outcome,
            }
            evidence = _build_evidence(
                actor=actor,
                run_id=request["run_id"],
                event_kind="execution.outcome",
                policy=policy,
                payload=payload,
                head=_head(cursor, actor, request["run_id"]),
                clock=self._clock,
                ids=self._ids,
            )
            cursor.execute(
                "SELECT gah_recover_builtin_execution(%s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)",
                (
                    _json(actor),
                    _json(
                        {
                            "operation_id": command["operation_id"],
                            "operation_digest": command["operation_digest"],
                        }
                    ),
                    _json(outcome),
                    _json(evidence),
                ),
            )
            result = cursor.fetchone()[0]
        return BuiltinExecution(
            result["outcome"],
            result["intent_evidence"],
            result["outcome_evidence"],
            bool(result["replayed"]),
        ).snapshot()

    def _outcome(
        self,
        *,
        actor: Mapping[str, Any],
        request: Mapping[str, Any],
        policy: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...],
        grant: Mapping[str, Any],
        intent: Mapping[str, Any],
        result_payload: Mapping[str, Any],
        status: str,
    ) -> dict[str, Any]:
        if not isinstance(intent, Mapping):
            raise ExecutionAdmissionError("execution outcome requires a persisted intent")
        try:
            intent_recorded_at = _parse_time(intent["recorded_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ExecutionAdmissionError(
                "execution outcome requires a valid persisted intent"
            ) from exc
        clock_time = _parse_time(_utc(self._clock()))
        occurred_at = _utc(max(clock_time, intent_recorded_at))
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
            "tenant_id": actor["tenant_id"],
            "outcome_id": self._ids(),
            "target_scope": scope,
            "run_id": request["run_id"],
            "request_ref": _ref("tool_request", request["request_id"], request["request_digest"]),
            "status": status,
            "effect_state": status,
            "evidence_refs": [
                _ref("evidence_envelope", intent["envelope_id"], intent["event_digest"])
            ],
            "provenance_digest": sha256_digest(
                {
                    "authorization_grant_digest": sha256_digest(grant),
                    "intent_evidence_digest": intent["event_digest"],
                    "result_payload": result_payload,
                }
            ),
            "result_payload": copy.deepcopy(dict(result_payload)),
            "producer_version": "builtin_execution.v1",
            "runtime_version": "phase5.1.local.v1",
            "policy_refs": [
                _ref("policy_decision", policy["decision_id"], policy["decision_digest"])
            ],
            "reviewer_refs": [
                _ref("approval_record", value["approval_id"], value["approval_digest"])
                for value in approvals
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
        return ActionOutcome(outcome, expected_tenant=actor["tenant_id"]).to_dict()


__all__ = [
    "BUILTIN_ECHO_ARTIFACT",
    "BUILTIN_ECHO_ARTIFACT_DIGEST",
    "BUILTIN_ECHO_TOOL_ID",
    "BUILTIN_ECHO_TOOL_VERSION",
    "BuiltinExecution",
    "BuiltinHandlerRegistry",
    "ExecutionAdmissionError",
    "ExecutionAuthorization",
    "PostgresBuiltinExecutionRuntime",
    "PostgresExecutionAdmissionAuthority",
    "build_execution_admission_command",
    "execution_operation_digest",
]
