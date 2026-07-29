"""Narrow PostgreSQL ports for an inert, governed skill lifecycle.

The runtime may resolve only an active revision digest.  It cannot read skill
artifacts or invoke lifecycle functions.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from governed_agent_harness.contracts import (
    DetachedProofVerifier,
    TrustContext,
    sha256_digest,
    skill_lifecycle_operation_digest,
    validate_skill_lifecycle_command,
)
from .store import PostgresDurableEffectStore


class SkillLifecycleState(str, Enum):
    INSTALLED = "installed"
    ACTIVE = "active"
    INACTIVE = "inactive"


@dataclass(frozen=True, slots=True)
class SkillLifecycleResult:
    operation_id: str
    operation_digest: str
    skill_id: str
    revision: int
    lifecycle_state: SkillLifecycleState
    artifact_digest: str
    transition_digest: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class ActiveSkillDigest:
    skill_id: str
    revision: int
    artifact_digest: str


class SkillLifecycleAuthority(Protocol):
    """Authority-only mutation port; it is intentionally absent from runtime ports."""

    def install_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult: ...
    def activate_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult: ...
    def rollback_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult: ...
    def deactivate_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult: ...
    def rebuild_skill_projection(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult: ...


class ActiveSkillResolver(Protocol):
    def resolve_active_skill(
        self, *, actor_context: Mapping[str, Any], skill_id: str
    ) -> ActiveSkillDigest | None: ...


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class _SkillEvidenceIds:
    """Generate distinct UUIDv7 identifiers when callers do not inject test IDs."""

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


def build_skill_lifecycle_wire_command(
    operation: str, command: Mapping[str, Any]
) -> dict[str, Any]:
    """Construct the one canonical command shape used by Python and SQL."""

    if "operation" in command or "operation_digest" in command:
        raise ValueError("callers must not supply lifecycle wire fields")
    wire = {"operation": operation, **dict(command)}
    wire["operation_digest"] = skill_lifecycle_operation_digest(wire)
    return wire


def _historical_replay_actor_binding_matches(
    actor_context: Mapping[str, Any],
    wire: Mapping[str, Any],
    operation: str,
) -> bool:
    if operation == "rebuild":
        return True
    proposal = wire.get("skill_proposal")
    if not isinstance(proposal, Mapping):
        return False
    scope = proposal.get("target_scope")
    if not isinstance(scope, Mapping):
        return False
    return (
        actor_context.get("record_type") == "actor_context"
        and proposal.get("tenant_id") == actor_context.get("tenant_id")
        and scope.get("actor_id") == actor_context.get("actor_id")
        and scope.get("selection") == {"level": "actor"}
        and scope.get("parent_digest") == sha256_digest(dict(actor_context))
    )


def _result(
    value: Any,
    *,
    expected_operation_id: str,
    expected_digest: str,
    expected_skill_id: str,
    expected_revision: int | None = None,
    expected_state: SkillLifecycleState | None = None,
    expected_artifact_digest: str | None = None,
    expected_transition_digest: str | None = None,
) -> SkillLifecycleResult:
    """Accept only the narrow, authority-bound lifecycle response shape."""

    fields = {
        "operation_id",
        "operation_digest",
        "skill_id",
        "revision",
        "lifecycle_state",
        "artifact_digest",
        "transition_digest",
        "replayed",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimeError("skill lifecycle authority returned an incomplete result")
    if (
        value["operation_id"] != expected_operation_id
        or value["operation_digest"] != expected_digest
        or value["skill_id"] != expected_skill_id
        or not isinstance(value["revision"], int)
        or value["revision"] < 1
    ):
        raise RuntimeError("skill lifecycle authority returned a mismatched result")
    if not all(
        isinstance(value[field], str) and value[field]
        for field in (
            "operation_id",
            "operation_digest",
            "skill_id",
            "artifact_digest",
            "transition_digest",
        )
    ):
        raise RuntimeError("skill lifecycle authority returned a malformed result")
    if not all(
        re.fullmatch(r"sha256:[0-9a-f]{64}", value[field])
        for field in ("operation_digest", "artifact_digest", "transition_digest")
    ):
        raise RuntimeError("skill lifecycle authority returned an invalid digest")
    if expected_transition_digest is not None and (
        value["transition_digest"] != expected_transition_digest
    ):
        raise RuntimeError("skill lifecycle authority returned an unbound transition")
    if expected_revision is not None and value["revision"] != expected_revision:
        raise RuntimeError("skill lifecycle authority returned an unbound revision")
    if expected_artifact_digest is not None and (
        value["artifact_digest"] != expected_artifact_digest
    ):
        raise RuntimeError("skill lifecycle authority returned an unbound artifact")
    if not isinstance(value["replayed"], bool):
        raise RuntimeError("skill lifecycle authority returned a malformed replay flag")
    try:
        state = SkillLifecycleState(value["lifecycle_state"])
    except ValueError as error:
        raise RuntimeError("skill lifecycle authority returned an unknown state") from error
    if expected_state is not None and state is not expected_state:
        raise RuntimeError("skill lifecycle authority returned an unbound state")
    return SkillLifecycleResult(
        operation_id=value["operation_id"],
        operation_digest=value["operation_digest"],
        skill_id=value["skill_id"],
        revision=value["revision"],
        lifecycle_state=state,
        artifact_digest=value["artifact_digest"],
        transition_digest=value["transition_digest"],
        replayed=value["replayed"],
    )


class PostgresSkillLifecycleAuthority:
    """Privileged wrapper over fixed SECURITY DEFINER lifecycle functions."""

    def __init__(
        self,
        *,
        privileged_connect: Callable[[], Any],
        evidence_writer_connect: Callable[[], Any],
        clock: Callable[[], datetime] | None = None,
        ids: Callable[[], str] | None = None,
        approval_verifier: DetachedProofVerifier | None = None,
        approval_trust: Callable[[datetime], TrustContext] | None = None,
        receipt_verifier: DetachedProofVerifier | None = None,
        receipt_trust: Callable[[datetime], TrustContext] | None = None,
    ) -> None:
        if evidence_writer_connect is privileged_connect:
            raise ValueError("lifecycle and evidence-writer connection factories must be distinct")
        self._privileged_connect = privileged_connect
        self._evidence_writer_connect = evidence_writer_connect
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        # Lifecycle evidence is append-only, so the default must be a genuine
        # per-event identifier generator rather than a replay-prone constant.
        self._ids = ids or _SkillEvidenceIds(self._clock)
        self._approval_verifier = approval_verifier
        self._approval_trust = approval_trust
        self._receipt_verifier = receipt_verifier
        self._receipt_trust = receipt_trust

    def install_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult:
        return self._call("gah_install_skill", "install", actor_context, command)

    def activate_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult:
        return self._call("gah_activate_skill", "activate", actor_context, command)

    def rollback_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult:
        return self._call("gah_rollback_skill", "rollback", actor_context, command)

    def deactivate_skill(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult:
        return self._call("gah_deactivate_skill", "deactivate", actor_context, command)

    def rebuild_skill_projection(
        self, *, actor_context: Mapping[str, Any], **command: Any
    ) -> SkillLifecycleResult:
        return self._call("gah_rebuild_skill_projection", "rebuild", actor_context, command)

    def _call(
        self,
        function: str,
        operation: str,
        actor_context: Mapping[str, Any],
        command: Mapping[str, Any],
    ) -> SkillLifecycleResult:
        wire = build_skill_lifecycle_wire_command(operation, command)
        digest = wire["operation_digest"]
        expected_transition_digest = None
        if _historical_replay_actor_binding_matches(actor_context, wire, operation):
            with self._privileged_connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT gah_lookup_skill_replay(%s::jsonb, %s::jsonb)",
                    (_json(actor_context), _json(wire)),
                )
                replay = cursor.fetchone()
                if replay is not None and replay[0] is not None:
                    return _result(
                        replay[0],
                        expected_operation_id=wire["operation_id"],
                        expected_digest=digest,
                        expected_skill_id=wire["skill_id"]
                        if operation == "rebuild"
                        else wire["skill_proposal"]["artifact_id"],
                        **_expected_result_bindings(operation, wire),
                    )
        digest = validate_skill_lifecycle_command(
            actor_context=actor_context,
            command=wire,
            now=self._clock(),
            approval_verifier=self._approval_verifier,
            approval_trust=self._approval_trust,
            receipt_verifier=self._receipt_verifier,
            receipt_trust=self._receipt_trust,
        )
        if operation == "rebuild":
            with self._privileged_connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT {function}(%s::jsonb, %s::jsonb)",
                    (_json(actor_context), _json(wire)),
                )
                row = cursor.fetchone()
        else:
            with (
                self._evidence_writer_connect() as writer_connection,
                writer_connection.cursor() as writer_cursor,
            ):
                writer_cursor.execute(
                    "SELECT gah_authorize_skill_lifecycle(%s::jsonb, %s::jsonb)",
                    (_json(actor_context), _json(wire)),
                )
                authorization_row = writer_cursor.fetchone()
                if authorization_row is None or authorization_row[0] is None:
                    raise RuntimeError("skill lifecycle writer authorization is unavailable")
                authorization = authorization_row[0]
                proposal = wire["skill_proposal"]
                policy = wire["policy_decision"]
                skill_id = proposal["artifact_id"]
                store = PostgresDurableEffectStore(
                    connect=self._privileged_connect,
                    privileged_connect=self._privileged_connect,
                    clock=self._clock,
                    ids=self._ids,
                )
                policy_ref = {
                    "record_type": "policy_decision",
                    "record_id": policy["decision_id"],
                    "record_digest": policy["decision_digest"],
                }
                ledger_payload = {
                    "actor_id": actor_context["actor_id"],
                    "operation_id": wire["operation_id"],
                    "operation_digest": digest,
                    "skill_id": skill_id,
                    "command": wire,
                    "writer_authorization": authorization,
                }
                with self._privileged_connect() as connection, connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT gah_lookup_skill_replay(%s::jsonb, %s::jsonb)",
                        (_json(actor_context), _json(wire)),
                    )
                    replay = cursor.fetchone()
                    if replay is not None and replay[0] is not None:
                        row = replay
                    else:
                        cursor.execute(
                            "SELECT gah_skill_lifecycle_evidence_head(%s::jsonb)",
                            (_json(actor_context),),
                        )
                        head = cursor.fetchone()
                        if head is None or head[0] is None:
                            raise RuntimeError(
                                "skill lifecycle evidence authority head is unavailable"
                            )
                        evidence, _version = store._build_evidence_from_head(
                            actor=actor_context,
                            run_id=actor_context["session_id"],
                            event_kind="skill.lifecycle_transition",
                            policy_ref=policy_ref,
                            payload=ledger_payload,
                            head=head[0],
                        )
                        wire = {**wire, "transition_evidence": evidence}
                        expected_transition_digest = evidence["event_digest"]
                        cursor.execute(
                            f"SELECT {function}(%s::jsonb, %s::jsonb)",
                            (_json(actor_context), _json(wire)),
                        )
                        row = cursor.fetchone()
        return _result(
            row[0] if row is not None else None,
            expected_operation_id=wire["operation_id"],
            expected_digest=digest,
            expected_skill_id=wire["skill_id"]
            if operation == "rebuild"
            else wire["skill_proposal"]["artifact_id"],
            expected_transition_digest=expected_transition_digest,
            **_expected_result_bindings(operation, wire),
        )


def _expected_result_bindings(operation: str, wire: Mapping[str, Any]) -> dict[str, Any]:
    """Bind lifecycle replies to postconditions already fixed by the command.

    Rebuild intentionally derives its result from durable history, so only the
    lifecycle operations with command-fixed postconditions are bound here.
    """

    if operation == "rebuild":
        return {}
    state = {
        "install": SkillLifecycleState.INSTALLED,
        "activate": SkillLifecycleState.ACTIVE,
        "rollback": SkillLifecycleState.ACTIVE,
        "deactivate": SkillLifecycleState.INACTIVE,
    }[operation]
    return {
        "expected_revision": wire["delivery_envelope"]["artifact_revision"],
        "expected_state": state,
        "expected_artifact_digest": wire["delivery_envelope"]["artifact_digest"],
    }


class PostgresActiveSkillResolver:
    """Runtime-only actor-scoped lookup with no artifact content exposure."""

    def __init__(self, *, runtime_connect: Callable[[], Any]) -> None:
        self._runtime_connect = runtime_connect

    def resolve_active_skill(
        self, *, actor_context: Mapping[str, Any], skill_id: str
    ) -> ActiveSkillDigest | None:
        with self._runtime_connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_resolve_active_skill(%s::jsonb, %s::jsonb)",
                (_json(actor_context), _json({"skill_id": skill_id})),
            )
            row = cursor.fetchone()
        value = row[0] if row is not None else None
        if value is None:
            return None
        if not isinstance(value, Mapping) or set(value) != {
            "skill_id",
            "revision",
            "artifact_digest",
        }:
            raise RuntimeError("active skill resolver returned a non-narrow result")
        if not isinstance(value["revision"], int):
            raise RuntimeError("active skill resolver returned a malformed revision")
        return ActiveSkillDigest(value["skill_id"], value["revision"], value["artifact_digest"])


__all__ = [
    "ActiveSkillDigest",
    "ActiveSkillResolver",
    "PostgresActiveSkillResolver",
    "PostgresSkillLifecycleAuthority",
    "SkillLifecycleAuthority",
    "SkillLifecycleResult",
    "SkillLifecycleState",
    "build_skill_lifecycle_wire_command",
]
