"""Real-PostgreSQL proof for the bounded Phase 5.1 built-in execution path."""

from __future__ import annotations

import base64
import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from unittest.mock import patch

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

import governed_agent_harness.persistence.execution as execution_module
from governed_agent_harness.contracts import (
    TrustContext,
    TrustedKey,
    apply_object_digest,
    canonical_bytes,
    sha256_digest,
    unsigned_body,
)
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import (
    BUILTIN_ECHO_ARTIFACT_DIGEST,
    BUILTIN_ECHO_TOOL_ID,
    BUILTIN_ECHO_TOOL_VERSION,
    BuiltinHandlerRegistry,
    ExecutionAuthorization,
    PostgresActiveSkillResolver,
    PostgresBuiltinExecutionRuntime,
    PostgresDurableEffectStore,
    PostgresExecutionAdmissionAuthority,
    PostgresSkillLifecycleAuthority,
    execution_operation_digest,
)
from governed_agent_harness.persistence.skills import build_skill_lifecycle_wire_command
from skill_lifecycle_support import command as build_skill_command, ref


NOW = datetime.now(timezone.utc)
_ID_STATE = [0xD000]
_ID_LOCK = threading.Lock()


_TEST_SIGNING_SEED = bytes.fromhex(
    "2f4b0b6f0906b7c5e3f0a25e7c5c9ddbcf8d175b75a5a09b2a1dc38841f47c72"
)
_TEST_ALGORITHM = "ed25519-rfc8032-gah-cjson-v1"


def _proof_frame(
    *,
    issuer: str,
    key_id: str,
    algorithm: str,
    proof_domain: str,
    object_digest: str,
    nonce: str,
    unsigned_bytes: bytes,
) -> bytes:
    """Return the frozen detached-proof frame used by this Phase 5.1 test."""

    return canonical_bytes(
        {
            "protocol": "gah.detached-proof.v1",
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": algorithm,
            "proof_domain": proof_domain,
            "object_digest": object_digest,
            "nonce": nonce,
            "unsigned_record": json.loads(unsigned_bytes),
        }
    )


def _signature_text(signature: bytes) -> str:
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def _signature_bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class DeterministicEd25519Verifier:
    """Test-only verifier backed by a fixed non-production Ed25519 key."""

    def __init__(self) -> None:
        self._verify_key = SigningKey(_TEST_SIGNING_SEED).verify_key

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
        if algorithm != _TEST_ALGORITHM:
            return False
        try:
            signature = _signature_bytes(detached_proof)
            if len(signature) != 64:
                return False
            self._verify_key.verify(
                _proof_frame(
                    issuer=issuer,
                    key_id=key_id,
                    algorithm=algorithm,
                    proof_domain=proof_domain,
                    object_digest=object_digest,
                    nonce=nonce,
                    unsigned_bytes=unsigned_bytes,
                ),
                signature,
            )
        except (BadSignatureError, TypeError, ValueError):
            return False
        return True


def _sign_record(
    record: Mapping[str, Any],
    *,
    issuer: str,
    key_id: str,
    proof_domain: str,
    nonce: str,
) -> dict[str, Any]:
    """Attach a deterministic test-only detached Ed25519 signature."""

    signed = copy.deepcopy(dict(record))
    signed["proof"] = {
        "issuer": issuer,
        "key_id": key_id,
        "algorithm": _TEST_ALGORITHM,
        "proof_domain": proof_domain,
        "object_digest": "sha256:" + "0" * 64,
        "nonce": nonce,
        "detached_proof": "A" * 86,
    }
    apply_object_digest(signed)
    proof = signed["proof"]
    signature = (
        SigningKey(_TEST_SIGNING_SEED)
        .sign(
            _proof_frame(
                issuer=proof["issuer"],
                key_id=proof["key_id"],
                algorithm=proof["algorithm"],
                proof_domain=proof["proof_domain"],
                object_digest=proof["object_digest"],
                nonce=proof["nonce"],
                unsigned_bytes=canonical_bytes(unsigned_body(signed)),
            )
        )
        .signature
    )
    proof["detached_proof"] = _signature_text(signature)
    return signed


class DeterministicGrantIssuer:
    def issue(self, *, unsigned_grant: Mapping[str, Any]) -> Mapping[str, Any]:
        return _sign_record(
            unsigned_grant,
            issuer="policy.authority",
            key_id="policy.key.v1",
            proof_domain="authorization_grant.v1",
            nonce="N" * 22,
        )


def _ids():
    def next_id() -> str:
        with _ID_LOCK:
            _ID_STATE[0] += 1
            return f"018f0000-0000-7000-8000-{_ID_STATE[0]:012x}"

    return next_id


def _ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="policy.authority",
                key_id="policy.key.v1",
                algorithms=frozenset({_TEST_ALGORITHM}),
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
            ),
        ),
        allowed_algorithms=frozenset({_TEST_ALGORITHM}),
        allowed_proof_domains=frozenset({"approval_record.v1", "authorization_grant.v1"}),
        expected_issuers=frozenset({"policy.authority"}),
        allowed_domain_issuers=frozenset(
            {
                ("approval_record.v1", "policy.authority"),
                ("authorization_grant.v1", "policy.authority"),
            }
        ),
        trust_policy_version="phase5.1.test.v1",
    )


def _receipt_trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="runtime.authority",
                key_id="runtime.key.v1",
                algorithms=frozenset({_TEST_ALGORITHM}),
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
            ),
        ),
        allowed_algorithms=frozenset({_TEST_ALGORITHM}),
        allowed_proof_domains=frozenset({"activation_receipt.v1"}),
        expected_issuers=frozenset({"runtime.authority"}),
        allowed_domain_issuers=frozenset({("activation_receipt.v1", "runtime.authority")}),
        trust_policy_version="phase5.1.receipt.v1",
    )


def _persisted_skill(
    postgres_connections,
    *,
    retention_expires_at: str | None = None,
    actor_expires_at: str = "2030-01-01T00:00:00.000Z",
    actor_id: str | None = None,
    session_id: str | None = None,
    provision: bool = False,
    database_roles: tuple[str, ...] = (
        "gah_app",
        "gah_writer",
        "gah_skill_authority",
        "gah_execution_authority",
    ),
):
    actor, command = build_skill_command()
    if retention_expires_at is not None:
        command["retention"]["expires_at"] = retention_expires_at
    actor["issued_at"] = "2026-01-01T00:00:00.000Z"
    actor["expires_at"] = actor_expires_at
    if actor_id is not None:
        actor["actor_id"] = actor_id
    if session_id is not None:
        actor["session_id"] = session_id
        actor["correlation_id"] = session_id
    if provision:
        import psycopg

        with postgres_connections["admin"]() as connection:
            dsn = connection.info.dsn
        PostgresDurableEffectStore.provision_principal(
            admin_connect=lambda: psycopg.connect(dsn),
            database_roles=database_roles,
            actor_context=actor,
        )
    target_scope = command["skill_proposal"]["target_scope"]
    target_scope["actor_id"] = actor["actor_id"]
    target_scope["parent_digest"] = sha256_digest(actor)
    target_scope["valid_until"] = actor["expires_at"]
    command["gate_decision"]["target_scope"] = copy.deepcopy(target_scope)
    command["delivery_envelope"]["target_scope"] = copy.deepcopy(target_scope)
    source = postgres_connections["store_at"](NOW).append(
        tenant_id=actor["tenant_id"],
        run_id=actor["session_id"],
        event_kind="kernel.policy_decided",
        policy_ref={
            "record_type": "policy_decision",
            "record_id": command["policy_decision"]["decision_id"],
            "record_digest": command["policy_decision"]["decision_digest"],
        },
        payload={
            "actor_id": actor["actor_id"],
            "policy_decision_digest": command["policy_decision"]["decision_digest"],
        },
    )
    evidence_ref = ref("evidence_envelope", source["envelope_id"], source["event_digest"])
    command["source_evidence"] = [source]
    proposal = command["skill_proposal"]
    proposal["evidence_refs"] = [evidence_ref]
    apply_object_digest(proposal)
    policy = command["policy_decision"]
    policy["request_digest"] = proposal["proposal_digest"]
    apply_object_digest(policy)
    gate = command["gate_decision"]
    gate["proposal_refs"] = [
        ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
    ]
    apply_object_digest(gate)
    delivery = command["delivery_envelope"]
    delivery.update(
        {
            "evidence_refs": [evidence_ref],
            "policy_refs": [
                ref("policy_decision", policy["decision_id"], policy["decision_digest"])
            ],
            "gate_decision_ref": ref("gate_decision", gate["gate_id"], gate["decision_digest"]),
            "issued_at": _ts(NOW - timedelta(minutes=10)),
            "expires_at": _ts(NOW + timedelta(days=1)),
        }
    )
    apply_object_digest(delivery)
    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: NOW,
        ids=_ids(),
        receipt_verifier=DeterministicEd25519Verifier(),
        receipt_trust=_receipt_trust,
    )
    authority.install_skill(actor_context=actor, **command)
    receipt = copy.deepcopy(build_positive_records()["activation_receipt"])
    receipt.update(
        {
            "target_scope": copy.deepcopy(delivery["target_scope"]),
            "delivery_id": delivery["delivery_id"],
            "delivery_digest": delivery["envelope_digest"],
            "artifact_type": "skill",
            "artifact_id": delivery["artifact_id"],
            "artifact_revision": delivery["artifact_revision"],
            "artifact_digest": delivery["artifact_digest"],
            "activated_revision": ref(
                "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
            ),
            "evidence_refs": copy.deepcopy(delivery["evidence_refs"]),
            "policy_refs": copy.deepcopy(delivery["policy_refs"]),
            "reviewer_refs": copy.deepcopy(delivery["reviewer_refs"]),
            "issued_at": _ts(NOW - timedelta(minutes=1)),
            "expires_at": _ts(NOW + timedelta(days=1)),
        }
    )
    receipt = _sign_record(
        receipt,
        issuer="runtime.authority",
        key_id="runtime.key.v1",
        proof_domain="activation_receipt.v1",
        nonce="R" * 22,
    )
    activate = copy.deepcopy(command)
    activate.update(
        {
            "operation_id": "phase5-skill-activate",
            "expected_revision": 1,
            "activation_receipt": receipt,
        }
    )
    authority.activate_skill(actor_context=actor, **activate)
    return actor, command


def _execution_command(actor, skill_command, *, operation_id="phase5-execution-1"):
    records = build_positive_records()
    request = copy.deepcopy(records["tool_request"])
    request.update(
        {
            "tenant_id": actor["tenant_id"],
            "actor_id": actor["actor_id"],
            "actor_context_digest": sha256_digest(actor),
            "run_id": actor["session_id"],
            "tool_id": BUILTIN_ECHO_TOOL_ID,
            "tool_version": BUILTIN_ECHO_TOOL_VERSION,
            "arguments": {
                "skill_id": skill_command["skill_proposal"]["artifact_id"],
                "revision": 1,
                "artifact_digest": BUILTIN_ECHO_ARTIFACT_DIGEST,
                "input": {"message": "hello"},
            },
            "effect_classes": ["execute_code"],
            "idempotency": {
                "tenant_id": actor["tenant_id"],
                "idempotency_key": f"phase5.{operation_id}",
                "operation_digest": sha256_digest(
                    {"operation_id": operation_id, "input": {"message": "hello"}}
                ),
            },
            "requested_at": _ts(NOW - timedelta(minutes=5)),
        }
    )
    apply_object_digest(request)
    policy = copy.deepcopy(records["policy_decision"])
    policy.update(
        {
            "tenant_id": actor["tenant_id"],
            "request_id": request["request_id"],
            "request_digest": request["request_digest"],
            "decision": "require_approval",
            "constraints": [],
            "isolation_profile": "none",
            "decided_at": _ts(NOW - timedelta(minutes=4)),
        }
    )
    apply_object_digest(policy)
    approval = copy.deepcopy(records["approval_record"])
    approval.update(
        {
            "tenant_id": actor["tenant_id"],
            "request_id": request["request_id"],
            "request_digest": request["request_digest"],
            "policy_decision_id": policy["decision_id"],
            "policy_decision_digest": policy["decision_digest"],
            "constraints": [],
            "separation_of_duties": {
                "required": True,
                "satisfied": True,
                "policy_id": "phase5.sod.v1",
            },
            "issued_at": _ts(NOW - timedelta(minutes=3)),
            "expires_at": "2030-01-01T00:00:00.000Z",
        }
    )
    approval = _sign_record(
        approval,
        issuer="policy.authority",
        key_id="policy.key.v1",
        proof_domain="approval_record.v1",
        nonce="Q" * 22,
    )
    return {
        "operation_id": operation_id,
        "skill_id": skill_command["skill_proposal"]["artifact_id"],
        "revision": 1,
        "artifact_digest": BUILTIN_ECHO_ARTIFACT_DIGEST,
        "tool_request": request,
        "policy_decision": policy,
        "gate_decision": copy.deepcopy(skill_command["gate_decision"]),
        "approvals": [approval],
        "source_evidence": copy.deepcopy(skill_command["source_evidence"]),
        "validity": copy.deepcopy(skill_command["validity"]),
        "retention": copy.deepcopy(skill_command["retention"]),
    }


def _authority(postgres_connections, now=NOW):
    return PostgresExecutionAdmissionAuthority(
        authority_connect=postgres_connections["execution_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        resolver=PostgresActiveSkillResolver(runtime_connect=postgres_connections["app"]),
        grant_issuer=DeterministicGrantIssuer(),
        grant_verifier=DeterministicEd25519Verifier(),
        grant_trust=_trust,
        approval_verifier=DeterministicEd25519Verifier(),
        approval_trust=_trust,
        clock=lambda: now,
        ids=_ids(),
        nonce=lambda: "A" * 22,
    )


def _counts(postgres_connections):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_builtin_execution_state")
        state = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM gah_evidence_events")
        evidence = cursor.fetchone()[0]
    return state, evidence


def _wait_for_writer_run_head_lock(postgres_connections) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with (
            postgres_connections["admin"]() as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_stat_activity "
                "WHERE usename='gah_writer' AND wait_event_type='Lock' "
                "AND position('gah_lock_run' in query) > 0"
                ")"
            )
            if cursor.fetchone()[0]:
                return True
        time.sleep(0.01)
    return False


def _wait_for_writer_commit_lock(postgres_connections) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_stat_activity "
                "WHERE usename='gah_writer' AND wait_event_type='Lock' "
                "AND position('gah_commit_evidence' in query) > 0"
                ")"
            )
            if cursor.fetchone()[0]:
                return True
        time.sleep(0.01)
    return False


def _wait_for_role_query_lock(postgres_connections, role: str, query_fragment: str) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_stat_activity "
                "WHERE usename=%s AND wait_event_type='Lock' "
                "AND position(%s in query) > 0"
                ")",
                (role, query_fragment),
            )
            if cursor.fetchone()[0]:
                return True
        time.sleep(0.01)
    return False


def _wait_for_skill_authority_lock(postgres_connections, query_fragment: str) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with (
            postgres_connections["admin"]() as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_stat_activity "
                "WHERE usename='gah_skill_authority' AND wait_event_type='Lock' "
                "AND position(%s in query) > 0"
                ")",
                (query_fragment,),
            )
            if cursor.fetchone()[0]:
                return True
        time.sleep(0.01)
    return False


def _authorize_lifecycle_writer(cursor, actor, wire):
    cursor.execute(
        "SELECT gah_authorize_skill_lifecycle(%s::jsonb, %s::jsonb)",
        (json.dumps(actor), json.dumps(wire)),
    )
    row = cursor.fetchone()
    assert row is not None and row[0] is not None
    return row[0]


def _snapshot(postgres_connections):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT to_jsonb(state_row) FROM gah_builtin_execution_state AS state_row "
            "ORDER BY tenant_id, operation_id"
        )
        state = cursor.fetchall()
        cursor.execute(
            "SELECT to_jsonb(event_row) FROM gah_evidence_events AS event_row "
            "ORDER BY tenant_id, actor_id, run_id, sequence_number"
        )
        evidence = cursor.fetchall()
        cursor.execute(
            "SELECT to_jsonb(head_row) FROM gah_run_heads AS head_row "
            "ORDER BY tenant_id, actor_id, run_id"
        )
        run_heads = cursor.fetchall()
        cursor.execute(
            "SELECT to_jsonb(key_row) FROM gah_execution_proof_keys AS key_row "
            "ORDER BY issuer, key_id, algorithm, proof_domain"
        )
        trust_keys = cursor.fetchall()
    return state, evidence, run_heads, trust_keys


def _drop_execution_binding_guard(cursor):
    cursor.execute(
        "ALTER TABLE gah_builtin_execution_state "
        "DROP CONSTRAINT gah_builtin_execution_state_actor_binding_guard"
    )


def _restore_execution_binding_guard(cursor):
    cursor.execute(
        "ALTER TABLE gah_builtin_execution_state "
        "ADD CONSTRAINT gah_builtin_execution_state_actor_binding_guard "
        "CHECK (gah_builtin_execution_state_actor_binding_valid("
        "tenant_id,actor_id,run_id,operation_id,operation_digest,"
        "request_id,request_digest,grant_id,grant_digest,skill_id,revision,"
        "artifact_digest,command_json,grant_json,issuance_evidence_json"
        ") IS TRUE)"
    )


def _execution_binding_guard_exists(cursor):
    cursor.execute(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint "
        "WHERE conrelid='gah_builtin_execution_state'::regclass "
        "AND conname='gah_builtin_execution_state_actor_binding_guard')"
    )
    return cursor.fetchone()[0]


def _direct_issue(
    postgres_connections,
    *,
    actor,
    command,
    grant,
    evidence,
    writer_authorization,
):
    with (
        postgres_connections["execution_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT gah_issue_builtin_execution_authorization"
            "(%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb)",
            (
                execution_module._json(actor),
                execution_module._json(command),
                execution_module._json(grant),
                execution_module._json(evidence),
                execution_module._json(writer_authorization),
            ),
        )
        return cursor.fetchone()[0]


def _tamper_proof_field(proof: dict[str, Any], field: str) -> None:
    """Change exactly one syntactically valid proof selector or signature."""

    if field == "issuer":
        proof[field] = "attacker.authority"
    elif field == "key_id":
        proof[field] = "attacker.key.v1"
    elif field == "algorithm":
        proof[field] = "attacker-ed25519-v1"
    elif field == "detached_proof":
        original = proof[field]
        proof[field] = ("A" if original[0] != "A" else "B") + original[1:]
    else:  # pragma: no cover - parametrization is the contract under test.
        raise AssertionError(f"unsupported proof tamper field: {field}")


def _proof_acceptances(postgres_connections, *, approval, grant) -> dict[str, Any]:
    with (
        postgres_connections["execution_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT to_char(date_trunc('milliseconds', transaction_timestamp()) "
            "AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')"
        )
        accepted_row = cursor.fetchone()
        assert accepted_row is not None and isinstance(accepted_row[0], str)
        accepted_at = accepted_row[0]
        values = []
        for record, digest_field in ((approval, "approval_digest"), (grant, "grant_digest")):
            cursor.execute(
                "SELECT gah_verify_execution_signed_record(%s::jsonb,%s,%s::timestamptz)",
                (execution_module._json(record), digest_field, accepted_at),
            )
            row = cursor.fetchone()
            assert row is not None and isinstance(row[0], Mapping)
            values.append(copy.deepcopy(dict(row[0])))
    return {"accepted_at": accepted_at, "approval": values[0], "grant": values[1]}


def _direct_issue_with_live_writer_and_tampered_grant(
    postgres_connections,
    *,
    actor: Mapping[str, Any],
    skill: Mapping[str, Any],
    proof_field: str,
):
    """Issue through SQL while the distinct writer holds the altered grant locks."""

    authority = _authority(postgres_connections)
    command = _execution_command(
        actor,
        skill,
        operation_id=f"phase5-direct-grant-proof-{proof_field}",
    )
    wire = execution_module.build_execution_admission_command(command)
    active = authority._resolver.resolve_active_skill(
        actor_context=actor,
        skill_id=wire["skill_id"],
    )
    assert active is not None
    bound_actor, request, policy, approvals = execution_module._parse_command(
        actor_context=actor,
        command=wire,
        active=active,
        now=NOW,
        approval_verifier=authority._approval_verifier,
        approval_trust=authority._approval_trust,
        registry=execution_module._STATIC_BUILTIN_REGISTRY,
    )
    grant = execution_module._grant(
        actor=bound_actor,
        request=request,
        policy=policy,
        approvals=approvals,
        now=NOW,
        ids=authority._ids,
        nonce=authority._nonce,
        issuer=authority._grant_issuer,
        verifier=authority._grant_verifier,
        trust_factory=authority._grant_trust,
        validity_expires_at=wire["validity"]["expires_at"],
        retention_expires_at=wire["retention"]["expires_at"],
    )
    proof_acceptances = _proof_acceptances(
        postgres_connections,
        approval=wire["approvals"][0],
        grant=grant,
    )
    _tamper_proof_field(grant["proof"], proof_field)
    apply_object_digest(grant)
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
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as writer_cursor,
    ):
        writer_cursor.execute(
            "SELECT gah_authorize_builtin_execution(%s::jsonb, %s::jsonb)",
            (execution_module._json(bound_actor), execution_module._json(writer_binding)),
        )
        writer_row = writer_cursor.fetchone()
        assert writer_row is not None and writer_row[0] is not None
        writer_authorization = writer_row[0]
        with (
            postgres_connections["execution_authority"]() as connection,
            connection.cursor() as cursor,
        ):
            evidence = execution_module._build_evidence(
                actor=bound_actor,
                run_id=request["run_id"],
                event_kind="execution.authorization_issued",
                policy=policy,
                payload={
                    "actor_id": bound_actor["actor_id"],
                    "operation_id": wire["operation_id"],
                    "operation_digest": wire["operation_digest"],
                    "command": wire,
                    "authorization_grant": grant,
                    "authorization_grant_digest": grant_digest,
                    "proof_acceptances": proof_acceptances,
                    "writer_authorization": writer_authorization,
                    "state": "authorized",
                },
                head=execution_module._head(cursor, bound_actor, request["run_id"]),
                clock=lambda: execution_module._parse_time(proof_acceptances["accepted_at"]),
                ids=authority._ids,
            )
        return _direct_issue(
            postgres_connections,
            actor=bound_actor,
            command=wire,
            grant=grant,
            evidence=evidence,
            writer_authorization=writer_authorization,
        )


def _direct_issue_with_live_writer_and_tampered_approval(
    postgres_connections,
    *,
    actor: Mapping[str, Any],
    skill: Mapping[str, Any],
    proof_field: str,
):
    """Direct SQL attack with a changed approval proof and recomputed commitments."""

    authority = _authority(postgres_connections)
    command = _execution_command(
        actor,
        skill,
        operation_id=f"phase5-direct-approval-proof-{proof_field}",
    )
    wire = execution_module.build_execution_admission_command(command)
    active = authority._resolver.resolve_active_skill(
        actor_context=actor,
        skill_id=wire["skill_id"],
    )
    assert active is not None
    bound_actor, request, policy, approvals = execution_module._parse_command(
        actor_context=actor,
        command=wire,
        active=active,
        now=NOW,
        approval_verifier=authority._approval_verifier,
        approval_trust=authority._approval_trust,
        registry=execution_module._STATIC_BUILTIN_REGISTRY,
    )
    grant = execution_module._grant(
        actor=bound_actor,
        request=request,
        policy=policy,
        approvals=approvals,
        now=NOW,
        ids=authority._ids,
        nonce=authority._nonce,
        issuer=authority._grant_issuer,
        verifier=authority._grant_verifier,
        trust_factory=authority._grant_trust,
        validity_expires_at=wire["validity"]["expires_at"],
        retention_expires_at=wire["retention"]["expires_at"],
    )
    proof_acceptances = _proof_acceptances(
        postgres_connections,
        approval=wire["approvals"][0],
        grant=grant,
    )
    if proof_field == "revoked_at":
        wire["approvals"][0]["revoked_at"] = _ts(NOW - timedelta(seconds=1))
        apply_object_digest(wire["approvals"][0])
        wire["approvals"][0]["proof"]["object_digest"] = wire["approvals"][0]["approval_digest"]
    else:
        _tamper_proof_field(wire["approvals"][0]["proof"], proof_field)
    unsigned_command = copy.deepcopy(wire)
    unsigned_command.pop("operation_digest")
    wire["operation_digest"] = execution_operation_digest(unsigned_command)
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
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as writer_cursor,
    ):
        writer_cursor.execute(
            "SELECT gah_authorize_builtin_execution(%s::jsonb, %s::jsonb)",
            (execution_module._json(bound_actor), execution_module._json(writer_binding)),
        )
        writer_row = writer_cursor.fetchone()
        assert writer_row is not None and writer_row[0] is not None
        writer_authorization = writer_row[0]
        with (
            postgres_connections["execution_authority"]() as connection,
            connection.cursor() as cursor,
        ):
            evidence = execution_module._build_evidence(
                actor=bound_actor,
                run_id=request["run_id"],
                event_kind="execution.authorization_issued",
                policy=policy,
                payload={
                    "actor_id": bound_actor["actor_id"],
                    "operation_id": wire["operation_id"],
                    "operation_digest": wire["operation_digest"],
                    "command": wire,
                    "authorization_grant": grant,
                    "authorization_grant_digest": grant_digest,
                    "proof_acceptances": proof_acceptances,
                    "writer_authorization": writer_authorization,
                    "state": "authorized",
                },
                head=execution_module._head(cursor, bound_actor, request["run_id"]),
                clock=lambda: execution_module._parse_time(proof_acceptances["accepted_at"]),
                ids=authority._ids,
            )
        return _direct_issue(
            postgres_connections,
            actor=bound_actor,
            command=wire,
            grant=grant,
            evidence=evidence,
            writer_authorization=writer_authorization,
        )


def test_exact_active_digest_executes_once_and_replays_after_restart(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    authority = _authority(postgres_connections)
    authorization = authority.issue(actor_context=actor, command=command)
    issued_counts = _counts(postgres_connections)
    issuance_replay = authority.issue(actor_context=actor, command=command)
    assert issuance_replay.grant == authorization.grant
    assert issuance_replay.replayed is True
    assert _counts(postgres_connections) == issued_counts
    calls: list[dict[str, Any]] = []
    original = BuiltinHandlerRegistry.invoke

    def counted(registry, *, request):
        calls.append(copy.deepcopy(dict(request)))
        return original(registry, request=request)

    with patch.object(BuiltinHandlerRegistry, "invoke", new=counted):
        first = PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: NOW,
            ids=_ids(),
        ).invoke(actor_context=actor, authorization=authorization)
        replay = PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: NOW,
            ids=_ids(),
        ).invoke(actor_context=actor, authorization=authorization)
    assert first.outcome["result_payload"] == {"echo": {"message": "hello"}}
    assert replay.outcome == first.outcome
    assert replay.replayed is True
    assert len(calls) == 1

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM gah_builtin_execution_state WHERE operation_id=%s",
            (command["operation_id"],),
        )
    rebuilt = authority.rebuild(
        actor_context=actor,
        operation_id=authorization.command["operation_id"],
        operation_digest=authorization.command["operation_digest"],
    )
    with patch.object(BuiltinHandlerRegistry, "invoke", new=counted):
        rebuilt_replay = PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: NOW,
            ids=_ids(),
        ).invoke(actor_context=actor, authorization=rebuilt)
    assert rebuilt_replay.outcome == first.outcome
    assert rebuilt_replay.replayed is True
    assert len(calls) == 1


def test_revoked_approval_is_rejected_before_authority_mutation(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill, operation_id="phase5-revoked-approval-rejected")
    command["approvals"][0]["revoked_at"] = _ts(NOW - timedelta(seconds=1))
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception, match="approval is revoked"):
        _authority(postgres_connections).issue(actor_context=actor, command=command)

    assert _snapshot(postgres_connections) == before


def test_exact_authorization_replay_rejects_admin_poisoned_revoked_approval(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill, operation_id="phase5-poisoned-revoked-replay")
    _authority(postgres_connections).issue(actor_context=actor, command=command)
    try:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            _drop_execution_binding_guard(cursor)
            cursor.execute(
                "SELECT command_json FROM gah_builtin_execution_state "
                "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
                (
                    actor["tenant_id"],
                    actor["actor_id"],
                    command["operation_id"],
                ),
            )
            original_command = cursor.fetchone()[0]
            cursor.execute(
                "UPDATE gah_builtin_execution_state SET command_json=jsonb_set("
                "command_json,'{approvals,0,revoked_at}',to_jsonb(%s::text)) "
                "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s "
                "RETURNING command_json",
                (
                    _ts(NOW - timedelta(seconds=1)),
                    actor["tenant_id"],
                    actor["actor_id"],
                    command["operation_id"],
                ),
            )
            poisoned_command = cursor.fetchone()[0]
        before = _snapshot(postgres_connections)
        with (
            postgres_connections["execution_authority"]() as connection,
            connection.cursor() as cursor,
        ):
            with pytest.raises(
                Exception, match="persisted execution approval is revoked or malformed"
            ):
                cursor.execute(
                    "SELECT gah_lookup_builtin_execution_authorization(%s::jsonb,%s::jsonb)",
                    (
                        execution_module._json(actor),
                        execution_module._json(poisoned_command),
                    ),
                )
        assert _snapshot(postgres_connections) == before
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            if not _execution_binding_guard_exists(cursor):
                cursor.execute(
                    "UPDATE gah_builtin_execution_state SET command_json=%s::jsonb "
                    "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
                    (
                        json.dumps(original_command),
                        actor["tenant_id"],
                        actor["actor_id"],
                        command["operation_id"],
                    ),
                )
                _restore_execution_binding_guard(cursor)


def test_recovery_requires_intent_and_leaves_authorization_consumable(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-recovery-requires-intent"),
    )
    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
    )
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception, match="recovery requires a persisted intent"):
        runtime.recover(actor_context=actor, authorization=authorization)

    assert _snapshot(postgres_connections) == before
    assert (
        runtime.invoke(actor_context=actor, authorization=authorization).outcome["status"]
        == "succeeded"
    )


def test_direct_sql_recovery_rejects_authorized_state_without_intent(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(
            actor, skill, operation_id="phase5-direct-recovery-requires-intent"
        ),
    )
    before = _snapshot(postgres_connections)
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="recovery requires a persisted intent"):
            cursor.execute(
                "SELECT gah_recover_builtin_execution(%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb)",
                (
                    execution_module._json(actor),
                    execution_module._json(
                        {
                            "operation_id": authorization.command["operation_id"],
                            "operation_digest": authorization.command["operation_digest"],
                        }
                    ),
                    "{}",
                    "{}",
                ),
            )
    assert _snapshot(postgres_connections) == before


def test_direct_sql_recovery_succeeds_in_fresh_runtime_transaction(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(
        actor, skill, operation_id="phase5-direct-fresh-transaction-recovery"
    )
    authorization = _authority(postgres_connections).issue(actor_context=actor, command=command)
    issued_command = authorization.command
    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
        lease_duration=timedelta(milliseconds=100),
    )

    def crash(_registry, *, request):
        del request
        raise RuntimeError("simulated host crash")

    with patch.object(BuiltinHandlerRegistry, "invoke", new=crash):
        with pytest.raises(RuntimeError, match="simulated host crash"):
            runtime.invoke(actor_context=actor, authorization=authorization)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_builtin_execution_state "
            "SET lease_expires_at=clock_timestamp()-interval '1 second' "
            "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s "
            "RETURNING intent_evidence_json",
            (actor["tenant_id"], actor["actor_id"], issued_command["operation_id"]),
        )
        intent = cursor.fetchone()[0]
    outcome = runtime._outcome(
        actor=actor,
        request=issued_command["tool_request"],
        policy=issued_command["policy_decision"],
        approvals=tuple(issued_command["approvals"]),
        grant=authorization.grant,
        intent=intent,
        result_payload={"error": "execution_outcome_unknown"},
        status="indeterminate",
    )
    payload = {
        "actor_id": actor["actor_id"],
        "operation_id": issued_command["operation_id"],
        "operation_digest": issued_command["operation_digest"],
        "authorization_grant_digest": sha256_digest(authorization.grant),
        "outcome_digest": outcome["outcome_digest"],
        "status": "indeterminate",
        "state": "indeterminate",
        "outcome": outcome,
    }
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        evidence = execution_module._build_evidence(
            actor=actor,
            run_id=issued_command["tool_request"]["run_id"],
            event_kind="execution.outcome",
            policy=issued_command["policy_decision"],
            payload=payload,
            head=execution_module._head(cursor, actor, issued_command["tool_request"]["run_id"]),
            clock=lambda: NOW,
            ids=_ids(),
        )
        cursor.execute(
            "SELECT gah_recover_builtin_execution(%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb)",
            (
                execution_module._json(actor),
                execution_module._json(
                    {
                        "operation_id": issued_command["operation_id"],
                        "operation_digest": issued_command["operation_digest"],
                    }
                ),
                execution_module._json(outcome),
                execution_module._json(evidence),
            ),
        )
        recovered = cursor.fetchone()[0]

    assert recovered["state"] == "indeterminate"
    assert recovered["outcome"]["status"] == "indeterminate"


def test_outcome_chronology_clamps_a_rollback_runtime_clock(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-outcome-clock-rollback"),
    )
    values = iter((NOW, NOW - timedelta(days=1), NOW - timedelta(days=1)))

    result = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: next(values),
        ids=_ids(),
    ).invoke(actor_context=actor, authorization=authorization)

    occurred_at = datetime.fromisoformat(result.outcome["occurred_at"].replace("Z", "+00:00"))
    intent_at = datetime.fromisoformat(result.intent_evidence["recorded_at"].replace("Z", "+00:00"))
    assert occurred_at >= intent_at


def test_direct_sql_rejects_outcome_backdated_before_persisted_intent(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill, operation_id="phase5-direct-backdated-outcome")
    authorization = _authority(postgres_connections).issue(actor_context=actor, command=command)
    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
    )

    def crash(_registry, *, request):
        del request
        raise RuntimeError("simulated host crash")

    with patch.object(BuiltinHandlerRegistry, "invoke", new=crash):
        with pytest.raises(RuntimeError, match="simulated host crash"):
            runtime.invoke(actor_context=actor, authorization=authorization)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT intent_evidence_json,execution_attempt_id,owner_generation "
            "FROM gah_builtin_execution_state WHERE operation_id=%s",
            (command["operation_id"],),
        )
        intent, attempt_id, generation = cursor.fetchone()
    outcome = runtime._outcome(
        actor=actor,
        request=command["tool_request"],
        policy=command["policy_decision"],
        approvals=tuple(command["approvals"]),
        grant=authorization.grant,
        intent=intent,
        result_payload={"echo": {"message": "hello"}},
        status="succeeded",
    )
    intent_at = datetime.fromisoformat(intent["recorded_at"].replace("Z", "+00:00"))
    backdated = _ts(intent_at - timedelta(milliseconds=1))
    outcome["occurred_at"] = backdated
    outcome["target_scope"]["derived_at"] = backdated
    apply_object_digest(outcome)
    payload = {
        "actor_id": actor["actor_id"],
        "operation_id": command["operation_id"],
        "operation_digest": authorization.command["operation_digest"],
        "authorization_grant_digest": sha256_digest(authorization.grant),
        "outcome_digest": outcome["outcome_digest"],
        "status": "succeeded",
        "state": "completed",
        "outcome": outcome,
    }
    before = _snapshot(postgres_connections)
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        evidence = execution_module._build_evidence(
            actor=actor,
            run_id=command["tool_request"]["run_id"],
            event_kind="execution.outcome",
            policy=command["policy_decision"],
            payload=payload,
            head=execution_module._head(cursor, actor, command["tool_request"]["run_id"]),
            clock=lambda: NOW,
            ids=_ids(),
        )
        with pytest.raises(Exception, match="outcome predates its persisted intent"):
            cursor.execute(
                "SELECT gah_complete_builtin_execution(%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb)",
                (
                    execution_module._json(actor),
                    execution_module._json(
                        {
                            "operation_id": command["operation_id"],
                            "operation_digest": authorization.command["operation_digest"],
                            "attempt_id": attempt_id,
                            "owner_generation": generation,
                        }
                    ),
                    execution_module._json(outcome),
                    execution_module._json(evidence),
                ),
            )
    assert _snapshot(postgres_connections) == before


def test_runtime_rejects_mutated_caller_authorization_before_handler_or_mutation(
    postgres_connections,
):
    """The runtime must never execute a caller-mutated copy of an issued command."""

    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-mutated-runtime-copy"),
    )
    mutated_command = copy.deepcopy(dict(authorization.command))
    mutated_command["tool_request"]["arguments"]["input"] = {"message": "mutated"}
    apply_object_digest(mutated_command["tool_request"])
    unsigned_command = copy.deepcopy(mutated_command)
    unsigned_command.pop("operation_digest")
    mutated_command["operation_digest"] = execution_operation_digest(unsigned_command)
    mutated = ExecutionAuthorization(
        mutated_command,
        authorization.grant,
        authorization.issuance_evidence,
    )
    before = _snapshot(postgres_connections)
    calls: list[dict[str, Any]] = []
    original = BuiltinHandlerRegistry.invoke

    def counted(registry, *, request):
        calls.append(copy.deepcopy(dict(request)))
        return original(registry, request=request)

    with patch.object(BuiltinHandlerRegistry, "invoke", new=counted):
        with pytest.raises(
            Exception, match="execution consume authorization is missing or changed"
        ):
            PostgresBuiltinExecutionRuntime(
                runtime_connect=postgres_connections["app"],
                clock=lambda: NOW,
                ids=_ids(),
            ).invoke(actor_context=actor, authorization=mutated)

    assert calls == []
    assert _snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    "mutation",
    (
        lambda actor: actor.__setitem__("correlation_id", "018f0000-0000-7000-8000-00000000fffe"),
        lambda actor: actor.__setitem__("roles", ["operator", "changed-role"]),
        lambda actor: actor.__setitem__("capabilities", ["memory.read", "changed.capability"]),
        lambda actor: actor.__setitem__("trust_level", "delegated_service"),
        lambda actor: actor.__setitem__("expires_at", "2030-01-01T00:00:01.000Z"),
    ),
)
def test_runtime_begin_rejects_changed_actor_context_without_mutation(
    postgres_connections,
    mutation,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-changed-actor-begin"),
    )
    changed_actor = copy.deepcopy(actor)
    mutation(changed_actor)
    before = _snapshot(postgres_connections)
    with pytest.raises(Exception, match="execution consume authorization is missing or changed"):
        PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: NOW,
            ids=_ids(),
        ).invoke(actor_context=changed_actor, authorization=authorization)
    assert _snapshot(postgres_connections) == before


def test_runtime_terminal_replay_rejects_changed_actor_context_without_mutation(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-changed-actor-terminal"),
    )
    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
    )
    runtime.invoke(actor_context=actor, authorization=authorization)
    changed_actor = copy.deepcopy(actor)
    changed_actor["correlation_id"] = "018f0000-0000-7000-8000-00000000fffd"
    before = _snapshot(postgres_connections)
    with pytest.raises(Exception, match="execution consume authorization is missing or changed"):
        runtime.invoke(actor_context=changed_actor, authorization=authorization)
    assert _snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    "mutation",
    (
        lambda actor: actor.__setitem__("session_id", "018f0000-0000-7000-8000-00000000fff1"),
        lambda actor: actor.__setitem__("correlation_id", "018f0000-0000-7000-8000-00000000fff2"),
    ),
)
def test_rebuild_existing_state_rejects_changed_session_or_actor_context_without_mutation(
    postgres_connections,
    mutation,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-rebuild-actor-binding"),
    )
    changed_actor = copy.deepcopy(actor)
    mutation(changed_actor)
    before = _snapshot(postgres_connections)
    with (
        postgres_connections["execution_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        with pytest.raises(Exception):
            cursor.execute(
                "SELECT gah_rebuild_builtin_execution(%s::jsonb,%s::jsonb)",
                (
                    json.dumps(changed_actor),
                    json.dumps(
                        {
                            "operation_id": authorization.command["operation_id"],
                            "operation_digest": authorization.command["operation_digest"],
                        }
                    ),
                ),
            )
        connection.rollback()
    assert _snapshot(postgres_connections) == before


def test_runtime_recovery_rejects_changed_actor_context_without_mutation(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-changed-actor-recovery"),
    )
    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
        lease_duration=timedelta(seconds=30),
    )

    def crash(_registry, *, request):
        del request
        raise RuntimeError("simulated host crash")

    with patch.object(BuiltinHandlerRegistry, "invoke", new=crash):
        with pytest.raises(RuntimeError, match="simulated host crash"):
            runtime.invoke(actor_context=actor, authorization=authorization)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_builtin_execution_state "
            "SET lease_expires_at=clock_timestamp()-interval '1 second' "
            "WHERE tenant_id=%s AND operation_id=%s",
            (actor["tenant_id"], authorization.command["operation_id"]),
        )
    changed_actor = copy.deepcopy(actor)
    changed_actor["correlation_id"] = "018f0000-0000-7000-8000-00000000fffc"
    before = _snapshot(postgres_connections)
    with pytest.raises(Exception, match="execution state is missing or digest-mismatched"):
        runtime.recover(actor_context=changed_actor, authorization=authorization)
    assert _snapshot(postgres_connections) == before


def test_issuance_snapshots_share_db_recorded_at_and_exact_replay_ignores_expiry(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=command,
    )
    payload = authorization.issuance_evidence["draft"]["inline_payload"]
    snapshots = payload["proof_acceptances"]
    assert authorization.issuance_evidence["recorded_at"] == snapshots["accepted_at"]
    assert snapshots["approval"]["accepted_at"] == snapshots["accepted_at"]
    assert snapshots["grant"]["accepted_at"] == snapshots["accepted_at"]
    assert snapshots["approval"]["trust"]["public_key"]
    assert snapshots["grant"]["trust"]["key_fingerprint"].startswith("sha256:")

    before = _snapshot(postgres_connections)
    expired_replay = _authority(
        postgres_connections,
        now=NOW + timedelta(days=5_000),
    ).issue(actor_context=actor, command=command)
    assert expired_replay.replayed is True
    assert expired_replay.grant == authorization.grant
    assert _snapshot(postgres_connections) == before


def test_historical_rebuild_uses_ledger_acceptance_after_authority_expiry(
    postgres_connections,
):
    """A rebuild authenticates the recorded acceptance, never the current wall clock."""

    retention_expiry = datetime.now(timezone.utc) + timedelta(seconds=2)
    actor, skill = _persisted_skill(
        postgres_connections,
        retention_expires_at=_ts(retention_expiry),
    )
    authorization = _authority(postgres_connections, now=datetime.now(timezone.utc)).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-historical-rebuild"),
    )
    while datetime.now(timezone.utc) <= retention_expiry:
        time.sleep(0.05)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM gah_builtin_execution_state WHERE tenant_id=%s AND operation_id=%s",
            (actor["tenant_id"], authorization.command["operation_id"]),
        )
    before = _snapshot(postgres_connections)

    rebuilt = _authority(
        postgres_connections,
        now=datetime.now(timezone.utc),
    ).rebuild(
        actor_context=actor,
        operation_id=authorization.command["operation_id"],
        operation_digest=authorization.command["operation_digest"],
    )

    assert rebuilt.replayed is True
    assert rebuilt.grant == authorization.grant
    assert rebuilt.issuance_evidence == authorization.issuance_evidence
    assert _snapshot(postgres_connections)[1:] == before[1:]


def test_replay_rejects_changed_actor_grant_or_snapshot_without_mutation(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=command,
    )
    before = _snapshot(postgres_connections)
    changed_actor = copy.deepcopy(actor)
    changed_actor["correlation_id"] = "018f0000-0000-7000-8000-00000000fffe"
    with pytest.raises(Exception, match="outside the resolved actor binding"):
        _authority(postgres_connections).issue(actor_context=changed_actor, command=command)
    changed_grant = copy.deepcopy(dict(authorization.grant))
    _tamper_proof_field(changed_grant["proof"], "detached_proof")
    with pytest.raises(Exception, match="conflicts"):
        _direct_issue(
            postgres_connections,
            actor=actor,
            command=authorization.command,
            grant=changed_grant,
            evidence=authorization.issuance_evidence,
            writer_authorization=authorization.issuance_evidence["draft"]["inline_payload"][
                "writer_authorization"
            ],
        )
    changed_writer_authorization = copy.deepcopy(
        authorization.issuance_evidence["draft"]["inline_payload"]["writer_authorization"]
    )
    changed_writer_authorization["lock_digest"] = "sha256:" + "e" * 64
    with pytest.raises(Exception, match="conflicts"):
        _direct_issue(
            postgres_connections,
            actor=actor,
            command=authorization.command,
            grant=authorization.grant,
            evidence=authorization.issuance_evidence,
            writer_authorization=changed_writer_authorization,
        )
    changed_evidence = copy.deepcopy(dict(authorization.issuance_evidence))
    changed_evidence["draft"]["inline_payload"]["proof_acceptances"]["grant"]["trust"][
        "policy_digest"
    ] = "sha256:" + "f" * 64
    with pytest.raises(Exception, match="conflicts"):
        _direct_issue(
            postgres_connections,
            actor=actor,
            command=authorization.command,
            grant=authorization.grant,
            evidence=changed_evidence,
            writer_authorization=authorization.issuance_evidence["draft"]["inline_payload"][
                "writer_authorization"
            ],
        )
    assert _snapshot(postgres_connections) == before


def test_evidence_head_read_is_noninserting_and_does_not_take_row_lock(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    _authority(postgres_connections).issue(actor_context=actor, command=command)
    before = _snapshot(postgres_connections)
    with (
        postgres_connections["execution_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT gah_builtin_execution_evidence_head(%s::jsonb, %s)",
            (execution_module._json(actor), actor["session_id"]),
        )
        assert cursor.fetchone() is not None
        cursor.execute(
            "SELECT count(*) FROM pg_locks AS locks "
            "JOIN pg_class AS relation ON relation.oid=locks.relation "
            "WHERE locks.pid=pg_backend_pid() AND relation.relname='gah_run_heads' "
            "AND locks.mode='RowShareLock'"
        )
        assert cursor.fetchone() == (0,)
    assert _snapshot(postgres_connections) == before


def test_first_execution_issuance_creates_its_evidence_head_atomically(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    fresh_actor = copy.deepcopy(actor)
    fresh_actor["session_id"] = "018f0000-0000-7000-8000-00000000f001"
    command = _execution_command(
        fresh_actor,
        skill,
        operation_id="phase5-first-execution-run",
    )
    with (
        postgres_connections["execution_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT gah_builtin_execution_evidence_head(%s::jsonb, %s)",
            (execution_module._json(fresh_actor), fresh_actor["session_id"]),
        )
        assert cursor.fetchone() == (
            {
                "last_event_digest": None,
                "last_recorded_at": None,
                "next_sequence": 0,
                "version": 0,
            },
        )
    authorization = _authority(postgres_connections).issue(
        actor_context=fresh_actor,
        command=command,
    )
    assert authorization.replayed is False
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT next_sequence, version FROM gah_run_heads "
            "WHERE tenant_id=%s AND actor_id=%s AND run_id=%s",
            (fresh_actor["tenant_id"], fresh_actor["actor_id"], fresh_actor["session_id"]),
        )
        assert cursor.fetchone() == (1, 1)


def test_changed_replay_and_wrong_digest_are_zero_mutation(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    authority = _authority(postgres_connections)
    authority.issue(actor_context=actor, command=command)
    before = _counts(postgres_connections)
    changed = copy.deepcopy(command)
    changed["tool_request"]["arguments"]["input"]["message"] = "changed"
    apply_object_digest(changed["tool_request"])
    changed["policy_decision"]["request_digest"] = changed["tool_request"]["request_digest"]
    apply_object_digest(changed["policy_decision"])
    changed["approvals"][0].update(
        {
            "request_digest": changed["tool_request"]["request_digest"],
            "policy_decision_digest": changed["policy_decision"]["decision_digest"],
        }
    )
    changed["approvals"][0] = _sign_record(
        changed["approvals"][0],
        issuer="policy.authority",
        key_id="policy.key.v1",
        proof_domain="approval_record.v1",
        nonce="Q" * 22,
    )
    with pytest.raises(Exception, match="conflicts"):
        authority.issue(actor_context=actor, command=changed)
    wrong = copy.deepcopy(command)
    wrong["artifact_digest"] = "sha256:" + "f" * 64
    wrong["tool_request"]["arguments"]["artifact_digest"] = wrong["artifact_digest"]
    apply_object_digest(wrong["tool_request"])
    with pytest.raises(Exception, match="conflicts"):
        authority.issue(actor_context=actor, command=wrong)
    assert _counts(postgres_connections) == before


@pytest.mark.parametrize("field", ("actor_id", "tenant_id"))
def test_cross_actor_or_tenant_resolution_is_zero_mutation(postgres_connections, field):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    forged = copy.deepcopy(actor)
    forged[field] = "018f0000-0000-7000-8000-00000000ffff"
    before = _counts(postgres_connections)
    with pytest.raises(Exception):
        _authority(postgres_connections).issue(
            actor_context=forged,
            command=command,
        )
    assert _counts(postgres_connections) == before


def test_same_tenant_actors_independently_issue_and_execute_identical_identifiers(
    postgres_connections,
):
    import psycopg
    from psycopg import sql

    actor_a, skill_a = _persisted_skill(postgres_connections)
    with postgres_connections["admin"]() as connection:
        parameters = connection.info.get_parameters()
    suffix = f"{time.time_ns():x}"[-10:]
    roles = {
        name: f"gah_identity_{name}_{suffix}" for name in ("app", "writer", "skill", "execution")
    }
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        for role in roles.values():
            cursor.execute(
                sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS INHERIT").format(
                    sql.Identifier(role)
                )
            )
        role_grants = (
            ("app", "gah_runtime"),
            ("writer", "gah_authority_writer"),
            ("skill", "gah_skill_lifecycle_authority"),
            ("execution", "gah_execution_admission_authority"),
        )
        for name, base_role in role_grants:
            cursor.execute(
                sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(base_role), sql.Identifier(roles[name])
                )
            )

    def role_connect(name):
        return psycopg.connect(**{**parameters, "user": roles[name]})

    actor_b_connections = {
        **postgres_connections,
        "app": lambda: role_connect("app"),
        "writer": lambda: role_connect("writer"),
        "skill_authority": lambda: role_connect("skill"),
        "execution_authority": lambda: role_connect("execution"),
        "store_at": lambda now: PostgresDurableEffectStore(
            connect=lambda: role_connect("app"),
            privileged_connect=lambda: role_connect("writer"),
            clock=lambda: now,
            ids=_ids(),
        ),
    }
    try:
        actor_b, skill_b = _persisted_skill(
            actor_b_connections,
            actor_id="018f0000-0000-7000-8000-0000000000a2",
            session_id="018f0000-0000-7000-8000-0000000000b2",
            provision=True,
            database_roles=tuple(roles.values()),
        )
        command_a = _execution_command(actor_a, skill_a)
        command_b = _execution_command(actor_b, skill_b)
        assert command_a["operation_id"] == command_b["operation_id"]
        assert command_a["tool_request"]["request_id"] == command_b["tool_request"]["request_id"]
        assert (
            command_a["tool_request"]["idempotency"]["operation_digest"]
            == command_b["tool_request"]["idempotency"]["operation_digest"]
        )
        authorization_a = _authority(postgres_connections).issue(
            actor_context=actor_a, command=command_a
        )
        authorization_b = _authority(actor_b_connections).issue(
            actor_context=actor_b, command=command_b
        )
        assert authorization_a.grant["grant_id"] != authorization_b.grant["grant_id"]
        result_a = PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: NOW,
            ids=_ids(),
        ).invoke(actor_context=actor_a, authorization=authorization_a)
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT actor_id,state FROM gah_builtin_execution_state "
                "WHERE tenant_id=%s AND operation_id=%s ORDER BY actor_id",
                (actor_a["tenant_id"], command_a["operation_id"]),
            )
            assert cursor.fetchall() == [
                (actor_a["actor_id"], "completed"),
                (actor_b["actor_id"], "authorized"),
            ]
        result_b = PostgresBuiltinExecutionRuntime(
            runtime_connect=actor_b_connections["app"],
            clock=lambda: NOW,
            ids=_ids(),
        ).invoke(actor_context=actor_b, authorization=authorization_b)

        assert result_a.outcome["status"] == result_b.outcome["status"] == "succeeded"
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT actor_id,state FROM gah_builtin_execution_state "
                "WHERE tenant_id=%s AND operation_id=%s ORDER BY actor_id",
                (actor_a["tenant_id"], command_a["operation_id"]),
            )
            assert cursor.fetchall() == [
                (actor_a["actor_id"], "completed"),
                (actor_b["actor_id"], "completed"),
            ]
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM gah_runtime_principals WHERE database_role = ANY(%s)",
                (list(roles.values()),),
            )
            for name, base_role in role_grants:
                cursor.execute(
                    sql.SQL("REVOKE {} FROM {}").format(
                        sql.Identifier(base_role), sql.Identifier(roles[name])
                    )
                )
            for role in roles.values():
                cursor.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_active_digest_change_after_issuance_is_zero_mutation(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    authorization = _authority(postgres_connections).issue(actor_context=actor, command=command)
    deactivate = copy.deepcopy(skill)
    deactivate.update(
        {
            "operation_id": "phase5-skill-deactivate",
            "expected_revision": 1,
            "activation_receipt": None,
        }
    )
    after_issuance = execution_module._parse_time(
        authorization.issuance_evidence["recorded_at"]
    ) + timedelta(milliseconds=1)
    PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: after_issuance,
        ids=_ids(),
    ).deactivate_skill(actor_context=actor, **deactivate)
    before = _counts(postgres_connections)
    with pytest.raises(Exception, match="stale or expired"):
        PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: after_issuance,
            ids=_ids(),
        ).invoke(actor_context=actor, authorization=authorization)
    assert _counts(postgres_connections) == before


def test_execution_issuance_and_skill_deactivation_have_no_deadlock_or_partial_state(
    postgres_connections,
):
    """One actor/skill/run admits only a complete issuance-before-deactivation ordering.

    The two authority paths deliberately contend on the same lifecycle/evidence
    surface.  Bounded server timeouts make a lock-order regression observable
    without permitting a hung test process.
    """

    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill, operation_id="phase5-lifecycle-race")
    deactivate = copy.deepcopy(skill)
    deactivate.update(
        {
            "operation_id": "phase5-lifecycle-race-deactivate",
            "expected_revision": 1,
            "activation_receipt": None,
        }
    )

    def bounded(factory):
        def connect():
            connection = factory()
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '2s'")
                cursor.execute("SET statement_timeout = '5s'")
            return connection

        return connect

    now = lambda: datetime.now(timezone.utc)
    issuance_authority = PostgresExecutionAdmissionAuthority(
        authority_connect=bounded(postgres_connections["execution_authority"]),
        evidence_writer_connect=bounded(postgres_connections["writer"]),
        resolver=PostgresActiveSkillResolver(runtime_connect=bounded(postgres_connections["app"])),
        grant_issuer=DeterministicGrantIssuer(),
        grant_verifier=DeterministicEd25519Verifier(),
        grant_trust=_trust,
        approval_verifier=DeterministicEd25519Verifier(),
        approval_trust=_trust,
        clock=now,
        ids=_ids(),
        nonce=lambda: "A" * 22,
    )
    lifecycle_authority = PostgresSkillLifecycleAuthority(
        privileged_connect=bounded(postgres_connections["skill_authority"]),
        evidence_writer_connect=bounded(postgres_connections["writer"]),
        clock=now,
        ids=_ids(),
    )
    start = threading.Barrier(2)

    def issue():
        try:
            start.wait(timeout=2)
            return "issued", issuance_authority.issue(actor_context=actor, command=command)
        except Exception as error:  # The terminal ordering determines this result.
            return "issue_error", error

    def deactivate_skill():
        try:
            start.wait(timeout=2)
            return "deactivated", lifecycle_authority.deactivate_skill(
                actor_context=actor,
                **deactivate,
            )
        except Exception as error:  # Surface timeout/deadlock errors below as failures.
            return "deactivate_error", error

    with ThreadPoolExecutor(max_workers=2) as pool:
        issue_future = pool.submit(issue)
        deactivate_future = pool.submit(deactivate_skill)
        issue_result = issue_future.result(timeout=8)
        deactivate_result = deactivate_future.result(timeout=8)

    outcomes = (issue_result, deactivate_result)
    errors = [value for kind, value in outcomes if kind.endswith("error")]

    def error_diagnostic(error: Exception) -> str:
        sqlstate = getattr(error, "sqlstate", None) or getattr(error, "pgcode", None)
        return f"{type(error).__name__}(sqlstate={sqlstate!r}): {error}"

    assert not any(
        (getattr(error, "sqlstate", None) or getattr(error, "pgcode", None))
        in {"40P01", "55P03", "57014"}
        or "deadlock detected" in str(error)
        or "lock timeout" in str(error)
        or "statement timeout" in str(error)
        for error in errors
    ), [error_diagnostic(error) for error in errors]
    assert deactivate_result[0] == "deactivated", deactivate_result[1]
    assert issue_result[0] in {"issued", "issue_error"}
    if issue_result[0] == "issue_error":
        assert "execution skill is not active" in str(
            issue_result[1]
        ) or "active skill binding is stale" in str(issue_result[1])

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM ("
            "SELECT sequence_number, prior_event_digest, event_digest, "
            "row_number() OVER (ORDER BY sequence_number) - 1 AS expected_sequence, "
            "lag(event_digest) OVER (ORDER BY sequence_number) AS expected_prior "
            "FROM gah_evidence_events WHERE tenant_id=%s AND actor_id=%s AND run_id=%s"
            ") AS chain WHERE sequence_number <> expected_sequence "
            "OR prior_event_digest IS DISTINCT FROM expected_prior",
            (actor["tenant_id"], actor["actor_id"], actor["session_id"]),
        )
        assert cursor.fetchone() == (0,)
        cursor.execute(
            "SELECT count(*) FROM gah_active_skill_projection "
            "WHERE tenant_id=%s AND actor_id=%s AND skill_id=%s",
            (actor["tenant_id"], actor["actor_id"], command["skill_id"]),
        )
        assert cursor.fetchone() == (0,)
        cursor.execute(
            "SELECT count(*) FROM gah_builtin_execution_state "
            "WHERE tenant_id=%s AND operation_id=%s",
            (actor["tenant_id"], command["operation_id"]),
        )
        state_count = cursor.fetchone()[0]
        cursor.execute(
            "SELECT count(*) FROM gah_evidence_events "
            "WHERE tenant_id=%s AND actor_id=%s AND run_id=%s "
            "AND envelope_json#>>'{draft,event_kind}'='execution.authorization_issued' "
            "AND envelope_json#>>'{draft,inline_payload,operation_id}'=%s",
            (
                actor["tenant_id"],
                actor["actor_id"],
                actor["session_id"],
                command["operation_id"],
            ),
        )
        issuance_count = cursor.fetchone()[0]
    if issue_result[0] == "issued":
        assert state_count == issuance_count == 1
    else:
        assert state_count == issuance_count == 0


def test_lifecycle_draft_lock_reads_advanced_run_head_after_skill_lock_wait(
    postgres_connections,
):
    """A generic append waits behind a lifecycle-owned authoritative head."""

    actor, skill = _persisted_skill(postgres_connections)
    deactivate = copy.deepcopy(skill)
    deactivate.update(
        {
            "operation_id": "phase5-draft-lock-deactivate",
            "expected_revision": 1,
            "activation_receipt": None,
        }
    )
    head_locked = threading.Event()
    release_lifecycle = threading.Event()
    next_id = _ids()

    def paused_ids() -> str:
        head_locked.set()
        if not release_lifecycle.wait(timeout=5):
            raise RuntimeError("test did not release lifecycle evidence drafting")
        return next_id()

    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: NOW + timedelta(milliseconds=2),
        ids=paused_ids,
    )
    completed = threading.Event()

    def deactivate_skill():
        try:
            return authority.deactivate_skill(actor_context=actor, **deactivate)
        finally:
            completed.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        lifecycle_future = pool.submit(deactivate_skill)
        assert head_locked.wait(timeout=5), "lifecycle never locked and read its run head"
        append_future = pool.submit(
            postgres_connections["store_at"](NOW + timedelta(milliseconds=3)).append,
            tenant_id=actor["tenant_id"],
            run_id=actor["session_id"],
            event_kind="kernel.policy_decided",
            policy_ref={
                "record_type": "policy_decision",
                "record_id": skill["policy_decision"]["decision_id"],
                "record_digest": skill["policy_decision"]["decision_digest"],
            },
            payload={
                "actor_id": actor["actor_id"],
                "policy_decision_digest": skill["policy_decision"]["decision_digest"],
            },
        )
        assert _wait_for_writer_run_head_lock(postgres_connections)
        assert not append_future.done()
        release_lifecycle.set()
        result = lifecycle_future.result(timeout=8)
        advanced = append_future.result(timeout=8)

    assert result.replayed is False
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT sequence_number FROM gah_evidence_events "
            "WHERE tenant_id=%s AND actor_id=%s AND run_id=%s AND event_digest=%s",
            (
                actor["tenant_id"],
                actor["actor_id"],
                actor["session_id"],
                result.transition_digest,
            ),
        )
        assert cursor.fetchone() == (advanced["sequence_number"] - 1,)
    assert advanced["prior_event_digest"] == result.transition_digest


def test_direct_commit_evidence_cannot_bypass_lifecycle_run_reservation(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    deactivate = copy.deepcopy(skill)
    deactivate.update(
        {
            "operation_id": "phase5-direct-commit-reservation",
            "expected_revision": 1,
            "activation_receipt": None,
        }
    )
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT gah_lock_run(%s::jsonb,%s::jsonb)",
            (
                execution_module._json(actor),
                execution_module._json({"run_id": actor["session_id"]}),
            ),
        )
        head = cursor.fetchone()[0]
    generic_payload = {
        "actor_id": actor["actor_id"],
        "operation_id": "phase5-direct-generic-commit",
        "operation_digest": sha256_digest({"kind": "direct-generic-commit"}),
    }
    generic_evidence = execution_module._build_evidence(
        actor=actor,
        run_id=actor["session_id"],
        event_kind="kernel.policy_decided",
        policy=skill["policy_decision"],
        payload=generic_payload,
        head=head,
        clock=lambda: NOW + timedelta(milliseconds=3),
        ids=_ids(),
    )
    commit_payload = {
        "run_id": actor["session_id"],
        "expected_version": head["version"],
        "envelope": generic_evidence,
    }
    reserved = threading.Event()
    release = threading.Event()
    next_id = _ids()

    def paused_ids():
        reserved.set()
        if not release.wait(timeout=5):
            raise RuntimeError("test did not release lifecycle reservation")
        return next_id()

    authority = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: NOW + timedelta(milliseconds=2),
        ids=paused_ids,
    )

    def direct_commit():
        try:
            with (
                postgres_connections["writer"]() as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute(
                    "SELECT gah_commit_evidence(%s::jsonb,%s::jsonb)",
                    (
                        execution_module._json(actor),
                        execution_module._json(commit_payload),
                    ),
                )
                return ("committed", cursor.fetchone()[0])
        except Exception as exc:
            return ("rejected", str(exc))

    with ThreadPoolExecutor(max_workers=2) as pool:
        lifecycle = pool.submit(authority.deactivate_skill, actor_context=actor, **deactivate)
        assert reserved.wait(timeout=5)
        commit = pool.submit(direct_commit)
        assert _wait_for_writer_commit_lock(postgres_connections)
        assert not commit.done()
        release.set()
        transition = lifecycle.result(timeout=8)
        commit_result = commit.result(timeout=8)
    assert transition.replayed is False
    assert commit_result[0] == "rejected"
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM gah_evidence_events "
            "WHERE envelope_json#>>'{draft,inline_payload,operation_id}'=%s",
            (generic_payload["operation_id"],),
        )
        assert cursor.fetchone() == (0,)


def test_begin_waits_for_operation_before_skill_so_deactivate_cannot_deadlock(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-begin-deactivate-lock-order"),
    )
    command = authorization.command
    start_payload = {
        "actor_id": actor["actor_id"],
        "operation_id": command["operation_id"],
        "operation_digest": command["operation_digest"],
        "authorization_grant_digest": sha256_digest(authorization.grant),
        "skill_id": command["skill_id"],
        "revision": command["revision"],
        "artifact_digest": command["artifact_digest"],
        "state": "executing",
    }
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        intent = execution_module._build_evidence(
            actor=actor,
            run_id=actor["session_id"],
            event_kind="execution.intent",
            policy=command["policy_decision"],
            payload=start_payload,
            head=execution_module._head(cursor, actor, actor["session_id"]),
            clock=lambda: NOW,
            ids=_ids(),
        )
    blocker = postgres_connections["admin"]()
    blocker_cursor = blocker.cursor()
    blocker_cursor.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (
            "execution:operation:"
            f"{actor['tenant_id']}:{actor['actor_id']}:{command['operation_id']}",
        ),
    )

    def begin():
        try:
            with postgres_connections["app"]() as connection, connection.cursor() as cursor:
                cursor.execute("SET lock_timeout='5s'")
                cursor.execute("SET statement_timeout='8s'")
                cursor.execute(
                    "SELECT gah_begin_builtin_execution(%s::jsonb,%s::jsonb,%s::jsonb,%s)",
                    (
                        execution_module._json(actor),
                        execution_module._json(
                            {
                                "operation_id": command["operation_id"],
                                "operation_digest": command["operation_digest"],
                                "command": command,
                                "grant": authorization.grant,
                            }
                        ),
                        execution_module._json(intent),
                        30,
                    ),
                )
                return ("began", cursor.fetchone()[0])
        except Exception as exc:
            return ("rejected", str(exc))

    deactivate = copy.deepcopy(skill)
    deactivate.update(
        {
            "operation_id": "phase5-deactivate-while-begin-waits",
            "expected_revision": 1,
            "activation_receipt": None,
        }
    )
    lifecycle = PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: datetime.now(timezone.utc) + timedelta(minutes=1),
        ids=_ids(),
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            begin_future = pool.submit(begin)
            assert _wait_for_role_query_lock(
                postgres_connections, "gah_app", "gah_begin_builtin_execution"
            )
            deactivate_future = pool.submit(
                lifecycle.deactivate_skill, actor_context=actor, **deactivate
            )
            deactivated = deactivate_future.result(timeout=6)
            assert deactivated.replayed is False
            blocker.commit()
            begin_result = begin_future.result(timeout=8)
    finally:
        blocker.rollback()
        blocker_cursor.close()
        blocker.close()
    assert begin_result[0] == "rejected"
    assert "stale or expired" in begin_result[1]


def test_same_operation_lifecycle_and_rebuild_follow_one_lock_order(postgres_connections):
    """Lifecycle draft helper waits on O before it can own the shared S lock."""

    actor, skill = _persisted_skill(postgres_connections)
    operation_id = "phase5-same-operation-rebuild-race"
    deactivate = copy.deepcopy(skill)
    deactivate.update(
        {
            "operation_id": operation_id,
            "expected_revision": 1,
            "activation_receipt": None,
        }
    )

    rebuild = {
        "operation_id": operation_id,
        "expected_revision": 1,
        "skill_id": skill["skill_proposal"]["artifact_id"],
    }

    def bounded(factory):
        def connect():
            connection = factory()
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '4s'")
                cursor.execute("SET statement_timeout = '8s'")
            return connection

        return connect

    lifecycle_wire = build_skill_lifecycle_wire_command("deactivate", deactivate)
    rebuild_wire = build_skill_lifecycle_wire_command("rebuild", rebuild)

    def direct_rebuild():
        with (
            bounded(postgres_connections["skill_authority"])() as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "SELECT gah_rebuild_skill_projection(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(rebuild_wire)),
            )
            return cursor.fetchone()

    def direct_lifecycle_draft_lock():
        with (
            bounded(postgres_connections["writer"])() as writer_connection,
            writer_connection.cursor() as writer_cursor,
            bounded(postgres_connections["skill_authority"])() as connection,
            connection.cursor() as cursor,
        ):
            authorization = _authorize_lifecycle_writer(writer_cursor, actor, lifecycle_wire)
            cursor.execute(
                "SELECT gah_lock_skill_lifecycle_draft(%s::jsonb, %s::jsonb, 'deactivate', %s::jsonb)",
                (json.dumps(actor), json.dumps(lifecycle_wire), json.dumps(authorization)),
            )
            assert cursor.fetchone() == (None,)
            cursor.execute(
                "SELECT gah_lookup_skill_replay(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(lifecycle_wire)),
            )
            return cursor.fetchone()

    operation_lock = f"skill-operation:{actor['tenant_id']}:{actor['actor_id']}:{operation_id}"
    skill_lock = (
        f"skill:{actor['tenant_id']}:{actor['actor_id']}:{skill['skill_proposal']['artifact_id']}"
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        with (
            postgres_connections["admin"]() as holder_connection,
            holder_connection.cursor() as holder_cursor,
        ):
            holder_cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (operation_lock,),
            )
            rebuild_future = pool.submit(direct_rebuild)
            assert _wait_for_skill_authority_lock(
                postgres_connections, "gah_rebuild_skill_projection"
            ), "rebuild did not queue on the operation lock"
            lifecycle_future = pool.submit(direct_lifecycle_draft_lock)
            assert _wait_for_skill_authority_lock(
                postgres_connections, "gah_lock_skill_lifecycle_draft"
            ), "lifecycle draft did not queue on the operation lock"
            with (
                postgres_connections["admin"]() as contender_connection,
                contender_connection.cursor() as contender_cursor,
            ):
                contender_cursor.execute(
                    "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
                    (skill_lock,),
                )
                assert contender_cursor.fetchone() == (True,)

        outcomes = []
        for future in (rebuild_future, lifecycle_future):
            try:
                outcomes.append(("ok", future.result(timeout=10)))
            except Exception as error:
                outcomes.append(("error", error))

    errors = [value for kind, value in outcomes if kind == "error"]

    def diagnostic(error: Exception) -> str:
        sqlstate = getattr(error, "sqlstate", None) or getattr(error, "pgcode", None)
        return f"{type(error).__name__}(sqlstate={sqlstate!r}): {error}"

    assert not any(
        (getattr(error, "sqlstate", None) or getattr(error, "pgcode", None))
        in {"40P01", "55P03", "57014"}
        or "deadlock detected" in str(error)
        or "lock timeout" in str(error)
        or "statement timeout" in str(error)
        for error in errors
    ), [diagnostic(error) for error in errors]
    assert not errors, [diagnostic(error) for error in errors]

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM gah_skill_projection_rebuilds "
            "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
            (actor["tenant_id"], actor["actor_id"], operation_id),
        )
        assert cursor.fetchone() == (1,)


def test_execution_issuance_takes_skill_lock_before_waiting_on_active_projection(
    postgres_connections,
):
    """The execution issuer owns the lifecycle skill lock before its row lock waits.

    Holding the active projection row makes the ordering externally observable:
    once issuance is blocked on that row, another transaction must be unable to
    acquire the same skill advisory lock.  The old implementation took the row
    lock during validation before acquiring the skill lock, so this proof fails
    against it without relying on an arbitrary sleep.
    """

    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill, operation_id="phase5-lock-order-proof")
    authority = _authority(postgres_connections)
    issued = threading.Event()

    def issue():
        try:
            result = authority.issue(actor_context=actor, command=command)
            issued.set()
            return result
        except Exception as error:  # Returned below so the proof keeps its diagnostic.
            return error

    with ThreadPoolExecutor(max_workers=1) as pool:
        with (
            postgres_connections["admin"]() as holder_connection,
            holder_connection.cursor() as holder_cursor,
        ):
            holder_cursor.execute(
                "SELECT 1 FROM gah_active_skill_projection "
                "WHERE tenant_id=%s AND actor_id=%s AND skill_id=%s FOR UPDATE",
                (actor["tenant_id"], actor["actor_id"], command["skill_id"]),
            )
            assert holder_cursor.fetchone() == (1,)
            future = pool.submit(issue)
            deadline = time.monotonic() + 5
            blocked_on_active_projection = False
            while time.monotonic() < deadline:
                with (
                    postgres_connections["admin"]() as observer_connection,
                    observer_connection.cursor() as observer_cursor,
                ):
                    observer_cursor.execute(
                        "SELECT EXISTS ("
                        "SELECT 1 FROM pg_stat_activity "
                        "WHERE usename='gah_execution_authority' "
                        "AND wait_event_type='Lock' "
                        "AND query LIKE 'SELECT gah_issue_builtin_execution_authorization%'"
                        ")"
                    )
                    blocked_on_active_projection = observer_cursor.fetchone()[0]
                if blocked_on_active_projection:
                    break
                time.sleep(0.01)
            assert blocked_on_active_projection, "issuance never blocked on the held projection row"
            assert not issued.is_set()
            with (
                postgres_connections["admin"]() as contender_connection,
                contender_connection.cursor() as contender_cursor,
            ):
                contender_cursor.execute(
                    "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"skill:{actor['tenant_id']}:{actor['actor_id']}:{command['skill_id']}",),
                )
                assert contender_cursor.fetchone() == (False,)
        result = future.result(timeout=8)

    assert not isinstance(result, Exception), result
    assert result.replayed is False


def test_lock_order_internal_issuer_is_not_an_authority_entrypoint(postgres_connections):
    """Only admission authority can call the ordered public issuer wrapper."""

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT "
            "has_function_privilege('gah_execution_authority', "
            "'gah_issue_builtin_execution_authorization(jsonb,jsonb,jsonb,jsonb,jsonb)', "
            "'EXECUTE'), "
            "has_function_privilege('gah_app', "
            "'gah_issue_builtin_execution_authorization(jsonb,jsonb,jsonb,jsonb,jsonb)', "
            "'EXECUTE'), "
            "has_function_privilege('gah_execution_authority', "
            "'gah_issue_builtin_execution_authorization_locked(jsonb,jsonb,jsonb,jsonb,jsonb)', "
            "'EXECUTE'), "
            "has_function_privilege('public', "
            "'gah_issue_builtin_execution_authorization_locked(jsonb,jsonb,jsonb,jsonb,jsonb)', "
            "'EXECUTE')"
        )
        assert cursor.fetchone() == (True, False, False, False)


def test_lifecycle_draft_lock_is_lifecycle_authority_only(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    wire = build_skill_lifecycle_wire_command(
        "deactivate",
        {
            **skill,
            "operation_id": "phase5-direct-draft-lock",
            "expected_revision": 1,
            "activation_receipt": None,
        },
    )
    function = "gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb)"
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT "
            "has_function_privilege('gah_skill_authority', %s, 'EXECUTE'), "
            "has_function_privilege('gah_app', %s, 'EXECUTE'), "
            "has_function_privilege('gah_writer', %s, 'EXECUTE'), "
            "has_function_privilege('gah_execution_authority', %s, 'EXECUTE'), "
            "has_function_privilege('public', %s, 'EXECUTE'), "
            "pg_get_userbyid(proowner), proconfig "
            "FROM pg_proc WHERE oid=%s::regprocedure",
            (function, function, function, function, function, function),
        )
        assert cursor.fetchone() == (
            True,
            False,
            False,
            False,
            False,
            "gah_schema_owner",
            ["search_path=pg_catalog, public"],
        )

    with (
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as writer_cursor,
        postgres_connections["skill_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        authorization = _authorize_lifecycle_writer(writer_cursor, actor, wire)
        cursor.execute(
            "SELECT gah_lock_skill_lifecycle_draft(%s::jsonb, %s::jsonb, 'deactivate', %s::jsonb)",
            (json.dumps(actor), json.dumps(wire), json.dumps(authorization)),
        )
        assert cursor.fetchone() == (None,)

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("GRANT gah_runtime TO gah_skill_authority")
    try:
        with (
            postgres_connections["writer"]() as writer_connection,
            writer_connection.cursor() as writer_cursor,
            postgres_connections["skill_authority"]() as connection,
            connection.cursor() as cursor,
        ):
            authorization = _authorize_lifecycle_writer(writer_cursor, actor, wire)
            with pytest.raises(Exception, match="requires lifecycle authority"):
                cursor.execute(
                    "SELECT gah_lock_skill_lifecycle_draft(%s::jsonb, %s::jsonb, 'deactivate', %s::jsonb)",
                    (json.dumps(actor), json.dumps(wire), json.dumps(authorization)),
                )
            connection.rollback()
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute("REVOKE gah_runtime FROM gah_skill_authority")


def test_lifecycle_draft_lock_requires_live_full_writer_pair_before_head_mutation(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    deactivate = {
        **skill,
        "operation_id": "phase5-draft-lock-live-writer",
        "expected_revision": 1,
        "activation_receipt": None,
    }
    wire = build_skill_lifecycle_wire_command("deactivate", deactivate)

    def counts():
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT (SELECT count(*) FROM gah_run_heads), "
                "(SELECT count(*) FROM gah_evidence_events), "
                "(SELECT count(*) FROM gah_skill_lifecycle_transitions)"
            )
            return cursor.fetchone()

    def direct(command, authorization):
        with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_lock_skill_lifecycle_draft(%s::jsonb, %s::jsonb, 'deactivate', %s::jsonb)",
                (json.dumps(actor), json.dumps(command), json.dumps(authorization)),
            )

    minimal = {
        "operation": "deactivate",
        "operation_id": "phase5-minimal-draft-lock",
        "skill_proposal": {"artifact_id": skill["skill_proposal"]["artifact_id"]},
    }
    minimal["operation_digest"] = sha256_digest(minimal)
    before = counts()
    with pytest.raises(Exception, match="command is malformed"):
        direct(minimal, None)
    assert counts() == before

    with pytest.raises(Exception, match="writer authorization is invalid"):
        direct(wire, None)
    assert counts() == before

    with (
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as writer_cursor,
    ):
        authorization = _authorize_lifecycle_writer(writer_cursor, actor, wire)
        changed = copy.deepcopy(authorization)
        changed["operation_id"] = "phase5-changed-writer-authorization"
        with pytest.raises(Exception, match="writer authorization is invalid"):
            direct(wire, changed)
    assert counts() == before

    def retarget_session(session_id: str):
        paired_actor = copy.deepcopy(actor)
        paired_actor["session_id"] = session_id
        paired_actor["correlation_id"] = session_id
        paired_wire = copy.deepcopy(
            build_skill_lifecycle_wire_command(
                "install",
                {**skill, "operation_id": f"phase5-fresh-head-{session_id[-4:]}"},
            )
        )
        scope = copy.deepcopy(paired_wire["skill_proposal"]["target_scope"])
        scope["parent_digest"] = sha256_digest(paired_actor)
        paired_wire["skill_proposal"]["target_scope"] = copy.deepcopy(scope)
        paired_wire["gate_decision"]["target_scope"] = copy.deepcopy(scope)
        paired_wire["delivery_envelope"]["target_scope"] = copy.deepcopy(scope)
        paired_wire["operation_digest"] = sha256_digest(
            {key: value for key, value in paired_wire.items() if key != "operation_digest"}
        )
        return paired_actor, paired_wire

    paired_actor, paired_wire = retarget_session("018f0000-0000-7000-8000-00000000f001")
    before = counts()
    with pytest.raises(RuntimeError, match="force lifecycle rollback"):
        with (
            postgres_connections["writer"]() as writer_connection,
            writer_connection.cursor() as writer_cursor,
            postgres_connections["skill_authority"]() as connection,
            connection.cursor() as cursor,
        ):
            authorization = _authorize_lifecycle_writer(writer_cursor, paired_actor, paired_wire)
            cursor.execute(
                "SELECT gah_lock_skill_lifecycle_draft(%s::jsonb, %s::jsonb, 'install', %s::jsonb)",
                (json.dumps(paired_actor), json.dumps(paired_wire), json.dumps(authorization)),
            )
            assert cursor.fetchone() == (None,)
            raise RuntimeError("force lifecycle rollback")
    assert counts() == before

    committed_actor, committed_wire = retarget_session("018f0000-0000-7000-8000-00000000f003")
    before = counts()
    with (
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as writer_cursor,
        postgres_connections["skill_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        authorization = _authorize_lifecycle_writer(writer_cursor, committed_actor, committed_wire)
        cursor.execute(
            "SELECT gah_lock_skill_lifecycle_draft(%s::jsonb, %s::jsonb, 'install', %s::jsonb)",
            (
                json.dumps(committed_actor),
                json.dumps(committed_wire),
                json.dumps(authorization),
            ),
        )
        assert cursor.fetchone() == (None,)
    assert counts() == before

    collision_actor, collision_wire = retarget_session("018f0000-0000-7000-8000-00000000f002")
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_run_heads (tenant_id, actor_id, run_id) VALUES (%s, %s, %s)",
            (
                collision_actor["tenant_id"],
                "018f0000-0000-7000-8000-00000000f099",
                collision_actor["session_id"],
            ),
        )
    before = counts()
    with (
        postgres_connections["writer"]() as writer_connection,
        writer_connection.cursor() as writer_cursor,
        postgres_connections["skill_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        authorization = _authorize_lifecycle_writer(writer_cursor, collision_actor, collision_wire)
        with pytest.raises(Exception, match="run scope conflicts with an existing actor"):
            cursor.execute(
                "SELECT gah_lock_skill_lifecycle_draft(%s::jsonb, %s::jsonb, 'install', %s::jsonb)",
                (
                    json.dumps(collision_actor),
                    json.dumps(collision_wire),
                    json.dumps(authorization),
                ),
            )
        connection.rollback()
    assert counts() == before


def test_concurrent_consume_has_one_handler_winner(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor, command=_execution_command(actor, skill)
    )
    calls: list[dict[str, Any]] = []
    call_lock = threading.Lock()
    original = BuiltinHandlerRegistry.invoke

    def counted(registry, *, request):
        with call_lock:
            calls.append(copy.deepcopy(dict(request)))
        return original(registry, request=request)

    def invoke():
        try:
            return PostgresBuiltinExecutionRuntime(
                runtime_connect=postgres_connections["app"],
                clock=lambda: NOW,
                ids=_ids(),
            ).invoke(actor_context=actor, authorization=authorization)
        except Exception as error:
            return error

    with patch.object(BuiltinHandlerRegistry, "invoke", new=counted):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: invoke(), range(2)))
    winners = [value for value in results if not isinstance(value, Exception)]
    losers = [value for value in results if isinstance(value, Exception)]
    assert len(calls) == 1
    assert len(winners) == len(losers) == 1
    assert "already consumed" in str(losers[0])
    with patch.object(BuiltinHandlerRegistry, "invoke", new=counted):
        replay = PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: NOW,
            ids=_ids(),
        ).invoke(actor_context=actor, authorization=authorization)
    assert replay.outcome == winners[0].outcome
    assert replay.replayed is True
    assert len(calls) == 1


def test_concurrent_exact_issue_converges_on_one_authorization(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    authority = _authority(postgres_connections)
    before = _counts(postgres_connections)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _index: authority.issue(actor_context=actor, command=command),
                range(2),
            )
        )

    assert results[0].command == results[1].command
    assert results[0].grant == results[1].grant
    assert results[0].issuance_evidence == results[1].issuance_evidence
    assert sorted(result.replayed for result in results) == [False, True]
    assert _counts(postgres_connections) == (before[0] + 1, before[1] + 1)


def test_grant_expiry_is_capped_by_retention(postgres_connections):
    now = datetime.now(timezone.utc)
    retention_expiry = now + timedelta(seconds=45)
    actor, skill = _persisted_skill(
        postgres_connections,
        retention_expires_at=_ts(retention_expiry),
    )
    command = _execution_command(actor, skill)

    authorization = _authority(postgres_connections, now=now).issue(
        actor_context=actor,
        command=command,
    )

    assert authorization.grant["expires_at"] == _ts(retention_expiry)


def test_generic_evidence_writer_cannot_create_reserved_execution_events(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    forged_command = copy.deepcopy(dict(authorization.command))
    forged_command["operation_id"] = "phase5-forged-ledger-authorization"
    forged_command.pop("operation_digest")
    forged_command["operation_digest"] = execution_operation_digest(forged_command)
    forged_payload = {
        "actor_id": actor["actor_id"],
        "operation_id": forged_command["operation_id"],
        "operation_digest": forged_command["operation_digest"],
        "command": forged_command,
        "authorization_grant": copy.deepcopy(dict(authorization.grant)),
        "authorization_grant_digest": sha256_digest(authorization.grant),
        "policy_decision_digest": forged_command["policy_decision"]["decision_digest"],
        "state": "authorized",
    }
    before = _counts(postgres_connections)

    after_issuance = execution_module._parse_time(
        authorization.issuance_evidence["recorded_at"]
    ) + timedelta(milliseconds=1)
    with pytest.raises(Exception, match="reserved"):
        postgres_connections["store_at"](after_issuance).append(
            tenant_id=actor["tenant_id"],
            run_id=actor["session_id"],
            event_kind="execution.authorization_issued",
            policy_ref={
                "record_type": "policy_decision",
                "record_id": forged_command["policy_decision"]["decision_id"],
                "record_digest": forged_command["policy_decision"]["decision_digest"],
            },
            payload=forged_payload,
        )

    assert _counts(postgres_connections) == before


@pytest.mark.parametrize(
    "proof_field",
    ("issuer", "key_id", "algorithm", "detached_proof"),
)
def test_direct_sql_rejects_tampered_signed_grant_proof_with_live_writer(
    postgres_connections,
    proof_field,
):
    """Terminal veto: SQL must verify, not merely shape-check, grant proofs."""

    actor, skill = _persisted_skill(postgres_connections)
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception, match="detached proof verification failed"):
        _direct_issue_with_live_writer_and_tampered_grant(
            postgres_connections,
            actor=actor,
            skill=skill,
            proof_field=proof_field,
        )

    assert _snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    "proof_field",
    ("issuer", "key_id", "algorithm", "detached_proof"),
)
def test_direct_sql_rejects_tampered_signed_approval_proof_with_live_writer(
    postgres_connections,
    proof_field,
):
    """Terminal veto: approval proof selectors are cryptographically bound too."""

    actor, skill = _persisted_skill(postgres_connections)
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception, match="detached proof verification failed"):
        _direct_issue_with_live_writer_and_tampered_approval(
            postgres_connections,
            actor=actor,
            skill=skill,
            proof_field=proof_field,
        )

    assert _snapshot(postgres_connections) == before


def test_direct_sql_rejects_revoked_approval_with_live_writer(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception, match="approval is revoked"):
        _direct_issue_with_live_writer_and_tampered_approval(
            postgres_connections,
            actor=actor,
            skill=skill,
            proof_field="revoked_at",
        )

    assert _snapshot(postgres_connections) == before


def test_native_ed25519_verifier_is_verify_only_and_rejects_malformed_inputs(
    postgres_connections,
):
    signing_key = SigningKey(_TEST_SIGNING_SEED)
    message = b"gah-ed25519-native-vector-v1"
    signature = signing_key.sign(message).signature
    public_key = signing_key.verify_key.encode()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT gah_crypto.ed25519_verify_detached(%s::bytea,%s::bytea,%s::bytea)",
            (signature, message, public_key),
        )
        assert cursor.fetchone() == (True,)
        for malformed_signature, malformed_message, malformed_key in (
            (signature[:-1], message, public_key),
            (signature, message, public_key[:-1]),
            (signature, b"x" * (1024 * 1024 + 1), public_key),
        ):
            with pytest.raises(Exception, match="gah_ed25519 input is invalid"):
                cursor.execute(
                    "SELECT gah_crypto.ed25519_verify_detached(%s::bytea,%s::bytea,%s::bytea)",
                    (malformed_signature, malformed_message, malformed_key),
                )
            connection.rollback()


@pytest.mark.parametrize("offset", (timedelta(days=-1), timedelta(days=1)))
def test_direct_sql_rejects_backdated_or_future_proof_acceptance_time(
    postgres_connections,
    offset,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    before = _snapshot(postgres_connections)
    with (
        postgres_connections["execution_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        with pytest.raises(Exception, match="detached proof verification failed"):
            cursor.execute(
                "SELECT gah_verify_execution_signed_record(%s::jsonb,%s,%s::timestamptz)",
                (
                    execution_module._json(authorization.grant),
                    "grant_digest",
                    _ts(datetime.now(timezone.utc) + offset),
                ),
            )
    assert _snapshot(postgres_connections) == before


def test_direct_sql_proof_time_bounds_match_recorded_acceptance_rules(postgres_connections):
    """Key and record time bounds are terminal SQL checks, independent of Python."""

    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    before = _snapshot(postgres_connections)
    with (
        postgres_connections["admin"]() as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT valid_from FROM gah_execution_proof_keys "
            "WHERE issuer=%s AND key_id=%s AND algorithm=%s AND proof_domain=%s",
            ("policy.authority", "policy.key.v1", _TEST_ALGORITHM, "authorization_grant.v1"),
        )
        key_row = cursor.fetchone()
    assert key_row is not None
    key_valid_from = key_row[0]

    cases = (
        (
            "issued-before-key",
            key_valid_from - timedelta(milliseconds=1),
            datetime.now(timezone.utc) + timedelta(minutes=1),
        ),
        (
            "future-issued",
            datetime.now(timezone.utc) + timedelta(minutes=1),
            datetime.now(timezone.utc) + timedelta(minutes=2),
        ),
        (
            "acceptance-after-expiry",
            datetime.now(timezone.utc) - timedelta(minutes=2),
            datetime.now(timezone.utc) - timedelta(minutes=1),
        ),
    )
    for _label, issued_at, expires_at in cases:
        forged = copy.deepcopy(dict(authorization.grant))
        forged["issued_at"] = _ts(issued_at)
        forged["expires_at"] = _ts(expires_at)
        forged = _sign_record(
            forged,
            issuer="policy.authority",
            key_id="policy.key.v1",
            proof_domain="authorization_grant.v1",
            nonce="A" * 22,
        )
        with (
            postgres_connections["execution_authority"]() as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "SELECT to_char(date_trunc('milliseconds', transaction_timestamp()) "
                "AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')"
            )
            accepted_at = cursor.fetchone()
            assert accepted_at is not None and isinstance(accepted_at[0], str)
            with pytest.raises(Exception, match="detached proof verification failed"):
                cursor.execute(
                    "SELECT gah_verify_execution_signed_record(%s::jsonb,%s,%s::timestamptz)",
                    (execution_module._json(forged), "grant_digest", accepted_at[0]),
                )
    assert _snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    "tamper",
    (
        "missing_approval_proof",
        "null_approval_proof",
        "missing_grant_proof",
        "extra_grant_field",
        "missing_grant_expiry",
        "extra_evidence_field",
    ),
)
def test_direct_sql_rejects_malformed_or_unsigned_authority_without_mutation(
    postgres_connections,
    tamper,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    command = copy.deepcopy(dict(authorization.command))
    grant = copy.deepcopy(dict(authorization.grant))
    evidence = copy.deepcopy(dict(authorization.issuance_evidence))
    writer_authorization = copy.deepcopy(
        evidence["draft"]["inline_payload"]["writer_authorization"]
    )
    if tamper == "missing_approval_proof":
        command["approvals"][0].pop("proof")
    elif tamper == "null_approval_proof":
        command["approvals"][0]["proof"] = None
    elif tamper == "missing_grant_proof":
        grant.pop("proof")
    elif tamper == "extra_grant_field":
        grant["forged"] = True
    elif tamper == "missing_grant_expiry":
        grant.pop("expires_at")
    else:
        evidence["forged"] = True
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception):
        _direct_issue(
            postgres_connections,
            actor=actor,
            command=command,
            grant=grant,
            evidence=evidence,
            writer_authorization=writer_authorization,
        )

    assert _snapshot(postgres_connections) == before


def test_direct_sql_exact_replay_accepts_committed_writer_authorization_without_mutation(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    evidence = copy.deepcopy(dict(authorization.issuance_evidence))
    before = _snapshot(postgres_connections)

    replay = _direct_issue(
        postgres_connections,
        actor=actor,
        command=authorization.command,
        grant=authorization.grant,
        evidence=evidence,
        writer_authorization=evidence["draft"]["inline_payload"]["writer_authorization"],
    )
    assert replay["replayed"] is True
    assert replay["grant"] == authorization.grant
    assert replay["issuance_evidence"] == authorization.issuance_evidence
    assert _snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    ("event_kind", "path", "value"),
    (
        (
            "execution.authorization_issued",
            "{draft,inline_payload,authorization_grant,proof,detached_proof}",
            '"forged"',
        ),
        ("execution.intent", "{draft,inline_payload,state}", '"authorized"'),
        ("execution.outcome", "{draft,inline_payload,state}", '"authorized"'),
    ),
)
def test_rebuild_rejects_admin_poisoned_canonical_evidence_without_mutation(
    postgres_connections,
    event_kind,
    path,
    value,
):
    actor, skill = _persisted_skill(postgres_connections)
    authority = _authority(postgres_connections)
    authorization = authority.issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
    ).invoke(actor_context=actor, authorization=authorization)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_evidence_events "
            "SET envelope_json=jsonb_set(envelope_json,%s::text[],%s::jsonb,false) "
            "WHERE envelope_json#>>'{draft,event_kind}'=%s "
            "AND envelope_json#>>'{draft,inline_payload,operation_id}'=%s",
            (
                path.strip("{}").split(","),
                value,
                event_kind,
                authorization.command["operation_id"],
            ),
        )
        assert cursor.rowcount == 1
        cursor.execute(
            "DELETE FROM gah_builtin_execution_state WHERE tenant_id=%s AND operation_id=%s",
            (actor["tenant_id"], authorization.command["operation_id"]),
        )
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception):
        authority.rebuild(
            actor_context=actor,
            operation_id=authorization.command["operation_id"],
            operation_digest=authorization.command["operation_digest"],
        )

    assert _snapshot(postgres_connections) == before


@pytest.mark.parametrize(
    "event_kind",
    (
        "execution.authorization_issued",
        "execution.intent",
        "execution.outcome",
    ),
)
def test_rebuild_rejects_rehashed_row_or_head_poison_without_mutation(
    postgres_connections,
    event_kind,
):
    """Rebuild requires envelope-row bindings and a current authoritative head.

    The administrator-only poison keeps every pre-existing row CHECK valid:
    it rehashes the chosen envelope and stored digest, then repairs the next
    row's relational predecessor when one exists.  The state projection is
    removed before rebuild, so a failure proves no replacement projection was
    written.
    """

    actor, skill = _persisted_skill(postgres_connections)
    authority = _authority(postgres_connections)
    authorization = authority.issue(
        actor_context=actor,
        command=_execution_command(actor, skill, operation_id="phase5-rehash-poison"),
    )
    PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
    ).invoke(actor_context=actor, authorization=authorization)

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT sequence_number, envelope_json FROM gah_evidence_events "
            "WHERE tenant_id=%s AND actor_id=%s AND run_id=%s "
            "AND envelope_json#>>'{draft,event_kind}'=%s "
            "AND envelope_json#>>'{draft,inline_payload,operation_id}'=%s",
            (
                actor["tenant_id"],
                actor["actor_id"],
                actor["session_id"],
                event_kind,
                authorization.command["operation_id"],
            ),
        )
        target = cursor.fetchone()
        assert target is not None
        sequence_number, original_envelope = target
        poisoned = copy.deepcopy(original_envelope)
        poisoned["draft"]["idempotency"]["idempotency_key"] += ".poisoned"
        poisoned["draft_digest"] = sha256_digest(poisoned["draft"])
        poisoned["payload_digest"] = sha256_digest(poisoned["draft"]["inline_payload"])
        unsigned_envelope = copy.deepcopy(poisoned)
        unsigned_envelope.pop("event_digest")
        poisoned["event_digest"] = sha256_digest(unsigned_envelope)
        cursor.execute(
            "UPDATE gah_evidence_events SET envelope_json=%s::jsonb,event_digest=%s "
            "WHERE tenant_id=%s AND actor_id=%s AND run_id=%s AND sequence_number=%s",
            (
                json.dumps(poisoned),
                poisoned["event_digest"],
                actor["tenant_id"],
                actor["actor_id"],
                actor["session_id"],
                sequence_number,
            ),
        )
        assert cursor.rowcount == 1
        if event_kind != "execution.outcome":
            cursor.execute(
                "UPDATE gah_evidence_events SET prior_event_digest=%s "
                "WHERE tenant_id=%s AND actor_id=%s AND run_id=%s "
                "AND sequence_number=%s",
                (
                    poisoned["event_digest"],
                    actor["tenant_id"],
                    actor["actor_id"],
                    actor["session_id"],
                    sequence_number + 1,
                ),
            )
            assert cursor.rowcount == 1
        cursor.execute(
            "DELETE FROM gah_builtin_execution_state WHERE tenant_id=%s AND operation_id=%s",
            (actor["tenant_id"], authorization.command["operation_id"]),
        )
        assert cursor.rowcount == 1
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception, match="authoritative row|authoritative run head"):
        authority.rebuild(
            actor_context=actor,
            operation_id=authorization.command["operation_id"],
            operation_digest=authorization.command["operation_digest"],
        )

    assert _snapshot(postgres_connections) == before


def test_retention_expiry_is_rechecked_at_consume_without_mutation(
    postgres_connections,
):
    retention_expiry = datetime.now(timezone.utc) + timedelta(seconds=3)
    actor, skill = _persisted_skill(
        postgres_connections,
        retention_expires_at=_ts(retention_expiry),
    )
    authorization = _authority(
        postgres_connections,
        now=datetime.now(timezone.utc),
    ).issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    while datetime.now(timezone.utc) <= retention_expiry:
        time.sleep(0.05)
    before = _snapshot(postgres_connections)

    with pytest.raises(Exception, match="stale or expired"):
        PostgresBuiltinExecutionRuntime(
            runtime_connect=postgres_connections["app"],
            clock=lambda: datetime.now(timezone.utc),
            ids=_ids(),
        ).invoke(actor_context=actor, authorization=authorization)

    assert _snapshot(postgres_connections) == before


def test_runtime_rejects_lease_that_outlives_actor_and_grant_without_mutation(
    postgres_connections,
):
    actor, skill = _persisted_skill(
        postgres_connections,
        actor_expires_at=_ts(NOW + timedelta(minutes=2)),
    )
    authorization = _authority(postgres_connections).issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )
    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
        lease_duration=timedelta(minutes=3),
    )
    invoked = False

    def record_invoke(_registry, *, request):
        nonlocal invoked
        del request
        invoked = True
        raise AssertionError("handler must not run beyond the authorization window")

    before = _snapshot(postgres_connections)
    with patch.object(BuiltinHandlerRegistry, "invoke", new=record_invoke):
        with pytest.raises(Exception):
            runtime.invoke(actor_context=actor, authorization=authorization)

    assert invoked is False
    assert _snapshot(postgres_connections) == before


def test_rebuild_preserves_live_execution_and_projection_loss_is_recovery_only(
    postgres_connections,
):
    actor, skill = _persisted_skill(postgres_connections)
    authority = _authority(postgres_connections)
    authorization = authority.issue(
        actor_context=actor,
        command=_execution_command(actor, skill),
    )

    def crash(_registry, *, request):
        del request
        raise RuntimeError("simulated host crash")

    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
        lease_duration=timedelta(seconds=30),
    )
    with patch.object(BuiltinHandlerRegistry, "invoke", new=crash):
        with pytest.raises(RuntimeError, match="simulated host crash"):
            runtime.invoke(actor_context=actor, authorization=authorization)
    live_snapshot = _snapshot(postgres_connections)

    replay = authority.rebuild(
        actor_context=actor,
        operation_id=authorization.command["operation_id"],
        operation_digest=authorization.command["operation_digest"],
    )

    assert replay.replayed is True
    assert _snapshot(postgres_connections) == live_snapshot
    with pytest.raises(Exception, match="lease"):
        runtime.recover(actor_context=actor, authorization=authorization)
    assert _snapshot(postgres_connections) == live_snapshot

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM gah_builtin_execution_state WHERE tenant_id=%s AND operation_id=%s",
            (actor["tenant_id"], authorization.command["operation_id"]),
        )
    evidence_before = _snapshot(postgres_connections)[1]
    rebuilt = authority.rebuild(
        actor_context=actor,
        operation_id=authorization.command["operation_id"],
        operation_digest=authorization.command["operation_digest"],
    )
    assert rebuilt.replayed is True
    assert _snapshot(postgres_connections)[1] == evidence_before

    recovered = runtime.recover(actor_context=actor, authorization=rebuilt)
    assert recovered.outcome["status"] == "indeterminate"


def test_expired_authorization_and_crash_recovery_fail_closed(postgres_connections):
    actor, skill = _persisted_skill(postgres_connections)
    command = _execution_command(actor, skill)
    authorization = _authority(postgres_connections).issue(actor_context=actor, command=command)
    before = _counts(postgres_connections)
    expired_grant = copy.deepcopy(dict(authorization.grant))
    expired_grant["expires_at"] = "2026-01-01T00:00:01.000Z"
    apply_object_digest(expired_grant)
    expired = ExecutionAuthorization(
        authorization.command,
        expired_grant,
        authorization.issuance_evidence,
    )
    try:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            _drop_execution_binding_guard(cursor)
            cursor.execute(
                "UPDATE gah_builtin_execution_state SET grant_json=%s::jsonb WHERE operation_id=%s",
                (
                    json.dumps(expired_grant),
                    command["operation_id"],
                ),
            )
        with pytest.raises(Exception, match="stale or expired"):
            PostgresBuiltinExecutionRuntime(
                runtime_connect=postgres_connections["app"],
                clock=lambda: NOW,
                ids=_ids(),
            ).invoke(actor_context=actor, authorization=expired)
        assert _counts(postgres_connections) == before
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            if not _execution_binding_guard_exists(cursor):
                cursor.execute(
                    "UPDATE gah_builtin_execution_state SET grant_json=%s::jsonb "
                    "WHERE operation_id=%s",
                    (
                        json.dumps(dict(authorization.grant)),
                        command["operation_id"],
                    ),
                )
                _restore_execution_binding_guard(cursor)

    def crash(_registry, *, request):
        del request
        raise RuntimeError("simulated host crash")

    runtime = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
        lease_duration=timedelta(milliseconds=100),
    )
    with patch.object(BuiltinHandlerRegistry, "invoke", new=crash):
        with pytest.raises(RuntimeError, match="simulated host crash"):
            runtime.invoke(actor_context=actor, authorization=authorization)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT intent_evidence_json,execution_attempt_id,owner_generation "
            "FROM gah_builtin_execution_state WHERE operation_id=%s",
            (command["operation_id"],),
        )
        intent, attempt_id, generation = cursor.fetchone()
    request = command["tool_request"]
    policy = command["policy_decision"]
    tampered_outcome = runtime._outcome(
        actor=actor,
        request=request,
        policy=policy,
        approvals=tuple(command["approvals"]),
        grant=authorization.grant,
        intent=intent,
        result_payload={"echo": {"message": "tampered"}},
        status="succeeded",
    )
    tampered_payload = {
        "actor_id": actor["actor_id"],
        "operation_id": command["operation_id"],
        "operation_digest": authorization.command["operation_digest"],
        "authorization_grant_digest": sha256_digest(authorization.grant),
        "outcome_digest": tampered_outcome["outcome_digest"],
        "status": "succeeded",
        "state": "completed",
        "outcome": tampered_outcome,
    }
    before_tamper = _counts(postgres_connections)
    connection = postgres_connections["app"]()
    try:
        with connection.cursor() as cursor:
            evidence = execution_module._build_evidence(
                actor=actor,
                run_id=request["run_id"],
                event_kind="execution.outcome",
                policy=policy,
                payload=tampered_payload,
                head=execution_module._head(cursor, actor, request["run_id"]),
                clock=lambda: NOW,
                ids=_ids(),
            )
            with pytest.raises(
                Exception,
                match="outcome is malformed or unbound|completion binding is invalid",
            ):
                cursor.execute(
                    "SELECT gah_complete_builtin_execution"
                    "(%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb)",
                    (
                        execution_module._json(actor),
                        execution_module._json(
                            {
                                "operation_id": command["operation_id"],
                                "operation_digest": authorization.command["operation_digest"],
                                "attempt_id": attempt_id,
                                "owner_generation": generation,
                            }
                        ),
                        execution_module._json(tampered_outcome),
                        execution_module._json(evidence),
                    ),
                )
    finally:
        connection.rollback()
        connection.close()
    assert _counts(postgres_connections) == before_tamper
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_builtin_execution_state "
            "SET lease_expires_at=clock_timestamp()-interval '1 second' "
            "WHERE operation_id=%s",
            (command["operation_id"],),
        )
    recovered = PostgresBuiltinExecutionRuntime(
        runtime_connect=postgres_connections["app"],
        clock=lambda: NOW,
        ids=_ids(),
    ).recover(actor_context=actor, authorization=authorization)
    assert recovered.outcome["status"] == "indeterminate"
