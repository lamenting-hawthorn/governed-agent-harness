"""Real-PostgreSQL proof for Phase 5.1 actor-scoped lifecycle hardening."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json

import pytest

from governed_agent_harness.contracts import (
    TrustContext,
    TrustedKey,
    apply_object_digest,
    sha256_digest,
)
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import (
    PostgresActiveSkillResolver,
    PostgresDurableEffectStore,
    PostgresSkillLifecycleAuthority,
)
from skill_lifecycle_support import command as build_command, ref


NOW = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)
RECEIPT_NOW = datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)


def _ids():
    sequence = 0xD000

    def next_id() -> str:
        nonlocal sequence
        sequence += 1
        return f"018f0000-0000-7000-8000-{sequence:012x}"

    return next_id


class _AcceptingVerifier:
    def verify(self, **_values: object) -> bool:
        return True


def _receipt_trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="runtime.authority",
                key_id="runtime.key.v1",
                algorithms=frozenset({"fixture-proof-v1"}),
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
            ),
        ),
        allowed_algorithms=frozenset({"fixture-proof-v1"}),
        allowed_proof_domains=frozenset({"activation_receipt.v1"}),
        expected_issuers=frozenset({"runtime.authority"}),
        allowed_domain_issuers=frozenset({("activation_receipt.v1", "runtime.authority")}),
        trust_policy_version="skill-actor-scope.test.v1",
    )


def _actor_and_command(
    postgres_connections,
    *,
    actor_id: str | None = None,
    session_id: str | None = None,
    provision: bool = False,
):
    actor, command = build_command()
    actor.update(
        {"issued_at": "2026-01-01T00:00:01.000Z", "expires_at": "2030-01-01T00:00:00.000Z"}
    )
    if actor_id is not None:
        actor["actor_id"] = actor_id
    if session_id is not None:
        actor["session_id"] = session_id
        actor["correlation_id"] = session_id
    apply_object_digest(actor)
    scope = command["skill_proposal"]["target_scope"]
    scope.update({"actor_id": actor["actor_id"], "parent_digest": sha256_digest(actor)})
    command["gate_decision"]["target_scope"] = copy.deepcopy(scope)
    command["delivery_envelope"]["target_scope"] = copy.deepcopy(scope)
    if provision:
        _provision_second_actor(postgres_connections, actor)
    source = postgres_connections["store_at"](NOW).append(
        tenant_id=actor["tenant_id"],
        run_id=f"{actor['session_id'][:-1]}f",
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
    source_ref = ref("evidence_envelope", source["envelope_id"], source["event_digest"])
    command["source_evidence"] = [source]
    proposal = command["skill_proposal"]
    proposal["evidence_refs"] = [source_ref]
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
            "evidence_refs": [source_ref],
            "policy_refs": [
                ref("policy_decision", policy["decision_id"], policy["decision_digest"])
            ],
            "gate_decision_ref": ref("gate_decision", gate["gate_id"], gate["decision_digest"]),
        }
    )
    apply_object_digest(delivery)
    return actor, command


def _activation_receipt(command):
    receipt = copy.deepcopy(build_positive_records()["activation_receipt"])
    delivery = command["delivery_envelope"]
    proposal = command["skill_proposal"]
    receipt.update(
        {
            "target_scope": copy.deepcopy(delivery["target_scope"]),
            "delivery_id": delivery["delivery_id"],
            "delivery_digest": delivery["envelope_digest"],
            "artifact_type": delivery["artifact_type"],
            "artifact_id": delivery["artifact_id"],
            "artifact_revision": delivery["artifact_revision"],
            "artifact_digest": delivery["artifact_digest"],
            "activated_revision": ref(
                "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
            ),
            "evidence_refs": copy.deepcopy(delivery["evidence_refs"]),
            "policy_refs": copy.deepcopy(delivery["policy_refs"]),
            "reviewer_refs": copy.deepcopy(delivery["reviewer_refs"]),
        }
    )
    return apply_object_digest(receipt)


def _authority(postgres_connections):
    return PostgresSkillLifecycleAuthority(
        privileged_connect=postgres_connections["skill_authority"],
        evidence_writer_connect=postgres_connections["writer"],
        clock=lambda: RECEIPT_NOW,
        ids=_ids(),
        receipt_verifier=_AcceptingVerifier(),
        receipt_trust=_receipt_trust,
    )


def _provision_second_actor(postgres_connections, actor) -> None:
    import psycopg

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT current_database()")
        cursor.fetchone()
        dsn = connection.info.dsn
    PostgresDurableEffectStore.provision_principal(
        admin_connect=lambda: psycopg.connect(dsn),
        database_roles=(
            "gah_app",
            "gah_writer",
            "gah_skill_authority",
            "gah_execution_authority",
        ),
        actor_context=actor,
    )


def test_same_tenant_actors_independently_activate_fixed_builtin_skill(postgres_connections):
    actor_a, install_a = _actor_and_command(
        postgres_connections,
    )
    authority = _authority(postgres_connections)
    first_a = authority.install_skill(actor_context=actor_a, **install_a)
    activate_a = copy.deepcopy(install_a)
    activate_a.update(
        {
            "operation_id": "same-operation-id",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install_a),
        }
    )
    active_a = authority.activate_skill(actor_context=actor_a, **activate_a)
    actor_b, install_b = _actor_and_command(
        postgres_connections,
        actor_id="018f0000-0000-7000-8000-0000000000a2",
        session_id="018f0000-0000-7000-8000-0000000000b2",
        provision=True,
    )
    first_b = authority.install_skill(actor_context=actor_b, **install_b)
    activate_b = copy.deepcopy(install_b)
    activate_b.update(
        {
            "operation_id": "same-operation-id",
            "expected_revision": 1,
            "activation_receipt": _activation_receipt(install_b),
        }
    )
    active_b = authority.activate_skill(actor_context=actor_b, **activate_b)
    replay_b = authority.activate_skill(actor_context=actor_b, **activate_b)
    _provision_second_actor(postgres_connections, actor_a)
    replay_a = authority.activate_skill(actor_context=actor_a, **activate_a)

    assert first_a.skill_id == first_b.skill_id == install_a["skill_proposal"]["artifact_id"]
    assert first_a.replayed is False and first_b.replayed is False
    assert active_a.replayed is False and active_b.replayed is False
    assert replay_a.replayed is True and replay_a.transition_digest == active_a.transition_digest
    assert replay_b.replayed is True and replay_b.transition_digest == active_b.transition_digest
    resolver = PostgresActiveSkillResolver(runtime_connect=postgres_connections["app"])
    assert resolver.resolve_active_skill(actor_context=actor_a, skill_id=active_a.skill_id)
    _provision_second_actor(postgres_connections, actor_b)
    assert resolver.resolve_active_skill(actor_context=actor_b, skill_id=active_b.skill_id)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT actor_id, lifecycle_state FROM gah_active_skill_projection "
            "WHERE tenant_id=%s AND skill_id=%s ORDER BY actor_id",
            (actor_a["tenant_id"], active_a.skill_id),
        )
        assert cursor.fetchall() == [
            (actor_a["actor_id"], "active"),
            (actor_b["actor_id"], "active"),
        ]


def test_generic_writer_cannot_poison_lifecycle_evidence_but_specialized_sink_can(
    postgres_connections,
):
    actor, command = _actor_and_command(
        postgres_connections,
    )
    with postgres_connections["skill_authority"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT gah_skill_lifecycle_evidence_head(%s::jsonb)", (json.dumps(actor),))
        head = cursor.fetchone()[0]
    forged, version = postgres_connections["store_at"](NOW)._build_evidence_from_head(
        actor=actor,
        run_id=actor["session_id"],
        event_kind="skill.lifecycle_transition",
        policy_ref={
            "record_type": "policy_decision",
            "record_id": command["policy_decision"]["decision_id"],
            "record_digest": command["policy_decision"]["decision_digest"],
        },
        payload={"actor_id": actor["actor_id"], "forged": True},
        head=head,
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_evidence_events")
        before = cursor.fetchone()[0]
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="reserved evidence event kind"):
            cursor.execute(
                "SELECT gah_commit_evidence(%s::jsonb,%s::jsonb)",
                (
                    json.dumps(actor),
                    json.dumps(
                        {
                            "run_id": actor["session_id"],
                            "expected_version": version,
                            "envelope": forged,
                        }
                    ),
                ),
            )
        connection.rollback()
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_evidence_events")
        assert cursor.fetchone()[0] == before

    installed = _authority(postgres_connections).install_skill(actor_context=actor, **command)
    assert installed.replayed is False
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM gah_evidence_events "
            "WHERE tenant_id=%s AND actor_id=%s "
            "AND envelope_json#>>'{draft,event_kind}'='skill.lifecycle_transition'",
            (actor["tenant_id"], actor["actor_id"]),
        )
        assert cursor.fetchone()[0] == 1


def test_actor_scope_schema_and_functions_are_explicit(postgres_connections):
    expected_constraints = {
        "gah_skill_artifact_revisions_actor_pkey": "PRIMARY KEY (tenant_id, actor_id, skill_id, revision)",
        "gah_skill_lifecycle_transitions_actor_pkey": (
            "PRIMARY KEY (tenant_id, actor_id, skill_id, transition_sequence)"
        ),
        "gah_active_skill_projection_actor_pkey": "PRIMARY KEY (tenant_id, actor_id, skill_id)",
    }
    functions = (
        "gah_lookup_skill_replay(jsonb,jsonb)",
        "gah_apply_skill_lifecycle_validated(jsonb,jsonb,text)",
        "gah_rebuild_skill_projection_validated(jsonb,jsonb)",
        "gah_authorize_skill_lifecycle(jsonb,jsonb)",
        "gah_skill_assert_writer_authorization(jsonb,jsonb,jsonb)",
        "gah_apply_skill_lifecycle(jsonb,jsonb,text)",
        "gah_issue_builtin_execution_authorization(jsonb,jsonb,jsonb,jsonb,jsonb)",
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = ANY(%s) ORDER BY conname",
            (list(expected_constraints),),
        )
        constraints = dict(cursor.fetchall())
        for name, definition in expected_constraints.items():
            assert constraints[name] == definition
        for function in functions:
            cursor.execute(
                "SELECT pg_get_functiondef(%s::regprocedure), proconfig "
                "FROM pg_proc WHERE oid=%s::regprocedure",
                (function, function),
            )
            definition, settings = cursor.fetchone()
            assert "actor_id" in definition
            assert settings == ["search_path=pg_catalog, public"]
