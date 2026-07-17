from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from governed_agent_harness.contracts import apply_object_digest, sha256_digest
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import (
    DurableStoreError,
    OptimisticConcurrencyError,
    PostgresDurableEffectStore,
)


def _inputs():
    records = build_positive_records()
    actor = records["actor_context"]
    request = records["tool_request"]
    policy = records["policy_decision"]
    approval = copy.deepcopy(records["approval_record"])
    grant = copy.deepcopy(records["authorization_grant"])
    grant["idempotency"] = copy.deepcopy(request["idempotency"])
    apply_object_digest(grant)
    return actor, request, policy, (approval,), grant


def _intent_payload(actor, request, policy, grant):
    return {
        "actor_id": actor["actor_id"],
        "request_digest": request["request_digest"],
        "policy_decision_digest": policy["decision_digest"],
        "authorization_grant_digest": sha256_digest(grant),
        "effect_classes": copy.deepcopy(request["effect_classes"]),
        "isolation_profile": grant["isolation_profile"],
    }


def test_postgres_prepare_complete_replay_and_per_run_sequence(postgres_connections):
    store = postgres_connections["store"]()
    actor, request, policy, approvals, grant = _inputs()
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }
    prepared = store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=approvals,
        grant=grant,
        policy_ref=policy_ref,
        intent_payload=_intent_payload(actor, request, policy, grant),
    )
    assert prepared.created is True
    assert prepared.state == "prepared"
    outcome = _outcome(prepared, policy, request, actor, grant, approvals, status="succeeded")
    completed = store.complete(
        actor_context=actor,
        request_id=request["request_id"],
        expected_version=prepared.version,
        outcome=outcome,
        policy_ref=policy_ref,
        outcome_payload={
            "actor_id": actor["actor_id"],
            "status": "succeeded",
            "outcome_digest": outcome["outcome_digest"],
            "request_digest": request["request_digest"],
            "authorization_grant_digest": sha256_digest(grant),
        },
        state="completed",
        execution_attempt_id=prepared.execution_attempt_id,
        owner_generation=prepared.owner_generation,
    )
    assert completed.state == "completed"
    replay = store.lookup(actor_context=actor, request_id=request["request_id"])
    assert replay is not None
    assert replay.outcome == outcome
    assert len(store.events(actor_context=actor, run_id=request["run_id"])) == 2
    with pytest.raises(OptimisticConcurrencyError):
        store.complete(
            actor_context=actor,
            request_id=request["request_id"],
            expected_version=prepared.version - 1,
            outcome=outcome,
            policy_ref=policy_ref,
            outcome_payload={"status": "succeeded"},
            state="completed",
            execution_attempt_id=prepared.execution_attempt_id,
            owner_generation=prepared.owner_generation,
        )


def test_postgres_forced_rls_hides_other_tenant(postgres_connections):
    store = postgres_connections["store"]()
    actor, request, policy, approvals, grant = _inputs()
    store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=approvals,
        grant=grant,
        policy_ref={
            "record_type": "policy_decision",
            "record_id": policy["decision_id"],
            "record_digest": policy["decision_digest"],
        },
        intent_payload=_intent_payload(actor, request, policy, grant),
    )
    other = copy.deepcopy(actor)
    other["tenant_id"] = "018f0000-0000-7000-8000-000000000099"
    with pytest.raises(Exception, match="outside actor scope"):
        store.lookup(actor_context=other, request_id=request["request_id"])
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception):
            cursor.execute("SELECT count(*) FROM gah_effect_executions")

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'gah_app'")
        assert cursor.fetchone() == (False, False)
        cursor.execute(
            "SELECT bool_or(has_table_privilege('gah_app', relname, 'SELECT')) "
            "FROM pg_class WHERE relname IN ('gah_run_heads','gah_evidence_events',"
            "'gah_effect_executions','gah_grant_consumptions')"
        )
        assert cursor.fetchone()[0] is False
        cursor.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname = 'gah_effect_executions'"
        )
        assert cursor.fetchone() == (True, True)


def test_postgres_prepare_race_consumes_one_grant_and_one_intent(postgres_connections):
    actor, request, policy, approvals, grant = _inputs()
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }

    def prepare_once():
        return postgres_connections["store"]().prepare(
            actor_context=actor,
            request=request,
            policy=policy,
            approvals=approvals,
            grant=grant,
            policy_ref=policy_ref,
            intent_payload=_intent_payload(actor, request, policy, grant),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: prepare_once(), range(2)))
    assert sum(result.created for result in results) == 1
    assert {result.state for result in results} == {"prepared"}
    assert (
        len(postgres_connections["store"]().events(actor_context=actor, run_id=request["run_id"]))
        == 1
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_effect_executions")
        assert cursor.fetchone()[0] == 1
        cursor.execute("SELECT count(*) FROM gah_grant_consumptions")
        assert cursor.fetchone()[0] == 1


def test_execution_lease_renewal_expiry_and_stale_owner_fence(postgres_connections):
    store = postgres_connections["store"]()
    actor, request, policy, approvals, grant = _inputs()
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }
    prepared = store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=approvals,
        grant=grant,
        policy_ref=policy_ref,
        intent_payload=_intent_payload(actor, request, policy, grant),
    )
    renewed = store.renew_lease(
        actor_context=actor,
        request_id=request["request_id"],
        execution_attempt_id=prepared.execution_attempt_id,
        owner_generation=prepared.owner_generation,
    )
    assert renewed.state == "executing"
    assert renewed.last_renewed_at >= prepared.last_renewed_at
    indeterminate = _outcome(
        prepared, policy, request, actor, grant, approvals, status="indeterminate"
    )
    recovery_payload = {
        "actor_id": actor["actor_id"],
        "request_digest": request["request_digest"],
        "authorization_grant_digest": sha256_digest(grant),
        "outcome_digest": indeterminate["outcome_digest"],
        "status": "indeterminate",
        "recovery": "lease_expired",
    }
    with pytest.raises(Exception, match="lease has not expired"):
        store.recover_expired(
            actor_context=actor,
            request_id=request["request_id"],
            outcome=indeterminate,
            policy_ref=policy_ref,
            outcome_payload=recovery_payload,
        )

    postgres_connections["expire_lease"](request["request_id"])
    recovered = store.recover_expired(
        actor_context=actor,
        request_id=request["request_id"],
        outcome=indeterminate,
        policy_ref=policy_ref,
        outcome_payload=recovery_payload,
    )
    assert recovered.state == "indeterminate"
    assert recovered.owner_generation == prepared.owner_generation + 1

    succeeded = _outcome(prepared, policy, request, actor, grant, approvals, status="succeeded")
    with pytest.raises(OptimisticConcurrencyError):
        store.complete(
            actor_context=actor,
            request_id=request["request_id"],
            expected_version=prepared.version,
            outcome=succeeded,
            policy_ref=policy_ref,
            outcome_payload={
                "actor_id": actor["actor_id"],
                "request_digest": request["request_digest"],
                "authorization_grant_digest": sha256_digest(grant),
                "outcome_digest": succeeded["outcome_digest"],
                "status": "succeeded",
            },
            state="completed",
            execution_attempt_id=prepared.execution_attempt_id,
            owner_generation=prepared.owner_generation,
        )


def test_live_completion_and_expired_recovery_race_has_one_terminal_event(
    postgres_connections,
):
    store = postgres_connections["store"]()
    actor, request, policy, approvals, grant = _inputs()
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }
    prepared = store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=approvals,
        grant=grant,
        policy_ref=policy_ref,
        intent_payload=_intent_payload(actor, request, policy, grant),
    )
    succeeded = _outcome(prepared, policy, request, actor, grant, approvals, status="succeeded")
    indeterminate = _outcome(
        prepared, policy, request, actor, grant, approvals, status="indeterminate"
    )
    postgres_connections["expire_lease"](request["request_id"])

    def complete():
        return store.complete(
            actor_context=actor,
            request_id=request["request_id"],
            expected_version=prepared.version,
            outcome=succeeded,
            policy_ref=policy_ref,
            outcome_payload={
                "actor_id": actor["actor_id"],
                "request_digest": request["request_digest"],
                "authorization_grant_digest": sha256_digest(grant),
                "outcome_digest": succeeded["outcome_digest"],
                "status": "succeeded",
            },
            state="completed",
            execution_attempt_id=prepared.execution_attempt_id,
            owner_generation=prepared.owner_generation,
        )

    def recover():
        return store.recover_expired(
            actor_context=actor,
            request_id=request["request_id"],
            outcome=indeterminate,
            policy_ref=policy_ref,
            outcome_payload={
                "actor_id": actor["actor_id"],
                "request_digest": request["request_digest"],
                "authorization_grant_digest": sha256_digest(grant),
                "outcome_digest": indeterminate["outcome_digest"],
                "status": "indeterminate",
                "recovery": "lease_expired",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(complete), pool.submit(recover)]
        results = []
        failures = []
        for future in futures:
            try:
                results.append(future.result())
            except Exception as exc:  # exact loser varies with lock acquisition
                failures.append(exc)
    assert len(results) == 1
    assert len(failures) == 1
    assert results[0].state == "indeterminate"
    assert len(store.events(actor_context=actor, run_id=request["run_id"])) == 2


def test_completion_prevents_later_expired_recovery_transition(
    postgres_connections,
):
    store = postgres_connections["store"]()
    actor, request, policy, approvals, grant = _inputs()
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }
    prepared = store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=approvals,
        grant=grant,
        policy_ref=policy_ref,
        intent_payload=_intent_payload(actor, request, policy, grant),
    )
    succeeded = _outcome(prepared, policy, request, actor, grant, approvals, status="succeeded")
    indeterminate = _outcome(
        prepared, policy, request, actor, grant, approvals, status="indeterminate"
    )
    completed = store.complete(
        actor_context=actor,
        request_id=request["request_id"],
        expected_version=prepared.version,
        outcome=succeeded,
        policy_ref=policy_ref,
        outcome_payload={
            "actor_id": actor["actor_id"],
            "request_digest": request["request_digest"],
            "authorization_grant_digest": sha256_digest(grant),
            "outcome_digest": succeeded["outcome_digest"],
            "status": "succeeded",
        },
        state="completed",
        execution_attempt_id=prepared.execution_attempt_id,
        owner_generation=prepared.owner_generation,
    )
    postgres_connections["expire_lease"](request["request_id"])
    reconciled = store.recover_expired(
        actor_context=actor,
        request_id=request["request_id"],
        outcome=indeterminate,
        policy_ref=policy_ref,
        outcome_payload={
            "actor_id": actor["actor_id"],
            "request_digest": request["request_digest"],
            "authorization_grant_digest": sha256_digest(grant),
            "outcome_digest": indeterminate["outcome_digest"],
            "status": "indeterminate",
            "recovery": "lease_expired",
        },
    )
    assert completed.state == reconciled.state == "completed"
    assert completed.outcome == reconciled.outcome == succeeded
    assert len(store.events(actor_context=actor, run_id=request["run_id"])) == 2


def test_postgres_rls_scope_and_runtime_role_are_fail_closed(postgres_connections):
    store = postgres_connections["store"]()
    actor, request, policy, approvals, grant = _inputs()
    store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=approvals,
        grant=grant,
        policy_ref={
            "record_type": "policy_decision",
            "record_id": policy["decision_id"],
            "record_digest": policy["decision_digest"],
        },
        intent_payload=_intent_payload(actor, request, policy, grant),
    )
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT set_config('gah.tenant_id', %s, true)", (actor["tenant_id"],))
        cursor.execute("SELECT set_config('gah.actor_id', %s, true)", ("other-actor",))
        for table in (
            "gah_run_heads",
            "gah_evidence_events",
            "gah_effect_executions",
            "gah_grant_consumptions",
        ):
            with pytest.raises(Exception):
                cursor.execute(f"SELECT count(*) FROM {table}")
        with pytest.raises(Exception):
            cursor.execute("UPDATE gah_effect_executions SET state = 'completed'")
        with pytest.raises(Exception):
            cursor.execute(
                "INSERT INTO gah_grant_consumptions "
                "(tenant_id, actor_id, grant_id, grant_digest, request_id, consumed_at) "
                "VALUES ('x','x','x','sha256:' || repeat('0',64),'x',now())"
            )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname IN ('gah_run_heads','gah_evidence_events',"
            "'gah_effect_executions','gah_grant_consumptions') ORDER BY relname"
        )
        assert cursor.fetchall() == [
            (name, True, True)
            for name in (
                "gah_effect_executions",
                "gah_evidence_events",
                "gah_grant_consumptions",
                "gah_run_heads",
            )
        ]


def test_postgres_chronology_regression_rolls_back_without_event(postgres_connections):
    actor, request, policy, approvals, grant = _inputs()
    now = [datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)]
    store = PostgresDurableEffectStore(
        connect=postgres_connections["app"],
        privileged_connect=postgres_connections["writer"],
        clock=lambda: now[0],
        ids=lambda: "018f0000-0000-7000-8000-000000000099",
    )
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }
    store.prepare(
        actor_context=actor,
        request=request,
        policy=policy,
        approvals=approvals,
        grant=grant,
        policy_ref=policy_ref,
        intent_payload=_intent_payload(actor, request, policy, grant),
    )
    before = len(store.events(actor_context=actor, run_id=request["run_id"]))
    now[0] = datetime(2025, 12, 31, 23, 59, tzinfo=timezone.utc)
    with pytest.raises(DurableStoreError):
        store.append(
            tenant_id=actor["tenant_id"],
            run_id=request["run_id"],
            event_kind="kernel.policy_decided",
            policy_ref=policy_ref,
            payload={"actor_id": actor["actor_id"]},
        )
    assert len(store.events(actor_context=actor, run_id=request["run_id"])) == before


def _outcome(prepared, policy, request, actor, grant, approvals, *, status):
    now = "2026-01-01T00:12:00.000Z"
    outcome = {
        "schema_version": "1.0",
        "record_type": "action_outcome",
        "tenant_id": request["tenant_id"],
        "outcome_id": "018f0000-0000-7000-8000-000000000088",
        "target_scope": {
            "schema_version": "1.0",
            "record_type": "memory_scope",
            "scope_id": "018f0000-0000-7000-8000-000000000089",
            "tenant_id": actor["tenant_id"],
            "actor_id": actor["actor_id"],
            "parent_record_type": "actor_context",
            "parent_digest": sha256_digest(actor),
            "selection": {"level": "actor"},
            "derived_at": now,
            "valid_until": actor["expires_at"],
        },
        "run_id": request["run_id"],
        "request_ref": {
            "record_type": "tool_request",
            "record_id": request["request_id"],
            "record_digest": request["request_digest"],
        },
        "status": status,
        "effect_state": status,
        "evidence_refs": [
            {
                "record_type": "evidence_envelope",
                "record_id": prepared.intent_evidence["envelope_id"],
                "record_digest": prepared.intent_evidence["event_digest"],
            }
        ],
        "provenance_digest": sha256_digest(
            {
                "authorization_grant_digest": sha256_digest(grant),
                "intent_evidence_digest": prepared.intent_evidence["event_digest"],
                "result_payload": {"ok": True},
            }
        ),
        "result_payload": {"ok": True},
        "producer_version": "governed_effects.v1",
        "runtime_version": "phase4.postgresql.v1",
        "policy_refs": [
            {
                "record_type": "policy_decision",
                "record_id": policy["decision_id"],
                "record_digest": policy["decision_digest"],
            }
        ],
        "reviewer_refs": [
            {
                "record_type": "approval_record",
                "record_id": approvals[0]["approval_id"],
                "record_digest": approvals[0]["approval_digest"],
            }
        ],
        "compatibility": {
            "contract_versions": ["action_outcome=1.0"],
            "runtime_version_range": ">=0.1",
        },
        "idempotency": copy.deepcopy(request["idempotency"]),
        "occurred_at": now,
        "outcome_digest": "sha256:" + "0" * 64,
    }
    apply_object_digest(outcome)
    return outcome
