from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

from governed_agent_harness.contracts import apply_object_digest
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import DurableStoreError


def _authority():
    records = build_positive_records()
    actor = records["actor_context"]
    request = records["tool_request"]
    policy = records["policy_decision"]
    approval = copy.deepcopy(records["approval_record"])
    approval.update(
        {
            "tenant_id": actor["tenant_id"],
            "request_id": request["request_id"],
            "request_digest": request["request_digest"],
            "policy_decision_id": policy["decision_id"],
            "policy_decision_digest": policy["decision_digest"],
            "constraints": copy.deepcopy(policy["constraints"]),
        }
    )
    apply_object_digest(approval)
    grant = copy.deepcopy(records["authorization_grant"])
    grant["idempotency"] = copy.deepcopy(request["idempotency"])
    grant["approval_refs"] = [
        {
            "record_type": "approval_record",
            "record_id": approval["approval_id"],
            "record_digest": approval["approval_digest"],
        }
    ]
    apply_object_digest(grant)
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }
    return actor, request, policy, approval, grant, policy_ref


def test_lifecycle_projection_is_rebuilt_from_canonical_evidence(postgres_connections):
    store = postgres_connections["store"]()
    actor, request, policy, approval, grant, policy_ref = _authority()
    submitted = store.persist_submission(
        actor_context=actor,
        request=request,
        policy=policy,
        state="approval_required",
        policy_ref=policy_ref,
    )
    approved = store.persist_approval(
        actor_context=actor,
        request_id=request["request_id"],
        expected_version=submitted.version,
        approval=approval,
        policy_ref=policy_ref,
    )
    issued = store.persist_grant(
        actor_context=actor,
        request_id=request["request_id"],
        expected_version=approved.version,
        grant=grant,
        policy_ref=policy_ref,
    )
    assert issued.state == "grant_issued"
    assert [event["draft"]["event_kind"] for event in issued.evidence] == [
        "kernel.policy_decided",
        "kernel.approval_accepted",
        "kernel.authorization_grant_issued",
    ]

    postgres_connections["tamper_projection"](request["request_id"])
    with pytest.raises(DurableStoreError, match="projection diverged"):
        store.load_lifecycle(actor_context=actor, request_id=request["request_id"])
    rebuilt = store.rebuild_lifecycle(actor_context=actor, request_id=request["request_id"])
    assert rebuilt == issued
    postgres_connections["tamper_projection_position"](request["request_id"])
    assert store.rebuild_lifecycle(actor_context=actor, request_id=request["request_id"]) == issued
    postgres_connections["delete_projection"](request["request_id"])
    assert store.load_lifecycle(actor_context=actor, request_id=request["request_id"]) is None
    assert store.rebuild_lifecycle(actor_context=actor, request_id=request["request_id"]) == issued
    assert store.load_lifecycle(actor_context=actor, request_id=request["request_id"]) == issued


def test_lifecycle_exact_replay_conflict_and_concurrent_transition(postgres_connections):
    actor, request, policy, approval, _grant, policy_ref = _authority()
    first = postgres_connections["store"]().persist_submission(
        actor_context=actor,
        request=request,
        policy=policy,
        state="approval_required",
        policy_ref=policy_ref,
    )
    replay = postgres_connections["store"]().persist_submission(
        actor_context=actor,
        request=request,
        policy=policy,
        state="approval_required",
        policy_ref=policy_ref,
    )
    assert replay == first

    def approve_once():
        return postgres_connections["store"]().persist_approval(
            actor_context=actor,
            request_id=request["request_id"],
            expected_version=first.version,
            approval=approval,
            policy_ref=policy_ref,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(approve_once) for _index in range(2)]
        results = []
        failures = []
        for future in futures:
            try:
                results.append(future.result())
            except Exception as exc:
                failures.append(exc)
    assert len(results) in {1, 2}
    assert len(failures) == 2 - len(results)
    assert all(result == results[0] for result in results)
    assert len(results[0].evidence) == 2
    assert (
        postgres_connections["store"]().persist_approval(
            actor_context=actor,
            request_id=request["request_id"],
            expected_version=first.version,
            approval=approval,
            policy_ref=policy_ref,
        )
        == results[0]
    )

    conflicting = copy.deepcopy(request)
    conflicting["arguments"] = {"changed": True}
    apply_object_digest(conflicting)
    with pytest.raises(Exception, match="idempotency|binding"):
        postgres_connections["store"]().persist_submission(
            actor_context=actor,
            request=conflicting,
            policy=policy,
            state="approval_required",
            policy_ref=policy_ref,
        )


def test_lifecycle_actor_isolation_and_invalid_append_is_atomic(postgres_connections):
    store = postgres_connections["store"]()
    actor, request, policy, _approval, _grant, policy_ref = _authority()
    before = store.events(actor_context=actor)
    invalid = copy.deepcopy(policy)
    invalid["request_digest"] = "sha256:" + "9" * 64
    apply_object_digest(invalid)
    with pytest.raises(DurableStoreError):
        store.persist_submission(
            actor_context=actor,
            request=request,
            policy=invalid,
            state="approval_required",
            policy_ref=policy_ref,
        )
    assert store.events(actor_context=actor) == before

    store.persist_submission(
        actor_context=actor,
        request=request,
        policy=policy,
        state="approval_required",
        policy_ref=policy_ref,
    )
    other = copy.deepcopy(actor)
    other["actor_id"] = "018f0000-0000-7000-8000-000000000099"
    with pytest.raises(Exception, match="outside actor scope"):
        store.load_lifecycle(actor_context=other, request_id=request["request_id"])


def test_concurrent_grant_issuance_has_one_authoritative_winner(postgres_connections):
    actor, request, policy, approval, grant, policy_ref = _authority()
    store = postgres_connections["store"]()
    submitted = store.persist_submission(
        actor_context=actor,
        request=request,
        policy=policy,
        state="approval_required",
        policy_ref=policy_ref,
    )
    approved = store.persist_approval(
        actor_context=actor,
        request_id=request["request_id"],
        expected_version=submitted.version,
        approval=approval,
        policy_ref=policy_ref,
    )

    def issue_once():
        return postgres_connections["store"]().persist_grant(
            actor_context=actor,
            request_id=request["request_id"],
            expected_version=approved.version,
            grant=grant,
            policy_ref=policy_ref,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(issue_once) for _index in range(2)]
        results, failures = [], []
        for future in futures:
            try:
                results.append(future.result())
            except Exception as exc:
                failures.append(exc)
    assert len(results) in {1, 2}
    assert len(failures) == 2 - len(results)
    assert all(result == results[0] for result in results)
    assert results[0].state == "grant_issued"
    assert len(results[0].evidence) == 3


def test_rebuild_and_approval_serialize_on_authoritative_run_head(postgres_connections):
    actor, request, policy, approval, _grant, policy_ref = _authority()
    submitted = postgres_connections["store"]().persist_submission(
        actor_context=actor,
        request=request,
        policy=policy,
        state="approval_required",
        policy_ref=policy_ref,
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        rebuild = pool.submit(
            postgres_connections["store"]().rebuild_lifecycle,
            actor_context=actor,
            request_id=request["request_id"],
        )
        approve = pool.submit(
            postgres_connections["store"]().persist_approval,
            actor_context=actor,
            request_id=request["request_id"],
            expected_version=submitted.version,
            approval=approval,
            policy_ref=policy_ref,
        )
        rebuild.result()
        approved = approve.result()
    assert approved.state == "approved"
    assert (
        postgres_connections["store"]().load_lifecycle(
            actor_context=actor, request_id=request["request_id"]
        )
        == approved
    )
