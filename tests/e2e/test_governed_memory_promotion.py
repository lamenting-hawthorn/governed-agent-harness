from __future__ import annotations

import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from governed_agent_harness.contracts import (
    TrustContext,
    TrustedKey,
    apply_object_digest,
    sha256_digest,
)
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import DurableStoreError
from governed_agent_harness.persistence.store import (
    PostgresDurableEffectStore,
    _validate_memory_transition_authority,
    memory_transition_binding_digest,
)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class _AcceptingVerifier:
    def verify(self, **values: object) -> bool:
        return True


def _trust(now: datetime) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            TrustedKey(
                issuer="policy.authority",
                key_id="policy.key.v1",
                algorithms=frozenset({"fixture-proof-v1"}),
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
            ),
        ),
        allowed_algorithms=frozenset({"fixture-proof-v1"}),
        allowed_proof_domains=frozenset({"approval_record.v1"}),
        expected_issuers=frozenset({"policy.authority"}),
        allowed_domain_issuers=frozenset({("approval_record.v1", "policy.authority")}),
        trust_policy_version="memory-promotion.test.v1",
    )


def _authority_records(now: datetime):
    records = build_positive_records()
    actor = copy.deepcopy(records["actor_context"])
    actor["auth"]["verified_at"] = _timestamp(now - timedelta(minutes=2))
    actor["issued_at"] = _timestamp(now - timedelta(minutes=1))
    actor["expires_at"] = _timestamp(now + timedelta(hours=1))
    scope = copy.deepcopy(records["memory_scope"])
    scope.update(
        {
            "tenant_id": actor["tenant_id"],
            "actor_id": actor["actor_id"],
            "parent_record_type": "actor_context",
            "parent_digest": sha256_digest(actor),
            "selection": {"level": "actor"},
            "derived_at": actor["issued_at"],
            "valid_until": actor["expires_at"],
        }
    )
    return records, actor, scope


def _proposal_bundle(records, actor, scope, source, now, *, operation="create", revision=1):
    memory = copy.deepcopy(records["memory_record"])
    memory.update(
        {
            "tenant_id": actor["tenant_id"],
            "memory_id": "018f0000-0000-7000-8000-0000000000f1",
            "revision": revision,
            "scope": copy.deepcopy(scope),
            "visibility": "actor",
            "observed_at": _timestamp(now),
            "effective_from": _timestamp(now - timedelta(seconds=1)),
            "effective_until": _timestamp(now + timedelta(days=7)),
            "expires_at": _timestamp(now + timedelta(days=7)),
            "retention": {
                "policy_id": "retention.standard.v1",
                "expires_at": _timestamp(now + timedelta(days=30)),
                "deletion_mode": "retain_non_sensitive_tombstone",
            },
            "lifecycle_state": "candidate",
            "proposition": {
                "kind": "fact",
                "subject": f"governed alpha revision {revision}",
                "predicate": "has.value",
                "value": "synthetic",
            },
        }
    )
    if revision > 1:
        memory["supersedes_revision"] = revision - 1
    span = {
        "evidence_id": source["draft"]["event_id"],
        "payload_digest": source["payload_digest"],
    }
    memory["provenance"] = [span]
    truth = copy.deepcopy(memory["truth_confidence"])
    truth["evidence_ids"] = [span["evidence_id"]]
    memory["truth_confidence"] = truth
    apply_object_digest(memory)

    proposal = copy.deepcopy(records["memory_proposal"])
    proposal.update(
        {
            "tenant_id": actor["tenant_id"],
            "proposal_id": f"018f0000-0000-7000-8000-{0xF100 + revision:012x}",
            "target_scope": copy.deepcopy(scope),
            "change_kind": operation,
            "proposed_record": memory,
            "evidence_spans": [span],
            "truth_confidence": copy.deepcopy(truth),
            "expires_at": _timestamp(now + timedelta(minutes=30)),
            "lifecycle_state": "pending",
        }
    )
    apply_object_digest(proposal)

    policy = copy.deepcopy(records["policy_decision"])
    policy.update(
        {
            "tenant_id": actor["tenant_id"],
            "decision_id": f"018f0000-0000-7000-8000-{0xF200 + revision:012x}",
            "request_id": proposal["proposal_id"],
            "request_digest": proposal["proposal_digest"],
            "decision": "authorize",
            "constraints": [],
            "isolation_profile": "no_effect",
            "decided_at": _timestamp(now),
        }
    )
    apply_object_digest(policy)

    decision = copy.deepcopy(records["memory_decision"])
    decision.update(
        {
            "tenant_id": actor["tenant_id"],
            "decision_id": f"018f0000-0000-7000-8000-{0xF300 + revision:012x}",
            "proposal_ref": {
                "record_type": "memory_proposal",
                "record_id": proposal["proposal_id"],
                "record_digest": proposal["proposal_digest"],
            },
            "disposition": "accept",
            "policy_refs": [
                {
                    "record_type": "policy_decision",
                    "record_id": policy["decision_id"],
                    "record_digest": policy["decision_digest"],
                }
            ],
            "constraints": [],
            "actor_context_digest": sha256_digest(actor),
            "decided_at": _timestamp(now),
        }
    )
    apply_object_digest(decision)
    return proposal, decision, policy


def _source_event(store, actor, records, *, run_id=None):
    policy = records["policy_decision"]
    return store.append(
        tenant_id=actor["tenant_id"],
        run_id=run_id or records["memory_proposal"]["producer"]["run_id"],
        event_kind="kernel.policy_decided",
        policy_ref={
            "record_type": "policy_decision",
            "record_id": policy["decision_id"],
            "record_digest": policy["decision_digest"],
        },
        payload={"actor_id": actor["actor_id"], "source": "synthetic observation"},
    )


def _projection_counts(postgres_connections, actor, memory_id):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT count(*) FROM gah_memory_records "
            "WHERE tenant_id = %s AND actor_id = %s AND memory_id = %s), "
            "(SELECT count(*) FROM gah_memory_transitions "
            "WHERE tenant_id = %s AND actor_id = %s AND memory_id = %s), "
            "(SELECT count(*) FROM gah_evidence_events "
            "WHERE tenant_id = %s AND actor_id = %s AND "
            "envelope_json #>> '{draft,event_kind}' = 'memory.promoted'), "
            "(SELECT coalesce(max(sequence_number), -1) FROM gah_evidence_events "
            "WHERE tenant_id = %s AND actor_id = %s), "
            "(SELECT coalesce(max(next_sequence), -1) FROM gah_run_heads "
            "WHERE tenant_id = %s AND actor_id = %s)",
            (
                actor["tenant_id"],
                actor["actor_id"],
                memory_id,
                actor["tenant_id"],
                actor["actor_id"],
                memory_id,
                actor["tenant_id"],
                actor["actor_id"],
                actor["tenant_id"],
                actor["actor_id"],
                actor["tenant_id"],
                actor["actor_id"],
            ),
        )
        return cursor.fetchone()


def _seed_foreign_source(postgres_connections, source, actor, now):
    foreign_actor_id = "018f0000-0000-7000-8000-00000000fefe"
    foreign_run_id = "018f0000-0000-7000-8000-00000000fefd"
    foreign = copy.deepcopy(source)
    foreign["envelope_id"] = "018f0000-0000-7000-8000-00000000fefc"
    foreign["draft"]["event_id"] = "018f0000-0000-7000-8000-00000000fefb"
    foreign["draft"]["run_id"] = foreign_run_id
    foreign["draft"]["occurred_at"] = _timestamp(now)
    foreign["draft"]["inline_payload"]["actor_id"] = foreign_actor_id
    foreign["draft"]["inline_payload"]["source"] = "foreign actor"
    foreign["draft"]["idempotency"]["idempotency_key"] = "kernel.foreign.source"
    foreign["draft"]["idempotency"]["operation_digest"] = sha256_digest(
        foreign["draft"]["inline_payload"]
    )
    foreign["draft_digest"] = sha256_digest(foreign["draft"])
    foreign["recorded_at"] = _timestamp(now)
    foreign["sequence_number"] = 0
    foreign["prior_event_digest"] = None
    foreign["payload_digest"] = sha256_digest(foreign["draft"]["inline_payload"])
    apply_object_digest(foreign)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_run_heads "
            "(tenant_id, actor_id, run_id, next_sequence, last_event_digest, last_recorded_at) "
            "VALUES (%s, %s, %s, 1, %s, %s::timestamptz)",
            (
                actor["tenant_id"],
                foreign_actor_id,
                foreign_run_id,
                foreign["event_digest"],
                foreign["recorded_at"],
            ),
        )
        cursor.execute(
            "INSERT INTO gah_evidence_events "
            "(tenant_id, actor_id, run_id, sequence_number, envelope_id, event_digest, "
            "prior_event_digest, envelope_json, recorded_at) "
            "VALUES (%s, %s, %s, 0, %s, %s, NULL, %s::jsonb, %s::timestamptz)",
            (
                actor["tenant_id"],
                foreign_actor_id,
                foreign_run_id,
                foreign["envelope_id"],
                foreign["event_digest"],
                json.dumps(foreign),
                foreign["recorded_at"],
            ),
        )
    return foreign


def _rebind_bundle(actor, proposal, decision, policy):
    apply_object_digest(proposal["proposed_record"])
    apply_object_digest(proposal)
    policy["request_id"] = proposal["proposal_id"]
    policy["request_digest"] = proposal["proposal_digest"]
    apply_object_digest(policy)
    decision["proposal_ref"]["record_id"] = proposal["proposal_id"]
    decision["proposal_ref"]["record_digest"] = proposal["proposal_digest"]
    decision["policy_refs"] = [
        {
            "record_type": "policy_decision",
            "record_id": policy["decision_id"],
            "record_digest": policy["decision_digest"],
        }
    ]
    decision["actor_context_digest"] = sha256_digest(actor)
    apply_object_digest(decision)


def test_authority_promotion_retrieval_replay_restart_revision_and_rebuild(
    postgres_connections,
):
    now = datetime.now(timezone.utc).replace(microsecond=123000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    authority = postgres_connections["promotion_authority_at"](now)
    source = _source_event(store, actor, records)
    proposal, decision, policy = _proposal_bundle(records, actor, scope, source, now)

    created = authority.promote_memory(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
    )
    replayed = postgres_connections["promotion_authority_at"](now).promote_memory(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
    )
    assert created.record["lifecycle_state"] == "active"
    assert created.record["revision"] == 1
    assert replayed.replayed is True
    assert replayed.binding_digest == created.binding_digest
    assert replayed.evidence == created.evidence

    query = copy.deepcopy(records["memory_query"])
    query.update(
        {
            "tenant_id": actor["tenant_id"],
            "scope": scope,
            "query": "governed alpha",
            "allowed_categories": ["fact"],
        }
    )
    query.pop("temporal_bound", None)
    matches = postgres_connections["store_at"](now).retrieve_memory(
        actor_context=actor, memory_query=query
    )
    assert [item.record["memory_id"] for item in matches] == [created.record["memory_id"]]

    revised_proposal, revised_decision, revised_policy = _proposal_bundle(
        records, actor, scope, source, now, operation="revise", revision=2
    )
    revised = authority.promote_memory(
        actor_context=actor,
        proposal=revised_proposal,
        memory_decision=revised_decision,
        policy_decision=revised_policy,
        expected_revision=1,
    )
    assert revised.record["revision"] == 2
    assert [
        item.record["revision"]
        for item in postgres_connections["store_at"](now).retrieve_memory(
            actor_context=actor, memory_query=query
        )
    ] == [2]

    supersede_proposal, supersede_decision, supersede_policy = _proposal_bundle(
        records, actor, scope, source, now, operation="supersede", revision=3
    )
    superseded = authority.promote_memory(
        actor_context=actor,
        proposal=supersede_proposal,
        memory_decision=supersede_decision,
        policy_decision=supersede_policy,
        expected_revision=2,
    )
    assert superseded.operation == "supersede"
    assert superseded.record["supersedes_revision"] == 2
    assert [
        item.record["revision"]
        for item in postgres_connections["store_at"](now).retrieve_memory(
            actor_context=actor, memory_query=query
        )
    ] == [3]
    rebuilt = postgres_connections["promotion_authority_at"](now).rebuild_memory_projection(
        actor_context=actor, memory_id=superseded.record["memory_id"]
    )
    assert rebuilt.record == superseded.record
    assert rebuilt.binding_digest == superseded.binding_digest


def test_retention_expiry_is_a_real_postgres_retrieval_ceiling(postgres_connections):
    now = datetime.now(timezone.utc).replace(microsecond=123000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    source = _source_event(store, actor, records)
    proposal, decision, policy = _proposal_bundle(records, actor, scope, source, now)
    proposal["proposed_record"]["retention"]["expires_at"] = _timestamp(now + timedelta(seconds=2))
    _rebind_bundle(actor, proposal, decision, policy)
    authority = postgres_connections["promotion_authority_at"](now)
    created = authority.promote_memory(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
    )
    query = copy.deepcopy(records["memory_query"])
    query.update(
        {
            "tenant_id": actor["tenant_id"],
            "scope": scope,
            "query": "governed alpha",
            "allowed_categories": ["fact"],
        }
    )
    query.pop("temporal_bound", None)
    assert [
        item.record["memory_id"]
        for item in store.retrieve_memory(actor_context=actor, memory_query=query)
    ] == [created.record["memory_id"]]
    time.sleep(2.2)
    assert store.retrieve_memory(actor_context=actor, memory_query=query) == ()


def test_rebuild_requires_current_actor_authority_before_projection_mutation(
    postgres_connections,
):
    now = datetime.now(timezone.utc).replace(microsecond=234000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    source = _source_event(store, actor, records)
    proposal, decision, policy = _proposal_bundle(records, actor, scope, source, now)
    authority = postgres_connections["promotion_authority_at"](now)
    created = authority.promote_memory(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
    )
    before = _projection_counts(postgres_connections, actor, created.record["memory_id"])

    future_actor = copy.deepcopy(actor)
    future_actor["issued_at"] = _timestamp(now + timedelta(minutes=1))
    with pytest.raises(DurableStoreError, match="actor authority is not currently valid"):
        authority.rebuild_memory_projection(
            actor_context=future_actor, memory_id=created.record["memory_id"]
        )
    expired_actor = copy.deepcopy(actor)
    expired_actor["expires_at"] = _timestamp(now - timedelta(seconds=1))
    with pytest.raises(DurableStoreError, match="actor authority is not currently valid"):
        authority.rebuild_memory_projection(
            actor_context=expired_actor, memory_id=created.record["memory_id"]
        )
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        for invalid_actor in (future_actor, expired_actor):
            with pytest.raises(Exception, match="actor authority is not currently valid"):
                cursor.execute(
                    "SELECT gah_rebuild_memory_projection(%s::jsonb, %s::jsonb)",
                    (
                        json.dumps(invalid_actor),
                        json.dumps({"memory_id": created.record["memory_id"]}),
                    ),
                )
            connection.rollback()
    assert _projection_counts(postgres_connections, actor, created.record["memory_id"]) == before


def test_rebuild_uses_memory_revision_order_across_equal_timestamp_runs(postgres_connections):
    now = datetime.now(timezone.utc).replace(microsecond=345000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    authority = postgres_connections["promotion_authority_at"](now)
    run_revision_one = "018f0000-0000-7000-8000-0000000000b2"
    run_revision_two = "018f0000-0000-7000-8000-0000000000b1"
    source_one = _source_event(store, actor, records, run_id=run_revision_one)
    proposal_one, decision_one, policy_one = _proposal_bundle(
        records, actor, scope, source_one, now
    )
    proposal_one["producer"]["run_id"] = run_revision_one
    _rebind_bundle(actor, proposal_one, decision_one, policy_one)
    first = authority.promote_memory(
        actor_context=actor,
        proposal=proposal_one,
        memory_decision=decision_one,
        policy_decision=policy_one,
    )
    source_two = _source_event(store, actor, records, run_id=run_revision_two)
    proposal_two, decision_two, policy_two = _proposal_bundle(
        records, actor, scope, source_two, now, operation="revise", revision=2
    )
    proposal_two["producer"]["run_id"] = run_revision_two
    _rebind_bundle(actor, proposal_two, decision_two, policy_two)
    second = authority.promote_memory(
        actor_context=actor,
        proposal=proposal_two,
        memory_decision=decision_two,
        policy_decision=policy_two,
        expected_revision=1,
    )
    rebuilt = authority.rebuild_memory_projection(
        actor_context=actor, memory_id=first.record["memory_id"]
    )
    assert second.record["revision"] == 2
    assert rebuilt.record == second.record
    assert rebuilt.revision == 2


def test_wrapper_and_direct_function_share_lock_order_and_one_commit(postgres_connections):
    now = datetime.now(timezone.utc).replace(microsecond=456000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    authority = postgres_connections["promotion_authority_at"](now)
    source = _source_event(store, actor, records)
    proposal, decision, policy = _proposal_bundle(records, actor, scope, source, now)
    builder = PostgresDurableEffectStore(
        connect=postgres_connections["writer"],
        privileged_connect=postgres_connections["writer"],
        clock=lambda: now,
        ids=lambda: "018f0000-0000-7000-8000-00000000eeee",
    )
    committed = _validate_memory_transition_authority(
        actor=actor,
        proposal=proposal,
        memory_decision=decision,
        policy=policy,
        approvals=(),
        expected_revision=None,
        now=now,
        constraint_registry=builder._constraint_registry,
        approval_verifier=None,
        approval_trust=None,
    )
    binding = memory_transition_binding_digest(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
        approvals=(),
        committed_record=committed,
        expected_revision=None,
    )
    transition = {
        "actor_id": actor["actor_id"],
        "actor_context": actor,
        "actor_context_digest": sha256_digest(actor),
        "proposal": proposal,
        "memory_decision": decision,
        "policy_decision": policy,
        "approvals": [],
        "committed_record": committed,
        "operation": proposal["change_kind"],
        "expected_revision": None,
        "binding_digest": binding,
        "policy_decision_digest": policy["decision_digest"],
    }
    with builder._connect() as connection, connection.cursor() as cursor:
        evidence = builder._prepare_evidence(
            cursor=cursor,
            actor=actor,
            run_id=proposal["producer"]["run_id"],
            event_kind="memory.promoted",
            policy_ref={
                "record_type": "policy_decision",
                "record_id": policy["decision_id"],
                "record_digest": policy["decision_digest"],
            },
            payload=transition,
        )
    direct_payload = {
        "proposal_id": proposal["proposal_id"],
        "binding_digest": binding,
        "expected_revision": None,
        "evidence": evidence,
        "transition": transition,
    }
    barrier = threading.Barrier(2)

    def direct_commit():
        barrier.wait()
        with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_commit_memory_transition(%s::jsonb, %s::jsonb)",
                (json.dumps(actor), json.dumps(direct_payload)),
            )
            return cursor.fetchone()[0]

    def wrapper_commit():
        barrier.wait()
        return authority.promote_memory(
            actor_context=actor,
            proposal=proposal,
            memory_decision=decision,
            policy_decision=policy,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        direct_future = executor.submit(direct_commit)
        wrapper_future = executor.submit(wrapper_commit)
        direct_result = direct_future.result(timeout=10)
        wrapper_result = wrapper_future.result(timeout=10)
    assert direct_result["replayed"] or wrapper_result.replayed
    assert _projection_counts(postgres_connections, actor, committed["memory_id"]) == (
        1,
        1,
        1,
        1,
        2,
    )


def test_foreign_evidence_and_changed_replay_bindings_fail_without_mutation(
    postgres_connections,
):
    now = datetime.now(timezone.utc).replace(microsecond=567000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    source = _source_event(store, actor, records)
    foreign_source = _seed_foreign_source(postgres_connections, source, actor, now)
    authority = postgres_connections["promotion_authority_at"](now)

    foreign_proposal, foreign_decision, foreign_policy = _proposal_bundle(
        records, actor, scope, foreign_source, now
    )
    memory_id = foreign_proposal["proposed_record"]["memory_id"]
    before = _projection_counts(postgres_connections, actor, memory_id)
    with pytest.raises(Exception, match="source evidence is missing"):
        authority.promote_memory(
            actor_context=actor,
            proposal=foreign_proposal,
            memory_decision=foreign_decision,
            policy_decision=foreign_policy,
        )
    assert _projection_counts(postgres_connections, actor, memory_id) == before

    mismatched_proposal, mismatched_decision, mismatched_policy = _proposal_bundle(
        records, actor, scope, source, now
    )
    mismatched_proposal["proposal_id"] = "018f0000-0000-7000-8000-00000000fa01"
    mismatched_decision["decision_id"] = "018f0000-0000-7000-8000-00000000fa02"
    mismatched_policy["decision_id"] = "018f0000-0000-7000-8000-00000000fa03"
    _rebind_bundle(actor, mismatched_proposal, mismatched_decision, mismatched_policy)
    policy_memory_id = mismatched_proposal["proposed_record"]["memory_id"]
    policy_before = _projection_counts(postgres_connections, actor, policy_memory_id)
    with pytest.raises(Exception, match="exact proposal"):
        authority.promote_memory(
            actor_context=actor,
            proposal=foreign_proposal,
            memory_decision=mismatched_decision,
            policy_decision=mismatched_policy,
        )
    assert _projection_counts(postgres_connections, actor, policy_memory_id) == policy_before

    valid_proposal, valid_decision, valid_policy = _proposal_bundle(
        records, actor, scope, source, now
    )
    created = authority.promote_memory(
        actor_context=actor,
        proposal=valid_proposal,
        memory_decision=valid_decision,
        policy_decision=valid_policy,
    )
    replay_before = _projection_counts(postgres_connections, actor, created.record["memory_id"])
    changed_proposal = copy.deepcopy(valid_proposal)
    changed_decision = copy.deepcopy(valid_decision)
    changed_policy = copy.deepcopy(valid_policy)
    changed_proposal["proposed_record"]["retention"]["expires_at"] = _timestamp(
        now + timedelta(days=2)
    )
    _rebind_bundle(actor, changed_proposal, changed_decision, changed_policy)
    with pytest.raises(Exception, match="replay conflicts"):
        authority.promote_memory(
            actor_context=actor,
            proposal=changed_proposal,
            memory_decision=changed_decision,
            policy_decision=changed_policy,
        )
    assert (
        _projection_counts(postgres_connections, actor, created.record["memory_id"])
        == replay_before
    )

    approval_proposal, approval_decision, approval_policy = _proposal_bundle(
        records, actor, scope, source, now
    )
    approval_policy["decision"] = "require_approval"
    apply_object_digest(approval_policy)
    approval_decision["policy_refs"][0]["record_digest"] = approval_policy["decision_digest"]
    apply_object_digest(approval_decision)
    mismatched_approval = copy.deepcopy(records["approval_record"])
    mismatched_approval.update(
        {
            "tenant_id": actor["tenant_id"],
            "request_id": "018f0000-0000-7000-8000-00000000abcd",
            "request_digest": approval_proposal["proposal_digest"],
            "policy_decision_id": approval_policy["decision_id"],
            "policy_decision_digest": approval_policy["decision_digest"],
            "disposition": "approved",
            "constraints": [],
            "issued_at": _timestamp(now),
            "expires_at": _timestamp(now + timedelta(minutes=10)),
            "separation_of_duties": {
                "required": True,
                "satisfied": True,
                "policy_id": "memory.approval.v1",
            },
        }
    )
    mismatched_approval.pop("revoked_at", None)
    apply_object_digest(mismatched_approval)
    approval_before = _projection_counts(
        postgres_connections, actor, approval_proposal["proposed_record"]["memory_id"]
    )
    with pytest.raises(Exception, match="approval does not bind"):
        postgres_connections["promotion_authority_at"](
            now, _AcceptingVerifier(), _trust
        ).promote_memory(
            actor_context=actor,
            proposal=approval_proposal,
            memory_decision=approval_decision,
            policy_decision=approval_policy,
            approvals=(mismatched_approval,),
        )
    assert (
        _projection_counts(
            postgres_connections, actor, approval_proposal["proposed_record"]["memory_id"]
        )
        == approval_before
    )


def test_stale_revision_rolls_back_promotion_evidence(postgres_connections):
    now = datetime.now(timezone.utc).replace(microsecond=456000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    source = _source_event(store, actor, records)
    proposal, decision, policy = _proposal_bundle(records, actor, scope, source, now)
    authority = postgres_connections["promotion_authority_at"](now)
    authority.promote_memory(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
    )
    before = store.events(actor_context=actor)
    stale_proposal, stale_decision, stale_policy = _proposal_bundle(
        records, actor, scope, source, now, operation="revise", revision=3
    )
    stale_proposal["proposal_id"] = "018f0000-0000-7000-8000-00000000ffff"
    apply_object_digest(stale_proposal)
    stale_policy["request_id"] = stale_proposal["proposal_id"]
    stale_policy["request_digest"] = stale_proposal["proposal_digest"]
    apply_object_digest(stale_policy)
    stale_decision["proposal_ref"]["record_id"] = stale_proposal["proposal_id"]
    stale_decision["proposal_ref"]["record_digest"] = stale_proposal["proposal_digest"]
    stale_decision["policy_refs"][0]["record_digest"] = stale_policy["decision_digest"]
    apply_object_digest(stale_decision)
    with pytest.raises(Exception, match="expected revision is stale"):
        authority.promote_memory(
            actor_context=actor,
            proposal=stale_proposal,
            memory_decision=stale_decision,
            policy_decision=stale_policy,
            expected_revision=2,
        )
    assert store.events(actor_context=actor) == before

    expired_proposal, expired_decision, expired_policy = _proposal_bundle(
        records, actor, scope, source, now, operation="revise", revision=3
    )
    expired_proposal["proposal_id"] = "018f0000-0000-7000-8000-00000000ffaa"
    expired_proposal["proposed_record"]["retention"]["expires_at"] = _timestamp(
        now - timedelta(seconds=1)
    )
    _rebind_bundle(actor, expired_proposal, expired_decision, expired_policy)
    with pytest.raises(DurableStoreError, match="retention authority is expired"):
        authority.promote_memory(
            actor_context=actor,
            proposal=expired_proposal,
            memory_decision=expired_decision,
            policy_decision=expired_policy,
            expected_revision=2,
        )
    assert store.events(actor_context=actor) == before

    partial_proposal, partial_decision, partial_policy = _proposal_bundle(
        records, actor, scope, source, now, operation="revise", revision=3
    )
    partial_proposal["proposal_id"] = "018f0000-0000-7000-8000-00000000ffab"
    partial_proposal["evidence_spans"][0]["json_pointer"] = ""
    partial_proposal["proposed_record"]["provenance"][0]["json_pointer"] = ""
    _rebind_bundle(actor, partial_proposal, partial_decision, partial_policy)
    with pytest.raises(DurableStoreError, match="partial evidence spans"):
        authority.promote_memory(
            actor_context=actor,
            proposal=partial_proposal,
            memory_decision=partial_decision,
            policy_decision=partial_policy,
            expected_revision=2,
        )
    assert store.events(actor_context=actor) == before


def test_approval_required_tombstone_and_unresolvable_evidence_fail_closed(
    postgres_connections,
):
    now = datetime.now(timezone.utc).replace(microsecond=789000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    authority = postgres_connections["promotion_authority_at"](now, _AcceptingVerifier(), _trust)
    source = _source_event(store, actor, records)
    proposal, decision, policy = _proposal_bundle(records, actor, scope, source, now)
    policy["decision"] = "require_approval"
    apply_object_digest(policy)
    decision["policy_refs"][0]["record_digest"] = policy["decision_digest"]
    apply_object_digest(decision)
    approval = copy.deepcopy(records["approval_record"])
    approval.update(
        {
            "tenant_id": actor["tenant_id"],
            "request_id": proposal["proposal_id"],
            "request_digest": proposal["proposal_digest"],
            "policy_decision_id": policy["decision_id"],
            "policy_decision_digest": policy["decision_digest"],
            "disposition": "approved",
            "constraints": [],
            "issued_at": _timestamp(now),
            "expires_at": _timestamp(now + timedelta(minutes=10)),
            "separation_of_duties": {
                "required": True,
                "satisfied": True,
                "policy_id": "memory.approval.v1",
            },
        }
    )
    approval.pop("revoked_at", None)
    apply_object_digest(approval)
    created = authority.promote_memory(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
        approvals=(approval,),
    )
    assert created.record["lifecycle_state"] == "active"

    tombstone_proposal, tombstone_decision, tombstone_policy = _proposal_bundle(
        records, actor, scope, source, now, operation="delete", revision=2
    )
    tombstone = authority.promote_memory(
        actor_context=actor,
        proposal=tombstone_proposal,
        memory_decision=tombstone_decision,
        policy_decision=tombstone_policy,
        expected_revision=1,
    )
    assert tombstone.record["lifecycle_state"] == "deleted"

    query = copy.deepcopy(records["memory_query"])
    query.update(
        {
            "tenant_id": actor["tenant_id"],
            "scope": scope,
            "query": "governed alpha",
            "allowed_categories": ["fact"],
        }
    )
    query.pop("temporal_bound", None)
    assert store.retrieve_memory(actor_context=actor, memory_query=query) == ()

    bad_proposal, bad_decision, bad_policy = _proposal_bundle(
        records,
        actor,
        scope,
        source,
        now,
        operation="revise",
        revision=3,
    )
    bad_digest = "sha256:" + "f" * 64
    bad_proposal["evidence_spans"][0]["payload_digest"] = bad_digest
    bad_proposal["proposed_record"]["provenance"][0]["payload_digest"] = bad_digest
    _rebind_bundle(actor, bad_proposal, bad_decision, bad_policy)
    before = store.events(actor_context=actor)
    with pytest.raises(Exception, match="source evidence is missing"):
        authority.promote_memory(
            actor_context=actor,
            proposal=bad_proposal,
            memory_decision=bad_decision,
            policy_decision=bad_policy,
            expected_revision=2,
        )
    assert store.events(actor_context=actor) == before


def test_concurrent_revisions_preserve_one_authoritative_history(postgres_connections):
    now = datetime.now(timezone.utc).replace(microsecond=987000)
    records, actor, scope = _authority_records(now)
    store = postgres_connections["store_at"](now)
    source = _source_event(store, actor, records)
    proposal, decision, policy = _proposal_bundle(records, actor, scope, source, now)
    authority = postgres_connections["promotion_authority_at"](now)
    authority.promote_memory(
        actor_context=actor,
        proposal=proposal,
        memory_decision=decision,
        policy_decision=policy,
    )
    first = _proposal_bundle(records, actor, scope, source, now, operation="revise", revision=2)
    second = copy.deepcopy(first)
    second[0]["proposal_id"] = "018f0000-0000-7000-8000-00000000f9f9"
    second[1]["decision_id"] = "018f0000-0000-7000-8000-00000000f9fa"
    second[2]["decision_id"] = "018f0000-0000-7000-8000-00000000f9fb"
    _rebind_bundle(actor, *second)

    def promote(bundle):
        return postgres_connections["promotion_authority_at"](now).promote_memory(
            actor_context=actor,
            proposal=bundle[0],
            memory_decision=bundle[1],
            policy_decision=bundle[2],
            expected_revision=1,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(promote, bundle) for bundle in (first, second)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except Exception as error:
                outcomes.append(error)
    assert sum(not isinstance(value, Exception) for value in outcomes) == 1
    assert sum("expected revision is stale" in str(value) for value in outcomes) == 1
    promotion_events = [
        event
        for event in store.events(actor_context=actor)
        if event["draft"]["event_kind"] == "memory.promoted"
    ]
    assert [
        event["draft"]["inline_payload"]["committed_record"]["revision"]
        for event in promotion_events
    ] == [1, 2]
