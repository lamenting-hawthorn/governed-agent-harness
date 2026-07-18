from __future__ import annotations

import copy

from governed_agent_harness.contracts import apply_object_digest, sha256_digest
from governed_agent_harness.contracts.positive_fixtures import build_positive_records


def _actor_scope(actor):
    return {
        "schema_version": "1.0",
        "record_type": "memory_scope",
        "scope_id": "018f0000-0000-7000-8000-0000000000a1",
        "tenant_id": actor["tenant_id"],
        "actor_id": actor["actor_id"],
        "parent_record_type": "actor_context",
        "parent_digest": sha256_digest(actor),
        "selection": {"level": "actor"},
        "derived_at": "2026-01-01T00:00:02.000Z",
        "valid_until": "2026-01-01T01:00:00.000Z",
    }


def _memory(records, scope, *, memory_id, revision, subject, state="active"):
    value = copy.deepcopy(records["memory_record"])
    value.update(
        {
            "memory_id": memory_id,
            "revision": revision,
            "scope": copy.deepcopy(scope),
            "visibility": "actor",
            "lifecycle_state": state,
            "proposition": {
                "kind": "fact",
                "subject": subject,
                "predicate": "has.value",
                "value": "synthetic",
            },
        }
    )
    return apply_object_digest(value)


def test_public_read_only_memory_flow_is_scoped_ranked_and_restart_safe(postgres_connections):
    records = build_positive_records()
    actor = records["actor_context"]
    scope = _actor_scope(actor)
    alpha = _memory(
        records,
        scope,
        memory_id="018f0000-0000-7000-8000-0000000000a2",
        revision=1,
        subject="alpha",
    )
    beta = _memory(
        records,
        scope,
        memory_id="018f0000-0000-7000-8000-0000000000a3",
        revision=1,
        subject="alpha supporting context",
    )
    deleted = _memory(
        records,
        scope,
        memory_id="018f0000-0000-7000-8000-0000000000a4",
        revision=1,
        subject="alpha deleted",
        state="deleted",
    )
    for record in (alpha, beta, deleted):
        postgres_connections["seed_memory"](record)

    query = copy.deepcopy(records["memory_query"])
    query["scope"] = scope
    query["query"] = "alpha"
    query["allowed_categories"] = ["fact"]
    query.pop("temporal_bound")
    first = postgres_connections["store"]().retrieve_memory(actor_context=actor, memory_query=query)
    restarted = postgres_connections["store"]().retrieve_memory(
        actor_context=actor, memory_query=query
    )

    assert [match.record["memory_id"] for match in first] == [
        alpha["memory_id"],
        beta["memory_id"],
    ]
    assert first == restarted
    assert first[0].relevance_score > first[1].relevance_score
    assert first[0].record["provenance"] == alpha["provenance"]

    limited = copy.deepcopy(query)
    limited["budget"]["max_records"] = 1
    assert [
        match.record["memory_id"]
        for match in postgres_connections["store"]().retrieve_memory(
            actor_context=actor, memory_query=limited
        )
    ] == [alpha["memory_id"]]
