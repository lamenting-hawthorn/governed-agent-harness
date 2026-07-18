from __future__ import annotations

import copy
import json

import pytest

from governed_agent_harness.contracts import apply_object_digest, sha256_digest
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import DurableStoreError


def _scope(actor):
    return {
        "schema_version": "1.0",
        "record_type": "memory_scope",
        "scope_id": "018f0000-0000-7000-8000-0000000000b1",
        "tenant_id": actor["tenant_id"],
        "actor_id": actor["actor_id"],
        "parent_record_type": "actor_context",
        "parent_digest": sha256_digest(actor),
        "selection": {"level": "actor"},
        "derived_at": "2026-01-01T00:00:02.000Z",
        "valid_until": "2026-01-01T01:00:00.000Z",
    }


def _record(records, scope, *, memory_id, revision=1, state="active", observed_at=None):
    value = copy.deepcopy(records["memory_record"])
    value.update(
        {
            "memory_id": memory_id,
            "revision": revision,
            "scope": copy.deepcopy(scope),
            "visibility": "actor",
            "lifecycle_state": state,
            "observed_at": observed_at or "2026-01-01T00:01:00.000Z",
            "effective_from": "2026-01-01T00:01:00.000Z",
            "proposition": {
                "kind": "fact",
                "subject": "memory alpha",
                "predicate": "has.value",
                "value": "synthetic",
            },
        }
    )
    return apply_object_digest(value)


def _query(records, scope):
    value = copy.deepcopy(records["memory_query"])
    value.update({"scope": copy.deepcopy(scope), "query": "alpha", "allowed_categories": ["fact"]})
    return value


def test_retrieval_hides_tombstones_old_revisions_and_out_of_temporal_bound(postgres_connections):
    records = build_positive_records()
    scope = _scope(records["actor_context"])
    old = _record(
        records,
        scope,
        memory_id="018f0000-0000-7000-8000-0000000000b2",
        revision=1,
    )
    tombstone = _record(
        records,
        scope,
        memory_id=old["memory_id"],
        revision=2,
        state="deleted",
    )
    active = _record(
        records,
        scope,
        memory_id="018f0000-0000-7000-8000-0000000000b3",
        observed_at="2026-01-01T00:02:00.000Z",
    )
    expired = _record(
        records,
        scope,
        memory_id="018f0000-0000-7000-8000-0000000000b4",
        observed_at="2024-01-01T00:02:00.000Z",
    )
    for record in (old, tombstone, active, expired):
        postgres_connections["seed_memory"](record)
    query = _query(records, scope)
    query["temporal_bound"] = {
        "from": "2026-01-01T00:00:00.000Z",
        "until": "2026-01-01T00:03:00.000Z",
    }

    matches = postgres_connections["store"]().retrieve_memory(
        actor_context=records["actor_context"], memory_query=query
    )
    assert [match.record["memory_id"] for match in matches] == [active["memory_id"]]


def test_retrieval_rejects_scope_escalation_and_runtime_direct_table_access(postgres_connections):
    records = build_positive_records()
    scope = _scope(records["actor_context"])
    query = _query(records, scope)
    query["scope"]["selection"] = {
        "level": "project",
        "project_id": records["actor_context"]["scope_authority"]["project_ids"][0],
    }
    with pytest.raises(DurableStoreError, match="actor scope"):
        postgres_connections["store"]().retrieve_memory(
            actor_context=records["actor_context"], memory_query=query
        )

    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception):
            cursor.execute("SELECT * FROM gah_memory_records")
        connection.rollback()
        forged = copy.deepcopy(records["actor_context"])
        forged["actor_id"] = "018f0000-0000-7000-8000-0000000000b9"
        with pytest.raises(Exception, match="outside actor scope"):
            cursor.execute(
                "SELECT gah_retrieve_memory(%s::jsonb, %s::jsonb)",
                (json.dumps(forged), json.dumps(_query(records, scope))),
            )
