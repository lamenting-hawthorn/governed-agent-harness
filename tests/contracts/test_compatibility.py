"""Canonical-schema, model, fixture, and round-trip compatibility coverage."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from governed_agent_harness.contracts import (
    DEFAULT_SCHEMA_STORE,
    MODEL_BY_RECORD_TYPE,
    MODEL_CLASSES,
    ContractError,
    SchemaError,
    SemanticError,
    canonical_bytes,
    parse_model,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
STRUCTURAL_CASES = json.loads(
    (FIXTURE_ROOT / "negative" / "structural_cases.json").read_text(encoding="utf-8")
)
CATALOG_TYPES = tuple(DEFAULT_SCHEMA_STORE.catalog)


def _expanded_structural_cases() -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for case in STRUCTURAL_CASES:
        if case["record_type"] != "*":
            expanded.append(case)
            continue
        for record_type in CATALOG_TYPES:
            expanded.append(
                {
                    **case,
                    "id": f"{case['id']}__{record_type}",
                    "record_type": record_type,
                }
            )
    return expanded


def _mutate(record: dict[str, Any], case: Mapping[str, Any]) -> None:
    parent: dict[str, Any] = record
    path = case["path"]
    for segment in path[:-1]:
        parent = parent[segment]
    key = path[-1]
    operation = case["operation"]
    if operation == "remove":
        del parent[key]
    elif operation == "set":
        parent[key] = copy.deepcopy(case["value"])
    elif operation == "replace_inline_with_protected":
        del record["inline_payload"]
        parent[key] = copy.deepcopy(case["value"])
    else:  # pragma: no cover - fixture format guard
        raise AssertionError(f"unknown fixture operation {operation!r}")


def test_catalog_models_and_fixture_set_are_exactly_aligned(
    positive_payloads: Mapping[str, bytes],
) -> None:
    model_types = {model.RECORD_TYPE for model in MODEL_CLASSES}
    assert len(CATALOG_TYPES) == 27
    assert len(MODEL_BY_RECORD_TYPE) == 27
    assert set(CATALOG_TYPES) == model_types == set(positive_payloads)


@pytest.mark.parametrize("record_type", CATALOG_TYPES)
def test_all_positive_fixtures_pass_schema_model_and_canonical_round_trip(
    record_type: str,
    positive_payloads: Mapping[str, bytes],
    positive_records: Mapping[str, dict[str, Any]],
) -> None:
    payload = positive_payloads[record_type]
    record = positive_records[record_type]

    DEFAULT_SCHEMA_STORE.validate_record(record, record_type)
    model_class = MODEL_BY_RECORD_TYPE[record_type]
    model = model_class.from_bytes(payload, expected_tenant=record["tenant_id"])
    parsed = parse_model(payload, expected_tenant=record["tenant_id"])
    canonical_payload = model.canonical_bytes()
    round_tripped = model_class.from_bytes(
        canonical_payload,
        expected_tenant=record["tenant_id"],
    )

    assert parsed.to_dict() == record
    assert round_tripped.to_dict() == record
    assert canonical_payload == canonical_bytes(record)
    assert round_tripped.canonical_digest() == model.canonical_digest()
    detached = model.to_dict()
    detached["tenant_id"] = "018f0000-0000-7000-8000-000000000999"
    assert model["tenant_id"] == record["tenant_id"]


@pytest.mark.parametrize(
    "case",
    _expanded_structural_cases(),
    ids=lambda case: case["id"],
)
def test_structural_negative_fixtures_are_rejected_by_schema_and_model(
    case: Mapping[str, Any],
    record_copy: Any,
) -> None:
    record_type = case["record_type"]
    record = record_copy(record_type)
    _mutate(record, case)

    with pytest.raises(SchemaError):
        DEFAULT_SCHEMA_STORE.validate_record(record, record_type)
    with pytest.raises(ContractError):
        MODEL_BY_RECORD_TYPE[record_type](record, verify_self_digests=False)


def test_unknown_record_type_fails_closed(record_copy: Any) -> None:
    record = record_copy("actor_context")
    record["record_type"] = "unknown_security_record"
    payload = json.dumps(record).encode("utf-8")

    with pytest.raises(SchemaError, match="unsupported record_type"):
        DEFAULT_SCHEMA_STORE.validate_record(record)
    with pytest.raises(SemanticError, match="unsupported record_type"):
        parse_model(payload, verify_self_digests=False)


def test_non_object_wire_value_fails_closed() -> None:
    with pytest.raises(SemanticError, match="wire record requires"):
        parse_model(b"[]")


def test_schema_catalog_audit_is_deterministic() -> None:
    DEFAULT_SCHEMA_STORE.audit_catalog()
    before = dict(DEFAULT_SCHEMA_STORE.catalog)
    DEFAULT_SCHEMA_STORE.audit_catalog()
    assert dict(DEFAULT_SCHEMA_STORE.catalog) == before
