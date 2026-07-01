"""Strict wire decoding, canonicalization, and digest mutation tests."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from governed_agent_harness.contracts import (
    MODEL_BY_RECORD_TYPE,
    JsonDecodeError,
    SemanticError,
    apply_object_digest,
    canonical_bytes,
    sha256_digest,
    strict_json_loads,
)

POSITIVE = Path(__file__).parent / "fixtures" / "positive"


@pytest.mark.parametrize("filename", ["canonicalization_vectors.json", "digest_vectors.json"])
def test_canonicalization_and_digest_vectors_are_exact(filename: str) -> None:
    vectors = json.loads((POSITIVE / filename).read_bytes())
    assert len(vectors) == 3
    for vector in vectors:
        assert canonical_bytes(vector["input"]).decode("utf-8") == vector["canonical"]
        if "digest" in vector:
            assert sha256_digest(vector["input"]) == vector["digest"]


def test_independent_known_answer_uses_utf16_key_order_and_literal_digest() -> None:
    value = {"\ue000": 2, "😀": 1, "a": 3}
    expected = b'{"a":3,"\xf0\x9f\x98\x80":1,"\xee\x80\x80":2}'
    expected_hexdigest = "a901d5c9340048b768183fd6fb82e7d0f7792049a0aafa9d2c7ccd845d984ad3"

    assert "\ue000" < "😀"  # Unicode code-point order.
    assert "😀".encode("utf-16-be") < "\ue000".encode("utf-16-be")
    assert canonical_bytes(value) == expected
    assert hashlib.sha256(expected).hexdigest() == expected_hexdigest
    assert sha256_digest(value) == f"sha256:{expected_hexdigest}"


def test_independent_known_answer_escapes_controls_without_fixture_generation() -> None:
    value = {"text": 'line\nquote"slash\\control\u000f'}
    expected = b'{"text":"line\\nquote\\"slash\\\\control\\u000f"}'

    assert canonical_bytes(value) == expected


def test_object_order_never_changes_canonical_bytes_or_digest() -> None:
    forward = {
        "schema_version": "1.0",
        "nested": {"z": 3, "a": 1, "middle": [True, None, "synthetic"]},
        "record_type": "determinism_probe",
    }
    reverse = {
        "record_type": "determinism_probe",
        "nested": {"middle": [True, None, "synthetic"], "a": 1, "z": 3},
        "schema_version": "1.0",
    }

    assert canonical_bytes(forward) == canonical_bytes(reverse)
    assert sha256_digest(forward) == sha256_digest(reverse)
    assert sha256_digest(forward) == sha256_digest(copy.deepcopy(forward))


@pytest.mark.parametrize(
    "token",
    ["0.0", "-0.0", "1.5", "1e3", "1E+3", "-2e-4"],
)
def test_every_floating_point_token_form_is_rejected(token: str) -> None:
    with pytest.raises(JsonDecodeError, match="floating-point token"):
        strict_json_loads(f'{{"number":{token}}}'.encode())


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_every_non_finite_json_token_is_rejected(token: str) -> None:
    with pytest.raises(JsonDecodeError, match="non-finite number token"):
        strict_json_loads(f'{{"number":{token}}}'.encode())


@pytest.mark.parametrize(
    "payload",
    [
        b'{"tenant_id":"first","tenant_id":"second"}',
        b'{"outer":{"proof":1,"proof":2}}',
    ],
)
def test_duplicate_json_keys_are_rejected_at_any_depth(payload: bytes) -> None:
    with pytest.raises(JsonDecodeError, match="duplicate object key"):
        strict_json_loads(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b'"\xff"',
        b'"\xc3\x28"',
        b'"\xed\xa0\x80"',
        b'"\xf0\x28\x8c\x28"',
        b'"\xf4\x90\x80\x80"',
    ],
)
def test_invalid_utf8_forms_are_rejected(payload: bytes) -> None:
    with pytest.raises(JsonDecodeError, match="invalid UTF-8"):
        strict_json_loads(payload)


@pytest.mark.parametrize("escaped", [b'"\\ud800"', b'"\\udfff"', b'"\\ud800\\ud800"'])
def test_escaped_unicode_surrogates_are_rejected(escaped: bytes) -> None:
    with pytest.raises(JsonDecodeError, match="Unicode surrogate"):
        strict_json_loads(escaped)


def test_unicode_replacement_and_repair_are_rejected() -> None:
    replacement = json.dumps("\ufffd").encode("utf-8")
    repaired = b'"\xff"'.decode("utf-8", errors="replace").encode("utf-8")

    with pytest.raises(JsonDecodeError, match="replacement character"):
        strict_json_loads(replacement)
    with pytest.raises(JsonDecodeError, match="replacement character"):
        strict_json_loads(repaired)


@pytest.mark.parametrize("value", [0.5, float("nan"), float("inf"), float("-inf")])
def test_in_memory_float_values_are_rejected_before_digesting(value: float) -> None:
    with pytest.raises(SemanticError, match="floating-point values"):
        canonical_bytes({"value": value})


@pytest.mark.parametrize("value", [9_007_199_254_740_992, -9_007_199_254_740_992])
def test_out_of_range_integer_values_are_not_interoperable(value: int) -> None:
    with pytest.raises(SemanticError, match="safe range"):
        canonical_bytes(value)


@pytest.mark.parametrize(
    ("record_type", "mutation"),
    [
        ("memory_record", ("proposition", "value", "tampered")),
        ("evidence_envelope", ("draft", "inline_payload", {"message": "tampered"})),
        ("tool_request", ("arguments", "input", "tampered")),
    ],
)
def test_modified_payload_after_digest_is_rejected(
    record_type: str,
    mutation: tuple[str, str, Any],
    record_copy: Any,
) -> None:
    record = record_copy(record_type)
    container, field, value = mutation
    record[container][field] = value

    with pytest.raises(SemanticError, match="digest|does not match"):
        MODEL_BY_RECORD_TYPE[record_type](record)


def test_recomputed_digest_is_deterministic_but_changes_after_payload_mutation(
    record_copy: Any,
) -> None:
    record = record_copy("tool_request")
    original = record["request_digest"]
    record["arguments"]["input"] = "changed-after-policy"
    apply_object_digest(record)
    first = record["request_digest"]
    apply_object_digest(record)

    assert first != original
    assert record["request_digest"] == first
    MODEL_BY_RECORD_TYPE["tool_request"](record)


def test_strict_decoder_accepts_only_bytes_like_inputs() -> None:
    with pytest.raises(TypeError, match="bytes-like"):
        strict_json_loads("{}")  # type: ignore[arg-type]


def test_model_canonicalization_does_not_alias_input(
    positive_records: Mapping[str, dict[str, Any]],
) -> None:
    original = copy.deepcopy(positive_records["actor_context"])
    model = MODEL_BY_RECORD_TYPE["actor_context"](original)
    original["auth"]["issuer"] = "mutated.outside.model"
    assert model["auth"]["issuer"] == "fixture.identity"
