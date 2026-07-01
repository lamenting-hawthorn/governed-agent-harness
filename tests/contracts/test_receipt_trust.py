"""Adversarial activation/rollback proof and cross-tenant binding tests."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest

from governed_agent_harness.contracts import (
    AcceptedTrustSnapshot,
    ContractError,
    HistoricalAcceptance,
    ProofVerificationError,
    RetroactiveKeyInvalidation,
    SemanticError,
    TrustedKey,
    accepted_trust_snapshot_digest,
    canonical_bytes,
    learning_artifact_is_active,
    sha256_digest,
    unsigned_body,
    validate_activation_delivery_binding,
    validate_rollback_activation_binding,
    validate_rollback_lifecycle,
    verify_runtime_receipt,
    verify_signed_record,
)

OTHER_TENANT = "018f0000-0000-7000-8000-000000000998"
OTHER_UUID = "018f0000-0000-7000-8000-000000000999"
SIGNED_ACCEPTANCE_TIME = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)


def _record_delivery_and_activation(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> tuple[HistoricalAcceptance, HistoricalAcceptance]:
    tenant_id = records["delivery_envelope"]["tenant_id"]
    initial_trust = trust_factory()
    delivery_acceptance = verify_signed_record(
        records["delivery_envelope"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=tenant_id,
    )
    activation_acceptance = verify_runtime_receipt(
        records["activation_receipt"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=tenant_id,
    )
    assert delivery_acceptance.canonical_record_digest == sha256_digest(
        records["delivery_envelope"]
    )
    assert activation_acceptance.canonical_record_digest == sha256_digest(
        records["activation_receipt"]
    )

    delivery_history = dataclasses.replace(delivery_acceptance, ledger_position=7)
    activation_history = dataclasses.replace(activation_acceptance, ledger_position=11)
    assert delivery_history.ledger_position >= 0
    assert activation_history.ledger_position >= 0
    assert delivery_history.ledger_position != activation_history.ledger_position
    return delivery_history, activation_history


def _replace_accepted_trust(
    acceptance: HistoricalAcceptance,
    **changes: object,
) -> HistoricalAcceptance:
    snapshot = dataclasses.replace(acceptance.accepted_trust, **changes)
    assert isinstance(snapshot, AcceptedTrustSnapshot)
    return dataclasses.replace(
        acceptance,
        accepted_trust=snapshot,
        accepted_trust_digest=accepted_trust_snapshot_digest(snapshot),
    )


def _record_activation_and_rollback(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
    *,
    expected_tenant: str | None = None,
) -> tuple[HistoricalAcceptance, HistoricalAcceptance]:
    initial_trust = trust_factory()
    activation_acceptance = verify_runtime_receipt(
        records["activation_receipt"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=expected_tenant,
    )
    rollback_acceptance = verify_runtime_receipt(
        records["rollback_receipt"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=expected_tenant,
    )
    return (
        dataclasses.replace(activation_acceptance, ledger_position=13),
        dataclasses.replace(rollback_acceptance, ledger_position=17),
    )


@pytest.mark.parametrize("record_type", ["activation_receipt", "rollback_receipt"])
def test_forged_receipts_fail_through_injected_verifier(
    record_type: str,
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    verifier.accepted = False
    receipt = record_copy(record_type)
    with pytest.raises(ProofVerificationError, match="detached proof verification failed"):
        verify_runtime_receipt(receipt, verifier=verifier, trust=trust_factory())
    assert len(verifier.calls) == 1
    assert verifier.calls[0]["unsigned_bytes"] == canonical_bytes(unsigned_body(receipt))


@pytest.mark.parametrize("record_type", ["activation_receipt", "rollback_receipt"])
@pytest.mark.parametrize(
    ("proof_field", "replacement", "error"),
    [
        ("key_id", "unknown.runtime.key", "key is not uniquely trusted"),
        ("issuer", "forged.runtime.authority", "issuer is not allowed"),
        ("algorithm", "forged-proof-v1", "algorithm is not allowed"),
    ],
)
def test_receipt_key_issuer_and_algorithm_mismatch_fail_before_crypto(
    record_type: str,
    proof_field: str,
    replacement: str,
    error: str,
    record_copy: Any,
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    receipt = record_copy(record_type)
    receipt["proof"][proof_field] = replacement
    redigest(receipt)
    with pytest.raises(ProofVerificationError, match=error):
        verify_runtime_receipt(receipt, verifier=verifier, trust=trust_factory())
    assert verifier.calls == []


@pytest.mark.parametrize(
    ("record_type", "wrong_domain"),
    [
        ("activation_receipt", "rollback_receipt.v1"),
        ("rollback_receipt", "activation_receipt.v1"),
    ],
)
def test_activation_and_rollback_proof_domains_are_not_interchangeable(
    record_type: str,
    wrong_domain: str,
    record_copy: Any,
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    receipt = record_copy(record_type)
    receipt["proof"]["proof_domain"] = wrong_domain
    redigest(receipt)
    with pytest.raises(ContractError, match="proof_domain|constant"):
        verify_runtime_receipt(receipt, verifier=verifier, trust=trust_factory())
    assert verifier.calls == []


@pytest.mark.parametrize("record_type", ["activation_receipt", "rollback_receipt"])
def test_receipt_domain_must_be_allowed_by_trust_policy(
    record_type: str,
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    with pytest.raises(ProofVerificationError, match="domain is not allowed"):
        verify_runtime_receipt(
            record_copy(record_type),
            verifier=verifier,
            trust=trust_factory(domains=frozenset()),
        )
    assert verifier.calls == []


def test_receipt_issuer_must_be_allowed_for_its_exact_domain(
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    with pytest.raises(ProofVerificationError, match="issuer is not allowed for the proof domain"):
        verify_runtime_receipt(
            record_copy("activation_receipt"),
            verifier=verifier,
            trust=trust_factory(allowed_domain_issuers=frozenset()),
        )
    assert verifier.calls == []


@pytest.mark.parametrize("record_type", ["approval_record", "authorization_grant"])
def test_altered_authority_detached_proof_fails_crypto_boundary(
    record_type: str,
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    record = record_copy(record_type)
    altered_proof = "X" * len(record["proof"]["detached_proof"])
    record["proof"]["detached_proof"] = altered_proof
    verifier.accepted = False

    with pytest.raises(ProofVerificationError, match="detached proof verification failed"):
        verify_signed_record(
            record,
            verifier=verifier,
            trust=trust_factory(now=SIGNED_ACCEPTANCE_TIME),
        )
    assert len(verifier.calls) == 1
    assert verifier.calls[0]["detached_proof"] == altered_proof


@pytest.mark.parametrize("record_type", ["approval_record", "authorization_grant"])
@pytest.mark.parametrize(
    ("proof_field", "replacement", "error"),
    [
        ("issuer", "learning.authority", "issuer is not allowed for the proof domain"),
        ("key_id", "unknown.policy.key", "key is not uniquely trusted"),
        ("algorithm", "forged-proof-v1", "algorithm is not allowed"),
    ],
)
def test_authority_proof_issuer_key_and_algorithm_fail_before_crypto(
    record_type: str,
    proof_field: str,
    replacement: str,
    error: str,
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    record = record_copy(record_type)
    record["proof"][proof_field] = replacement

    with pytest.raises(ProofVerificationError, match=error):
        verify_signed_record(
            record,
            verifier=verifier,
            trust=trust_factory(now=SIGNED_ACCEPTANCE_TIME),
        )
    assert verifier.calls == []


@pytest.mark.parametrize(
    ("record_type", "wrong_domain"),
    [
        ("approval_record", "authorization_grant.v1"),
        ("authorization_grant", "approval_record.v1"),
    ],
)
def test_authority_proof_domains_are_not_interchangeable(
    record_type: str,
    wrong_domain: str,
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    record = record_copy(record_type)
    record["proof"]["proof_domain"] = wrong_domain

    with pytest.raises(ContractError, match="proof_domain|constant"):
        verify_signed_record(
            record,
            verifier=verifier,
            trust=trust_factory(now=SIGNED_ACCEPTANCE_TIME),
        )
    assert verifier.calls == []


@pytest.mark.parametrize("record_type", ["approval_record", "authorization_grant"])
def test_expired_authority_record_cannot_receive_first_acceptance(
    record_type: str,
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    with pytest.raises(ProofVerificationError, match="expired before first acceptance"):
        verify_signed_record(
            record_copy(record_type),
            verifier=verifier,
            trust=trust_factory(now=datetime(2027, 1, 1, tzinfo=timezone.utc)),
        )
    assert verifier.calls == []


def test_cross_tenant_activation_receipt_and_delivery_cannot_bind(
    records: dict[str, dict[str, Any]],
    rebind_tenant: Callable[[dict[str, Any], str], dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    receipt = rebind_tenant(records["activation_receipt"], OTHER_TENANT)
    verify_runtime_receipt(
        receipt,
        verifier=verifier,
        trust=trust_factory(),
        expected_tenant=OTHER_TENANT,
    )
    with pytest.raises(SemanticError, match="tenant_id"):
        validate_activation_delivery_binding(receipt, records["delivery_envelope"])

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        receipt,
        verifier=verifier,
        trust=trust_factory(),
        expected_tenant=records["delivery_envelope"]["tenant_id"],
    )


def test_cross_tenant_delivery_cannot_use_valid_activation_receipt(
    records: dict[str, dict[str, Any]],
    rebind_tenant: Callable[[dict[str, Any], str], dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery = rebind_tenant(records["delivery_envelope"], OTHER_TENANT)
    with pytest.raises(SemanticError, match="tenant_id"):
        validate_activation_delivery_binding(records["activation_receipt"], delivery)
    assert not learning_artifact_is_active(
        delivery,
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(),
        expected_tenant=OTHER_TENANT,
    )


def test_active_predicate_rejects_forged_delivery_proof(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery = records["delivery_envelope"]
    delivery["proof"]["detached_proof"] = "X" * len(delivery["proof"]["detached_proof"])
    verifier.accepted = False

    assert not learning_artifact_is_active(
        delivery,
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(),
        expected_tenant=delivery["tenant_id"],
    )
    assert len(verifier.calls) == 1
    assert verifier.calls[0]["proof_domain"] == "delivery_envelope.v1"


def test_unrecorded_valid_delivery_and_activation_do_not_establish_active_state(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    histories = _record_delivery_and_activation(records, verifier, trust_factory)
    tenant_id = records["delivery_envelope"]["tenant_id"]

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(),
        expected_tenant=tenant_id,
    )
    assert learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=histories),
        expected_tenant=tenant_id,
    )


def test_recorded_activation_survives_key_removal_and_current_policy_rotation(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    histories = _record_delivery_and_activation(records, verifier, trust_factory)
    for history in histories:
        assert history.accepted_trust_digest == accepted_trust_snapshot_digest(
            history.accepted_trust
        )
    tenant_id = records["delivery_envelope"]["tenant_id"]
    verifier.calls.clear()
    historical_trust = trust_factory(
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        trusted_keys=(),
        allowed_algorithms=frozenset(),
        domains=frozenset(),
        expected_issuers=frozenset(),
        allowed_domain_issuers=frozenset(),
        historical_acceptances=histories,
    )

    assert learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=historical_trust,
        expected_tenant=tenant_id,
    )
    assert [call["proof_domain"] for call in verifier.calls] == [
        "delivery_envelope.v1",
        "activation_receipt.v1",
    ]


@pytest.mark.parametrize(
    ("delivery_position", "activation_position"),
    [
        (-1, 11),
        (7, -1),
        (False, 11),
        (7, True),
        (7, 7),
        (11, 7),
    ],
)
def test_active_state_requires_nonnegative_delivery_before_activation_ledger_order(
    delivery_position: int,
    activation_position: int,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery_history, activation_history = _record_delivery_and_activation(
        records, verifier, trust_factory
    )
    histories = (
        dataclasses.replace(delivery_history, ledger_position=delivery_position),
        dataclasses.replace(activation_history, ledger_position=activation_position),
    )

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=histories),
        expected_tenant=records["delivery_envelope"]["tenant_id"],
    )


@pytest.mark.parametrize("missing_history", ["delivery", "activation"])
def test_active_state_requires_both_acceptance_histories(
    missing_history: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery_history, activation_history = _record_delivery_and_activation(
        records, verifier, trust_factory
    )
    histories = (activation_history,) if missing_history == "delivery" else (delivery_history,)
    tenant_id = records["delivery_envelope"]["tenant_id"]

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=histories),
        expected_tenant=tenant_id,
    )


@pytest.mark.parametrize("duplicated_history", ["delivery", "activation"])
def test_duplicate_matching_acceptance_history_fails_closed(
    duplicated_history: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery_history, activation_history = _record_delivery_and_activation(
        records, verifier, trust_factory
    )
    duplicate = delivery_history if duplicated_history == "delivery" else activation_history
    histories = (delivery_history, activation_history, duplicate)
    tenant_id = records["delivery_envelope"]["tenant_id"]

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=histories),
        expected_tenant=tenant_id,
    )


@pytest.mark.parametrize("altered_record", ["delivery", "activation"])
def test_altered_signed_record_after_acceptance_history_fails_closed(
    altered_record: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    histories = _record_delivery_and_activation(records, verifier, trust_factory)
    delivery = records["delivery_envelope"]
    activation = records["activation_receipt"]
    target = delivery if altered_record == "delivery" else activation
    target["proof"]["detached_proof"] = "Q" * len(target["proof"]["detached_proof"])
    tenant_id = delivery["tenant_id"]

    assert not learning_artifact_is_active(
        delivery,
        activation,
        verifier=verifier,
        trust=trust_factory(
            now=datetime(2027, 1, 1, tzinfo=timezone.utc),
            historical_acceptances=histories,
        ),
        expected_tenant=tenant_id,
    )


def test_corrupted_accepted_trust_snapshot_fails_closed(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery_history, activation_history = _record_delivery_and_activation(
        records, verifier, trust_factory
    )
    corrupted = dataclasses.replace(
        delivery_history,
        accepted_trust=dataclasses.replace(
            delivery_history.accepted_trust,
            trust_policy_version="corrupted.trust.v1",
        ),
    )

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=(corrupted, activation_history)),
        expected_tenant=records["delivery_envelope"]["tenant_id"],
    )


def test_corrupted_accepted_trust_snapshot_digest_fails_closed(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery_history, activation_history = _record_delivery_and_activation(
        records, verifier, trust_factory
    )
    corrupted = dataclasses.replace(
        delivery_history,
        accepted_trust_digest="sha256:" + "0" * 64,
    )

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=(corrupted, activation_history)),
        expected_tenant=records["delivery_envelope"]["tenant_id"],
    )


def test_mismatched_proof_and_accepted_trust_snapshot_fails_closed(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery_history, activation_history = _record_delivery_and_activation(
        records, verifier, trust_factory
    )
    mismatched = _replace_accepted_trust(
        delivery_history,
        issuer="runtime.authority",
    )

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=(mismatched, activation_history)),
        expected_tenant=records["delivery_envelope"]["tenant_id"],
    )


@pytest.mark.parametrize(
    "snapshot_changes",
    [
        {"trust_policy_version": ""},
        {"allowed_algorithms": ("fixture-proof-v1", "fixture-proof-v1")},
        {"allowed_proof_domains": ()},
        {"expected_issuers": ()},
        {"allowed_domain_issuers": ()},
        {"key_algorithms": ()},
        {"clock_skew_microseconds": False},
        {"clock_skew_microseconds": -1},
        {
            "key_valid_from": datetime(2026, 1, 2, tzinfo=timezone.utc),
            "key_valid_until": datetime(2026, 1, 1, tzinfo=timezone.utc),
        },
    ],
)
def test_invalid_accepted_trust_snapshot_fields_fail_closed(
    snapshot_changes: dict[str, object],
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    delivery_history, activation_history = _record_delivery_and_activation(
        records, verifier, trust_factory
    )
    invalid = _replace_accepted_trust(delivery_history, **snapshot_changes)

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=trust_factory(historical_acceptances=(invalid, activation_history)),
        expected_tenant=records["delivery_envelope"]["tenant_id"],
    )


@pytest.mark.parametrize("invalidated_issuer", ["learning.authority", "runtime.authority"])
def test_retroactive_delivery_or_activation_key_invalidation_fails_closed(
    invalidated_issuer: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    histories = _record_delivery_and_activation(records, verifier, trust_factory)
    historical_trust = trust_factory(
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        trusted_keys=(),
        historical_acceptances=histories,
        retroactive_invalidations=(
            RetroactiveKeyInvalidation(
                issuer=invalidated_issuer,
                key_id=(
                    "learning.key.v1"
                    if invalidated_issuer == "learning.authority"
                    else "runtime.key.v1"
                ),
                invalid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ),
    )

    assert not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=historical_trust,
        expected_tenant=records["delivery_envelope"]["tenant_id"],
    )


def test_cross_tenant_rollback_cannot_reference_activation(
    records: dict[str, dict[str, Any]],
    rebind_tenant: Callable[[dict[str, Any], str], dict[str, Any]],
) -> None:
    rollback = rebind_tenant(records["rollback_receipt"], OTHER_TENANT)
    with pytest.raises(SemanticError, match="tenant_id"):
        validate_rollback_activation_binding(rollback, records["activation_receipt"])


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("delivery_id", OTHER_UUID),
        ("delivery_digest", "sha256:" + "9" * 64),
        ("artifact_id", OTHER_UUID),
        ("artifact_revision", 2),
        ("artifact_digest", "sha256:" + "8" * 64),
    ],
)
def test_activation_receipt_must_exactly_bind_delivery(
    field: str,
    replacement: Any,
    records: dict[str, dict[str, Any]],
) -> None:
    receipt = records["activation_receipt"]
    receipt[field] = replacement
    with pytest.raises(SemanticError, match="mismatch|binding"):
        validate_activation_delivery_binding(receipt, records["delivery_envelope"])


def test_activation_receipt_must_exactly_bind_delivery_target_scope(
    records: dict[str, dict[str, Any]],
) -> None:
    receipt = records["activation_receipt"]
    receipt["target_scope"]["scope_id"] = OTHER_UUID

    with pytest.raises(SemanticError, match="target_scope mismatch"):
        validate_activation_delivery_binding(receipt, records["delivery_envelope"])


@pytest.mark.parametrize(
    "lifecycle_state",
    ["exported", "delivery_failed", "rejected_by_runtime", "legacy_exported"],
)
def test_activation_requires_delivered_delivery_state(
    lifecycle_state: str,
    records: dict[str, dict[str, Any]],
) -> None:
    delivery = records["delivery_envelope"]
    delivery["lifecycle_state"] = lifecycle_state

    with pytest.raises(SemanticError, match="requires a delivered delivery envelope"):
        validate_activation_delivery_binding(records["activation_receipt"], delivery)


@pytest.mark.parametrize(
    "issued_at",
    ["2026-01-01T00:22:59.000Z", "2026-01-02T00:23:00.001Z"],
)
def test_activation_issue_time_must_be_within_delivery_validity(
    issued_at: str,
    records: dict[str, dict[str, Any]],
) -> None:
    receipt = records["activation_receipt"]
    receipt["issued_at"] = issued_at

    with pytest.raises(SemanticError, match="outside the delivery validity window"):
        validate_activation_delivery_binding(receipt, records["delivery_envelope"])


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("artifact_id", OTHER_UUID),
        ("artifact_revision", 2),
        ("artifact_digest", "sha256:" + "7" * 64),
    ],
)
def test_rollback_receipt_must_exactly_bind_activation(
    field: str,
    replacement: Any,
    records: dict[str, dict[str, Any]],
) -> None:
    rollback = records["rollback_receipt"]
    rollback[field] = replacement
    with pytest.raises(SemanticError, match="mismatch|binding"):
        validate_rollback_activation_binding(rollback, records["activation_receipt"])


def test_rollback_receipt_must_exactly_bind_activation_target_scope(
    records: dict[str, dict[str, Any]],
) -> None:
    rollback = records["rollback_receipt"]
    rollback["target_scope"]["scope_id"] = OTHER_UUID

    with pytest.raises(SemanticError, match="target_scope mismatch"):
        validate_rollback_activation_binding(rollback, records["activation_receipt"])


def test_rollback_cannot_be_issued_before_activation(
    records: dict[str, dict[str, Any]],
) -> None:
    rollback = records["rollback_receipt"]
    rollback["issued_at"] = "2026-01-01T00:23:59.999Z"

    with pytest.raises(SemanticError, match="cannot be before activation"):
        validate_rollback_activation_binding(rollback, records["activation_receipt"])


def test_rollback_receipt_reference_id_and_digest_are_both_bound(
    records: dict[str, dict[str, Any]],
    record_copy: Any,
) -> None:
    rollback = record_copy("rollback_receipt")
    rollback["activation_receipt_ref"]["record_id"] = OTHER_UUID
    with pytest.raises(SemanticError, match="ID mismatch"):
        validate_rollback_activation_binding(rollback, records["activation_receipt"])

    rollback = records["rollback_receipt"]
    rollback["activation_receipt_ref"]["record_digest"] = "sha256:" + "6" * 64
    with pytest.raises(SemanticError, match="digest mismatch"):
        validate_rollback_activation_binding(rollback, records["activation_receipt"])


def test_rollback_lifecycle_accepts_strict_historical_order_without_current_trust(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    tenant_id = records["activation_receipt"]["tenant_id"]
    histories = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=tenant_id,
    )
    historical_trust = trust_factory(
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        trusted_keys=(),
        allowed_algorithms=frozenset(),
        domains=frozenset(),
        expected_issuers=frozenset(),
        allowed_domain_issuers=frozenset(),
        historical_acceptances=histories,
    )

    validate_rollback_lifecycle(
        records["rollback_receipt"],
        records["activation_receipt"],
        verifier=verifier,
        trust=historical_trust,
        expected_tenant=tenant_id,
    )


@pytest.mark.parametrize(
    ("activation_position", "rollback_position"),
    [
        (17, 13),
        (13, 13),
        (-1, 17),
        (13, -1),
        (False, 17),
        (13, True),
    ],
)
def test_rollback_lifecycle_requires_nonnegative_activation_before_rollback_order(
    activation_position: int,
    rollback_position: int,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    tenant_id = records["activation_receipt"]["tenant_id"]
    activation_history, rollback_history = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=tenant_id,
    )
    histories = (
        dataclasses.replace(activation_history, ledger_position=activation_position),
        dataclasses.replace(rollback_history, ledger_position=rollback_position),
    )

    with pytest.raises(ProofVerificationError):
        validate_rollback_lifecycle(
            records["rollback_receipt"],
            records["activation_receipt"],
            verifier=verifier,
            trust=trust_factory(historical_acceptances=histories),
            expected_tenant=tenant_id,
        )


@pytest.mark.parametrize("missing_history", ["activation", "rollback"])
def test_rollback_lifecycle_requires_both_acceptance_histories(
    missing_history: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    tenant_id = records["activation_receipt"]["tenant_id"]
    activation_history, rollback_history = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=tenant_id,
    )
    histories = (rollback_history,) if missing_history == "activation" else (activation_history,)

    with pytest.raises(ProofVerificationError, match="exactly one historical"):
        validate_rollback_lifecycle(
            records["rollback_receipt"],
            records["activation_receipt"],
            verifier=verifier,
            trust=trust_factory(historical_acceptances=histories),
            expected_tenant=tenant_id,
        )


@pytest.mark.parametrize("duplicated_history", ["activation", "rollback"])
def test_rollback_lifecycle_rejects_duplicate_acceptance_histories(
    duplicated_history: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    tenant_id = records["activation_receipt"]["tenant_id"]
    activation_history, rollback_history = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=tenant_id,
    )
    duplicate = activation_history if duplicated_history == "activation" else rollback_history
    histories = (activation_history, rollback_history, duplicate)

    with pytest.raises(ProofVerificationError, match="exactly one historical"):
        validate_rollback_lifecycle(
            records["rollback_receipt"],
            records["activation_receipt"],
            verifier=verifier,
            trust=trust_factory(historical_acceptances=histories),
            expected_tenant=tenant_id,
        )


@pytest.mark.parametrize("malformation", ["mutable_collection", "wrong_member_type"])
def test_rollback_lifecycle_rejects_malformed_history(
    malformation: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    tenant_id = records["activation_receipt"]["tenant_id"]
    activation_history, rollback_history = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=tenant_id,
    )
    base_trust = trust_factory(historical_acceptances=(activation_history, rollback_history))
    malformed = (
        [activation_history, rollback_history]
        if malformation == "mutable_collection"
        else (activation_history, object(), rollback_history)
    )
    malformed_trust = dataclasses.replace(base_trust, historical_acceptances=malformed)

    with pytest.raises(ProofVerificationError, match="historical acceptance"):
        validate_rollback_lifecycle(
            records["rollback_receipt"],
            records["activation_receipt"],
            verifier=verifier,
            trust=malformed_trust,
            expected_tenant=tenant_id,
        )


@pytest.mark.parametrize("record_type", ["activation", "rollback"])
@pytest.mark.parametrize("corruption", ["snapshot", "snapshot_digest"])
def test_rollback_lifecycle_rejects_corrupted_historical_trust(
    record_type: str,
    corruption: str,
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    tenant_id = records["activation_receipt"]["tenant_id"]
    activation_history, rollback_history = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=tenant_id,
    )
    target = activation_history if record_type == "activation" else rollback_history
    corrupted = (
        _replace_accepted_trust(target, trust_policy_version="")
        if corruption == "snapshot"
        else dataclasses.replace(target, accepted_trust_digest="sha256:" + "0" * 64)
    )
    histories = (
        (corrupted, rollback_history)
        if record_type == "activation"
        else (activation_history, corrupted)
    )

    with pytest.raises(ProofVerificationError):
        validate_rollback_lifecycle(
            records["rollback_receipt"],
            records["activation_receipt"],
            verifier=verifier,
            trust=trust_factory(historical_acceptances=histories),
            expected_tenant=tenant_id,
        )


@pytest.mark.parametrize(
    ("mismatch", "replacement"),
    [
        ("tenant", OTHER_TENANT),
        ("artifact_id", OTHER_UUID),
        ("artifact_digest", "sha256:" + "7" * 64),
        ("artifact_revision", 2),
        ("activation_id", OTHER_UUID),
        ("activation_digest", "sha256:" + "6" * 64),
    ],
)
def test_rollback_lifecycle_rejects_cross_binding_mismatches(
    mismatch: str,
    replacement: Any,
    records: dict[str, dict[str, Any]],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
    rebind_tenant: Callable[[dict[str, Any], str], dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    rollback = records["rollback_receipt"]
    expected_tenant = records["activation_receipt"]["tenant_id"]
    if mismatch == "tenant":
        rebind_tenant(rollback, replacement)
        expected_tenant = None
    elif mismatch == "activation_id":
        rollback["activation_receipt_ref"]["record_id"] = replacement
        redigest(rollback)
    elif mismatch == "activation_digest":
        rollback["activation_receipt_ref"]["record_digest"] = replacement
        redigest(rollback)
    else:
        rollback[mismatch] = replacement
        redigest(rollback)

    histories = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=expected_tenant,
    )

    with pytest.raises(SemanticError):
        validate_rollback_lifecycle(
            rollback,
            records["activation_receipt"],
            verifier=verifier,
            trust=trust_factory(historical_acceptances=histories),
            expected_tenant=expected_tenant,
        )


def test_rollback_lifecycle_honors_retroactive_key_invalidation(
    records: dict[str, dict[str, Any]],
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    tenant_id = records["activation_receipt"]["tenant_id"]
    histories = _record_activation_and_rollback(
        records,
        verifier,
        trust_factory,
        expected_tenant=tenant_id,
    )
    historical_trust = trust_factory(
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        trusted_keys=(),
        allowed_algorithms=frozenset(),
        domains=frozenset(),
        expected_issuers=frozenset(),
        allowed_domain_issuers=frozenset(),
        historical_acceptances=histories,
        retroactive_invalidations=(
            RetroactiveKeyInvalidation(
                issuer="runtime.authority",
                key_id="runtime.key.v1",
                invalid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ),
    )

    with pytest.raises(ProofVerificationError, match="retroactive key revocation"):
        validate_rollback_lifecycle(
            records["rollback_receipt"],
            records["activation_receipt"],
            verifier=verifier,
            trust=historical_trust,
            expected_tenant=tenant_id,
        )


def test_receipt_expiry_blocks_first_acceptance_but_not_recorded_history(
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    receipt = record_copy("activation_receipt")
    initial = verify_runtime_receipt(receipt, verifier=verifier, trust=trust_factory())
    after_expiry = datetime(2027, 1, 1, tzinfo=timezone.utc)

    with pytest.raises(ProofVerificationError, match="expired before first acceptance"):
        verify_runtime_receipt(
            receipt,
            verifier=verifier,
            trust=trust_factory(now=after_expiry),
        )

    history = dataclasses.replace(initial, ledger_position=42)
    accepted = verify_runtime_receipt(
        receipt,
        verifier=verifier,
        trust=trust_factory(
            now=after_expiry,
            revoked_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
            historical_acceptances=(history,),
        ),
    )
    assert accepted is history


def test_historical_acceptance_requires_exact_receipt_and_complete_ledger(
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
    redigest: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    receipt = record_copy("activation_receipt")
    initial = verify_runtime_receipt(receipt, verifier=verifier, trust=trust_factory())
    after_expiry = datetime(2027, 1, 1, tzinfo=timezone.utc)

    incomplete = dataclasses.replace(initial, ledger_position=-1)
    with pytest.raises(ProofVerificationError, match="metadata is incomplete"):
        verify_runtime_receipt(
            receipt,
            verifier=verifier,
            trust=trust_factory(now=after_expiry, historical_acceptances=(incomplete,)),
        )

    tampered = record_copy("activation_receipt")
    tampered["reason"] = "not-declared"  # schema rejection remains fail closed
    with pytest.raises(ContractError):
        verify_runtime_receipt(
            tampered,
            verifier=verifier,
            trust=trust_factory(
                now=after_expiry,
                historical_acceptances=(dataclasses.replace(initial, ledger_position=1),),
            ),
        )

    changed = record_copy("activation_receipt")
    changed["artifact_revision"] = 2
    redigest(changed)
    with pytest.raises(ProofVerificationError, match="expired before first acceptance"):
        verify_runtime_receipt(
            changed,
            verifier=verifier,
            trust=trust_factory(
                now=after_expiry,
                historical_acceptances=(dataclasses.replace(initial, ledger_position=1),),
            ),
        )


def test_retroactive_key_invalidation_invalidates_receipt_after_key_removal(
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    receipt = record_copy("activation_receipt")
    initial = verify_runtime_receipt(receipt, verifier=verifier, trust=trust_factory())
    base_trust = trust_factory(
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        trusted_keys=(),
        historical_acceptances=(dataclasses.replace(initial, ledger_position=2),),
        retroactive_invalidations=(
            RetroactiveKeyInvalidation(
                issuer="runtime.authority",
                key_id="runtime.key.v1",
                invalid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ),
    )

    with pytest.raises(ProofVerificationError, match="retroactive key revocation"):
        verify_runtime_receipt(receipt, verifier=verifier, trust=base_trust)


def test_duplicate_retroactive_key_invalidations_fail_closed(
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    receipt = record_copy("activation_receipt")
    initial = verify_runtime_receipt(receipt, verifier=verifier, trust=trust_factory())
    invalidation = RetroactiveKeyInvalidation(
        issuer="runtime.authority",
        key_id="runtime.key.v1",
        invalid_from=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    trust = trust_factory(
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        trusted_keys=(),
        historical_acceptances=(dataclasses.replace(initial, ledger_position=2),),
        retroactive_invalidations=(invalidation, invalidation),
    )

    with pytest.raises(ProofVerificationError, match="duplicate retroactive invalidations"):
        verify_runtime_receipt(receipt, verifier=verifier, trust=trust)


def test_receipt_key_algorithm_policy_is_independent_of_global_allowlist(
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    trust = trust_factory(algorithms=frozenset({"different-proof-v1"}))
    with pytest.raises(ProofVerificationError, match="not allowed for the key"):
        verify_runtime_receipt(
            record_copy("activation_receipt"),
            verifier=verifier,
            trust=trust,
        )


def test_receipt_trust_requires_unique_key_binding(
    record_copy: Any,
    verifier: Any,
    trust_factory: Callable[..., Any],
) -> None:
    trust = trust_factory()
    duplicate = TrustedKey(
        issuer="runtime.authority",
        key_id="runtime.key.v1",
        algorithms=frozenset({"fixture-proof-v1"}),
        valid_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    trust = dataclasses.replace(trust, trusted_keys=(*trust.trusted_keys, duplicate))
    with pytest.raises(ProofVerificationError, match="not uniquely trusted"):
        verify_runtime_receipt(
            record_copy("activation_receipt"),
            verifier=verifier,
            trust=trust,
        )
