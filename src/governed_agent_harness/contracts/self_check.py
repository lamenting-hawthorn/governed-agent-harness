"""Scoped deterministic positive-fixture validation command."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .canonical import canonical_bytes, sha256_bytes, sha256_digest
from .errors import ContractError, ProofVerificationError
from .models import MODEL_BY_RECORD_TYPE, MODEL_CLASSES, parse_model
from .positive_fixtures import TENANT_ID, build_positive_fixture_files
from .schema import DEFAULT_SCHEMA_STORE
from .validation import (
    ConstraintRegistry,
    IdempotencyResult,
    RetroactiveKeyInvalidation,
    TrustContext,
    TrustedKey,
    accepted_trust_snapshot_digest,
    compare_idempotency_bindings,
    learning_artifact_is_active,
    validate_activation_delivery_binding,
    validate_approval_binding,
    validate_constraint_support,
    validate_grant_binding,
    validate_policy_request_binding,
    validate_rollback_activation_binding,
    validate_scope_narrowing,
    verify_runtime_receipt,
    verify_signed_record,
)

FIXTURE_DIRECTORY = (
    Path(__file__).resolve().parents[3] / "tests" / "contracts" / "fixtures" / "positive"
)


class _FixtureProofVerifier:
    """Explicit synthetic verifier for fixture plumbing; never production crypto."""

    def verify(self, **values: object) -> bool:
        authorities = {
            "approval_record.v1": ("policy.authority", "policy.key.v1"),
            "authorization_grant.v1": ("policy.authority", "policy.key.v1"),
            "delivery_envelope.v1": ("learning.authority", "learning.key.v1"),
            "activation_receipt.v1": ("runtime.authority", "runtime.key.v1"),
            "rollback_receipt.v1": ("runtime.authority", "runtime.key.v1"),
        }
        domain = values.get("proof_domain")
        unsigned_bytes = values.get("unsigned_bytes")
        return (
            isinstance(domain, str)
            and authorities.get(domain) == (values.get("issuer"), values.get("key_id"))
            and values.get("algorithm") == "fixture-proof-v1"
            and values.get("nonce") == "N" * 22
            and values.get("detached_proof") == "P" * 43
            and isinstance(unsigned_bytes, bytes)
            and values.get("object_digest") == sha256_bytes(unsigned_bytes)
        )


def _trusted_key(issuer: str, key_id: str) -> TrustedKey:
    return TrustedKey(
        issuer=issuer,
        key_id=key_id,
        algorithms=frozenset({"fixture-proof-v1"}),
        valid_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
        valid_until=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )


def _trust(
    *,
    now: datetime,
    domains: frozenset[str],
    domain_issuers: frozenset[tuple[str, str]],
) -> TrustContext:
    return TrustContext(
        now=now,
        trusted_keys=(
            _trusted_key("policy.authority", "policy.key.v1"),
            _trusted_key("learning.authority", "learning.key.v1"),
            _trusted_key("runtime.authority", "runtime.key.v1"),
        ),
        allowed_algorithms=frozenset({"fixture-proof-v1"}),
        allowed_proof_domains=domains,
        expected_issuers=frozenset(issuer for _, issuer in domain_issuers),
        allowed_domain_issuers=domain_issuers,
        trust_policy_version="fixture.trust.v1",
        clock_skew=timedelta(seconds=30),
    )


def _write_fixtures(expected: dict[str, bytes]) -> None:
    FIXTURE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for path in FIXTURE_DIRECTORY.glob("*.json"):
        if path.name not in expected:
            raise ContractError(
                f"unexpected positive fixture prevents deterministic write: {path.name}"
            )
    for name, payload in expected.items():
        (FIXTURE_DIRECTORY / name).write_bytes(payload)


def _load_record_fixtures(expected: dict[str, bytes]) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for record_type in DEFAULT_SCHEMA_STORE.catalog:
        name = f"{record_type}.json"
        payload = (FIXTURE_DIRECTORY / name).read_bytes()
        if payload != expected[name]:
            raise ContractError(f"fixture is not deterministically generated: {name}")
        model = parse_model(payload, expected_tenant=TENANT_ID)
        if model.RECORD_TYPE != record_type:
            raise ContractError(f"fixture model mismatch: {name}")
        records[record_type] = model.to_dict()
    return records


def _check_vectors(expected: dict[str, bytes]) -> int:
    count = 0
    for name in ("canonicalization_vectors.json", "digest_vectors.json"):
        payload = (FIXTURE_DIRECTORY / name).read_bytes()
        if payload != expected[name]:
            raise ContractError(f"fixture vector is not deterministically generated: {name}")
        vectors = json.loads(payload)
        for vector in vectors:
            actual = canonical_bytes(vector["input"]).decode("utf-8")
            if actual != vector["canonical"]:
                raise ContractError(f"canonicalization vector failed: {vector['name']}")
            if "digest" in vector and sha256_digest(vector["input"]) != vector["digest"]:
                raise ContractError(f"digest vector failed: {vector['name']}")
            count += 1
    return count


def _check_cross_record_invariants(records: dict[str, dict[str, object]]) -> None:
    constraint_registry = ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})})
    for record in records.values():
        validate_constraint_support(record, constraint_registry)
    validate_scope_narrowing(records["memory_scope"], records["actor_context"])
    child_scope = copy.deepcopy(records["memory_scope"])
    child_scope["parent_record_type"] = "memory_scope"
    child_scope["parent_digest"] = sha256_digest(records["memory_scope"])
    validate_scope_narrowing(child_scope, records["memory_scope"])
    validate_policy_request_binding(records["policy_decision"], records["tool_request"])
    validate_approval_binding(
        records["approval_record"], records["policy_decision"], records["tool_request"]
    )
    verifier = _FixtureProofVerifier()
    grant_trust = _trust(
        now=datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc),
        domains=frozenset({"approval_record.v1", "authorization_grant.v1"}),
        domain_issuers=frozenset(
            {
                ("approval_record.v1", "policy.authority"),
                ("authorization_grant.v1", "policy.authority"),
            }
        ),
    )
    validate_grant_binding(
        records["authorization_grant"],
        records["tool_request"],
        records["policy_decision"],
        [records["approval_record"]],
        constraint_registry=constraint_registry,
        verifier=verifier,
        trust=grant_trust,
    )
    for altered_type in ("approval_record", "authorization_grant"):
        altered_approval = copy.deepcopy(records["approval_record"])
        altered_grant = copy.deepcopy(records["authorization_grant"])
        altered = altered_approval if altered_type == "approval_record" else altered_grant
        altered["proof"]["detached_proof"] = "Q" * 43
        try:
            validate_grant_binding(
                altered_grant,
                records["tool_request"],
                records["policy_decision"],
                [altered_approval],
                constraint_registry=constraint_registry,
                verifier=verifier,
                trust=grant_trust,
            )
        except ProofVerificationError:
            pass
        else:
            raise ContractError(f"altered {altered_type} proof was accepted")
    validate_activation_delivery_binding(
        records["activation_receipt"], records["delivery_envelope"]
    )
    validate_rollback_activation_binding(records["rollback_receipt"], records["activation_receipt"])
    binding = records["tool_request"]["idempotency"]
    if compare_idempotency_bindings(None, binding) is not IdempotencyResult.NEW:
        raise ContractError("new idempotency binding was not classified as new")
    if compare_idempotency_bindings(binding, dict(binding)) is not IdempotencyResult.REPLAY:
        raise ContractError("equal idempotency binding was not classified as replay")


def _check_receipt_proofs(records: dict[str, dict[str, object]]) -> None:
    verifier = _FixtureProofVerifier()
    initial_trust = _trust(
        now=datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
        domains=frozenset({"delivery_envelope.v1", "activation_receipt.v1", "rollback_receipt.v1"}),
        domain_issuers=frozenset(
            {
                ("delivery_envelope.v1", "learning.authority"),
                ("activation_receipt.v1", "runtime.authority"),
                ("rollback_receipt.v1", "runtime.authority"),
            }
        ),
    )
    if learning_artifact_is_active(
        records["delivery_envelope"],
        None,
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("delivery became active without a runtime receipt")
    delivery_acceptance = verify_signed_record(
        records["delivery_envelope"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=TENANT_ID,
    )
    activation_acceptance = verify_runtime_receipt(
        records["activation_receipt"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=TENANT_ID,
    )
    for label, acceptance in (
        ("delivery", delivery_acceptance),
        ("activation", activation_acceptance),
    ):
        if acceptance.accepted_trust_digest != accepted_trust_snapshot_digest(
            acceptance.accepted_trust
        ):
            raise ContractError(f"{label} acceptance trust snapshot digest was not canonical")
    if learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("unrecorded acceptances activated an artifact")
    altered_delivery = copy.deepcopy(records["delivery_envelope"])
    altered_delivery["proof"]["detached_proof"] = "Q" * 43
    if learning_artifact_is_active(
        altered_delivery,
        records["activation_receipt"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("altered delivery proof activated an artifact")
    verify_runtime_receipt(
        records["rollback_receipt"],
        verifier=verifier,
        trust=initial_trust,
        expected_tenant=TENANT_ID,
    )

    delivery_history = dataclasses.replace(delivery_acceptance, ledger_position=0)
    activation_history = dataclasses.replace(activation_acceptance, ledger_position=1)
    historical_trust = dataclasses.replace(
        initial_trust,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        trusted_keys=(),
        allowed_algorithms=frozenset(),
        allowed_proof_domains=frozenset(),
        expected_issuers=frozenset(),
        allowed_domain_issuers=frozenset(),
        trust_policy_version="fixture.trust.v2",
        historical_acceptances=(delivery_history, activation_history),
    )
    if not learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=historical_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError(
            "accepted artifact became inactive after proof expiry, key removal, or policy rotation"
        )
    if learning_artifact_is_active(
        altered_delivery,
        records["activation_receipt"],
        verifier=verifier,
        trust=historical_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("altered delivery proof matched historical acceptance")
    for delivery_position, activation_position in ((-1, 1), (0, -1), (2, 2), (3, 2)):
        ordered_trust = dataclasses.replace(
            historical_trust,
            historical_acceptances=(
                dataclasses.replace(delivery_history, ledger_position=delivery_position),
                dataclasses.replace(activation_history, ledger_position=activation_position),
            ),
        )
        if learning_artifact_is_active(
            records["delivery_envelope"],
            records["activation_receipt"],
            verifier=verifier,
            trust=ordered_trust,
            expected_tenant=TENANT_ID,
        ):
            raise ContractError(
                "artifact activated without a distinct delivery-before-activation ledger order"
            )
    duplicate_history_trust = dataclasses.replace(
        historical_trust,
        historical_acceptances=(delivery_history, delivery_history, activation_history),
    )
    if learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=duplicate_history_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("duplicate historical acceptance activated an artifact")
    corrupted_snapshot = dataclasses.replace(
        delivery_history,
        accepted_trust=dataclasses.replace(
            delivery_history.accepted_trust,
            trust_policy_version="corrupted.trust",
        ),
    )
    corrupted_snapshot_trust = dataclasses.replace(
        historical_trust,
        historical_acceptances=(corrupted_snapshot, activation_history),
    )
    if learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=corrupted_snapshot_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("corrupted accepted-trust snapshot activated an artifact")
    corrupted_digest = dataclasses.replace(
        delivery_history,
        accepted_trust_digest="sha256:" + "0" * 64,
    )
    corrupted_digest_trust = dataclasses.replace(
        historical_trust,
        historical_acceptances=(corrupted_digest, activation_history),
    )
    if learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=corrupted_digest_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("corrupted accepted-trust digest activated an artifact")
    compromised_trust = dataclasses.replace(
        historical_trust,
        retroactive_invalidations=(
            RetroactiveKeyInvalidation(
                issuer="runtime.authority",
                key_id="runtime.key.v1",
                invalid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ),
    )
    if learning_artifact_is_active(
        records["delivery_envelope"],
        records["activation_receipt"],
        verifier=verifier,
        trust=compromised_trust,
        expected_tenant=TENANT_ID,
    ):
        raise ContractError("retroactively invalidated key history activated an artifact")


def run(*, write: bool = False) -> str:
    expected = build_positive_fixture_files()
    if write:
        _write_fixtures(expected)
    DEFAULT_SCHEMA_STORE.audit_catalog()
    expected_models = set(DEFAULT_SCHEMA_STORE.catalog)
    actual_models = {model.RECORD_TYPE for model in MODEL_CLASSES}
    if expected_models != actual_models or len(MODEL_BY_RECORD_TYPE) != 27:
        raise ContractError("static model registry does not exactly match the 27-record catalog")
    records = _load_record_fixtures(expected)
    vector_count = _check_vectors(expected)
    _check_cross_record_invariants(records)
    _check_receipt_proofs(records)
    expected_names = set(expected)
    actual_names = {path.name for path in FIXTURE_DIRECTORY.glob("*.json")}
    if actual_names != expected_names:
        raise ContractError(
            f"positive fixture file set differs: missing={sorted(expected_names - actual_names)}, "
            f"extra={sorted(actual_names - expected_names)}"
        )
    return (
        f"PASS: 27 models, 27 positive records, {vector_count} vector checks, "
        "cross-record bindings, proof trust, historical acceptance, deterministic files"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="write deterministic positive fixtures"
    )
    arguments = parser.parse_args()
    try:
        print(run(write=arguments.write))
    except (ContractError, OSError, ValueError) as exc:
        print(f"FAIL: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
