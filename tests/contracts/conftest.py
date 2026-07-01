"""Shared synthetic fixtures for canonical contract compatibility tests."""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from governed_agent_harness.contracts import (  # noqa: E402
    ConstraintRegistry,
    HistoricalAcceptance,
    RetroactiveKeyInvalidation,
    TrustContext,
    TrustedKey,
    apply_object_digest,
)

POSITIVE_FIXTURES = ROOT / "tests" / "contracts" / "fixtures" / "positive"
NEGATIVE_FIXTURES = ROOT / "tests" / "contracts" / "fixtures" / "negative"

TENANT_ID = "018f0000-0000-7000-8000-000000000001"
OTHER_TENANT_ID = "018f0000-0000-7000-8000-000000000999"


class RecordingVerifier:
    """Synthetic injected verifier that records calls and has no crypto authority."""

    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.calls: list[dict[str, object]] = []

    def verify(self, **values: object) -> bool:
        self.calls.append(dict(values))
        return self.accepted


def _redigest_tree(record: dict[str, Any]) -> dict[str, Any]:
    for value in record.values():
        if isinstance(value, dict):
            if value.get("schema_version") == "1.0" and isinstance(value.get("record_type"), str):
                _redigest_tree(value)
        elif isinstance(value, list):
            for item in value:
                if (
                    isinstance(item, dict)
                    and item.get("schema_version") == "1.0"
                    and isinstance(item.get("record_type"), str)
                ):
                    _redigest_tree(item)
    return apply_object_digest(record)


def _rebind_tenant(value: Any, tenant_id: str) -> None:
    if isinstance(value, dict):
        if "tenant_id" in value:
            value["tenant_id"] = tenant_id
        for child in value.values():
            _rebind_tenant(child, tenant_id)
    elif isinstance(value, list):
        for child in value:
            _rebind_tenant(child, tenant_id)


@pytest.fixture(scope="session")
def positive_payloads() -> Mapping[str, bytes]:
    return {
        path.stem: path.read_bytes()
        for path in sorted(POSITIVE_FIXTURES.glob("*.json"))
        if not path.name.endswith("_vectors.json")
    }


@pytest.fixture(scope="session")
def positive_records(positive_payloads: Mapping[str, bytes]) -> Mapping[str, dict[str, Any]]:
    return {name: json.loads(payload) for name, payload in positive_payloads.items()}


@pytest.fixture
def records(
    positive_records: Mapping[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return copy.deepcopy(dict(positive_records))


@pytest.fixture
def record_copy(
    positive_records: Mapping[str, dict[str, Any]],
) -> Callable[[str], dict[str, Any]]:
    return lambda record_type: copy.deepcopy(positive_records[record_type])


@pytest.fixture
def redigest() -> Callable[[dict[str, Any]], dict[str, Any]]:
    return _redigest_tree


@pytest.fixture
def rebind_tenant() -> Callable[[dict[str, Any], str], dict[str, Any]]:
    def rebind(record: dict[str, Any], tenant_id: str) -> dict[str, Any]:
        _rebind_tenant(record, tenant_id)
        return _redigest_tree(record)

    return rebind


@pytest.fixture
def constraint_registry() -> ConstraintRegistry:
    return ConstraintRegistry({"example.org/max_actions": frozenset({"1.0"})})


@pytest.fixture
def verifier() -> RecordingVerifier:
    return RecordingVerifier()


@pytest.fixture
def trust_factory() -> Callable[..., TrustContext]:
    def factory(
        *,
        now: datetime = datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
        issuer: str = "runtime.authority",
        key_id: str = "runtime.key.v1",
        algorithms: frozenset[str] = frozenset({"fixture-proof-v1"}),
        allowed_algorithms: frozenset[str] = frozenset({"fixture-proof-v1"}),
        domains: frozenset[str] = frozenset(
            {
                "approval_record.v1",
                "authorization_grant.v1",
                "delivery_envelope.v1",
                "activation_receipt.v1",
                "rollback_receipt.v1",
            }
        ),
        expected_issuers: frozenset[str] | None = None,
        allowed_domain_issuers: frozenset[tuple[str, str]] | None = None,
        valid_until: datetime | None = datetime(2026, 1, 2, tzinfo=timezone.utc),
        revoked_at: datetime | None = None,
        trusted_keys: tuple[TrustedKey, ...] | None = None,
        historical_acceptances: tuple[HistoricalAcceptance, ...] = (),
        retroactive_invalidations: tuple[RetroactiveKeyInvalidation, ...] = (),
    ) -> TrustContext:
        key_bindings = (
            (issuer, key_id),
            ("policy.authority", "policy.key.v1"),
            ("learning.authority", "learning.key.v1"),
        )
        keys = (
            tuple(
                TrustedKey(
                    issuer=key_issuer,
                    key_id=key_name,
                    algorithms=algorithms,
                    valid_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
                    valid_until=valid_until,
                    revoked_at=revoked_at,
                )
                for key_issuer, key_name in key_bindings
            )
            if trusted_keys is None
            else trusted_keys
        )
        domain_issuers = (
            allowed_domain_issuers
            if allowed_domain_issuers is not None
            else frozenset(
                {
                    ("approval_record.v1", "policy.authority"),
                    ("authorization_grant.v1", "policy.authority"),
                    ("delivery_envelope.v1", "learning.authority"),
                    ("activation_receipt.v1", issuer),
                    ("rollback_receipt.v1", issuer),
                }
            )
        )
        return TrustContext(
            now=now,
            trusted_keys=keys,
            allowed_algorithms=allowed_algorithms,
            allowed_proof_domains=domains,
            expected_issuers=(
                expected_issuers
                if expected_issuers is not None
                else frozenset({issuer, "policy.authority", "learning.authority"})
            ),
            allowed_domain_issuers=domain_issuers,
            trust_policy_version="fixture.trust.v1",
            clock_skew=timedelta(seconds=30),
            historical_acceptances=historical_acceptances,
            retroactive_invalidations=retroactive_invalidations,
        )

    return factory
