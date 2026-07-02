"""Reuse the synthetic contract fixtures without making tests a Python package."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_CONTRACT_CONFTEST = Path(__file__).parents[1] / "contracts" / "conftest.py"
_SPEC = importlib.util.spec_from_file_location("contract_test_fixtures", _CONTRACT_CONFTEST)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - repository layout guard
    raise RuntimeError("contract fixture module is unavailable")
_FIXTURES = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_FIXTURES)

positive_payloads = _FIXTURES.positive_payloads
positive_records = _FIXTURES.positive_records
records = _FIXTURES.records
verifier = _FIXTURES.verifier
trust_factory = _FIXTURES.trust_factory
