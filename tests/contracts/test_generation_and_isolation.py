"""Deterministic generation and offline-only contract test guarantees."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import urllib.request
import venv
import zipfile
from pathlib import Path
from typing import Any

import pytest

from governed_agent_harness.contracts import DEFAULT_SCHEMA_STORE, SchemaError, canonical_bytes
from governed_agent_harness.contracts.positive_fixtures import build_positive_fixture_files
from governed_agent_harness.contracts.self_check import run as run_self_check

ROOT = Path(__file__).resolve().parents[2]
POSITIVE = ROOT / "tests" / "contracts" / "fixtures" / "positive"
NEGATIVE = ROOT / "tests" / "contracts" / "fixtures" / "negative"
AUTHORITATIVE_SCHEMAS = ROOT / "contracts" / "v1"
PACKAGED_SCHEMAS = ROOT / "src" / "governed_agent_harness" / "contracts" / "schemas" / "v1"


def test_positive_fixture_generation_is_byte_for_byte_clean() -> None:
    generated = build_positive_fixture_files()
    actual = {path.name: path.read_bytes() for path in sorted(POSITIVE.glob("*.json"))}
    assert len(generated) == 29
    assert set(generated) == set(actual)
    assert generated == actual


def test_packaged_schemas_are_byte_identical_to_authority() -> None:
    authoritative = {
        path.name: path.read_bytes() for path in sorted(AUTHORITATIVE_SCHEMAS.glob("*.json"))
    }
    packaged = {path.name: path.read_bytes() for path in sorted(PACKAGED_SCHEMAS.glob("*.json"))}
    assert packaged == authoritative


def test_offline_installed_wheel_smoke(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "-w",
            str(wheelhouse),
            ".",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr
    wheel = next(wheelhouse.glob("governed_agent_harness-*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        wheel_schemas = {
            Path(name).name: archive.read(name)
            for name in archive.namelist()
            if name.startswith("governed_agent_harness/contracts/schemas/v1/")
        }
    authoritative_schemas = {
        path.name: path.read_bytes() for path in AUTHORITATIVE_SCHEMAS.glob("*.json")
    }
    assert wheel_schemas == authoritative_schemas
    environment = tmp_path / "environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr
    program = """
import governed_agent_harness.contracts as contracts
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.contracts.self_check import run

assert len(contracts.DEFAULT_SCHEMA_STORE.catalog) == 27
record = build_positive_records()["actor_context"]
contracts.DEFAULT_SCHEMA_STORE.validate_record(record, "actor_context")
first = run()
assert first == run()
print(first)
"""
    smoke = subprocess.run(
        [str(python), "-I", "-B", "-c", program],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert smoke.returncode == 0, smoke.stderr
    assert smoke.stdout.startswith("PASS: 27 models, 27 positive records")


def test_self_check_has_no_network_or_external_service_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> Any:
        raise AssertionError(f"external dependency attempted: args={args!r}, kwargs={kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    result = run_self_check(write=False)
    assert result.startswith("PASS: 27 models, 27 positive records, 6 vector checks")


def test_contract_import_is_isolated_from_legacy_repository_packages() -> None:
    program = """
import os
import sys
import threading
from pathlib import Path

environment_before = dict(os.environ)
threads_before = tuple(thread.ident for thread in threading.enumerate())
import governed_agent_harness.contracts as contracts
from governed_agent_harness.contracts.self_check import run

assert contracts.__name__ == "governed_agent_harness.contracts"
assert Path(contracts.__file__).resolve().parent == (
    Path(os.environ["PYTHONPATH"]).resolve() / "governed_agent_harness" / "contracts"
)
assert run().startswith("PASS: 27 models, 27 positive records, 6 vector checks")
legacy_roots = ("contracts", "src", "agent_architecture", "skillloop")
assert not any(
    name == root or name.startswith(f"{root}.")
    for name in sys.modules
    for root in legacy_roots
)
assert environment_before == dict(os.environ)
assert threads_before == tuple(thread.ident for thread in threading.enumerate())
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-B", "-c", program],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_canonical_schemas_do_not_reference_remote_resources() -> None:
    def walk(value: Any) -> list[str]:
        if isinstance(value, dict):
            refs = [value["$ref"]] if isinstance(value.get("$ref"), str) else []
            for child in value.values():
                refs.extend(walk(child))
            return refs
        if isinstance(value, list):
            refs = []
            for child in value:
                refs.extend(walk(child))
            return refs
        return []

    schema_names = {"definitions.schema.json", *DEFAULT_SCHEMA_STORE.catalog.values()}
    for schema_name in schema_names:
        document = json.loads((ROOT / "contracts" / "v1" / schema_name).read_bytes())
        assert all("://" not in ref and not ref.startswith("urn:") for ref in walk(document))

    with pytest.raises(SchemaError, match="remote schema reference is forbidden"):
        DEFAULT_SCHEMA_STORE.resolve_ref("https://example.invalid/schema.json", "catalog.json")


def test_negative_fixture_manifest_is_canonical_and_synthetic() -> None:
    payload = (NEGATIVE / "structural_cases.json").read_bytes()
    cases = json.loads(payload)
    canonical = canonical_bytes(cases)
    assert len(cases) >= 10
    assert canonical == canonical_bytes(json.loads(canonical))
    lowered = payload.lower()
    for marker in (b"password", b"secret", b"api_key", b"private_key", b"sk-"):
        assert marker not in lowered
