from __future__ import annotations

import os
import shutil
import subprocess
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def postgres_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    """Start an isolated local PostgreSQL cluster without printing credentials or DSNs."""

    if os.environ.get("GAH_SKIP_POSTGRES") == "1":
        _unavailable("PostgreSQL integration explicitly disabled")
    binaries = {name: shutil.which(name) for name in ("initdb", "pg_ctl")}
    if any(value is None for value in binaries.values()):
        _unavailable("PostgreSQL server binaries are unavailable")
    external_socket = os.environ.get("GAH_TEST_POSTGRES_SOCKET")
    external_port = os.environ.get("GAH_TEST_POSTGRES_PORT", "5432")
    external_database = os.environ.get("GAH_TEST_POSTGRES_DB", "postgres")
    if external_socket:
        yield {
            "host": external_socket,
            "port": external_port,
            "user": "postgres",
            "dbname": external_database,
        }
        return
    root = tmp_path_factory.mktemp("gah-postgres")
    data = root / "data"
    socket = root / "socket"
    socket.mkdir()
    port = str(55450 + (os.getpid() % 100))
    try:
        subprocess.run(
            [
                binaries["initdb"],
                "--no-locale",
                "--encoding=UTF8",
                "--auth-local=trust",
                "--auth-host=reject",
                "--username=postgres",
                f"--pgdata={data}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        _unavailable("PostgreSQL cluster could not start in this sandbox")
    with (data / "postgresql.conf").open("a", encoding="utf-8") as config:
        config.write("\nlisten_addresses = ''\n")
    options = f"-F -k {socket} -p {port}"
    try:
        subprocess.run(
            [binaries["pg_ctl"], f"--pgdata={data}", "--wait", "start", f"--options={options}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        _unavailable("PostgreSQL server could not start in this sandbox")
    try:
        yield {"host": str(socket), "port": port, "user": "postgres", "dbname": "postgres"}
    finally:
        subprocess.run(
            [binaries["pg_ctl"], f"--pgdata={data}", "--wait", "--mode=fast", "stop"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


@pytest.fixture
def postgres_connections(postgres_server: dict[str, str], tmp_path: Path):
    try:
        import psycopg
    except ImportError:
        _unavailable("psycopg is unavailable")
        return
    from governed_agent_harness.persistence import (
        PostgresDurableEffectStore,
        PostgresMemoryPromotionAuthority,
    )

    admin_values = dict(postgres_server)
    admin = psycopg.connect(**admin_values)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute("DROP ROLE IF EXISTS gah_app")
        cursor.execute("DROP ROLE IF EXISTS gah_writer")
        cursor.execute("CREATE ROLE gah_app LOGIN NOSUPERUSER NOBYPASSRLS INHERIT")
        cursor.execute("CREATE ROLE gah_writer LOGIN NOSUPERUSER NOBYPASSRLS INHERIT")
    admin.close()
    PostgresDurableEffectStore.install_schema(
        admin_connect=lambda: psycopg.connect(**admin_values),
        application_role="gah_app",
        authority_role="gah_writer",
    )
    from governed_agent_harness.contracts.positive_fixtures import build_positive_records

    actor = build_positive_records()["actor_context"]
    PostgresDurableEffectStore.provision_principal(
        admin_connect=lambda: psycopg.connect(**admin_values),
        database_roles=("gah_app", "gah_writer"),
        actor_context=actor,
    )
    reset = psycopg.connect(**admin_values)
    reset.autocommit = True
    with reset.cursor() as cursor:
        cursor.execute(
            "TRUNCATE gah_memory_transitions, gah_grant_consumptions, gah_effect_executions, "
            "gah_request_lifecycle, gah_evidence_events, gah_run_heads, gah_memory_records"
        )
    reset.close()
    app_values = {**admin_values, "user": "gah_app"}
    writer_values = {**admin_values, "user": "gah_writer"}
    yield {
        "admin": lambda: psycopg.connect(**admin_values),
        "app": lambda: psycopg.connect(**app_values),
        "writer": lambda: psycopg.connect(**writer_values),
        "store": lambda: PostgresDurableEffectStore(
            connect=lambda: psycopg.connect(**app_values),
            privileged_connect=lambda: psycopg.connect(**writer_values),
            clock=lambda: datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc),
            ids=_ids(),
        ),
        "store_at": lambda now: PostgresDurableEffectStore(
            connect=lambda: psycopg.connect(**app_values),
            privileged_connect=lambda: psycopg.connect(**writer_values),
            clock=lambda: now,
            ids=_ids(),
        ),
        "promotion_authority_at": lambda now, verifier=None, trust=None: (
            PostgresMemoryPromotionAuthority(
                privileged_connect=lambda: psycopg.connect(**writer_values),
                clock=lambda: now,
                ids=_ids(),
                approval_verifier=verifier,
                approval_trust=trust,
            )
        ),
        "store_for_lease": lambda lease_duration: PostgresDurableEffectStore(
            connect=lambda: psycopg.connect(**app_values),
            privileged_connect=lambda: psycopg.connect(**writer_values),
            clock=lambda: datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc),
            ids=_ids(),
            lease_duration=lease_duration,
        ),
        "expire_lease": lambda request_id: _admin_update(
            admin_values,
            "UPDATE gah_effect_executions "
            "SET last_renewed_at = clock_timestamp() - interval '2 seconds', "
            "lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE request_id = %s",
            (request_id,),
        ),
        "tamper_projection": lambda request_id: _admin_update(
            admin_values,
            "UPDATE gah_request_lifecycle SET version = version + 1 WHERE request_id = %s",
            (request_id,),
        ),
        "tamper_projection_position": lambda request_id: _admin_update(
            admin_values,
            "UPDATE gah_request_lifecycle SET last_evidence_sequence = "
            "last_evidence_sequence + 100 WHERE request_id = %s",
            (request_id,),
        ),
        "delete_projection": lambda request_id: _admin_update(
            admin_values,
            "DELETE FROM gah_request_lifecycle WHERE request_id = %s",
            (request_id,),
        ),
        "seed_memory": lambda record: _seed_memory(admin_values, record),
    }
    cleanup = psycopg.connect(**admin_values)
    cleanup.autocommit = True
    with cleanup.cursor() as cursor:
        cursor.execute(
            "DELETE FROM gah_runtime_principals WHERE database_role IN ('gah_app', 'gah_writer')"
        )
        cursor.execute("REVOKE gah_runtime FROM gah_app")
        cursor.execute("REVOKE gah_authority_writer FROM gah_writer")
        cursor.execute("DROP ROLE IF EXISTS gah_app")
        cursor.execute("DROP ROLE IF EXISTS gah_writer")
    cleanup.close()


def _ids():
    def next_id() -> str:
        with _ID_LOCK:
            _ID_STATE[0] += 1
            return f"018f0000-0000-7000-8000-{_ID_STATE[0]:012x}"

    return next_id


def _admin_update(values, statement, parameters) -> None:
    import psycopg

    connection = psycopg.connect(**values)
    with connection, connection.cursor() as cursor:
        cursor.execute(statement, parameters)


def _seed_memory(values, record) -> None:
    import psycopg

    connection = psycopg.connect(**values)
    with connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_memory_records ("
            "tenant_id, actor_id, memory_id, revision, record_digest, record_json, "
            "scope_json, proposition_json, observed_at, effective_from, effective_until, "
            "expires_at, lifecycle_state"
            ") VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, "
            "%s::timestamptz, %s::timestamptz, %s::timestamptz, %s::timestamptz, %s)",
            (
                record["tenant_id"],
                record["scope"]["actor_id"],
                record["memory_id"],
                record["revision"],
                record["record_digest"],
                _json(record),
                _json(record["scope"]),
                _json(record["proposition"]),
                record["observed_at"],
                record["effective_from"],
                record["effective_until"],
                record["expires_at"],
                record["lifecycle_state"],
            ),
        )


def _json(value) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _unavailable(message: str) -> None:
    if os.environ.get("GAH_REQUIRE_POSTGRES") == "1":
        pytest.fail(message)
    pytest.skip(message)


_ID_STATE = [100]
_ID_LOCK = threading.Lock()
