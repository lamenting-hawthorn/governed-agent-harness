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
    if external_socket:
        yield {
            "host": external_socket,
            "port": external_port,
            "user": "postgres",
            "dbname": "postgres",
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
    from governed_agent_harness.persistence import PostgresDurableEffectStore

    admin_values = dict(postgres_server)
    admin = psycopg.connect(**admin_values)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = 'gah_app'")
        if cursor.fetchone() is not None:
            cursor.execute(
                "REVOKE ALL ON gah_run_heads, gah_evidence_events, gah_effect_executions, gah_grant_consumptions FROM gah_app"
            )
        cursor.execute("DROP ROLE IF EXISTS gah_app")
        cursor.execute("CREATE ROLE gah_app LOGIN NOSUPERUSER NOBYPASSRLS INHERIT")
    admin.close()
    PostgresDurableEffectStore.install_schema(
        admin_connect=lambda: psycopg.connect(**admin_values), application_role="gah_app"
    )
    reset = psycopg.connect(**admin_values)
    reset.autocommit = True
    with reset.cursor() as cursor:
        cursor.execute(
            "TRUNCATE gah_grant_consumptions, gah_effect_executions, gah_evidence_events, gah_run_heads"
        )
    reset.close()
    app_values = {**admin_values, "user": "gah_app"}
    yield {
        "admin": lambda: psycopg.connect(**admin_values),
        "app": lambda: psycopg.connect(**app_values),
        "store": lambda: PostgresDurableEffectStore(
            connect=lambda: psycopg.connect(**app_values),
            privileged_connect=lambda: psycopg.connect(**admin_values),
            clock=lambda: datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc),
            ids=_ids(),
        ),
    }
    cleanup = psycopg.connect(**admin_values)
    cleanup.autocommit = True
    with cleanup.cursor() as cursor:
        cursor.execute(
            "REVOKE ALL ON gah_run_heads, gah_evidence_events, gah_effect_executions, gah_grant_consumptions FROM gah_app"
        )
        cursor.execute("DROP ROLE IF EXISTS gah_app")
    cleanup.close()


def _ids():
    def next_id() -> str:
        with _ID_LOCK:
            _ID_STATE[0] += 1
            return f"018f0000-0000-7000-8000-{_ID_STATE[0]:012x}"

    return next_id


def _unavailable(message: str) -> None:
    if os.environ.get("GAH_REQUIRE_POSTGRES") == "1":
        pytest.fail(message)
    pytest.skip(message)


_ID_STATE = [100]
_ID_LOCK = threading.Lock()
