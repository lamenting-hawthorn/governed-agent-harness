from __future__ import annotations

import os
import shutil
import subprocess
import sys
import venv
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest

from governed_agent_harness.persistence.migration import (
    Migration,
    MigrationError,
    apply_migrations,
    discover_migrations,
)


@pytest.fixture
def migration_database(postgres_server: dict[str, str]) -> Iterator[dict[str, object]]:
    import psycopg
    from psycopg import sql

    database = f"gah_migration_test_{uuid4().hex}"
    admin = psycopg.connect(**postgres_server)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    admin.close()

    def connect():
        return psycopg.connect(**{**postgres_server, "dbname": database})

    try:
        yield {"database": database, "connect": connect}
    finally:
        cleanup = psycopg.connect(**postgres_server)
        cleanup.autocommit = True
        with cleanup.cursor() as cursor:
            cursor.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))
        cleanup.close()


def test_packaged_migrations_are_contiguous_and_checksum_exact() -> None:
    migrations = discover_migrations()

    assert [(migration.version, migration.name) for migration in migrations] == [
        (1, "0001_durable_effects.sql"),
        (2, "0002_fenced_lifecycle.sql"),
        (3, "0003_runtime_api.sql"),
    ]
    assert migrations[0].checksum.startswith("sha256:")
    assert len(migrations[0].checksum) == 71
    assert migrations == discover_migrations()


def test_non_public_install_target_fails_closed(
    migration_database: dict[str, object],
) -> None:
    from psycopg import sql

    connect = migration_database["connect"]
    assert callable(connect)
    schema = f"gah_unsupported_{uuid4().hex}"
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))

    def non_public_connect():
        connection = connect()
        with connection.cursor() as cursor:
            cursor.execute(
                sql.SQL("SET search_path = {}, pg_catalog").format(sql.Identifier(schema))
            )
        connection.commit()
        return connection

    with pytest.raises(MigrationError, match="current_schema.*public"):
        apply_migrations(admin_connect=non_public_connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass(%s)", (f"{schema}.gah_schema_migrations",))
        assert cursor.fetchone()[0] is None


def test_fresh_install_registers_migration_and_is_idempotent(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]
    assert callable(connect)

    first = apply_migrations(admin_connect=connect)
    second = apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT version, checksum, applied_at IS NOT NULL FROM gah_schema_migrations"
        )
        rows = cursor.fetchall()
        cursor.execute("SELECT to_regclass('gah_run_heads'), to_regclass('gah_effect_executions')")
        tables = cursor.fetchone()
    assert rows == [(item.version, item.checksum, True) for item in first]
    assert second == first
    assert all(table is not None for table in tables)


def test_advisory_lock_serializes_concurrent_fresh_installers(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _index: apply_migrations(admin_connect=connect), range(2))
        )

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT version, count(*) FROM gah_schema_migrations GROUP BY version ORDER BY version"
        )
        rows = cursor.fetchall()
    assert results[0] == results[1]
    assert rows == [(1, 1), (2, 1), (3, 1)]


def test_exact_phase4_schema_is_registered_without_reexecution(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]
    migration = discover_migrations()[0]
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(migration.sql)

    apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT version, checksum FROM gah_schema_migrations")
        assert cursor.fetchall() == [
            (item.version, item.checksum) for item in discover_migrations()
        ]


def test_legacy_schema_with_preexisting_authority_grants_fails_closed(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(discover_migrations()[0].sql)
        cursor.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles "
            "WHERE rolname = 'gah_authority_writer') THEN "
            "CREATE ROLE gah_authority_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOINHERIT NOREPLICATION NOBYPASSRLS; "
            "END IF; END $$"
        )
        cursor.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
            "TO gah_authority_writer"
        )
    with pytest.raises(MigrationError, match="do not exactly match"):
        apply_migrations(admin_connect=connect)


def test_phase4_rows_receive_deterministic_fencing_backfill(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(discover_migrations()[0].sql)
        cursor.execute(
            """
            INSERT INTO gah_run_heads (tenant_id, actor_id, run_id)
            VALUES ('tenant-1', 'actor-1', 'run-1')
            """
        )
        cursor.execute(
            """
            INSERT INTO gah_effect_executions (
                tenant_id, actor_id, run_id, request_id, idempotency_key,
                operation_digest, binding_digest, grant_id, grant_digest, state,
                actor_context_json, request_json, policy_json, approvals_json,
                grant_json, intent_envelope_json, prepared_at
            ) VALUES (
                'tenant-1', 'actor-1', 'run-1', 'request-1', 'idem-1',
                'sha256:operation', 'sha256:binding', 'grant-1', 'sha256:grant', 'prepared',
                '{"tenant_id":"tenant-1","actor_id":"actor-1"}'::jsonb,
                '{"tenant_id":"tenant-1","actor_id":"actor-1","run_id":"run-1",'
                    '"request_id":"request-1","idempotency":{'
                    '"idempotency_key":"idem-1","operation_digest":"sha256:operation"}}'::jsonb,
                '{}'::jsonb, '[]'::jsonb,
                '{"tenant_id":"tenant-1","actor_id":"actor-1","run_id":"run-1",'
                    '"request_id":"request-1","grant_id":"grant-1"}'::jsonb,
                '{}'::jsonb, '2026-01-01T00:00:00Z'::timestamptz
            )
            """
        )

    apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT execution_attempt_id, owner_generation,
                   lease_expires_at = prepared_at, last_renewed_at = prepared_at
              FROM gah_effect_executions
             WHERE request_id = 'request-1'
            """
        )
        assert cursor.fetchone() == ("legacy:request-1", 1, True, True)


def test_fencing_and_lifecycle_schema_are_installed_with_restricted_roles(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT attname, attnotnull
              FROM pg_attribute
             WHERE attrelid = 'gah_effect_executions'::regclass
               AND attname IN (
                   'execution_attempt_id', 'owner_generation',
                   'lease_expires_at', 'last_renewed_at'
               )
             ORDER BY attname
            """
        )
        attempt_columns = cursor.fetchall()
        cursor.execute(
            """
            SELECT relrowsecurity, relforcerowsecurity,
                   pg_get_userbyid(relowner)
              FROM pg_class
             WHERE oid = 'gah_request_lifecycle'::regclass
            """
        )
        lifecycle_security = cursor.fetchone()
        cursor.execute(
            """
            SELECT rolname, rolcanlogin, rolsuper, rolbypassrls
              FROM pg_roles
             WHERE rolname IN ('gah_authority_writer', 'gah_runtime', 'gah_schema_owner')
             ORDER BY rolname
            """
        )
        roles = cursor.fetchall()
        cursor.execute(
            "SELECT has_table_privilege('gah_runtime', 'gah_request_lifecycle', 'SELECT')"
        )
        runtime_can_select = cursor.fetchone()[0]
    assert attempt_columns == [
        ("execution_attempt_id", True),
        ("last_renewed_at", True),
        ("lease_expires_at", True),
        ("owner_generation", True),
    ]
    assert lifecycle_security == (True, True, "gah_schema_owner")
    assert roles == [
        ("gah_authority_writer", False, False, False),
        ("gah_runtime", False, False, False),
        ("gah_schema_owner", False, False, False),
    ]
    assert runtime_can_select is False


def test_altered_phase4_schema_is_rejected(migration_database: dict[str, object]) -> None:
    connect = migration_database["connect"]
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(discover_migrations()[0].sql)
        cursor.execute("ALTER TABLE gah_run_heads ADD COLUMN forged text")

    with pytest.raises(MigrationError, match="do not exactly match"):
        apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass('gah_schema_migrations')")
        assert cursor.fetchone() == (None,)


def test_partial_legacy_schema_is_rejected(migration_database: dict[str, object]) -> None:
    connect = migration_database["connect"]
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("CREATE TABLE gah_run_heads (tenant_id text)")

    with pytest.raises(MigrationError, match="unsafe bootstrap state"):
        apply_migrations(admin_connect=connect)


def test_checksum_drift_and_unknown_version_are_rejected(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_schema_migrations SET checksum = %s WHERE version = 1",
            ("sha256:" + "0" * 64,),
        )
    with pytest.raises(MigrationError, match="checksum drift"):
        apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_schema_migrations SET checksum = %s WHERE version = 1",
            (discover_migrations()[0].checksum,),
        )
        cursor.execute(
            "INSERT INTO gah_schema_migrations (version, checksum) VALUES (4, %s)",
            ("sha256:" + "1" * 64,),
        )
    with pytest.raises(MigrationError, match="unknown migration version 0004"):
        apply_migrations(admin_connect=connect)


def test_registry_tampering_and_empty_registry_with_legacy_tables_fail_closed(
    migration_database: dict[str, object],
) -> None:
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("ALTER TABLE gah_schema_migrations ADD COLUMN forged text")
    with pytest.raises(MigrationError, match="incompatible column layout"):
        apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("ALTER TABLE gah_schema_migrations DROP COLUMN forged")
        cursor.execute("DELETE FROM gah_schema_migrations")
    with pytest.raises(MigrationError, match="unsafe bootstrap state"):
        apply_migrations(admin_connect=connect)


def test_failed_migration_rolls_back_registry_and_schema(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    broken = Migration(
        version=4,
        name="0004_broken.sql",
        checksum="sha256:" + "2" * 64,
        sql="CREATE TABLE gah_partial (id integer); SELECT definitely_not_a_function()",
    )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: (*packaged, broken))
    connect = migration_database["connect"]

    with pytest.raises(Exception, match="definitely_not_a_function"):
        apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT to_regclass('gah_schema_migrations'), to_regclass('gah_partial'), "
            "to_regclass('gah_run_heads')"
        )
        assert cursor.fetchone() == (None, None, None)


def test_autocommit_connection_is_rejected(migration_database: dict[str, object]) -> None:
    connect = migration_database["connect"]

    def autocommit_connect():
        connection = connect()
        connection.autocommit = True
        return connection

    with pytest.raises(MigrationError, match="must not use autocommit"):
        apply_migrations(admin_connect=autocommit_connect)


def test_installed_wheel_discovers_identical_packaged_migrations(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    build_root = tmp_path / "build-context"
    build_root.mkdir()
    shutil.copy2(root / "pyproject.toml", build_root / "pyproject.toml")
    shutil.copytree(root / "src", build_root / "src")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    environment = os.environ.copy()
    environment.update({"PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(wheelhouse),
            str(build_root),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr
    wheel = next(wheelhouse.glob("governed_agent_harness-*.whl"))
    installed = tmp_path / "installed"
    venv.EnvBuilder(with_pip=True).create(installed)
    python = installed / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr
    expected = [(item.version, item.name, item.checksum) for item in discover_migrations()]
    program = (
        "from governed_agent_harness.persistence.migration import discover_migrations; "
        "print([(m.version, m.name, m.checksum) for m in discover_migrations()])"
    )
    smoke = subprocess.run(
        [str(python), "-I", "-B", "-c", program],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert smoke.returncode == 0, smoke.stderr
    assert smoke.stdout.strip() == repr(expected)
