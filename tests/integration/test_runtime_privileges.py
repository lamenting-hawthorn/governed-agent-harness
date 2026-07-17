from __future__ import annotations

import copy
import json

import pytest

from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.persistence import DurableStoreError, PostgresDurableEffectStore


TABLES = (
    "gah_schema_migrations",
    "gah_runtime_principals",
    "gah_run_heads",
    "gah_evidence_events",
    "gah_request_lifecycle",
    "gah_effect_executions",
    "gah_grant_consumptions",
)


def test_runtime_and_owner_roles_are_least_privilege(postgres_connections):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolinherit, rolreplication, rolbypassrls FROM pg_roles "
            "WHERE rolname IN ('gah_authority_writer', 'gah_schema_owner', 'gah_runtime') "
            "ORDER BY rolname"
        )
        assert cursor.fetchall() == [
            ("gah_authority_writer", False, False, False, False, False, False, False),
            ("gah_runtime", False, False, False, False, False, False, False),
            ("gah_schema_owner", False, False, False, False, False, False, False),
        ]
        for table in TABLES:
            for role in ("gah_app", "gah_writer"):
                cursor.execute(
                    "SELECT has_table_privilege(%s, %s, 'SELECT'), "
                    "has_table_privilege(%s, %s, 'INSERT,UPDATE,DELETE')",
                    (role, table, role, table),
                )
                assert cursor.fetchone() == (False, False)
        cursor.execute(
            "SELECT has_function_privilege('gah_app', "
            "'gah_runtime_read(text,jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_app', 'gah_submit_lifecycle(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', 'gah_submit_lifecycle(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('public', 'gah_submit_lifecycle(jsonb,jsonb)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (True, False, True, False)
        cursor.execute(
            "SELECT has_function_privilege('gah_app', "
            "'gah_authority_write_internal(text,jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_authority_write_internal(text,jsonb,jsonb)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (False, False)


def test_installer_rejects_collapsed_runtime_and_authority_role(postgres_connections):
    with pytest.raises(DurableStoreError, match="must be distinct"):
        PostgresDurableEffectStore.install_schema(
            admin_connect=postgres_connections["admin"],
            application_role="gah_app",
            authority_role="gah_app",
        )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT pg_has_role('gah_app', 'gah_authority_writer', 'MEMBER')")
        assert cursor.fetchone()[0] is False


def test_installer_rejects_reserved_unsafe_and_nested_service_roles(postgres_connections):
    with pytest.raises(DurableStoreError, match="reserved"):
        PostgresDurableEffectStore.install_schema(
            admin_connect=postgres_connections["admin"],
            application_role="gah_app",
            authority_role="gah_runtime",
        )

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("CREATE ROLE gah_unsafe NOLOGIN NOSUPERUSER NOBYPASSRLS")
        cursor.execute("CREATE ROLE gah_nested_runtime LOGIN NOSUPERUSER NOBYPASSRLS")
        cursor.execute("CREATE ROLE gah_nested_authority LOGIN NOSUPERUSER NOBYPASSRLS")
        cursor.execute("GRANT gah_nested_authority TO gah_nested_runtime")
    try:
        with pytest.raises(DurableStoreError, match="unsafe attributes"):
            PostgresDurableEffectStore.install_schema(
                admin_connect=postgres_connections["admin"],
                application_role="gah_unsafe",
            )
        with pytest.raises(DurableStoreError, match="unsafe membership path"):
            PostgresDurableEffectStore.install_schema(
                admin_connect=postgres_connections["admin"],
                application_role="gah_nested_runtime",
                authority_role="gah_nested_authority",
            )
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute("GRANT gah_schema_owner TO gah_nested_authority")
        with pytest.raises(DurableStoreError, match="unsafe membership path"):
            PostgresDurableEffectStore.install_schema(
                admin_connect=postgres_connections["admin"],
                authority_role="gah_nested_authority",
            )
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_has_role('gah_nested_runtime', 'gah_runtime', 'MEMBER'), "
                "pg_has_role('gah_nested_authority', 'gah_authority_writer', 'MEMBER')"
            )
            assert cursor.fetchone() == (False, False)
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute("REVOKE gah_schema_owner FROM gah_nested_authority")
            cursor.execute("REVOKE gah_nested_authority FROM gah_nested_runtime")
            cursor.execute("DROP ROLE gah_nested_runtime")
            cursor.execute("DROP ROLE gah_nested_authority")
            cursor.execute("DROP ROLE gah_unsafe")


def test_runtime_cannot_use_direct_sql_migrations_or_ungranted_functions(
    postgres_connections,
):
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        for statement in (
            "SELECT * FROM gah_request_lifecycle",
            "INSERT INTO gah_run_heads (tenant_id, actor_id, run_id) VALUES ('x','x','x')",
            "UPDATE gah_effect_executions SET state = 'completed'",
            "DELETE FROM gah_evidence_events",
            "UPDATE gah_schema_migrations SET checksum = 'sha256:' || repeat('0',64)",
            "ALTER TABLE gah_request_lifecycle ADD COLUMN forged text",
            "SELECT pg_read_file('postgresql.conf')",
        ):
            with pytest.raises(Exception):
                cursor.execute(statement)
            connection.rollback()


def test_runtime_function_scope_cannot_forge_tenant_actor_or_authority(postgres_connections):
    actor = build_positive_records()["actor_context"]
    forged_tenant = copy.deepcopy(actor)
    forged_tenant["tenant_id"] = "018f0000-0000-7000-8000-000000000099"
    forged_actor = copy.deepcopy(actor)
    forged_actor["actor_id"] = "018f0000-0000-7000-8000-000000000099"

    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        for forged in (forged_tenant, forged_actor):
            with pytest.raises(Exception, match="outside actor scope"):
                cursor.execute(
                    "SELECT gah_runtime_read('events', %s::jsonb, '{}'::jsonb)",
                    (json.dumps(forged),),
                )
            connection.rollback()
        for function_name in (
            "gah_lock_run",
            "gah_commit_evidence",
            "gah_submit_lifecycle",
            "gah_accept_approval",
            "gah_issue_grant",
            "gah_rebuild_lifecycle",
            "gah_prepare_effect",
            "gah_renew_effect",
            "gah_complete_effect",
            "gah_recover_effect",
        ):
            with pytest.raises(Exception, match="permission denied"):
                cursor.execute(
                    f"SELECT {function_name}(%s::jsonb, '{{}}'::jsonb)",
                    (json.dumps(actor),),
                )
            connection.rollback()
