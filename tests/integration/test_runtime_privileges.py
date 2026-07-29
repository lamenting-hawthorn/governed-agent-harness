from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

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
    "gah_memory_records",
    "gah_memory_transitions",
)


def test_runtime_and_owner_roles_are_least_privilege(postgres_connections):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolinherit, rolreplication, rolbypassrls FROM pg_roles "
            "WHERE rolname IN ('gah_authority_writer', 'gah_schema_owner', 'gah_runtime', "
            "'gah_skill_lifecycle_authority') "
            "ORDER BY rolname"
        )
        assert cursor.fetchall() == [
            ("gah_authority_writer", False, False, False, False, False, False, False),
            ("gah_runtime", False, False, False, False, False, False, False),
            ("gah_schema_owner", False, False, False, False, False, False, False),
            ("gah_skill_lifecycle_authority", False, False, False, False, False, False, False),
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
            "has_function_privilege('gah_app', 'gah_retrieve_memory(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_app', 'gah_submit_lifecycle(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', 'gah_submit_lifecycle(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', 'gah_retrieve_memory(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('public', 'gah_retrieve_memory(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('public', 'gah_submit_lifecycle(jsonb,jsonb)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (True, True, False, True, False, False, False)
        cursor.execute(
            "SELECT has_function_privilege('gah_app', "
            "'gah_authority_write_internal(text,jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_authority_write_internal(text,jsonb,jsonb)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (False, False)
        cursor.execute(
            "SELECT "
            "has_function_privilege('gah_app', "
            "'gah_commit_memory_transition(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_app', "
            "'gah_rebuild_memory_projection(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_commit_memory_transition(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_rebuild_memory_projection(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('public', "
            "'gah_commit_memory_transition(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_skill_authority', "
            "'gah_install_skill(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_install_skill(jsonb,jsonb)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (False, False, True, True, False, True, False)


def test_evidence_and_skill_lifecycle_credentials_are_capability_separated(postgres_connections):
    lifecycle_functions = (
        "gah_skill_lifecycle_evidence_head(jsonb)",
        "gah_lookup_skill_replay(jsonb,jsonb)",
        "gah_install_skill(jsonb,jsonb)",
        "gah_activate_skill(jsonb,jsonb)",
        "gah_rollback_skill(jsonb,jsonb)",
        "gah_deactivate_skill(jsonb,jsonb)",
        "gah_rebuild_skill_projection(jsonb,jsonb)",
        "gah_rebuild_skill_projection_validated(jsonb,jsonb)",
        "gah_apply_skill_lifecycle(jsonb,jsonb,text)",
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_has_role('gah_skill_authority', 'gah_authority_writer', 'MEMBER'), "
            "pg_has_role('gah_skill_authority', 'gah_skill_lifecycle_authority', 'MEMBER'), "
            "pg_has_role('gah_writer', 'gah_authority_writer', 'MEMBER'), "
            "pg_has_role('gah_writer', 'gah_skill_lifecycle_authority', 'MEMBER')"
        )
        assert cursor.fetchone() == (False, True, True, False)
        cursor.execute(
            "SELECT has_function_privilege('gah_skill_authority', "
            "'gah_commit_evidence(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_skill_authority', "
            "'gah_authority_write_internal(text,jsonb,jsonb)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (False, False)
        cursor.execute(
            "SELECT has_function_privilege('gah_skill_authority', "
            "'gah_rebuild_skill_projection_validated(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_skill_authority', "
            "'gah_skill_authorization_lock_keys(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_skill_authority', "
            "'gah_skill_authorization_ordered_locks(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_skill_authority', "
            "'gah_authorize_skill_lifecycle(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_skill_authority', "
            "'gah_skill_assert_writer_authorization(jsonb,jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_authorize_skill_lifecycle(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_skill_assert_writer_authorization(jsonb,jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', "
            "'gah_skill_authorization_lock_keys(jsonb,jsonb)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (False, False, False, False, False, True, False, False)
        for function in lifecycle_functions:
            cursor.execute(
                "SELECT has_function_privilege('gah_writer', %s, 'EXECUTE'), "
                "has_function_privilege('gah_runtime', %s, 'EXECUTE')",
                (function, function),
            )
            assert cursor.fetchone() == (False, False)


def test_writer_cannot_set_role_to_lifecycle_authority(postgres_connections):
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute("SET ROLE gah_skill_lifecycle_authority")
        connection.rollback()


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


def test_installer_rejects_sequential_lifecycle_role_reuse_without_new_grants(
    postgres_connections,
):
    roles = ("gah_sequential_lifecycle_authority", "gah_sequential_lifecycle_application")
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        for role in roles:
            cursor.execute(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS INHERIT")
    try:
        for role, keyword, target_group in (
            (roles[0], "authority_role", "gah_authority_writer"),
            (roles[1], "application_role", "gah_runtime"),
        ):
            PostgresDurableEffectStore.install_schema(
                admin_connect=postgres_connections["admin"],
                skill_lifecycle_authority_role=role,
            )
            with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT (SELECT count(*) FROM pg_auth_members), "
                    "(SELECT count(*) FROM gah_schema_migrations)"
                )
                before_memberships, before_migrations = cursor.fetchone()
            with pytest.raises(DurableStoreError, match="unsafe membership path"):
                PostgresDurableEffectStore.install_schema(
                    admin_connect=postgres_connections["admin"], **{keyword: role}
                )
            with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_has_role(%s, 'gah_skill_lifecycle_authority', 'MEMBER'), "
                    "pg_has_role(%s, %s, 'MEMBER'), "
                    "(SELECT count(*) FROM pg_auth_members), "
                    "(SELECT count(*) FROM gah_schema_migrations)",
                    (role, role, target_group),
                )
                assert cursor.fetchone() == (
                    True,
                    False,
                    before_memberships,
                    before_migrations,
                )
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            for role in roles:
                cursor.execute(f"REVOKE gah_skill_lifecycle_authority FROM {role}")
                cursor.execute(f"DROP ROLE {role}")


def test_installer_serializes_opposing_authority_role_grants(postgres_connections):
    role = "gah_concurrent_authority_lifecycle"
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS INHERIT")
    barrier = Barrier(3)

    def install_as(keyword):
        barrier.wait(timeout=5)
        try:
            PostgresDurableEffectStore.install_schema(
                admin_connect=postgres_connections["admin"], **{keyword: role}
            )
        except DurableStoreError as error:
            assert "unsafe membership path" in str(error)
            return "rejected"
        return "granted"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(install_as, "authority_role"),
                pool.submit(install_as, "skill_lifecycle_authority_role"),
            )
            barrier.wait(timeout=5)
            outcomes = tuple(future.result(timeout=10) for future in futures)
        assert sorted(outcomes) == ["granted", "rejected"]
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_has_role(%s, 'gah_authority_writer', 'MEMBER'), "
                "pg_has_role(%s, 'gah_skill_lifecycle_authority', 'MEMBER'), "
                "(SELECT count(*) FROM pg_auth_members membership "
                "JOIN pg_roles member ON member.oid = membership.member "
                "JOIN pg_roles group_role ON group_role.oid = membership.roleid "
                "WHERE member.rolname = %s AND group_role.rolname IN "
                "('gah_authority_writer', 'gah_skill_lifecycle_authority'))",
                (role, role, role),
            )
            writer_member, lifecycle_member, membership_count = cursor.fetchone()
        assert writer_member != lifecycle_member
        assert membership_count == 1
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(f"REVOKE gah_authority_writer FROM {role}")
            cursor.execute(f"REVOKE gah_skill_lifecycle_authority FROM {role}")
            cursor.execute(f"DROP ROLE {role}")


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
            "SELECT * FROM gah_memory_records",
            "SELECT * FROM gah_memory_transitions",
            "INSERT INTO gah_memory_records (tenant_id, actor_id, memory_id, revision, "
            "record_digest, record_json, scope_json, proposition_json, observed_at, "
            "effective_from, lifecycle_state) VALUES ('x','x','x',1,'sha256:x','{}','{}','{}',"
            "clock_timestamp(),clock_timestamp(),'active')",
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
            with pytest.raises(Exception, match="outside actor scope"):
                cursor.execute(
                    "SELECT gah_retrieve_memory(%s::jsonb, "
                    '\'{"record_type":"memory_query"}\'::jsonb)',
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
            "gah_commit_memory_transition",
            "gah_rebuild_memory_projection",
        ):
            with pytest.raises(Exception, match="permission denied"):
                cursor.execute(
                    f"SELECT {function_name}(%s::jsonb, '{{}}'::jsonb)",
                    (json.dumps(actor),),
                )
            connection.rollback()
