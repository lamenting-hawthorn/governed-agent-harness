from __future__ import annotations

import os
import json
import shutil
import subprocess
import sys
import venv
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest

from governed_agent_harness.contracts import canonical_bytes, sha256_digest

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
        (4, "0004_read_only_memory_retrieval.sql"),
        (5, "0005_governed_memory_promotion.sql"),
        (6, "0006_governed_skill_lifecycle.sql"),
        (7, "0007_skill_lifecycle_authority_role.sql"),
        (8, "0008_fix_skill_replay_lock_key.sql"),
        (9, "0009_fix_skill_lifecycle_predicates.sql"),
        (10, "0010_skill_lifecycle_authority_split.sql"),
        (11, "0011_builtin_execution_admission.sql"),
        (12, "0012_harden_lifecycle_and_execution_authority.sql"),
        (13, "0013_actor_scoped_skill_keys_and_evidence_reservation.sql"),
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
        cursor.execute(
            "SELECT to_regclass('gah_run_heads'), to_regclass('gah_effect_executions'), "
            "to_regclass('gah_memory_records')"
        )
        tables = cursor.fetchone()
    assert rows == [(item.version, item.checksum, True) for item in first]
    assert second == first
    assert all(table is not None for table in tables)


def test_populated_phase12_lifecycle_state_survives_actor_key_upgrade(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Apply 13 over a real 1--12 lifecycle row, not only an empty schema."""

    import copy
    from datetime import datetime, timedelta, timezone

    import psycopg

    import governed_agent_harness.persistence.migration as migration_module
    from governed_agent_harness.contracts import TrustContext, TrustedKey, apply_object_digest
    from governed_agent_harness.contracts.positive_fixtures import build_positive_records
    from governed_agent_harness.persistence import (
        PostgresActiveSkillResolver,
        PostgresDurableEffectStore,
        PostgresSkillLifecycleAuthority,
    )
    from skill_lifecycle_support import command as build_skill_command, ref

    class AcceptingVerifier:
        def verify(self, **_values: object) -> bool:
            return True

    def receipt_trust(now: datetime) -> TrustContext:
        return TrustContext(
            now=now,
            trusted_keys=(
                TrustedKey(
                    issuer="runtime.authority",
                    key_id="runtime.key.v1",
                    algorithms=frozenset({"fixture-proof-v1"}),
                    valid_from=now - timedelta(days=1),
                    valid_until=now + timedelta(days=1),
                ),
            ),
            allowed_algorithms=frozenset({"fixture-proof-v1"}),
            allowed_proof_domains=frozenset({"activation_receipt.v1"}),
            expected_issuers=frozenset({"runtime.authority"}),
            allowed_domain_issuers=frozenset({("activation_receipt.v1", "runtime.authority")}),
            trust_policy_version="upgrade-path.test.v1",
        )

    def activation_receipt(command):
        receipt = copy.deepcopy(build_positive_records()["activation_receipt"])
        delivery = command["delivery_envelope"]
        proposal = command["skill_proposal"]
        receipt.update(
            {
                "target_scope": copy.deepcopy(delivery["target_scope"]),
                "delivery_id": delivery["delivery_id"],
                "delivery_digest": delivery["envelope_digest"],
                "artifact_type": delivery["artifact_type"],
                "artifact_id": delivery["artifact_id"],
                "artifact_revision": delivery["artifact_revision"],
                "artifact_digest": delivery["artifact_digest"],
                "activated_revision": ref(
                    "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
                ),
                "evidence_refs": copy.deepcopy(delivery["evidence_refs"]),
                "policy_refs": copy.deepcopy(delivery["policy_refs"]),
                "reviewer_refs": copy.deepcopy(delivery["reviewer_refs"]),
            }
        )
        return apply_object_digest(receipt)

    connect = migration_database["connect"]
    packaged = discover_migrations()
    phase12 = tuple(migration for migration in packaged if migration.version <= 12)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase12)

    with connect() as connection:
        parameters = connection.info.get_parameters()
    role_suffix = uuid4().hex[:12]
    app_role = f"gah_upgrade_app_{role_suffix}"
    writer_role = f"gah_upgrade_writer_{role_suffix}"
    skill_role = f"gah_upgrade_skill_{role_suffix}"
    execution_role = f"gah_upgrade_execution_{role_suffix}"
    service_roles = (app_role, writer_role, skill_role, execution_role)
    try:
        with connect() as connection, connection.cursor() as cursor:
            for role in service_roles:
                cursor.execute(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS INHERIT")
        PostgresDurableEffectStore.install_schema(
            admin_connect=connect,
            application_role=app_role,
            authority_role=writer_role,
            skill_lifecycle_authority_role=skill_role,
            execution_admission_authority_role=execution_role,
        )

        actor, command = build_skill_command()
        actor.update(
            {
                "actor_id": "018f0000-0000-7000-8000-0000000000c1",
                "session_id": "018f0000-0000-7000-8000-0000000000d1",
                "correlation_id": "018f0000-0000-7000-8000-0000000000d1",
                "issued_at": "2026-01-01T00:00:01.000Z",
                "expires_at": "2030-01-01T00:00:00.000Z",
            }
        )
        apply_object_digest(actor)
        PostgresDurableEffectStore.provision_principal(
            admin_connect=connect, database_roles=service_roles, actor_context=actor
        )

        def role_connect(role: str):
            return psycopg.connect(**{**parameters, "user": role})

        sequence = 0xE000

        def ids() -> str:
            nonlocal sequence
            sequence += 1
            return f"018f0000-0000-7000-8000-{sequence:012x}"

        local_connections = {
            "admin": connect,
            "app": lambda: role_connect(app_role),
            "writer": lambda: role_connect(writer_role),
            "skill_authority": lambda: role_connect(skill_role),
            "store_at": lambda now: PostgresDurableEffectStore(
                connect=lambda: role_connect(app_role),
                privileged_connect=lambda: role_connect(writer_role),
                clock=lambda: now,
                ids=ids,
            ),
        }
        now = datetime(2026, 1, 1, 0, 12, tzinfo=timezone.utc)
        scope = command["skill_proposal"]["target_scope"]
        scope.update({"actor_id": actor["actor_id"], "parent_digest": sha256_digest(actor)})
        command["gate_decision"]["target_scope"] = copy.deepcopy(scope)
        command["delivery_envelope"]["target_scope"] = copy.deepcopy(scope)
        source = local_connections["store_at"](now).append(
            tenant_id=actor["tenant_id"],
            run_id="018f0000-0000-7000-8000-0000000000df",
            event_kind="kernel.policy_decided",
            policy_ref={
                "record_type": "policy_decision",
                "record_id": command["policy_decision"]["decision_id"],
                "record_digest": command["policy_decision"]["decision_digest"],
            },
            payload={
                "actor_id": actor["actor_id"],
                "policy_decision_digest": command["policy_decision"]["decision_digest"],
            },
        )
        source_ref = ref("evidence_envelope", source["envelope_id"], source["event_digest"])
        command["source_evidence"] = [source]
        proposal = command["skill_proposal"]
        proposal["evidence_refs"] = [source_ref]
        apply_object_digest(proposal)
        policy = command["policy_decision"]
        policy["request_digest"] = proposal["proposal_digest"]
        apply_object_digest(policy)
        gate = command["gate_decision"]
        gate["proposal_refs"] = [
            ref("skill_proposal", proposal["proposal_id"], proposal["proposal_digest"])
        ]
        apply_object_digest(gate)
        delivery = command["delivery_envelope"]
        delivery.update(
            {
                "evidence_refs": [source_ref],
                "policy_refs": [
                    ref("policy_decision", policy["decision_id"], policy["decision_digest"])
                ],
                "gate_decision_ref": ref("gate_decision", gate["gate_id"], gate["decision_digest"]),
            }
        )
        apply_object_digest(delivery)

        authority = PostgresSkillLifecycleAuthority(
            privileged_connect=local_connections["skill_authority"],
            evidence_writer_connect=local_connections["writer"],
            clock=lambda: datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc),
            ids=ids,
            receipt_verifier=AcceptingVerifier(),
            receipt_trust=receipt_trust,
        )
        installed = authority.install_skill(actor_context=actor, **command)
        activate = copy.deepcopy(command)
        activate.update(
            {
                "operation_id": "upgrade-existing-activation",
                "expected_revision": 1,
                "activation_receipt": activation_receipt(command),
            }
        )
        active = authority.activate_skill(actor_context=actor, **activate)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*), min(evidence_event_digest) FROM gah_skill_lifecycle_transitions"
            )
            transitions_before = cursor.fetchone()
            cursor.execute("SELECT count(*), min(event_digest) FROM gah_evidence_events")
            evidence_before = cursor.fetchone()

        monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
        applied = apply_migrations(admin_connect=connect)
        assert applied[-1].version == 13
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*), min(evidence_event_digest) FROM gah_skill_lifecycle_transitions"
            )
            assert cursor.fetchone() == transitions_before
            cursor.execute("SELECT count(*), min(event_digest) FROM gah_evidence_events")
            assert cursor.fetchone() == evidence_before
            cursor.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname='gah_active_skill_projection_actor_pkey'"
            )
            assert cursor.fetchone()[0] == "PRIMARY KEY (tenant_id, actor_id, skill_id)"

        replay = authority.activate_skill(actor_context=actor, **activate)
        assert replay.replayed is True
        assert replay.transition_digest == active.transition_digest
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*), min(evidence_event_digest) FROM gah_skill_lifecycle_transitions"
            )
            assert cursor.fetchone() == transitions_before
            cursor.execute("SELECT count(*), min(event_digest) FROM gah_evidence_events")
            assert cursor.fetchone() == evidence_before
        resolved = PostgresActiveSkillResolver(
            runtime_connect=lambda: role_connect(app_role)
        ).resolve_active_skill(actor_context=actor, skill_id=installed.skill_id)
        assert resolved is not None
        assert resolved.artifact_digest == active.artifact_digest
    finally:
        with connect() as connection, connection.cursor() as cursor:
            for role in service_roles:
                cursor.execute(f"DROP ROLE IF EXISTS {role}")


def test_phase44_registered_schema_upgrades_once_to_execution_admission(
    migration_database: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import governed_agent_harness.persistence.migration as migration_module

    connect = migration_database["connect"]
    assert callable(connect)
    packaged = discover_migrations()
    phase44 = packaged[:10]
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase44)
    assert apply_migrations(admin_connect=connect) == phase44
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)

    first_upgrade = apply_migrations(admin_connect=connect)
    second_upgrade = apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT version, checksum FROM gah_schema_migrations ORDER BY version")
        migrations = cursor.fetchall()
        cursor.execute(
            "SELECT to_regclass('gah_builtin_execution_state'), "
            "to_regprocedure("
            "'gah_issue_builtin_execution_authorization(jsonb,jsonb,jsonb,jsonb,jsonb)'"
            ") IS NOT NULL"
        )
        installed = cursor.fetchone()
    assert first_upgrade == second_upgrade == packaged
    assert migrations == [(item.version, item.checksum) for item in packaged]
    assert installed == ("gah_builtin_execution_state", True)


@pytest.mark.parametrize(
    ("replacement", "match"),
    (
        (
            ("gah_ed25519", "gah_ed25519_missing_test_artifact"),
            "gah_ed25519_missing_test_artifact",
        ),
        (
            ("extension_row.extversion <> '1.0'", "extension_row.extversion <> '9.9'"),
            "gah_ed25519 extension identity is unavailable or unsafe",
        ),
    ),
)
def test_execution_native_extension_identity_gate_rolls_back_on_missing_or_wrong_artifact(
    migration_database: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    replacement: tuple[str, str],
    match: str,
) -> None:
    """Harness-only SQL variants prove the native identity gate is transactional.

    No installed extension files or PostgreSQL catalogs are changed: this test
    substitutes only the in-memory migration payload before `apply_migrations`.
    """

    import governed_agent_harness.persistence.migration as migration_module

    connect = migration_database["connect"]
    assert callable(connect)
    packaged = discover_migrations()
    phase44 = packaged[:10]
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase44)
    assert apply_migrations(admin_connect=connect) == phase44

    candidate = packaged[10]
    original, changed = replacement
    modified_sql = candidate.sql.replace(original, changed)
    assert modified_sql != candidate.sql
    modified = Migration(
        version=candidate.version,
        name=candidate.name,
        checksum=candidate.checksum,
        sql=modified_sql,
    )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: (*phase44, modified))

    with pytest.raises(Exception, match=match):
        apply_migrations(admin_connect=connect)

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT version FROM gah_schema_migrations ORDER BY version")
        applied_versions = cursor.fetchall()
        cursor.execute(
            "SELECT to_regclass('gah_builtin_execution_state'), "
            "to_regprocedure('gah_rebuild_builtin_execution(jsonb,jsonb)'), "
            "to_regnamespace('gah_crypto')"
        )
        leftovers = cursor.fetchone()
    assert applied_versions == [(item.version,) for item in phase44]
    assert leftovers == (None, None, None)


@pytest.mark.parametrize(
    "value",
    (
        None,
        True,
        False,
        [None, True, False, -9007199254740991, 9007199254740991],
        {"text": 'quote=" slash=\\ control=\b\t\n'},
        {"\U0001f600": "astral-first-in-utf16", "\ue000": "bmp-second-in-utf16"},
    ),
)
def test_sql_canonical_digest_matches_python_contract(
    migration_database: dict[str, object], value: object
) -> None:
    connect = migration_database["connect"]
    assert callable(connect)
    apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT gah_canonical_json(%s::jsonb), gah_canonical_sha256(%s::jsonb)",
            (json.dumps(value, ensure_ascii=False), json.dumps(value, ensure_ascii=False)),
        )
        canonical, digest = cursor.fetchone()
    assert canonical == canonical_bytes(value).decode("utf-8")
    assert digest == sha256_digest(value)


@pytest.mark.parametrize(
    "value",
    (1.5, 9007199254740992, -9007199254740992, "\ufffd", {"\ufffd": "forbidden"}),
)
def test_sql_canonical_digest_rejects_values_outside_contract_domain(
    migration_database: dict[str, object], value: object
) -> None:
    connect = migration_database["connect"]
    assert callable(connect)
    apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception):
            cursor.execute("SELECT gah_canonical_sha256(%s::jsonb)", (json.dumps(value),))


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
    assert rows == [
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 1),
        (5, 1),
        (6, 1),
        (7, 1),
        (8, 1),
        (9, 1),
        (10, 1),
        (11, 1),
        (12, 1),
        (13, 1),
    ]


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
        cursor.execute(
            "SELECT relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner), "
            "has_table_privilege('gah_runtime', 'gah_memory_records', 'SELECT'), "
            "has_function_privilege('gah_runtime', 'gah_retrieve_memory(jsonb,jsonb)', 'EXECUTE') "
            "FROM pg_class WHERE oid = 'gah_memory_records'::regclass"
        )
        memory_security = cursor.fetchone()
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
    assert memory_security == (True, True, "gah_schema_owner", False, True)


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
            "INSERT INTO gah_schema_migrations (version, checksum) VALUES (14, %s)",
            ("sha256:" + "1" * 64,),
        )
    with pytest.raises(MigrationError, match="unknown migration version 0014"):
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
        version=14,
        name="0014_broken.sql",
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
