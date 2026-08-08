from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
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
        (14, "0014_serialize_lifecycle_evidence_drafts.sql"),
        (15, "0015_verify_lifecycle_receipts_and_harden_execution.sql"),
        (16, "0016_actor_scope_execution_and_verify_lifecycle_approvals.sql"),
        (17, "0017_validate_lifecycle_actor_and_policy_bounds.sql"),
        (18, "0018_governed_github_markdown_knowledge.sql"),
        (19, "0019_local_readonly_mcp_resources.sql"),
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


def test_phase19_upgrade_preserves_knowledge_boundary_and_adds_runtime_mcp_reads(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Upgrade a real phase-18 database and fingerprint the L1 read boundary."""

    import governed_agent_harness.persistence.migration as migration_module

    connect = migration_database["connect"]
    assert callable(connect)
    packaged = discover_migrations()
    phase18 = tuple(migration for migration in packaged if migration.version <= 18)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase18)
    assert apply_migrations(admin_connect=connect) == phase18

    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    assert apply_migrations(admin_connect=connect)[-1].version == 19
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner) "
            "FROM pg_class WHERE relname IN "
            "('gah_github_markdown_sources', 'gah_github_markdown_revisions', "
            "'gah_github_markdown_operations') "
            "ORDER BY relname"
        )
        assert cursor.fetchall() == [
            ("gah_github_markdown_operations", True, True, "gah_schema_owner"),
            ("gah_github_markdown_revisions", True, True, "gah_schema_owner"),
            ("gah_github_markdown_sources", True, True, "gah_schema_owner"),
        ]
        cursor.execute(
            "SELECT "
            "has_table_privilege('gah_runtime', 'public.gah_github_markdown_sources', 'select'), "
            "has_table_privilege('gah_authority_writer', 'public.gah_github_markdown_sources', 'select'), "
            "has_table_privilege('gah_runtime', 'public.gah_github_markdown_revisions', 'select'), "
            "has_table_privilege('gah_authority_writer', 'public.gah_github_markdown_revisions', 'select'), "
            "has_table_privilege('gah_runtime', 'public.gah_github_markdown_operations', 'select'), "
            "has_table_privilege('gah_authority_writer', 'public.gah_github_markdown_operations', 'select')"
        )
        assert cursor.fetchone() == (False, False, False, False, False, False)
        cursor.execute(
            "SELECT "
            "has_function_privilege('gah_runtime', "
            "'public.gah_import_github_markdown(jsonb,jsonb,jsonb)', 'execute'), "
            "has_function_privilege('gah_authority_writer', "
            "'public.gah_import_github_markdown(jsonb,jsonb,jsonb)', 'execute'), "
            "has_function_privilege('gah_authority_writer', "
            "'public.gah_github_markdown_reserve_operation(jsonb,text,text,text,text)', 'execute'), "
            "has_function_privilege('gah_runtime', "
            "'public.gah_retrieve_github_markdown(jsonb,text,integer)', 'execute'), "
            "has_function_privilege('gah_runtime', "
            "'public.gah_mcp_assert_local_actor(jsonb,text)', 'execute'), "
            "has_function_privilege('gah_runtime', "
            "'public.gah_list_github_markdown_mcp_resources(jsonb,text,timestamptz,text,text,integer)', 'execute'), "
            "has_function_privilege('gah_runtime', "
            "'public.gah_read_github_markdown_mcp_resource(jsonb,text,text)', 'execute'), "
            "has_function_privilege('gah_authority_writer', "
            "'public.gah_read_github_markdown_mcp_resource(jsonb,text,text)', 'execute')"
        )
        assert cursor.fetchone() == (False, True, False, True, True, True, True, False)
    assert apply_migrations(admin_connect=connect)[-1].version == 19


@pytest.mark.parametrize(
    "upgrade_case",
    (
        "valid",
        "future_authorize",
        "unsupported_constraints",
        "legacy_pre_policy",
        "expired_receipt",
        "expired_approval",
    ),
)
def test_populated_phase12_lifecycle_state_survives_actor_key_upgrade(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch, upgrade_case: str
) -> None:
    """Apply 13 over a real 1--12 lifecycle row, not only an empty schema."""

    import copy
    import dataclasses
    import base64
    from datetime import datetime, timezone
    from hashlib import sha256

    import psycopg
    from nacl.signing import SigningKey

    import governed_agent_harness.persistence.migration as migration_module
    from governed_agent_harness.contracts import (
        TrustContext,
        TrustedKey,
        apply_object_digest,
        verify_runtime_receipt,
    )
    from governed_agent_harness.contracts.positive_fixtures import build_positive_records
    from governed_agent_harness.persistence import (
        PostgresActiveSkillResolver,
        PostgresDurableEffectStore,
        PostgresSkillLifecycleAuthority,
    )
    from skill_lifecycle_support import command as build_skill_command, ref

    signing_key = SigningKey(
        bytes.fromhex("2f4b0b6f0906b7c5e3f0a25e7c5c9ddbcf8d175b75a5a09b2a1dc38841f47c72")
    )
    algorithm = "ed25519-rfc8032-gah-cjson-v1"

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
                    algorithms=frozenset({algorithm}),
                    valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
                    valid_until=(
                        datetime(2026, 1, 2, tzinfo=timezone.utc)
                        if upgrade_case == "expired_receipt"
                        else datetime(2030, 1, 1, tzinfo=timezone.utc)
                    ),
                ),
            ),
            allowed_algorithms=frozenset({algorithm}),
            allowed_proof_domains=frozenset({"activation_receipt.v1", "rollback_receipt.v1"}),
            expected_issuers=frozenset({"runtime.authority"}),
            allowed_domain_issuers=frozenset(
                {
                    ("activation_receipt.v1", "runtime.authority"),
                    ("rollback_receipt.v1", "runtime.authority"),
                }
            ),
            trust_policy_version="upgrade-path.test.v1",
        )

    def activation_receipt(command):
        receipt = copy.deepcopy(build_positive_records()["activation_receipt"])
        delivery = command["delivery_envelope"]
        proposal = command["skill_proposal"]
        receipt.update(
            {
                "expires_at": (
                    "2026-01-02T00:00:00.000Z"
                    if upgrade_case == "expired_receipt"
                    else "2030-01-01T00:00:00.000Z"
                ),
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
        apply_object_digest(receipt)
        unsigned = copy.deepcopy(receipt)
        unsigned.pop("proof", None)
        unsigned.pop("receipt_digest", None)
        object_digest = sha256_digest(unsigned)
        proof = {
            "issuer": "runtime.authority",
            "key_id": "runtime.key.v1",
            "algorithm": algorithm,
            "proof_domain": "activation_receipt.v1",
            "object_digest": object_digest,
            "nonce": "U" * 22,
        }
        frame = canonical_bytes(
            {
                "protocol": "gah.detached-proof.v1",
                **proof,
                "unsigned_record": unsigned,
            }
        )
        proof["detached_proof"] = (
            base64.urlsafe_b64encode(signing_key.sign(frame).signature).rstrip(b"=").decode("ascii")
        )
        receipt["receipt_digest"] = object_digest
        receipt["proof"] = proof
        return receipt

    def rollback_receipt(command, activation):
        receipt = copy.deepcopy(build_positive_records()["rollback_receipt"])
        delivery = command["delivery_envelope"]
        proposal = command["skill_proposal"]
        receipt.update(
            {
                "expires_at": (
                    "2026-01-02T00:00:00.000Z"
                    if upgrade_case == "expired_receipt"
                    else "2030-01-01T00:00:00.000Z"
                ),
                "target_scope": copy.deepcopy(activation["target_scope"]),
                "activation_receipt_ref": ref(
                    "activation_receipt", activation["receipt_id"], activation["receipt_digest"]
                ),
                "artifact_type": delivery["artifact_type"],
                "artifact_id": delivery["artifact_id"],
                "artifact_revision": delivery["artifact_revision"],
                "artifact_digest": delivery["artifact_digest"],
                "rollback_revision": ref(
                    "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
                ),
                "restored_revision_ref": ref(
                    "skill_proposal", proposal["artifact_id"], delivery["artifact_digest"]
                ),
                "evidence_refs": copy.deepcopy(delivery["evidence_refs"]),
                "policy_refs": copy.deepcopy(delivery["policy_refs"]),
                "reviewer_refs": copy.deepcopy(delivery["reviewer_refs"]),
            }
        )
        apply_object_digest(receipt)
        unsigned = copy.deepcopy(receipt)
        unsigned.pop("proof", None)
        unsigned.pop("receipt_digest", None)
        object_digest = sha256_digest(unsigned)
        proof = {
            "issuer": "runtime.authority",
            "key_id": "runtime.key.v1",
            "algorithm": algorithm,
            "proof_domain": "rollback_receipt.v1",
            "object_digest": object_digest,
            "nonce": "R" * 22,
        }
        frame = canonical_bytes(
            {
                "protocol": "gah.detached-proof.v1",
                **proof,
                "unsigned_record": unsigned,
            }
        )
        proof["detached_proof"] = (
            base64.urlsafe_b64encode(signing_key.sign(frame).signature).rstrip(b"=").decode("ascii")
        )
        receipt["receipt_digest"] = object_digest
        receipt["proof"] = proof
        return receipt

    def policy_approval(approval):
        unsigned = copy.deepcopy(approval)
        unsigned.pop("proof", None)
        unsigned.pop("approval_digest", None)
        digest = sha256_digest(unsigned)
        proof = {
            "issuer": "policy.authority",
            "key_id": "policy.key.v1",
            "algorithm": algorithm,
            "proof_domain": "approval_record.v1",
            "object_digest": digest,
            "nonce": "P" * 22,
        }
        frame = canonical_bytes(
            {"protocol": "gah.detached-proof.v1", **proof, "unsigned_record": unsigned}
        )
        proof["detached_proof"] = (
            base64.urlsafe_b64encode(signing_key.sign(frame).signature).rstrip(b"=").decode("ascii")
        )
        approval["approval_digest"] = digest
        approval["proof"] = proof
        return approval

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
        public_key = signing_key.verify_key.encode()
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO gah_execution_proof_keys ("
                "issuer,key_id,algorithm,proof_domain,public_key,"
                "public_key_fingerprint,trust_policy_version,trust_policy_digest,"
                "valid_from,valid_until) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz)",
                (
                    "runtime.authority",
                    "runtime.key.v1",
                    algorithm,
                    "activation_receipt.v1",
                    public_key,
                    "sha256:" + sha256(public_key).hexdigest(),
                    "upgrade-path.test.v1",
                    "sha256:" + "1" * 64,
                    "2020-01-01T00:00:00.000Z",
                    (
                        "2026-01-02T00:00:00.000Z"
                        if upgrade_case == "expired_receipt"
                        else "2030-01-01T00:00:00.000Z"
                    ),
                ),
            )
            cursor.execute(
                "INSERT INTO gah_execution_proof_keys ("
                "issuer,key_id,algorithm,proof_domain,public_key,"
                "public_key_fingerprint,trust_policy_version,trust_policy_digest,"
                "valid_from,valid_until) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz)",
                (
                    "runtime.authority",
                    "runtime.key.v1",
                    algorithm,
                    "rollback_receipt.v1",
                    public_key,
                    "sha256:" + sha256(public_key).hexdigest(),
                    "upgrade-path.test.v1",
                    "sha256:" + "1" * 64,
                    "2020-01-01T00:00:00.000Z",
                    (
                        "2026-01-02T00:00:00.000Z"
                        if upgrade_case == "expired_receipt"
                        else "2030-01-01T00:00:00.000Z"
                    ),
                ),
            )
            if upgrade_case in {"legacy_pre_policy", "expired_approval"}:
                cursor.execute(
                    "INSERT INTO gah_execution_proof_keys (issuer,key_id,algorithm,proof_domain,"
                    "public_key,public_key_fingerprint,trust_policy_version,trust_policy_digest,"
                    "valid_from,valid_until) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz)",
                    (
                        "policy.authority",
                        "policy.key.v1",
                        algorithm,
                        "approval_record.v1",
                        public_key,
                        "sha256:" + sha256(public_key).hexdigest(),
                        "upgrade-path.test.v1",
                        "sha256:" + "2" * 64,
                        "2020-01-01T00:00:00.000Z",
                        (
                            "2026-01-02T00:00:00.000Z"
                            if upgrade_case == "expired_approval"
                            else "2030-01-01T00:00:00.000Z"
                        ),
                    ),
                )
        # Seed real Phase 12 state through the then-current lifecycle path.
        # The current Python port calls the Phase 14 draft-lock helper, which
        # did not exist in that historical schema.  This test-only no-op is
        # removed before the genuine 13/14 upgrade; it cannot mask either
        # migration's DDL or data-upgrade behavior.
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "CREATE FUNCTION gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb) "
                "RETURNS jsonb LANGUAGE sql AS 'SELECT NULL::jsonb'"
            )
            cursor.execute(
                "REVOKE ALL ON FUNCTION gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb) "
                "FROM PUBLIC"
            )
            cursor.execute(
                f"GRANT EXECUTE ON FUNCTION gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb) TO {skill_role}"
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
        if upgrade_case in {"legacy_pre_policy", "expired_approval"}:
            policy["decision"] = "require_approval"
            policy["decided_at"] = "2026-01-01T00:00:00.000Z"
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
        if upgrade_case in {"legacy_pre_policy", "expired_approval"}:
            approval = copy.deepcopy(build_positive_records()["approval_record"])
            approval.update(
                {
                    "tenant_id": actor["tenant_id"],
                    "request_id": proposal["proposal_id"],
                    "request_digest": proposal["proposal_digest"],
                    "policy_decision_id": policy["decision_id"],
                    "policy_decision_digest": policy["decision_digest"],
                    "constraints": copy.deepcopy(policy["constraints"]),
                    "issued_at": "2026-01-01T00:10:00.000Z",
                    "expires_at": (
                        "2026-01-02T00:00:00.000Z"
                        if upgrade_case == "expired_approval"
                        else "2030-01-01T00:00:00.000Z"
                    ),
                }
            )
            approval = policy_approval(approval)
            command["approvals"] = [approval]
            delivery["reviewer_refs"] = [
                ref("approval_record", approval["approval_id"], approval["approval_digest"])
            ]
            apply_object_digest(delivery)

        authority = PostgresSkillLifecycleAuthority(
            privileged_connect=local_connections["skill_authority"],
            evidence_writer_connect=local_connections["writer"],
            clock=lambda: datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc),
            ids=ids,
            receipt_verifier=AcceptingVerifier(),
            receipt_trust=receipt_trust,
            approval_verifier=(
                AcceptingVerifier()
                if upgrade_case in {"legacy_pre_policy", "expired_approval"}
                else None
            ),
            approval_trust=(
                lambda when: TrustContext(
                    now=when,
                    trusted_keys=(
                        TrustedKey(
                            "policy.authority",
                            "policy.key.v1",
                            frozenset({algorithm}),
                            datetime(2020, 1, 1, tzinfo=timezone.utc),
                            (
                                datetime(2026, 1, 2, tzinfo=timezone.utc)
                                if upgrade_case == "expired_approval"
                                else datetime(2030, 1, 1, tzinfo=timezone.utc)
                            ),
                        ),
                    ),
                    allowed_algorithms=frozenset({algorithm}),
                    allowed_proof_domains=frozenset({"approval_record.v1"}),
                    expected_issuers=frozenset({"policy.authority"}),
                    allowed_domain_issuers=frozenset({("approval_record.v1", "policy.authority")}),
                    trust_policy_version="upgrade-path.test.v1",
                )
            )
            if upgrade_case in {"legacy_pre_policy", "expired_approval"}
            else None,
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
        rollback = copy.deepcopy(command)
        rollback.update(
            {
                "operation_id": "upgrade-existing-rollback",
                "expected_revision": 1,
                "activation_receipt": activate["activation_receipt"],
                "rollback_receipt": rollback_receipt(command, activate["activation_receipt"]),
            }
        )

        def rollback_receipt_trust(when: datetime) -> TrustContext:
            trust = receipt_trust(when)
            activation_history = verify_runtime_receipt(
                rollback["activation_receipt"],
                verifier=AcceptingVerifier(),
                trust=trust,
                expected_tenant=actor["tenant_id"],
            )
            rollback_history = verify_runtime_receipt(
                rollback["rollback_receipt"],
                verifier=AcceptingVerifier(),
                trust=trust,
                expected_tenant=actor["tenant_id"],
            )
            return dataclasses.replace(
                trust,
                historical_acceptances=(
                    dataclasses.replace(activation_history, ledger_position=1),
                    dataclasses.replace(rollback_history, ledger_position=2),
                ),
            )

        PostgresSkillLifecycleAuthority(
            privileged_connect=local_connections["skill_authority"],
            evidence_writer_connect=local_connections["writer"],
            clock=lambda: datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc),
            ids=ids,
            receipt_verifier=AcceptingVerifier(),
            receipt_trust=rollback_receipt_trust,
            approval_verifier=authority._approval_verifier,
            approval_trust=authority._approval_trust,
        ).rollback_skill(actor_context=actor, **rollback)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*), min(evidence_event_digest) FROM gah_skill_lifecycle_transitions"
            )
            transitions_before = cursor.fetchone()
            cursor.execute("SELECT count(*), min(event_digest) FROM gah_evidence_events")
            evidence_before = cursor.fetchone()

        with connect() as connection, connection.cursor() as cursor:
            cursor.execute("DROP FUNCTION gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb)")
        phase14 = tuple(migration for migration in packaged if migration.version <= 14)
        monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase14)
        assert apply_migrations(admin_connect=connect)[-1].version == 14
        if upgrade_case in {"legacy_pre_policy", "expired_approval"}:
            phase15 = tuple(migration for migration in packaged if migration.version <= 15)
            monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase15)
            assert apply_migrations(admin_connect=connect)[-1].version == 15
        if upgrade_case == "legacy_pre_policy":
            # Test-only admin corruption of a stored v15 receipt: the live
            # Python boundary was used only to create the valid historical
            # row; this mutation isolates 0016's legacy migration preflight.
            with connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT operation_id, command_json FROM gah_skill_lifecycle_transitions "
                    "WHERE tenant_id=%s AND actor_id=%s ORDER BY transition_sequence LIMIT 1",
                    (actor["tenant_id"], actor["actor_id"]),
                )
                operation_id, poisoned = cursor.fetchone()
                policy = poisoned["policy_decision"]
                policy["decided_at"] = "2026-01-02T00:00:00.000Z"
                apply_object_digest(policy)
                approval = poisoned["approvals"][0]
                approval["policy_decision_digest"] = policy["decision_digest"]
                poisoned["approvals"] = [policy_approval(approval)]
                poisoned["delivery_envelope"]["policy_refs"] = [
                    ref("policy_decision", policy["decision_id"], policy["decision_digest"])
                ]
                poisoned["delivery_envelope"]["reviewer_refs"] = [
                    ref(
                        "approval_record",
                        poisoned["approvals"][0]["approval_id"],
                        poisoned["approvals"][0]["approval_digest"],
                    )
                ]
                apply_object_digest(poisoned["delivery_envelope"])
                unsigned = dict(poisoned)
                unsigned.pop("operation_digest")
                poisoned["operation_digest"] = sha256_digest(unsigned)
                cursor.execute(
                    "UPDATE gah_skill_lifecycle_transitions "
                    "SET operation_digest=%s, command_json=%s::jsonb "
                    "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
                    (
                        poisoned["operation_digest"],
                        json.dumps(poisoned),
                        actor["tenant_id"],
                        actor["actor_id"],
                        operation_id,
                    ),
                )
            monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
            with pytest.raises(Exception, match="lifecycle approval authority binding"):
                apply_migrations(admin_connect=connect)
            with connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT max(version) FROM gah_schema_migrations")
                assert cursor.fetchone() == (15,)
            return
        if upgrade_case in {"future_authorize", "unsupported_constraints"}:
            phase16 = tuple(migration for migration in packaged if migration.version <= 16)
            monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase16)
            assert apply_migrations(admin_connect=connect)[-1].version == 16
            # This admin-only fixture mutation creates a canonically rebound
            # historical v16 row. It is intentionally after the live Python
            # path, so it proves 0017's migration preflight rather than
            # bypassing the newly hardened live boundary.
            with connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT operation_id, command_json FROM gah_skill_lifecycle_transitions "
                    "WHERE tenant_id=%s AND actor_id=%s ORDER BY transition_sequence LIMIT 1",
                    (actor["tenant_id"], actor["actor_id"]),
                )
                operation_id, poisoned = cursor.fetchone()
                policy = poisoned["policy_decision"]
                if upgrade_case == "future_authorize":
                    policy["decided_at"] = "2030-01-01T00:00:00.000Z"
                else:
                    parameters = {"mode": "opaque"}
                    policy["constraints"] = [
                        {
                            "constraint_id": "example.invalid/unsupported",
                            "constraint_version": "v1",
                            "parameters": parameters,
                            "parameters_digest": sha256_digest(parameters),
                        }
                    ]
                apply_object_digest(policy)
                poisoned["delivery_envelope"]["policy_refs"] = [
                    ref("policy_decision", policy["decision_id"], policy["decision_digest"])
                ]
                apply_object_digest(poisoned["delivery_envelope"])
                unsigned = dict(poisoned)
                unsigned.pop("operation_digest")
                poisoned["operation_digest"] = sha256_digest(unsigned)
                cursor.execute(
                    "UPDATE gah_skill_lifecycle_transitions "
                    "SET operation_digest=%s, command_json=%s::jsonb "
                    "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
                    (
                        poisoned["operation_digest"],
                        json.dumps(poisoned),
                        actor["tenant_id"],
                        actor["actor_id"],
                        operation_id,
                    ),
                )
                cursor.execute(
                    "SELECT command_json FROM gah_skill_lifecycle_transitions "
                    "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
                    (actor["tenant_id"], actor["actor_id"], operation_id),
                )
                poisoned_before_upgrade = cursor.fetchone()[0]
            monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
            expected_error = (
                "policy decision is after its acceptance time"
                if upgrade_case == "future_authorize"
                else "lifecycle policy authority shape is invalid"
            )
            with pytest.raises(Exception, match=expected_error):
                apply_migrations(admin_connect=connect)
            with connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT max(version) FROM gah_schema_migrations")
                assert cursor.fetchone() == (16,)
                cursor.execute(
                    "SELECT command_json FROM gah_skill_lifecycle_transitions "
                    "WHERE tenant_id=%s AND actor_id=%s AND operation_id=%s",
                    (actor["tenant_id"], actor["actor_id"], operation_id),
                )
                assert cursor.fetchone()[0] == poisoned_before_upgrade
                cursor.execute(
                    "SELECT to_regprocedure('gah_verify_lifecycle_approvals_0016(jsonb,timestamptz,boolean)')"
                )
                assert cursor.fetchone() == (None,)
                cursor.execute(
                    "SELECT "
                    "to_regprocedure('gah_actor_extension_scalar_valid(jsonb)'), "
                    "to_regprocedure('gah_actor_extension_value_valid(jsonb)'), "
                    "to_regprocedure('gah_actor_extensions_valid(jsonb)')"
                )
                assert cursor.fetchone() == (None, None, None)
                cursor.execute(
                    "SELECT count(*), min(evidence_event_digest) FROM gah_skill_lifecycle_transitions"
                )
                assert cursor.fetchone() == transitions_before
                cursor.execute("SELECT count(*), min(event_digest) FROM gah_evidence_events")
                assert cursor.fetchone() == evidence_before
            return
        monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
        applied = apply_migrations(admin_connect=connect)
        assert applied[-1].version == 19
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
            cursor.execute(
                "SELECT to_regprocedure('gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb)')"
            )
            if cursor.fetchone()[0] is not None:
                cursor.execute(
                    "REVOKE ALL ON FUNCTION "
                    "gah_lock_skill_lifecycle_draft(jsonb,jsonb,text,jsonb) "
                    f"FROM {skill_role}"
                )
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
        (14, 1),
        (15, 1),
        (16, 1),
        (17, 1),
        (18, 1),
        (19, 1),
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
            "INSERT INTO gah_schema_migrations (version, checksum) VALUES (20, %s)",
            ("sha256:" + "1" * 64,),
        )
    with pytest.raises(MigrationError, match="unknown migration version 0020"):
        apply_migrations(admin_connect=connect)


@pytest.mark.parametrize(
    "poison",
    (
        "unknown_key",
        "issued_after_recorded_at",
        "cross_bound",
        "proposal_delivery_cross_bound",
        "row_command_cross_bound",
    ),
)
def test_phase15_upgrade_rejects_untrusted_persisted_lifecycle_receipt_atomically(
    migration_database: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    poison: str,
) -> None:
    import base64
    from hashlib import sha256

    from nacl.signing import SigningKey

    import governed_agent_harness.persistence.migration as migration_module

    signing_key = SigningKey(
        bytes.fromhex("2f4b0b6f0906b7c5e3f0a25e7c5c9ddbcf8d175b75a5a09b2a1dc38841f47c72")
    )
    packaged = discover_migrations()
    phase14 = tuple(item for item in packaged if item.version <= 14)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase14)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    tenant = "018f0000-0000-7000-8000-000000000001"
    actor = "018f0000-0000-7000-8000-000000000002"
    skill = "018f0000-0000-7000-8000-000000000023"
    artifact = {"kind": "synthetic", "version": 1}
    artifact_digest = sha256_digest(artifact)
    proposal_digest = "sha256:" + "b" * 64
    scope = {"tenant_id": tenant, "actor_id": actor}
    policy_ref = {
        "record_type": "policy_decision",
        "record_id": "018f0000-0000-7000-8000-000000000028",
        "record_digest": "sha256:" + "8" * 64,
    }
    install_command = {
        "operation": "install",
        "operation_digest": "sha256:" + "c" * 64,
        "skill_proposal": {
            "proposal_id": "018f0000-0000-7000-8000-000000000024",
            "artifact_id": skill,
            "artifact_revision": 1,
            "artifact": artifact,
            "tenant_id": tenant,
            "proposal_digest": proposal_digest,
            "target_scope": scope,
        },
        "delivery_envelope": {
            "tenant_id": tenant,
            "delivery_id": "018f0000-0000-7000-8000-000000000027",
            "envelope_digest": "sha256:" + "7" * 64,
            "artifact_type": "skill",
            "artifact_id": skill,
            "artifact_revision": 1,
            "artifact_digest": artifact_digest,
            "target_scope": scope,
            "lifecycle_state": "delivered",
            "issued_at": "2025-01-01T00:00:00.000Z",
            "expires_at": "2030-01-01T00:00:00.000Z",
            "evidence_refs": [],
            "policy_refs": [policy_ref],
            "reviewer_refs": [],
        },
        "policy_decision": {
            "decision_id": policy_ref["record_id"],
            "decision_digest": policy_ref["record_digest"],
        },
        "artifact": artifact,
    }
    key_id = "runtime.missing.v1" if poison == "unknown_key" else "runtime.after-recorded.v1"
    issued_at = (
        "2026-02-01T00:00:00.000Z"
        if poison == "issued_after_recorded_at"
        else "2026-01-01T00:00:00.000Z"
    )
    receipt = {
        "record_type": "activation_receipt",
        "tenant_id": tenant,
        "receipt_id": "018f0000-0000-7000-8000-000000000029",
        "issuer_role": "runtime_authority",
        "target_scope": scope,
        "delivery_id": install_command["delivery_envelope"]["delivery_id"],
        "delivery_digest": install_command["delivery_envelope"]["envelope_digest"],
        "artifact_type": "skill",
        "artifact_id": skill,
        "artifact_revision": 1,
        "artifact_digest": artifact_digest,
        "activated_revision": {
            "record_type": "skill_proposal",
            "record_id": skill,
            "record_digest": artifact_digest,
        },
        "evidence_refs": [],
        "policy_refs": [policy_ref],
        "reviewer_refs": [],
        "issued_at": issued_at,
        "expires_at": "2030-01-01T00:00:00.000Z",
    }
    if poison == "cross_bound":
        receipt["artifact_id"] = "018f0000-0000-7000-8000-0000000000ff"
    elif poison == "proposal_delivery_cross_bound":
        foreign_artifact_id = "018f0000-0000-7000-8000-0000000000fe"
        receipt["artifact_id"] = foreign_artifact_id
        install_command["delivery_envelope"]["artifact_id"] = foreign_artifact_id
    receipt["receipt_digest"] = sha256_digest(receipt)
    proof = {
        "issuer": "runtime.authority",
        "key_id": key_id,
        "algorithm": "ed25519-rfc8032-gah-cjson-v1",
        "proof_domain": "activation_receipt.v1",
        "object_digest": receipt["receipt_digest"],
        "nonce": "P" * 22,
    }
    proof_frame = canonical_bytes(
        {
            "protocol": "gah.detached-proof.v1",
            **proof,
            "unsigned_record": {
                key: value for key, value in receipt.items() if key != "receipt_digest"
            },
        }
    )
    proof["detached_proof"] = (
        base64.urlsafe_b64encode(signing_key.sign(proof_frame).signature)
        .rstrip(b"=")
        .decode("ascii")
    )
    receipt["proof"] = proof
    activation_command = {
        **install_command,
        "operation": "activate",
        "operation_id": "poisoned-pre15-activation",
        "operation_digest": "sha256:" + "d" * 64,
        "activation_receipt": receipt,
        "rollback_receipt": None,
    }
    evidence = {
        "record_type": "evidence_envelope",
        "recorded_at": "2026-01-01T00:30:00.000Z",
        "event_digest": "sha256:" + "e" * 64,
    }
    with connect() as connection, connection.cursor() as cursor:
        if poison != "unknown_key":
            public_key = signing_key.verify_key.encode()
            cursor.execute(
                "INSERT INTO gah_execution_proof_keys ("
                "issuer,key_id,algorithm,proof_domain,public_key,"
                "public_key_fingerprint,trust_policy_version,trust_policy_digest,"
                "valid_from,valid_until) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz)",
                (
                    "runtime.authority",
                    key_id,
                    "ed25519-rfc8032-gah-cjson-v1",
                    "activation_receipt.v1",
                    public_key,
                    "sha256:" + sha256(public_key).hexdigest(),
                    "phase5.1.upgrade-poison.test.v1",
                    "sha256:" + "f" * 64,
                    issued_at,
                    "2030-01-01T00:00:00.000Z",
                ),
            )
        persisted_skill = (
            "018f0000-0000-7000-8000-0000000000fd" if poison == "row_command_cross_bound" else skill
        )
        cursor.execute(
            "ALTER TABLE gah_skill_artifact_revisions "
            "DROP CONSTRAINT gah_skill_artifact_command_sink_guard"
        )
        cursor.execute(
            "ALTER TABLE gah_skill_lifecycle_transitions "
            "DROP CONSTRAINT gah_skill_transition_command_sink_guard"
        )
        cursor.execute(
            "INSERT INTO gah_skill_artifact_revisions ("
            "tenant_id,actor_id,skill_id,revision,proposal_id,proposal_digest,"
            "artifact_digest,artifact_json,command_json) VALUES "
            "(%s,%s,%s,1,%s,%s,%s,'{}'::jsonb,%s::jsonb)",
            (
                tenant,
                actor,
                persisted_skill,
                install_command["skill_proposal"]["proposal_id"],
                proposal_digest,
                artifact_digest,
                json.dumps(install_command),
            ),
        )
        cursor.execute(
            "INSERT INTO gah_skill_lifecycle_transitions ("
            "tenant_id,actor_id,skill_id,transition_sequence,operation_id,operation,"
            "operation_digest,expected_revision,target_revision,from_state,to_state,"
            "command_json,evidence_json,evidence_event_digest) VALUES "
            "(%s,%s,%s,1,%s,'activate',%s,1,1,'installed','active',"
            "%s::jsonb,%s::jsonb,%s)",
            (
                tenant,
                actor,
                persisted_skill,
                activation_command["operation_id"],
                activation_command["operation_digest"],
                json.dumps(activation_command),
                json.dumps(evidence),
                evidence["event_digest"],
            ),
        )
        cursor.execute(
            "ALTER TABLE gah_skill_artifact_revisions "
            "ADD CONSTRAINT gah_skill_artifact_command_sink_guard "
            "CHECK (gah_skill_lifecycle_sink_command_valid("
            "tenant_id,actor_id,skill_id,revision,artifact_digest,command_json) IS TRUE) "
            "NOT VALID"
        )
        cursor.execute(
            "ALTER TABLE gah_skill_lifecycle_transitions "
            "ADD CONSTRAINT gah_skill_transition_command_sink_guard "
            "CHECK (gah_skill_lifecycle_sink_command_valid("
            "tenant_id,actor_id,skill_id,target_revision,"
            "command_json #>> '{delivery_envelope,artifact_digest}',command_json) IS TRUE) "
            "NOT VALID"
        )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    expected = (
        "activation receipt is not bound"
        if poison == "cross_bound"
        else (
            "lifecycle proposal and delivery composition is invalid"
            if poison == "proposal_delivery_cross_bound"
            else (
                "persisted lifecycle row and command binding is invalid"
                if poison == "row_command_cross_bound"
                else "detached proof verification failed"
            )
        )
    )
    with pytest.raises(Exception, match=expected):
        apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT max(version), "
            "to_regprocedure('gah_verify_persisted_lifecycle_receipts"
            "(jsonb,text,timestamptz,boolean,text,text,text,integer)') "
            "FROM gah_schema_migrations"
        )
        assert cursor.fetchone() == (14, None)


def test_phase15_upgrade_rejects_persisted_revoked_execution_replay_atomically(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase14 = tuple(item for item in packaged if item.version <= 14)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase14)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    tenant = "018f0000-0000-7000-8000-000000000001"
    command = {
        "operation_id": "poisoned-execution-replay",
        "operation_digest": "sha256:" + "1" * 64,
        "skill_id": "018f0000-0000-7000-8000-000000000023",
        "revision": 1,
        "artifact_digest": "sha256:" + "2" * 64,
        "tool_request": {
            "request_id": "018f0000-0000-7000-8000-000000000025",
            "request_digest": "sha256:" + "3" * 64,
        },
        "approvals": [{"revoked_at": "2026-01-01T00:00:00.000Z"}],
    }
    grant = {
        "grant_id": "018f0000-0000-7000-8000-000000000026",
        "request_id": command["tool_request"]["request_id"],
    }
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_builtin_execution_state ("
            "tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,"
            "request_digest,grant_id,grant_digest,skill_id,revision,artifact_digest,"
            "command_json,grant_json,state,issuance_evidence_json,issued_at) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s::jsonb,%s::jsonb,"
            "'authorized','{}'::jsonb,%s::timestamptz)",
            (
                tenant,
                "018f0000-0000-7000-8000-000000000002",
                "018f0000-0000-7000-8000-000000000003",
                command["operation_id"],
                command["operation_digest"],
                command["tool_request"]["request_id"],
                command["tool_request"]["request_digest"],
                grant["grant_id"],
                "sha256:" + "4" * 64,
                command["skill_id"],
                command["artifact_digest"],
                json.dumps(command),
                json.dumps(grant),
                "2026-01-01T00:00:00.000Z",
            ),
        )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    with pytest.raises(Exception, match="persisted execution approval is revoked"):
        apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT max(version), "
            "to_regprocedure('gah_lookup_builtin_execution_authorization_approval_validated"
            "(jsonb,jsonb)') FROM gah_schema_migrations"
        )
        assert cursor.fetchone() == (14, None)


def test_phase16_upgrade_rejects_ambiguous_actor_execution_state_atomically(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """0016 must not relabel a populated v15 row whose actor binding is false."""

    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase15 = tuple(item for item in packaged if item.version <= 15)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase15)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_builtin_execution_state ("
            "tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,"
            "request_digest,grant_id,grant_digest,skill_id,revision,artifact_digest,"
            "command_json,grant_json,state,issuance_evidence_json,issued_at) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,'{}'::jsonb,'{}'::jsonb,"
            "'authorized','{}'::jsonb,%s::timestamptz)",
            (
                "018f0000-0000-7000-8000-000000000001",
                "018f0000-0000-7000-8000-000000000002",
                "018f0000-0000-7000-8000-000000000003",
                "phase16-ambiguous-actor-row",
                "sha256:" + "1" * 64,
                "018f0000-0000-7000-8000-000000000004",
                "sha256:" + "2" * 64,
                "018f0000-0000-7000-8000-000000000005",
                "sha256:" + "3" * 64,
                "018f0000-0000-7000-8000-000000000006",
                "sha256:" + "4" * 64,
                "2026-01-01T00:00:00.000Z",
            ),
        )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    with pytest.raises(Exception, match="cannot migrate ambiguous execution actor bindings"):
        apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT max(version) FROM gah_schema_migrations), "
            "count(*) FROM gah_builtin_execution_state"
        )
        assert cursor.fetchone() == (15, 1)


def test_phase16_upgrade_preserves_populated_internally_bound_actor_state(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A populated v15 row that satisfies 0016's exact binding survives unchanged."""

    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase15 = tuple(item for item in packaged if item.version <= 15)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase15)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    tenant = "018f0000-0000-7000-8000-000000000001"
    actor = "018f0000-0000-7000-8000-000000000002"
    run = "018f0000-0000-7000-8000-000000000003"
    operation = "phase16-bound-populated-row"
    operation_digest = "sha256:" + "1" * 64
    request = "018f0000-0000-7000-8000-000000000004"
    request_digest = "sha256:" + "2" * 64
    grant_id = "018f0000-0000-7000-8000-000000000005"
    skill = "018f0000-0000-7000-8000-000000000006"
    artifact_digest = "sha256:" + "3" * 64
    grant = {
        "tenant_id": tenant,
        "actor_id": actor,
        "run_id": run,
        "request_id": request,
        "request_digest": request_digest,
        "grant_id": grant_id,
    }
    command = {
        "operation_id": operation,
        "operation_digest": operation_digest,
        "skill_id": skill,
        "revision": 1,
        "artifact_digest": artifact_digest,
        "tool_request": {
            "tenant_id": tenant,
            "actor_id": actor,
            "run_id": run,
            "request_id": request,
            "request_digest": request_digest,
            "arguments": {"input": {"message": "gah.builtin.echo.v1"}},
        },
    }
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT gah_canonical_sha256(%s::jsonb)", (json.dumps(grant),))
        grant_digest = cursor.fetchone()[0]
        issuance = {
            "tenant_id": tenant,
            "draft": {
                "tenant_id": tenant,
                "run_id": run,
                "inline_payload": {
                    "actor_id": actor,
                    "operation_id": operation,
                    "operation_digest": operation_digest,
                    "command": command,
                    "authorization_grant": grant,
                    "authorization_grant_digest": grant_digest,
                },
            },
        }
        cursor.execute(
            "INSERT INTO gah_builtin_execution_state ("
            "tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,"
            "request_digest,grant_id,grant_digest,skill_id,revision,artifact_digest,"
            "command_json,grant_json,state,issuance_evidence_json,issued_at) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s::jsonb,%s::jsonb,"
            "'authorized',%s::jsonb,%s::timestamptz)",
            (
                tenant,
                actor,
                run,
                operation,
                operation_digest,
                request,
                request_digest,
                grant_id,
                grant_digest,
                skill,
                artifact_digest,
                json.dumps(command),
                json.dumps(grant),
                json.dumps(issuance),
                "2026-01-01T00:00:00.000Z",
            ),
        )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    assert apply_migrations(admin_connect=connect)[-1].version == 19
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT tenant_id,actor_id,operation_id,grant_digest,command_json,grant_json "
            "FROM gah_builtin_execution_state"
        )
        assert cursor.fetchone() == (
            tenant,
            actor,
            operation,
            grant_digest,
            command,
            grant,
        )


def test_phase16_upgrade_rejects_rebound_sentinel_echo_input_atomically(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """0016 must reject a legacy row whose only changed binding is echo input."""

    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase15 = tuple(item for item in packaged if item.version <= 15)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase15)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    tenant = "018f0000-0000-7000-8000-000000000001"
    actor = "018f0000-0000-7000-8000-000000000002"
    run = "018f0000-0000-7000-8000-000000000003"
    operation = "phase16-sentinel-input-row"
    operation_digest = "sha256:" + "1" * 64
    request = "018f0000-0000-7000-8000-000000000004"
    request_digest = "sha256:" + "2" * 64
    grant_id = "018f0000-0000-7000-8000-000000000005"
    skill = "018f0000-0000-7000-8000-000000000006"
    artifact_digest = "sha256:" + "3" * 64
    grant = {
        "tenant_id": tenant,
        "actor_id": actor,
        "run_id": run,
        "request_id": request,
        "request_digest": request_digest,
        "grant_id": grant_id,
    }
    command = {
        "operation_id": operation,
        "operation_digest": operation_digest,
        "skill_id": skill,
        "revision": 1,
        "artifact_digest": artifact_digest,
        "tool_request": {
            "tenant_id": tenant,
            "actor_id": actor,
            "run_id": run,
            "request_id": request,
            "request_digest": request_digest,
            "arguments": {"input": {"message": "gah.builtin.echo.v1"}},
        },
    }
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT gah_canonical_sha256(%s::jsonb)", (json.dumps(grant),))
        grant_digest = cursor.fetchone()[0]
        issuance = {
            "tenant_id": tenant,
            "draft": {
                "tenant_id": tenant,
                "run_id": run,
                "inline_payload": {
                    "actor_id": actor,
                    "operation_id": operation,
                    "operation_digest": operation_digest,
                    "command": command,
                    "authorization_grant": grant,
                    "authorization_grant_digest": grant_digest,
                },
            },
        }
        cursor.execute(
            "INSERT INTO gah_builtin_execution_state ("
            "tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,"
            "request_digest,grant_id,grant_digest,skill_id,revision,artifact_digest,"
            "command_json,grant_json,state,issuance_evidence_json,issued_at) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s::jsonb,%s::jsonb,"
            "'authorized',%s::jsonb,%s::timestamptz)",
            (
                tenant,
                actor,
                run,
                operation,
                operation_digest,
                request,
                request_digest,
                grant_id,
                grant_digest,
                skill,
                artifact_digest,
                json.dumps(command),
                json.dumps(grant),
                json.dumps(issuance),
                "2026-01-01T00:00:00.000Z",
            ),
        )
        sentinel = {"sentinel": "must-not-persist"}
        cursor.execute(
            "UPDATE gah_builtin_execution_state SET "
            "command_json=jsonb_set(command_json,'{tool_request,arguments,input}',%s::jsonb), "
            "issuance_evidence_json=jsonb_set("
            "issuance_evidence_json,'{draft,inline_payload,command,tool_request,arguments,input}',"
            "%s::jsonb) WHERE tenant_id=%s AND operation_id=%s",
            (json.dumps(sentinel), json.dumps(sentinel), tenant, operation),
        )
        assert cursor.rowcount == 1
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    with pytest.raises(Exception, match="cannot migrate ambiguous execution actor bindings"):
        apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT (SELECT max(version) FROM gah_schema_migrations), "
            "command_json#>'{tool_request,arguments,input}', "
            "issuance_evidence_json#>'{draft,inline_payload,command,tool_request,arguments,input}', "
            "to_regprocedure('gah_builtin_execution_state_actor_binding_valid("
            "text,text,text,text,text,text,text,text,text,text,integer,text,jsonb,jsonb,jsonb)') "
            "FROM gah_builtin_execution_state WHERE tenant_id=%s AND operation_id=%s",
            (tenant, operation),
        )
        assert cursor.fetchone() == (15, sentinel, sentinel, None)


def test_phase16_principal_entry_lock_waits_before_actor_binding_preflight(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """0016 cannot inspect actor bindings while a legacy principal reader is live."""

    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase15 = tuple(item for item in packaged if item.version <= 15)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase15)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    reader = connect()
    reader_cursor = reader.cursor()
    reader_cursor.execute("SELECT 1 FROM gah_runtime_principals LIMIT 1")
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            upgrade = pool.submit(apply_migrations, admin_connect=connect)
            deadline = time.monotonic() + 5
            waiting = False
            while time.monotonic() < deadline:
                with connect() as observer, observer.cursor() as cursor:
                    cursor.execute(
                        "SELECT EXISTS (SELECT 1 FROM pg_locks AS locks "
                        "WHERE locks.relation='gah_runtime_principals'::regclass "
                        "AND locks.mode='AccessExclusiveLock' AND NOT locks.granted)"
                    )
                    waiting = cursor.fetchone()[0]
                if waiting:
                    break
                time.sleep(0.01)
            assert waiting and not upgrade.done(), "0016 did not wait on principal entry"
            reader.commit()
            assert upgrade.result(timeout=8)[-1].version == 19
    finally:
        reader.rollback()
        reader_cursor.close()
        reader.close()


def test_phase16_tenant_global_grant_rejects_second_actor_bound_state(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Actor-scoped caller IDs do not make an authority-issued grant reusable."""

    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase15 = tuple(item for item in packaged if item.version <= 15)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase15)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    apply_migrations(admin_connect=connect)
    tenant = "018f0000-0000-7000-8000-000000000001"
    grant_id = "018f0000-0000-7000-8000-0000000000f0"

    def row(actor_suffix: str):
        actor = f"018f0000-0000-7000-8000-000000000{actor_suffix}"
        run = f"018f0000-0000-7000-8000-000000000{actor_suffix}1"
        request = f"018f0000-0000-7000-8000-000000000{actor_suffix}2"
        skill = f"018f0000-0000-7000-8000-000000000{actor_suffix}3"
        operation = f"phase16-grant-{actor_suffix}"
        operation_digest = "sha256:" + actor_suffix[0] * 64
        request_digest = "sha256:" + actor_suffix[1] * 64
        artifact_digest = "sha256:" + ("c" if actor_suffix == "a1" else "d") * 64
        grant = {
            "tenant_id": tenant,
            "actor_id": actor,
            "run_id": run,
            "request_id": request,
            "request_digest": request_digest,
            "grant_id": grant_id,
        }
        command = {
            "operation_id": operation,
            "operation_digest": operation_digest,
            "skill_id": skill,
            "revision": 1,
            "artifact_digest": artifact_digest,
            "tool_request": {
                "tenant_id": tenant,
                "actor_id": actor,
                "run_id": run,
                "request_id": request,
                "request_digest": request_digest,
                "arguments": {"input": {"message": "gah.builtin.echo.v1"}},
            },
        }
        return (
            actor,
            run,
            request,
            skill,
            operation,
            operation_digest,
            request_digest,
            artifact_digest,
            grant,
            command,
        )

    def insert(cursor, values):
        (
            actor,
            run,
            request,
            skill,
            operation,
            operation_digest,
            request_digest,
            artifact_digest,
            grant,
            command,
        ) = values
        cursor.execute("SELECT gah_canonical_sha256(%s::jsonb)", (json.dumps(grant),))
        grant_digest = cursor.fetchone()[0]
        issuance = {
            "tenant_id": tenant,
            "draft": {
                "tenant_id": tenant,
                "run_id": run,
                "inline_payload": {
                    "actor_id": actor,
                    "operation_id": operation,
                    "operation_digest": operation_digest,
                    "command": command,
                    "authorization_grant": grant,
                    "authorization_grant_digest": grant_digest,
                },
            },
        }
        cursor.execute(
            "INSERT INTO gah_builtin_execution_state ("
            "tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,"
            "request_digest,grant_id,grant_digest,skill_id,revision,artifact_digest,"
            "command_json,grant_json,state,issuance_evidence_json,issued_at) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s::jsonb,%s::jsonb,"
            "'authorized',%s::jsonb,%s::timestamptz)",
            (
                tenant,
                actor,
                run,
                operation,
                operation_digest,
                request,
                request_digest,
                grant_id,
                grant_digest,
                skill,
                artifact_digest,
                json.dumps(command),
                json.dumps(grant),
                json.dumps(issuance),
                "2026-01-01T00:00:00.000Z",
            ),
        )

    first, second = row("a1"), row("b1")
    with connect() as connection, connection.cursor() as cursor:
        insert(cursor, first)
    with connect() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="grant_id"):
            insert(cursor, second)
        connection.rollback()
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_builtin_execution_state")
        assert cursor.fetchone() == (1,)


def test_phase15_upgrade_serializes_preflight_after_concurrent_legacy_writer(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase14 = tuple(item for item in packaged if item.version <= 14)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase14)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    command = {
        "operation_id": "concurrent-poisoned-replay",
        "operation_digest": "sha256:" + "1" * 64,
        "skill_id": "018f0000-0000-7000-8000-000000000023",
        "revision": 1,
        "artifact_digest": "sha256:" + "2" * 64,
        "tool_request": {
            "request_id": "018f0000-0000-7000-8000-000000000025",
            "request_digest": "sha256:" + "3" * 64,
        },
        "approvals": [{"revoked_at": "2026-01-01T00:00:00.000Z"}],
    }
    grant = {
        "grant_id": "018f0000-0000-7000-8000-000000000026",
        "request_id": command["tool_request"]["request_id"],
    }
    writer = connect()
    writer_cursor = writer.cursor()
    writer_cursor.execute("SELECT pg_backend_pid()")
    writer_pid = writer_cursor.fetchone()[0]
    writer_cursor.execute(
        "INSERT INTO gah_builtin_execution_state ("
        "tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,"
        "request_digest,grant_id,grant_digest,skill_id,revision,artifact_digest,"
        "command_json,grant_json,state,issuance_evidence_json,issued_at) VALUES "
        "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s::jsonb,%s::jsonb,"
        "'authorized','{}'::jsonb,%s::timestamptz)",
        (
            "018f0000-0000-7000-8000-000000000001",
            "018f0000-0000-7000-8000-000000000002",
            "018f0000-0000-7000-8000-000000000003",
            command["operation_id"],
            command["operation_digest"],
            command["tool_request"]["request_id"],
            command["tool_request"]["request_digest"],
            grant["grant_id"],
            "sha256:" + "4" * 64,
            command["skill_id"],
            command["artifact_digest"],
            json.dumps(command),
            json.dumps(grant),
            "2026-01-01T00:00:00.000Z",
        ),
    )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            upgrade = pool.submit(apply_migrations, admin_connect=connect)
            deadline = time.monotonic() + 5
            waiting = False
            while time.monotonic() < deadline:
                with connect() as observer, observer.cursor() as cursor:
                    cursor.execute(
                        "SELECT EXISTS ("
                        "SELECT 1 FROM pg_locks AS held "
                        "JOIN pg_stat_activity AS activity ON activity.pid=held.pid "
                        "WHERE held.pid<>%s AND held.pid<>pg_backend_pid() "
                        "AND activity.datname=current_database() "
                        "AND held.relation='gah_builtin_execution_state'::regclass "
                        "AND held.mode='ShareRowExclusiveLock' "
                        "AND held.granted IS FALSE)",
                        (writer_pid,),
                    )
                    waiting = cursor.fetchone()[0]
                if waiting:
                    break
                time.sleep(0.01)
            proved_wait = waiting and not upgrade.done()
            writer.commit()
            assert proved_wait, "migration did not wait behind the legacy execution writer"
            with pytest.raises(Exception, match="persisted execution approval is revoked"):
                upgrade.result(timeout=8)
    finally:
        writer.rollback()
        writer_cursor.close()
        writer.close()
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT max(version) FROM gah_schema_migrations")
        assert cursor.fetchone()[0] == 14


def test_phase15_upgrade_rejects_backdated_terminal_execution_atomically(
    migration_database: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    import governed_agent_harness.persistence.migration as migration_module

    packaged = discover_migrations()
    phase14 = tuple(item for item in packaged if item.version <= 14)
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: phase14)
    connect = migration_database["connect"]
    apply_migrations(admin_connect=connect)
    tenant = "018f0000-0000-7000-8000-000000000001"
    actor = "018f0000-0000-7000-8000-000000000002"
    command = {
        "operation_id": "poisoned-terminal-chronology",
        "operation_digest": "sha256:" + "1" * 64,
        "skill_id": "018f0000-0000-7000-8000-000000000023",
        "revision": 1,
        "artifact_digest": "sha256:" + "2" * 64,
        "tool_request": {
            "request_id": "018f0000-0000-7000-8000-000000000025",
            "request_digest": "sha256:" + "3" * 64,
        },
        "approvals": [{}],
    }
    grant = {
        "grant_id": "018f0000-0000-7000-8000-000000000026",
        "request_id": command["tool_request"]["request_id"],
    }
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO gah_builtin_execution_state ("
            "tenant_id,actor_id,run_id,operation_id,operation_digest,request_id,"
            "request_digest,grant_id,grant_digest,skill_id,revision,artifact_digest,"
            "command_json,grant_json,state,issuance_evidence_json,intent_evidence_json,"
            "outcome_json,outcome_evidence_json,execution_attempt_id,owner_generation,"
            "lease_expires_at,issued_at,completed_at) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s::jsonb,%s::jsonb,"
            "'completed','{}'::jsonb,%s::jsonb,%s::jsonb,'{}'::jsonb,%s,1,"
            "%s::timestamptz,%s::timestamptz,%s::timestamptz)",
            (
                tenant,
                actor,
                "018f0000-0000-7000-8000-000000000003",
                command["operation_id"],
                command["operation_digest"],
                command["tool_request"]["request_id"],
                command["tool_request"]["request_digest"],
                grant["grant_id"],
                "sha256:" + "4" * 64,
                command["skill_id"],
                command["artifact_digest"],
                json.dumps(command),
                json.dumps(grant),
                json.dumps({"recorded_at": "2026-01-02T00:00:00.000Z"}),
                json.dumps({"occurred_at": "2026-01-01T00:00:00.000Z"}),
                "018f0000-0000-7000-8000-000000000027",
                "2026-01-03T00:00:00.000Z",
                "2026-01-01T00:00:00.000Z",
                "2026-01-03T00:00:00.000Z",
            ),
        )
    monkeypatch.setattr(migration_module, "discover_migrations", lambda: packaged)
    with pytest.raises(Exception, match="terminal execution predates its intent"):
        apply_migrations(admin_connect=connect)
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT max(version), "
            "to_regprocedure('gah_builtin_execution_validate_outcome"
            "(jsonb,jsonb,jsonb,jsonb,jsonb,text)') FROM gah_schema_migrations"
        )
        version, public_validator = cursor.fetchone()
        assert version == 14
        assert public_validator is not None
        cursor.execute(
            "SELECT to_regprocedure('gah_builtin_execution_validate_outcome_validated"
            "(jsonb,jsonb,jsonb,jsonb,jsonb,text)')"
        )
        assert cursor.fetchone()[0] is None


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
        version=20,
        name="0020_broken.sql",
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
