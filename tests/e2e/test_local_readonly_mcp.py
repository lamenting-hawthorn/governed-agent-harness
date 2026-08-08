"""Real-PostgreSQL contract test for the Phase 5.3 local stdio MCP surface."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import ANY

import anyio
import pytest
from mcp import types
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from governed_agent_harness.contracts import apply_object_digest, sha256_digest
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.knowledge.local_mcp import (
    LocalMcpBootstrapError,
    LocalMcpConfig,
    build_local_mcp_server,
    load_local_mcp_config,
)
from governed_agent_harness.knowledge import (
    CitedGithubMarkdown,
    GithubMarkdownResourcePage,
    ListedGithubMarkdown,
    PinnedGithubMarkdown,
    PostgresGithubMarkdownAuthority,
)
from governed_agent_harness.persistence import PostgresDurableEffectStore


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _live_actor(postgres_connections):
    actor = copy.deepcopy(build_positive_records()["actor_context"])
    current = datetime.now(timezone.utc)
    actor["auth"]["verified_at"] = _timestamp(current.replace(microsecond=0))
    actor["issued_at"] = _timestamp(current)
    actor["expires_at"] = _timestamp(current.replace(microsecond=0) + timedelta(hours=1))
    PostgresDurableEffectStore.provision_principal(
        admin_connect=postgres_connections["admin"],
        database_roles=("gah_app", "gah_writer"),
        actor_context=actor,
    )
    return actor


def _source(*, commit_sha: str = "a" * 40, path: str = "docs/roadmap.md"):
    return PinnedGithubMarkdown(
        repository="acme/brain",
        commit_sha=commit_sha,
        path=path,
        content="# Roadmap\n\nThe MCP resource is cited and untrusted.\n",
        classification="internal",
        retention_expires_at=_timestamp(datetime.now(timezone.utc) + timedelta(days=30)),
    )


def _ids():
    state = [0xD000]

    def next_id() -> str:
        state[0] += 1
        return f"018f0000-0000-7000-8000-{state[0]:012x}"

    return next_id


def _policy(actor, *, operation_id: str, operation_digest: str, decision_id: str):
    policy = copy.deepcopy(build_positive_records()["policy_decision"])
    policy.update(
        {
            "tenant_id": actor["tenant_id"],
            "decision_id": decision_id,
            "request_id": operation_id,
            "request_digest": operation_digest,
            "decision": "authorize",
            "rule_refs": ["knowledge.github_import.v1"],
            "constraints": [],
            "isolation_profile": "no_effect",
            "decided_at": _timestamp(datetime.now(timezone.utc)),
        }
    )
    return apply_object_digest(policy)


def _import(postgres_connections, actor, source, *, operation_suffix: int, ids=None):
    operation_id = f"018f0000-0000-7000-8000-{operation_suffix:012x}"
    imported = PostgresGithubMarkdownAuthority(
        privileged_connect=postgres_connections["writer"],
        clock=lambda: datetime.now(timezone.utc),
        ids=_ids() if ids is None else ids,
    ).import_markdown(
        actor_context=actor,
        operation_id=operation_id,
        run_id=actor["session_id"],
        source=source,
        policy_decision=_policy(
            actor,
            operation_id=operation_id,
            operation_digest=source.operation_digest(operation_id),
            decision_id=f"018f0000-0000-7000-8000-{operation_suffix + 1:012x}",
        ),
    )
    return imported.result, operation_id


def _write_config(tmp_path, actor):
    config = tmp_path / "local-mcp.json"
    config.write_text(json.dumps(_bootstrap_document(actor), sort_keys=True), encoding="utf-8")
    config.chmod(0o600)
    return config


def _bootstrap_document(actor, *, project_id=None):
    return {
        "version": 1,
        "project_id": actor["scope_authority"]["project_ids"][0]
        if project_id is None
        else project_id,
        "actor_context": actor,
    }


def _server_parameters(postgres_connections, config):
    with postgres_connections["app"]() as connection:
        dsn = connection.info.dsn
    root = str(Path(__file__).resolve().parents[2])
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "governed_agent_harness.knowledge.local_mcp", "--config", str(config)],
        env={"GAH_RUNTIME_DATABASE_DSN": dsn, "PYTHONPATH": str(Path(root) / "src")},
        cwd=root,
    )


def _knowledge_counts(postgres_connections):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT "
            "(SELECT count(*) FROM gah_github_markdown_sources), "
            "(SELECT count(*) FROM gah_github_markdown_revisions), "
            "(SELECT count(*) FROM gah_github_markdown_operations), "
            "(SELECT count(*) FROM gah_evidence_events), "
            "(SELECT count(*) FROM gah_run_heads), "
            "(SELECT count(*) FROM gah_memory_records), "
            "(SELECT count(*) FROM gah_skill_artifact_revisions), "
            "(SELECT count(*) FROM gah_builtin_execution_state)"
        )
        return cursor.fetchone()


def test_local_mcp_bootstrap_rejects_every_untrusted_config_shape(tmp_path):
    """The public bootstrap loader rejects unsafe files with one safe error boundary."""

    actor = copy.deepcopy(build_positive_records()["actor_context"])
    valid = _write_config(tmp_path, actor)
    assert load_local_mcp_config(valid) == LocalMcpConfig(
        project_id=actor["scope_authority"]["project_ids"][0], actor_context=actor
    )

    def assert_rejected(path):
        with pytest.raises(LocalMcpBootstrapError) as rejected:
            load_local_mcp_config(path)
        assert str(rejected.value) == "local MCP bootstrap is invalid"

    broader_mode = tmp_path / "broader-mode.json"
    broader_mode.write_text(json.dumps(_bootstrap_document(actor)), encoding="utf-8")
    broader_mode.chmod(0o640)
    assert_rejected(broader_mode)

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(valid)
    assert_rejected(symlink)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"version":1,"version":1,"project_id":'
        + json.dumps(actor["scope_authority"]["project_ids"][0])
        + ',"actor_context":'
        + json.dumps(actor)
        + "}",
        encoding="utf-8",
    )
    duplicate.chmod(0o600)
    assert_rejected(duplicate)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b"x" * 65_536 + b"}")
    oversized.chmod(0o600)
    assert_rejected(oversized)

    undeclared = tmp_path / "undeclared.json"
    undeclared.write_text(
        json.dumps(_bootstrap_document(actor) | {"unexpected": True}), encoding="utf-8"
    )
    undeclared.chmod(0o600)
    assert_rejected(undeclared)

    for name, project_id in (
        ("malformed-project.json", "not-a-project"),
        ("non-v7-project.json", "018f0000-0000-4000-8000-00000000d0ff"),
        ("outside-authority-project.json", "018f0000-0000-7000-8000-00000000d0ff"),
    ):
        config = tmp_path / name
        config.write_text(
            json.dumps(_bootstrap_document(actor, project_id=project_id)), encoding="utf-8"
        )
        config.chmod(0o600)
        assert_rejected(config)


def test_local_mcp_sdk_surface_is_resource_only_and_uses_safe_errors(monkeypatch):
    """Exercise the exact modern SDK surface without substituting DB authority."""

    actor = build_positive_records()["actor_context"]
    source = _source()
    citation = {
        "evidence_id": "018f0000-0000-7000-8000-00000000d001",
        "payload_digest": "sha256:" + "b" * 64,
    }
    common = {
        "source_identity": source.source_identity,
        "revision_uri": source.revision_uri,
        "repository": source.repository,
        "commit_sha": source.commit_sha,
        "path": source.path,
        "content_digest": source.content_digest,
        "classification": source.classification,
        "citation": citation,
        "imported_at": "2026-08-08T00:00:00.000Z",
        "retention_expires_at": source.retention_expires_at,
        "freshness_checked_at": "2026-08-08T00:00:01.000Z",
    }
    listed = ListedGithubMarkdown(**common)
    cited = CitedGithubMarkdown(content=source.content, **common)
    calls = []

    class RuntimeReader:
        def __init__(self, *, runtime_connect):
            assert callable(runtime_connect)

        def verify_local_mcp_bootstrap(self, *, actor_context, project_id):
            assert actor_context == actor
            assert project_id == actor["scope_authority"]["project_ids"][0]

        def list_local_mcp_resources(self, *, actor_context, project_id, cursor):
            assert actor_context == actor
            assert project_id == actor["scope_authority"]["project_ids"][0]
            assert cursor is None
            calls.append(("list", actor_context, project_id))
            return GithubMarkdownResourcePage(resources=(listed,), next_cursor=None)

        def read_local_mcp_resource(self, *, actor_context, project_id, revision_uri):
            assert actor_context == actor
            assert project_id == actor["scope_authority"]["project_ids"][0]
            calls.append(("read", actor_context, project_id))
            return cited if revision_uri == source.revision_uri else None

    import governed_agent_harness.knowledge.local_mcp as local_mcp

    monkeypatch.setattr(local_mcp, "PostgresGithubMarkdownReader", RuntimeReader)
    server = build_local_mcp_server(
        config=LocalMcpConfig(
            project_id=actor["scope_authority"]["project_ids"][0], actor_context=actor
        ),
        runtime_connect=lambda: None,
    )
    attacker_data = {
        "actor_context": {"actor_id": "attacker"},
        "tenant_id": "attacker-tenant",
        "database_credential": {"kind": "attacker-controlled"},
        "database_role": "attacker_role",
        "policy_authority": "attacker-policy",
        "source_scope": "all-sources",
    }

    async def exercise():
        async with Client(server, mode="auto") as client:
            assert client.protocol_version == "2026-07-28"
            assert client.session.initialize_result is None
            assert client.session.discover_result is not None
            assert client.session.discover_result.supported_versions == ["2026-07-28"]
            assert client.server_capabilities.resources is not None
            assert client.server_capabilities.tools is None
            assert client.server_capabilities.prompts is None
            assert client.server_capabilities.tasks is None
            listed_result = await client.list_resources(meta=attacker_data)
            assert listed_result.ttl_ms == 0
            assert listed_result.cache_scope == "private"
            assert listed_result.resources[0].meta == cited.local_mcp_metadata()
            read_result = await client.read_resource(source.revision_uri, meta=attacker_data)
            assert read_result.ttl_ms == 0
            assert read_result.cache_scope == "private"
            assert read_result.contents[0].text == source.content
            assert read_result.contents[0].meta == cited.local_mcp_metadata()
            with pytest.raises(MCPError) as unavailable:
                await client.read_resource("not-a-uri")
            assert (unavailable.value.code, unavailable.value.message) == (
                -32602,
                "Resource unavailable",
            )
            with pytest.raises(MCPError) as request_override:
                await client.read_resource(
                    source.revision_uri,
                    meta=attacker_data,
                    request_state=json.dumps(attacker_data, sort_keys=True),
                )
            assert (request_override.value.code, request_override.value.message) == (
                -32602,
                "Resource unavailable",
            )
            assert calls == [
                ("list", actor, actor["scope_authority"]["project_ids"][0]),
                ("read", actor, actor["scope_authority"]["project_ids"][0]),
                ("read", actor, actor["scope_authority"]["project_ids"][0]),
            ]

    anyio.run(exercise)

    async def legacy_protocol_is_rejected():
        with pytest.raises(BaseExceptionGroup) as rejected:
            async with Client(server, mode="legacy"):
                pass

        def leaves(error):
            if isinstance(error, BaseExceptionGroup):
                return [leaf for child in error.exceptions for leaf in leaves(child)]
            return [error]

        assert [
            (error.code, error.message)
            for error in leaves(rejected.value)
            if isinstance(error, MCPError)
        ] == [(types.UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version")]

    anyio.run(legacy_protocol_is_rejected)


def test_local_mcp_list_paginates_without_content_or_mutation(postgres_connections, tmp_path):
    actor = _live_actor(postgres_connections)
    ids = _ids()
    expected_uris = set()
    for index in range(26):
        source = _source(commit_sha=f"{index + 1:040x}", path=f"docs/local-mcp-{index:02d}.md")
        imported, _operation_id = _import(
            postgres_connections,
            actor,
            source,
            operation_suffix=0xD100 + index * 2,
            ids=ids,
        )
        expected_uris.add(imported.revision_uri)
    before = _knowledge_counts(postgres_connections)
    parameters = _server_parameters(postgres_connections, _write_config(tmp_path, actor))

    async def exercise():
        async with Client(stdio_client(parameters), mode="auto") as client:
            first = await client.list_resources()
            assert first.ttl_ms == 0
            assert first.cache_scope == "private"
            assert len(first.resources) == 25
            assert first.next_cursor is not None
            assert all("content" not in resource.meta for resource in first.resources)
            second = await client.list_resources(cursor=first.next_cursor)
            assert second.ttl_ms == 0
            assert second.cache_scope == "private"
            assert len(second.resources) == 1
            assert second.next_cursor is None
            assert {
                str(resource.uri) for resource in first.resources + second.resources
            } == expected_uris

    anyio.run(exercise)
    assert _knowledge_counts(postgres_connections) == before


def test_local_mcp_stdio_client_discovers_lists_reads_and_does_not_mutate(
    postgres_connections, tmp_path
):
    actor = _live_actor(postgres_connections)
    source = _source()
    imported, _operation_id = _import(postgres_connections, actor, source, operation_suffix=0xD011)
    before = _knowledge_counts(postgres_connections)
    parameters = _server_parameters(postgres_connections, _write_config(tmp_path, actor))

    async def exercise():
        async with Client(stdio_client(parameters), mode="auto") as client:
            assert client.protocol_version == "2026-07-28"
            assert client.session.initialize_result is None
            assert client.session.discover_result is not None
            assert client.session.discover_result.supported_versions == ["2026-07-28"]
            capabilities = client.server_capabilities
            assert capabilities.resources is not None
            assert capabilities.resources.subscribe is False
            assert capabilities.resources.list_changed is False
            assert capabilities.tools is None
            assert capabilities.prompts is None
            assert capabilities.logging is None
            assert capabilities.tasks is None
            assert capabilities.extensions is None
            listed = await client.list_resources()
            assert listed.ttl_ms == 0
            assert listed.cache_scope == "private"
            assert listed.next_cursor is None
            assert len(listed.resources) == 1
            resource = listed.resources[0]
            assert resource.uri == imported.revision_uri
            assert resource.mime_type == "text/markdown"
            assert resource.meta == {
                "source_identity": source.source_identity,
                "repository": source.repository,
                "commit_sha": source.commit_sha,
                "path": source.path,
                "content_digest": source.content_digest,
                "classification": source.classification,
                "citation": dict(imported.citation),
                "untrusted_context": True,
                "read_only": True,
                "scope": "actor-scoped",
                "authority": "database-runtime-principal-bound",
                "imported_at": ANY,
                "retention_enforced": True,
                "expires_at": source.retention_expires_at,
                "freshness": {"state": "eligible_at_read", "checked_at": ANY},
            }
            read = await client.read_resource(resource.uri)
            assert read.ttl_ms == 0
            assert read.cache_scope == "private"
            assert len(read.contents) == 1
            content = read.contents[0]
            assert content.uri == resource.uri
            assert content.mime_type == "text/markdown"
            assert content.text == source.content
            assert content.meta | {"freshness": resource.meta["freshness"]} == resource.meta
            assert content.meta["freshness"]["state"] == "eligible_at_read"
            assert content.meta["freshness"]["checked_at"] != ""

    anyio.run(exercise)
    assert _knowledge_counts(postgres_connections) == before


def test_local_mcp_read_hides_cross_actor_unknown_malformed_expired_and_revoked_resources(
    postgres_connections, tmp_path
):
    actor = _live_actor(postgres_connections)
    source = _source()
    evidence_ids = _ids()
    imported, _operation_id = _import(
        postgres_connections, actor, source, operation_suffix=0xD021, ids=evidence_ids
    )
    parameters = _server_parameters(postgres_connections, _write_config(tmp_path, actor))

    async def read_errors():
        async with Client(stdio_client(parameters), mode="auto") as client:
            for uri in (
                "not-a-uri",
                "https://github.com/acme/brain/blob/" + "b" * 40 + "/docs/no.md",
            ):
                with pytest.raises(MCPError) as raised:
                    await client.read_resource(uri)
                assert (raised.value.code, raised.value.message, raised.value.data) == (
                    -32602,
                    "Resource unavailable",
                    None,
                )
            with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE gah_github_markdown_revisions "
                    "SET retention_expires_at = clock_timestamp() - interval '1 second' "
                    "WHERE revision_uri = %s",
                    (imported.revision_uri,),
                )
            with pytest.raises(MCPError) as expired:
                await client.read_resource(imported.revision_uri)
            assert (expired.value.code, expired.value.message, expired.value.data) == (
                -32602,
                "Resource unavailable",
                None,
            )

    anyio.run(read_errors)

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_github_markdown_revisions "
            "SET retention_expires_at = %s::timestamptz WHERE revision_uri = %s",
            (source.retention_expires_at, imported.revision_uri),
        )
    authority = PostgresGithubMarkdownAuthority(
        privileged_connect=postgres_connections["writer"],
        clock=lambda: datetime.now(timezone.utc),
        ids=evidence_ids,
    )
    revoke_operation = "018f0000-0000-7000-8000-00000000d023"

    async def revoke_after_first_read():
        async with Client(stdio_client(parameters), mode="auto") as client:
            assert (await client.read_resource(imported.revision_uri)).contents[
                0
            ].text == source.content
            assert authority.revoke_source(
                actor_context=actor,
                operation_id=revoke_operation,
                run_id=actor["session_id"],
                source_identity=source.source_identity,
                policy_decision=_policy(
                    actor,
                    operation_id=revoke_operation,
                    operation_digest=sha256_digest(
                        {
                            "operation_id": revoke_operation,
                            "source_identity": source.source_identity,
                        }
                    ),
                    decision_id="018f0000-0000-7000-8000-00000000d024",
                ),
            )
            with pytest.raises(MCPError) as revoked:
                await client.read_resource(imported.revision_uri)
            assert (revoked.value.code, revoked.value.message, revoked.value.data) == (
                -32602,
                "Resource unavailable",
                None,
            )

    anyio.run(revoke_after_first_read)


def test_local_mcp_cross_actor_uri_and_bootstrap_stdout_are_safe(postgres_connections, tmp_path):
    actor = _live_actor(postgres_connections)
    source = _source()
    imported, _operation_id = _import(postgres_connections, actor, source, operation_suffix=0xD031)
    other = copy.deepcopy(actor)
    other["actor_id"] = "018f0000-0000-7000-8000-00000000d032"
    other["session_id"] = "018f0000-0000-7000-8000-00000000d033"
    other["correlation_id"] = "018f0000-0000-7000-8000-00000000d034"
    other["scope_authority"]["project_ids"] = ["018f0000-0000-7000-8000-00000000d035"]
    PostgresDurableEffectStore.provision_principal(
        admin_connect=postgres_connections["admin"],
        database_roles=("gah_app",),
        actor_context=other,
    )
    parameters = _server_parameters(postgres_connections, _write_config(tmp_path, other))

    async def cross_actor_read():
        async with Client(stdio_client(parameters), mode="auto") as client:
            assert (await client.list_resources()).resources == []
            with pytest.raises(MCPError) as denied:
                await client.read_resource(imported.revision_uri)
            assert (denied.value.code, denied.value.message, denied.value.data) == (
                -32602,
                "Resource unavailable",
                None,
            )

    anyio.run(cross_actor_read)

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}", encoding="utf-8")
    malformed.chmod(0o600)
    environment = os.environ.copy()
    environment.update(
        {
            "GAH_RUNTIME_DATABASE_DSN": "postgresql://secret-must-not-appear@example.invalid/db",
            "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
        }
    )
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "governed_agent_harness.knowledge.local_mcp",
            "--config",
            str(malformed),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 1
    assert process.stdout == ""
    assert process.stderr == "Local MCP startup unavailable\n"
    assert "secret-must-not-appear" not in process.stderr
