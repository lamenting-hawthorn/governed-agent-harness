"""Local-only, actor-bound MCP stdio resources for governed Markdown knowledge.

This adapter intentionally owns transport only.  PostgreSQL remains the
authorization boundary: every list/read re-checks the trusted bootstrap actor,
its project membership, the runtime database principal, revocation, and
retention before returning an immutable cited resource.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from governed_agent_harness.contracts import ActorContext
from governed_agent_harness.knowledge.github_markdown import (
    PostgresGithubMarkdownReader,
)

_CONFIG_MAX_BYTES = 65_536
_PROJECT_ID_LENGTH = 36
_PROTOCOL_VERSION = "2026-07-28"
_SAFE_RESOURCE_ERROR = "Resource unavailable"
_SAFE_STARTUP_ERROR = "Local MCP startup unavailable"


class LocalMcpBootstrapError(RuntimeError):
    """The trusted local bootstrap could not be established."""


@dataclass(frozen=True, slots=True)
class LocalMcpConfig:
    """Closed bootstrap input; it intentionally contains no database credential."""

    project_id: str
    actor_context: Mapping[str, Any]


def load_local_mcp_config(path: str | Path) -> LocalMcpConfig:
    """Load one owner-only, regular, canonical actor bootstrap JSON file."""

    payload = _read_owner_only_config(Path(path))
    try:
        raw = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise LocalMcpBootstrapError("local MCP bootstrap is invalid") from error
    if (
        not isinstance(raw, dict)
        or set(raw) != {"version", "project_id", "actor_context"}
        or type(raw["version"]) is not int
        or raw["version"] != 1
        or not isinstance(raw["project_id"], str)
        or len(raw["project_id"]) != _PROJECT_ID_LENGTH
        or not isinstance(raw["actor_context"], dict)
    ):
        raise LocalMcpBootstrapError("local MCP bootstrap is invalid")
    try:
        actor = ActorContext(raw["actor_context"]).to_dict()
    except Exception as error:
        raise LocalMcpBootstrapError("local MCP bootstrap is invalid") from error
    project_id = raw["project_id"]
    if not _project_is_in_actor_authority(actor, project_id):
        raise LocalMcpBootstrapError("local MCP bootstrap is invalid")
    return LocalMcpConfig(project_id=project_id, actor_context=actor)


def build_local_mcp_server(
    *, config: LocalMcpConfig, runtime_connect: Callable[[], Any]
) -> Server[Any]:
    """Construct the exact resources/list and resources/read L1 server surface."""

    reader = PostgresGithubMarkdownReader(runtime_connect=runtime_connect)
    reader.verify_local_mcp_bootstrap(
        actor_context=config.actor_context,
        project_id=config.project_id,
    )

    async def discover(context: Any, _params: types.RequestParams) -> types.DiscoverResult:
        _require_modern_protocol(context.protocol_version)
        return types.DiscoverResult(
            supported_versions=[_PROTOCOL_VERSION],
            capabilities=types.ServerCapabilities(
                resources=types.ResourcesCapability(subscribe=False, list_changed=False)
            ),
            ttl_ms=0,
            cache_scope="private",
        )

    async def list_resources(
        context: Any, params: types.PaginatedRequestParams
    ) -> types.ListResourcesResult:
        _require_modern_protocol(context.protocol_version)
        try:
            page = reader.list_local_mcp_resources(
                actor_context=config.actor_context,
                project_id=config.project_id,
                cursor=params.cursor,
            )
        except Exception:
            raise _resource_unavailable() from None
        return types.ListResourcesResult(
            resources=[
                types.Resource(
                    name=f"Governed GitHub Markdown: {resource.path}",
                    uri=resource.revision_uri,
                    mimeType="text/markdown",
                    _meta=resource.local_mcp_metadata(),
                )
                for resource in page.resources
            ],
            next_cursor=page.next_cursor,
            ttl_ms=0,
            cache_scope="private",
        )

    async def read_resource(
        context: Any, params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        _require_modern_protocol(context.protocol_version)
        if params.input_responses is not None or params.request_state is not None:
            raise _resource_unavailable()
        try:
            resource = reader.read_local_mcp_resource(
                actor_context=config.actor_context,
                project_id=config.project_id,
                revision_uri=params.uri,
            )
        except Exception:
            raise _resource_unavailable() from None
        if resource is None:
            raise _resource_unavailable()
        return types.ReadResourceResult(
            contents=[
                types.TextResourceContents(
                    uri=resource.revision_uri,
                    mimeType="text/markdown",
                    text=resource.content,
                    _meta=resource.local_mcp_metadata(),
                )
            ],
            ttl_ms=0,
            cache_scope="private",
        )

    server = Server(
        "governed-agent-harness-local-knowledge",
        version="0.1.0",
        title="Governed local knowledge",
        description="Actor-scoped cited untrusted Markdown resources.",
        on_list_resources=list_resources,
        on_read_resource=read_resource,
    )
    server.add_request_handler("server/discover", types.RequestParams, discover)
    server.middleware.append(_modern_only_middleware)
    return server


async def serve_local_mcp(*, config: LocalMcpConfig, runtime_connect: Callable[[], Any]) -> None:
    """Run exactly one local stdio MCP server without stdout diagnostics."""

    server = build_local_mcp_server(config=config, runtime_connect=runtime_connect)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main(argv: list[str] | None = None) -> int:
    """Start the local stdio server from trusted config and process environment only."""

    parser = argparse.ArgumentParser(description="Run local read-only governed knowledge MCP.")
    parser.add_argument("--config", required=True, help="owner-only local bootstrap JSON path")
    arguments = parser.parse_args(argv)
    try:
        config = load_local_mcp_config(arguments.config)
        runtime_connect = _runtime_connect_from_environment()
        anyio.run(partial(serve_local_mcp, config=config, runtime_connect=runtime_connect))
    except Exception:
        print(_SAFE_STARTUP_ERROR, file=sys.stderr)
        return 1
    return 0


async def _modern_only_middleware(context: Any, call_next: Any) -> Any:
    _require_modern_protocol(context.protocol_version)
    return await call_next(context)


def _require_modern_protocol(protocol_version: str | None) -> None:
    if protocol_version != _PROTOCOL_VERSION:
        raise MCPError(
            types.UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            {"supported": [_PROTOCOL_VERSION]},
        )


def _resource_unavailable() -> MCPError:
    return MCPError(types.INVALID_PARAMS, _SAFE_RESOURCE_ERROR)


def _runtime_connect_from_environment() -> Callable[[], Any]:
    dsn = os.environ.get("GAH_RUNTIME_DATABASE_DSN")
    if not isinstance(dsn, str) or not dsn or len(dsn) > 4096:
        raise LocalMcpBootstrapError("local MCP runtime database is unavailable")

    def connect() -> Any:
        import psycopg

        return psycopg.connect(dsn)

    return connect


def _read_owner_only_config(path: Path) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
        ):
            raise LocalMcpBootstrapError("local MCP bootstrap is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            current = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(current.st_mode)
                or stat.S_IMODE(current.st_mode) != 0o600
                or current.st_uid != os.geteuid()
                or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise LocalMcpBootstrapError("local MCP bootstrap is invalid")
            payload = handle.read(_CONFIG_MAX_BYTES + 1)
    except (OSError, ValueError) as error:
        raise LocalMcpBootstrapError("local MCP bootstrap is invalid") from error
    if not payload or len(payload) > _CONFIG_MAX_BYTES:
        raise LocalMcpBootstrapError("local MCP bootstrap is invalid")
    return payload


def _project_is_in_actor_authority(actor: Mapping[str, Any], project_id: str) -> bool:
    scope = actor.get("scope_authority")
    if not isinstance(scope, Mapping):
        return False
    allowed_levels = scope.get("allowed_levels")
    project_ids = scope.get("project_ids")
    return (
        isinstance(allowed_levels, list)
        and "project" in allowed_levels
        and isinstance(project_ids, list)
        and project_id in project_ids
    )


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess stdio tests.
    logging.basicConfig(
        stream=sys.stderr, level=logging.WARNING, format="%(levelname)s: %(message)s"
    )
    raise SystemExit(main())


__all__ = [
    "LocalMcpBootstrapError",
    "LocalMcpConfig",
    "build_local_mcp_server",
    "load_local_mcp_config",
    "main",
    "serve_local_mcp",
]
