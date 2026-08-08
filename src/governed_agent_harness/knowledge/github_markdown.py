"""One bounded GitHub-Markdown knowledge source.

The adapter is deliberately credential-free: an application-owned client may
fetch a *pinned* Git commit, but this module never accepts a branch name, token,
or generic URL.  Imported text remains untrusted context and is never routed to
an executor or promoted to governed memory automatically.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from governed_agent_harness.contracts import ActorContext, PolicyDecision, sha256_digest
from governed_agent_harness.persistence import DurableStoreError, PostgresDurableEffectStore

_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,98}/[A-Za-z0-9][A-Za-z0-9_.-]{0,98}")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_UUID_V7 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
_MAX_MARKDOWN_BYTES = 65_536
_SECRET_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{82,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
)


class GithubMarkdownSourceError(DurableStoreError):
    """A pinned-source boundary rejected the requested knowledge operation."""


class PinnedGithubMarkdownClient(Protocol):
    """Application-owned adapter for one immutable GitHub file revision.

    The caller must have resolved authentication and authorization outside this
    package.  ``commit_sha`` is always a full immutable Git object ID, never a
    branch, tag, or mutable default-ref alias.
    """

    def read_markdown(self, *, repository: str, commit_sha: str, path: str) -> str: ...


@dataclass(frozen=True, slots=True)
class PinnedGithubMarkdown:
    """A sanitized Markdown file at one immutable Git commit."""

    repository: str
    commit_sha: str
    path: str
    content: str
    classification: str
    retention_expires_at: str

    @classmethod
    def fetch(
        cls,
        *,
        client: PinnedGithubMarkdownClient,
        repository: str,
        commit_sha: str,
        path: str,
        classification: str,
        retention_expires_at: str,
    ) -> PinnedGithubMarkdown:
        """Read exactly one requested immutable revision through an injected client."""

        preliminary = cls(
            repository=repository,
            commit_sha=commit_sha,
            path=path,
            content="",
            classification=classification,
            retention_expires_at=retention_expires_at,
        )
        preliminary._validate_locator()
        content = client.read_markdown(
            repository=preliminary.repository,
            commit_sha=preliminary.commit_sha,
            path=preliminary.path,
        )
        source = cls(
            repository=repository,
            commit_sha=commit_sha,
            path=path,
            content=content,
            classification=classification,
            retention_expires_at=retention_expires_at,
        )
        source.validate()
        return source

    @property
    def source_identity(self) -> str:
        return f"github://{self.repository}/{self.path}"

    @property
    def revision_uri(self) -> str:
        return f"https://github.com/{self.repository}/blob/{self.commit_sha}/{self.path}"

    @property
    def content_digest(self) -> str:
        return sha256_digest({"content": self.content, "media_type": "text/markdown"})

    def operation_digest(self, operation_id: str) -> str:
        """Bind policy to one source identity, content digest, and import operation."""

        return sha256_digest({"operation_id": operation_id, "source": self.to_dict()})

    def to_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "source_identity": self.source_identity,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "path": self.path,
            "revision_uri": self.revision_uri,
            "media_type": "text/markdown",
            "content": self.content,
            "content_digest": self.content_digest,
            "classification": self.classification,
            "retention_expires_at": self.retention_expires_at,
        }

    def validate(self) -> None:
        self._validate_locator()
        if not isinstance(self.content, str):
            raise GithubMarkdownSourceError("GitHub source content must be text")
        try:
            encoded = self.content.encode("utf-8")
        except UnicodeError as error:
            raise GithubMarkdownSourceError("GitHub source content is not UTF-8") from error
        if not self.content or len(encoded) > _MAX_MARKDOWN_BYTES:
            raise GithubMarkdownSourceError(
                "GitHub Markdown content exceeds the bounded source limit"
            )
        if "\x00" in self.content:
            raise GithubMarkdownSourceError(
                "GitHub Markdown content contains a forbidden control character"
            )
        if any(pattern.search(self.content) for pattern in _SECRET_PATTERNS):
            raise GithubMarkdownSourceError(
                "GitHub Markdown content appears to contain credential material"
            )
        if self.classification not in {"public", "internal", "confidential", "restricted"}:
            raise GithubMarkdownSourceError("GitHub source classification is unsupported")
        if not isinstance(self.retention_expires_at, str) or not _TIMESTAMP.fullmatch(
            self.retention_expires_at
        ):
            raise GithubMarkdownSourceError("GitHub source retention expiry is malformed")
        try:
            parsed = datetime.fromisoformat(self.retention_expires_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise GithubMarkdownSourceError(
                "GitHub source retention expiry is malformed"
            ) from error
        if parsed.tzinfo is None:
            raise GithubMarkdownSourceError("GitHub source retention expiry is malformed")

    def _validate_locator(self) -> None:
        if not isinstance(self.repository, str) or _REPOSITORY.fullmatch(self.repository) is None:
            raise GithubMarkdownSourceError("GitHub repository must be one owner/name identifier")
        if not isinstance(self.commit_sha, str) or _COMMIT_SHA.fullmatch(self.commit_sha) is None:
            raise GithubMarkdownSourceError("GitHub source must use one full lowercase commit SHA")
        if not isinstance(self.path, str) or not self.path.endswith((".md", ".markdown")):
            raise GithubMarkdownSourceError("GitHub source path must be one Markdown file")
        if len(self.path.encode("utf-8")) > 1024:
            raise GithubMarkdownSourceError("GitHub source path exceeds the bounded source limit")
        parts = self.path.split("/")
        if (
            not parts
            or any(not _PATH_SEGMENT.fullmatch(part) for part in parts)
            or any(part in {".", ".."} for part in parts)
        ):
            raise GithubMarkdownSourceError("GitHub source path is malformed")


@dataclass(frozen=True, slots=True)
class CitedGithubMarkdown:
    """Read-only result deliberately labeled as untrusted external context."""

    source_identity: str
    revision_uri: str
    repository: str
    commit_sha: str
    path: str
    content: str
    content_digest: str
    classification: str
    citation: Mapping[str, str]
    imported_at: str | None = None
    retention_expires_at: str | None = None
    freshness_checked_at: str | None = None

    @property
    def is_untrusted_context(self) -> bool:
        return True

    def as_read_only_mcp_resource(self) -> dict[str, Any]:
        """Return an MCP-compatible resource shape without starting an MCP server."""

        metadata: dict[str, Any] = {
            "source_identity": self.source_identity,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "path": self.path,
            "content_digest": self.content_digest,
            "classification": self.classification,
            "citation": dict(self.citation),
            "untrusted_context": True,
            "read_only": True,
        }
        if self.imported_at is not None:
            metadata.update(self.local_mcp_metadata())
        return {
            "uri": self.revision_uri,
            "mimeType": "text/markdown",
            "text": self.content,
            "metadata": metadata,
        }

    def local_mcp_metadata(self) -> dict[str, Any]:
        """Return metadata permitted on the local MCP resource transport."""

        if (
            self.imported_at is None
            or self.retention_expires_at is None
            or self.freshness_checked_at is None
        ):
            raise GithubMarkdownSourceError("GitHub knowledge resource metadata is unavailable")
        return _local_mcp_metadata(
            source_identity=self.source_identity,
            repository=self.repository,
            commit_sha=self.commit_sha,
            path=self.path,
            content_digest=self.content_digest,
            classification=self.classification,
            citation=self.citation,
            imported_at=self.imported_at,
            retention_expires_at=self.retention_expires_at,
            freshness_checked_at=self.freshness_checked_at,
        )


@dataclass(frozen=True, slots=True)
class ListedGithubMarkdown:
    """Content-free metadata for one local MCP resource-list entry."""

    source_identity: str
    revision_uri: str
    repository: str
    commit_sha: str
    path: str
    content_digest: str
    classification: str
    citation: Mapping[str, str]
    imported_at: str
    retention_expires_at: str
    freshness_checked_at: str

    def local_mcp_metadata(self) -> dict[str, Any]:
        return _local_mcp_metadata(
            source_identity=self.source_identity,
            repository=self.repository,
            commit_sha=self.commit_sha,
            path=self.path,
            content_digest=self.content_digest,
            classification=self.classification,
            citation=self.citation,
            imported_at=self.imported_at,
            retention_expires_at=self.retention_expires_at,
            freshness_checked_at=self.freshness_checked_at,
        )


@dataclass(frozen=True, slots=True)
class GithubMarkdownResourcePage:
    """A bounded actor-scoped local-MCP resource page."""

    resources: tuple[ListedGithubMarkdown, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class RetrievedGithubMarkdown:
    result: CitedGithubMarkdown
    replayed: bool = False


class PostgresGithubMarkdownAuthority:
    """Authority-only durable import and logical-revocation boundary."""

    def __init__(
        self,
        *,
        privileged_connect: Callable[[], Any],
        clock: Callable[[], datetime],
        ids: Callable[[], str],
    ) -> None:
        self._connect = privileged_connect
        self._clock = clock
        self._store = PostgresDurableEffectStore(
            connect=privileged_connect,
            privileged_connect=privileged_connect,
            clock=clock,
            ids=ids,
        )

    def import_markdown(
        self,
        *,
        actor_context: Mapping[str, Any],
        operation_id: str,
        run_id: str,
        source: PinnedGithubMarkdown,
        policy_decision: Mapping[str, Any],
    ) -> RetrievedGithubMarkdown:
        actor = ActorContext(actor_context).to_dict()
        source.validate()
        _validate_uuid(operation_id, "GitHub import operation_id")
        _validate_uuid(run_id, "GitHub import run_id")
        policy = _validate_import_policy(
            policy_decision=policy_decision,
            actor=actor,
            operation_id=operation_id,
            operation_digest=source.operation_digest(operation_id),
            now=self._clock(),
        )
        payload = {
            "operation_id": operation_id,
            "operation_digest": source.operation_digest(operation_id),
            "run_id": run_id,
            "source": source.to_dict(),
            "policy_decision": policy,
        }
        import_binding_digest = sha256_digest(payload)
        existing = self._lookup_revision(
            actor=actor,
            source=source,
            import_binding_digest=import_binding_digest,
        )
        if existing is not None:
            return RetrievedGithubMarkdown(existing, replayed=True)
        policy_ref = _policy_ref(policy)
        evidence_payload = {
            "actor_id": actor["actor_id"],
            "operation_id": operation_id,
            "operation_digest": payload["operation_digest"],
            "source": _evidence_source_metadata(payload["source"]),
            "policy_decision_digest": policy["decision_digest"],
        }
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                evidence = self._store._prepare_evidence(
                    cursor=cursor,
                    actor=actor,
                    run_id=run_id,
                    event_kind="knowledge.github_markdown_imported",
                    policy_ref=policy_ref,
                    payload=evidence_payload,
                )
                cursor.execute(
                    "SELECT gah_import_github_markdown(%s::jsonb,%s::jsonb,%s::jsonb)",
                    (_json(actor), _json(payload), _json(evidence)),
                )
                row = cursor.fetchone()
        except Exception as error:
            if "github markdown revision already exists" not in str(error).lower():
                raise
            raced = self._lookup_revision(
                actor=actor,
                source=source,
                import_binding_digest=import_binding_digest,
            )
            if raced is None:
                raise GithubMarkdownSourceError(
                    "GitHub import replay could not be recovered"
                ) from error
            return RetrievedGithubMarkdown(raced, replayed=True)
        if row is None or not isinstance(row[0], dict):
            raise GithubMarkdownSourceError("GitHub source import returned malformed data")
        return RetrievedGithubMarkdown(_cited(row[0]))

    def revoke_source(
        self,
        *,
        actor_context: Mapping[str, Any],
        operation_id: str,
        run_id: str,
        source_identity: str,
        policy_decision: Mapping[str, Any],
    ) -> bool:
        actor = ActorContext(actor_context).to_dict()
        _validate_uuid(operation_id, "GitHub revocation operation_id")
        _validate_uuid(run_id, "GitHub revocation run_id")
        _validate_source_identity(source_identity)
        operation_digest = sha256_digest(
            {"operation_id": operation_id, "source_identity": source_identity}
        )
        policy = _validate_import_policy(
            policy_decision=policy_decision,
            actor=actor,
            operation_id=operation_id,
            operation_digest=operation_digest,
            now=self._clock(),
        )
        payload = {
            "operation_id": operation_id,
            "operation_digest": operation_digest,
            "run_id": run_id,
            "source_identity": source_identity,
            "policy_decision": policy,
        }
        evidence_payload = {
            "actor_id": actor["actor_id"],
            "operation_id": operation_id,
            "operation_digest": operation_digest,
            "source_identity": source_identity,
            "policy_decision_digest": policy["decision_digest"],
        }
        with self._connect() as connection, connection.cursor() as cursor:
            evidence = self._store._prepare_evidence(
                cursor=cursor,
                actor=actor,
                run_id=run_id,
                event_kind="knowledge.github_markdown_revoked",
                policy_ref=_policy_ref(policy),
                payload=evidence_payload,
            )
            cursor.execute(
                "SELECT gah_revoke_github_markdown_source(%s::jsonb,%s::jsonb,%s::jsonb)",
                (_json(actor), _json(payload), _json(evidence)),
            )
            row = cursor.fetchone()
        if row is None or row[0] is not True:
            raise GithubMarkdownSourceError("GitHub source revocation returned malformed data")
        return True

    def _lookup_revision(
        self,
        *,
        actor: Mapping[str, Any],
        source: PinnedGithubMarkdown,
        import_binding_digest: str,
    ) -> CitedGithubMarkdown | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_lookup_github_markdown_revision(%s::jsonb,%s,%s,%s,%s)",
                (
                    _json(actor),
                    source.source_identity,
                    source.commit_sha,
                    source.content_digest,
                    import_binding_digest,
                ),
            )
            row = cursor.fetchone()
        if row is None or row[0] is None:
            return None
        if not isinstance(row[0], dict):
            raise GithubMarkdownSourceError("GitHub source replay returned malformed data")
        return _cited(row[0])


class PostgresGithubMarkdownReader:
    """Runtime-only actor-scoped cited retrieval boundary."""

    def __init__(self, *, runtime_connect: Callable[[], Any]) -> None:
        self._connect = runtime_connect

    def retrieve(
        self,
        *,
        actor_context: Mapping[str, Any],
        query: str,
        max_results: int = 10,
    ) -> tuple[CitedGithubMarkdown, ...]:
        actor = ActorContext(actor_context).to_dict()
        if not isinstance(query, str) or not query.strip() or len(query) > 256:
            raise GithubMarkdownSourceError("GitHub knowledge query is malformed")
        if (
            isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= 10
        ):
            raise GithubMarkdownSourceError("GitHub knowledge result limit is malformed")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gah_retrieve_github_markdown(%s::jsonb,%s,%s)",
                (_json(actor), query, max_results),
            )
            row = cursor.fetchone()
        value = row[0] if row is not None else []
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise GithubMarkdownSourceError("GitHub knowledge retrieval returned malformed data")
        return tuple(_cited(item) for item in value)

    def verify_local_mcp_bootstrap(
        self, *, actor_context: Mapping[str, Any], project_id: str
    ) -> None:
        """Prove a local bootstrap is bound to a runtime-only database principal."""

        actor = ActorContext(actor_context).to_dict()
        _validate_project_id(project_id)
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                _open_read_only_runtime_transaction(cursor)
                cursor.execute(
                    "SELECT gah_mcp_assert_local_actor(%s::jsonb,%s)",
                    (_json(actor), project_id),
                )
        except Exception as error:
            raise GithubMarkdownSourceError("local MCP bootstrap is unavailable") from error

    def list_local_mcp_resources(
        self,
        *,
        actor_context: Mapping[str, Any],
        project_id: str,
        cursor: str | None = None,
        page_size: int = 25,
    ) -> GithubMarkdownResourcePage:
        """List content-free resources through the current DB authority binding."""

        actor = ActorContext(actor_context).to_dict()
        _validate_project_id(project_id)
        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= 50
        ):
            raise GithubMarkdownSourceError("local MCP resource page limit is malformed")
        after = _decode_local_mcp_cursor(cursor)
        try:
            with self._connect() as connection, connection.cursor() as database_cursor:
                _open_read_only_runtime_transaction(database_cursor)
                database_cursor.execute(
                    "SELECT gah_list_github_markdown_mcp_resources("
                    "%s::jsonb,%s,%s::timestamptz,%s,%s,%s)",
                    (
                        _json(actor),
                        project_id,
                        after["imported_at"] if after is not None else None,
                        after["source_identity"] if after is not None else None,
                        after["commit_sha"] if after is not None else None,
                        page_size,
                    ),
                )
                row = database_cursor.fetchone()
        except Exception as error:
            raise GithubMarkdownSourceError("local MCP resource list is unavailable") from error
        value = row[0] if row is not None else []
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise GithubMarkdownSourceError("local MCP resource list is unavailable")
        listed = tuple(_listed(item) for item in value)
        visible = listed[:page_size]
        next_cursor = _encode_local_mcp_cursor(visible[-1]) if len(listed) > page_size else None
        return GithubMarkdownResourcePage(resources=visible, next_cursor=next_cursor)

    def read_local_mcp_resource(
        self,
        *,
        actor_context: Mapping[str, Any],
        project_id: str,
        revision_uri: str,
    ) -> CitedGithubMarkdown | None:
        """Read one exact immutable URI or return no resource without a visibility leak."""

        actor = ActorContext(actor_context).to_dict()
        _validate_project_id(project_id)
        if not isinstance(revision_uri, str) or not revision_uri or len(revision_uri) > 2048:
            return None
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                _open_read_only_runtime_transaction(cursor)
                cursor.execute(
                    "SELECT gah_read_github_markdown_mcp_resource(%s::jsonb,%s,%s)",
                    (_json(actor), project_id, revision_uri),
                )
                row = cursor.fetchone()
        except Exception as error:
            raise GithubMarkdownSourceError("local MCP resource is unavailable") from error
        if row is None or row[0] is None:
            return None
        if not isinstance(row[0], dict):
            raise GithubMarkdownSourceError("local MCP resource is unavailable")
        return _local_mcp_cited(row[0])


def _validate_import_policy(
    *,
    policy_decision: Mapping[str, Any],
    actor: Mapping[str, Any],
    operation_id: str,
    operation_digest: str,
    now: datetime,
) -> dict[str, Any]:
    policy = PolicyDecision(policy_decision, expected_tenant=actor["tenant_id"]).to_dict()
    if (
        policy["request_id"] != operation_id
        or policy["request_digest"] != operation_digest
        or policy["decision"] != "authorize"
        or policy["constraints"] != []
        or policy["isolation_profile"] != "no_effect"
    ):
        raise GithubMarkdownSourceError(
            "GitHub source policy is not an exact bounded authorization"
        )
    try:
        decided_at = datetime.fromisoformat(policy["decided_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise GithubMarkdownSourceError("GitHub source policy timestamp is malformed") from error
    current = now.astimezone(timezone.utc)
    if decided_at > current:
        raise GithubMarkdownSourceError("GitHub source policy is from the future")
    return policy


def _policy_ref(policy: Mapping[str, Any]) -> dict[str, str]:
    return {
        "record_type": "policy_decision",
        "record_id": policy["decision_id"],
        "record_digest": policy["decision_digest"],
    }


def _evidence_source_metadata(source: Mapping[str, Any]) -> dict[str, Any]:
    """Retain citation metadata in the shared ledger without duplicating source text."""

    return {key: value for key, value in source.items() if key != "content"}


def _cited(value: Mapping[str, Any]) -> CitedGithubMarkdown:
    citation = value.get("citation")
    fields = (
        "source_identity",
        "revision_uri",
        "repository",
        "commit_sha",
        "path",
        "content",
        "content_digest",
        "classification",
    )
    if (
        not isinstance(citation, Mapping)
        or set(citation) != {"evidence_id", "payload_digest"}
        or any(not isinstance(citation.get(field), str) for field in citation)
    ):
        raise GithubMarkdownSourceError("GitHub knowledge result has an invalid citation")
    if any(not isinstance(value.get(field), str) for field in fields):
        raise GithubMarkdownSourceError("GitHub knowledge result is malformed")
    return CitedGithubMarkdown(
        source_identity=value["source_identity"],
        revision_uri=value["revision_uri"],
        repository=value["repository"],
        commit_sha=value["commit_sha"],
        path=value["path"],
        content=value["content"],
        content_digest=value["content_digest"],
        classification=value["classification"],
        citation={
            "evidence_id": citation["evidence_id"],
            "payload_digest": citation["payload_digest"],
        },
    )


def _listed(value: Mapping[str, Any]) -> ListedGithubMarkdown:
    fields = (
        "source_identity",
        "revision_uri",
        "repository",
        "commit_sha",
        "path",
        "content_digest",
        "classification",
        "imported_at",
        "retention_expires_at",
        "freshness_checked_at",
    )
    _validate_local_mcp_result(value, fields=fields)
    return ListedGithubMarkdown(
        source_identity=value["source_identity"],
        revision_uri=value["revision_uri"],
        repository=value["repository"],
        commit_sha=value["commit_sha"],
        path=value["path"],
        content_digest=value["content_digest"],
        classification=value["classification"],
        citation={
            "evidence_id": value["citation"]["evidence_id"],
            "payload_digest": value["citation"]["payload_digest"],
        },
        imported_at=value["imported_at"],
        retention_expires_at=value["retention_expires_at"],
        freshness_checked_at=value["freshness_checked_at"],
    )


def _local_mcp_cited(value: Mapping[str, Any]) -> CitedGithubMarkdown:
    fields = (
        "source_identity",
        "revision_uri",
        "repository",
        "commit_sha",
        "path",
        "content",
        "content_digest",
        "classification",
        "imported_at",
        "retention_expires_at",
        "freshness_checked_at",
    )
    _validate_local_mcp_result(value, fields=fields)
    return CitedGithubMarkdown(
        source_identity=value["source_identity"],
        revision_uri=value["revision_uri"],
        repository=value["repository"],
        commit_sha=value["commit_sha"],
        path=value["path"],
        content=value["content"],
        content_digest=value["content_digest"],
        classification=value["classification"],
        citation={
            "evidence_id": value["citation"]["evidence_id"],
            "payload_digest": value["citation"]["payload_digest"],
        },
        imported_at=value["imported_at"],
        retention_expires_at=value["retention_expires_at"],
        freshness_checked_at=value["freshness_checked_at"],
    )


def _validate_local_mcp_result(value: Mapping[str, Any], *, fields: tuple[str, ...]) -> None:
    citation = value.get("citation")
    if (
        not isinstance(citation, Mapping)
        or set(citation) != {"evidence_id", "payload_digest"}
        or any(not isinstance(citation.get(field), str) for field in citation)
        or any(not isinstance(value.get(field), str) for field in fields)
    ):
        raise GithubMarkdownSourceError("local MCP resource is unavailable")
    _validate_source_identity(value["source_identity"])
    try:
        PinnedGithubMarkdown(
            repository=value["repository"],
            commit_sha=value["commit_sha"],
            path=value["path"],
            content="x",
            classification=value["classification"],
            retention_expires_at=value["retention_expires_at"],
        )._validate_locator()
    except GithubMarkdownSourceError as error:
        raise GithubMarkdownSourceError("local MCP resource is unavailable") from error
    if value["source_identity"] != f"github://{value['repository']}/{value['path']}":
        raise GithubMarkdownSourceError("local MCP resource is unavailable")
    if value["revision_uri"] != (
        f"https://github.com/{value['repository']}/blob/{value['commit_sha']}/{value['path']}"
    ):
        raise GithubMarkdownSourceError("local MCP resource is unavailable")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value["content_digest"]):
        raise GithubMarkdownSourceError("local MCP resource is unavailable")
    if value["classification"] not in {"public", "internal", "confidential", "restricted"}:
        raise GithubMarkdownSourceError("local MCP resource is unavailable")
    for field in ("imported_at", "retention_expires_at", "freshness_checked_at"):
        _validate_utc_timestamp(value[field], "local MCP resource")


def _local_mcp_metadata(
    *,
    source_identity: str,
    repository: str,
    commit_sha: str,
    path: str,
    content_digest: str,
    classification: str,
    citation: Mapping[str, str],
    imported_at: str,
    retention_expires_at: str,
    freshness_checked_at: str,
) -> dict[str, Any]:
    return {
        "source_identity": source_identity,
        "repository": repository,
        "commit_sha": commit_sha,
        "path": path,
        "content_digest": content_digest,
        "classification": classification,
        "citation": dict(citation),
        "untrusted_context": True,
        "read_only": True,
        "scope": "actor-scoped",
        "authority": "database-runtime-principal-bound",
        "imported_at": imported_at,
        "retention_enforced": True,
        "expires_at": retention_expires_at,
        "freshness": {
            "state": "eligible_at_read",
            "checked_at": freshness_checked_at,
        },
    }


def _encode_local_mcp_cursor(resource: ListedGithubMarkdown) -> str:
    payload = json.dumps(
        {
            "commit_sha": resource.commit_sha,
            "imported_at": resource.imported_at,
            "source_identity": resource.source_identity,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode_local_mcp_cursor(cursor: str | None) -> dict[str, str] | None:
    if cursor is None:
        return None
    if (
        not isinstance(cursor, str)
        or not cursor
        or len(cursor) > 512
        or re.fullmatch(r"[A-Za-z0-9_-]+", cursor) is None
    ):
        raise GithubMarkdownSourceError("local MCP resource cursor is malformed")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(
            base64.urlsafe_b64decode(padded.encode("ascii")), object_pairs_hook=_unique_object
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise GithubMarkdownSourceError("local MCP resource cursor is malformed") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"commit_sha", "imported_at", "source_identity"}
        or any(not isinstance(item, str) for item in value.values())
    ):
        raise GithubMarkdownSourceError("local MCP resource cursor is malformed")
    _validate_source_identity(value["source_identity"])
    if _COMMIT_SHA.fullmatch(value["commit_sha"]) is None:
        raise GithubMarkdownSourceError("local MCP resource cursor is malformed")
    _validate_utc_timestamp(value["imported_at"], "local MCP resource cursor")
    return value


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_project_id(project_id: str) -> None:
    if not isinstance(project_id, str) or _UUID_V7.fullmatch(project_id) is None:
        raise GithubMarkdownSourceError("local MCP project identifier is malformed")


def _validate_utc_timestamp(value: str, label: str) -> None:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise GithubMarkdownSourceError(f"{label} timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GithubMarkdownSourceError(f"{label} timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise GithubMarkdownSourceError(f"{label} timestamp is malformed")


def _open_read_only_runtime_transaction(cursor: Any) -> None:
    """Reject a privileged or writable connection before every L1 read."""

    cursor.execute("SET TRANSACTION READ ONLY")
    cursor.execute(
        "SELECT current_user = session_user, "
        "(SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb "
        "AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls "
        "FROM pg_catalog.pg_roles WHERE rolname = session_user), "
        "pg_catalog.pg_has_role(session_user, 'gah_runtime', 'MEMBER'), "
        "pg_catalog.pg_has_role(session_user, 'gah_authority_writer', 'MEMBER'), "
        "pg_catalog.pg_has_role(session_user, 'gah_skill_lifecycle_authority', 'MEMBER'), "
        "pg_catalog.pg_has_role(session_user, 'gah_execution_admission_authority', 'MEMBER')"
    )
    if cursor.fetchone() != (True, True, True, False, False, False):
        raise GithubMarkdownSourceError("local MCP runtime principal is unavailable")


def _validate_uuid(value: str, label: str) -> None:
    if not isinstance(value, str) or _UUID_V7.fullmatch(value) is None:
        raise GithubMarkdownSourceError(f"{label} must be a UUIDv7")


def _validate_source_identity(value: str) -> None:
    if not isinstance(value, str) or not value.startswith("github://"):
        raise GithubMarkdownSourceError("GitHub source identity is malformed")
    remainder = value.removeprefix("github://")
    parts = remainder.split("/")
    if len(parts) < 3:
        raise GithubMarkdownSourceError("GitHub source identity is malformed")
    repository = "/".join(parts[:2])
    path = "/".join(parts[2:])
    try:
        PinnedGithubMarkdown(
            repository=repository,
            commit_sha="0" * 40,
            path=path,
            content="x",
            classification="internal",
            retention_expires_at="2099-01-01T00:00:00.000Z",
        )._validate_locator()
    except GithubMarkdownSourceError as error:
        raise GithubMarkdownSourceError("GitHub source identity is malformed") from error


def _json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


__all__ = [
    "CitedGithubMarkdown",
    "GithubMarkdownSourceError",
    "GithubMarkdownResourcePage",
    "ListedGithubMarkdown",
    "PinnedGithubMarkdown",
    "PinnedGithubMarkdownClient",
    "PostgresGithubMarkdownAuthority",
    "PostgresGithubMarkdownReader",
    "RetrievedGithubMarkdown",
]
