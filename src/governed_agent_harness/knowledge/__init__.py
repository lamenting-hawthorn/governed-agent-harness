"""Bounded, evidence-backed knowledge-source adapters.

The package intentionally contains no HTTP client, credential store, background
worker, or MCP server.  Callers supply a pinned source revision through an
injected adapter; PostgreSQL is the authority for durable ingestion, revocation,
and actor-scoped retrieval.
"""

from .github_markdown import (
    CitedGithubMarkdown,
    GithubMarkdownSourceError,
    PinnedGithubMarkdown,
    PinnedGithubMarkdownClient,
    PostgresGithubMarkdownAuthority,
    PostgresGithubMarkdownReader,
    RetrievedGithubMarkdown,
)

__all__ = [
    "CitedGithubMarkdown",
    "GithubMarkdownSourceError",
    "PinnedGithubMarkdown",
    "PinnedGithubMarkdownClient",
    "PostgresGithubMarkdownAuthority",
    "PostgresGithubMarkdownReader",
    "RetrievedGithubMarkdown",
]
