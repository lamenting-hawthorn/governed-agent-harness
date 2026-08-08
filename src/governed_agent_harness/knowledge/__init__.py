"""Bounded, evidence-backed knowledge-source adapters.

The package intentionally contains no HTTP client, credential store, or
background worker.  Its one local MCP stdio adapter is read-only transport over
the actor-bound PostgreSQL retrieval authority; callers still supply a pinned
source revision through an injected adapter.
"""

from .github_markdown import (
    CitedGithubMarkdown,
    GithubMarkdownSourceError,
    GithubMarkdownResourcePage,
    ListedGithubMarkdown,
    PinnedGithubMarkdown,
    PinnedGithubMarkdownClient,
    PostgresGithubMarkdownAuthority,
    PostgresGithubMarkdownReader,
    RetrievedGithubMarkdown,
)

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
