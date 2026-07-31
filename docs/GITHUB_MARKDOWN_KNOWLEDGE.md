# Governed GitHub Markdown Knowledge

## Implemented boundary

Phase 5.2 is one deliberately small, PostgreSQL-backed knowledge path:

```text
application-owned pinned reader
  -> one GitHub owner/repository + full lowercase commit SHA + Markdown path
  -> immutable durable revision with canonical evidence and exact policy binding
  -> actor-scoped cited read-only retrieval
  -> resource-shaped, explicitly untrusted context
```

`PinnedGithubMarkdownClient` is injected by the application. The harness never
accepts a branch, tag, generic URL, or credential. The application resolves
authentication before it calls the client; neither a token nor a secret
reference is stored in this package or its PostgreSQL tables.

An import requires a canonical actor context, a bounded `authorize` decision
whose request digest covers the full source revision, and an evidence envelope.
The source identity is `github://owner/repository/path`; its immutable revision
is a full 40-character lowercase commit SHA. A changed SHA creates a distinct
revision. Re-importing is idempotent only when the complete import binding
(operation, run, source metadata, and policy decision) is identical. A changed
binding or different content under the same SHA fails closed. Expired revisions
return no content. The authority can logically revoke a source with separately
bound evidence; revocation removes every revision of that source from retrieval
and permanently rejects re-import. An operation ID is durably single-use for
this boundary: it cannot be rebound to another source or to a revocation.

The runtime role cannot call import or revocation functions and has no table
privileges. It can retrieve only records for the tenant/actor bound to its
database login. Results include the source identity, immutable revision URL,
content digest, classification, and evidence/payload citation. The source is an
input only as explicitly untrusted context and an output only as cited read-only
retrieval; it is neither executable nor a memory-promotion input.

The shared evidence ledger stores citation metadata and the source-content
digest, never a duplicate of the Markdown body. The generic actor-scoped event
read therefore cannot become a retention or revocation bypass: source content is
available only through the dedicated retrieval boundary, which checks revocation
and retention first.

## Explicit non-goals

This is not a general GitHub connector or a production company-brain service.
It does not provide GitHub HTTP/OAuth, webhook or polling sync, secret
brokerage, source ACL synchronization, physical deletion, proposal linking,
automatic memory promotion, embeddings, cross-actor sharing, an MCP server, or
hosted operations. `as_read_only_mcp_resource()` is a transport-neutral resource
shape, not an MCP transport implementation.

The approved delivery sequence is [local read-only MCP
first](LOCAL_FIRST_MCP_ROADMAP.md), then a local Git-checkout adapter, and only
then a secret-broker and connector-authority boundary for any live GitHub API
client. Source-ACL, deletion, retention, and revocation propagation must be
proven before background synchronization or further SaaS sources.
