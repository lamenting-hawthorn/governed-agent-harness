# Governed GitHub Markdown Knowledge

## Implemented boundary

Phase 5.2 is one deliberately small, PostgreSQL-backed knowledge path:

```text
application-owned pinned reader
  -> one GitHub owner/repository + full lowercase commit SHA + Markdown path
  -> immutable durable revision with canonical evidence and exact policy binding
    -> actor-scoped cited read-only retrieval
    -> local-only read-only MCP stdio resource
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

Phase 5.3 adds a local-process-only MCP 2026-07-28 stdio adapter. Its trusted
bootstrap is an owner-only (`0600`), regular, non-symlink JSON file containing
exactly a version, one UUIDv7 project ID, and a complete canonical
`ActorContext`; the project must be in that context's project authority. The
runtime DSN comes only from `GAH_RUNTIME_DATABASE_DSN`, never from the config
or an MCP request. Each list and exact immutable-URI read opens a read-only
runtime transaction and re-checks the actor/project against the
database-login binding, logical revocation, and retention expiry. MCP request
data therefore cannot choose an actor, tenant, database credential, role,
policy, or source scope.

The only advertised capabilities are `resources/list` and `resources/read`.
Listing is bounded and content-free; exact reads return the Markdown body with
safe MCP `_meta`: source identity, immutable revision URI/SHA, digest,
classification, citation, generic actor-scoped/database-bound authority
semantics, import time, retention expiry, and freshness check time. Both
responses use `ttlMs: 0` and `cacheScope: private`. Unknown, malformed,
cross-actor, expired, and revoked URIs all return the same JSON-RPC `-32602`
`Resource unavailable` result. Stdout carries MCP protocol messages only;
sanitized startup diagnostics use stderr.

For a local bootstrap already provisioned with the existing runtime principal,
write the full canonical actor record to a protected file and start the server:

```json
{
  "version": 1,
  "project_id": "<project-uuidv7-present-in-actor-context>",
  "actor_context": "<complete canonical ActorContext object>"
}
```

```console
chmod 600 .gah/local-mcp.json
export GAH_RUNTIME_DATABASE_DSN='<local runtime DSN>'
python -m governed_agent_harness.knowledge.local_mcp --config .gah/local-mcp.json
```

The quoted `actor_context` line above is explanatory shorthand, not a valid
config fragment: replace it with the full validated JSON object. Keep the
runtime DSN in the process environment and out of shell history, source files,
and logs.

## Explicit non-goals

This is not a general GitHub connector or a production company-brain service.
It does not provide GitHub HTTP/OAuth, webhook or polling sync, secret
brokerage, source ACL synchronization, physical deletion, proposal linking,
automatic memory promotion, embeddings, cross-actor sharing, remote MCP,
HTTP, hosted operations, resource templates, subscriptions, prompts, tools,
Tasks, Apps, logging controls, raw ledger access, or write operations.
`as_read_only_mcp_resource()` remains a transport-neutral resource shape; the
implemented stdio adapter exposes only the separately documented L1 resource
surface above.

The approved delivery sequence is [local read-only MCP
first](LOCAL_FIRST_MCP_ROADMAP.md), then a local Git-checkout adapter, and only
then a secret-broker and connector-authority boundary for any live GitHub API
client. Source-ACL, deletion, retention, and revocation propagation must be
proven before background synchronization or further SaaS sources.
