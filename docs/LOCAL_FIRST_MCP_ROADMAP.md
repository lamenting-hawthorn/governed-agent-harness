# Local-first MCP roadmap

## Decision

The product is **local-first and cloud-portable**. A useful single-user path
MUST run on a developer-controlled machine without a managed account or
service. Self-hosted and managed-cloud deployments are later delivery modes,
not different authority models. A cloud deployment cannot gain a policy,
identity, evidence, or data-access privilege that the local contract does not
define.

This is a plan, not a claim that an MCP server, an embedded store, a live
GitHub connector, or any hosted deployment exists today. Phase 5.2 currently
provides only the bounded PostgreSQL source-to-retrieval boundary described in
[Governed GitHub Markdown knowledge](GITHUB_MARKDOWN_KNOWLEDGE.md).

## Fixed trust boundary

```text
untrusted source input
  -> immutable evidence-backed revision
  -> proposal-only linking (later, separately authorized)
  -> actor-scoped cited retrieval
  -> read-only MCP resource or tool result
```

- Source content is an **input** only as untrusted context. It cannot execute,
  alter policy, or silently become memory.
- Retrieval is an **output** only with its source, immutable revision,
  authority/scope, evidence citation, and freshness or expiry state.
- MCP is a transport for that governed output. It is not an authority boundary
  and it does not make tools in a host application governed.
- Automatic linking, promotion, background ingestion, and every write remain
  outside the first MCP slice.

## Deployment contract

| Mode | Intended use | Required semantic boundary |
| --- | --- | --- |
| Local | One trusted user and project on one machine. | Local identity, policy, evidence, retention, and cited retrieval work without a managed service. |
| Self-hosted | A team operates its own infrastructure. | Same public operations and policy/evidence bindings; deployment supplies authenticated identity, secrets, backups, and tenant controls. |
| Managed cloud | A provider operates the infrastructure. | The same public operations and policy/evidence bindings; managed identity or secrets never create an alternate privileged path. |

Local does not mean security-free: local identity depends on OS ownership and
restricted data permissions. It does mean that the default product workflow
does not require hosted control-plane access. The current Phase 5.2 proof is a
local PostgreSQL test boundary; embedded local storage remains planned and
must not be claimed as shipped.

## Delivery sequence

### L0 — current bounded source authority

Completed in Phase 5.2: an application-owned, credential-free reader supplies
one Markdown file at an immutable Git commit SHA. Import, retention, logical
revocation, and actor-scoped cited retrieval are PostgreSQL-governed. There is
no live GitHub API client, local Git reader, MCP transport, background worker,
or source ACL synchronization.

### L1 — local read-only MCP adapter

Build a `stdio` MCP server over the existing retrieval application service.
It is local-process only, read-only, and derives its actor from local process
ownership plus explicit project configuration; it never trusts an actor value
from a tool argument.

The first exposed surface is deliberately small:

- a resource listing only the actor-scoped knowledge records the caller may
  retrieve;
- a resource read returning the existing cited, untrusted resource shape; and
- optionally, one bounded read-only search tool if resource enumeration alone
  is insufficient.

Every result carries source identity, immutable revision, content digest,
classification, evidence citation, scope/authority, and freshness/expiry. A
missing, expired, or revoked revision is indistinguishable from unavailable
content to the MCP caller. There are no MCP write tools, approval-resolution
tools, raw-ledger reads, arbitrary source URLs, or connector credentials.

Use the [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
as the protocol baseline. The local server must declare only capabilities it
implements and test its published resource/tool schemas. Do not add Tasks,
MCP Apps, or a remote transport in L1.

### L2 — local repository source adapter

Add one read-only adapter for a user-provided local Git checkout. It resolves
only a full immutable commit SHA and a bounded Markdown path, then calls the
same L0 import command. It may use the user's existing local clone but does not
receive, persist, log, or forward a GitHub token. This makes the first useful
source workflow fully local even when the source originated in GitHub.

Acceptance evidence: forged refs, mutable branch/tag names, symlink/path
escapes, changed content at a claimed SHA, revoked content, cross-actor access,
and malformed resource requests all fail closed without mutation.

### L3 — live GitHub connector authority

Only after L2, introduce a connector authority and opaque secret-reference
boundary for a live GitHub API client. The harness receives neither raw token
nor secret value. Before polling, webhooks, or any background synchronization,
prove source-ACL propagation, retention/deletion/revocation propagation,
credential scope, egress restrictions, retries, rate/cost caps, and audit
receipts. Classification and links remain proposals until separately reviewed
and authorized.

### L4 — remote MCP deployment profiles

Add self-hosted and managed remote MCP only after the local surface has
conformance evidence. Remote requests authenticate on every request and map
credentials to canonical actor and tenant context; caller-supplied identity and
scope never decide access. Bearer tokens are audience-bound to this server and
are never forwarded to a connector or another MCP server.

Implement the 2026-07-28 stateless/discovery and cache semantics only for
declared capabilities. Auth-visible resource results are evaluated per request,
not per connection. Telemetry may carry trace context but never restricted
source content or secrets. Remote MCP begins with the same read-only resource
set as L1; network transport does not justify write tools or background work.

## Gates before each expansion

| Before | Required evidence |
| --- | --- |
| L1 merge | Local end-to-end MCP client test, actor-scope and revoked/expired negative tests, schema/capability conformance, and independent security review. |
| L2 merge | Real local Git fixture tests for immutable revision and path containment, plus zero-mutation failure tests. |
| L3 merge | Secret-broker and connector authority review; real GitHub integration test with a least-privilege test credential; ACL/deletion/revocation propagation evidence. |
| L4 merge | Remote authentication and audience-binding tests, tenant-leakage adversarial tests, stateless request tests, deployment recovery evidence, and separate self-hosted/managed operational proofs. |

Passing a lower gate does not prove a higher one: local proof is not hosted or
production proof, and a transport conformance test is not connector or access
control proof.

## Explicitly deferred

- MCP write operations, approval resolution, and raw evidence access.
- Automatic memory promotion, "compiled truth", or silent conflict resolution.
- Multi-SaaS ingestion, webhooks, polling, and autonomous background agents.
- MCP Tasks, Apps, and host-side execution claims.
- Any managed-cloud-only feature that changes the local authorization or
  evidence contract.
