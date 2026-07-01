# Threat Model

## Scope

This threat model covers the governance kernel, execution-engine adapters,
tool broker and sandbox, identity and policy services, memory and knowledge
providers, skills, evidence ledger, APIs, CLI, telemetry, and learning imports.
It must be updated when a trust boundary, data flow, provider, or enforcement
tier changes.

This is a design-time threat model, not a certification or claim that all
listed mitigations are implemented.

## Assets

- User and tenant data, prompts, files, messages, and knowledge.
- Credentials, model-provider keys, tool capabilities, and approvals.
- Policy definitions, actor roles, and capability manifests.
- Memory records, source evidence, revisions, and deletion state.
- Skills, adapters, learning artifacts, and release packages.
- Audit ledger integrity and availability.
- Host resources, external systems, money, and reputation affected by tools.

## Adversaries

- An unauthenticated remote caller.
- An authenticated user attempting privilege or tenant escalation.
- Malicious or compromised content source, webpage, document, or tool output.
- A model producing unsafe, deceptive, or malformed output.
- A malicious skill, adapter, dependency, package publisher, or update.
- A compromised provider or operator credential.
- An insider misusing legitimate administrative access.
- Accidental misuse, faulty policy, configuration drift, and software defects.

## Security invariants

1. No protected effect occurs without a valid, current policy decision bound to
   the normalized request and actor context.
2. No tenant-scoped read or write crosses tenant boundaries.
3. No memory becomes trusted without source evidence and policy disposition.
4. No learning artifact mutates live behavior automatically.
5. No skill gains permissions merely by being installed or selected.
6. No secret enters model context or telemetry by default.
7. Every governed request, decision, approval, and outcome is attributable and
   integrity-linked.
8. Unsupported enforcement is disclosed, not simulated.

## Primary threats and controls

| Threat | Attack path and impact | Required preventive controls | Required detection/tests |
| --- | --- | --- | --- |
| Prompt injection | Retrieved content instructs the model to disclose data or invoke tools | Treat content as data; isolate instructions from evidence; gate every effect; classify egress | Injection corpus, canary secrets, unexpected tool/egress alerts |
| Indirect injection through tool output | Tool returns instructions that influence later actions | Label provenance and trust; do not elevate tool output; re-evaluate subsequent effects | Chained-tool adversarial E2E tests |
| Memory poisoning | Attacker causes false, malicious, or cross-scope memory to be committed | Evidence requirement, authority/confidence fields, deduplication, conflict detection, policy/human review, supersession | Poisoning corpus, provenance queries, anomalous promotion metrics |
| Tool bypass | Engine, extension, or skill invokes side effects outside the broker | Capability-limited engine API, no raw effect handles, broker-only tools, network/filesystem containment | Direct-call negative tests, process/network monitoring |
| Approval replay or mutation | Approved arguments are changed or approval is reused | Hash normalized request and actor; nonce, expiry, single-use record, atomic consume | Replay, TOCTOU, mutation, concurrency tests |
| Tenant escape | Missing filter, shared cache, service role, or forged actor exposes another tenant | Trusted actor context, deny-by-default authorization, storage policies, scoped cache keys, separate service identities | Cross-tenant matrix tests and audit alerts |
| Secret exfiltration | Prompt, tool, error, trace, or child process leaks a credential | Opaque handles, late injection, egress policy, structured redaction, environment isolation | Canary credentials, snapshot scans, log export tests |
| Path traversal/symlink race | Crafted path writes or reads outside allowed root | Canonicalize at sink, descriptor-relative operations where available, no-follow semantics, mount isolation | Traversal, symlink, race, platform tests |
| SSRF/network pivot | Tool reaches metadata, localhost, internal network, or redirect target | Network deny-by-default, DNS/IP validation at every hop, destination policy, sandbox network boundary | DNS rebinding, redirect, IPv4/IPv6, metadata tests |
| Command/code injection | Untrusted arguments enter shell or interpreter | Structured process API, no shell by default, schema validation, argument boundaries, sandbox | Injection corpus and fuzzing |
| Denial of service/cost abuse | Recursive agent/tool use exhausts compute, tokens, storage, or budget | Per-run budgets, quotas, depth and concurrency caps, timeouts, backpressure | Load, cancellation, quota, retry-storm tests |
| Evidence tampering | Attacker edits/deletes/reorders audit events | Append-only authorization, hash chaining or signed checkpoints, restricted administration, external export | Integrity verifier, gap/sequence alerts, restore tests |
| Audit disclosure | Evidence contains prompts, secrets, or PII readable too broadly | Data minimization, field classification, encryption, scoped access, redacted views | Authorization and redaction tests |
| Skill/package compromise | Typosquat or update gains code execution and permissions | Registry trust policy, lockfiles, hashes/signatures, explicit permissions, review and rollback | SBOM/scans, install conformance, compromised fixture |
| Policy tampering or downgrade | Attacker changes policy or selects weaker version | Signed/versioned policy, restricted changes, four-eyes approval for high risk, decision records | Policy-diff alerts, downgrade tests |
| Confused deputy | Service credential performs action beyond caller authority | Delegation with actor and resource binding, intersection of caller/service permissions | Delegation matrix tests |
| Provider compromise | Model, memory, telemetry, or identity provider leaks or alters data | Minimize shared data, TLS, scoped credentials, integrity validation, provider isolation, exit plan | Contract tests, anomaly alerts, credential rotation drill |
| Learning artifact poisoning | Crafted trace produces unsafe skill/policy/memory update | Quarantine, provenance verification, schema and eval gates, human approval, versioned install, rollback | Malicious artifact fixtures and rollback E2E |
| Deletion resurrection | Deleted data remains in projection, cache, backup, or derived memory | Tombstones, lineage graph, cache invalidation, backup expiry, deletion verification | End-to-end erasure tests and sampled audits |

## Abuse cases by enforcement tier

- **Observe:** users may incorrectly assume prevention. Products must label this
  as post-hoc visibility and show effects that cannot be intercepted.
- **Advise:** the engine may ignore advice. Advice failure must not be recorded
  as policy enforcement.
- **Gate:** a covered request may still escape through an uncovered execution
  path. Capability conformance must enumerate and test every effect class.
- **Isolate:** containment may be platform-limited or vulnerable. Capability
  manifests must report filesystem, network, process, and secret controls
  independently.

## Memory-specific abuse cases

Memory retrieval can be an instruction-delivery and data-leak channel. Retrieval
must filter tenant and actor scope before ranking, preserve source provenance,
label trust and freshness, apply purpose and model-egress policy, and bound the
amount of retrieved content. Memory conflicts are surfaced rather than resolved
solely by model preference. Correction creates a new revision; it does not erase
the original audit relationship.

## Residual risks

No design fully eliminates model deception, zero-day sandbox escape, malicious
insiders with broad operational access, provider compromise, or inference of
sensitive facts from permitted data. Deployers must select controls appropriate
to their data and threat level. High-impact autonomous actions should require
human approval or an external control system even when technically gateable.

## Review process

Threat-model review is required for new tools, providers, stored data classes,
authentication modes, effect types, sandbox backends, skill formats, learning
imports, and changes to policy or evidence semantics. Each review records owner,
date, affected boundaries, new threats, mitigations, tests, and accepted risks.
