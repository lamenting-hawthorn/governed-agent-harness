# Developer Experience

## Goal

A new contributor should be able to install the supported toolchain, initialize
a governed project, run a useful local agent, make an approval decision, inspect
the evidence, restart, and retrieve approved memory without provisioning an
external service.

The commands below define the intended product surface. Until a command ships,
release documentation must label it as planned rather than presenting it as
current behavior.

## Installation profiles

The product should support explicit profiles instead of silently installing
optional infrastructure:

| Profile | Includes | Intended user |
| --- | --- | --- |
| `local` | CLI, Pi engine, embedded storage, local policy, basic isolation | Individual developer and quickstart |
| `sdk` | Contracts, kernel SDK, client types | Application integrator |
| `server` | Daemon, hosted storage provider, service diagnostics | Team deployment |
| `enterprise` | Enterprise extension points and deployment assets | Controlled organizational rollout |

`local` is the default. Optional SkillLoop, GBrain, MCP, and engine adapters are
installed explicitly and report their compatibility before activation.

## Golden path CLI

```console
$ gah init
Created .gah/config.yaml
Initialized local data store
Installed policy profile: local-safe
Next: gah doctor

$ gah doctor
Configuration       ok
Storage             ok
Execution engine    pi (compatible)
Policy              local-safe (enforcing)
Isolation           available

$ gah run
> Summarize the repository and write NOTES.md
Approval required: write_file NOTES.md
[a]llow once  [d]eny  [v]iew request

$ gah runs inspect <run-id>
$ gah memory list
$ gah replay <run-id> --effects=simulate
```

The exact binary name may change before the first public release, but the
operation model should remain stable.

## Command requirements

### `gah init`

- Creates only project-owned configuration and state selected by the user.
- Refuses to overwrite existing files without an explicit flag and preview.
- Writes no secret values.
- Pins schema and policy versions.
- Supports `--profile`, `--engine`, `--data-dir`, and `--non-interactive`.
- Prints every created path and the next safe command.

### `gah doctor`

- Is read-only unless an explicit `--repair` is supplied.
- Reports configuration origin without displaying secret values.
- Checks schema migrations, file permissions, storage integrity, policy load,
  adapter compatibility, and actual isolation availability.
- Distinguishes `ok`, `warning`, `degraded`, and `error` with actionable fixes.
- Supports structured output with stable codes: `--format json`.
- Can create a sanitized support bundle only with explicit destination and
  preview.

### `gah run`

- Selects project, actor, engine, model, and policy explicitly or from visible
  configuration.
- Shows when enforcement is active, degraded, or unavailable before the run.
- Streams useful progress without exposing chain-of-thought or secrets.
- Presents approvals with tool, effect summary, scope, risk, and exact argument
  diff after transformation.
- Handles cancellation and timeout with a terminal evidence record.

### `gah runs`

- Lists and inspects runs using stable run and correlation identifiers.
- Shows normalized events, decisions, approvals, effects, and results in causal
  order.
- Redacts restricted content by default and identifies redaction explicitly.
- Exports versioned JSON/JSONL without claiming omitted data is complete.

### `gah memory`

- Separates proposals from committed memory.
- Supports inspect, approve, reject, supersede, expire, and delete according to
  policy.
- Displays evidence, scope, authority, confidence, retention, and revision.
- Never represents a retrieved candidate as committed trusted memory.

### `gah policy`

- Validates and explains a policy without executing effects.
- Supports a dry-run decision against a recorded or synthetic request.
- Shows the loaded version and configuration source.
- Makes permissive rules visible while refusing any configuration that would
  allow an effect to fail open when synchronous policy evaluation is
  unavailable.

### `gah skills` and `gah adapters`

- List installed versions, integrity identities, permissions, compatibility,
  and status.
- Preview installation or upgrade effects before applying changes.
- Keep a lockfile for deterministic resolution.
- Support explicit rollback to an available compatible artifact.

## Configuration experience

Configuration precedence must be deterministic and inspectable:

```text
compiled safe defaults
< user configuration
< project configuration
< environment references
< explicit command arguments
```

Security-sensitive configuration must not accept ambiguous coercion. `gah
config explain <key>` should show the effective value's source, redacting secret
material. Deprecations emit actionable warnings for at least one compatible
release window before removal.

Suggested project files:

```text
.gah/
  config.yaml
  policy.yaml
  skills.lock
  adapters.lock
```

Local mutable state should default outside the repository or inside an ignored
directory. Initialization should update ignore files only with an explicit,
previewed choice.

## Errors and recovery

All interfaces return a stable machine-readable error code, a safe human
message, correlation ID, and suggested next action. Errors should distinguish:

- invalid request;
- policy denial;
- approval required or expired;
- unavailable declared capability;
- adapter incompatibility;
- storage or migration failure;
- engine/model failure;
- ambiguous external effect outcome.

Retry guidance must reflect idempotency. The CLI must never encourage blind
retry when an external effect may already have occurred.

## Extension developer workflow

An adapter or provider author should be able to:

1. Scaffold a package from a minimal template.
2. Implement a versioned contract without importing internal kernel modules.
3. Declare capabilities and compatibility ranges.
4. Run the public conformance kit locally.
5. Add negative-path fixtures for every effect or trust boundary.
6. Produce a package with provenance and integrity metadata.
7. Install it into an isolated test profile and inspect activation decisions.

Expected technical contracts are documented in `docs/ARCHITECTURE.md`, while
testing requirements are expected in `docs/TESTING_STRATEGY.md`.

## Local-to-hosted transition

Moving from local to hosted mode should change endpoints, identity, and storage
configuration without changing run, policy, evidence, memory, or skill
semantics. A migration command must preview:

- objects and schema versions to transfer;
- redactions or excluded local-only data;
- tenant and project scope mapping;
- policy differences;
- rollback and backup location.

The tool must not upload local traces, memories, or secrets implicitly.

## Contributor experience

The repository should expose one documented setup path, one fast validation
command, and focused package commands. A contributor should not need enterprise
services to run unit and local integration tests. Fixtures must contain no real
credentials, private traces, or customer data.

Pull requests should report which contracts changed, whether compatibility is
affected, what threats were tested, and which release note category applies.

## Measuring developer experience

Measure these from reproducible onboarding and CI runs:

- clean-machine quickstart completion and failure points;
- median time to diagnose seeded configuration failures;
- percentage of errors with stable codes and actionable remediation;
- adapter scaffold-to-conformance completion;
- local-to-hosted migration verification and rollback success;
- documentation command accuracy in release CI.

Do not publish target numbers until baselines and measurement scripts exist.
