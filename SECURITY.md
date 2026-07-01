# Security Policy

## Project status

Governed Agent Harness is under active development. Until a release is
explicitly marked stable, assume interfaces and security controls are
experimental. Documentation defines intended requirements and does not by
itself prove that a control is implemented.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include secrets,
customer data, exploit details, or private traces in a public channel.

Use GitHub's private vulnerability reporting feature for this repository when
it is enabled. If no private reporting channel is available, contact the
repository owner through the private contact method listed on the GitHub
repository profile and ask for a secure reporting channel before sharing
details. Maintainers must publish a dedicated security contact before the first
stable release.

Include, when safe:

- affected version or commit and deployment mode;
- component, adapter, tool, and enforcement tier;
- impact and preconditions;
- minimal reproduction using synthetic data;
- whether the issue may be actively exploited; and
- suggested mitigation, if known.

Never test against systems or data you do not own or have permission to use.

## Maintainer response

Maintainers will acknowledge a valid private channel as soon as practical,
triage severity and affected versions, coordinate remediation and disclosure,
and credit reporters who want attribution. Concrete response-time commitments
will be published only when the project has maintainers and support capacity to
meet them.

Critical issues may require disabling a capability, revoking an artifact,
rotating credentials, or publishing an urgent release. Public disclosure should
wait until users have a reasonable opportunity to mitigate, unless active harm
requires a different coordinated response.

## Supported versions

No stable supported-version policy exists yet. Before the first stable release,
this file will list supported release lines and security-fix policy. Users of
development snapshots should track the latest revision and review changes.

## Security expectations

- Tool and other protected effects must be policy-evaluated before execution.
- Memory promotion requires evidence and policy disposition.
- Learning artifacts must not mutate the runtime automatically.
- Observe and Advise integrations are not preventive enforcement.
- Secrets and private data must not be attached to issues or test fixtures.

See `docs/SECURITY_MODEL.md` and `docs/THREAT_MODEL.md` for design requirements
and limitations.
