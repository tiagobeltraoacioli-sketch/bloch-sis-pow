# Wave 50 NET-21: explicit metrics exposure acknowledgement

Date: 2026-09-18. Branch: `codex/wave50-network-next`. Starting point:
`d914a77`. Scope: local listener policy, focused tests and documentation. No
wire encoding, consensus rule, persisted state, deployment or live listener
changed.

## Recovered residual

The itemized NET-21 source remains
`a79c88b:docs/audit/deep-audit-2026-09-16/A6-node-network-rpc.md`, recovered in
Wave 43. Metrics and health are opt-in and default to loopback, but an operator
could previously expose validator activity, keystore status, peer counts, lag
and finality health merely by changing `--metrics-bind`. The GET-only endpoint
has no authentication.

## Local mitigation

When metrics are enabled, `metrics_bind_plan` now parses `--metrics-bind` as an
IP address and permits loopback IPv4 or IPv6 directly. Every non-loopback
address, including wildcard, private overlay and public addresses, is refused
unless the command carries the standalone `--allow-public-metrics` switch.
The refusal occurs before the engine starts or binds a listener.

The switch parser does not accept the acknowledgement when it is another
option's value or appears after `--`. This prevents a malformed command such
as `--metrics-bind --allow-public-metrics` from accidentally authorizing the
exposure. An unused bind remains inert when metrics are disabled, preserving
the existing off-by-default behavior.

The help and monitoring/integration documentation explicitly say the flag adds
no authentication. It only makes a routable listener a visible operator
decision; firewalling and deployment qualification remain mandatory.

## Status and residual

NET-21 remains `PARTIAL`. This closes accidental metrics exposure in the local
CLI but does not make intentional exposure safe, add TLS/authentication, hide
the build fingerprint or standard libp2p identify metadata, or change the RPC
peer-count fields. No production command line or firewall was inspected or
changed.

## Validation

- `cargo test -p bloch-pos-node metrics_bind_tests --offline`: five focused
  tests passed; 523 unrelated node tests were filtered out.
- `git diff d914a77..HEAD --check`: passed.

The build emitted inherited unused-import and dead-code warnings. Workspace
formatting was not changed.
