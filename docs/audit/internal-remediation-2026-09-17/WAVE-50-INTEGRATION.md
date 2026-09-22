# Wave 50 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`d914a77`. Four agents implemented and independently reviewed checkpoint,
network, storage and vault changes. No consensus gate was armed, no release
binary was built or signed, and no deployment, credential, fund or public
network was changed.

## Ledger result

All 200 finding rows and classifications remain intact:

- 71 `IMPLEMENTED`;
- 98 `PARTIAL`;
- 15 `UNARMED CANDIDATE`;
- 5 `PROTOCOL DECISION`;
- 7 `BASE CHANGED`;
- 1 `OPEN`;
- 1 `REFUTED IN AUDIT`; and
- 2 `VERIFIED POSITIVE`.

This wave narrows SR-02, NET-21, EN-23 and BV-10 without treating a local guard
as production evidence. SR-03 remains the sole open finding: the repository
still contains no independent signer set and fresh signed checkpoint envelope.

## Integrated changes

SR-02 now refuses external checkpoint onboarding unless the envelope,
signer-arrangement file and independently obtained SHA3-256 arrangement pin are
all present. The same bytes that are fingerprinted are subsequently decoded.
The CLI refuses incomplete tuples, duplicates, option-as-value confusion and
options after `--`. The V1 digest still binds only the numeric arrangement ID,
so authenticated production publication and a future versioned digest binding
remain necessary.

NET-21 now refuses an enabled metrics listener on any non-loopback IP unless
`--allow-public-metrics` is supplied as a standalone option before `--`.
Metrics that are disabled remain inert. The acknowledgement supplies no
authentication, TLS, firewall rule or production exposure evidence.

EN-23 changes block-log replay from a second raw whole-file copy to bounded
frame-by-frame decode over one snapshotted inode. It preserves the 8 MiB frame
limit, codec, order and incomplete-tail behavior. The complete decoded history
and later replay structures remain resident; quadratic replay, retention and
production peak-RSS/SLA qualification remain open.

BV-10 introduces a strict bounded public recovery-context record carrying the
exact V1/V2/V3 derivation family, network, vault ID and funded `H(r)`. Restore
requires an independently retained network and funded hash before returning a
zeroizing preimage. The record is not authenticated and provides no global
reuse registry, single-use enforcement or on-chain lifecycle tracking.

## Independent review corrections

Cross-review found no functional blocker in the streaming decoder, recovery
context or mandatory pin path. It did identify and close low-level hardening
gaps:

- a stable recovery-context golden byte fixture and maximum-length mainnet
  round trip now protect persistent backup compatibility;
- the stale-anchor recovery message names the mandatory pin;
- the ceremony checklist requires publishing its fingerprint through an
  independently authenticated channel; and
- the weak-subjectivity CLI parser now fails closed on ambiguous or incomplete
  input shapes.

Concurrent file growth/rename stress and measured peak RSS remain explicit
EN-23 test gaps, not claimed evidence.

## Validation

- `bloch-pos-node` unit tests passed 510/510 with 19 ignored rehearsals. All
  integration targets passed. The first three-process cold-start attempt made
  no blocks after startup connection refusals; its isolated rerun passed in
  53.34 seconds. This timing flake is recorded rather than hidden.
- Focused weak-subjectivity tests passed 32/32; metrics tests passed 5/5; store
  tests passed 27/27; the block-log repair CLI passed 3/3.
- `bloch-pq-vault` passed 40/40 after independent-review hardening; its focused
  recovery-context/preimage tests passed 7/7.
- Cross-review also reran the streaming decoder, store and cache-continuation
  paths without a failure. Socket-bearing tests ran outside the restricted
  sandbox.
- Ledger arithmetic, conflict-marker scan, comment/constant checks and
  `git diff --check` are integration gates. Workspace-wide `cargo fmt --check`
  still reports the inherited formatting backlog and is not claimed green.

## Launch boundary

The new binary is **not ready to launch**. The Wave 49 canonical container has
not been built on two independently authenticated Linux builders; hosted CI is
not evidenced green; release and rollback artifacts are unsigned; SR-03 lacks
a fresh independently signed weak-subjectivity signer set/envelope; rollback
has not been rehearsed on a scratch systemd host; and no staged rollout or
fleet `/proc` digest verification exists. No production readiness notice is
valid until those external records exist.
