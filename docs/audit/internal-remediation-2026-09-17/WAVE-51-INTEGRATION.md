# Wave 51 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`2abb416`. Four agents implemented and cross-reviewed the vault, cryptographic
test boundary, canonical replay and network-serving changes. No consensus gate
was armed, no release binary was built or signed, and no deployment, credential,
fund, public service or live node was changed.

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

This wave narrows BV-10, CR-08, EN-23 and NET-22 without treating repository
hardening as product adoption, operational evidence or production closure.
SR-03 remains the sole open finding: there is still no fresh checkpoint
envelope approved by an independently controlled signer set.

## Integrated changes

BV-10 gains an opt-in, domain-separated PQ signature envelope over the strict
recovery context. Restore verifies it against an independently supplied owner
public key before selecting a derivation. Trust-anchor distribution, global
vault-ID uniqueness, reuse/single-use tracking and on-chain PQ proof remain
outside the library.

CR-08 removes the public manual deterministic-RNG guard. The scoped closure is
now the only public override and repository KAT callers use it. This closes the
known `mem::forget` misuse surface, but cannot promise erasure of opaque RNG
state, caller seed copies, compiler temporaries or state after process abort.

EN-23 adds a checked linear canonical-replay path for the node's locked block
log. Every frame still passes the full transition and signature checks, while
fork choice, orphan release and branch pruning no longer rescan an already
selected prefix. Decoded envelope/state retention, transition growth, reorg
fallback and production RSS/SLA qualification remain.

NET-22 makes sync serving fail boundedly when `blocks.idx` is missing,
malformed, empty beside history or disagrees with the selected log record.
Open-time rebuild still restores this derived index, and a valid lagging index
still serves its unindexed crash-window tail. A long valid tail and decode
before admission remain residual costs.

## Independent review corrections

Cross-review found no functional blocker in the signed recovery envelope or
bounded index failure. The crypto review found stale public-boundary wording;
the current README, specification and KAT descriptions now consistently expose
only the scoped API. Replay review added full no-mutation assertions for failed
frames, corrected stale comments, and made the benchmark assert zero
fork-choice entries per canonical frame. The benchmark is explicitly a
regression signal, not an asymptotic proof or production SLA.

## Validation

- `bloch-pos-node` passed 512 unit tests with 19 ignored rehearsals. All
  integration targets passed: 118 tests passed and 6 performance tests were
  explicitly ignored, including the three-process cold start and 80-test
  recovery fence.
- Focused replay boot tests passed 2/2 and store tests passed 28/28.
- `bloch-pq-vault` passed 42/42 on the integrated head.
- `bloch-crypto` passed 185 tests with 2 ignored; ACVP, Falcon submission and
  dual-AND integration targets passed. `pqcrypto-internals` passed 17 tests
  with 1 ignored helper, 2 vendor-pin tests and 2 doctests. The Genesis-3
  ML-DSA KAT passed 4/4.
- Ledger arithmetic, comment/constant validation, conflict-marker scanning and
  `git diff --check` passed at integration.
- Workspace-wide `cargo fmt --check` still has the inherited formatting backlog
  recorded by earlier checkpoints and is not claimed green.

## Launch boundary

The new binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks the
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary/fleet digest evidence
exists. These external gates must be satisfied before a readiness notice or
production rollout.
