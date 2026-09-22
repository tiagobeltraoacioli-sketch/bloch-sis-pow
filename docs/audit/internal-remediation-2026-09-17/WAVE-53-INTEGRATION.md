# Wave 53 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`405bfb0`. Four agents implemented and cross-reviewed vault anchor validation,
RPC isolation, devnet pre-decode admission and deploy-image policy. No
consensus gate was armed, no release binary was built or signed, and no
deployment, credential, fund, registry or live node was changed.

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

This wave narrows BV-11, EN-18, NET-22 and INF-14. All remain `PARTIAL` because
their operational, protocol or external-provenance residuals remain. SR-03 is
still the sole open finding.

## Integrated changes

BV-11 adds an opt-in Bitcoin anchor verifier that requires an independently
trusted PQ owner key and expected Bitcoin network, validates both committed
addresses, then verifies the existing signature. Generic verification and wire
bytes remain unchanged. A separate additive error type preserves exhaustive
matches over the historical public error enum. Some legacy test-network
encodings remain ambiguous between testnet/signet/regtest.

EN-18 recognizes static `getbuildinfo` before reserving one of the 16 engine
permits or touching the consensus channel. It uses the same canonical formatter
as the retained direct-engine fallback. Chain, block, mempool and transaction
work that needs engine-owned state remains on the bounded queue.

NET-22 uses the devnet frame tag and bounded raw length to acquire normalized-IP
and aggregate class/byte capacity before payload decoding. Saturated frames are
shed without decode; malformed frames release both reservations; decoded class
and canonical size must equal the precharge. The bounded frame allocation still
occurs before this point, and libp2p decode-before-peer-admission remains.

INF-14 refuses YAML anchors, aliases and merge keys instead of silently treating
inheritance as outside the image-pin guard. The lexer distinguishes comments
from `#` in plain/quoted scalars, rejects multiline quoted scalars it does not
model, and skips literal/folded block content. Generated configurations,
registry authenticity and fleet state remain outside this structural check.

## Independent review corrections

Adversarial review twice found concrete YAML bypasses: comment stripping inside
quotes, then plain-scalar `x#y` and multiline quote state. The final lexer and
mutations close those cases while retaining valid quoted and block-scalar text;
the reviewer approved the final version.

Vault review found that adding Bitcoin policy variants to the historical public
error enum would break downstream exhaustive matches and that address strings
do not uniquely identify every Bitcoin test network. The implementation now
uses a separate error type and documents that boundary. EN-18 review found no
dispatch blocker and the regression now compares the complete canonical build
identity object. Review of the devnet reservation found matched class/byte
accounting and release paths with no functional blocker.

## Validation

- `bloch-pos-node` passed 516 unit tests with 19 ignored rehearsals. All
  integration targets passed: 118 tests passed and 6 performance tests were
  explicitly ignored, including three-process cold start and the 80-test
  recovery fence.
- The complete RPC unit group passed 63/63 outside the socket-restricted
  sandbox. Both focused devnet pre-decode regressions passed.
- `bloch-pq-vault` passed 44/44 plus its compile-fail doctest.
- The deploy-image mutation suite passed all 8 groups, the real guard passed
  all 15 deploy YAML files, and both scripts compiled as Python.
- Ledger arithmetic, comment/constant validation, conflict-marker scanning and
  `git diff --check` passed at integration.
- Workspace-wide `cargo fmt --check` still has the inherited formatting
  backlog and is not claimed green.

## Launch boundary

The new binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
