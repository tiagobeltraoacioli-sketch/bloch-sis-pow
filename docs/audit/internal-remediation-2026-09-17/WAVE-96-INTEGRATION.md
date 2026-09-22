# Wave 96 integration — safe audit remediation through Waves 87–96

Date: 2026-09-19
Starting consolidation: `be16a79`
Integrated head before this ledger commit: `6d794cb`

## Integrated corrections

- CR-07: repository diversified sub-seeds, existing CLI mnemonic/keystore
  prompts, and new-password/confirmation prompts now acquire explicit
  zeroizing owners without changing public formats, derivation or KDF inputs.
- NET-04 / EN-08: local block broadcasts bind one encoded frame to its exact
  block id without cloning the retained envelope or decoding the body again;
  remote connection-churn diagnostics are bounded without conditioning state
  cleanup; devnet fanout queues share immutable frame allocations.
- NET-22: block-log page scans and index repair reuse fixed-size header buffers
  instead of allocating one header vector per inspected frame.
- INF-03: both checked-in CI guards reject YAML directives and multiple
  document boundaries outside block scalar bodies.
- INF-01: the two-output release comparator now rejects local aliases,
  noncanonical trees/manifests/metadata and malformed commit, epoch, snapshot
  and target fields. These checks strengthen only local candidate evidence.

The integrated commits are `fffb2db`, `cc966a8`, `7e1b605`, `7f8108f`,
`ebf9db7`, `b3c0fb3`, `df03acf`, `8f34af1`, `7a91290`, `d285a0e`, `7719e49`,
`fa985f0`, `46de03c`, `cfc07e7`, `3ea599c` and `6d794cb`.

`df03acf` contains both the reviewed CR-07 diversified-seed change and the
reviewed NET-22 fixed-header-buffer change because their already-staged files
were captured together in the shared worktree. No history was rewritten; the
combined scope and validation are recorded explicitly here.

## Validation evidence

```text
cargo test -p bloch-crypto --offline
# root full rerun outside the sandbox: 216 passed; 0 failed; 4 ignored

cargo test -p bloch-crypto --features wallet-cli --offline
# after Wave 88: 223 passed; 0 failed; 4 ignored
# after Wave 89: 224 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos devnet_broadcast_ --offline
# 2 passed; 0 failed; 589 filtered out

cargo test -p bloch-pos-node --bin bloch-pos shared_sync_ --offline
# 7 passed; 0 failed; 584 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# before shared devnet frames: 571 passed; 0 failed; 19 ignored
# integrated shared-frame head: 572 passed; 0 failed; 19 ignored; 72.72s

python3 -I scripts/check-tests-blocking.selftest.py
# 175 cases behave as documented

python3 scripts/check-scanners-blocking.selftest.py
# 136 cases, both directions

python3 -I scripts/check-tests-blocking.py
# 8 live crates covered on both pipelines

python3 scripts/check-scanners-blocking.py
# 8 GitLab + 8 GitHub jobs blocking

bash scripts/compare-pos-release-builds.selftest.sh
# PASS after every Wave 88–96 comparator hardening
```

Socket-bearing crypto and node suites were run outside the restricted macOS
sandbox after sandboxed attempts returned `EPERM` on loopback binds. Compiler
output contained only pre-existing warnings. Focused reports contain the exact
additional unit/check commands for each correction.

## Ledger reconciliation

`FINDINGS.md` still contains 200 rows and 200 unique IDs. No status was
upgraded by this integration:

```text
IMPLEMENTED: 71
PARTIAL: 98
UNARMED CANDIDATE: 15
PROTOCOL DECISION: 5
BASE CHANGED: 7
OPEN: 1
REFUTED IN AUDIT: 1
VERIFIED POSITIVE: 2
```

CR-07, NET-04, EN-08, NET-22, INF-01 and INF-03 remain `PARTIAL`. SR-03 is
still the sole `OPEN` finding.

## Release decision

The MW binary is **not ready for launch**. This macOS host still has no Docker,
Podman or minisign executable, so it did not produce a canonical Linux release
artifact. The following evidence remains mandatory and external:

1. two independently authenticated canonical Linux builds of the reviewed
   commit and a passing byte-for-byte comparator result;
2. full hosted CI plus authenticated builder/image/tool provenance on the
   release commit;
3. release and rollback artifacts signed with the real release key, published
   through the reviewed channel and independently approved;
4. a fresh independently signed weak-subjectivity envelope for SR-03;
5. a scratch-systemd rollback drill; and
6. staged canary/fleet rollout with running `/proc` digest verification.

No push, deployment, signing, publication or release authorization was
performed during these waves.
