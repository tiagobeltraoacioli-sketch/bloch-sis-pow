# L2 settlement program switch (audit L2N-01 / L2N-02)

Status 2026-11-23: **written and tested, INERT, candidate values, nothing released or deployed.**

The native chain pins the SP1 guest program an L2 settlement must name and the
key its proof is verified under (`l2_settlement::mainnet::PROGRAM`, identities
3..6: configuration commitment, guest ELF, KoalaBear key, BN254 key). The
deployed program `settlement_v3_mainnet` accepts a prover-chosen block context
(audit L2N-01, Critical) and caps the lifetime mint (L2N-02). The fix is a new
guest program, `settlement_v3_mainnet_bound` (bloch-l2-evm
`docs/MAINNET-PROGRAM.md`). This document is the native half: how the L1
changes the pinned program, and the order of the releases on both sides.

## The rule

| Item | Value |
|---|---|
| Gate | `params::L2_SETTLEMENT_PROGRAM_SWITCH_ACTIVATION_EPOCH` = `u64::MAX` (inert) |
| Pinned successor | `l2_settlement::mainnet::PROGRAM_SWITCH` (candidate, see below) |
| Arming guard | `l2_settlement::mainnet::PROGRAM_SWITCH_FINAL` = `false`; the build fails if the gate is armed while it is `false` |
| Listed in | `hard_forks::GATES_UNARMED_IN_CANONICAL_HISTORY`, `tools/bloch-indexer` gate table |

At the first epoch boundary whose new epoch is `>=` the gate, an installed L2
whose policy names exactly the deployed program names the pinned successor
instead (`State::switch_program`, called from the epoch roll). Four values of
the committed policy are written; the state root changes at that block.

- Up to the last block before the boundary: only a settlement of the old
  program is valid.
- From the boundary block on (the first block of the gate's epoch, its own
  transactions included): only a settlement of the new program is valid.
- **No overlap.** A proof of the old program still pending at the boundary is
  refused and the same L2 block is proved again under the new program. Honest
  blocks are identical under both programs, so the settler can prepare that
  proof before the boundary; the cost is at most one proof time. An overlap
  would keep the old program acceptable in a window everybody knows about, and
  one foreign settlement of the old program in that window leaves a head the
  new program cannot extend either, which is the finding itself.
- Unchanged: network identities, chain id, L2 genesis, attestor set, head,
  inbox, the pinned source (the request the prover reads does not change at
  the switch) and the **proof policy commitment** (`15486996…747d`: it commits
  to the SP1 circuit version, the Groth16 wrapper key and the statement tag,
  none of which a guest change touches; the release host must re-derive it).
- The switch happens once. After it nothing is pending, and a development L2
  (any chain id but 700770) never switches.

A reorg needs no special handling: the program in force is committed state, so
each branch carries its own.

## Deposits follow the program (audit L1X-03)

`L2_CUMULATIVE_DEPOSIT_CAP_ACTIVATION_EPOCH` (inert) makes the L1 refuse a
deposit the guest could not mint. Which deposits those are depends on the
program in force, so the rule reads it from the state
(`State::deposit_within_supply_cap`):

| Program in force | Cap gate inert | Cap gate armed |
|---|---|---|
| Deployed (lifetime mint cap) | no cumulative rule (today) | lifetime deposit total `<=` 100 000 000 000 BLCH; past it deposits are closed |
| Successor (outstanding-supply cap) | no cumulative rule | escrow `<=` 100 000 000 000 BLCH; cannot fire on an L1 that conserves its supply |

The two gates may be armed in either order. A successor pinned with the
deployed cap (a context-only program) keeps the lifetime rule.

## Candidate values: NOT FINAL

`PROGRAM_SWITCH.to` holds the identities of the candidate ELF built on
2026-11-23 from bloch-l2-evm `codex/audit-fixes-l2-20261123` at `21ec80c` (ELF
SHA-256 `ac2e1ca5…8892`). They change with any change to the guest or to the
L2 core crate. They are recorded so the mechanism can be tested against the
pinned mainnet policy; they must never be armed.

## Activation sequence

1. **L2: release candidate.** Owner decisions taken (both guest fixes or
   context only; the `prevrandao` switch block). Build the ELF at the release
   commit with `build-reproducible.sh`, verify with `verify-reproducible.sh`
   from two checkouts, derive the keys and the proof policy with
   `bloch-evm-sp1-settlement-v3 --mainnet-bound identity`.
2. **L1: re-pin.** Replace the four values of `PROGRAM_SWITCH.to` (and
   `supply_cap` if the context-only program was chosen). Print the fixture
   request (`print_mainnet_bound_program_fixture_request`; it equals
   `mainnet-empty.request` while the test chain is unchanged).
3. **L2: real proof.** Prove L2 block 1 for that request with the release ELF
   (`--mainnet-bound prove-groth16`). Run the native check
   `mainnet_bound_program_real_groth16` against it, commit the fixture and
   make that test a normal one. Only then set `PROGRAM_SWITCH_FINAL = true`.
4. **L1 release A (gate still inert)** and **L2 release** (prover with the new
   ELF, settler able to prove with `--mainnet-bound`, follower / attestors /
   replica with both program identities and linked to release A). Signed,
   rolled out to every validator and every operator host. Indexer rebuilt.
5. **L1 release B: the owner arms the epoch.** Historical replay and
   mixed-fleet qualification first (a rehearsal network with
   `l2-activation-rehearsal-mainnet-policy` takes the same switch). The L2
   side is configured with the same epoch. Rolled out before the epoch with
   the usual margin.
6. **At the boundary.** The settler stops submitting old-program proofs in
   the last epoch before the gate (or accepts that one is refused), and
   submits the new-program proof of the pending block once the boundary block
   is the head. `getl2settlement.program.set` turns from `initial` to
   `switched`.

Until step 6 the switch protects nothing. The interim protections are the
settler-authorization gate (stop-gap, also inert) and the exposure cap.

## Observability

`getl2settlement.program`: `set` (`initial` / `switched`), the four identities
in force, `proof_policy`, `supply_cap` (`gross-minted` / `outstanding`), and
`switch` (the pinned successor, `activation_epoch` or null while inert,
`taken`, `final`).

## What the tests cover

Consensus crate, `transition/audit_20261123_l2n01_switch_tests.rs`, with the
gate armed at a chosen epoch through a test seam: inert behaviour; the boundary
(last block before, the boundary block, after); the verifying key handed to
the verifier; a reorg across the boundary; the settler rule in the three
orders; the deposit rule in every gate combination and through the boundary
block; the restart cache.

Proofs are doubles, with one exception: the real Groth16 proof of the
**deployed** program is refused by the real verifier after the switch, as it
is and behind a statement renamed to the new program. **No real proof of the
new program exists**, so its acceptance by the real verifier is not exercised
(step 3). Not run either: a node-level or multi-node rehearsal, the
historical replay, the mixed-fleet qualification.

## Known behaviour at the boundary (node-local, not consensus)

Mempool admission judges a settlement against the head. During the last slot
before the boundary a new-program settlement is therefore refused by the
mempool (not barred: it can be resubmitted), and a pending old-program one is
dropped by the proposer's own probe when it builds the boundary block. The
settler should submit the new proof after it sees the boundary block.
