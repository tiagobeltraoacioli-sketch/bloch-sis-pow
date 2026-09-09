# Validator exit and withdrawal lifecycle

Status: implemented per **ADR-041** (accepted 2026-09-08); **ARMED at epoch
2700 by founder decision on 2026-09-09** — runbook
`docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md`, verification report
`docs/audit/VALIDATOR-LIFECYCLE-IMPLEMENTATION-2026-09-09.md`. All five
lifecycle gates carry `2_700`; a compile-time module in `params.rs` refuses
any arming order the ADR forbids. Below epoch 2700 nothing here changes
behaviour: the only wire change is that three fresh tags decode (and three
tombstoned bytes refuse with their own error), and a block carrying any of
them is consensus-invalid below the gates — the same verdict a pre-format
binary reaches at its decoder. From epoch 2700 on, every node must run a
binary carrying the armed constants or it diverges at the boundary.

This document is the lifecycle counterpart of
`BLOCH-FUNDED-VALIDATOR-ADMISSION.md` and assumes it: admission (0x0B)
creates the record and names the withdrawal credential; this lifecycle is
how the record exits and how its value leaves.

## Wire assignments (ADR-041 D1)

Integers are little-endian; vectors carry a u32 length prefix. The frozen
registry (`crates/bloch-pos-committee/tests/wire_tag_registry.rs`) is the
authority; edits to it land in the same commit as the decoder arms, per the
0x0B precedent.

| Tag | Meaning | Status | Payload |
|---|---|---|---|
| 0x07 | — | **TOMBSTONED, permanent** | never decodes: `TxDecodeError::TombstonedTag` |
| 0x08 | — | **TOMBSTONED, permanent** | never decodes |
| 0x09 | — | **TOMBSTONED, permanent** | never decodes |
| 0x0A | `RandaoRecommit` | Released; gate `RANDAO_RECOMMIT_ACTIVATION_EPOCH` armed at 2700 | u32 validator; 32-byte new commitment; u64 epoch; signature vector |
| 0x0C | `ExitV2` | Released; gate `EXIT_AUTH_ACTIVATION_EPOCH` armed at 2700 | 32-byte pubkey hash; u64 epoch; signature vector |
| 0x0D | `Withdraw` | Released; gate `WITHDRAWAL_ACTIVATION_EPOCH` armed at 2700 | u32 validator — **five canonical bytes total** |

The contested `0x07`–`0x09` range carried incompatible meanings across live
lineages (four meanings on one line of development at the worst); the ruling
retires the range instead of picking winners, and the decoder answers each
byte with its own error forever, so a resurrected branch binary is refused
loudly rather than half-understood. `ExitV2` moved off `0x08` (its first
draft's encode-only claim) to the fresh `0x0C`; nothing ever decoded either
byte, so no finalised block is re-read. The txid of every staking shape
folds the tag byte, so **a byte is fixed in the same release that arms its
gate, never after** — re-assigning `0x0D` after activation would re-key the
payout outpoint of every executed withdrawal.

The transaction id is the existing `SHA3-256(DS_TXID ‖ SHA3-256(DS_SPEND ‖
canonical bytes))`. For `ExitV2` the signing root is
`SHA3-256(DS_EXIT ‖ pubkey_hash ‖ epoch)`; for `RandaoRecommit`,
`beacon::recommit_signing_root` under `DS_RANDAO`. `Withdraw` has no signing
root because it carries no signature (below).

## Exit (0x0C)

Main's `ExitV2`, unchanged in substance: a hybrid signature (ML-DSA-65 AND
Falcon-1024) verified **in consensus** against the pubkey the registry
committed at registration — never a key carried in the message — over the
`DS_EXIT` root. The signed epoch must **equal** the inclusion epoch, so a
captured exit cannot be replayed at a time its signer never chose. At most
`MAX_EXITS_PER_EPOCH = 4` voluntary exits per epoch, derived from committed
`exit_epoch` values (no new field; slashing ejections neither spend nor are
blocked by the budget). The legacy unauthenticated `Exit` (0x03) is
consensus-invalid once either the admission or the exit-auth gate is live.

An exit sets `exit_epoch = inclusion_epoch + EXIT_DELAY_EPOCHS` (32; duties
stop then) and `withdrawable_epoch = exit_epoch + WITHDRAWAL_DELAY_EPOCHS`
(2,048 ≈ 22.8 days; the weak-subjectivity margin — the stake stays slashable
throughout).

## Withdrawal (0x0D): an unsigned pull crank

**Anyone may crank any matured bond; nobody can steal one.** The payout is
fully determined by committed state: one fresh eUTXO
`{ txid, vout 0, value = payout, script_hash = withdrawal_credentials }`,
where the credential is the 32-byte script the deposit signed (genesis
records hold the carried form `founder H160 ‖ 12 zero bytes`, which the
transfer ownership rule opens — executed in test, not assumed). A signed
claim was rejected: the destination was fixed and signed at deposit, so a
~4.6 KB hybrid witness buys no authority and adds a griefing surface (a lost
validator key would strand funds that belong to the credential holder). A
push payout at the epoch boundary was rejected as unmetered work on the
chain's most fork-prone path.

Guards, in order, every one before any mutation:

1. gate: `WITHDRAWAL_ACTIVATION_EPOCH` (committed epoch, never node-local);
2. indeterminate write-off class refused (a bond slashed before the
   low-water recorder existed has an uncomputable write-off; refusal is the
   only reversible answer);
3. `epoch ≥ withdrawable_epoch` — which is also the must-have-exited rule,
   since the field is `u64::MAX` until an exit or slash schedules it;
4. credential must already be 32 bytes;
5. `staked_sat > 0` — **the zero is the paid marker**: a second crank finds
   nothing to pay, so there is no `withdrawn` field and no record-encoding
   migration;
6. explicit u64 narrowing of the payout (never saturating);
7. output-collision refusal at `(txid, 0)`.

Priced but fee-free: the five bytes and their gas count against both block
caps once staking-tx metering arms (no free-stuffing vector), and the
settled fee is zero — a fee would come out of the payout and make exactly
the bonds that pay zero (fully slashed, pure write-off) unclosable, leaving
their write-off unrecorded. One per validator per lifetime.

### The amount: backedness, re-keyed for funded admission (D3/D4)

```
unbacked = min(principal_unbacked, low_water(bond))
payout   = staked_sat − min(unbacked, staked_sat)
```

- **FundedDeposit (0x0B) bonds:** `principal_unbacked = 0`. The bond
  destroyed real eUTXO coins the issuance counter had already counted, so
  the withdrawal pays principal **plus** accrual in full.
- **Genesis records (the 64 launch bonds):** `principal_unbacked` is the
  seeded principal (25,000 BLCH each), read from the manifest per record,
  never a flat constant. The payout is **accrual only**; the principal —
  1,600,000 BLCH the manifest seeded straight into `staked_sat`, never into
  the eUTXO set and never into `GENESIS_ISSUED_SAT` — leaves as
  `written_off_sat`, an audit entry, never a coin. All 64 credentials are
  the founder's: **the founder forfeits the 1.6M BLCH of nominal principal
  to keep spendable ≤ issued** (founder decision #2, reaffirmed in the ADR).
- **Legacy `Deposit`/`Delegate`:** written off in full — the fail-closed
  arm. Empty on any reachable chain: `DEPOSIT_ACTIVATION_EPOCH` is
  `u64::MAX` **permanently**, and the arming-order module makes changing
  that a build error, because the classification above leans on it.

The **low-water floor** (`TAG_STAKE_LOW_WATER`) is the smallest the bond has
been since the recorder started; without it, a pre-withdrawal slash's burn
would be charged a second time and the second charge would land on rewards
the operator really earned. The recorder runs UNGATED at the only
`staked_sat` reduction site (a gate would arrive too late to write the
history the gate must read) and is root-safe today because that site is
itself behind the evidence gate (closed below 2700); a zero mark is committed, never
elided — present-and-zero (slashed to nothing) and absent (never slashed)
are different facts, and collapsing them would hand the indeterminate class
a payout instead of a refusal.

### Conservation and the audit the invariant cannot run

Enforced in the arm, per withdrawal:

```
staked_before − staked_after == payout + written_off
issued_sat unchanged
```

`accounted_supply_sat` counts `staked_sat`, so the block-level
`supply_conserved` delta **cannot see** a full-principal payout — the offset
cancels (demonstrated by test: a hand-forged full payout passes the
invariant). The payout rule is the guard, and the audit that observes it is
`supply_gap_sat`: a correct genesis withdrawal shrinks the genesis gap by
exactly the written-off amount; the counterfeit leaves it untouched while
1.6M BLCH of phantom becomes spendable coin.

## State-root components

| Tag | Component | Form |
|---|---|---|
| 0x1B | `written_off_sat` | single leaf, committed only once non-zero; monotone |
| 0x1C | `stake_low_water` | per-validator; **zero values committed** |

Fresh bytes `0x1B`/`0x1C` — the ported branch used `0x18`/`0x19`, which this
lineage has since released to other components; keeping them would alias two
live columns. Both components are empty on every state that exists today, so
every pre-gate root is byte-identical (pinned against the recorded fixture
root, and by the leak pin below).

## Slashing interaction (D5)

A slashed validator withdraws through the **same** crank: the penalty was
burned from `staked_sat` at prosecution, the low-water recorder captured the
floor, and `apply_slashing_evidence` re-stamps
`withdrawable_epoch = max(existing, slash_epoch + WITHDRAWAL_DELAY_EPOCHS)`
so the residue stays reachable for late correlated evidence. The 2× rule is
code now: `CORRELATION_WINDOW_EPOCHS ≥ 2 × WITHDRAWAL_DELAY_EPOCHS` is a
compile-time assertion. The A7 whistleblower cap rides the same flag day: a
reward may never exceed the backed share the slash consumed from the
offender's own bond — unbounded, slashing an unbacked genesis bond would
mint withdrawable coin into somebody else's bond past the cap's own counter.
Below the gate rewards are paid byte-for-byte as today (applying the cap
early would change what a slash pays on the live chain and fork the fleet on
the next slash).

The node-side whistleblower path is live (gated): a node that observes an
equivocation now constructs the §7.3 evidence transaction, admits it to its
own mempool and broadcasts it (`engine::report_equivocation`), with a
transport-level relay gate so pre-upgrade peers cannot score down honest
relayers before the flag day.

## Gate packaging: one lifecycle epoch `L = 2700`

**ARMED 2026-09-09** (founder decision at ~epoch 2413; epoch 2700 lands
≈2026-09-12 21:31 UTC). The runbook is `docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md`;
the value below is what the five `*_armed_epoch_matches_the_runbook`
tripwires in `transition.rs` check against.

```
FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH = 2_700      (armed)
EXIT_AUTH_ACTIVATION_EPOCH                  = 2_700      (armed)
WITHDRAWAL_ACTIVATION_EPOCH                 = 2_700      (armed)
SLASHING_EVIDENCE_ACTIVATION_EPOCH          = 2_700      (armed)
RANDAO_RECOMMIT_ACTIVATION_EPOCH            = 2_700      (armed; severable rider)
DEPOSIT_ACTIVATION_EPOCH                    = u64::MAX   (permanent)
LEAK_RECOVERY_ACTIVATION_EPOCH              = 2_700      (armed 2026-09-06 — same boundary, see docs/LEAK-RECOVERY-FLAG-DAY.md)
```

Five separate constants — independently revocable before release, armed
together on 2026-09-09 — pinned by
the compile-time arming-order module in `params.rs`:
`ADMISSION == EXIT_AUTH`, `WITHDRAWAL ≥ EXIT_AUTH`,
`EVIDENCE ≤ WITHDRAWAL`, `DEPOSIT == u64::MAX`. Each assertion was verified
by violating it (the build fails naming the broken invariant). One combined
flag day because every flag day costs a coordinated fleet rebuild plus ~21
minutes of mute RPC per node restart; blast radius is bought down with
rehearsal, not stages. The `RandaoRecommit` rider defaults to `L` (its
deadline is real: first chains exhaust ~2027-02-11) and is deliberately
unconstrained by the ordering module — dropping it changes nothing else.

Crank policy (founder decision #5): each node auto-cranks its own matured
withdrawal (`engine::crank_own_withdrawal`, once per slot turn) — mempool
convenience; consensus is permissionless either way.

## Operator workflow: exit and withdraw

Nothing here works before `L` is armed; below it every message is refused by
mempool policy and by consensus independently.

1. **Exit.** Build `ExitV2` for the CURRENT epoch: sign
   `SHA3-256(DS_EXIT ‖ your pubkey-hash ‖ epoch)` with the validator
   keystore (both hybrid halves) and submit within the same epoch — a
   message signed for any other epoch is refused, and there are at most 4
   voluntary exits per epoch (a refused exit retries next epoch). Verify
   with `getvalidatorbykey`: `exit_epoch` set means accepted; duties stop 32
   epochs later; the record is then locked for 2,048 further epochs.
2. **Wait out `withdrawable_epoch`.** The bond remains slashable — that is
   the point of the margin. There is no cancel: an exit is irrevocable.
3. **Withdraw.** Nothing to sign: a running node with your keystore cranks
   automatically at maturity; otherwise submit the five-byte `Withdraw`
   (tag `0x0D` + your u32 index) from anywhere — the payout can only ever
   land on the credential signed at deposit. Funded bonds receive principal
   plus accrual; genesis-era bonds receive accrual only (the write-off is
   consensus, not a choice).
4. **Spend.** The payout is an ordinary eUTXO at `(withdraw_txid, 0)`,
   locked to the withdrawal credential; spend it with the credential's PQ
   key through the ordinary transfer path (`listunspent` on the credential
   script shows it). Registration never established that you control that
   key — the admission spec's warning stands; there is no rotation and no
   recovery path for a lost withdrawal key.

Re-entry after a genesis-era exit is `FundedDeposit` with real coins — a new
record and a new key; indices are never reused.

## Release boundaries and validation

Arming `L` changes block validity and must follow the admission spec's
discipline: publish the epoch before it arrives, one reproducible release,
fleet rebuild audited node-by-node, soak with zero two-root blocks. `L` was
set to 2700 on 2026-09-09; the rollout, the watch list and the open items
(T-6 unreconciled, no weak-subjectivity ceremony, no transport soak with the
lifecycle enabled, no external audit) are in
`docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md`. Only after `L` is past and one full
withdrawal has settled on mainnet does the admission spec's "not for public
funds" sentence discharge — arming is not that announcement.

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee -p bloch-pos-node --no-fail-fast
python3 scripts/rehearse-validator-admission.py      # full lifecycle + RANDAO rehearsal, gates at 0 in a disposable copy
python3 scripts/check-validator-lifecycle-mutations.py
bash scripts/hardened-clippy.sh
```

The lifecycle rehearsal compiles a disposable source copy with the five
gates at epoch 0 and the two exit clocks shortened (maturation under the
shipped values is 2,080 epochs of engine time; the shipped delay arithmetic
is covered by the committee suite), then drives two real engines through
deposit → activate → attest → wrong-key-exit refused → exit → maturation →
auto-crank → full-principal payout → **a real spend of the payout eUTXO by
the withdrawal key**, with root agreement at every slot. The RandaoRecommit
rider is rehearsed at the committee layer only (exhaustion takes 8,192
proposals per chain).

Known limits, unchanged from the ADR: delegation positions still have no
payout path (their own ADR); the genesis supply offset stays committed
history; withdrawal credentials cannot rotate; the exit clock counts epochs,
not finalized checkpoints; `DS_EXIT` is not network-bound (deferred to the
`SIGHASH_NETWORK_BINDING` decision); no independent audit of the combined
lifecycle has occurred.
