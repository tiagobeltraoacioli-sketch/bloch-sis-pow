# WS3 — Coherence activation

Status: **NOT DELIVERABLE, and not by a date — the current design is measurably
infeasible and needs an architecture decision, not a schedule.**
This is the one workstream where the honest answer is "not in September."

## Correction to the brief

**The premise "`coherence_root` is a hardcoded `[9; 32]` / `[0u8; 32]` and is
never computed" is wrong, and the correction changes the whole risk picture.**

On mainline `coherence_root` is computed, committed, mirrored, **and validated on
block acceptance**:

- declared `crates/bloch-pos-committee/src/header.rs:111`, bytes 272..304 of the
  canonical header
- computed `derive.rs:297` — `coherence_binding(acc, nf) = SHA3-256(DS_COHERENCE ‖ acc ‖ nf)`,
  `DS_COHERENCE = b"BLCH4:COHERE\0\0\0\0"` (`params.rs:709`)
- stamped by producer `produce.rs:240`, node `engine.rs:1169`
- committed as SMT leaves `state_root.rs:1770-1777` under tags `0x07`/`0x08`
- **validated, hard, no gate:** `transition.rs:3285-3287` —
  `if header.coherence_root != pre.coherence_root() { return Err(TransitionError::CoherenceRootMismatch) }`,
  in step 3b of `apply_block` beside `body_root` and `attestation_root`.

Every `[9; 32]` in the tree is inside a `#[cfg(test)]` module. A node emitting a
different value is rejected by every peer today, unconditionally.

**Consequence: activation is not "turning on an ignored field."** The field is
already load-bearing and already pinned to
`SHA3-256(DS_COHERENCE ‖ empty_acc_root ‖ empty_nf_root)`. Making the accumulator
and nullifier roots actually contain something changes `coherence_root`, changes
`state_root`, and is therefore a **hard fork requiring a coordinated fleet
rebuild.** That is more work than the brief assumed, not less.

**One real production defect, found in passing.** `crates/bloch-pos-node/src/genesis.rs:946`
stamps `coherence_root: [0u8; 32]` and its doc claims "all three carried roots are
zero" — but `tools/genesis4-ceremony/src/lib.rs:922` stamps the real
`coherence_binding(...)`, and `:1730-1734` enforces *"an empty pool must commit
the C1.1 empty-set root, not zeros."* **Two genesis constructors disagree on
chain identity.** COHERENCE-C1.2 §7 flags this verbatim and declines to fix it:
*"Whoever owns `genesis.rs` owes either a fix or a written reason."* **PMO action:
assign that owner.** It is inert today only because `genesis.rs` is not the
constructor that made the live chain.

## What exists (merged, live)

`crates/coherence-core` (708 lines, deps only `sha3` + `serde`, zkVM-compilable)
is a **genuine implementation**, not a skeleton: note commitments
(`SHAKE256_32(DOM_CM ‖ …)`), position-bound nullifiers, an incremental
`CommitmentTree` at depth 32, a full `NullifierSet` sparse Merkle tree at depth
256 with non-membership proofs, the `check_spend` statement, and `ShieldedTx`.
Domains frozen at `bloch:coherence:{cm,nf,mt,nfset}:v1`. **Byte-identical across
every worktree** — stable, merged, uncontested.

Specs C1 and C1.1 are **ratified and on mainline**.

## The feasibility number — this is the finding

`docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md` (identical, md5
`ca46fa55ce6bc3652b6dddd241fce589`, in 10 worktrees; **not on mainline**).
SP1 6.5.0, real guest compiled from `coherence-core`, CPU prover, 8 cores, 16 GB:

| Config | Cycles | Core proof | Compressed proof |
| --- | ---: | --- | --- |
| 2-in / 2-out | 1,042,629 | 2.66 MiB in 83.3 s | **1.21 MiB in 214.8 s** |
| 8-in / 8-out | 4,117,538 | 2.70 MiB in 161.9 s | **1.21 MiB in 289.3 s** |

`MAX_BLOCK_TX_BYTES_V2 = 524,288` (`fee_market.rs:85`). So **one** shielded
transaction is **2.43×** an entire block compressed, **5.32×** as Core.

The audit's verdict: *"O desenho da C1 §3, 'FRI cru no corpo do bloco', não é
viável nos limites atuais… Não falta ajustar constante. Falta decidir
arquitetura."*

Two structural facts that should shape any decision:
1. **Compressed proofs are constant-size.** 4× the work grew Core by 1.4% and
   Compressed by **384 bytes (0.03%)** — FRI size tracks the padded shard
   (`MAX_SHARD_SIZE = 1<<24`), not output count. Therefore `MAX_TX_OUTPUTS` and
   proof size **do not compete**, and any analysis trading one against the other
   rests on a false premise. It also makes `SHIELDED_VERIFY_GAS_PROVISIONAL`
   (`fee_market.rs:155`, `= 25 × HYBRID_VERIFY_GAS`) priceable as a constant.
2. **Prove time is 3.6 minutes** for the 2-in/2-out compressed case. That is the
   number the anchor window must be sized against — it replaces the hand-wave
   "minutes" in the spec.

Three exits, none cheap: raise the block cap to ~1.5 MiB (2.4× V2, on a fleet at
13% measured cadence where a binary rotation already costs quorum); move the proof
out of the block body (data availability — scaffold exists at `c5d01f3` on
`feat/zk-ledger`); or Groth16/PLONK, which is **forbidden** by C1 §3 (pairings are
not post-quantum). **This is a founder architecture decision. The PMO cannot
schedule around it.**

## Built but unmerged

| Work | Where |
| --- | --- |
| **COHERENCE-C1.2 draft** (376 lines, sole copy) — anchor policy §3, ratchet §4, `NoteCiphertext` §1, and the §7 list of what it deliberately does not do | `agent-a7231ac21293ef1fa` @ `80a1985f` |
| Node-side **SP1 proof verifier** `bloch-pos-node/src/coherence.rs` (467 lines) | `agent-adc805103a1d8e18e` @ `11b6f533` |
| DEV-7 anchor policy, `TAG_COHERENCE_ANCHORS = 0x17`, `COHERENCE_ANCHOR_ACTIVATION_EPOCH = u64::MAX` | `agent-a905f26b0f5a3faaf` @ `551e94bf` |
| Turnstile counter (`ShieldedPoolExceedsIssued`, enforcing `pool ≤ issued ≤ TOTAL_SUPPLY_SAT`), `TAG_SHIELDED_POOL = 0x17` | `agent-a14a11d370747fe90` @ `327e19cf` |
| `measure/hybrid-baseline` (sole copy) + `TxClass::Shielded { nullifiers }` refactor | `agent-a1a79e7f69714c8e2` @ `bd0e5c3d` |
| The proof-size audit + `measure/{guest,host}` harness | 10 worktrees, one of which (`agent-ae0fd121efaf2d8a8` @ `4bd3032d`) is **detached — no branch** |

The verifier is **deliberately doubly inert**: Genesis-4 has no shielded-tx wire
tag, so nothing can reach `ShieldedVerifier::verify`; and without both the
`sp1-verify` feature *and* `BLOCH_SHIELDED_VERIFY=sp1` the only backend is
`RejectAll`, which it also falls back to on any init failure. *"There is no
shortcut accept anywhere."* It builds its client with explicit `.cpu()`, never
`ProverClient::from_env()`, so `SP1_PROVER=mock` cannot swap in an accepting mock.
`PINNED_ELF_SHAKE256_HEX = None` — **no consensus ELF pin exists**, and the guest
`Cargo.lock` problem is documented: *"sem lock, dois builds honestos divergem →
ELF diferente → vkey diferente → hard fork silencioso."*

`crates/coherence-prover` is excluded at `Cargo.toml:41` for a stated reason
(nightly-only SP1 toolchains), guarded by an emphatic anti-drop note at `:36-44`.
Mainline `measure/` is a **broken fragment with no `Cargo.toml` — it does not
build.** The working harness exists only in worktrees.

## Activation constant — correctly disarmed

`COHERENCE_ANCHOR_ACTIVATION_EPOCH: u64 = u64::MAX`
(`agent-a905f26b0f5a3faaf/…/params.rs:339`). The only coherence activation
constant anywhere; mainline has none. **Leave it.**

The gate is read correctly — `transition.rs:2981` uses the **committed epoch
being closed, never node-local state**, citing the 2026-08-08 `expected_bits`
fork as the standing reason. And the design lets the mechanism ship *before* the
flag day: the anchor record becomes a state-root leaf only once non-empty, so
below the epoch every state root is byte-identical to what the fleet signs today,
with a test proving it (`state_root.rs:3529`). That is the right shape. Note the
documented arming precondition on top of the fleet rebuild: **the finality-rewind
fix must land first.**

## Not built

`shield_tx`/unshield (F10 — the pool is structurally sealed and provably empty,
since `check_spend` enforces `Σin = Σout + fee`); the shielded-tx wire surface;
shielded-pool store persistence; the DEV-8 ratchet in code; `NoteCiphertext` /
ML-KEM-1024 (DEV-2); a reproducible pinned guest ELF; `CommitmentTree::root()` as
O(1) frontier (F7 — it is O(n) per call today); reorg undo wired to fork choice
(F5).

## Honest date

**No date. Not "September", not "Q4."** The gating item is a founder architecture
decision on where a 1.21 MiB constant-size proof lives, and every downstream
estimate is meaningless until it is made. Anything I wrote here as a date would be
a schedule hiding a slip.

**What the PMO can deliver now, and should:**
1. **Arbitrate `0x17`** (see the registry, C-3). Two unmerged worktrees claim the
   same append-only state-root tag; tags re-key every leaf of the component they
   name, so a wrong merge is a silent consensus fork. `agent-a14a11d370747fe90`
   already defers to the PMO in-source at `state_root.rs:265-273`;
   `agent-a905f26b0f5a3faaf` does not acknowledge the conflict.
   **Assignment: `0x17` = `TAG_COHERENCE_ANCHORS`, `0x18` = `TAG_SHIELDED_POOL`.**
2. **Merge the proof-size audit into mainline `docs/audit/`.** It is identical in
   10 worktrees, conflicts with nothing, and it is the number the architecture
   decision turns on. Cheap, and it stops the measurement being rediscovered.
3. **Name an owner for `genesis.rs:946`.**
4. **Put §6 of the audit in front of the founder** — C1.2 ratification is blocked
   on the founder having seen it. That is the decision that unblocks everything
   else, and it is not an engineering task.

**What to tell the exchange:** coherence is not part of this integration. The
header field is stable, validated, and committed to the empty-pool value; nothing
about it will move under them. That is a true and reassuring statement, and it
costs nothing to make.
