# NOTICE (DRAFT): L2 withdrawal claims require own-chain finality (mandatory node upgrade)

> **Draft, not published, not activated.** In the source the gate
> `params::HF1_CLAIM_FINALITY_EPOCH` is still `u64::MAX`
> (inert). Before publishing: choose **E**, arm the constant and its pinning
> test in a release commit, replay the full L1 history with that build, run
> the mixed-fleet qualification, sign the release, then fill every `{{…}}`.
>
> **HF1.** This rule is the claim-finality half of HF1 (branch
> `codex/hf1-core-20261020`). It may be armed on its own. The other half,
> the frozen finality set (`params::HF1_FROZEN_FINALITY_SET_EPOCH`), may
> only be armed at the same epoch as this rule or later; a build that arms
> the frozen set without this rule does not compile.

| | |
| --- | --- |
| Published | `{{DATE}}` (T−`{{N}}` days; recommended N ≥ 7) |
| Activation epoch **E** | `{{E}}`, first slot `{{E × 32}}`, expected around `{{UTC}}` (30 s slots, 32 slots per epoch; the epoch number is binding, not the clock time) |
| Release | `bloch-pos` `{{VERSION}}`, commit `{{COMMIT}}` (branch `codex/hf1-core-20261020`) |
| Binary SHA-256 (Linux x86-64) | `{{SHA256}}` |
| Release signing key | `bloch-release-20260922.pub` (minisign), key id `1A5D96A5C4955EF7` |
| Who must act | **every** validator, archival / RPC node, bootnode, explorer, indexer, bridge operator and exchange node |

## 1. Summary

From the first block of epoch **E**, an L2 withdrawal claim (L1 transaction
0x16) is valid only if the FFG-finalized checkpoint it relies on is **this
chain's own checkpoint**. Until now the rule compared epochs only. During a
network split, a branch that carries the other branch's attestations can
finalize the other branch's checkpoint, and under the old rule it then paid
claims as if its own history were final. The same withdrawal could therefore
be paid on both sides of a split.

This is a **consensus change (hard fork)**. From the first block of E the L1
state root commits a small new L2 component, the chain's own checkpoint roots.
A node that has not upgraded rejects that block (`StateRootMismatch`) and
stops following the chain at epoch E.

Nothing changes before E. The new release produces the same blocks and state
roots as the current one and replays all history unchanged. Upgrading early is
safe, and we ask you to do it.

## 2. What changes at epoch E

- **Own checkpoint roots.** Each epoch boundary records the chain's own
  checkpoint root for the new epoch: the last block strictly before the
  epoch's first slot, which is the root attesters already vote for. These
  roots are committed in the L2 state. At most four are kept: the finalized
  epoch's root and the three newest.
- **Claim validity.** A claim must already prove against a matured withdrawal
  root whose accepting block is in the finalized prefix. It is now also
  refused (`NotFinalized`) unless the finalized checkpoint's root equals this
  chain's own root at that epoch.
- **Claims pause at activation.** No checkpoint before E is recorded, so
  claims wait until the first checkpoint recorded under the new rule
  finalizes. On a healthy chain that takes about **2 epochs (≈ 32 min)** after
  E. Deposits, settlements and data availability are unaffected.
- **No other change.** FFG justification and finality, fork choice, rewards,
  the inactivity leak, delays, attestor thresholds and release windows all
  stay as they are.

## 3. RPC change (`getl2settlement`, no consensus impact)

Released together with this change. Old fields keep their names.

- `withdrawals.matured` / `matured_large` mean the **delay only**. They now
  carry a `finalized` flag. A matured root with `finalized: false` is refused.
- **New:** `withdrawals.claimable` / `claimable_large` give the newest root a
  claim in the next block can prove against: matured **and** finalized, by the
  exact predicate consensus applies. Claim tooling must use these.
- `withdrawals.roots[].finalized` now applies the full consensus predicate,
  including the own-chain rule once E has passed.
- **New:** `withdrawals.finalized_checkpoint` gives `{epoch, root, own_root,
  own_chain_rule_active}`. After E, `own_root` ≠ `root` means this node's chain
  is carrying a finality that is not its own. Treat that as a split: claims on
  this node's chain will not release, and nothing on it should be credited.

## 4. Interim guidance for exchanges and bridges (now until epoch E)

Until E, the double payout described above is possible on mainnet during a
network split, such as the one on 2026-10-13. Until the upgrade is active:

1. **Credit BLCH from L2 claims (and all BLCH deposits) only on node-level
   finality.** Wait for `gettxstatus` = `"finalized"` (or `getblockbyid` →
   `finality: "finalized"` for the including block). Your node computes this
   against its **own canonical chain**, so a checkpoint finalized on another
   branch does not count. Do **not** use `getl2settlement`
   (`matured`, `roots[].finalized`) or bare epoch numbers as a crediting
   signal. Those compare epochs only.
2. **Halt crediting and withdrawals when finality is not your own.** If
   `getchaininfo.finalized.epoch` > 0 but `getchaininfo.finalized_height` is
   `null`, the finalized checkpoint is not on your node's canonical chain.
   Stop and contact the operators.
3. **Cross-check against at least two independent nodes.** Before crediting
   claim outputs over 100 BLCH, confirm the same `finalized.root` and the same
   including block on two nodes operated by different parties.
4. **Watch for split signals.** These include a stalled `finalized_height`,
   peers disagreeing on the head or finalized root, and `WS_CONFLICT` in node
   logs. On any of them, pause L2-claim crediting until operators announce
   recovery.
5. **Claim tooling:** prove against `withdrawals.claimable` once you run the
   new release. On the old release, use a root whose `finalized` is true
   **and** whose accepting block your node reports as `"finalized"`.

## 5. What you must do

1. **Upgrade before epoch E** to `bloch-pos` `{{VERSION}}`. Required by
   `{{DATE T−2}}` so the readiness check counts you.
2. **Verify the binary** (`minisign -Vm SHA256SUMS -p bloch-release-20260922.pub`,
   then `sha256sum --check SHA256SUMS`).
3. Restart as usual. The local state cache stays valid. Before E it is
   byte-identical, and from E on it gains one optional trailing section.
4. **Exchanges and bridges:** apply section 4 now, and switch claim tooling to
   `withdrawals.claimable` after upgrading.

## 6. Go / no-go

- **GO** if at least 90% of active stake runs the new release at T−1 day and
  the full-history replay plus the mixed-fleet qualification passed on the
  release commit.
- **NO-GO / postpone** otherwise. We will publish a new E with at least 3
  days' notice. Section 4 stays in force until the rule is active.

## 7. Follow-up (separate, later flag day; not part of this release)

The root cause is that the FFG tally counts votes for any `target_root`
without checking that it lies on the counting chain. Ethereum counts only
"matching target" attestations, whose target equals the state's own block
root at that epoch. The own checkpoint roots this release commits are exactly
the input that rule needs. We will propose it separately because it changes
justification, participation credit and the inactivity leak during splits,
and so needs its own simulation and qualification.
