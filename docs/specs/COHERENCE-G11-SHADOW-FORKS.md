<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# G11 — Coherence continuity across the Genesis-4 seam: the three shadow forks

> **Genesis-4 is live.** Bloch has been running under **proof of stake** since
> 21:31:19 UTC on 2026-08-13, when Genesis-3 (proof of work) stopped
> permanently at height **39,918**. 30 s slots, 32-slot epochs, Casper-style
> justification/finalisation by epoch, hybrid ML-DSA-65 ‖ Falcon-1024
> signatures on every consensus path. Nothing in this document that describes
> mining, hashrate, difficulty, retargeting or proof-of-work depth describes
> the current network.
>
> **The live security question is concentration, not hashrate.** All 64
> validators are operated by a single entity; 93.94% of the carryover
> (17,046,829,380 of 18,146,400,000 BLOCH) sits at one address and carried
> balances are stakeable, so if that balance stakes the Nakamoto coefficient
> is 1; and 56,046,829,380 of the 57,146,400,000 BLOCH issued at slot 0 is
> held by the founder and the Foundation, leaving 1.92% of genesis supply in
> third-party hands. One operator can halt the chain and one holder can outvote
> every other. The live transport is a point-to-point TCP full mesh with a
> fixed peer list, **no discovery and no authentication**, and
> `Deposit`/`Delegate` are refused at every node's mempool — which is why a
> third party cannot yet join the network or become a validator.

> **Gate text** (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, gate table): *"Shield-before /
> spend-after passes on three shadow forks; nullifier set and accumulator
> provably unbroken; shielded roots finalized (§6.6)."*
>
> **Owner:** A3 executes, A8/A9 supply vectors. **Status:** plan — concrete
> enough to run; the unit-scale seam crossing is already automated
> (`tools/genesis4-ceremony`, test `shield_before_spend_after_crosses_the_seam`).

## What the seam is

Genesis-3 **stopped permanently at height 39,918 on 2026-08-13** (this line was
written against a planned terminal height of 80,000, which was never reached).
Genesis-4 launched from that snapshot the same day, not ~6 months
later from signed artifacts. Balances cross through the carryover TSV; the
shielded pool **cannot** — a note is a commitment at a consensus leaf position
(`nf = SHAKE256(DOM_NF ‖ nk ‖ rho ‖ LE64(position))`, C1 §1.3), so the pool
crosses through the Coherence artifact (`genesis4-ceremony --coherence`):
leaves in exact position order + the complete nullifier set. The ceremony
replays the leaves through the C1-frozen tree (`coherence-core`), commits
accumulator root, nullifier-set root, counts and artifact digest into the
genesis `state_root`, and stamps `BlockHeaderV4.coherence_root =
derive::coherence_binding(acc, nf)` — the same function every child-block
validator re-derives from parent-committed state.

## Preconditions and known gaps (read before scheduling)

1. **On mainnet the pool is provably empty**: the shielded verifier defaults
   to `RejectAll` and no shield bridge exists (value cannot enter the pool) —
   `BLOCH-COHERENCE-UNDER-POS.md` F3/F4/F10. Forks B and C therefore need the
   pool *artificially* live: run the Genesis-3 node with the mock/permissive
   verifier path used by `src/coherence/mod.rs`'s tests, or drive
   `ShieldedPool::apply_block_self` from a harness. This is a shadow fork —
   never a mainnet configuration.
2. **No pool exporter exists** (the G3 pool is RAM-only, F1/F11). For shadow
   forks the operator IS the only note holder, so the artifact can be
   assembled from the harness's own records (every appended `cm` in order,
   every published `nf`). If A3 prefers a node-side export, it is a ~50-line
   debug RPC (`getcoherencepool`) walking `CommitmentTree.leaves` and the
   nullifier `HashSet` — flag it `--debug-rpc`, never ship enabled.
3. ~~**The Genesis-4 node / genesis loader does not exist yet** (DEV-1).~~
   **Superseded 2026-08-13:** both exist. The loader is
   `crates/bloch-pos-node/src/genesis.rs` (`BPOSMAN1` manifest, deterministic
   block-0 and `CommittedState` synthesis, SHA3-256 manifest digest pinned
   into the data dir) and the node is the binary running the live chain.
   Steps marked **[G4-loader]** should now run against it. Note that
   `derive::validate_block` no longer exists either — it was deleted
   2026-08-12 and validation happens only in
   `transition::Transition::apply_block`.
4. The nullifier-set root is the **ratified C1.1** commitment: a SHAKE-256
   sparse Merkle tree over the nullifier keyspace under `DOM_NFSET`
   (`coherence_core::NullifierSet`, `COHERENCE-C1.1.md`). This replaced an
   interim SHA3 commitment on 2026-08-12; any genesis id from a rehearsal run
   before that date must be regenerated, because the root is a leaf of the
   genesis `state_root`.

   Fork C gains a case from the rev: a **non-membership proof** taken at the
   pre-halt anchor must still verify against the carried root after the
   crossing. If it does not, leaf-level state moved even though the root
   matched, and the spend path is broken in a way the root alone cannot show.

## Fork A — mainnet rehearsal (empty pool)

The fork that must match what the real ceremony will do.

1. Private Genesis-3 net (2 nodes, localhost — the gossipsub-debug recipe),
   terminal height lowered to something reachable (e.g. 2,000) via the
   terminal-height constant in a shadow build. Mine past a few retargets; no
   shielded txs (verifier stays `RejectAll`, as on mainnet).
2. Halt at terminal height. Run `bloch-snapshot-utxo`, then
   `build_carryover.py` (no founder exclusion, no cap — the 2026-08-11
   decisions). Write the empty pool artifact:
   `printf 'bloch-coherence-carryover\t1\n' > genesis4-coherence.tsv`.
3. Two operators independently run `genesis4-ceremony` with both artifacts and
   both digests. **Assert:** identical `block_id`; printed
   `accumulator root` equals the empty `coherence-core` tree root (KAT in the
   crate tests); header `coherence_root != 0^32`.
4. Negative: rerun with (a) `--coherence-shake256` off by one hex digit,
   (b) an artifact with one fabricated leaf appended. **Assert:** both refuse
   before writing any output ("coherence digest mismatch").
5. **[G4-loader]** Feed the document's `coherence-accumulator-root` /
   `coherence-nullifier-root` into `CommittedState::genesis`; produce and
   validate 3 blocks with `produce::produce_block` / `derive::validate_block`.
   **Assert:** every child carries `coherence_root =
   coherence_binding(acc, nf)` and a mutated `coherence_root` rejects with
   `CoherenceRootMismatch` (mutation already covered by the crate's matrix
   test — rerun it in the shadow build).

**Pass = ** ceremony reproducible across operators, empty pool committed as a
real root, tampering fail-closed, mirror validated on children.

## Fork B — live pool: shield before, spend after

The gate's core scenario.

1. Same private net, mock verifier enabled. Before the halt:
   - shield 8 notes across ≥ 3 blocks (positions 0..7 — record every `cm` in
     append order and every wallet witness at creation time);
   - spend notes at positions 1 and 4 (record their nullifiers `nf_1`,
     `nf_4`); create the change notes the spends emit (more leaves);
   - save each unspent note's witness (Merkle path) **as of the terminal
     block** — this is "the witness computed under the old tree" §6.6.1
     protects.
2. Halt exactly at terminal height. Export the artifact: all leaves in
   position order, all published nullifiers sorted. Publish its SHAKE-256.
3. Ceremony as in Fork A (non-empty artifact). **Assert:** printed leaf count
   = total appends, nullifier count = total spends;
   `accumulator root` equals the node's last anchor at the halt (compare
   against the node's `anchor()` logged at halt).
4. Spend-after, at unit scale (runnable today): for each unspent note, run
   `coherence_core::check_spend` with the pre-halt witness against the
   ceremony's `coherence-accumulator-root` as anchor. **Assert:** `Ok(())`.
   For each spent note, **assert** its `nf` is in the artifact set (replay
   must be rejectable by set lookup).
5. **[G4-loader]** With the loader live: submit a real spend of a pre-halt
   note in Genesis-4 block 1 (old witness, genesis anchor). **Assert:**
   accepted. Resubmit the same nullifier. **Assert:** rejected as
   double-spend. Shield a new note; **assert** its position =
   `coherence-leaves` from the document (position continuity — no collision
   with carried nullifiers by position reuse).
6. Restart the Genesis-4 node. **Assert:** identical roots after restart
   (persistence — the F11 fix must exist by then; if the pool is still
   RAM-only this step FAILS the gate, by design).

**Pass = ** old witness spends, old nullifier still burns, positions continue,
roots survive restart.

## Fork C — adversarial seam

Every way the crossing can be corrupted must be *visible* or *refused*.

1. **Reordered leaves:** swap two leaves in Fork B's artifact, fix the digest
   to match (an "honest-looking" but wrong export). Ceremony builds — but
   **assert** the `block_id` differs from Fork B's published one (operators
   comparing block_ids catch it; this is why agreement, not one output, is
   the evidence). Then **assert** the pre-halt witnesses now FAIL against the
   reordered root — the unspendability failure mode, demonstrated, not
   assumed.
2. **Dropped nullifier** (the revive attack): remove `nf_4`, keep the
   published digest. **Assert:** ceremony refuses (digest mismatch). With a
   colluding "published" digest, **assert** different `block_id` — visibly a
   different chain.
3. **Truncated leaves:** drop the last leaf; same two assertions.
4. **Wrong-order sections / unsorted nullifiers / duplicate nullifier /
   uppercase hex:** parser must refuse (covered by
   `coherence_parser_is_strict`; rerun in the fork environment).
5. **[G4-loader]** Loader fed a document whose `coherence-accumulator-root`
   disagrees with the artifact it names: must refuse to start (the
   `chain_requires_carryover` posture extended to the pool).

**Pass = ** nothing corrupt crosses silently; everything corrupt is either
refused or is a visibly different chain.

## Mapping back to the gate text

| Gate clause | Where it is proven |
|---|---|
| Shield-before / spend-after, three forks | Forks A (vacuous but rehearsed), B (§4–5), C (§1 negative) |
| Nullifier set provably unbroken | B §4–5 (old nf still burns), C §2 (drop is refused/visible) |
| Accumulator provably unbroken | B §3–4 (root equality + old witness), C §1/§3 |
| Shielded roots finalized (§6.6) | A §5 / B §5: roots inside `state_root` leaves + `coherence_root` mirror validated by `derive::validate_block`, under FFG finality |

## What this plan does not cover (say it now, not in week three)

- The **shield/unshield bridge** still does not exist (F10); Fork B "shields"
  through the harness. When the bridge lands, rerun B with real `shield_tx`s.
- **SP1 real-proof verification** at the seam (the mock verifier stands in).
  A separate KAT run with `sp1-verify` + pinned ELF belongs to the C2 gate,
  not G11.
- Pool **persistence** (F11) is consumed by B §6 but built by DEV-3 — this
  plan tests it, does not implement it.
