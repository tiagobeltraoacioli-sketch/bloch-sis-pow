# A5 — bloch-pos-node engine audit (engine.rs, engine/*, genesis.rs, node tests)

Auditor: A5 (engine). Tree: `main` at `562e220` (working tree clean). Read-only; no build/test run.

## 1. Scope & method

Read in full: `crates/bloch-pos-node/src/engine.rs` (11,480 lines incl. tests), `engine/validator_lifecycle.rs`, `engine/validator_admission_tests.rs`, `engine/devnet_tools_tests.rs`, `engine/replay_bench.rs` (header/knobs), `genesis.rs` (3,326 lines), `tests/cold_start.rs`, `tests/replay_hotpath_perf.rs`, `tests/fuzz_harness_resolves.rs`, `tests/published_checksums.rs`. Read for verification of callers/callees: `net.rs` (queue budget, frame reader, devnet inbound/outbound loops, get-blocks limiter), `codec.rs` (all), `store.rs` (open/append/read_all/rewrite/blocks_after), `slashprot.rs` (guards, commit), `rpc.rs` (EngineBackend), `main.rs` (flag→env wiring), `bloch-pos-committee`: `transition.rs` (`compute_post_state`/`apply_block`/`process_epoch`, tx decoder, roster/seed/key-lookup, `apply_transfer` head), `gossip.rs` (`AttestationPool::process/on_block/hold/prune`), `forkchoice.rs` (`Store::head`), `attestation.rs` (`validate`), `committees.rs`, `fee_market.rs`, `params.rs` constants, `bloch-crypto` `verify`.

Prior material skimmed for KNOWN/NEW labelling: SECURITY.md (M-1), `docs/audit/groundstate_audit.md`, `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`, `docs/audit/VAD-04-LIFECYCLE-SOAK-2026-09-11.md`, `docs/audit/VALIDATOR-ADMISSION-REVIEW-2026-09-08.md` (VAD-03), `docs/specs/BLOCH-POS-NODE-INTEGRATION.md`, `docs/specs/BLOCH-ATTESTATION-GOSSIP.md`, `docs/post-mortems/2026-08-24-finality-divergence.md`, `deploy/FLAG-DAY-EPOCH-2700.md`, `deploy/monitoring/README.md`, `docs/THREAT-MODEL-AUDIT.md` (Genesis-3 era). The "Round-3 remediation audit" that SECURITY.md cites (M-1, M-4, M-5, NEW-1) is not in the tree; its findings are known only through code comments and `deploy/monitoring/README.md`, so "KNOWN (R3 …)" below means "the code comments claim this was an R3 finding and I verified the current code against that claim".

Method: adversarial reading of the block/attestation/transaction paths from an unauthenticated devnet-mesh peer's point of view (the live transport per `net.rs` module doc: no authentication, no admission control, no per-peer rate limit except get-blocks), plus the privileged (validator-key) attacker; every claimed fix in comments was re-derived from the code. All line numbers are for `crates/bloch-pos-node/src/engine.rs` unless another file is named. Cost figures use the repo's own measured numbers (hybrid verify ≈ 145 µs, engine.rs:5738; ML-DSA-65+Falcon-1024 pubkey 3,749 B, signature ≈ 4,589 B).

## 2. Findings (ordered by severity)

### EN-01 — One admissible transaction censors every transaction on the network (`select_transactions` breaks on the first over-cap entry)
- Severity: **High** (borderline Critical: network-wide, no precondition, sustained; block production and finality continue, only value transfer stops)
- Status: **NEW**
- Refs: `engine.rs:3166-3216` (`select_transactions`), `:5621-5688` (`admissible` Transfer arm), `:2877-2942` (`sweep_mempool`), `:2843-2875` (`evict_stale_mempool`), `:3022-3144` (`on_transaction`)
- Description: The producer packs by walking the mempool in descending `tx_tip_rate` and **`break`s** at the first entry whose `max(encoded, declared)` does not fit the remaining cap:
  ```rust
  let n = (encoded.len() as u64).max(declared);
  if bytes.saturating_add(n) > cap { break; }
  ```
  A transaction whose wire size alone exceeds `max_block_tx_bytes` (524,288 B post-800) therefore stops the selection dead, and every lower-priced honest transaction behind it is skipped. Such a transaction is admissible: `admissible` checks structure, dust, `price_bounds` (≤ 60 M gas — 64 inputs at 72,748 gas + 16/byte is ≈ 13 M) and `declared_size_bound` (declared ≤ encoded + 4,589), then verifies each input's signature against **the pubkey carried in the input**. It never checks that the pubkey owns the outpoint (that is consensus's `ScriptMismatch`, transition.rs:3941) and never checks duplicates within the tx (consensus `DuplicateInput`, transition.rs:3932). So the attacker builds a ~530 KB V1 transfer with ~64 inputs naming *existing* outpoints (anyone's — e.g. the founder's well-known outputs) signed with the attacker's own key, sets `tip_millisat_per_gas` to anything above the honest population (the ceiling is `MAX_TIP_MILLISAT_PER_GAS` = total supply × 1000; nothing at the door checks the tip is payable), and submits it once over the mesh (or RPC). Every node admits it, re-broadcasts it, and sorts it first.
- Why it is never evicted: it never reaches the transition (it is never selected), so the proposer's drop loop never bars it; `sweep_mempool` only checks outpoint *existence*, which passes; the only exit is `MEMPOOL_TTL_SLOTS` = 100 head slots (≈50 min), and `an_expiry_bars_nothing` — the same bytes are re-admitted on the next offer. One 530 KB frame every 50 minutes keeps every proposer on the network producing empty blocks indefinitely.
- Variant: several high-tip transactions of ~300 KB that spend real outpoints under the wrong key: the first is selected, refused by the transition (`ScriptMismatch`, indexed), removed and barred; the loop retries with the now-empty remainder → empty block. Each proposal burns one attacker entry; 4,096 entries (64 sources × 64) ≈ 34 hours of empty blocks per batch.
- Evidence: `selection_budgets_by_declared_bytes_not_wire_bytes` (engine.rs:7447) only asserts `consensus_weight <= cap` and `!selected.is_empty()` with an attacker tx at tip 0; with a higher tip the `break` yields an empty selection, which no test covers.
- Recommendation: `continue` (skip) instead of `break` when an entry does not fit, and refuse at the door any transfer whose `max(encoded, declared)` exceeds the block byte cap. In `on_transaction` (which, unlike the stateless `admissible`, holds `self.state`) also check outpoint existence **and ownership** (`owns(sha3(pubkey), entry.script_hash)`) and in-tx duplicate outpoints — one SHA3 + one map lookup per input, before the hybrid verifies. Make expiry of a never-selectable entry bar the bytes (or key on a stable id).
- Confidence: high (code path fully traced; not executed).

### EN-02 — Mempool is bounded by count (4,096) but not by bytes: ~28 GB per node from one unauthenticated peer
- Severity: **High**
- Status: **NEW for bloch-pos-node** (class recorded for the Genesis-3 node in `docs/THREAT-MODEL-AUDIT.md:135-136` "mempool bounded by count not bytes"; the PoS engine's `MEMPOOL_MAX` doc at engine.rs:167 only describes a count)
- Refs: `engine.rs:167-172` (`MEMPOOL_MAX`), `:190` (`MEMPOOL_MAX_PER_SOURCE`), `:3041-3047` (per-source cap keyed on the *first* input's pubkey), `:5621-5688` (`admissible`), `codec.rs:24` (`MAX_FIELD_LEN` 8 MiB), `net.rs:271-323` (byte budget applies only to the *queue*, not the mempool)
- Description: A V1 transfer may carry up to ~824 inputs before `price_bounds` refuses (60 M / 72,748), each ≈ 8.3 KB (pubkey + signature) ≈ 6.8 MB per transaction, all inputs may be byte-identical copies of one (pubkey, signature) pair (duplicate outpoints are consensus-only), and `tx_bytes` may be under-declared at the door (only the ceiling is policed). With 64 throwaway keys (per-source cap is on the first input only) an attacker fills 4,096 × 6.8 MB ≈ 28 GB of `mempool` + the parallel `mempool_admitted_at` keys (another copy of every canonical encoding, since the map key *is* the bytes: `mempool: BTreeMap<Vec<u8>, PosTransaction>` — so each entry costs ≈ 2× its wire size). Every admitted transaction is re-broadcast to every peer, so the whole fleet fills. Signing cost to the attacker: one hybrid signature per transaction (≈4,096 signatures). Eviction: TTL 100 slots, no bar, re-sendable; fee-rate eviction at capacity favours the attacker (EN-06).
- Recommendation: add a byte budget to the mempool (e.g. ≤ 2 × block byte cap × some factor), refuse any single transaction above the block byte cap, reject duplicate inputs and unowned outpoints at the door (EN-01), and key `mempool` by txid rather than by the full canonical bytes.
- Confidence: high.

### EN-03 — Doppelgänger protection halts a validator permanently when its *own* pre-restart attestation is replayed to it
- Severity: **High** (unauthenticated; realistic precondition: a routine restart in the same epoch after the validator's duty slot; the attacker can pre-position by continuously replaying)
- Status: **NEW**
- Refs: `engine.rs:1714-1732` (`note_possible_doppelganger`), `:3813-3826` (`apply_decision` Accept → hook), `:3719-3733` (`on_attestation` epoch window), `:4795-4818` (window armed from boot wall slot), `gossip.rs:355-369` (dedup only against a per-process `seen`)
- Description: The hook treats *any* accepted attestation under this node's index during the 64-slot post-boot window as proof of a live duplicate and sets `doppelganger_halted = true` "permanently, until a restart". A validator attests exactly once per epoch (committees partition 64 validators over 32 slots). If it restarts at any later slot of the same epoch, its own earlier, genuinely signed attestation is (a) still inside `on_attestation`'s `{wall_epoch, wall_epoch+1}` window, (b) unknown to the fresh `AttestationPool` (the `seen` map is in-memory), (c) verified by its own key → `Accept` → hook → halt. The devnet mesh is unauthenticated and attestations are public, so any peer can hold every validator's latest attestation and replay it every few seconds; on a running node the replay is deduped (`Ignore`), on a freshly restarted one it lands. Result: the validator signs nothing until an operator restarts it with `BLOCH_NO_DOPPELGANGER=1` — and the runbook (`deploy/FLAG-DAY-EPOCH-2700.md` §3) tells operators *not* to use that flag. Across a fleet restart wave this converts routine restarts into missed epochs and feeds the inactivity leak. Reference clients (Lighthouse) avoid exactly this by not counting sightings from the epoch the node started in.
- Related gap (Info): the hook is invoked from `apply_decision` and after `blocks.insert`, but **not** for attestations accepted via `release_held` (engine.rs:3890-3902), so a real duplicate whose attestation arrived before its block is not detected — the protection is asymmetric.
- Recommendation: only count sightings whose *signed slot* is ≥ the boot wall slot (attestation `data.slot` / header `slot`): a validator cannot have signed a slot after its own boot unless a second instance exists; the field is signature-bound so a peer cannot forge it. Apply the same hook on the `release_held` path.
- Confidence: high.

### EN-04 — `on_transaction` runs an O(mempool) SHA3 scan *before* any cheap refusal: ~40 ms of consensus-thread CPU per 120-byte frame
- Severity: **High** (single-node DoS by an unauthenticated peer at KB/s bandwidth; every validator can be targeted simultaneously)
- Status: **NEW**
- Refs: `engine.rs:3037-3047`, `:514-528` (`tx_source_hash` computes `Sha3_256::digest(pubkey)` for the first input of *every* mempool entry on every call)
- Description:
  ```rust
  if let Some(source) = tx_source_hash(&tx) {
      let from_source = self.mempool.values().filter(|t| tx_source_hash(t) == Some(source)).count();
  ```
  runs after the dedup and `is_rejected` checks but before `admissible`, capacity, and every signature check. Each mempool entry's ~3.75 KB pubkey is re-hashed (≈10 µs) per incoming transaction: 4,096 entries ≈ 40 ms; 500 entries (an organic population) ≈ 5 ms. A minimal Transfer frame (one input, 1-byte pubkey, ~120 bytes) is enough to trigger the scan and is then refused by `admissible` for free. 200 such frames per second — 24 KB/s — pin the consensus thread on a moderately full mempool; the attacker can pre-fill the mempool itself (EN-02). While pinned, `attest`/`propose` (same thread, `run` loop engine.rs:5210-5219) are delayed and blocks queue up.
- Recommendation: cache the source hash per entry (store `(source_hash, tx)` or keep a `BTreeMap<[u8;32], usize>` counter updated on insert/remove); run the per-source check after the cheap structural refusals.
- Confidence: high.

### EN-05 — Future-slot blocks are stored *and applied* immediately: a scheduled proposer can void up to 7 preceding slots, and honest clock skew voids slots by accident
- Severity: **Medium** (privileged: any validator key; also triggered by honest skew ≥ 1 slot)
- Status: **NEW**
- Refs: `engine.rs:415` (`FUTURE_SLOT_TOLERANCE` = 8), `:2355-2367` (only refuses beyond tolerance), `:2474-2476` (insert + `advance` at once), `:1884-1886` (`propose` builds on `head_id()` with no slot check), `:2058-2070` (REFUSED OWN BLOCK drops the block's txs from the mempool), `forkchoice.rs::head` (descends into any child, ties to the highest id), `transition.rs` step 1 (`header.slot <= pre.slot` → `NonMonotonicSlot`)
- Description: A block whose `header.slot` is up to 8 slots past this node's wall slot is authenticated, inserted into `blocks`, and `advance()` runs fork choice and `apply_canonical` right away — the transition has no notion of wall time, so a block for slot s+k applied at slot s is valid. The validator scheduled for slot s+k (k ≤ 8) publishes at slot s: every node adopts it as head (only child of H, or the higher-id sibling of the honest slot-s block — the attacker can grind its id via body contents); the honest proposers for s..s+k−1 then build on a head whose slot exceeds theirs → `NonMonotonicSlot` → "REFUSED OWN BLOCK", slot lost, and their selected transactions are dropped from their own mempool. Attesters at those slots vote for the attacker's block. Each validator gets ~0.5 proposals per epoch, so one malicious validator can void ≈ 12 % of slots continuously; a validator whose clock is 30–60 s ahead does the same to 1–2 slots per proposal by accident. Ethereum clients queue future blocks until their slot for precisely this reason.
- Recommendation: park a gossiped block whose slot is ahead of the wall slot (beyond a sub-slot disparity) in a bounded queue and ingest it when its slot arrives; never build on a head whose slot ≥ the proposing slot (skip the slot rather than sign an invalid block); do not drop own transactions on a refused own block.
- Confidence: high.

### EN-06 — Mempool ordering and capacity eviction trust an unbacked, sender-chosen `tip_millisat_per_gas`
- Severity: **Medium** (network-wide censorship at capacity; no precondition beyond bandwidth)
- Status: **KNOWN in class** (VAD-03, `docs/audit/VALIDATOR-ADMISSION-REVIEW-2026-09-08.md:27`: "Fee-based eviction also relies on the announced tip before funding is checked" — stated for `FundedDeposit`; the mempool doc engine.rs:3013-3015 admits "no fee floor"); **NEW** that it applies to transfers and combines with EN-01/EN-02
- Refs: `engine.rs:3058-3083` (evict lowest rate when incoming rate is strictly higher), `:3181-3184` (ordering), `fee_market.rs:245,268` (`MAX_TIP` = `TOTAL_SUPPLY_SAT * 1000`)
- Description: Nothing at the door checks that the sender can pay the tip (or the base fee); the tip is a field the attacker sets. At capacity every honest transaction is evicted by an attacker transaction claiming a higher rate; in selection the attacker's entries always sort first. Combined with EN-01 this is what makes the censorship deterministic.
- Recommendation: price-check at the door against the spent outputs' values once EN-01's ownership/existence check exists (`spent ≥ outputs + intrinsic_gas × (base_fee + tip)`); a fee floor.
- Confidence: high.

### EN-07 — No per-peer budget on hybrid verifications for unauthenticated attestations/transactions on the devnet mesh; rejected messages are not remembered
- Severity: **Medium** (single-node CPU DoS; needs ~200 Mbps for full saturation via attestations, less via transactions; EN-04 is the cheap variant)
- Status: **partly KNOWN** (the cost is acknowledged at engine.rs:5738 and gossip.rs's R3 NEW-1 comment bounds the *Hold* pool; no prior source quantifies the reject path on the live transport)
- Refs: `gossip.rs:355-405` (steps 3–5: dedup covers only accepted/pending; a `Reject`ed or `Ignore`d attestation leaves no trace), `engine.rs:3744-3811` (`judge`), `net.rs:1010-1030` (inbound loop: no rate limit on data frames), `engine.rs:5681-5686` (V1 verifies every input, duplicates included)
- Description: Per attestation frame (~4.7 KB) the engine pays `rolled_to` (memo hit), an ancestry walk, a committee draw and one hybrid verify ≈ 150–200 µs, and a bad-signature attestation is rejected without being recorded, so the same bytes cost the same again. Varying `source_root` gives unlimited distinct signing roots for a committee member's index (committee membership is public). Transactions: up to 824 verifies per ~6.8 MB frame (all inputs verified even when they are copies of one pair). The queue byte budget bounds memory, not CPU. On libp2p, gossipsub scoring charges `Reject`s to the peer; on the live devnet mesh nothing does.
- Recommendation: per-connection token bucket for data frames (mirror `GetBlocksLimiter`); a small negative cache keyed by `(validator, signing_root)` for rejected attestations; dedupe identical `(pubkey, signature)` pairs in a V1 transfer before verifying (verify once per distinct pair).
- Confidence: high on mechanism; the bandwidth threshold is an estimate.

### EN-08 — The shared engine queue budget has no per-peer fairness: one peer can keep honest blocks and attestations shed
- Severity: **Medium**
- Status: **partly KNOWN** (O06 introduced the budget, `net.rs:251-271`; per-peer fairness is not discussed)
- Refs: `net.rs:313-330` (class caps: blocks may take the whole 64 MiB), `net.rs:687-700` (`send_to_engine` sheds when reservation fails), `engine.rs:2276-2294` (a junk 8 MiB block costs the engine ~20 ms of hashing/decoding before the ~150 µs failed verify)
- Description: Eight 8 MiB block frames (a header + ~1,700 garbage attestations, no valid signature needed) reserve the entire byte budget; while they wait, `try_reserve` fails for every honest frame from every other connection, which is shed. The engine drains them in ~160 ms, so a sender at ~50 MB/s keeps the budget full permanently; honest blocks then arrive only through the rate-limited pull path (8 pages/s/connection). The devnet mesh accepts up to 128 inbound connections from anyone.
- Recommendation: per-connection share of the budget (or per-connection queues drained round-robin); charge the reservation after the cheap header/commitment checks rather than at the socket.
- Confidence: medium-high (traced; drain cost estimated).

### EN-09 — A validator key can grow `blocks` (a fork-choice input) without bound above the finalized floor
- Severity: **Medium** (privileged: any of the 64 keys)
- Status: **NEW** (H8 closed the unauthenticated half; the field doc at engine.rs:911-914 only names canonical growth)
- Refs: `engine.rs:2453-2476` (authenticated + parent known ⇒ stored), `:2745-2750` (only the block that fails `apply_canonical` is removed), `:2519-2548` (pruning only below `first_slot_of_epoch(finalized_epoch)`), `:5423-5474` (`forkchoice_store` is O(|blocks| + Σ body attestations) per call, ≥ 2 calls per ingest)
- Description: Any block signed by a registered key whose parent is known and whose slot ≤ wall + 8 is stored regardless of whether the signer is the scheduled proposer for that slot (that is only checked at apply time, and a block is only applied if fork choice selects it). A malicious validator can emit hundreds of distinct blocks per second (vary slot/parent/body), each ~5 KB, all stored for at least two epochs before pruning; fork choice and `prune_below_finalized` become O(n) per ingest on every node. `ancestral_boundary_mix` (EN-15) and `path_to_canonical` bounds also grow with it.
- Recommendation: check `schedule::proposer(seed, slot)` against `proposer_index` at the door (a hash from state this node already holds), cap non-canonical stored blocks per proposer per slot, and prune stored blocks older than N epochs behind the head regardless of finality.
- Confidence: high.

### EN-10 — Duties are signed against an artificially rolled stale state while the node is behind
- Severity: **Medium** (self-inflicted; degrades peer scoring on libp2p, wastes slashprot watermarks, spawns junk fork blocks)
- Status: **NEW**
- Refs: `engine.rs:5210-5219` (`attest`/`propose` gated only on `in_grace` and `slot > last_*`, not on `behind`), `:1753-1761`, `:1818-1826` (roster/seed from `rolled_to(e)`), `transition.rs:2354-2400` (`seed_for_epoch` on a rolled state falls to the frozen head mix), `slashprot.rs:311-341` (watermarks consumed)
- Description: After the 2-slot grace and the 64-slot doppelgänger window a node that is still syncing (a cold start is hours per the replay comments) rolls its stale head forward through every missing epoch; `boundary_mixes` then hold the head's frozen mix, so the committee/proposer draw is wrong. The node signs an attestation for the wall epoch (target = its stale checkpoint) — consuming the epoch's attestation watermark so it cannot vote correctly once caught up — and, whenever the wrong draw names it, a block on its stale head that is valid *on that branch*, stored by every peer (EN-09 shape). Peers `Reject` the attestations (`NotInCommittee`), which on libp2p penalises the syncing node's score.
- Recommendation: skip duties while `behind` (head more than one slot behind wall and no recent apply), which the loop already computes.
- Confidence: high.

### EN-11 — `gettxstatus` hashes every mempool transaction on the consensus thread
- Severity: **Medium** (requires RPC reachability; public RPC nodes exist and the RPC has no auth/rate limit)
- Status: **NEW**
- Refs: `engine.rs:2594-2610` (`tx_status`: `self.mempool.values().any(|tx| &tx.txid() == txid)`), `transition.rs:696` (`txid` hashes the canonical bytes)
- Description: Each call re-encodes and hashes every mempool entry; with an EN-02-sized mempool that is tens of GB of SHA3 per RPC call, serialised on the consensus thread (the RPC only answers `getbalance`/`getutxos` off-thread, rpc.rs:960-1015). Even an organic 4,096 × few-KB mempool costs ~ms per call with no concurrency limit.
- Recommendation: maintain a `txid → key` index on admission/removal; answer from it.
- Confidence: high.

### EN-12 — `release_held` judges released attestations with the *wall epoch's* seed and roster, not the attestation's
- Severity: **Low**
- Status: **NEW** (the comment at engine.rs:3866-3873 names a different, narrower "KNOWN GAP")
- Refs: `engine.rs:3852-3877`
- Description: `rolled_epoch = epoch_of(self.wall_slot)` is used for both the roster and `seed_for_attestation(&root, rolled_epoch)`, but `on_attestation` admits attestations for `wall_epoch + 1`. An attestation for the next epoch held across a boundary race is re-judged with the previous epoch's seed → `NotInCommittee` → `Reject`, which on libp2p penalises the honest relaying peer. Also the fallback `unwrap_or_else(|| Self::seed_for(&rolled, rolled_epoch))` reintroduces the head-anchored seed the 2026-08-24 fix removed.
- Recommendation: derive seed and roster per released attestation from `epoch_of(att.data.slot)`; on an unjudgeable seed return `Ignore`, never `Reject`.
- Confidence: high.

### EN-13 — Re-offered orphans pay a hybrid verify on every delivery
- Severity: **Low**
- Status: **NEW** (the test `the_same_orphan_offered_repeatedly_occupies_one_slot` pins the slot count, not the verify count)
- Refs: `engine.rs:2257-2270` (door dedup checks `blocks`, `canonical`, `parked_refused_finality` — not `orphans`), `:2422-2433` (verify), `:2490-2493` (dedup inside `park_orphan`, after the verify)
- Recommendation: add `self.orphans.iter().any(|(seen, _)| *seen == id)` to the door check.
- Confidence: high.

### EN-14 — Orphans hanging off a latch-refused branch keep the sync pump broadcasting `get_blocks` to all peers indefinitely
- Severity: **Low**
- Status: **KNOWN residual of R3 M-1** (the fix at engine.rs:2262-2270 stops re-authentication of the parked blocks themselves; it does not cover their children)
- Refs: `engine.rs:2450-2458`, `:2139-2147` (`sync_after_slot`: `needs_sync` or non-empty `orphans` ⇒ request), `:5225-5231` (broadcast every two slots), `:2539-2547` (orphans pruned only below the finalized floor)
- Description: Children of a parked branch have an unknown parent (it is neither in `blocks` nor canonical) → `park_orphan` → `needs_sync = true` every time; `sync_after_slot` returns a window two epochs below the orphan; every peer answers up to 512 blocks per request, every two slots, forever (or until finality moves past the orphan's slot).
- Recommendation: treat a parent that is in `parked_refused_finality` as "refused" and drop the child at the door.
- Confidence: high.

### EN-15 — `ancestral_boundary_mix` walk is bounded by `blocks.len()`, and stored non-canonical blocks are not slot-monotone
- Severity: **Low** (privileged; amplifies EN-09)
- Status: **NEW**
- Refs: `engine.rs:1451-1474`, `:3779` (called per arriving attestation)
- Description: Stored blocks are only signature-authenticated and connected; a parent may have a higher slot than its child (the transition would refuse it, but only at apply). A validator key can build a stored chain whose slots never drop below `first_slot_of_epoch(epoch)`, so every attestation whose `target_root` names its tip walks the whole chain (`for _ in 0..=self.blocks.len()`).
- Recommendation: refuse at the door a block whose slot ≤ its parent's slot (both known); cap the walk at `2 × SLOTS_PER_EPOCH` steps.
- Confidence: high.

### EN-16 — The proposer's drop loop bars innocent transactions on non-indexed transition errors
- Severity: **Low** (largely unreachable from mempool contents today)
- Status: **partly KNOWN** (engine.rs:1945-1965 documents the tail fallback as deliberate)
- Refs: `engine.rs:1966-1997`, `:1278-1286`
- Description: For `TransitionError::Attestation(i)`, `TooManyAttestations`, cap errors, root mismatches etc. the loop pops the *tail* transaction, removes it from the mempool and bars it for 128 slots, repeating until the selection is empty — up to 256 honest transactions barred and the slot lost — for a fault that is not in any transaction. The attestation case is reachable whenever the gossip judge (head-rolled roster/seed) and the transition (parent pre-state) disagree, e.g. after a reorg once deposits are armed; the attestation set is never pruned by the loop.
- Recommendation: on a non-transaction error, retry once with `atts` emptied before touching `txs`; never bar on non-indexed errors.
- Confidence: medium.

### EN-17 — `do_reorg` rewrites the whole block log synchronously on the consensus thread
- Severity: **Low** (liveness; grows with chain age)
- Status: **NEW** (the write-to-temp+rename design is documented in `store.rs:782-800`; its O(chain) cost per reorg is not)
- Refs: `engine.rs:3670-3678`, `store.rs:785-800`
- Description: Every reorg — including the depth-1 give-back the module doc calls routine — re-encodes and writes every canonical envelope (mainnet: ~10⁵ blocks, ~1 GB) plus fsync, on the thread that attests and proposes; disk usage doubles transiently. Also `read_all` (store.rs:739) loads the entire log into memory at boot.
- Recommendation: truncate-and-append (index-backed) instead of full rewrite; or move the rewrite off-thread behind a durable "pending reorg" marker.
- Confidence: high on mechanism; size is an estimate.

### EN-18 — RPC events bypass the queue budget and are answered on the consensus thread
- Severity: **Low** (loopback default; the public RPC nodes are the exposure)
- Status: **KNOWN in spirit** (engine.rs:5106-5114 warns the RPC has no rate limiting)
- Refs: `engine.rs:4674-4680` (one unbounded `mpsc::channel`), `rpc.rs:1017-1046` (`ENGINE_TIMEOUT` = 10 s is a client timeout, not a server bound)
- Description: `EngineEvent::Rpc` is not reserved in `QueueBudget`; a flood grows the channel without bound and each request (e.g. `getvalidators` ≈ 480 KB of hex, `getblock` by slot = O(chain) scan, `gettxstatus` per EN-11) is served inline.
- Confidence: high.

### EN-19 — `RandaoRecommit` is signed outside slashing protection and outside the doppelgänger gate
- Severity: **Low** (inert: `RANDAO_RECOMMIT_ACTIVATION_EPOCH` = u64::MAX)
- Status: **NEW**
- Refs: `engine/validator_lifecycle.rs:139-201` (`keys.sign` directly; called from the slot loop before `attest`, engine.rs:5211), `:1734-1745` (only `attest`/`propose` consult `doppelganger_blocks_duties`)
- Description: Not slashable today, but it is a signed consensus message emitted by the key with no watermark and no duplicate-instance guard; the field doc at engine.rs:1050-1056 claims slashprot is "consulted before EVERY signature this node makes".
- Confidence: high.

### EN-20 — Two implementations of the boot identity rule; the tested one has no production caller
- Severity: **Info**
- Status: **NEW**
- Refs: `engine.rs:4390-4406` (`check_registry_identity`, called only from `genesis.rs` tests), `:4410-4425` (`check_joining_registry_identity`, the one `run` calls at :4944, with different semantics: advances the RANDAO chain by `reveals_used`, checks activation/exit epochs), `:4306-4322` (manifest pre-pass, a third)
- Also: the wall-slot formula is written out four times (`wall_slot()` :3924, slot loop :5166, doppelgänger :4800, WS gate :5026) — consistent today.
- Recommendation: delete `check_registry_identity` or make it the callee; point the genesis.rs gate tests at the live function.

### EN-21 — `genesis_validator_count` assumes dense manifest indices
- Severity: **Info** (inert on the live dense manifest)
- Refs: `engine.rs:4868`, `:2435-2441`; `genesis.rs:880-1018` (`Manifest::decode` does not check index uniqueness/density)
- Description: The genesis/deposit-added line is `proposer_index < validators.len()`; a sparse or unsorted manifest would treat a genesis index ≥ len as deposit-added (park instead of `Reject` on a bad signature — a free orphan-pool slot per bad frame) and a hole below len as unregistered. `Manifest::decode` should refuse duplicate indices.

### EN-22 — Env/flag-driven node-local safety behaviour (summary; see §3)
- Severity: **Info**
- Status: **KNOWN** (R3 M-1 for the rewind override; R6 HIGH-8 for the doppelgänger bypass)
- Description: `BLOCH_ALLOW_FINALITY_REWIND` changes which branch a node adopts (it lifts the latch that otherwise keeps a node on its own finalized branch); two nodes with different settings can end on different branches after the same input — by design, loudly logged at boot and on every use (verified: engine.rs:4778-4787, :3473-3489). `BLOCH_NO_DOPPELGANGER` removes the duplicate-instance guard. Neither is read by the committee crate; no runtime env var reaches a consensus rule (the committee's `rehearsal` switches are `cfg(test)`, params.rs:498).

### EN-23 — Per-ingest cost and memory grow with chain age; replay is quadratic
- Severity: **Info / Low**
- Status: **KNOWN** (engine.rs:78-86 module doc; engine.rs:911-914; the perf test comment at :6497-6502 "what makes a REPLAY quadratic")
- Refs: `engine.rs:915`, `:5423-5474`, `:2519-2538`, `:2725`
- Description: every canonical envelope stays in `blocks` (mainnet ≈ 10⁵ × ~10–15 KB ≈ 1+ GB and growing ~15 GB/year); `forkchoice_store` rebuilds the parent map and re-observes every body attestation on every call; `prune_below_finalized` scans all blocks per applied block; boot replay therefore costs O(n²) in chain length on top of the state-root cost. Not an attack, but it bounds how long the current design can run.

### EN-24 — Serving `get_blocks` is rate-limited per connection, not per peer/IP
- Severity: **Info** (net.rs; out of my strict scope, recorded as residual)
- Refs: `net.rs:531-537`, `:874-905`, `MAX_INBOUND_CONNECTIONS` = 128
- Description: 128 connections × 8 pages/s × 512 blocks ≈ 5 GB/s of disk reads and egress from one host.

## 3. Environment variables read by the node (runtime and build)

| Variable | Read at | Effect |
|---|---|---|
| `BLOCH_ALLOW_FINALITY_REWIND` (`=1`/`true`; also set by `--allow-finality-rewind`, main.rs:1459) | engine.rs:4778 (once at boot) | Lifts the finality latch: `cut_below_finalized_latch` returns `None` for a cut below this node's own finalized checkpoint, so `advance`/`do_reorg` adopt the heavier branch; logged at boot and at each use. Node-local safety, changes which branch this node follows. |
| `BLOCH_NO_DOPPELGANGER` (any value; also `--no-doppelganger-check`, main.rs:1464) | engine.rs:4795 | Disables the 64-slot post-boot observation window and the permanent halt on a sighting; duties start immediately. |
| `BLOCH_KEYSTORE_PASSPHRASE_FILE` / `BLOCH_KEYSTORE_PASSPHRASE` | keys.rs:230-231, main.rs:784 | Keystore unseal credential (file preferred). A missing credential path no longer silently selects observer mode (engine.rs:4555-4575). |
| `BLOCH_KEYSTORE_ALLOW_PLAINTEXT` (`=1`; also `--allow-plaintext-keystore`) | keys.rs:333 | Permits reading/writing an unsealed `validator.key`. |
| `BLOCH_P2P_TRACE` | p2p.rs:1361 | Verbose libp2p tracing only. |
| `BLOCH_RPC_HOST_ALLOWLIST` | rpc.rs:1384/1405 | Extra `Host` header values the RPC accepts (DNS-rebinding guard relaxation). |
| `BLOCH_BENCH_BLOCKS/RUNS/CARRYOVER/DEPTH` | engine/replay_bench.rs:149 | `cfg(test)` benchmark knobs only. |
| `BLOCH_BUILD_COMMIT` (build.rs:181-218), `BLOCH_BUILD_VERSION`, `BLOCH_SOURCE_DIGEST`, `BLOCH_SOURCE_FILES`, `BLOCH_SOURCE_BYTES`, `BLOCH_BUILD_COMMIT_SOURCE`, `BLOCH_BUILD_TREE_STATE` (`env!` in main.rs:91,121-125) | compile time | Build identity reported by `getbuildinfo`; no runtime effect. |
| `CARGO_MANIFEST_DIR`, `RUSTC`, `PROFILE`, `TARGET` | build.rs | Build only. |

`bloch-pos-committee` reads no environment variable at runtime (only `env!("CARGO_MANIFEST_DIR")` in a header.rs test). `params::rehearsal` mutation switches are `#[cfg(test)]`.

## 4. Positive observations (claims verified)

- **Finality latch (F-03 / R3 M-1)**: `finalized_latch` is engine-owned, ratcheted only upward (`ratchet_finalized`), consulted in both `advance` (:2755) and `do_reorg` (:3575), strict `<`, refusal counted, exported, branch parked and re-offers dropped at the door before any signature work (:2262-2270). Tests cover arm/refuse/strict/park/override (finality_latch_tests). Residual (KNOWN, SECURITY.md M-1): a node whose own finality genuinely diverged from the network stays partitioned until an operator sets the override.
- **Slashing protection on every attestation and proposal path**: `guard_attestation` (:1783) and `guard_proposal` (:2016) run before signing, write-durably (temp+fsync+rename+dir fsync, slashprot.rs:345-370), and implement min-source/min-target (EIP-3076-style) surround/double-vote refusal; `every_signature_leaves_a_durable_watermark_the_next_boot_can_read` pins the wiring; the watermark file is bound to key+genesis (`open_bound`). Producer-side equivocation fence across restarts also holds: block appended+fsynced before broadcast (store.rs:696-733; engine.rs:3292-3301).
- **Crash consistency**: state is in-memory only; the log is the only durable input; append is write+`sync_data`; a truncated trailing frame is dropped and re-synced; `rewrite` is atomic (rename + dir fsync); a crash between watermark and append loses the slot but never double-signs; a crash between `state.set` and `append` loses at most the last applied block, which sync re-fetches.
- **Replay determinism**: boot replay (`ingest_replay`) re-runs the same `apply_block` over the linear log with an empty loose pool; the log is always the canonical chain (rewritten on reorg), so fork choice walks one path and the latch, finality view and head are rebuilt identically. `Source::Replay` exempts the log from both wall-clock bounds (pinned by `boot_replay_applies_a_block_the_same_node_would_reject_from_gossip`). `cold_start.rs` cross-checks per-slot (block id, state root) between a founder and a cold-synced node over libp2p.
- **Producer = validator seam**: the header is stamped from `tr_probe.compute_post_state` on the same parent state, then the block goes through the real `apply_block`; an own-block refusal is loud but non-fatal (h28080 class); `root_budget_tests` pin two state-root computations per proposed slot. The proposer's attestation filter mirrors transition step 8 (epoch, slot ≤ header, source<target, committee from the same partition, `MAX_ATTESTATIONS_PER_BLOCK`).
- **Duty view vs. consensus authority**: `attest`/`propose` and the transition all draw roster and seed from `consensus_roster_at`/`seed_for_epoch` on the same (head-rolled) state; the leak-applied roster is the same object on both sides; `epoch_committees` has no stake filter (membership is index-set only), so the leak cannot re-partition committees. `the_attester_and_the_judge_draw_the_same_committee_below_the_flag_day` pins the seed agreement. `randao_positioned` re-derives the reveal position from committed `reveals_used`, so a reorg cannot desynchronise the RANDAO chain.
- **Ingest ordering (H8/C1)**: dedup → commitment roots → body decode → slot 0 → `MAX_FUTURE_SLOTS` horizon → tolerance → proposer signature (head registry) → parent known → store; nothing unauthenticated reaches `blocks`; forgery under a genesis index is `Reject`, deposit-added ambiguity is parked (O04). `MAX_EPOCH_ADVANCE` backs the horizon for `Local`/`Replay` sources.
- **Fork choice**: rebuilt from scratch per call (no drifting cache), order-independent, equivocators dropped, weights from this node's committed roster only, differential-tested against the O(V·D²) reference (`lmd_ghost_head_reference` is `#[cfg(test)]`, so the binary carries one implementation — the answer to "why two").
- **`Refusal`/`culprit_index`**: the index is bounds-checked against the *current* selection length (stale-index safe); the four refusal shapes reach the RPC as distinct codes with `until_slot` for the retryable one.
- **Panic surface on peer input**: none found. All `expect`/`unwrap` in non-test engine code sit on canonical-chain invariants (`replay_to`, `do_reorg`'s `expect("stored")`, `process_epoch` infallibility); arithmetic on peer-controlled `slot`/`epoch` is saturating or guarded (`first_slot_of_epoch` returns `Option`); `codec` bounds every length; `Manifest::decode` refuses zero `slot_ms`, non-hybrid suites, >u64 allocations.
- **genesis.rs**: carryover ingestion is streaming, strict, four-way checked (SHA3 file digest, SHAKE set root, count, post-split total), duplicate/unsorted outpoints refused, dust rule deterministic with a pinned tie-break; a committed-but-uningested carryover cannot build genesis silently; v2 (`BPOSMAN2`) binding is inert and frozen-v1 identity is pinned; the 1.6 M BLOCH unfunded-bond offset is enforced as a ceiling rather than warned about.

## 5. Test-coverage gaps

- No test drives `select_transactions` with a high-tip entry larger than the byte cap (EN-01) or asserts that honest entries behind a non-fitting one are still selected.
- No test bounds mempool bytes, or admits a transfer with duplicate inputs / inputs owned by another key (EN-02, EN-06).
- `doppelganger_tests` use a zero-signature synthetic attestation; none replays the node's *own* signed attestation after a simulated restart, and none covers the `release_held` path (EN-03).
- No CPU-cost test for `on_transaction` with a full mempool (EN-04), nor a rejected-attestation replay test (EN-07).
- No test ingests a block for slot > wall slot and asserts it is *not applied* until its slot (EN-05); `the_producer_is_not_refused_by_the_bound_it_imposes_on_peers` only covers the producer side.
- No test for `attest`/`propose` while `behind` (EN-10) — `validator_admission_tests` drive both nodes in lockstep.
- `release_held` is exercised only indirectly; no test holds an epoch-(E+1) attestation across a boundary (EN-12).
- No multi-branch reorg test where the loose pool and block bodies disagree about a validator's latest message, and no test of `advance` convergence with a chain of invalid stored blocks (EN-09/EN-16).
- `replay_hotpath_perf.rs` and `replay_bench.rs` are `#[ignore]`d measurements; there is no CI assertion on per-ingest cost vs. chain length (EN-23).
- `cold_start.rs` runs on `--transport libp2p` only; no integration test exercises the live devnet mesh's inbound path with hostile frames.
- The identity gate tests in genesis.rs pin `check_registry_identity`, which production does not call (EN-20).

## 6. Residual risk / not covered

- I did not execute any code; cost figures are derived from the repo's own measurements and byte sizes.
- `net.rs`, `p2p.rs`, `store.rs`, `rpc.rs`, `ws_boot.rs`, `keys.rs` were read only where the engine calls into them; their own surfaces (libp2p scoring parameters, sync limiter, Host allowlist, keystore sealing) are another auditor's.
- The committee crate's rules (finality arithmetic, leak, seed look-ahead, transfer rules) were taken as given except where the engine duplicates them.
- The VAD-04 partition non-healing (leak-applied fork-choice weights differing per branch) is a consensus-design property already documented in `docs/audit/VAD-04-LIFECYCLE-SOAK-2026-09-11.md` §3.3 and not re-derived here; the engine's `forkchoice_store` reads `active_validators()` = leak-applied roster (engine.rs:5447-5449), as that report says.
- Behaviour after the inert flag days (deposits, slashing evidence, RANDAO recommit, exit v2, dust rule) was reviewed for shape only; those paths are unreachable on the live chain and their gated code has not run in production.
