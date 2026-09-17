# A4 — State root (SMT), header/BlockId, wire codec, domain tags, weak-subjectivity checkpoints

Auditor: A4. Date: 2026-09-16. Tree: `/home/user/bloch-sis-pow` (read-only; no cargo run).

## 1. Scope & method

Files read in full (non-test code) and cross-checked by grep of callers/callees:

- `crates/bloch-pos-committee/src/state_root.rs` (SMT, records, `build_state_tree_inner`, `verify_inclusion`, memo), `header.rs`, `ws.rs`, `derive.rs`, `interfaces.rs` (outline + Boundary 7), `params.rs` (all constants, DS tags, const-asserts).
- `crates/bloch-pos-committee/src/transition.rs`: `CommittedState` (1466–1755), `compute_root` (2594–2830), `genesis` (2129–2200), `seed_for_epoch` (2354), `duty_roster_at` (2483–2533), `compute_post_state` header steps (5440–5645), `apply_block` (5981–5995), binding test (13242–13407).
- Tests: `tests/wire_tag_registry.rs`, `tests/one_state_root.rs`, `tests/state_root_carryover_scale.rs`, `tests/spec_reconcile.rs`, inline test names/bodies of `state_root.rs`, `header.rs`, `ws.rs`.
- Node: `crates/bloch-pos-node/src/codec.rs` (full), `ws_boot.rs` (all non-test code), `ws_tool.rs` (`checkpoint`, `view_of`, `verify`, `envelope` call sites, `manifest_identity`), `engine.rs` (`checkpoint_root`, `enforce_ws_anchor`, WS boot call), `genesis.rs` (`genesis_mix`, `anchor_header`, `genesis_pre_state_root`, `genesis_id`, `state_anchored_at`, `Manifest` fields), `checkpoints/wscheckpoint-1536.{bin,json}`.
- Prior-audit context: `BLOCH-POS-GAPS.md`, `checkpoints/README.md`, `checkpoints/DECISIONS-2026-09-02.md`, `docs/CHECKPOINT-CEREMONY-CHECKLIST.md`, CERTIK dossier §3, `SECURITY.md`, `groundstate_audit.md` (Genesis-3 era, not applicable).

Independent verification performed: recomputed `ws_digest` of `wscheckpoint-1536.bin` in Python (`SHA3-256(DS_WSCKPT ‖ 154 B)` = `a5d0…4e44`, matches the JSON view and the README); decoded all nine fields from the binary and matched the JSON; computed today's wall epoch (≈3024) to assess freshness.

Method: adversarial read of every hash preimage (domain tag, marker, length framing), every collection iterated into a commitment (BTreeMap vs Vec order), every peer-facing decoder (length prefixes, allocation, trailing bytes), every checkpoint rule (threshold semantics, duplicates, replay, downgrade, window bounds), and — for GAP-1 — a field-by-field diff of `CommittedState` against what `compute_root` feeds `ConsensusState`, then of the genesis manifest against what `genesis_root` binds.

## 2. Findings (ordered by severity)

### SR-01 — Genesis cohort is bound by neither the state root nor the genesis block id (only by the 32-bit `network_id`)
- Severity: **Medium**. Status: **NEW** (GAP-1 family; the transition test pins it as "chain identity", which is the false premise).
- Refs: `transition.rs:1497` (`genesis_cohort`), `:2186` (seeded from manifest), `:2532` (`apply_cohort_cap` on every duty roster), `:13399-13406` (test asserts root does not move and says "genesis_cohort is chain identity"); `genesis.rs:117` (`Manifest.cohort`), `:856` (in `encode()`), `:1289-1325` (`genesis_mix` folds carryover digest + `genesis_time_ms` + `slot_ms` only), `:1334-1349` (`anchor_header`: every field zero except `randao_mix`), `:1384-1393` (`genesis_id = BlockId::of(header{state_root = genesis_pre_state_root})`); `ws_boot.rs:100-104` (`network_id_of` = first 4 LE bytes of the manifest digest).
- Description: `CommittedState::genesis_cohort` is read at every epoch (`duty_roster_at` → `apply_cohort_cap`) and changes every validator's effective weight (cohort combined weight tapers to 1/3), hence the proposer draw and committee partition. It is (a) not a state-root component (pinned by the transition test), (b) not in the genesis header (`anchor_header` only carries `genesis_mix`, and the V2Bound `genesis_mix` folds the carryover digest and the two clock fields — the comment at `genesis.rs:1298-1301` claims those two were "the ONLY manifest fields left out of the genesis id", which is false for `cohort`), and (c) not in the genesis state root (the cohort is not a leaf). The only place the cohort reaches a hash that a checkpoint or peer ever compares is `network_id`, a 32-bit truncation of `SHA3(manifest bytes)`.
- Attack / failure scenario: two manifests differing only in `cohort` produce the same `genesis_root`, the same state root at every height, and different proposer/committee schedules from epoch 0 — "a substituted manifest that pairs at height 0 and diverges later", exactly the failure the C5 fix at `genesis.rs:1298-1320` says it closes. A node handed a doctored manifest (the file is an unauthenticated release artifact; a fresh node has no DB to refuse it) would reject every honest block as `WrongProposer` — a self-partition with agreeing roots — and a 2^32 grind on the manifest's free bytes (e.g. an allocation memo, if any exists, or cohort ordering itself since `genesis` sorts+dedups the cohort but the manifest bytes are hashed as encoded) defeats the `network_id` check. Requires a supply-chain/manifest substitution, hence Medium, not High.
- Evidence:
  ```rust
  // transition.rs:2532
  genesis_cohort::apply_cohort_cap(&roster, &self.genesis_cohort, epoch)
  // genesis.rs:1334 — the genesis id binds only randao_mix (+ state_root via genesis_header)
  fn anchor_header(&self) -> BlockHeaderV4 { BlockHeaderV4 { parent: [0u8;32], state_root: [0u8;32], ..., randao_mix: self.genesis_mix(), ... } }
  // transition.rs:13403
  g.genesis_cohort.push(3);
  assert_eq!(g.compute_root(), base, "genesis_cohort is chain identity");
  ```
- Recommendation: bind the cohort into chain identity — fold `SHA3(cohort)` (or the whole manifest digest) into the V2Bound `genesis_mix` preimage, or commit the sorted cohort as a state-root singleton leaf (next free tag `0x1F`) so state-sync can reconstruct it; rewrite the test comment to say what actually binds it. Same treatment for `genesis_principal_sat` (bound only through the genesis-state registry, not reconstructible from a later root — see §4). Note the genesis id is the checkpoint's `genesis_root`, so the fix is a flag-day-free change only if applied to the manifest→mix derivation before any new network; on the live chain it must be a leaf.
- Confidence: high on the binding gap (verified in code and the test); medium on practical exploitability.

### SR-02 — The signer arrangement (keys + quorum rule + review clock) is not bound by the checkpoint digest
- Severity: **Medium**. Status: **KNOWN** — `checkpoints/DECISIONS-2026-09-02.md` §3b and correction 1, `checkpoints/README.md` ("this file carries the quorum RULE"), `ws_boot.rs:692-702`.
- Refs: `ws.rs:245-281` (`canonical_serialize`/`ws_digest` cover `signer_set_id: u32` only); `ws_boot.rs:676-683` (no keys are baked: "this devnet build bakes no Phase A keys"); `ws_boot.rs:231-343` (`decode_signer_set_file`), `:392-410` (`shape_policy_of`), `:456-461` (`arrangement_window`).
- Description: `ws_digest` binds the arrangement only by integer id. The node trusts whatever keys, `threshold`, `min_external` and `adopted_epoch` the `--ws-signer-set` file declares, after a shape gate (must be exactly 2-of-3/≥1 external or 3-of-5/≥2), a duplicate-key refusal, and a window check. Verified: `boot` calls `shape_policy_of` → `verify_envelope_with_shape_policy` → `arrangement_window` (`ws_boot.rs:716-763`), and `ws-envelope`/`ws-verify` apply the same shape gate (`ws_tool.rs:917-939`, `:1298-1363`) — the NEW-2 claim in the code holds.
- Attack: an attacker who can substitute both files on the channel a fresh node fetches from (the same unauthenticated channel) needs no signature forgery: a same-shaped set with three attacker keys and an envelope signed by two of them verifies on every node. Residual mitigation is out-of-band comparison of the arrangement fingerprint, which the checklist (§7) tells operators to publish but which no tool enforces.
- Recommendation: bake the Phase-A arrangement into the release (spec §6.3 already says so) and make the file form a test fixture; until then, print and require `--ws-signer-set-fingerprint <hex>` at boot so the second channel is machine-checked.
- Confidence: high.

### SR-03 — Fresh-install onboarding is currently refused: the genesis anchor aged out at epoch 2016 and no signed envelope exists anywhere in the tree
- Severity: **Medium** (liveness for new nodes / integrators; not a chain halt). Status: **partly KNOWN** (DECISIONS memo §1 predicted the outage at 2026-09-05 07:07 UTC); the current state — deadline passed, artifact still unsigned in-repo — is **NEW** as observed today.
- Refs: `ws_boot.rs:849-863` (`RequireCheckpoint` → `anchor_age < WS_PERIOD_EPOCHS` else `ERR_WS_REQUIRE_CHECKPOINT`); `ws.rs:140-145` (`WS_PERIOD_EPOCHS = 2048 − 32 = 2016`, `WS_FRESH_EPOCHS = 1008`); `checkpoints/` contains only `wscheckpoint-1536.{bin,json}` — no `*.envelope.bin`, no `signer-set-*.bin` (verified by `find`).
- Description: wall epoch today ≈ 3024. Genesis anchor age ≈ 3024 > 2016 → every fresh node without `--ws-checkpoint` refuses. The only minted checkpoint (epoch 1536) is unsigned; even once signed it is already STALE (age ≈ 1488 > 1008) and EXPIRES at epoch 3552 (≈ 2026-10-02). The exchange-integration doc's fallback ("copy `blocks.log`, `meta.bin`, `ws_latest.bin`") is a full bypass of the mechanism (an unsigned 200 MB tarball including the trust anchor), as the memo itself notes.
- Recommendation: run the ceremony on a *current* publication epoch (≥ 2816 today; 3072 finalizes ≈ 2026-09-17), publish envelope + arrangement + both digests, and add a CI check that fails when the newest in-repo envelope's epoch is older than `wall − WS_FRESH_EPOCHS`.
- Confidence: high.

### SR-04 — `ws-verify` diverges from the booting node: it omits the `arrangement_window` lower bound and carries stale duplicate-key text
- Severity: **Low**. Status: **NEW**.
- Refs: `ws_tool.rs:1234-1405` (`verify`) — no call to `ws_boot::arrangement_window`; compare `ws_boot.rs:748-763` (boot refuses `cp.epoch < adopted_epoch`) and `ws_boot.rs:483-491` (`combine` refuses too); `ws_tool.rs:1284-1291` prints "ws::verify_envelope will still ACCEPT it" for duplicate keys although `decode_signer_set_file` (`ws_boot.rs:329-335`) refuses such a file before that line can run; `ws_tool.rs:1156` claims `verify` is "the exact check a booting node runs".
- Failure scenario: coordinator assembles an arrangement with `--adopted-epoch` later than the checkpoint epoch (e.g. adopts at 1792 and signs 1536 as the memo's fallback suggests), `ws-verify` prints `VERDICT: ACCEPTED`, the checklist §7 says publish — and every joiner refuses with "outside arrangement window". Discovered in the field, after the ceremony.
- Recommendation: call `arrangement_window` in `verify` and print the window; delete the unreachable duplicate-key branch or make it a decode-error explanation.
- Confidence: high.

### SR-05 — A checkpoint's `state_root` / `validator_set_root` are never validated against the block they name, on either side
- Severity: **Low** today (no state download exists); becomes High the day checkpoint-sync state download ships. Status: **NEW**.
- Refs: `ws_tool.rs:262-337` (`view_of` takes `block_id` and `state_root` from RPC JSON; never fetches the header, never checks `BlockId::of(header) == block_id` or `header.state_root == state_root`); `ws.rs:708-720` (`cross_check` compares `block_root` only); `engine.rs:1581-1630` (`enforce_ws_anchor` builds a probe with `state_root: [0u8;32]`, comment: "the rest of the artifact is not re-litigated"); `ws.rs` module docs: "State download then verifies every piece against `state_root` / `validator_set_root`".
- Failure: a compromised or buggy RPC (or a coordinator's edit) can mint a checkpoint with the right `block_root` and a wrong `state_root`; signers re-derive against their own nodes (mitigation), but a node that holds the block never cross-checks the two fields, so a mismatched artifact is accepted and stored as `ws_latest` forever. Nothing today reads `state_root`, so the impact is latent.
- Recommendation: `view_of` should fetch the canonical header bytes, recompute `BlockId::of` and take `state_root` from the header; `enforce_ws_anchor`/`boot` should assert `header(block_root).state_root == cp.state_root` when the block is local; fail closed on mismatch.
- Confidence: high.

### SR-06 — `single_derivation_path` has scan blind spots (currently clean)
- Severity: **Low**. Status: **NEW**.
- Refs: `header.rs:642-720`; `:647` (`read_dir(&src_dir)` non-recursive — `src/transition/{funded,lifecycle}.rs` and `src/transition/*/tests.rs` are never scanned); `:582-605` (`strip_line` treats a `'"'` char literal as opening a string and would hide the rest of that line; `/* */` block comments are not stripped — safe direction).
- Verification: grep of `src/transition/**` for `BlockId(`, `for BlockId`, `BlockId as`, `= BlockId;` — no hits; no `'"'` char literal exists in the crate; the node crate derives ids only through `BlockId::of`/`.block_id()`/`.id()` (39 call sites, no `Sha3(DS_BLOCK ‖ …)` anywhere else). So the invariant holds today; the guard just does not look everywhere it claims to.
- Recommendation: recurse into subdirectories; handle char literals (`'"'`, `'\''`) in `strip_line`; consider scanning `crates/bloch-pos-node/src` for `DS_BLOCK`/`DS_PROPOSE` as a second fence.
- Confidence: high.

### SR-07 — `ws::verify_envelope` alone accepts a zero-threshold arrangement and does not compare signer keys; the crate relies on the node decoder for both
- Severity: **Low** (defense-in-depth; all production callers are gated). Status: threshold=0 **NEW**; duplicate keys **KNOWN** (DECISIONS correction 1; `ws_boot.rs:311-335`).
- Refs: `ws.rs:450-522`: `if env.signatures.len() < set.threshold` is vacuous at `threshold = 0` and `min_external = 0`, so an envelope with zero signatures returns `Ok`; `seen: [bool;256]` is by index, never by `pubkey` bytes. `matches_policy` (`ws.rs:370-377`) fixes the shape only when the caller uses `verify_envelope_with_shape_policy`; `decode_signer_set_file` refuses `threshold == 0` and duplicate keys.
- Recommendation: add `threshold >= 1`, `threshold <= signers.len()`, `min_external <= threshold`, non-empty signers and pairwise-distinct keys to `verify_envelope` itself (boot-time only, no consensus gate needed), so a future release that bakes keys (bypassing the decoder, as `ws_boot.rs:301-305` warns) cannot lose the checks.
- Confidence: high.

### SR-08 — `codec::decode_envelope` pre-allocates from untrusted counts and hard-codes the attestation cap
- Severity: **Low**. Status: **NEW**.
- Refs: `codec.rs:186-199` — `natt > 4096` literal (not `params::MAX_ATTESTATIONS_PER_BLOCK`, enforced separately at `transition.rs:5685`), then `Vec::with_capacity(natt)` (~4096 × 152 B ≈ 620 KB) and `Vec::with_capacity(ntx)` (65 536 × 24 B ≈ 1.5 MB) before any element is read. `Reader::bytes` correctly refuses `n > MAX_FIELD_LEN` and only allocates after `take(n)` succeeds, so per-field allocation is bounded by input length; only the two capacity hints exceed the input.
- Impact: ~2 MB transient allocation per malformed ~320-byte frame; freed on the `truncated` error. Rate is bounded by the network layer (other auditor). No panic: every `take`/`try_into` is checked.
- Recommendation: drop the hints or cap them at `min(n, remaining_len / min_item_len)`; reference `MAX_ATTESTATIONS_PER_BLOCK`.
- Confidence: high.

### SR-09 — ADR-041 leaves (`0x1B`–`0x1E`) have no root-binding test, and the spec registry stops at `0x16`
- Severity: **Low** (test/docs; code verified correct by reading). Status: **NEW**.
- Refs: `state_root.rs:276-279` (tags), `:1990-2004` (`written_off_sat != 0` conditional leaf; `randao_generations` zero-is-absent; `funded_validators` value = `hash_value(&[1])`); neither `every_component_field_is_load_bearing` (`state_root.rs:3535-3675`) nor `every_committed_state_field_is_bound_by_the_root` (`transition.rs:13242`) mutates `written_off_sat`, `funded_validators`, `stake_low_water` or `randao_generations`; `tests/spec_reconcile.rs:118-147` pins the migration spec "up to 0x16"; grep of `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` and `BLOCH-POS-INTERFACES.md` for `TAG_VALIDATOR_FEE_REWARD`, `TAG_DELEGATOR_ISSUANCE_REWARD`, `TAG_PROPOSED_CURRENT`, `TAG_FC_RECENT_VOTE`, `TAG_WRITTEN_OFF`, `TAG_STAKE_LOW_WATER`, `TAG_RANDAO_GENERATION`, `TAG_FUNDED_VALIDATOR`, `DS_SPEND2`: zero hits each.
- Why it matters: "zero has no leaf" rules are exactly where an off-by-one silently un-commits a value; and an independent implementer reading the spec would omit eight components and `DS_SPEND2`.
- Recommendation: add `must_move!` entries for the four ADR-041 fields (and for `issued_sat`, `evm`, `eutxos` in the transition test); extend the §6.1 tables to `0x1E` and add `DS_SPEND2`; update `f06` to pin the full range.
- Confidence: high.

### SR-10 — `state_root.rs` doc claims "no global mutable state" while holding a thread-local two-generation memo (consensus-safe, doc false)
- Severity: **Info**. Status: **NEW**.
- Refs: `state_root.rs:69-72` vs `:397-490` (`SINGLETON_MEMO: thread_local RefCell<HashMap>`; key = `(key, value_hash, depth)`, value = pure fold; two generations of 600 000 entries).
- Verified safe: the memo key is the entire input of `singleton_subtree_root` (the `empty` table is a constant of `DS_STATE`), so a hit equals a recomputation; `tests/state_root_carryover_scale.rs` runs each derivation on its own thread for this reason. Memory: up to ~2 × 600k × ~150 B ≈ 180 MB per thread that computes roots; only `engine.rs` does (33 call sites, one file), so one thread.
- Recommendation: fix the module doc; document the memory bound.
- Confidence: high.

### SR-11 — Domain-tag hygiene: several tags cover two or three preimage shapes, docs are stale, and three tags live outside the registry
- Severity: **Info** (no exploitable collision found: shapes differ in length or in inner-domain). Status: **NEW** (except `DS_PROPOSE` spec row, KNOWN/resolved GAP-7).
- Refs: `DS_RANDAO` — `beacon.rs:283` mix (16+32+32), `:322` **signing** root for re-commit (16+4+8+32), `genesis.rs:1295` genesis mix (16+32+32+8+8): a signed message and two hash-chain steps share a tag, separated by length only. `DS_DEPOSIT` — `staking.rs:291` (`DepositTx::signing_root`, fixed widths) vs `:452` (`wire_deposit_pop_root`, length-prefixed). `DS_SPEND` — `transition.rs:654-673`: structured fold for `Transfer`/`TransferV2`, but `canonical_bytes()` of every other variant. `DS_SLASH` — `slashing.rs:220` and `:491`: identical shape (`validator ‖ lo ‖ hi`) for attestation-pair and header-pair ids; distinct only because inner roots are `DS_ATTEST` vs `DS_PROPOSE`; its doc (`params.rs:1925`) still says "and voluntary-exit signing roots" though exits use `DS_EXIT`. Orphan doc comments at `params.rs:1936-1941` and `:1957-1961`. `transition/funded.rs:18-20` defines `BLOCH:VALIDATOR:{DEPOSIT,FUNDING,POSSESSION}:V1` outside the `DS_*` namespace and outside `domain_separators_match_the_frozen_registry` (`tests/wire_tag_registry.rs:1047`, which scans `params.rs` only).
- Recommendation: one tag ↔ one preimage shape (add a shape byte after the tag where a tag is shared), move the funded tags into `params.rs` so the registry test sees them, fix the two doc comments.
- Confidence: high.

### SR-12 — The weak-subjectivity window's slashability premise is void while slashing, exits and withdrawals are unarmed
- Severity: **Info**. Status: **KNOWN** (CERTIK dossier F-4 reopened: finality is not slashing-backed; `SECURITY.md`).
- Refs: `ws.rs:1-60`, `:140` (`WS_PERIOD = WITHDRAWAL_DELAY − EXIT_DELAY`); `params.rs:1345,1425,1826` (`EXIT_AUTH_`, `SLASHING_EVIDENCE_`, `WITHDRAWAL_ACTIVATION_EPOCH = u64::MAX`), `:1999-2006` (const-assert ties them together).
- Description: the window is derived from "signers of F are still slashable until F + 2016". Today no key can exit or withdraw (so the window never needs to close) and no evidence can be applied (so nothing inside the window is deterred either). The checkpoint therefore protects only against the eventual post-withdrawal key reuse, not against the present validator set — which is founder-operated with 93.94% of stake. Not a code defect; a statement the ceremony announcement must make.
- Confidence: high.

### SR-13 — Same-epoch re-mint is a permanent boot refusal for every node that stored the first artifact
- Severity: **Info**. Status: **KNOWN** (`checkpoints/README.md` "One-way door", DECISIONS hazard note, test `re_minting_one_epoch_halts_every_node_that_saw_the_first`).
- Refs: `ws.rs:601-611` (`accept`: same epoch, different digest → `Conflict`), `ws_boot.rs:806-822` (`Conflict` → boot refused). `issued_at` is inside the digest, so an honest re-mint of the same epoch is a conflict. Verified; nothing to add beyond the runbook rule.

## 3. Domain-separation tags (`params.rs:1880-1957`) — value, use sites (non-test), reuse

| Tag | Value (16 B) | Used at | Preimage shapes under this tag | Reused / notes |
|---|---|---|---|---|
| `DS_SORTITION` | `BLCH4:SORTIT\0\0\0\0` | `committees.rs:341`; `sample.rs:126` (legacy, retained) | seed ‖ role ‖ … (two modules, one dead) | one shape family; legacy module shares it |
| `DS_ATTEST` | `BLCH4:ATTEST\0\0\0\0` | `attestation.rs:44` | fixed 8+32+8+32+8+32 | single |
| `DS_BLOCK` | `BLCH4:BLOCK\0\0\0\0\0` | `header.rs:285` (`BlockId::of`) | 304-B header | single; KAT pinned |
| `DS_BODY` | `BLCH4:BODY\0\0\0\0\0\0` | `derive.rs:106` | marker(leaf/node/empty) ‖ kind(tx/att) ‖ … | one family, marker+kind separated |
| `DS_STATE` | `BLCH4:STATE\0\0\0\0\0` | `state_root.rs:284` | marker 0x00–0x04 ‖ … | one family, marker separated |
| `DS_RANDAO` | `BLCH4:RANDAO\0\0\0\0` | `beacon.rs:283` (mix, 80 B), `beacon.rs:322` (re-commit **signing root**, 60 B), node `genesis.rs:1295` (genesis mix, 96 B) | **three** | shared between a signed message and hash-chain steps; length-separated only (SR-11) |
| `DS_DEPOSIT` | `BLCH4:DEPOSIT\0\0\0` | `staking.rs:291`, `staking.rs:452` | **two** (fixed vs length-prefixed) | SR-11 |
| `DS_SPEND` | `BLCH4:SPEND\0\0\0\0\0` | `transition.rs:654` | structured fold (Transfer/V2) or `canonical_bytes()` (other variants) | **two**; SR-11 |
| `DS_SPEND2` | `BLCH4:SPEND2\0\0\0\0` | `transition.rs:736` | binding ‖ base root | gated (`u64::MAX`); absent from spec §6.1 and from the released registry table |
| `DS_TXID` | `BLCH4:TXID\0\0\0\0\0\0` | `transition.rs:698` | 32-B spend root | single |
| `DS_SLASH` | `BLCH4:SLASH\0\0\0\0\0` | `slashing.rs:220`, `:491` | `validator ‖ lo ‖ hi` twice (attestation pair / header pair) | same shape ×2, disambiguated by inner domains; doc stale (SR-11); never a signing root |
| `DS_PROPOSE` | `BLCH4:PROPOSE\0\0\0` | `header.rs:227` | 304-B header | single; ≠ `DS_BLOCK` (pinned) |
| `DS_EXIT` | `BLCH4:EXIT\0\0\0\0\0\0` | `staking.rs:684` | 32+8 | single |
| `DS_WSCKPT` | `BLCH4:WSCKPT\0\0\0\0` | `ws.rs:277` | 154-B checkpoint | single; independently recomputed |
| `DS_COHERENCE` | `BLCH4:COHERE\0\0\0\0` | `derive.rs:56` | 32+32 | single |

Outside the `DS_*` namespace (not covered by `domain_separators_match_the_frozen_registry`): `BLOCH:VALIDATOR:DEPOSIT:V1`, `…:FUNDING:V1`, `…:POSSESSION:V1` (`transition/funded.rs:18-20`); `BLCH4:GENESIS-4:MAINNET` (`transition.rs:719`, a 32-B label, not a hash tag); legacy `BLOCH-BLOCK-ID-V1` (pinned disjoint at `header.rs:729-746`). All 15 `DS_*` values are pairwise distinct, 16 bytes, zero-padded (pinned by `tests/wire_tag_registry.rs:1047` pairwise check over everything scanned from `params.rs`, and by inline tests). No tag is a prefix of another (fixed 16 B).

## 4. `CommittedState` fields (`transition.rs:1466-1755`) vs the state root (`compute_root`, `:2594-2830`)

| Field | Bound by `state_root`? | How / consequence if two nodes disagree |
|---|---|---|
| `admission_network_domain: Option<[u8;32]>` | **No** (explicit: "deliberately outside") | full manifest digest; read only by gated funded-admission (`funded.rs:258,287`, gate `u64::MAX`). Post-gate: nodes with different manifests accept/refuse different admissions with agreeing roots. Bound to chain identity only via 32-bit `network_id` (SR-01 class) |
| `slot` | No (pinned) | header-bound (`head` = id of header carrying `slot`) — sound |
| `epoch` | Yes (indirectly) | `randao_window` keys the running mix by `self.epoch`; `FinalityRecord.next_epoch` |
| `head: BlockId` | No | it *is* the header's identity; sound |
| `validators` (index, pubkey, staked_sat→u64 saturating, activation, exit, slashed, randao_commitment, withdrawable, credentials, commission) | Yes, all 10 columns | `TAG_VALIDATOR 0x02`, length-prefixed pubkey/credentials |
| `reveals_used` | Yes | folded into the validator leaf |
| `randao_mix` | Yes | running entry of `randao_window` |
| `boundary_mixes` (last 2) | Yes | `TAG_RANDAO 0x05` |
| `genesis_mix` | **No** (pinned as "chain identity") | seed fallback for epochs < 1+lookahead and the "unreachable" `None` arm (`:2387,2394`); bound to chain identity via genesis header `randao_mix` — sound, but the fallback arm means a node lacking a boundary would silently seed from it |
| `genesis_cohort` | **No** (pinned as "chain identity") | **not bound by `genesis_root` either** — SR-01. Consequence: divergent duty rosters under identical roots |
| `genesis_principal_sat` | **No** (not pinned either way) | derived from genesis registry stake → reconstructible only from the *genesis* state, not from a later root; read by ADR-041 `unbacked_principal_sat` (`lifecycle.rs:49-57`, gated). State-sync from a checkpoint cannot rebuild it without the manifest |
| `written_off_sat` | Yes (leaf only if ≠ 0) | `TAG_WRITTEN_OFF 0x1B`; untested (SR-09) |
| `funded_validators` | Yes | `TAG_FUNDED_VALIDATOR 0x1E`, value `hash([1])`; untested |
| `stake_low_water` | Yes | `TAG_STAKE_LOW_WATER 0x1C`; untested |
| `randao_generations` | Yes (leaf only if ≠ 0) | `TAG_RANDAO_GENERATION 0x1D`; untested |
| `finality_engine` (justified map, current_justified, finalized, leaked, next_epoch) | Yes, all 5 fields | one leaf `TAG_FINALITY 0x09`; sources are BTreeMaps so the stable sorts in `FinalityRecord::serialize` are canonical |
| `previous_justified` | Yes | in the finality leaf |
| `pending_votes` (all 6 `AttestationData` fields + signing_root) | Yes | `TAG_PENDING_VOTE 0x0A` keyed `(validator, signing_root)` |
| `latest_messages` | Yes | `TAG_FC_MESSAGE 0x0B` |
| `fc_equivocators` | Yes | `TAG_FC_EQUIVOCATOR 0x0C` |
| `fc_recent_votes` | Yes (empty pre-gate) | `TAG_FC_RECENT_VOTE 0x1A` keyed `(validator, slot)` |
| `current_participation` / `previous_participation` | Yes | `0x03` / `0x04` |
| `deposit_history` (`QueuedDeposit`: 3 fields) | Yes, all | `TAG_DEPOSIT_QUEUE 0x0D` keyed by pubkey hash |
| `pubkey_index` | No (pinned: derived) | derivable from `validators` + `deposit_history`; sound |
| `delegations` (`Delegation`: 6 fields) | Yes, all | `TAG_DELEGATION 0x0E`, positionally keyed |
| `pending_fee_rewards` | Yes | `0x0F` |
| `slashing.applied`, `.window` | Yes | `0x11`, `0x12` |
| `slashing.ejected` | No (documented) | `= {v : registry[v].slashed}`; pinned by `ejected_set_is_exactly_the_slashed_registry` |
| `delegator_slash_losses` / `delegator_fee_rewards` / `validator_fee_rewards` / `delegator_issuance_rewards` | Yes | `0x13`, `0x16`, `0x17`, `0x18` |
| `current_proposed` | Yes | `0x19` |
| `base_fee_millisat_per_gas`, `block_gas_used`, `block_tx_bytes` | Yes | one leaf `TAG_BASE_FEE 0x15` |
| `taint_root`, `coherence_*_root` | Yes | `0x06`, `0x07`, `0x08` (+ header `coherence_root` mirror) |
| `evm` (4 fields) | Yes | `0x10` |
| `issued_sat` | Yes | `0x14` |
| `eutxos` (txid, vout, value, script_hash) | Yes | `0x01`, via the kept `Smt` (single `eutxo_leaf` definition) |

GAP-1 status: the 2026-08-11/12 extension closed the fields GAP-1 named (finality, `reveals_used`, queues, pending fees, fork-choice messages) — verified in `compute_root`. What remains unbound is the genesis triple (`genesis_mix`, `genesis_cohort`, `genesis_principal_sat`) plus `admission_network_domain`; of these only `genesis_mix` is actually covered by chain identity. The epoch-2700 work (`LEAK_RECOVERY_ACTIVATION_EPOCH`) does not touch the component list; every post-2700 component (`0x17`–`0x1E`) is committed and contributes zero leaves pre-gate (`pre_activation_root_is_byte_identical_with_the_recent_vote_component_present` pins one of them). `interfaces::StateRoots` (14 fields) and `StateCommitment` still have no implementation (GAP-5 still open; `grep impl StateCommitment` → none).

## 5. Positive observations (verified)

- SMT soundness: every hash is `SHA3(DS_STATE ‖ marker ‖ …)` with distinct markers for leaf/node/empty/key/value (`state_root.rs:113-123, 282-297`); the key is inside the leaf preimage; depth is fixed at 256 and `verify_inclusion` refuses any proof whose length ≠ 256 (`:1032-1037`); the empty leaf is a hash output, not zeros (`:331-340`); keys are `SHA3(… ‖ tag ‖ entry_key)` with the tag at a fixed offset, so no two components can alias, and every per-component entry key is fixed-width (pinned by `same_natural_key_under_different_components_does_not_alias`). `Smt::get`'s `bit(key, 256)` is unreachable (a `Split` cannot sit at depth 256 with unique keys).
- Incremental tree vs flat recursion vs an independent reference (memo removed, all 256 levels) agree at n = 4 527 by default and at 452 726 under `--ignored`, each on its own thread (`tests/state_root_carryover_scale.rs`). `collapse` correctness is documented as shape-only, with the six depth-arithmetic mutations that do move roots named.
- Serialization: fixed widths, LE, length prefixes on the two variable fields of `ValidatorRecord`, `Option<u64>` encoded `0x00 | 0x01‖v`, count prefixes on the finality lists, every collection sourced from a `BTreeMap`/`BTreeSet` (`CommittedState` doc: "BTreeMap everywhere"); `randao_window` is the single retention rule (`tests/one_state_root.rs`).
- Header: 304-byte fixed-width injective encoding; strict length on decode (trailing bytes refused, `header.rs:166-172`); every field moves the id (12 mutations); KAT pinned from an independent implementation; `BlockId` has a private field, no `From`/`Default`/deserializer; signature lives in the envelope, so re-signing cannot mint a new id; `proposal_signing_root` is `SHA3(DS_PROPOSE ‖ full header)` — it **covers `state_root`**, `proposer_index`, `slot`, `parent`, so the proposer signature cannot be moved to another slot/index/state; transition order verified: slot → parent → version → body/attestation/coherence roots → schedule → signature → … → `state_root` last (`transition.rs:5449-5510, 5636-5643, 5989-5993`).
- Wire codec: strict trailing-byte refusal, `checked_add` bounds in `Reader::take`, no panic site, every length ≤ `MAX_FIELD_LEN` and allocated only after the bytes are present; the header is decoded by the committee crate's own function (no second layout).
- Body Merkle: promotion (not duplication) of odd nodes with leaf/node/empty markers and a tree-kind byte, so CVE-2012-2459-style duplication is structurally impossible and tx vs attestation trees cannot alias; attestation leaves commit the signature.
- WS: `ws_digest` binds version, network id, genesis root, epoch, block root, state root, validator-set root, issued_at, signer-set id; fixed 154 bytes; decoder self-checks by re-serializing (`ws_boot.rs:121-149`); every listed signature must verify (no "enough valid ones"), quorum and external counts run before any hybrid verify, signatures verify under both halves (`staking::verify_hybrid`, AND, `sig.len() <= MLDSA65_SIG_BYTES` refused); anti-rollback ignores older epochs; running nodes never reorg on a checkpoint (`cross_check` → alarm only; hard anchor → `exit(1)` only for nodes with no finality of their own); `ws_latest` persisted with fsync + dir fsync; the NEW-2 shape gate, duplicate-key refusal, saturating-`adopted_epoch` refusal and `arrangement_window` are all present on the boot path and on `ws-envelope`.
- The published epoch-1536 artifact: bytes, JSON view and digest are mutually consistent and reproduce from the documented formula.
- Const-asserts: ADR-041 gates tied together and `DEPOSIT_ACTIVATION_EPOCH == u64::MAX` enforced at compile time (`params.rs:1999-2006`); `WS_PERIOD_EPOCHS` is a const subtraction (compile error if it ever underflowed); `EXIT_DELAY_EPOCHS > 0` asserted; tokenomics/fee-market invariants asserted.

## 6. Test-coverage gaps

1. No root-binding test for `TAG_WRITTEN_OFF`, `TAG_STAKE_LOW_WATER`, `TAG_RANDAO_GENERATION`, `TAG_FUNDED_VALIDATOR` (SR-09), including the zero-is-absent edges.
2. `every_committed_state_field_is_bound_by_the_root` (`transition.rs:13242`) lacks `must_move` for `issued_sat`, `evm`, `eutxos`, the four ADR-041 fields and `validators[].{pubkey, activation_epoch, exit_epoch, slashed}`, and lacks "deliberately not committed" pins for `genesis_principal_sat`, `admission_network_domain`, `head`; the list is therefore not the executable inventory it claims to be.
3. `every_component_field_is_load_bearing` (`state_root.rs`) does not mutate `validators[].{exit_epoch, slashed, withdrawable_epoch, commission_bps}` nor any `applied_evidence`/`slash_window`/`delegator_slash_losses` entry (the transition test covers those three).
4. `tests/spec_reconcile.rs::f06` pins the registry only "up to 0x16" and a 14-tag DS table; it cannot detect the eight undocumented component tags or `DS_SPEND2`.
5. `domain_separators_match_the_frozen_registry` scans `params.rs` only; the funded-admission tags in `transition/funded.rs` are invisible to it.
6. `single_derivation_path` does not scan `src/transition/**` (SR-06).
7. No test asserts `ws-verify`'s verdict equals `ws_boot::boot`'s for the arrangement-window rule (SR-04); `combine_agrees_with_verify_envelope` covers the crate function only.
8. No test that a checkpoint whose `state_root` disagrees with the header at `block_root` is refused (SR-05) — because no code does it.
9. No test that a manifest differing only in `cohort` yields a different `genesis_root` (SR-01) — because it does not.
10. `FinalityRecord::serialize` has no test for duplicate epochs/validators in its input (unreachable today; document the precondition).

## 7. Residual risk / not covered

- The network framing that bounds envelope size and per-peer rate (`net.rs`/`p2p.rs`), RPC handlers that serve `getblockbyslot`/`getchaininfo`, file/IO handling of `ws_latest.bin` and the data directory, keystore handling: other auditors (A7 and the node-side WS auditor). I only verified that the node consumes checkpoint semantics as documented.
- Transaction-level preimages under `DS_SPEND`/`DS_SPEND2` (the `TransferV2 { .. }` fields excluded from the spend root) and the funded-admission tags: noted for the transaction auditor; not exhaustively analysed here.
- `bloch-crypto` hybrid verification internals (Falcon signature length handling, ML-DSA raw verify) are trusted as injected; I verified only the AND composition and the split offset.
- The per-thread memo's memory bound is derived from the constant, not measured.
- Whether any deployed binary already bakes Phase-A keys (the tree says none does) could not be checked against release artifacts.
- I did not run the test suite; every "verified" above is by reading the code paths and by the one Python recomputation.
