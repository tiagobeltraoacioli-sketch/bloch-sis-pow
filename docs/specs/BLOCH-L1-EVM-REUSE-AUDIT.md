<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# EVM at L1 — Reuse Audit

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

*A1, wave of 2026-08-11. Companion to `docs/FLEET-BRIEF-2026-08-11.md` §"EVM at
L1, no L2". This document answers, file by file, what of the existing execution
codebases survives the move to EVM at the base layer, what becomes dead code,
and what survives only if rewritten. It **informs** the state-model decision
(DEV-1) and the authorisation decision (DEV-2); it does not take either.*

---

## 0. Where the code actually lives

The instruction said the L2 EVM code might be in `crates/bloch-l2-evm` of this
repo. **It is not.** This repo (`~/dev/BlochPOS`) contains no L2 crates at all
(`crates/` = bloch-btc-wallet, bloch-crypto, bloch-euvm, bloch-ffg,
bloch-pos-committee, bloch-pos-node, bloch-pq-vault, bloch-sis-pow,
coherence-core, coherence-prover, pqcrypto-internals). The L2 stack lives in
the **old node repo**:

- **`/Users/tiagoacioli/dev/bloch-protocol/l2/`** — eight standalone Cargo
  workspaces: `bloch-l2-evm`, `bloch-l2-node`, `bloch-l2-sequencer`,
  `bloch-l2-bridge`, `bloch-l2-anchor`, `bloch-l2-prover`,
  `bloch-l2-stf-program`, `bloch-l2-stf-prover-script`. ~22,409 lines of Rust
  (sources + tests) total. This is the code behind the chainId-8400 service on
  the miner-box (`bloch-l2-node` is the deployed binary; it has `--data-dir`
  JSON-snapshot persistence, so the old "NO persistence" comment in its
  `Cargo.toml` is stale).
- **`/Users/tiagoacioli/dev/bloch-protocol/docs/specs/`** —
  `BLOCH-L2-BRIDGE-SECURITY.md`, `BLOCH-L2-PROVER-SCOPE.md`,
  `BLOCH-L2-EVM-DESIGN.md`, `BLOCH-L2-BRIDGE-THREAT-MODEL.md`,
  `BLOCH-PERMISSIONLESS-TOKENS-L2.md`. None of these were copied into this
  repo's `docs/specs/`.

The eUTXO VM is in **this** repo: `crates/bloch-euvm` (~10,600 lines), plus
its node adapter `src/euvm/` (~2,500 lines) and call sites in `src/main.rs`.
I verified directly (not via the crate's own stale docs) that it is
consensus-wired: `src/main.rs:2690-2711` gates block acceptance on
`euvm_active(block.height)` and routes every non-coinbase tx through
`validate_tx_in_block_euvm`; `src/euvm/mod.rs::euvm_activation_height`
returns **0 on Genesis3Mainnet** (active from genesis). The node builds it
under `--features euvm` (off by default; `Dockerfile.euvm` builds with it).

**Licensing note.** The `bloch-protocol` L2 sources carry MIT OR Apache-2.0 — a different repository, and not the Genesis-4 licence (superseded here by AGPL-3.0-or-later, ADR-039)
headers. Porting them into this AGPL-3.0-or-later repo is licence-compatible
(permissive → AGPL), but every ported file gets a new
`SPDX-License-Identifier: AGPL-3.0-or-later` header per the fleet rule.

**Method note.** Three sub-inventories (execution, bridge/prover, euvm) were
produced by reading agents over the full sources; I independently verified the
load-bearing claims (accept-path wiring, `lib.rs` module list, the coinbase-
carrier fix and its pinning test, the SMT hash discipline) and read the two
normative L2 security docs in full myself. Line numbers for `bloch-protocol`
files refer to that repo's current working tree.

---

## 1. Verdict key

- **SURVIVES** — reusable at L1 essentially as-is (port, re-header, re-pin).
- **REWRITE** — the *design or technique* survives; the code does not, or
  survives only after substantive rework.
- **DEAD** — loses its object entirely under "EVM at L1, no L2".
- **CONDITIONAL** — verdict depends on a decision this audit does not take
  (named in each case).

---

## 2. `bloch-l2-evm` — the engine. Mostly SURVIVES.

This crate is the single most reusable artifact of the whole L2 program:
unmodified **revm `=41.0.0`** at `SpecId::CANCUN`, real keccak-256 MPT state
root via `alloy-trie 0.9`, `no_std`-clean (`#![cfg_attr(not(feature="std"),
no_std)]`), zero L2-infrastructure dependencies (no sp1, no jsonrpsee, no
tokio).

| File | ~Lines | Verdict | Why |
|---|---|---|---|
| `src/lib.rs` | 80 | SURVIVES | Module wiring, `REVM_PIN`, lints (`deny(float_arithmetic)`). L2 only in prose. |
| `src/chainspec.rs` | 176 | SURVIVES (edited) | `ChainSpec` + the EIP-1559 `next_base_fee` formula are pure chain config. **Must change:** `base_fee_vault`/`sequencer_fee_vault` predeploys and `coinbase() == sequencer_fee_vault` are L2 fee plumbing; `block_reward = 0` was justified by "bridged BLCH only" — at L1 the reward/fee fields must follow Tokenomics V4 (import from `tokenomics_v4.rs`, never restate). |
| `src/executor.rs` | 856 | SURVIVES (edited) | `execute_block` phases 2–5 (blob rejection, revm Context build, per-tx `transact_commit`, gas accounting, EIP-1559 effective price, block gas limit, state-root fill) are exactly what an L1 block executor does. **Delete:** phase 1 (the `deposits` mint loop, `minted_wei`) — deposits don't exist without a bridge. **Change:** the basefee-to-vault routing (lines ~253–263, "never burn") **directly conflicts with V4** ("fees burn during emission, then 100% to validators") — see §8. |
| `src/stateroot.rs` | 688 | SURVIVES / CONDITIONAL on DEV-1 | Real hexary keccak-256 MPT (`alloy_trie::HashBuilder`), Ethereum account RLP, EIP-161 exclusion, **plus** the proven stateless machinery: `stateless_new_root` (sparse proof-based root update handling insert/update/delete with trie restructures) and its four `p0_3*` pinned tests. Reusable verbatim **iff** DEV-1 keeps keccak-MPT as the EVM state commitment. If DEV-1 mandates a SHA3/SHAKE SMT instead, this file is a REWRITE: the technique ports, `alloy-trie` does not. See §7/§8. |
| `src/proving.rs` | 360 | SURVIVES (same condition) | Host witness generator (`generate_batch_witness`, self-verifying against `stateless_new_root`) + `hydrate_and_verify`. Pure-Rust, no SP1 dep. This is generic stateless-execution machinery; its L1 uses are discussed in §6. |
| `src/state.rs` | 312 | SPLIT | `L2Account` views, `balance_of`/`nonce_of`, and `credit_balance` (credit outside EVM semantics — exactly what block rewards/fee payments need) SURVIVE. `DepositMint`, `DepositProvenance::BridgedBlch`, `deposit_mint`, the `total_minted_wei` supply ledger are DEAD (bridge-only). The serde derive on `L2State` (what makes the JSON snapshot possible) survives but see the persistence caveat in §8. |
| `src/scale.rs` | 107 | SURVIVES — deliberately reclassified | The inventory agent called this "L2-specific in its entirety". I disagree, and this is an audit judgment: `ATOM_SCALE = 10^10` is the **8-decimal-sats ⇄ 18-decimal-wei** mapping. If the L1 EVM's native balance is BLCH whose base accounting unit remains u64 sats (V4 is specified in sats), the exact-conversion discipline (`wei % ATOM_SCALE == 0`, never round, typed errors) reappears at L1 at every boundary between EVM state and base accounting. CONDITIONAL on DEV-1's unit decision, but the problem it solves does not die with the bridge. |
| `src/stubs.rs` | 86 | DEAD | All `todo!()`; each stub already superseded by real code elsewhere (`bloch-l2-node` for rpc/txpool, `proving.rs` for the witness generator). Delete on port. |

---

## 3. `bloch-l2-node` — the service. SPLIT: EVM plumbing survives, service glue dies.

| File | ~Lines | Verdict | Why |
|---|---|---|---|
| `src/txdecode.rs` | 114 | SURVIVES — and it is DEV-2's single most important file | EIP-2718 decode (`TxEnvelope::decode_2718`), rejection of 4844/7702, chain-id check, and **the only sender-authentication point in the entire EVM stack: `envelope.recover_signer()` at line 62 — secp256k1 ecrecover via alloy's `k256` feature**. There is no PQ signature on any user transaction anywhere in the L2 codebase. Whatever authorisation model DEV-2 prices, this 114-line file is the entire surface to swap or extend. |
| `src/rpc.rs` | 612 | SURVIVES | Standard `eth_*` surface over jsonrpsee (22 methods incl. `eth_sendRawTransaction`, `eth_call`, `eth_getLogs`, EIP-1898 tags, MetaMask-decodable revert errors). Nothing rollup-specific. Known devnet shortcuts to fix at L1: historical tags answered with latest state; `transactionsRoot`/`receiptsRoot` hardcoded to the empty-trie constant; `logsBloom` all-zero; `eth_estimateGas` = measured+50%, no binary search. No `eth_getProof`, no `eth_subscribe`. |
| `src/node.rs` | 549 | SPLIT | SURVIVES: receipt construction, cumulative gas/log indices, the non-committing `call()` path for `eth_call`/`estimateGas`, `extract_logs`, base-fee advance. DEAD/REWRITE: `CHAIN_ID = 8400` const; genesis-by-synthetic-deposit (funds dev accounts through the bridge mint path — at L1, genesis allocation comes from consensus, i.e. the V4 snapshot); `devnet_block_hash` (an ad-hoc keccak concat, **not** an RLP header hash — at L1 block identity is the PoS header, single-derivation-path rule); block production draining the sequencer mempool (at L1 the proposer is a PoS validator and the payload comes from consensus). |
| `src/main.rs` | 213 | DEAD (patterns only) | ChainId-8400 banner, Anvil dev keys, faucet-via-deposit. The tokio/jsonrpsee/CORS/SIGTERM scaffolding is trivially re-writable; nothing worth porting verbatim. |
| `src/bin/devtx.rs` | 78 | SURVIVES (dev tooling) | secp256k1 EIP-1559 tx signer/encoder. Useful test tooling for whichever authorisation option keeps a secp256k1 path; DEAD under PQ-only. |

Snapshot persistence (`node.rs` `Snapshot`/`save`/`restore`: atomic-rename
JSON dump of the serde-serialized revm `CacheDB` + block/tx/receipt indices,
no history) is **devnet-grade by design** — fine for chainId 8400, not a state
backend for an L1. There is no reusable production persistence layer in any of
these crates; that is new work regardless of every other decision (§8).

---

## 4. `bloch-l2-sequencer` — SPLIT: txpool policy survives, sequencer-operator machinery dies.

| File | ~Lines | Verdict | Why |
|---|---|---|---|
| `src/mempool.rs` | 602 | SURVIVES (edited) | Admission policy (size cap, fee floor, nonce ≥ account, replace-by-fee with 10% bump on both fees, per-sender cap 64, nonce-gap ≤ 16) and nonce-contiguous ordering are ordinary L1 txpool machinery. **Caveats:** it verifies no signatures (fields taken at face value — at L1, admission must sit behind `txdecode`'s recovery); the two-lane FIFO-not-tip-auction ordering was a *sequencer fairness commitment* — an L1 proposer policy is a different (DEV/econ) decision. |
| `src/fees.rs` | 171 | SURVIVES | Clean EIP-1559 math + `effective_tip`. Note it is a **second, independent implementation** of the same formula as `chainspec.rs::next_base_fee` (the node uses the ChainSpec one). Port ONE. The fleet's `single_derivation_path` lesson applies to fee formulas too. |
| `src/txtype.rs` | 131 | SURVIVES (minus `0x7E`) | Panic-free EIP-2718 leading-byte classifier. Drop the `Deposit(0x7E)` arm. |
| `src/hash.rs` | 184 | SURVIVES (or drop) | Self-contained Keccak-f[1600] (keccak256 + sha3_256) with FIPS-202 vectors. Existed only to keep the crate dep-free; at L1 use one hashing crate, don't carry a third keccak. |
| `src/params.rs` | 80 | SPLIT | Chain params (gas limit, elasticity, denominators, mempool caps) survive as *shapes* — the values are L2 testnet's. Batcher bounds (256 KiB / 150 blocks / 300 s) DEAD. |
| `src/deposit.rs` | 264 | DEAD | `0x7E` deposit tx codec + `source_hash` derivation. Bridge-only. |
| `src/block.rs` | 241 | MOSTLY DEAD | The mandatory-deposits-first rule is bridge-only; the greedy gas packing is trivial. |
| `src/batch.rs` | 435 | DEAD | zstd batch compression + `batch_data_hash` + `BatchSealer` — DA/anchoring payloads. No DA layer exists at L1 (execution is consensus). |
| `src/receipt.rs` | 377 | DEAD as product; **extract the pattern** | Sequencer inclusion receipts die with the sequencer. But this file contains the L2 stack's only PQ signature: a clean `ReceiptSigScheme` trait with a working **ML-DSA-65 implementation over RustCrypto `ml_dsa`** (seed→ExpandedSigningKey, deterministic signing, 1952-byte FIPS-204 vkey encoding, tamper-tested). For DEV-2, this is a small worked example of PQ-signing an EVM-adjacent artifact — worth lifting as a reference even though the receipt itself is dead. Note: the node's real consensus verifier is `bloch_crypto::crypto::verify` (hybrid ML-DSA-65‖Falcon-1024); anything consensus-facing must use that, not RustCrypto `ml_dsa`. |
| `src/stubs.rs` | 59 | DEAD | `todo!()`s; one is stale (claims zstd unimplemented; `batch.rs` implements it). |
| `tests/pipeline.rs` | 173 | DEAD | Exercises the deposit/batch pipeline. |

---

## 5. The bridge dies. `bloch-l2-bridge` + `bloch-l2-anchor`: DEAD, with named extractions.

**Does the L2↔L1 bridge die? Yes, entirely and by definition.** A bridge
moves value between two execution domains; with the EVM at L1 there is only
one domain — there is nowhere to bridge to. Deposits, withdrawals, the anchor
chain, release gating, proof-of-reserves, the escrow vault, the K(amount)
depth schedule: every one of these loses its object, not just its priority.
Two additional facts make the retirement clean:

1. **No value is at stake.** `BLOCH-L2-BRIDGE-SECURITY.md` §4 gates were
   conjunctive and never cleared; the system was mandated zero-value, the v1
   vault was never funded beyond test posture, and the chainId-8400 devnet
   holds faucet/dev balances only. Retiring this code deletes scaffolds; it
   migrates no users.
2. **The Genesis-4 base makes half its threat model moot anyway.** T1/T2/T10
   (majority-reorg, depth heuristics, K-schedules) are artifacts of a
   51%-attackable PoW base with no finality. Under PoS with a finality gadget,
   "confirmation depth as a price on reorgs" stops being the security
   primitive. The bridge's most sophisticated machinery was compensating for a
   base property Genesis-4 removes.

   **What replaces it, so this does not read as a net security gain.** The
   reorg price is gone and a different exposure takes its place: finality on
   Genesis-4 is a two-thirds quorum of a validator set whose 64 members are
   **all operated by one entity**, over a ledger 93.94% of which sits at a
   single stakeable address. Depth-based attacks are moot; the base is not
   thereby safer, it has a different single point of failure.

**Retirement accounting** (sources + tests, approximate):

| Retired unit | ~Lines |
|---|---|
| `bloch-l2-anchor` (all: envelope 1133, manager 1278, source 1201, gating 395, sha3 199, lib 116, tests 1064) | 5,386 |
| `bloch-l2-bridge` (all: watcher 1033, release 962, status 816, harness 619, merkle 391, envelope 389, withdrawal 386, reserves 213, atoms 130, stubs 122, hex 101, lib 54, tests 667) | 5,883 |
| `bloch-l2-prover` (all — see §6: stf 1642, public_values 590, witness 568, mock 289, hash 264, sp1_stub 108, lib 77, tests 272) | 3,810 |
| `bloch-l2-stf-program` + `bloch-l2-stf-prover-script` (see §6) | 330 |
| Sequencer L2-only files (deposit, batch, receipt, block deposit-rule, pipeline test) | ~1,300 |
| Node/evm L2 glue (deposit path, chainId-8400 genesis/banner, devnet hash) | ~500 |
| **Total retired** | **~17,200 of ~22,400 (≈75%)** |

What survives from the L2 tree is essentially §2–§4's SURVIVES rows:
`bloch-l2-evm` minus its deposit path, `txdecode`/`rpc`/`call`, and the txpool
policy — on the order of 5,000 lines, all of it the *EVM-generic* portion.

### 5.1 Extract before deleting

**(a) The Wave-4 HIGH — coinbase-carrier — generalises beyond the bridge and
must not be lost.** Location: `bloch-l2-anchor/src/envelope.rs:381-400`
(`input0_key_hash`), pinned by `coinbase_carrier_cannot_forge_the_sequencer_
binding` (same file, lines 1039-1086), consumed at `manager.rs:385-389`.

The finding, in one paragraph: any protocol that authenticates on-chain data
by reading a key out of a transaction input's `script_sig` must fail closed on
the **coinbase shape** (`prev_txid == [0;32] && prev_index == u32::MAX`),
because block validation iterates `transactions.iter().skip(1)` — a coinbase's
`script_sig` is never signature-validated and is therefore attacker-chosen
free bytes. A miner can paste any *public* key into it and forge an
"authenticated" binding for the price of one block. This is a property of the
**base chain**, not of the bridge. It applies to anything at L1 that ever
reads authenticated envelopes or key bindings out of transactions —
Ustav-at-L1 readers, attestation tooling, explorers, any future anchor-reading
protocol. **Recommendation: port the fail-closed check and its regression test
into this repo as a reusable rule/test-pattern before `bloch-l2-anchor` is
archived.** The same applies to the sibling Wave-4 patterns worth keeping as
*test disciplines*: fail-closed contiguity (`SyncError::NonContiguous`),
equivocation-as-evidence (never silently drop a conflicting signed artifact),
zero-vkey rejection ("names no program" must not authenticate), and
validated-restore (a corrupt snapshot must be rejected, not arithmetic-
underflowed into a spurious credit — `WatcherRestoreError::
DepositHeightBeyondTip`, pinned Wave 4 MEDIUM).

**(b) Generic library code**, small and clean, worth lifting only on demand:
`bridge/src/merkle.rs` (391 lines: Ethereum-deposit-contract incremental
keccak Merkle, depth 32, with negative tests) — generic, but has no L1
consumer today; `bridge/src/hex.rs` (101 lines) — trivial; the reorg-aware
height→hash journal skeleton (`manager.rs`/`watcher.rs`, explicitly copied
from `bloch-tokens`' indexer) — the canonical pattern for any chain-reading
tool, though PoS finality reduces how much rewinding a reader ever does.

**(c) Methodology, not code.** The Wave 2→4 loop (adversarial review → PoC
test that *demonstrates* the attack → fix → the PoC inverted into a pinned
regression named after the finding) produced the coinbase-carrier catch. The
open-defect ledger format of `BLOCH-L2-BRIDGE-SECURITY.md` §2 is worth
imitating for the L1-EVM security notes this wave will produce.

**(d) Explicitly NOT worth extracting:** the K(amount) schedules
(`gating.rs`, `status.rs`) — depth-heuristic policy for a finality-less base;
the 7-item release checklist and `NullifierLog` (custodial release
machinery); the L2D0/L2V0 envelope codecs; `reserves.rs` PoR arithmetic;
`withdrawal.rs` ABI leaves and their golden vectors (bridge-normative by
construction). All of it is competent code whose *object* no longer exists.

**Operational footnote** (out of this audit's scope to execute): the running
chainId-8400 service (`bloch-l2.service` + `l2rpc.posternlabs.com` on the
miner-box) becomes decommissionable when L1 EVM lands; and the reserved
chainId 8400 / chainlist entry is an identity the L1 EVM could inherit or
abandon — founder/DEV call, flagged here only so it is not forgotten.

---

## 6. The prover: what it proved, and what it can still do at L1

What the SP1 scope actually proved (all verified in-repo, per
`BLOCH-L2-PROVER-SCOPE.md` §5b and the code):

- **Real and load-bearing, and it lives in `bloch-l2-evm` (the surviving
  crate), not in the prover crate:** stateless READ (re-execution from
  touched-accounts-only), MPT witness verification against `prev_state_root`,
  stateless root UPDATE with restructures (`stateroot::stateless_new_root`,
  ~90 lines over `alloy-trie`), a self-verifying host witness generator
  (`proving::generate_batch_witness`), and `no_std`-cleanliness. All pinned by
  tests that run today.
- **Never built:** the actual SP1 guest ELF. `bloch-l2-stf-program` (182
  lines) is fully wired to the tested logic but has never been through
  `cargo prove build --docker`; the host script's `demo_batch()` is
  `unimplemented!()`. No FRI proof of an EVM batch has ever been produced.
- **DEAD regardless:** `bloch-l2-prover`'s toy `stf.rs` (1,642 lines — a flat
  SHAKE account-map STF that is *not* revm and disagrees with the real guest
  about the state commitment), the forgeable `MockProver`, and the
  `BatchPublicValues`/`ExecutionWitness` encodings, whose field set (batch
  index, L1 origin, consumed-deposit roots, DA pointers) is the rollup
  contract. The prover *crate* dies with the bridge.

**Does proving L2 execution still serve anything when the EVM is at L1?**
Honest answer: **nothing in this wave needs it.** At L1, every validator
executes every block; validity proofs are not a consensus requirement, and
the thing the prover existed to remove — trust in a single sequencer's state
roots — has no analogue. The defensible future uses, none of which has a
committed consumer today:

1. **PQ light clients / mobile verification.** An SP1-FRI proof that "block N
   under state root X executed to root Y" would let a wallet verify L1 EVM
   execution without running a node — hash-based, consistent with the C1-frozen
   Coherence stack (raw FRI, no curves). This is the strongest candidate, and
   the `coherence-prover` program/script/service template plus the L40S GPU
   service already exist in this repo.
2. **Stateless validation / validator state relief** — the witness generator +
   `stateless_new_root` are exactly a stateless-client kit for whatever
   commitment DEV-1 picks (if keccak-MPT: usable now; if SHAKE-SMT: rewrite).
3. **Snapshot attestation** — a proof chain over the Genesis-4 weak-
   subjectivity snapshot lineage. Speculative; `BLOCH-WEAK-SUBJECTIVITY.md`
   does not currently ask for it.

**Recommendation:** keep `proving.rs` + `stateroot.rs` alive (they ride along
inside `bloch-l2-evm` at near-zero carrying cost, well-tested); archive —
don't port — `bloch-l2-stf-program`/`-script` (330 lines, trivially
recreatable from the surviving pieces if use-case 1 is ever funded); delete
the prover crate with the bridge. If no light-client scope is ever adopted,
nothing of value was kept dead.

---

## 7. `bloch-euvm` as a state layer for the EVM

### 7.1 The SMT (`crates/bloch-euvm/src/state.rs`, ~1,161 lines) — verified

The brief's question was whether the non-per-UTXO SMT "really is" the obvious
candidate for the EVM's state layer. Findings first, verdict after.

**It is real, and better than its own doc says.** `docs/euvm-non-local-state.md`
claims the module is "not even crate-wired" — stale: `lib.rs:755` declares
`pub mod state;` today, and the doc's other open item (gas-constant drift) is
also closed — `shake256_gas_tracks_the_vm_s_own_gas_schedule` (state.rs:933)
now pins `SHAKE256_GAS = 60` against the VM's own schedule. What exists:

- A fixed-depth-256 sparse Merkle tree, keyed `SHAKE-256(0x02 ‖ key)`, leaf
  `SHAKE-256(0x00 ‖ key_hash ‖ len ‖ value)`, node `SHAKE-256(0x01 ‖ L ‖ R)`
  — disjoint pre-image spaces by domain tag, empty-subtree ladder,
  membership/non-membership proofs, tamper tests. Same `sha3::Shake256`
  discipline as the VM's `Op::Shake256`, byte-for-byte.
- Typed wrappers (`Registry`, `HolderSet`, `Snapshot`, `MembershipList` +
  allow/deny gates) — these are **Ustav** primitives, not EVM ones.
- One load-bearing use: `harness.rs:194` builds an SMT over the block's
  consumed/created outputs and commits its root in the `"EUV1"` section (the
  F1 audit remediation).

**Why it is NOT usable as-written as a live EVM state backend** (each point is
in the code, not a guess):

1. `root()` is a full O(n log n) refold of the entire entry set **on every
   call** — no incremental update, no node cache. Fine at test sizes; not a
   per-block state root over millions of accounts.
2. Backing store is an in-memory `BTreeMap<Vec<u8>, Vec<u8>>` — no
   persistence layer at all.
3. Proofs are uncompressed: 256 × 32 B = 8 KiB each, with no empty-ladder
   run compression.
4. `subtree_hash` silently keeps `entries[0]` on a (≈2⁻²⁵⁶) slot collision
   rather than erroring — acceptable assumption, but an assumption.
5. The allow/deny gates do not bind `proof.key` to any caller identity — the
   crate's own `tests/audit_stateproof.rs` pins the bypass **as the attacker's
   success** (`deny_gate_is_bypassable_with_a_made_up_identity`,
   `allow_gate_kyc_bypass_by_relaying_a_members_proof`); a documented
   integration hazard, not a hidden one.

**Verdict: REWRITE, not SURVIVES.** The SMT is the right *specification* if
DEV-1 wants a SHAKE-256 commitment for EVM accounts (hash discipline, domain
tags, proof format, and the existing test vectors all carry over), but the
implementation must be rebuilt as an incremental, persistent, cached-node
structure with compressed proofs before it can be a state layer for anything
production-sized. Calling it "the obvious candidate" is right about the design
and wrong about the code.

**The fact DEV-1 must not miss: there are already THREE commitment structures
in play, sharing no code and not even a hash function.**

| Structure | Hash | Where | Status |
|---|---|---|---|
| `bloch-euvm::state` SMT | SHAKE-256, depth 256 | this repo | reference impl, non-incremental |
| `bloch-pos-committee/src/state_root.rs` SMT | **SHA3-256**, depth 256, `DS_STATE` domain, `TAG_EUTXO = 0x01` over `EutxoEntry{txid,vout,value,script_hash}` | this repo | the actual Genesis-4 `state_root` leaf machinery; `transition.rs:442` currently passes `eutxos: &[]` ("owned by the node's transaction layer") |
| `bloch-l2-evm::stateroot` MPT | keccak-256, hexary | bloch-protocol | production-shaped, with the whole stateless kit |

The `single_derivation_path` lesson applies verbatim: the wave must end with
ONE commitment per role, chosen explicitly. Two facts to weigh (informing,
not deciding): **(a)** keccak-256 is the same Keccak-f[1600] permutation as
SHA3-256 with different padding — identical Grover margins; keeping the
keccak-MPT for the EVM sub-state is *not* a PQ regression, only a uniformity
deviation. **(b)** keccak-MPT roots are what Ethereum tooling understands
(`eth_getProof`, standard light-client formats); a SHAKE-SMT commitment for
EVM accounts forfeits that compatibility and the entire proven stateless kit
in §6. The cheapest coherent design on the table is "EVM keccak-MPT root as
ONE leaf under the SHA3-256 PoS state root" — but that is DEV-1's call.

### 7.2 The rest of the crate — conditional on the euvm survival decision

The brief lists "does `bloch-euvm` survive, get absorbed, or die" as a
question for this wave. This audit does not decide it; it prices both
branches. What is unconditional: **nothing in bloch-euvm besides `state.rs`
is state-layer material** — everything else is execution, and eUTXO-shaped
execution at that.

| File | ~Lines | Shape | If euvm dies at Genesis-4 | If euvm coexists with the EVM |
|---|---|---|---|---|
| `src/lib.rs` (the VM) | 1,196 | inherently eUTXO (datum/redeemer, per-input validators, multi-asset `Value` conservation) | DEAD as contract layer | survives as-is; coexistence semantics = DEV-1's state question |
| `src/state.rs` | 1,161 | account/global (the exception) | REWRITE per §7.1 — survives euvm's death independently | same |
| `src/batcher.rs` | 1,008 | inherently eUTXO — exists *only* because of one-spend-per-block UTXO contention; the problem does not exist in an account model (the EVM's account nonce + mempool is the solution) | DEAD | alive for eUTXO-side AMMs only |
| `src/minting.rs` | 1,391 | inherently eUTXO (asset id = hash of minting policy, conservation over inputs/outputs) | DEAD — EVM-native tokens are contracts | alive for native assets |
| `src/modules.rs` (Ustav compiler) | 1,171 | compiles charters **to eUTXO validator programs** | The charter *model* (`TokenCharter`, `charter_id`, module kinds) SURVIVES into Ustav-at-L1 — it is the natural consensus object; the compiler backend is DEAD and needs an EVM/native-rule backend | survives whole |
| `src/kirpich.rs` + `kirpich/` | 3,840 | SPLIT: lanes A–C (conflicts/completeness/params — 16 of 23 rules) are pure charter-scalar checks, **VM-agnostic**; lane D (emitted-bytecode audit: gas ceilings, `Op::Pick` bounds, constant-tail verdicts, KRP-063's `validator_hash == BLCH`) reasons about eUTXO bytecode | Lanes A–C SURVIVE into Ustav-at-L1 essentially unchanged; lane D REWRITE against whatever Ustav-at-L1 validates. Note: `compile_charter_audited` is opt-in today — `compile_charter` un-audited is still reachable; Ustav-at-L1 as a consensus object makes the gate mandatory by construction, which is precisely the promotion's point | same split |
| `src/harness.rs` | 826 | eUTXO block-acceptance model; contains the EUV1 section + `eutxo_state_root` | DEAD (superseded by real wiring) — but its SMT-over-block-effects pattern is a usable idea for committing EVM receipts/effects | alive |
| node adapter `src/euvm/{mod,miner}.rs` + `main.rs` call sites | ~2,500 | eUTXO codec/validation/miner-mirror, consensus-wired on G3 | DEAD — the G3 chain halted at h 39,918 on 2026-08-13 and G4 does not carry euvm | REWRITE for the PoS node either way (the G4 node is `bloch-pos-node`, which references euvm **zero** times today — both PoS crates have no euvm dependency at all) |

A fact for the founder's version of this decision: euvm has real downstream
consumers in this repo — `bloch-pq-vault` (Governance/Custody validators),
`bloch-btc-wallet` (`hybrid_wbtc_validator`), and the `euvm-tooling/`
workspace. Killing euvm orphans those; keeping it means Genesis-4 runs two
contract VMs with two state models. Neither is free; nobody should pick
silently (the brief's own rule).

---

## 8. Inputs to DEV-1 and DEV-2 (facts, not decisions)

**For DEV-1 (state model):**
1. Three commitment structures exist (§7.1 table); pick one per role,
   explicitly. Keccak is not a PQ liability; it is a uniformity deviation
   with a large compatibility + reuse payoff.
2. The entire proven stateless kit (§6) is keccak-MPT-bound. A SHAKE-SMT
   decision re-opens P0.3 (stateless root update) against a structure whose
   only implementation is non-incremental.
3. The V4 fee conflict is concrete and sits in code: `executor.rs` routes
   basefee to a vault ("never burn", a bridge-conservation rule); V4 says
   fees **burn during emission, then 100% to validators**. The L1 executor
   must implement V4's rule — import the constants, don't restate.
4. Unit decision: if base accounting stays u64 sats, `scale.rs`'s exactness
   discipline is the wei-boundary law (§2). 21e9 BLCH × 1e8 = 2.1e18 sats
   fits u64; the wei representation needs U256, which the EVM has natively.
5. No production persistence layer exists anywhere in the audited code. The
   L1 EVM state DB (MPT-backed or SMT-backed) is new work in every branch.
6. `bloch-pos-committee`'s `state_root.rs` already reserves `TAG_EUTXO` and
   `transition.rs` passes an empty eUTXO set with an ownership comment — the
   seam where the EVM sub-root would also attach is the same closed leaf
   list the brief names.

**For DEV-2 (authorisation):**
1. The complete secp256k1 surface is one function call:
   `txdecode.rs:62 recover_signer()`. Everything upstream (alloy decode) and
   downstream (revm `TxEnv`) is signature-agnostic. The engine
   (`bloch-l2-evm`) performs **no** signature verification at all — pricing
   the three options from the brief is pricing replacements/augmentations of
   this one file plus address-derivation.
2. ~4.6 KB hybrid signatures cannot ride EIP-2718 envelopes that existing
   tooling will produce; a PQ path is necessarily a new tx type or an
   out-of-envelope witness — with the fee/consensus consequences the brief
   demands be made explicit.
3. Two PQ signing precedents exist in the audited code: `receipt.rs`'s
   `ReceiptSigScheme`/ML-DSA-65 (RustCrypto, non-consensus) and the node's
   real hybrid verifier `bloch_crypto::crypto::verify` bridged through
   `NodePqVerifier` (`src/euvm/mod.rs:74`) — the latter is the only one
   valid for consensus, per the frozen suite rule.

---

## 9. Stale-doc corrections found during this audit

Recorded so nobody re-derives from a stale source; none of these changes code.

1. `crates/bloch-euvm/docs/euvm-non-local-state.md` — says `lib.rs` has no
   `mod state;` and that the gas constant is untested. Both false today
   (`lib.rs:755`; `state.rs:933`).
2. `src/euvm/mod.rs:1-2` — says "NOT wired into `accept_block`". False:
   `main.rs:2690-2711` wires it; activation height is 0 on Genesis3Mainnet.
   Root `Cargo.toml:65-67` carries the same stale claim.
3. `crates/bloch-euvm/INTEGRATION.md` + `audit/INTERNAL-AUDIT-2026-07.md` —
   still assert `EUVM_ACTIVATION_HEIGHT = u64::MAX` and "do not lower until
   third-party audit"; the value is 4320 in `harness.rs:52` and 0 (G3) in the
   node adapter. The audit's activation gate was overtaken by the G3 launch
   decision; the docs were never reconciled.
4. `bloch-protocol/l2/bloch-l2-node/Cargo.toml` header — "NO persistence";
   false since the `--data-dir` snapshot landed.
5. `bloch-l2-evm/src/executor.rs:392-404` test doc — says stateless new-root
   "does not work yet"; `stateless_new_root` exists and is pinned.
6. `bloch-l2-prover/src/public_values.rs:17-20` — doc says
   `ENCODED_LEN` = 320; the constant is 336 (Wave 4 added `base_fee`).
7. `bloch-l2-sequencer` README + `stubs.rs` — list receipt-signing and zstd
   as stubs; both are implemented.

---

## 10. What this audit did NOT do

- **Did not run any tests or builds.** No `cargo test`/`cargo build` was
  executed in either repo; every "pinned by test X" claim is from reading the
  test source, not from a green run. In particular I did not re-run the
  bloch-euvm suite or the L2 crates' suites.
- **Did not decide** the state model (DEV-1), the authorisation model
  (DEV-2), euvm's survival, the fee-routing implementation, or the chainId
  question — all flagged with the facts each decision needs.
- **Did not port any code.** The extract-before-delete list (§5.1) is a list,
  not a done migration; the coinbase-carrier rule/test is not yet in this
  repo.
- **Did not inspect the running miner-box service** (deployed binary/flags of
  `bloch-l2.service`); the service description is from the source tree +
  operational memory, not a live check.
- **Did not verify the SP1 guest builds** — nobody ever has; that is a
  finding (§6), not an omission, but I did not attempt the build either.
- **Did not audit cryptography** beyond reading (no independent analysis of
  the SMT's domain separation or the MPT proofs beyond what the code and its
  tests state).
- **Delegated the raw file inventories** to three reading agents and
  independently verified the load-bearing claims (consensus wiring, the
  coinbase-carrier fix location and mechanism, the SMT implementation, the
  ecrecover call site, the two normative L2 security docs read in full);
  per-file line counts and some per-file characterisations of files I did not
  open myself rest on those inventories.
