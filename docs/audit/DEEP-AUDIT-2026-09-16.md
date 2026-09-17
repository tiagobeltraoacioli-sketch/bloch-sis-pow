# Deep audit of the Bloch Protocol repository — 2026-09-16

*Internal, tool-assisted adversarial audit of `tiagobeltraoacioli-sketch/bloch-sis-pow` at commit `562e220`. Eleven parallel area reviews, one adversarial verification pass, one dynamic run. This is not a third-party audit and does not change the "unaudited" status in `SECURITY.md`.*

## 1. Executive summary

**The live chain is exposed today to an unauthenticated network attacker and to any single compromised proposer key, and it will open a consensus-safety hole the day funded validator admission is armed.** None of the 197 findings in this report is a theft or inflation of the ledger by an unprivileged party, and the consensus arithmetic, codec, state root and signature layer held up well under line-by-line review. What did not hold up is the *node* around that arithmetic — its mempool, its transaction selection, its doppelgänger guard, its transport limits — and three consensus-level rules whose consequences were written down only in part.

**Eleven distinct High findings** (fifteen rows before merging the ones three reviewers found independently), grouped by who can trigger them:

| # | Finding | Who can trigger it | Live today? | IDs |
|---|---|---|---|---|
| 1 | **One admissible transaction censors every transaction on the network.** The proposer's selection loop `break`s at the first entry that does not fit the block; a ~530 KB transfer with a high tip, signed by the attacker over *anyone's* outpoints, is admitted, relayed, sorted first, never evicted, and empties every proposer's block for 50 minutes per submission. | anyone with a devnet port or the bootnodes' RPC | yes | EN-01 |
| 2 | **Consensus-thread CPU exhaustion through the mempool door.** Every incoming transaction re-hashes every mempool entry's 3.7 KB public key before any cheap check; ~24 KB/s of junk pins a validator's engine. | anyone | yes | EN-04, NET-02 |
| 3 | **Mempool memory exhaustion.** Bounded by count (4,096) not bytes; 6.8 MB self-signed transfers with duplicate inputs fill ~28 GB per node and are re-broadcast fleet-wide. | anyone | yes | EN-02 |
| 4 | **A routine restart can halt a validator until an operator intervenes.** The doppelgänger guard counts the node's *own* pre-restart attestation, which any peer can replay, as proof of a duplicate. | anyone | yes | EN-03 |
| 5 | **Bootnode lock-out and public RPC on the consensus thread.** 128 idle connections from one IP fill the global inbound cap; the public `:8080` RPC (with `sendrawtransaction`) executes on the consensus thread. | anyone | yes | NET-03, NET-01 |
| 6 | **The unauthenticated legacy `Exit` (tag `0x03`) is consensus-valid.** One block proposer can retire the other 63 validators; after 32 epochs it is the whole roster, finalizes alone, and the chain dies when its RANDAO chain runs out. Documented as a bond-lock griefing; the takeover consequence was not written down. | one proposer key (all founder-operated) | yes | TX-01, FC-03, ST-02 |
| 7 | **~60 epochs without an included attestation kill the chain permanently.** The inactivity leak reaches 100 % at t = 64, the leaked roster is the duty roster since epoch 1,400, a zero-weight roster has no proposer, and recovery needs a vote that needs a block. `params.rs` still claims 45 days of dark time are survivable. | an operational outage of ~16 h | yes | FC-01 |
| 8 | **The genesis-cohort cap hands a lone 25,000 BLCH outsider one third of consensus at month six and a two-thirds finality supermajority at month twelve**, because the cap scales the cohort to a multiple of *whatever outsiders hold* and the deposit cap prevents anyone from bringing more than the minimum bond. | the first independent validator, once admission is armed | no — becomes live at flag day L | FC-02, ST-01 |
| 9 | **Every RANDAO chain is terminal**; the first exhaustions (~2027-02) remove proposers permanently while the re-commit gate is inert. | time | yes | TX-12 (known) |
| 10 | **One SSH key and one Fly account reach every validator keystore.** | theft of one credential | yes | INF-02 (known) |
| 11 | **The blocking supply-chain CI gates are red** on the current tree — `rustls` RUSTSEC-2026-0285 in five lockfiles and `libp2p-quic` GHSA-5hq8-qhww-jm7q (CVSS 8.2, remote crash of a QUIC listener; latent while the fleet stays on the devnet transport) — Medium by impact, listed here because it blocks every fix above from merging. Both lock bumps ride with this report's PR. | — | yes | LD-01, LD-04 |

**Verification.** All 73 High/Medium findings were handed to a skeptical verifier whose brief was to refute them from the code; every High was additionally queued for an independent second reviewer. The skeptic pass returned for 10 of the 11 area annexes (68 findings: 55 confirmed, 12 partially confirmed — mechanism real, severity or scope narrower — and 1 refuted, INF-05, where the lead's own `cargo deny` run passes); the five staking findings (ST-01…ST-05) and 17 of the 22 second-lens reviews did not return because the session's agent budget was exhausted, and the completeness critic did not run. Those gaps are named in Annex A13 rather than papered over. The lead read the source directly for the top findings (Annex A13 §A13.5). Severities in this report are the lead's after that process; the reviewers' originals are kept beside them.

**What is not broken.** Consensus determinism, codec injectivity, header and state-root binding, value conservation, the AND hybrid-signature combiner, the vendored PQClean provenance, slashing-protection ordering, the sealed keystore, the finality-incident closure and the CI pinning discipline were each verified in code and are listed in §5. The repository's candour about its own gaps is a control in its own right.

**Totals.** 197 findings + 4 from the dynamic run: 15 High, 36 Medium, 96 Low, 52 Info (lead severities; 1 refuted). 120 are labelled NEW, 65 KNOWN or KNOWN-refined against the eleven prior internal audits in `docs/audit/`. Test suites of the live crates: 1,349 passed, 0 failed (Annex A12).

## 2. Scope and method

**Tree audited.** `tiagobeltraoacioli-sketch/bloch-sis-pow` at commit `562e220` (merge of PR #21, 2026-09-11), branch `claude/dazzling-thompson-4y60q8`, working tree clean. 2,449 tracked files; 212,561 lines of Rust in 389 files across 13 workspace crates plus `legacy/genesis3-node`, two out-of-workspace Rust projects (`pool/`, `pool-proxy/`, `anchoring/`, `euvm-tooling/`, `services/pq-shield-api/`), TypeScript/Go/Python SDKs and tools, NixOS modules, CI pipelines and deployment manifests.

**What was read in full, line by line.** Every non-test line of the live consensus crate (`crates/bloch-pos-committee/src`, 38.7 K lines), the live node (`crates/bloch-pos-node/src`, 35.7 K lines), the signature crate (`crates/bloch-crypto`, 11.5 K lines), the vendored PQ FFI fork (`crates/pqcrypto-internals`) including its C sources, `coherence-core`, `bloch-sis-pow`, `bloch-pq-vault`, `bloch-ustav`, `bloch-btc-wallet`, `libp2p-yamux`, `tools/genesis4-ceremony`, `services/pq-shield-api`, `anchoring`, every CI workflow and guard script, every Dockerfile, Fly/Akash/compose manifest, NixOS module, dependency-policy file, and the carried-ledger tooling. Test suites were read to establish what is and is not covered, not as evidence of correctness.

**What was skimmed or sampled.** `legacy/genesis3-node` (41 K lines) only along the paths that produced the carried-over ledger; `crates/bloch-euvm` and `crates/bloch-ffg` only to confirm they are unreachable from the live node; `pool/`, `pool-proxy/`, `apps/`, `sdk/`, `tools/{indexer,faucet}` for web-facing attack surface; `docs/` for claims to verify against code.

**Method.** Eleven parallel adversarial reviews, each owning one surface (Annexes A1–A11), with a common finding schema and a common severity scale. Each reviewer was required to (1) read the prior internal audits in `docs/audit/` and `docs/specs/BLOCH-POS-GAPS.md` and label every finding NEW or KNOWN, (2) treat a code comment claiming a fix as a claim to verify, (3) confirm every finding by tracing callers and callees, and (4) state confidence. The lead then re-verified every Critical and High finding directly against the source before it entered this report, ran the workspace build and the live-crate test suites and `clippy` (Annex A12), and cross-checked findings from different reviewers that touch the same code. Findings the lead could not confirm are either downgraded with the reason stated or omitted.

**Severity scale.**

| Severity | Meaning |
|---|---|
| Critical | consensus split, theft or inflation, key compromise, or remote halt of the network, with no precondition beyond network access |
| High | the same with realistic preconditions (a malicious peer, one malicious validator, host read access, a leaked backup), or crash/stall of a single node by an unauthenticated peer or RPC client |
| Medium | requires a privileged position, or is a defense-in-depth gap with plausible impact |
| Low | hard to exploit or minor impact |
| Info | documentation, dead code, maintainability that raises future risk |

**What this audit is not.** It is an internal review by a language model with tool access, not a third-party audit. It did not run the node on a network, did not fuzz, did not do formal verification, and did not review the economics beyond conservation and cap arithmetic. `SECURITY.md`'s statement that no external audit has been contracted remains accurate after this report.

## 3. What is live, and what the audit weighs most

Genesis-4 has produced a block every 30 s since 2026-08-13 21:31:19 UTC on 64 founder-operated validators. At audit time the chain is at epoch ≈ 3,065. Three facts about the live deployment shape almost every finding in this report and are stated once here:

1. **The transport is a plain, unauthenticated TCP mesh.** The fleet runs `--transport devnet` (`crates/bloch-pos-node/src/net.rs`): no handshake, no peer identity, no encryption. Any host that can reach a node's devnet port, and anyone who can reach the two public bootnodes' JSON-RPC on `:8080`, can inject blocks, attestations and transactions into every validator's engine. Signatures are verified, so forgery is not possible, but *cost* is: every unauthenticated frame buys work on the consensus thread. The libp2p transport (Noise) exists in the tree but is not what the fleet runs.
2. **Fifteen of nineteen consensus flag-day gates are inert.** The code carries deposit, exit authentication, slashing evidence, withdrawal, dust, tx-byte bounds, RANDAO re-commit, rewards V2, the ancestry seed, fee/stake decoupling and funded admission — all behind `u64::MAX` (Annex A0 §A0.3). On mainnet today there is **no slashing, no authenticated exit, no way for a new validator to join, and no RANDAO re-commit**. Every "fixed" claim for those rules describes a future flag day.
3. **One operator holds every validator key and ~94 % of the stake.** This is documented and disclosed (`SECURITY.md`, `docs/audit/CERTIK-CENTRALIZATION.md`). Findings that require "one malicious validator" therefore describe what a single compromised host, credential or insider can do to the chain, not a Byzantine-minority attack among independent parties.

The consequence for prioritisation: the most urgent defects are the ones an *unauthenticated* party can trigger today (network-level denial of service, transaction censorship, validator-halt traps), followed by the ones a single compromised proposer key can trigger today (roster takeover through the unauthenticated legacy `Exit`), followed by design defects that will become live at the next flag day (cohort cap inversion, leak-to-zero liveness death).

## 4. The consequence of the inert gates, stated once

Fifteen `*_ACTIVATION_EPOCH` constants are `u64::MAX` (Annex A0 §A0.3). Read together they say: on mainnet today no validator can be added or removed by an authenticated message, no equivocation is punished, no RANDAO chain can be re-committed, transaction signatures do not bind the network id, dust and byte bounds are policy rather than rule, and the reward model is the interim one. Every one of those is a *documented* decision, and every one is also the reason a High in this report is High: `0x03` is reachable because `EXIT_AUTH` is inert; the cohort cap will invert because `FUNDED_VALIDATOR_ADMISSION` will arm it; RANDAO chains will run out because `RANDAO_RECOMMIT` is inert. The flag-day plan (`deploy/FLAG-DAY-LIFECYCLE.md`) closes several of them at once — and it is also the moment finding 8 becomes exploitable, which is why §7 orders the cohort-cap redesign *before* L.

## 5. What the codebase does well

The audit is critical by design; this section exists so that the balance is not lost. Every item below was verified in code by the reviewer of that area, not taken from documentation.

- **Consensus determinism.** `bloch-pos-committee` has one runtime dependency (`sha3`), uses `BTreeMap`/`BTreeSet` for every committed collection, has no floats, clocks, environment reads or `HashMap` on the consensus path, and reads every flag-day gate from the committed epoch rather than a wall clock. The ~242 `unwrap`/`expect` calls in `transition.rs` are all inside the test module; the non-test path has zero. No panic reachable from a peer-supplied block was found in the committee crate or the engine.
- **Codec injectivity and header binding.** The transaction codec is injective and total (fixed-width scalars, length prefixes, canonical booleans, trailing bytes refused). The 304-byte header is fixed-width; `BlockId` has a single constructor guarded by a source-scanning test; the proposer signature covers the full header including the state root; body, attestation, coherence and state roots are all recomputed and compared. The body Merkle tree promotes odd leaves and uses leaf/node/empty markers, so CVE-2012-2459-style duplication is structurally impossible.
- **State root.** The sparse Merkle tree separates leaf, node, empty, key and value hashing under `DS_STATE`, fixes depth at 256, refuses proofs of the wrong length, and now binds every field GAP-1 named as missing in August (finality, `reveals_used`, queues, pending fees, fork-choice messages). Three implementations (incremental, flat recursion, independent reference) agree at 452,726 entries.
- **Value conservation.** Every live transaction path enforces strict equality (`spent == created + fee`); the supply cap is enforced at the source and as an invariant on the pre-state; fee arithmetic is bounded by compile-time proofs plus two consensus ceilings; the split of the carried ledger is exact to the satoshi (independently recomputed in Annex A11).
- **Signature layer.** The hybrid combiner is a true AND with no early accept and no classical fallback; ML-DSA-65 is FIPS 204 final; the vendored PQClean C sources are byte-identical to upstream `pqcrypto-internals 0.2.11` and hash-pinned; the seeded-RNG fork is used at exactly one production site (keygen from seed) that never signs inside the seeded scope; validator keys and the genesis ceremony use OS randomness only.
- **Slashing protection and keystore.** Both consensus signatures pass through a durable min-source/min-target watermark (temp, fsync, rename, directory fsync) *before* the signature exists; the keystore is Argon2id (64 MiB, t=3) plus XChaCha20-Poly1305 with the entire public header as AAD; `Keystore` implements neither `Debug` nor `Clone`; the data-dir lock is `O_EXCL` + `flock` with inode re-verification.
- **Finality incident closure.** The 2026-08-24 three-root divergence is reproduced by a test that runs the shipped arithmetic, the cure is tested by the same harness, the epoch-2700 floor is pinned by a test, and the roster-split fix is guarded by thread-local mutation tests wired to the production functions.
- **Supply-chain hygiene.** Every GitHub Action is pinned by commit SHA; there is no `pull_request_target`; the workflow token is read-only; `Cargo.lock` has no git or foreign-registry sources; both vendored forks carry written rationale, upstream diffs and regression guards; advisory acceptances are dated and expire.
- **Candour.** The repository documents its own gaps unusually plainly (unauthenticated transport, single SSH key, unfilled fleet inventory, no release container, the 38 corrupted `vout` rows, the one-subsidy ledger gap). That candour is itself a control: it made this audit faster and it means several findings below are refinements of things the project already wrote down.

## 6. Findings

Severities are the lead's after verification (Annex A13). *Live today?* is whether the precondition holds on mainnet at epoch ≈ 3,065 (gates, transport, exposure). Each ID links to the full write-up — evidence, code excerpts, recommendation — in its annex; this section carries only the claim, the trigger and the consequence. Findings that three reviewers reached independently are merged and carry all their IDs.

### 6.1 High

**EN-01 — Transaction censorship by one admissible transaction** *(Annex A5; trigger: anyone (devnet port or bootnode RPC); live today: yes)*  
`select_transactions` (`engine.rs:3166-3216`) `break`s at the first entry whose `max(encoded, declared)` exceeds the remaining block byte budget. `admissible` verifies each input signature against the pubkey *carried in the input* and never checks ownership or duplicates; the sweep only checks outpoint existence; TTL expiry (100 slots) bars nothing. One ~530 KB high-tip transfer therefore sits at the head of every proposer's ordering and empties every block network-wide, for ~50 minutes per submission, indefinitely. Fix: `continue` instead of `break`; refuse any transfer larger than the block cap at the door; check ownership and duplicates at admission.

**EN-04 / NET-02 — Consensus-thread CPU exhaustion at the mempool door** *(Annex A5, A6; trigger: anyone; live today: yes)*  
`on_transaction` (`engine.rs:3037-3047`) computes `SHA3(pubkey)` of *every* mempool entry's first input (~3.7 KB each) for every incoming transaction, before `admissible`, capacity or any signature check. A 120-byte junk frame costs ~40 ms of consensus-thread CPU at a full mempool, which the attacker can fill (EN-02). ~24 KB/s pins the engine; `attest`/`propose` run on the same thread. Fix: cache the source hash per entry, order the cheap refusals first.

**EN-02 — Mempool memory exhaustion** *(Annex A5; trigger: anyone; live today: yes)*  
`MEMPOOL_MAX = 4,096` bounds entries, not bytes; a V1 transfer may carry ~824 inputs (≈ 6.8 MB) all copies of one `(pubkey, signature)` pair, and the map key *is* the canonical bytes (2× cost). 64 throwaway keys defeat the per-source cap; every admitted entry is re-broadcast. ≈ 28 GB per node from one peer. Fix: byte budget, txid keys, duplicate-input refusal at the door.

**EN-03 — Doppelgänger guard halts a validator on its own replayed attestation** *(Annex A5; trigger: anyone; live today: yes)*  
During the 64-slot post-boot window `note_possible_doppelganger` (`engine.rs:1714-1732`) treats *any* accepted attestation under this node's index as a live duplicate and halts signing until a restart with `BLOCH_NO_DOPPELGANGER=1` — the flag the epoch-2700 runbook forbids. The node's own earlier attestation of the same epoch is still in-window, unknown to the fresh pool and valid, so a restart after the duty slot self-halts, and a peer can pre-position by replaying. Not applied on the `release_held` path either. Fix: count only sightings whose signed slot ≥ boot slot; apply the hook on both paths.

**NET-03 / NET-01 — Bootnode lock-out; public RPC on the consensus thread** *(Annex A6; trigger: anyone; live today: yes)*  
`MAX_INBOUND_CONNECTIONS = 128` is global with no per-IP cap and a 5-byte frame every < 120 s keeps a slot forever (`net.rs:963, 523, 791-813`): 128 connections lock every third party out of both public bootnodes. The same bootnodes forward the full unauthenticated JSON-RPC on `:8080`, including `sendrawtransaction`, and every method but two executes on the consensus thread (`engine.rs:5358`); a one-minute stall from RPC has already been observed. Fix: per-IP caps, idle close, RPC off-thread or behind the read-only proxy.

**TX-01 / FC-03 / ST-02 — Unauthenticated legacy `Exit` (0x03): roster takeover, then chain death** *(Annex A1, A2, A3; trigger: one proposer key; live today: yes)*  
`transition.rs:3489-3522`: the arm is gated on `exit_auth_active || funded_validator_admission_active`, both permanently false (`u64::MAX`), then requires only a registered active index — no signature, no `MAX_EXITS_PER_EPOCH` (that budget lives in the `ExitV2` arm), 0 gas. The mempool refuses the message (`engine.rs:5844`) but a proposer writes the body directly. 63 exits in one block ⇒ at E+32 the survivor is the whole roster (`duty_roster_at` drops `epoch >= exit_epoch`, the cohort cap returns `Deferred` with zero outsider stake), finalizes alone, and after ≤ 8,192 further proposals its RANDAO chain is exhausted with re-commit inert: permanent death. Exited records can never re-register. Documented (VAD-01, `params.rs:1296-1345`) as bond-lock griefing; the takeover and death consequences were not. Verified by the lead in source. Fix: proposer-side refusal and alert now; consensus refusal of 0x03 at the next flag day.

**FC-01 — ~60 empty epochs leak everyone to zero; no proposer can ever be drawn** *(Annex A2; trigger: fleet-wide outage of ≈ 16 h; live today: yes)*  
`finality.rs:517-548`: bite = remaining·t/64 with t = epochs past the 4-epoch threshold, so the whole stake is gone at t = 64 (≈ t = 55 by rounding). `close_epoch` is run for every skipped epoch on the next block (`transition.rs:5539-5541`) with no votes, so everyone is absent. Since `LEAKED_ROSTER_ACTIVATION_EPOCH = 1,400` the leaked roster *is* the duty roster; `sample` filters `effective_stake > 0`; `proposer` returns `None`; post-2700 recovery needs a valid vote, which needs a block. `MAX_EPOCH_ADVANCE`'s doc still promises 45.5 days of dark time. Verified by the lead in source. Fix: floor the roster weight or fall back to the unleaked roster when the leaked total is zero (flag day); correct the doc; add the ≥ 70-empty-epoch test.

**FC-02 / ST-01 — Genesis-cohort cap hands a lone minimum-bond outsider a finality supermajority** *(Annex A2, A3; trigger: the first independent validator, after flag day L; live today: no — at L)*  
`genesis_cohort.rs:176`: `cap = others × bps / (10 000 − bps)` once outsiders hold ≥ 25,000 BLCH, i.e. the cohort is scaled to a multiple of *whatever outsiders hold*. Today (bps ≈ 9,396) one 25 k outsider takes 6 % of weight and issuance; at bps < 6,667 (~month 6) ≥ 1/3 (can stall finality alone); at the 3,333 floor (month 12) `3 × 25,000 ≥ 2 × 37,499` — a lone 2/3 supermajority, ~2/3 of proposer draws, ~2/3 of ~3.9 B BLOCH/year. Because the deposit cap is computed from the *capped* total, nobody can bring more than 25 k per validator, so the independent share is split by validator count (a Sybil race). Tokenomics §3.3.1's "2/3 is out of reach either way" is false. Arithmetic confirmed by three readings; the skeptic proposed Medium on precondition grounds, the lead keeps High because L is scheduled (Annex A13). Fix before L: cap the cohort's *share* only when outsider stake is meaningful relative to the cohort; compute the deposit cap from uncapped stake.

**TX-12 — Every RANDAO chain is terminal; exhaustions begin ~2027-02** *(Annex A1; trigger: time; live today: yes)*  
KNOWN (H-R7-1): `RANDAO_RECOMMIT_ACTIVATION_EPOCH = u64::MAX`; chains are 8,192 reveals; drawn-but-exhausted proposers produce empty slots and the mix stops moving. Verified that the gated re-commit path is correctly ordered. Needs the flag day before the first exhaustion.

**INF-02 — One credential class reaches the majority of validator keys** *(Annex A10; trigger: theft of one SSH key or Fly token; live today: yes)*  
KNOWN (`deploy/SSH-ROLE-SEPARATION.md`): one key and one account reach all 65 hosts; 49 validators are Fly machines with no public IP reachable only through the Fly account; keystores were plaintext fleet-wide until the 2026-09-12 flag day whose completion is unrecorded (`FLEET-INVENTORY.md` is a template). Fix: role split with hardware-backed keys, scoped deploy token, recorded sealed-keystore sweep.

### 6.2 Medium

| ID | Annex | Live? | Finding | Verification |
|---|---|---|---|---|
| TX-02 | A1 | yes | Per-block byte/gas caps are enforced only after all transactions have executed; a scheduled proposer can force ~16× a maximal block's execution work per slot before rejec… | CONFIRMED |
| TX-06 | A1 | yes | Zero-value and arbitrary-count outputs are valid: permanent state growth at ~6 sat per entry | CONFIRMED |
| TX-08 | A1 | yes | Producer fee share compounds into `staked_sat` (consensus weight) with no per-block cap | CONFIRMED |
| TX-11 | A1 | yes | Slashing is unreachable; equivocation is free | CONFIRMED — lead decision: KNOWN and documented residual (slashing inert until L); severity Medium as the skeptic proposed, because the consequence is t |
| INF-01 | A10 | yes | The live validator binary is built and shipped by a pipeline that exists only outside the repository — HIGH — status: partially KNOWN (`deploy/RELEASE-INTEGRITY.md` §8.1/… | CONFIRMED — both verifiers: Medium |
| LG-01 | A11 | no | The carried ledger holds exactly 39,917 Genesis-3 subsidies, not 39,918; the missing coinbase is unexplained and two concrete mechanisms exist in the exporter/node that p… | PARTIALLY_CONFIRMED — lead decision: reviewer High, skeptic Low. The one-subsidy gap is arithmetically certain (independently recomputed by two reviewers) and the |
| FC-04 | A2 | yes | RANDAO grinding of the *next* epoch's committees and proposer schedule is free and one epoch too close (F6 open, proposer reward absent) | CONFIRMED |
| FC-05 | A2 | yes | LMD-GHOST has no proposer boost and a root-value tie-break: ex-ante reorgs and balancing are cheap at 2 attesters per slot | PARTIALLY_CONFIRMED — partially confirmed |
| FC-07 | A2 | yes | With the 1/2 floor armed, any two disjoint sets holding ≥ 1/3 of unleaked stake each finalize conflicting checkpoints after ~25 epochs, with no slashable offence by anyone | CONFIRMED |
| FC-08 | A2 | yes | Sub-epoch duty-view lag: with `back = 1` the seed and the source checkpoint for epoch E depend on the *last block* of E−1, which honest first-slot attesters may not have … | CONFIRMED |
| ST-03 | A3 | — | Correlated-slashing amplification mixes raw-bond penalties (numerator) with effective, capped/leaked stake (denominator): one slash of a cohort validator saturates the wi… | skeptic pass pending |
| ST-04 | A3 | — | Self-slashing is a faster, cap-free exit: ejection at E+1 bypasses `MAX_EXITS_PER_EPOCH`, withdrawability lands 32 epochs *earlier* than a voluntary exit, and a slash on … | skeptic pass pending |
| ST-05 | A3 | — | Post-L, unauthenticated lifecycle transactions cost the node 1–4 hybrid verifications each before any per-source accounting; `tx_source_hash` returns `None` for ExitV2/Wi… | skeptic pass pending |
| SR-02 | A4 | yes | The signer arrangement (keys + quorum rule + review clock) is not bound by the checkpoint digest | CONFIRMED |
| SR-03 | A4 | yes | Fresh-install onboarding is currently refused: the genesis anchor aged out at epoch 2016 and no signed envelope exists anywhere in the tree | CONFIRMED |
| EN-05 | A5 | yes | Future-slot blocks are stored *and applied* immediately: a scheduled proposer can void up to 7 preceding slots, and honest clock skew voids slots by accident | CONFIRMED |
| EN-06 | A5 | yes | Mempool ordering and capacity eviction trust an unbacked, sender-chosen `tip_millisat_per_gas` | CONFIRMED |
| EN-07 | A5 | yes | No per-peer budget on hybrid verifications for unauthenticated attestations/transactions on the devnet mesh; rejected messages are not remembered | CONFIRMED |
| EN-08 | A5 | yes | The shared engine queue budget has no per-peer fairness: one peer can keep honest blocks and attestations shed | PARTIALLY_CONFIRMED — partially confirmed |
| EN-09 | A5 | yes | A validator key can grow `blocks` (a fork-choice input) without bound above the finalized floor | CONFIRMED |
| EN-10 | A5 | yes | Duties are signed against an artificially rolled stale state while the node is behind | CONFIRMED |
| EN-11 | A5 | yes | `gettxstatus` hashes every mempool transaction on the consensus thread | CONFIRMED |
| NET-04 | A6 | yes | Unauthenticated devnet frames buy bounded but sustained consensus-thread CPU (hybrid verifies) and unbounded log spam; `Reject` has no consequence on this transport | CONFIRMED |
| NET-05 | A6 | yes | Devnet `get-blocks` serving is rate-limited per *connection* only (no per-IP/global cap), pages are 4× larger than libp2p's and carry no byte cap | CONFIRMED |
| NET-09 | A6 | yes | Devnet idle-close at 120 s silently drops the first broadcast after an idle period; the honest cadence on non-sync connections is ~16 minutes | CONFIRMED |
| NET-10 | A6 | yes | RPC JSON parser memory amplification and id echo | CONFIRMED |
| NET-11 | A6 | yes | RPC connection exhaustion/slowloris: 64 slots, 30 s deadline, no per-IP limit | CONFIRMED |
| NET-12 | A6 | yes | Bootnode/observer hosts are a privileged frame-push position into all 63 validators | CONFIRMED |
| CR-01 | A8 | no | `coherence_core::check_spend` has no spend authorization: `nk` is prover-chosen, so any note plaintext holder (incl. the sender) can spend, and one note yields unlimited … | CONFIRMED — skeptic: Medium |
| CR-02 | A8 | yes | Hybrid signatures are third-party malleable (SUF-CMA broken): PQClean's non-padded `falcon-1024` verifier accepts the 1280-byte zero-padded encoding; the suite-envelope l… | CONFIRMED |
| BV-01 | A9 | no | The deposit key and the branch-A key are the same key, so the "pre-signed U + delete the bypass key" covenant emulation is structurally impossible; a hot-device compromis… | PARTIALLY_CONFIRMED — skeptic: Medium |
| BV-02 | A9 | no | The clawback cannot be fee-bumped by a watchtower as documented; the only way to give a watchtower that power is to hand it `recovery_sk`, which lets it steal (the "grief… | PARTIALLY_CONFIRMED — skeptic: Medium |
| BV-03 | A9 | no | `pq-shield-api` receives exactly the public keys whose secrecy the vault's security rests on (`recovery_pubkey`, `hot_pubkey`) plus the unvault intent, over plaintext HTT… | PARTIALLY_CONFIRMED — skeptic: Medium |
| BV-04 | A9 | no | Recovery key is a non-hardened BIP-32 sibling of the hot key in *both* derivations (V1 and the A4-M-5 "fix" V2); `hot_sk` + one xpub ⇒ `recovery_sk` | CONFIRMED |

Plus **LD-01** and **LD-04** (Annex A12 §A12.6): blocking supply-chain gates red on the tree — `rustls 0.23.38` (RUSTSEC-2026-0285, via `libp2p-websocket`) and `libp2p-quic 0.13.0` (GHSA-5hq8-qhww-jm7q, CVSS 8.2, remote panic of a QUIC listener, latent while the fleet stays on the devnet transport); both lock bumps are included in this PR.

### 6.3 Low

| ID | Annex | Finding |
|---|---|---|
| TX-03 | A1 | Single-input transfers are cross-format malleable: a relay can re-encode V1↔V2 producing a distinct, valid `canonical_bytes` with the same `txid` |
| TX-04 | A1 | `network_binding()` is a compile-time label, not a genesis-derived value, so the (inert) sighash binding does not actually separate networks built from the same source |
| TX-05 | A1 | Mempool and consensus compute the funded-deposit cap from different `total_active` values (leak-applied vs unleaked) |
| TX-07 | A1 | Declared `tx_bytes` may exceed the encoding by any amount; one small transfer can fill the block byte budget |
| TX-09 | A1 | Issuance accounting below `REWARDS_V2`: delegators receive zero issuance, leak does not reduce income, credit is one unscoped bit, withheld proposals are unpriced |
| TX-10 | A1 | Staking-class transactions are unmetered (0 gas, 0 bytes) and there is no consensus transaction-count cap |
| TX-13 | A1 | `MAX_EPOCH_ADVANCE = 4096` is a hard liveness ceiling: a network-wide stall longer than ~45.5 days can only be resumed by a hard fork |
| TX-14 | A1 | Genesis bonded 1,600,000 BLOCH outside `issued_sat`; the conservation invariant is a one-sided delta that can never see it, and burns are uncounted |
| TX-15 | A1 | Duplicate `(validator, signing_root)` attestations cost one hybrid verify each and are accepted (idempotent) |
| TX-16 | A1 | Body decode, re-encode and Merkle hashing (steps 3b) run before the proposer signature (step 7); an unauthenticated peer can force ~8 MiB of hashing per message |
| INF-03 | A10 | GitLab's `check` stage is red on `main`, so its `test` stage never runs; the "both pipelines gate the live crates" claim is false — MEDIUM — NEW |
| INF-04 | A10 | GitHub and GitLab pipelines diverge; the pipeline this clone actually pushes to is the weaker one — MEDIUM — NEW |
| INF-06 | A10 | SP1 prover image: pipe-to-shell installers, floating base images, whole-repo `COPY` — MEDIUM — NEW |
| INF-07 | A10 | Alerting has holes and the alert docs contradict the exporter — MEDIUM — NEW |
| INF-08 | A10 | Runbooks name a CLI and an RPC method that do not exist, on the host-loss fencing path — MEDIUM — NEW |
| INF-09 | A10 | No rollback is currently possible, and the release signing flow is unspecified — MEDIUM — KNOWN (`deploy/RELEASE-INTEGRITY.md` §8.7), restated because it is load-bearing |
| INF-10 | A10 | Bootnodes expose the full unauthenticated PoS JSON-RPC (incl. `sendrawtransaction`) on `:8080`, contradicting the published posture — MEDIUM — status: KNOWN in `docs/THIRD-PARTY-QU… |
| INF-11 | A10 | The `check-*-blocking` guards are bypassable by trivial spellings and cover only five jobs — LOW — NEW |
| INF-12 | A10 | Scanner binaries are pinned by version, not by hash; a pre-existing binary on the self-hosted runner is trusted blindly — LOW — NEW |
| INF-13 | A10 | `.dockerignore` does not exclude key material; only `COPY . .` makes it bite — LOW — NEW |
| INF-14 | A10 | Image-pin guard exemptions are loose and its own docs are stale — LOW — NEW |
| INF-15 | A10 | Retired-but-deployable configs publish unauthenticated RPC; explorer upstream is plain HTTP via a third-party DNS — LOW — NEW (explorer part is KNOWN in `wrangler.toml`) |
| INF-16 | A10 | `scripts/prova-relanca.sh` executes a wrapper from world-writable `/private/tmp` — LOW — NEW |
| INF-17 | A10 | The attested/appliance image keeps sshd enabled with NixOS defaults; the persist-volume encryption design is internally inconsistent — LOW — NEW |
| INF-18 | A10 | Nix modules that cannot work as shipped — LOW — mostly KNOWN (admitted TODOs) |
| INF-19 | A10 | History claims (`catalog-dev.secret.pem`, "55 findings", leaked PAT) cannot be verified from this clone; CI never scans history — LOW — status: KNOWN (`.gitleaks.toml:18-26`, `docs… |
| INF-20 | A10 | Minor key-handling and hygiene items — LOW — NEW |
| LG-02 | A11 | vout endianness (Legacy M-3): the bug is in the exporter/`iter_utxos_sorted`, the Genesis-4 loader carries the corrupted index verbatim into committed state |
| LG-03 | A11 | Snapshot exporter and `iter_utxos_sorted` silently drop undecodable UTXO rows (fail-open on the ledger-producing path) |
| LG-04 | A11 | Faucet per-address cooldown is bypassable by hex case variation |
| LG-05 | A11 | Faucet accepts cross-site form POSTs (CSRF-driven drips) |
| LG-06 | A11 | Explorer/pool-site RPC path: plaintext upstream via a third-party wildcard DNS, and the archival node's full unauthenticated RPC (write methods included) is internet-exposed beside… |
| LG-07 | A11 | Reference indexer: unbounded responses and whole-state rewrite |
| LG-08 | A11 | Python SDK amount parsing accepts non-ASCII digits and has an uncaught-exception path |
| FC-06 | A2 | Node-side fork choice is order- and store-shape-dependent (O01), and feeds *every stored block* including orphans |
| FC-09 | A2 | `close_epoch` silently swallows `FinalityError::OutOfOrderEpoch`; a desynchronised engine would stop finality forever with no signal |
| FC-10 | A2 | Attestation and proposal signing roots bind no network/genesis identity |
| FC-11 | A2 | The leak is absolute (satoshis) while `duty_roster_at` rescales effective stake; a residual leak can zero a validator the moment a cap binds |
| FC-12 | A2 | Committed `fc_equivocators` bar is permanent and has no exit/slash/recovery path |
| ST-06 | A3 | `close_epoch` mints delegator issuance shares into the ledger without advancing `issued_sat`; the supply-conservation rule would then refuse every boundary block (latent; unreachab… |
| ST-07 | A3 | Attestation and proposal signing roots carry no network/genesis binding, so a validator key reused on another network (devnet, a fork with the same slot numbering) yields *valid* s… |
| ST-08 | A3 | Cohort-cap `Deferred` threshold is a cliff: one 5% slash, an exit, or a leak-independent effective-stake dip of the sole independent validator below 25,000 BLCH flips the cap off i… |
| ST-09 | A3 | Mempool and consensus derive the funded-deposit stake cap from different totals (unleaked vs leak-applied roster) |
| SR-01 | A4 | Genesis cohort is bound by neither the state root nor the genesis block id (only by the 32-bit `network_id`) |
| SR-04 | A4 | `ws-verify` diverges from the booting node: it omits the `arrangement_window` lower bound and carries stale duplicate-key text |
| SR-05 | A4 | A checkpoint's `state_root` / `validator_set_root` are never validated against the block they name, on either side |
| SR-06 | A4 | `single_derivation_path` has scan blind spots (currently clean) |
| SR-07 | A4 | `ws::verify_envelope` alone accepts a zero-threshold arrangement and does not compare signer keys; the crate relies on the node decoder for both |
| SR-08 | A4 | `codec::decode_envelope` pre-allocates from untrusted counts and hard-codes the attestation cap |
| SR-09 | A4 | ADR-041 leaves (`0x1B`–`0x1E`) have no root-binding test, and the spec registry stops at `0x16` |
| EN-12 | A5 | `release_held` judges released attestations with the *wall epoch's* seed and roster, not the attestation's |
| EN-13 | A5 | Re-offered orphans pay a hybrid verify on every delivery |
| EN-14 | A5 | Orphans hanging off a latch-refused branch keep the sync pump broadcasting `get_blocks` to all peers indefinitely |
| EN-15 | A5 | `ancestral_boundary_mix` walk is bounded by `blocks.len()`, and stored non-canonical blocks are not slot-monotone |
| EN-16 | A5 | The proposer's drop loop bars innocent transactions on non-indexed transition errors |
| EN-17 | A5 | `do_reorg` rewrites the whole block log synchronously on the consensus thread |
| EN-18 | A5 | RPC events bypass the queue budget and are answered on the consensus thread |
| EN-19 | A5 | `RandaoRecommit` is signed outside slashing protection and outside the doppelgänger gate |
| NET-06 | A6 | libp2p sync codec buffers up to 8 MiB per inbound *request* substream for a 13-byte message |
| NET-07 | A6 | libp2p sync steering: `peer_head` is set from the unvalidated header slot before the engine judges, and the top-`SYNC_FANOUT` claimants are always chosen |
| NET-08 | A6 | libp2p: identify-advertised addresses overwrite the `dialed` map, letting a connected peer suppress redials to honest configured peers (eclipse assist) |
| NET-13 | A6 | libp2p `with_peer_score` failure is warn-not-fatal; a scoring-less node is a flood amplifier |
| NET-14 | A6 | Devnet sync slots are sticky for the connection lifetime; a silent slot-holder throttles catch-up |
| NET-15 | A6 | The engine's sync pump broadcasts `get-blocks` to every devnet peer; each answers a 512-block page |
| NET-16 | A6 | Metrics server has no whole-request deadline (per-read timeout renews) |
| NET-17 | A6 | Devnet page has a block-count cap but no byte cap (unlike libp2p) |
| NET-18 | A6 | Deploy/config drift: NixOS PoS module defaults to `--transport libp2p`, which does not interoperate with the live fleet; its comment about the binary's default is stale |
| NET-19 | A6 | libp2p identity file is written non-atomically with the default umask before `chmod 0600`, and the chmod result is ignored |
| NET-20 | A6 | Frame-cliff vs consensus caps on the production transport |
| KS-01 | A7 | `keygen` silently overwrites an existing `validator.key` (no `create_new`, no lock, no confirmation) |
| KS-02 | A7 | Production passphrase file (`BLOCH_KEYSTORE_PASSPHRASE_FILE`) is not mode-checked; only the `keys seal --passphrase-file` path is |
| KS-03 | A7 | No minimum passphrase length on the `keygen` / env path; the mainnet ceremony sealed 64 keystores through it |
| KS-04 | A7 | Slashing protection has no import/export and no "minimum slot" initialization; the host-loss runbook's fencing step cannot be executed with the shipped tools |
| KS-05 | A7 | Interactive passphrase entry: echo not restored on signal, `tcsetattr` restore result ignored, and `Stdin`'s buffer retains the passphrase |
| KS-06 | A7 | `ws-sign` / `ws-signer-set` key-file hygiene: non-zeroized hex copy of the secret, no mode check on `.sk`, `.sk` write not fsynced |
| KS-07 | A7 | Block log has no per-frame checksum; a zero-filled tail is classified as corruption (boot refusal, no repair tool); a replayed block that fails `apply_block` is dropped along with … |
| KS-08 | A7 | `keys seal` / `keys inspect` run as another user leave root-owned `validator.key` / `LOCK`, so the next node start fails |
| KS-09 | A7 | Source-digest scope gaps: a compiled C include (`.macros`) and dot-directories are outside the hash; toolchain env not captured |
| KS-10 | A7 | Non-atomic writes: `save_with` truncates `validator.key` in place; `meta.bin` written with `fs::write` and no fsync |
| KS-11 | A7 | Header-supplied KDF cost is honored down to the Argon2 floor with no minimum or warning; caps still allow minutes of CPU per open |
| KS-12 | A7 | Toolchain pin is crate-scoped; documented root-level build commands bypass it |
| CR-03 | A8 | `SUITE_MLDSA65_ONLY` (0x0002) is accepted by the live Genesis-4 transfer verifier with no activation gate, contradicting the "hybrid on every consensus path" claim |
| CR-04 | A8 | Seed-derived keys are reused across contexts: `bloch-btc-wallet` default identity and `bloch-pq-vault` V1 derive the PQ key from the raw BIP39 seed, which is the same ChaCha20 seed… |
| CR-05 | A8 | Address checksum does not bind the network; `Wallet::build_tx` accepts a recipient `Address` of the other network |
| CR-06 | A8 | Index-0 convention mismatch between `wallet::disclosure::keypair_at` and `hd_wallet::derive_at` |
| CR-07 | A8 | Wallet-library robustness nits (panics / zeroization gaps on untrusted or edge inputs) |
| CR-08 | A8 | `SeededRngGuard` design hazards: a forgotten guard seeds the thread forever; ChaCha state is not zeroized; `Drop` touches TLS unconditionally |
| BV-05 | A9 | `csv_delay = 0` (and any tiny Δ) is accepted everywhere; branch A becomes immediately spendable and the vault silently provides no window |
| BV-06 | A9 | Remote-triggerable panic in `pq-shield-api` `/anchor/commitment`: an empty or >8192-byte `pq_recovery_pubkey` reaches the *panicking* `anchor_guard_governance` wrapper |
| BV-07 | A9 | The anchor has no freshness / rotation / revocation semantics; two valid anchors for the same vault under the same trusted key are indistinguishable, and nothing posts or orders an… |
| BV-08 | A9 | No dust, absurd-fee, or fee-estimation checks in the tx builders or the API; pre-signed transactions freeze fees |
| BV-09 | A9 | Secret material is never zeroized: `VaultKeys` (`Clone`), `pq_secret: Vec<u8>`, `SecretKey` (`Copy`, no `Drop`), master `Xpriv`, the HKDF IKM copy |
| BV-10 | A9 | `r` is deterministic in `(pq_sk, vault_id)` with a client-chosen, API-invisible `vault_id`; reuse or derivation-version confusion silently degrades or locks the vault |
| BV-11 | A9 | `SignedAnchor::deserialize` ignores trailing bytes; anchor address fields are never validated as addresses |
| BV-12 | A9 | `pq-shield-api` deployment posture: plain HTTP, no authentication, no per-client rate limit, `0.0.0.0` bind supported; CSRF-shaped requests reach handlers |
| BV-13 | A9 | `anchoring/src/http.rs`: no read/write timeout, API key sent in clear over whatever scheme the caller passes, lenient RPC parsing |
| BV-14 | A9 | The Ustav "PQ boundary" is a name-denylist tripwire that runs only in GitHub Actions; the GitLab pipeline neither runs it nor blocks on `bloch-ustav`/`bloch-euvm`/`bloch-btc-wallet… |
| BV-15 | A9 | `script_eval.rs` diverges from Bitcoin Core in ways that matter for standardness, and it is the *only* thing validating the vault's scripts |

Plus **LD-02** (stale `Cargo.lock` entries and `deny.toml` ignores; corrects INF-05).

### 6.4 Info

| ID | Annex | Finding |
|---|---|---|
| TX-17 | A1 | `FundedDeposit::decode` enforces consensus rules (`validate_shape`) inside the decoder, contrary to the stated decode/judge split |
| TX-18 | A1 | `Delegate.eligible` is a wire-supplied bit that consensus records verbatim |
| TX-19 | A1 | Spec/code drift in `BLOCH-L1-FEE-MARKET.md` and `BLOCH-TOKENOMICS-V4.md` |
| TX-20 | A1 | `interfaces.rs` `StateRoots` (14 fields, "closed again at eight components") vs `state_root.rs` (~25 tags) and the frozen `StateTransition::apply_block` doc "error order is consens… |
| TX-21 | A1 | Two block-validation stacks (`derive::validate_block` vs `transition`) still coexist |
| TX-22 | A1 | `CommittedState::genesis` silently overwrites duplicate validator indices / pubkeys from the manifest |
| INF-05 | A10 | `deny.toml` duplicate allowlist no longer matches `Cargo.lock`; the blocking `supply-chain` gate is very likely red — MEDIUM — NEW |
| INF-21 | A10 | A checked-in agent workflow with a stale, founder-specific context — INFO — NEW |
| INF-22 | A10 | Documentation rot that would mislead an operator — INFO — NEW |
| LG-09 | A11 | Pool: shares and ledger keyed by the raw `mining.authorize` username, not the parsed address |
| LG-10 | A11 | Documentation drift on the ledger-critical code (dust recipient, snapshot vintage, zero-value rows, dead "tip height" print) |
| LG-11 | A11 | Pool/pool-proxy: advisor findings verified closed; residual notes for a redeploy |
| LG-12 | A11 | euvm / ffg reachability from the live node |
| LG-13 | A11 | coherence-prover / SP1, spikes, fuzz |
| FC-13 | A2 | Arithmetic/panic notes (Info) |
| FC-14 | A2 | Documentation / spec divergences (Info) |
| ST-10 | A3 | Stale/contradictory comments on the slashing path |
| ST-11 | A3 | `genesis_principal_sat` and `admission_network_domain` are uncommitted, manifest-derived consensus inputs; the domain is `SHA3(manifest.encode())`, so any manifest re-encoding/form… |
| ST-12 | A3 | Arming L also switches on gas/byte metering for ExitV2, RandaoRecommit and SlashingEvidence (`staking_tx_charge` reads `\|\| withdrawal_active`), which `deploy/FLAG-DAY-LIFECYCLE.m… |
| ST-13 | A3 | Activation queue: intra-epoch order is grindable by `pubkey_hash` and the queue is unbounded (economically bounded by 25,000 BLCH per entry locked ≥ 2,080 epochs) |
| ST-14 | A3 | Mutation guard (`scripts/check-validator-lifecycle-mutations.py`) matches the code and each of its eight mutations is killed by `transition::tests::validator_lifecycle`; gaps in wh… |
| ST-15 | A3 | Whistleblower is always the *including proposer*; the observer who gossips evidence earns nothing, and evidence is trivially front-run |
| ST-16 | A3 | A queued funded validator whose deposit epoch is never finalized has no exit: `ExitV2` requires `activation_epoch <= epoch`, `Withdraw` requires an exit, and the only way out is a … |
| SR-10 | A4 | `state_root.rs` doc claims "no global mutable state" while holding a thread-local two-generation memo (consensus-safe, doc false) |
| SR-11 | A4 | Domain-tag hygiene: several tags cover two or three preimage shapes, docs are stale, and three tags live outside the registry |
| SR-12 | A4 | The weak-subjectivity window's slashability premise is void while slashing, exits and withdrawals are unarmed |
| SR-13 | A4 | Same-epoch re-mint is a permanent boot refusal for every node that stored the first artifact |
| EN-20 | A5 | Two implementations of the boot identity rule; the tested one has no production caller |
| EN-21 | A5 | `genesis_validator_count` assumes dense manifest indices |
| EN-22 | A5 | Env/flag-driven node-local safety behaviour (summary; see §3) |
| EN-23 | A5 | Per-ingest cost and memory grow with chain age; replay is quadratic |
| EN-24 | A5 | Serving `get_blocks` is rate-limited per connection, not per peer/IP |
| NET-21 | A6 | Information exposure by design (Info) |
| NET-22 | A6 | Minor code-level notes (Info) |
| KS-13 | A7 | Stale documentation: `KEYSTORE-AT-REST.md` says "No re-seal tool" and "Option A is the only one an operator can actually execute" |
| KS-14 | A7 | Ceremony script exports the passphrase into the environment of 64 child processes |
| KS-15 | A7 | `scripts/ws-ceremony-drill.sh` leaves throwaway signer `.sk` files in its work dir |
| KS-16 | A7 | WS boot refusal + `Restart=on-failure` is a replay-every-5-seconds crash loop |
| KS-17 | A7 | `--allow-plaintext-keystore` is matched anywhere in argv |
| KS-18 | A7 | Doppelganger protection is in-memory, window-bounded and flag-bypassable |
| CR-09 | A8 | Fork provenance documentation is inaccurate: README/NOTICE/VENDOR.toml claim only `src/lib.rs` changed and `build.rs` is identical to upstream; `build.rs` and `Cargo.toml` differ, … |
| CR-10 | A8 | Legacy raw-signature magic ambiguity (1/65536) remains for signatures |
| CR-11 | A8 | No standards-traceable KATs for ML-DSA-65 / Falcon-1024; seeded golden vectors pin the *crate*, not the *standard* |
| CR-12 | A8 | Genesis-3 PoW crate: `asert_next_bits` underflows on `new_height < anchor_height`; `bits_to_target` maps invalid compact bits to `Target::MIN` |
| BV-16 | A9 | Chameleon: no chameleon hash / trapdoor exists; the actual "forgery capability" belongs to whoever supplies `TrustedBurnCheckpoint`, and it is total (any amount of the route's escr… |
| BV-17 | A9 | `hybrid_wbtc_validator` (the "Custody 2-of-2" anchor guard) is never executed in a test, and it cannot run on the PQ-only Ustav kernel the anchor is supposed to live in |
| BV-18 | A9 | Documentation overclaims relative to the code (collected) |
| BV-19 | A9 | Minor robustness items in `bloch-btc-wallet` / `bloch-pq-vault` derivation |
| BV-20 | A9 | `guard_no_secrets` inspects key names only; a secret placed in a free-form value passes and is echoed back; `deny_unknown_fields` is ineffective on the flattened `AnchorVerifyReq` |
| BV-21 | A9 | `anchoring/` convention: first-`BLA1`-output heuristic, no signer binding, non-consensus tx codec |

Plus **LD-03** (18-minute unoptimized PoW test suite).

### 6.5 Refuted

| ID | Claim | Why |
|---|---|---|
| INF-05 | `deny.toml` allowlist stale ⇒ blocking supply-chain gate red | `cargo deny check bans` passes on the tree (Annex A12 §A12.4); the raw `Cargo.lock` duplicates the reviewer counted are unreachable leftovers of the excluded SP1 stack. The hygiene half survives as LD-02 (Low). |

## 7. Recommendations, in the order they should be done

The order is by *exposure today*, not by severity label: what an unauthenticated party can do now comes first, what one compromised key can do now second, what the next flag day will open third, and structural work last. Each item names the finding(s) it closes and whether it needs a consensus flag day.

### 7.1 Now — node-local, no flag day, ship in the next release

1. **Refuse to include tag `0x03` (`Exit`) when *proposing*, and alarm on any block that carries one.** Consensus cannot refuse it without a flag day, but a proposer-side refusal plus a fleet alert turns a silent roster takeover into a loud one and costs nothing. Also measure the block log for any historical `0x03`; if there are none, the consensus refusal in 7.3 is replay-safe. Closes the operational half of TX-01 / FC-03 / ST-02.
2. **Fix `select_transactions` to `continue` past an entry that does not fit instead of `break`, and refuse at the mempool door any transfer whose `max(encoded, declared)` exceeds the block byte cap.** One admissible transaction currently empties every proposer's selection network-wide. EN-01.
3. **Check outpoint existence *and ownership* and refuse duplicate inputs at the mempool door**, and give the mempool a byte budget (keyed by txid, not by full canonical bytes). EN-01, EN-02, EN-06, NET-02.
4. **Cache the per-source hash on each mempool entry** (or keep a per-source counter) and move the per-source check after the cheap structural refusals. Today every incoming transaction re-hashes every mempool entry's 3.7 KB public key on the consensus thread. EN-04, NET-02.
5. **Doppelgänger: count only sightings whose *signed slot* is at or after the boot wall slot, and apply the hook on the `release_held` path too.** A routine restart in the same epoch can currently halt a validator until an operator restarts it with the flag the runbook forbids. EN-03.
6. **Per-IP inbound connection cap and per-IP `get-blocks` budget on the devnet transport**; close idle inbound connections and make the dialer resend the first frame after a peer-side close. NET-03, NET-05, NET-09.
7. **Move RPC execution off the consensus thread** (or at least `sendrawtransaction`, `gettxstatus`, `getmempoolinfo`), add a per-IP RPC connection cap, and put the bootnodes' `:8080` behind the read-only allowlisting proxy the explorer already uses. NET-01, NET-11, EN-11, INF-10.
8. **Do not apply blocks from the future immediately**: store, but apply at their slot. A proposer for slot s+k can otherwise void slots s..s+k−1. EN-05.
9. **Keystore hygiene**: `keygen` must refuse to overwrite; the node's passphrase-file path must enforce 0600; enforce a minimum passphrase length on every path; write `validator.key` and `meta.bin` atomically. KS-01, KS-02, KS-03, KS-10.
10. **Ship a slashing-protection import/export and a "minimum slot" fence** so the host-loss runbook can actually be executed. KS-04.

### 7.2 Now — repository, CI and operations

11. **Commit the pipeline that builds the fleet image** (`bloch-g4` Dockerfile, Fly config, `start.sh`), build from a digest-pinned base with the pinned `1.94.1` toolchain and `--locked`, and publish `(commit, source digest, sha256, OCI digest)` per release. Until then the release-integrity gate is not met. INF-01.
12. **Split the fleet credential**: hardware-backed per-role SSH keys with `from=`/`command=` restrictions, a scoped Fly deploy token behind hardware 2FA, and a recorded per-host sweep that every keystore is `BPOSKEY2`. INF-02.
13. **Make the GitLab `check` stage green** (trademark gate and comment-constant guard) so the `test` stage runs again, or move the 13 GitLab-only blocking gates to GitHub; mirror the coherence-prover lockfiles into the GitHub `osv-scanner` job. INF-03, INF-04.
14. **Get the blocking supply-chain gates green again**: `cargo update -p rustls --precise 0.23.45` in all five workspaces and `cargo update -p libp2p-quic` (0.13.1) — both applied in this report's PR (RUSTSEC-2026-0285 and GHSA-5hq8-qhww-jm7q failed `cargo-audit`, `cargo-deny` and `osv-scanner` on 2026-09-17); then prune the 289 stale `Cargo.lock` entries with `cargo update --workspace`, and delete the ten `deny.toml`/`audit.toml` ignores that match nothing in the resolved graph. LD-01, LD-02, INF-05.
15. **Alerting**: restart loops, `store_append_failures`, `validator_active == 0`, heartbeat absence, missed duties; fix the monitoring README's three "do not exist" metrics that the exporter already emits. INF-07.
16. **Fix the runbooks that name tools that do not exist** (`bloch-pos-cli getvalidatorstatus`) on the host-loss fencing path. INF-08.
17. **Settle the carried-ledger provenance**: publish from the two snapshot nodes the applied tip hash, selected-chain height and block 39,918's disposition; state in `CARRYOVER-SNAPSHOT.md` whether the ledger is the state after block 39,917 or 39,918; if a real block's coinbase was dropped, record the 40,000 BLOCH as an accepted, documented loss. LG-01, LG-03.
18. **Run a full-history secret scan on an unshallowed clone with both remotes**, and confirm the GitLab token rotation. INF-19.

### 7.3 Before the next flag day (needs a coordinated consensus change)

19. **Refuse `0x03` in consensus** independently of the ADR-041 lifecycle, or at minimum apply `MAX_EXITS_PER_EPOCH` to the legacy arm. TX-01 / FC-03 / ST-02.
20. **Bound the inactivity leak so the roster can never reach zero weight for everyone** (cap `t`, or fall back to the unleaked duty roster when the leak-adjusted total is zero), and correct the `MAX_EPOCH_ADVANCE` documentation: the real dark-time ceiling is ~60 epochs, not 45 days. FC-01.
21. **Redesign the genesis-cohort cap before funded admission opens.** As written, the first 25,000 BLOCH outsider holds 6 % of consensus today, one third at month six and a lone two-thirds finality supermajority at month twelve, and the deposit cap (computed from the *capped* total) prevents anyone from bringing more than the minimum bond. Cap the cohort's *share* only once outsider stake is meaningful relative to the cohort, compute the deposit cap from uncapped stake, and correct tokenomics §3.3.1. FC-02 / ST-01, ST-08, ST-09.
22. **Check block byte/gas caps *before* executing each transaction** (verdict-preserving; only the error moves earlier). TX-02.
23. **Correlated-slashing amplification**: price the window against raw bonds, not capped/leaked effective stake; align the self-slash timeline with the voluntary-exit timeline. ST-03, ST-04.
24. **Bind attestation and proposal signing roots to the genesis/network identity** before slashing arms, and make `network_binding()` genesis-derived. FC-10, ST-07, TX-04.
25. **Bind the genesis cohort into `genesis_root`** (or the state root) so two manifests differing only in cohort cannot share a chain id. SR-01.
26. **Reject the Falcon zero-padded encoding (last byte `0x00`), bind the two hybrid halves, and restrict the legacy signature fallback**; gate suite `0x0002` on the transfer path. CR-02, CR-03.
27. **Add a proposer boost or equivalent** and a seed look-ahead of more than one epoch (F6) before the fleet is anything but a single operator. FC-04, FC-05.

### 7.4 Before any activation of the affected product

28. **Coherence shielded pool**: define the key hierarchy (`nk = PRF(spending key)`, `pk_d` from it), make `check_spend` prove knowledge of the spending key, and add the wrong-`nk` and same-note-same-nullifier tests. Do not activate P1 with the current statement. CR-01.
29. **PQ-shield vault**: separate the deposit key from the branch-A key, give the clawback a fee-bump path that does not hand out `recovery_sk` (anchor output / ACP), harden recovery-key derivation, enforce a minimum `csv_delay`, fix the API panic, and rewrite the README's claims to the property actually delivered. BV-01…BV-08.
30. **Weak-subjectivity onboarding**: mint and sign a fresh checkpoint under the Phase-A arrangement (the only artifact is unsigned and stale), have `ws-verify` apply the same window rule as `boot`, and validate the checkpoint's roots against the header at `block_root`. SR-03, SR-04, SR-05.

### 7.5 Structural

31. **Authenticate and encrypt the validator transport.** Every finding in §7.1 items 3–7 is an instance of one fact: the live mesh accepts frames from anyone. Rolling `--transport libp2p`/`dual` (Noise) removes the unauthenticated class, but the latent libp2p findings (NET-06, NET-07, NET-08) must be fixed first, and the README should stop calling the transport post-quantum until it is.
32. **Arm the lifecycle flag day (L) with the fixes above in place**, not before: it closes `0x03`, opens deposits and exits, and switches on slashing — and it is also the moment FC-02/ST-01 becomes exploitable.
33. **Commission the third-party audit** the repository has been preparing for, with this report and its annexes as the entry dossier. Nothing here substitutes for it.

## 8. Test-coverage gaps that matter

The live crates carry 1,034 `#[test]` functions and the suites pass (Annex A12). Coverage is nevertheless shaped by what the authors expected to break, and every reviewer found the same pattern: the passing side of a rule is well pinned, the adversarial side is not. The gaps below are the ones whose absence let a High or Medium finding in this report go unnoticed; each is listed in full in the annex named.

| Gap | Would have caught | Annex |
|---|---|---|
| No test that 63 legacy `Exit` messages in one block are accepted and the survivor finalizes alone; nothing pins that the legacy arm ignores `MAX_EXITS_PER_EPOCH` | TX-01 / FC-03 / ST-02 | A1, A3 |
| No test rolls `close_epoch` across ≥ 60 empty epochs and asserts a proposer still exists | FC-01 | A2 |
| No cohort-cap test with a *single* minimum-bond outsider at the taper floor | FC-02 / ST-01 | A2, A3 |
| No test drives `select_transactions` with a high-tip entry larger than the byte cap | EN-01 | A5 |
| No test bounds mempool bytes, or admits a transfer with duplicate inputs or inputs owned by another key | EN-02, EN-06 | A5 |
| Doppelgänger tests use a synthetic zero-signature attestation; none replays the node's own signed attestation after a restart | EN-03 | A5 |
| No CPU-cost test for `on_transaction` at a full mempool; no rejected-attestation replay test | EN-04, NET-02, EN-07 | A5, A6 |
| No per-IP inbound bound test (none exists); no aggregate `get-blocks` load test | NET-03, NET-05 | A6 |
| No fuzz target for `PosTransaction::from_canonical_bytes`, the RPC JSON parser, or the devnet frame reader | TX-16, NET-10 | A1, A6 |
| No test that a Falcon signature zero-padded to exactly 1,280 bytes is rejected (the existing "+1 byte" test passes for the wrong reason) | CR-02 | A8 |
| No test that suite 0x0002 is refused on a consensus path (the only 0x0002 test proves it is accepted) | CR-03 | A8 |
| coherence-core has no negative test for a wrong `nk` and no "same note ⇒ same nullifier" invariant | CR-01 | A8 |
| `store.rs` has no test for a truncated, zero-filled or corrupt mid-log frame, and no crash-consistency test | KS-07, KS-10 | A7 |
| No regtest or `bitcoinconsensus` validation of the vault scripts; no test that a watchtower can bump a clawback; no negative test for `csv_delay = 0` | BV-01, BV-02, BV-05 | A9 |
| `tests/e2e.rs` still exercises the reference harness (`RefTransition`), not the shipped transition (GAP-7, unchanged since 2026-08-11) | — | A2 |
| Root-binding tests lack `must_move` cases for `issued_sat`, `evm`, `eutxos`, the four ADR-041 fields and several validator columns | SR-09 | A4 |
| `bloch-ustav`, `pq-shield-api` and `anchoring` tests are non-blocking or run in no pipeline | BV-14 | A9, A10 |

## 9. Residual risk and what this audit did not do

- **Nothing was executed against a network.** Every cost figure (CPU per frame, bytes per mempool entry, seconds per malicious block) is derived from code structure and the repository's own measurements, not from a benchmark on the fleet. The dynamic work was limited to building the workspace and running the live crates' test suites, `clippy`, `cargo-deny` and `cargo-audit` (Annex A12).
- **Live fleet state is unknown.** Whether the epoch-2700 keystore sealing completed on all 64 hosts, what image the Fly machines run, whether the leaked GitLab token was rotated, which validator ports are actually reachable, and whether `:8080` is still forwarded on the bootnodes, cannot be established from the tree. `deploy/FLEET-INVENTORY.md` is a template.
- **The clone is shallow** (103 commits). History-only claims in `.gitleaks.toml` (a demo signing key once committed, 55 historical findings) could not be checked. A full-history secret scan on an unshallowed clone with both remotes is still owed.
- **Retired code was sampled, not audited.** `legacy/genesis3-node` was read along the ledger-export path only; `pool/`, `pool-proxy/`, the eUTXO VM and the FFG committee were checked for reachability and for the previously reported advisor findings.
- **Cryptographic primitives were not re-audited.** The vendored PQClean sources were verified byte-identical to upstream and hash-pinned; the algorithms themselves, the AVX2 ML-DSA variant's side-channel behaviour and the Argon2/AES software paths were not evaluated.
- **Economics beyond arithmetic** (whether the tokenomics allocation, vesting and emission schedule are sound as policy) is out of scope; only conservation, cap enforcement and rounding were checked.
- **Documents cited as KNOWN but not in the tree** (the Round-1/2/3/6/7 remediation audits, the 2026-09-07 external review) could not be read; every KNOWN label relies on code comments and runbooks that cite them. If those documents already record a finding labelled NEW here, the label should be corrected, not the finding.

## 10. Annexes

All annexes are in `docs/audit/deep-audit-2026-09-16/`. Each area annex (A1–A11) is the full report of the reviewer who owned that surface: scope and method, every finding with file:line evidence, positive observations, test-coverage gaps and residual risk. Where the lead's verification changed a severity or a status, the change is recorded in the consolidated table in §6 of this report, not by editing the reviewer's text.

| Annex | File | Scope |
|---|---|---|
| A0 | `A0-inventory.md` | Repository map, build/toolchain, warnings, the 19 flag-day gates, determinism and panic-surface metrics |
| A1 | `A1-consensus-transition.md` | State transition, transaction codec and execution, fee market, emission, header, params |
| A2 | `A2-consensus-finality-forkchoice.md` | FFG finality and leak, LMD-GHOST, attestations, gossip admission, RANDAO, committees, proposer schedule |
| A3 | `A3-consensus-staking-lifecycle.md` | Deposits, activation, exits, withdrawals, delegation, slashing, cohort cap, rewards, ADR-041 lifecycle |
| A4 | `A4-consensus-state-root-ws.md` | Sparse Merkle state root, header/BlockId, wire codec, domain-separation tags, weak-subjectivity checkpoints |
| A5 | `A5-node-engine.md` | Node engine: ingest, mempool, production, duties, sync, replay, finality latch, doppelgänger, genesis assembly |
| A6 | `A6-node-network-rpc.md` | Devnet and libp2p transports, framing, sync protocol, JSON-RPC, metrics, vendored yamux fork |
| A7 | `A7-node-storage-keys-boot.md` | Block log, keystore, slashing protection, boot gate, CLI tools, build identity, key ceremony |
| A8 | `A8-crypto.md` | Hybrid ML-DSA-65 ‖ Falcon-1024, pqcrypto-internals fork and seeded RNG, wallet, coherence-core, bloch-sis-pow |
| A9 | `A9-bitcoin-vault-ustav.md` | PQ-shield vault, btc-wallet, pq-shield-api, anchoring SDK, Ustav token kernel |
| A10 | `A10-infra-supply-chain.md` | CI/CD, dependency policy, Docker/Fly/Akash/Nix, secrets sweep, carryover integrity, runbooks |
| A11 | `A11-legacy-apps-sdk.md` | Genesis-3 ledger provenance, faucet/indexer/explorer, SDKs, mining pool, euvm/ffg reachability |
| A12 | `A12-dynamic.md` | Build, test suites, clippy, cargo-deny, cargo-audit, lead's static scans |
| A13 | `A13-verification.md` | Adversarial verification: per-finding verdicts from the refutation pass, the independent second lens on every High, and the completeness critic |
| A14 | `A14-reproducers/` | Reproduction tests and step-by-step plans written by the second-lens reviewers (not run, not added to the repository's test suite) |
