| ID | Lead severity | Reviewer | Status | Verified | Live today? | Title | Annex |
|---|---|---|---|---|---|---|---|
| EN-01 | **High** | High | NEW | CONFIRMED | yes | One admissible transaction censors every transaction on the network (`select_transactions` breaks on the first over-cap entry) | A5 |
| EN-02 | **High** | High | NEW | CONFIRMED | yes | Mempool is bounded by count (4,096) but not by bytes: ~28 GB per node from one unauthenticated peer | A5 |
| EN-03 | **High** | High | NEW | CONFIRMED | yes | Doppelgänger protection halts a validator permanently when its *own* pre-restart attestation is replayed to it | A5 |
| EN-04 | **High** | High | NEW | CONFIRMED | yes | `on_transaction` runs an O(mempool) SHA3 scan *before* any cheap refusal: ~40 ms of consensus-thread CPU per 120-byte frame | A5 |
| FC-01 | **High** | High | NEW | CONFIRMED | yes | Post-e1400, ~60 epochs without any included attestation leaks every validator to zero and the chain dies permanently (no proposer can ever be drawn) | A2 |
| FC-02 | **High** | High | KNOWN | CONFIRMED | no | Genesis-cohort cap hands a supermajority to the first minimum-bond independent validator once the taper is deep | A2 |
| FC-03 | **High** | High | KNOWN | CONFIRMED | yes | Unauthenticated legacy `Exit` (tag 0x03) is consensus-valid: one scheduled proposer can retire the other 63 validators and own the roster after 32 epochs | A2 |
| INF-02 | **High** | High | KNOWN | CONFIRMED | yes | One credential class controls the majority of validator keys — HIGH — status: KNOWN (`deploy/SSH-ROLE-SEPARATION.md`, FLAG-DAY-EPOCH-800 "Known gaps")… | A10 |
| NET-01 | **High** | High | KNOWN | CONFIRMED | yes | Public bootnodes expose the full unauthenticated RPC (incl. `sendrawtransaction`) on `:8080`, and RPC executes on the consensus thread | A6 |
| NET-02 | **High** | High | NEW | CONFIRMED | yes | Mempool admission is O(N × SHA3) per transaction and admits/relays transactions whose inputs do not exist; one public submission point can saturate ev… | A6 |
| NET-03 | **High** | High | NEW | CONFIRMED | yes | Devnet inbound connection cap is global with no per-IP limit; 128 idle connections from one attacker lock every other peer out of a bootnode indefinitely | A6 |
| ST-01 | **High** | High | NEW | not in verification set | — | Genesis-cohort cap hands the *non-cohort* side a calendar-fixed consensus share regardless of its stake; a single 25,000 BLCH outsider reaches 1/3 (st… | A3 |
| ST-02 | **High** | High | KNOWN | not in verification set | — | Legacy unauthenticated `Exit` (0x03) is live and un-capped today: any single proposer can force-exit the entire roster in one block, killing the chain… | A3 |
| TX-01 | **High** | High | KNOWN | CONFIRMED | yes | Legacy `Exit` (tag 0x03) is live, unauthenticated and uncapped: one block proposer can retire the entire validator set; the survivor holds 100% of con… | A1 |
| TX-12 | **High** | High | KNOWN | CONFIRMED | yes | Every RANDAO chain is terminal; the first exhaustions (~2027-02) start removing proposers permanently | A1 |
| BV-01 | **Medium** | High | NEW | PARTIALLY_CONFIRMED | no | The deposit key and the branch-A key are the same key, so the "pre-signed U + delete the bypass key" covenant emulation is structurally impossible; a … | A9 |
| BV-02 | **Medium** | High | NEW | PARTIALLY_CONFIRMED | no | The clawback cannot be fee-bumped by a watchtower as documented; the only way to give a watchtower that power is to hand it `recovery_sk`, which lets … | A9 |
| BV-03 | **Medium** | High | NEW | PARTIALLY_CONFIRMED | no | `pq-shield-api` receives exactly the public keys whose secrecy the vault's security rests on (`recovery_pubkey`, `hot_pubkey`) plus the unvault intent… | A9 |
| BV-04 | **Medium** | Medium | KNOWN | CONFIRMED | no | Recovery key is a non-hardened BIP-32 sibling of the hot key in *both* derivations (V1 and the A4-M-5 "fix" V2); `hot_sk` + one xpub ⇒ `recovery_sk` | A9 |
| CR-01 | **Medium** | High | NEW | CONFIRMED | no | `coherence_core::check_spend` has no spend authorization: `nk` is prover-chosen, so any note plaintext holder (incl. the sender) can spend, and one no… | A8 |
| CR-02 | **Medium** | Medium | NEW | CONFIRMED | yes | Hybrid signatures are third-party malleable (SUF-CMA broken): PQClean's non-padded `falcon-1024` verifier accepts the 1280-byte zero-padded encoding; … | A8 |
| EN-05 | **Medium** | Medium | NEW | CONFIRMED | yes | Future-slot blocks are stored *and applied* immediately: a scheduled proposer can void up to 7 preceding slots, and honest clock skew voids slots by a… | A5 |
| EN-06 | **Medium** | Medium | KNOWN | CONFIRMED | yes | Mempool ordering and capacity eviction trust an unbacked, sender-chosen `tip_millisat_per_gas` | A5 |
| EN-07 | **Medium** | Medium | KNOWN | CONFIRMED | yes | No per-peer budget on hybrid verifications for unauthenticated attestations/transactions on the devnet mesh; rejected messages are not remembered | A5 |
| EN-08 | **Medium** | Medium | KNOWN | PARTIALLY_CONFIRMED | yes | The shared engine queue budget has no per-peer fairness: one peer can keep honest blocks and attestations shed | A5 |
| EN-09 | **Medium** | Medium | NEW | CONFIRMED | yes | A validator key can grow `blocks` (a fork-choice input) without bound above the finalized floor | A5 |
| EN-10 | **Medium** | Medium | NEW | CONFIRMED | yes | Duties are signed against an artificially rolled stale state while the node is behind | A5 |
| EN-11 | **Medium** | Medium | NEW | CONFIRMED | yes | `gettxstatus` hashes every mempool transaction on the consensus thread | A5 |
| FC-04 | **Medium** | Medium | KNOWN | CONFIRMED | yes | RANDAO grinding of the *next* epoch's committees and proposer schedule is free and one epoch too close (F6 open, proposer reward absent) | A2 |
| FC-05 | **Medium** | Medium | KNOWN | PARTIALLY_CONFIRMED | yes | LMD-GHOST has no proposer boost and a root-value tie-break: ex-ante reorgs and balancing are cheap at 2 attesters per slot | A2 |
| FC-07 | **Medium** | Medium | KNOWN | CONFIRMED | yes | With the 1/2 floor armed, any two disjoint sets holding ≥ 1/3 of unleaked stake each finalize conflicting checkpoints after ~25 epochs, with no slasha… | A2 |
| FC-08 | **Medium** | Medium | KNOWN | CONFIRMED | yes | Sub-epoch duty-view lag: with `back = 1` the seed and the source checkpoint for epoch E depend on the *last block* of E−1, which honest first-slot att… | A2 |
| INF-01 | **Medium** | High | KNOWN | CONFIRMED | yes | The live validator binary is built and shipped by a pipeline that exists only outside the repository — HIGH — status: partially KNOWN (`deploy/RELEASE… | A10 |
| LG-01 | **Medium** | High | KNOWN (refined) | PARTIALLY_CONFIRMED | no | The carried ledger holds exactly 39,917 Genesis-3 subsidies, not 39,918; the missing coinbase is unexplained and two concrete mechanisms exist in the … | A11 |
| NET-04 | **Medium** | Medium | KNOWN | CONFIRMED | yes | Unauthenticated devnet frames buy bounded but sustained consensus-thread CPU (hybrid verifies) and unbounded log spam; `Reject` has no consequence on … | A6 |
| NET-05 | **Medium** | Medium | NEW | CONFIRMED | yes | Devnet `get-blocks` serving is rate-limited per *connection* only (no per-IP/global cap), pages are 4× larger than libp2p's and carry no byte cap | A6 |
| NET-09 | **Medium** | Medium | NEW | CONFIRMED | yes | Devnet idle-close at 120 s silently drops the first broadcast after an idle period; the honest cadence on non-sync connections is ~16 minutes | A6 |
| NET-10 | **Medium** | Medium | NEW | CONFIRMED | yes | RPC JSON parser memory amplification and id echo | A6 |
| NET-11 | **Medium** | Medium | NEW | CONFIRMED | yes | RPC connection exhaustion/slowloris: 64 slots, 30 s deadline, no per-IP limit | A6 |
| NET-12 | **Medium** | Medium | KNOWN (refined) | CONFIRMED | yes | Bootnode/observer hosts are a privileged frame-push position into all 63 validators | A6 |
| SR-02 | **Medium** | Medium | KNOWN | CONFIRMED | yes | The signer arrangement (keys + quorum rule + review clock) is not bound by the checkpoint digest | A4 |
| SR-03 | **Medium** | Medium | KNOWN | CONFIRMED | yes | Fresh-install onboarding is currently refused: the genesis anchor aged out at epoch 2016 and no signed envelope exists anywhere in the tree | A4 |
| ST-03 | **Medium** | Medium | NEW | not in verification set | — | Correlated-slashing amplification mixes raw-bond penalties (numerator) with effective, capped/leaked stake (denominator): one slash of a cohort valida… | A3 |
| ST-04 | **Medium** | Medium | NEW | not in verification set | — | Self-slashing is a faster, cap-free exit: ejection at E+1 bypasses `MAX_EXITS_PER_EPOCH`, withdrawability lands 32 epochs *earlier* than a voluntary e… | A3 |
| ST-05 | **Medium** | Medium | NEW | not in verification set | — | Post-L, unauthenticated lifecycle transactions cost the node 1–4 hybrid verifications each before any per-source accounting; `tx_source_hash` returns … | A3 |
| TX-02 | **Medium** | Medium | NEW | CONFIRMED | yes | Per-block byte/gas caps are enforced only after all transactions have executed; a scheduled proposer can force ~16× a maximal block's execution work p… | A1 |
| TX-06 | **Medium** | Medium | KNOWN | CONFIRMED | yes | Zero-value and arbitrary-count outputs are valid: permanent state growth at ~6 sat per entry | A1 |
| TX-08 | **Medium** | Medium | KNOWN | CONFIRMED | yes | Producer fee share compounds into `staked_sat` (consensus weight) with no per-block cap | A1 |
| TX-11 | **Medium** | High | KNOWN | CONFIRMED | yes | Slashing is unreachable; equivocation is free | A1 |
| BV-05 | **Low** | Medium | NEW | CONFIRMED | no | `csv_delay = 0` (and any tiny Δ) is accepted everywhere; branch A becomes immediately spendable and the vault silently provides no window | A9 |
| BV-06 | **Low** | Medium | NEW | CONFIRMED | no | Remote-triggerable panic in `pq-shield-api` `/anchor/commitment`: an empty or >8192-byte `pq_recovery_pubkey` reaches the *panicking* `anchor_guard_go… | A9 |
| BV-07 | **Low** | Medium | NEW | PARTIALLY_CONFIRMED | no | The anchor has no freshness / rotation / revocation semantics; two valid anchors for the same vault under the same trusted key are indistinguishable, … | A9 |
| BV-08 | **Low** | Medium | NEW | CONFIRMED | no | No dust, absurd-fee, or fee-estimation checks in the tx builders or the API; pre-signed transactions freeze fees | A9 |
| BV-09 | **Low** | Low | NEW | not in verification set | — | Secret material is never zeroized: `VaultKeys` (`Clone`), `pq_secret: Vec<u8>`, `SecretKey` (`Copy`, no `Drop`), master `Xpriv`, the HKDF IKM copy | A9 |
| BV-10 | **Low** | Low | KNOWN (refined) | not in verification set | — | `r` is deterministic in `(pq_sk, vault_id)` with a client-chosen, API-invisible `vault_id`; reuse or derivation-version confusion silently degrades or… | A9 |
| BV-11 | **Low** | Low | NEW | not in verification set | — | `SignedAnchor::deserialize` ignores trailing bytes; anchor address fields are never validated as addresses | A9 |
| BV-12 | **Low** | Low | KNOWN | not in verification set | — | `pq-shield-api` deployment posture: plain HTTP, no authentication, no per-client rate limit, `0.0.0.0` bind supported; CSRF-shaped requests reach hand… | A9 |
| BV-13 | **Low** | Low | NEW | not in verification set | — | `anchoring/src/http.rs`: no read/write timeout, API key sent in clear over whatever scheme the caller passes, lenient RPC parsing | A9 |
| BV-14 | **Low** | Low | NEW | not in verification set | — | The Ustav "PQ boundary" is a name-denylist tripwire that runs only in GitHub Actions; the GitLab pipeline neither runs it nor blocks on `bloch-ustav`/… | A9 |
| BV-15 | **Low** | Low | KNOWN | not in verification set | — | `script_eval.rs` diverges from Bitcoin Core in ways that matter for standardness, and it is the *only* thing validating the vault's scripts | A9 |
| CR-03 | **Low** | Medium | NEW | CONFIRMED | yes | `SUITE_MLDSA65_ONLY` (0x0002) is accepted by the live Genesis-4 transfer verifier with no activation gate, contradicting the "hybrid on every consensu… | A8 |
| CR-04 | **Low** | Low | KNOWN | not in verification set | — | Seed-derived keys are reused across contexts: `bloch-btc-wallet` default identity and `bloch-pq-vault` V1 derive the PQ key from the raw BIP39 seed, w… | A8 |
| CR-05 | **Low** | Low | NEW | not in verification set | — | Address checksum does not bind the network; `Wallet::build_tx` accepts a recipient `Address` of the other network | A8 |
| CR-06 | **Low** | Low | NEW | not in verification set | — | Index-0 convention mismatch between `wallet::disclosure::keypair_at` and `hd_wallet::derive_at` | A8 |
| CR-07 | **Low** | Low | NEW | not in verification set | — | Wallet-library robustness nits (panics / zeroization gaps on untrusted or edge inputs) | A8 |
| CR-08 | **Low** | Low | NEW | not in verification set | — | `SeededRngGuard` design hazards: a forgotten guard seeds the thread forever; ChaCha state is not zeroized; `Drop` touches TLS unconditionally | A8 |
| EN-12 | **Low** | Low | NEW | not in verification set | — | `release_held` judges released attestations with the *wall epoch's* seed and roster, not the attestation's | A5 |
| EN-13 | **Low** | Low | NEW | not in verification set | — | Re-offered orphans pay a hybrid verify on every delivery | A5 |
| EN-14 | **Low** | Low | KNOWN | not in verification set | — | Orphans hanging off a latch-refused branch keep the sync pump broadcasting `get_blocks` to all peers indefinitely | A5 |
| EN-15 | **Low** | Low | NEW | not in verification set | — | `ancestral_boundary_mix` walk is bounded by `blocks.len()`, and stored non-canonical blocks are not slot-monotone | A5 |
| EN-16 | **Low** | Low | KNOWN | not in verification set | — | The proposer's drop loop bars innocent transactions on non-indexed transition errors | A5 |
| EN-17 | **Low** | Low | NEW | not in verification set | — | `do_reorg` rewrites the whole block log synchronously on the consensus thread | A5 |
| EN-18 | **Low** | Low | KNOWN | not in verification set | — | RPC events bypass the queue budget and are answered on the consensus thread | A5 |
| EN-19 | **Low** | Low | NEW | not in verification set | — | `RandaoRecommit` is signed outside slashing protection and outside the doppelgänger gate | A5 |
| FC-06 | **Low** | Medium | KNOWN (refined) | CONFIRMED | yes | Node-side fork choice is order- and store-shape-dependent (O01), and feeds *every stored block* including orphans | A2 |
| FC-09 | **Low** | Low | NEW | not in verification set | — | `close_epoch` silently swallows `FinalityError::OutOfOrderEpoch`; a desynchronised engine would stop finality forever with no signal | A2 |
| FC-10 | **Low** | Low | NEW | not in verification set | — | Attestation and proposal signing roots bind no network/genesis identity | A2 |
| FC-11 | **Low** | Low | NEW | not in verification set | — | The leak is absolute (satoshis) while `duty_roster_at` rescales effective stake; a residual leak can zero a validator the moment a cap binds | A2 |
| FC-12 | **Low** | Low | KNOWN | not in verification set | — | Committed `fc_equivocators` bar is permanent and has no exit/slash/recovery path | A2 |
| INF-03 | **Low** | Medium | NEW | CONFIRMED | yes | GitLab's `check` stage is red on `main`, so its `test` stage never runs; the "both pipelines gate the live crates" claim is false — MEDIUM — NEW | A10 |
| INF-04 | **Low** | Medium | NEW | PARTIALLY_CONFIRMED | yes | GitHub and GitLab pipelines diverge; the pipeline this clone actually pushes to is the weaker one — MEDIUM — NEW | A10 |
| INF-06 | **Low** | Medium | NEW | CONFIRMED | no | SP1 prover image: pipe-to-shell installers, floating base images, whole-repo `COPY` — MEDIUM — NEW | A10 |
| INF-07 | **Low** | Medium | NEW | CONFIRMED | yes | Alerting has holes and the alert docs contradict the exporter — MEDIUM — NEW | A10 |
| INF-08 | **Low** | Medium | NEW | CONFIRMED | yes | Runbooks name a CLI and an RPC method that do not exist, on the host-loss fencing path — MEDIUM — NEW | A10 |
| INF-09 | **Low** | Medium | KNOWN | CONFIRMED | yes | No rollback is currently possible, and the release signing flow is unspecified — MEDIUM — KNOWN (`deploy/RELEASE-INTEGRITY.md` §8.7), restated because… | A10 |
| INF-10 | **Low** | Medium | KNOWN | PARTIALLY_CONFIRMED | yes | Bootnodes expose the full unauthenticated PoS JSON-RPC (incl. `sendrawtransaction`) on `:8080`, contradicting the published posture — MEDIUM — status:… | A10 |
| INF-11 | **Low** | Low | NEW | not in verification set | — | The `check-*-blocking` guards are bypassable by trivial spellings and cover only five jobs — LOW — NEW | A10 |
| INF-12 | **Low** | Low | NEW | not in verification set | — | Scanner binaries are pinned by version, not by hash; a pre-existing binary on the self-hosted runner is trusted blindly — LOW — NEW | A10 |
| INF-13 | **Low** | Low | NEW | not in verification set | — | `.dockerignore` does not exclude key material; only `COPY . .` makes it bite — LOW — NEW | A10 |
| INF-14 | **Low** | Low | NEW | not in verification set | — | Image-pin guard exemptions are loose and its own docs are stale — LOW — NEW | A10 |
| INF-15 | **Low** | Low | NEW | not in verification set | — | Retired-but-deployable configs publish unauthenticated RPC; explorer upstream is plain HTTP via a third-party DNS — LOW — NEW (explorer part is KNOWN … | A10 |
| INF-16 | **Low** | Low | NEW | not in verification set | — | `scripts/prova-relanca.sh` executes a wrapper from world-writable `/private/tmp` — LOW — NEW | A10 |
| INF-17 | **Low** | Low | NEW | not in verification set | — | The attested/appliance image keeps sshd enabled with NixOS defaults; the persist-volume encryption design is internally inconsistent — LOW — NEW | A10 |
| INF-18 | **Low** | Low | KNOWN | not in verification set | — | Nix modules that cannot work as shipped — LOW — mostly KNOWN (admitted TODOs) | A10 |
| INF-19 | **Low** | Low | KNOWN | not in verification set | — | History claims (`catalog-dev.secret.pem`, "55 findings", leaked PAT) cannot be verified from this clone; CI never scans history — LOW — status: KNOWN … | A10 |
| INF-20 | **Low** | Low | NEW | not in verification set | — | Minor key-handling and hygiene items — LOW — NEW | A10 |
| KS-01 | **Low** | Medium | NEW | CONFIRMED | yes | `keygen` silently overwrites an existing `validator.key` (no `create_new`, no lock, no confirmation) | A7 |
| KS-02 | **Low** | Medium | NEW | CONFIRMED | yes | Production passphrase file (`BLOCH_KEYSTORE_PASSPHRASE_FILE`) is not mode-checked; only the `keys seal --passphrase-file` path is | A7 |
| KS-03 | **Low** | Medium | NEW | PARTIALLY_CONFIRMED | no | No minimum passphrase length on the `keygen` / env path; the mainnet ceremony sealed 64 keystores through it | A7 |
| KS-04 | **Low** | Medium | KNOWN (refined) | PARTIALLY_CONFIRMED | yes | Slashing protection has no import/export and no "minimum slot" initialization; the host-loss runbook's fencing step cannot be executed with the shippe… | A7 |
| KS-05 | **Low** | Low | NEW | not in verification set | — | Interactive passphrase entry: echo not restored on signal, `tcsetattr` restore result ignored, and `Stdin`'s buffer retains the passphrase | A7 |
| KS-06 | **Low** | Low | NEW | not in verification set | — | `ws-sign` / `ws-signer-set` key-file hygiene: non-zeroized hex copy of the secret, no mode check on `.sk`, `.sk` write not fsynced | A7 |
| KS-07 | **Low** | Low | KNOWN (refined) | not in verification set | — | Block log has no per-frame checksum; a zero-filled tail is classified as corruption (boot refusal, no repair tool); a replayed block that fails `apply… | A7 |
| KS-08 | **Low** | Low | NEW | not in verification set | — | `keys seal` / `keys inspect` run as another user leave root-owned `validator.key` / `LOCK`, so the next node start fails | A7 |
| KS-09 | **Low** | Low | NEW | not in verification set | — | Source-digest scope gaps: a compiled C include (`.macros`) and dot-directories are outside the hash; toolchain env not captured | A7 |
| KS-10 | **Low** | Low | NEW | not in verification set | — | Non-atomic writes: `save_with` truncates `validator.key` in place; `meta.bin` written with `fs::write` and no fsync | A7 |
| KS-11 | **Low** | Low | KNOWN | not in verification set | — | Header-supplied KDF cost is honored down to the Argon2 floor with no minimum or warning; caps still allow minutes of CPU per open | A7 |
| KS-12 | **Low** | Low | KNOWN | not in verification set | — | Toolchain pin is crate-scoped; documented root-level build commands bypass it | A7 |
| LG-02 | **Low** | Low | KNOWN (refined) | not in verification set | — | vout endianness (Legacy M-3): the bug is in the exporter/`iter_utxos_sorted`, the Genesis-4 loader carries the corrupted index verbatim into committed… | A11 |
| LG-03 | **Low** | Medium | NEW | PARTIALLY_CONFIRMED | no | Snapshot exporter and `iter_utxos_sorted` silently drop undecodable UTXO rows (fail-open on the ledger-producing path) | A11 |
| LG-04 | **Low** | Low | NEW | not in verification set | — | Faucet per-address cooldown is bypassable by hex case variation | A11 |
| LG-05 | **Low** | Low | NEW | not in verification set | — | Faucet accepts cross-site form POSTs (CSRF-driven drips) | A11 |
| LG-06 | **Low** | Low | — | not in verification set | — | Explorer/pool-site RPC path: plaintext upstream via a third-party wildcard DNS, and the archival node's full unauthenticated RPC (write methods includ… | A11 |
| LG-07 | **Low** | Low | NEW | not in verification set | — | Reference indexer: unbounded responses and whole-state rewrite | A11 |
| LG-08 | **Low** | Low | NEW | not in verification set | — | Python SDK amount parsing accepts non-ASCII digits and has an uncaught-exception path | A11 |
| NET-06 | **Low** | Medium | NEW | CONFIRMED | no | libp2p sync codec buffers up to 8 MiB per inbound *request* substream for a 13-byte message | A6 |
| NET-07 | **Low** | Medium | NEW | CONFIRMED | no | libp2p sync steering: `peer_head` is set from the unvalidated header slot before the engine judges, and the top-`SYNC_FANOUT` claimants are always chosen | A6 |
| NET-08 | **Low** | Medium | NEW | CONFIRMED | no | libp2p: identify-advertised addresses overwrite the `dialed` map, letting a connected peer suppress redials to honest configured peers (eclipse assist) | A6 |
| NET-13 | **Low** | Low | KNOWN | not in verification set | — | libp2p `with_peer_score` failure is warn-not-fatal; a scoring-less node is a flood amplifier | A6 |
| NET-14 | **Low** | Low | NEW | not in verification set | — | Devnet sync slots are sticky for the connection lifetime; a silent slot-holder throttles catch-up | A6 |
| NET-15 | **Low** | Low | NEW | not in verification set | — | The engine's sync pump broadcasts `get-blocks` to every devnet peer; each answers a 512-block page | A6 |
| NET-16 | **Low** | Low | NEW | not in verification set | — | Metrics server has no whole-request deadline (per-read timeout renews) | A6 |
| NET-17 | **Low** | Low | NEW | not in verification set | — | Devnet page has a block-count cap but no byte cap (unlike libp2p) | A6 |
| NET-19 | **Low** | Low | NEW | not in verification set | — | libp2p identity file is written non-atomically with the default umask before `chmod 0600`, and the chmod result is ignored | A6 |
| NET-20 | **Low** | Low | KNOWN | not in verification set | — | Frame-cliff vs consensus caps on the production transport | A6 |
| SR-01 | **Low** | Medium | NEW | CONFIRMED | yes | Genesis cohort is bound by neither the state root nor the genesis block id (only by the 32-bit `network_id`) | A4 |
| SR-04 | **Low** | Low | NEW | not in verification set | — | `ws-verify` diverges from the booting node: it omits the `arrangement_window` lower bound and carries stale duplicate-key text | A4 |
| SR-05 | **Low** | Low | NEW | not in verification set | — | A checkpoint's `state_root` / `validator_set_root` are never validated against the block they name, on either side | A4 |
| SR-06 | **Low** | Low | NEW | not in verification set | — | `single_derivation_path` has scan blind spots (currently clean) | A4 |
| SR-07 | **Low** | Low | KNOWN | not in verification set | — | `ws::verify_envelope` alone accepts a zero-threshold arrangement and does not compare signer keys; the crate relies on the node decoder for both | A4 |
| SR-08 | **Low** | Low | NEW | not in verification set | — | `codec::decode_envelope` pre-allocates from untrusted counts and hard-codes the attestation cap | A4 |
| SR-09 | **Low** | Low | NEW | not in verification set | — | ADR-041 leaves (`0x1B`–`0x1E`) have no root-binding test, and the spec registry stops at `0x16` | A4 |
| ST-06 | **Low** | Low | NEW | not in verification set | — | `close_epoch` mints delegator issuance shares into the ledger without advancing `issued_sat`; the supply-conservation rule would then refuse every bou… | A3 |
| ST-07 | **Low** | Low | KNOWN | not in verification set | — | Attestation and proposal signing roots carry no network/genesis binding, so a validator key reused on another network (devnet, a fork with the same sl… | A3 |
| ST-08 | **Low** | Low | NEW | not in verification set | — | Cohort-cap `Deferred` threshold is a cliff: one 5% slash, an exit, or a leak-independent effective-stake dip of the sole independent validator below 2… | A3 |
| ST-09 | **Low** | Low | NEW | not in verification set | — | Mempool and consensus derive the funded-deposit stake cap from different totals (unleaked vs leak-applied roster) | A3 |
| TX-03 | **Low** | Low | NEW | not in verification set | — | Single-input transfers are cross-format malleable: a relay can re-encode V1↔V2 producing a distinct, valid `canonical_bytes` with the same `txid` | A1 |
| TX-04 | **Low** | Low | NEW | not in verification set | — | `network_binding()` is a compile-time label, not a genesis-derived value, so the (inert) sighash binding does not actually separate networks built fro… | A1 |
| TX-05 | **Low** | Low | NEW | not in verification set | — | Mempool and consensus compute the funded-deposit cap from different `total_active` values (leak-applied vs unleaked) | A1 |
| TX-09 | **Low** | Medium | KNOWN | CONFIRMED | yes | Issuance accounting below `REWARDS_V2`: delegators receive zero issuance, leak does not reduce income, credit is one unscoped bit, withheld proposals … | A1 |
| TX-10 | **Low** | Low | KNOWN | not in verification set | — | Staking-class transactions are unmetered (0 gas, 0 bytes) and there is no consensus transaction-count cap | A1 |
| TX-13 | **Low** | Low | KNOWN | not in verification set | — | `MAX_EPOCH_ADVANCE = 4096` is a hard liveness ceiling: a network-wide stall longer than ~45.5 days can only be resumed by a hard fork | A1 |
| TX-14 | **Low** | Low | KNOWN | not in verification set | — | Genesis bonded 1,600,000 BLOCH outside `issued_sat`; the conservation invariant is a one-sided delta that can never see it, and burns are uncounted | A1 |
| TX-15 | **Low** | Low | KNOWN | not in verification set | — | Duplicate `(validator, signing_root)` attestations cost one hybrid verify each and are accepted (idempotent) | A1 |
| TX-16 | **Low** | Low | NEW | not in verification set | — | Body decode, re-encode and Merkle hashing (steps 3b) run before the proposer signature (step 7); an unauthenticated peer can force ~8 MiB of hashing p… | A1 |
| BV-16 | **Info** | Info | KNOWN | not in verification set | — | Chameleon: no chameleon hash / trapdoor exists; the actual "forgery capability" belongs to whoever supplies `TrustedBurnCheckpoint`, and it is total (… | A9 |
| BV-17 | **Info** | Info | NEW | not in verification set | — | `hybrid_wbtc_validator` (the "Custody 2-of-2" anchor guard) is never executed in a test, and it cannot run on the PQ-only Ustav kernel the anchor is s… | A9 |
| BV-18 | **Info** | Info | NEW | not in verification set | — | Documentation overclaims relative to the code (collected) | A9 |
| BV-19 | **Info** | Info | KNOWN | not in verification set | — | Minor robustness items in `bloch-btc-wallet` / `bloch-pq-vault` derivation | A9 |
| BV-20 | **Info** | Info | NEW | not in verification set | — | `guard_no_secrets` inspects key names only; a secret placed in a free-form value passes and is echoed back; `deny_unknown_fields` is ineffective on th… | A9 |
| BV-21 | **Info** | Info | KNOWN | not in verification set | — | `anchoring/` convention: first-`BLA1`-output heuristic, no signer binding, non-consensus tx codec | A9 |
| CR-09 | **Info** | Info | NEW | not in verification set | — | Fork provenance documentation is inaccurate: README/NOTICE/VENDOR.toml claim only `src/lib.rs` changed and `build.rs` is identical to upstream; `build… | A8 |
| CR-10 | **Info** | Info | KNOWN | not in verification set | — | Legacy raw-signature magic ambiguity (1/65536) remains for signatures | A8 |
| CR-11 | **Info** | Info | KNOWN | not in verification set | — | No standards-traceable KATs for ML-DSA-65 / Falcon-1024; seeded golden vectors pin the *crate*, not the *standard* | A8 |
| CR-12 | **Info** | Info | NEW | not in verification set | — | Genesis-3 PoW crate: `asert_next_bits` underflows on `new_height < anchor_height`; `bits_to_target` maps invalid compact bits to `Target::MIN` | A8 |
| EN-20 | **Info** | Info | NEW | not in verification set | — | Two implementations of the boot identity rule; the tested one has no production caller | A5 |
| EN-21 | **Info** | Info | — | not in verification set | — | `genesis_validator_count` assumes dense manifest indices | A5 |
| EN-22 | **Info** | Info | KNOWN | not in verification set | — | Env/flag-driven node-local safety behaviour (summary; see §3) | A5 |
| EN-23 | **Info** | Info | KNOWN | not in verification set | — | Per-ingest cost and memory grow with chain age; replay is quadratic | A5 |
| EN-24 | **Info** | Info | — | not in verification set | — | Serving `get_blocks` is rate-limited per connection, not per peer/IP | A5 |
| FC-13 | **Info** | Info | — | not in verification set | — | Arithmetic/panic notes (Info) | A2 |
| FC-14 | **Info** | Info | — | not in verification set | — | Documentation / spec divergences (Info) | A2 |
| INF-05 | **Info** | Medium | NEW | REFUTED | no | `deny.toml` duplicate allowlist no longer matches `Cargo.lock`; the blocking `supply-chain` gate is very likely red — MEDIUM — NEW | A10 |
| INF-21 | **Info** | Info | NEW | not in verification set | — | A checked-in agent workflow with a stale, founder-specific context — INFO — NEW | A10 |
| INF-22 | **Info** | Info | NEW | not in verification set | — | Documentation rot that would mislead an operator — INFO — NEW | A10 |
| KS-13 | **Info** | Info | NEW | not in verification set | — | Stale documentation: `KEYSTORE-AT-REST.md` says "No re-seal tool" and "Option A is the only one an operator can actually execute" | A7 |
| KS-14 | **Info** | Info | NEW | not in verification set | — | Ceremony script exports the passphrase into the environment of 64 child processes | A7 |
| KS-15 | **Info** | Info | NEW | not in verification set | — | `scripts/ws-ceremony-drill.sh` leaves throwaway signer `.sk` files in its work dir | A7 |
| KS-16 | **Info** | Info | NEW | not in verification set | — | WS boot refusal + `Restart=on-failure` is a replay-every-5-seconds crash loop | A7 |
| KS-17 | **Info** | Info | NEW | not in verification set | — | `--allow-plaintext-keystore` is matched anywhere in argv | A7 |
| KS-18 | **Info** | Info | KNOWN | not in verification set | — | Doppelganger protection is in-memory, window-bounded and flag-bypassable | A7 |
| LG-09 | **Info** | Info | NEW | not in verification set | — | Pool: shares and ledger keyed by the raw `mining.authorize` username, not the parsed address | A11 |
| LG-10 | **Info** | Info | NEW | not in verification set | — | Documentation drift on the ledger-critical code (dust recipient, snapshot vintage, zero-value rows, dead "tip height" print) | A11 |
| LG-11 | **Info** | Info | — | not in verification set | — | Pool/pool-proxy: advisor findings verified closed; residual notes for a redeploy | A11 |
| LG-12 | **Info** | Info | — | not in verification set | — | euvm / ffg reachability from the live node | A11 |
| LG-13 | **Info** | Info | — | not in verification set | — | coherence-prover / SP1, spikes, fuzz | A11 |
| NET-21 | **Info** | Info | — | not in verification set | — | Information exposure by design (Info) | A6 |
| NET-22 | **Info** | Info | — | not in verification set | — | Minor code-level notes (Info) | A6 |
| SR-10 | **Info** | Info | NEW | not in verification set | — | `state_root.rs` doc claims "no global mutable state" while holding a thread-local two-generation memo (consensus-safe, doc false) | A4 |
| SR-11 | **Info** | Info | NEW | not in verification set | — | Domain-tag hygiene: several tags cover two or three preimage shapes, docs are stale, and three tags live outside the registry | A4 |
| SR-12 | **Info** | Info | KNOWN | not in verification set | — | The weak-subjectivity window's slashability premise is void while slashing, exits and withdrawals are unarmed | A4 |
| SR-13 | **Info** | Info | KNOWN | not in verification set | — | Same-epoch re-mint is a permanent boot refusal for every node that stored the first artifact | A4 |
| ST-10 | **Info** | Info | NEW | not in verification set | — | Stale/contradictory comments on the slashing path | A3 |
| ST-11 | **Info** | Info | NEW | not in verification set | — | `genesis_principal_sat` and `admission_network_domain` are uncommitted, manifest-derived consensus inputs; the domain is `SHA3(manifest.encode())`, so… | A3 |
| ST-12 | **Info** | Info | NEW | not in verification set | — | Arming L also switches on gas/byte metering for ExitV2, RandaoRecommit and SlashingEvidence (`staking_tx_charge` reads `\|\| withdrawal_active`), whic… | A3 |
| ST-13 | **Info** | Info | KNOWN | not in verification set | — | Activation queue: intra-epoch order is grindable by `pubkey_hash` and the queue is unbounded (economically bounded by 25,000 BLCH per entry locked ≥ 2… | A3 |
| ST-14 | **Info** | Info | NEW | not in verification set | — | Mutation guard (`scripts/check-validator-lifecycle-mutations.py`) matches the code and each of its eight mutations is killed by `transition::tests::va… | A3 |
| ST-15 | **Info** | Info | — | not in verification set | — | Whistleblower is always the *including proposer*; the observer who gossips evidence earns nothing, and evidence is trivially front-run | A3 |
| ST-16 | **Info** | Info | — | not in verification set | — | A queued funded validator whose deposit epoch is never finalized has no exit: `ExitV2` requires `activation_epoch <= epoch`, `Withdraw` requires an ex… | A3 |
| TX-17 | **Info** | Info | NEW | not in verification set | — | `FundedDeposit::decode` enforces consensus rules (`validate_shape`) inside the decoder, contrary to the stated decode/judge split | A1 |
| TX-18 | **Info** | Info | NEW | not in verification set | — | `Delegate.eligible` is a wire-supplied bit that consensus records verbatim | A1 |
| TX-19 | **Info** | Info | NEW | not in verification set | — | Spec/code drift in `BLOCH-L1-FEE-MARKET.md` and `BLOCH-TOKENOMICS-V4.md` | A1 |
| TX-20 | **Info** | Info | KNOWN (refined) | not in verification set | — | `interfaces.rs` `StateRoots` (14 fields, "closed again at eight components") vs `state_root.rs` (~25 tags) and the frozen `StateTransition::apply_bloc… | A1 |
| TX-21 | **Info** | Info | KNOWN | not in verification set | — | Two block-validation stacks (`derive::validate_block` vs `transition`) still coexist | A1 |
| TX-22 | **Info** | Info | NEW | not in verification set | — | `CommittedState::genesis` silently overwrites duplicate validator indices / pubkeys from the manifest | A1 |
| NET-18 | **Low/Info** | Low/Info | NEW | not in verification set | — | Deploy/config drift: NixOS PoS module defaults to `--transport libp2p`, which does not interoperate with the live fleet; its comment about the binary'… | A6 |
| TX-07 | **Low–Medium** | Low–Medium | KNOWN | not in verification set | — | Declared `tx_bytes` may exceed the encoding by any amount; one small transfer can fill the block byte budget | A1 |
