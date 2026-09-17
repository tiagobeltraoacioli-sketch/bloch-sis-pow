# A8 — Crypto layer audit (bloch-crypto, pqcrypto-internals fork, coherence-core, bloch-sis-pow)

Auditor: A8 (crypto). Repository: `/home/user/bloch-sis-pow` @ `562e220`. Date: 2026-09-16. Read-only; no repository file was modified.

---

## 1. Scope & method

**In scope, read in full (non-test and test code):**

- `crates/bloch-crypto/src/{lib.rs, crypto/mod.rs, address.rs, util.rs, types/*.rs, wallet/{mod,encryption,seed,disclosure,client,cli,errors}.rs, hd_wallet/mod.rs, bin/postern-wallet.rs}`; `core/mod.rs` transaction/sighash/script_sig/txid/varint sections and the cast inventory of `core/{mod,auxpow,tokenomics_v2}.rs`; `tests/tx_under_dual_and.rs`.
- `crates/pqcrypto-internals/{src/lib.rs, build.rs, Cargo.toml, VENDOR.toml, README.md, NOTICE, tests/vendor_pin.rs}` and every file under `cfiles/` and `include/`.
- `crates/coherence-core/src/lib.rs`.
- `crates/bloch-sis-pow/src/*` (lib, params, field, shake, expand, matrix, encode, difficulty, error, solver, verify).
- Workspace-wide grep for every `with_seeded_rng` / `randombytes_fill` / `SEEDED_RNG_STACK` / `PQCRYPTO_RUST_randombytes` / `generate_keypair_from_seed` / `diversified_keypair` / `from_seed` call site (incl. `bloch-pos-node/src/keys.rs`, `tools/genesis4-ceremony`, `bloch-pq-vault`, `bloch-btc-wallet`, `bloch-ustav`, `legacy/genesis3-node`).
- Live-chain consumers of `bloch_crypto::crypto::{verify, verify_mldsa65_raw, falcon::verify}` in `bloch-pos-committee` (`staking.rs`, `ws.rs`, `derive.rs`, `gossip.rs`, `slashing.rs`, `interfaces.rs`) and `bloch-pos-node` (`engine.rs`, `keys.rs`, `ws_boot.rs`, `p2p.rs`, `genesis.rs`) — read only far enough to determine the impact of crypto-layer findings.
- Prior docs read for KNOWN/NEW labelling: `docs/audit/AUDIT-2026-04-20_ERA1.md`, `docs/audit/groundstate_audit.md`, `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`, `docs/adr/ADR-020-pq-hybridization-roadmap.md`, `docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md`, `docs/specs/BLOCH-GENESIS-KEYS.md`, `docs/specs/COHERENCE-C1.md`, `COHERENCE-C1.1.md`, `BLOCH-COHERENCE-UNDER-POS.md`, `SECURITY.md`, `scripts/falcon-clean-guard.sh`, CI (`.gitlab-ci.yml`, `.github/workflows/tests.yml`).

**Upstream diffing: possible (network access worked).** Downloaded from crates.io into the scratchpad: `pqcrypto-internals-0.2.11`, `pqcrypto-falcon-0.4.1`, `pqcrypto-mldsa-0.1.2`, `pqcrypto-traits-0.3.5`.

- `diff -r` of vendored `cfiles/` and `include/` against upstream `pqcrypto-internals-0.2.11`: **byte-for-byte identical (23 files)**. All 23 SHA-256 pins in `VENDOR.toml` recomputed and match; no unpinned file on disk.
- `src/lib.rs`: modified as documented (seeded-RNG stack, fail-closed abort). `build.rs`: **modified** (wasm32/wasi openbsd-libc handling, lines 33–48) — contrary to README/NOTICE/VENDOR.toml claims (see CR-09). `Cargo.toml`: modified (adds `rand_chacha`, `rand_core`, `getrandom_wasm_js` feature, wasm dep, dev-deps).
- An empirical C harness was compiled in the scratchpad from the exact PQClean `falcon-1024/clean` sources that `pqcrypto-falcon 0.4.1` vendors (`scratchpad/upstream/harness/`) to confirm CR-02. Nothing in the repository was built or executed.

Method: line-by-line reading as cryptographer + attacker (hybrid combiner, encodings/canonicality, key substitution, domain separation, RNG scoping, KDF/AEAD, seed derivation, untrusted decoding), then confirmation of every claim in code or by experiment. Where a code comment claims a prior fix, the fix was verified in code.

---

## 2. Findings (ordered by severity)

### CR-01 — `coherence_core::check_spend` has no spend authorization: `nk` is prover-chosen, so any note plaintext holder (incl. the sender) can spend, and one note yields unlimited distinct nullifiers

- **Severity:** High (precondition: activation of the Coherence shielded pool with this statement; NOT reachable on the live Genesis-4 chain today).
- **Status:** NEW as a code-level finding. Partially KNOWN at spec level: `docs/specs/COHERENCE-C1.md:72-73` states "nk derives from the note's spending key (spend authority)" and `:129` lists "exact pk_d/nk derivation" as open; no prior doc records that the shipped statement enforces no authorization at all, nor the variable-nk double-spend consequence.
- **Files:** `crates/coherence-core/src/lib.rs:50-52` (`Note::nullifier`), `:380-385` (`SpendInput { note, position, path, nk }`), `:412-460` (`check_spend`, nullifier check at `:443-446`); consumer `crates/coherence-prover/program` (out of scope, not read).
- **Description:** `check_spend` verifies (a) `cm(note)` is in the tree at `position`, (b) `public.nullifiers[i] == SHAKE(DOM_NF ‖ nk ‖ rho ‖ position)` for the witness-supplied `nk`, (c) output commitments, (d) value balance. Nothing ties `nk` to `note.pk_d` (or to any secret the recipient alone holds). There is no spend-authorization key, no proof-of-knowledge of a spending key, and `nk` is a free 32-byte witness input.
- **Attack scenario:** (1) *Sender theft:* the creator of a note knows `(v, pk_d, rho, psi)` because they computed `cm`; after the note is in the tree they can produce a valid spend with any `nk` and take the value. (2) *Unbounded double-spend / inflation:* anyone holding a note's plaintext (sender or receiver) spends it repeatedly with `nk_1, nk_2, …`; each spend yields a fresh nullifier that is not in the set, so every spend is accepted. (3) The nullifier-set SMT (C1.1) cannot help — it only detects reuse of the *same* nullifier.
- **Evidence:**
  ```rust
  // lib.rs:443-446
  let nf = inp.note.nullifier(&inp.nk, inp.position);
  if public.nullifiers.get(i) != Some(&nf) { return Err(SpendError::Nullifier(i)); }
  ```
  Test `check_spend_accepts_valid_and_rejects_inflation_and_forgery` (`:514-549`) uses `let nk = [3u8; 32]` unrelated to `pk_d`; no negative test for a "wrong" `nk` exists because none is possible.
- **Live-chain reachability (verified):** `bloch-pos-committee/src/transition.rs:5507-5508` only requires `header.coherence_root == pre.coherence_root()` (roots frozen from genesis); no `PosTransaction` variant carries a shielded spend; `coherence-core` is not referenced by the committee crate's Cargo.toml. So this cannot be exploited on the live chain, but it is the "exact statement the ZK circuit proves" for the gated P1 track.
- **Recommendation:** Define the key hierarchy before any activation: `nk = PRF(spending key)`, `pk_d = F(ivk(spending key), diversifier)`; make `check_spend` take the spending secret as witness and re-derive both `nk` and `pk_d` from it (Sapling/Orchard pattern), and add a spend-authorization signature or in-circuit proof binding the public inputs. Add negative tests: wrong `nk` → reject; two spends of the same note → same nullifier. Record this as an explicit blocker in COHERENCE-C1/C4 gating docs.
- **Confidence:** High (direct code reading; no ambiguity).

### CR-02 — Hybrid signatures are third-party malleable (SUF-CMA broken): PQClean's non-padded `falcon-1024` verifier accepts the 1280-byte zero-padded encoding; the suite-envelope legacy fallback accepts header-stripped signatures; concatenation allows half mix-and-match

- **Severity:** Medium (consensus-neutral on the live chain as far as verified, but it silently invalidates the "signature bytes are unique" assumption, gives 2× gossip amplification, and the crate's own negative test provides false assurance).
- **Status:** NEW. No prior doc mentions Falcon padded-encoding acceptance or envelope-strip malleability. (The committee code does assume signatures are *non-unique* — `interfaces.rs:742`, `schedule.rs:34`, `slashing.rs:211-214` — but only because signing is randomized, i.e. signer-controlled; third-party malleability is a different threat.)
- **Files:** `crates/bloch-crypto/src/crypto/mod.rs:210-215` (`parse_envelope_or_legacy`), `:254` (used for signatures in `verify`), `:272-294` (`verify_hybrid_mldsa_falcon`), `:522-530` (`falcon::verify`), `:949-952` (misleading test); upstream `pqcrypto-falcon-0.4.1/pqclean/crypto_sign/falcon-1024/clean/pqclean.c:249-263` (`do_verify`), `codec.c:398-468` (`comp_decode`).
- **Description:** Three independent channels:
  1. **Falcon padded encoding.** PQClean `do_verify` decodes the compressed value with `comp_decode`; if fewer bytes were consumed than supplied, it *accepts* the signature when the value length is exactly `1280 − 40 − 1 = 1239` and the trailing bytes are zero (cross-compat with `falcon-padded-1024`). Bloch's hybrid split gives Falcon "the remainder", and `falcon1024::DetachedSignature::from_bytes` accepts any length ≤ 1462. Hence for every hybrid signature `hdr ‖ mldsa(3309) ‖ falcon(L)` with `L ≤ 1280` (always in practice: observed L = 1269…1275), `hdr ‖ mldsa ‖ falcon ‖ 0^(1280−L)` also verifies.
  2. **Envelope strip.** `parse_envelope_or_legacy` treats any signature without the `B1 0C` magic as legacy suite 0x0001. Removing the 4-byte header from an enveloped 0x0001 signature yields a raw body that verifies for the same (enveloped or legacy) pubkey; conversely a raw signature can be wrapped. `parse_pubkey_envelope_or_legacy` fixed this for pubkeys (A4 lows) by exact length; signatures are variable-length so the magic heuristic remains.
  3. **Mix-and-match.** Both halves sign the same 32-byte digest with no cross-binding; given two honest hybrid signatures `(m1‖f1)`, `(m2‖f2)` on the same message under the same key, `(m1‖f2)` and `(m2‖f1)` also verify.
  Combined: ≥ 4 valid encodings per signature without the secret key.
- **Attack scenario / impact (verified):** Genesis-3 `Transaction::txid` excludes `script_sig` (`core/mod.rs:1317-1331`) — no txid malleability. Genesis-4: attestation gossip dedups by `data.signing_root()` before the signature check (`gossip.rs:348-368`), slashing `id()` excludes signatures (`slashing.rs:215-224`), ws envelopes dedup by signer index. But the libp2p gossipsub message-id is `SHA3(payload)[..16]` (`p2p.rs:853-857`), so a relayer can re-broadcast every attestation/transfer as a distinct message (≥2×) that survives gossipsub dedup; `attestation_leaf` commits the signature bytes (`derive.rs:160-171`) so two blocks carrying the "same" attestation set can have different attestation roots; any future component that hashes or compares signature bytes (mempool dedup, wtxid-style ids, evidence caches, fee-by-size) inherits the class. `docs/integration/...-v2.md:951` acknowledges witness-inclusive ids are malleable, but attributes it to re-signing.
- **Evidence:** Harness compiled from the vendored PQClean sources (`scratchpad/upstream/harness/harness.c`):
  ```
  trial 0: siglen=1270 orig=1 padded1280=1 plus1=0
  trial 1: siglen=1273 orig=1 padded1280=1 plus1=0
  trial 2: siglen=1275 orig=1 padded1280=1 plus1=0
  trial 3: siglen=1274 orig=1 padded1280=1 plus1=0
  trial 4: siglen=1269 orig=1 padded1280=1 plus1=0
  SUMMARY trials=5 orig_ok=5 padded1280_ok=5 plus1_ok=0
  ```
  `pqclean.c:253-263`:
  ```c
  if (v != sigbuflen) {
      if (sigbuflen == PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES - NONCELEN - 1) {
          while (v < sigbuflen) { if (sigbuf[v++] != 0) return -1; }
      } else { return -1; }
  }
  ```
  `crypto/mod.rs:949-952` asserts only `sig ‖ 0x00` (one byte, not the padded length) fails — which is exactly the case the C code rejects, so the test passes while the padded case is accepted. `crypto/mod.rs:210-215`:
  ```rust
  fn parse_envelope_or_legacy(b: &[u8]) -> (u16, &[u8]) {
      match parse_envelope(b) { Some(x) => x, None => (SUITE_MLDSA65_FALCON1024, b) }
  }
  ```
- **Recommendation:** (a) In `falcon::verify`, enforce canonical compressed encoding. A complete and cheap check: a canonical Falcon compressed value always ends in a byte containing the last coefficient's unary terminator bit, so it is never `0x00`; reject `signature_bytes.last() == Some(&0x00)` (or reject `len == 1280 && trailing zero`). (b) Bind the Falcon half to the ML-DSA half (e.g. sign `H(domain ‖ msg ‖ mldsa_sig)` with Falcon, or include both signatures' hashes in a wrapper commitment) to close mix-and-match. (c) Restrict legacy raw-signature acceptance to legacy raw pubkeys (exact-length classified) and/or to a height window; enveloped pubkeys should require enveloped signatures. All three are consensus tightenings for Transfer/attestation validity on Genesis-4: gate behind an activation and first scan history for any padded/raw encodings already included. (d) Fix the misleading test to pad to exactly 1280 and add tests for (2) and (3).
- **Confidence:** High for (1) (empirical) and (2)/(3) (code reading); Medium for the completeness of the live-chain impact survey (committee/node crates were read only where signature bytes are consumed).

### CR-03 — `SUITE_MLDSA65_ONLY` (0x0002) is accepted by the live Genesis-4 transfer verifier with no activation gate, contradicting the "hybrid on every consensus path" claim

- **Severity:** Medium (defense-in-depth: the hybrid guarantee is silently opt-out per output; retro-fitting a gate is a flag-day once any 0x0002 output exists).
- **Status:** NEW. The code itself says gating is "future work" (`crypto/mod.rs:296-299`); SECURITY.md:15-16 and the CertiK dossier §2 claim hybrid signatures on every consensus path.
- **Files:** `crates/bloch-crypto/src/crypto/mod.rs:248-264` (`verify` dispatch), `:300-313`; `crates/bloch-pos-node/src/engine.rs:5681-5686` (mempool door uses `bloch_crypto::crypto::verify` on user-supplied `i.pubkey`); `crates/bloch-pos-node/src/keys.rs:1141` (`HybridVerifier::verify_with_key` → same `crypto::verify`, used by the transition for Transfer spends); contrast `bloch-pos-committee/src/staking.rs:356,387` (validator deposits DO require 0x0001 + `HYBRID_PK_BYTES`).
- **Description:** Transfer outputs commit to `script_hash = H(pubkey)` where the pubkey carries its suite; a spender presenting a 0x0002 pubkey and a 0x0002 (ML-DSA-only) signature passes both the mempool check and the transition's injected verifier. Validator keys are correctly gated, but user funds are not.
- **Attack scenario:** No third-party downgrade of someone else's key is possible (addresses commit to the suite). Harm requires an ML-DSA-65 break *and* a 0x0002 output: those funds are then forgeable while hybrid outputs are not. Practically: a wallet bug or a malicious wallet can issue single-scheme addresses that users believe are hybrid; and any later decision to require hybrid becomes a hard fork for existing 0x0002 outputs.
- **Recommendation:** Make `verify` reject 0x0002 unless `height ≥ SUITE_0002_ACTIVATION` (`u64::MAX` today), threaded from the caller like `ChainId`; or restrict the live transfer path to `SUITE_MLDSA65_FALCON1024` explicitly (as `deposit_shape` does). Document the decision in SECURITY.md.
- **Confidence:** High.

### CR-04 — Seed-derived keys are reused across contexts: `bloch-btc-wallet` default identity and `bloch-pq-vault` V1 derive the PQ key from the raw BIP39 seed, which is the same ChaCha20 seed `Wallet::from_seed` uses → same hybrid keypair (same address) as the Bloch wallet base key

- **Severity:** Low.
- **Status:** KNOWN (A4-M-5 / I-13; `derive_vault_keys_v2` and `PqSeedKdf::V2DomainSeparated` exist), but the *default* entry points still select V1 raw-seed reuse.
- **Files:** `crates/bloch-crypto/src/crypto/mod.rs:108-134` (raw `seed[..32]` → ChaCha20 key, no domain tag), `wallet/mod.rs:144` (`seed_bytes[..32]`), `crates/bloch-btc-wallet/src/lib.rs:17-18` (`derive_identity` → `PqSeedKdf::V1RawSeedReuse`), `crates/bloch-pq-vault/src/lib.rs:151` (`derive_vault_keys` V1 → `generate_keypair_from_seed(seed)`).
- **Description:** Only `diversified_seed` (`crypto/mod.rs:358-364`) domain-separates. The base keypair is `KeyGen(ChaCha20(seed[..32]))` with no context tag, so any component that feeds the same 32 bytes derives the same signing key, and the same key ends up as a BTC-vault PQ clawback key, a "quantum-ready identity", and the Bloch spending key.
- **Recommendation:** Make V2 the default in both crates; consider a `generate_keypair_from_seed_tagged(seed, purpose)` API and deprecate the untagged one.
- **Confidence:** High.

### CR-05 — Address checksum does not bind the network; `Wallet::build_tx` accepts a recipient `Address` of the other network

- **Severity:** Low.
- **Status:** NEW.
- **Files:** `crates/bloch-crypto/src/address.rs:65-98,130-139` (checksum = `SHA3d(hash)[..4]`, prefix outside the checksum), `crates/bloch-crypto/src/wallet/mod.rs:312-362` (`build_tx` never compares `recipient.network()` with `self.network`).
- **Description:** `bloch1q<payload>` and `bloch1t<payload>` share a valid checksum for the same 20-byte hash; a testnet address pasted into a mainnet wallet parses fine and `build_tx` pays that hash on mainnet. Funds are not burned (same key controls the hash on both networks) but the user did not intend a mainnet payment to a testnet identity, and cross-network address reuse links identities.
- **Recommendation:** Fold the network byte into the checksum preimage in the next address version; meanwhile reject `recipient.network() != self.network` in `build_tx`/`TxBuilder::build` and in the CLI.
- **Confidence:** High.

### CR-06 — Index-0 convention mismatch between `wallet::disclosure::keypair_at` and `hd_wallet::derive_at`

- **Severity:** Low (interoperability/correctness; a disclosure for an HD wallet's address 0 cannot be produced).
- **Status:** NEW.
- **Files:** `crates/bloch-crypto/src/wallet/disclosure.rs:165-173` (`index 0 → generate_keypair_from_seed(seed[..32])`, `N>0 → diversified_keypair`), `crates/bloch-crypto/src/hd_wallet/mod.rs:334-339` (`index i → diversified_keypair(seed, i)` for all i, including 0).
- **Recommendation:** Pick one convention (HD: all indices diversified) and make `keypair_at` delegate to it, with a version field in the bundle.
- **Confidence:** High.

### CR-07 — Wallet-library robustness nits (panics / zeroization gaps on untrusted or edge inputs)

- **Severity:** Low.
- **Status:** NEW (individual items); prior "A4 lows" covered nonce-length panics and KDF bounds, which are fixed and verified.
- **Files / items:**
  - `wallet/mod.rs:320` — `InsufficientFunds { needed: amount + fee }` evaluated before the `checked_add` at `:324`; with `overflow-checks = true` this panics on `amount + fee > u64::MAX`.
  - `wallet/mod.rs:830` — `selected_total += utxo.2.value` unchecked over RPC-supplied values (panic on overflow).
  - `wallet/mod.rs:844` — `prev_txid.copy_from_slice(&txid[..32.min(txid.len())])` panics when a caller passes a txid shorter than 32 bytes (length mismatch).
  - `wallet/encryption.rs:189-205, 369-387` — AES key `[u8; 32]` zeroized manually only on the success path (early `?` at `:201-202`/`:384-385` skips it); use `Zeroizing`.
  - `wallet/encryption.rs:237-327` — v1 `decrypt` returns the secret as a plain `Vec<u8>` (v2 uses `Zeroizing`).
  - `wallet/cli.rs:190-191` — amounts parsed as `f64` then `(x * 1e8).round() as u64` (float rounding; negative saturates to 0).
  - `hd_wallet/mod.rs:169,180` — `max + 1` on `u32` indices unchecked (theoretical).
- **Recommendation:** Checked arithmetic, `Zeroizing<[u8;32]>` for KDF outputs, length checks before `copy_from_slice`, integer amount parsing.
- **Confidence:** High.

### CR-08 — `SeededRngGuard` design hazards: a forgotten guard seeds the thread forever; ChaCha state is not zeroized; `Drop` touches TLS unconditionally

- **Severity:** Low (no reachable misuse found; the only production guard is a local in `generate_keypair_from_seed`).
- **Status:** NEW (I-2 nesting and K-H1 fail-closed are KNOWN and verified fixed).
- **Files:** `crates/pqcrypto-internals/src/lib.rs:100-118` (guard/Drop), `:162-169` (`with_seeded_rng`), `:178-201` (`randombytes_fill`).
- **Description:** (a) `mem::forget(guard)` (or storing a guard in a long-lived structure) leaves the thread's `randombytes()` deterministic for its lifetime, including for **signing** (Falcon salt + sampler seed, ML-DSA `rnd`); nothing detects or logs this. (b) The `ChaCha20Rng` inside `SeededEntry` (keyed by the wallet seed) is dropped without zeroization. (c) `Drop` calls `SEEDED_RNG_STACK.with`, which panics if the TLS slot is already destroyed (guard stored in another thread-local dropped later). (d) `randombytes_fill` is `pub`, so any crate can draw from an active seeded stream.
- **Recommendation:** Wrap the RNG in `Zeroizing`/implement `Drop` that overwrites; add a debug-assert/log in `PQCRYPTO_RUST_randombytes` when a seeded stream serves a request of exactly 40 or 32 bytes outside keygen (heuristic), or better expose `keypair_from_seed` that takes the guard internally and never leaks it (the upstream reconciliation plan); use `try_with` in `Drop`.
- **Confidence:** High on the mechanics; Low on exploitability (none found).

### CR-09 — Fork provenance documentation is inaccurate: README/NOTICE/VENDOR.toml claim only `src/lib.rs` changed and `build.rs` is identical to upstream; `build.rs` and `Cargo.toml` differ, and the hash pin does not cover `build.rs`

- **Severity:** Info.
- **Status:** NEW (G3 pin mechanism itself is KNOWN and works).
- **Files:** `crates/pqcrypto-internals/README.md` ("What changes: Only src/lib.rs … build.rs … identical to upstream 0.2.11"), `NOTICE` (same claim), `VENDOR.toml:3-6`, `build.rs:33-48` (added wasi/openbsd-libc logic, `cargo::rustc-link-lib`), `Cargo.toml` (new deps/features).
- **Description:** Verified by diff against the crates.io tarball. `build.rs` controls compiler flags and which C files are compiled; it is exactly the kind of file a supply-chain edit would target, and it is outside the tripwire.
- **Recommendation:** Pin `build.rs` (and `Cargo.toml`) in `VENDOR.toml`; correct the three documents; record the upstream tarball SHA-256 (`pqcrypto-internals-0.2.11.crate`) so the pin becomes a provenance statement rather than a self-consistency check. CI already runs `cargo test -p pqcrypto-internals` (`.gitlab-ci.yml:652`, `.github/workflows/tests.yml:92`), so the extended pin would be enforced.
- **Confidence:** High.

### CR-10 — Legacy raw-signature magic ambiguity (1/65536) remains for signatures

- **Severity:** Info (only affects raw, pre-envelope signatures, which no current signer emits — `Keypair::sign` always envelopes).
- **Status:** KNOWN in spirit (A4 lows fixed pubkeys; the test at `crypto/mod.rs:822-828` documents that the signature heuristic still misclassifies).
- **Files:** `crypto/mod.rs:210-215, 254`.
- **Description:** A raw hybrid signature whose ML-DSA bytes start with `B1 0C` is parsed as enveloped with a random suite → verify false. Historical Genesis-3 signatures on-chain are unaffected (already validated). Superseded by CR-02(2)'s recommendation.
- **Confidence:** High.

### CR-11 — No standards-traceable KATs for ML-DSA-65 / Falcon-1024; seeded golden vectors pin the *crate*, not the *standard*

- **Severity:** Info.
- **Status:** KNOWN (P0.3; `full_nist_kat_wiring_todo` is `#[ignore]`d at `crypto/mod.rs:1138-1149`).
- **Description:** `primitive_lengths_match_hybrid_split_offsets`, `upstream_built_hybrid_verifies_through_bloch`, golden seed→key hashes and the Falcon `clean` seeded KAT are all self-referential to `pqcrypto-*`. A silently wrong upstream (e.g. a pre-standard Dilithium build) would pass. Verified here by source inspection instead: pqcrypto-mldsa 0.1.2 vendors PQClean `ml-dsa-65` with FIPS 204 final semantics (K‖L in keygen seed expansion `sign.c:33-35`, `_ctx` API, hedged `rnd`, exact `siglen` check, canonical hint decoding).
- **Recommendation:** Vendor ACVP/NIST `.rsp` vectors and an AES-256-CTR DRBG shim in a test; or at least pin SHA-256 of a NIST-KAT-derived pk/sig pair produced once out-of-band.
- **Confidence:** High.

### CR-12 — Genesis-3 PoW crate: `asert_next_bits` underflows on `new_height < anchor_height`; `bits_to_target` maps invalid compact bits to `Target::MIN`

- **Severity:** Info (bloch-sis-pow is NOT on the Genesis-4 consensus path — verified: no reference from `bloch-pos-committee`, `bloch-pos-node` or `genesis4-ceremony`; bloch-crypto pulls it only for the legacy `Block::validate_pow`).
- **Status:** NEW (minor).
- **Files:** `crates/bloch-sis-pow/src/difficulty.rs:235` (`(new_height - anchor_height) as i64`, u64 subtraction), `:146-147`.
- **Confidence:** High.

---

## 3. `with_seeded_rng` / seeded-path call sites — scope analysis

Workspace-wide grep (excluding `target/`): 3 call sites in bloch-crypto, 2 in a legacy test file, none elsewhere. `randombytes_fill` and `SEEDED_RNG_STACK` are referenced only inside `pqcrypto-internals/src/lib.rs`. `PQCRYPTO_RUST_randombytes` is called only by the C side (`falcon-1024/clean/pqclean.c:60,177,192`; `ml-dsa-65/{clean,avx2}/sign.c` keygen + `rnd`).

| # | Site | Prod/Test | Guard lifetime | What runs inside the scope | Signing inside? | Nesting / thread hand-off / panic | Verdict |
|---|------|-----------|----------------|-----------------------------|-----------------|-----------------------------------|---------|
| 1 | `crates/bloch-crypto/src/crypto/mod.rs:124` `generate_keypair_from_seed` | **Prod** | Local `_guard`, dropped at function return (`:134`) | `mldsa65::keypair()` (consumes 32 B), `falcon::keypair()` (consumes 48 B) | No | No nesting; synchronous, no `.await`; guard is `!Send + !Sync`; a Rust panic in the wrappers unwinds and drops the guard; C never unwinds | OK |
| 1a | via `crypto::diversified_keypair` (`:367-371`) ← `hd_wallet::derive_at:335`, `disclosure::keypair_at:171` | Prod | same as #1 | same | No | same | OK |
| 1b | via `wallet::Wallet::from_seed_versioned:144`, `bloch-pq-vault/src/lib.rs:151,204`, `bloch-btc-wallet/src/lib.rs:178`, `disclosure::keypair_at:169` | Prod | same as #1 | same | No | same | OK (see CR-04 for seed reuse) |
| 1c | `bloch-pos-node/src/engine.rs:6532,6600,6890,7064,7287`; `bloch-ustav/tests/*`; `bloch-pq-vault/src/anchor.rs` tests | Test | same as #1 | same | Signing happens *after* the guard dropped (separate calls) | — | OK |
| 2 | `crypto/mod.rs:660` `falcon_clean_seeded_kat_is_byte_stable_and_verifies` | Test | Block scope `:659-664` | `falcon::keypair()` **and `falcon::sign()`** | **Yes (deliberate, regression pin only)** | Block-scoped; not nested | OK — test-only; clearly commented |
| 3 | `crypto/mod.rs:915` `golden_deterministic_mldsa_signature_half_is_byte_stable` | Test | `_guard` explicitly `drop`ped `:917` | `sign()` (hybrid; ML-DSA `rnd` and Falcon salt/seed drawn from the stream) | **Yes (deliberate)** | Not nested | OK — test-only |
| 4 | `legacy/genesis3-node/tests/kat_mldsa65.rs:89,112` | Test (retired chain) | block-scoped | keygen + deterministic sign | Yes (deliberate) | — | OK |
| — | Validator keys: `bloch-pos-node/src/keys.rs:395` `generate_keypair()` + `os_random` RANDAO seed | Prod | no guard | OS RNG | — | — | OK — not seed-derived |
| — | Genesis-4 ceremony `tools/genesis4-ceremony` | Prod | no guard; consumes public data only; `pseudo_bytes` is `#[cfg(test)]` | — | — | — | OK |

Other properties verified in the fork: LIFO stack with identity-based removal (I-2, tests `:553-628`); OS-RNG failure and NULL buffer abort the process instead of returning `-1` (K-H1, `:228-243, 282-303`); `len == 0` no-op; upstream behaviour byte-identical when the stack is empty (`getrandom::fill`). Hazards that remain are design-level (CR-08).

---

## 4. Exact PQ primitives in use

| Crate (Cargo.lock) | Source | Variant actually linked | Sizes (bytes) | Notes |
|---|---|---|---|---|
| `pqcrypto-mldsa` **0.1.2** (pinned `=0.1.2`) | crates.io, PQClean-backed | `ml-dsa-65`, **FIPS 204 final** (keygen `H(ξ‖K‖L)`, `*_ctx` API, hedged signing `randombytes(rnd,32)`). Default features **on** (`avx2`,`neon`,`std`) → runtime dispatch to `PQCLEAN_MLDSA65_AVX2_*` on x86_64 with AVX2, `clean` otherwise | pk 1952 / sk 4032 / sig 3309 (fixed) | Bloch calls `detached_sign` = pure ML-DSA with empty context. Verify checks `siglen == 3309`, canonical hints, `‖z‖ < γ1−β`. |
| `pqcrypto-falcon` **0.4.1** (pinned `=0.4.1`, `default-features=false`, `features=["std"]`) | crates.io, PQClean-backed | `falcon1024` = **non-padded** `falcon-1024/clean` (integer-emulated FP). No avx2/aarch64 objects compiled (verified in `build.rs` gating; guarded by `falcon_native_fp_variants_are_not_linked` + `scripts/falcon-clean-guard.sh`) | pk 1793 / sk 2305 / sig **variable ≤ 1462** (observed 1269–1275: `0x3A` ‖ 40-byte nonce ‖ compressed value) | Verifier also accepts the 1280-byte zero-padded form (CR-02). Signing randomized (40-byte salt + 48-byte sampler seed). |
| `pqcrypto-traits` 0.3.5 | crates.io | — | — | |
| `pqcrypto-internals` **0.2.11** | **vendored fork** (`[patch.crates-io]`) | C sources byte-identical to upstream; `lib.rs`/`build.rs`/`Cargo.toml` modified | — | OS RNG: `getrandom` 0.3.4; seeded: `rand_chacha` 0.9.0 `ChaCha20Rng` |
| Hybrid envelope (bloch-crypto) | — | `B1 0C ‖ suite u16 LE ‖ body`; suites 0x0001 (hybrid), 0x0002 (ML-DSA-only) | pk 3749 / sk 6341 / sig 4 + 3309 + (≤1462) ≤ 4775, typical ≈ 4584 | README's "~4.6 KB" is accurate for the typical case; `SIG_SIZE` = 4775 is the fee-sizing bound. |
| Hashes | `sha3` 0.10.9 (SHA3-256 addresses/sighash/keyfile AAD; SHAKE-256 coherence + PoW), `sha2` 0.10 (txid SHA-256d, BIP39 PBKDF2) | | | |
| Wallet at rest | `argon2` 0.5.3 Argon2id (256 MiB, t=4, p=4; bounded on load ≤1 GiB/16/16) + `aes-gcm` 0.10.3 AES-256-GCM (16-B salt, 12-B random nonce, AAD binds pk+network[+version]) | | | Node validator keystore: Argon2id + XChaCha20-Poly1305 (`keys.rs`). |
| Seed phrase | `bip39` 2.2.2 (English), PBKDF2-HMAC-SHA512 ×2048 (`pbkdf2` 0.12.2), official Trezor vectors pinned; legacy V1 PBKDF2-SHA256 retained behind an explicit `SeedVersion` | | | |

`pqcrypto-kyber` 0.8.1 appears in the lock only via `legacy/genesis3-node`.

---

## 5. Positive observations

- **AND-combiner is sound and single-sourced.** `verify_hybrid_mldsa_falcon` requires both halves; the committee's `staking::verify_hybrid` re-enforces AND at fixed split points and rejects `sig.len() <= 3309`; `WsHybridVerifier` maps to `verify_mldsa65_raw`/`falcon::verify`. No OR path, no early-accept, no classical (Ed25519/secp256k1) fallback anywhere in bloch-crypto.
- **Key substitution:** ML-DSA binds `tr = H(pk)` into μ, so DSKS on the hybrid is blocked by the ML-DSA half; addresses hash the *enveloped* pubkey, so suite is committed (`addresses_commit_to_suite` test).
- **Domain separation** is systematic and length-prefixed where inputs are variable: sighash v2 (`BLOCH-SIGHASH-v2 ‖ ver ‖ chain_id ‖ body`), signed-message digest (A4-M-4 fixed; CLI no longer hex-decodes), disclosure digest, keyfile AAD v1/v2, `diversified_seed`, coherence `DOM_*` tags with fixed-width fields, PoW `shake256_dom` (every input length-prefixed).
- **Seeded RNG fork:** minimal, well-tested; upstream semantics preserved when inactive; fail-closed on RNG failure (K-H1 verified, child-process abort tests); nesting fixed (I-2 verified). Production keygen from seed never signs inside the scope; validator keys are OS-random; the ceremony consumes public data only.
- **Falcon `clean` pin (F1)** is enforced at three levels (Cargo `default-features=false`, `cargo metadata` guard in CI, linked-symbol tripwire test) — verified `build.rs` gating compiles avx2/aarch64 only when the features are set.
- **Vendored C provenance:** byte-identical to upstream 0.2.11; the hash pin runs in both CI systems.
- **Wallet at rest:** Argon2id with sane bounds on untrusted params (L1), AEAD with AAD binding of pubkey + network (M2), nonce-length guards (A4 lows), 0600 atomic writes (L-4/M), address re-derived from the decrypted pubkey rather than trusted from metadata, `Keypair` custom `Serialize` never emits the secret, Zeroizing on plaintext buffers. BIP39 official vectors pinned; K-M3 versioning avoids silent key rotation.
- **Deterministic keygen reproducibility hazard is handled:** exact-version pins (`=0.1.2`, `=0.4.1`), golden seed→key hashes, `SeedVersion`, and `BLOCH-GENESIS-KEYS.md §4.3` advising raw-secret backups over seed-only backups.
- **bloch-sis-pow:** `const_assert` of `√k·β < q` for both widths, k=0 rejected, `unsigned_abs` for `i32::MIN`, i64 accumulation, rejection sampling in expansion, length-prefixed SHAKE, `bits_to_target` fails closed. Not on the live path.
- **coherence-core:** position high-bit guard (`verify_path`), public/witness count binding (C2), nullifier-set SMT root (C1.1). (Authorization gap: CR-01.)
- `#[forbid(unsafe_code)]` in bloch-crypto and coherence-core; only 6 `#[allow]`s in scope (`seed.rs:363,389 deprecated`, `core/mod.rs:1793 clippy::absurd_extreme_comparisons`, `pqcrypto-internals/src/lib.rs:64 nonstandard_style`, `bloch-sis-pow/src/lib.rs:92 deprecated`) — all benign. The full `as`-cast inventory (68 non-test casts across the in-scope crates) was reviewed: all are length→prefix widenings, bounded byte packing, or i64 accumulation; none truncates untrusted data unchecked (the only narrowing casts sit behind explicit range checks in `difficulty.rs`, `encode.rs`, `expand.rs`).

---

## 6. Test-coverage gaps

- No test that a Falcon signature zero-padded to **exactly 1280 bytes** is rejected (the existing "+1 byte" test passes for the wrong reason); no test that header-stripped / header-added signatures are rejected; no mix-and-match test (CR-02).
- No NIST/ACVP KATs for ML-DSA-65 or Falcon-1024 (KNOWN, P0.3); crate-oracle equivalence only.
- No test that `crypto::verify` rejects suite 0x0002 on a consensus path (CR-03); the only 0x0002 test proves it is *accepted*.
- coherence-core: no negative test for a wrong `nk`, no "same note → same nullifier" invariant (CR-01).
- No cross-thread test that a guard on thread A does not affect thread B; no test that `randombytes_fill` after a leaked guard is detected (CR-08).
- No test for `Address` network mismatch in `build_tx`; no test that `disclosure::keypair_at(0)` equals `HdWallet` index 0 (it does not, CR-06).
- `vendor_pin.rs` does not cover `build.rs`/`Cargo.toml` (CR-09).
- Fuzz: `fuzz_verify_never_panics` is in-tree SplitMix; cargo-fuzz targets exist under `fuzz/` (excluded from the workspace; not run here).

---

## 7. Residual risk / not covered

- `bloch-pos-committee` and `bloch-pos-node` were read only where they consume crypto outputs; a full audit of every place signature bytes enter an identity, cache, or size-based rule on the live chain belongs to the consensus auditors — CR-02's impact statement should be re-checked against their findings.
- `crates/coherence-prover` (SP1 guest) and `fuzz/` were not read; CR-01 assumes the guest calls `check_spend` as documented.
- `core/mod.rs` (3,520 lines), `core/auxpow.rs`, `core/tokenomics_v2.rs` were read only for the signature/txid/sighash/varint paths and the cast inventory; Genesis-3 consensus semantics were not re-audited (retired chain).
- Side-channel behaviour of the linked ML-DSA AVX2 variant and of `argon2`/`aes-gcm` software paths was not evaluated beyond noting the F1 rationale covers Falcon only.
- Upstream PQClean *algorithm* sources inside `pqcrypto-falcon`/`pqcrypto-mldsa` were consulted for the API/encoding behaviour relevant here, not audited in full.
- The `rand_chacha` 0.9 `ChaCha20Rng` byte-stream stability across future 0.9.x releases is assumed (golden hashes would catch a change).
- Network access allowed diffing against crates.io tarballs; the GitHub `Groundstate100/pqcrypto-fork` repository named in the README was not fetched.
