# A9 — Bitcoin-facing crates + Ustav token kernel: security & correctness audit

Auditor: A9. Repository: `/home/user/bloch-sis-pow` (read-only; no cargo invoked).
Date: 2026-09-16.

---

## 1. Scope & method

### 1.1 Files read in full

| Area | Files |
|---|---|
| `crates/bloch-pq-vault` | `Cargo.toml`, `src/lib.rs` (591 L), `src/vault.rs` (282 L), `src/preimage.rs` (91 L), `src/script_eval.rs` (233 L), `src/anchor.rs` (581 L) |
| `crates/bloch-btc-wallet` | `Cargo.toml`, `src/lib.rs` (320 L) |
| `services/pq-shield-api` | `Cargo.toml`, `Cargo.lock` (version pins), `src/main.rs` (42 L), `src/lib.rs` (1001 L), `README.md` (287 L) |
| `anchoring/` | `Cargo.toml`, `README.md`, `src/{lib,error,http,commitment,anchor,tx,rpc,convention,sdk}.rs`, `examples/anchored_notary.rs`, `.gitignore` |
| `crates/bloch-ustav` | `Cargo.toml`, `README.md`, `src/lib.rs`, `tests/chameleon_crypto.rs`, `tests/crypto_kernel.rs`, `examples/lifecycle.rs`, `examples/chameleon_roundtrip.rs` |
| Kernel the ustav crate re-exports | `crates/bloch-euvm/src/ustav.rs` (963 L), `src/ustav/encoding.rs`, `src/ustav/chameleon.rs` (690 L), `src/ustav/chameleon/wire.rs`, `docs/ustav-kernel.md`, `docs/chameleon-v1.md` |
| Gates / scripts | `scripts/check-ustav-pq-boundary.py`, `.github/workflows/ustav.yml`, relevant sections of `.gitlab-ci.yml` and `.github/workflows/tests.yml` |
| Specs / prior audits | `docs/specs/PQ-SHIELD-NONCUSTODIAL-NATIVE.md` (529 L, full), `docs/adr/ADR-040-evm-and-ustav-at-l1.md`, `docs/specs/BLOCH-KIRPICH-UNDER-POS.md` (skim), `docs/audit/groundstate_audit.md` (skim), `SECURITY.md` (full), `audit/CONSOLIDATED-SECURITY-REPORT.md` and `docs/PUBLIC-RELEASE-AUDIT.md` (grep for in-scope crates) |
| Supporting code paths | `crates/bloch-crypto/src/crypto/mod.rs` (envelope, `sign`, `verify`, `generate_keypair_from_seed`), `crates/bloch-euvm/src/kirpich/{limits,params,completeness}.rs` (rules reachable from the API), `crates/bloch-euvm/src/lib.rs` (`SigVerifier`, `VerifyEcdsa`), registry sources of `secp256k1-0.29.1` (`SecretKey` is `Copy`) and `bitcoin-0.32.8` (`push_int`, `Sequence::from_height`) |

### 1.2 Corrections to the brief

- **`anchoring/` is not a Bitcoin anchoring SDK.** It anchors 32-byte commitments *into Bloch* (P2PKH "burn" outputs, JSON-RPC to a Bloch node on port 16210). No Bitcoin RPC, no OP_RETURN, no Bitcoin tx construction exists there. It was audited on its own terms (RPC credential handling, `http.rs`, commitment format, tx codec, convention).
- **There is no chameleon *hash* anywhere in the tree.** `tests/chameleon_crypto.rs` exercises the "Color-Changing Chameleon v1" native-escrow/EVM-representation module (`bloch_euvm::ustav::chameleon`). A repo-wide grep for `trapdoor` / `chameleon hash` finds only PoW-hardness prose. The nearest thing to a "trapdoor holder" is the party that supplies `TrustedBurnCheckpoint` (see BV-16).
- **Prior-audit tags cited in code (`A4-M-5`, `I-13`, `K-2`, `K-M6`, `L-16`, `M1`) have no corresponding document in the repository.** `groundstate_audit.md`, `SECURITY.md`, `audit/CONSOLIDATED-SECURITY-REPORT.md` and `docs/PUBLIC-RELEASE-AUDIT.md` do not mention `bloch-pq-vault`, `pq-shield-api`, `bloch-btc-wallet`, `anchoring` or `bloch-ustav` findings at all (the public-release audit lists their files only for missing SPDX headers). "KNOWN" below therefore means *acknowledged in code comments or the pq-shield-api README*, with the citation given.

### 1.3 Adversary models applied

(a) mempool observer / CRQC holder on Bitcoin; (b) unauthenticated HTTP client of `pq-shield-api`; (c) owner who loses or leaks exactly one of `{hot_sk, recovery_sk, pq_sk, r}`; (d) miner (fee selection, censorship for Δ); plus the Ustav-specific adversaries: token issuer, holder, snapshot supplier, checkpoint supplier.

### 1.4 What I did not do

No `cargo build/test/tree` was run (lead runs centrally). Claims about `axum` default body limits and `ureq` defaults are from documented crate behaviour of the locked versions (`axum 0.7.9`, `ureq 2.x`), not from re-reading their sources; confidence is stated per finding.

---

## 2. Findings

Severity scale (per brief): **Critical** = theft with no precondition; **High** = theft with realistic preconditions; **Medium** = funds lock / griefing / defense-in-depth gap; **Low** = hard to exploit / minor; **Info** = quality / docs.

---

### BV-01 — The deposit key and the branch-A key are the same key, so the "pre-signed U + delete the bypass key" covenant emulation is structurally impossible; a hot-device compromise bypasses the delay entirely

- **Severity:** High
- **Status:** NEW. (The *covenant caveat itself* is KNOWN: `lib.rs:34-38` HONEST LIMITS #2, spec §2.0(2)/§9.2. What is new is that the implementation cannot satisfy even the operational mitigation the caveat relies on.)
- **Refs:** `crates/bloch-pq-vault/src/vault.rs:64-72` (`deposit_script` uses `hot_pubkey`), `vault.rs:76-94` (`trigger_script` branch A uses the same `p.hot_pubkey`, line 83), `src/lib.rs:105-122` (`VaultKeys` has exactly `hot_sk` + `recovery_sk`), `lib.rs:34-38`, spec `docs/specs/PQ-SHIELD-NONCUSTODIAL-NATIVE.md:124-136, 149-150, 308-311`.
- **Description.** The design (spec §2.0(2), §4 step 3) says the only thing that makes V spendable *solely* through the delayed trigger T is: pre-sign U, then **securely delete the deposit/"trigger bypass" key**. That requires the key that signs V's spend to be *different* from the key that must survive to sign branch A later. In the code they are the same `hot_pubkey`:

  ```rust
  // vault.rs:64-72
  pub fn deposit_script(recovery_hash: &[u8; 32], hot_pubkey: &PublicKey) -> ScriptBuf { ... push_key(hot_pubkey) ... }
  // vault.rs:76-84 (branch A)
  .push_int(p.csv_delay as i64).push_opcode(op::OP_CSV).push_opcode(op::OP_DROP).push_key(&p.hot_pubkey).push_opcode(op::OP_CHECKSIG)
  ```
  Consequently there is no "bypass key" that can be deleted: deleting `hot_sk` makes branch A permanently unspendable (the vault degenerates to "clawback only"), and keeping it means V can be spent directly, to *any* address, with `hot_sk` + `r`, skipping T and Δ altogether. `lib.rs:38` ("This crate builds and signs those txs; it cannot make anyone delete a key") and the API README (which points integrators at `derive_vault_keys`) present the operational mitigation as available; it is not.
- **Attack scenario.** The hot signing device necessarily holds `hot_sk` (for branch A) and the 32-byte preimage `r` (it must assemble U's witness `[sig, r]`). Classical compromise of that device (malware, backup leak) yields both. The attacker builds a single P2WSH spend of V directly to their address — no trigger, no Δ, no clawback window. The recovery key on the cold device never gets a chance to act. This is exactly the threat vaults exist to mitigate (Revault, "deleted-key" vaults), and here it is fully unmitigated: the construction offers the same protection as a plain `OP_SHA256 <H(r)> OP_EQUALVERIFY <hot> OP_CHECKSIG` output.
- **Evidence:** as above; `VaultKeys` derives idx 0 (hot) and idx 1 (recovery) only (`lib.rs:147-148`, `193-194`).
- **Recommendation.** Introduce a third, ephemeral deposit key `K_d` (fresh per vault, never derived from the seed) used only in `deposit_script`; pre-sign U with it; document and, where possible, enforce deletion (e.g. return it only inside a `Zeroizing` wrapper, never persist it). Branch A keeps `hot_pubkey`. Until that exists, the crate and API docs must say plainly that the delay is *not* enforced against a hot-key holder, only against a CRQC that learns `hot_pubkey` from U.
- **Confidence:** High (direct code reading; the property is definitional).

---

### BV-02 — The clawback cannot be fee-bumped by a watchtower as documented; the only way to give a watchtower that power is to hand it `recovery_sk`, which lets it steal (the "griefing only, never theft" claim does not hold)

- **Severity:** High
- **Status:** NEW. (The fee-race risk in general is KNOWN, `lib.rs:47-51` #6/#7, spec §2.2; the contradiction between "watchtower can fee-bump" and "watchtower cannot steal" is new.)
- **Refs:** `vault.rs:170-195` (`build_clawback_tx`: single input, single output, `ENABLE_RBF_NO_LOCKTIME`; doc-comment line 172-173 "RBF so a watchtower can fee-bump it"), `vault.rs:200-218` (`p2wsh_sighash` hard-codes `EcdsaSighashType::All`), `lib.rs:214-221` (`ecdsa_witness_sig` appends `SIGHASH_ALL`), `services/pq-shield-api/src/lib.rs:530-532` ("RBF-enabled so a watchtower can fee-bump the race"), spec `§4.1 L320-335`, `§7 L408`, `lib.rs:47-49`.
- **Description.** The clawback is a 1-in/1-out transaction signed `SIGHASH_ALL`. Setting the RBF bit does not give a third party any ability to raise the fee:
  - **RBF** requires a new signature over a new output value → needs `recovery_sk`.
  - **CPFP** requires spending the clawback's output → needs the key of `designated_safe_dest` (cold by design, spec §9.4).
  - **Adding a fee input** would need `SIGHASH_ALL|ANYONECANPAY` (not offered; `p2wsh_sighash` accepts no sighash-type parameter) — and even then the output amount is fixed.
  - **No anchor output / fee ladder** is built (`build_clawback_tx` emits exactly one output).
  So a watchtower holding only the pre-signed clawback cannot bump; a watchtower that *can* bump must hold `recovery_sk`, and branch B has no covenant on the destination (`trigger_script` branch B checks only `SHA256(r)==H(r)` and a signature under `recovery_pubkey`), so such a watchtower can send the coins anywhere once `r` is public (it is public from the moment U is broadcast). The spec's non-custodial guarantee (§4.1: "cannot move funds anywhere except the owner's own pre-committed cold address", §6, `lib.rs:48-49`) is therefore false for any watchtower that can do the job the spec assigns to it. Additionally, because the clawback is meant to be *pre-signed at setup* (spec §4 step 3), its fee is frozen at setup time; a fee spike during the Δ window can make it unconfirmable, with no bump path.
- **Attack scenario.** Owner hires a watchtower service and, following the README's promise, gives it the ability to "fee-bump" — in practice `recovery_sk` (or a signing oracle). Attacker (or the service itself) waits for any unvault, learns `r` from U's witness, and signs a branch-B spend to its own address with a higher fee than the owner's clawback. Miner picks the higher fee. Loss of the full trigger amount.
- **Recommendation.** (1) Sign the pre-signed clawback with `SIGHASH_ALL|ANYONECANPAY` (or SINGLE|ACP with an explicit fee-input pattern) so a watchtower can attach its own fee input without touching the output; (2) or add a small anchor output spendable by the watchtower key for CPFP; (3) or pre-sign a fee ladder; (4) correct `vault.rs:172-173`, `pq-shield-api/src/lib.rs:531`, spec §4.1/§6/§7 and `lib.rs:48-49` to state that a watchtower with bump capability is a theft-capable party.
- **Confidence:** High.

---

### BV-03 — `pq-shield-api` receives exactly the public keys whose secrecy the vault's security rests on (`recovery_pubkey`, `hot_pubkey`) plus the unvault intent, over plaintext HTTP, to a third-party operator; "non-custodial" protects only field *names*

- **Severity:** High under the crate's own threat model (CRQC: public key ⇒ private key); Medium against a classical adversary (privacy/linkability, head start).
- **Status:** NEW.
- **Refs:** `services/pq-shield-api/src/lib.rs:216-237` (`VaultParamsReq` requires `hot_pubkey`, `recovery_pubkey`), `:378-420` (`/vault/address`), `:423-456` (`/vault/unvault-tx` also takes `deposit_outpoint` — the intent to unvault, before it is in the mempool), `:497-538` (`/vault/clawback-tx` takes the trigger outpoint and `safe_destination`), `:89-131` (`guard_no_secrets` scans key *names* only), `src/main.rs:17` (`PQ_SHIELD_BIND`), `README.md:19-23` ("this endpoint is how third-party builders integrate"), spec §0.1 (P2WSH chosen precisely so pubkeys are hidden at rest), spec §2.2 L200-205 ("branch B's safety against a CRQC rests on `recovery_pubkey` not being derivable in time — i.e. it too is only revealed at branch-B spend").
- **Description.** The whole construction is built on P2WSH so that `hot_pubkey` and — load-bearingly — `recovery_pubkey` are never seen by anyone until the corresponding spend. Every vault route of the API requires the client to POST both keys to the service. An operator (or any on-path observer, since the service speaks plain HTTP by design, `lib.rs:634-641`) obtains `recovery_pubkey` at vault-creation time. Under the CRQC model that *is* `recovery_sk`, obtained months before the clawback that was supposed to be the owner's unforgeable edge. `/vault/unvault-tx` additionally tells the operator which outpoint is about to be unvaulted before U is broadcast, and `/vault/clawback-tx` tells it the safe destination. The secret-name guard (`FORBIDDEN_FRAGMENTS`, `FORBIDDEN_EXACT`) cannot help: the sensitive material is precisely what the API is designed to accept.
- **Attack scenario.** (i) Operator/observer with a CRQC: records `recovery_pubkey` per vault; when U appears, has `recovery_sk` ready and RBF-races the owner's clawback to its own address (BV-02 shows branch B has no destination covenant). (ii) Classical operator: learns the deposit script preimage → can link deposits to owners and front-run knowledge of unvaults (sells the feed).
- **Recommendation.** Ship the construction logic as a *client-side library/WASM* rather than a hosted service (the README already notes the WASM option); if a hosted service must exist, document that it must be self-hosted on the owner's own machine and never receive `recovery_pubkey` (e.g. accept the trigger script hash/P2WSH program instead of keys, or accept only `hot_pubkey` + a caller-supplied `recovery_pubkey_hash`-based script variant). At minimum, the README's threat model must say the operator learns the keys the design hides.
- **Confidence:** High on the fact; the severity classification depends on accepting the crate's own CRQC premise.

---

### BV-04 — Recovery key is a non-hardened BIP-32 sibling of the hot key in *both* derivations (V1 and the A4-M-5 "fix" V2); `hot_sk` + one xpub ⇒ `recovery_sk`

- **Severity:** Medium (High if a watch-only xpub of the vault branch is ever exported)
- **Status:** KNOWN but **not fixed in the crate** — `services/pq-shield-api/README.md:244-250` ("audit finding M1, Medium … derive the recovery key on a HARDENED path"), `src/lib.rs:414-416` and the landing HTML repeat the advice; `crates/bloch-pq-vault/src/lib.rs:72-99` (A4-M-5) changed the *purpose* field but kept the sibling structure.
- **Refs:** `lib.rs:141` (`m/84'/{coin}/0'/0/{idx}`), `lib.rs:186` (`m/1998'/{coin}/0'/0/{idx}`), `lib.rs:147-148, 193-194` (idx 0 = hot, idx 1 = recovery).
- **Description.** Both keys are unhardened children (`/0/0`, `/0/1`) of the same chain node. Standard BIP-32 arithmetic: given the parent extended *public* key `(K_par, c_par)` and any one child private key `k_i`, `k_par = k_i − IL_i (mod n)`, and every sibling follows. The README instructs integrators to do what the crate's own helper — which the README also tells them to use ("e.g. via `bloch-pq-vault::derive_vault_keys`", README L201-203) — does not do. The `derive_vault_keys_v2` doc-comment (`lib.rs:159-168`) says the fix makes the keys "never the same key a wallet UI shows"; it says nothing about the hot→recovery derivability that M1 is about.
- **Attack scenario.** Hot device compromised (has `hot_sk`) + any place the chain-level or account-level xpub of the vault branch was exported (watch-only wallet, address-derivation service, the pq-shield-api operator if a future route takes an xpub) ⇒ attacker derives `recovery_sk`; after the owner's next unvault (`r` public) the attacker claws back to itself. Precondition is weaker for V1 (BIP-84 account xpubs are routinely exported).
- **Recommendation.** Derive `recovery_sk` under a hardened leaf on a separate hardened account (e.g. `m/1998'/coin'/1'/0'/0'`), or from an independent seed; add a test asserting that hot and recovery are not siblings under any unhardened node. Keep V1/V2 pinned for existing vaults but mark both as M1-vulnerable in the enum docs.
- **Confidence:** High.

---

### BV-05 — `csv_delay = 0` (and any tiny Δ) is accepted everywhere; branch A becomes immediately spendable and the vault silently provides no window

- **Severity:** Medium
- **Status:** NEW
- **Refs:** `vault.rs:48-59` (`csv_delay: u16`, no validation), `vault.rs:80` (`push_int(0)` → `OP_0`, verified in `bitcoin-0.32.8 builder.rs:41-42`), `vault.rs:160` (`Sequence::from_height(0)` → `Sequence(0)`), `services/pq-shield-api/src/lib.rs:224, 258, 306` (`csv_delay: u16`, no minimum), spec §7 L400-402 (default 144, "minimum useful ~36").
- **Description.** With Δ=0 the branch-A script is `OP_IF OP_0 OP_CSV OP_DROP <hot> OP_CHECKSIG …`; BIP-112 with a required value of 0 and an nSequence of 0 (disable bit clear, block type) passes immediately. Nothing in the crate or the API rejects `0` or values below the spec's own minimum. The anchor records Δ but `verify_anchor` does not range-check it against a floor either. For a service explicitly marketed to third-party integrators, a default-less `u16` field is a foot-gun that turns the vault into an undelayed 1-of-1.
- **Attack scenario.** Integrator bug / copy-paste sends `csv_delay: 0` (or the JSON default of a typed language). Vault "works" (addresses, txs, sighashes all succeed). The owner believes they have a 24 h window; a CRQC or a hot-key thief spends branch A in the same block as T.
- **Recommendation.** Enforce `csv_delay >= MIN_CSV_DELAY` (≥ 36 per spec; consider 144 default) in `VaultParams` construction (make the field private, add a constructor returning `Result`), in the API DTOs, and in `verify_anchor`/`deserialize`.
- **Confidence:** High.

---

### BV-06 — Remote-triggerable panic in `pq-shield-api` `/anchor/commitment`: an empty or >8192-byte `pq_recovery_pubkey` reaches the *panicking* `anchor_guard_governance` wrapper

- **Severity:** Medium (DoS / robustness of an unauthenticated service)
- **Status:** NEW (the panic was *introduced* by the K-2 fix: `anchor.rs:293-307`)
- **Refs:** `services/pq-shield-api/src/lib.rs:541-545` (`anchor_commitment` → `vaultlib::anchor_guard_governance_hash(&anchor.pq_recovery_pubkey)`), `:355` (`hexbytes` accepts any length incl. empty), `crates/bloch-pq-vault/src/lib.rs:240-242` (calls `anchor::anchor_guard_governance`), `src/anchor.rs:303-307` (`.unwrap_or_else(|e| panic!(...))`), `crates/bloch-euvm/src/kirpich/params.rs:237-248` (KRP-045 Deny on empty signer), `kirpich/limits.rs:7, 51-53` (KRP-046 Deny when a key exceeds `MAX_KEY_BYTES = 8192`), test `anchor.rs:576-580` confirms the panic.
- **Description.** The K-2 fix deliberately converted a silent bad compile into a panic and left a checked variant (`anchor_guard_governance_checked`) for callers that can propagate `Result`. The HTTP handler is such a caller but goes through the infallible wrapper. `pq_recovery_pubkey` is untrusted hex of up to the body limit (~2 MiB → ~1 MiB of bytes), so both Deny rules are reachable: `""` (KRP-045) and anything longer than 8192 bytes (KRP-046). The panic unwinds through the handler into the per-connection task spawned by `axum::serve`; tokio catches it, so the process survives, but the connection (and any pipelined/keep-alive requests on it) is dropped and a backtrace is printed to stderr per request. No `CatchPanic` layer is installed (`lib.rs:642-657`). The service's `Cargo.toml` has no `panic = "abort"`, so this is not a process crash (confidence: high; if the deployment profile ever sets `panic="abort"`, this becomes a one-request process kill).
- **Attack scenario.** `curl -d '{"btc_vault_address":"x","recovery_hash":"<64 hex>","pq_recovery_pubkey":"","designated_safe_dest":"x","csv_delay":144}' /anchor/commitment` in a loop: log spam, dropped connections, and the concurrency permit churn. Trivial, unauthenticated.
- **Recommendation.** Use `anchor_guard_governance_checked` in `anchor_guard_governance_hash` (return `Result`) and map `CharterAuditDenied` to HTTP 400; validate `pq_recovery_pubkey` as a well-formed suite-0x0001 envelope of exactly 4+1952+1793 bytes (reuse `bloch_ustav::BlochVerifier::valid_pq_key`-style checks) at the edge; add `tower_http::catch_panic::CatchPanicLayer` as defense-in-depth.
- **Confidence:** High.

---

### BV-07 — The anchor has no freshness / rotation / revocation semantics; two valid anchors for the same vault under the same trusted key are indistinguishable, and nothing posts or orders anchors on Bloch today

- **Severity:** Medium (design gap; theft precondition is `pq_sk` compromise, which the spec itself says is handled by "rotating the anchor")
- **Status:** NEW (the "not consensus-wired" limit is KNOWN: `lib.rs:55-58`, `anchor.rs:23-26`; the missing rotation semantics are not acknowledged)
- **Refs:** `anchor.rs:65-88` (`PqShieldAnchor` fields: no nonce/sequence/height/expiry other than free-form `policy`), `anchor.rs:183-205` (`verify_anchor` checks version, key identity, signature only), spec §4.2 L342-344 ("`pq_sk` compromise: rotate the anchor"), spec §3.2 L288-291 ("anyone can verify … have not been rotated").
- **Description.** `verify_anchor` answers "was this blob signed by the trusted key" and nothing else. There is no monotonic field, no `supersedes` pointer, no expiry, no revocation record, and no code path anywhere in the repo that submits an anchor to a Bloch eUTXO (the guard programs are compiled, their *hashes* returned by the API, but no datum is ever built or posted). A watchtower fed two anchors — the owner's and a later one signed with a compromised `pq_sk` naming an attacker's `designated_safe_dest` — has no rule to pick, and the spec's recovery procedure for `pq_sk` compromise ("rotate") cannot be expressed in the format. Even when Bloch ordering exists, `commitment_bytes` does not bind the anchor to the trigger script/`recovery_pubkey`, only to the deposit address string, so an anchor cannot be checked against the T it is supposed to govern.
- **Attack scenario.** `pq_sk` leaks (it is derived from the same seed as everything else; V1 uses the raw seed bytes). Attacker signs a fresh anchor for the same `btc_vault_address` and `H(r)` with its own `designated_safe_dest` and a later `policy` string; a watchtower that honours "latest anchor" claws back to the attacker; one that honours "first anchor" ignores legitimate rotation. Both behaviours are consistent with the code.
- **Recommendation.** Add `sequence: u64` (or Bloch height) and `prev_anchor_hash: [u8;32]` to the committed fields, define "highest sequence under the trusted key wins", add an explicit revocation record, bind `trigger_script_hash` (P2WSH program of T) into the commitment, and implement/describe the actual Bloch posting path or stop describing Bloch as an enforcement plane.
- **Confidence:** High on the gap; Medium on exploitability (requires `pq_sk`).

---

### BV-08 — No dust, absurd-fee, or fee-estimation checks in the tx builders or the API; pre-signed transactions freeze fees

- **Severity:** Medium (funds lock / silent overpayment), Low for the overpayment half
- **Status:** NEW
- **Refs:** `vault.rs:124, 151, 180` (`saturating_sub(fee_sat)`, no dust check), `services/pq-shield-api/src/lib.rs:429-431, 466-468, 504-506` (only `fee_sat >= amount` is rejected), README L113-114.
- **Description.** `fee_sat = amount − 1` produces a 1-sat P2WSH output (dust threshold 330 sat): the signed tx is unrelayable → for the *clawback* that means the owner's only defense during Δ cannot enter the mempool at all. Conversely `fee_sat = 0.99 × amount` is accepted; Bitcoin Core's `sendrawtransaction` only refuses above `maxfeerate` (0.10 BTC/kvB), i.e. ≈0.015 BTC for a ~150 vB tx — everything below is silently paid to miners. There is no fee-rate estimation; combined with the pre-signed model (spec §4 step 3) the clawback fee is fixed at setup, which BV-02 shows cannot be corrected later.
- **Recommendation.** Reject outputs below the dust limit for the destination script type; require `fee_sat <= max(absurd_fee_abs, fee_rate_cap × vsize)`; expose vsize and a suggested fee-rate range in the API response; and fix BV-02 so setup-time fees are not final.
- **Confidence:** High.

---

### BV-09 — Secret material is never zeroized: `VaultKeys` (`Clone`), `pq_secret: Vec<u8>`, `SecretKey` (`Copy`, no `Drop`), master `Xpriv`, the HKDF IKM copy

- **Severity:** Low
- **Status:** NEW
- **Refs:** `lib.rs:105-122` (`#[derive(Clone)] pub struct VaultKeys { pub hot_sk: SecretKey, … pub pq_secret: Vec<u8>, … }`), `lib.rs:138, 183` (`Xpriv::new_master`), `preimage.rs:42` (`Hkdf::new(Some(HKDF_SALT), pq_sk)` over the full 4032+Falcon-sk enveloped blob), registry `secp256k1-0.29.1/src/key.rs:57-58` (`#[derive(Copy, Clone)] pub struct SecretKey`), `:972` (`non_secure_erase` is manual and never called here).
- **Description.** `bloch-crypto` depends on `zeroize` but `generate_keypair_from_seed` returns a plain `Vec<u8>` and the vault stores it as such; secp256k1 secret keys are `Copy` and leave copies on the stack in every closure/derive call; nothing wraps the seed. All public fields, so any caller can clone freely. Not an exploit by itself; a memory-disclosure or core-dump amplifier.
- **Recommendation.** Wrap `pq_secret` and the seed in `zeroize::Zeroizing`, implement `Drop` for `VaultKeys` calling `non_secure_erase` on the two `SecretKey`s, drop `Clone`, and make fields private with accessor methods.
- **Confidence:** High.

---

### BV-10 — `r` is deterministic in `(pq_sk, vault_id)` with a client-chosen, API-invisible `vault_id`; reuse or derivation-version confusion silently degrades or locks the vault

- **Severity:** Low
- **Status:** Partially KNOWN (`services/pq-shield-api/README.md:255-256` warns "use a unique `vault_id` per vault"; `lib.rs:117-121` warns about `key_derivation` versioning) — the absence of any mechanism is NEW.
- **Refs:** `preimage.rs:41-50`, `lib.rs:124-157` vs `169-211` (V1 vs V2 produce different `pq_secret`, hence different `r`), API: no `vault_id` field anywhere.
- **Description.** Nothing derives `vault_id` from the deposit (e.g. the funding outpoint) or checks that an `H(r)` has not been used before. Reusing a `vault_id` after one unvault makes the hash-gate of the new V publicly satisfiable (only the hot signature remains). Re-deriving keys under the other `VaultKeyDerivation` variant yields a different `r`; the deposit then looks unspendable until the owner guesses the right variant. Neither condition is detectable server-side; both are silent.
- **Recommendation.** Derive `vault_id` from a value that is unique per vault by construction (e.g. `SHA256(deposit_script)` is circular — use the funding outpoint at first spend, or a random per-vault salt stored with the anchor `policy`); persist `key_derivation` inside the anchor; have the API refuse `recovery_hash` values it has already seen in-session (best-effort).
- **Confidence:** High.

---

### BV-11 — `SignedAnchor::deserialize` ignores trailing bytes; anchor address fields are never validated as addresses

- **Severity:** Low
- **Status:** NEW
- **Refs:** `anchor.rs:216-256` (no "cursor at end" check after `get_bytes()` for the signature), `anchor.rs:99-102` (addresses are opaque bytes), `services/pq-shield-api/src/lib.rs:349-360` (`to_anchor` only `.trim()`s `btc_vault_address` / `designated_safe_dest`; `validate_destination` is used only in the tx routes).
- **Description.** Two different blobs (`serialize() ‖ garbage`) decode to the same anchor; any system that keys anchors by blob hash sees duplicates. Separately, an anchor can commit to a `designated_safe_dest` that is malformed or on the wrong network; the mismatch surfaces only when someone tries to build the clawback (`/vault/clawback-tx` rejects it), i.e. during the attack window.
- **Recommendation.** Reject trailing bytes in `deserialize`; validate both address strings with `validate_destination(…, network)` in `to_anchor` (add a `network` field or infer from `target_chain`) and in `verify_anchor`.
- **Confidence:** High.

---

### BV-12 — `pq-shield-api` deployment posture: plain HTTP, no authentication, no per-client rate limit, `0.0.0.0` bind supported; CSRF-shaped requests reach handlers

- **Severity:** Low
- **Status:** KNOWN in part — L-16 comments (`lib.rs:615-641`) document the TLS-proxy requirement and add a 10 s timeout + 64-concurrency ceiling. The remaining points are NEW.
- **Refs:** `src/main.rs:17-31`, `src/lib.rs:622, 631, 642-657` (no `CorsLayer`, no `CatchPanicLayer`, no body-limit override — relies on axum's default 2 MiB for `Bytes`, confidence medium), handlers take raw `Bytes` without a `Content-Type` check.
- **Description.** The concurrency ceiling is global, so 64 slow clients starve everyone; there is no per-IP control. Cross-origin `text/plain` form POSTs reach the handlers (no state, so no impact today, but any future stateful route inherits it). Nothing is logged (good), but nothing is audited either.
- **Recommendation.** Ship a reference reverse-proxy config with TLS + per-IP limits; add `CatchPanicLayer` (BV-06), an explicit `DefaultBodyLimit`, and a `Content-Type: application/json` check; document that `0.0.0.0` must never be used without the proxy.
- **Confidence:** High (Medium on the axum default-limit detail).

---

### BV-13 — `anchoring/src/http.rs`: no read/write timeout, API key sent in clear over whatever scheme the caller passes, lenient RPC parsing

- **Severity:** Low
- **Status:** NEW
- **Refs:** `anchoring/src/http.rs:34-40` (`ureq::Agent::new()` — ureq 2 default: 30 s connect timeout, **no** read/write timeout; confidence medium, from documented defaults), `:42-46, 55-57` (`X-API-Key` header; URL scheme unchecked; the doc example is `http://`), `rpc.rs:130-144` (`confirmations` defaults to 0 when absent, `height` optional), `rpc.rs:184-192` (`hex` fallback parses with the non-consensus codec of `tx.rs`, so a real node's raw tx cannot be decoded — `tx.rs:1-15` says so).
- **Description.** A stalled or malicious node hangs `wait_for_confirmations` forever (each poll blocks with no read timeout); the shared secret is sent over plaintext if the URL is `http://` to a remote host; a node that omits `confirmations` is treated as "0 confirmations" rather than an error (harmless: only delays). `into_string()` is capped by ureq at 10 MiB, so response size is bounded.
- **Recommendation.** `AgentBuilder::new().timeout_read(…).timeout_write(…)`, refuse non-`https` URLs when the host is not loopback unless explicitly overridden, treat a missing `confirmations` field as `BadResponse`.
- **Confidence:** Medium-High.

---

### BV-14 — The Ustav "PQ boundary" is a name-denylist tripwire that runs only in GitHub Actions; the GitLab pipeline neither runs it nor blocks on `bloch-ustav`/`bloch-euvm`/`bloch-btc-wallet` tests, and `pq-shield-api` / `anchoring` tests are gated nowhere

- **Severity:** Low (process / assurance gap)
- **Status:** NEW (the script itself says "a dependency regression guard, not a cryptographic proof"; the CI-coverage asymmetry is not documented)
- **Refs:** `scripts/check-ustav-pq-boundary.py:11-14` (denylist: `ecdsa,k256,p256,p384,p521,elliptic-curve,secp256k1,secp256k1-sys,ed25519,ed25519-dalek,rsa`), `:20-23` (`cargo tree --locked -p bloch-ustav --edges normal`), `.github/workflows/ustav.yml:25-34`, `.gitlab-ci.yml:650-653` (blocking `build-and-test` lists `bloch-pq-vault` but **not** `bloch-ustav`), `:658-668` (`workspace-tests` with `allow_failure: true` is the only GitLab job running `bloch-ustav`, `bloch-euvm`, `bloch-btc-wallet`), `:515-527` (`pq-shield-api` appears only as a lockfile to scan), `anchoring/.gitignore` (`Cargo.lock` ignored → excluded from `audit-all-lockfiles.sh`/osv), `Cargo.toml` root (`anchoring/` and `services/pq-shield-api/` are private workspaces, contrary to the manifest's own "NOTHING ELSE IS EXCLUDED" note at lines 32-38).
- **Description.** (1) The denylist misses `curve25519-dalek`, `x25519-dalek`, `blst`, `bls12_381`, `libsecp256k1`, `schnorrkel`, `ring`, `openssl` and any vendored/renamed fork (all of `secp256k1`, `k256`, `ecdsa`, `ed25519-dalek`, `blst`, `bls12_381`, `curve25519-dalek`, `x25519-dalek` are present in the root `Cargo.lock` for *other* crates, so a single misplaced path dependency would be caught only if its name is on the list). (2) The property that actually matters — the *kernel* has no ECDSA path — is enforced in code (`ustav.rs:42-47` `NativeVmVerifier`, `:709-711` `Custody` rejected, `:744-751` `VerifyEcdsa` rejected, `:936-961` boundary test), which is good; the script is at best a secondary signal and is absent from the pipeline the repository declares as canonical (`repository = "https://gitlab.com/bloch-protocol/bloch"`). (3) `pq-shield-api`'s seven tests and `anchoring`'s unit tests never run in CI; `anchoring` has no lockfile at all, so its `ureq`/`serde_json` pins are neither reproducible nor advisory-scanned.
- **Recommendation.** Add the boundary script and `-p bloch-ustav` to the blocking GitLab job (and to `scripts/check-tests-blocking.py`'s expected set); extend the denylist and additionally assert the *absence of any crate that links C code from a classical-crypto sys crate* (`*-sys` with `secp`/`ssl`/`sodium` in the name); commit `anchoring/Cargo.lock`; run `cargo test` for both private workspaces.
- **Confidence:** High.

---

### BV-15 — `script_eval.rs` diverges from Bitcoin Core in ways that matter for standardness, and it is the *only* thing validating the vault's scripts

- **Severity:** Low (test-only module, documented as non-consensus), but see §5 for why it matters
- **Status:** KNOWN as a limitation (`script_eval.rs:1-22`); the specific divergences are NEW
- **Refs:** `script_eval.rs:83-91` (`OP_IF` accepts any truthy value — no MINIMALIF; Core enforces it as *policy* for segwit v0, so a non-minimal selector produced by a future client change would pass this evaluator and be rejected by the network), `:121-128` (`OP_CHECKSIG` ignores NULLFAIL, never checks the sighash-type byte or low-S; Core policy rejects high-S and a failing non-empty sig), `:146` (no CLEANSTACK), `:206-220` (`decode_scriptnum` has no 4/5-byte limit and `(byte as i64) << (8*i)` panics in debug for pushes ≥ 9 bytes), no op-count/stack-size limits, `check_csv:159-169` treats a `required` value with the disable bit set as a failure whereas Core treats it as a no-op (irrelevant for Δ ≤ 65535).
- **Description.** The crate's tests "prove" only that its own model accepts its own scripts. No test runs the produced transactions through `bitcoinconsensus` (available as a feature of the `bitcoin` crate) or a regtest node. Witness ordering, `push_int` encoding of Δ, MINIMALIF selectors, and the BIP-68 maturity arithmetic are therefore unvalidated against the real network. I read them and they look correct (see §4), but that is a manual review, not a test.
- **Recommendation.** Add a `bitcoinconsensus`-backed test for each of U, branch A, branch B (valid + each negative case), and a regtest integration test script under `scripts/` that funds V, broadcasts U, asserts branch A is rejected before Δ and accepted after, and asserts the clawback confirms.
- **Confidence:** High.

---

### BV-16 — Chameleon: no chameleon hash / trapdoor exists; the actual "forgery capability" belongs to whoever supplies `TrustedBurnCheckpoint`, and it is total (any amount of the route's escrow to any PQ recipient)

- **Severity:** Info (documented and intentional in the reference implementation)
- **Status:** KNOWN — `chameleon.rs:126-138` ("Host-authenticated adapter checkpoint … Never deserialize an untrusted claim and treat its chosen root as this input"), `docs/chameleon-v1.md` "Checkpoint trust is explicit".
- **Refs:** `chameleon.rs:370-430` (`claim`: checkpoint fields are compared for route/code-hash/non-zero only; the burn root is *trusted*), `wire.rs:142-160` (`verify_inclusion`), `tests/chameleon_crypto.rs:118-126` and `examples/chameleon_roundtrip.rs:205-212` (checkpoints are literal test constants).
- **Description.** Answering the brief's question directly: there is no trapdoor hash and no trapdoor holder. The party that can forge is the host feeding checkpoints: it can construct any burn tree (`root_and_proof`) and release the entire locked backing of a route to any PQ key (`claim` checks `locked ≥ burn.amount` and a nullifier per `(route, nonce)`, so repeated forged nonces drain the route). Supply is *conserved* (escrow moves owner, `native.supply` is unchanged), so the damage is theft of backing from exporters, not inflation. The code and docs say this plainly; the risk is an integrator treating the reference host as a bridge.
- **Recommendation.** None for the kernel; keep the loud warnings. For any host, checkpoint authentication is the whole security of returns.
- **Confidence:** High.

---

### BV-17 — `hybrid_wbtc_validator` (the "Custody 2-of-2" anchor guard) is never executed in a test, and it cannot run on the PQ-only Ustav kernel the anchor is supposed to live in

- **Severity:** Info
- **Status:** NEW
- **Refs:** `crates/bloch-btc-wallet/src/lib.rs:193-208` (`Pick(3)`, `Pick(2)` stack choreography; only `validator_hash` stability is tested, `:259-269`), `crates/bloch-pq-vault/src/anchor.rs:314-316` (`anchor_guard_custody`), `crates/bloch-euvm/src/ustav.rs:42-47` (`NativeVmVerifier` maps only `verify_pq`; `VerifyEcdsa` returns false), `:744-751` (any compiled program containing `VerifyEcdsa` is `ClassicalPolicyNotAllowed`), spec §7 L406-407 ("`Custody` 2-of-2 recommended for high value").
- **Description.** The recommended high-value anchor guard is an ECDSA+PQ program; the only PQ-native ledger in the repo (Ustav v3) refuses exactly that shape by design (ADR-040 amendment). The recommendation and the kernel are mutually exclusive, and the program's redeemer layout has no execution test (the euvm test at `lib.rs:922-937` tests a *different* program that pushes the signatures as constants).
- **Recommendation.** Either drop the Custody guard from the pq-vault docs/API (`bloch_custody_guard_hash`) or state it targets the legacy Genesis-3 eUVM only; add an execution test with real ECDSA+PQ signatures through `bloch_euvm::run`.
- **Confidence:** High.

---

### BV-18 — Documentation overclaims relative to the code (collected)

- **Severity:** Info
- **Status:** NEW (individual items cross-referenced)
- **Refs & claims:**
  - `services/pq-shield-api/README.md:63-65`: "Bitcoin enforces the hash+timelock half, **Bloch enforces the PQ half**" — no code posts, orders, or checks anchors on Bloch; `bloch-euvm` is not consensus-wired (`lib.rs:55-58`).
  - `README.md:60-62`, `vault.rs:18-23`, API response strings ("PQ-gated clawback"): after U, `r` is public, so branch B is gated by `recovery_sk` alone (spec §2.2 admits this; the short-form marketing strings do not).
  - `vault.rs:172-173`, `lib.rs:531`: "watchtower can fee-bump" — BV-02.
  - `lib.rs:34-38`, spec §2.0(2)/§4 step 3: "secure deletion of the deposit bypass key" — BV-01 (no such key).
  - `pq-shield-api/README.md:25`: "Read … the security audit before shipping value" — no such audit document exists in the tree (§1.2).
  - Spec header L3-6: "No code in this repo implements this yet" — stale; `crates/bloch-pq-vault` implements it.
- **Recommendation.** One pass to align the three layers (spec, crate docs, API README/strings) with §3 below.
- **Confidence:** High.

---

### BV-19 — Minor robustness items in `bloch-btc-wallet` / `bloch-pq-vault` derivation

- **Severity:** Info
- **Status:** KNOWN (documented in code) except the regtest note
- **Refs:** `crates/bloch-pq-vault/src/lib.rs:131-138` (`derive_vault_keys` V1 keeps `.expect()` panics on a short seed by design), `crates/bloch-btc-wallet/src/lib.rs:92-98` (V1 `PqSeedKdf::V1RawSeedReuse` reuses `seed[..32]` verbatim as the ML-DSA/Falcon keygen seed, I-13), `:131-134` (`KnownHrp::Testnets` only — `derive_identity(seed, false)` cannot produce `bcrt` addresses although the vault tests run on `Network::Regtest`).
- **Description.** Nothing new to exploit; noted so the lead can see the full V1/V2 compatibility surface. `bloch_crypto::generate_keypair_from_seed` is real now (seeded RNG via the vendored `pqcrypto-internals`), closing groundstate C-2.
- **Confidence:** High.

---

### BV-20 — `guard_no_secrets` inspects key names only; a secret placed in a free-form value passes and is echoed back; `deny_unknown_fields` is ineffective on the flattened `AnchorVerifyReq`

- **Severity:** Info
- **Status:** NEW
- **Refs:** `services/pq-shield-api/src/lib.rs:100-131`, `:308` (`policy: String` echoed into `commitment_bytes_hex`), `:318-335` (`#[serde(deny_unknown_fields)]` + `#[serde(flatten)] fields: Option<AnchorFields>` — serde documents that `deny_unknown_fields` is not supported with `flatten`).
- **Description.** The guard is a best-effort tripwire and is described as "enforcement" (`lib.rs:16-20`, README L14-17). A client that pastes a WIF into `policy` gets it committed into the anchor bytes. No server-side impact; the wording over-promises.
- **Recommendation.** Describe the guard as best-effort; optionally scan values for WIF/xprv/hex-64 patterns as a warning.
- **Confidence:** High.

---

### BV-21 — `anchoring/` convention: first-`BLA1`-output heuristic, no signer binding, non-consensus tx codec

- **Severity:** Info
- **Status:** KNOWN (README "honest limitation" section; `tx.rs:1-15`)
- **Refs:** `convention.rs:104-121` (returns the first output starting with `b"BLA1"`; a genuine P2PKH hash matches with probability 2⁻³²; a tx with two anchors yields only the first), `sdk.rs:177-228` (`MockSigner` does no coin selection/fees/change), `commitment.rs:53-62` (domain-separated, length-prefixed SHA3-256 — good).
- **Description.** The commitment format itself is sound. An `InclusionReference` proves "a tx with this txid at this height carried these 32 bytes", nothing about who anchored them; anyone can anchor anything. Fee/change/UTXO selection are delegated to an unimplemented `TxSigner`, so "tx construction (fee, change, UTXO selection, dust)" has no code to audit beyond the 1-sat burn default (`convention.rs:59`), whose acceptability depends on Bloch's (unstated here) dust policy.
- **Confidence:** High.

---

## 3. pq-vault: the security property actually delivered vs. the documented claim

**Documented claim (spec §0, §2.2, §4.1, §6; crate `lib.rs:1-22`; API README L19-26, L59-65):** a *commit-delay-reveal vault* on stock Bitcoin in which (i) the deposit can only be spent through a delayed trigger, (ii) during the delay the owner (or a non-custodial watchtower that "cannot steal") can claw back with a *PQ-authorized* path, (iii) "Bitcoin enforces the hash+timelock half, Bloch enforces the PQ half", and (iv) the whole thing is "transition-era defense-in-depth" against a CRQC.

**What the code actually delivers, in plain language:**

1. **At rest, V is a P2WSH output.** Its script (two hashes, one pubkey) is hidden. This is real and is the strongest property in the crate. It is also exactly what any P2WSH/P2WPKH output already gives you; the vault adds nothing at rest.

2. **To spend V you need `hot_sk` AND a 32-byte secret `r` that was derived from the PQ key at setup.** This is a genuine second factor against a *classical* leak of `hot_sk` alone. It is the only place the PQ key contributes anything, and it contributes it once: `r` becomes public the moment V is spent.

3. **There is no covenant and no way to emulate one with these keys (BV-01).** Anyone holding `hot_sk` + `r` can send V anywhere immediately. The "delay" applies only to spenders who *choose* to route through T. Against the hot-device-compromise threat the vault provides no delay at all.

4. **Once U is broadcast, T's branch B is protected by `recovery_sk` alone** — `r` is public (spec §2.2 says so; the "PQ-gated clawback" wording does not). Branch B has no destination restriction; whoever holds `recovery_sk` after an unvault can take the coins.

5. **Branch A's CSV delay is correctly encoded** (BIP-68/112, block-based, `nSequence = Δ`, tx v2, `OP_CSV OP_DROP`, minimal selectors) and, for Δ ≥ 1, the network will indeed refuse a branch-A spend for Δ blocks after T confirms. This is the one property a CRQC observer cannot bypass. Δ = 0 is accepted (BV-05).

6. **The anchor is an offline signed record.** `verify_anchor` tells a party that *already trusts a PQ pubkey* that the owner committed to `{V address, H(r), safe dest, Δ, policy}`. Nothing on Bitcoin reads it; nothing on Bloch stores or orders it (no posting code exists); it has no rotation semantics (BV-07). It constrains only an honest watchtower's *choice* of destination. "Bloch enforces the PQ half" is not true of any code in the repository.

7. **The watchtower model as written cannot exist (BV-02):** a watchtower that can only broadcast the pre-signed clawback cannot fee-bump; one that can fee-bump holds `recovery_sk` and can steal. "Griefing only, never theft" holds for the first kind, "can win the fee race" only for the second.

8. **Against the stated adversary (CRQC watching the mempool):** the honest bottom line is: *if* the owner unvaults, *and* the CRQC's `T_shor` on `hot_pubkey` exceeds Δ, *and* the owner or a `recovery_sk`-holding watchtower gets a clawback confirmed before the CRQC derives `recovery_sk` from the clawback's own mempool-revealed `recovery_pubkey` and RBF-races it, the owner keeps the coin at a fresh address. Every clause is required. The spec's §9 states most of these; the crate/API summaries do not.

**Net:** the crate is a correct, standard implementation of "P2WSH hash-locked deposit → OP_IF { CSV-delayed hot spend | immediate recovery spend }" with a PQ-derived hash preimage. It is not a vault in the Revault/deleted-key sense, its watchtower story is internally inconsistent, and its PQ component is a setup-time factor plus an off-chain signed note. A user who reads the HONEST LIMITS gets most of this; a user who reads the API README or the response strings does not.

---

## 4. Positive observations

- **Bitcoin script construction is correct where it is implemented.** `deposit_script`/`trigger_script` are minimal and standard; `push_int(Δ)` yields minimal scriptnums (`OP_N` for 1–16, 2-byte LE for 144); `OP_CSV OP_DROP` is right; branch selectors are `0x01`/empty (MINIMALIF-clean); tx version 2; `LockTime::ZERO`; deposit input `nSequence = 0xfffffffd` (BIP-68 disabled, RBF signalled); branch-A `nSequence = from_height(Δ)` (type bit clear, matches the block-based script value). BIP-143 sighash is computed with the witnessScript as scriptCode and the correct amount; the e2e tests verify real secp256k1 signatures. Trigger script ≈113 bytes, well within P2WSH limits. Segwit txids are non-malleable, so pre-signed clawbacks referencing `U`'s txid are safe against witness malleation.
- **Commit/reveal MEV is *not* a problem here:** every spend is signature-gated in addition to the hash, so a mempool observer who sees `r` cannot front-run U or the clawback without the corresponding private key (classically). The remaining race is the CRQC one the spec admits.
- **`preimage.rs` is consistent:** HKDF-SHA256 with fixed salt and domain-tagged info, 32-byte output, single SHA-256 commitment — matching `OP_SHA256` (not HASH160, not SHA256d). Domain separation is injective (fixed-length prefix).
- **Anchor verification was fixed correctly (K-M6):** identity comes from the verifier, not the blob; tamper tests cover destination, `H(r)`, Δ, transplanted signatures, unsupported versions, and Δ width truncation; `deserialize` bounds every length against the buffer (no allocation before bounds check).
- **`bloch_crypto::verify` and `sign` are panic-free on malformed input** (envelope parse → `false`/`Err`; body length guards before `from_bytes`), so `/anchor/verify` with garbage `trusted_pq_pubkey`/`signature` returns `valid:false`, not a crash.
- **pq-shield-api input handling is careful in the places it looks:** 33-byte compressed pubkeys parsed through `PublicKey::from_slice`, 32-byte hashes, txids parsed, `network` whitelisted, destinations validated for the request's network, `deny_unknown_fields` on DTOs, `fee ≥ amount` rejected, Δ `u16` at the edge, no request logging, no outbound requests (no SSRF surface), no state (no CSRF impact), timeout + concurrency ceiling (L-16).
- **Ustav kernel (`bloch-euvm::ustav`) invariants are enforced with checked arithmetic:** `sum(inputs) + delta == sum(outputs)` in `i128` (`ustav.rs:427-429`), `0 ≤ supply + delta ≤ cap` (`:430-435`), `|delta| ≤ u64::MAX` (`:168-170`), positive amounts, strictly-sorted unique inputs (no double-spend within a tx), mint-nonce monotonicity, policy-revision binding, expiry, output-collision check, all validation before any mutation (`:479-495`), snapshot restore re-checks `sum(UTXOs) == supply` and an *externally supplied* root. Every input requires an owner PQ signature; every output owner is admitted through `valid_pq_key` (suite 0x0001, exact 3749-byte body, Falcon header/coefficient check — a real structural check the PQClean wrapper does not do).
- **PQ-only boundary is enforced in code, not just by the script:** `Custody` charters rejected at registration and restore, compiled programs containing `VerifyEcdsa` rejected, the VM adapter never routes ECDSA to the PQ callback (tested at `ustav.rs:936-961`), legacy raw (non-enveloped) keys/signatures rejected at admission. `bloch-euvm` itself depends only on `sha2`/`sha3`.
- **Chameleon accounting is conservative:** export locks rather than burns, `claim` moves ownership without changing supply, nullifiers are permanent, restore re-derives `exported − returned == locked` per route, and the export authorization digest is distinct from the plain transfer digest (tested).
- **Domain-separated, length-prefixed encodings everywhere** (`encoding.rs`, `anchor.rs`, `commitment.rs`, `wire.rs`), with independent Python-computed KATs pinned for Ustav.

---

## 5. Test-coverage gaps

1. **No consensus-grade validation of the vault scripts** (BV-15): no `bitcoinconsensus` feature test, no regtest run. The e2e tests validate `script_eval`'s model of Bitcoin, not Bitcoin.
2. **No negative test for `csv_delay = 0`** or below the spec minimum (BV-05).
3. **No test that a watchtower can actually bump a clawback** — the claim is only prose (BV-02).
4. **No test that V cannot be spent except via U** — because it can (BV-01); a regtest test would have surfaced this.
5. **No test of anchor rotation / two competing anchors** (BV-07).
6. **No fuzz target for `SignedAnchor::deserialize`** or for `guard_no_secrets`/`parse_guarded` (the repo's `fuzz/` covers other parsers; `SECURITY.md:135-137` says "new parsers of untrusted bytes get a target").
7. **pq-shield-api tests call handlers directly**; only one test goes through `router()`. No test sends an empty or oversized `pq_recovery_pubkey` (BV-06), an oversized body, or a wrong-network address to `/anchor/commitment`.
8. **`hybrid_wbtc_validator` never executed** (BV-17).
9. **bloch-btc-wallet has no BIP-32 vector for index 1 / the `1998'` branch** and no test asserting hot/recovery are not unhardened siblings (BV-04).
10. **anchoring**: `HttpTransport` untested (feature-gated, no mock HTTP server); `decode` has no test for a tx with two anchors or an anchor at the last output; no lockfile.
11. **Ustav**: no property-based/fuzz test over `apply` sequences for supply conservation (the audit tests in `bloch-euvm/tests/audit_conservation.rs` target the legacy VM path; `ustav_kernel.rs` has hand-written cases only); Governance quorum with duplicate signer slots and `threshold > signers` are covered by Kirpich tests but not by an end-to-end kernel test with real PQ keys (`crypto_kernel.rs` covers 2-of-2 only).
12. **CI:** `bloch-ustav` tests are non-blocking in GitLab; `pq-shield-api` and `anchoring` tests run nowhere (BV-14).

---

## 6. Residual risk / not covered

- **Out of my scope but load-bearing:** `bloch-crypto`'s Falcon/ML-DSA verification internals, `bloch-euvm`'s VM (`run`, `compile_governance`, Kirpich lanes) and the SMT (`state.rs`) are relied upon by both the anchor guard and the Ustav kernel; I read only their entry points. Another auditor owns them.
- **Bitcoin-network behaviour was reasoned, not executed:** standardness (dust thresholds, MINIMALIF policy, `maxfeerate`) is from Bitcoin Core knowledge, not a live node. A regtest run is the right follow-up (§5 item 1).
- **Crate-default assumptions:** axum 0.7 `Bytes` body limit (2 MiB) and ureq 2 timeout/TLS defaults were not re-verified from source in this environment (sources for those exact versions were not in the local registry); confidence is stated per finding.
- **Miner-side:** a miner (or a majority) can censor the clawback for Δ blocks or select the CRQC's higher-fee branch-B replacement; nothing in the design can address this and the spec does not claim to. Δ=144 vs. mining-pool concentration is a policy question, not a code one.
- **Key-loss matrix (adversary (c)) summary:** lose `hot_sk` → re-derive (seed). Lose `recovery_sk` → no clawback, branch A still works. Lose `pq_sk` with `r` cached → vault still operable, no anchor rotation. Lose `pq_sk` and `r` → V unspendable (hash-gate). Leak `hot_sk`+`r` → total loss, no delay (BV-01). Leak `recovery_sk` → theft on next unvault. Leak `pq_sk` → anchor forgery/rotation ambiguity (BV-07), `r` computable. All keys derive from one seed in both V1 and V2 (`lib.rs:8-9`), so "lose one key" is rarely the real failure mode; "lose the seed" is, and it is total, as documented.
- **Ustav at L1** (ADR-040) is direction only; the kernel is not consensus-wired, so everything in §2 about Ustav is about a library, not a live ledger. Wire codec, block binding, persistence and fee calibration (`docs/ustav-kernel.md` items 1-6) do not exist and were not audited.
- **Chameleon EVM side** (`bloch-l2-bridge`, Solidity adapter, `FrozenExportRootVerifier`) is outside this repository and was not reviewed; `examples/chameleon_roundtrip.rs` requires it to run.
