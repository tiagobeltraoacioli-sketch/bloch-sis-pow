# Bloch-SIS Protocol — Standalone Specification (v0.1, frozen-for-audit draft)

**Status: advisory / design-freeze draft. This is a PLAN and a description of the
code as it exists, NOT a claim of security.** No cryptographic audit has been
performed. Nothing here is "secure," "proven," "audited," or "quantum-safe." The
coin has no value and is not a security; no revenue touches the token. This
document is not legal or financial advice.

This spec exists so an external auditor does not have to reverse-engineer intent
from the source. Every normative statement is grounded in a cited `file:line` in
the repository at the time of writing. **Where a roadmap document and the code
disagree, this spec follows the CODE and flags the divergence.** Discrepancies
found during authoring are collected in §11.

Roadmap item this fulfils: P0.2 (standalone protocol spec + explicit threat
model) from `roadmap-crypto-core.md` §3.1. The companion threat model is
`docs/THREAT-MODEL-AUDIT.md` (alongside the existing `docs/THREAT-MODEL.md` and
`docs/THREAT_MODEL.md`).

---

## 0. Scope and conventions

- **In scope:** the hybrid signature construction; key/address derivation; the
  transaction, block and P2P wire formats; the transaction sighash; the
  Bloch-SIS Proof-of-Work; and the consensus validity + fork-choice rules.
- **Out of scope here (documented elsewhere):** wallet-at-rest encryption
  (`wallet/encryption.rs`), the shielded/Coherence pool, the Postern product
  crates, and the attestation ("seal") layer — the blockchain-repo attestation
  hooks are stubs.
- **Endianness:** all integers are little-endian on the wire unless a structure
  is explicitly Bitcoin-compatible (still LE) or a hash comparison is stated as
  big-endian.
- **Hashes:** `SHA3-256` and `SHAKE-256` (Keccak) for Bloch-native structures;
  `SHA-256d` (double SHA-256) only where Bitcoin/stratum compatibility is
  required (mining header, txid, merkle trees).

---

## 1. Hybrid signature construction (FROZEN)

**File:** `crates/bloch-crypto/src/crypto/mod.rs`.

### 1.1 Algorithms and byte layout

The signer is a **concatenation hybrid of two distinct lattice families**:
ML-DSA-65 (Module-LWE/SIS, FIPS 204, via `pqcrypto-mldsa 0.1`) and Falcon-1024
(NTRU, via `pqcrypto-falcon 0.4`). The wire order is **ML-DSA first, Falcon
second** — this is load-bearing and is the single most important fact for a
second implementer (see §11 for the naming inconsistency in code comments).

Fixed ML-DSA-65 lengths (`crypto/mod.rs:20-22`):

| Constant | Value (bytes) |
|---|---|
| `MLDSA_PUBKEY_LEN` | 1952 |
| `MLDSA_SECRET_LEN` | 4032 |
| `MLDSA_SIG_LEN`    | 3309 |

**Suite-ID envelope (Roadmap #1 — crypto-agility, hard fork).** Every public key,
secret key and signature is wrapped in a **4-byte suite header** so the verifier
dispatches on an in-band algorithm identifier instead of fixed offsets:

```
byte 0     : 0xB1  ┐ 2-byte magic "B1 0C" (distinguishes an enveloped object
byte 1     : 0x0C  ┘ from a legacy raw ML-DSA blob; a mismatch ⇒ verify false)
bytes 2..4 : suite_id : u16 LE
```

Suite registry (`crypto/mod.rs`): `0x0000` reserved/invalid; `0x0001 =
SUITE_MLDSA65_FALCON1024` (today's hybrid); `0x0002 = SUITE_MLDSA65_ONLY`
(ML-DSA-65 only, the "Falcon removed" suite, present as a concrete proof Falcon is
removable — no live output uses it yet); `0xFFFF` reserved. Unknown/reserved suite
⇒ verify returns `false` (never panics). NOT a security claim; unaudited.

Composite objects, **suite 0x0001** (`magic ‖ 01 00 ‖ body`):

```
public_key = HDR(4) ‖ mldsa65_pk(1952)  ‖ falcon1024_pk(1793)      → 3749 bytes
secret_key = HDR(4) ‖ mldsa65_sk(4032)  ‖ falcon1024_sk(2305)      → 6341 bytes
signature  = HDR(4) ‖ mldsa65_sig(3309) ‖ falcon1024_sig(variable) → 3313 + Falcon tail
```

The Falcon-1024 signature is **variable length** (Falcon emits a
compressed/variable signature). The verifier does NOT length-check the Falcon
tail; it strips the 4-byte header, then splits the body at the fixed ML-DSA offset
and passes the remainder to Falcon verify. Size constants used only for fee/size
estimation (not consensus) live at `core/mod.rs`: `PUBKEY_SIZE=3749`,
`PRIVKEY_SIZE=6341`, `SIG_SIZE=4775` (header + hybrid; Falcon max tail 1462).

### 1.2 Verify semantics — AND-combiner, parse-failure ⇒ false

`verify(pk_env, msg, sig_env)` first parses the 4-byte envelope on BOTH the pk
and the sig (parse failure — len<4 or bad magic — ⇒ `false`), requires
`pk_suite == sig_suite`, then dispatches on the suite. For **suite 0x0001** the
body is verified by the **strict AND-combiner** below (identical to the
pre-envelope path, now on the post-header `*_body` slices); suite 0x0002 verifies
an ML-DSA-65-only body; any other suite ⇒ `false`:

1. If `pk_body.len() <= 1952` **or** `sig_body.len() <= 3309`, return `false`.
   Note the comparison is `<=`, so a signature with a zero-length Falcon tail is
   rejected.
2. Split `pk` at 1952 → `(mpk, fpk)`; split `sig` at 3309 → `(msig, fsig)`.
3. Parse `mpk` and `msig`; **any parse error ⇒ return `false`**
   (`crypto/mod.rs:118-125`). This is the documented "Audit L-1 fix" and is a
   **consensus rule**: a malformed signature MUST be treated as invalid, never as
   an error that aborts validation.
4. If ML-DSA `verify_detached_signature` fails ⇒ return `false`.
5. Return the Falcon half's result: `falcon::verify(fpk, msg, fsig)`
   (`crypto/mod.rs:130`, `311-319`). Falcon verify itself returns `false` on any
   parse failure.

**BOTH halves must verify** for `verify` to return `true`. Rationale as coded
(`crypto/mod.rs:282-290`): a cryptanalytic break of one lattice family does not
by itself forge a signature. Auditor note: this is EUF-CMA-robust only because
both halves sign the **identical** `message` byte string — there is no distinct
per-half message transform. Hybrid-boundary tamper tests now exist
(`golden_vector_verifies_and_rejects_tampering` flips each half; the envelope
negatives cover bad-magic / unknown-suite / suite-mismatch / header-only;
`tests/sprint_b6_hybrid_sig.rs` covers the both-halves-required property).

### 1.3 Signing

`sign(sk, msg)` (`crypto/mod.rs:89-100`): split `sk` at 4032, ML-DSA
`detached_sign` then append `falcon::sign`. ML-DSA signing is **hedged/randomized**
(FIPS 204 default) — two signatures over the same message differ. Falcon signing
uses floating-point Gaussian sampling and is **not constant-time** (side-channel
exposure inherited from the PQClean C library; see the threat model). Verification
of both halves is deterministic/integer and therefore consensus-safe.

### 1.4 Deterministic keygen from seed

`generate_keypair_from_seed(seed)` (`crypto/mod.rs:62-87`):

- Requires `seed.len() >= 32`; uses **only the first 32 bytes** as a ChaCha20
  key (longer seeds are truncated, not hashed — caller's responsibility).
- Installs a **thread-local ChaCha20-seeded RNG** that overrides PQClean's
  `PQCRYPTO_RUST_randombytes` for the duration of the two `keypair()` calls, via
  the **vendored fork** of `pqcrypto-internals` (`with_seeded_rng`,
  `crates/pqcrypto-internals/src/lib.rs`; wired through `[patch.crates-io]` in
  the root `Cargo.toml`).
- An RAII guard restores the OS RNG on drop, so the override does not leak into
  later `generate_keypair()` calls (`crypto/mod.rs:78`, test at `254-262`).
- Guarantee: same 32-byte seed ⇒ **byte-identical** `(pk, sk)` on any platform
  supported by `pqcrypto-mldsa 0.1`. ML-DSA keygen is deterministic-from-seed
  (FIPS 204 Alg. 6). **Falcon keygen is deterministic only given the byte stream,
  with a documented floating-point-platform caveat** (`crypto/mod.rs:79-81`) —
  relevant to reproducible wallet recovery, NOT to consensus verification.
- **Crypto-agility caveat (frozen behaviour):** the seed→keypair mapping is
  pinned to `pqcrypto-mldsa 0.1.x`. A future crate upgrade that changes keygen
  order would produce different keypairs from the same seed
  (`crypto/mod.rs:49-55`). Wallet files should record the crate version.

The seeded-RNG override is the highest-leverage line of unreviewed code in the
tree: it silently changes the RNG for **all** PQClean crates on that thread. An
invariant (no seeded guard alive across a `sign()`) is asserted only by
convention today.

---

## 2. Key and address scheme (FROZEN)

**Files:** `crypto/mod.rs:133-183`, `crates/bloch-crypto/src/address.rs`,
`core/mod.rs:15-16`.

### 2.1 Address derivation

```
h20      = SHA3-256(public_key)[0..20]              (20-byte pubkey hash)
inner    = SHA3-256(h20)
outer    = SHA3-256(inner)
checksum = outer[0..4]
payload  = h20 ‖ checksum                           (24 bytes)
address  = prefix ‖ hex(payload)                    (prefix + 48 hex chars)
```

Prefixes (`core/mod.rs:15-16`): `bloch1q` (mainnet), `bloch1t` (testnet). The
network tag is part of the human-readable string ONLY; it is **not** committed
into the 20-byte hash or the checksum. Parsing/validation is in
`address.rs:65-98` (prefix, exactly 48 hex chars → 24 bytes, checksum equality).

The on-chain commitment is the bare 20-byte hash: `script_pubkey` is exactly
`SHA3-256(pubkey)[0..20]`, where `pubkey` is now the **enveloped** public key
(4-byte suite header ‖ body — §1.1). **This is P2PKH-equivalent: one hybrid
signature authorises one input. There is no script/opcode system, no multisig, no
timelock predicate.**

**Crypto-agility (Roadmap #1 — addresses now suite-committing).** Because the
address hashes the enveloped pubkey (header included), a `SUITE_MLDSA65_ONLY` key
and a `SUITE_MLDSA65_FALCON1024` key with the same ML-DSA body hash to **different**
addresses. This closes the earlier gap where an address's security was the min over
any suite whose pubkey could hash to the same 20 bytes: the suite is now bound by
the address. The spend-time check (`SHA3-256(pk)[..20] == script_pubkey`) is
unchanged and Just Works — both sides hash the same enveloped bytes. NOTE: this
changed every pubkey, signature, and address — a hard fork bundled pre-mainnet.

### 2.2 Diversified (unlinkable) addresses

`diversified_seed(master, i) = SHA3-256("bloch:diversifier:v1" ‖ master ‖
i.to_le_bytes())` (`crypto/mod.rs:149-155`), then an **independent** hybrid
keypair per index via `generate_keypair_from_seed` (`crypto/mod.rs:158-170`).
These are independent keypairs recoverable from the master seed — **not**
view/spend stealth addresses (no scan key; a sender cannot derive them).

### 2.3 Seed phrases / HD wallet (context; out of the consensus surface)

BIP39 24-word default; `to_seed_bytes` = PBKDF2-HMAC-SHA256, 2048 rounds, salt
`"mnemonic"` (`wallet/seed.rs`). The "HD wallet" (`hd_wallet/mod.rs`) stores each
address as an independently generated keypair encrypted under a master key — it
is **not** lattice-HD derivation, and recovery requires **both** the mnemonic and
the wallet file. Note two non-unified notions of "derived key" coexist
(`diversified_keypair` is seed-deterministic; the HD wallet is not).

---

## 3. Proof-of-Work — Bloch-SIS-PoW (FROZEN structure, UNFROZEN security params)

**Crate:** `crates/bloch-sis-pow`. This is a **SHAKE-256 hashcash with a
Module-SIS structural gate.**

> **SECURITY HONESTY (verbatim intent from `lib.rs:16-26`):** the PoW's security
> is the **cumulative hashcash work** of the aux-hash target, **NOT lattice
> hardness**. A trapdoorless PoW cannot be both lattice-hard and mineable. **No
> "N-bit lattice security" number attaches to this PoW at any parameter set.**
> The Module-SIS residual is a *structural gate*, not the security source. The
> post-quantum property is SHAKE-256's (Grover: quadratic speedup only).

### 3.1 Parameters (`params.rs`)

| Symbol | Constant | Value | Note |
|---|---|---|---|
| `N` | `params::N` | 256 | solution dimension, `s ∈ {−B..B}^N` |
| `M` | `params::M` | 512 | full row dimension of `A` (`m = 2n`) |
| `q` | `params::Q` | 8 380 417 = 2²³−2¹³+1 | identical to ML-DSA-65 (shared NTT aspiration) |
| `B` | `params::B` | 2 | `‖s‖_∞ ≤ B`, coeffs in `{−2,−1,0,1,2}` |
| `β` | `params::BETA` | q/16 = 523 776 | residual bound, `‖A·s − t‖_∞ < β` |
| `POW_SEED_LEN` | | 64 | SHAKE seed length |
| `AUX_HASH_LEN` | | 32 | aux hash / target width (256-bit) |

**`β = q/16` is loose and NOT security-validated** (`params.rs:14-20, 100-113`).

### 3.2 Solution validity

A solution is `(nonce ν: u64, s: [i32; 256])`. Verify (`verify.rs:83-141`,
pseudocode `verify.rs:13-25`) checks, for a given residual width `k`:

1. **Norm:** `‖s‖_∞ ≤ B` (else `SolutionTooLarge`) — `verify.rs:103-105`.
2. **Seed:** `seed = SHAKE256_dom(DOMAIN_LABEL_POW_SEED, [header, ν.to_le_bytes()], 64)`
   (`solver.rs:246-253`). NB: `shake256_dom` length-prefixes every field
   (§3.4), so the seed is domain-separated and unambiguous — it is **not** a raw
   `header‖ν` concatenation.
3. **Expand:** `(A, t)` for the first `k` rows via rejection sampling of 23-bit
   chunks `< q` (`expand.rs:29-95`). `A` uses sub-label `"MATRIX-A"` under
   `DOMAIN_LABEL_POW_SEED`; `t` uses sub-label `"VECTOR-T"` under
   `DOMAIN_LABEL_TARGET` — so `A` and `t` are independent. The first-`k`-row
   prefix is bit-identical to the full expansion (a pure speedup, no consensus
   change) — `expand.rs:62-74, 104-111`.
4. **Residual:** `r = center_mod_q(A·s − t)` over the first `k` rows; require
   `‖r‖_∞ < β` (else `ResidualTooLarge`) — `matrix.rs:71-81`,
   `field.rs:22-34`, `verify.rs:115-123`.
5. **Aux hash / difficulty:**
   `aux = SHAKE256_dom(DOMAIN_LABEL_POW_AUX, [encode(s), ν.to_le_bytes(), header], 32)`;
   require `aux < target` as a 256-bit **big-endian** integer, strict `<`
   (`verify.rs:125-138`, `difficulty.rs:151-161`). Byte order of the operands is
   `encode(s) ‖ ν ‖ header`.

`encode(s)` (`encode.rs:21-43`) packs each coefficient as one signed byte (`i8`),
256 bytes total; it **rejects** any `|coeff| > B` and wrong lengths.

### 3.3 The height-gated k-regime and soft fork SF-1

The residual width `k` is the only thing that changes with height. It is
**single-sourced** through `bloch_crypto::core::canonical_residual_coeffs(height)`
(`core/mod.rs:151-158`), which both the validator (`Block::validate_pow`) and the
node PoW mirror (`src/pow/mod.rs:134-149`) call, so miner and verifier cannot
diverge.

| Regime | `k` | Constant | Structural rejection floor ≈ `k·log2(q/2β) = 3k` bits | Security |
|---|---|---|---|---|
| Testnet (pre-activation) | 4 | `TESTNET_RESIDUAL_COEFFS` (`lib.rs:115`) | ~2¹² | **ZERO by design** |
| Canonical (post-activation) | 8 | `CANONICAL_RESIDUAL_COEFFS` (`lib.rs:162`) | ~2²⁴ | candidate; still hashcash-only |
| Full-`M` compat | 512 | `params::M` | — | **broken both ways** (see below) |

- **k = 4 is explicitly ZERO security** (`lib.rs:109-115`). Testnet mining is
  gated only by the relaxed residual plus an easy aux target.
- **Soft fork SF-1 (k: 4 → 8)** is a pure *tightening*: because the residual
  check inspects the first `k` coefficients, any `k=8`-valid solution is
  automatically `k=4`-valid (prefix subset) — old nodes accept new-rule blocks
  (no partition); a `k=4`-only solution fails `k=8` with prob ≈ 1 − 8⁻⁴
  (`lib.rs:155-161`). A compile-time assert enforces `CANONICAL ≥ TESTNET` so a
  future edit cannot silently turn this into a chain-splitting loosening
  (`lib.rs:177-181`).
- **k = 8 buys ~2²⁴ rejection floor, NOT security.** The floor is amortised into
  the aux-hash grind and is not the security source; k = 8 is the *candidate*
  canonical width pending the no-shortcut / attacker-asymmetry proof
  (`lib.rs:143-162`).
- **Full-`M` at β = q/16 is broken in both directions:** simultaneously in the
  trivial q-ary regime (`√M·β ≥ q`, no lattice hardness) AND infeasible to
  honestly mine. It is retained for wire-compat and regime-separation tests only
  (`verify.rs:55-71`, `src/pow/mod.rs:196-212`).

**Guardrail S1** (`lib.rs:129-171`): `residual_regime_nontrivial(k,β,q) ≡
k·β² < q²` is asserted at **compile time** for both k=4 and k=8, and via
`debug_assert!` in `mine`/`verify_regime` for any runtime width. This keeps the
gate structurally non-trivial; it is defensive engineering, not a security proof.

**Activation height is a PLACEHOLDER.** `CANONICAL_K_ACTIVATION_HEIGHT =
1_000_000` (`core/mod.rs`) is a clearly-future placeholder that **MUST be set
to `current tip + safety margin` before any live SF-1 deploy**, with every mining
node upgraded before the chain reaches it. There being no live mainnet, the
constant deliberately STAYS at the placeholder; a named `PLACEHOLDER_ACTIVATION_HEIGHT`
mirror plus a **CI guard** (`core/mod.rs`, test `mainnet_release_guard::
canonical_k_activation_height_is_set_for_mainnet`, gated behind a `mainnet` cargo
feature) fails a mainnet artifact whose height is still the placeholder, is
`u64::MAX`, or is implausibly large. Default `--features node` builds do not
compile the guard and keep the placeholder green; the guard bites only when a
mainnet release is cut. (The compile-time `CANONICAL ≥ TESTNET` assert stays
independent and valid.)

### 3.4 Domain separation (`shake.rs`)

Every PoW SHAKE call routes through `shake256_dom(label, inputs, out_len)`
(`shake.rs:47-62`), which writes the **label** length-prefixed, then each input
length-prefixed (`u64` LE length ‖ bytes) — `feed_with_len`, `shake.rs:25-28`.
This makes concatenations unambiguous (`SHAKE("foo"‖"bar") ≠ SHAKE("foob"‖"ar")`,
test `shake.rs:130-138`). The three context labels (each change is a hard fork):
`BLOCH-POW-SEED-V1`, `BLOCH-POW-AUX-V1`, `BLOCH-POW-TARGET-V1`
(`lib.rs:183-194`).

### 3.5 Difficulty — ASERT-Lattice (`difficulty.rs`)

- Target block time **30 s** (`difficulty.rs:20-21`, `TARGET_BLOCK_TIME = 30`).
  See §11 — a stale code comment elsewhere says "150s".
- ASERT half-life **2 days** (`ASERT_HALFLIFE = 172800`, `difficulty.rs:23-24`).
- Per-step clamp **±4×** (`MAX_FACTOR_NUMERATOR/DENOMINATOR = 4/1`,
  `difficulty.rs:32-34`; e_milli clamped to ±2000 milli, `difficulty.rs:225`).
  A prior "audit H3" bug made the integer exponent a byte shift, silently turning
  the clamp into ±65536×; it is fixed to a true bit shift (`difficulty.rs:239-241`).
- `bits` is a **Bitcoin-compact** 32-bit encoding: `exponent = bits>>24`,
  `mantissa = bits & 0x007FFFFF`; the `0x00800000` sign bit and zero mantissa map
  to `Target::MIN` (nothing passes) — `difficulty.rs:73-81`. `Target` is a
  256-bit big-endian byte array (`difficulty.rs:43-53`).
- `work_from_bits(bits) ≈ 2²⁵⁶ / target`, approximated on the **top 16 bytes** of
  the target into a `u128` (`src/pow/mod.rs:59-70`). This feeds GhostDAG
  accumulated work.

The solver (`solver.rs`) is brute-force with a non-cryptographic SplitMix64 RNG
choosing which candidate is tried — fine, since it only selects among valid
solutions, and all PoW inputs (`A, t, s`) are public, so PoW constant-timeness is
not security-relevant. The "shared NTT with ML-DSA" is aspirational, not
implemented (naive O(m·n) matmul, `matrix.rs`).

---

## 4. Transaction wire format (FROZEN)

**File:** `core/mod.rs:625-975`.

### 4.1 Structures

```
TxInput  { prev_txid:[u8;32], prev_index:u32, script_sig:Vec<u8>, sequence:u32 }
TxOutput { value:u64, script_pubkey:Vec<u8> }          // script_pubkey = 20-byte hash
Transaction { version:u32, inputs:Vec<TxInput>, outputs:Vec<TxOutput>, locktime:u32 }
```

`script_sig` encoding (`core/mod.rs:627, 908-930`):
`[sig_len: u32 LE][sig][pubkey_len: u32 LE][pubkey]`. Built by
`build_script_sig`, parsed by `parse_script_sig` (returns `None` on any
length/bounds inconsistency).

### 4.2 Canonical stratum/Bitcoin serialization (`to_stratum_bytes`, `core/mod.rs:775-796`)

```
version           u32 LE
input_count       varint (Bitcoin CompactSize; core/mod.rs:657-670)
for each input:
    prev_txid     32 bytes
    prev_index    u32 LE
    [if include_script_sig] script_sig_len varint, script_sig bytes
    sequence      u32 LE
output_count      varint
for each output:
    value         u64 LE
    script_pubkey_len varint
    script_pubkey bytes
locktime          u32 LE
```

Parsing (`from_stratum_bytes`, `core/mod.rs:804-844`) is bounded/EOF-safe:
implausible counts and lengths are rejected (`in/out_count > 100_000`,
`script_sig > 10_000`, `script_pubkey > 10_000`), and pre-allocation is clamped
by remaining bytes, never by the untrusted count alone ("audit M1").

### 4.3 txid and coinbase (`core/mod.rs:846-867`)

`txid = SHA-256d(to_stratum_bytes(include_script_sig = is_coinbase()))`.

- **Non-coinbase:** serialized **without** script_sig → third-party signature
  malleability cannot change the txid ("VULN-06 preservation").
- **Coinbase:** serialized **with** script_sig (has no signature to malleate; the
  `"height:N"` encoding + extranonce make it unique). Coinbase is identified by a
  single input with `prev_txid == [0u8;32]` and `prev_index == u32::MAX`.

### 4.4 Sighash — SIGHASH_ALL-style, chain-id bound (v2, Roadmap #8)

`Transaction::sighash(input_index, chain_id)` (`core/mod.rs`):

```
stripped = tx.clone()
for each input i:
    input[i].script_sig = (i == input_index) ? b"BLOCH_SIGHASH" : []
body     = bincode::standard( stripped )                 // the v1 body, unchanged
preimage = SIGHASH_DOMAIN(16) ‖ [SIGHASH_VERSION=0x02](1)
           ‖ chain_id.to_le_bytes()(4) ‖ body            // 21-byte fixed prefix
sighash  = SHA3-256( preimage )
```

`SIGHASH_DOMAIN = b"BLOCH-SIGHASH-v2"` (16B). `chain_id : ChainId` is a u32 LE
registry — `Mainnet = 0xB10C_0001`, `Testnet = 0xB10C_0002` — folded into the
signed preimage. All prefix fields are fixed length and only the trailing bincode
blob is variable, so the concatenation is unambiguous.

It commits to `version`, `locktime`, **every** input's outpoint
(`prev_txid`/`prev_index`/`sequence`), the signed input's index (via the
`BLOCH_SIGHASH` marker on that input only), **every** output, AND the chain-id.
The spent UTXO's *value* is bound implicitly — the verifier looks it up by
outpoint. The encoder uses `.expect` (not `unwrap_or_default`) precisely so a
silent empty encoding cannot turn the sighash into a fixed replayable constant.

**Chain-id closes the cross-fork replay gap.** A mainnet signature is over a
preimage containing `0xB10C_0001`; presenting the same bytes on testnet makes the
verifier recompute with `0xB10C_0002` → a different 32-byte digest → ML-DSA and
Falcon both fail, *even when outpoints coincide*. `chain_id` is an EXPLICIT
consensus input threaded from the node's network (`ChainId::for_network` /
`core::node_chain_id()`), NOT taken from the transaction and NOT a compile-time
flag. This changed the signed bytes of every tx — a hard fork bundled pre-mainnet.
NO security property is claimed (unaudited).

Also note the digest is over **bincode** here, whereas `txid` uses the stratum
byte format — two different serializers are load-bearing in the tx path.

### 4.5 Verification path (`src/main.rs`, mirror in `src/rpc/mod.rs`)

Per input: parse `script_sig` → `(sig, pk)`; require
`SHA3-256(pk)[0..20] == utxo.script_pubkey` (`pk` is the enveloped pubkey); then
`crypto::verify(pk, tx.sighash(i, core::node_chain_id()), sig)` — the suite-ID
dispatch over the full hybrid AND-combiner. The miner and both validators
(block-validation in `main.rs`, mempool-admission in `rpc/mod.rs`) read the SAME
`node_chain_id()`, so consensus is single-sourced. Value conservation
`Σ inputs ≥ Σ outputs` with checked arithmetic; in-context double-spend tracking
via a spent set. (The inline comment "Verify ML-DSA-65 signature" is stale — the
call is the hybrid; see §11.)

---

## 5. Block and header wire format (FROZEN)

**File:** `core/mod.rs:184-1123`.

### 5.1 In-memory header

```
BlockHeader { version:u32, parents:Vec<[u8;32]>, merkle_root:MerkleRoot,
              timestamp:u64, bits:u32, nonce:u64 }
```

`MerkleRoot` is a `#[serde(transparent)]` newtype over `[u8;32]` — byte-identical
on the wire to a bare array ("audit L-2"; `core/mod.rs:216-263`).

### 5.2 The 80-byte MiningHeader (PoW projection)

To let SHA-256d-style stratum tooling hash a fixed 80-byte structure, PoW is over
a **projection** of the header (`core/mod.rs:275-387`):

```
offset  field
0..4    version                 u32 LE
4..36   prev_hash               = parents_commitment(parents)   (32 bytes)
36..68  merkle_root             (32 bytes)
68..72  timestamp low-32 bits   u32 LE
72..76  bits                    u32 LE
76..80  nonce low-32 bits       u32 LE
```

- `parents_commitment` (`core/mod.rs:406-426`): sort parents byte-ascending
  (permutation-invariant), then pairwise SHA-256d (Bitcoin merkle style, odd
  level duplicates last) to one root; empty → all-zeros (genesis); single parent
  → itself.
- `pow_hash = SHA-256d(MiningHeader.to_bytes())` (`core/mod.rs:383-386, 587-589`).
  Consensus-critical; the projection maps u64 timestamp/nonce to their low 32
  bits (the miner searches the 32-bit nonce plus stratum extranonce/ntime-roll).

### 5.3 PoW preimage and the SIS instance

`pow_preimage()` = the **first 76 bytes** of the mining header (i.e. the 80-byte
layout **minus** the 4-byte nonce): `version ‖ prev_hash ‖ merkle ‖ timestamp ‖
bits` (`core/mod.rs:591-598`). The SIS crate derives its seed as
`SHAKE256(SEED_DOMAIN ‖ preimage ‖ nonce_le)` with the **full u64** `header.nonce`
supplied separately — the nonce must NOT appear in the preimage.

`Block::validate_pow` verifies the block's `pow_solution` against this instance at
`canonical_residual_coeffs(height)` (§3.3). `dag_hash = SHA3-256(full_bytes)` over
the complete header (all fields) is a **separate** identifier used for DAG
indexing, not for PoW (`core/mod.rs:600-622`).

### 5.4 Block structure and identity

```
Block { header:BlockHeader, transactions:Vec<Transaction>, blue_score:u64,
        height:u64, pow_solution:Vec<i32> (len 256 when mined),
        shielded_transactions:Vec<ShieldedTx> }
```

`block_hash` (`core/mod.rs:1010-1019`) =
`SHA3-256("BLOCH-BLOCK-ID-V1" ‖ pow_preimage ‖ nonce_le ‖ Σ_c c.to_le_bytes())` —
binds the PoW witness `s`, so two distinct solutions for the same header get
distinct ids (witness-malleability resistance). It is deterministic even for an
unmined block; PoW validity is enforced separately.

### 5.5 Canonical block wire format (`to_bitcoin_bytes`, `core/mod.rs:1034-1065`)

```
header:  BlockHeader::to_bitcoin_bytes(blue_score, height)   [see 5.6]
tx_count: varint
transactions: Transaction::to_stratum_bytes(include_script_sig = true) × N
pow_solution_len: varint
pow_solution: i32 LE × len            (0-length for a template)
shielded_count: varint
shielded_transactions: write_shielded_tx × N   [core/mod.rs:709-720]
```

Parsing (`from_bitcoin_bytes`, `core/mod.rs:1073+`) is strict: trailing garbage
past the last element is rejected; `tx_count > 1_000_000`, `parents_count > 256`,
etc. are rejected.

### 5.6 Header wire format with DAG extension (`to_bitcoin_bytes`, `core/mod.rs:458-559`)

```
bytes 0..80   the 80-byte MiningHeader (§5.2)
extension:
  parents_count      varint
  parents            [u8;32] × N
  timestamp_high32   u32 LE
  nonce_high32       u32 LE
  blue_score         u64 LE
  height             u64 LE
```

On parse, `prev_hash` in the 80-byte prefix MUST equal
`parents_commitment(parents)` or the header is rejected as tampered
(`core/mod.rs:517-526`). Full u64 timestamp/nonce are reassembled from
low-32 (mining header) ‖ high-32 (extension). This is consensus-critical wire
format; changing it is a hard fork.

---

## 6. P2P wire format

### 6.1 Application/gossip layer (`src/network/mod.rs`)

Transport is **libp2p gossipsub + mDNS + identify** (`network/mod.rs:115-126`).
`NETWORK_MAGIC = 0x424C5349` ("BLSI", `core/mod.rs:17`). Application messages
(`network/mod.rs:44-73`) are a serde enum:

```
NewBlock       { block_hash:[u8;32], blue_score:u64, height:u64, block_data:Vec<u8> }
NewTransaction { txid:[u8;32], tx_data:Vec<u8> }
PeerTip        { peer_id:String, blue_score:u64, height:u64 }
PeerExchange   { peers:Vec<String> }
PeerRequest
PeerCount      { count:usize, addresses:Vec<String> }
GetHeaders     { from_blue_score:u64, limit:u32 }
Headers        { entries:Vec<SyncEntry{hash:[u8;32],blue_score:u64,height:u64}> }
GetBlock       { block_hash:[u8;32] }
Version        { version:u32, user_agent:String, blue_score:u64, height:u64, timestamp:u64 }
VersionAck
```

`PROTOCOL_VERSION = 1`, `MIN_PROTOCOL_VERSION = 1` (`network/mod.rs:40-42`).
`block_data`/`tx_data` are the §5.5 / §4.2 byte encodings; a receiver re-parses
and fully re-validates (the `block_hash`/`txid` in the envelope are hints, not
trust anchors — the block is re-hashed and PoW-verified). These application
messages are **not themselves signed** at the app layer; their integrity rests on
re-validation plus the transport layer below.

### 6.2 PQ transport handshake (`src/transport/mod.rs`)

A separate authenticated PQ transport exists (not the default libp2p path; see
§11 for the two parallel handshakes). `DOMAIN_MAGIC = "BLOCH-PQ-v1-handshake"`,
`PQ_PROTOCOL_VERSION = 1` (`transport/mod.rs:86-89`). It is a **Kyber768 KEM +
hybrid-signature-authenticated** handshake:

```
HandshakeInit { version:u8, kyber_pk:Vec<u8>, identity_pk:Vec<u8>,
                nonce:[u8;32], signature:Vec<u8> }        (transport/mod.rs:127-134)
HandshakeResp { ciphertext:Vec<u8>, identity_pk:Vec<u8>, signature:Vec<u8> }
SessionConfirm { mac:[u8;32] }
```

- `identity_pk`/`signature` are the **hybrid** (ML-DSA ‖ Falcon) pubkey/sig,
  verified with `crypto::verify` (`transport/mod.rs:102-108`).
- Transcript binding: `t1 = SHA3-256(MAGIC ‖ version ‖ kyber_pk ‖ id_pk_i ‖
  nonce)`; `t2 = SHA3-256(t1 ‖ ciphertext ‖ id_pk_r)` (`transport/mod.rs:153-180`).
- Session keys: `HKDF-SHA256(salt = t2, ikm = kyber_shared_secret)` with distinct
  labels `LABEL_I2R / LABEL_R2I / LABEL_CONFIRM`; stream cipher is
  ChaCha20-Poly1305 (`transport/mod.rs:92-96, 187-203`). Confirmation MAC is
  HMAC-SHA256 over `t2 ‖ role`.
- Replay protection: 32-byte initiator nonce, transcript-bound. Self-labelled
  no formal proof, no third-party audit (`transport/mod.rs:63`).

A second, libp2p-native variant exists in `src/transport/upgrade.rs`
(`DOMAIN_MAGIC ‖ "-libp2p"`, `upgrade.rs:174-175`) — a hybrid Kyber + libp2p
identity handshake. Which handshake is live on which path is an implementation
detail an auditor must pin down before scoping the network layer.

---

## 7. Consensus rules (re-derivable summary)

### 7.1 Block validity (validator: `Block::validate_pow` + `src/main.rs` accept path)

A block is valid iff:

1. **Wire well-formedness:** parses under §5.5 with no trailing garbage; bounded
   counts.
2. **Height binding:** `height == max(parent heights) + 1` (VULN-02), and the
   wire `height` matches the block content — enforced in the `NewBlock` handler
   and `accept_block` (`core/mod.rs:143-150` documents the invariant the k-selector
   relies on). A block cannot lie about its height to dodge the k=8 gate.
3. **PoW:** `pow_solution` (length 256) verifies via `verify_regime(pow_preimage,
   nonce, solution, bits_to_target(bits), canonical_residual_coeffs(height))`
   (§3.2–3.3).
4. **Difficulty:** `bits == next_bits(GENESIS_BITS, GENESIS_TIMESTAMP,
   parent_timestamp, height)` via ASERT-Lattice (`src/pow/mod.rs:77-90`;
   validator recomputes and compares, `main.rs:1366-1369`).
5. **Timestamp sanity:** not more than `MAX_FUTURE_SECS = 7200` in the future
   (`core/mod.rs:72`).
6. **Transactions:** every tx validates per §4.5 (input existence, pubkey-hash
   match, hybrid sig verify, value conservation, in-block double-spend set);
   coinbase maturity `COINBASE_MATURITY = 100` enforced (`core/mod.rs:32-70`);
   dust threshold `546` (`core/mod.rs:71`); `MAX_BLOCK_SIZE = 1_000_000`
   (`core/mod.rs:27`).

Genesis is pinned (`GENESIS_*`, `core/mod.rs:95-182`), including a testnet-regime
`GENESIS_POW_SOLUTION` (zero security; the mainnet ceremony re-mines).

### 7.2 Fork choice — GhostDAG (`src/consensus/mod.rs`)

- Parameter `GHOSTDAG_K = 10` (`core/mod.rs:18`; `GhostDAG::with_default_k`,
  `consensus/mod.rs:487-494`).
- Per-block `GhostdagData { blue_score:u64, blue_work:u128, selected_parent }`
  (`consensus/mod.rs:32-58`): `selected_parent = argmax(blue_work)` over parents;
  `blue_score(B) = blue_score(selected_parent) + |mergeset_blues(B)| + 1`
  (`consensus/mod.rs:10-11`); `blue_work` is cumulative chain work (Kaspa-aligned,
  fed by `work_from_bits`, §3.5).
- Canonical head is the tip of maximal accumulated work; `is_ancestor` uses
  blue_score/height shortcuts (`consensus/mod.rs:282-299`).
- **Finality/anti-reorg:** reorgs deeper than `CHECKPOINT_DEPTH = 1000` are
  rejected; block bodies pruned below `tip − PRUNING_DEPTH = 10_000`
  (`core/mod.rs:79-80`). Reorg re-validates inputs/no-double-spend/value/maturity
  (`src/reorg.rs`).

### 7.3 Emission (context)

Tokenomics (`tokenomics_v2.rs`): initial subsidy 8,400 BLOCH,
`HALVING_INTERVAL = 1_036_800` (~1 yr @ 30 s) — this V2 curve governs only
heights below the **Emission V3** flag-day fork at local height 40,000
(emission height 453,743 incl. carryover). From the fork: subsidy
2,600 BLOCH (`EMISSION_V3_INITIAL_REWARD_BLOCH`), halving every 1,555,200
blocks (~1.5 yr, `EMISSION_V3_HALVING_INTERVAL`, counter restarts at the
fork), schedule 2,600 → 1,300 → 650 → 325 → 162 then a perpetual
100 BLOCH tail floor (supply is **not hard-capped**; see
`docs/specs/TOKENOMICS_V3.md`). **The coin is
valueless by design** — emission parameters do not confer value or a security.

---

## 8. What changing a field costs (hard-fork map)

Changing any of the following is a **hard fork** (new genesis, incompatible
chain): the PoW params `N/M/q/B/β` (`params.rs:5`); the three PoW domain labels
(`lib.rs:183-194`); the mining-header 80-byte layout or `pow_hash`
(`core/mod.rs:333-335, 456-457`); the block/header wire format
(`core/mod.rs:456-457`); the txid/sighash algorithm; the address/checksum scheme.
Raising `k` at the activation height is a **soft fork** (SF-1, §3.3). The
pre-mainnet bundle #8 landed three such hard forks together: the chain-id sighash
(§4.4), the suite-ID envelope on pk/sig (§1.1, §10), and the resulting
suite-committing address change (§2.1).

---

## 9. Wire-freeze status

| Surface | Frozen? | Where |
|---|---|---|
| Enveloped pk/sig layout (4B suite header + 1952/3309 offsets) | **Freeze candidate** | §1.1 |
| Address + checksum scheme (hashes enveloped pk) | **Freeze candidate** | §2.1 |
| Tx wire format + txid | **Freeze candidate** | §4.2–4.3 |
| Tx sighash (chain-id bound, v2) | **Freeze candidate — chain-id fix landed (§4.4)** | §4.4 |
| Block/header wire format | **Freeze candidate** | §5 |
| PoW structure (seed/expand/residual/aux) | **Freeze candidate** | §3 |
| PoW canonical `(k, β)` | **NOT frozen** — research track | §3.1, §3.3 |
| `CANONICAL_K_ACTIVATION_HEIGHT` | **NOT set** — placeholder | §3.3 |
| P2P app messages | v1, small; freeze candidate | §6.1 |
| PQ transport handshake | v1; two variants, needs consolidation | §6.2, §11 |

An audit of an unfrozen surface is worth little; §9 is the checklist of what to
freeze first (roadmap P0.1).

---

## 10. Crypto-agility — suite-ID envelope (Roadmap #1, implemented)

Algorithm identity is now **explicit and in-band**: every pk, sk and sig carries a
4-byte suite header (`magic B1 0C ‖ suite_id u16 LE`, §1.1) and the verifier
dispatches on the suite id. The earlier gap (identity implicit in fixed offsets;
no in-band version; addresses suite-agnostic) is closed:

- The verifier parses the envelope, requires `pk_suite == sig_suite`, and
  dispatches: `0x0001` → hybrid ML-DSA-65 ‖ Falcon-1024 AND-combiner; `0x0002` →
  ML-DSA-65 only; unknown/reserved (`0x0000`, `0xFFFF`, …) ⇒ `false`. Parse
  failure (len<4 / bad magic) ⇒ `false`, never a panic (consensus rule).
- Migrating (e.g. dropping Falcon via `SUITE_MLDSA65_ONLY`, or adding FN-DSA /
  ML-DSA-87) now registers a new suite id and a dispatch arm; old outputs keep
  verifying via their suite arm — no forced migration. Gating *acceptance* of new
  suites behind a height activation (reusing the SF-1 pattern) is future work.
- Addresses commit to the suite (§2.1): the address hashes the enveloped pk.

This is a design-stage, **unaudited** change; NO security property is claimed. The
`0x0002` suite exists as a concrete proof Falcon is removable in principle — no
live output uses it yet.

---

## 11. Discrepancies found (code wins)

1. **Kyber IS used in the node.** `roadmap-crypto-core.md` §1.1/App.B state
   `pqcrypto-kyber` is a declared-but-**unused** dependency in the blockchain
   repo. The code contradicts this: `src/transport/mod.rs:68` imports
   `pqcrypto_kyber::kyber768` and uses it as the KEM for the PQ transport
   handshake (§6.2), and `src/transport/upgrade.rs` uses a Kyber-based libp2p
   upgrade. The roadmap statement is true only for the *signature crypto core*
   (`bloch-crypto`), not the node's transport layer. Note it is **Kyber768**
   here, versus Postern-courier's ML-KEM-1024.
2. **Block-time comment is stale.** `core/mod.rs:28` comments
   `TARGET_BLOCK_TIME` as "150s (V2)", and the genesis comment (`core/mod.rs:98`)
   says "calibrated for 150s". The actual constants are **30 s**
   (`tokenomics_v2.rs:78`, `difficulty.rs:21`). The 30 s value is internally
   consistent between the tokenomics and ASERT crates; only the inline comments
   are wrong. Spec uses 30 s (§3.5, §7.1).
3. **ML-DSA/Falcon naming vs byte order.** Comments variously call the scheme
   "ML-DSA-65 ‖ Falcon-1024" (`crypto/mod.rs:16`) and "Falcon-1024 ‖ ML-DSA-65"
   (`crypto/mod.rs:284`, `core/mod.rs:87`). The **byte layout is ML-DSA-first**
   (split at 1952/3309). This spec fixes the order to the wire truth (§1.1); the
   comments should be corrected (roadmap P0.6) to prevent an incompatible
   second implementation.
4. **Stale verify comment.** `main.rs:1788` says "Verify ML-DSA-65 signature";
   the call is the full hybrid AND-combiner (§4.5).

---

*End of SPEC.md. Companion: `docs/THREAT-MODEL.md`.*
