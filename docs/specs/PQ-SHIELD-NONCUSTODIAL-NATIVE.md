# PQ-Shield — a non-custodial, native, opt-in post-quantum *defensive vault* for coins that have no PQ signature scheme

> **STATUS: DESIGN ONLY. Unaudited. Not built, not wired, not booted.**
> No code in this repo implements this yet. This document specifies a design and,
> more importantly, states precisely what it **cannot** do. Read §0 and §9 before
> anything else. Designed ≠ built ≠ booted.

> **Honest-disclosure discipline** (house style, cf. `COHERENCE-v0.2.md §4`,
> `BLOCH-SIS-ATTESTATION.md §0/§5`): we make *integrity/defense* claims, not
> *immunity* claims. Where a limit exists we name it in the same breath as the
> feature, not in a footnote.

---

## 0. The hard cryptographic constraint (stated first, not papered over)

A coin whose spend path ultimately checks a **classical** signature —
secp256k1 ECDSA/Schnorr for BTC/BCH/LTC/DOGE, secp256k1 ECDSA for ETH — can be
spent by anyone who holds (or can *derive*) that private key. A
cryptographically-relevant quantum computer (CRQC) running Shor's algorithm
derives the private key from the **public key**. Therefore:

> **A fully non-custodial + native + *unconditionally* quantum-safe layer for such
> a coin is impossible without one of:**
> - **(a) a soft fork of that coin** adding a PQ opcode / output type — e.g.
>   **BIP-360 (P2QRH)** for Bitcoin. This is a *real* fix, but it is **not
>   something Postern/Bloch can ship unilaterally**; it requires the coin's own
>   consensus to change. Out of scope here.
> - **(b) moving the value off the coin** onto a chain that *does* verify PQ
>   signatures (wrap / wBTC-PQ / bridge). That is **custodial or federated** —
>   it changes the trust model and is a *separate* product (the wrapped-BTC /
>   custody bridge; see §8.3). **This document is explicitly NOT that.**

This spec claims **neither** (a) nor (b). What we *can* build non-custodially and
natively, on the coin as it exists today, is a **defensive vault** that:

1. **protects the spend/reveal window** — the only moment a not-yet-spent coin's
   key is exposed on-chain — with a mandatory delay, and
2. gives the owner a **PQ-authorized recovery / clawback path** that is
   publicly auditable and provably tied to the owner's post-quantum key.

Everything below is framed around **that achievable goal and only that goal.**

### 0.1 A correction we owe the reader up front (address-level baseline)

The intuitive claim "unspent coins are quantum-safe because the pubkey is hidden
behind a hash" is **true for some Bitcoin output types and false for others.**
Getting this right is load-bearing for the whole design:

| Output type | What sits in the `scriptPubKey` | Quantum-exposed *at rest* (before first spend)? |
|---|---|---|
| P2PKH (`1…`) | `HASH160(pubkey)` (20-byte hash) | **No** — pubkey hidden behind a hash; CRQC sees only a hash |
| P2WPKH (`bc1q…`) | `HASH160(pubkey)` (witness v0) | **No** — same, pubkey revealed only at spend |
| P2WSH (`bc1q…`, 32-byte) | `SHA256(witnessScript)` | **No** — the *entire script* (and every pubkey in it) is hidden behind a hash |
| **P2TR (`bc1p…`)** | **the 32-byte x-only *output key* Q = P + t·G** | **YES — a live EC point is published.** A CRQC can solve the ECDLP for Q and key-path-spend it, *even for a "NUMS" internal key* |
| Reused address (any type) whose pubkey already appeared in a past spend | hash, but pubkey already public | **YES** — pubkey is already on chain from the earlier spend |

**Consequence:** Taproot outputs are **not** quantum-safe at rest — the output
key is a spendable public key on-chain. This flatly contradicts the common
shorthand and it changes our design choices (see §2.0). The genuinely
quantum-*conservative*, at-rest-hiding Bitcoin output is **P2WSH** (or P2WPKH):
the script/pubkey lives only as a `SHA256`/`HASH160` preimage until spend, and
finding a colliding preimage is a hash attack (Grover-only, ~128-bit residual
security), not an ECDLP attack.

So the real, narrow exposure this vault targets is: **(i) the spend window**
(the transaction that first reveals a pubkey), and **(ii) address reuse**
(pubkey already public). The vault does nothing for a coin whose key is
*already* exposed and cannot; see §9.

---

## 1. Threat model (be specific about the adversary)

**Adversary: a CRQC-equipped attacker** who can, given a secp256k1 public key,
recover the private key in some time `T_shor` (unknown today; assume it is
*fast-but-not-instant* relative to block intervals for the design to have any
value — this assumption is itself a limit, see §9). The attacker:

- **can** watch the mempool and the chain, learn any pubkey the moment it is
  revealed, and forge signatures under any pubkey they have seen;
- **can** broadcast, RBF-bump, and race transactions;
- **cannot** invert `SHA256`/`HASH160` (only Grover speed-up ⇒ treat 256-bit
  preimage as ~128-bit; still infeasible), and **cannot** produce a valid
  **ML-DSA-65 ‖ Falcon-1024** signature (the PQ scheme in `bloch-crypto`).

**Defender: the coin owner**, holding a hybrid identity (one seed → BTC key + PQ
key, exactly as `crates/bloch-btc-wallet/src/lib.rs::derive_identity` already
produces), who is (or whose watchtower is) **online during the delay window.**

**What "win" means.** The attacker wins if they move the coin to an address they
control. The defender wins if the coin ends up at a fresh, unexposed
owner-controlled address (a new hidden-pubkey output or a fresh vault). "Nobody
moves it" during the window is a defender *hold*, not yet a win.

---

## 2. The Bitcoin construction — commit-delay-reveal vault + PQ-gated clawback

**Opcode budget: existing Bitcoin only. No soft fork.** We use exactly:
`OP_CHECKSIG`/`OP_CHECKSIGVERIFY` (BIP-340/341/342 for Taproot, else ECDSA),
`OP_CHECKSEQUENCEVERIFY` (**CSV, BIP-112**, relative timelock, semantics per
BIP-68), optionally `OP_CHECKLOCKTIMEVERIFY` (**CLTV, BIP-65**, absolute
timelock), and `OP_SHA256 … OP_EQUALVERIFY` hash-locks. Script tree via Taproot
(**BIP-341/342**) *or* a P2WSH branch (see §2.0).

### 2.0 Output-type choice — and the honest covenant caveat

Two design tensions, both disclosed:

1. **Taproot vs P2WSH.** The task asks for a "Taproot vault." Taproot gives
   cheaper, more private script-path spends and a clean tap-tree of branches —
   **but** its key-path output key is a live EC point (§0.1), so a *Taproot*
   vault offers **zero at-rest quantum protection**; it protects the spend
   window only. If you also want **at-rest** hiding, use **P2WSH** (the whole
   script, hence every pubkey, is behind `SHA256`). This spec describes the
   branch logic once and notes that it can be instantiated as either a
   **tap-tree** (Taproot, spend-window-only, NUMS-disabled internal key) or a
   **P2WSH witnessScript** (at-rest hidden, recommended for the highest-value
   cold vault). **Recommendation: P2WSH for the deposit; Taproot acceptable for
   the short-lived trigger output.** Neither choice changes the trust model —
   both are non-custodial.

2. **No covenants today (the big one).** A *script-enforced* "you may only spend
   this by first moving to a delayed output, and the delayed output may only go
   to address X" is a **covenant**. Bitcoin has **no covenant opcode** in
   consensus today (`OP_CTV`/BIP-119, `OP_VAULT`/BIP-345 are **proposals**, i.e.
   soft forks we cannot ship unilaterally — same category as BIP-360). **Without
   a covenant, the commit-delay-reveal structure below is enforced by
   *pre-signed transactions + secure deletion of the trigger key*, NOT by
   consensus.** This is the Revault-style vault pattern. Its guarantee is
   **operational** (the owner must actually delete/withhold the bypass key),
   **not** a consensus guarantee. We state this plainly because it is the single
   most important caveat in the construction. A covenant soft fork (or moving to
   Bloch's eUTXO, which *does* have covenant-grade validators) removes this
   caveat; on stock Bitcoin it stands.

### 2.1 The three outputs

```
                 (funds at rest — hidden)
   ┌───────────────────────────────────────────┐
   │ V = DEPOSIT output  (P2WSH recommended)    │
   │ scriptPubKey = SHA256(depositScript)       │
   │ depositScript spend condition:             │
   │     OP_SHA256 <H(r)> OP_EQUALVERIFY         │   ← hash-gate binds the spend to the
   │     <hot_pubkey> OP_CHECKSIG                │     PQ-derived preimage r (see §2.3)
   └───────────────────────────────────────────┘
                     │  spent ONLY by the pre-signed UNVAULT tx U
                     │  (trigger key deleted ⇒ U is the sole spend — see §2.0(2))
                     ▼
   ┌───────────────────────────────────────────┐
   │ T = TRIGGER / unvault output               │   ← broadcasting U == "unvault trigger";
   │ two script branches (tap-tree or P2WSH):   │     this is the public, watchable event
   │                                            │
   │  A) DELAY-TO-DESTINATION (the normal path) │
   │     <Δ> OP_CHECKSEQUENCEVERIFY OP_DROP      │   ← CSV relative delay Δ (BIP-112/68)
   │     <hot_pubkey> OP_CHECKSIG               │
   │                                            │
   │  B) CLAWBACK / RECOVERY (the defense)      │
   │     OP_SHA256 <H(r)> OP_EQUALVERIFY         │   ← immediate (NO delay); needs the
   │     <recovery_pubkey> OP_CHECKSIG         │     PQ-derived preimage r + recovery sig
   └───────────────────────────────────────────┘
        │ branch A after Δ                │ branch B any time during Δ
        ▼                                 ▼
   final destination                 FRESH COLD address / new vault
   (hot-key signed)                  (recovery-key signed, PQ-authorized)
```

- **Normal ("unvault") path = commit-delay-reveal.** To spend normally the owner
  **broadcasts U** (the commit/trigger — this is the only moment a pubkey is
  revealed), then **waits the CSV delay Δ** on branch A before the funds can
  reach their destination. Δ is the defensive window.
- **Clawback path = immediate + PQ-gated.** Branch B has **no** CSV delay, so
  during Δ *only the party who can satisfy branch B can move the coin
  immediately.* Branch B requires revealing the preimage `r` **and** a signature
  under `recovery_pubkey`.

### 2.2 Why the delay buys something — the race, quantified

Timeline of the normal spend, under CRQC attack:

| t | Event | Attacker state |
|---|---|---|
| `< 0` | Funds at rest in V (P2WSH). | **Blind** — sees only `SHA256(depositScript)`. No pubkey to attack. |
| `0` | Owner broadcasts **U**. `hot_pubkey` (and `r`) become visible; **T** confirms; CSV clock Δ starts. | Learns `hot_pubkey`; begins Shor to derive `hot_sk`; **also** scrapes `r` from U's witness. |
| `(0, Δ)` | **Owner (or watchtower) can execute branch B immediately** to a fresh cold address. | To steal via branch A the attacker must *also* wait Δ **and** forge `hot_sk`. Branch B needs `r` **and** `recovery_sk`. |
| `Δ` | Branch A becomes spendable. | Fastest theft path opens *now*. |

**What Δ buys:** branch A (the only path that redirects to an *arbitrary*
attacker address) is CSV-locked for Δ for **everyone**, attacker included. Branch
B (immediate) is the owner's edge — it is gated by `recovery_sk`, which the
attacker cannot forge from anything revealed. So **if the owner is watching, they
claw back within Δ and win the coin outright.** The attacker only wins if the
owner fails to claw back within Δ (offline, or out-fee'd — see next).

**What Δ does NOT buy (the honest teeth of it):**

- **Preimage front-running.** `r` is revealed in U's witness (branch A/B both
  reference `H(r)`; the deposit spend reveals `r`). Once `r` is public, an
  attacker who *also* forges `recovery_sk` (CRQC) could themselves satisfy branch
  B. So branch B's safety against a CRQC rests on `recovery_pubkey` **not being
  derivable in time** — i.e. it too is only revealed at branch-B spend, and the
  race is again "who lands a branch-B spend first, with higher fee." This is the
  **same fee-bumping / preimage-stealing race as Lightning/atomic-swaps** and we
  do not pretend to have solved it. Mitigation is *operational*: the owner's
  watchtower pre-signs the branch-B clawback and stands ready to RBF it above the
  attacker. Δ only has to be long enough for the watchtower to land one
  fee-competitive transaction.
- **Choosing Δ is a UX tax.** Δ blocks of delay on *every* normal withdrawal.
  Δ = 144 (~1 day) is a defensible default for a cold vault; Δ = 6 (~1h) is
  barely a window; Δ = 1008 (~1 week) is strong but painful. There is **no free
  lunch**: the security of the window scales with how long you are willing to
  wait to spend your own money, and with your watchtower's uptime.

### 2.3 Binding the preimage to the PQ key (how Bitcoin checks a hash while Bloch checks PQ)

Bitcoin can only check `SHA256(r) == H(r)`. It **cannot** verify an ML-DSA/Falcon
signature. So the "PQ authorization" of a clawback is achieved by a **split
enforcement** that the two chains jointly pin:

- **Derivation.** The recovery preimage is `r = HKDF(pq_sk, "pq-shield/v1" ‖ vault_id)`
  — a high-entropy secret **only the holder of the PQ secret key can produce.**
  Its commitment `H(r) = SHA256(r)` goes into branch B (and the deposit
  hash-gate). *Ability to reveal `r` ⇒ possession of `pq_sk` at setup time.* That
  is the concrete "preimage bound to the PQ key."
- **Anchor.** At vault creation the owner signs (ML-DSA-65 ‖ Falcon-1024, via
  `bloch_crypto::crypto::sign`) a record on Bloch binding
  `{btc_vault_address, H(r), pq_recovery_pubkey, designated_safe_destination, policy}`
  (§3). This is the **publicly auditable proof** that the PQ-key holder set up
  this recovery and *pre-designated where a clawback may send*.
- **Division of labour (say it plainly):** **Bitcoin enforces the hash + timelock
  half; Bloch enforces the PQ half; the shared value `H(r)` and the shared
  `designated_safe_destination` are the hinge.** Revealing `r` on Bitcoin is
  *not*, by itself, a proof-to-Bitcoin of PQ authorization — Bitcoin never sees a
  PQ sig. The PQ authorization is what the **Bloch anchor** attests and what a
  compliant watchtower/relayer enforces (it will co-sign / fee-bump a clawback
  **only** to the anchored `designated_safe_destination`). A dishonest holder of
  `r` could send branch B anywhere; the guarantee is that *the legitimate,
  anchored recovery flow is PQ-authorized and auditable*, not that Bitcoin
  refuses other destinations (it cannot — no covenant, §2.0(2)).

---

## 3. Bloch as the PQ registry/anchor (the part Bitcoin structurally cannot do)

Bloch is PQ-native (its eUTXO validators verify ML-DSA‖Falcon via
`Op::VerifySig`, see `crates/bloch-euvm`). We use it as the **PQ enforcement and
audit plane** the coin itself lacks.

### 3.1 Record format — the `PqShieldAnchor` datum

A Bloch eUTXO whose datum carries the commitment, guarded so that **only the
owner's PQ key can create/rotate/revoke it.** Reusing the existing
`bloch-euvm` machinery in `crates/bloch-euvm/src/modules.rs`:

```
PqShieldAnchor {                         // serialized into the eUTXO datum
  version:                u16,           // = 1
  target_chain:           enum,          // Bitcoin | Litecoin | BCH | Dogecoin | EthereumL1
  btc_vault_address:      Bytes,         // the P2WSH/P2TR deposit address V
  recovery_hash:          [u8;32],       // H(r) = SHA256(HKDF(pq_sk, ...))
  pq_recovery_pubkey:     Bytes,         // ML-DSA-65 ‖ Falcon-1024 enveloped pubkey
  designated_safe_dest:   Bytes,         // the ONLY address the anchored clawback flow targets
  csv_delay:              u32,           // Δ in blocks (must match the on-BTC branch A)
  policy:                 Bytes,         // watchtower policy id, rotation rules, expiry
}
```

### 3.2 How it maps onto / extends the `Custody` module

`modules.rs::ModuleKind::Custody` is the **hybrid 2-of-2 ECDSA + PQ** validator
(`compile_custody`): BOTH a secp256k1/ECDSA key **and** an ML-DSA‖Falcon key must
sign. `crates/bloch-btc-wallet/src/lib.rs::hybrid_wbtc_validator` emits the same
2-of-2 shape. The `PqShieldAnchor` maps on cleanly:

- **Anchor guard = a `Governance` 1-of-1 (or `Custody` 2-of-2) over the PQ key.**
  The eUTXO holding the datum is guarded by a validator that requires
  `Op::VerifySig(sighash, pq_recovery_pubkey, sig)` — i.e. **only a valid
  ML-DSA‖Falcon signature updates the anchor.** For belt-and-suspenders you can
  use the full `Custody` 2-of-2 (BTC key **and** PQ key), matching the
  wallet's `hybrid_wbtc_validator` so the *same* hybrid identity that owns the
  BTC vault owns its anchor. This is a **strict extension** of `Custody`: the
  extra fields (`recovery_hash`, `designated_safe_dest`, `csv_delay`,
  `target_chain`) live in the *datum*; the *guard program* is exactly the
  existing custody/governance validator — no new opcode, no new module kind
  required, just a datum convention on top of the audited compiler.
- **Auditability.** Because the anchor is an ordinary Bloch eUTXO, anyone can
  verify: *this `H(r)` and this `designated_safe_dest` were committed, in this
  block, under this PQ pubkey, and have not been rotated.* That public, PQ-signed
  timeline is precisely what Bitcoin's hashlock cannot provide on its own.

> Honest limit inherited from `modules.rs` itself: that file is **FOUNDATION,
> unaudited, NOT consensus-wired** (its own header). The anchor design assumes a
> real PQ verifier and real datum serialization are wired in the Integrate phase.
> Designed ≠ built.

---

## 4. Opt-in flow, end to end

1. **Generate the hybrid identity** — `derive_identity(seed, mainnet)` in
   `crates/bloch-btc-wallet` already yields, from **one** seed:
   `btc_p2wpkh`, `btc_p2tr`, `btc_pubkey` (secp256k1), `pq_pubkey`
   (ML-DSA-65‖Falcon-1024), and a `bloch_address`. No new key ceremony.
2. **Derive the recovery secret** `r = HKDF(pq_sk, "pq-shield/v1" ‖ vault_id)`;
   compute `H(r)`.
3. **Construct the vault + pre-sign** — build V (deposit, P2WSH), the pre-signed
   **U** (unvault → T), and, ideally, a pre-signed branch-B clawback tx to
   `designated_safe_dest`. **Securely delete the trigger bypass key** so U is the
   only spend of V (§2.0(2)).
4. **Anchor on Bloch** — sign and post the `PqShieldAnchor` (§3). *This must
   happen before/at deposit; the anchor is the recovery authority.*
5. **Deposit BTC** to V. Funds now sit hidden at rest.
6. **Later — normal spend:** broadcast U (commit), wait Δ, then branch A to the
   destination. **Or — under attack:** the owner/watchtower detects an
   unauthorized U (or any unvault they did not initiate) and immediately executes
   the pre-signed branch-B clawback to `designated_safe_dest`.

### 4.1 Watchtower — non-custodial by construction

A watchtower (the user's own daemon, or a service they hire) watches the chain
for **any** spend of V / appearance of T. Its **only** powers are:

- **alert** the owner, and
- **broadcast / RBF the *pre-authorized* branch-B clawback** — which can send
  **only** to `designated_safe_dest` (that address is baked into the pre-signed
  clawback tx and the anchor).

It **never** holds `hot_sk`, never holds `pq_sk`, and **cannot** move funds
anywhere except the owner's own pre-committed cold address. So a malicious or
compromised watchtower can *grief* (trigger a clawback the owner didn't want,
sending funds to the owner's *own* cold address — annoying, not theft) but
**cannot steal.** That is the non-custodial guarantee. Multiple independent
watchtowers can run in parallel for liveness.

### 4.2 Key loss & backup

- **Lose `hot_sk`, keep the seed:** re-derive it (BIP-84/86 deterministic).
- **Lose the seed:** you lose *both* keys and `r`. The vault is unrecoverable —
  same as any self-custody wallet. No backdoor exists (by design: non-custodial).
- **`pq_sk` compromise:** rotate the anchor (PQ-sign a new `PqShieldAnchor` with
  a fresh `H(r')`, `pq_recovery_pubkey'`) and re-vault. The old `r` is single-use
  and burns on first clawback anyway.

---

## 5. Generalization to other coins

### 5.1 UTXO coins with hashlock + relative timelock — works as-is

Any coin with `OP_SHA256`/equivalent **and** a relative timelock
(CSV/BIP-112-equivalent) supports the exact §2 construction:

| Coin | Hashlock | Relative timelock | Notes |
|---|---|---|---|
| **Bitcoin** | ✅ | ✅ CSV | reference design; P2WSH or tap-tree |
| **Litecoin** | ✅ | ✅ CSV | near-identical to BTC; MWEB outputs excluded |
| **Bitcoin Cash** | ✅ | ✅ CSV | note: BCH *has* covenant-ish introspection (CashScript) — a covenant-enforced variant is possible there, removing the §2.0(2) caveat on BCH specifically |
| **Dogecoin** | ✅ | ✅ CSV (post-1.14.6) | works; longer block time makes Δ cheaper in wall-clock |

The Bloch anchor is chain-agnostic (`target_chain` field, §3.1).

### 5.2 Account-model chains (Ethereum) — a *user-owned* vault contract

ETH has no PQ precompile and its account key is ECDSA (quantum-forgeable), so the
same split applies. The vault becomes a **minimal, user-deployed, user-owned
contract** (NOT a federation, NOT an upgradeable admin proxy):

- `trigger()` — starts a timelock `Δ` (block-number or timestamp gate).
- `withdraw()` — after `Δ`, sends to a **fixed, constructor-set** destination
  (the contract *is* the covenant ETH lacks natively — this is the one advantage
  of the account model).
- `clawback(bytes r)` — **immediate**, requires `SHA256(r) == H(r)`, sends to the
  constructor-set `recoveryAddress`.
- Bloch `PqShieldAnchor` with `target_chain = EthereumL1` binds `H(r)` +
  `recoveryAddress` under the PQ key, same as §3.

Honest ETH-specific limits: the contract cannot verify PQ sigs on-chain (no
precompile), so the PQ half still lives on Bloch; and the deploying EOA's key is
ECDSA — a CRQC that forges it can interact with the contract's *public* methods
like anyone, so the contract's safety must rest on the hashlock + timelock +
fixed destinations, **never** on "only the owner EOA can call it."

---

## 6. What is genuinely non-custodial here (and why)

| Property | This design | Custodial bridge (§8.3) |
|---|---|---|
| Who can move the coin | only keys the **owner** holds / pre-committed destinations | a **custodian / federation** |
| Watchtower's max power | alert + fire a clawback to the *owner's own* cold address | n/a |
| Failure of the operator | griefing at worst (funds → owner's cold addr) | **loss of funds** |
| Trust added vs. bare self-custody | secure-deletion assumption (§2.0(2)) + watchtower uptime | full custodial trust |

---

## 7. Concrete parameters & defaults (design targets, not tuned)

- **Δ (CSV delay):** default **144 blocks (~24h)** for a cold vault; minimum
  useful ~**36 (~6h)**; high-security ~**1008 (~1 week)**. Must equal the
  `csv_delay` in the anchor.
- **`r`:** ≥ 32 bytes of HKDF output from `pq_sk`.
- **Deposit output:** **P2WSH** (at-rest hiding). Taproot only if the owner
  accepts spend-window-only protection (§0.1/§2.0).
- **Anchor guard:** `Governance` 1-of-1 over the PQ key minimum; `Custody`
  2-of-2 (BTC + PQ) recommended for high value.
- **Watchtowers:** ≥ 2 independent, each with the pre-signed branch-B clawback.

---

## 8. Comparison with the two things this is *not*

### 8.1 vs. BIP-360 / P2QRH (the real fix)
A soft fork adding a native PQ output type is the **correct, unconditional**
solution — funds guarded by an actual PQ signature, no window, no watchtower.
**We cannot ship it unilaterally**; it needs Bitcoin's consensus. Our vault is a
*stopgap that works today on unmodified Bitcoin*. If/when P2QRH activates,
migrate into it and retire the vault.

### 8.2 vs. this vault (honest positioning)
Our vault = **defense-in-depth for the transition era**: at-rest hiding (P2WSH)
+ a mandatory delay on the exposure window + a PQ-authorized, audited clawback.
It reduces the attack surface to "CRQC that also wins a fee race within Δ against
a watching owner." It does not eliminate it.

### 8.3 vs. the custodial wrapped-BTC bridge
> **Note:** the task referenced `docs/specs/BLOCH-BRIDGE-DESIGN.md`; that file
> does **not exist in this repo** at time of writing (see report). The contrast
> is with the *concept* of wrapping BTC into a PQ-verifying representation
> (`wBTC-PQ`) on Bloch — cf. `bloch-btc-wallet::hybrid_wbtc_validator` and the
> `Custody` 2-of-2 module.

Wrapping **moves the value** to a chain that verifies PQ sigs. That gives
unconditional PQ safety **for the wrapped representation** — at the cost of a
**custodial / federated peg** holding the real BTC. Different trust model,
different product. **This vault deliberately keeps the coin on its native chain
and adds no custodian.** The two are complementary, not substitutes.

---

## 9. HONEST LIMITS (mandatory, read this)

1. **Not quantum immunity — spend-window protection + recovery only.** A CRQC
   that (a) compromises the exposed key **and** (b) wins the branch-A/branch-B
   fee race within Δ, **or** simply strikes while the owner is **not watching**,
   **still steals the coin.** We reduce the odds; we do not zero them.
2. **The covenant caveat is real and structural.** On stock Bitcoin the
   commit-delay-reveal shape is enforced by **pre-signed txs + secure deletion of
   the bypass key**, not by consensus (§2.0(2)). If the owner fails to delete
   that key (or their signing device retains it), the vault can be bypassed —
   including by a CRQC that derives it. This is an *operational* trust
   assumption. A covenant soft fork or moving to Bloch's eUTXO removes it;
   nothing we can ship unilaterally does.
3. **Taproot is not quantum-safe at rest** (§0.1). If you instantiate the vault
   as Taproot, you get **spend-window protection only**; the deposit output key
   is CRQC-spendable at rest. Use **P2WSH** if you want at-rest hiding. The
   common "unspent Taproot is quantum-safe" claim is **false** and we do not
   repeat it.
4. **The clawback destination MUST itself be a fresh, unexposed (hidden-pubkey)
   address or a new vault.** Clawing back to a reused or Taproot address just
   *moves the same exposure.* The anchor's `designated_safe_dest` should be a
   never-before-seen P2WSH/P2WPKH.
5. **Address reuse defeats the whole thing.** If the vault (or the destination)
   pubkey has ever appeared on-chain, it is already exposed and the delay
   protects nothing.
6. **Requires the owner or watchtower online during Δ.** An offline owner with no
   watchtower has *no* defense during the window. Watchtowers add liveness but
   also a griefing surface (§4.1) — griefing only, never theft.
7. **Hashlock preimage front-running is unsolved here** (§2.2). We rely on Δ
   being long enough for a fee-competitive watchtower to land the clawback, not
   on any cryptographic prevention of the race. Same class of risk as Lightning
   HTLCs.
8. **`T_shor` assumption.** The design has value only if deriving a key from a
   pubkey takes *some* time comparable to or longer than Δ + block confirmation.
   If a future CRQC forges signatures **instantly and cheaply**, the whole
   window-based approach collapses and only (a) a PQ soft fork or (b) never
   exposing the key (never spending, or P2QRH) helps. **We cannot bound
   `T_shor`.**
9. **Foundational, unaudited, unbuilt.** No consensus wiring, no audited PQ
   verifier in `modules.rs` (its own disclaimer), no implementation of any of the
   above. **Designed ≠ built ≠ booted.**

---

## 10. Open question for the founder (the decision this design cannot make for you)

> **Given that a stock-Bitcoin vault's commit-delay-reveal can only be enforced
> by pre-signed-tx + secure-key-deletion (an *operational*, not consensus,
> guarantee — §2.0(2)/§9.2), and given that Taproot leaks a CRQC-spendable key at
> rest (§0.1), is the honest, shippable product actually:**
> **(A)** this native P2WSH pre-signed vault + Bloch anchor — *real today, but
> only spend-window + operational-trust strong; or*
> **(B)** put the same PQ-anchor / hybrid-identity engineering behind a **push
> for BIP-360 adoption** (the only unconditional native fix) and, in the interim,
> offer the **custodial wBTC-PQ path** (§8.3) for users who want unconditional PQ
> safety *now* and will accept a peg;
> **or (C)** ship the vault explicitly branded as *transition-era
> defense-in-depth*, paired with (B), never as "quantum-proof"?**

The cryptography permits all three; only (C)+(B) is defensible under this
project's no-overclaiming discipline. **Which one carries the product name is a
positioning/ethics call, not a technical one — and it is yours.**

---

### Appendix A — References
- **BIP-341 / BIP-342** — Taproot / Tapscript.
- **BIP-112 (CSV)** + **BIP-68** — relative timelocks (`OP_CHECKSEQUENCEVERIFY`).
- **BIP-65 (CLTV)** — absolute timelock (`OP_CHECKLOCKTIMEVERIFY`).
- **BIP-340** — Schnorr signatures over secp256k1.
- **BIP-84 / BIP-86** — native SegWit / Taproot HD derivation (used by
  `bloch-btc-wallet`).
- **BIP-360 (P2QRH)** — *proposed* post-quantum output type. **Soft fork; not
  shippable unilaterally.** The real fix.
- **BIP-119 (OP_CTV) / BIP-345 (OP_VAULT)** — *proposed* covenant opcodes. **Soft
  forks; not available.** Would remove the §2.0(2) caveat.
- Revault — the pre-signed-transaction, non-covenant vault pattern this design
  follows on stock Bitcoin.

### Appendix B — In-repo anchors
- `crates/bloch-btc-wallet/src/lib.rs` — `derive_identity` (one seed → BTC +
  PQ), `hybrid_wbtc_validator` (2-of-2 ECDSA+PQ guard shape reused by the anchor).
- `crates/bloch-euvm/src/modules.rs` — `ModuleKind::Custody` (hybrid 2-of-2) and
  `ModuleKind::Governance` (n-of-m PQ multisig): the anchor guard programs.
- `crates/bloch-crypto/src/crypto/mod.rs` — `generate_keypair_from_seed`, `sign`,
  `verify` (ML-DSA-65 ‖ Falcon-1024); `address` module (`bloch1…`).
- `docs/specs/BLOCH-SIS-ATTESTATION.md`, `docs/specs/COHERENCE-v0.2.md` —
  house honest-disclosure style this doc follows.
