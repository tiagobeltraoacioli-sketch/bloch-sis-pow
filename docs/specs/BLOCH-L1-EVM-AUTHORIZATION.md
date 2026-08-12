<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-L1-EVM-AUTHORIZATION — who may spend, when the EVM comes to L1

**Status:** proposal for founder decision. Prices the three options in the
fleet brief (`docs/FLEET-BRIEF-2026-08-11.md`, "EVM at L1") plus one the brief
did not list, and recommends one. Nothing here is decided until the founder
decides.

**Scope:** the authorization model only — which signatures move value in the
L1 EVM, what that costs in bytes and tooling, and where the quantum boundary
sits. The account-state/eUTXO coexistence design, the gas schedule itself, and
the fate of `crates/bloch-euvm` are *referenced* where they interact with
authorization but are **not decided here** (see §9).

---

## 1. The facts, verified in this repo

Everything below was read from the code on 2026-08-11, not assumed.

### 1.1 The signature envelope (`crates/bloch-crypto/src/crypto/mod.rs`)

Public keys, secret keys and signatures are wrapped in a suite envelope:
`SUITE_HEADER_LEN` (4 bytes) = 2-byte magic `SUITE_MAGIC` (`0xB1 0x0C`) +
little-endian `u16` suite id, then the raw body. Suites:
`SUITE_MLDSA65_FALCON1024 = 0x0001` (the one arrangement every consensus role
uses) and the escape hatch `SUITE_MLDSA65_ONLY = 0x0002`. Un-headered blobs
parse as legacy `0x0001` (`parse_envelope_or_legacy`, mod.rs:176) for
carry-over wallets.

Sizes (constants named where they live; arithmetic here is derived from them):

| Piece | Constant | Bytes |
|---|---|---|
| ML-DSA-65 pubkey | `MLDSA_PUBKEY_LEN` (mod.rs) = `MLDSA65_PK_BYTES` (staking.rs) | 1,952 |
| Falcon-1024 pubkey | `FALCON1024_PK_BYTES` (staking.rs) | 1,793 |
| Hybrid pubkey body | `HYBRID_PK_BYTES` (staking.rs:63) | 3,745 (3,749 enveloped) |
| ML-DSA-65 signature | `MLDSA_SIG_LEN` = `MLDSA65_SIG_BYTES` | 3,309 (fixed) |
| Falcon-1024 signature | variable; max `falcon1024::signature_bytes()` = 1,462 (pqcrypto-falcon 0.4.1, PQClean non-padded), typical ≈ 1,280 | ≈ 1,280 |
| **Hybrid signature** | positional split at `MLDSA65_SIG_BYTES` | **≈ 4,589 body / ≈ 4,593 enveloped; worst case 4,775 enveloped** |

The hybrid signature has **no length prefix** — the split point is fixed at
`MLDSA65_SIG_BYTES` precisely so one signature has exactly one encoding
(staking.rs:65-70). For comparison: a secp256k1 recoverable signature is
65 bytes, and needs no pubkey on the wire at all. The hybrid is ~70× the
signature and, unlike ECDSA, is **not recoverable** — the verifier must be
handed the 3,745-byte pubkey or already know it.

### 1.2 How staking treats the hybrid key (`crates/bloch-pos-committee/src/staking.rs`)

Two things matter for this document:

- `DepositTx.validator_pubkey` is a **fixed `[u8; HYBRID_PK_BYTES]`** and
  `DepositTx.suite` must equal `SUITE_MLDSA65_FALCON1024` — the escape hatch
  `SUITE_MLDSA65_ONLY` is *explicitly not valid for staking* (staking.rs:52-56).
  Consensus roles are hybrid-PQ-only today, by type. Any EVM authorization
  model that lets secp256k1 near consensus would be a new decision, not an
  extension of an existing one.
- `verify_hybrid` (staking.rs:128-149) rejects any signature `<=
  MLDSA65_SIG_BYTES` and enforces AND-composition of the two halves through a
  trait that exposes them separately, so no implementation can degrade the
  hybrid to an OR. Note the encoding difference from bloch-crypto: staking
  carries the suite as a struct field and the key/signature **raw** (no 4-byte
  envelope); bloch-crypto carries them enveloped. The EVM transaction format
  must pick one — this spec picks the envelope (§6.1), because the EVM side
  will meet keys from wallets, where the envelope is the wire format.

### 1.3 The capacity budget (G10, `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`)

Gate G10 (§11) requires **54 KB/block average and the ≈ 588 KB epoch-boundary
burst sustained on the real fleet for ≥ 14 days**. Read §6.5 next to it: the
adopted attestation design (committee 128 at epoch boundary + 8 per slot)
*alone* averages 53.8 KB/block. **The G10 average is consumed by consensus
overhead before the first user transaction.** EVM traffic is additive, and G10's
threshold must be re-derived once an EVM tx budget exists (§8.3). The evidence
that headroom exists is the Phase 4 exit criterion: sustained propagation at
the **296 KB/block working point** with no mesh or stream-limit regressions —
i.e. ≈ 242 KB/block of measured-but-not-yet-gated room above the attestations.

Slots are `SLOT_DURATION_SECS` = 30 s (params.rs). There is **no
`MAX_BLOCK_BYTES` consensus constant in the crate yet**; whoever wires the EVM
in must introduce one, and G10 is its calibration input.

### 1.4 What EVM tooling actually assumes

Every mainstream tool signs **secp256k1 ECDSA with public-key recovery**:
the transaction carries `(v, r, s)`, the node runs `ecrecover`, and the sender
address (20 bytes, `keccak256(pk)[12..]`) falls out of the signature. This
assumption is load-bearing in: MetaMask, Ledger/Trezor firmware, ethers.js
`Wallet`, viem, Hardhat and Foundry broadcast paths, WalletConnect-connected
wallets, every relayer, `ecrecover`-based contract patterns (EIP-2612 permit,
EIP-2771 meta-transactions, Safe signature checks, EIP-712 flows), and most
bridge validator sets.

One accident of history helps us: Bloch base addresses are **already 20-byte
payloads** — `address_from_pubkey` (crypto/mod.rs:247-252) is
`SHA3-256(enveloped pk)[..20]`. PQ accounts therefore fit the EVM's 20-byte
`address` type, `msg.sender`, and the ABI **without any width change**. This is
why "EVM semantics without EVM signing" (§4) is smaller than it sounds.

---

## 2. The boundary principle (used by every option below)

Stated once, applied everywhere:

> **Value is quantum-safe iff every authorization path that can move it —
> directly or transitively — verifies a post-quantum signature.** Transitively
> means: the owner path, every admin/upgrade/pause/minter role, every proxy
> admin, every oracle or keeper input that gates release, every delegate. One
> secp256k1 key anywhere in that closure poisons the whole position.

The corollary that kills most comfortable intuitions: *where funds are stored
proves nothing.* A contract "holding PQ funds" is not a boundary; the set of
keys that can cause the EVM to execute a transfer of those funds is.

---

## 3. Option 1 — secp256k1 accounts accepted at L1

EVM transactions are standard Ethereum typed transactions; the node runs
`ecrecover`; secp256k1 EOAs hold native BLCH and tokens at L1.

### 3.1 What stops working: nothing. That is the problem.

MetaMask, Ledger, Trezor, Hardhat, Foundry, ethers.js, viem, WalletConnect,
Blockscout/Etherscan-class explorers, ecrecover-based bridges — all work
day one, unmodified. Adoption cost ≈ zero. This option is maximally cheap and
maximally corrosive.

### 3.2 Bytes and capacity

A secp transfer is ~110 B RLP; an ERC-20 transfer ~190 B; call it 150 B.
Derived against §1.3: each 100 KB/block of transaction budget carries ≈ 680
secp txs (≈ 22.7 tx/s at 30 s slots); the full measured 296 KB working point
gives ≈ 1,600 tx/block ≈ 55 tx/s. Capacity is a non-issue for option 1 —
which produces the perverse effect in §3.4.

### 3.3 What a quantum adversary steals — exactly

- **Every secp EOA that has ever sent a transaction.** Recovery means the full
  public key is exposed in *every signature*; Shor's algorithm yields the
  private key; the attacker takes the entire balance — native BLCH, every
  token, every position the EOA controls.
- **Every unused secp address, at the moment it tries to move.** An unspent
  address is shielded only by the 20-byte hash. The first outgoing transaction
  reveals the pubkey *in the mempool*; a mature quantum adversary derives the
  key inside the 30 s slot and front-runs with a higher fee. "We'll migrate
  when quantum arrives" therefore fails: the migration transaction is itself
  the exposure event.
- **Everything reachable through secp-held roles**: `Ownable` owners, proxy
  admin keys, minter/pauser roles, secp multisig signers (a Safe of five secp
  keys is five Shor runs, not a threshold), oracle signer keys, bridge
  validator keys.

### 3.4 Does it contaminate the PQ side? Yes, three ways.

1. **Through contracts.** By §2, any PQ user's position in a contract with a
   secp admin, upgrade path, or oracle dependency is stealable. Auditing an
   entire ecosystem's role graphs for "no secp in the closure" is not a thing
   anyone has ever done at scale; in practice the boundary is invisible to
   users and unenforceable.
2. **Through the stake.** Stolen BLCH is indistinguishable and liquid, and by
   settled decision 7 of the brief, *liquid is stakeable*. A quantum thief
   converts theft into validator weight, throttled only by
   `MIN_DEPOSIT_SAT` and `MAX_ACTIVATIONS_PER_EPOCH` (staking.rs) — a rate
   limit, not a barrier. The §4.1 taint set (`DepositInput.tainted`) tracks
   premine/treasury descent only; quantum-stolen coins are untainted by
   construction. **This is a direct path from the secp lane into consensus.**
3. **Through the security budget.** PoS security is denominated in BLCH. A
   mass-theft event craters the price, which craters the cost of attacking
   finality. The PQ side's consensus math survives; its economics do not.

### 3.5 The blunt note the brief demands

Bloch's stated reason to exist is that its authorization path survives a
quantum adversary. Option 1 ships a chain whose *dominant* authorization path
(it is the cheap one — §3.2 vs §4.3, a ~31× byte advantage) is the exact
construction the project was founded to replace, on a base layer that
simultaneously spends ≈ 4.6 KB per signature on consensus messages to avoid
that construction. It is not a compromise; it is the thesis, negated, with the
PQ machinery kept on as decoration. If the founder chooses this, the public
security documentation must say, in these words or stronger: *balances in
secp256k1 accounts on Bloch L1 have Ethereum's quantum security, not Bloch's,
and a quantum adversary can convert them into validator stake.*

### 3.6 One-way door

Once value sits under secp authorization, removing the verifier is
confiscation. A chain that launches with option 1 can never cleanly become
option 2; a chain that launches with option 2 can always add a secp lane later
by soft addition if the founder so decides. Reversibility alone breaks the tie
between these options — and it breaks it against option 1.

---

## 4. Option 2 — PQ-only accounts: EVM semantics without EVM signing

The EVM executes unmodified — Solidity bytecode, 20-byte addresses, gas,
events. But the only transaction type that exists is a Bloch-typed transaction
authorized by `SUITE_MLDSA65_FALCON1024` (concrete format: §6.1). `ecrecover`
the *precompile* still exists for contracts that want it (it is pure math),
but no transaction is ever authorized by it.

### 4.1 What breaks — named, with the exact reason

| Tool | Verdict | Why, precisely |
|---|---|---|
| **MetaMask** | Never works | Signs secp only. Snaps can run ML-DSA/Falcon in WASM, but MetaMask's custom-account Snap allowlist is closed to mainstream distribution, and a software Snap adds no custody security anyway (verified 2026-07-17, `WALLET-METAMASK-HW-INTEGRATION-PLAN.md` in the G3 repo). |
| **Ledger / Trezor** | Never works (years) | No shipping secure element signs ML-DSA or Falcon; Falcon signing needs constant-time floating-point emulation (see `BLOCH-FALCON-ONLINE-SIGNING.md`), which is research-grade on embedded targets. Ledger's experimental ML-DSA SDK lacks side-channel countermeasures and has no Falcon at all. |
| **ethers.js / viem** | Ports (S effort) | `Wallet` hardcodes secp, but both expose a Signer/Account abstraction; a `BlochSigner` wrapping WASM ML-DSA+Falcon and the §6.1 tx type is a small library. Read paths (`Provider`, `eth_call`, contracts, ABI) work unmodified. |
| **Hardhat** | Plugin (M effort) | Signing is pluggable per network config; a custom signer plugin covers deploy and scripts. In-process unit tests (no real signatures) work unmodified today. |
| **Foundry** | Patch or unlocked-node flow (M effort) | `forge` tests work unmodified (the test VM does not verify sender signatures). `forge script --broadcast` signs secp in Rust; near-term answer is the `--unlocked` flow against a node holding a local PQ keystore; the honest answer for public use is an upstream signer patch. |
| **WalletConnect** | Transport survives, peers don't | The protocol relays JSON-RPC and is signature-agnostic; but the wallet at the other end must produce PQ signatures, and today that set is {Postern wallet}. |
| **Block explorers** | Patch (M effort) | Blockscout-class indexers need the §6.1 tx type decoded and the SHA3 address derivation; everything downstream (contracts, tokens, events) is standard. |
| **Bridges / relayers** | Case-by-case | Anything whose *authorization* is `ecrecover` over validator/user sigs must re-key to the PQ precompile (§6.2). Light-client/proof-verifying bridges are unaffected in principle. |
| **ecrecover contract patterns** | Dead as authorization | EIP-2612 permit, EIP-2771 meta-tx, Safe secp signature checks. Their PQ equivalents exist only via the §6.2 precompile. |

### 4.2 What survives untouched — this list is why option 2 is viable at all

Solidity, Vyper, solc, the entire compiled-contract ecosystem; the ABI;
`eth_call`, `eth_estimateGas`, `eth_getLogs`, storage reads (none of these
carry a user signature); events and indexers; contract-to-contract
composability; audited DeFi bytecode, redeployed as-is. **The signature never
appears inside the EVM** — `msg.sender` is a 20-byte address in every option —
so the loss is confined to the *transaction signing path*, which is exactly
the part Postern already owns: the existing wallet signs
`SUITE_MLDSA65_FALCON1024` for the base chain today, and no third-party HSM or
hardware wallet signs Bloch in *any* option (this is already the exchange-
custody blocker, and option 1 would not fix it — it would just add accounts
that aren't Bloch-secure).

### 4.3 Bytes and capacity — the honest numbers

Derived from §1.1 and §1.3 (marked ≈ where Falcon's variable length matters):

- Steady-state PQ EVM tx: ≈ 100 B body + 4,593 B enveloped signature ≈
  **4.7 KB**. First transaction from an account additionally reveals the
  3,749 B enveloped pubkey (thereafter stored in account state and looked up
  by address — the account model's one genuine gift to a non-recoverable
  suite): ≈ **8.5 KB**.
- Per 100 KB/block of tx budget: ≈ 21 PQ txs ≈ 0.71 tx/s, vs ≈ 680 secp txs.
  **The byte ratio against secp is ≈ 31×.** At the full measured 296 KB
  working point: ≈ 51 tx/block ≈ 1.7 tx/s.

Two things stop this from being a knockout against option 2. First, **this is
not a new cost** — settled decision 2 froze the suite, so every Bloch base
transaction already pays ≈ 4.6 KB per signature; option 1 would not make Bloch
fast, it would make the *vulnerable* lane 31× cheaper than the native one and
invite the whole economy onto it (§3.5). Second, the cost is per-*authorization*,
not per-effect: batching (one signature over many calls, natively supported by
the §6.1 format), contract wallets via the precompile, and the shielded pool
all amortize it. 1.7 tx/s of *authorizations* at launch scale is consistent
with the chain Bloch actually is; it is not consistent with "come deploy your
DEX for Ethereum users", and no document should promise that.

### 4.4 What a wallet must implement, and whether the path is real

Keygen for both families; the §6.1 signing root (SHA3 with a `DS_*` domain
tag, chain id, nonce); ML-DSA-65 signing (unproblematic in software);
**Falcon-1024 signing through the constant-time `clean`/fpemu path only** —
the same rule the validator crate pins with a symbol test (settled decision 2,
`BLOCH-FALCON-ONLINE-SIGNING.md`); envelope wrapping; assembly of an ≈ 8.5 KB
first-use transaction. The path is real because it is already walked: the
Postern wallet signs exactly this suite for the base chain. What is *not* real,
and must be said plainly in user-facing docs: hardware-wallet custody and
MetaMask, for the foreseeable future, in every option that keeps Bloch's
security claim. The only "hardware-equivalent" today is an air-gapped signer on
a general-purpose CPU.

---

## 5. Option 3 — both, dual authorization

Both transaction types verify; secp and PQ accounts coexist in one state.

### 5.1 What it actually buys

MetaMask-day-one (from option 1) while PQ users keep PQ accounts (from
option 2). That is the whole benefit, and it is real — for adoption optics.

### 5.2 What it costs — consensus

- **Two verifier stacks in consensus forever**, and §3.6 applies with teeth:
  the secp lane can never be removed once value sits under it, so "dual as a
  transition" is a fiction unless the sunset is a *launch-day consensus rule*
  (e.g. secp verification hard-stops at a pre-committed height, after which
  those balances are movable only via a PQ-authorized migration op — which is
  confiscation-with-notice for anyone asleep).
- **Account-kind pinning**: secp addresses are `keccak256(pk)[12..]`, PQ
  addresses `SHA3-256(env pk)[..20]` — two derivations into one 20-byte space
  with no domain separation *visible in the address*. The account's kind must
  be pinned in state at first authorization and never mutable; collision
  across derivations is cryptographically negligible but the *kind* logic is
  new consensus surface.
- The full §3.3–§3.4 quantum inventory applies unreduced — including the
  stolen-BLCH-becomes-stake path. Dual does not halve the damage; the damage
  is a function of what the secp lane holds, and adoption pressure (§5.3)
  pushes holdings *toward* that lane.

### 5.3 What it costs — fees, and why no schedule is clean

Gas must price bytes, because bytes are the scarce resource (§1.3). Then:

- **Cost-reflective pricing** (per-byte honest): a secp transfer costs ~31×
  less than a PQ transfer. Every fee-sensitive user and every contract
  deployer rationally chooses the quantum-vulnerable lane; the PQ lane becomes
  a premium curiosity. The fee market *itself* campaigns against the thesis.
- **Equalized pricing** (PQ subsidized to parity): validators carry 31× the
  bytes for the same fee — a gossip/storage DoS vector priced at a discount,
  and G10 recalibration must assume the worst mix.
- Under V4, fees **burn** during the emission years and go to validators after
  (`tokenomics_v4.rs`, `validator_reward_flat_sat` — "fee-only from here on");
  either pricing distortion therefore also distorts burn rate and, post-
  emission, validator income, as a function of *which lane wins*.

There is no third schedule. Dual authorization forces choosing which
distortion to institutionalize.

### 5.4 Verdict

Option 3 is option 1's security posture with option 2's engineering bill,
plus an interaction surface (kind-pinning, dual mempool validation, dual
explorer/wallet matrix, a fee-schedule dilemma) neither pure option has. The
only honest version is the pre-committed-sunset variant, and that variant's
end state is option 2 anyway, reached through a confiscation event. If the
destination is option 2, start there.

---

## 6. The fourth path — what the recommendation is actually made of

The brief invited unlisted options. Two deserve pricing; two exist mainly to
be rejected on the record.

### 6.1 PQ-typed transaction (the vehicle for option 2)

An EIP-2718-style typed transaction (type byte from the unreserved
`0x05..0x7f` range, fixed at implementation):

```
BlochTx {
    type_byte,
    chain_id, nonce, gas_limit, max_fee, to, value, data,   // EVM-standard
    sender:      [u8; 20],          // explicit — nothing is recovered
    sender_pk:   Option<Vec<u8>>,   // enveloped pk; REQUIRED on the account's
                                    // first authorization, FORBIDDEN after
                                    // (state stores pk; two encodings of one
                                    // tx would otherwise exist)
    signature:   Vec<u8>,           // enveloped hybrid sig over the signing root
}
```

Rules: the signing root is `SHA3(DS_EVM_TX ‖ canonical fields)` with a new
16-byte domain tag following the `params.rs` `DS_*` pattern; verification
enforces `address_from_pubkey`-consistency between `sender` and the stored/
revealed pk, the envelope suite must be `SUITE_MLDSA65_FALCON1024` (the
`0x0002` escape hatch stays exactly as available and exactly as unused as it
is in staking — §1.2), and AND-composition is enforced at the split point as
in `verify_hybrid`. `data` may carry a call batch, so one ≈ 4.6 KB signature
amortizes over many calls. CPU is not the constraint: the §6.5.1 spike shows
hybrid verification is dominated by ML-DSA, with Falcon 4.5× cheaper — native
verify is microseconds-scale; **bytes, not cycles, are what gas must defend**
(intrinsic gas per signature byte; calibration belongs to the gas spec, §9).

### 6.2 Hybrid-verify precompile

A precompile `pq_verify(pk_envelope, msg32, sig_envelope) → bool`, thin over
`bloch_crypto::verify`, gas derived from the measured verify cost plus a
per-byte input charge. This is what resurrects the ecrecover-shaped contract
patterns inside option 2: PQ permit, PQ meta-transactions, contract wallets,
PQ-validator bridges, and Ustav/Kirpich charter checks that need signature
verification. Small, priceable, no new cryptography. It should ship with the
first EVM block: without it, option 2's contract ecosystem has no way to
verify its own chain's signatures.

### 6.3 Enshrined account abstraction — phase 2, not launch

Full native AA (every account's validity rule is code, validation-scope rules
à la ERC-4337/EIP-7562) would buy key rotation without address change — the
best long-term PQ-migration story — and future suite agility beyond the
envelope's `u16`. It is also the largest single piece of consensus surface in
this document, with known DoS subtleties in validation scoping. Priced: L
effort, its own spec, its own adversarial review. The §6.1/§6.2 pair neither
requires nor precludes it. Do not put it on the launch critical path.

### 6.4 PQ-bounded secp session keys — priced, and deferred

The tempting middle: a PQ root account signs (once, via Postern wallet) a
delegation to a secp session key with an allowance, expiry, and scope;
MetaMask then drives day-to-day calls; quantum theft is bounded by the
allowance. Honest pricing: it reintroduces the entire secp verifier into
consensus (small code, permanent surface); users set allowances high because
low allowances defeat the convenience; the fee asymmetry of §5.3 returns in
bounded form; and every explorer/wallet must understand delegation state.
It is the only secp-shaped idea compatible with the boundary principle (§2) —
the root of the closure stays PQ — so it is *not* rejected on principle. It is
deferred: revisit only against observed demand, as its own gated spec, never
as a launch feature.

### 6.5 secp256k1 for "non-value-moving" calls — rejected

Reads need no signature at all (`eth_call` is unsigned — §4.2), so the only
thing this lane could authorize is state writes; and writes that "move no
value" — `approve`, `setOwner`, `upgradeTo`, oracle posts — are precisely the
authorization-state changes that *control* value (§2). The lane is either
pointless or unsound at every point in between. Rejected.

---

## 7. Comparison and recommendation

| | 1: secp | 2: PQ-only | 3: dual |
|---|---|---|---|
| MetaMask / Ledger day one | yes | never | yes (secp lane) |
| Hardhat/Foundry/ethers | unmodified | S–M ports (signing path only) | both, dual matrix |
| Marginal tx bytes | ~150 B | ≈ 4.7 KB (≈ 8.5 KB first use) | mix; adverse selection → secp |
| tx/s per 100 KB/block budget | ≈ 22.7 | ≈ 0.71 | between, trending to secp |
| Quantum theft | everything in §3.3 | none at L1 authorization | §3.3 unreduced |
| Stolen funds → stake path | open | closed | open |
| Thesis | negated | intact | negated with better optics |
| Reversible | no (§3.6) | yes — can add lanes later | no |
| New consensus surface | secp verifier | tx type + precompile | all of it + kind-pinning + fee dilemma |

**Recommendation: Option 2, delivered as §6.1 + §6.2, with §6.3 as phase 2
and §6.4 held in reserve.** Four load-bearing reasons, in order:

1. **Reversibility.** Option 2 keeps every door open; options 1 and 3 weld
   theirs shut (§3.6). Under uncertainty this alone decides.
2. **The byte cost is already paid.** The suite is frozen (settled decision 2);
   the base chain carries ≈ 4.6 KB signatures either way. Option 1 doesn't
   buy throughput for Bloch — it builds a discount lane out of the one
   construction the chain exists to retire, and prices it 31× under the
   native one.
3. **The tooling loss is confined to the signing path** (§4.2), and no
   third-party custody signs Bloch's base in *any* option — the signing path
   is already Postern's to own, and Postern's wallet already signs this suite.
4. **The stolen-funds-to-stake path** (§3.4.2) means options 1 and 3 leak
   quantum risk into consensus itself, not merely into user balances. That is
   contamination of the PQ side in the strictest sense, and only option 2
   closes it.

The cost, stated without varnish so the founder decides with eyes open:
**MetaMask never works, no hardware wallet works, and L1 EVM throughput is
authorizations-scale (single-digit tx/s), not Ethereum-scale.** Every public
document must say so. What Bloch offers a Solidity developer is unmodified
bytecode, unmodified tooling up to the signing call, and the only EVM whose
authorization survives the adversary the others are pretending not to see.

---

## 8. Interactions this spec pins (but does not fully design)

### 8.1 The closed leaf list

`state_root.rs` commits a closed set of component tags (`TAG_EUTXO` `0x01`
through `TAG_COHERENCE_NULLIFIERS` `0x08`, state_root.rs:83-90). The EVM
component enters as **one new tag committing the EVM state root** (the
`TAG_TAINT_ROOT` pattern: single leaf, empty entry key), not as per-account
leaves — the EVM keeps its own tree; the SMT commits its root. Growing the
closed list is consensus; it must be one tag, added once, and the
`single_derivation_path` property test's discipline applies: the
account→pubkey map of §6.1 lives *inside* the EVM state, not as a second
component.

### 8.2 Gas versus V4

Gas remains a metering unit; the fee in sat follows V4 unchanged — burned
during emission, to validators after (`tokenomics_v4.rs`). Authorization's
only demand on the gas spec: **intrinsic gas must charge per signature and
pubkey byte** at a rate calibrated to G10's byte budget, so a PQ signature's
footprint is paid by its sender, and batching (§6.1) is what amortizes it.

### 8.3 G10 must be restated

G10's 54 KB average is the attestation floor (§1.3). Before the EVM ships, the
gate needs a second line: attestation floor **plus** the EVM tx budget the
fleet must sustain, validated the same way (≥ 14 days, real fleet, epoch
bursts included), with the 296 KB working point as the current evidence
ceiling. A `MAX_BLOCK_BYTES` consensus constant must exist by then; it does
not today.

## 9. Not decided here

- The account-state ↔ eUTXO value-flow design (how BLCH moves between UTXOs
  and EVM accounts) and the survival/absorption/death of `crates/bloch-euvm` —
  sibling work of this wave. This spec constrains it only via §8.1 and the
  requirement that any move *into* the EVM is authorized by the UTXO side's
  existing rules and any move *out* by §6.1.
- The gas schedule numbers (§8.2 gives the calibration requirement only).
- Precompile gas constants and the §6.1 type byte (implementation-time, with
  measurements).
- Shielded-pool ↔ EVM interaction: the Coherence pool is C1-frozen (settled
  decision 3); nothing here touches it, and no EVM path may mint into or burn
  out of the pool except through the pool's own frozen rules.
