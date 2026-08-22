<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-L1-EVM-PQ-TX — the PQ-typed transaction and the hybrid-verify precompile

```
Document:   BLOCH-L1-EVM-PQ-TX
Status:     SPEC — implementation scope for §6.1 + §6.2 of the authorization
            dossier. No code exists yet. Nothing here is consensus-wired.
Created:    2026-08-22
Owner:      EVM authorization lead
Decision:   D-AUTH IS TAKEN. The founder chose OPTION 2 (PQ-only accounts:
            EVM semantics without EVM signing) on 2026-08-21, on the
            recommendation of docs/specs/BLOCH-L1-EVM-AUTHORIZATION.md §7.
            This document implements the vehicle of that decision and
            NOTHING ELSE.
Relates:    docs/specs/BLOCH-L1-EVM-AUTHORIZATION.md (the decided dossier;
              §6.1 and §6.2 are the scope, §6.3/§6.4 are deferred, §6.5 is
              rejected)
            docs/specs/BLOCH-L1-EXECUTION-PLAN.md (SR-2, milestones E2/E5/X1/X2)
            docs/adr/ADR-040-evm-and-ustav-at-l1.md
            docs/specs/BLOCH-L1-EVM-RPC-SURFACE.md §5.2 (branch B)
            docs/specs/BLOCH-L1-EVM-REUSE-AUDIT.md (src/txdecode.rs, src/txtype.rs)
            crates/bloch-crypto/src/crypto/mod.rs (the suite envelope)
            crates/bloch-pos-committee/src/staking.rs (verify_hybrid, the AND rule)
            crates/bloch-pos-committee/src/fee_market.rs (TxClass::EvmPq — already priced)
            crates/bloch-pos-committee/src/params.rs (DS_* tags, flag-day idiom)
```

## 0. The posture, stated before anything else

**The EVM is not at L1 and nothing in this document puts it there.** This
specifies a standalone, pure, dependency-light crate — a vehicle built inert,
behind a flag day pinned at `u64::MAX`, with **no call site anywhere in the
node's state-transition path**. `crates/bloch-euvm` and the planned
`crates/bloch-sbpf` hold exactly this posture; this crate copies it.

Wiring it in collides with ADR-040 and with the SR-2 single-re-freeze rule
(`BLOCH-L1-EXECUTION-PLAN.md` §0). That collision is escalated, not worked
around. **Activation is a separate founder decision** and lands as milestone
X2, after X1, with the fleet rebuilt first.

The urgency is not theoretical: at the time of writing mainnet finality has
been stalled for 27 epochs and blocks arrive roughly one per 40 slots. A line
of this crate reaching consensus by accident is not a red test — it is an
incident. Hence: the crate is not a member dependency of `bloch-pos-node`, and
the acceptance criterion in §9.4 is a grep, not an opinion.

**What is decided (D-AUTH) and must be repeated in every public document:**
MetaMask never works. No hardware wallet works. L1 EVM throughput is
**authorizations-scale, single-digit tx/s** — the unit is a signature, not an
effect. `BLOCH-L1-EVM-AUTHORIZATION.md` §7 is the source; do not soften it.

**What this document does NOT do:** re-open D-AUTH; implement §6.3 (enshrined
account abstraction — phase 2); implement §6.4 (PQ-bounded secp session keys —
deferred, revisit only against observed demand); implement §6.5 (rejected);
touch `state_root.rs`, the closed component list, or `EvmCommitment`; touch the
gas schedule (`fee_market::TxClass::EvmPq` already prices this transaction —
see §7); touch `bloch-euvm`; add a secp256k1 verifier anywhere.

If an implementer finds they need any of the above, that is the signal that
scope has moved, and the answer is to stop and escalate — not to widen the PR.

---

## 1. Crate shape

```
crates/bloch-l1-evm-auth/          # the envelope + the precompile logic
  src/lib.rs         # activation gate, error taxonomy, module docs
  src/tx.rs          # BlochTx struct, canonical encode/decode (§3)
  src/root.rs        # signing root, txid (§4)
  src/verify.rs      # the authorization rules (§5) — the whole point
  src/batch.rs       # the call-batch payload (§6)
  src/precompile.rs  # pq_verify input/output/gas (§8)
  tests/             # §9, including the mutation matrix
```

**Workspace membership.** A **member of the root workspace**, with **no
private `[workspace]` table**. The root `Cargo.toml` states the rule and the
reason: a crate carrying its own workspace is invisible to `cargo test
--workspace`, "that is how the entire PoS consensus once went untested".
`BLOCH-L1-EXECUTION-PLAN.md` §2 (E2) says "own workspace" for the sibling
engine crate; **that phrasing is superseded by the root manifest** and E2's
line should be corrected when it is next touched. Flagged, not silently
diverged from.

**Dependencies:** `sha3` only. No `revm`, no `alloy`, no `k256`/`secp256k1`,
no `bloch-crypto` (see the seam below), no node crates, no `serde`, no I/O, no
clock, no `HashMap` (`BTreeMap` where ordering can be observed).
`#![forbid(unsafe_code)]`. The workspace release profile already pins
`overflow-checks = true`; every arithmetic site is additionally checked in
source and returns `Err`, never wraps and never panics.

**The verifier seam.** The crate does **not** link the PQClean FFI. It takes
verification through a trait, exactly as `staking.rs` does and for the same
two reasons: the crate stays testable without the C stack, and the
AND-composition lives *here* rather than in whatever the caller injects.

```rust
pub trait HybridKeyVerifier {
    fn verify_mldsa65(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool;
    fn verify_falcon1024(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool;
}
```

Identical in shape to `staking::HybridKeyVerifier`, and deliberately so: the
halves are exposed *separately* so no implementation can degrade the hybrid to
an OR. The node supplies the real one over `bloch_crypto`'s raw-half entry
points (`verify_mldsa65_raw` and the Falcon half) at wiring time.

**The state seam.** The account→pubkey map lives *inside the EVM state*
(`BLOCH-L1-EVM-AUTHORIZATION.md` §8.1 — it is not a second state-root
component, and this crate must not create one). The crate reads it through:

```rust
pub trait PubkeyDirectory {
    /// The enveloped hybrid public key already recorded for this account, or
    /// `None` if the account has never authorized a transaction.
    fn pubkey_of(&self, sender: &[u8; 20]) -> Option<&[u8]>;
}
```

Pure lookup. The crate never writes; it returns, on success, the pk that the
caller (E2) must record on first authorization.

---

## 2. Constants this crate freezes

| Constant | Value | Why |
|---|---|---|
| `TX_TYPE_PQ_CALL` | `0x50` | EIP-2718 leading byte, in the unreserved custom range (`0x05..0x7f` per the dossier §6.1; `0x40..0x7f` per `BLOCH-L1-EVM-RPC-SURFACE.md` §5.2, which suggests `0x50`). `0x50` satisfies both — pick it and stop having two answers. |
| `TX_TYPE_PQ_BATCH` | `0x51` | The call-batch kind (§6). |
| `SUITE_MLDSA65_FALCON1024` | `0x0001` | The only suite this transaction accepts. |
| `MLDSA65_PK_BYTES` / `FALCON1024_PK_BYTES` / `HYBRID_PK_BYTES` | 1,952 / 1,793 / 3,745 | Restated from `staking.rs` as consensus constants of this module, same as staking restates them. |
| `MLDSA65_SIG_BYTES` | 3,309 | The fixed positional split. **No length prefix** — one signature, exactly one encoding. |
| `SUITE_HEADER_LEN` | 4 | `0xB1 0x0C ‖ suite_u16_le`. |
| `DS_EVM_TX` | `*b"BLCH4:EVMTX\0\0\0\0\0"` | New 16-byte tag, right-padded with zeros so no tag prefixes another — the `params.rs` pattern, followed exactly. Signing root domain. |
| `DS_EVM_TXID` | `*b"BLCH4:EVMTXID\0\0\0"` | Transaction identity, derived from the witness-free signing root — the `DS_TXID` idiom (§4.2). |
| `DS_EVM_CALL` | `*b"BLCH4:EVMCALL\0\0\0"` | The precompile's message domain (§8.2). |
| `ACTIVATION_EPOCH` | `u64::MAX` | Flag day. Inert until the founder lowers it, fleet rebuilt first. |

**Where the flag day lives.** In this crate, at `u64::MAX`, for now — putting
it in `params.rs` today means editing a consensus crate for a rule with no
consensus reader. The wiring PR (X2) relocates it to `params.rs` beside
`LEAKED_ROSTER_ACTIVATION_EPOCH` and `BLOCK_BYTES_V2_ACTIVATION_EPOCH` **in
the same PR that adds the gate**, so it is never defined in two places.

**How the gate is read — the 2026-08-08 rule.** Every entry point takes the
epoch as an explicit parameter:

```rust
pub fn verify(tx: &BlochTx, epoch: u64, dir: &dyn PubkeyDirectory,
              v: &dyn HybridKeyVerifier) -> Result<Authorized, AuthReject>;
```

`epoch` is derived **by the caller, from the block's own header slot**, and is
never read from node-local state. The crate cannot read node state — it has no
way to. This is structural, not a convention: on 2026-08-08 this chain forked
because `expected_bits` came from local mutable state and nodes with identical
binaries diverged. The gate returns `AuthReject::NotActivated` for
`epoch < ACTIVATION_EPOCH`, which at `u64::MAX` is every epoch that will ever
exist.

---

## 3. The transaction

```rust
pub struct BlochTx {
    pub type_byte: u8,          // TX_TYPE_PQ_CALL | TX_TYPE_PQ_BATCH
    pub chain_id:  u64,
    pub nonce:     u64,
    pub gas_limit: u64,
    pub max_fee:   u128,        // millisat per gas — fee_market's unit, not a second one
    pub to:        Option<[u8; 20]>,  // None = contract creation
    pub value:     u128,        // satoshi
    pub data:      Vec<u8>,
    pub sender:    [u8; 20],    // EXPLICIT. Nothing is ever recovered.
    pub sender_pk: Option<Vec<u8>>,   // enveloped pk; REQUIRED on the account's
                                      // first authorization, FORBIDDEN after
    pub signature: Vec<u8>,     // enveloped hybrid signature
}
```

### 3.1 Canonical encoding — one encoding, or it is malleability

Wire form is `type_byte ‖ payload`. The payload is **not RLP**. RLP admits
non-minimal integer encodings and this repo's rule, from `DS_TXID` through
the hybrid signature's fixed split point, is that one object has exactly one
encoding. The payload follows the house codec of
`transition.rs` — fixed-width little-endian scalars, 4-byte length prefixes on
byte strings, in declaration order:

```
u64 chain_id ‖ u64 nonce ‖ u64 gas_limit ‖ u128 max_fee
‖ u8 to_present ‖ [20]to (present only if to_present == 1)
‖ u128 value ‖ u32 data_len ‖ data
‖ [20]sender
‖ u8 pk_present ‖ u32 pk_len ‖ pk   (both present only if pk_present == 1)
‖ u32 sig_len ‖ sig
```

Decoder rules, all of them fail-closed:

- `to_present` and `pk_present` MUST be exactly `0` or `1`. `2` is not "true".
- **Trailing bytes are a rejection**, never ignored. This chain has already
  paid for that lesson: nodes built before the AuxPoW merge froze at block
  10802 on "trailing bytes in block body".
- Length prefixes MUST match the bytes that follow; truncation is a rejection.
- `data_len` MUST be within the caller-supplied payload budget
  (`fee_market::max_block_tx_bytes(epoch)`); the crate takes the budget as a
  parameter and never assumes a constant.
- Malformed input returns `Err`. **Never a panic** — consensus rule.
- Re-encoding a decoded transaction MUST reproduce the input byte for byte.
  This is a property test (§9.1), not a comment.

### 3.2 Sizes and what they buy

Fixed fields sum to 107 bytes with an empty `data` and no pubkey (five more
bytes carry the pubkey's presence flag and length prefix when one is
present). The enveloped hybrid signature is ≈ 4,593 B (worst case 4,775 — Falcon-1024's signature is variable and the
split point, not a length prefix, is what makes it unambiguous). Enveloped
hybrid pubkey is 3,749 B.

- steady-state transfer: **≈ 4,700 B ≈ 4.7 KB**
- first authorization from an account: **≈ 8,453 B ≈ 8.5 KB**

Against the live payload cap `MAX_BLOCK_TX_BYTES_V2` = 524,288 B (active from
epoch 800) and 30-second slots: **≤ 111 authorizations per block ≈ 3.7/s** if
the *entire* payload were EVM — which it is not; the cap is shared with eUTXO
transfers, attestations and everything else. The honest public number stays
what the dossier says: single-digit tx/s, and the unit is the authorization.

---

## 4. The signing root and the transaction id

### 4.1 Signing root

```
signing_root = SHA3-256( DS_EVM_TX
                       ‖ u8 type_byte
                       ‖ u64 chain_id ‖ u64 nonce ‖ u64 gas_limit ‖ u128 max_fee
                       ‖ u8 to_present ‖ [20]to?
                       ‖ u128 value ‖ u32 data_len ‖ data
                       ‖ [20]sender )
```

All scalars little-endian, matching `DepositTx::signing_root`.

**`sender_pk` and `signature` are deliberately NOT in the root.** The
signature cannot be inside the root it is produced over; and the pubkey is
excluded for a reason worth stating, because the obvious alternative has a
live failure mode:

- The root binds the **20-byte `sender`**, which *is* `SHA3-256(enveloped
  pk)[..20]`. Covering the address covers the key, up to second-preimage
  resistance on 160 bits — the same tier this chain already accepts for every
  carried Genesis-3 output (`transition.rs::owns`). A key-substitution attack
  needs a *second preimage* of an existing account's address (2^160), not a
  birthday collision: grinding two of your own keys to one address buys
  nothing, because both keys are yours.
- Had the pk been inside the root, the root would depend on whether the
  account is at first use — a fact the wallet learns only from state at
  *inclusion* time. Two transactions in flight, the first replaced or dropped,
  and the second's encoding assumption breaks. Excluding the pk makes the
  signature independent of that race.

Consequence, stated so nobody discovers it in production: an attacker who
strips a required `sender_pk` (or adds a forbidden one, using a pk the account
already revealed) produces a transaction that **fails validation** — §5. It is
drop-equivalent censorship, never theft, and it cannot change the id (§4.2).

### 4.2 Identity

```
evm_txid = SHA3-256( DS_EVM_TXID ‖ signing_root )
```

Derived from the witness-free root, following `DS_TXID` exactly: nobody can
re-key a transaction in flight by re-encoding its witness. Both encodings of
one authorization therefore share one id, which is what keeps the mempool from
holding two entries for one effect.

---

## 5. The authorization rules — the whole point of the crate

`verify(tx, epoch, dir, verifier)` applies, in this order, each with its own
reject variant (one variant per reason; "invalid" alone makes a divergence
undebuggable from logs — the `DepositReject` idiom):

1. `epoch >= ACTIVATION_EPOCH` else `NotActivated`.
2. `type_byte ∈ {TX_TYPE_PQ_CALL, TX_TYPE_PQ_BATCH}` else `UnknownType`.
3. `chain_id` equals the caller-supplied chain id else `WrongChain`.
4. **Suite.** Parse the 4-byte envelope on `signature`, and on `sender_pk` if
   present. Both MUST carry the magic `0xB1 0x0C` and suite **exactly
   `0x0001`**, else `WrongSuite`.
   - `0x0002` (`SUITE_MLDSA65_ONLY`) is rejected. The escape hatch stays
     exactly as available and exactly as unused as it is in staking
     (`staking.rs:52-56`): a single-family suite would silently drop the
     hybrid property for that account's whole lifetime.
   - **The legacy un-headered fallback is NOT accepted here.**
     `bloch_crypto::verify` accepts a bare `mldsa ‖ falcon` blob as suite
     `0x0001` because carry-over wallets predate the envelope. There is no
     carry-over EVM account — the plane does not exist yet — so this path
     requires the explicit envelope. Accepting both would also mean two
     addresses for one key, since the address hashes the *enveloped* bytes.
     This is why the crate parses the envelope itself instead of handing bytes
     to `bloch_crypto::verify`.
5. **The `sender_pk` presence rule.** Let `stored = dir.pubkey_of(&tx.sender)`.
   - `stored.is_none() && tx.sender_pk.is_none()` → `MissingPubkey`. The
     verifier has no key and nothing to verify against; a non-recoverable
     suite cannot invent one.
   - `stored.is_some() && tx.sender_pk.is_some()` → `RedundantPubkey`. **Even
     if the bytes are identical.** This is the subtle one and it is not
     defensive pedantry: "present and equal is also fine" would make two
     encodings of one transaction valid at the same instant, and two encodings
     is malleability. The rule is presence, not equality.
   - Exactly one of the two is present → continue with that key as `pk`.
6. **Address consistency.** `SHA3-256(pk)[..20] == tx.sender` else
   `AddressMismatch`. Nothing is recovered; `sender` is a claim and this is
   the check that makes the claim binding. **If an address can be authorized
   by a key that is not its own, that is theft** — §9.2 tests exactly that,
   with a control.
7. **Hybrid verification, AND at the split point.**

   ```rust
   if sig_body.len() <= MLDSA65_SIG_BYTES { return Err(BadSignature); }
   let (mldsa_pk, falcon_pk)   = pk_body.split_at(MLDSA65_PK_BYTES);
   let (mldsa_sig, falcon_sig) = sig_body.split_at(MLDSA65_SIG_BYTES);
   verifier.verify_mldsa65(mldsa_pk, &root, mldsa_sig)
       && verifier.verify_falcon1024(falcon_pk, &root, falcon_sig)
   ```

   `pk_body.len()` MUST equal `HYBRID_PK_BYTES` exactly (`BadPubkeyLength`).
   A signature with no room for a Falcon half is **malformed, not "a valid
   ML-DSA-only signature"** — rejecting it here is what keeps the escape hatch
   an explicit decision rather than a parsing accident (`verify_hybrid`'s own
   words). AND, never OR: read `staking.rs:128-149` and follow it. Short-
   circuiting is safe — this is a verification path, no secret is present.
8. On success return `Authorized { sender, evm_txid, pubkey_to_record }`,
   where `pubkey_to_record` is `Some(pk)` exactly when this was the account's
   first authorization. **The crate does not write state**; E2 records it.

Nonce, balance, gas and fee sufficiency are **not** this crate's job — they
are execution-layer checks in E2, against state this crate cannot see.

---

## 6. The call batch (§6.1's "`data` may carry a call batch")

The dossier's throughput argument rests on one ≈ 4.6 KB signature amortizing
over many operations. Two ways to get there, and only one preserves the sender:

- A multicall **contract** needs no consensus surface at all — but then
  `msg.sender` for every sub-call is the multicall contract, not the user,
  which breaks token allowances and every `Ownable` check. It does not deliver
  what §6.1 claims.
- A contract **wallet** delivers it via account abstraction — which is §6.3,
  explicitly deferred to phase 2.

So the batch is a transaction *kind*: `type_byte = TX_TYPE_PQ_BATCH`, where
`data` is the canonical batch payload:

```
u32 count ‖ count × ( u8 to_present ‖ [20]to? ‖ u128 value ‖ u32 len ‖ calldata )
```

`count >= 1`; strict decode; trailing bytes rejected; the whole payload is
covered by the signing root because `data` is. The crate provides the
**decoder and its rules only**.

**Semantics are E2's, and they are new consensus surface:** every sub-call
executes with `msg.sender` = the PQ account; the batch is atomic (any sub-call
reverting reverts the whole transaction); gas is metered per sub-call against
the one `gas_limit`; `count` is bounded by the payload budget. Because those
are consensus semantics rather than an encoding, **`TX_TYPE_PQ_BATCH` is
ratified by the founder at wiring time, not by this document**. It is
specified now because it costs nothing while inert and because leaving it out
would leave §6.1's amortization claim without a mechanism.

---

## 7. Gas — already priced, do not re-price

`fee_market::TxClass::EvmPq` exists and is calibrated:
`intrinsic_gas = TX_FLAT_GAS (5,000) + tx_bytes × GAS_PER_BYTE (16) +
HYBRID_VERIFY_GAS (72,748)`.

For a 4,700-byte steady-state transaction: **152,948 gas**. First use
(8,453 B): **212,996 gas**. Against `BLOCK_GAS_LIMIT` = 60,000,000 that is 392
transactions per block by gas, versus **111 by bytes**. **Bytes bind, not
gas** — precisely the dossier's "bytes, not cycles, are what gas must defend",
now a checkable inequality rather than a sentence. §9.1 asserts it, so that a
future gas edit that inverts it fails a test instead of silently making
signature bytes the cheap resource.

This crate **defines no gas constant of its own**. The one exception is the
precompile's own charge (§8.3), which is derived from `fee_market`'s constants
and belongs to the precompile, not to the transaction.

Two follow-ups for the fee-market owner, as separate PRs under the
two-reviewer rule — **not in this crate's PR**:

- `TxClass::EvmSecp256k1` and `SECP256K1_VERIFY_GAS` are documented as
  "priced but gated on the founder's dual-authorisation decision". That
  decision is now made and it is option 2: the arm is unreachable. The doc
  comments should record D-AUTH rather than leaving a reader to conclude the
  question is open.
- G10's byte gate needs its second line (dossier §8.3: attestation floor plus
  an EVM tx budget, ≥ 14 days on the real fleet) before any activation.

---

## 8. The hybrid-verify precompile (§6.2)

Without it, option 2's contract ecosystem has no way to verify its own chain's
signatures: PQ permit, PQ meta-transactions, contract wallets, PQ-validator
bridges, Ustav/Kirpich charter checks. It ships with the first EVM block.

### 8.1 Address and shape

Address `0x00000000000000000000000000000000000000ff` — high enough in the
precompile space that upstream Ethereum's continued allocation from `0x01`
upward will not collide with it for the foreseeable future.

Input is standard Solidity ABI encoding of `(bytes pk, bytes32 msg, bytes sig)`
so a contract calls it with `abi.encode(...)` and a `staticcall`. Strict
decode: non-canonical offsets, oversized lengths and trailing padding are all
failures. Output is 32 bytes: `0x…01` true, `0x…00` false.

**It never reverts and never panics.** Malformed input returns false. A
precompile that reverts on some inputs and not others is a divergence surface
between implementations; a total function is not.

### 8.2 The message domain — a decision this document takes

The precompile verifies over

```
SHA3-256( DS_EVM_CALL ‖ u64 chain_id ‖ msg32 )
```

not over `msg32` directly. The dossier calls the precompile "thin over
`bloch_crypto::verify`" and leaves the domain open; one extra hash keeps it
thin and closes a real hole. Without it, a contract can hand a user an
arbitrary 32-byte digest to sign — and a digest is a digest: if it happens to
be some transaction's `signing_root`, the "signature over a message" is also a
signature that **moves that user's funds**. Domain separation makes a
precompile signature and a transaction authorization mutually unreplayable,
which is what every tag in `params.rs` exists for. The chain id is inside for
the same reason it is inside the transaction root.

Wallet rule that goes with it, in the wallet docs: never sign a 32-byte blob
the wallet did not construct itself.

Suite rule: **`0x0001` only**, envelope required, legacy blob rejected — the
same rules as §5.4, from the same code path.

### 8.3 Gas

`PQ_VERIFY_GAS = HYBRID_VERIFY_GAS (72,748) + input_len × GAS_PER_BYTE (16)`,
both from `fee_market`, so there is one calibration and one place to edit.

**Charged from the input length, before verification, and charged in full on
malformed input.** A cheap failure path is a DoS invitation: an attacker who
can make an invalid input cost less than a valid one has found a free way to
make every node work. Malformed costs exactly what well-formed costs.

---

## 9. Tests — and the rule that a green suite proves nothing

Every negative test carries a **control half** that must pass with the same
fixture and one field changed back. A rejection test that would also pass
against a function returning `Err` unconditionally is not a test.

### 9.1 Properties

- **Round-trip:** `decode(encode(tx)) == tx`, and `encode(decode(bytes)) ==
  bytes` byte for byte. Random and adversarial fixtures.
- **Every field is bound:** mutating any single field in the signing-root
  preimage changes the root — the `deposit_signing_root_binds_every_field`
  pattern, pairwise-distinct across all mutants, including `type_byte` and
  `sender`.
- **Domain separation:** no `DS_EVM_TX` root equals a `DS_EVM_TXID`,
  `DS_EVM_CALL`, `DS_DEPOSIT` or `DS_SPEND` digest of the same bytes; and the
  three new tags are 16 bytes, so none prefixes another.
- **Totality:** a fuzz corpus of arbitrary bytes through `decode` and through
  the precompile never panics — `cargo fuzz` targets, in the excluded `fuzz`
  workspace, plus a seeded proptest run in CI.
- **Bytes bind before gas:** `MAX_BLOCK_TX_BYTES_V2 / 4,700 <
  BLOCK_GAS_LIMIT / intrinsic_gas(EvmPq, 4,700)` — asserted, so a future gas
  edit that makes signature bytes the cheap resource turns a test red.

### 9.2 Named negative/control pairs

| Test | Negative | Control |
|---|---|---|
| First-use pk missing | fresh account, `sender_pk = None` → `MissingPubkey` | same tx with the correct pk → accepted |
| Later pk present | account with a stored pk, `sender_pk = Some(same bytes)` → `RedundantPubkey` | same tx with `sender_pk = None` → accepted |
| **Theft** | valid signature by key B over a tx whose `sender` is A's address → `AddressMismatch` | the same signature with `sender` = B's address → accepted |
| Wrong-key stored | `sender` matches, but `dir` returns a *different* key → `AddressMismatch` | `dir` returns the right key → accepted |
| Half-forged (ML-DSA) | valid Falcon half, garbage ML-DSA half → `BadSignature` | both halves valid → accepted |
| Half-forged (Falcon) | valid ML-DSA half, garbage Falcon half → `BadSignature` | both halves valid → accepted |
| Truncated to ML-DSA | `sig_body.len() == MLDSA65_SIG_BYTES` exactly → `BadSignature` | full hybrid → accepted |
| Escape hatch | suite `0x0002` on pk or sig → `WrongSuite` | suite `0x0001` → accepted |
| Legacy blob | un-enveloped `mldsa‖falcon` pk → `WrongSuite` | enveloped → accepted |
| Suite mismatch | pk `0x0001`, sig `0x0002` → `WrongSuite` | both `0x0001` → accepted |
| Cross-chain replay | valid tx, other `chain_id` → `WrongChain` | matching chain id → accepted |
| Cross-domain replay | signature produced over a `DS_EVM_CALL` message, presented as a tx → `BadSignature` | the tx's own root → accepted |
| Trailing bytes | valid encoding ‖ `0x00` → `Err` | without the byte → decodes |
| Bool smuggling | `to_present = 2` → `Err` | `= 1` → decodes |
| **Flag day** | `epoch = u64::MAX - 1`, otherwise valid → `NotActivated` | `epoch = u64::MAX` → accepted |
| Batch decode | `count = 0`; truncated sub-call; trailing bytes → `Err` | well-formed batch → decodes |
| Precompile | short input, bad offsets, wrong suite → false, gas charged in full | valid triple → true |

### 9.3 Proof by mutation — required, not optional

A review on 2026-08-21 reverted two consensus sites and **489 tests stayed
green**. The suite is therefore not evidence until it kills the following
mutants; the harness (`cargo-mutants`, or a scripted patch/build/test loop) is
part of the deliverable and runs in CI. Each mutation MUST turn the suite red,
and the PR records which test caught which:

1. `&&` → `||` at the hybrid AND site.
2. `MLDSA65_SIG_BYTES` split point → ±1.
3. `MLDSA65_PK_BYTES` split point → ±1.
4. `sig.len() <= MLDSA65_SIG_BYTES` → `<`.
5. Address-consistency check deleted.
6. Address comparison truncated to 8 bytes.
7. `RedundantPubkey` relaxed to "present and equal is fine".
8. `MissingPubkey` relaxed to "verify against nothing, accept".
9. Suite check `== 0x0001` → `!= 0x0000`.
10. Strict envelope → `parse_envelope_or_legacy` fallback.
11. Trailing-byte rejection deleted from the decoder.
12. Activation gate `>=` → `>`, and gate deleted entirely.
13. `chain_id` dropped from the signing-root preimage.
14. `sender` dropped from the signing-root preimage.
15. `DS_EVM_CALL` dropped from the precompile's message.
16. Precompile gas charged only on success.

A mutant that survives is a missing test, and the missing test is written
before the PR moves.

### 9.4 Inertness — the acceptance criterion, mechanical

CI asserts all four:

1. `bloch-l1-evm-auth` appears in **no** `[dependencies]` of
   `bloch-pos-node`, `bloch-pos-committee`, or any crate they pull.
2. `ACTIVATION_EPOCH == u64::MAX`.
3. `grep -rn "bloch_l1_evm_auth" crates/bloch-pos-*/src/` is empty.
4. `cargo test --workspace` passes with the crate as a member, and the node
   binary's dependency tree is byte-identical to the pre-PR tree.

---

## 10. Sequencing, and what each step is allowed to touch

| Step | Deliverable | Touches |
|---|---|---|
| A1 | this spec | `docs/specs/` only |
| A2 | crate skeleton, constants, error taxonomy, seams, `ACTIVATION_EPOCH = u64::MAX` | new crate + one line in root `members` |
| A3 | §3 codec + §4 roots, with §9.1 properties and the fuzz targets | new crate only |
| A4 | §5 verification, with the full §9.2 pair matrix | new crate only |
| A5 | §6 batch decoder | new crate only |
| A6 | §8 precompile logic (pure — no revm) | new crate only |
| A7 | §9.3 mutation harness in CI + §9.4 inertness assertions | new crate + CI config |
| A8 | doc-fix PR: `BLOCH-L1-EVM-RPC-SURFACE.md` §5.2's address derivation (§11), E2's "own workspace" phrasing | `docs/` only |
| — | **STOP.** Wiring is X2, after X1, after the founder. | — |

`bloch-crypto`, `bloch-pos-committee`, `bloch-pos-node` and `bloch-euvm` are
**not touched by any step**. The one exception in step A2 is adding the crate
to the root workspace `members` list, which the root manifest mandates.

---

## 11. Contradictions found in the existing docs, flagged not silently resolved

1. **Two address derivations.** `BLOCH-L1-EVM-RPC-SURFACE.md` §5.2 says the
   sender address is "20 bytes of SHA3-256(suite ‖ pubkeys)". The dossier
   pins `address_from_pubkey` = `SHA3-256(enveloped pk)[..20]`, whose preimage
   is `0xB1 0x0C ‖ suite_le ‖ mldsa_pk ‖ falcon_pk`. Those are different
   preimages and therefore **different addresses for one key**. The dossier is
   the decided document and this spec follows it; the RPC doc's sentence is
   wrong and step A8 fixes it. Until then, no implementer should read that
   line as authority.
2. **Workspace membership.** `BLOCH-L1-EXECUTION-PLAN.md` §2 says the new EVM
   crates get their "own workspace"; the root `Cargo.toml` forbids exactly
   that, with the reason. Root manifest wins (§1); the plan's line needs the
   same correction.
3. **The EVM state leaf already exists.** `state_root.rs` carries
   `EvmCommitment` (account root, receipts root, gas used, base fee) and
   `transition.rs` commits it. The dossier §8.1 discusses the leaf as future
   work and SR-2 treats the re-freeze as pending. Whoever owns X1 should
   confirm which statement is current before the re-freeze round is planned —
   flagged, unsure, and **outside this spec's scope**: this crate does not
   touch the state root either way.

## 12. Not decided here

`bloch-euvm`'s fate; the eUTXO ↔ EVM value flow; chainId (8400 reuse versus a
new id — note that under option 2 no secp-signed `bloch-l2-evm` transaction
can ever replay here, since no secp transaction verifies at all, which removes
the replay argument against reuse but not the identity argument); the precompile
address if a future upstream allocation reaches it; and the activation epoch,
which is the founder's, once G10 has its second line and the fleet is rebuilt.
