<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — Transaction Format, Signing Procedure and Address Specification


> ### STATUS — RECOVERED AND VERIFIED, NOT PUBLISHABLE AS WRITTEN
>
> This document was written on **2026-08-13** from measurement, on the branch
> `worktree-agent-a95fe62ba79532310`
> (commit `42653509`), and was never landed. It existed on that ref and on no
> other; it is recovered here on **2026-09-01**, before that branch is deleted,
> because the measurement in it is worth keeping.
>
> **It has not been rewritten.** The body below is the 2026-08-13 text
> verbatim. Every falsifiable claim in it was re-checked against `main` @
> `737078d1` on 2026-09-01, and where the tree has since moved, a
> **CORRECTION** block sits immediately above the affected section. Read those
> blocks; the prose underneath them was true when written and is not true now.
>
> **Eight corrections below. Four of them are not editorial** — following the
> uncorrected text would cause real harm, not just confusion.
>
> The full verdict, claim by claim — including what could **not** be verified
> from source alone and needs a live node — is in
> `docs/integration/BLOCH-G4-DOCS-VERIFICATION-2026-09-01.md`.
>
> Do not send this to an integrator, and do not publish it, until §§ marked
> CORRECTION are rewritten and the captures re-measured against a current node.

```
Document:   BLOCH-G4-TRANSACTIONS
Audience:   Exchange integration, custody and wallet engineering
Status:     Partner document — NOT for publication. Deliver as a file.
Scope:      Transactions, signing, addresses. The RPC method surface is
            BLOCH-G4-RPC.md; the Genesis-3 → Genesis-4 snapshot mapping is
            covered separately. Neither is restated here.
Repository: BlochPOS, branch merge/pos-into-main
Source:     crates/bloch-pos-committee/src/transition.rs   (the rules)
            crates/bloch-pos-committee/src/params.rs       (domain tags)
            crates/bloch-pos-committee/src/fee_market.rs   (the fee)
            crates/bloch-crypto/src/crypto/mod.rs          (the suite)
            crates/bloch-crypto/src/address.rs             (addresses)
            crates/bloch-pos-node/src/main.rs              (submit-tx)
Verified:   2026-08-13, by building this branch and executing the code.
            §12 states exactly what was and was not executed.
```

---

## 0. Read this first — the custody reality

**No HSM on the market signs ML-DSA-65 ‖ Falcon-1024.**

This is not a gap waiting on a vendor roadmap, a firmware update, or a later
chain version. Bloch's signature suite is two lattice schemes ANDed together
(`crates/bloch-crypto/src/crypto/mod.rs:204-226`). Every commercial HSM,
every Ledger and Trezor, every cloud KMS signs over elliptic curves —
secp256k1, P-256, Ed25519. None of them has an ML-DSA implementation you can
load a Bloch key into, and none of them has Falcon at all. A device that
signed only one of the two halves would produce a signature Bloch consensus
rejects, because both halves are verified.

The consequence, stated without softening: **an exchange holds Bloch keys in
software, under its own controls, or it does not hold Bloch.** The controls
that remain available to you are the ordinary ones — an air-gapped signing
host, HSM-held encryption of the key file at rest, multi-party approval in
front of the signer, hardware-backed operator authentication — but the
signing operation itself happens in general-purpose memory on a machine you
own. Plan the threat model around that, and price the operational cost of it,
before you commit to a listing date.

Two properties of the Genesis-4 design make this materially more workable
than it sounds, and both are load-bearing in §5:

1. The signing root is a **32-byte digest** that depends on nothing secret.
   Your transaction builder can be an ordinary online service; only the step
   that turns 32 bytes into a signature needs the key. The two can be on
   different machines, on different networks, with a one-way channel between
   them.
2. The node's own tooling refuses to hold keys. `bloch-pos submit-tx` prints
   the digest and stops (§5.3). There is no code path in this repository that
   generates a spending key on a node, and `getnewaddress` answers with a
   permanent refusal (`crates/bloch-pos-node/src/rpc.rs:208-237`).

There is one further custody fact you need before you design anything, and it
is in §10: **as this branch stands, no output in existence is spendable.**
That bounds what §12 could verify and it bounds what you can pilot.

---


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **Two variants move value now, not one.** `transition.rs:295-437` defines six
> variants; `TransferV2` (wire tag **`0x06`**, `transition.rs:370-385`, encoded
> at `:629-651`, decoded at `:783-820`) is a witness-deduplicated transfer: a
> per-owner witness table (`WitnessKey{pubkey, signature}`) plus 40-byte inputs
> (`TransferInputV2{txid, vout, key_index}`).
>
> Its signing root and txid are **byte-identical** to V1's — both fold through
> one helper (`transition.rs:474-531`) — so a wallet signature is valid under
> either encoding. It is gated on
> `params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH = 800` (`params.rs:301`).
> **Check `getchaininfo` before assuming it is inert**: the live chain was past
> epoch 1,400 at the 2026-08-29 flag day, which would make tag `0x06` active.

## 1. What moves value

Exactly one transaction variant moves coins: `PosTransaction::Transfer`
(`crates/bloch-pos-committee/src/transition.rs:242-267`). The other four
variants — `Deposit`, `Exit`, `Delegate`, `SlashingEvidence` — are
staking-lifecycle and slashing messages. They are encoded by the same
function and share the same wire framing, but they do not move eUTXOs and are
out of scope for a deposit/withdrawal integration.

The model is UTXO, not accounts. A transfer names outputs it consumes and
outputs it creates, and consensus checks that the two sides balance.

### 1.1 The three structures

```rust
pub struct TransferInput {          // transition.rs:178-192
    pub txid:      [u8; 32],        // id of the tx that created the output
    pub vout:      u32,             // index of that output within it
    pub pubkey:    Vec<u8>,         // the witness: the spender's public key
    pub signature: Vec<u8>,         // the witness: the hybrid signature
}

pub struct TransferOutput {         // transition.rs:195-204
    pub value:       u64,           // satoshis; 1 BLOCH = 100_000_000 sat
    pub script_hash: [u8; 32],      // SHA3-256 of the locking script
}

PosTransaction::Transfer {          // transition.rs:242-267
    inputs:               Vec<TransferInput>,
    outputs:              Vec<TransferOutput>,
    tx_bytes:             u64,      // declared payload size (§4)
    tip_millisat_per_gas: u128,     // the only user-set price in the system
}
```

`(txid, vout)` is the outpoint — the key under which the committed unspent set
stores the output (`crates/bloch-pos-committee/src/state_root.rs:404-416`).
The set is keyed by outpoint and holds `{txid, vout, value, script_hash}`; it
does **not** hold the public key. A ≈3.7 KB key only reaches the wire when the
coin actually moves.

`script_hash` is the whole locking language. There is no script VM at
Genesis-4: the condition committed by `script_hash` is fixed at
`SHA3-256(spender's public key)` — pay-to-pubkey-hash and nothing more. No
datums, no multisig, no timelocks, no P2SH. The source states this as a scope
decision and warns that widening it must introduce a new discriminant rather
than an optional field (`transition.rs:429-434`).

### 1.2 Units

| Quantity | Unit | Width |
|---|---|---|
| Output value | satoshi | `u64` per output |
| Sums of values | satoshi | `u128` — a sum of `u64`s is not a `u64` |
| `tip_millisat_per_gas` | millisatoshi per gas | `u128` |
| Base fee | millisatoshi per gas | `u128` |
| Settled fee | satoshi | `u128` |

1 BLOCH = 100,000,000 satoshi (`tokenomics_v4.rs:41`). Total supply is
100,000,000,000 BLOCH = 10^19 satoshi (`tokenomics_v4.rs:84-85`). That fits in
a `u64` — barely, at about 54% of `u64::MAX` — which is exactly why sums are
`u128`: a single output is safely `u64`, but nothing in the type system bounds
a sum of outputs by the supply, and the code does not rely on it being bounded.
Do the same in your implementation. A 64-bit accumulator over an attacker-chosen
set of outputs is a wraparound waiting to happen.

---

## 2. The canonical encoding

`PosTransaction::canonical_bytes()`
(`transition.rs:447-521`) is the wire form. It is the byte string the block
body carries, the string `body_root` is a Merkle root over, and the string
`from_canonical_bytes` must invert exactly. **You have to reproduce it or your
signature verifies against nothing** — because the length of this encoding is
what `tx_bytes` is checked against (§4.1), and `tx_bytes` is inside the
signing root.

### 2.1 Rules the encoding obeys

- One-byte discriminant first.
- Then fixed-width **little-endian** fields in declaration order.
- Every variable-length field is preceded by a `u32` little-endian length.
- List counts are `u32` little-endian and are themselves length prefixes, so a
  truncated list cannot decode as a shorter valid one.
- No serde, no derive, no version negotiation. Two distinct transactions
  never share an encoding; that injectivity is what makes `body_root`
  meaningful.
- Decoding refuses trailing bytes (`TxDecodeError::TrailingBytes`) and refuses
  non-canonical field values, e.g. a bool that is neither 0 nor 1
  (`transition.rs:594-609`).

### 2.2 Byte layout of a `Transfer`

| Order | Field | Width | Encoding |
|---|---|---|---|
| 1 | discriminant | 1 | `0x01` |
| 2 | `inputs.len()` | 4 | u32 LE |
| 3 | **per input, in order:** | | |
| 3a | `txid` | 32 | raw bytes, as stored |
| 3b | `vout` | 4 | u32 LE |
| 3c | `pubkey.len()` | 4 | u32 LE |
| 3d | `pubkey` | variable | raw bytes |
| 3e | `signature.len()` | 4 | u32 LE |
| 3f | `signature` | variable | raw bytes |
| 4 | `outputs.len()` | 4 | u32 LE |
| 5 | **per output, in order:** | | |
| 5a | `value` | 8 | u64 LE |
| 5b | `script_hash` | 32 | raw bytes |
| 6 | `tx_bytes` | 8 | u64 LE |
| 7 | `tip_millisat_per_gas` | 16 | u128 LE |

Discriminants for the other variants, for completeness: `0x02` Deposit,
`0x03` Exit, `0x04` Delegate, `0x05` SlashingEvidence. Tag `0x05` is
**one-way by construction** — it folds in signing roots rather than the
messages themselves, so `from_canonical_bytes` returns
`EvidenceNotDecodable` for it (`transition.rs:534-549`, `:602`).

### 2.3 Size

```
size = 33 + 40 * n_outputs + Σ_inputs ( 44 + len(pubkey) + len(signature) )
```

where `33 = 1 (tag) + 4 (n_in) + 4 (n_out) + 8 (tx_bytes) + 16 (tip)` and
`44 = 32 (txid) + 4 (vout) + 4 (pk len) + 4 (sig len)`.

With the real suite (`len(pubkey) = 3749`) and a measured signature of 4,583
bytes, a 1-input / 1-output transfer encodes to **8,449 bytes**. That figure
is from the execution in §11, not from arithmetic on paper.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **The hex blob printed below is truncated and will fail the KAT this document
> tells you to build.** It is 122 bytes, not the 124 the caption claims: the
> `script_hash` run has 30 `22` bytes instead of 32. The correct 124-byte
> encoding, regenerated from the field values in the table above rather than
> retyped, is:
>
> ```
> 010100000011111111111111111111111111111111111111111111111111111111111111110000
> 000004000000aaaaaaaa03000000bbbbbb0100000040420f000000000022222222222222222222
> 222222222222222222222222222222222222222222227017000000000000e80300000000000000
> 00000000000000
> ```

### 2.4 Worked vector — the exact bytes

A 1-input / 1-output transfer with deliberately tiny witnesses, so the layout
is readable. Witness bytes are `0xAA…` and `0xBB…`; they are not a valid key
or signature and consensus would reject them, but `canonical_bytes` does not
validate, and the point here is the layout.

```
inputs  = [ { txid: 0x11 * 32, vout: 0, pubkey: AA AA AA AA, signature: BB BB BB } ]
outputs = [ { value: 1_000_000, script_hash: 0x22 * 32 } ]
tx_bytes = 6000
tip_millisat_per_gas = 1000
```

```
01                                                             tag
01000000                                                       n_in = 1
1111111111111111111111111111111111111111111111111111111111111111   txid
00000000                                                       vout = 0
04000000 aaaaaaaa                                              pubkey (4 bytes)
03000000 bbbbbb                                                signature (3 bytes)
01000000                                                       n_out = 1
40420f0000000000                                               value = 1_000_000
2222222222222222222222222222222222222222222222222222222222222222   script_hash
7017000000000000                                               tx_bytes = 6000
e8030000000000000000000000000000                               tip = 1000
```

Concatenated, 124 bytes:

```
010100000011111111111111111111111111111111111111111111111111111111111111110000
000004000000aaaaaaaa03000000bbbbbb0100000040420f00000000002222222222222222222222
222222222222222222222222222222222222227017000000000000e8030000000000000000000000
000000
```

(Line breaks for the page only; the value is one unbroken hex string.)

---

## 3. The signing root and the txid

### 3.1 Domain tags

Every signed or identifying digest in Genesis-4 is domain-separated by a
**fixed 16-byte, zero-right-padded tag**, so no tag can be a prefix of
another (`crates/bloch-pos-committee/src/params.rs:69-70`).

| Constant | ASCII | Hex |
|---|---|---|
| `DS_SPEND` | `BLCH4:SPEND` + 5×NUL | `424c4348343a5350454e440000000000` |
| `DS_TXID` | `BLCH4:TXID` + 6×NUL | `424c4348343a54584944000000000000` |

Source: `params.rs:95` and `params.rs:104`.

They are distinct on purpose. A spend authorisation must not be replayable as
any other signed message, and the digest that *identifies* a transaction must
not double as the digest a key *signed* — otherwise a txid seen on the chain
would be a valid signing target.

### 3.2 The signing root

`PosTransaction::spend_signing_root()` (`transition.rs:356-377`). This is the
32-byte digest each input's signature is taken over — the same one root for
every input, so an N-input transfer costs N verifications and not N roots.

**Preimage, for the `Transfer` variant:**

```
DS_SPEND                        16 bytes
inputs.len()                     4 bytes  u32 LE
  per input, in order:
    txid                        32 bytes
    vout                         4 bytes  u32 LE
outputs.len()                    4 bytes  u32 LE
  per output, in order:
    value                        8 bytes  u64 LE
    script_hash                 32 bytes
tx_bytes                         8 bytes  u64 LE
tip_millisat_per_gas            16 bytes  u128 LE

signing_root = SHA3-256( preimage )
```

Note what is **not** there: `pubkey` and `signature`. The witnesses are
excluded, and this is not a weakening. A signature is produced over this root
and then stored inside the transaction; if the root covered the witnesses it
would have to cover the signature being produced over it, and no signer could
ever compute the value to sign. Excluding the witnesses is the only
construction that terminates, and it is the standard one — Bitcoin's sighash
and Ethereum's RLP-minus-VRS do the same thing (`transition.rs:323-336`).

What that leaves unsigned is exactly the witness bytes, and consensus checks
every use it makes of them against something that *is* signed: the pubkey
against the output's committed `script_hash`, the signature against this root
(§4.2). A third party may substitute neither without failing one of those two
checks.

**What is covered, and why each field is in it** (`transition.rs:338-351`):

- **the spend points** — otherwise a signature authorising the movement of one
  coin would authorise the movement of any coin;
- **the outputs, in order** — otherwise the destination and the amount could be
  rewritten in flight, which is the entire attack;
- **`tx_bytes` and the tip** — both set the fee, and the fee is the difference
  between what the inputs carry and what the outputs receive. An unsigned fee
  term is an unsigned deduction from the sender's own money.

Lengths are prefixed and every field is fixed-width, so no two distinct
transfers share a preimage.

For the non-`Transfer` variants there is no spend to authorise, and the
function returns `SHA3-256(DS_SPEND ‖ canonical_bytes())` so that it is total.
Nothing in the transition asks them for one.

### 3.3 The txid

```
txid = SHA3-256( DS_TXID ‖ signing_root )
```

`transition.rs:393-398`. Taken over the **witness-free** root, so a payment's
id — and with it the outpoint key of every output the transfer creates — is
fixed the moment the sender decides what to send, and cannot be moved
afterwards by anyone re-encoding the signatures. A txid over the full
encoding would let a relay change where a payment lands in the set, breaking
any transaction already built to spend it. That is transaction malleability,
and it is designed out here rather than patched later.

Practical consequences for an exchange:

- **You know the txid before you sign.** Your ledger can record it at build
  time. There is no "the txid changed in the mempool" failure mode.
- **You can build a chain of unconfirmed spends** safely, because the child's
  input outpoint is knowable from the parent's root.
- **Two transfers with identical spend points, outputs, `tx_bytes` and tip
  have the same txid.** They are the same transaction. Since an outpoint is
  consumed at most once and a zero-input transfer is refused
  (`TransferReject::NoInputs`), two *applicable* transfers cannot collide.
- The transaction never carries its own id. A transaction that named its own
  id could name one already in the set.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **The preimage printed below is also truncated** — 123 bytes, not 124, again
> one `22` short in the `script_hash`. The quoted `signing_root` and `txid` are
> **correct**: they were independently recomputed on 2026-09-01 from the correct
> 124-byte preimage and match to the byte. Only the printed blob is wrong. The
> correct preimage is:
>
> ```
> 424c4348343a5350454e4400000000000100000011111111111111111111111111111111111111
> 11111111111111111111111111000000000100000040420f000000000022222222222222222222
> 222222222222222222222222222222222222222222227017000000000000e80300000000000000
> 00000000000000
> ```

### 3.4 Verified vector

The following was produced by the Rust code in this branch and independently
reproduced by a from-scratch Python implementation (§11). Use it as your first
known-answer test — it depends on no key and no network, so it is portable.

Transaction: the one in §2.4.

```
preimage (124 bytes):
424c4348343a5350454e44000000000001000000111111111111111111111111111111111111
1111111111111111111111111111000000000100000040420f00000000002222222222222222
22222222222222222222222222222222222222222222227017000000000000e8030000000000
000000000000000000

signing_root = fb89823b501d25bb0683c02a1edf8175405c09160f3f8211bc03928709412c4c
txid         = 992c87f11b9e2da370b3db07213c16618bd988a43d8b9224eeeae2fb8a163670
```

**Witness independence, pinned:** replacing the 4-byte pubkey with 40 bytes of
`0xCC` and the 3-byte signature with 400 bytes of `0xDD` leaves both the
signing root and the txid byte-identical. Executed and asserted.

**The tip is signed, pinned:** changing `tip_millisat_per_gas` from 1000 to
1001, and nothing else, changes the signing root. Executed and asserted.

---

## 4. What consensus checks, in the order it checks it

`CommittedState::apply_transfer` (`transition.rs:1508-1625`) is the function
that moves the ledger. The order is consensus and it is cheapest-first:
structure, then set membership, then the script hashes, then conservation, and
only then the signatures — the one expensive operation, deliberately last.
An attacker spamming unfundable or malformed transfers gets rejected on
arithmetic, not on ≈7.3 million instructions per input.

Every check runs before any mutation, so a refused transfer leaves the state
untouched.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> The "256 KiB payload cap" cited in this section is epoch-gated now:
> `fee_market.rs:65` `MAX_BLOCK_TX_BYTES = 262_144` **before** epoch 800, and
> `:85` `MAX_BLOCK_TX_BYTES_V2 = 524_288` from epoch 800 onward, selected by
> `max_block_tx_bytes(epoch)` (`:96-99`, gate at `params.rs:321`).

### 4.1 Structure

- `inputs` must be non-empty → `NoInputs`.
- `tx_bytes` **must not be below** the transaction's own
  `canonical_bytes().len()` → `UnderdeclaredSize` (`transition.rs:1528-1530`).

Declaring **more** than you use is allowed; you simply pay for it. Declaring
less is refused, because the declared size is what the fee market charges and
what the block's 256 KiB payload cap is measured against. A witness-heavy
transfer that could sit below the bytes every node must gossip and store would
make both the charge and the cap advisory.

§5.4 explains why, given Falcon's variable-length signatures, you should
deliberately over-declare.

### 4.2 Authorisation — per input, both halves

For each input, with `entry` the committed output at `(txid, vout)`:

```rust
SHA3-256(input.pubkey) == entry.script_hash          // transition.rs:1549-1552
verifier.verify_with_key(input.pubkey,
                         signing_root,
                         input.signature) == true    // transition.rs:1598-1603
```

**Both are load-bearing, and neither implies the other.** The hash alone lets
anyone who can read the chain replay a public key they saw in an earlier
spend. The signature alone lets anyone sign with a key of their own choosing.
Together they say: only the holder of the key this output committed to may
move it.

`verify_with_key` is the real hybrid suite —
`bloch_crypto::crypto::verify`, both halves ANDed
(`crates/bloch-pos-node/src/keys.rs:130-135`). Spending an output is exactly
as hard to forge as attesting to a block.

The hash is checked **before** the signature: one hash against one hybrid
verification, and a wrong key cannot be made right by any signature.

### 4.3 No outpoint twice

Spend points are collected into a `BTreeSet` before anything is consumed, so
the duplicate check sees the transaction whole → `DuplicateInput`. An outpoint
that is not in the committed set → `UnknownInput`; this covers both "never
existed" and "already spent", including spent by an earlier transaction in the
same block.

### 4.4 Conservation — equality, not `>=`

```
sum(input values)  ==  sum(output values)  +  fee
```

with `fee = charge.base_fee_sat + charge.priority_fee_sat` from
`fee_market::charge` (`transition.rs:1561-1578`). All arithmetic in `u128`.

**The transaction does not declare what it feels like paying.** The fee is
derived from the transaction's class and declared size, priced at the base fee
the committed state fixes. The source records two earlier revisions of this
type and why each was closed: one carried `base_fee_sat`/`priority_fee_sat` as
declared numbers, which is not a placeholder for a fee market but the absence
of one; the next carried three gas terms with no sender, recipient or amount,
so the chain had balances and no payments (`transition.rs:221-241`).

Equality rather than `>=` is deliberate. A transfer that overpays has
misdeclared its outputs, and silently sweeping the remainder to the proposer
would be a fee nobody set. **You must compute the fee exactly and put the
change in an explicit output.** There is no implicit change.

### 4.5 Output keys

Derived from the witness-free root, so the transaction cannot choose where it
writes: output `i` of the transfer is stored at `(txid, i)`. A collision with
a live output → `OutputExists`. That needs a SHA3-256 collision to happen and
is refused rather than assumed away.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **The taxonomy below is 8 of 13.** `interfaces.rs:379-463` now carries five
> more, all from the V2 path: `FormatNotActive` (`:425`), `BadKeyIndex`
> (`:428`), `DuplicateWitnessKey` (`:435`), `WitnessKeyUnused` (`:442`),
> `WitnessTableNotCanonical` (`:462`). The eight listed are still correct and
> correctly described; read the section as "the Transfer **V1** taxonomy".

### 4.6 The complete reject taxonomy

`TransferReject` (`crates/bloch-pos-committee/src/interfaces.rs:379-420`):

| Variant | Meaning |
|---|---|
| `NoInputs` | Zero inputs. Funds nothing, and its id would be a function of its outputs alone. |
| `UnderdeclaredSize` | `tx_bytes` below the canonical encoding's own length. |
| `DuplicateInput` | The same outpoint appears twice in one transfer. |
| `UnknownInput` | Outpoint not in the unspent set — never existed, or already spent. |
| `ScriptMismatch` | `SHA3-256(pubkey) != script_hash`. |
| `BadSignature` | The signature does not verify under the supplied key over the signing root. |
| `ValueNotConserved` | `sum(in) != sum(out) + fee`. |
| `OutputExists` | An output would take an outpoint already in the set. |

A block containing a rejected transfer is rejected whole.

---

## 5. The fee, concretely

`crates/bloch-pos-committee/src/fee_market.rs`.

### 5.1 Gas

```
gas = TX_FLAT_GAS  +  tx_bytes * GAS_PER_BYTE  +  HYBRID_VERIFY_GAS * n_inputs
    = 5_000        +  tx_bytes * 16            +  72_748 * n_inputs
```

Constants at `fee_market.rs:85` (`GAS_PER_BYTE = 16`), `:89`
(`TX_FLAT_GAS = 5_000`), `:107` (`HYBRID_VERIFY_GAS = 72_748`, derived as
7,274,849 measured RV32IM instructions ÷ 100 instructions-per-gas).

The class term uses the **actual** input count, not a number the transaction
asserts: an asserted count would let a transfer buy N verifications' worth of
node CPU at the price of one.

### 5.2 Price

```
base_fee_sat     = ceil( gas * base_fee_millisat_per_gas / 1000 )
priority_fee_sat = ceil( gas * tip_millisat_per_gas      / 1000 )
fee              = base_fee_sat + priority_fee_sat
```

Both round **up**: a truncating division would make `gas * price < 1000`
millisat cost zero satoshis, and free gas at a granularity the attacker
controls is a DoS invitation (`fee_market.rs:234-254`).

The base fee is EIP-1559, ±1/8 per block, over two resources (gas and payload
bytes), floored at `MIN_BASE_FEE_MILLISAT_PER_GAS = 10` and clamped above.
**The base fee is the protocol's; the tip is the only user-set price in the
system.** You must read the current base fee from the node — see
BLOCH-G4-RPC.md — because your conservation equation will not balance against
a stale one.

### 5.3 Worked example (executed)

One input, one output, `tx_bytes = 12_000`, `tip = 1_000` millisat/gas, base
fee at the floor of 10 millisat/gas:

```
gas               = 5_000 + 12_000*16 + 72_748      = 269_748
base_fee_sat      = ceil(269_748 * 10   / 1000)     =       2_698
priority_fee_sat  = ceil(269_748 * 1000 / 1000)     =     269_748
total fee                                           =     272_446 sat
                                                    =   0.00272446 BLOCH
```

Note the shape of that: at a tip of 1,000 millisat/gas — which is the default
`bloch-pos submit-tx` uses — the **tip is 100× the base fee**. 1,000
millisat/gas is 1 satoshi per gas, and gas for a PQ-signed transfer runs to
the hundreds of thousands. Set your tip deliberately; do not inherit the
tool's default into production.

### 5.4 The `tx_bytes` circularity, and how to resolve it

This is the single most likely thing to break your first implementation.

- `tx_bytes` is **inside the signing root**. Fix it before you sign, and it
  must not move afterwards.
- Consensus refuses `tx_bytes` below the encoding's actual length.
- The encoding's actual length includes the signatures.
- **Falcon-1024 signatures are variable-length** (§6.3). You cannot know the
  exact encoded length before you sign.

Raising `tx_bytes` after signing to make it fit would silently invalidate the
signature that was produced over the smaller value.

**The resolution: over-declare to the upper bound before signing.** Use

```
tx_bytes = 33 + 40 * n_outputs + n_inputs * (44 + 3749 + SIG_MAX)
```

with `SIG_MAX = 4775` (§6.3). For 1 input / 1 output that is **8,641** bytes,
against the measured real encoding of 8,449 — 192 bytes of slack, which is
3,072 extra gas, or **31 satoshis** of base fee at the floor. Over-declaring is
explicitly allowed; the cost of the slack is trivial and the cost of getting it
wrong is a re-sign. (Your tip is charged on the same gas, so at a high tip the
slack costs proportionally more — one more reason to set the tip deliberately.)

`submit-tx` takes the same approach with a different constant, defaulting to
`1024 + n_inputs * (4589 + len(pubkey) + 64)` (`main.rs:328-331`). With the
real 3,749-byte key that is 9,426 for one input — safely above the upper
bound, at the cost of a little more fee. Either is fine; what is not fine is
computing `tx_bytes` from a signature you have not produced yet.

---

## 6. The signature suite

### 6.1 What it is

**ML-DSA-65 ‖ Falcon-1024, and both halves are verified.**

`crates/bloch-crypto/src/crypto/mod.rs:204-226`. ML-DSA-65 is FIPS 204;
Falcon-1024 is the other NIST lattice signature family. The design intent is
defence in depth across two families: a break in one does not by itself let an
attacker spend. The cost is that you carry two of everything.

A public key is `mldsa_pk ‖ falcon_pk`; a signature is
`mldsa_sig ‖ falcon_sig`. The split on verification uses the **fixed ML-DSA
lengths**, and the Falcon part is whatever remains — which is how a
variable-length Falcon tail is accommodated without a length field.

| Component | Bytes |
|---|---|
| ML-DSA-65 public key | 1,952 |
| ML-DSA-65 secret key | 4,032 |
| ML-DSA-65 signature | 3,309 (fixed) |
| Falcon-1024 public key | 1,793 |
| Falcon-1024 signature | **variable** |

### 6.2 The suite envelope — and which form hashes where

Every public key, secret key and signature carries a **4-byte header**
(`crypto/mod.rs:24-62`):

```
byte 0     0xB1   ┐ magic "B1 0C"
byte 1     0x0C   ┘
bytes 2-3  suite_id, u16 LE     0x0001 = ML-DSA-65 ‖ Falcon-1024
                                0x0002 = ML-DSA-65 only (defined, unused)
                                0x0000 and 0xFFFF reserved, never valid
```

So a public key on the wire is **3,749 bytes**: a 4-byte header
(`b10c0100`) followed by a 3,745-byte body (1,952 + 1,793). Both figures
appear in our documentation and they are not interchangeable:

| Form | Bytes | Where it appears |
|---|---|---|
| **Enveloped** | **3,749** | What `generate_keypair()` returns. What goes in `TransferInput.pubkey`. What `SHA3-256` is taken over to make `script_hash`. |
| Raw body | 3,745 | The pre-envelope legacy form. The 3,745-byte `byte[i] = i mod 251` vector in the Genesis-3 address KAT. |

**They hash differently, so they are different owners.** An output locked to
`SHA3-256(enveloped)` cannot be spent by presenting the raw body, and vice
versa — the `ScriptMismatch` check does not know or care which form you meant.

Both forms *verify*, however. `parse_envelope_or_legacy`
(`crypto/mod.rs:165-178`) treats a key with no `B1 0C` magic as suite 0x0001,
which exists so pre-envelope carry-over wallets stay spendable. The suite of
the key and the suite of the signature must match, or verification fails
before either half is checked (`crypto/mod.rs:187-190`).

**Rule for an integrator: pick the enveloped 3,749-byte form and use it
everywhere.** It is what the current keygen produces, it is what makes an
address suite-committing, and mixing forms within one wallet produces outputs
you cannot spend with the key you think owns them.

### 6.3 Signature length is not fixed

Falcon-1024 signatures are variable-length. A hybrid signature therefore has
no fixed size, and **any constant you see is a bound or an average, never a
wire length.**

Two constants exist in this repository and they disagree, so know which is
which:

| Constant | Value | Source | What it is |
|---|---|---|---|
| `SIG_SIZE` | **4,775** | `crates/bloch-crypto/src/core/mod.rs:330` | `4 + 3309 + 1462` — header + ML-DSA + Falcon's **maximum** tail. An upper bound. |
| `HYBRID_SIG_BYTES` | **4,589** | `crates/bloch-pos-committee/src/fee_market.rs:93` | A *measured* size, used only for fee estimation. |

Measured on this branch, two signatures produced by the same key over the same
root came out at **4,583** and **4,580** bytes — different lengths, different
bytes, both verifying. Falcon signing is randomised.

Consequences you must design around:

- Never allocate or validate against a fixed signature length.
- Never assume signing twice is idempotent. It is not, and neither the txid
  nor the signing root changes — only the encoding does (§3.3).
- Use **4,775** when you need an upper bound (sizing `tx_bytes`, §5.4).
- Do not use 4,589 as a bound. It is below the true maximum by 186 bytes;
  it is a fee-estimation figure and nothing else.

### 6.4 Signing

```rust
signature = bloch_crypto::crypto::sign(secret_key, signing_root)
```

`crypto/mod.rs:134-163`. The message is the 32-byte signing root, passed as
the message — **not** re-hashed, not prefixed, not wrapped. The domain tag is
already inside the root. Both halves sign the same 32 bytes; the outputs are
concatenated ML-DSA-first and the result is wrapped in the envelope of the
same suite the secret key carried.

Verification (`crypto/mod.rs:180-226`):

1. Parse the envelope on the key and on the signature; suites must match.
2. Split the key body at 1,952 and the signature body at 3,309.
3. Verify ML-DSA-65 over the 32-byte root. Any parse failure ⇒ `false`.
4. Verify Falcon-1024 over the same 32 bytes.
5. Return the **AND**.

Malformed input at any step returns `false` and never panics. That is a
consensus rule, not a nicety.

---

## 7. The integration path

### 7.1 The shape

```
   your builder                      your signer            the node
   (online, no keys)                 (offline, key)         (network)
        │                                  │                     │
   1. read UTXOs, base fee ────────────────┼─────────────────────┤
   2. choose inputs/outputs                │                     │
   3. compute fee, set tx_bytes            │                     │
   4. compute signing_root ───32 bytes───▶ │                     │
                                     5. sign both halves         │
        │ ◀────────────── signature (≈4.6 KB) ───────────────────┤
   6. assemble canonical_bytes             │                     │
   7. verify locally (§8)                  │                     │
   8. submit ──────────────────────────────┼────────────────────▶│
```

Only step 5 needs the key, and its entire input is 32 bytes that reveal
nothing. This is what makes an air-gapped signer practical despite §0.

### 7.2 `bloch-pos submit-tx`

The node binary ships a tool built for exactly this split. **Run without
`--signature`, it prints the signing root and sends nothing.**

```
bloch-pos submit-tx --to <host:port> --pubkey <hex>
                    --spend <txid-hex>:<vout>  [--spend ...]
                    --pay <script-hash-hex>:<sat>  [--pay ...]
                    [--signature <hex>] [--tx-bytes n] [--tip millisat-per-gas]
```

- `--pay` order **is** the output order. Position = vout. This is
  consensus-visible.
- `--spend` is repeatable; each is a 32-byte txid hex, a colon, and a vout.
- Omitting `--signature` prints the root on stdout, an explanation on stderr,
  and exits 0 having opened no socket.
- The tool never holds a key and has no keygen. This is deliberate: a devnet
  convenience that generated a keypair here would be a keypair on an
  operator's shell history (`main.rs:239-246`).

**Executed, on this branch:**

```console
$ bloch-pos submit-tx --to 127.0.0.1:9 --pubkey aabbcc \
    --spend 3333...3333:7 \
    --pay 98ba9b8ec52b17f18f26e80860e697ac940f09ac8a6a43698025f54931f86b8d:500000 \
    --tx-bytes 12000 --tip 1000
8d9a678cf71727a52c646ee729d134be2af7ef3a7922a04afacd221d002b0126
submit-tx: no --signature given; the line above is the signing root.
Sign it with the key whose SHA3-256 the spent outputs commit to, then
re-run with the SAME flags plus --signature <hex>. Changing any flag
(including --tx-bytes and --tip) changes the root and voids the
signature. Nothing was sent.
$ echo $?
0
```

Two things that run confirms beyond the printed text:

1. `--to 127.0.0.1:9` is a dead port. Exit 0 with no connection error proves
   nothing was sent. The same command **with** `--signature` against the same
   port exits 1 with `Connection refused`, which proves the send is real when
   a signature is present.
2. The printed root, `8d9a678c…`, is **byte-identical** to the root the
   library computed for the same transfer built with a genuine 3,749-byte
   public key (§11, KAT2). The `--pubkey aabbcc` above is three arbitrary
   bytes. This is the witness-independence property of §3.2, demonstrated
   across two independent code paths.

### 7.3 The `--tx-bytes` guard, executed

```console
$ bloch-pos submit-tx ... --tx-bytes 50 --signature ddeeff
submit-tx: --tx-bytes 50 is below this transaction's 123-byte encoding;
a node would refuse it. Re-run the unsigned step with --tx-bytes 123
(or more) and sign that root instead.
$ echo $?
2
```

The tool reports rather than "fixes" it, because the fix is to re-sign at a
larger `--tx-bytes` and only the key holder can do that.

### 7.4 Two limitations of `submit-tx` you will hit

- **One key for all inputs.** It applies the single `--pubkey` and the single
  `--signature` to every input (`main.rs:285-292`, `:358-362`). A transfer
  spending outputs locked to two different keys cannot be built with this
  tool. Consensus supports it — the signing root is shared, so each owner
  signs the same 32 bytes and contributes their own `(pubkey, signature)` —
  but you will need your own builder.
- **No acknowledgement.** The transport does not answer. "Submitted" means
  bytes left the socket. Confirmation is seeing the transfer in a finalized
  block, and nothing less.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **The premise of this section is no longer true; its advice still is.**
> `engine.rs:1382` (`on_transaction`) now calls `admissible()`, and
> `engine.rs:2767-2772` **verifies every input's hybrid signature** against the
> spend signing root before the transaction enters the mempool. A transfer
> sitting in a mempool *has* been authorised.
>
> Still true, and still the reason to wait for a finalized block: admission
> applies no fee floor, no per-sender accounting, no replacement policy, and
> **no set-membership or conservation check** — the code says so at
> `engine.rs:1367-1371`. Keep the conclusion; replace the reasoning.

### 7.5 Mempool admission proves nothing

Worth stating because it will otherwise mislead your monitoring. The node's
mempool admission is *only* "the bytes decoded"
(`crates/bloch-pos-node/src/engine.rs:651-676`): no signature check, no fee
floor, no per-sender accounting, no replacement policy. A transfer sitting in
a mempool has not been authorised by anything. Treat inclusion in a finalized
block — and the `finalized: true` flag, not a confirmation count — as the only
settlement signal.

---

## 8. Build a known-answer test before you move value

Do not let the first execution of your signing path be one that moves money.
The sequence below is cheap, needs no network, and catches every
encoding-level error class described above.

1. **Reproduce the key-independent vector.** Build the §2.4 transaction in
   your own code. Assert the preimage hex, the signing root
   `fb89823b…412c4c`, the txid `992c87f1…163670`, and the 124-byte encoding
   from §2.4. If any of these differ, your field order, your endianness, or
   your domain tag is wrong, and no amount of correct cryptography will save
   you.
2. **Assert witness independence.** Change the pubkey and signature bytes to
   anything else. The root and txid must not move.
3. **Assert the tip and `tx_bytes` are signed.** Change each by one. The root
   must move.
4. **Round-trip.** Decode your own encoding back into a transaction and
   compare structurally. Assert that appending a single trailing byte makes
   decoding fail.
5. **Generate a throwaway key, sign, and verify locally.** Sign the root and
   verify with the same suite before you go near a node. Then flip one bit of
   the root and assert verification fails.
6. **Assert the script-hash binding.** `SHA3-256(your enveloped 3,749-byte
   pubkey)` must equal the `script_hash` of the output you intend to spend.
   Compare with the raw 3,745-byte body too, and observe that it differs
   (§6.2) — that is the mistake this check exists to catch.
7. **Assert conservation.** Compute the fee with the base fee the node
   reports, and assert `sum(in) == sum(out) + fee` exactly, in 128-bit
   arithmetic.
8. **Cross-check against `submit-tx`.** Run the tool unsigned with the same
   parameters and assert its printed root equals yours. This checks your
   implementation against the reference implementation, at zero risk.
9. **Only then** submit, and only a minimum-value transfer, and watch for it
   in a finalized block.

A from-scratch Python reimplementation sufficient for steps 1–3 is 15 lines,
and was used to independently confirm the vectors in this document:

```python
import hashlib
DS_SPEND = b'BLCH4:SPEND' + b'\x00' * 5     # 16 bytes
DS_TXID  = b'BLCH4:TXID'  + b'\x00' * 6     # 16 bytes

def signing_root(inputs, outputs, tx_bytes, tip):
    p  = DS_SPEND
    p += len(inputs).to_bytes(4, 'little')
    for txid, vout in inputs:
        p += txid + vout.to_bytes(4, 'little')
    p += len(outputs).to_bytes(4, 'little')
    for value, script_hash in outputs:
        p += value.to_bytes(8, 'little') + script_hash
    p += tx_bytes.to_bytes(8, 'little')
    p += tip.to_bytes(16, 'little')
    return hashlib.sha3_256(p).digest()

def txid(root):
    return hashlib.sha3_256(DS_TXID + root).digest()
```

Note `hashlib.sha3_256` — FIPS-202 SHA3, **not** Keccak-256, and not SHAKE. If
your language's "sha3" is Ethereum's Keccak, you have the wrong function and
every digest in this document will disagree.

---

## 9. Addresses

### 9.1 Genesis-4 has no address format

State this plainly to your product team before they design a deposit page:
**Genesis-4 does not define a human-facing address.** The identifier is the raw
32-byte `script_hash`, and every interface in the Genesis-4 node takes and
returns it as 64 hex characters — `getbalance`, `getutxos`/`listunspent`, and
`submit-tx --pay`.

- `getnewaddress` answers with a **permanent** refusal, on two independent
  grounds: a node RPC must never mint keys, and there is no frozen address
  format to return a string in
  (`crates/bloch-pos-node/src/rpc.rs:208-237`).
- The frozen interface contract records it as an open point: "the concrete
  format (address hash width, version byte, whether a script hash is
  admissible) must be fixed and a KAT added. The freeze deliberately does not
  guess." (`docs/specs/BLOCH-POS-INTERFACES.md` §4.5.)
- The Genesis-4 crates do not reference `bloch_crypto::address` at all. They
  depend on `bloch-crypto` only for `generate_keypair`, `sign`, `verify` and
  `split_envelope`.

So: `script_hash = SHA3-256(enveloped 3,749-byte public key)`, 32 bytes, hex.
That is the Genesis-4 "address" today, and it has **no checksum**. A
mistyped 64-hex-character string is a valid-looking `script_hash` that nobody
holds the key to, and a withdrawal to it is unrecoverable. Until a format is
frozen, **your own layer must supply the integrity check** — require the user
to paste a string your system issued, or wrap the hex in an envelope of your
own with its own checksum, and never accept bare user-typed hex.

### 9.2 The Genesis-3 format, which is what actually exists

Genesis-3 addresses are what your users hold today and what the carryover
snapshot is keyed by, so you must implement them regardless.

```
address   = prefix ‖ hex( hash20 ‖ checksum4 )

hash20    = SHA3-256( enveloped public key )[0..20]
checksum4 = SHA3-256( SHA3-256( hash20 ) )[0..4]
```

| Element | Value |
|---|---|
| Mainnet prefix | `bloch1q` — 7 ASCII characters |
| Testnet prefix | `bloch1t` — 7 ASCII characters |
| Hash | **SHA3-256** (FIPS-202), truncated to 20 bytes |
| Checksum | SHA3-256 applied **twice** over the 20-byte hash, first 4 bytes |
| Body | lowercase hex |
| Total length | **55 characters** (7 + 40 + 8) |

Source: `crates/bloch-crypto/src/address.rs:55-61` (derivation), `:120-128`
(encoding), `:63-98` (decoding); prefixes at
`crates/bloch-crypto/src/core/mod.rs:135-136`.

**It is not bech32.** Several comments inside our own repository say it is;
they are wrong. There is no HRP separator semantics, no witness version, no
5-bit squashing, no polymod, and no bech32 charset. The proof is on the wire:
the address body contains `1` and `b`, both excluded from the bech32 charset
`qpzry9x8gf2tvdw0s3jn54khce6mua7l`. **A bech32 decoder rejects every valid
Bloch address.** Do not reach for a bech32 library.

**It is not hash160 either**, despite that name appearing in our carryover
code. There is no RIPEMD anywhere in the dependency tree. The 20 bytes are
`SHA3-256(pubkey)[0..20]` — a 160-*bit* value, never `RIPEMD160(SHA256(·))`.

### 9.3 The checksum does not cover the network prefix

This is the finding that most directly threatens user funds.

```
mainnet: bloch1q98ba9b8ec52b17f18f26e80860e697ac940f09ac565787bd
testnet: bloch1t98ba9b8ec52b17f18f26e80860e697ac940f09ac565787bd
              ^
```

The checksum is computed over the 20-byte hash **alone**. Mainnet and testnet
addresses for the same key differ in exactly one character and carry
**identical checksums**. A testnet address is a structurally valid,
checksum-passing mainnet address.

Nothing in the encoding protects a user who pastes one for the other. **Your
validator must compare the 7-character prefix explicitly**; a checksum check
alone will not catch it.

### 9.4 What an exchange must implement to validate an address

Before you accept a withdrawal request to a Genesis-3-format address, all of
the following, in order. Reject on the first failure with a distinguishable
error.

1. **Length is exactly 55 characters.** Not "at least", not "48 hex after
   something".
2. **The prefix is exactly the 7 characters of your network** — `bloch1q` for
   mainnet — compared as a whole string. Not a `trim_start_matches`, which
   strips repeatedly and will happily eat `bloch1qbloch1q`. Two lenient
   parsers in our own Genesis-3 tree get this wrong; do not copy them.
3. **The remaining 48 characters are lowercase hex** `[0-9a-f]`. Reject
   uppercase. Rust's `hex::decode` accepts uppercase and re-emits lowercase,
   so the same address has two spellings that round-trip to different strings;
   our TypeScript SDK rejects uppercase. **Rust and TypeScript therefore
   disagree on validity today.** Choose lowercase-only and normalise on the
   way in.
4. **Decode to 24 bytes.** Split into `hash20 = bytes[0..20]` and
   `checksum = bytes[20..24]`.
5. **Recompute** `SHA3-256(SHA3-256(hash20))[0..4]` and compare to `checksum`
   in constant time or otherwise; a mismatch is a rejection.
6. **Reject any address on your deny-list of known non-addresses** — in
   particular, do not let a user withdraw to the 20-byte prefix of a carried
   output (§10) believing it is a Genesis-4 destination.

Reference implementation, 4 lines, independently written and confirmed against
the in-tree vectors:

```python
import hashlib

def validate(addr: str, prefix: str = "bloch1q") -> bytes:
    assert len(addr) == 55 and addr.startswith(prefix)
    body = addr[len(prefix):]
    assert all(c in "0123456789abcdef" for c in body)
    raw = bytes.fromhex(body)
    h20, cks = raw[:20], raw[20:]
    assert hashlib.sha3_256(hashlib.sha3_256(h20).digest()).digest()[:4] == cks
    return h20
```

### 9.5 Verified address vectors

Produced on this branch from a throwaway key generated in a temporary
directory and discarded:

```
public key      : 3749 bytes, enveloped, header b10c0100
script_hash (G4): 98ba9b8ec52b17f18f26e80860e697ac940f09ac8a6a43698025f54931f86b8d
hash20      (G3): 98ba9b8ec52b17f18f26e80860e697ac940f09ac
mainnet address : bloch1q98ba9b8ec52b17f18f26e80860e697ac940f09ac565787bd
testnet address : bloch1t98ba9b8ec52b17f18f26e80860e697ac940f09ac565787bd
```

Note the relationship: the Genesis-3 `hash20` is literally the **first 20
bytes** of the Genesis-4 `script_hash`, because both are SHA3-256 of the same
enveloped key and Genesis-3 truncates. That is not a coincidence, and §10 is
built on it.

The in-tree known-answer vector, for a public key of the **raw 3,745-byte**
form where `byte[i] = i mod 251` (`tests/vectors/kat_address.json`):

```
SHA3-256[0:20]  : 8bb805e36e9c74d7f17ffafdc0ae9370574ec8ce
mainnet         : bloch1q8bb805e36e9c74d7f17ffafdc0ae9370574ec8ce07b6a1b7
testnet         : bloch1t8bb805e36e9c74d7f17ffafdc0ae9370574ec8ce07b6a1b7
```

Use both. The first pins the enveloped form your wallet will actually produce;
the second pins your hash function against a vector our own test suite
asserts.

---


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **THIS SECTION IS NOW THE OPPOSITE OF THE TRUTH. Carried outputs ARE
> spendable.**
>
> §10.2's headline finding — "no output in existence is spendable", the entire
> opening ledger stranded, a migration spend path that "does not exist yet" —
> was resolved by exactly the rule §10.3 predicted. `transition.rs:1361-1366`:
>
> ```rust
> fn owns(key_hash: &[u8; 32], script_hash: &[u8; 32]) -> bool {
>     if key_hash == script_hash { return true; }
>     script_hash[20..] == [0u8; 12] && key_hash[..20] == script_hash[..20]
> }
> ```
>
> It is called from both spend paths (`:2162` V1, `:2362` V2) and pinned by
> `a_carried_output_opens_for_its_genesis3_owner` (`transition.rs:8851-8905`).
> A carried or vested-allocation output opens today for the holder of the
> Genesis-3 key that owned it.
>
> Two things to carry forward rather than delete: the **security tier is not the
> same** — a zero-extended carried output is protected by the 160 bits of the
> Genesis-3 hash, not 256 — and §10.1's description of the ownership rule and
> the zero-extension convention is accurate and worth keeping. §10.2, the
> headline of §10, and discrepancy #7 in §12.6 should go.

## 10. Carried balances, and why they cannot be spent yet

### 10.1 The ownership rule

A Genesis-3 balance crosses into Genesis-4 through the snapshot. The
snapshot's address column is a 20-byte Genesis-3 hash; the committed
`script_hash` field is 32. The conversion is therefore a consensus rule — it
decides who owns each output — and it was decided rather than inferred
(`crates/bloch-pos-node/src/genesis.rs:393-462`, `:582-600`):

```
script_hash[0..20]  = the snapshot's 20 bytes (the Genesis-3 hash)
script_hash[20..32] = 0x00
```

**Zero-extension to the right, no re-hashing.** The criterion was
auditability: a holder proves their balance crossed by comparing their own
Genesis-3 address against the first 20 bytes of the field, with no conversion
table and no preimage argument. An exchange or an auditor reconciling the
migration wants exactly that comparison, and this is what makes it available.

For the key in §9.5, the carried form would be:

```
98ba9b8ec52b17f18f26e80860e697ac940f09ac000000000000000000000000
```

The padding direction is itself consensus. Padding on the left would give
every output a different owner, which is a different ledger. A snapshot row
whose address column is not exactly 20 bytes is refused rather than converted.

### 10.2 The consequence: carried outputs are not spendable

The spend rule is `SHA3-256(pubkey) == script_hash` (§4.2). A carried
`script_hash` ends in twelve zero bytes. `SHA3-256` of any public key does not
produce twelve trailing zeros — not in practice, and not in any quantity you
could search for. **Therefore no carried output satisfies the implemented
authorisation rule.**

The source says so itself, in the same doc comment that decides the rule:

> "a carried output is not spendable by any rule of the form
> `SHA3-256(script) == script_hash`, so the migration spend path must
> recognise carried outputs explicitly — **that path does not exist yet** and
> this is the fact it has to be built around."

I searched `bloch-pos-committee` and `bloch-pos-node` for any branch that
special-cases the zero-extended form. **There is none.** `transition.rs:1549`
is the only ownership rule in the codebase.

### 10.3 The scope of that, which is larger than the carryover

The same zero-extension is used for the five vested genesis allocations —
founder, VC, team, marketing, liquidity — all of which are written to the
founder's Genesis-3 hash zero-extended
(`crates/bloch-pos-node/src/main.rs:566-586`,
`crates/bloch-pos-committee/src/tokenomics_v4.rs:386-395`). Those are equally
unspendable under the current rule.

And there is no other way for an eUTXO to come into existence. The unspent set
is written in exactly two places: the opening balances at state construction
(`transition.rs:995`) and `apply_transfer` (`transition.rs:1614`). Staking
rewards accrue to validator records, not to outputs.

Put together: **every output in the opening ledger is unspendable, and the
only thing that creates a spendable output is spending one.** There is no
bootstrap. This is the reason §12 reports what it does about end-to-end
execution, and it is the single most important thing to know before
scheduling an integration.

What must land before an exchange can process a Genesis-4 withdrawal:

1. A migration spend path that recognises the 20-byte-plus-zeros form
   explicitly and defines its authorisation rule — presumably "present a key
   whose `SHA3-256[0..20]` matches `script_hash[0..20]` and whose
   `script_hash[20..32]` is zero", but that is our inference and not a
   decision that has been made.
2. A flag-day or genesis decision fixing when that path activates.
3. A frozen Genesis-4 address format with a checksum (§9.1).
4. Its known-answer vectors, per the interfaces contract.

---

## 11. What was executed, and the vectors it produced

A harness was compiled against this branch and run. The keypair was generated
in the test process, used in memory, and never written to disk or printed.

```
KAT1  — key-independent, portable
  signing_root  = fb89823b501d25bb0683c02a1edf8175405c09160f3f8211bc03928709412c4c
  txid          = 992c87f11b9e2da370b3db07213c16618bd988a43d8b9224eeeae2fb8a163670
  canonical_len = 124
  witness independence      : asserted, passes
  tip is inside the root    : asserted, passes
  canonical round-trip      : asserted, passes

KAT2  — a real ML-DSA-65 ‖ Falcon-1024 key
  pubkey length             = 3749
  pubkey suite header       = b10c0100
  script_hash               = 98ba9b8ec52b17f18f26e80860e697ac940f09ac8a6a43698025f54931f86b8d
  signing_root              = 8d9a678cf71727a52c646ee729d134be2af7ef3a7922a04afacd221d002b0126
  signature length, run 1   = 4583
  signature length, run 2   = 4580          (same key, same root)
  signature bytes equal     = false
  both signatures verify    = true
  bit-flipped root rejected : asserted, passes
  encoded transaction       = 8449 bytes
  txid                      = 3a9aee38b6f7901da4f449d32e8acf5163c6570bbf1335c407ecf00a9ab97188
  canonical round-trip      : asserted, passes
  fee: gas=269748  base_fee_sat=2698  priority_fee_sat=269748

KAT3  — the carried form for the same key
  98ba9b8ec52b17f18f26e80860e697ac940f09ac000000000000000000000000
```

Three independent confirmations of the same numbers:

1. The Rust consensus crate produced KAT1's root and txid.
2. A **from-scratch Python implementation**, written against the field list in
   §3.2 and sharing no code with the repository, reproduced KAT1's root
   `fb89823b…` and txid `992c87f1…` exactly.
3. The `bloch-pos submit-tx` binary, invoked from a shell with a deliberately
   wrong 3-byte pubkey, printed KAT2's root `8d9a678c…` — identical to the
   library's value for the same transfer built with the real 3,749-byte key.

The Python address checksum in §9.4 likewise reproduced the mainnet and
testnet strings in §9.5 from the 20-byte hash alone.

---

## 12. What was NOT verified

Read this section before you rely on anything above.

### 12.1 No end-to-end signed transfer was demonstrated. Nothing was submitted to any network.

Stated without hedging: **I did not move value, and I could not have.** What
was executed is everything up to the socket — transaction construction, the
signing root, hybrid signing with a real key, hybrid verification, the
canonical encoding, the decode round-trip, the fee arithmetic, and the
`submit-tx` unsigned and guard paths. What was not executed is a transfer
accepted by `apply_transfer` inside a running node and appearing in a block.

The reason is §10.2, and it is structural rather than a matter of effort:

- A devnet genesis built by `bloch-pos genesis` commits **no** allocations and
  **no** carryover (`main.rs:691-696`), so its unspent set is empty and there
  is nothing to spend.
- A mainnet manifest's outputs are all in the zero-extended carried form,
  which no implemented rule can authorise.
- `apply_transfer` is a private method; the only way to reach it is through
  `apply_block`, which requires a funded opening state that cannot be
  constructed by any shipped tool.

An end-to-end value transfer is therefore not demonstrable on any network
today by anyone, with any key. Treat every statement in §4 as *read from the
source and reasoned about*, not as *observed against a live chain*. The
authorisation and conservation rules are pinned by the crate's own unit tests
against a toy verifier, which is stronger than nothing and weaker than a
running chain.

### 12.2 The signature was verified by the same library that produced it

`bloch_crypto::crypto::sign` and `::verify` are two functions in one crate
over one PQClean build. A KAT against an independent ML-DSA-65 or Falcon-1024
implementation was **not** performed, and there is no cross-implementation
vector in this document. If your signer uses a different PQClean vintage, a
different Falcon variant, or a padded rather than compressed Falcon
encoding, this document will not catch it — build a cross-implementation KAT
of your own before you trust either side.

### 12.3 Falcon determinism was not characterised

Two signatures over one root differed in length and in bytes. Whether the
length distribution has a hard floor, and whether `SIG_SIZE`'s 1,462-byte
Falcon bound is a proven maximum or an observed one, was not established. Size
your buffers from the bound and do not assume it is tight.

### 12.4 The base fee was not read from a live Genesis-4 node

The fee worked examples use `MIN_BASE_FEE_MILLISAT_PER_GAS = 10`, the floor
and genesis value. No Genesis-4 chain was queried. The EIP-1559 controller
moves the base fee ±1/8 per block over two axes; your conservation equation
must use the value the node reports at the time you build, and I did not
observe that value in operation.

### 12.5 Not reviewed here, by scope

The RPC method surface (`BLOCH-G4-RPC.md`) and the Genesis-3 → Genesis-4
snapshot mapping are owned by other passes. Where this document mentions
`getutxos` or the base fee it is pointing at them, not specifying them. I did
not read the live Genesis-3 chain, did not touch
`BLOCH-EXCHANGE-INTEGRATION.md`, and did not verify its Genesis-3 measurements
beyond re-deriving the address scheme independently.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **Discrepancy #7 is closed** — see the CORRECTION above §10; the carried
> ledger is spendable. **#1, #2, #4, #5 and #6 were re-checked on 2026-09-01 and
> are all still open**, unchanged. #3's substance is unchanged but its paths
> moved: the stratum sources are now under `legacy/genesis3-node/src/stratum/`.

### 12.6 Discrepancies found, unresolved

| # | Finding | Where |
|---|---|---|
| 1 | `HYBRID_SIG_BYTES = 4,589` sits **186 bytes below** `SIG_SIZE = 4,775`, the stated Falcon maximum. Both are described as sizes of the same object. Only one can bound it. | `fee_market.rs:93` vs `core/mod.rs:330` |
| 2 | "hash160" is used throughout the carryover code for a value that is `SHA3-256(pubkey)[0..20]`. There is no RIPEMD in the tree. The name invites an integrator to implement `RIPEMD160(SHA256(·))` and get a different chain. | `genesis.rs:221-225`, `:399`, `:591`; `tokenomics_v4.rs:386` |
| 3 | "bech32" is claimed for the address format in at least eight comments and two spec documents. It is not bech32 and a bech32 decoder rejects every valid address. | §9.2; `docs/API.md:275`, `docs/specs/BLOCH-L1-EVM-RPC-SURFACE.md:315`, several `src/stratum/` comments |
| 4 | Rust's address parser accepts uppercase hex; the TypeScript SDK rejects it. The two disagree on which strings are valid addresses. | `address.rs:63-98` vs `sdk/typescript/src/address.ts:92` |
| 5 | The address checksum does not cover the network prefix, so a testnet address is a checksum-valid mainnet address. | §9.3 |
| 6 | Genesis-4's `script_hash` identifier has **no checksum at all**. | §9.1 |
| 7 | The entire opening ledger is unspendable and there is no bootstrap path. | §10.2, §10.3 |

Items 5, 6 and 7 are the ones that should reach a decision-maker rather than a
backlog.

---


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **Roughly two thirds of the line numbers below no longer resolve.** Re-derive
> them, or cite by symbol name. Current locations: mempool admission
> `engine.rs:1345-1388` and `:2711+`; `TransferOutput` `transition.rs:276-283`;
> `Transfer` `:322-368`; `spend_signing_root` `:474-531`; `txid` `:548-554`;
> `canonical_bytes` `:602-700`; `from_canonical_bytes` `:730-828`;
> `apply_transfer` `:2120-2233` with the ownership check at `:2159-2163`;
> `EutxoEntry` `state_root.rs:996-1006`; the DS tags `params.rs:638` and `:647`;
> fee market `fee_market.rs:121/:125/:129/:143/:291-304`. The `crypto/mod.rs`,
> `address.rs`, `core/mod.rs`, `interfaces.rs`, `keys.rs`, `main.rs` and
> `rpc.rs` citations are still within a few lines.
>
> Two gaps an integrator will hit that the document never covers: there is **no
> minimum-value or dust rule** on transfer outputs — a zero-satoshi output is
> accepted by both `apply_transfer` and `admissible` (`BelowMinimum` exists only
> on `DepositReject`, `interfaces.rs:469`) — and RPC amounts come back as
> **decimal strings**, not JSON numbers (`rpc.rs:280-282`, `:1496`), even though
> the wire format is u64 LE as described.

## 13. Source index

| Subject | File and lines |
|---|---|
| `TransferInput` | `crates/bloch-pos-committee/src/transition.rs:178-192` |
| `TransferOutput` | `crates/bloch-pos-committee/src/transition.rs:195-204` |
| `Transfer` variant, and its two closed revisions | `transition.rs:216-267` |
| `spend_signing_root` | `transition.rs:320-377` |
| `txid` | `transition.rs:379-398` |
| `canonical_bytes` | `transition.rs:400-521` |
| `from_canonical_bytes` | `transition.rs:523-611` |
| `TxDecodeError` | `transition.rs:614-645` |
| `apply_transfer` — the rules | `transition.rs:1471-1625` |
| `TransferReject` | `crates/bloch-pos-committee/src/interfaces.rs:379-420` |
| `DS_SPEND`, `DS_TXID` | `crates/bloch-pos-committee/src/params.rs:86-104` |
| Gas, price, `charge` | `crates/bloch-pos-committee/src/fee_market.rs:78-155`, `:234-254`, `:342-362` |
| `EutxoEntry` | `crates/bloch-pos-committee/src/state_root.rs:404-416` |
| Suite envelope, sign, verify | `crates/bloch-crypto/src/crypto/mod.rs:16-62`, `:134-163`, `:180-226` |
| Legacy pre-envelope acceptance | `crypto/mod.rs:165-178` |
| `SIG_SIZE` upper bound | `crates/bloch-crypto/src/core/mod.rs:330` |
| Address derive / encode / decode | `crates/bloch-crypto/src/address.rs:55-61`, `:120-128`, `:63-98` |
| Network prefixes | `crates/bloch-crypto/src/core/mod.rs:135-136` |
| `verify_with_key` — the real suite | `crates/bloch-pos-node/src/keys.rs:122-136` |
| `submit-tx` | `crates/bloch-pos-node/src/main.rs:221-389` |
| Mempool admission | `crates/bloch-pos-node/src/engine.rs:651-676` |
| Carryover ownership rule | `crates/bloch-pos-node/src/genesis.rs:393-462`, `:582-600` |
| Genesis allocations | `crates/bloch-pos-node/src/main.rs:566-586` |
| `getnewaddress` refusal | `crates/bloch-pos-node/src/rpc.rs:208-237` |
| Address format open point | `docs/specs/BLOCH-POS-INTERFACES.md` §4.5 |
