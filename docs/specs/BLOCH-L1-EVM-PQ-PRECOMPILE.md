<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-L1-EVM-PQ-PRECOMPILE — hybrid verification from inside the EVM

**Status:** implementation of `BLOCH-L1-EVM-AUTHORIZATION.md` §6.2, under the
founder's decision of 2026-08-21 (**option 2**: PQ-only accounts, EVM
semantics without EVM signing). The authorization spec decided *what*; this
one fixes the ABI, the semantics, the gas, and the boundary with §6.1. It
re-opens none of that decision, and it does not touch §6.3 (enshrined account
abstraction, "phase 2, not launch"), §6.4 (PQ-bounded secp session keys,
"priced, and deferred"), or §6.5 (rejected there, rejected here).

**Inert.** The EVM is not on L1 and nothing here puts it there. The crate is
`crates/bloch-evm-pq-precompile`; **no crate in the tree depends on it**,
`bloch-pos-node`'s dependency list is unchanged, it is unreachable from
`transition.rs`, it adds no constant to `params.rs` and no tag to the closed
component list in `state_root.rs`. Wiring it in collides with ADR-040 and the
single-re-freeze rule SR-2 and is a separate founder decision. Mainnet has
been without finality for 27 epochs and produces a block roughly every 40
slots; a line of this reaching consensus by accident today would be an
incident, not a red test.

---

## 1. What it is for

Without a way to verify `SUITE_MLDSA65_FALCON1024` from inside the EVM, every
authorize-by-signature contract pattern is simply dead under option 2:
EIP-2612 `permit`, EIP-2771 meta-transactions, Safe-style signature checks,
bridge validator sets, Ustav/Kirpich charter checks. §6.2 of the
authorization spec is one paragraph long and says it must ship with the first
EVM block. This is that paragraph, made exact.

It is **not** an authorization path. The precompile is called by contract code
during execution; it can never authorize a transaction. Transaction
authorization is §6.1, the sibling front.

---

## 2. ABI

### 2.1 Address

```
0x00000000000000000000000000000000B10C0001
```

Sixteen zero bytes, then the `B1 0C` suite magic reused as a **namespace**
magic, then a big-endian `u16` index. Two reasons for a reserved block rather
than the next free low address: upstream Ethereum keeps assigning
`0x01..0x0a…`, so a future EIP landing on the same number would silently
change what a deployed contract calls; and the sibling state-model front needs
addresses of its own. Index `0x0001` is this precompile. `0x0002` and up are
**left unassigned for the state-model front** — the withdrawal precompile's
index is that front's call, not this one's.

### 2.2 Input

Exact framing, no ABI decoding, no dynamic offsets:

```
offset  size   field
0       32     msg32      the 32 bytes that were signed
32      32     pk_len     u256 big-endian, canonical (top 24 bytes zero)
64      32     sig_len    u256 big-endian, canonical
96      pk_len pk         enveloped hybrid public key
...     sig_len sig       enveloped hybrid signature
```

`96 + pk_len + sig_len` must equal the input length **exactly**. `pk_len` must
equal 3,749 (`SUITE_HEADER_LEN` + `HYBRID_PK_BYTES`). `sig_len` must lie in
`3,314 ..= 4,775` — the ML-DSA half is fixed at 3,309 and the Falcon half is
variable up to `falcon1024::signature_bytes()` = 1,462, which is why the
signature is a band where the key is a constant.

Maximum well-formed input: **8,620 bytes**. Typical: **8,438**.

### 2.3 Output

32 bytes.

- Success: twelve zero bytes ‖ the signer's 20-byte Bloch address,
  `SHA3-256(enveloped pk)[..20]`.
- Failure: 32 zero bytes.

**Never reverts.** Failure is the zero word, following the `ecrecover`
convention, so the caller decides what an invalid signature means. Calling it
before the flag day yields no code at the address, so `staticcall` returns
`success = false` with empty data — which `BlochPQ.recover` maps to
`address(0)`, i.e. "no signer", never "valid".

### 2.4 Why the address and not a `bool`

A `bool` precompile would force every contract to trust a signer address
handed to it *alongside* the signature, because no contract can derive one:
Solidity's `keccak256` and the EVM's `SHA3` opcode are **Keccak-256**, and a
Bloch address is **FIPS-202 SHA3-256** — a different padding rule. No amount
of Solidity reproduces `crypto::address_from_pubkey`. Returning the address
makes the precompile the single authority on that derivation, which is also
what keeps the EVM's notion of an account owner in step with the `sender`
field of a §6.1 transaction.

---

## 3. Semantics

### 3.1 Totality

`pq_verify_raw` is a total function of its input bytes: it never panics, never
reverts, reads no state, and returns the same 32 bytes for the same input on
every node. It is therefore safe under `STATICCALL`, and its result cannot
depend on which node is executing — the property the 2026-08-08 consensus
failure existed for the lack of.

### 3.2 The three rules `bloch_crypto::verify` does not impose

The base verifier must stay bug-compatible with pre-envelope carry-over
wallets. Inside the EVM that tolerance is a defect, so the precompile adds:

1. **Strict envelope, both objects.** `crypto::verify` routes through
   `parse_envelope_or_legacy` (`crypto/mod.rs:173`), which reads an
   un-headered blob as suite `0x0001`. Accepting that here would mean **one
   authorization with two valid byte strings** — signature malleability, which
   silently breaks any contract that de-duplicates by `keccak256(sig)`:
   Safe-style bookkeeping, bridge and relayer replay caches, anything that
   records "this signature has been used".
2. **One suite.** Only `SUITE_MLDSA65_FALCON1024` (`0x0001`).
   `SUITE_MLDSA65_ONLY` (`0x0002`) is exactly as available and exactly as
   unused as staking makes it (`staking.rs:52-56`) — a single-family suite
   would drop the hybrid property.
3. **Exact framing.** The declared lengths must account for every input byte,
   and the length words must be canonical. Two length fields plus a body is
   precisely the shape that admits many encodings of one call.

Rule 1 is the load-bearing one and the only one of the three a behavioural
test can see at all — see §11, M1 and M3.

### 3.3 What it deliberately does *not* do

- **It does not read state.** A variant that looked the public key up by
  address would save 3,749 bytes per call and is explicitly not built: it
  would break `STATICCALL` purity and make the gas depend on whether an
  account exists — a data-dependent price, which is exactly what §4's
  charge-by-length rule exists to forbid. If anyone wants it later: new
  index, new spec, its own review.
- **It does not interpret `msg32`.** See §8, the cross-replay requirement.

### 3.4 Reference implementation

`crates/bloch-evm-pq-precompile/src/lib.rs`. The Solidity side —
`contracts/BlochPQ.sol` and `contracts/PQPermitToken.sol` — is normative
reference, **not compiled**: there is no pinned `solc` and no EVM in this
repository (§9).

---

## 4. Gas — the central decision

### 4.1 The formula

```
pq_verify_gas(len) = 72,748 + 39 × ceil(len / 32)
```

Charged **from the length alone**, before any parsing, identical for a valid
signature, an invalid one, and 96 bytes of garbage.

### 4.2 The base: derived, not chosen

`72,748` is `fee_market::HYBRID_VERIFY_GAS`, taken as a re-export rather than
re-derived. That constant is `HYBRID_VERIFY_INSTRUCTIONS / INSTRUCTIONS_PER_GAS`
= `7,274,849 / 100`, where 7,274,849 is the measured RV32IM instruction count
for one hybrid verification (`spikes/prover-cost/RESULTS.md`, 2026-08-10).

The argument for reusing it verbatim: **a hybrid verification does not get
cheaper because a contract asked for it instead of a transaction envelope.**
If the two prices ever diverge, the cheaper one becomes the attack surface.
Two modules deciding one rule is this repository's recurring failure mode, and
a precompile spec is not the place to re-open the fee market's calibration.

### 4.3 The per-word term: 39, and the arithmetic

The only per-byte work is copying the input and hashing the public key with
SHA3-256 to derive the address. From the same measurement, one Keccak-f
permutation costs ≈ 16,300 RV32IM instructions — 16,386 and 16,270 in two
independent implementations, which is the cross-check that says the
measurement is real rather than an artifact of one code path. SHA3-256 absorbs
136 bytes per permutation:

```
16,300 / 136   = 119.9  instructions per byte
119.9 × 32     = 3,836  instructions per 32-byte word
3,836 / 100    = 38.4   gas per word          (INSTRUCTIONS_PER_GAS = 100)
               → 39     rounded up
```

Two objections answered:

- **"Why not `GAS_PER_BYTE` = 16, i.e. 512/word?"** That price defends *block
  bytes* — gossip and storage — and the precompile's input is memory the
  transaction already paid for as calldata. Charging it twice would price
  bytes that no node has to carry a second time.
- **"39 is ≈ 6.5× the EVM's `SHA3` opcode (6/word)."** It is, and that gap is
  a finding about the opcode schedule, not about this precompile: see §10. The
  anchor chosen here is the one tied to a measurement of *this chain's* code.
  The cost of preferring it is bounded and small — 10,530 gas at the maximum
  input against a 72,748 base, **12.7%** — and cannot grow, because `pk_len`
  is fixed and `MAX_INPUT_BYTES` caps the rest.

### 4.4 Charging by length and not by validity

A 96-byte malformed call pays 72,865 gas for no work at all. Deliberate. An
early-out discount would hand an attacker a cheap probe and would make the
price a function of the *data*. On a chain that has already lost consensus
once to a rule computed from mutable node-local state (2026-08-08,
`expected_bits`), "gas is a pure function of one integer" is worth more than
the gas it wastes. Overpricing is the safe direction.

### 4.5 The prices

| input | bytes | words | gas |
|---|---:|---:|---:|
| minimum (rejected — below the header) | 96 | 3 | 72,865 |
| cheapest that can reach the verifier | 7,159 | 224 | **81,484** |
| typical (4,593-byte signature) | 8,438 | 264 | 83,044 |
| maximum (4,775-byte signature) | 8,620 | 270 | 83,278 |

### 4.6 The DoS arithmetic

`BLOCK_GAS_LIMIT` = 60,000,000 gas per 30 s slot.

- **823** cheapest *calls* (96 bytes, rejected at framing) — but these do **no
  verification work**; do not confuse the two numbers.
- **736** actual *verifications*, at the cheapest input that reaches the
  verifier. This is the wall-clock ceiling.
- 736 × 7,274,849 = **5,354,288,864 instructions**, against the budget the
  block gas limit already implies: 60,000,000 × 100 = **6,000,000,000**.
  10.8% headroom.

**A block spent entirely in this precompile cannot exceed the instruction
budget its own gas limit implies.** That is what anchoring on the fee market's
number *means*, and it is why the precompile needs no per-block invocation cap
of its own. It is pinned two ways: a `const _: () = assert!(…)` in the crate,
and the `a_block_of_this_precompile_fits_the_blocks_instruction_budget` and
`gas_never_undersells_the_measured_verification` tests. The second one is not
decoration — `HYBRID_VERIFY_GAS` truncates `7,274,849 / 100` to 72,748 and so
under-sells a verification by 49 instructions *on its own*; it is the per-word
term that covers it, by ~178×.

Attacker cost for one hostile block: 60,000,000 gas at the fee floor
(`MIN_BASE_FEE_MILLISAT_PER_GAS` = 10 millisat/gas) = 600,000 sat = **0.006
BLCH**. Cheap for one block; the defence against a *sustained* attack is the
1559 controller (×1.125 per over-target block ⇒ ≈ ×100 after 40 full blocks).
The fee floor is a fee-market lever, not a precompile lever.

### 4.7 Measured wall clock

See §6. The instruction-count anchor is what the gas schedule rests on; the
wall clock answers a different question — whether a hostile block fits a slot.

---

## 5. What this changes about the chain's worst case

**The precompile decouples verification count from block bytes.** Today every
hybrid verification the chain performs is bounded by bytes: 524,288 B per
block (`MAX_BLOCK_TX_BYTES_V2`, in force since epoch 800) ÷ ≈ 4,693 B for a
steady-state §6.1 transaction ≈ **111 verifications per block**. With the
precompile, one ≈ 8.4 KB transaction can call it in a loop: **736**.

That is a **6.6× rise in the worst-case verification work one block can
impose**, and it is invisible in every byte-based capacity estimate the
project has written, including G10's.

It is not an argument against shipping — the anchor keeps the total inside the
block's instruction budget (§4.6) and the measured wall clock leaves the slot
room (§6) — but it is the kind of coupling that stays invisible until the day
it isn't. The mitigation is pre-agreed in *shape*, not built: a per-block cap
on invocations, constant pinned at `u64::MAX`, flag day, gate reading the
epoch **derived from the block**.

---

## 6. Measurement

`cargo run --release --example cost -p bloch-evm-pq-precompile`.

Measured 2026-08-22 on the development machine (x86_64 darwin, heavily
loaded — these are not best-case numbers):

| profile | median | min | max | n |
|---|---:|---:|---:|---:|
| **release** (what the fleet runs) | **190 µs** | 189 µs | 198 µs | 25 |
| debug | 1,079 µs | 1,051 µs | 1,201 µs | 25 |

A rejected call — framing failure, no verification — costs **0.018 µs**, five
thousand times less. The two must never be quoted as one number.

Worst case for a block, at the release figure: 736 × 190 µs = **0.140 s**, or
**0.47% of a 30 s slot**. The slot has room by more than two orders of
magnitude, and gas is what binds, exactly as intended.

### 6.1 A correction to a number circulating on the sibling front

An earlier §6.2 write-up reported 1.64–2.04 ms for the same operation and
concluded that `BLOCH-L1-EVM-AUTHORIZATION.md` §6.1 is wrong to call native
verification "microseconds-scale". **That figure is a debug-profile artifact.**
The table above reproduces it — 1,079 µs, same order — and then shows the
release build at 190 µs, 5.7× faster. The fleet builds release (`test.sh`
runs `cargo build --release -p bloch-pos-node`), so 190 µs is the number that
describes the chain.

The authorization spec's claim therefore **stands**, and no correction to it
is owed on this point. What does change is the size of the margin: 190 µs is
"hundreds of microseconds", not "a few", so a *sustained* attack has ~200×
of slot headroom rather than the ~10,000× that "microseconds" invites people
to assume. Quote the margin, not the adjective.

Still open, and listed as an activation gate: this is a laptop. The fleet's
slowest box is the measurement that counts.

---

## 7. `permitPQ` — the pattern, and its honest price

### 7.1 It works

`contracts/PQPermitToken.sol` grants an allowance against an ML-DSA ‖ Falcon
signature over a verbatim EIP-712 digest (`keccak256`, chain id, verifying
contract), with `BlochPQ.recover` in place of `ecrecover`.
`tests/permit_pattern.rs` models the contract statement for statement and
pins: the allowance is granted and spends; the nonce is consumed; and the
permit is refused on replay, wrong spender, wrong value, wrong deadline,
wrong nonce, expiry, a signature from another key, another contract, another
chain, and a stripped envelope — each with its control half.

### 7.2 It is **not** EIP-2612, and cannot be

`permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` carries the
signature in `(v, r, s)` — 65 bytes. A hybrid signature is ≈ 4,589 bytes and
needs a 3,749-byte public key beside it, because the suite is **not
recoverable**. There is no encoding of one into the other. Consequences, so
nobody discovers them by integrating:

- The **selector differs**. Every router, aggregator and permit-forwarder that
  calls the 2612 selector reverts here — including Uniswap V2's
  `removeLiquidityWithPermit`.
- A stock `UniswapV2ERC20` redeployed on Bloch exposes a `permit` **no Bloch
  wallet can satisfy**: a dead entry point, not an error message. Supporting
  permit in the Postern DEX is a **source fork** of `UniswapV2ERC20` and of the
  router paths that call it.
- The type hash is `PermitPQ(...)`, deliberately **not** `Permit(...)`, so no
  signature can ever cross between the two families. Pinned by
  `this_is_not_eip_2612`.

### 7.3 And for the ordinary case it is worse than two transactions

The counts, from §6.1's format and `fee_market::intrinsic_gas`:

| approach | bytes | intrinsic gas |
|---|---:|---:|
| two txs (`approve`, then `swap`) | 9,374 | 305,480 |
| **one §6.1 tx with a call batch** | **4,687** | **152,740** |
| one tx carrying `permitPQ` | 13,023 | 286,116 + 83,044 precompile |

The reason is structural on any PQ chain: the transaction already carries a
4.6 KB signature, and the permit adds a **second** one plus a 3.7 KB public
key that a non-recoverable suite cannot omit. EIP-2612 exists because on
Ethereum a signature is 65 bytes and an extra transaction costs 21,000 gas;
both halves of that trade invert here.

**Consequence for the DEX:** the Postern Uniswap-V2 fork runs in one
transaction per swap via §6.1's **call batch**, not via permit. The
precompile's real value is the case where **the signer is not the sender** —
relayed and sponsored calls, contract wallets, multisig, bridge validator
sets, Ustav/Kirpich charter checks.

---

## 8. Boundary with §6.1 — assumptions, written to break loudly

The sibling front (`l1-evm-pq-txtype`) owns the transaction type. This spec
assumes, and must be re-reviewed if any of these move:

1. **Envelope encoding**, not staking's raw-plus-suite-field form. §6.1 of the
   authorization spec already picks the envelope; this precompile requires it.
2. **Suite `0x0001` only.**
3. **Address derivation is `SHA3-256(enveloped pk)[..20]`, identical to
   `crypto::address_from_pubkey`.** The §6.1 `sender` field, the EVM account
   key, and this precompile's return value must be the *same* 20 bytes. If
   §6.1 adds a domain tag to that derivation, both change on the **same flag
   day**; that needs a shared constant and a cross-crate test pinning it
   before either front ships.
4. **The §6.1 signing root stays SHA3-based and domain-tagged.** This is a
   hard requirement, not a preference — see below.

### 8.1 Cross-replay between a contract digest and a transaction signing root

`msg32` is **opaque** to the precompile. It cannot tell a permit digest from a
§6.1 signing root, and nothing inside it can. Today the two spaces do not
overlap for a **structural** reason: the §6.1 root is
`SHA3-256(DS_EVM_TX ‖ fields)` and contract digests are `keccak256` —
different functions.

- **Requirement on §6.1:** keep the root SHA3-based and domain-tagged. If it
  migrates to `keccak256` for tooling familiarity, that separation collapses
  and the two fronts must define a domain-tag registry over one hash space
  **before either ships**.
- **Requirement on the wallet:** never sign 32 opaque bytes blind. This is why
  `permitDigest` is `public view` — so a wallet recomputes the digest from the
  structured fields and shows the user what is being authorized.

---

## 9. Activation gates — all open

The precompile is inert (`PQ_PRECOMPILE_ACTIVATION_EPOCH = u64::MAX`, pinned
by `the_precompile_is_inert_at_every_epoch_the_chain_can_reach`). Before any
flag day:

1. Re-run the cost harness on the **slowest box in the fleet**, not a laptop,
   with the worst-case 4,775-byte signature.
2. Compile the Solidity with a **pinned `solc`** and replace the host model in
   `tests/permit_pattern.rs` with execution against a pinned EVM.
3. Freeze **KATs**: `(pk, msg, sig)` triples with their expected 32-byte
   outputs, including the rejection cases, so the schedule cannot drift
   silently.
4. Run a **differential** against `bloch_crypto::verify` over random and
   adversarial inputs, asserting they diverge **only** on the three rules in
   §3.2.
5. When wiring: move the activation constant to `params.rs` beside
   `LEAKED_ROSTER_ACTIVATION_EPOCH` and `BLOCK_BYTES_V2_ACTIVATION_EPOCH`,
   delete the crate-local one, gate on the epoch **derived from the block**,
   and rebuild the fleet **before** the flag day.

This front is **not** part of the SR-2 re-freeze: it adds no `StateRoots`
component and no closed-list tag. It lives inside whatever the EVM component
tag already commits.

---

## 10. Referred, not fixed here

The same arithmetic that yields 39 gas/word says the EVM `SHA3` opcode —
adopted 1:1 by `BLOCH-L1-FEE-MARKET.md` §3.2 at 30 + 6/word — is **≈ 6.5×
under-priced** against this chain's own RV32IM anchor. A block full of `SHA3`
would imply ≈ 6.5× the anchor's instruction budget. That is a finding for the
owner of the **opcode schedule**. A precompile cannot and should not fix it,
and re-deriving fee-market constants inside a precompile spec would be exactly
the two-houses-one-rule failure this document declines in §4.2.

---

## 11. Mutation record

Sixteen mutations, each applied alone to the shipped source, `cargo test -p
bloch-evm-pq-precompile --no-fail-fast` run, then reverted. Harness and raw
results kept out of the tree; the table is the deliverable. This exists
because a review on 2026-08-21 showed that reverting two consensus sites
survived a 489-test suite: a green suite is evidence of nothing until
something has been broken on purpose.

**11 killed, 5 survived.**

| # | mutation | result | caught by |
|---|---|---|---|
| M1 | strict envelope on the **signature** deleted | **killed** | `an_unenveloped_signature_is_refused_here_although_bloch_crypto_accepts_it`, `the_stripped_envelope_does_not_open_a_second_permit_encoding` |
| M2 | strict envelope on the **public key** deleted | *survived* | — |
| M3 | any suite tag accepted | **killed** | `the_envelope_predicate_admits_only_suite_0x0001` |
| M4 | exact framing relaxed to `<=` | **killed** | `a_trailing_byte_is_refused` |
| M5 | `u256` length words no longer canonical | **killed** | `a_non_canonical_length_word_is_refused` |
| M6 | `MAX_INPUT_BYTES` guard deleted | *survived* | — |
| M7 | signature lower length bound deleted | *survived* | — |
| M8 | signature upper length bound deleted | *survived* | — |
| M9 | `pk_len` exactness relaxed to `>=` | *survived* | — |
| M10 | address hashed over the pk **body**, not the envelope | **killed** | 11 tests, incl. `the_returned_address_is_the_chains_address_derivation` |
| M11 | gas base cut to `ecrecover`'s 3,000 | **killed** | *compile error* — the `const _: () = assert!` in §4.6 |
| M12 | per-word charge dropped to the EVM `SHA3` price (6) | **killed** | `gas_is_the_documented_formula`, `a_block_of_this_precompile_fits_the_blocks_instruction_budget`, `a_malformed_short_call_still_pays_in_full` |
| M13 | out-of-gas check removed | **killed** | `insufficient_gas_is_out_of_gas_not_a_free_answer` |
| M14 | verification result computed and discarded | **killed** | 8 tests |
| M15 | `permitPQ` no longer checks signer **is** owner | **killed** | `a_signature_from_another_key_cannot_permit_your_balance` |
| M16 | `permitPQ` never consumes the nonce | **killed** | `a_pq_signature_grants_an_allowance_and_the_allowance_spends`, `the_same_permit_cannot_be_replayed` |

### 11.1 What the campaign changed

**M3 survived the first round.** The behavioural suite could not see the
suite rule at all: `crypto::verify` dispatches on the tag itself, so a
`0x0002`-tagged hybrid body fails inside the base verifier no matter what
this precompile checks. The fix was not another end-to-end case — there is
none — but to state rule 2 as a rule: `is_hybrid_envelope` is now `pub` and
tested directly. That is why it reads `pub` for a two-line helper.

**M12 was not caught by `gas_never_undersells_the_measured_verification`.**
6 gas/word still covers the instruction cost; what it stops covering is the
*documented derivation*. The lesson is that an inequality test cannot pin a
price — only the stated formula can, which is why
`gas_is_the_documented_formula` asserts the exact numbers.

### 11.2 The five survivors, and why they are not holes

All five are checks that are **enforced twice**. Each is reported rather than
removed, and none is left un-explained:

- **M2 (pk envelope) and M9 (`pk_len` exactness)** are the same rule from two
  directions. `pk_len` must be 3,749 and the envelope body must be 3,745, so
  either check alone rejects everything the other would. And an
  *un-enveloped* 3,749-byte blob can never verify anyway: read as legacy, its
  Falcon half is 1,797 bytes where Falcon-1024 needs 1,793. Behaviourally
  unobservable — not untested, **unobservable**.
- **M7 (signature lower bound)** is the same rule as "the envelope body must
  be strictly longer than the ML-DSA half", stated once in lengths and once
  in bodies.
- **M6 (`MAX_INPUT_BYTES`) and M8 (signature upper bound)** are work bounds,
  and §4.4's charge-by-length rule is what makes them behaviourally invisible:
  an oversized call simply pays more and fails. Their real job is to make
  `MAX_INPUT_BYTES` a true bound so the gas table and the DoS arithmetic in
  §4.5–§4.6 mean something.

The honest summary: **charge-by-length and the fixed suite geometry make the
size guards non-load-bearing today.** They are kept as the bound the
arithmetic is written against, and if either the suite grows or the framing
rule loosens, this paragraph is the record of what used to be covering them.

---

## 12. Out of scope

- §6.3 enshrined account abstraction; §6.4 PQ-bounded secp session keys; §6.5
  (rejected). Not designed, not prototyped, not prepared.
- Wiring the EVM to the node's state-transition path.
- The §6.1 type byte, signing root, `sender_pk` field, and call-batch encoding.
- The withdrawal precompile's index inside the reserved `0x…B10C____` block.
- Re-pricing `SHA3` or any fee-market constant. `HYBRID_VERIFY_INSTRUCTIONS`,
  `INSTRUCTIONS_PER_GAS`, `GAS_PER_BYTE`, `TX_FLAT_GAS` and `BLOCK_GAS_LIMIT`
  are consumed as data.
- Restating G10. The precompile adds CPU, not bytes; §8.3 of the authorization
  spec still stands on its own terms.
