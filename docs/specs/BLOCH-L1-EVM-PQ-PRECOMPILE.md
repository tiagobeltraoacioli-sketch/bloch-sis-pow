<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-L1-EVM-PQ-PRECOMPILE — verifying Bloch's own signatures from inside the EVM

```
Document:   BLOCH-L1-EVM-PQ-PRECOMPILE
Status:     SPECIFICATION + inert reference implementation. Nothing here is
            wired to consensus and nothing here may be wired to consensus
            without a separate founder decision (ADR-040, SR-2).
Decides:    BLOCH-L1-EVM-AUTHORIZATION.md §6.2 — the hybrid-verify precompile,
            its ABI, its gas price, and its activation posture.
Founder
decision:   OPTION 2 (PQ-only accounts), taken 2026-08-21. This front builds
            half of what that option is made of: §6.1 + §6.2.
Out of
scope:      §6.3 (enshrined account abstraction — "phase 2, not launch"),
            §6.4 (PQ-bounded secp session keys — "priced, and deferred"),
            §6.5 (secp for non-value-moving calls — REJECTED). Not designed,
            not prototyped, not mentioned as future work in any public doc.
Code:       spikes/pq-precompile/  (standalone, NOT a workspace member)
Reads:      crates/bloch-crypto/src/crypto/mod.rs (the verifier and the
            envelope), crates/bloch-pos-committee/src/{fee_market,staking}.rs
            (the gas anchor and the hybrid rules)
```

---

## 0. The rule that outranks everything else in this document

**The EVM is not at L1, and nothing here puts it there.** This front builds a
vehicle: a pure function, its price, and its tests. It is not reachable from
`transition.rs`, it is not a workspace member, it adds no dependency to the node
binary, and it introduces no constant into `params.rs`. Turning it on is a
separate founder decision that collides with ADR-040 and with SR-2's
single-re-freeze rule.

There is an operational reason to be pedantic about this today and not merely
disciplined: mainnet finality has been stalled for 27 epochs and the chain is
producing roughly one block every 40 slots. A line of this front reaching
consensus by accident right now would not be a red test; it would be an
incident on a chain that is already sick.

Consequently the reference implementation lives in `spikes/pq-precompile/`,
alongside `spikes/prover-cost/`, with its own `[workspace]` table — invisible
to `cargo build --workspace`, unreachable from the node.

---

## 1. What the precompile is

One pure function, callable from Solidity, that answers the only question
`ecrecover` used to answer on this chain and can no longer answer for anyone:

> did the holder of Bloch account `0x…` sign these 32 bytes?

Without it, every contract pattern whose authorization is a signature dies at
launch: EIP-2612 `permit`, EIP-2771 meta-transactions, Safe-style
`checkSignatures`, contract wallets, bridge validator sets, any Ustav/Kirpich
charter check that verifies a signature. §6.2 of the authorization spec is
right that it "should ship with the first EVM block": without it, option 2's
contract ecosystem cannot verify its own chain's signatures.

| | |
|---|---|
| Address | `0x00000000000000000000000000000000B10C0001` |
| Input | `msg32 ‖ u256(pk_len) ‖ u256(sig_len) ‖ pk_envelope ‖ sig_envelope` |
| Output | 32 bytes: `0…0 ‖ addr20` if valid, 32 zero bytes if not |
| Gas | `72,748 + 39 · ceil(len/32)` — charged from **length only**, before parsing |
| Reverts | never (only out-of-gas) |
| State | reads none; `STATICCALL`-safe; `view`/`pure` on the Solidity side |

### 1.1 The address, and why it is not `0x0b`

Ethereum's precompiles occupy `0x01..0x0a` and upstream keeps appending. The
withdrawal precompile of `BLOCH-L1-EVM-STATE-MODEL.md` §4.3 also needs an
address. So this document reserves a **block** rather than a number: 16 zero
bytes, then the envelope's own magic `B1 0C`, then a big-endian `u16` index.

```
0x00000000000000000000000000000000B10C____
                                  ^^^^  ^^^^
                                  magic index
```

`pq_verify` takes index `0x0001`. Index `0x0002` is left for the withdrawal
precompile; the state-model front owns that assignment, this document only
declines to squat on it. Upstream Ethereum can add precompiles for as long as
it likes without ever colliding.

### 1.2 The input framing, and why every field is pinned

```
  [  0.. 32)  msg32    — 32-byte digest. OPAQUE here (see §8.3).
  [ 32.. 64)  pk_len   — u256 BE. MUST equal 3,749.
  [ 64.. 96)  sig_len  — u256 BE. MUST be in 3,314 ..= 4,775.
  [ 96..  ..)  pk_envelope ‖ sig_envelope, and NOTHING after.
```

Big-endian `u256` lengths because that is what `abi.encodePacked` emits for a
`uint256`, so a caller builds this input with one line of Solidity and no
custom assembly.

- **`pk_len` is a constant, not a bound.** Suite `0x0001`'s enveloped public
  key is exactly 3,749 bytes (4-byte envelope + `HYBRID_PK_BYTES` 3,745). A
  fixed length makes the per-word gas term unfarmable: nobody can buy input
  words without also buying a verification (§5.4).
- **`sig_len` is a range**, because Falcon-1024's signature is variable —
  `4 + MLDSA65_SIG_BYTES + 1` at the low end, `4 + 3,309 + 1,462` at the high
  end. The split point itself is fixed at `MLDSA65_SIG_BYTES`, which is
  precisely why the hybrid signature needs no internal length prefix
  (staking.rs:65-70).
- **No trailing bytes.** One authorization has exactly one encoding. Trailing
  bytes are not merely untidy: they change the gas charged, so tolerating them
  hands an attacker a knob that makes two identical authorizations cost
  differently (proved by mutation, §3.4).
- A length word that does not fit in a `usize` is **rejected, not truncated**.
  Silent truncation is how `2^64 + 96` becomes `96`.

---

## 2. Return the address, not a bool

§6.2 sketches the signature as `pq_verify(pk, msg32, sig) → bool`. This
document implements it as `→ address` — the signer's 20-byte Bloch account,
zero on failure. That is an implementation-time interface choice (§9 of the
authorization spec explicitly leaves those open), and it is made for two
reasons that a bool cannot answer.

**Reason one: Solidity cannot derive a Bloch address.** A Bloch address is
`SHA3-256(enveloped pk)[..20]` (`address_from_pubkey`, crypto/mod.rs:274).
The EVM's `keccak256` opcode is **Keccak-f[1600] with the original padding**,
not FIPS-202 SHA3-256; they are different functions with different outputs. A
contract given a public key therefore has **no way to compute which account it
belongs to**. With a bool return, every caller would have to accept an address
supplied *next to* the signature and trust it — which is not a check at all.
Putting the derivation inside the precompile is the only place it can live
without adding a second precompile.

**Reason two: it makes the classic hole hard to write.** `if (pq_verify(...))`
means "somebody signed this", which is what an attacker wants it to mean. An
address return cannot be consumed without a comparison. It is also
`ecrecover`-shaped, so `abi.decode(ret, (address))` and every audited
"compare the recovered address to the stored owner" pattern port verbatim.

Failure is `address(0)`. A public key whose SHA3-256 begins with 20 zero bytes
is a 2⁻¹⁶⁰ event; the library treats `address(0)` as unusable, exactly as
`ecrecover` consumers already do.

---

## 3. Three rules `bloch_crypto::verify` does not enforce

The authorization spec says the precompile is "thin over `bloch_crypto::verify`".
It must be thin over it, not equal to it. `verify` is deliberately permissive in
ways that are correct for the carry-over chain and wrong inside the EVM. Each
rule below is proved load-bearing by a mutant that removes it
(`spikes/pq-precompile/tests/precompile.rs`).

### 3.1 Strict envelope — no legacy fallback

`verify` routes through `parse_envelope_or_legacy` (crypto/mod.rs:173): an
un-headered blob is treated as suite `0x0001`, so that pre-envelope carry-over
wallets stay spendable. That is right for the base chain and wrong inside the
EVM, and it is wrong on the **signature** side specifically.

The pubkey side is closed by framing alone: `pk_len` must be exactly 3,749 and
a legacy raw pubkey is 3,745, so it never reaches the verifier. The signature
side cannot be closed that way, because `sig_len` must be a *range* — Falcon is
variable-length — and a legacy raw signature (≈ 4,586 B) sits inside it.
`bloch_crypto::verify` reads suite `0x0001` from the enveloped pubkey and, via
the legacy fallback, `0x0001` from the un-enveloped signature; the suites match
and it returns true.

The damage is **signature malleability**: one authorization, two distinct valid
encodings. Contracts that de-duplicate by `keccak256(sig)` — Safe-style
signature bookkeeping, bridge and relayer replay caches — would see two
different signatures for one approval, which is the classic way a replay guard
is bypassed without forging anything.

So the precompile parses the envelope itself, on both objects, and rejects
anything un-headered.

### 3.2 One suite — `SUITE_MLDSA65_FALCON1024` only

`verify` also accepts `SUITE_MLDSA65_ONLY` (`0x0002`), the "Falcon removed"
escape hatch. Staking already refuses it by type (`DepositTx.suite` must be
`0x0001`, staking.rs:52-56). The precompile refuses it too, for a reason
specific to being priced: **a `0x0002` verification is roughly 4.5× cheaper to
compute than a hybrid one** (Falcon-1024 verifies 4.5× cheaper than ML-DSA-65 —
`spikes/prover-cost/RESULTS.md`) yet would be sold at the hybrid price and
would authorize in the same 20-byte address space. One suite, one price, one
behaviour. Suite agility remains where it belongs: a *new precompile index*
with its own measured price, not a branch inside this one.

Mutation `B` builds a genuine `0x0002` keypair by re-enveloping the ML-DSA
halves, confirms the crate's own verifier accepts it, and asserts the
precompile does not. Stated honestly: today the fixed `pk_len` rejects a
1,956-byte ML-DSA-only pubkey *before* the suite check runs, so the suite check
has no witness and deleting it changes no observable outcome. It is kept as the
guard that becomes load-bearing the moment a second suite with a 3,745-byte
public key exists — and §3.6 records that this is a guard, not a proved rule,
rather than letting a green test imply otherwise.

### 3.3 The address commits to the envelope

`SHA3-256` is taken over the **enveloped** public key, header included — that
is what makes an address suite-committing. Mutation `C` is the tempting
"strip the header first" refactor; the test asserts it moves the address, and
that the reference matches the chain's own `address_from_pubkey` output.

### 3.4 Exact framing

Mutation `D` accepts trailing bytes and is shown to (i) accept a padded input
the reference rejects and (ii) produce a different gas charge for the same
authorization.

### 3.5 What is deliberately NOT re-implemented

The cryptography. Suite dispatch, the `<=`-length guards, the `from_bytes`
parse-fail-to-`false` discipline, and the AND-composition of the two halves
stay in `crates/bloch-crypto` and `staking.rs::verify_hybrid`, where they are
audited and where the Falcon `clean`-path tripwire test already guards them.
The precompile adds framing and address derivation, and delegates.

### 3.6 The mutation record — including the two that survived

Rule 4 of this base's discipline is *prove by mutation*: a suite that passes
with a load-bearing line reverted is not evidence. Each rule was reverted in the
reference implementation and the suite re-run. The result, verbatim:

| # | Mutation applied to `src/lib.rs` | Suite | Caught by |
|---|---|---|---|
| M1 | strict envelope check deleted | **FAILS** | `mutation_a_strict_envelope_is_load_bearing_on_the_SIGNATURE` |
| M2 | exact framing → tolerant (`!=` → `<`) | **FAILS** (2 tests) | `mutation_d…`, `framing_is_exact` |
| M3 | address hashed over the body, not the envelope | **FAILS** (2 tests) | `mutation_c…`, `valid_hybrid_signature_returns_the_signers_address` |
| M4 | `PQ_VERIFY_BASE_GAS` = 3,000 (ecrecover's price) | **FAILS** | `gas_never_undersells_the_measured_verification` |
| M5 | `pk_len ==` relaxed to `pk_len >=` | *passes* | nothing — unobservable |
| M6 | `MAX_INPUT_BYTES` upper guard deleted | *passes* | nothing — unobservable |

M1 is the one that earns the method. The first version of that test stripped
the envelope from **both** objects, and it passed against a reference with the
check deleted — because the pubkey was rejected on length before the missing
check could matter. The test was measuring framing and reporting it as envelope
enforcement. The corrected witness (enveloped pubkey, raw signature) is the
subject of §3.1, and the finding in §3.1 exists only because the mutation was
actually run.

M5 and M6 are recorded as **unobservable, not untested**: exact framing plus
`bloch_crypto`'s own exact body-length checks already imply both. They are kept
because they make the maximum input size a constant a reader can see without
chasing three checks into another crate — and §5.4's whole gas bound is stated
over that constant. `the_length_caps_are_implied_by_the_field_rules` pins the
property instead of pretending the lines are load-bearing.

---

## 4. Totality — the consensus-safety property

`pq_verify` is **total**: every byte string maps to a 32-byte output. It cannot
revert, cannot panic, and has no data-dependent failure mode that is not a
`false`. This is the same rule the crypto crate already states for consensus
("parse failure ⇒ verify returns false and NEVER panics"), and inside the EVM
it matters more, not less: a panic in a precompile is a node crash on a
block that other nodes accepted — a partition, not an error.

The test suite includes a totality sweep over malformed inputs at every
interesting length, and every negative test carries its control half so that a
verifier stuck at `false` cannot pass the suite.

---

## 5. Gas — the central decision

A precompile that verifies a 7.3-million-instruction signature is a CPU vending
machine. If the price is below cost, the machine sells validator time at a
discount and the cheapest denial-of-service on this chain is a `for` loop.
So the number is derived, not chosen, and the derivation is here in full.

### 5.1 The anchor is not re-decided here

`crates/bloch-pos-committee/src/fee_market.rs` already fixes the whole native
schedule against one measurement and one ratio:

| Constant | Value | Meaning |
|---|---|---|
| `HYBRID_VERIFY_INSTRUCTIONS` | 7,274,849 | measured RV32IM instructions for one hybrid verification (`spikes/prover-cost/RESULTS.md`, marginal count over 1–4 signatures, dispersion < 0.5%) |
| `INSTRUCTIONS_PER_GAS` | 100 | the single calibration ratio of the native schedule |
| `HYBRID_VERIFY_GAS` | 72,748 | what an eUTXO input and a §6.1 transaction already pay |
| `GAS_PER_BYTE` | 16 | the **bandwidth** price of a transaction byte |
| `BLOCK_GAS_LIMIT` | 60,000,000 | 2 M gas/s at 30 s slots |

Re-deriving any of these inside a precompile spec would be exactly the failure
mode this repo keeps hitting: two places deciding one rule. This front consumes
them.

### 5.2 The price

```
pq_verify_gas(len) = PQ_VERIFY_BASE_GAS + PQ_VERIFY_PER_WORD_GAS · ceil(len / 32)
                   = 72,748 + 39 · words
```

**Base = 72,748.** Identical to `HYBRID_VERIFY_GAS`, because it is the same
verification, measured once. A hybrid verification does not become cheaper
because it was requested by a contract instead of by a transaction envelope,
and if the two prices ever diverge the cheaper one becomes the attack surface.
One measured number, one ratio, no hand-tuned constant.

**Per word = 39.** The only per-byte work is copying the input and hashing the
public key with SHA3-256 for the address. From the same spike: a Keccak-f
permutation costs ≈ 16,300 RV32IM instructions (16,386 and 16,270 measured in
two independent implementations — the cross-check that says the measurement is
real). SHA3-256 absorbs 136 bytes per permutation:

```
16,300 instr / 136 B      = 119.9 instr per byte
119.9 × 32                = 3,836 instr per 32-byte word
3,836 / 100 instr-per-gas =    38.4 gas per word   → 39
```

This is ~6.5× the EVM's own `SHA3` opcode price (6 gas/word), and the gap is
not a mistake: it is the pre-existing disagreement between Ethereum's schedule
(adopted 1:1 by `BLOCH-L1-FEE-MARKET.md` §3.2 for execution) and this chain's
RV32IM anchor (used for everything native). Where the two disagree inside a
*native* component, this document takes the anchor, because the anchor is the
one tied to a measurement of this chain's own code. The cost of that choice is
bounded and small: at the maximum input the per-word term is 10,530 gas against
a 72,748 base — **12.7%** — and it cannot grow, because the input length is
bounded (§5.4).

> **Referred out, not fixed here:** the same arithmetic says the EVM's `SHA3`
> opcode, adopted 1:1, is priced ~6.5× under this chain's anchor. A block full
> of `SHA3` therefore implies ~6.5× the anchor's instruction budget. That is a
> finding for the fee-market owner about the *opcode* schedule, not something a
> precompile can or should correct.

### 5.3 Charged on length, before execution, regardless of validity

`pq_verify_gas` is a function of `input.len()` **only**. Never of content,
never of validity, never of which check failed. Three consequences, all
intended:

1. A malformed 96-byte input costs 72,865 gas — the full base for no work at
   all. Deliberate over-charging. The alternative, a cheap early-exit path,
   would give an attacker a discounted probe and would make gas depend on
   parse results, i.e. on data.
2. Gas is knowable before execution, so builders and `eth_estimateGas` are
   exact rather than probabilistic.
3. It is deterministic across implementations by construction. There is no
   branch whose taking a node could disagree about. Given that this chain has
   already had a real consensus failure from a rule read out of local mutable
   state (2026-08-08, `expected_bits`), "the gas is a pure function of one
   integer" is worth more than the gas it wastes.

Pinned by `gas_is_a_function_of_length_only`: the same-length valid and garbage
inputs must price identically.

### 5.4 The DoS bound — what a full block buys

Input length is bounded above, tightly, because the public-key length is fixed:

```
max input = 96 + 3,749 + 4,775 = 8,620 B = 270 words
max gas   = 72,748 + 270 × 39  = 83,278
typical   = 96 + 3,749 + ~4,587 = ~8,432 B = 264 words → 83,044 gas
min       = 96 B (rejected)                          → 72,865 gas
```

Add the EVM's own warm `STATICCALL` floor (100 gas) and divide the block:

| | calls per 60 M-gas block |
|---|---|
| cheapest possible call (96 B, **rejected**, no lattice work) | 822 |
| cheapest **real** verification (typical ≈ 8,432 B input) | 721 |

The instruction-budget check, which is the argument in one line:

```
721 real verifications × 7,274,849 instr = 5.25 G instructions
BLOCK_GAS_LIMIT × INSTRUCTIONS_PER_GAS   = 6.00 G instructions
```

**A block spent entirely on this precompile cannot exceed the instruction
budget the block gas limit already implies.** That is true by construction —
it is what pricing at the anchor *means* — and it is pinned as an assertion
(`gas_never_undersells_the_measured_verification`) so a future edit that
lowers the base fails the build rather than the network.

Native wall-clock is the second half of the check, because RV32IM instructions
are a zkVM proxy, not x86 cycles. Measured with the harness in this spike
(`cargo run --release --bin pq-precompile-cost`):

```
valid  call : 1,640 – 2,040 us   (5 runs, median 1,880 us)
reject call :         0.03 us   (control half: framing only, no lattice work)

cheapest CALL   (96 B, rejected) : 72,965 gas -> 822 calls,  0.026 ms of CPU
cheapest VERIFY (8,432 B input)  : 83,144 gas -> 721 verifications
anchor instructions those are    : 5.25 G   (block budget 6.00 G)
native wall-clock for that block : 1.36 s at the median (range 1.18 – 1.47 s)
                                 = 4.5 % of a 30 s slot (range 3.9 – 4.9 %)
```

Two things this measurement changes.

**First, a correction to the authorization spec.** §6.1 there says native
verification is "microseconds-scale" and concludes "CPU is not the constraint;
bytes, not cycles, are what gas must defend". The measured figure is
**≈ 1.9 milliseconds** — two to three orders of magnitude off. The reason is not a
mistake in that document's reasoning but a build constraint it did not account
for: `pqcrypto-falcon` is declared `default-features = false` precisely to
forbid the AVX2/NEON floating-point variants (settled decision 2, the
`falcon_native_fp_variants_are_not_linked` tripwire), so the fleet runs
PQClean's integer-emulated `clean` path — the slow, constant-time one, on
purpose. **The chain's own security decision is what makes verification
expensive**, and any capacity statement that assumes microseconds is wrong.

The conclusion nevertheless survives at the block level: under 5 % of a slot
for a maximally hostile block is comfortable, and gas priced at the anchor is
what keeps it there. But the margin is ~20×, not ~10,000×, so the fleet
measurement of §5.6 is a real gate and not a formality.

**Second, the control half matters.** A rejected call is ~60,000× cheaper than
an accepted one (0.03 µs vs 1,880 µs) and is charged the same 72,748-gas base.
That asymmetry is the design working: the expensive path is the one that gets
paid for, and the cheap path is over-charged rather than discounted.


Attacker economics: 60 M gas at the fee floor (`MIN_BASE_FEE_MILLISAT_PER_GAS`
= 10 millisat/gas) is **600,000 sat = 0.006 BLCH per block**. That is cheap for
one block and is *supposed* to be: the defence against a sustained attack is
the 1559 controller, which raises the base fee by up to 1/8 per block while
utilisation is above target — roughly ×100 after 40 consecutive full blocks.
The floor price is a fee-market lever, not a precompile lever.

### 5.5 The honest part: this raises the per-block verification ceiling

Today every PQ verification the node performs is bounded by **bytes**: a
signature must arrive in a block, and blocks are capped
(`MAX_BLOCK_TX_BYTES_V2` = 512 KiB from epoch 800). At ~4,687 bytes per §6.1
transaction that is ≈ 111 verifications per block (measured), and the attestation load is
a separate, known 128-per-epoch-boundary.

The precompile **breaks that coupling**: one 8.4 KB transaction can call it in
a loop, so verification count is bounded by gas, not by bytes. 721 versus 111
is a **6.5× increase in the worst-case verification work a single block can
impose**, bought with ~9 KB of block space.

This is not an argument against shipping it — the anchor keeps the total inside
the block's own instruction budget, and the measured wall-clock says the slot has room. It is an argument for saying it out loud, because it is the kind of
coupling that is invisible until the day it is not, and because the mitigation
if the fleet ever disagrees with the measurement is cheap and should be
pre-agreed: a per-block cap on precompile invocations, enforced the same way
every other consensus rule here is — a constant at `u64::MAX`, a flag day, and
a gate that reads the epoch derived from the block.

### 5.6 What is still open

- **The measurement must be repeated on fleet hardware.** The number above
  comes from a developer laptop. The binding number is the slowest validator
  the fleet actually runs (Fly shared-CPU instances, and the fleet is already
  RAM-starved — `bloch-pos-notincommittee-stall`). Gate: the same harness on a
  fleet box before activation.
- **The worst-case input, not the typical one.** Falcon verification cost has
  mild input dependence through signature decompression. The harness measures
  a typical signature; the activation gate should measure the 4,775-byte
  worst case and the shortest-legal case and take the max.
- **Interaction with G10** (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md`): G10's byte
  budget is unaffected by this front — the precompile adds CPU, not bytes. Its
  CPU is inside the gas limit. No G10 restatement is required *by this
  document*; §8.3 of the authorization spec's restatement requirement is about
  the §6.1 transaction budget and stands unchanged.

---

## 6. The demonstration: a PQ `permit`

`spikes/pq-precompile/contracts/PQPermitToken.sol` is a minimal ERC-20 whose
`permitPQ` grants an allowance from an ML-DSA‖Falcon signature instead of
`ecrecover`. `BlochPQ.sol` is the library any contract should use to call the
precompile: `recover(digest, pk, sig) → address` and
`verify(signer, digest, pk, sig) → bool`.

The digest construction is **EIP-712 verbatim** — `\x19\x01 ‖ domainSeparator ‖
structHash`, keccak256 throughout, chainId and `verifyingContract` inside the
domain. Only the signature algorithm differs. That keeps every wallet's and
indexer's existing typed-data display code usable, and it keeps the replay
protections that the pattern is actually made of.

`spikes/pq-precompile/tests/permit_pattern.rs` is a faithful host model of that
contract — same digest bytes, same checks, same order, calling the same
`pq_verify` — because this repo has no `solc` and no EVM host (`bloch-euvm` is
the eUTXO predicate VM; revm is the state-model front's decision and is not a
dependency yet). It proves:

- a PQ signature grants the allowance and consumes the nonce;
- replay fails, wrong spender fails, wrong value fails, wrong deadline fails,
  expired fails — each with its control half;
- **a valid signature by the wrong signer fails** (the check that a bool return
  would have made easy to omit);
- the same permit does not work on another contract or another chain id;
- mutation: dropping the nonce from the struct hash makes one signature
  authorise forever, and the reference is asserted to differ;
- mutation: reusing EIP-2612's typehash string would let signatures cross
  between the two permit families.

What this does **not** prove is that `solc` emits the bytes the model assumes.
That is a wiring-wave gate (§9), not a claim made here.

---

## 7. What is not compatible — read this before integrating

### 7.1 `permitPQ` is not EIP-2612, and cannot be

EIP-2612 is `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`.
A 4,589-byte signature and a 3,749-byte public key do not fit in `(v, r, s)`.
The PQ function is therefore
`permitPQ(address,address,uint256,uint256,bytes,bytes)` — **a different
selector**. Every router, aggregator, and periphery contract that calls the
2612 selector reverts. Uniswap V2's `removeLiquidityWithPermit` passes
`(v, r, s)`: it will not work against a PQ token, ever.

The `DOMAIN_SEPARATOR` and the typed-data *shape* are compatible; the typehash
string is `PermitPQ(...)`, not `Permit(...)`, deliberately, so a signature can
never cross between the families.

A contract that redeploys unmodified `UniswapV2ERC20` bytecode on Bloch gets a
`permit` function **no Bloch wallet can ever satisfy** — a dead entry point, not
an error message. Supporting `permit` on the Postern DEX is a *source-level
fork* of `UniswapV2ERC20` and of the router paths that call it. Say so in the
DEX's own documentation.

### 7.2 The one thing everyone will want it for is the one thing it is worst at

The founder's framing was: does this decide whether the DEX works at L1 without
two transactions per swap? The byte arithmetic answers plainly, using this
chain's own numbers.

| Doing "approve then swap" | tx bytes | intrinsic gas | authorizations |
|---|---|---|---|
| Two transactions | 2 × 4,687 = **9,374** | 2 × 152,740 = 305,480 | 2 |
| One §6.1 transaction carrying a **call batch** | **4,687** | 152,740 | 1 |
| One transaction using `permitPQ` | 100 + 4,587 + (3,749 + 4,587) = **13,023** | 286,116 + 83,044 precompile = 369,160 | 2 |

*(4,687 B = ~100 B of §6.1 body + a 4,587 B enveloped signature, measured; intrinsic =
`TX_FLAT_GAS` + bytes·16 + `HYBRID_VERIFY_GAS`.)*

**A self-permit is worse than two transactions**, in bytes and in gas. The
reason is structural and applies to every PQ chain: the transaction already
carries one 4.6 KB signature, and the permit adds a *second* one plus a 3.7 KB
public key that a non-recoverable suite cannot avoid sending. EIP-2612 exists
because on Ethereum a signature is 65 bytes and an extra transaction is 21,000
gas; both halves of that trade invert here.

So the answer to "does the DEX need two transactions per swap" is **no — and
`permit` is not why**. The §6.1 call batch is: one signature, many calls, one
authorization. That is the sibling front's feature, and it is the thing the DEX
should be built on.

What the precompile is genuinely for is the case where **the signer is not the
sender**: sponsored / relayed transactions (someone else pays the gas), contract
wallets and multisigs, bridge and oracle validator sets, and charter checks.
There the signature has to travel inside calldata no matter what, and there is
no cheaper construction. That is a real and necessary capability. It is not a
throughput optimization, and no public document should imply it is.

### 7.3 The public key travels every time

The precompile is pure: it reads no state, so it cannot look a public key up by
address. Every call carries 3,749 bytes of public key. A variant that read the
account's stored key (§6.1 stores it on first authorization) would save those
bytes and is **explicitly not built here**: it would make the precompile
state-reading, break `STATICCALL` purity, and make gas depend on whether an
account exists — a data-dependent price, which §5.3 exists to forbid. If
someone wants it later it is a new index, a new spec, and its own review.

---

## 8. The boundary with §6.1 (the sibling front)

§6.2 depends on §6.1's envelope decisions. Stated as assumptions, so that a
change on that side fails loudly here instead of silently.

### 8.1 What this front assumes

1. **The wire format is bloch-crypto's envelope**, not staking's raw-plus-field
   form: 4-byte header (`B1 0C` ‖ `u16` LE suite) prepended to the body, for
   both public key and signature. The authorization spec §1.2 already picks the
   envelope for the EVM side; this front implements that choice.
2. **`SUITE_MLDSA65_FALCON1024` = `0x0001` only.** If §6.1 ever admits another
   suite for transactions, this precompile does **not** follow automatically —
   a new suite is a new price and therefore a new precompile index.
3. **Address derivation is `SHA3-256(enveloped pk)[..20]`**, identical to
   `address_from_pubkey`. This is the seam that must not drift: §6.1's `sender`
   field, the EVM account key, and this precompile's return value are all the
   same 20 bytes. If §6.1 adds a domain tag to the derivation, both change on
   the same flag day, and a shared constant plus a cross-crate test should pin
   it before either ships.
4. **Sizes**: `HYBRID_PK_BYTES` 3,745, `MLDSA65_SIG_BYTES` 3,309,
   `falcon1024::signature_bytes()` 1,462 max. These are read from the crates,
   not asserted independently.

### 8.2 What this front does **not** do, so §6.1 must

Transaction-level authorization. The `sender`/`sender_pk` rules, the
first-use-reveal-then-forbidden discipline, the nonce, the chain id, the
canonical signing root, and the intrinsic `HYBRID_VERIFY_GAS` charge are all
outside this precompile. The precompile is never on the path that authorizes a
transaction; it is only ever called *by contract code, during execution*.

### 8.3 The one cross-front safety property, and the hard dependency it creates

`msg32` is **opaque** to the precompile. It cannot tell a permit digest from a
transaction signing root. If those two digest spaces ever overlap, a signature
collected by a malicious contract could be replayed as a transaction that moves
the signer's funds. Nothing inside the precompile can prevent that.

Today they cannot overlap, for a structural reason worth protecting:

- §6.1's signing root is `SHA3-256(DS_EVM_TX ‖ canonical fields)` — FIPS-202.
- Contract digests are `keccak256(...)` — the EVM's native hash, a *different
  function*.

**Requirement on the sibling front:** keep the §6.1 signing root SHA3-based and
domain-tagged. If it moves to keccak256 for EVM-tooling familiarity, this
structural separation collapses and the two fronts must jointly define a tag
registry over one hash space before either ships. Pinned by
`a_contract_digest_can_never_be_a_transaction_signing_root`.

**Requirement on the wallet:** never blind-sign 32 opaque bytes. The signing
request must carry the structured fields; the wallet recomputes the digest
(hence `permitDigest` is `public view` on the contract) and displays what is
being authorized. This is the same rule EIP-712 exists to enforce, and it is
strictly more important on a chain where the same key also authorizes
consensus-relevant operations.

---

## 9. Activation posture

The discipline of this base, applied to this front:

1. **Inert until a flag day.** When (and only when) the EVM is wired, activation
   is a `PQ_PRECOMPILE_ACTIVATION_EPOCH` constant shipped at `u64::MAX`, in the
   shape `LEAKED_ROSTER_ACTIVATION_EPOCH` and `BLOCK_BYTES_V2_ACTIVATION_EPOCH`
   already use. Below it the precompile address is empty and a call to it is a
   plain call to an account with no code.
2. **The gate reads the epoch derived from the block**, never local state.
   This chain has already lost consensus once to a rule computed from mutable
   local state (2026-08-08): nodes with *identical binaries* diverged.
3. **Fleet rebuilt before the flag day, not after.**
4. **Not part of the SR-2 re-freeze.** The precompile adds no `StateRoots`
   component and no closed-list tag. It is inside the EVM component that
   `TAG_EVM_COMMITMENT` (0x09) already commits.

Gates that must close before any activation proposal:

- [ ] the wall-clock measurement repeated on the slowest fleet hardware, worst-case input
- [ ] the Solidity artifacts compiled with a pinned `solc` and the host model replaced by real EVM execution against the pinned revm version
- [ ] KATs: fixed `(pk, msg, sig)` vectors with their expected 32-byte outputs, byte-frozen, so an implementation change is caught
- [ ] a differential run of the precompile against `bloch_crypto::verify` over random and adversarial inputs, asserting they differ **only** on the three rules of §3
- [ ] the §6.1 address-derivation seam pinned by a shared constant and a cross-crate test (§8.1.3)

---

## 10. Running it

```
cd spikes/pq-precompile
cargo test --release              # framing, totality, gas, 4 mutation proofs, permit pattern
cargo run --release --bin pq-precompile-cost   # the §5.4 numbers, on this machine
```

Standalone workspace. It does not build the node, and the node does not build it.

---

## 11. Not decided here

- Whether the EVM comes to L1 at all, and when (ADR-040, founder).
- The §6.1 transaction type byte, signing root, and batch encoding.
- The withdrawal precompile's index inside the reserved block (state-model front).
- The `SHA3` opcode repricing question raised in §5.2 (fee-market owner).
- Anything in §6.3, §6.4, or §6.5 of the authorization spec. §6.5 is rejected
  there and stays rejected; §6.3 and §6.4 are deferred there and are not
  prepared for, prototyped, or advertised here.
