# bloch-anchoring

**A reference L2 / anchoring & commitment framework for Bloch.**
A historical Genesis-3-shaped scaffold: submit a commitment in the offline
model, query RPC depth and retrieve carrier data by height or txid. This is not
a Genesis-4 consensus codec, authenticated inclusion proof or finality verifier. Fork it to build an L2, a finality gadget (FFG), a notary, or
an RWA anchoring system.

> Roadmap reference: **§2.2 (anchored systems)**, **§1.2/1.3 (JSON-RPC, UTXO,
> P2PKH, `sendrawtransaction`)**. This crate is the Phase-3 "L2 / anchoring
> framework" scaffold.

---

## ⚠️ Status — binding honesty rails

- **SCAFFOLD / reference implementation. Unaudited. Pre-production.** Do not ship
  this to mainnet value without your own review and hardening.
- **Bloch is ownerless, neutral, and agnostic.** Anyone can build L2s, finality
  gadgets, and RWA systems on it. **No category is reserved to anyone**, and
  **Postern Labs holds no protocol privilege** — it is one builder among many.
- **The model is historical.** This scaffold models Genesis-3 PoW interfaces.
  Its depth labels do not implement Genesis-4 validator finality. RPC counts
  remain unverified assertions, even when they satisfy a caller's policy.
- **BLCH is neutral gas — not a security, with no value claim from anyone.** It
  pays fees; that is its only role here.
- **RWA builders own their own legal and regulatory responsibility** (securities,
  custody, KYC/AML, jurisdiction). Bloch provides **no compliance layer** and
  does not KYC, freeze, or blacklist. Compliance, if any, is opt-in at your edge.

License: **MIT OR Apache-2.0** (permissive, matching the protocol).

---

## The pattern

```
  your system (L2 / FFG / notary / RWA)         Bloch L1 (PoW UTXO)
  ───────────────────────────────────           ──────────────────
  runs execution, keeps its own DA               orders + timestamps
  computes a 32-byte commitment      ──anchor──▶ the commitment, and
  (state root / checkpoint / batch)              gives it PoW-depth
  proves inclusion later             ◀─retrieve─ immutability. Nothing
                                                 more.
```

1. **Commit.** Compute a fixed 32-byte [`Commitment`] over your current state.
2. **Anchor.** `submit_commitment` builds a Bloch tx embedding the commitment
   and broadcasts it via `sendrawtransaction` (you pay BLCH fees).
3. **Confirm.** `wait_for_confirmations` polls `gettxstatus`/`getblockcount`
   until the tx is buried `N` blocks deep (`0` = mempool, `1..=99` = confirmed,
   `100+` = final — PoW depth, no BFT).
4. **Prove.** `prove_by_txid` / `prove_by_height` retrieve the tx via
   `gettransaction`, recover the commitment straight off the outputs, and return
   an **inclusion reference**.

```rust
use bloch_anchoring::rpc::{BlochRpc, MockTransport};
use bloch_anchoring::{AnchorClient, Anchoring, Commitment, MockSigner, WaitPolicy};

let client = AnchorClient::new(BlochRpc::new(MockTransport::new(1000)), MockSigner::default());
let commitment = Commitment::hash_payload(b"my L2 state root");
let anchor = client.submit_commitment(&commitment).unwrap();
let reference = client.prove_by_txid(&anchor.txid).unwrap();
assert_eq!(reference.commitment, commitment);
```

Full runnable version: `cargo run --example anchored_notary`.

---

## "Bloch settles nothing about your validity" — the boundary

Bloch's contribution is exactly three things: an **ordering**, a **timestamp**,
and an **anchor** (immutability under PoW depth). It makes **no statement about
whether your L2's state transition was valid, whether your batch is available,
or whether your finality rule was followed.** Those are yours.

If you anchor a commitment to an invalid state, Bloch will happily order and
timestamp it. The anchor proves *"this digest existed at this height"* — never
*"this digest is correct."* Validity, fraud proofs, validity proofs, and
challenge games all live in **your** system.

## Agnostic by design — bring your own architecture

Bloch prescribes nothing above the base layer (Principle 0). This framework is
deliberately unopinionated:

- **Any L2 model** — rollup (optimistic or ZK), sidechain, state channel,
  anchored notary, finality gadget. The `Anchoring` trait doesn't care.
- **Any VM / execution** — EVM, WASM, Move, custom, or none. Off-base, yours.
- **Your DA is yours.** See below.
- **Your signing is yours.** The SDK builds the anchor's carrier outputs and
  hands them to a [`TxSigner`] you provide; in production that wraps
  `bloch-crypto`'s `WalletCore` (coin selection + hybrid Falcon-1024 ‖ ML-DSA-65
  signing). The included `MockSigner` is for the offline example only.

## The data-availability boundary

**Bloch anchors *commitments*, not bulk data.** A Bloch transaction is a tiny
UTXO tx, not a data blob store. Your blocks, batches, and proofs must live in
**your own DA**:

- your L2's own DA layer,
- an external DA network,
- content-addressed storage (IPFS/S3/…), referenced by the anchored digest,
- a validity-proof system where DA is implied by the proof.

The anchored 32-byte commitment is the *link* between Bloch's ordered timeline
and your off-chain data. Anyone with your data can recompute the commitment and
check it against the on-chain anchor (the example does exactly this).

---

## How the commitment is embedded today (and the honest limitation)

The historical reference model has **no data-carrier / `OP_RETURN` output or script system**
(roadmap §1.6). The only output form is a **fixed 20-byte P2PKH**
`script_pubkey = SHA3-256(pubkey)[..20]` (§1.3). There is no opcode to mark
bytes as data.

So this reference uses a **convention over existing primitives** (see
`src/convention.rs`, "Bloch Anchor v1"): it writes the 32-byte commitment into
the 20-byte `script_pubkey` fields of **two P2PKH-shaped "burn"
outputs**:

```
carrier[0].script_pubkey = MAGIC("BLA1") ‖ commitment[0..16]      (4 + 16 = 20)
carrier[1].script_pubkey = commitment[16..32] ‖ ZERO_PAD(4)       (16 + 4 = 20)
```

A reader recovers the commitment by scanning outputs for the magic prefix and
reassembling the bytes — **no script execution required**. Each carrier is
funded with 1 sat of dust that is **economically burned** (no keypair is known
for these hashes).

**This convention has real costs, by design of today's base:**

- it **burns dust** per anchor,
- it **bloats the UTXO set** with unspendable outputs,
- it **overloads the P2PKH address space** for a non-payment purpose,
- it caps neatly at 32 bytes across 2 outputs (more data → more burn outputs).

### What a future data-carrier GIP would add

A **first-class data-carrier / commitment output** is a **future GIP** (roadmap
§1.6, §2.2 — "not a first-class interface today"). Introduced through the
GIP/RFC process with node-operator signaling — **a neutral community proposal,
not a Postern decision** — it would let you:

- anchor a full 32-byte (or larger) commitment in **one explicit output**,
- **without burning value** and **without UTXO-set bloat** (prunable / clearly
  non-spendable by construction),
- with an **unambiguous "this is data, not a spend" marker** (no address-space
  overloading, no magic-prefix heuristic),
- optionally with a **`getmerkleproof`-style read** enabling compact SPV
  inclusion proofs against the block tx-root.

Until then, the burn convention here is the pragmatic path, and this crate is
structured so that only `src/convention.rs` changes when the GIP lands.

### Inclusion *reference*, not full SPV proof

Today's RPC (§1.2) lets you retrieve a tx and confirm its block + depth, but does
**not** expose a Merkle branch. So `InclusionReference` proves: a tx with this
txid exists, is mined at this height, its outputs decode to *this* commitment,
and it is buried *N* deep. A compact Merkle-inclusion proof is the natural
addition once a `getmerkleproof` RPC (or the data-carrier GIP) lands.

---

## Layout

```
src/commitment.rs  — Commitment (32-byte digest): from bytes/hex/hash_payload
src/anchor.rs      — Txid, Anchor, Finality (PoW-depth), InclusionReference
src/convention.rs  — the "Bloch Anchor v1" P2PKH-burn embedding (encode/decode)
src/tx.rs          — minimal self-contained UTXO tx codec (round-trips outputs)
src/rpc.rs         — RpcTransport trait, typed BlochRpc, in-memory MockTransport
src/sdk.rs         — Anchoring trait, AnchorClient, TxSigner, MockSigner
src/http.rs        — real ureq JSON-RPC transport (feature = "http")
examples/anchored_notary.rs — end-to-end reference to fork
```

## Build & test

```sh
cargo build                 # offline, default (trait + mock transport)
cargo test                  # unit tests for commitment/convention/tx/rpc/sdk
cargo run --example anchored_notary
cargo build --features http # adds the real ureq transport (needs network to USE)
```

The default build **depends on nothing from the Bloch node** and does not touch
the network, so it compiles offline. A live integration enables `http` and swaps
`MockSigner` for a `bloch-crypto` `WalletCore`-backed signer that emits the exact
consensus wire bytes.

---

## Design notes for forkers

- **This crate is standalone on purpose** — not a member of the root Bloch
  workspace. Copy it, vendor it, or depend on it directly; it won't drag in the
  node.
- **The `RpcTransport` seam** means you can back it with `ureq`, `reqwest`, a
  connection pool, a retrying/multiplexed client, or a mock — your choice.
- **The `TxSigner` seam** keeps coin selection, fees, and hybrid PQ signing in
  your wallet, where they belong.
- **Only `convention.rs` is coupled to today's P2PKH-only base.** When a
  data-carrier GIP ships, re-implement `encode`/`decode` there and the rest of
  the framework is unchanged.

---

*Ownerless base · plans not promises · unaudited mainnet-beta · BLCH not a
security. Postern Labs is one builder among many and holds no protocol
privilege. Each builder owns their own legal responsibilities, especially for
RWA.*


## Internal audit transport and decoding hardening (2026-09-17)

The optional HTTP transport uses a 5-second connect deadline, 10-second read
and write deadlines, and a 15-second overall deadline. Responses are capped at
1 MiB. API keys require HTTPS, embedded URL credentials are refused, and
redirects are disabled so credentials cannot follow an endpoint redirect.
Unauthenticated local HTTP remains supported. JSON-RPC responses must echo the
numeric request ID and version `2.0`; envelopes mixing a result with an error
are refused.

The reference carrier decoder now requires zero reserved padding and rejects
transactions containing multiple valid carrier pairs instead of selecting the
first. These checks do not provide signer binding or turn this scaffold's
transaction codec into a supported current-node transaction format. The
framework remains pre-production and requires separate integration work.

## Strict reference parsing and caller policy (BV-21 follow-up)

The mock transaction decoder now rejects trailing bytes, nonminimal/overflowing
LEB128 encodings, impossible input/output counts and platform-truncated lengths.
Valid reference serialization is unchanged. This does not make its LEB128 codec
compatible with consensus transaction bytes.

`BlochRpc::get_transaction_outputs_only` requires an explicit decoded output
array and refuses raw-hex-only responses. The existing `get_transaction` retains
its historical mock-codec fallback for reference compatibility; do not use that
fallback as a production transaction decoder.

`AnchorClient::reference_matching_policy(txid, expected, minimum_height,
minimum_confirmations)` uses the outputs-only reader, checks the expected
commitment, requires a mined height at or above the caller's cutoff, and requires
a positive confirmation threshold. It queries again on each invocation. This
limits accidental reuse of the wrong or older reference; it does not establish
wall-clock freshness, signer identity, honest RPC responses, selected-chain
membership or cryptographic inclusion. A subsequent reorg can invalidate the
returned observation. Existing `prove_by_*` methods remain inclusion references,
not proofs. The carrier convention does not prove that its outputs are unspendable.
BV-21 remains partial pending authenticated signer/chain integration and a real
consensus transaction codec.
