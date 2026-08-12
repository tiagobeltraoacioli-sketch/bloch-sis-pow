# What Bloch is / is NOT today

> **SUPERSEDED FRAMING — 2026-08-11.** Genesis-3 page. Three claims below are
> retracted: **"ownerless"** (ADR-036 — issuer + two-entity foundation);
> **"prescribes no VM, no L2 model"** (founder decision: native **EVM at L1**,
> no rollup, and **Ustav as a consensus object**); and the permanence of PoW
> (Genesis-3 halts at height 80,000; Genesis-4 is PoS). See
> [index](index.md).

> **Honesty rails (full text in [index](index.md)):** unaudited mainnet-beta;
> relaxed PoW (**k=4**) → work is **trivially forgeable**; small,
> **51%-attackable** network. Bloch is **ownerless / neutral / agnostic**;
> Postern is one builder, no privilege. **BLCH is neutral native gas — never a
> value/investment claim.**

This page exists so you don't design against capabilities that aren't there. It
is written from reading the source, not from assuming an EVM/smart-contract
platform.

---

## What Bloch IS today **[exists today]**

Bloch is a **post-quantum, pure-PoW UTXO BlockDAG L1 with a JSON-RPC surface**.
Concretely:

- **A UTXO chain**, Bitcoin/Kaspa-like — **not** an account/EVM model. You
  select unspent outputs, build a transaction, sign, and broadcast.
- **Fixed P2PKH outputs.** `script_pubkey` is just the 20-byte
  `SHA3-256(pubkey)[..20]`.
- **Post-quantum signatures.** `script_sig` is a hybrid **Falcon-1024 ‖
  ML-DSA-65** signature + pubkey; both lattice families must verify.
  `SIGHASH_ALL`; the `txid` excludes `script_sig` (non-malleable).
- **~35 JSON-RPC methods** over a single `POST /` endpoint (port `16210`) — the
  entire public developer surface.
- **PoW-depth finality.** `0` = mempool, `1–99` = confirmed, `100+` = final. No
  BFT, no validator set.
- **A native gas token, BLCH.** Integer satoshis are the truth
  (`1 BLOCH = 1e8 sat`). BLCH pays for on-chain activity — a neutral protocol
  fact, **never a value claim**.
- **A reference wallet core** (`WalletCore`) that does mnemonic → keypair →
  address, hybrid signing, and RPC shaping; byte-compatible with the node, with
  UniFFI Kotlin/Swift bindings.

**What you can build with this today:** wallets, payment apps / point-of-sale,
explorers, indexers, analytics dashboards, merchant tools — and
**externally-anchored systems** (see the [anchoring
quickstart](04-anchoring-quickstart.md)).

## What Bloch is NOT today — said plainly

| Capability | Reality today |
|---|---|
| **Smart-contract VM** (EVM / WASM / Move / …) | **Absent.** No VM, no bytecode, no on-chain programmability. |
| **On-chain scripting language** | **Absent.** Strictly single-signature P2PKH — no script interpreter, no opcodes. |
| **k-of-n multisig on-chain** | **Absent.** The ~10 KB `script_sig` cap can't even hold a second hybrid co-signer; multisig would need a consensus change (proposed as **GIP-008**, **[planned]**). |
| **A first-class data-carrier / anchor output** | **Not a first-class interface today.** Anchoring is a *pattern* you can do crudely; an ergonomic anchoring interface is **[planned]** (see §2.2 of the roadmap). |
| **Public testnet + faucet** | **Not deployed. [planned]** |
| **Published client SDK / indexer service** | **Not published.** OpenAPI spec exists; SDKs are generated-but-unwrapped. **[planned]** |
| **Live, proven multi-node network** | **Not proven.** Today it is effectively a low-node demo. |
| **Private (shielded) transactions** | **Latent stub, NOT live.** The privacy design (Coherence) is scaffold only — the node-side verifier is a reject-all stub, so shielded txs never apply. **Do not treat private transactions as available.** |

## What this means for how you design

- **No contracts on the base.** Rich programmability lives **off-base** — in
  your app, or in an L2 that anchors to Bloch. Bloch stays agnostic underneath
  (it prescribes no VM, no L2 model, no DA/settlement approach).
- **No multisig, timelocks, or covenants on-chain yet.** If your product needs
  them, they don't exist today; the nearest concrete proposal is **GIP-008**
  (k-of-n hybrid-signature descriptor outputs — a constrained predicate, not a
  VM), and it must go through the neutral **GIP process** with node-operator
  signaling. It is a **community proposal, not a Postern decision.**
- **Anchoring is a pattern, not an API.** You *can* commit a compact commitment
  into a transaction today, but there is no clean data-carrier output and no
  retrieve/prove helper yet — those are **[planned]**.
- **Don't rely on confirmations as settlement.** Under **k=4** on a low-hashrate
  network, even 100+ confirmations carry **no real security today**.

## The neutrality frame (why "not today" isn't "never, decided by Postern")

Bloch is **ownerless and permissionless**. Missing capabilities are not
Postern's to grant or withhold: **anyone can build** apps, L2s, finality
gadgets, RWA systems, and — via community proposal through the GIP/RFC process —
even an execution layer. Postern's own products (a wallet, an explorer, a
designed finality gadget, a designed RWA module) are cited across these docs
**only as examples of what a builder can do**; they are **not the platform, not
privileged, and carry no special protocol access.** A different team's
equivalent is equally first-class. **Each builder owns their own legal and
regulatory responsibilities** — this matters especially for RWA and anything
touching securities, payments, or custody.

---

*Ownerless base · plans not promises · unaudited mainnet-beta · BLCH not a
security. This page is offered under MIT OR Apache-2.0.*
