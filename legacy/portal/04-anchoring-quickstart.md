# Anchoring quickstart (L2s / finality gadgets / notaries)


> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch),
> live since 21:31:19 UTC that day; its public read RPC is
> `https://posternlabs.com/g4rpc` and it exposes a different, much smaller
> method set than the one used below. Kept because Genesis-4's opening ledger is
> derived from Genesis-3. It is not what runs.
>
> **The risk disclosure below is superseded, not withdrawn.** "Small,
> low-hashrate, 51%-attackable" was Genesis-3's risk and was true of it. Under
> Genesis-4 the security question is concentration: **all 64 validators are run
> by one entity**, **93.94% of the carryover sits at a single address**, and
> **56.05 B of the 57.15 B BLOCH issued at genesis is held by the founder and
> the Foundation**. One operator can halt the chain and one holder can outvote
> every other. A third party cannot yet join: the transport is a point-to-point
> TCP full mesh with a fixed peer list, no discovery and no authentication, and
> `Deposit`/`Delegate` are refused at every node's mempool. "Ownerless" was
> retracted (ADR-036). Unaudited, not a security, no value claim: all still true.

> **SUPERSEDED FRAMING — 2026-08-11.** Genesis-3 page; the "ownerless"
> claims below were retracted (ADR-036, two-entity foundation), Genesis-3
> halts at height 80,000, and at Genesis-4 the base gains a native **EVM at
> L1** — external-L2 anchoring stays possible, but it is no longer the
> prescribed path for EVM workloads. See the note in [index](index.md).

> **Honesty rails (full text in [index](index.md)):** unaudited mainnet-beta;
> relaxed PoW (**k=4**) → work is **trivially forgeable**; small,
> **51%-attackable** network. Bloch is **ownerless / neutral / agnostic**;
> Postern is one builder, no privilege. **BLCH is neutral native gas — never a
> value/investment claim.**

If you're building an **L2, rollup, sidechain, state-channel hub, finality
gadget, or notary**, the way you use Bloch today is **anchoring**: you run your
**own** system and periodically **commit a compact commitment** — a state root,
checkpoint hash, or batch digest — into a Bloch transaction, paying the fee in
**BLCH**. Bloch's PoW then gives that commitment an **immutable ordering +
timestamp + anchor**.

> **Status: the pattern is possible today; ergonomic tooling is [planned].**
> There is **no first-class data-carrier / commitment output** and no
> retrieve/prove helper yet (see [What Bloch is / is NOT](03-what-bloch-is-and-is-not.md)).
> Doing this today is **crude and hand-rolled**. A clean anchoring/commitment
> interface, a checkpoint/anchor SDK, DA guidance, and a reference
> anchored-notary example are **[planned]** (roadmap §2.2 / Phase 3), and any
> consensus-level piece (e.g. a data-carrier output type) must go through a
> **GIP**.

---

## The one boundary that matters

> **Bloch settles nothing about your system's internal validity.** It provides
> **ordering, timestamp, and data-anchoring only.** Your L2's execution,
> validity rules, data availability (DA), and finality are **yours**. Bring your
> own architecture — Bloch stays agnostic underneath (Principle 0).

Bloch anchors **commitments, not bulk data.** Your DA lives somewhere else (your
own DA layer, an external DA network, etc.); the Bloch anchor only *references*
it. Decide where your data lives before you anchor.

## The pattern, end to end

1. **Compute a compact commitment.** e.g. `commitment = H(state_root ‖ epoch)`,
   a fixed-size digest. Keep it small — you're anchoring a fingerprint, not the
   data.
2. **Embed it in a Bloch transaction and pay in BLCH.** Because there is **no
   data-carrier output today**, this is the crude part: you must carry the
   commitment via a convention your own indexer understands (the ergonomic,
   consensus-blessed way is **[planned]**, potentially via a GIP). **Do not
   invent a scheme that bloats the UTXO set or that others can't verify** — wait
   for, or help design, the standard interface if you need interoperability.
3. **Broadcast** with `sendrawtransaction` (signed by `bloch-wallet` /
   `WalletCore` — see the [cookbook](02-rpc-cookbook.md#recipe-5--build--broadcast-a-payment)).
4. **Wait for depth.** Poll `gettxstatus [txid]`; choose a confirmation target
   for your checkpoint (`100+` = `final`). Remember the rails: under **k=4** on a
   low-hashrate network, this depth carries **no real security today**.
5. **Retrieve / prove later.** Read the anchoring transaction back by `txid`
   (`gettransaction`) or by block (`getblock` / `gettxsbyblock` /
   `getblockbyheight`) and check its inclusion. A dedicated **inclusion-proof
   helper is [planned]**; today you assemble this yourself from block reads.

```js
// Minimal, hand-rolled anchor confirmation loop (reference, untested).
// Assumes callRpc() from 01-build-your-first-bloch-app.md and that the tx
// carrying `commitment` was already built + signed by the reference signer.
async function anchorAndConfirm(signedRawHex, target = 100) {
  const { txid } = await callRpc(ENDPOINT, "sendrawtransaction", [signedRawHex]);
  for (;;) {
    const s = await callRpc(ENDPOINT, "gettxstatus", [txid]);
    if (s.confirmations >= target && s.status !== "pending") return { txid, status: s };
    await new Promise(r => setTimeout(r, 10_000));
  }
}
```

## "Build your own finality gadget" — a neutral ecosystem path **[planned]**

Anyone can build a finality layer over Bloch — **permissioned or
trust-minimized, your choice.** A bonded validator committee producing finality
certificates, a BFT overlay, an optimistic or ZK rollup's finality proof — all
are legitimate, and **none is reserved to anyone.**

**One example, among many — the anchoring framework to point at:** Postern's
designed finality gadget is a **permissioned, Postern-operated notary-checkpoint**
(individual **ML-DSA-65** attestations from a single-trust-domain signer set,
era rotation, anchored to Bloch) — a **"trust Postern" finality attestation.** It
is deliberately **NOT** BFT, **NOT** decentralized, **NOT** trust-minimized, and
carries **no economic security** (no bonded validator committee, no DKG, no
bonding/slashing) in this phase. It is **designed, not deployed**; it runs on the
**same public base every other builder has**; and it confers **Postern no special
protocol status.** A completely different finality gadget from a completely
different team — including a genuinely trust-minimized or decentralized one — is
equally first-class. Treat it as a **reference for the pattern**, not as "the"
framework — the ergonomic, reusable checkpoint/anchor SDK and reference
anchored-notary are still **[planned]**.

## RWA anchoring — read this first

RWA (real-world-asset) systems can use this same anchoring pattern (tokenized
registries, attestation of off-chain claims, settlement rails). But:

> **Your legal and regulatory responsibilities are yours.** RWA touches
> securities, custody, KYC/AML, and jurisdiction-specific law. Bloch is a
> **neutral base that dictates nothing** here and provides **no compliance
> layer**; the protocol does **not** KYC, freeze, or blacklist. Compliance, if
> any, is opt-in **at the edge**, by the builder/user — never enforced by
> consensus. **Each RWA builder owns their own legal exposure.**

## What's planned to make this ergonomic **[planned]**

- A **first-class anchoring / commitment interface** (a data-carrier output or
  commitment convention) plus RPC helpers to **retrieve and prove** anchored
  commitments by height/txid.
- A **checkpoint / anchor SDK**: submit-commitment, wait-for-N-confirmations,
  inclusion-proof helpers.
- **Data-availability guidance** for where your DA lives and how it references
  the Bloch anchor.
- An open, permissively-licensed **reference anchored-notary example** any
  L2/FFG/RWA builder can fork.

Until those land, anchoring works but is **do-it-yourself**. Plan accordingly —
plans, not promises.

---

*Ownerless base · plans not promises · unaudited mainnet-beta · BLCH not a
security. Each builder owns their own legal responsibilities, especially for
RWA. This page is offered under MIT OR Apache-2.0.*
