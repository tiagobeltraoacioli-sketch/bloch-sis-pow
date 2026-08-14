# Bloch Developer Portal


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

> **SUPERSEDED FRAMING — written 2026-08-11.** These portal pages describe
> Genesis-3 as the live chain and predate three founder decisions: the
> **ownerless thesis was retracted** (ADR-036 — issuer + two-entity foundation,
> `docs/specs/BLOCH-ENTITY-STRUCTURE.md`); Genesis-3 halts and Genesis-4
> relaunches as PoS; and the base layer gains a **native EVM and the Ustav
> charter standard at L1** — so "no VM, no L2 model prescribed" stops being
> true at Genesis-4. The halt height named in the original of this note
> (80,000) was never reached: the rule was later lowered to 50,000 and the
> chain in fact stopped at **39,918** on 2026-08-13. Do not republish without
> the ADR-036 rewrite.

> A neutral commons, an agnostic base, an open ecosystem. Anyone can build on
> Bloch. Postern Labs is **one builder among many**, with **no special protocol
> access and no gatekeeping power**.

This portal is a builder-facing entry point to Bloch: what it exposes today, the
handful of RPC flows you actually need, and small reference apps you can fork.

---

## ⚠️ Read this before you build (binding honesty rails)

Building on Bloch **today is genuinely experimental**. None of the pages here
change that. In one place:

- **Unaudited mainnet-beta.** "Mainnet-beta" is a designation, not a security
  claim. A third-party audit is contracted but **not done**.
- **Relaxed PoW (k=4) applies today → proof-of-work is trivially forgeable.**
  The k=8 hardening was reverted (it stalled the low-hashrate chain) and
  re-activates only with a matched difficulty reduction. **Until then, no
  security is claimed.**
- **Nascent network: very few nodes, low hashrate → 51%-attackable.**
- **No live public testnet + faucet and no published SDK yet.** Those are
  *plans*, not shipped things. Where this portal mentions them, they are labelled
  **[planned]**.
- **Bloch is ownerless, neutral, and technology-agnostic.** Anyone can build
  anything on top. Postern's products (wallet, explorer, a designed finality
  gadget) are cited **only as examples**, never as the platform and never
  privileged.
- **BLCH is the neutral native gas token.** Its only role here is a protocol
  fact: it pays for on-chain activity (ETH-like at the protocol level, usable for
  development). **This is never a value or investment claim.** BLCH has no price
  and no value claim from anyone; on the current zero-security regime it is worth
  nothing by design. A **17% founder premine** (10-year cliff, 40-year vesting)
  is disclosed. **Do not build here because "the token will appreciate" — no one
  promises that it will.**

**Plans, not promises.** Every capability is tagged **[exists today]** or
**[planned]**. Do not read a *planned* item as shipped.

---

## Contents

1. **[Build your first Bloch app](01-build-your-first-bloch-app.md)** — connect to
   a node's JSON-RPC, read the chain, and understand the request/response shape
   (including the `result.error` quirk).
2. **[RPC cookbook](02-rpc-cookbook.md)** — copy-paste recipes for the top flows:
   read balance/UTXOs, validate an address, estimate a fee, build + broadcast a
   payment, and track confirmations.
3. **[What Bloch is / is NOT today](03-what-bloch-is-and-is-not.md)** — an honest
   inventory: UTXO + P2PKH, no VM, no scripting, anchoring is a pattern (not a
   first-class interface yet).
4. **[Anchoring quickstart](04-anchoring-quickstart.md)** — the "commit a
   compact commitment into a Bloch tx" pattern for L2s / finality gadgets /
   notaries, and where the ergonomic anchoring framework fits (**[planned]**).

## Reference apps

Small, self-contained, permissively-licensed apps live in
[`../../examples/`](../../examples/):

- `examples/balance-viewer/` — a minimal balance + UTXO viewer (single HTML file).
- `examples/block-explorer/` — a tiny block / transaction explorer view (single
  HTML file).
- `examples/payment-builder/` — a payment **preview/builder** demo that does coin
  selection and shows the unsigned transaction plan (Node script). Signing +
  broadcast is delegated to the reference signer (`bloch-wallet`), because Bloch
  transactions use hybrid post-quantum signatures that a browser cannot produce.

Every app carries its own honesty + license header and is labelled
**reference, untested against a live node**.

---

## The one-line surface

Bloch is an **ownerless, permissionless, technology-agnostic** post-quantum PoW
**UTXO** L1 with a **JSON-RPC** surface and **BLCH** as native gas — and **no VM,
no scripting, no smart contracts today.** Building on it today means
**RPC-integrated apps** and **externally-anchored systems**.

## License

All portal docs and reference apps are offered under **MIT OR Apache-2.0**
(permissive), matching the protocol. Adopt them freely, including commercially.
