# ERA 1 — Pre-rebrand Post-Quantum Handshake on the GroundState Chain

> **Note (April 2026 rebrand).** This document is the factual record
> of an event that occurred on **2026-04-20T21:58:42Z** on the chain
> that operated under the GroundState project name (`grnd`). In
> April 2026 the codebase was rebranded to **Bloch-SIS Protocol
> (BLOCH)** and the chain was reset for genesis regeneration (Phase 6
> of the rebrand). The handshake described below happened on the
> predecessor chain — Era 1 in this project's history — not on the
> Bloch-SIS Protocol chain that will follow.
>
> The event is preserved here unmodified because the dates, peer IDs,
> hashes, addresses, Docker image tags, and log lines below are
> historical facts about the predecessor chain. They are not
> identifiers of the Bloch-SIS Protocol chain.
>
> **Nothing below describes any network that is running.** The GroundState
> chain was reset; the Bloch-SIS / Genesis-3 proof-of-work chain that
> followed it stopped permanently at height **39,918** on 2026-08-13. The
> live chain today is **Genesis-4, proof of stake** (30 s slots, 32-slot
> epochs, finality by epoch), live since 21:31:19 UTC on 2026-08-13. In
> particular: the closing line "The network is live" is about GroundState
> mainnet in April 2026, the `scan.groundstate.network` RPC endpoint and the
> `groundstate77/groundstate` image are not endpoints of anything current,
> and the mining commands will not connect you to a network. There is no
> mining on Genesis-4.
>
> Original document follows verbatim.

---

# First Post-Quantum P2P Handshake

**Date**: 2026-04-20T21:58:42Z
**Network**: GroundState mainnet (`grnd`)
**Genesis**: `0000000060cd9cd15e00707afa1f8fb56dec9df2668554b4efb3ef424fa2a37e`
**Version**: v0.5.14-sprintr

## What happened

At 21:58:42 UTC on 2026-04-20, two GroundState nodes completed a successful libp2p connection using the ML-KEM-768 (Kyber) hybrid post-quantum transport upgrade. This is, to our knowledge, the first production blockchain P2P connection established over a NIST FIPS 203 post-quantum key-encapsulation mechanism on an operational mainnet.

The handshake itself is cryptographically unremarkable — ML-KEM-768 is a standardized primitive with a published transcript protocol. What is novel is the integration context: a live blockchain network with consensus, mining, and gossipsub message propagation running over a PQ-secured transport layer, not a lab benchmark or protocol demo.

## The two endpoints

**Seed** (Njalla VPS, Debian 13)
- IP: `80.78.28.142`
- Peer ID: `12D3KooWQfXJzXRG7t4r1hQVHfijHsuMZ22ecAUD3YGhMvjvDbQp`
- Role: non-mining bootstrap node
- Resources: 1 vCPU, 1.4 GB RAM
- Chain state at connect: 28 blocks, blue_score 27

**Worker** (Akash decentralized cloud, node5)
- Peer ID: `12D3KooWBi3NofvexMdJxWuEidJp2j8jxRu1rnKDY7LG8S8cYwda`
- Role: active miner
- Resources: 40 CPU cores, 32 GB RAM
- Initial hashrate: 21–40 Mhash/s across 40 threads
- Mining address: `grnd1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45`

## Cryptographic stack

- **Key exchange**: ML-KEM-768 (NIST FIPS 203, previously known as CRYSTALS-Kyber)
- **Session encryption**: ChaCha20-Poly1305 (RFC 7539) with counter-derived 96-bit nonces
- **Key derivation**: HKDF-SHA256 over the Kyber shared secret
- **Peer identity / authentication**: libp2p Ed25519 signatures over the transcript. This is classical, not post-quantum — see "Hybrid model" below for the threat-model reasoning.
- **MITM binding**: SHA3-256 transcript hash covering version byte, Kyber public key, libp2p identity public key, and per-session nonce
- **Multiplexing**: yamux
- **Transport**: TCP (port 16110) and WebSocket (port 16111)
- **Implementation**: `pqcrypto-kyber = "0.8"` (Rust crate)

Transaction signatures on the chain use ML-DSA-65 (NIST FIPS 204, CRYSTALS-Dilithium variant). The signature path is end-to-end post-quantum; the transport path is hybrid as described above.

## Hybrid model

The transport is a *hybrid* design, not a fully post-quantum one:

| Property | Primitive | Post-quantum? |
| --- | --- | --- |
| Key exchange (confidentiality) | ML-KEM-768 | ✅ |
| Peer identity (authentication) | libp2p Ed25519 | ❌ classical |
| Session cipher | ChaCha20-Poly1305 | ❌ classical, but symmetric |
| Transcript binding | SHA3-256 | — |

This matches the TLS 1.3 hybrid pattern shipped by AWS, Cloudflare, and Google. It protects against **harvest-now-decrypt-later** attacks (ciphertext captured today cannot be decrypted by a future quantum adversary, because the session key comes from ML-KEM-768). It does **not** protect against active MITM by a future quantum adversary who can forge Ed25519 signatures to impersonate a peer on a new connection.

A fully-PQ identity path (ML-DSA peer identities) would require forking libp2p; the cost–benefit tradeoff currently favors the hybrid design, which is why it is presented as such here.

## Verifying the event

Log line from the worker stdout:

```
[2026-04-20T21:58:42Z INFO groundstate::network] ✓ connected: 12D3KooWQfXJzXRG7t4r1hQVHfijHsuMZ22ecAUD3YGhMvjvDbQp
```

Same event confirmed on the seed via `grnd-seed` container logs. The chain state is queryable:

```bash
curl -s -X POST https://scan.groundstate.network/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getnetworkinfo","id":1}'
```

## What we learned getting here

Reaching a successful PQ handshake on mainnet took roughly a month of iterative work. The path looked like this:

1. ML-KEM transport module drafted in v0.5.0, integrated into libp2p SwarmBuilder via `KyberConfig`
2. First deployment attempts on Akash failed because port forwarding via cluster proxy did not pass TCP bidirectionally — `Failed to negotiate transport protocol(s)` on every dial
3. Moved seed to dedicated VPS (Njalla) to get direct TCP
4. On 2026-04-20, diagnosed a self-dial loop: `DEFAULT_SEEDS` in `src/core/mod.rs` contained the seed's own multiaddr, so the seed was dialing itself and producing `Local peer ID` errors every 60 seconds that masked real peer traffic
5. Added Sprint R instrumentation to capture per-IP failure counts and exact libp2p error strings
6. Patched `src/network/mod.rs` to skip multiaddrs matching our own peer ID across three call sites (initial bootstrap, heartbeat reconnect, PEX)
7. Built `v0.5.14-sprintr` Docker image (Rust 1.86 base, ~45 min build)
8. Redeployed seed; several side issues surfaced in order: volume file permissions (fixed with `chown 1000:1000`), container entrypoint override (fixed by prepending `groundstate` to the `command:` array), and data-dir write permission on Akash (fixed by using `/tmp/grnd-data`)
9. Worker deployed, handshake completed, mining started

The dominant lesson: **observability paid for itself within minutes**. The Sprint R patch identified the self-dial bug in a single heartbeat cycle after weeks of symptom-chasing. Any future consensus or networking work should budget instrumentation up-front.

## Reproducibility

The exact binary that produced this handshake is published at:

```
docker pull groundstate77/groundstate:v0.5.14-sprintr
```

Source tree at commit `6a672b4` on branch `sprint-r-network-stability` in `Groundstate100/groundstate`. Build inputs: Rust 1.86-slim-bookworm, Debian 12 build-essential toolchain.

To reproduce a handshake against this seed:

```bash
docker run -d --name grnd-worker \
  -e RUST_LOG=info \
  groundstate77/groundstate:v0.5.14-sprintr \
  --mine \
  --miner-address YOUR_GRND_ADDRESS \
  --peer /ip4/80.78.28.142/tcp/16110/p2p/12D3KooWQfXJzXRG7t4r1hQVHfijHsuMZ22ecAUD3YGhMvjvDbQp \
  --data-dir /tmp/grnd-data \
  --listen /ip4/0.0.0.0/tcp/16110
```

A successful `✓ connected:` line in the container logs indicates a completed Kyber handshake.

## What this does not prove

- It does not prove ML-KEM-768 is breaking NIST-level security in production. It proves the protocol runs and the implementation is correct on the happy path.
- It does not prove the chain is secure against quantum attacks at the application layer; that depends on wallet-level signature choices and address formats.
- It does not prove resistance to side-channel attacks on the Kyber implementation. The `pqcrypto-kyber` crate uses reference code that has had side-channel patches (KyberSlash, late 2024) applied, but side-channel hardening remains an open area.
- It does not prove scalability. Two peers is not a network. Multi-peer propagation, chain reorg handling under PQ transport latency, and gossipsub mesh stability at scale all remain to be measured.

## What comes next

Short term, the chain needs more peers, RPC hardening for the public explorer at `scan.groundstate.network`, and a clean separation between `DEFAULT_SEEDS` (what workers should dial) and the seed's own bootstrap-skip list. The `sprint-r-network-stability` patches will be merged to `main` after a review round.

Medium term: persistent storage on worker nodes (`/tmp` is fine for validation, not for production), stratum mining protocol, and a signed binary release pipeline with reproducible builds.

The network is live. The genesis hash above is the canonical entry point for anyone who wants to join.

---

*This document is a factual record of a single event. Terms like "first" are scoped to the author's direct knowledge of the post-quantum blockchain space as of the date above. Prior or concurrent work by others may exist and is not disputed.*
