<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# RETIRED — this described the Genesis-1 proof-of-work node on Fly.io

> **If you are trying to stand up a node that follows the live chain, this is
> the wrong document. Use [`deploy/OBSERVER-NODE.md`](../OBSERVER-NODE.md).**

The guide that used to live here deployed the original Bloch-SIS
**proof-of-work** node (`bloch`, `--mine`, P2P on 16110, RPC on 16210) to
Fly.io, and its endpoint examples were fill-in templates — most notoriously

    /ip4/<dedicated-ipv4>/tcp/16110/p2p/<peer-id>

which was never a dialable value, only a shape. A partner lost real time to
that ambiguity, which is why this file now says so instead of carrying the
template forward.

None of it applies anymore:

- The live chain is **Genesis-4, proof of stake**. Its binary is `bloch-pos`
  (`bloch-pos-node 0.1.0-mainnet`); there is no `--mine` and nothing to
  scale CPUs for. Ports follow the `19000+N` (P2P) / `16400+N` (RPC) fleet
  convention, not 16110/16210.
- The Genesis-1/3 PoW chains this document deployed nodes for are
  terminated (Genesis-3 ended at height 39,918 on 2026-08-13).
- The project's own Fly fleet was decommissioned on 2026-08-23; Fly is not
  part of the current topology and no Fly-specific instructions are
  maintained.

Nothing stops you from running a Genesis-4 **observer** node on Fly or any
other host you control — the requirements are ordinary (one always-on Linux
VM, a persistent volume for `--data-dir`, outbound TCP). The prerequisites,
flags, artifacts, port rules, and chain-verification steps are all in
[`deploy/OBSERVER-NODE.md`](../OBSERVER-NODE.md), and they are
platform-neutral on purpose.
