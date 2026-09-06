<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Postern Labs — products ⟂ protocol

**This file was referenced from five other documents
(`PRINCIPLES.md`, `docs/PROJECT-STATUS.md`, `docs/EVOLUTION.md`) but did not
exist in this repository until 2026-09-06.** It is created now, short and
factual, rather than leaving those references pointing at nothing.

## The boundary

Two distinct things share the "Bloch" name, and conflating them is the
recurring source of confusion this file exists to close:

- **The Bloch protocol** — the consensus rules and specification
  (`docs/specs/`). Anyone may implement it; the rules themselves have no
  owner. As of Genesis-4, governance of the *protocol's evolution* runs
  through Foundation-directed decisions and founder-controlled flag-day
  activations (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`;
  `PRINCIPLES.md`'s sealed header retracts the earlier "ownerless" framing
  — read that retraction before quoting principle 1 or 2 as current).
- **Postern Labs** — the company that builds and operates products on top
  of the protocol: the reference node implementation and OS images
  (`os/`), the wallet, the block explorer, the attestation tooling
  (`os/ATTESTATION.md`), and Postern Cloud (`os/cloud.nix`,
  `docs/specs/POSTERN-CLOUD.md`). Postern Labs is **one builder among
  others could in principle be** — the protocol's open specification does
  not require any product to be Postern-branded — but in practice, as of
  this writing, Postern Labs operates the genesis validator fleet and the
  products most users interact with.

## What this means in practice, stated plainly

- A finding about the **protocol** (a consensus rule, a wire format, an
  activation gate) is in scope for `SECURITY.md`'s protocol-and-node
  sections regardless of which company or individual runs the node that
  exhibits it.
- A finding about a **Postern Labs product** (the wallet's key handling,
  the explorer's RPC failover, Postern Cloud's attestation flow) is a
  product-security question for Postern Labs specifically, not a claim
  about the protocol's neutrality.
- Neither layer's problems are the other layer's alibi: a protocol defect
  is not excused by "that's just how Postern built it," and a Postern
  product defect is not excused by "the protocol itself is fine."

## What this file is not

It is not a corporate "about us" page, a governance charter, or a roadmap.
Those belong in `PRINCIPLES.md`, the ADRs under `docs/adr/`, and
`ROADMAP.md` respectively — this file's only job is to say what "Postern
Labs" refers to when another document points here, and to do so honestly
given the 2026-08/09 governance retractions rather than repeat the
"ownerless commons" language that predates them.
