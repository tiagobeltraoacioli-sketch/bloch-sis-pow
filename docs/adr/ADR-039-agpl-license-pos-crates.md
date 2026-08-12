<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ADR-039 — PoS crates licensed AGPL-3.0-or-later

- **Status:** Accepted and applied (founder decision, 2026-08-11; commit
  `e268838`)
- **Resolves:** `BLOCH-POS-NODE-INTEGRATION.md` §8.4 (the license blocker)
- **Relates to:** `crates/bloch-crypto` (already AGPL-3.0-or-later),
  `crates/bloch-pos-committee`, `crates/bloch-pos-node`,
  `tools/genesis4-ceremony`

## Context

`bloch-crypto` is AGPL-3.0-or-later, and AGPL is viral: the moment the
Genesis-4 node links it for the hybrid PQ signature verify — which it must —
the whole `bloch-pos` binary inherits AGPL regardless of what the leaf
crates declare. The PoS crates had been created under `MIT OR Apache-2.0`,
which left the published license of the leaves contradicting the effective
license of the binary.

Two exits existed: re-extract the PQ verify surface into a permissive leaf
crate, or relicense the leaves to match the chain they link. The
node-integration plan carried this as blocker §8.4 because the answer
gated the M1 transaction-format decision (reusing `bloch-crypto`'s tx types
pulls the AGPL dependency into M1 instead of M2).

## Decision

1. **`bloch-pos-committee`, `bloch-pos-node` and `tools/genesis4-ceremony`
   are relicensed `MIT OR Apache-2.0` → `AGPL-3.0-or-later`** (45 SPDX
   headers + 3 `Cargo.toml`, commit `e268838`). One license across the whole
   dependency chain, the same license as the Genesis-3 node this binary
   succeeds. No permissive re-extraction of the PQ verify surface.
2. **New files in these trees carry
   `SPDX-License-Identifier: AGPL-3.0-or-later`** — headers on source and
   docs alike; this is the standing rule for the wave, not a one-off sweep.
3. **`bloch-sis-pow` deliberately stays `MIT OR Apache-2.0`.** It is the
   reference implementation of the PoW, published as a specification, and it
   dies with the Genesis-3 halt at the terminal height. Keeping it
   permissive is a separate, standing decision — not an omission and not
   dragged along by this one.

## Consequences

- **The obligation, stated plainly:** anyone who runs a *modified* Genesis-4
  node as a network service must publish their modifications (AGPL network
  clause). That reciprocity is the point of the choice, not a side effect.
- **§8.4 stops being a milestone blocker.** The M1 transaction-format
  decision can pull `bloch-crypto` in whenever the engineering says so; the
  license no longer distorts the dependency schedule.
- **Release verification:** A6 verifies that published release artifacts
  carry the recorded license.
- **Inbound contributions** to these crates are accepted under
  AGPL-3.0-or-later only; a contribution that cannot be is declined.
- Downstream embedders who wanted permissive PoS consensus code do not get
  it from these crates. If that demand ever materialises, the answer is a
  fresh permissive extraction decided on its own merits — not a quiet
  dual-licensing of files in this tree.
