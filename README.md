# Bloch Protocol

> A post-quantum Layer 1. Hybrid lattice signatures on every consensus path.
> Running proof of work today; proof of stake next.

**About the repository name.** The project is **Bloch Protocol**. The
repositories are called `bloch-sis-pow` (GitHub) and `BlochSISPoW-project`
(GitLab) because that is what the project was called when they were created,
and those URLs are published. The names are historical; they are not being
changed. If you cloned one of these, you are in the right place.

- GitHub: <https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow>
- GitLab: <https://gitlab.com/blochsispow-group/BlochSISPoW-project>

---

## Read this first if you want to run a node on the live chain

The trunk of this repository is the **proof-of-stake** work. The chain that
is live right now is **Genesis-3**, which is proof of work, and it is **not
what the trunk builds**.

Genesis-3 halts by consensus rule at a terminal height, days away at the time
of writing. To join it for the time it has left:

- **Run a published binary** — see [Prebuilt binaries](#prebuilt-binaries)
  below. This is the shortest path and it is what the fleet runs.
- **Or build from a Genesis-3 branch**, not from the trunk. `g3-integration`
  is the Genesis-3 source line. Note before you use it: as of its last commit
  (2026-08-09) it does **not** carry the terminal-height rule — the constant
  `GENESIS3_TERMINAL_HEIGHT` does not exist on it, so a node built from it
  would keep going past the terminal height and fork off the network. The
  branch that carries the rule is **`deploy/g3-terminal-50000`**, which is
  what the fleet builds from. If in doubt, run the published binary.

You will also need a datadir snapshot and the carryover file; a from-zero
sync cannot complete (see [docs/SNAPSHOT-BOOTSTRAP.md](./docs/SNAPSHOT-BOOTSTRAP.md)
and [docs/CARRYOVER.md](./docs/CARRYOVER.md)).

There is nothing to run on Genesis-4 yet. The proof-of-stake node is a devnet
binary, not released software, and there is **no Genesis-4 launch date**.

---

## What Bloch is

A Layer 1 whose consensus-critical cryptography is post-quantum end to end:

| Layer | What it uses | Cost of that choice |
| --- | --- | --- |
| Signatures | **Hybrid ML-DSA-65 ‖ Falcon-1024** — both must verify (`SUITE_MLDSA65_FALCON1024 = 0x0001`) | ~4.6 KB per signature, not recoverable from the message, and no hardware wallet implements it. MetaMask, Ledger and Trezor cannot sign a Bloch transaction. |
| Hashing | SHAKE-256 / SHA-3 with domain separation | Slower than SHA-2 on hardware built for Bitcoin. |
| Transport | ML-KEM-768 hybrid + ChaCha20-Poly1305 | Peer identity is hybrid; the underlying libp2p identity remains classical Ed25519. |
| Shielded pool | SHAKE-256 commitments and nullifiers, SP1 raw FRI-STARK, no elliptic-curve ZK | Proofs are large and proving is expensive. The mainnet pool is provably empty — nothing has ever been shielded. |

The trade the project makes is explicit: it gives up the entire existing
wallet and tooling ecosystem in exchange for not having a quantum-vulnerable
authorisation path. Every design question downstream of that — including
whether to run an EVM at L1 — reopens the same trade.

**The coin is not a security and not an asset.** No token sale, no listing,
no price, no value claim. Supply is heavily concentrated: the founder holds
roughly 94% of the carried-over balance, which is stakeable, so a naive
Nakamoto coefficient is 1. Bounding mechanisms exist and are documented with
what they do *not* reach — see `docs/audit/CERTIK-CENTRALIZATION.md` and
`docs/specs/BLOCH-TOKENOMICS-V4.md` §4A. There is no framing that makes this
number acceptable, and none is attempted here.

**Unaudited.** A third-party audit is being prepared for, not completed. The
pre-audit dossier is in `docs/audit/`.

## Consensus today: Genesis-3, proof of work — ending

Chain id `0xB10C_0004`, launched 2026-07-29 as a carryover restart.
SHA-256d proof of work over a GhostDAG-Q BlockDAG, ~30 s target, Stratum V1
for ASICs, merged-mineable with Bitcoin via AuxPoW since local height 8,500.

It ends. Not by an operator stopping it — by a consensus rule: above the
terminal height every node rejects every block, so the chain has no valid
successor and stops producing. The signed snapshot for Genesis-4 is taken at
that height.

**The terminal height is 50,000** (founder decision, 2026-08-12, lowered from
80,000). Be aware of a real discrepancy while reading this tree:

- the deployed fleet builds from branch `deploy/g3-terminal-50000`, where
  `crates/bloch-crypto/src/core/mod.rs` sets `GENESIS3_TERMINAL_HEIGHT =
  50_000`;
- on this branch the same constant still reads `80_000`
  (`crates/bloch-crypto/src/core/mod.rs:438`), and a number of documents in
  `docs/` and `legacy/` still say 80,000.

The constant on the branch the fleet runs is what governs the chain. Do not
take 80,000 from this tree as current.

Everything specific to this era — mining, GhostDAG, AuxPoW, stratum,
difficulty retargeting, tokenomics V1/V2/V3 — is in [`legacy/`](./legacy/),
with [`legacy/README.md`](./legacy/README.md) explaining what in it remains
true and what does not.

## Consensus next: Genesis-4, proof of stake — not launched

A **linear** chain of slots and epochs. GhostDAG is retired. Fork choice is
LMD-GHOST; finality is Casper-style FFG over an epoch committee; the
randomness beacon is RANDAO; signatures stay ML-DSA-65 ‖ Falcon-1024, with no
BLS anywhere. Design of record:
`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`.

Governance is **not** ownerless. That thesis was retracted in writing
(`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`) in favour of a
two-entity foundation structure. The founder allocates the genesis validator
cohort and is bound by a consensus rule taking that cohort under one third
within a year. This is a weaker decentralisation claim than the project made
earlier, and it is the true one.

Supply is fixed at `TOTAL_SUPPLY_BLOCH` in
`crates/bloch-pos-committee/src/tokenomics_v4.rs` — read the constant; do not
trust a supply number written in prose, including in this file. The cap is
intended to become a consensus invariant every node checks. The honest
strength of that claim: no mechanism *inside* the protocol can raise it — no
vote, no key, no governance path. A hard fork adopted by every operator can
change any rule, so "impossible to change" would be false.

### designed ≠ built ≠ booted

| Component | Designed | Built | Booted |
| --- | --- | --- | --- |
| Genesis-3 PoW node (`src/`, root package) | yes | yes | **yes — mainnet, until the terminal height** |
| AuxPoW merged mining with Bitcoin | yes | yes | yes — since local height 8,500 |
| eUTXO VM (`crates/bloch-euvm`) | yes | yes | yes — consensus-wired at Genesis-3 height 0 |
| Coherence shielded pool (C1 frozen) | yes | verifier present | never used; the mainnet pool is provably empty |
| PoS consensus core (`crates/bloch-pos-committee`) | yes | yes — 348 tests green, measured 2026-08-12 | no — unaudited, not wired into the Genesis-3 node |
| PoS node (`crates/bloch-pos-node`) | yes | partial — M1/M2 | **devnet only**: real processes producing, attesting, justifying and finalising over a local TCP mesh. Not mainnet-ready. |
| Tokenomics V4 | yes | constants + const-asserts in the crate | no — nothing has been issued under it |
| Weak-subjectivity checkpoints | yes | no | no |
| EVM at L1 | proposal; direction accepted (`docs/adr/ADR-040-evm-and-ustav-at-l1.md`) | **no code exists** — the authorization model is an open founder decision | no |
| Ustav (PSTRN-1) charter at L1 | proposal | no — nothing wired | no |
| Third-party audit | scoped | pre-audit dossier written | **not performed** |

## Where things are

```
src/, crates/bloch-crypto, crates/bloch-sis-pow, crates/bloch-euvm, …
                            the Genesis-3 node and its crates. Live on
                            mainnet until the terminal height.
crates/bloch-pos-committee  PoS consensus core. Standalone workspace —
                            run cargo from inside the crate.
crates/bloch-pos-node       Genesis-4 node binary. Standalone workspace, devnet.
tools/genesis4-ceremony     Genesis-4 launch tooling.
docs/                       Current documentation. Index: docs/README.md
docs/specs/                 Normative PoS design.
docs/adr/                   Decision records, including superseded ones.
docs/audit/                 Pre-audit dossier and the two Era-1 audits.
legacy/                     The Genesis-3 record. See legacy/README.md
gips/                       The GIP process (GIP-0001, editors, template).
```

`bloch-pos-committee` and `bloch-pos-node` are deliberately **not** members of
the root workspace. Nothing in the proof-of-stake work can enter the
Genesis-3 build graph, its lockfile, or its binary.

## Build

```bash
cargo build --release        # needs a C toolchain (clang/cmake) for rocksdb
```

This builds the Genesis-3 node and its crates. Binaries land in
`target/release/`: `bloch` (node), `bloch-cli`, `bloch-calibrate`, and
`bloch-wallet` (which needs `--features bloch-crypto/wallet-cli`).

The proof-of-stake crates are separate workspaces and are not built by the
above:

```bash
cargo build --release --manifest-path crates/bloch-pos-node/Cargo.toml
```

## Test

```bash
cargo test                                        # Genesis-3 node workspace
cd crates/bloch-pos-committee && cargo test       # PoS consensus core
cd crates/bloch-pos-node      && cargo test       # PoS node
```

The PoS crates each declare their own `[workspace]`, so `cargo test` from the
repository root does **not** reach them. Run them from inside the crate.

## Prebuilt binaries

Building from source is the recommended path — you run the bytes you
compiled, and the build is reproducible by design (see [REPRO.md](./REPRO.md)).
The binaries below are a convenience, not the standard.

Prebuilt `bloch` and `bloch-cli` for **Linux x86_64**. The current release is
`genesis3-node-terminal-50000-20260812`:

- GitHub releases: <https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases>
- GitLab releases: <https://gitlab.com/blochsispow-group/BlochSISPoW-project/-/releases>
- Mirror: <https://posternlabs.com> — serves the same `bloch` and `bloch-cli`

**Requires glibc ≥ 2.39** (Ubuntu 24.04 or newer). On older distributions,
build from source. Verify `SHA256SUMS` before running anything.

**Take the latest non-superseded release.** Genesis-3 consensus flag-days
make an older build diverge, not merely lag: the Emission V3 flag-day at
local height 40,000 cut the block reward, and a binary built before that
change forks off the network at that height rather than following it. Every
release before `genesis3-node-terminal-50000-20260812` is tagged
`[SUPERSEDED]` in the release list for that reason — including
`genesis3-node-linux-20260805`, which predates five consensus flag-days.

**If you are running a node through the halt, this release is mandatory.**
It is the first published binary that stops at 50,000; everything older still
carries 80,000, keeps accepting blocks past the terminal height, and forks
away from the network at the moment of the halt. The `bloch` in it is the
exact binary the fleet runs — copied off a production node and verified
against `/proc/<pid>/exe`, not rebuilt and assumed equal.

## Security

Report vulnerabilities privately — see [SECURITY.md](./SECURITY.md). The
threat models are `docs/THREAT-MODEL.md`, `docs/THREAT_MODEL.md` and
`docs/THREAT-MODEL-AUDIT.md` for the Genesis-3 era, and
`docs/specs/BLOCH-POS-THREAT-MODEL.md` plus `-THREAT-MODEL-2.md` for the
proof-of-stake design.

## License & Copyright

Copyright (C) 2026 Tiago Beltrão de Azevedo Tenório Acioli.

The Bloch **protocol** — its consensus rules and specification — is open;
anyone may implement it. **This implementation** is the author's copyrighted
work, licensed to the public under the **GNU Affero General Public License
v3.0 or later** (`AGPL-3.0-or-later`); see [LICENSE](LICENSE) and
[AUTHORS](AUTHORS). Any distributed fork — or any use of the software to
provide a service over a network — must release its complete corresponding
source under the same license. A commercial license without the AGPL
obligations is available from the author.

One deliberate exception: `crates/bloch-sis-pow` stays `MIT OR Apache-2.0`.
It is the reference implementation of the proof of work, published as a
specification, and it dies with the Genesis-3 halt
(`docs/adr/ADR-039-agpl-license-pos-crates.md`).

"Bloch", "Bloch Protocol" and "Postern Labs" are trademarks of the author.
