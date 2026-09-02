# Bloch Protocol

> A post-quantum Layer 1. Hybrid lattice signatures on every consensus path.
> Running **proof of stake** — Genesis-4, live since 2026-08-13.

**About the repository name.** The project is **Bloch Protocol**. The
repositories are called `bloch-sis-pow` (GitHub) and `BlochSISPoW-project`
(GitLab) because that is what the project was called when they were created,
and those URLs are published. The names are historical; they are not being
changed. If you cloned one of these, you are in the right place.

- GitHub: <https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow>
- GitLab: <https://gitlab.com/blochsispow-group/BlochSISPoW-project>

---

## Read this first if you want to run a node on the live chain

The live chain is **Genesis-4**, proof of stake. It started at
**2026-08-13 21:31:19 UTC** and has been producing a block every 30 s and
finalising every epoch since. The trunk of this repository builds it:

```bash
cargo build --release -p bloch-pos-node   # -> target/release/bloch-pos
```

**Genesis-3, the proof-of-work chain, is over.** It stopped at height
**39,918**, and Genesis-4's opening ledger is the balance set carried across
from that height. There is no Genesis-3 network left to join — a node you
build and start today has no peers producing blocks and nothing to sync to.
The Genesis-3 node is still here, still compiles, and is still the thing an
auditor re-derives the opening ledger with; it lives at
[`legacy/genesis3-node/`](./legacy/genesis3-node/) and is described under
[Genesis-3](#consensus-before-genesis-3-proof-of-work--closed).

> **One number in this tree is not yet the final one.** The consensus constant
> `GENESIS3_TERMINAL_HEIGHT` (`crates/bloch-crypto/src/core/mod.rs`) still
> reads `50_000` on this branch. The chain actually stopped at 39,918, and the
> commit that makes the halt a rule at that height rather than an operational
> state — `f21dc6d`, "Genesis-3 terminal height is 39,918, the height it
> stopped at" — is on the branch `deploy/g3-rpc-height-fix` and has **not**
> been merged here. Merging it is a founder decision, because it changes a
> consensus constant. Until it is merged, read 39,918 from
> `CARRYOVER_MEASURED_HEIGHT` in
> `crates/bloch-pos-committee/src/tokenomics_v4.rs`, which is the height the
> live Genesis-4 genesis was actually built from, and do not take `50_000`
> from this tree as the last word.

---

## What Bloch is

A Layer 1 whose consensus-critical cryptography is post-quantum end to end:

| Layer | What it uses | Cost of that choice |
| --- | --- | --- |
| Signatures | **Hybrid ML-DSA-65 ‖ Falcon-1024** — both must verify (`SUITE_MLDSA65_FALCON1024 = 0x0001`) | ~4.6 KB per signature, not recoverable from the message, and no hardware wallet implements it. MetaMask, Ledger and Trezor cannot sign a Bloch transaction. |
| Hashing | SHAKE-256 / SHA-3 with domain separation | Slower than SHA-2 on hardware built for Bitcoin. |
| Transport | **Not post-quantum, and on the live chain not encrypted at all.** | The Genesis-4 fleet runs `--transport devnet`: a plain TCP full mesh with a fixed peer list, **no authentication and no handshake** (`crates/bloch-pos-node/src/net.rs`). The libp2p layer in the tree (`--transport libp2p`) uses **Noise**, which is classical. There is no ML-KEM anywhere in `crates/bloch-pos-node`. The ML-KEM-768 + ChaCha20-Poly1305 hybrid transport was a **Genesis-3 / Era-1** property (see [FIRST_POST_QUANTUM_HANDSHAKE.md](./FIRST_POST_QUANTUM_HANDSHAKE.md)) and did not carry over. |
| Shielded pool | SHAKE-256 commitments and nullifiers, SP1 raw FRI-STARK, no elliptic-curve ZK | Proofs are large and proving is expensive. The mainnet pool is provably empty — nothing has ever been shielded. |

The trade the project makes is explicit: it gives up the entire existing
wallet and tooling ecosystem in exchange for not having a quantum-vulnerable
authorisation path. Every design question downstream of that — including
whether to run an EVM at L1 — reopens the same trade.

**The coin is not a security and not an asset.** No listing, no price, no
value claim. There has been **no public token sale**; the founder states that
18,128,356,145 BLCH (18.13% of the cap) was sold privately to third parties,
which is a declared fact the chain cannot corroborate. Supply is heavily
concentrated: at genesis the founder held 93.94% of the carried-over balance,
98.08% of issued supply and 56.05% of the 100-billion cap, all stakeable, so a
naive Nakamoto coefficient is 1; today the same address holds 66.35% of issued
supply (37.92% of the cap). No coin, sold or held, is locked on chain. Current
holdings are measured and dated in
[`docs/LIVE-SUPPLY.md`](./docs/LIVE-SUPPLY.md), with every percentage against a
named denominator — never quoted from memory, because that number moves and
this file cannot. Bounding mechanisms exist and are documented with
what they do *not* reach — see `docs/audit/CERTIK-CENTRALIZATION.md` and
`docs/specs/BLOCH-TOKENOMICS-V4.md` §4A. There is no framing that makes this
number acceptable, and none is attempted here.

**Unaudited.** A third-party audit is being prepared for, not completed. The
pre-audit dossier is in `docs/audit/`.

## Consensus before: Genesis-3, proof of work — closed

Chain id `0xB10C_0004`, launched 2026-07-29 as a carryover restart, stopped
2026-08-13 at height **39,918**. SHA-256d proof of work over a GhostDAG-Q
BlockDAG, ~30 s target, Stratum V1 for ASICs, merged-mineable with Bitcoin via
AuxPoW from local height 8,500.

It stopped 82 blocks short of the Emission V3 flag day at height 40,000, so
the block reward ended at 8,400 BLOCH and never became 2,600. That fork was
planned, tested, documented — and never happened.

The code did not go away. It is a normal workspace member at
[`legacy/genesis3-node/`](./legacy/genesis3-node/) (binary `bloch`) and it
still compiles, because Genesis-4's opening ledger *is* Genesis-3's output and
an auditor asked to accept that ledger has to be able to re-derive it. What
moved is its position: it used to be the **root package** of this workspace,
so a bare `cargo build` produced the proof-of-work node and presented it as
the repository's default output. That is no longer true or appropriate.

**To reproduce a published Genesis-3 binary, do not build from
`legacy/genesis3-node/` on this branch.** Check out the `genesis3-node-*` tag
the release was cut from, or the branch `deploy/g3-terminal-50000`; on those
refs the package still sits at the repository root exactly as it did when the
binary was built, which is what `repro-manifest.sh` and [REPRO.md](./REPRO.md)
assume. Moving a package changes no bytes of the program, but it does change
paths, and reproducibility is checked against paths.

**Reading older documents.** Around 40 files under `docs/` — release notes,
ADRs, threat models, post-mortems — cite paths of the form `src/consensus/…`
or `src/main.rs:2077`. Those were correct when they were written and they have
not been rewritten, deliberately: a release note is a record of what was true
at a moment, and editing the record to match a later directory layout is how
a project's history quietly stops matching its own artifacts. Read
`src/X` in any Genesis-3-era document as `legacy/genesis3-node/src/X`.
`git log --follow` resolves it automatically.

Everything else specific to this era — mining, GhostDAG, AuxPoW, stratum,
difficulty retargeting, tokenomics V1/V2/V3 — is in [`legacy/`](./legacy/),
with [`legacy/README.md`](./legacy/README.md) explaining what in it remains
true and what does not.

## Consensus today: Genesis-4, proof of stake — live

**Live since 2026-08-13 21:31:19 UTC**, on 64 genesis validators across five
servers, producing a block every 30 s and finalising every epoch. The opening
ledger is the Genesis-3 balance set carried across from height 39,918.

A **linear** chain of slots and epochs. GhostDAG is retired. Fork choice is
LMD-GHOST; finality is Casper-style FFG over an epoch committee; the
randomness beacon is RANDAO; signatures stay ML-DSA-65 ‖ Falcon-1024, with no
BLS anywhere. Design of record:
`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`.

Launching is not auditing. The chain running does not mean the consensus code
has been reviewed by anyone outside this repository — see **Unaudited** above,
and the 64-validator, five-server, one-allocator starting point under
Governance below. Both are properties of the live network, not of a plan.

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
| Genesis-3 PoW node (`legacy/genesis3-node/`) | yes | yes | **ran mainnet 2026-07-29 → h39,918; stopped** |
| AuxPoW merged mining with Bitcoin | yes | yes | ran from local height 8,500 until the halt |
| eUTXO VM (`crates/bloch-euvm`) | yes | yes | ran — consensus-wired at Genesis-3 height 0; **not** wired into Genesis-4 |
| Coherence shielded pool (C1 frozen) | yes | verifier present | never used; the mainnet pool is provably empty |
| PoS consensus core (`crates/bloch-pos-committee`) | yes | yes — 366 tests green, measured 2026-08-13 | **yes — live** |
| PoS node (`crates/bloch-pos-node`) | yes | yes | **yes — mainnet since 2026-08-13 21:31:19 UTC**, 64 validators on five servers, justifying and finalising |
| Tokenomics V4 | yes | constants + const-asserts in the crate | yes — it is the live emission |
| Weak-subjectivity checkpoints | yes | no | no |
| EVM at L1 | proposal; direction accepted (`docs/adr/ADR-040-evm-and-ustav-at-l1.md`) | **no code exists** — the authorization model is an open founder decision | no |
| Ustav (PSTRN-1) charter at L1 | proposal | no — nothing wired | no |
| Third-party audit | scoped | pre-audit dossier written | **not performed** |

## Where things are

The repository root is a **virtual manifest** — it is a workspace, not a
package. Nothing is the "default" build any more, which is the point: the root
package used to be the Genesis-3 proof-of-work node.

```
GENESIS-4 — the live chain
  crates/bloch-pos-committee  PoS consensus core. Frozen, audit-facing.
  crates/bloch-pos-node       The `bloch-pos` binary the fleet runs.
  tools/genesis4-ceremony     Assembled the live genesis block.

SHARED — used by both eras
  crates/bloch-crypto         Hybrid ML-DSA-65 ‖ Falcon-1024. On the
                              Genesis-4 consensus path.
  crates/bloch-sis-pow        Reference PoW; pulled in by bloch-crypto,
  crates/coherence-core       and so is this. Neither is PoW-only, which
                              is why they did not move under legacy/.
  crates/pqcrypto-internals   Vendored fork ([patch.crates-io] at the root).
  crates/bloch-btc-wallet, crates/bloch-pq-vault

GENESIS-3 — closed, kept buildable for audit
  legacy/genesis3-node/       The `bloch` node. Ran mainnet to h39,918.
                              Was the root package until 2026-08-13.
  crates/bloch-euvm, crates/bloch-ffg
                              eUTXO VM + FFG committee, behind its `euvm`
                              feature. Never wired into Genesis-4.
  legacy/                     The written Genesis-3 record. legacy/README.md

docs/                         Current documentation. Index: docs/README.md
docs/specs/                   Normative PoS design.
docs/adr/                     Decision records, including superseded ones.
docs/audit/                   Pre-audit dossier and the two Era-1 audits.
gips/                         The GIP process (GIP-0001, editors, template).
```

Everything above except `crates/coherence-prover` and `fuzz` — both of which
need nightly/SP1 toolchains — is a workspace member, so `cargo build
--workspace` and `cargo test --workspace` reach all of it. This has not always
been true: the PoS consensus crates and the genesis ceremony tool each carried
a private `[workspace]` table, which made them invisible to exactly the
command a reviewer runs first. If you add a crate, add it to `members`.

## Build

```bash
cargo build --release -p bloch-pos-node   # the live Genesis-4 node
```

Produces `target/release/bloch-pos`. Needs a C toolchain (clang/cmake).

```bash
cargo build --release --workspace         # everything, both eras
```

Also produces the Genesis-3 binaries — `bloch`, `bloch-cli`,
`bloch-calibrate`, and `bloch-wallet` (which needs
`--features bloch-crypto/wallet-cli`). Building them is a compile check on a
chain that has stopped; see the reproducibility note under
[Genesis-3](#consensus-before-genesis-3-proof-of-work--closed) before using
the result for anything that has to match a published release.

## Test

```bash
cargo test --workspace                              # everything
cargo test -p bloch-pos-committee -p bloch-pos-node # Genesis-4 consensus only
```

**`cargo test --workspace` is red, and was red before the workspace was
reorganised.** Stated here rather than discovered by the next person who runs
it. Measured 2026-08-13 on a clean checkout, `--release`:

| Suite | Result |
| --- | --- |
| `bloch-pos-committee` — the live consensus core | **366 passed, 0 failed, 1 ignored** (+2 doc-tests) |
| `bloch-pos-node` | 93 passed, 0 failed — **but see the flake below** |
| `genesis4-ceremony` | 10 passed, **18 failed** |
| `bloch` (Genesis-3, retired) | 304 passed, **1 failed** |

Every one of these reproduces on `e17faef`, the commit before the
reorganisation. The move introduced none of them. The `bloch-pos-node` entry
was counted as a failure when this table was first written; re-running it on
2026-08-13 showed it is a flaky test harness, and it is described as such
below.

- The `bloch` failure is `pow::tests::k4_mined_block_rejected_at_canonical_height`,
  a probabilistic assertion about the k=4→k=8 proof-of-work gate. It fails
  identically on the commit before the reorganisation, so it is inherited, not
  introduced — and it is a test of a chain that has stopped.
- The `genesis4-ceremony` failures are **pre-existing and were simply never
  run.** The crate used to declare its own `[workspace]`, which made
  `cargo test --workspace` skip it; running it inside its old private
  workspace at the previous commit produces the same 10/18 split. The tool
  that assembled the live genesis block had failing tests and nothing
  reported it. That is the whole argument for the membership change.
- The `bloch-pos-node` failure is
  `a_cold_node_builds_the_same_chain_from_genesis_without_a_donated_datadir`,
  and it is a **flake, not a failure** — diagnosed 2026-08-13. It failed on one
  run and passed on the next from the same clean checkout. The cause is in the
  test harness, not the node: `free_port()` asks the kernel for an ephemeral
  port, and the RPC port is then derived as `listen + 1000` on a `u16`
  (`crates/bloch-pos-node/tests/cold_start.rs:151`). macOS hands out ephemeral
  ports from 49152–65535, so any draw above 64535 overflows — and
  `overflow-checks = true` in the workspace profile turns that into a panic
  rather than a wrap. Three nodes per run, roughly a 6% chance each, so about
  one run in six dies before a node ever starts. The fix is to draw the RPC
  port with `free_port()` too instead of deriving it by addition; it is left to
  whoever owns that file.

None of these are consensus changes and none were fixed here — this commit
moves files and fixes build wiring. Fixing them is separate work.

## Prebuilt binaries

**These are Genesis-3 binaries, and Genesis-3 has stopped.** They are kept
published because they are the artifacts an auditor replays the closed chain
with, not because there is a network for them to join. There is no prebuilt
Genesis-4 node yet; build `bloch-pos` from source.

Building from source is the recommended path — you run the bytes you
compiled, and the build is reproducible by design (see [REPRO.md](./REPRO.md)).
The binaries below are a convenience, not the standard.

Prebuilt `bloch` and `bloch-cli` for **Linux x86_64**. The last release is
`genesis3-node-terminal-50000-20260812`:

- GitHub releases: <https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases>
- GitLab releases: <https://gitlab.com/blochsispow-group/BlochSISPoW-project/-/releases>
- Mirror: <https://posternlabs.com/dl/bloch-genesis3-terminal-50000-linux-x86_64.tar.gz>

The mirror serves files only under `/dl/`, by full filename. Any other path on
that host — `/bloch`, `/bloch-cli` — answers `200` with the site's own HTML
page, so a wrong download URL there succeeds, produces a file, and gives you
nothing to notice. Check `content-type: application/gzip` before trusting a
download from the mirror.

**`/dl/` also still holds four superseded node tarballs**, including one named
`bloch-genesis3-linux-x86_64.tar.gz` — a name that reads like "the current
one" and is not. None of the four halts at 50,000. Take the filename with
`terminal-50000` in it, or use a release page, where superseded builds are
labelled as such.

**Requires glibc ≥ 2.39** (Ubuntu 24.04 or newer). On older distributions,
build from source. Verify `SHA256SUMS` before running anything.

**Take the latest non-superseded release.** Genesis-3 consensus flag-days
make an older build diverge, not merely lag: the Emission V3 flag-day at
local height 40,000 cut the block reward, and a binary built before that
change forks off the network at that height rather than following it. Every
release before `genesis3-node-terminal-50000-20260812` is tagged
`[SUPERSEDED]` in the release list for that reason — including
`genesis3-node-linux-20260805`, which predates five consensus flag-days.

This release was the one the fleet ran through the halt — the `bloch` in it
was copied off a production node and verified against `/proc/<pid>/exe`, not
rebuilt and assumed equal. It stops at 50,000; the chain in fact stopped at
39,918, 82 blocks before the Emission V3 flag day, so the reward never
stepped down and no binary ever needed the 39,918 rule to follow the network.
That rule matters now for a different reason — it is what stops someone
restarting a miner and extending a chain whose terminal snapshot has already
been used — and it is not in any published release. See the note at the top
of this file.

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
