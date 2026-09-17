# Reproduction — INF-01 (build/ship pipeline for the live fleet binary lives outside the repo)

Not a Rust test: the claim is about the *absence* of an in-repo build definition
for the container the fleet runs, and about an out-of-repo build/registry/Fly
pipeline. It is reproduced by grepping the tree and by comparing against the
public GitHub tags/releases. All steps are read-only.

## A. The fleet image has no build definition in the repo (main OR the release tag)

```sh
cd /home/user/bloch-sis-pow
# Only the runbook mentions bloch-g4 / start.sh; everything else is libp2p protocol ids.
grep -rn -I 'bloch-g4\|start\.sh' . | grep -v '^./target' | grep -v '^./.git/'
#   -> deploy/FLAG-DAY-EPOCH-800.md:47  image registry.fly.io/bloch-g4:g4-flagday-6a7301ea
#   -> deploy/FLAG-DAY-EPOCH-800.md:54  "...carryover.tsv, mainnet.manifest, start.sh..."
#   -> crates/bloch-pos-node/src/p2p.rs  (protocol-id strings "/bloch-g4/..."), not a build.

# No fly.toml for app bloch-g4; the only fly.toml are retired G3 nodes.
find . -name '*.fly.toml' -o -name 'fly.toml' | grep -v target
#   -> blochv-node-*.fly.toml (G3), deploy/genesis2/*, deploy/sp1-prover/fly.toml,
#      fly.euvm.toml, fly.toml (G3 blochv-node), pool.fly.toml, postern-os-build.fly.toml
#      NONE for bloch-g4.

# The only Dockerfile that builds a node builds the retired G3 `bloch`, and says so:
sed -n '1,25p' Dockerfile
#   "GENESIS-3 IMAGE ... NOT THE LIVE CHAIN ... There is deliberately no container
#    image for it [bloch-pos] here."
```

Same holds on the fleet-lineage release tag, not just this shallow `main` clone
(checked via the GitHub API, ref refs/tags/g4-node-20260901):
- `deploy/` on the tag: no bloch-g4 Dockerfile, no start.sh, no bloch-g4 fly.toml.
- repo root on the tag: same fly.toml set as main (all G3), Dockerfile = the G3 one.
- `search_code repo:.../bloch-sis-pow bloch-g4 filename:Dockerfile` -> 0 results.

## B. The repo admits the release container does not exist

```sh
sed -n '/## 8. Not done here/,/canonical/p' deploy/RELEASE-INTEGRITY.md
#   §8.1: "No bloch-pos release container exists yet. Dockerfile / deploy/repro/build.sh
#          build the Genesis-3 bloch node. The canonical /build container ... for
#          bloch-pos is specified here but not written ... It must exist before the
#          first real release."
```

The fleet image is recorded as built on a *floating* base tag, by an undescribed process:

```sh
sed -n '45,55p' deploy/FLAG-DAY-EPOCH-800.md
#   image  registry.fly.io/bloch-g4:g4-flagday-6a7301ea
#   digest sha256:e29a5148...   binary "built in rust:1-bookworm"   (floating rust:1)
#   "inherits the previous fleet image and replaces exactly one file, the node binary"
```

Contrast the pinned inputs the repo *claims* for a release
(`RELEASE-INTEGRITY.md` §2: `rust-toolchain.toml` = 1.94.1, digest-pinned base,
`/build`, `--locked`). The Aug-22 fleet image obeys none of these, and its
source commits (`6a7301ea`, merge `8e0cb15f`) are absent from the clone and from
the tag list; the later epoch-2700 rebuild (`d953fcc`, `FLAG-DAY-EPOCH-2700.md`)
is likewise not a published release.

## C. What CI proves is the runner build, not the fleet artifact

```sh
sed -n '/## 6. What CI proves/,/scratch systemd host/p' deploy/RELEASE-INTEGRITY.md
#   pos-release-integrity proves same-PATH determinism + stamp on the CI runner.
#   "CI cannot prove, by design: the canonical container hash (needs the release
#    container, §8.1) ... the fleet sweep (§4) — CI has no fleet credentials".
```

`scripts/pos-release-integrity.sh` builds `bloch-pos` twice in the CI runner's
own workspace and compares the two hashes to each other; it never compares
against the bytes registry.fly.io/bloch-g4 actually ships.

## D. The mitigations that DO exist (why this is Medium, not High)

1. There IS a published, independently reproducible source-build reference for
   the fleet lineage. GitHub release `genesis4-node-20260814` ships
   `bloch-pos-linux-x86_64` (sha256 c0f70703...) + `SHA256SUMS`; and
   `docs/THIRD-PARTY-QUICKSTART.md:311-315` records that tag `g4-node-20260901`
   builds byte-identically to `sha256 ac79e2fa...` on three machines. So an
   auditor is NOT left with "no reference hash" for a source build — the
   reviewer's "no reference hash exists" is overstated. What is missing is a
   reference for the *container/fleet image* and for the flag-day rebuilds.
2. A fleet sweep is defined and partly automatable: `getbuildinfo` returns
   `source_digest` (SHA3-256 over the compiled source set, `build.rs`), and the
   §4 sweep hashes `/proc/$PID/exe`. `scripts/lifecycle-fleet-verify.sh` drives it.
   But every such check compares against a reference the *operator* produces, and
   `source_digest` is tamper-evident, not tamper-proof (a hostile builder edits
   `build.rs`; `rpc.rs:2400-2420` says exactly this).

## E. Precondition for the impactful scenario

The gap does not itself grant an attacker anything. The scenario the reviewer
describes — pushing an arbitrary `bloch-pos` to 49 validators — requires a
stolen Fly API token / registry credential / compromised operator workstation.
That is INF-02's credential concentration, a privileged position, NOT reachable
via the live chain's network surface (bound gates in params.rs, `--transport
devnet`, public RPC on the bootnodes). INF-01 removes an *audit/detection*
control on top of that; it is a verifiability / defense-in-depth gap.

## Expected result

Steps A-C reproduce every factual claim (no in-repo build definition, floating
base, CI proves only the runner build). Step D shows the reviewer's "no
reference hash" wording is partly inaccurate. Step E shows the impact needs a
privileged credential and is not network-reachable — so the finding is a real
Medium defense-in-depth/verifiability gap, not a High exploit.
