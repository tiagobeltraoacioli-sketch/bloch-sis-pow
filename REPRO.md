# Postern OS — Reproducibility runbook (#2 pin inputs, #9 determinism)

Operator-facing companion to the audit plan. This file holds the EXACT host
command sequences a human runs on the **aarch64 Linux Nix host** to (a) pin all
Nix inputs (roadmap #2) and (b) measure determinism (roadmap #9). Agents cannot
run Nix; the tooling here (`flake.nix`, `repro-manifest.sh`, `repro-compare.sh`,
the `repro` CI job) is prepared so these commands Just Work.

## Honest claim ladder (binding — do not let tooling erode it)

1. Before any pin: **NOT reproducible.** `nixpkgs = nixos-25.05` is a moving
   branch and `mobile-nixos` has no in-tree rev; "same input → same image" is
   false across time and hosts.
2. After committing `flake.lock` (+ the mobile-nixos rev, #2 below): you may say
   **"reproducible-by-design" / "deterministic inputs pinned."** You may NOT say
   "reproducible." Same inputs now resolve to fixed store hashes — that is all.
3. After `repro-compare.sh` prints REPRODUCIBLE across **two independent
   builders** (bit-for-bit identical narHash, diffoscope-clean) (#9): only then
   is the word **"reproducible"** earned, and only then may `os_roothash` be
   published as a verified reference.
4. **"Attested"** is never earned by any of the above. It is earned ONLY when the
   sealed image boots on real confidential-computing hardware (SEV-SNP/TDX,
   `/dev/sev-guest` / `/dev/tdx_guest`). Until then attestation is aspirational.

Throughout: the code is **unaudited**, the coin has **no value**, testnet is
zero-security. A single-host `--rebuild --check` pass is necessary but NOT
sufficient — it is not the two-builder test.

## Platform caveat (why aarch64 vs x86_64 matters)

`flake.nix` wires the OS/image outputs to `system = "x86_64-linux"`. On the
aarch64 host these build ONLY under binfmt qemu emulation (slow) or on a real
x86_64 builder:

| Target | Native on aarch64? |
|---|---|
| `.#packages.aarch64-linux.bloch` | yes — cheapest determinism probe (RocksDB 8.10 C++ is the #1 nondeterminism risk) |
| `.#packages.aarch64-linux.attested-image` | yes — aarch64-native sealed image (added for exactly this) |
| `.#mobile-image` | yes — PinePhone image, aarch64 |
| `.#iso` / `.#desktop-iso` / `.#attested-image` | no — x86_64 only (emulate or use an x86_64 builder) |

A bit-for-bit comparison is only meaningful between two hosts producing the
**same attr on the same build platform**. Start with the native aarch64 attrs.

## #2 — Pin all Nix inputs (run in repo root on the Nix host)

```bash
cd /path/to/bloch-blockchain

# 1. Resolve the moving branches -> fixed revs; writes flake.lock.
nix flake lock

# 2. Record exactly what got pinned (for the commit msg + os/MOBILE.md).
nix flake metadata --json | jq -r '
  "nixpkgs      rev: " + .locks.nodes.nixpkgs.locked.rev,
  "mobile-nixos rev: " + .locks.nodes["mobile-nixos"].locked.rev'

# 3. mobile-nixos is flake=false: its OWN nixpkgs pin lives inside its tree
#    (npins). Record the resolved rev for os/MOBILE.md.
MN=$(nix flake metadata --json | jq -r '.locks.nodes["mobile-nixos"].locked.path // empty')
MN=${MN:-$(nix build --no-link --print-out-paths \
      "github:mobile-nixos/mobile-nixos/$(nix flake metadata --json \
      | jq -r '.locks.nodes["mobile-nixos"].locked.rev')")}
jq -r '.pins.nixpkgs | (.revision // .rev) , (.url // .repository)' "$MN/npins/sources.json" 2>/dev/null \
  || grep -RnoE 'rev = "[0-9a-f]{40}"' "$MN"/*.nix "$MN"/npins/* 2>/dev/null | head

# 4. (Recommended) make the mobile-nixos pin a diffable line: paste the rev from
#    step 2 into flake.nix (see the commented block above `inputs.mobile-nixos`),
#    then re-run `nix flake lock` so the lock matches the pinned input.

# 5. Commit. Honest claim this unlocks: "reproducible-by-design", NOT "reproducible".
git add flake.lock flake.nix os/MOBILE.md
#   commit body: "Pin all Nix inputs (flake.lock) + mobile-nixos rev.
#   reproducible-by-design; NOT yet independently verified (see #9)."

# 6. Drift guard (also enforced in CI):
nix flake check --no-build
nix flake lock --no-update-lock-file    # errors if the lock would need updating
git diff --exit-code flake.lock         # fails on any drift
```

## #9 — Determinism (run in repo root on the Nix host)

```bash
# ── Single-host self-check (native aarch64, cheapest first) ──────────────────
nix build .#packages.aarch64-linux.bloch           --rebuild --check --keep-failed -L
nix build .#packages.aarch64-linux.attested-image  --rebuild --check --keep-failed -L
nix build .#mobile-image                           --rebuild --check --keep-failed -L
# on divergence, --keep-failed leaves the two dirs; diff them:
diffoscope /nix/store/<hash>-bloch /nix/store/<hash>-bloch.check | tee diffoscope-bloch.txt

# ── Two-builder test (the one that earns the word "reproducible") ────────────
# On host A AND host B, same committed flake.lock, same attr:
./repro-manifest.sh .#packages.aarch64-linux.bloch          # each host
./repro-manifest.sh .#packages.aarch64-linux.attested-image # each host (image: adds image_sha256 + roothash)
# then, on either host, with both manifests present:
./repro-compare.sh manifest-hostA-*.txt manifest-hostB-*.txt
# REPRODUCIBLE => publish os_roothash as a VERIFIED reference; else diffoscope shows the diff.
```

Do NOT publish `os_roothash` or say "reproducible" until `repro-compare.sh`
prints REPRODUCIBLE across two independent builders.

## x86_64 `.#attested-image` on an aarch64 host

Two options, in preference order:
- **(b, recommended)** use the aarch64-native `.#packages.aarch64-linux.attested-image`
  variant added to `flake.nix` — builds + `--rebuild --check` natively; pair
  with a second aarch64 host for the two-builder test.
- **(a)** emulate x86_64: `extra-platforms = x86_64-linux` in `nix.conf` + binfmt
  qemu-user, then `nix build .#attested-image --rebuild --check` — correct but
  slow; the true bit-for-bit partner should be a native x86_64 host.

## CI

- `.gitlab-ci.yml` gains a `nix` stage with a `repro` job (tag
  `bloch-nix-aarch64`, `allow_failure: true`) running the native aarch64
  `--rebuild --check` on `.#packages.aarch64-linux.bloch` and
  `.#packages.aarch64-linux.attested-image`. Flip `allow_failure` to `false`
  once the two-builder compare is green.
- A `mainnet-guard` placeholder job is present but inert (`rules: when: never`)
  until Dev-A's `mainnet` feature + `cargo test --features mainnet` guard land.
- Tooling-license note: diffoscope (GPL-3.0) and Nix/CI helpers run only as
  ephemeral CI/dev tools, never linked into or shipped in the image closure. The
  no-AGPL rule (barred even as a network service) is not a ban on GPL dev tools.

---

## DEFERRED TODO — git-dep rev-pin of `bloch-crypto` (bloch-protocol)

**Blocked on Dev-A's merged commit SHA.** DO NOT do this until that SHA exists.
Three manifests in the **bloch-protocol** repo (NOT this repo) pin `bloch-crypto`
to the moving `branch = "main"`; each must be pinned to the fixed rev once known.
Same one-line edit in all three — replace `branch = "main"` with `rev = "<SHA>"`:

| # | File (in bloch-protocol) | Line | Current |
|---|---|---|---|
| 1 | `crates/postern-seal-companion/Cargo.toml` | 45 | `bloch-crypto = { git = "https://gitlab.com/blochsispow-group/BlochSISPoW-project.git", branch = "main" }` |
| 2 | `crates/postern-consiglio-auth/Cargo.toml` | 43 | `bloch-crypto = { git = "https://gitlab.com/blochsispow-group/BlochSISPoW-project.git", branch = "main" }` |
| 3 | `mobile/core/Cargo.toml` | 18 | `bloch-crypto = { git = "https://gitlab.com/blochsispow-group/BlochSISPoW-project.git", branch = "main" }` |

Edit to make in each (fill `<DEV_A_SHA>` with the merged 40-char commit):

```toml
bloch-crypto = { git = "https://gitlab.com/blochsispow-group/BlochSISPoW-project.git", rev = "<DEV_A_SHA>" }
```

Then in bloch-protocol: `cargo update -p bloch-crypto` (or `cargo generate-lockfile`)
and commit the updated `Cargo.lock` so the git dep is fully pinned.

> Note: `Cargo.toml` line 62 of bloch-protocol also carries a `branch = "main"`
> git dep (`pqcrypto-internals`, same GitLab group). That is a separate upstream
> pin, out of scope for this bloch-crypto rev-pin; flag it if a full freeze is
> wanted for the audit bundle (#11).
