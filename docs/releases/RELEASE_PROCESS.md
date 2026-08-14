# Release Process

> **Historical runbook — proof-of-work era.** This describes the release flow
> for the Bloch-SIS Protocol proof-of-work node (`v0.5.x`/`v0.6.x`), for a
> chain that stopped permanently at height 39,918 on 2026-08-13. The live chain
> is **Genesis-4, proof of stake**, and its node is `crates/bloch-pos-node`;
> the surfaces named below (Docker Hub `blochlayer/bloch`, the Akash SDLs, the
> GitHub Release page, the `v0.5.N` version line) are **not** the release path
> for it. Kept as the record of how proof-of-work releases were cut; do not
> follow it for a Genesis-4 release without confirming each surface still
> exists and is still the intended one.

This document is the operational runbook for cutting a new Bloch-SIS Protocol (BLOCH)
release. It exists because the flow touches four surfaces — the source
repo, the Docker Hub registry, the Akash SDL deployments, and the
public GitHub Release page — and getting any one of them wrong leaves
the network in an inconsistent state.

## TL;DR — happy path

From a clean `main` with all intended code merged:

```bash
# 1. Bump version + write release notes
vim Cargo.toml                           # bump version = "0.5.N"
vim docs/releases/v0.5.N.md              # new release notes
git add -A
git commit -m "Release v0.5.N — <headline>"
git push origin main

# 2. Tag the release commit
git tag -a v0.5.N -m "v0.5.N — <headline>"
git push origin v0.5.N
```

At this point the CI workflow (`.github/workflows/ci.yml`) does four
things automatically:

1. Compiles and runs the full test suite against the tagged commit
2. Builds the Docker image
3. Pushes it to Docker Hub as **both** `blochlayer/bloch:v0.5.N`
   and `blochlayer/bloch:latest`
4. Publishes a CI attestation in the job summary

Then manually:

```bash
# 3. Update SDLs to pin the new version (optional — do this when you
#    actually intend to redeploy; otherwise leave SDLs on the last
#    version that is known-good in production)
sed -i '' 's|v0.5.PREV|v0.5.N|' deploy/node1.sdl.yaml deploy/node2.sdl.yaml
git add -A
git commit -m "deploy: bump SDL images to v0.5.N"
git push origin main

# 4. Create the GitHub Release (UI or gh CLI)
gh release create v0.5.N \
  --title "v0.5.N — <headline>" \
  --notes-file docs/releases/v0.5.N.md
```

## Surface inventory

| Surface | Artifact | Update method |
|---|---|---|
| Git tag | `v0.5.N` on the release commit | `git tag && git push origin v0.5.N` |
| Docker registry | `blochlayer/bloch:v0.5.N` + `:latest` | CI workflow on tag push |
| Akash deployments | `deploy/node{1,2}.sdl.yaml` image references | Manual edit + commit, then `akash` CLI redeploy |
| GitHub Release | Release page with notes | `gh release create` or the web UI |
| `Cargo.toml` | `version = "0.5.N"` | Manual edit in the release commit |

## Versioning rules

Bloch-SIS Protocol uses semantic versioning with the Rust-flavored twist that
**0.x releases are API-unstable**. The rule this repo follows:

- **Bump patch** (`0.5.10 → 0.5.11`): no consensus break, no
  external-API break, pure additions / fixes / internal refactors
  with wire-format preserved.
- **Bump minor** (`0.5.x → 0.6.0`): deliberate consensus change,
  breaking internal API, or any protocol-visible format bump. A
  minor bump is a scheduled event and typically ships its own
  migration guide.
- **Bump major** (`0.x → 1.0.0`): "mainnet-candidate" milestone.
  Reserved for the first release the team is willing to back for
  long-term stability.

## Pre-release checklist

Run through this before the `git tag`:

- [ ] All target sprints merged to `main`
- [ ] `cargo test` passes locally on the release commit
- [ ] `cargo build --release` produces working binaries
- [ ] `Cargo.toml` version matches the intended release
- [ ] `docs/releases/v0.5.N.md` exists and is complete
- [ ] Release notes reference no credentials, no host-specific paths,
      no personally-identifying information
- [ ] Audit tracker (`docs/audit/AUDIT-2026-04-20.md`) reflects the
      current scoreboard if any audit findings were closed
- [ ] Public-facing PDF (`FIRST_POST_QUANTUM_HANDSHAKE.md`) is in
      sync with the code if transport or crypto changed

## Rollback

If a release is found to be broken after publish:

1. **Registry**: Docker images are immutable — the bad `:v0.5.N` stays
   on Docker Hub. Roll forward with `v0.5.N+1` rather than trying to
   untag. Update `:latest` by re-pushing the previous good tag as
   `:latest` if needed:
   ```bash
   docker pull blochlayer/bloch:v0.5.PREV
   docker tag blochlayer/bloch:v0.5.PREV blochlayer/bloch:latest
   docker push blochlayer/bloch:latest
   ```
2. **SDL deployments**: edit the SDL image reference back to
   `v0.5.PREV` and redeploy. No data loss — RocksDB state from the
   bad release decodes cleanly on the previous release if no
   schema change was involved.
3. **GitHub Release**: mark the bad release as "pre-release" or
   delete it; create a new release for `v0.5.N+1` with a short note
   explaining the regression.
4. **Git tag**: leave the bad tag in place for auditability (deleted
   tags invite confusion). The rollback is signaled by the NEW tag,
   not by removing the OLD one.

## The CI workflow (reference)

`.github/workflows/ci.yml` is the source of truth for what happens on
a release push. Key branches of the workflow:

- `push` to `main` → build, test, publish `blochlayer/bloch:latest` +
  `blochlayer/bloch:<sha>`.
- `push` of a tag matching `v*` → build, test, publish
  `blochlayer/bloch:<tag>` + `blochlayer/bloch:latest`.
- `pull_request` → build, test, emit CI attestation hash in the job
  summary (for PoI claims), do not publish.

The image is built for `linux/amd64` only. Multi-arch support (arm64
for Apple Silicon validators, for example) is a roadmap item.

## History

| Version | Date | Commit | Notes |
|---|---|---|---|
| v0.5.10 | 2026-04-21 | Release commit at tag | Reorg-ready; closes all CRITICAL audit findings |
| v0.5.11 | 2026-04-21 | Release commit at tag | Audit fortnight; 40 %→88 % resolved |
