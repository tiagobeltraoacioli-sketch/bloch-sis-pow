# Reproducible build (Bloch-SIS-Linux L1)

> **Historical — Genesis-3.** The image built and hashed here is the root
> `Dockerfile`, i.e. `bloch`, the proof-of-work node for the chain that stopped
> permanently at height 39,918 on 2026-08-13. Nothing here covers the live
> chain: **Genesis-4, proof of stake** ships `bloch-pos` as a signed release
> tarball, and its build determinism is measured by
> `scripts/pos-release-integrity.sh` and documented in
> `deploy/RELEASE-INTEGRITY.md` — that is the reproducibility claim of record
> for what runs today. Kept as part of the Genesis-3 record.
>
> `build.sh` passes the repo root as the build context with no `-f`, so it
> builds the root `Dockerfile` — which, as that file's own header states, does
> not currently build (its `COPY carryover.tsv` wants a file the repository
> stores compressed). The reference digest below was measured before that
> regression; it has not been re-measured since, so treat it as a record, not
> as a digest you can reproduce today.

Goal: **anyone can rebuild the node image from public source and get the same
content digest** — so an operator (or a TEE attestation, L3) can prove the
running node is exactly the audited code, with nothing injected.

## Build

```bash
deploy/repro/build.sh          # build once, print the OCI image digest + notes
deploy/repro/build.sh verify   # build TWICE and assert the two digests match
```

The image is emitted as an OCI archive and hashed; that hash is the
content-addressed digest to publish and compare.

### Verified reference

| Commit | OCI image sha256 |
|---|---|
| `b67929f` | `8de44fc747cb6a8ec8dee9188df0a677e814d30943da005f4367536e439af48a` |

Two independent builds of `b67929f` produced this identical digest (`build.sh
verify` → ✅). Reproduce it and compare; a match proves your tree is byte-for-byte
the audited source. (Later commits change the tree and thus the digest — record a
new row when you cut a release.)

## What makes it reproducible

1. **Base images pinned by digest** — `Dockerfile` uses
   `rust:…@sha256:…` and `debian:…@sha256:…`, never floating tags.
2. **Locked dependency graph** — `Cargo.lock` is committed and the build runs
   `cargo build --locked` (fails on any drift). All deps are in-tree: the
   `pqcrypto-internals` fork is **vendored** (`crates/pqcrypto-internals`), so
   there is no network/private git dependency.
3. **Clamped timestamps** — `SOURCE_DATE_EPOCH` is set to the HEAD commit time
   and buildkit's `rewrite-timestamp=true` rewrites every layer/file mtime, so
   builds don't differ just by wall-clock.

## Verifying a node

1. Build the image at commit `X`; record the digest `D`.
2. Independently rebuild at `X` (another machine / another person). If you also
   get `D`, the artifact is reproducible.
3. (L3) A TEE attestation quote's measured rootfs hash is checked against `D` —
   only then does "this endpoint runs unmodified, audited Bloch at commit X"
   hold. See `docs/specs/BLOCH-SIS-LINUX.md`.

## Known limitation (be honest)

The runtime stage still runs `apt-get install ca-certificates libssl3` and the
builder installs a C toolchain. `apt` fetches **whatever package versions are
current in the Debian mirror at build time**, which can drift over weeks even
with a pinned base-image digest. Pinning the base digest removes base drift, and
clamped timestamps remove mtime drift, but apt-version drift is the remaining
gap.

To close it (planned, L1→L2):
- Pin apt to a **snapshot.debian.org** timestamped mirror, **or**
- Move the image build to **Nix** / **apko** (fully pinned, content-addressed
  package graph) — the intended end state per `BLOCH-SIS-LINUX.md §2.1`.

Until then, "reproducible" holds strongly for the **compiled `bloch` binary**
(locked deps + clamped time) and the base layers, with apt as the caveat.
