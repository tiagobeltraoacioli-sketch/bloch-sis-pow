# SP1 candidate build input review — 2026-09-17

This records verified input identities, not a successful container build or a
reproducibility claim. No Docker/Podman or compatible GPU was available on the
local macOS host. The downloaded Linux archive was hashed, not executed.

| Input | Version | SHA256 |
| --- | --- | --- |
| Official Rust image index | `rust:1.94.1-slim-bookworm` | `cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2` |
| NVIDIA CUDA development image index | `nvidia/cuda:12.5.0-devel-ubuntu22.04` | `4b46c69e223d971f0fb279fd6381a0f3a057e09ba6de08bfbf7db751b1ad6db1` |
| NVIDIA CUDA runtime image index | `nvidia/cuda:12.5.0-runtime-ubuntu22.04` | `75292ffaba88ea846d7f28261d4ed302fbe1124f10ff9da30e44034206916110` |
| SP1 Linux x86_64 toolchain archive | `succinct-1.85.0` | `e601270a28c5fa6cbbfada396ba9a5c7fdeb38fa65ce6b1059f03b952e7d7477` |

Image-index bodies were fetched through Docker Hub's HTTPS registry API; their
locally calculated hashes matched the registry's `Docker-Content-Digest` values.
The exact [upstream toolchain release](https://github.com/succinctlabs/rust/releases/tag/succinct-1.85.0)
archive was downloaded completely (423,886,096 bytes) and hashed locally. These
are pins obtained through upstream HTTPS, not independently verified publisher
signatures or build provenance attestations.

The [SP1 CLI 4.2.1 source](https://docs.rs/crate/sp1-cli/4.2.1/source/src/lib.rs)
names `succinct-1.85.0` as its supported guest toolchain. `cargo install --locked
--version '=4.2.1' sp1-cli` uses the published CLI's lockfile. The guest and service
use their separate committed lockfiles and exact SP1 package versions.
The [SP1 build source](https://docs.rs/crate/sp1-build/4.2.1/source/src/build.rs)
only copies the ELF when an output directory is selected, so the recipe now
provides that directory and the exact filename used by `include_bytes!`.

Remaining qualification includes Linux ABI compatibility of the copied Rust
installation, native build dependencies, GPU driver/runtime integration, SP1
artifact downloads and actual proof execution. Apt repositories/package versions
are not snapshot-pinned, and published CLI build metadata may include timestamps.
The final service image has not been built, independently reproduced or signed.
A frozen digest alone does not certify these old dependency versions as free of
vulnerabilities. Existing advisory policy and the statement authorization blocker
remain separate requirements.
