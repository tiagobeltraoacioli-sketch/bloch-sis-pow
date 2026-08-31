# syntax=docker/dockerfile:1
#
# Coherence SP1 shielded-spend prover — GPU build for Fly.io (L40S / A100).
#
# Multi-stage: install the SP1 toolchain, build the guest ELF (cargo prove
# build), build the CUDA-enabled service, ship a slim CUDA runtime.
#
# Build context = repo root (needs crates/coherence-core + coherence-prover):
#   fly deploy --config deploy/sp1-prover/fly.toml --dockerfile deploy/sp1-prover/Dockerfile
#
# CPU-only fallback (reliable, slower): pass --build-arg CUDA_FEATURE="" and use
# a rust:1-bookworm base instead of the CUDA images. See README.

ARG CUDA=12.5.0

# ── build ─────────────────────────────────────────────────────────────────────
FROM nvidia/cuda:${CUDA}-devel-ubuntu22.04 AS build
ARG CUDA_FEATURE="--features cuda"
# PINNED SP1 release. Must stay in lockstep with the `=6.5.0` pins in
# crates/coherence-prover/{program,script,service}/Cargo.toml: sp1up without a
# version installs whatever is current, whose toolchain/SDK pair will not match
# the pinned crates (the 4.x-era mismatch produced `must be a 32-bit elf`).
ARG SP1UP_VERSION=v6.5.0
# protoc is REQUIRED: sp1-prover-types generates code from .proto in its build
# script. Ubuntu 22.04's apt protobuf (3.12) is too old, so install a pinned
# upstream release. (Measured working on macOS with libprotoc 36.0.)
ARG PROTOC_VERSION=31.1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl git build-essential pkg-config libssl-dev ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# protoc (pinned)
RUN curl -sSfL -o /tmp/protoc.zip \
      "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" \
    && unzip -o /tmp/protoc.zip -d /usr/local 'bin/protoc' 'include/*' \
    && rm /tmp/protoc.zip \
    && protoc --version

# Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# SP1 toolchain, PINNED (sp1up installs cargo-prove + the succinct RISC-V
# toolchain for exactly this release).
RUN curl -L https://sp1up.succinct.xyz | bash \
    && /root/.sp1/bin/sp1up --version "${SP1UP_VERSION}"
ENV PATH="/root/.sp1/bin:${PATH}"

WORKDIR /src
COPY . .

# 1) Guest ELF (RISC-V). SP1 6.x writes it to
#    crates/coherence-prover/program/target/elf-compilation/
#      riscv64im-succinct-zkvm-elf/release/coherence-spend-program
#    (the old program/elf/riscv32im-... path is gone). --locked holds the
#    committed guest Cargo.lock: same lock + same toolchain => same ELF =>
#    same vkey. A drifting guest build is a silent verifier fork.
RUN cd crates/coherence-prover/program && cargo prove build --locked

# 2) The CUDA-enabled HTTP prover service (links the ELF via include_bytes!).
#    NOTE: crates/coherence-prover is EXCLUDED from the repo-root workspace —
#    build from its own workspace dir, not the repo root.
RUN cd crates/coherence-prover && cargo build --release --locked \
      -p coherence-prover-service ${CUDA_FEATURE}

# ── runtime ───────────────────────────────────────────────────────────────────
FROM nvidia/cuda:${CUDA}-runtime-ubuntu22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 prover

COPY --from=build /src/crates/coherence-prover/target/release/coherence-prover-service /usr/local/bin/coherence-prover-service

# SP1 caches circuit artifacts / proving params under ~/.sp1 (GBs). Mount a
# volume here (see fly.toml) so cold starts don't re-download them.
ENV SP1_HOME=/data/.sp1
ENV PORT=8080
USER prover
EXPOSE 8080
ENTRYPOINT ["coherence-prover-service"]
