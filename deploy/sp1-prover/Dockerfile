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
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl git build-essential pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# SP1 toolchain (sp1up installs cargo-prove + the succinct RISC-V toolchain).
# Pin SP1UP_VERSION for reproducibility once you settle on an SP1 release.
RUN curl -L https://sp1up.succinct.xyz | bash \
    && /root/.sp1/bin/sp1up
ENV PATH="/root/.sp1/bin:${PATH}"

WORKDIR /src
COPY . .

# 1) Guest ELF (RISC-V). Produces crates/coherence-prover/program/elf/...
RUN cd crates/coherence-prover/program && cargo prove build

# 2) The CUDA-enabled HTTP prover service (links the ELF via include_bytes!).
RUN cargo build --release --locked \
      -p coherence-prover-service ${CUDA_FEATURE}

# ── runtime ───────────────────────────────────────────────────────────────────
FROM nvidia/cuda:${CUDA}-runtime-ubuntu22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 prover

COPY --from=build /src/target/release/coherence-prover-service /usr/local/bin/coherence-prover-service

# SP1 caches circuit artifacts / proving params under ~/.sp1 (GBs). Mount a
# volume here (see fly.toml) so cold starts don't re-download them.
ENV SP1_HOME=/data/.sp1
ENV PORT=8080
USER prover
EXPOSE 8080
ENTRYPOINT ["coherence-prover-service"]
