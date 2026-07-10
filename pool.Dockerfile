# Postern-operated instance of the reference Bloch-SIS-PoW mining pool.
# The pool is a STANDALONE cargo workspace (pool/) with path deps into crates/,
# so both dirs must be in the build context. Base images pinned by digest,
# mirroring the node Dockerfile (reproducible-build prerequisite).
FROM rust:1.94-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS builder
WORKDIR /build

# C toolchain for pqcrypto (PQClean) + blst pulled in via bloch-crypto.
RUN apt-get update && apt-get install -y \
    clang pkg-config libssl-dev libclang-dev cmake build-essential git \
    && rm -rf /var/lib/apt/lists/*

# crates/ holds the vendored path deps (bloch-crypto, bloch-sis-pow,
# pqcrypto-internals) the pool resolves via ../crates.
COPY crates ./crates
COPY pool ./pool

ARG SOURCE_DATE_EPOCH
RUN cd pool && cargo build --release --locked --bin bloch-pool

# ─── Runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/pool/target/release/bloch-pool /usr/local/bin/bloch-pool
ENTRYPOINT ["/usr/local/bin/bloch-pool"]
