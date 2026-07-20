# ─── Builder ─────────────────────────────────────────────────
# Base images pinned by digest (reproducible-build prerequisite, L1). Update the
# digest deliberately, never float the tag. See deploy/repro/README.md.
FROM rust:1.94-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS builder
WORKDIR /build

# C toolchain for rocksdb (bindgen/libclang), blst, and pqcrypto (PQClean).
RUN apt-get update && apt-get install -y \
    clang \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the whole workspace. `crates/` holds the vendored bloch-sis-pow path
# dependency, so it MUST be present or the build fails to resolve it.
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY src ./src
COPY tests ./tests

# Build the node binary (release, LTO per Cargo.toml profile). --locked forces
# the committed Cargo.lock (fails on drift) — required for reproducibility.
# SOURCE_DATE_EPOCH (passed as a build arg) clamps build timestamps.
ARG SOURCE_DATE_EPOCH
RUN cargo build --release --locked --bin bloch

# ─── Runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/bloch /usr/local/bin/bloch

# Genesis-2 carry-over snapshot, verified fail-closed at first boot. Baked at
# /carryover.tsv — OUTSIDE /bloch-data, because that path is a mounted volume
# that would hide a file baked into the image. Nodes pass
# --carryover-snapshot /carryover.tsv.
COPY carryover.tsv /carryover.tsv
RUN chown 10001:10001 /carryover.tsv

# ── Hardening (Bloch-SIS-Linux L2, container tier) ────────────────────────────
# Non-root user (created without useradd so it works on any slim base), owning
# the data dir. The node binds ports >1024, so it needs no capabilities.
RUN echo 'bloch:x:10001:10001::/home/bloch:/usr/sbin/nologin' >> /etc/passwd \
 && echo 'bloch:x:10001:' >> /etc/group \
 && mkdir -p /bloch-data /home/bloch \
 && chown -R 10001:10001 /bloch-data /home/bloch
# Entrypoint disables core dumps (THREAT_MODEL: a core dump can leak secret key
# material mid-execution) before exec'ing the node.
RUN printf '#!/bin/sh\nulimit -c 0\nexec bloch "$@"\n' > /usr/local/bin/bloch-entrypoint \
 && chmod +x /usr/local/bin/bloch-entrypoint

# Ports:
#   16110  P2P TCP (gossipsub + IBD sync)
#   16111  P2P WebSocket
#   16210  RPC (JSON-RPC over HTTP) — protect with --rpc-api-key if global
#   16310  Metrics (Prometheus, only if --metrics passed)
EXPOSE 16110 16111 16210 16310
ENV RUST_LOG=info
VOLUME ["/bloch-data"]

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/bloch-entrypoint"]
# Default: a public node (P2P + RPC bound to all interfaces). Add "--mine" to
# run a miner, or "--peer <multiaddr>" to bootstrap from a known peer.
CMD ["--rpc-bind", "0.0.0.0", "--rpc-port", "16210", "--listen", "/ip4/0.0.0.0/tcp/16110", "--data-dir", "/bloch-data"]
