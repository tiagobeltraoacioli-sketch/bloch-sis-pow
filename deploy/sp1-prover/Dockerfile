# Coherence SP1 prover candidate build. NOT qualified for funded-pool activation.
# Context: repository root. Build for linux/amd64; see README.md and the
# guest authorization blocker before using any resulting artifact.
FROM rust:1.94.1-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS rust

FROM nvidia/cuda:12.5.0-devel-ubuntu22.04@sha256:4b46c69e223d971f0fb279fd6381a0f3a057e09ba6de08bfbf7db751b1ad6db1 AS build
ARG TARGETARCH
ARG PROVER_BACKEND=cuda
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_TOOLCHAIN=1.94.1 \
    PATH=/usr/local/cargo/bin:$PATH
RUN test "$TARGETARCH" = amd64 \
    && apt-get update && apt-get install -y --no-install-recommends \
       curl ca-certificates git build-essential pkg-config libssl-dev clang cmake \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo /usr/local/cargo
RUN test "$(rustc --version | awk '{print $2}')" = 1.94.1

# No pipe-to-shell installers or mutable "latest" toolchain selection. This
# archive was downloaded and hashed from the exact upstream release; its hash
# is not independent signature/provenance verification. See BUILD-INPUTS.md.
RUN curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
      --retry 3 --connect-timeout 20 --max-time 3600 \
      https://github.com/succinctlabs/rust/releases/download/succinct-1.85.0/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz \
      -o /tmp/sp1-toolchain.tar.gz \
    && echo 'e601270a28c5fa6cbbfada396ba9a5c7fdeb38fa65ce6b1059f03b952e7d7477  /tmp/sp1-toolchain.tar.gz' | sha256sum -c - \
    && mkdir -p /opt/sp1-toolchain \
    && tar -xzf /tmp/sp1-toolchain.tar.gz -C /opt/sp1-toolchain \
    && rm /tmp/sp1-toolchain.tar.gz \
    && rustup toolchain link succinct /opt/sp1-toolchain \
    && cargo install --locked --version '=4.2.1' sp1-cli

WORKDIR /build
# Deliberate source allowlist. No whole-repository COPY or host-generated ELF.
COPY crates/coherence-core/Cargo.toml crates/coherence-core/Cargo.toml
COPY crates/coherence-core/src crates/coherence-core/src
COPY crates/coherence-prover/program/Cargo.toml crates/coherence-prover/program/Cargo.lock crates/coherence-prover/program/
COPY crates/coherence-prover/program/src crates/coherence-prover/program/src
COPY crates/coherence-prover/service/Cargo.toml crates/coherence-prover/service/Cargo.lock crates/coherence-prover/service/
COPY crates/coherence-prover/service/src crates/coherence-prover/service/src

# SP1 4.2.1 does not copy an ELF here by default. Name the include_bytes! target
# explicitly and detect metadata/build commands that mutate the guest lock.
WORKDIR /build/crates/coherence-prover/program
RUN sha256sum Cargo.lock > /tmp/sp1-guest-lock.sha256 \
    && cargo prove build --locked --output-directory elf --elf-name riscv32im-succinct-zkvm-elf \
    && sha256sum -c /tmp/sp1-guest-lock.sha256
WORKDIR /build
# The service is its own workspace, excluded from the repository root workspace.
RUN case "$PROVER_BACKEND" in \
      cuda) cargo build --manifest-path crates/coherence-prover/service/Cargo.toml --target-dir /build/service-target --release --locked --features cuda ;; \
      cpu) cargo build --manifest-path crates/coherence-prover/service/Cargo.toml --target-dir /build/service-target --release --locked ;; \
      *) echo 'PROVER_BACKEND must be cuda or cpu' >&2; exit 1 ;; \
    esac

FROM nvidia/cuda:12.5.0-runtime-ubuntu22.04@sha256:75292ffaba88ea846d7f28261d4ed302fbe1124f10ff9da30e44034206916110 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 prover \
    && mkdir -p /data/.sp1 && chown -R 10001:10001 /data
COPY --from=build /build/service-target/release/coherence-prover-service /usr/local/bin/coherence-prover-service
ENV HOME=/data SP1_HOME=/data/.sp1 PORT=8080
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["coherence-prover-service"]
