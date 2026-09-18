# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-or-later
# Canonical bloch-pos binary build. The build context must be a git archive of
# the release commit; scripts/build-pos-release-container.sh enforces that.
FROM rust:1.94-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS build

ARG BLOCH_BUILD_COMMIT
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_SNAPSHOT=20260917T000000Z

WORKDIR /build

# Freeze the native build toolchain to one Debian archive view. Cargo inputs
# remain locked by Cargo.lock and crate checksums; the Rust image is pinned by
# digest above. A snapshot outage must fail, never fall back to a live mirror.
RUN printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s bookworm main\n' "$DEBIAN_SNAPSHOT" \
      > /etc/apt/sources.list \
 && rm -f /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      build-essential clang cmake libclang-dev libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

COPY . .

RUN case "$BLOCH_BUILD_COMMIT" in \
      ''|*[!0-9a-f]*) echo 'BLOCH_BUILD_COMMIT must be a lowercase hexadecimal commit' >&2; exit 1 ;; \
    esac \
 && test "${#BLOCH_BUILD_COMMIT}" -eq 40 \
 && case "$SOURCE_DATE_EPOCH" in ''|*[!0-9]*) exit 1 ;; esac \
 && pin="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' crates/bloch-pos-node/rust-toolchain.toml)" \
 && rustc --version | grep -F "rustc $pin " \
 && test ! -e crates/bloch-pos-node/Cargo.lock \
 && test ! -e crates/bloch-pos-committee/Cargo.lock

ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
RUN BLOCH_BUILD_COMMIT="$BLOCH_BUILD_COMMIT" cargo build \
      --release --locked -p bloch-pos-node --bin bloch-pos

RUN set -eu; \
    mkdir /release; \
    cp target/release/bloch-pos /release/bloch-pos; \
    chmod 0755 /release/bloch-pos; \
    binary_sha="$(sha256sum /release/bloch-pos | awk '{print $1}')"; \
    printf '%s  bloch-pos\n' "$binary_sha" > /release/SHA256SUMS; \
    version="$(/release/bloch-pos --version)"; \
    printf '%s\n' "$version" | grep -F "${BLOCH_BUILD_COMMIT%${BLOCH_BUILD_COMMIT#????????????}}"; \
    { \
      printf 'artifact_kind=canonical-container-candidate\n'; \
      printf 'source_commit=%s\n' "$BLOCH_BUILD_COMMIT"; \
      printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"; \
      printf 'debian_snapshot=%s\n' "$DEBIAN_SNAPSHOT"; \
      printf 'target=%s\n' "$(rustc -vV | sed -n 's/^host: //p')"; \
      printf 'binary_sha256=%s\n' "$binary_sha"; \
      printf 'signed=false\n'; \
      printf 'deployment_authorized=false\n'; \
    } > /release/BUILD-INFO

FROM scratch AS export
COPY --from=build /release/ /
