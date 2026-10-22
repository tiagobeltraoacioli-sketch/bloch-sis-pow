# syntax=docker/dockerfile:1.7
# Test-only extension of the canonical build image. Never export this binary.
ARG BUILD_IMAGE
FROM ${BUILD_IMAGE}
RUN apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends python3 git rsync \
 && rm -rf /var/lib/apt/lists/*
# Tests read tracked docs, deploy files and fuzz fixtures omitted by the release
# image. /workspace is an explicitly supported path in the buildinfo leak test.
WORKDIR /workspace
COPY . .
ENV CARGO_TARGET_DIR=/build/target
