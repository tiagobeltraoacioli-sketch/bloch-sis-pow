# OSS-Fuzz build image for the Bloch node fuzzers.
# base-builder-rust ships a pinned nightly Rust + cargo-fuzz + the sanitizer
# runtimes, so nothing extra needs installing for a pure-Rust workspace.
FROM gcr.io/oss-fuzz-base/base-builder-rust

# Clone the node repo. OSS-Fuzz builds from a public checkout; the fuzz crate
# lives at fuzz/ and path-depends on the workspace members + the vendored
# pqcrypto-internals fork (via [patch.crates-io]), all present in this tree.
RUN git clone --depth 1 https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow.git bloch

WORKDIR bloch
COPY build.sh $SRC/
