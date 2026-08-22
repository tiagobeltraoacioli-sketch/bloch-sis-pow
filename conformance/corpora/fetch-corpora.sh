#!/usr/bin/env bash
# Fetch the pinned reference corpora (PINS.toml) into $CORPORA_DIR (default:
# ~/.cache/bloch-conformance). Never writes into the repo. After a first fetch
# of a corpus whose manifest does not exist yet, generates it; when a manifest
# exists, VERIFIES against it and fails loudly on mismatch — a run over an
# unverified corpus must refuse to report a rate (spec §5).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="${CORPORA_DIR:-$HOME/.cache/bloch-conformance}"
mkdir -p "$DIR"

fetch() { # name repo commit [sparse-subset]
    local name="$1" repo="$2" commit="$3" subset="${4:-}"
    local dst="$DIR/$name"
    if [ ! -d "$dst/.git" ]; then
        if [ -n "$subset" ]; then
            git clone --filter=blob:none --no-checkout "$repo" "$dst"
            git -C "$dst" sparse-checkout set "$subset"
        else
            git clone --no-checkout "$repo" "$dst"
        fi
    fi
    git -C "$dst" fetch origin "$commit"
    git -C "$dst" checkout --detach "$commit"
    echo "$name @ $(git -C "$dst" rev-parse HEAD)"
}

manifest() { # name subdir manifest-file
    local name="$1" sub="$2" mf="$HERE/manifests/$3"
    ( cd "$DIR/$name/$sub" &&
      if [ -f "$mf" ]; then
          shasum -a 256 -c "$mf" --quiet && echo "$name: manifest OK"
      else
          find . -type f ! -path './.git/*' -print0 | sort -z | xargs -0 shasum -a 256 > "$mf"
          echo "$name: manifest GENERATED at $mf — commit it"
      fi )
}

# ethereum/tests at this commit ships the maintained state tests as a PREBUILT
# TARBALL, not a directory tree (measured 2026-08-22 — see PINS.toml). Fetch the
# tarball, pin it by sha256, extract, and manifest the extracted tree.
fetch ethereum-tests https://github.com/ethereum/tests.git c67e485ff8b5be9abc8ad15345ec21aa22e290d9 fixtures_general_state_tests.tgz
TARBALL="$DIR/ethereum-tests/fixtures_general_state_tests.tgz"
echo "82bc3cb1c23f48b2b8a2b3d9cb5d9b96ddf6c31683f75368173bee3b25a24274  $TARBALL" | shasum -a 256 -c -
mkdir -p "$DIR/ethereum-tests-extracted"
tar -xzf "$TARBALL" -C "$DIR/ethereum-tests-extracted"
manifest ethereum-tests-extracted GeneralStateTests ethereum-tests-c67e485f.sha256

fetch anza-sbpf https://github.com/anza-xyz/sbpf.git 2510663bb8d894e8e3094be351e4bb4b604f1f84
manifest anza-sbpf . anza-sbpf-2510663b.sha256

# NOT branch HEAD: vm_interp was deleted upstream in af5e637b (2026-02-20), so
# HEAD yields an EMPTY vm_interp. 395c84ae is the last commit carrying the
# 108811 fixtures. See PINS.toml for the measurement. Guard against a silent
# empty checkout — an empty corpus is the worst possible input to a conformance
# report (it passes).
fetch firedancer-test-vectors https://github.com/firedancer-io/test-vectors.git 395c84aeadf5d14a2c00223395179a123ceeb266 vm_interp
test "$(find "$DIR/firedancer-test-vectors/vm_interp" -type f | wc -l)" -gt 0 \
    || { echo "FATAL: vm_interp checkout is EMPTY — wrong pin"; exit 1; }
manifest firedancer-test-vectors vm_interp firedancer-vm-interp-395c84ae.sha256
