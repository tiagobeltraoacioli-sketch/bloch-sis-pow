#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install the guard's test-only harness into a source tree (idempotent).
#
#   overlay.sh <guard-tree> <target-tree>
#
# Touches only cfg(test) code: copies engine/hf_replay_guard.rs, adds its
# `#[cfg(test)] mod` line to engine.rs, and widens six private items of the
# cfg(test) replay benchmark to pub(super). The shipped binary is unchanged.
set -euo pipefail
G="${1:?guard tree}"; T="${2:?target tree}"
E="$T/crates/bloch-pos-node/src/engine.rs"
RB="$T/crates/bloch-pos-node/src/engine/replay_bench.rs"
[ -f "$E" ] && [ -f "$RB" ] || { echo "overlay: $T lacks engine.rs/replay_bench.rs" >&2; exit 2; }
if [ "$(cd "$G" && pwd -P)" != "$(cd "$T" && pwd -P)" ]; then
  cp "$G/crates/bloch-pos-node/src/engine/hf_replay_guard.rs" "$T/crates/bloch-pos-node/src/engine/hf_replay_guard.rs"
fi
grep -q '^mod hf_replay_guard;' "$E" || \
  perl -0pi -e 's/(#\[cfg\(test\)\]\nmod replay_bench;\n)/$1\n\/\/\/ Hard-fork port guard: "gates off is byte-identical". `cfg(test)`, instrumentation only.\n#[cfg(test)]\nmod hf_replay_guard;\n/' "$E"
grep -q '^mod hf_replay_guard;' "$E" || { echo "overlay: could not anchor mod line in engine.rs" >&2; exit 2; }
perl -pi -e '
  s/^fn boot_engine\(/pub(super) fn boot_engine(/;
  s/^fn clone_manifest\(/pub(super) fn clone_manifest(/;
  s/^struct Generator \{/pub(super) struct Generator {/;
  s/^    fn new\(dir: &Path/    pub(super) fn new(dir: &Path/;
  s/^    fn block_at\(/    pub(super) fn block_at(/;
  s/^    manifest: Manifest,/    pub(super) manifest: Manifest,/;
' "$RB"
for pat in 'pub(super) fn boot_engine(' 'pub(super) fn clone_manifest(' 'pub(super) struct Generator {' 'pub(super) fn new(dir: &Path' 'pub(super) fn block_at(' 'pub(super) manifest: Manifest,'; do
  grep -qF "$pat" "$RB" || { echo "overlay: replay_bench.rs anchor missing: $pat" >&2; exit 2; }
done
