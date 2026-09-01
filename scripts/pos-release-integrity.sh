#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# pos-release-integrity.sh — CI gate for G8, "release integrity"
# (docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md §11; runbook + measured
# baseline in deploy/RELEASE-INTEGRITY.md).
#
# WHY THIS GATE EXISTS (both incidents are documented, not hypothetical):
#   - The published Genesis-3 release WAS the broken binary — commit f819e87f,
#     an abandoned branch — while the network fixes lived only on an
#     unpublished branch on the boxes. Fresh nodes built from the release froze
#     at block 10802 ("trailing bytes in block body"). Fleet and release had
#     diverged and nobody noticed until nodes died.
#   - The 2026-08-11 fleet survey found three boxes running three different
#     binaries, all reporting the same version string.
#
# WHAT IT CHECKS (all blocking):
#   1. Lockfiles are honest: both PoS workspaces resolve with --locked and the
#      committed Cargo.locks do not drift during the build.
#   2. The build is deterministic where determinism is promised: two clean
#      builds of bloch-pos from the same source path, same toolchain, same
#      stamp produce bit-identical binaries. (Path-INdependence is measured
#      and known-false on stable cargo — -Cmetadata hashes the absolute
#      manifest path — which is why releases build at the canonical /build
#      path in a container; see deploy/RELEASE-INTEGRITY.md §3.)
#   3. The stamp is live: `bloch-pos --version` reports the exact commit the
#      CI is building. A binary that cannot say what it is cannot be compared
#      against a fleet, which is how the G3 divergence stayed invisible.
#
# Usage: bash scripts/pos-release-integrity.sh    (from anywhere in the repo)
# Runtime: ~1 minute (the PoS skeleton workspace is small by design).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

NODE_DIR="$REPO_ROOT/crates/bloch-pos-node"
COMMITTEE_DIR="$REPO_ROOT/crates/bloch-pos-committee"

fail() { echo "pos-release-integrity: FAIL — $*" >&2; exit 1; }

# ── 0. Preconditions ─────────────────────────────────────────────────────────
[ -f "$NODE_DIR/rust-toolchain.toml" ] \
  || fail "crates/bloch-pos-node/rust-toolchain.toml is missing. The release \
binary needs a pinned compiler; restore the pin (and bump it only in its own \
commit)."
PINNED="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$NODE_DIR/rust-toolchain.toml")"
echo "pinned toolchain: $PINNED"

# rustup resolves the pin per-directory; assert it actually took effect, so a
# runner without the pinned toolchain fails loudly instead of building with
# whatever is lying around.
ACTIVE="$(cd "$NODE_DIR" && rustc --version)"
echo "active toolchain in crate dir: $ACTIVE"
case "$ACTIVE" in
  *"$PINNED"*) : ;;
  *) fail "active rustc ($ACTIVE) is not the pinned $PINNED. Install it: \
rustup toolchain install $PINNED" ;;
esac

# ── 1. Lockfile honesty ──────────────────────────────────────────────────────
# --locked fails if Cargo.lock would need any change; the git diff afterwards
# catches a lockfile the build itself rewrote. Both PoS workspaces are
# standalone (deliberately outside the G3 node workspace), so both are checked.
( cd "$COMMITTEE_DIR" && cargo metadata --format-version 1 --locked >/dev/null ) \
  || fail "bloch-pos-committee Cargo.lock is stale — commit the lockfile change deliberately."
( cd "$NODE_DIR" && cargo metadata --format-version 1 --locked >/dev/null ) \
  || fail "bloch-pos-node Cargo.lock is stale — commit the lockfile change deliberately."
echo "lockfiles: ok (--locked resolves cleanly in both PoS workspaces)"

# ── 2. Deterministic double build ────────────────────────────────────────────
# Same source path, two fresh target dirs. BLOCH_BUILD_COMMIT is passed
# explicitly so the stamp is identical even on a dirty CI tree, and so this is
# the same code path a container release build uses.
COMMIT="$(git rev-parse --short=12 HEAD)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pos-repro.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

build() { # $1 = target dir
  ( cd "$NODE_DIR" && \
    BLOCH_BUILD_COMMIT="$COMMIT" cargo build --release --locked \
      --target-dir "$1" )
}

echo "building bloch-pos twice at commit $COMMIT …"
build "$WORK/t1"
build "$WORK/t2"

sha() { # portable sha256 of $1
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
H1="$(sha "$WORK/t1/release/bloch-pos")"
H2="$(sha "$WORK/t2/release/bloch-pos")"
echo "build 1 sha256: $H1"
echo "build 2 sha256: $H2"
[ "$H1" = "$H2" ] || fail "two clean builds of the same commit differ. The \
build is non-deterministic — find the input that changed (toolchain, \
lockfile, RUSTFLAGS, env leaking into build.rs) BEFORE cutting any release. \
Compare with: diff <(nm t1/release/bloch-pos) <(nm t2/release/bloch-pos)"
echo "determinism: ok (bit-identical, same path)"

# ── 3. Stamp is live and truthful ────────────────────────────────────────────
VOUT="$("$WORK/t1/release/bloch-pos" --version)"
echo "--version: $VOUT"
case "$VOUT" in
  *"$COMMIT"*) : ;;
  *) fail "--version does not contain the built commit $COMMIT. The build.rs \
stamp is broken or bypassed; a fleet running this binary is unidentifiable." ;;
esac

# The lockfiles must not have been rewritten by the builds above.
git diff --exit-code -- \
  "$NODE_DIR/Cargo.lock" "$COMMITTEE_DIR/Cargo.lock" \
  || fail "a build rewrote a committed Cargo.lock."

# ── 4. The binary can state which consensus flag days it knows ───────────────
# A release is only comparable to a fleet if both can answer "which activation
# epochs do you implement?". Until `selfcheck --json` existed, neither could:
# `selfcheck` printed `self-check passed` and silently IGNORED `--json`, so the
# only way to know whether a box would follow a flag day was to arm it and
# watch. That is how genesis4-node-20260814 shipped — it predated every armed
# gate, diverged on schedule, and its release page said nothing, because there
# was no artifact that could say it.
#
# Three things are blocking here:
#   a. the statement exists and parses;
#   b. it is COMPLETE — every *_ACTIVATION_EPOCH in params.rs appears in it.
#      An incomplete statement is worse than none: two binaries that genuinely
#      disagree would publish the same gates_digest and a fleet sweep would
#      call them compatible;
#   c. the digest is stable across the two identical builds above, since the
#      fleet sweep compares it as a string.
GJ="$($WORK/t1/release/bloch-pos selfcheck --json 2>/dev/null)" \
  || fail "\`bloch-pos selfcheck --json\` failed. The release binary cannot \
state which consensus gates it links, so it cannot be compared against the \
fleet before a flag day."

case "$GJ" in
  *'"gates_digest"'*) : ;;
  *) fail "\`selfcheck --json\` produced no gates_digest. Either the flag is \
being ignored again (the exact defect this gate replaces — the pre-2026-09 \
binary accepted --json and printed 'self-check passed'), or the statement was \
removed." ;;
esac

# (b) completeness, checked here as well as in the unit test, because CI must
# refuse to CUT a release with a drifted table even if tests were skipped.
DECLARED="$(grep -c '^pub const [A-Za-z0-9_]*_ACTIVATION_EPOCH' \
  "$COMMITTEE_DIR/src/params.rs" || true)"
STATED="$(printf '%s' "$GJ" | grep -c '"name":' || true)"
[ "$DECLARED" -gt 0 ] \
  || fail "found zero \`pub const *_ACTIVATION_EPOCH\` in params.rs. The \
declaration style changed and this check no longer sees them — as written it \
would wave through any gate table at all. Fix the pattern."
[ "$DECLARED" = "$STATED" ] \
  || fail "params.rs declares $DECLARED activation gate(s) but \
\`selfcheck --json\` states $STATED. The CONSENSUS_GATES table in \
crates/bloch-pos-node/src/main.rs is out of sync. An incomplete gates_digest \
makes incompatible binaries look identical to the fleet sweep. Add the \
missing row(s); do NOT change params.rs to make this pass."

GD="$(printf '%s' "$GJ" | sed -n 's/.*"gates_digest": "\([0-9a-f]*\)".*/\1/p')"
GD2="$("$WORK/t2/release/bloch-pos" selfcheck --json 2>/dev/null \
  | sed -n 's/.*"gates_digest": "\([0-9a-f]*\)".*/\1/p')"
[ -n "$GD" ] && [ "$GD" = "$GD2" ] \
  || fail "gates_digest differs between two identical builds ($GD vs $GD2). \
The fleet sweep compares this as a string; a digest that is not a pure \
function of the source is useless."
echo "consensus gates: ok ($DECLARED gate(s) declared and stated, digest $GD)"

echo
echo "pos-release-integrity: PASS — locked, deterministic (same-path),"
echo "commit-stamped, gate-complete. Reference values for THIS runner's platform:"
echo "  bloch-pos @ $COMMIT : $H1"
echo "  gates_digest        : $GD"
echo "PUBLISH THE gates_digest ON THE RELEASE PAGE. It is what an operator"
echo "compares a box against with scripts/fleet-gate-sweep.sh before arming a"
echo "flag day, and the only thing that makes 'will this node follow?' answerable"
echo "NOTE: this hash is platform- and path-scoped. The publishable reference"
echo "hash is the canonical /build container build — deploy/RELEASE-INTEGRITY.md §3."
