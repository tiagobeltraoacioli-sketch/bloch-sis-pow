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
#   1. Lockfiles are honest: the ONE lockfile cargo actually reads for the PoS
#      crates — the root Cargo.lock — resolves with --locked and does not drift
#      during the build, and no member carries a dead lockfile beside it.
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
# Usage: bash scripts/pos-release-integrity.sh                (from anywhere)
#        bash scripts/pos-release-integrity.sh --locks-only   (section 1 only)
#
# --locks-only exists so the lockfile guard can be exercised on its own, in a
# second or two and without a compiler, by
# scripts/pos-release-integrity.selftest.py — which drives THIS script against
# synthetic workspaces rather than a copy of its logic, so the selftest cannot
# drift away from the guard it certifies.
#
# Runtime: ~1 minute (the PoS skeleton workspace is small by design).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

fail() { echo "pos-release-integrity: FAIL — $*" >&2; exit 1; }

# The root Cargo.lock is the only lockfile cargo reads for this workspace (see
# section 1), so it is the only one a build can rewrite and the only one worth
# diffing. Shared by section 1 — where a lock that is ALREADY dirty is caught
# before a minute of building — and section 3, which is the real point: the
# build must not have touched it.
assert_root_lock_undrifted() { # $1 = what a difference would mean
  git diff --exit-code -- "$REPO_ROOT/Cargo.lock" >/dev/null \
    || fail "the committed root Cargo.lock differs from the working tree: $1"
}

NODE_DIR="$REPO_ROOT/crates/bloch-pos-node"

LOCKS_ONLY=0
case "${1:-}" in
  --locks-only) LOCKS_ONLY=1 ;;
  "")           : ;;
  *)            fail "unknown argument '$1' (only --locks-only is accepted)." ;;
esac

# ── 1. Lockfile honesty ──────────────────────────────────────────────────────
# THIS SECTION USED TO AIM AT FILES CARGO NEVER OPENS. It resolved --locked
# from inside each PoS crate directory and then diffed
# crates/bloch-pos-node/Cargo.lock and crates/bloch-pos-committee/Cargo.lock,
# on the belief — still repeated in the old comments and in
# deploy/RELEASE-INTEGRITY.md — that the two crates were standalone
# workspaces. They are not: both are `members` of the root virtual manifest,
# so cargo resolves them, and every other member, against the ROOT Cargo.lock
# alone. A member's own Cargo.lock is dead weight. The post-build drift diff
# therefore watched two files nothing writes and could not fail: measured on
# this tree, appending a line to the root Cargo.lock left the old diff at
# exit 0. Six such dead lockfiles were deleted with this change.
#
# What runs now:
#   (a) one --locked resolve of the ROOT workspace, invoked from the node crate
#       dir so rustup still applies the pinned toolchain (there is no root
#       rust-toolchain.toml, deliberately — see that file's header) while cargo
#       walks up and validates the root lock;
#   (b) an assert that the two PoS crates are still members of that workspace,
#       so a crate that grows its own [workspace] table fails here instead of
#       silently going unguarded — it would need its own lock back, and this
#       guard updated in the same commit;
#   (c) a hard failure on any committed Cargo.lock inside a member directory,
#       because such a file reads as authoritative and is not.
#
# NOTE: --no-deps must NOT be added here. Measured: `cargo metadata --no-deps
# --locked` exits 0 against a stale lock — it skips resolution, and with it the
# --locked check. The full resolve is the check.
LOCK_META="$(mktemp "${TMPDIR:-/tmp}/pos-lock-meta.XXXXXX")"
trap 'rm -f "$LOCK_META"' EXIT
( cd "$NODE_DIR" && cargo metadata --format-version 1 --locked ) > "$LOCK_META" \
  || fail "the root Cargo.lock is stale — it does not resolve with --locked. \
Commit the lockfile change deliberately (cargo update -p <crate>), never as a \
build side effect."

LOCK_META_PATH="$LOCK_META" REPO_ROOT="$REPO_ROOT" python3 - <<'PY' \
  || fail "workspace/lockfile layout is not what this guard assumes (above)."
import json, os, sys

repo_root = os.path.realpath(os.environ["REPO_ROOT"])
with open(os.environ["LOCK_META_PATH"], encoding="utf-8") as fh:
    meta = json.load(fh)

ws_root = os.path.realpath(meta["workspace_root"])
if ws_root != repo_root:
    print(f"  resolved workspace root is {ws_root}, expected the repo root")
    print(f"  {repo_root}. The PoS crates moved out of this workspace; point")
    print("  this guard at the lockfile that now governs them.")
    sys.exit(1)

member_ids = set(meta["workspace_members"])
members = {p["name"]: p["manifest_path"] for p in meta["packages"]
           if p["id"] in member_ids}

# Fail-closed on a rename or a crate that grew its own [workspace]: a guard
# that silently stops covering its subject is the failure mode this repo has
# already been bitten by three times.
missing = [n for n in ("bloch-pos-node", "bloch-pos-committee") if n not in members]
if missing:
    print(f"  {', '.join(missing)} is not a member of the root workspace.")
    print("  Either it was renamed, or it now carries its own [workspace]")
    print("  table — in which case it needs its own committed Cargo.lock and")
    print("  this guard must check that lock too. Update both in one commit.")
    sys.exit(1)

stray = sorted(
    os.path.relpath(os.path.join(os.path.dirname(m), "Cargo.lock"), repo_root)
    for m in members.values()
    if os.path.exists(os.path.join(os.path.dirname(m), "Cargo.lock"))
)
if stray:
    print("  workspace members carry their own Cargo.lock, which cargo never")
    print("  reads — the root Cargo.lock governs every member:")
    for s in stray:
        print(f"    {s}")
    print("  Delete them. A dead lockfile beside a live crate is read as")
    print("  authoritative by humans and by guards; that is exactly the bug")
    print("  this section was written to stop repeating.")
    sys.exit(1)

print(f"lockfiles: ok — root Cargo.lock resolves --locked and governs all "
      f"{len(members)} workspace members; no dead per-member lockfiles")
PY

assert_root_lock_undrifted "it is dirty before the build even starts. Commit \
the lockfile change (or restore it) so the post-build drift check in section 3 \
means something."

if [ "$LOCKS_ONLY" = 1 ]; then
  echo "pos-release-integrity: PASS (--locks-only)"
  exit 0
fi

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

# ── 2. Deterministic double build ────────────────────────────────────────────
# Same source path, two fresh target dirs. BLOCH_BUILD_COMMIT is passed
# explicitly so the stamp is identical even on a dirty CI tree, and so this is
# the same code path a container release build uses.
COMMIT="$(git rev-parse --short=12 HEAD)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pos-repro.XXXXXX")"
trap 'rm -rf "$WORK" "$LOCK_META"' EXIT

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

# The lockfile must not have been rewritten by the builds above. Section 1
# proved it was clean going in, so a difference here is the build's doing.
assert_root_lock_undrifted "a build rewrote it. Find what resolved differently \
before cutting any release."

echo
echo "pos-release-integrity: PASS — locked, deterministic (same-path),"
echo "commit-stamped. Reference hashes for THIS runner's platform:"
echo "  bloch-pos @ $COMMIT : $H1"
echo "NOTE: this hash is platform- and path-scoped. The publishable reference"
echo "hash is the canonical /build container build — deploy/RELEASE-INTEGRITY.md §3."
