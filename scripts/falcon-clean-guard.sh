#!/usr/bin/env bash
# falcon-clean-guard.sh — CI gate for PoS finding F1
# (docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md §3.2).
#
# WHAT: fails the pipeline if the workspace's resolved feature set for
# `pqcrypto-falcon` includes "avx2" or "neon".
#
# WHY: those features compile and runtime-dispatch Falcon SIGNING to PQClean's
# native floating-point variants (AVX2 doubles on x86_64, `typedef double fpr`
# on aarch64). A PoS validator signs on a publicly known schedule, so signing
# must run PQClean's `clean` variant only — integer-emulated IEEE-754,
# constant-time by construction. The workspace pins
# `default-features = false`, but Cargo features are ADDITIVE: any member or
# future dependency re-enabling the defaults silently restores native-FP
# dispatch for every binary. This guard catches that at the dependency-graph
# level; the `falcon_native_fp_variants_are_not_linked` test in bloch-crypto
# catches it at the linked-binary level. Both must stay green.
#
# Usage: bash scripts/falcon-clean-guard.sh   (run from anywhere in the repo)
set -euo pipefail
cd "$(dirname "$0")/.."

# NOTE: cargo's JSON goes through a temp file, not a pipe — `python3 -` takes
# its SCRIPT from stdin (the heredoc), so piping the JSON in as well would
# leave json.load reading an empty stream.
meta_json="$(mktemp)"
trap 'rm -f "$meta_json"' EXIT
cargo metadata --format-version 1 --locked > "$meta_json"

META_JSON_PATH="$meta_json" python3 - <<'PY'
import json, os, sys

with open(os.environ["META_JSON_PATH"], encoding="utf-8") as fh:
    meta = json.load(fh)
nodes = (meta.get("resolve") or {}).get("nodes") or []
found = []
for node in nodes:
    # node id formats vary across cargo versions; match on the package name.
    ident = node.get("id", "")
    if "pqcrypto-falcon" in ident:
        found.append((ident, sorted(node.get("features") or [])))

if not found:
    # A silent rename/removal must not turn this guard into a no-op.
    print("falcon-clean-guard: FAIL — pqcrypto-falcon not found in the resolved")
    print("dependency graph. If it was renamed or removed, update this guard")
    print("(and the tripwire test in crates/bloch-crypto) in the same change.")
    sys.exit(1)

bad = False
for ident, features in found:
    fp = sorted(set(features) & {"avx2", "neon"})
    if fp:
        bad = True
        print(f"falcon-clean-guard: FAIL — {ident} resolves with native")
        print(f"floating-point features {fp} (full set: {features}).")
    else:
        print(f"falcon-clean-guard: ok — {ident} features: {features}")

if bad:
    print()
    print("Falcon signing would dispatch to PQClean's native floating-point")
    print("variants. Under PoS the validator signs on a PUBLIC schedule and must")
    print("use the integer-only constant-time `clean` variant exclusively.")
    print("Find the declaration that re-enabled the defaults with:")
    print("    cargo tree -i pqcrypto-falcon -e features")
    print("and restore `default-features = false, features = [\"std\"]`.")
    print("See docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md §3.2 (finding F1).")
    sys.exit(1)

print("falcon-clean-guard: PASS — Falcon-1024 signing is pinned to the")
print("constant-time integer-only `clean` implementation.")
PY
