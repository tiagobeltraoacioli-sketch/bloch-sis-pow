#!/usr/bin/env bash
# repro-compare.sh <manifest-A.txt> <manifest-B.txt>
#
# Diff two host manifests produced by repro-manifest.sh. Exits non-zero on ANY
# divergence and prints exactly which field diverged. When narHash differs and
# both outpaths exist locally, runs diffoscope to localise the nondeterminism.
#
# "REPRODUCIBLE" is printed only when narHash (and, for images, image_sha256 and
# roothash) are identical across the two builders AND the two manifests agree on
# the flake.lock hash and the attr. See REPRO.md §"#9".
#
# Exit codes: 0 reproducible, 1 a compared field diverged, 2 the comparison could
# not be made (unreadable, incomparable, or missing the fields it rests on). 2 is
# NOT a pass — every "cannot tell" path here must land on it.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <manifest-A.txt> <manifest-B.txt>" >&2
  exit 2
fi
A="$1"; B="$2"

for f in "$A" "$B"; do
  [ -r "$f" ] || { echo "cannot read manifest: $f" >&2; exit 2; }
done

# `|| true` is load-bearing. A missing field is a NORMAL outcome — the image
# fields are absent from a plain node-package manifest — but this script runs
# under `set -o pipefail`, which turns grep's "no match" (exit 1) into the status
# of the whole pipeline, and `set -e` then kills the script at the first
# `va=$(field image_sha256 ...)`. That is what main did: for
# `.#packages.aarch64-linux.bloch` — the cheapest probe and the one REPRO.md tells
# you to run first — it printed "match narHash" and exited 1 with no message, i.e.
# reported NOT REPRODUCIBLE for a clean match. Braces keep the fallback inside the
# first pipeline stage so `head` still gets a (possibly empty) stream.
field() { { grep "^$1:" "$2" || true; } | sed "s/^$1:[[:space:]]*//" | head -1; }

diverged=0
report_field() {
  local name="$1"; local va vb
  va=$(field "$name" "$A"); vb=$(field "$name" "$B")
  # Only compare fields present in BOTH manifests (image fields are absent for
  # the plain node package).
  if [ -n "$va" ] && [ -n "$vb" ]; then
    if [ "$va" != "$vb" ]; then
      echo "DIVERGED  $name:"
      echo "    A ($A): $va"
      echo "    B ($B): $vb"
      diverged=1
    else
      echo "match     $name: $va"
    fi
  fi
}

# ── Same experiment? Checked FIRST, and fatal ───────────────────────────────
# Two builds are comparable only if they read the same inputs (flake.lock) and
# built the same thing (attr). This was a WARNING guarded by `[ -n "$la" ]`, so
# an EMPTY field — which is exactly what the old repro-manifest.sh wrote when
# flake.lock was missing — skipped the check entirely, and even a real mismatch
# only printed to stderr while the script went on to announce REPRODUCIBLE. The
# guard was silent in precisely the case it exists for. Empty is now refused as
# hard as a mismatch: an unknown input pin is not evidence of a matching one.
la=$(field flake.lock "$A"); lb=$(field flake.lock "$B")
if [ -z "$la" ] || [ -z "$lb" ]; then
  echo "INCONCLUSIVE: flake.lock hash missing from a manifest (A:'${la:-<none>}' B:'${lb:-<none>}')." >&2
  echo "Without it there is no evidence the two builders used the same inputs," >&2
  echo "so an identical narHash would not mean the build is reproducible." >&2
  echo "Re-run repro-manifest.sh on both hosts with the lock committed." >&2
  exit 2
fi
if [ "$la" != "$lb" ]; then
  echo "NOT COMPARABLE: flake.lock sha256 differs between builders — not the same inputs." >&2
  echo "    A ($A): $la" >&2
  echo "    B ($B): $lb" >&2
  echo "This is not a reproducibility result either way: the two hosts built from" >&2
  echo "different pins. Sync the lock and rebuild." >&2
  exit 2
fi
ta=$(field attr "$A"); tb=$(field attr "$B")
if [ -z "$ta" ] || [ -z "$tb" ]; then
  echo "INCONCLUSIVE: attr missing from a manifest (A:'${ta:-<none>}' B:'${tb:-<none>}')." >&2
  exit 2
fi
if [ "$ta" != "$tb" ]; then
  echo "NOT COMPARABLE: different flake attr ($ta vs $tb) — unlike outputs." >&2
  exit 2
fi

report_field narHash
report_field image_sha256
report_field roothash

# Guard against a false REPRODUCIBLE: narHash is the bit-for-bit test, so it MUST
# be present in both manifests and actually compared. If it is missing (build
# failed to write it, malformed manifest), report_field above silently skipped it
# and `diverged` is still 0 — do NOT let that read as "reproducible".
na=$(field narHash "$A"); nb=$(field narHash "$B")
if [ -z "$na" ] || [ -z "$nb" ]; then
  echo >&2
  echo "INCONCLUSIVE: narHash missing from a manifest (A:'${na:-<none>}' B:'${nb:-<none>}')." >&2
  echo "Cannot claim REPRODUCIBLE without a narHash comparison. Re-run repro-manifest.sh." >&2
  exit 2
fi

echo
if [ "$diverged" -eq 0 ]; then
  echo "REPRODUCIBLE: narHash identical across builders."
  grep -E '^(image_sha256|roothash):' "$A" || true
  exit 0
fi

echo "NOT REPRODUCIBLE: a field diverged (see above)."
pa=$(field outpath "$A"); pb=$(field outpath "$B")
if command -v diffoscope >/dev/null 2>&1 && [ -e "$pa" ] && [ -e "$pb" ]; then
  echo "Running diffoscope on the outpaths -> diffoscope-diff.txt"
  diffoscope "$pa" "$pb" | tee diffoscope-diff.txt || true
fi
exit 1
