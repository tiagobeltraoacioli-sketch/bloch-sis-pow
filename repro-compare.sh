#!/usr/bin/env bash
# repro-compare.sh <manifest-A.txt> <manifest-B.txt>
#
# Diff two host manifests produced by repro-manifest.sh. Exits non-zero on ANY
# divergence and prints exactly which field diverged. When narHash differs and
# both outpaths exist locally, runs diffoscope to localise the nondeterminism.
#
# "REPRODUCIBLE" is printed only when narHash (and, for images, image_sha256 and
# roothash) are identical across the two builders. See REPRO.md §"#9".
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <manifest-A.txt> <manifest-B.txt>" >&2
  exit 2
fi
A="$1"; B="$2"

for f in "$A" "$B"; do
  [ -r "$f" ] || { echo "cannot read manifest: $f" >&2; exit 2; }
done

field() { grep "^$1:" "$2" | sed "s/^$1:[[:space:]]*//" | head -1; }

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

# Sanity: warn (do not fail) if the two builders used different flake.lock or attr.
la=$(field flake.lock "$A"); lb=$(field flake.lock "$B")
if [ -n "$la" ] && [ "$la" != "$lb" ]; then
  echo "WARNING: flake.lock sha256 differs between builders — not the same inputs!" >&2
fi
ta=$(field attr "$A"); tb=$(field attr "$B")
if [ -n "$ta" ] && [ "$ta" != "$tb" ]; then
  echo "WARNING: different flake attr ($ta vs $tb) — comparing unlike outputs." >&2
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
