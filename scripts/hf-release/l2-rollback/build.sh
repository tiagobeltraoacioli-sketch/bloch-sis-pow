#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Reproducible build of the L2 program ROLLBACK emergency release.
#
#   build.sh <base-commit> <out-dir> --swap-epoch S --rollback-epoch R --publish-epoch P
#            [--head-reset reset.json] [--min-lead N] [--candidate-pins]
#
# 1. clones <base-commit> (the SHIPPED swap release) into <out-dir>/src;
# 2. runs arm.py there and commits the result with a fixed author and the base
#    commit's dates, so every builder gets the same armed commit hash;
# 3. builds it in the canonical release container
#    (scripts/build-pos-release-container.sh) into <out-dir>/builder-a;
# 4. writes <out-dir>/RELEASE.txt (base, armed commit, manifest, binary digest).
#
# A second builder runs the same command on another host and then
#   scripts/compare-pos-release-builds.sh <A>/builder-a <B>/builder-a
# Qualification: scripts/hf-release/qualify.sh <armed-commit> ... (see the checklist).
# Never signs, publishes or deploys. Exit 0 only if every step succeeded.
set -euo pipefail
base="${1:?usage: build.sh <base-commit> <out-dir> --swap-epoch S --rollback-epoch R --publish-epoch P [...]}"
out="${2:?out-dir}"; shift 2
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
[ ! -e "$out" ] || { echo "build.sh: $out exists; use a new directory" >&2; exit 1; }
mkdir -p "$out"; out="$(cd "$out" && pwd)"
git -C "$repo" cat-file -e "$base^{commit}"
git clone -q --no-hardlinks "$repo" "$out/src"
cd "$out/src"
git checkout -q --detach "$base"
python3 -I "$here/arm.py" --tree . --manifest "$out/manifest.json" "$@" > /dev/null
# arm.py of the base must be the one used: compare, so a builder cannot use a newer tool by accident.
cmp -s "$here/arm.py" scripts/hf-release/l2-rollback/arm.py || echo "build.sh: WARN: arm.py differs from the base commit's copy" >&2
when="$(git log -1 --format=%cI "$base")"
R="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["rollback_epoch"])' "$out/manifest.json")"
git add -A crates/bloch-pos-committee/src
GIT_AUTHOR_NAME="bloch release kit" GIT_AUTHOR_EMAIL="release@invalid" GIT_COMMITTER_NAME="bloch release kit" \
GIT_COMMITTER_EMAIL="release@invalid" GIT_AUTHOR_DATE="$when" GIT_COMMITTER_DATE="$when" \
  git -c commit.gpgsign=false commit -q -m "EMERGENCY: L2 program rollback at e$R (arm.py, manifest sha256 $(sha256sum "$out/manifest.json" | cut -c1-16))"
armed="$(git rev-parse HEAD)"
git diff --stat "$base" "$armed" > "$out/armed.diffstat"
scripts/build-pos-release-container.sh "$out/builder-a" 2>&1 | tee "$out/build.log"
bin_sha="$(sha256sum "$out"/builder-a/bloch-pos* 2>/dev/null | head -1 | cut -d' ' -f1 || true)"
{
  echo "base_commit=$base"
  echo "armed_commit=$armed"
  echo "manifest_sha256=$(sha256sum "$out/manifest.json" | cut -d' ' -f1)"
  echo "bloch_pos_sha256=${bin_sha:-see builder-a}"
  echo "built_at=$(date -u +%FT%TZ) host=$(hostname)"
} > "$out/RELEASE.txt"
cat "$out/RELEASE.txt"
