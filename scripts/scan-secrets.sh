#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run only after ci-install-scanner.sh has verified the pinned executable.
set -euo pipefail
cd "$(dirname "$0")/.."
scanner="${CI_TOOLS_BIN:-$HOME/.local/bin}/gitleaks"
repository="$PWD"
source="$repository"
work=""
cleanup() { if [ -n "$work" ]; then rm -rf -- "$work"; fi; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mode="${1:-}"
case "$mode" in
  history)
    [ "$(git rev-parse --is-shallow-repository)" = false ] || {
      echo "secret scan: full history requires a non-shallow checkout" >&2
      exit 1
    }
    scope=(--log-opts=--all)
    ;;
  tree)
    scope=(--no-git)
    umask 077
    work="$(mktemp -d "${TMPDIR:-/tmp}/bloch-secret-tree.XXXXXX")"
    source="$work/source"
    mkdir "$source"
    python3 scripts/prepare-secret-scan-tree.py "$source"
    ;;
  *) echo "usage: scan-secrets.sh history|tree" >&2; exit 2 ;;
esac
baseline=".gitleaks-${mode}-baseline.json"
[ -f "$baseline" ] || { echo "secret scan: missing reviewed $mode baseline" >&2; exit 1; }
[ -x "$scanner" ] || { echo "secret scan: verified scanner is not installed" >&2; exit 1; }
baseline="$repository/$baseline"
if [ "$mode" = tree ]; then
    python3 scripts/prepare-secret-scan-baseline.py "$source" \
      "$repository/.gitleaks-tree-baseline-files.json" "$baseline" "$work/baseline.json"
    baseline="$work/baseline.json"
fi
cd "$source"
"$scanner" detect --source . --config "$repository/.gitleaks.toml" --no-banner --redact \
  --baseline-path "$baseline" "${scope[@]}"
