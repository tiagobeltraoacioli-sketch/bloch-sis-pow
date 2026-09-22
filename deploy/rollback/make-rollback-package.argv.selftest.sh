#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regression tests for rollback argument preservation.  The rollback drop-in
# must not replace a service command with a bare bloch-pos binary: validators
# need the exact arguments of the process they replace.  Arguments are stored
# NUL-delimited and consumed by a launcher without shell re-parsing.
#
# This test assembles a package with disposable signing keys.  It never writes
# to /opt or /etc and never starts, stops or restarts a service.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
REPO_ROOT="$(pwd)"
ASSEMBLER="$REPO_ROOT/deploy/rollback/make-rollback-package.sh"

command -v minisign >/dev/null || {
  echo "FAIL: minisign is required for rollback argv self-tests"
  exit 1
}

W="$(mktemp -d "${TMPDIR:-/tmp}/rollback-argv-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT
fails=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }

# Supply the Linux sha256sum interface when this test runs on macOS.
mkdir -p "$W/bin"
REAL_SHA256SUM="$(command -v sha256sum || true)"
REAL_SHASUM="$(command -v shasum || true)"
if [ -z "$REAL_SHA256SUM" ] && [ -z "$REAL_SHASUM" ]; then
  echo "FAIL: no SHA-256 implementation is available"
  exit 1
fi
export REAL_SHA256SUM REAL_SHASUM
cat > "$W/bin/sha256sum" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [ -n "${REAL_SHA256SUM:-}" ]; then
  exec "$REAL_SHA256SUM" "$@"
fi
if [ "${1:-}" = -c ]; then
  exec "$REAL_SHASUM" -a 256 -c "$2"
fi
exec "$REAL_SHASUM" -a 256 "$@"
SHIM
chmod 0755 "$W/bin/sha256sum"
export PATH="$W/bin:$PATH"

minisign -G -W -f -p "$W/release.pub" -s "$W/release.key" >/dev/null 2>&1

STAMP='0.0.1-argv-selftest (abcdef123456)'
cat > "$W/bloch-pos" <<'BINARY'
#!/usr/bin/env bash
set -euo pipefail
stamp='0.0.1-argv-selftest (abcdef123456)'
if [ "${1:-}" = --version ]; then
  printf 'bloch-pos-node %s argv-selftest\n' "$stamp"
  exit 0
fi
: "${ROLLBACK_ARGV_LOG:?ROLLBACK_ARGV_LOG is required when the stub is launched}"
: > "$ROLLBACK_ARGV_LOG"
for argument in "$@"; do
  printf '%s\0' "$argument" >> "$ROLLBACK_ARGV_LOG"
done
BINARY
chmod 0755 "$W/bloch-pos"

if ! BLOCH_ROLLBACK_SECKEY="$W/release.key" \
    BLOCH_ROLLBACK_PUBKEY="$W/release.pub" \
    "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$W/dist" \
    > "$W/assemble.log" 2>&1; then
  echo "FAIL: rollback package assembly failed"
  sed 's/^/       /' "$W/assemble.log"
  exit 1
fi

TARBALL="$W/dist/bloch-pos-rollback-abcdef123456.tar.gz"
mkdir -p "$W/extracted"
tar -xzf "$TARBALL" -C "$W/extracted"
PKG="$W/extracted/bloch-pos-rollback-abcdef123456"

# A static drop-in that names only bloch-pos is the original production bug.
# The drop-in may name only the signed launcher; argv belongs in argv.nul, not
# in systemd syntax where quoting, percent expansion and shell-like text are
# easy to reinterpret.
if [ -x "$PKG/rollback-launcher" ]; then
  ok "package contains an executable rollback launcher"
else
  bad "package does not contain an executable rollback launcher"
fi
if awk '$2 == "rollback-launcher" { found = 1 } END { exit !found }' \
    "$PKG/SHA256SUMS"; then
  ok "signed manifest covers rollback-launcher"
else
  bad "signed manifest does not cover rollback-launcher"
fi
if grep -Eq '^ExecStart=.*/rollback-launcher$' "$PKG/99-rollback.conf" \
   && grep -Eq '^StandardInput=file:.*/argv\.nul$' "$PKG/99-rollback.conf" \
   && ! grep -Eq '^ExecStart=.*/bloch-pos([[:space:]]|$)' \
      "$PKG/99-rollback.conf"; then
  ok "drop-in feeds captured argv to the launcher without systemd re-quoting"
else
  bad "drop-in does not safely feed captured argv to the launcher"
fi
if grep -Fq 'install -m 0600 "$ARGV_TMP" "$DEST/argv.nul"' "$PKG/install.sh"; then
  ok "captured argv is staged with owner-only permissions"
else
  bad "captured argv may expose service arguments to other local users"
fi

# Exercise the launcher itself with values that would be corrupted or
# executed by eval, shell interpolation, word splitting, globbing, or systemd
# percent expansion.  The expected output is also NUL-delimited so the empty
# argument and all byte boundaries are compared exactly.
if [ -x "$PKG/rollback-launcher" ]; then
  sentinel="$W/MUST-NOT-EXIST"
  argv0='/old release/bloch-pos'
  args=(
    '--validator-index' '64'
    '--label' 'value with spaces'
    '--empty' ''
    '--glob' '*?[abc]'
    '--semicolon' 'left; touch forbidden'
    '--command-substitution' "\$(touch $sentinel)"
    '--quotes' 'single'"'"'" double" backslash\\'
    '--systemd-percent' '%n-%i-%%'
  )
  : > "$PKG/argv.nul"
  printf '%s\0' "$argv0" >> "$PKG/argv.nul"
  : > "$W/expected.nul"
  for argument in "${args[@]}"; do
    printf '%s\0' "$argument" >> "$PKG/argv.nul"
    printf '%s\0' "$argument" >> "$W/expected.nul"
  done

  if ROLLBACK_ARGV_LOG="$W/observed.nul" "$PKG/rollback-launcher" \
      < "$PKG/argv.nul" \
      > "$W/launcher.out" 2>&1; then
    if cmp -s "$W/expected.nul" "$W/observed.nul"; then
      ok "launcher preserves spaces, empty argv, metacharacters and percent tokens byte-for-byte"
    else
      bad "launcher changed argument bytes or boundaries"
      od -An -tx1 "$W/expected.nul" | sed 's/^/       expected: /'
      od -An -tx1 "$W/observed.nul" | sed 's/^/       observed: /'
    fi
  else
    bad "rollback launcher failed with a valid NUL-delimited argv file"
    sed 's/^/       /' "$W/launcher.out"
  fi
  if [ -e "$sentinel" ]; then
    bad "launcher evaluated command substitution from an argument"
  else
    ok "launcher treats shell metacharacters as data"
  fi
fi

# An inactive service has no authoritative argv to preserve.  install.sh must
# fail before it stages bytes or invokes daemon-reload/restart.  PATH supplies
# a harmless systemctl whose show operation reports PID 0; any mutating action
# is logged and makes the test fail.  Defensive mkdir/install shims also make
# this safe in root-run CI: a regression can attempt staging, but it cannot
# write the self-test payload below /opt or /etc.
cat > "$W/bin/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  show)
    printf '0\n'
    ;;
  *)
    printf '%s\0' "$@" >> "${ROLLBACK_SYSTEMCTL_LOG:?}"
    ;;
esac
SYSTEMCTL
chmod 0755 "$W/bin/systemctl"
REAL_MKDIR="$(command -v mkdir)"
REAL_INSTALL="$(command -v install)"
export REAL_MKDIR REAL_INSTALL
cat > "$W/bin/mkdir" <<'MKDIR'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  case "$argument" in
    /opt|/opt/*|/etc|/etc/*)
      printf 'mkdir:%s\0' "$argument" >> "${ROLLBACK_FILESYSTEM_LOG:?}"
      exit 97
      ;;
  esac
done
exec "$REAL_MKDIR" "$@"
MKDIR
cat > "$W/bin/install" <<'INSTALL'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  case "$argument" in
    /opt|/opt/*|/etc|/etc/*)
      printf 'install:%s\0' "$argument" >> "${ROLLBACK_FILESYSTEM_LOG:?}"
      exit 98
      ;;
  esac
done
exec "$REAL_INSTALL" "$@"
INSTALL
chmod 0755 "$W/bin/mkdir" "$W/bin/install"
: > "$W/systemctl-mutating.nul"
: > "$W/filesystem-mutating.nul"
if ( cd "$PKG" && \
    ROLLBACK_SYSTEMCTL_LOG="$W/systemctl-mutating.nul" \
    ROLLBACK_FILESYSTEM_LOG="$W/filesystem-mutating.nul" \
    BLOCH_ROLLBACK_PUBKEY="$W/release.pub" \
    ./install.sh bloch-inactive-selftest.service ) \
    > "$W/inactive.out" 2>&1; then
  bad "installer accepted a service with no running process"
elif ! grep -Eqi 'not running|no main PID|active process|running process' \
    "$W/inactive.out"; then
  bad "installer refused an inactive service without an actionable diagnostic"
  sed 's/^/       /' "$W/inactive.out"
elif grep -Fq '== stage binary' "$W/inactive.out"; then
  bad "installer began staging before refusing the service with no process"
elif [ -s "$W/filesystem-mutating.nul" ]; then
  bad "installer attempted a filesystem mutation after finding no process"
elif [ -s "$W/systemctl-mutating.nul" ]; then
  bad "installer called a mutating systemctl action after finding no process"
else
  ok "installer refuses a service with no process before daemon-reload or restart"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "rollback argv selftest: all checks passed"
else
  echo "rollback argv selftest: $fails FAILED"
fi
exit $((fails > 0))
