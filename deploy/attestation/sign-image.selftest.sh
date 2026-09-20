#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SIGN_IMAGE="$SCRIPT_DIR/sign-image.sh"
IMAGE="example.invalid/bloch:test"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sign-image-selftest.XXXXXX")"
WORK="$(cd -P -- "$WORK" && pwd)"
trap 'rm -rf -- "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/external"
cat >"$WORK/bin/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${COSIGN_LOG:?}"
case "${1:-}" in
  sign|verify) exit 0 ;;
  triangulate) printf '%s\n' 'example.invalid/bloch@sha256:fixture' ;;
  *) exit 70 ;;
esac
EOF
chmod 0755 "$WORK/bin/cosign"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_ok() {
  local name="$1" key="$2" pub="$3" path_dir="${4:-$WORK/bin}" log="$WORK/cosign.log" output
  : >"$log"
  if ! output="$(PATH="$path_dir:$PATH" COSIGN_LOG="$log" COSIGN_KEY="$key" COSIGN_PUB="$pub" \
      "$SIGN_IMAGE" "$IMAGE" 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail "$name: expected success"
  fi
  [[ "$(wc -l <"$log" | tr -d '[:space:]')" == 3 ]] || fail "$name: expected three cosign calls"
  grep -Fx -- "sign --key $key --yes $IMAGE" "$log" >/dev/null || fail "$name: wrong sign arguments"
  grep -Fx -- "verify --key $pub $IMAGE" "$log" >/dev/null || fail "$name: wrong verify arguments"
  grep -Fx -- "triangulate $IMAGE" "$log" >/dev/null || fail "$name: wrong triangulate arguments"
}

run_bad() {
  local name="$1" expected="$2" key="$3" pub="$4" path_dir="${5:-$WORK/bin}" log="$WORK/cosign.log" output rc
  : >"$log"
  set +e
  output="$(PATH="$path_dir:$PATH" COSIGN_LOG="$log" COSIGN_KEY="$key" COSIGN_PUB="$pub" \
      "$SIGN_IMAGE" "$IMAGE" 2>&1)"
  rc=$?
  set -e
  [[ $rc -ne 0 ]] || fail "$name: expected failure"
  grep -F -- "$expected" <<<"$output" >/dev/null || {
    printf '%s\n' "$output" >&2
    fail "$name: missing diagnostic: $expected"
  }
  [[ ! -s "$log" ]] || fail "$name: cosign was invoked before rejection"
}

printf '%s\n' secret >"$WORK/external/cosign.key"
printf '%s\n' public >"$WORK/external/cosign.pub"
chmod 0600 "$WORK/external/cosign.key"
run_ok "external canonical key" "$WORK/external/cosign.key" "$WORK/external/cosign.pub"
chmod 0400 "$WORK/external/cosign.key"
run_ok "external read-only key" "$WORK/external/cosign.key" "$WORK/external/cosign.pub"
chmod 0600 "$WORK/external/cosign.key"

for unsafe_mode in 0640 0644 0666; do
  unsafe_key="$WORK/external/unsafe-$unsafe_mode.key"
  printf '%s\n' secret >"$unsafe_key"
  chmod "$unsafe_mode" "$unsafe_key"
  run_bad "unsafe secret mode $unsafe_mode" "permissions must be 0400 or 0600" \
    "$unsafe_key" "$WORK/external/cosign.pub"
done

mkdir -p "$WORK/worktree/.git" "$WORK/worktree/secrets"
printf '%s\n' secret >"$WORK/worktree/secrets/cosign.key"
printf '%s\n' public >"$WORK/worktree/secrets/cosign.pub"
chmod 0600 "$WORK/worktree/secrets/cosign.key"
run_bad "repository-local key" "outside a Git worktree" \
  "$WORK/worktree/secrets/cosign.key" "$WORK/worktree/secrets/cosign.pub"

mkdir -p "$WORK/linked-worktree/secrets"
printf '%s\n' 'gitdir: elsewhere' >"$WORK/linked-worktree/.git"
printf '%s\n' secret >"$WORK/linked-worktree/secrets/cosign.key"
printf '%s\n' public >"$WORK/linked-worktree/secrets/cosign.pub"
chmod 0600 "$WORK/linked-worktree/secrets/cosign.key"
ln -s "$WORK/linked-worktree" "$WORK/worktree-link"
run_bad "physical linked-worktree ancestor" "outside a Git worktree" \
  "$WORK/worktree-link/secrets/cosign.key" "$WORK/worktree-link/secrets/cosign.pub"

ln -s "$WORK/external/cosign.key" "$WORK/external/key-symlink"
run_bad "secret symlink" "must not be a symbolic link" \
  "$WORK/external/key-symlink" "$WORK/external/cosign.pub"

printf '%s\n' secret >"$WORK/external/hardlinked.key"
chmod 0600 "$WORK/external/hardlinked.key"
ln "$WORK/external/hardlinked.key" "$WORK/external/hardlinked-alias.key"
run_bad "secret hardlink" "must have exactly one hard link" \
  "$WORK/external/hardlinked.key" "$WORK/external/cosign.pub"

run_bad "relative secret path" "must be an absolute path" \
  "relative.key" "$WORK/external/cosign.pub"
run_bad "missing secret" "COSIGN_KEY does not exist" \
  "$WORK/external/missing.key" "$WORK/external/cosign.pub"
run_bad "missing public key" "expected public key" \
  "$WORK/external/cosign.key" "$WORK/external/missing.pub"

mkdir -p "$WORK/stat-fail-bin" "$WORK/stat-malformed-bin"
ln -s "$WORK/bin/cosign" "$WORK/stat-fail-bin/cosign"
ln -s "$WORK/bin/cosign" "$WORK/stat-malformed-bin/cosign"
cat >"$WORK/stat-fail-bin/stat" <<'EOF'
#!/usr/bin/env bash
exit 71
EOF
cat >"$WORK/stat-malformed-bin/stat" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' malformed
EOF
chmod 0755 "$WORK/stat-fail-bin/stat" "$WORK/stat-malformed-bin/stat"
run_bad "stat command failure" "cannot inspect COSIGN_KEY permissions" \
  "$WORK/external/cosign.key" "$WORK/external/cosign.pub" "$WORK/stat-fail-bin"
run_bad "malformed stat output" "permissions must be 0400 or 0600" \
  "$WORK/external/cosign.key" "$WORK/external/cosign.pub" "$WORK/stat-malformed-bin"

printf '%s\n' "sign-image selftest: all checks passed"
