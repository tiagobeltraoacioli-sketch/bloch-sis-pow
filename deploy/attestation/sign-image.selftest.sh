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
  local name="$1" key="$2" pub="$3" log="$WORK/cosign.log" output
  : >"$log"
  if ! output="$(PATH="$WORK/bin:$PATH" COSIGN_LOG="$log" COSIGN_KEY="$key" COSIGN_PUB="$pub" \
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
  local name="$1" expected="$2" key="$3" pub="$4" log="$WORK/cosign.log" output rc
  : >"$log"
  set +e
  output="$(PATH="$WORK/bin:$PATH" COSIGN_LOG="$log" COSIGN_KEY="$key" COSIGN_PUB="$pub" \
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
run_ok "external canonical key" "$WORK/external/cosign.key" "$WORK/external/cosign.pub"

mkdir -p "$WORK/worktree/.git" "$WORK/worktree/secrets"
printf '%s\n' secret >"$WORK/worktree/secrets/cosign.key"
printf '%s\n' public >"$WORK/worktree/secrets/cosign.pub"
run_bad "repository-local key" "outside a Git worktree" \
  "$WORK/worktree/secrets/cosign.key" "$WORK/worktree/secrets/cosign.pub"

mkdir -p "$WORK/linked-worktree/secrets"
printf '%s\n' 'gitdir: elsewhere' >"$WORK/linked-worktree/.git"
printf '%s\n' secret >"$WORK/linked-worktree/secrets/cosign.key"
printf '%s\n' public >"$WORK/linked-worktree/secrets/cosign.pub"
ln -s "$WORK/linked-worktree" "$WORK/worktree-link"
run_bad "physical linked-worktree ancestor" "outside a Git worktree" \
  "$WORK/worktree-link/secrets/cosign.key" "$WORK/worktree-link/secrets/cosign.pub"

ln -s "$WORK/external/cosign.key" "$WORK/external/key-symlink"
run_bad "secret symlink" "must not be a symbolic link" \
  "$WORK/external/key-symlink" "$WORK/external/cosign.pub"

printf '%s\n' secret >"$WORK/external/hardlinked.key"
ln "$WORK/external/hardlinked.key" "$WORK/external/hardlinked-alias.key"
run_bad "secret hardlink" "must have exactly one hard link" \
  "$WORK/external/hardlinked.key" "$WORK/external/cosign.pub"

run_bad "relative secret path" "must be an absolute path" \
  "relative.key" "$WORK/external/cosign.pub"
run_bad "missing secret" "COSIGN_KEY does not exist" \
  "$WORK/external/missing.key" "$WORK/external/cosign.pub"
run_bad "missing public key" "expected public key" \
  "$WORK/external/cosign.key" "$WORK/external/missing.pub"

printf '%s\n' "sign-image selftest: all checks passed"
