#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regression test for L1M-09 (generate-mainnet-attestor-keys.sh): with
# --age-recipient the plaintext .sk is generated only in the RAM staging dir,
# never in --out-dir, and the staging dir is gone afterwards; without age the
# script refuses an unencrypted volume unless explicitly overridden.
# Uses stub `bloch-pos` / `age` / `fdesetup` / `findmnt` / `lsblk`; generates no
# real key. Run: scripts/l2-activation/test-generate-mainnet-attestor-keys.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/generate-mainnet-attestor-keys.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$WORK/bin" "$WORK/ram"
# ws-keygen stub: records where it wrote the secret.
cat >"$WORK/bin/bloch-pos" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == ws-keygen && "$2" == --out ]] || exit 2
umask 077
printf 'SECRET-%s' "$RANDOM" >"$3.sk"; printf 'PUBLIC' >"$3.pk"
echo "$3.sk" >>"$KEYGEN_LOG"
STUB
cat >"$WORK/bin/age" <<'STUB'
#!/usr/bin/env bash
# age -r R -o OUT IN
printf 'AGE(' >"$4"; cat "$5" >>"$4"; printf ')' >>"$4"
STUB
printf '#!/usr/bin/env bash\necho "${FAKE_FDE:-false}"\n' >"$WORK/bin/fdesetup"
printf '#!/usr/bin/env bash\necho /dev/fake\n' >"$WORK/bin/findmnt"
printf '#!/usr/bin/env bash\n[[ "${FAKE_FDE:-false}" == true ]] && echo crypt || echo disk\n' >"$WORK/bin/lsblk"
chmod +x "$WORK/bin/"*
export PATH="$WORK/bin:$PATH" KEYGEN_LOG="$WORK/keygen.log"

if [[ "$(uname -s)" == Linux ]]; then
    t=$(stat -f -c %T /dev/shm 2>/dev/null || true)
    if [[ "$t" == tmpfs || "$t" == ramfs ]]; then RAM=/dev/shm; else echo "SKIP age path: /dev/shm is not tmpfs"; RAM=""; fi
else
    RAM="$WORK/ram"   # non-Linux: the operator vouches for --ram-dir
fi

# 1. age path: plaintext only in RAM, out-dir holds .pk + .sk.age, stage removed.
if [[ -n "$RAM" ]]; then
    OUT="$WORK/out-age"
    "$SCRIPT" --index 2 --binary "$WORK/bin/bloch-pos" --out-dir "$OUT" \
        --age-recipient age1test --ram-dir "$RAM" >/dev/null
    [[ -f "$OUT/attestor-2.pk" && -f "$OUT/attestor-2.sk.age" ]] || fail "missing outputs"
    [[ ! -e "$OUT/attestor-2.sk" ]] || fail "plaintext .sk in out-dir"
    grep -q "^$RAM/attestor-stage\." "$KEYGEN_LOG" || fail "ws-keygen did not write into the RAM stage: $(cat "$KEYGEN_LOG")"
    grep -q "^$OUT" "$KEYGEN_LOG" && fail "ws-keygen wrote into out-dir"
    stage=$(dirname "$(head -1 "$KEYGEN_LOG")")
    [[ ! -e "$stage" ]] || fail "staging dir $stage not removed"
    grep -q '^AGE(SECRET-' "$OUT/attestor-2.sk.age" || fail "secret not encrypted"
fi

# 2. a non-RAM --ram-dir is refused on Linux.
if [[ "$(uname -s)" == Linux ]]; then
    if "$SCRIPT" --index 1 --binary "$WORK/bin/bloch-pos" --out-dir "$WORK/out-x" \
        --age-recipient age1test --ram-dir "$WORK" >/dev/null 2>&1; then fail "non-RAM --ram-dir accepted"; fi
fi

# 3. plaintext path: refused on an unencrypted volume, accepted on an encrypted one or with the override.
: >"$KEYGEN_LOG"
if FAKE_FDE=false "$SCRIPT" --index 0 --binary "$WORK/bin/bloch-pos" --out-dir "$WORK/out-plain" >/dev/null 2>&1; then
    fail "plaintext key written to an unencrypted volume"
fi
[[ ! -s "$KEYGEN_LOG" ]] || fail "ws-keygen ran before the refusal"
FAKE_FDE=true "$SCRIPT" --index 0 --binary "$WORK/bin/bloch-pos" --out-dir "$WORK/out-plain" >/dev/null
[[ -f "$WORK/out-plain/attestor-0.sk" ]] || fail "encrypted-volume plaintext path did not write"
FAKE_FDE=false "$SCRIPT" --index 1 --binary "$WORK/bin/bloch-pos" --out-dir "$WORK/out-plain" \
    --plaintext-on-unencrypted-disk >/dev/null
[[ -f "$WORK/out-plain/attestor-1.sk" ]] || fail "override path did not write"

echo "PASS generate-mainnet-attestor-keys.sh (L1M-09)"
