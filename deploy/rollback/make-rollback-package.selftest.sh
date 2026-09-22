#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-test for the integrity half of deploy/rollback/make-rollback-package.sh
# and the install.sh it generates (audit finding I-H3).
#
# The defect this pins: SHA256SUMS travels INSIDE the tarball, and install.sh
# runs as root. `sha256sum -c` over a manifest that ships with the bytes it
# describes proves internal consistency and nothing else — anyone who can
# rewrite the tarball rewrites the manifest too, and the check still passes.
# The headline case below is exactly that attack: swap the binary, recompute
# SHA256SUMS, leave the signature alone. It MUST fail, and it must fail at the
# signature step, before a single byte is staged.
#
# Everything here uses a DISPOSABLE keypair generated into a temp dir. No
# release key, no box, no service is touched: install.sh is only ever invoked
# with --verify-only, which returns before it would stage or restart anything.
#
# Usage: bash deploy/rollback/make-rollback-package.selftest.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
REPO_ROOT="$(pwd)"
ASSEMBLER="$REPO_ROOT/deploy/rollback/make-rollback-package.sh"

command -v minisign >/dev/null || {
  echo "FAIL: minisign is not installed — this test cannot verify the property"
  echo "it exists to verify, so it fails rather than skipping."
  echo "  macOS: brew install minisign   Debian/Ubuntu: apt install minisign"
  exit 1
}

W="$(mktemp -d "${TMPDIR:-/tmp}/rollback-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT
fails=0
ok()   { echo "  ok   $1"; }
bad()  { echo "  FAIL $1"; fails=$((fails + 1)); }

# Put a controllable SHA-256 shim first on PATH. Canonical mode delegates to
# the host implementation; adversarial modes let the real assembler prove it
# fails closed on successful-but-malformed output. This also supplies the
# Linux `sha256sum` interface used by generated install.sh on macOS.
mkdir -p "$W/bin"
REAL_SHA256SUM="$(command -v sha256sum || true)"
REAL_SHASUM="$(command -v shasum || true)"
REAL_LN="$(command -v ln || true)"
[ -n "$REAL_SHA256SUM" ] || [ -n "$REAL_SHASUM" ] || {
  echo "FAIL: no host SHA-256 implementation is available"
  exit 1
}
export REAL_SHA256SUM REAL_SHASUM REAL_LN
cat > "$W/bin/sha256sum" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
delegate() {
  if [ -n "${REAL_SHA256SUM:-}" ]; then
    exec "$REAL_SHA256SUM" "$@"
  elif [ "${1:-}" = -c ]; then
    exec "$REAL_SHASUM" -a 256 -c "$2"
  else
    exec "$REAL_SHASUM" -a 256 "$@"
  fi
}
case "${ROLLBACK_SHA_MODE:-canonical}" in
  canonical) delegate "$@" ;;
  exit) exit 71 ;;
  short) printf '%063d  %s\n' 0 "${1:-input}" ;;
  nonhex) printf '%064d  %s\n' 0 "${1:-input}" | tr 0 g ;;
  uppercase) printf '%064d  %s\n' 0 "${1:-input}" | tr 0 A ;;
  duplicate)
    printf '%064d  %s\n' 0 "${1:-input}"
    printf '%064d  second-row\n' 0
    ;;
  late-duplicate|tarball-duplicate)
    state="${ROLLBACK_SHA_STATE:?missing ROLLBACK_SHA_STATE}"
    count=0
    [ ! -f "$state" ] || count="$(cat "$state")"
    count=$((count + 1))
    printf '%s\n' "$count" > "$state"
    fail_at=3
    [ "${ROLLBACK_SHA_MODE}" != tarball-duplicate ] || fail_at=8
    if [ "$count" -eq "$fail_at" ]; then
      printf '%064d  %s\n' 0 "${1:-input}"
      printf '%064d  second-row\n' 0
    else
      delegate "$@"
    fi
    ;;
  *) exit 72 ;;
esac
SHIM
chmod 0755 "$W/bin/sha256sum"
cat > "$W/bin/ln" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
destination="${@: -1}"
case "${ROLLBACK_LN_MODE:-canonical}:$destination" in
  fail-final-tarball:*/bloch-pos-rollback-*.tar.gz)
      echo "injected final tarball publication failure" >&2
      exit 73
      ;;
  race-final-tarball:*/bloch-pos-rollback-*.tar.gz)
      printf 'concurrent publication sentinel\n' > "$destination"
      echo "injected concurrent final tarball collision" >&2
      exec "$REAL_LN" "$@"
      ;;
esac
exec "$REAL_LN" "$@"
SHIM
chmod 0755 "$W/bin/ln"
export PATH="$W/bin:$PATH"

# ── disposable keys ─────────────────────────────────────────────────────────
minisign -G -W -f -p "$W/rel.pub" -s "$W/rel.key" >/dev/null 2>&1
minisign -G -W -f -p "$W/other.pub" -s "$W/other.key" >/dev/null 2>&1

# ── a stand-in for the known-good binary ────────────────────────────────────
STAMP='0.0.1-selftest (abcdef123456)'
cat > "$W/bloch-pos" <<'BINSTUB'
#!/usr/bin/env bash
stamp='0.0.1-selftest (abcdef123456)'
case "${ROLLBACK_SELFTEST_VERSION_MODE:-canonical}" in
  canonical)
    printf 'bloch-pos-node %s built-by-selftest\n' "$stamp"
    ;;
  exit)
    exit 73
    ;;
  later-decoy)
    printf '%s\n' 'bloch-pos-node 0.0.1-selftest (deadbeef1234) decoy-first'
    printf 'decoy %s\n' "$stamp"
    ;;
  embedded)
    printf 'bloch-pos-node x%sy built-by-selftest\n' "$stamp"
    ;;
  self-mutating)
    printf 'bloch-pos-node %s before-mutation\n' "$stamp"
    printf '%s\n' '#!/usr/bin/env bash' \
      "echo 'bloch-pos-node $stamp changed-by-version'" > "$0"
    chmod 0755 "$0"
    ;;
  *)
    exit 74
    ;;
esac
BINSTUB
chmod 0755 "$W/bloch-pos"

expect_stamp_failure() { # $1 = case, $2 = binary, $3 = stamp, $4 = diagnostic
  name="$1"
  binary="$2"
  stamp="$3"
  expected="$4"
  output="$W/stamp-$name"
  log="$W/stamp-$name.log"
  if BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
      "$ASSEMBLER" "$binary" "$stamp" "$output" > "$log" 2>&1; then
    bad "assembler accepted $name rollback stamp"
  elif ! grep -Fq "$expected" "$log"; then
    bad "assembler rejected $name rollback stamp without the expected diagnostic"
    sed 's/^/       /' "$log"
  elif [ -d "$output" ] \
      && [ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    bad "assembler published output after rejecting $name rollback stamp"
  else
    ok "assembler refuses $name rollback stamp before publication"
  fi
}

expect_stamp_failure truncated "$W/bloch-pos" '0.0.1-selftest' \
  'rollback stamp must be one canonical version-and-commit token'

DECOY_STAMP='0.0.1-selftest (deadbeef1234)'
cat > "$W/decoy-version-bloch-pos" <<BINSTUB
#!/usr/bin/env bash
printf '%s\n' 'bloch-pos-node 0.0.1-selftest (abcdef123456) built-by-selftest'
printf '%s\n' 'decoy $DECOY_STAMP'
BINSTUB
chmod 0755 "$W/decoy-version-bloch-pos"
expect_stamp_failure second-line-decoy "$W/decoy-version-bloch-pos" \
  "$DECOY_STAMP" 'STAMP MISMATCH'

EMBEDDED_STAMP='0.0.1-selftest (decafbad1234)'
cat > "$W/embedded-version-bloch-pos" <<BINSTUB
#!/usr/bin/env bash
printf '%s\n' 'bloch-pos-node x${EMBEDDED_STAMP}y built-by-selftest'
BINSTUB
chmod 0755 "$W/embedded-version-bloch-pos"
expect_stamp_failure embedded-token "$W/embedded-version-bloch-pos" \
  "$EMBEDDED_STAMP" 'STAMP MISMATCH'

expect_sha_failure() { # $1 = mode, $2 = expected diagnostic
  mode="$1"
  expected="$2"
  output="$W/sha-$mode"
  log="$W/sha-$mode.log"
  state="$W/sha-$mode.state"
  if ROLLBACK_SHA_MODE="$mode" ROLLBACK_SHA_STATE="$state" \
      BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
      "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$output" > "$log" 2>&1; then
    bad "assembler accepted $mode SHA-256 output"
  elif ! grep -Fq "$expected" "$log"; then
    bad "assembler rejected $mode SHA-256 output without the expected diagnostic"
    sed 's/^/       /' "$log"
  elif [ -d "$output" ] \
      && [ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    bad "assembler published output after rejecting $mode SHA-256 output"
  else
    ok "assembler refuses $mode SHA-256 output before publication"
  fi
}

expect_sha_failure exit 'SHA-256 tool failed for the rollback binary'
expect_sha_failure short 'digest that is not exactly 64 characters for the rollback binary'
expect_sha_failure nonhex 'non-lowercase hexadecimal digest for the rollback binary'
expect_sha_failure uppercase 'non-lowercase hexadecimal digest for the rollback binary'
expect_sha_failure duplicate 'non-lowercase hexadecimal digest for the rollback binary'
expect_sha_failure late-duplicate \
  'non-lowercase hexadecimal digest for rollback manifest entry STAMP'
expect_sha_failure tarball-duplicate \
  'non-lowercase hexadecimal digest for the rollback tarball'

publication_failure_out="$W/publication-failure"
mkdir -p "$publication_failure_out"
if ROLLBACK_LN_MODE=fail-final-tarball \
    BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
    "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$publication_failure_out" \
    > "$W/publication-failure.log" 2>&1; then
  bad "assembler accepted a failed final tarball publication"
elif ! grep -Fq 'injected final tarball publication failure' \
    "$W/publication-failure.log"; then
  bad "final tarball publication failed without the injected diagnostic"
elif [ -n "$(find "$publication_failure_out" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  bad "failed final tarball publication left public or temporary output"
else
  ok "failed final tarball publication rolls back its public key and temporaries"
fi

publication_race_out="$W/publication-race"
mkdir -p "$publication_race_out"
publication_race_tar="$publication_race_out/bloch-pos-rollback-abcdef123456.tar.gz"
if ROLLBACK_LN_MODE=race-final-tarball \
    BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
    "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$publication_race_out" \
    > "$W/publication-race.log" 2>&1; then
  bad "assembler accepted a concurrent final tarball collision"
elif ! grep -Fq 'injected concurrent final tarball collision' \
    "$W/publication-race.log"; then
  bad "concurrent final tarball collision lacked the injected diagnostic"
elif [ "$(cat "$publication_race_tar")" != 'concurrent publication sentinel' ]; then
  bad "cleanup removed or modified the concurrent final tarball"
elif [ "$(find "$publication_race_out" -mindepth 1 -maxdepth 1 -exec printf x \; | wc -c | tr -d '[:space:]')" != 1 ]; then
  bad "concurrent final tarball collision left owned public or temporary output"
else
  ok "concurrent final tarball is preserved while owned publication is rolled back"
fi

expect_collision_refusal() { # $1 = final suffix
  suffix="$1"
  output="$W/collision-${suffix##*.}"
  mkdir -p "$output"
  sentinel="$output/bloch-pos-rollback-abcdef123456.$suffix"
  printf 'preexisting publication sentinel\n' > "$sentinel"
  if BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
      "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$output" \
      > "$W/collision-${suffix##*.}.log" 2>&1; then
    bad "assembler overwrote existing rollback $suffix output"
  elif ! grep -Fq 'refusing to overwrite existing rollback publication' \
      "$W/collision-${suffix##*.}.log"; then
    bad "existing rollback $suffix output failed without collision diagnostic"
  elif [ "$(cat "$sentinel")" != 'preexisting publication sentinel' ]; then
    bad "existing rollback $suffix output was modified"
  elif [ "$(find "$output" -mindepth 1 -maxdepth 1 -exec printf x \; | wc -c | tr -d '[:space:]')" != 1 ]; then
    bad "rollback $suffix collision left additional output"
  else
    ok "assembler refuses existing rollback $suffix output without modification"
  fi
}

expect_collision_refusal tar.gz
expect_collision_refusal pub

# ── 1. the assembler fails closed with no signing key ───────────────────────
out="$(env -u BLOCH_ROLLBACK_SECKEY "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$W/unsigned" 2>&1)"
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'refusing to assemble an unsigned'; then
  ok "assembler refuses to build an unsigned package"
else
  bad "assembler built a package with no signing key (rc=$rc)"
fi
[ -e "$W/unsigned" ] && bad "an unsigned package was left on disk at $W/unsigned"

# ── assemble a real one ─────────────────────────────────────────────────────
BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
  "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$W/dist" > "$W/assemble.log" 2>&1 || {
  echo "FAIL: assembly failed"; cat "$W/assemble.log"; exit 1; }
TARBALL="$W/dist/bloch-pos-rollback-abcdef123456.tar.gz"
[ -f "$TARBALL" ] || { echo "FAIL: no tarball at $TARBALL"; cat "$W/assemble.log"; exit 1; }
mkdir -p "$W/x" && tar -xzf "$TARBALL" -C "$W/x"
PKG="$W/x/bloch-pos-rollback-abcdef123456"

# ── 2. the package carries a detached signature over the manifest ───────────
if [ -f "$PKG/SHA256SUMS.minisig" ]; then
  ok "package carries SHA256SUMS.minisig"
else
  bad "package has no detached signature over SHA256SUMS"
fi
if minisign -V -q -p "$W/rel.pub" -x "$PKG/SHA256SUMS.minisig" -m "$PKG/SHA256SUMS" >/dev/null 2>&1; then
  ok "signature verifies against the release public key"
else
  bad "signature does not verify against the release public key"
fi

# ── 3. the manifest covers every file that reaches root, not just the binary ─
for f in bloch-pos STAMP rollback-launcher 99-rollback.conf install.sh README; do
  if awk -v n="$f" '$2 == n { found = 1 } END { exit !found }' "$PKG/SHA256SUMS"; then
    ok "manifest covers $f"
  else
    bad "manifest does not cover $f (it runs as root)"
  fi
done

# ── 4. the public key is published beside the tarball, never inside it ──────
shopt -s nullglob
inside_pub=("$PKG"/*.pub)
shopt -u nullglob
if [ ${#inside_pub[@]} -ne 0 ]; then
  bad "a public key ships inside the tarball — it would authenticate nothing"
else
  ok "no public key inside the tarball (trust root stays out of band)"
fi
[ -f "$W/dist/bloch-pos-rollback-abcdef123456.pub" ] \
  && ok "public key published beside the tarball" \
  || bad "public key was not published beside the tarball"

# ── the verification harness ────────────────────────────────────────────────
# Each case runs on a pristine copy, with the pinned key supplied out of band.
# verify <case> <package dir> <pinned pubkey> [version mode]
#   -> $W/<case>.out, rc in $W/<case>.rc
verify() {
  mode="${4:-canonical}"
  ( cd "$2" && ROLLBACK_SELFTEST_VERSION_MODE="$mode" \
      BLOCH_ROLLBACK_PUBKEY="$3" ./install.sh --verify-only ) > "$W/$1.out" 2>&1
  printf '%s\n' "$?" > "$W/$1.rc"
}
expect_ok() { # $1 = case, $2 = what
  if [ "$(cat "$W/$1.rc")" = 0 ] && grep -q 'PACKAGE VERIFIED' "$W/$1.out"; then
    ok "$2"
  else
    bad "$2 — install.sh refused:"; sed 's/^/       /' "$W/$1.out"
  fi
}
expect_fail() { # $1 = case, $2 = what, $3 = expected message fragment
  if [ "$(cat "$W/$1.rc")" != 0 ] && grep -qF -- "$3" "$W/$1.out" \
     && ! grep -q 'PACKAGE VERIFIED' "$W/$1.out"; then
    ok "$2"
  else
    bad "$2 — expected a NONZERO exit and a message containing: $3"
    sed 's/^/       /' "$W/$1.out"
  fi
}

# ── 5. the good package verifies ────────────────────────────────────────────
rm -rf "$W/case-good"; cp -R "$PKG" "$W/case-good"
verify good "$W/case-good" "$W/rel.pub"
expect_ok good "an untampered package verifies"

# ── runtime identity: signed bytes must report their signed stamp ───────────
for mode in exit later-decoy embedded self-mutating; do
  rm -rf "$W/case-version-$mode"
  cp -R "$PKG" "$W/case-version-$mode"
  verify "version-$mode" "$W/case-version-$mode" "$W/rel.pub" "$mode"
done
expect_fail version-exit "a failing packaged --version is refused" \
  "rollback binary --version failed"
expect_fail version-later-decoy \
  "a packaged stamp present only on a later version line is refused" \
  "first version line does not report the packaged stamp"
expect_fail version-embedded \
  "a packaged stamp embedded inside a larger version token is refused" \
  "first version line does not report the packaged stamp"
expect_fail version-self-mutating \
  "a packaged binary that changes while reporting its version is refused" \
  "rollback binary changed while reporting its version"

# ── 6. THE HEADLINE CASE (I-H3): swapped binary + recomputed manifest ───────
# The attacker does the obvious thing: replace the binary, then rebuild
# SHA256SUMS so `sha256sum -c` is happy. Only the detached signature notices.
rm -rf "$W/case-swapped"; cp -R "$PKG" "$W/case-swapped"
printf '#!/bin/sh\necho pwned\n' > "$W/case-swapped/bloch-pos"
( cd "$W/case-swapped" && : > SHA256SUMS
  for f in bloch-pos STAMP rollback-launcher 99-rollback.conf install.sh README; do
    printf '%s  %s\n' "$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')" "$f" >> SHA256SUMS
  done )
# sanity: the manifest the attacker wrote is internally consistent
( cd "$W/case-swapped" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) \
  && ok "attacker's recomputed manifest passes sha256sum -c (the old check)" \
  || bad "test setup: the recomputed manifest should satisfy sha256sum -c"
verify swapped "$W/case-swapped" "$W/rel.pub"
expect_fail swapped "swapped binary + recomputed manifest is REFUSED (signature)" \
  "does not carry a valid signature"

# ── 7. tampered install.sh — the file that runs as root ─────────────────────
rm -rf "$W/case-script"; cp -R "$PKG" "$W/case-script"
printf '\n# injected\n' >> "$W/case-script/install.sh"
verify script "$W/case-script" "$W/rel.pub"
expect_fail script "tampered install.sh is caught by the signed manifest" \
  "install.sh: FAILED"

# ── 8. stripped signature is not tolerated ──────────────────────────────────
rm -rf "$W/case-strip"; cp -R "$PKG" "$W/case-strip"; rm -f "$W/case-strip/SHA256SUMS.minisig"
verify strip "$W/case-strip" "$W/rel.pub"
expect_fail strip "a stripped signature is refused, not warned about" \
  "no SHA256SUMS.minisig"

# ── 9. no pinned key on the box ⇒ refuse, never fall back to hashes ─────────
rm -rf "$W/case-nokey"; cp -R "$PKG" "$W/case-nokey"
verify nokey "$W/case-nokey" "$W/does-not-exist.pub"
expect_fail nokey "no trusted key ⇒ refusal, no unauthenticated fallback" \
  "no trusted signing key"

# ── 10. a package signed by another key is refused ─────────────────────────
BLOCH_ROLLBACK_SECKEY="$W/other.key" BLOCH_ROLLBACK_PUBKEY="$W/other.pub" \
  "$ASSEMBLER" "$W/bloch-pos" "$STAMP" "$W/dist-other" >/dev/null 2>&1
mkdir -p "$W/xo" && tar -xzf "$W/dist-other/bloch-pos-rollback-abcdef123456.tar.gz" -C "$W/xo"
verify wrongkey "$W/xo/bloch-pos-rollback-abcdef123456" "$W/rel.pub"
expect_fail wrongkey "a package signed by an untrusted key is refused" \
  "signed by a key this box does not trust"

# ── 11. a valid signature pasted from another package is refused ───────────
# Same signing key, different binary: the trusted comment names the binary
# hash, so the signature cannot be moved between packages.
printf '#!/usr/bin/env bash\necho "bloch-pos-node %s other"\n' "$STAMP" > "$W/bloch-pos2"
chmod 0755 "$W/bloch-pos2"
BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
  "$ASSEMBLER" "$W/bloch-pos2" "$STAMP" "$W/dist2" >/dev/null 2>&1
mkdir -p "$W/x2" && tar -xzf "$W/dist2/bloch-pos-rollback-abcdef123456.tar.gz" -C "$W/x2"
rm -rf "$W/case-paste"; cp -R "$PKG" "$W/case-paste"
cp "$W/x2/bloch-pos-rollback-abcdef123456/SHA256SUMS"         "$W/case-paste/SHA256SUMS"
cp "$W/x2/bloch-pos-rollback-abcdef123456/SHA256SUMS.minisig" "$W/case-paste/SHA256SUMS.minisig"
verify paste "$W/case-paste" "$W/rel.pub"
expect_fail paste "a valid signature from another package is refused" \
  "signed statement does not name"

# ── 12. an input that rewrites itself during --version stays coherent ───────
MUTATING_STAMP='0.0.1-self-mutating (feedface1234)'
cat > "$W/self-mutating-bloch-pos" <<'MUTATING'
#!/usr/bin/env bash
stamp='0.0.1-self-mutating (feedface1234)'
if [ "${1:-}" = --version ]; then
  printf 'bloch-pos-node %s before-mutation\n' "$stamp"
  printf '%s\n' '#!/usr/bin/env bash' \
    "echo 'bloch-pos-node $stamp final-private-bytes'" > "$0"
  chmod 0755 "$0"
fi
MUTATING
chmod 0755 "$W/self-mutating-bloch-pos"
BLOCH_ROLLBACK_SECKEY="$W/rel.key" BLOCH_ROLLBACK_PUBKEY="$W/rel.pub" \
  "$ASSEMBLER" "$W/self-mutating-bloch-pos" "$MUTATING_STAMP" \
  "$W/dist-mutating" > "$W/mutating-assemble.log" 2>&1 || {
  echo "FAIL: self-mutating input assembly failed"
  sed 's/^/       /' "$W/mutating-assemble.log"
  exit 1
}
MUTATING_TARBALL="$W/dist-mutating/bloch-pos-rollback-feedface1234.tar.gz"
mkdir -p "$W/x-mutating"
tar -xzf "$MUTATING_TARBALL" -C "$W/x-mutating"
MUTATING_PKG="$W/x-mutating/bloch-pos-rollback-feedface1234"
MUTATING_HASH="$(sha256sum "$MUTATING_PKG/bloch-pos" | awk '{print $1}')"
MUTATING_MANIFEST_HASH="$(awk '$2 == "bloch-pos" { print $1 }' \
  "$MUTATING_PKG/SHA256SUMS")"
MUTATING_INSTALL_HASH="$(sed -n 's/^PACKAGE_BINARY_SHA256=//p' \
  "$MUTATING_PKG/install.sh")"
MUTATING_STATEMENT="$(minisign -V -Q -p "$W/rel.pub" \
  -x "$MUTATING_PKG/SHA256SUMS.minisig" \
  -m "$MUTATING_PKG/SHA256SUMS")"
if [ "$MUTATING_HASH" = "$MUTATING_MANIFEST_HASH" ] \
   && [ "$MUTATING_HASH" = "$MUTATING_INSTALL_HASH" ] \
   && grep -Fq "sha256(bloch-pos) = $MUTATING_HASH" "$MUTATING_PKG/README" \
   && printf '%s\n' "$MUTATING_STATEMENT" | grep -Fq \
        "sha256(bloch-pos)=$MUTATING_HASH"; then
  ok "self-mutating input has one binary identity in package, manifest, installer, README and signature"
else
  bad "self-mutating input produced conflicting binary identities"
fi
verify mutating "$MUTATING_PKG" "$W/rel.pub"
expect_ok mutating "self-mutating input's final private bytes verify"

# ── 13. --verify-only changes nothing ──────────────────────────────────────
if grep -q 'Nothing was installed' "$W/good.out" \
   && ! grep -qE 'systemctl|install -m 0755' "$W/good.out"; then
  ok "--verify-only stages nothing and restarts nothing"
else
  bad "--verify-only did more than verify"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "rollback-package selftest: all checks passed"
else
  echo "rollback-package selftest: $fails FAILED"
fi
exit $((fails > 0))
