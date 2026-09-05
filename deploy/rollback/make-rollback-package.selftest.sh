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

# macOS has no sha256sum; install.sh is written for the Linux fleet and calls
# it directly. Shim it so the generated script runs verbatim here too.
mkdir -p "$W/bin"
if ! command -v sha256sum >/dev/null; then
  cat > "$W/bin/sha256sum" <<'SHIM'
#!/usr/bin/env bash
if [ "${1:-}" = "-c" ]; then shasum -a 256 -c "$2"; else shasum -a 256 "$@"; fi
SHIM
  chmod 0755 "$W/bin/sha256sum"
fi
export PATH="$W/bin:$PATH"

# ── disposable keys ─────────────────────────────────────────────────────────
minisign -G -W -f -p "$W/rel.pub" -s "$W/rel.key" >/dev/null 2>&1
minisign -G -W -f -p "$W/other.pub" -s "$W/other.key" >/dev/null 2>&1

# ── a stand-in for the known-good binary ────────────────────────────────────
STAMP='0.0.1-selftest (abcdef123456)'
cat > "$W/bloch-pos" <<BINSTUB
#!/usr/bin/env bash
echo "bloch-pos-node $STAMP built-by-selftest"
BINSTUB
chmod 0755 "$W/bloch-pos"

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
for f in bloch-pos STAMP 99-rollback.conf install.sh README; do
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
# verify <case> <package dir> <pinned pubkey> -> $W/<case>.out, rc in $W/<case>.rc
verify() {
  ( cd "$2" && BLOCH_ROLLBACK_PUBKEY="$3" ./install.sh --verify-only ) > "$W/$1.out" 2>&1
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

# ── 6. THE HEADLINE CASE (I-H3): swapped binary + recomputed manifest ───────
# The attacker does the obvious thing: replace the binary, then rebuild
# SHA256SUMS so `sha256sum -c` is happy. Only the detached signature notices.
rm -rf "$W/case-swapped"; cp -R "$PKG" "$W/case-swapped"
printf '#!/bin/sh\necho pwned\n' > "$W/case-swapped/bloch-pos"
( cd "$W/case-swapped" && : > SHA256SUMS
  for f in bloch-pos STAMP 99-rollback.conf install.sh README; do
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

# ── 12. --verify-only changes nothing ──────────────────────────────────────
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
