#!/usr/bin/env bash
# C-R6-1 composed-image proof: read the EFFECTIVE merged option values of the
# two ISO configurations with `nix eval` — not the module text — and fail
# unless the installer profile's sshd + empty-password defaults are actually
# overridden in the composition.
#
# Without os/installer-hardening.nix in the flake's ISO module lists this
# script FAILS on every assertion below (openssh.enable=true,
# PermitRootLogin="yes", initialHashedPassword="", bloch.mine=true for
# bloch-os), because profiles/installation-device.nix wins the merge.
#
# Needs a Nix host with flakes (same assumption as the flake-lock-drift job).
# The default CI runner has no Nix; scripts/check-iso-hardening.py is the
# no-Nix structural guard that runs everywhere.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
assert_eq() { # cfg attrpath expected
  local got
  got=$(nix eval ".#nixosConfigurations.$1.config.$2" 2>&1) || {
    echo "FAIL  $1  $2  (eval error: $got)"; fail=1; return; }
  if [ "$got" = "$3" ]; then
    echo "ok    $1  $2 = $got"
  else
    echo "FAIL  $1  $2 = $got  (expected $3)"; fail=1
  fi
}

for cfg in bloch-os postern-desktop; do
  assert_eq "$cfg" services.openssh.enable                          'false'
  assert_eq "$cfg" services.openssh.settings.PermitRootLogin        '"no"'
  assert_eq "$cfg" services.openssh.settings.PasswordAuthentication 'false'
  assert_eq "$cfg" users.users.root.initialHashedPassword           '"!"'
  assert_eq "$cfg" users.users.nixos.initialHashedPassword          '"!"'
  assert_eq "$cfg" services.bloch.mine                              'false'
  assert_eq "$cfg" networking.firewall.enable                       'true'
done

if [ "$fail" -ne 0 ]; then
  echo "check-iso-hardening: COMPOSED image still carries installer-profile sshd/empty-password defaults" >&2
  exit 1
fi
echo "check-iso-hardening: composed ISO configs are hardened (sshd off, passwords locked, mining off)"
