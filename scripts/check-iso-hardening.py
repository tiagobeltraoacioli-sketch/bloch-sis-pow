#!/usr/bin/env python3
"""C-R6-1: refuse ISO configurations that leave the NixOS installer profile's
sshd + empty-password defaults in force at the image composition.

WHY THIS EXISTS
---------------
`.#iso` and `.#desktop-iso` are composed from nixos-25.05's
installation-cd-minimal.nix, which imports profiles/installation-device.nix.
That upstream profile — invisible in this repository's own module text — sets:

    services.openssh.enable                   = mkDefault true;   # prio 1000
    services.openssh.settings.PermitRootLogin = mkDefault "yes";  # prio 1000
    users.users.nixos.initialHashedPassword   = "";               # prio  100
    users.users.root.initialHashedPassword    = "";               # prio  100

so hardening os/configuration.nix's TEXT changes nothing about the composed
image: it boots with sshd reachable (the openssh module opens port 22 through
the firewall by default) and two empty-password accounts. The first-pass fix
for C-R6-1 fell into exactly that trap.

The real fix is os/installer-hardening.nix, imported by BOTH ISO
nixosConfigurations in flake.nix, overriding those options at mkForce
(mkOverride 50 — beats the profile's plain 100 and mkDefault 1000), locking
the passwords with "!" and forcing mining off on live media.

WHAT THIS GUARD DOES (no Nix on the default runner, so structural — the
composed-value proof is scripts/check-iso-hardening.sh via `nix eval` on the
Nix host):

  1. os/installer-hardening.nix exists and contains each required override AT
     mkForce PRIORITY. mkDefault (1000) or a plain assignment (100) would lose
     or tie against the profile, so anything but lib.mkForce on the exact
     option is refused. Passwords must be locked ("!"), not empty.
  2. EVERY `modules = [ ... ]` list in flake.nix that pulls in the installer
     profile (installation-cd-minimal.nix) also imports
     ./os/installer-hardening.nix — a new ISO config cannot quietly ship
     without the hardening.
  3. scripts/check-iso-hardening.sh still asserts the composed values
     (openssh.enable false, locked passwords, mine false) so the eval-side
     proof cannot be hollowed out while this guard stays green.

Verified by violation in check-iso-hardening.selftest.py: every one of those
shapes goes red by name on synthetic trees, and the honest shape stays green.

Pure Python 3. No toolchain, no build, no network, no Nix.
"""

import re
import sys
from pathlib import Path

HARDENING = "os/installer-hardening.nix"
PROFILE_MARKER = "installation-cd-minimal.nix"
EVAL_SCRIPT = "scripts/check-iso-hardening.sh"

# option -> regex that matches ONLY the mkForce'd hardened assignment.
# `[^;]*` never crosses a `;`, so a mkDefault/plain assignment cannot satisfy it.
REQUIRED_OVERRIDES = {
    "services.openssh.enable = mkForce false": re.compile(
        r"services\.openssh\.enable\s*=\s*lib\.mkForce\s+false\s*;"
    ),
    "PermitRootLogin = mkForce \"no\"": re.compile(
        r"PermitRootLogin\s*=\s*lib\.mkForce\s+\"no\"\s*;"
    ),
    "PasswordAuthentication = mkForce false": re.compile(
        r"PasswordAuthentication\s*=\s*lib\.mkForce\s+false\s*;"
    ),
    "users.users.root.initialHashedPassword = mkForce \"!\" (locked, not empty)": re.compile(
        r"users\.users\.root\.initialHashedPassword\s*=\s*lib\.mkForce\s+\"!\"\s*;"
    ),
    "users.users.nixos.initialHashedPassword = mkForce \"!\" (locked, not empty)": re.compile(
        r"users\.users\.nixos\.initialHashedPassword\s*=\s*lib\.mkForce\s+\"!\"\s*;"
    ),
    "services.bloch.mine = mkForce false (no mining on live media)": re.compile(
        r"services\.bloch\.mine\s*=\s*lib\.mkForce\s+false\s*;"
    ),
}

# The composed-value assertions the eval script must keep making.
EVAL_MUST_ASSERT = [
    "services.openssh.enable",
    "users.users.root.initialHashedPassword",
    "users.users.nixos.initialHashedPassword",
    "services.bloch.mine",
]


def module_lists(flake_text: str):
    """Yield the raw text of every `modules = [ ... ]` list in flake.nix."""
    for m in re.finditer(r"modules\s*=\s*\[", flake_text):
        depth, i = 1, m.end()
        while i < len(flake_text) and depth:
            if flake_text[i] == "[":
                depth += 1
            elif flake_text[i] == "]":
                depth -= 1
            i += 1
        yield flake_text[m.end() : i - 1]


def check(root: Path) -> list:
    errors = []

    hard = root / HARDENING
    if not hard.is_file():
        errors.append(f"{HARDENING} is missing — the ISO images compose the "
                      f"upstream installer profile (sshd on, empty root/nixos "
                      f"passwords) with nothing overriding it.")
        hard_text = ""
    else:
        hard_text = hard.read_text(encoding="utf-8")

    if hard_text:
        for label, rx in REQUIRED_OVERRIDES.items():
            if not rx.search(hard_text):
                errors.append(
                    f"{HARDENING}: required override not found at mkForce "
                    f"priority: {label}. mkDefault(1000)/plain(100) loses or "
                    f"ties against profiles/installation-device.nix; only "
                    f"lib.mkForce (50) wins the merge."
                )

    flake = root / "flake.nix"
    if not flake.is_file():
        errors.append("flake.nix is missing.")
        return errors
    flake_text = flake.read_text(encoding="utf-8")

    iso_lists = [b for b in module_lists(flake_text) if PROFILE_MARKER in b]
    if not iso_lists:
        errors.append(
            f"flake.nix: no modules list imports {PROFILE_MARKER} — if the "
            f"ISO outputs moved, update this guard rather than deleting it."
        )
    for block in iso_lists:
        if "./os/installer-hardening.nix" not in block:
            head = " ".join(block.split())[:100]
            errors.append(
                f"flake.nix: a modules list imports {PROFILE_MARKER} without "
                f"./os/installer-hardening.nix — that image boots with the "
                f"installer profile's sshd + empty passwords. Block: {head}..."
            )

    ev = root / EVAL_SCRIPT
    if not ev.is_file():
        errors.append(f"{EVAL_SCRIPT} is missing — the composed-value proof "
                      f"(nix eval on the merged config) must exist.")
    else:
        ev_text = ev.read_text(encoding="utf-8")
        for attr in EVAL_MUST_ASSERT:
            if attr not in ev_text:
                errors.append(f"{EVAL_SCRIPT}: no longer asserts composed "
                              f"value of {attr}.")

    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    errors = check(root)
    if errors:
        for e in errors:
            print(f"check-iso-hardening: FAIL: {e}")
        print(f"check-iso-hardening: {len(errors)} problem(s). The composed "
              f"ISO images are (or may again become) remotely reachable with "
              f"empty passwords — see os/installer-hardening.nix.")
        return 1
    print("check-iso-hardening: ok — both ISO compositions import the "
          "mkForce hardening (sshd off, passwords locked, mining off) and "
          "the nix-eval proof still asserts the composed values.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
