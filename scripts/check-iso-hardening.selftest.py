#!/usr/bin/env python3
"""Selftest for check-iso-hardening.py: every failure shape the C-R6-1 second
pass found (or that would quietly reopen it) must go RED by name on a synthetic
tree, and the honest shape must stay GREEN. This is the reason to trust the
guard's verdict. Pure Python 3, no Nix."""

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("guard", HERE / "check-iso-hardening.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

GOOD_HARDENING = '''{ config, lib, ... }:
{
  services.openssh.enable = lib.mkForce false;
  services.openssh.settings = {
    PermitRootLogin = lib.mkForce "no";
    PasswordAuthentication = lib.mkForce false;
  };
  users.users.root.initialHashedPassword = lib.mkForce "!";
  users.users.nixos.initialHashedPassword = lib.mkForce "!";
  services.bloch.mine = lib.mkForce false;
}
'''

GOOD_FLAKE = '''{
  outputs = { self, nixpkgs }: {
    nixosConfigurations.bloch-os = nixpkgs.lib.nixosSystem {
      modules = [
        "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
        ./os/configuration.nix
        ./os/installer-hardening.nix
      ];
    };
    nixosConfigurations.postern-desktop = nixpkgs.lib.nixosSystem {
      modules = [
        "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
        ./os/desktop.nix
        ./os/installer-hardening.nix
      ];
    };
    nixosConfigurations.bloch-os-attested = nixpkgs.lib.nixosSystem {
      modules = [ "${nixpkgs}/nixos/modules/image/repart.nix" ./os/configuration.nix ];
    };
  };
}
'''

GOOD_EVAL = '''#!/usr/bin/env bash
nix eval .#...services.openssh.enable
nix eval .#...users.users.root.initialHashedPassword
nix eval .#...users.users.nixos.initialHashedPassword
nix eval .#...services.bloch.mine
'''


def build(root: Path, flake=GOOD_FLAKE, hardening=GOOD_HARDENING, ev=GOOD_EVAL):
    (root / "os").mkdir(parents=True, exist_ok=True)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "flake.nix").write_text(flake, encoding="utf-8")
    if hardening is not None:
        (root / "os" / "installer-hardening.nix").write_text(hardening, encoding="utf-8")
    if ev is not None:
        (root / "scripts" / "check-iso-hardening.sh").write_text(ev, encoding="utf-8")


failures = []


def expect(name, errors, must_mention=None, green=False):
    if green:
        if errors:
            failures.append(f"{name}: expected GREEN, got: {errors}")
        else:
            print(f"selftest ok: {name} -> green")
        return
    if not errors:
        failures.append(f"{name}: expected RED, guard said ok")
        return
    if must_mention and not any(must_mention in e for e in errors):
        failures.append(f"{name}: red, but no error mentions {must_mention!r}: {errors}")
        return
    print(f"selftest ok: {name} -> red by name")


with tempfile.TemporaryDirectory() as td:
    td = Path(td)

    # 1. Honest shape is green.
    r = td / "good"; build(r)
    expect("honest shape", guard.check(r), green=True)

    # 2. The exact main-before-fix shape: no hardening module, no eval script,
    #    ISO lists without the import.
    r = td / "mainlike"; build(r,
        flake=GOOD_FLAKE.replace("        ./os/installer-hardening.nix\n", ""),
        hardening=None, ev=None)
    expect("main-before-fix (module missing)", guard.check(r), "installer-hardening.nix is missing")

    # 3. Module exists but ONE ISO config (desktop) ships without it.
    r = td / "one-iso-unhardened"; build(r,
        flake=GOOD_FLAKE.replace(
            "./os/desktop.nix\n        ./os/installer-hardening.nix",
            "./os/desktop.nix"))
    expect("one ISO composed without hardening", guard.check(r),
           "without ./os/installer-hardening.nix")

    # 4. Softened priority: mkDefault instead of mkForce loses to the profile's
    #    plain-100 empty password / ties its mkDefault sshd. Must be refused.
    r = td / "mkdefault"; build(r,
        hardening=GOOD_HARDENING.replace(
            "services.openssh.enable = lib.mkForce false",
            "services.openssh.enable = lib.mkDefault false"))
    expect("sshd override softened to mkDefault", guard.check(r),
           "services.openssh.enable = mkForce false")

    # 5. Password 'locked' with the profile's own empty string — still
    #    passwordless login. Must be refused.
    r = td / "empty-pass"; build(r,
        hardening=GOOD_HARDENING.replace(
            'users.users.root.initialHashedPassword = lib.mkForce "!"',
            'users.users.root.initialHashedPassword = lib.mkForce ""'))
    expect("root password empty instead of locked", guard.check(r),
           "users.users.root.initialHashedPassword")

    # 6. Mining silently re-enabled on live media.
    r = td / "mining"; build(r,
        hardening=GOOD_HARDENING.replace(
            "  services.bloch.mine = lib.mkForce false;\n", ""))
    expect("live-media mining override dropped", guard.check(r),
           "services.bloch.mine")

    # 7. Eval-side proof hollowed out (stops reading the composed values).
    r = td / "hollow-eval"; build(r,
        ev="#!/usr/bin/env bash\necho hardened, trust me\n")
    expect("nix-eval proof no longer asserts composed values", guard.check(r),
           "no longer asserts composed value")

    # 8. Profile import renamed/moved with the guard blind: no modules list
    #    references the installer profile at all -> guard must demand its own
    #    update, not go silently green.
    r = td / "profile-gone"; build(r,
        flake=GOOD_FLAKE.replace("installation-cd-minimal.nix", "some-other-profile.nix"))
    expect("installer profile no longer visible to guard", guard.check(r),
           "update this guard")

if failures:
    for f in failures:
        print(f"selftest FAIL: {f}")
    sys.exit(1)
print("check-iso-hardening.selftest: all shapes verified (7 red by name, 1 green)")
