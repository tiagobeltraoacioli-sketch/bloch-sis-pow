#!/usr/bin/env python3
"""Mutation selftest for check-attested-ssh.py."""

import importlib.util
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("guard", HERE / "check-attested-ssh.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)

ATTESTED = '''{
  services.openssh = {
    enable = false;
    openFirewall = false;
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
    };
  };
}
'''

CLOUD = '''{
  imports = [ ./attested.nix ];
  networking.firewall.interfaces.wg0.allowedTCPPorts = [ 22 ];
  services.openssh = {
    enable = lib.mkForce true;
    openFirewall = false;
    settings.PermitRootLogin = "no";
    settings.PasswordAuthentication = false;
    settings.KbdInteractiveAuthentication = false;
  };
}
'''


def run(attested: str = ATTESTED, cloud: str = CLOUD) -> list[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "os").mkdir()
        (root / "os/attested.nix").write_text(attested, encoding="utf-8")
        (root / "os/cloud.nix").write_text(cloud, encoding="utf-8")
        return GUARD.check(root)


def expect_red(name: str, errors: list[str], needle: str) -> None:
    assert any(needle in error for error in errors), f"{name}: {errors}"
    print(f"selftest ok: {name} -> red by name")


assert not run(), run()
print("selftest ok: honest posture -> green")
expect_red("appliance sshd re-enabled", run(ATTESTED.replace("enable = false", "enable = true")), "disabled by default")
expect_red("cloud override softened", run(cloud=CLOUD.replace("lib.mkForce true", "lib.mkDefault true")), "explicitly override")
expect_red("cloud opens global firewall", run(cloud=CLOUD.replace("openFirewall = false", "openFirewall = true")), "globally")
expect_red("cloud permits root", run(cloud=CLOUD.replace('PermitRootLogin = "no"', 'PermitRootLogin = "yes"')), "root SSH")
expect_red("cloud permits passwords", run(cloud=CLOUD.replace("PasswordAuthentication = false", "PasswordAuthentication = true")), "password SSH")
expect_red("wg0 rule removed", run(cloud=CLOUD.replace("networking.firewall.interfaces.wg0.allowedTCPPorts = [ 22 ];\n", "")), "specifically on wg0")
print("check-attested-ssh.selftest: all shapes verified (6 red by name, 1 green)")
