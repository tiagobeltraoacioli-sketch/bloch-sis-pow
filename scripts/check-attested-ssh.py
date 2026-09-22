#!/usr/bin/env python3
"""Structural guard for the remote-access posture of attested images.

The appliance profile must disable sshd.  The confidential-cloud profile may
override that default, but only with key-only, non-root SSH and a firewall rule
that exposes port 22 on wg0 rather than on every interface.  This guard is the
no-Nix CI half; check-iso-hardening.sh evaluates the composed attested values on
the Nix runner.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def _block(text: str, marker: str) -> str | None:
    start = text.find(marker)
    if start < 0:
        return None
    opening = text.find("{", start + len(marker))
    if opening < 0:
        return None
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : pos]
    return None


def _requires(errors: list[str], text: str, pattern: str, message: str) -> None:
    if not re.search(pattern, text, re.MULTILINE):
        errors.append(message)


def check(root: Path) -> list[str]:
    errors: list[str] = []
    attested_path = root / "os/attested.nix"
    cloud_path = root / "os/cloud.nix"
    if not attested_path.is_file():
        errors.append("os/attested.nix is missing")
        return errors
    if not cloud_path.is_file():
        errors.append("os/cloud.nix is missing")
        return errors

    attested = _block(attested_path.read_text(encoding="utf-8"),
                      "services.openssh =")
    if attested is None:
        errors.append("os/attested.nix: services.openssh block is missing")
    else:
        _requires(errors, attested, r"\benable\s*=\s*false\s*;",
                  "os/attested.nix: sshd must be disabled by default")
        _requires(errors, attested, r"\bopenFirewall\s*=\s*false\s*;",
                  "os/attested.nix: OpenSSH must not open a global firewall rule")
        _requires(errors, attested, r"PermitRootLogin\s*=\s*\"no\"\s*;",
                  "os/attested.nix: root SSH login must be denied")
        _requires(errors, attested, r"PasswordAuthentication\s*=\s*false\s*;",
                  "os/attested.nix: password SSH authentication must be denied")
        _requires(errors, attested, r"KbdInteractiveAuthentication\s*=\s*false\s*;",
                  "os/attested.nix: keyboard-interactive SSH authentication must be denied")

    cloud_text = cloud_path.read_text(encoding="utf-8")
    cloud = _block(cloud_text, "services.openssh =")
    if cloud is None:
        errors.append("os/cloud.nix: services.openssh exception is missing")
    else:
        _requires(errors, cloud, r"\benable\s*=\s*lib\.mkForce\s+true\s*;",
                  "os/cloud.nix: SSH exception must explicitly override the appliance default")
        _requires(errors, cloud, r"\bopenFirewall\s*=\s*false\s*;",
                  "os/cloud.nix: SSH exception must not open port 22 globally")
        _requires(errors, cloud, r"PermitRootLogin\s*=\s*\"no\"\s*;",
                  "os/cloud.nix: root SSH login must be denied")
        _requires(errors, cloud, r"PasswordAuthentication\s*=\s*false\s*;",
                  "os/cloud.nix: password SSH authentication must be denied")
        _requires(errors, cloud, r"KbdInteractiveAuthentication\s*=\s*false\s*;",
                  "os/cloud.nix: keyboard-interactive SSH authentication must be denied")

    _requires(
        errors,
        cloud_text,
        r"networking\.firewall\.interfaces\.wg0\.allowedTCPPorts\s*=\s*\[\s*22\s*\]\s*;",
        "os/cloud.nix: port 22 must be allowed specifically on wg0",
    )
    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    errors = check(root)
    if errors:
        for error in errors:
            print(f"check-attested-ssh: FAIL: {error}")
        return 1
    print("check-attested-ssh: ok — appliance sshd is off; cloud SSH is key-only, non-root and wg0-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
