#!/usr/bin/env python3
"""Adversarial tests for pinned-rust-toolchain.py."""

from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT = Path(__file__).with_name("pinned-rust-toolchain.py")


def run(*paths: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *(str(path) for path in paths)],
                          text=True, capture_output=True, check=False)


with tempfile.TemporaryDirectory(prefix="bloch-toolchain-pin-test-") as directory:
    root = Path(directory)
    first, second = root / "first.toml", root / "second.toml"
    first.write_text('[toolchain]\nchannel = "1.94.1"\n')
    second.write_text('[toolchain]\nchannel = "1.94.1"\n')
    result = run(first, second)
    assert result.returncode == 0 and result.stdout == "1.94.1\n", result

    second.write_text('[toolchain]\nchannel = "nightly-2026-09-01"\n')
    result = run(first, second)
    assert result.returncode != 0 and "disagree" in result.stderr, result

    for invalid in ('[toolchain]\n',
                    '[toolchain]\nchannel = "1.94.1"\nchannel = "stable"\n',
                    '[toolchain]\nchannel = "$(touch /tmp/no)"\n'):
        second.write_text(invalid)
        result = run(second)
        assert result.returncode != 0 and "toolchain pin error" in result.stderr, result

print("pinned toolchain parser: all adversarial cases passed")

repo = SCRIPT.parents[1]
for relative in ("scripts/check-validator-lifecycle-mutations.py",
                 ".github/workflows/ustav.yml"):
    assert "1.94.1" not in (repo / relative).read_text(), f"stale pin in {relative}"
gitlab = (repo / ".gitlab-ci.yml").read_text()
assert "sudo apt-get install -y minisign" not in gitlab
print("toolchain consumers and rollback job: no hardcoded pin or sudo install")
