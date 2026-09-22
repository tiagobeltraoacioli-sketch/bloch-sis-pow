#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the real pinned scanner and wrapper in disposable local Git trees."""
from pathlib import Path
import json
import hashlib
import os
import shutil
import subprocess
import tempfile

repository = Path(__file__).resolve().parent.parent
tools = Path(os.environ.get("CI_TOOLS_BIN", str(Path.home() / ".local/bin"))).resolve()
scanner = tools / "gitleaks"
env = dict(os.environ, CI_TOOLS_BIN=str(tools),
           GIT_AUTHOR_NAME="Secret scan regression", GIT_AUTHOR_EMAIL="fixture@example.invalid",
           GIT_COMMITTER_NAME="Secret scan regression", GIT_COMMITTER_EMAIL="fixture@example.invalid")

def run(args, cwd, expected=0):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode != expected:
        # Avoid echoing scanner output or synthetic fixture contents on failure.
        raise AssertionError(f"{args[0]} returned {result.returncode}, expected {expected}")
    return result.stdout + result.stderr

with tempfile.TemporaryDirectory(prefix="bloch-secret-regression-") as temporary:
    root = Path(temporary) / "source"
    root.mkdir()
    (root / "scripts").mkdir()
    for name in ("scan-secrets.sh", "prepare-secret-scan-tree.py", "prepare-secret-scan-baseline.py"):
        shutil.copyfile(repository / "scripts" / name, root / "scripts" / name)
    (root / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
    run(["git", "init", "-q"], root)
    # Intentionally fake credential used only to test detection, never a real token.
    token = "".join(("syntheticA91b42", "C73d64E85f26", "G17h08I39"))
    synthetic = f'api_key = "{token}"\n'
    (root / "fixture.txt").write_text(synthetic)
    (root / ".gitleaks-tree-baseline-files.json").write_text(json.dumps({
        "fixture.txt": hashlib.sha256(synthetic.encode()).hexdigest(),
    }))
    run(["git", "add", "."], root)
    run(["git", "commit", "-qm", "Synthetic scanner fixture"], root)
    for mode, flags in (("history", ["--log-opts=--all"]), ("tree", ["--no-git"])):
        baseline = root / f".gitleaks-{mode}-baseline.json"
        run([str(scanner), "detect", "--source", ".", "--redact", "--no-banner",
             "--config", str(root / ".gitleaks.toml"), "--report-format", "json",
             "--report-path", str(baseline), *flags], root, expected=1)
        records = json.loads(baseline.read_text())
        assert len(records) == 1 and records[0]["Secret"] == "REDACTED"
        run(["bash", "scripts/scan-secrets.sh", mode], root)
    print("ok: exact reviewed redacted history and tree findings are suppressed")

    (root / "fixture.txt").write_text(f'api_key = "{token[::-1]}"\n')
    run(["bash", "scripts/scan-secrets.sh", "tree"], root, expected=1)
    (root / "fixture.txt").write_text(synthetic)
    print("ok: replacement bytes at an approved source location are a new finding")

    (root / "target").mkdir()
    (root / "target/generated.txt").write_text(synthetic)
    run(["bash", "scripts/scan-secrets.sh", "tree"], root)
    print("ok: untracked build output does not enter the tracked-source scan")

    (root / "new.txt").write_text(synthetic)
    run(["git", "add", "new.txt"], root)
    run(["bash", "scripts/scan-secrets.sh", "tree"], root, expected=1)
    print("ok: newly tracked input still triggers the source scan")
    run(["git", "rm", "-q", "--cached", "new.txt"], root)

    # The same bytes/path/line in a later commit must not inherit old approval.
    run(["git", "rm", "-q", "fixture.txt"], root)
    run(["git", "commit", "-qm", "Remove synthetic scanner fixture"], root)
    (root / "fixture.txt").write_text(synthetic)
    run(["git", "add", "fixture.txt"], root)
    run(["git", "commit", "-qm", "Reintroduce synthetic scanner fixture"], root)
    run(["bash", "scripts/scan-secrets.sh", "history"], root, expected=1)
    print("ok: reintroduced bytes at the same path and line are a new history finding")

    shallow = Path(temporary) / "shallow"
    run(["git", "clone", "-q", "--depth=1", root.as_uri(), str(shallow)], root)
    output = run(["bash", "scripts/scan-secrets.sh", "history"], shallow, expected=1)
    assert "non-shallow checkout" in output
    print("ok: shallow history is refused before scanning")

    # Symlink contents are inspected; an external file is never dereferenced.
    external = Path(temporary) / "external.txt"
    external.write_text(synthetic)
    (root / "external-link").symlink_to(external)
    run(["git", "add", "external-link"], root)
    exported = Path(temporary) / "exported"
    exported.mkdir()
    run(["python3", "scripts/prepare-secret-scan-tree.py", str(exported)], root)
    assert not (exported / "external-link").is_symlink()
    assert (exported / "external-link").read_text() == str(external)
    assert not (exported / "target").exists()
    print("ok: source inventory copies link text without following external targets")

print("secret scanner regressions: PASS")
