#!/usr/bin/env python3
"""Selftest for the reproducible-inputs guard and the two repro-* scripts.

A guard is only worth blocking on if it can be shown to FAIL. Three guards
audited in this repository were green while what they guarded was broken, and
the reproducibility tooling was a fourth: `repro-compare.sh` could print
REPRODUCIBLE for two builds that used different nixpkgs, because the field it
compares was written empty by `repro-manifest.sh` and its check was skipped on
empty. Nothing failed. That is the shape this selftest exists to make
impossible to reintroduce.

It builds synthetic repositories and synthetic manifests and asserts, BY NAME:

  * check-repro-inputs.py goes RED for a missing lock, a stub lock, an input
    locked to a branch instead of a full rev, a lock with no narHash, revs that
    were never recorded, recorded revs that contradict the lock, and a
    `flake-lock-drift` job that has been softened back to allow_failure — and
    GREEN for an honest, fully pinned tree.
  * it does NOT fire on an unrelated job's allow_failure (no false positive).
  * repro-compare.sh REFUSES to reach "REPRODUCIBLE" when the flake.lock field
    is empty in a manifest or differs between them, or when the attrs differ —
    the three fail-open paths — while still passing an honest match and still
    reporting a genuine narHash divergence as a divergence.
  * repro-manifest.sh refuses to write a manifest with no lock to hash, and
    does so BEFORE invoking nix (asserted with a nix stub that records having
    been called).

Pure Python 3 + bash. No toolchain, no build, no network, no Nix.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
GUARD = HERE / "check-repro-inputs.py"
COMPARE = REPO / "repro-compare.sh"
MANIFEST = REPO / "repro-manifest.sh"

REV_A = "a" * 40
REV_B = "b" * 40
NAR = "sha256-0000000000000000000000000000000000000000000="

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok       {name}")
    else:
        print(f"  FAILED   {name}  {detail}")
        failures.append(f"{name} {detail}".strip())


# ── synthetic repository ────────────────────────────────────────────────────

FLAKE_NIX = '''{
  # A commented-out input must NOT be picked up:
  # inputs.ghost.url = "github:nobody/ghost";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  inputs.mobile-nixos = { url = "github:mobile-nixos/mobile-nixos"; flake = false; };
  outputs = { self, nixpkgs, mobile-nixos }: { };
}
'''

CI_BLOCKING = '''stages:
  - check
  - nix

some-other-job:
  stage: check
  script:
    - true
  allow_failure: true

flake-lock-drift:
  stage: nix
  script:
    - nix flake lock --no-update-lock-file
    - git diff --exit-code flake.lock
  allow_failure: false

trailing-job:
  stage: check
  script:
    - true
'''

CI_SOFT = CI_BLOCKING.replace(
    """    - git diff --exit-code flake.lock
  allow_failure: false""",
    """    - git diff --exit-code flake.lock
  allow_failure: true""",
)

CI_NO_JOB = "\n".join(
    l for l in CI_BLOCKING.splitlines() if "flake-lock-drift" not in l
)


def lock_json(nixpkgs_locked: dict | None, mobile_locked: dict | None) -> str:
    nodes: dict = {"root": {"inputs": {}}}
    if nixpkgs_locked is not None:
        nodes["root"]["inputs"]["nixpkgs"] = "nixpkgs"
        nodes["nixpkgs"] = {"locked": nixpkgs_locked}
    if mobile_locked is not None:
        nodes["root"]["inputs"]["mobile-nixos"] = "mobile-nixos"
        nodes["mobile-nixos"] = {"locked": mobile_locked}
    return json.dumps({"nodes": nodes, "root": "root", "version": 7}, indent=2)


GOOD_LOCK = lock_json(
    {"type": "github", "rev": REV_A, "narHash": NAR},
    {"type": "github", "rev": REV_B, "narHash": NAR},
)


def lock_sh(nixpkgs_rev: str, mobile_rev: str) -> str:
    return (
        "#!/usr/bin/env bash\n"
        f'EXPECT_NIXPKGS="{nixpkgs_rev}"\n'
        f'EXPECT_MOBILE_NIXOS="{mobile_rev}"\n'
    )


def build_repo(tmp: Path, *, lock: str | None, ci: str, sh: str) -> Path:
    root = tmp
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "flake.nix").write_text(FLAKE_NIX)
    (root / ".gitlab-ci.yml").write_text(ci)
    (root / "scripts" / "flake-lock.sh").write_text(sh)
    if lock is not None:
        (root / "flake.lock").write_text(lock)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return root


def run_guard(*, lock: str | None, ci: str = CI_BLOCKING,
              sh: str | None = None) -> tuple[int, str]:
    if sh is None:
        sh = lock_sh(REV_A[:7], REV_B[:7])
    with tempfile.TemporaryDirectory() as td:
        root = build_repo(Path(td), lock=lock, ci=ci, sh=sh)
        p = subprocess.run([sys.executable, str(GUARD)], cwd=root,
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


def case(name: str, *, expect_rc: int, needle: str = "", **kw) -> None:
    rc, out = run_guard(**kw)
    ok = rc == expect_rc and (needle in out if needle else True)
    check(name, ok, f"(rc={rc}, wanted {expect_rc}"
                    + (f", needle {needle!r} {'found' if needle in out else 'MISSING'}"
                       if needle else "") + ")")


print("check-repro-inputs.py — the guard")

case("honest fully-pinned tree passes", expect_rc=0, needle="PASS", lock=GOOD_LOCK)

case("missing flake.lock is refused", expect_rc=1,
     needle="flake.lock is MISSING", lock=None)

case("stub lock (nodes = {root}) is refused", expect_rc=1,
     needle="no node in flake.lock",
     lock=json.dumps({"nodes": {"root": {}}, "root": "root", "version": 7}))

case("input locked to a branch, not a rev, is refused", expect_rc=1,
     needle="full 40-hex rev",
     lock=lock_json({"type": "github", "ref": "nixos-25.05", "narHash": NAR},
                    {"type": "github", "rev": REV_B, "narHash": NAR}))

case("short rev is not accepted as a pin", expect_rc=1,
     needle="full 40-hex rev",
     lock=lock_json({"type": "github", "rev": REV_A[:7], "narHash": NAR},
                    {"type": "github", "rev": REV_B, "narHash": NAR}))

case("rev without narHash is refused", expect_rc=1,
     needle="no narHash",
     lock=lock_json({"type": "github", "rev": REV_A},
                    {"type": "github", "rev": REV_B, "narHash": NAR}))

case("unparseable lock is refused", expect_rc=1,
     needle="does not parse as JSON", lock="{not json")

case("UNRECORDED expected revs are refused", expect_rc=1,
     needle="has not recorded a rev",
     lock=GOOD_LOCK, sh=lock_sh("UNRECORDED", "UNRECORDED"))

case("recorded rev contradicting the lock is refused", expect_rc=1,
     needle="disagree",
     lock=GOOD_LOCK, sh=lock_sh("deadbee", REV_B[:7]))

case("input with no EXPECT_ constant is refused", expect_rc=1,
     needle="records no EXPECT_ constant",
     lock=GOOD_LOCK,
     sh='#!/usr/bin/env bash\nEXPECT_NIXPKGS="' + REV_A[:7] + '"\n')

case("flake-lock-drift softened to allow_failure is refused", expect_rc=1,
     needle="allow_failure: true", lock=GOOD_LOCK, ci=CI_SOFT)

case("deleting the flake-lock-drift job is refused", expect_rc=1,
     needle="no `flake-lock-drift` job", lock=GOOD_LOCK, ci=CI_NO_JOB)

case("another job's allow_failure is NOT a false positive", expect_rc=0,
     needle="PASS", lock=GOOD_LOCK, ci=CI_BLOCKING)


# ── repro-compare.sh ────────────────────────────────────────────────────────

def manifest(attr: str = ".#pkg", lock: str = "LOCKHASH",
             nar: str = "sha256-out=", outpath: str = "/nonexistent/out") -> str:
    lines = [f"attr:        {attr}",
             "host:        selftest",
             "nix:         nix (Nix) 0.0",
             f"flake.lock:  {lock}",
             f"outpath:     {outpath}",
             f"narHash:     {nar}"]
    return "\n".join(lines) + "\n"


def run_compare(a: str, b: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as td:
        pa, pb = Path(td) / "A.txt", Path(td) / "B.txt"
        pa.write_text(a)
        pb.write_text(b)
        p = subprocess.run(["bash", str(COMPARE), str(pa), str(pb)],
                           cwd=td, capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


print()
print("repro-compare.sh — the cross-builder guard")

# A node-package manifest carries no image_sha256/roothash. On main, `field`
# ran under `set -o pipefail`, so grep's "no match" on those absent fields
# killed the script: it printed "match narHash" and exited 1 — NOT REPRODUCIBLE
# for a clean match, on the exact attr REPRO.md says to compare first.
rc, out = run_compare(manifest(), manifest())
check("node-package manifests (no image fields) reach REPRODUCIBLE",
      rc == 0 and "REPRODUCIBLE" in out, f"(rc={rc})")

img_a = manifest() + "image:       /nonexistent/x.raw\nimage_sha256:abc\nroothash:    def\n"
rc, out = run_compare(img_a, img_a)
check("image manifests still compare image_sha256 and roothash",
      rc == 0 and "match     image_sha256" in out and "match     roothash" in out,
      f"(rc={rc})")

rc, out = run_compare(img_a, manifest() +
                      "image:       /nonexistent/x.raw\nimage_sha256:ZZZ\nroothash:    def\n")
check("diverging image_sha256 is caught",
      rc == 1 and "DIVERGED  image_sha256" in out, f"(rc={rc})")

# THE REGRESSION: an empty flake.lock field is what the old repro-manifest.sh
# wrote when the lock was missing, and the old compare skipped its check on it.
rc, out = run_compare(manifest(lock=""), manifest())
check("empty flake.lock field never reaches REPRODUCIBLE",
      rc == 2 and "REPRODUCIBLE" not in out, f"(rc={rc})")

rc, out = run_compare(manifest(lock=""), manifest(lock=""))
check("empty flake.lock field on BOTH sides never reaches REPRODUCIBLE",
      rc == 2 and "REPRODUCIBLE" not in out, f"(rc={rc})")

rc, out = run_compare(manifest(lock="AAA"), manifest(lock="BBB"))
check("differing flake.lock fails instead of warning",
      rc == 2 and "REPRODUCIBLE" not in out and "NOT COMPARABLE" in out,
      f"(rc={rc})")

rc, out = run_compare(manifest(attr=".#a"), manifest(attr=".#b"))
check("differing attr fails instead of warning",
      rc == 2 and "REPRODUCIBLE" not in out, f"(rc={rc})")

rc, out = run_compare(manifest(nar="sha256-x="), manifest(nar="sha256-y="))
check("genuine narHash divergence still reports NOT REPRODUCIBLE",
      rc == 1 and "NOT REPRODUCIBLE" in out, f"(rc={rc})")

rc, out = run_compare(manifest(nar=""), manifest())
check("missing narHash is INCONCLUSIVE, not a pass",
      rc == 2 and "REPRODUCIBLE:" not in out, f"(rc={rc})")


# ── repro-manifest.sh ───────────────────────────────────────────────────────

print()
print("repro-manifest.sh — refuses to write an uncomparable manifest")

with tempfile.TemporaryDirectory() as td:
    tdp = Path(td)
    bindir = tdp / "bin"
    bindir.mkdir()
    sentinel = tdp / "nix-was-called"
    # A nix stub that records having been run. If the lock check happens after
    # the build, this file appears and the test fails — the point is that an
    # unusable manifest is refused BEFORE an expensive build, and that the
    # refusal does not depend on having Nix at all.
    (bindir / "nix").write_text(
        f"#!/bin/sh\ntouch '{sentinel}'\necho /nonexistent/out\n"
    )
    (bindir / "nix").chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    work = tdp / "work"
    work.mkdir()
    p = subprocess.run(["bash", str(MANIFEST), ".#pkg"], cwd=work,
                       capture_output=True, text=True, env=env)
    out = p.stdout + p.stderr
    check("no flake.lock -> exit 2, not a manifest",
          p.returncode == 2 and "flake.lock missing" in out, f"(rc={p.returncode})")
    check("refused before invoking nix", not sentinel.exists())
    check("no manifest file was written",
          not list(work.glob("manifest-*.txt")))


# ── verdict ─────────────────────────────────────────────────────────────────

print()
if failures:
    print("=" * 74)
    print("SELFTEST FAILED — the guard cannot be trusted to block.")
    print("=" * 74)
    for f in failures:
        print(f"  {f}")
    sys.exit(1)

print("check-repro-inputs.selftest: PASS")
sys.exit(0)
