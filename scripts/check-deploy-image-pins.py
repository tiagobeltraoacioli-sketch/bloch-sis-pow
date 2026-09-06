#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""check-deploy-image-pins.py — refuse a deploy config that pulls by mutable tag.

WHY THIS EXISTS (Round-1 audit finding MED-7)
----------------------------------------------
Every Dockerfile in this repository pins its base images by digest, with the
comment "Update the digest deliberately, never float the tag." (Dockerfile:27,
Dockerfile.euvm:2-3, pool.Dockerfile:3-4) — a deliberate, stated discipline.
The deployment configs under deploy/ (Akash SDLs, docker-compose files) that
pull the BUILT node/pool image do not follow it: `docker.io/blochv/bloch:0.1`,
`bloch:latest`, `bloch:local`, `bloch:v0.1.0`, and similar bare-tag references.
A mutable tag means anyone with push access to that registry path — or the
registry operator itself — can retag it, and every deploy that references the
tag pulls new bytes on its next restart with no diff and no gate. This also
defeats `deploy/attestation/image-security-policy.json`'s
`"signedIdentity": {"type": "matchRepoDigestOrExact"}`, which is written to
bind a DIGEST, not a name.

WHAT THIS GUARD DOES
--------------------
Scans every tracked YAML file under deploy/ (docker-compose files included,
wherever they live) for an `image:` key and requires the value to carry a
`@sha256:<64-hex>` digest. It does not attempt to resolve or verify the
digest against a registry — that is what `deploy/RELEASE-INTEGRITY.md`'s
attestation policy and `sign-image.sh` already do; this is the cheap,
offline, "did anyone forget to pin it at all" check that catches the escape
before it reaches a registry pull.

OWNERSHIP NOTE, stated plainly: this script is the CI/supply-chain gate. It
does not itself pin any image (that is deploy/ configuration content, owned
by the deployment/ops workstream) — it only fails the pipeline until that
pinning is done. On THIS revision it is RED: every image: reference under
deploy/ is a bare tag (verified: `grep -rn 'image:' deploy/` finds zero
`@sha256:` occurrences). That is an honest finding, not a bug in the guard —
see the selftest for proof the guard can also go green on a pinned config.

Usage: python3 scripts/check-deploy-image-pins.py
Exit 0 = every deploy/ image: reference carries a @sha256 digest.
Exit 1 = at least one does not (each is printed, file:line).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO / "deploy"

# `image:` inside a YAML mapping — same shape whether it's an Akash SDL
# service, a docker-compose service, or a raw Kubernetes-style manifest.
IMAGE_RE = re.compile(r"^\s*image:\s*(\S+)")
DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]{64}\b")

# A value that is a template placeholder for the deployer to fill in is not
# a "mutable tag" finding in the same sense — it never resolves to a running
# image at all until edited. Recognised ONLY by an exact, deliberately narrow
# marker so this can never quietly swallow a real unpinned production image:
# the line must ALSO carry one of these comment markers, not just any word.
PLACEHOLDER_MARKERS = ("YOUR_USER", "TODO:", "replace with your published image")


def find_yaml_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.y*ml") if p.is_file())


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(text.split("\n"), start=1):
        m = IMAGE_RE.match(line)
        if not m:
            continue
        value = m.group(1)
        if DIGEST_RE.search(line):
            continue
        if any(marker in line for marker in PLACEHOLDER_MARKERS):
            continue
        problems.append(
            "%s:%d: image `%s` has no @sha256 digest pin"
            % (path.relative_to(REPO), lineno, value)
        )
    return problems


def main() -> int:
    if not DEPLOY_DIR.is_dir():
        print("check-deploy-image-pins: FAIL — deploy/ does not exist", file=sys.stderr)
        return 1

    files = find_yaml_files(DEPLOY_DIR)
    problems: list[str] = []
    for f in files:
        problems += check_file(f)

    if problems:
        print("check-deploy-image-pins: FAIL — %d unpinned image(s)\n" % len(problems))
        for p in problems:
            print("  * %s" % p)
        print(
            "\nPin every `image:` to `@sha256:<64-hex>` (finding MED-7, Round 1) — "
            "record the digest in the release notes beside the binary sha256, the "
            "same way deploy/RELEASE-INTEGRITY.md §7.6 already does. A placeholder "
            "the operator must still fill in (YOUR_USER / TODO: / 'replace with "
            "your published image') is exempt until it names a real image."
        )
        return 1

    print(
        "check-deploy-image-pins: OK — every deploy/ image: reference is "
        "@sha256-pinned (%d file(s) scanned)" % len(files)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
