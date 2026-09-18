#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove check-deploy-image-pins.py fires on a mutable-tag image and stays quiet on a pinned one.

Builds a synthetic `deploy/` tree in a temp dir — never the real one — so
this can assert both directions without depending on whether the real deploy/
configs happen to be pinned today:

  * a bare-tag `image:` (the MED-7 shape) goes red, BY NAME (file:line in the
    output);
  * a `@sha256:`-pinned image, and a recognised placeholder line, stay green;
  * YAML anchors, aliases and merge keys fail closed rather than bypassing the
    explicit image-scalar scan;
  * a `deploy/` directory that does not exist at all is refused, not skipped.

Run: python3 scripts/check-deploy-image-pins.selftest.py
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-deploy-image-pins.py")

DIGEST = "a" * 64

PINNED_COMPOSE = """\
services:
  node:
    image: docker.io/blochv/bloch@sha256:%s
""" % DIGEST

UNPINNED_COMPOSE = """\
services:
  node:
    image: docker.io/blochv/bloch:0.1
"""

LOCAL_BUILD_COMPOSE = """\
services:
  node1:
    build: { context: .., dockerfile: Dockerfile }
    pull_policy: never
    image: bloch:latest  # local build only: docker build -t bloch . — never pulled from a registry
"""

PLACEHOLDER_COMPOSE = """\
services:
  node:
    image: REPLACE_WITH_DIGEST_PINNED_IMAGE
"""

MIXED_COMPOSE = """\
services:
  node:
    image: docker.io/blochv/bloch@sha256:%s
  sidecar:
    image: docker.io/blochv/sidecar:latest
""" % DIGEST


def run_checker(repo_root: str) -> subprocess.CompletedProcess:
    # The checker resolves REPO as its own parent's parent, so it must be run
    # with a copy of itself inside the synthetic tree, not against the real
    # repository. Copy the checker in, next to a `deploy/` directory.
    scripts_dir = os.path.join(repo_root, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    checker_copy = os.path.join(scripts_dir, "check-deploy-image-pins.py")
    with open(CHECKER, encoding="utf-8") as src, open(checker_copy, "w", encoding="utf-8") as dst:
        dst.write(src.read())
    return subprocess.run(
        [sys.executable, checker_copy],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )


def write_deploy(repo_root: str, name: str, content: str) -> None:
    deploy_dir = os.path.join(repo_root, "deploy")
    os.makedirs(deploy_dir, exist_ok=True)
    with open(os.path.join(deploy_dir, name), "w", encoding="utf-8") as fh:
        fh.write(content)


def case_unpinned_fails() -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        write_deploy(tmp, "docker-compose.yml", UNPINNED_COMPOSE)
        r = run_checker(tmp)
        if r.returncode == 0:
            return "unpinned image did not fail the guard:\n%s" % r.stdout
        if "docker-compose.yml:3" not in r.stdout:
            return "failure did not name the file:line:\n%s" % r.stdout
        if "docker.io/blochv/bloch:0.1" not in r.stdout:
            return "failure did not quote the offending image:\n%s" % r.stdout
    return None


def case_pinned_passes() -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        write_deploy(tmp, "docker-compose.yml", PINNED_COMPOSE)
        r = run_checker(tmp)
        if r.returncode != 0:
            return "digest-pinned image was rejected:\n%s%s" % (r.stdout, r.stderr)
        if "OK" not in r.stdout:
            return "pinned case did not print OK:\n%s" % r.stdout
    return None


def case_placeholder_passes() -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        write_deploy(tmp, "template.yml", PLACEHOLDER_COMPOSE)
        write_deploy(tmp, "docker-compose.yml", LOCAL_BUILD_COMPOSE)
        r = run_checker(tmp)
        if r.returncode != 0:
            return "recognised placeholder was rejected:\n%s%s" % (r.stdout, r.stderr)
    return None


def case_mixed_catches_the_one_unpinned() -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        write_deploy(tmp, "docker-compose.yml", MIXED_COMPOSE)
        r = run_checker(tmp)
        if r.returncode == 0:
            return "mixed file (one pinned, one not) did not fail:\n%s" % r.stdout
        if "sidecar:latest" not in r.stdout:
            return "failure did not name the unpinned sidecar image:\n%s" % r.stdout
        if "1 unpinned" not in r.stdout:
            return "expected exactly 1 unpinned finding (the pinned line must not " \
                   "also be flagged):\n%s" % r.stdout
    return None


def case_no_deploy_dir_is_refused() -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        # No deploy/ directory created at all.
        r = run_checker(tmp)
        if r.returncode == 0:
            return "a repo with no deploy/ directory passed instead of failing"
        if "does not exist" not in (r.stdout + r.stderr):
            return "missing-deploy-dir case did not explain why:\n%s%s" % (r.stdout, r.stderr)
    return None


def case_nested_yaml_is_scanned() -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        deploy_dir = os.path.join(tmp, "deploy")
        nested = os.path.join(deploy_dir, "akash", "genesis2")
        os.makedirs(nested, exist_ok=True)
        with open(os.path.join(nested, "deploy.yaml"), "w", encoding="utf-8") as fh:
            fh.write(UNPINNED_COMPOSE)
        r = run_checker(tmp)
        if r.returncode == 0:
            return "a nested deploy/**/*.yaml with an unpinned image passed:\n%s" % r.stdout
        if "akash/genesis2/deploy.yaml" not in r.stdout:
            return "failure did not name the nested file:\n%s" % r.stdout
    return None


def case_bypass_regressions() -> str | None:
    cases = {
        "comment digest": UNPINNED_COMPOSE.rstrip() + " # @sha256:" + DIGEST + "\n",
        "TODO comment": UNPINNED_COMPOSE.rstrip() + " # TODO: pin later\n",
        "user comment": UNPINNED_COMPOSE.rstrip() + " # YOUR_USER\n",
        "local comment": UNPINNED_COMPOSE.rstrip() + " # local build only\n",
        "trailing digest bytes": PINNED_COMPOSE.rstrip() + "suffix\n",
        "missing never": LOCAL_BUILD_COMPOSE.replace("    pull_policy: never\n", ""),
        "missing build": LOCAL_BUILD_COMPOSE.replace("    build: { context: .., dockerfile: Dockerfile }\n", ""),
        "other service policy": LOCAL_BUILD_COMPOSE.replace("    pull_policy: never\n", "") + "  other:\n    pull_policy: never\n",
        "single-quoted inline mapping": "services:\n  node: { 'image': bloch:latest }\n",
        "quoted inline mapping": 'services:\n  node: { "image": bloch:latest }\n',
        "inline mapping": "services:\n  node: { image: bloch:latest }\n",
        "list image": "containers:\n  - image: bloch:latest\n",
        "quoted key": 'services:\n  node:\n    "image": bloch:latest\n',
    }
    for name, content in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            write_deploy(tmp, "docker-compose.yml", content)
            r = run_checker(tmp)
            if r.returncode == 0:
                return "bypass accepted: %s\n%s" % (name, content)
    with tempfile.TemporaryDirectory() as tmp:
        write_deploy(tmp, "other.yml", LOCAL_BUILD_COMPOSE)
        if run_checker(tmp).returncode == 0:
            return "local-build exception escaped its single reviewed path"
    with tempfile.TemporaryDirectory() as tmp:
        write_deploy(tmp, "quoted.yml", PINNED_COMPOSE.replace("image: ", 'image: "').rstrip() + '"\n')
        if run_checker(tmp).returncode != 0:
            return "valid quoted digest refused"
    return None


def case_yaml_inheritance_fails_closed() -> str | None:
    cases = {
        "anchor": "x-base: &base\n  image: docker.io/blochv/bloch@sha256:%s\n" % DIGEST,
        "punctuated anchor": "x-base: &base.v1/path\n  image: docker.io/blochv/bloch@sha256:%s\n" % DIGEST,
        "alias": "services:\n  node: *base\n",
        "merge key": "services:\n  node:\n    <<: *base\n",
        "quoted merge key": 'services:\n  node:\n    "<<": *base\n',
        "flow alias": "services: { node: *base }\n",
        "quoted hash before anchor": 'x-base: { note: "x#y", holder: &base { image: bloch:latest } }\n',
        "quoted hash before alias": 'services: { note: "x#y", node: *base }\n',
        "flow literal merge": "services: { node: { <<: { image: bloch:latest } } }\n",
    }
    for name, content in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            write_deploy(tmp, "inheritance.yml", content)
            r = run_checker(tmp)
            if r.returncode == 0:
                return "YAML inheritance bypass accepted: %s\n%s" % (name, content)
            if "unsupported YAML inheritance" not in r.stdout:
                return "inheritance refusal did not name its reason: %s\n%s" % (name, r.stdout)

    accepted = {
        "quoted alias text": PINNED_COMPOSE + 'x-note: "use *base here and x#y"\n',
        "single quoted alias text": PINNED_COMPOSE + "x-note: 'use *base and x#y'\n",
        "block scalar alias text": PINNED_COMPOSE + "x-script: |\n  cp *base /tmp/output\n  echo x#y\n",
        "folded scalar anchor text": PINNED_COMPOSE + "x-script: >-\n  echo &base is documentation\n",
    }
    for name, content in accepted.items():
        with tempfile.TemporaryDirectory() as tmp:
            write_deploy(tmp, "literal.yml", content)
            r = run_checker(tmp)
            if r.returncode != 0:
                return "ordinary quoted/block text was refused: %s\n%s%s" % (
                    name, r.stdout, r.stderr
                )
    return None


def main() -> int:
    if not os.path.exists(CHECKER):
        print("selftest: FAIL — checker script not found at %s" % CHECKER)
        return 1

    cases = [
        ("15 digest/exemption/syntax regressions", case_bypass_regressions),
        ("YAML anchors, aliases and merge keys fail closed", case_yaml_inheritance_fails_closed),
        ("bare-tag image fails, names the file:line and the image", case_unpinned_fails),
        ("@sha256-pinned image passes", case_pinned_passes),
        ("recognised placeholder line passes", case_placeholder_passes),
        ("mixed file: pinned line ignored, unpinned line still caught", case_mixed_catches_the_one_unpinned),
        ("missing deploy/ directory is refused, not silently skipped", case_no_deploy_dir_is_refused),
        ("nested deploy/**/*.yaml files are scanned, not just top-level", case_nested_yaml_is_scanned),
    ]

    failures = []
    for name, fn in cases:
        err = fn()
        if err:
            failures.append((name, err))

    if failures:
        print("check-deploy-image-pins selftest: FAIL — %d/%d cases\n" % (len(failures), len(cases)))
        for name, err in failures:
            print("  * %s\n    %s" % (name, err.replace("\n", "\n    ")))
        return 1

    print("check-deploy-image-pins selftest: OK — %d cases behave as documented" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
