#!/usr/bin/env python3
"""deny-license-exceptions-guard.py — CI gate for audit finding D-H1-deny-agpl.

WHAT: fails the pipeline when `deny.toml`'s per-crate copyleft exceptions do
not EXACTLY match the copyleft (AGPL/GPL/LGPL) crates in the root workspace.

WHY: the workspace relicensed its own crates to AGPL-3.0-or-later, and AGPL is
deliberately absent from `[licenses] allow` so a THIRD-PARTY copyleft dep still
fails the gate. First-party crates are readmitted one by one through
`[[licenses.exceptions]]`. That hand-maintained list drifted: four AGPL members
(bloch-pos-committee, bloch-pos-node, bloch-pq-vault, genesis4-ceremony) were
never added, so the BLOCKING `supply-chain` job could not have been passing as
configured. A list you have to remember to update is not a policy.

This guard derives the truth from the manifests instead:

  * every copyleft workspace member MUST have an exception allowing its exact
    license expression        — otherwise `cargo deny check licenses` is red;
  * every exception that admits copyleft MUST name a copyleft member
    — otherwise a rename/typo leaves a dead entry, or widens the policy for a
      crate that is no longer first-party;
  * copyleft MUST NOT be in the global `[licenses] allow`
    — that is what keeps third-party copyleft denied.

It is a fast, offline, network-free pre-check for the same defect
`cargo deny check licenses` catches after resolving the whole graph.

Usage: python3 scripts/deny-license-exceptions-guard.py   (run from anywhere)
Exit 0 = consistent. Exit 1 = drift, with the exact lines to add or remove.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Copyleft families that the global `allow` deliberately excludes. Matched
# against the SPDX expression so "AGPL-3.0-or-later", "GPL-2.0-only" and
# "LGPL-3.0" are all caught, while "Apache-2.0" and "MIT" are not.
COPYLEFT = re.compile(r"\b(?:A|L)?GPL-", re.IGNORECASE)


def load(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def member_dirs(root: dict) -> list[Path]:
    """Workspace `members`, with globs expanded and `exclude` honoured."""
    ws = root.get("workspace", {})
    excluded = {(REPO / e).resolve() for e in ws.get("exclude", [])}
    dirs: list[Path] = []
    for entry in ws.get("members", []):
        matches = sorted(REPO.glob(entry)) if any(c in entry for c in "*?[") else [REPO / entry]
        for d in matches:
            if (d / "Cargo.toml").is_file() and d.resolve() not in excluded:
                dirs.append(d)
    return dirs


def package_license(manifest: dict, root: dict) -> str:
    """A member's license, resolving `license.workspace = true` inheritance."""
    lic = manifest.get("package", {}).get("license")
    if isinstance(lic, dict) and lic.get("workspace"):
        lic = root.get("workspace", {}).get("package", {}).get("license")
    return lic or ""


def main() -> int:
    root = load(REPO / "Cargo.toml")
    deny = load(REPO / "deny.toml")

    # name -> license expression, for every copyleft workspace member.
    copyleft_members: dict[str, str] = {}
    for d in member_dirs(root):
        manifest = load(d / "Cargo.toml")
        name = manifest.get("package", {}).get("name")
        lic = package_license(manifest, root)
        if name and COPYLEFT.search(lic):
            copyleft_members[name] = lic

    # name -> allowed licenses, for every exception admitting copyleft.
    exceptions: dict[str, list[str]] = {}
    for exc in deny.get("licenses", {}).get("exceptions", []):
        allow = exc.get("allow", [])
        if any(COPYLEFT.search(a) for a in allow):
            exceptions[exc["name"]] = allow

    errors: list[str] = []

    for name, lic in sorted(copyleft_members.items()):
        if name not in exceptions:
            errors.append(
                f"workspace member `{name}` is {lic} but has no deny.toml exception.\n"
                f"    Add to deny.toml:\n"
                f'        [[licenses.exceptions]]\n'
                f'        name = "{name}"\n'
                f'        allow = ["{lic}"]'
            )
        elif lic not in exceptions[name]:
            errors.append(
                f"workspace member `{name}` is {lic} but its deny.toml exception "
                f"allows {exceptions[name]} — the expressions must match exactly."
            )

    for name in sorted(exceptions):
        if name not in copyleft_members:
            errors.append(
                f"deny.toml grants a copyleft exception to `{name}`, which is not a "
                f"copyleft workspace member (renamed, removed, or a typo). Remove it "
                f"— a stale exception silently admits copyleft from a crate the "
                f"project no longer owns."
            )

    globally_allowed = [a for a in deny.get("licenses", {}).get("allow", []) if COPYLEFT.search(a)]
    if globally_allowed:
        errors.append(
            f"[licenses] allow contains copyleft {globally_allowed}. Copyleft must be "
            f"granted per-crate via [[licenses.exceptions]] only, or THIRD-PARTY "
            f"copyleft dependencies stop failing the gate."
        )

    if errors:
        print("deny.toml license-exception drift:\n", file=sys.stderr)
        for err in errors:
            print(f"  - {err}\n", file=sys.stderr)
        print(
            f"{len(errors)} problem(s). `cargo deny check licenses` cannot pass as "
            f"configured; see the exceptions block in deny.toml.",
            file=sys.stderr,
        )
        return 1

    names = ", ".join(sorted(copyleft_members))
    print(f"deny.toml OK — {len(copyleft_members)} copyleft workspace members, each with a matching exception:")
    print(f"  {names}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
