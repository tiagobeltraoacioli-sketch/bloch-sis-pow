#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Apply source exceptions only to the exact reviewed file bytes.

A redacted native baseline does not bind replacement secret bytes at the same
location. History findings also bind immutable commits; tree findings do not.
An edited file therefore loses its exceptions until explicitly reviewed again.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).resolve()
pins = json.loads(Path(sys.argv[2]).read_text())
findings = json.loads(Path(sys.argv[3]).read_text())
if not isinstance(pins, dict) or not isinstance(findings, list):
    raise SystemExit("secret scan: malformed reviewed source baseline")
approved = set()
for name, expected in pins.items():
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SystemExit("secret scan: invalid reviewed source pin")
    candidate = source / path
    if not candidate.is_file() or candidate.is_symlink():
        continue
    if not candidate.resolve().is_relative_to(source):
        raise SystemExit("secret scan: reviewed source escaped scan tree")
    with candidate.open("rb") as incoming:
        digest = hashlib.sha256()
        for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
            digest.update(chunk)
        actual = digest.hexdigest()
    if actual == expected:
        approved.add(name)
filtered = [finding for finding in findings if finding.get("File") in approved]
Path(sys.argv[4]).write_text(json.dumps(filtered))
