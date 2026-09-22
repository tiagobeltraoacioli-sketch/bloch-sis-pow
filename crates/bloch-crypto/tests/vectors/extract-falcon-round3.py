#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Extract public verification data from the exact official Falcon submission."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ARCHIVE_SHA256 = "d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47"
RSP_SHA256 = "036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d"
archive_path = Path(sys.argv[1])
with archive_path.open("rb") as incoming:
    digest = hashlib.sha256()
    for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != ARCHIVE_SHA256:
    raise SystemExit("unreviewed Falcon submission archive")
with zipfile.ZipFile(archive_path) as archive:
    name = "falcon-round3/KAT/falcon1024-KAT.rsp"
    if archive.getinfo(name).file_size > 2 * 1024 * 1024:
        raise SystemExit("unexpected Falcon response file size")
    raw = archive.read(name)
if hashlib.sha256(raw).hexdigest() != RSP_SHA256:
    raise SystemExit("unreviewed Falcon response file")
cases = []
for block in raw.decode("ascii").split("\n\n"):
    fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
    if fields.get("count") not in {"0", "1", "99"}:
        continue
    # Deliberately omit seed and secret key, even though submission KATs are public.
    cases.append({key: int(fields[key]) if key in {"count", "mlen", "smlen"} else fields[key].lower()
                  for key in ("count", "mlen", "msg", "pk", "smlen", "sm")})
if [case["count"] for case in cases] != [0, 1, 99]:
    raise SystemExit("missing reviewed Falcon cases")
Path(sys.argv[2]).write_text(json.dumps(cases, indent=2) + "\n")
