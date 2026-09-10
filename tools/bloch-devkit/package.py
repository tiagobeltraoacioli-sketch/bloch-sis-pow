#!/usr/bin/env python3
"""Build reproducible, source-only downloads for the static developer sites."""
import hashlib
from pathlib import Path
import sys
import zipfile
from bloch_dev import VERSION

root = Path(__file__).resolve().parent
allowed = {".py", ".md", ".sol", ".toml", ".rs", ".json", ".mjs", ".lock"}
files = sorted(p for p in root.rglob("*") if p.is_file() and (p.suffix in allowed or p.name == "LICENSE")
               and not any(part in {"__pycache__", "node_modules", "target", ".bloch-dev"}
                           for part in p.relative_to(root).parts))
for target in sys.argv[1:]:
    destination = Path(target)
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f"bloch-devkit-{VERSION}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path in files:
            info = zipfile.ZipInfo(f"bloch-devkit-{VERSION}/" + path.relative_to(root).as_posix(),
                                   date_time=(2026, 9, 10, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, path.read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n")
    print(f"{archive}: {len(files)} source files, SHA-256 {digest}")
