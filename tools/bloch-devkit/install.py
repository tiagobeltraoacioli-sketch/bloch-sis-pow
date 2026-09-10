#!/usr/bin/env python3
"""Install the CLI and templates without third-party Python dependencies."""
from pathlib import Path
import shlex
import shutil
import sys

source = Path(__file__).resolve().parent
destination = Path.home() / ".local/share/bloch-dev/kit"
destination.mkdir(parents=True, exist_ok=True)
shutil.copy2(source / "bloch_dev.py", destination / "bloch_dev.py")
shutil.copy2(source / "bloch_network.py", destination / "bloch_network.py")
for name in ("README.md", "INTEGRATION.md", "COMMUNITY.md", "NETWORK.md", "VALIDATION.md"):
    shutil.copy2(source / name, destination / name)
shutil.copytree(source / "templates", destination / "templates", dirs_exist_ok=True)
binary = Path.home() / ".local/bin/bloch-dev"
binary.parent.mkdir(parents=True, exist_ok=True)
binary.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " "
                  + shlex.quote(str(destination / "bloch_dev.py")) + ' "$@"\n')
binary.chmod(0o755)
print(f"Installed {binary}\nAdd {binary.parent} to PATH, or run the absolute path.")
