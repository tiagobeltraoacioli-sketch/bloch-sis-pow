#!/usr/bin/env python3
"""Print the repository Rust channel after validating both release pins."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PINS = (
    ROOT / "rust-toolchain.toml",
    ROOT / "crates/bloch-pos-node/rust-toolchain.toml",
)
CHANNEL = re.compile(r'^channel\s*=\s*"([A-Za-z0-9._-]+)"\s*$')


def read_channel(path: Path) -> str:
    matches = [match.group(1) for line in path.read_text().splitlines()
               if (match := CHANNEL.match(line.strip()))]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected exactly one simple channel assignment")
    return matches[0]


def main() -> int:
    paths = tuple(Path(arg).resolve() for arg in sys.argv[1:]) or DEFAULT_PINS
    try:
        channels = [(path, read_channel(path)) for path in paths]
    except (OSError, ValueError) as error:
        print(f"toolchain pin error: {error}", file=sys.stderr)
        return 1
    expected = channels[0][1]
    mismatches = [f"{path}={channel}" for path, channel in channels if channel != expected]
    if mismatches:
        print("toolchain pins disagree: " + ", ".join(mismatches), file=sys.stderr)
        return 1
    print(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
