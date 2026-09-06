#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Windowed negation filter for scripts/ci-banned-words.sh (finding LOW-7, Round 1).

Reads `git grep -iInE` hit lines ("path:lineno:content") on stdin, one per
line, and re-prints only the lines that carry a genuinely AFFIRMATIVE match:
a matched phrase with no negation word in the `window` characters immediately
BEFORE it. A negation word elsewhere on the line (after the phrase, or too
far before it) does not launder an affirmative claim — that whole-line
behaviour was the bug this file fixes: "Bloch is fully attested; no other
chain is." used to pass, because "no" is real but negates "other chain", not
"fully attested".

Usage: <hit lines on stdin> | ci-banned-words-negation-filter.py <earned_re> <negation_re> <window>
"""

from __future__ import annotations

import re
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: ci-banned-words-negation-filter.py <earned_re> <negation_re> <window>",
              file=sys.stderr)
        return 2

    earned_re = re.compile(sys.argv[1], re.IGNORECASE)
    negation_re = re.compile(sys.argv[2], re.IGNORECASE)
    window = int(sys.argv[3])

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        # git grep -I output: "path:lineno:content" — content may itself
        # contain colons, so split on the first two only.
        parts = line.split(":", 2)
        content = parts[2] if len(parts) == 3 else line
        affirmative = False
        for m in earned_re.finditer(content):
            preceding = content[max(0, m.start() - window):m.start()]
            if not negation_re.search(preceding):
                affirmative = True
                break
        if affirmative:
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
