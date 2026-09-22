#!/usr/bin/env python3
"""Reject known PQ Shield documentation overclaims.

This is deliberately a wording guard, not evidence that the construction is
secure or deployed. It keeps corrected trust-boundary statements from silently
regressing while the protocol integration remains future work.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Mapping


TARGETS = (
    "crates/bloch-pq-vault/src/anchor.rs",
    "crates/bloch-pq-vault/src/vault.rs",
    "docs/specs/PQ-SHIELD-NONCUSTODIAL-NATIVE.md",
    "services/pq-shield-api/README.md",
    "services/pq-shield-api/src/lib.rs",
)

BANNED = (
    "Bloch enforces the PQ half",
    "PQ-gated clawback",
    "PQ-authorized clawback",
    "watchtower can fee-bump",
    "No code in this repo implements this yet",
    "Securely delete the trigger bypass key",
)

REQUIRED = {
    "crates/bloch-pq-vault/src/anchor.rs": (
        "No code here posts, orders or enforces",
    ),
    "crates/bloch-pq-vault/src/vault.rs": (
        "keyless watchtower needs pre-signed replacements",
    ),
    "docs/specs/PQ-SHIELD-NONCUSTODIAL-NATIVE.md": (
        "Opt-in `SeparatedDepositV1` separates the public",
        "Giving a service `recovery_sk` or an equivalent signing oracle",
        "it does not post or order it on Bloch",
    ),
    "services/pq-shield-api/README.md": (
        "does not post, order, revoke,",
        "finite pre-signed replacements",
    ),
}


def violations(documents: Mapping[str, str]) -> list[str]:
    failures: list[str] = []
    for name, text in documents.items():
        for phrase in BANNED:
            if phrase.casefold() in text.casefold():
                failures.append(f"{name}: obsolete claim: {phrase!r}")
    for name, phrases in REQUIRED.items():
        text = documents.get(name, "")
        for phrase in phrases:
            if phrase not in text:
                failures.append(f"{name}: missing limitation: {phrase!r}")
    return failures


def selftest() -> None:
    valid = {name: "\n".join(REQUIRED.get(name, ())) for name in TARGETS}
    assert violations(valid) == []

    for phrase in BANNED:
        poisoned = dict(valid)
        poisoned[TARGETS[0]] += f"\n{phrase}\n"
        found = violations(poisoned)
        assert any(phrase in failure for failure in found), phrase

    for name, phrases in REQUIRED.items():
        for phrase in phrases:
            incomplete = dict(valid)
            incomplete[name] = incomplete[name].replace(phrase, "")
            found = violations(incomplete)
            assert any(name in failure and phrase in failure for failure in found), phrase

    print("PQ Shield claims guard self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0

    root = Path(__file__).resolve().parent.parent
    documents = {name: (root / name).read_text(encoding="utf-8") for name in TARGETS}
    failures = violations(documents)
    if failures:
        print("PQ Shield claim check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PQ Shield claims match the implemented trust boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
