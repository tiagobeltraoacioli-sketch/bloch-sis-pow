#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run every workspace package and reject incomplete or interrupted evidence."""
import argparse
import json
from pathlib import Path
import re
import subprocess

MATRIX = (
    ("live", ["--workspace", "--exclude", "bloch", "--exclude", "bloch-l2-proof"]),
    # These suites include mining/backfill and real proof generation; debug
    # builds take hours and are not their documented execution profile.
    ("legacy", ["--release", "-p", "bloch"]),
    ("proof", ["--release", "-p", "bloch-l2-proof"]),
    # Cargo's workspace defaults do not include this lib target (test=false).
    ("indexer-lib", ["-p", "bloch-indexer", "--lib"]),
)


def assess(log, rc, allow_packages=(), allow_tests=()):
    summaries = re.findall(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", log, re.M)
    passed, failed, ignored = (sum(int(s[i]) for s in summaries) for i in range(3))
    failures, pending = [], []
    other_errors = []
    for line in log.splitlines():
        if re.match(r"\s*(Running|Doc-tests) ", line):
            failures.extend(("?", name) for name in pending)
            pending = []
        match = re.match(r"test (.+) \.\.\. FAILED$", line)
        if match:
            pending.append(match[1])
        package = re.search(r"^error: test failed, to rerun pass `-p ([\w-]+)", line)
        if package:
            failures.extend((package[1], name) for name in pending)
            pending = []
        elif re.match(r"^error(?:\[|:)", line) and not re.match(r"^error: \d+ targets failed:", line):
            other_errors.append(line)
    failures.extend(("?", name) for name in pending)
    blocking = [(pkg, name) for pkg, name in failures
                if pkg not in allow_packages and not any(name == t or name.endswith("::" + t) for t in allow_tests)]
    # 101 can be a compilation failure or a crashed test process as well as an
    # ordinary assertion failure. Allowed failures never excuse those cases.
    interrupted = bool(re.search(r"signal:|process didn't exit successfully|could not compile|could not execute", log))
    complete = bool(summaries) and not other_errors and not interrupted and failed == len(failures)
    status = "FAIL"
    if rc == 0 and complete and failed == 0:
        status = "PASS"
    elif rc == 101 and complete and failed > 0 and not blocking:
        status = "WARN"
    return dict(status=status, exit_code=rc, passed=passed, failed=failed, ignored=ignored,
                failures=failures, blocking=blocking, other_errors=other_errors,
                complete=complete)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    parser.add_argument("--allow-package", action="append", default=[])
    parser.add_argument("--allow-test", action="append", default=[])
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    for label, options in MATRIX:
        command = ["cargo", "test", *options, "--locked", "--no-fail-fast"]
        log = args.out / (label + ".log")
        print(f"{label}: {' '.join(command)}", flush=True)
        with log.open("w") as stream:
            rc = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT).returncode
        result = dict(label=label, command=command,
                      **assess(log.read_text(), rc, args.allow_package, args.allow_test))
        results.append(result)
        # Persist after each stage, but only the final summary certifies that
        # all four stages finished. A killed runner cannot leave a PASS behind.
        (args.out / (label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        print(f"{label}: {result['status']} rc={rc}, {result['passed']} passed, {result['failed']} failed", flush=True)
    status = "FAIL" if any(r["status"] == "FAIL" for r in results) else (
        "WARN" if any(r["status"] == "WARN" for r in results) else "PASS")
    (args.out / "summary.json").write_text(json.dumps(dict(status=status, stages=results), indent=2) + "\n")
    raise SystemExit(1 if status == "FAIL" else 0)


if __name__ == "__main__":
    main()
