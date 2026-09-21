#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove the lockfile section of `pos-release-integrity.sh` fires, and on the right file.

Why this file exists
--------------------
The lockfile guard was green for its whole life while guarding nothing. It
resolved `--locked` from inside crates/bloch-pos-node and crates/bloch-pos-
committee and then diffed *their* Cargo.lock files — but both crates are
members of the root virtual workspace, so cargo has never read either file.
Measured on the tree before the fix: append a line to the root Cargo.lock and
the guard's drift diff still exited 0. Six dead per-member lockfiles had
accumulated beside live crates, reading as authoritative.

A guard nobody has tried to break is a guard nobody knows works. So this drives
the REAL script — copied byte-for-byte into a synthetic workspace built in a
temporary directory, never the real tree — in its `--locks-only` mode, and
asserts BOTH directions:

  * an honest tree passes, and passes for the stated reason (the success line
    must say the ROOT lock governs the members);
  * a stale root Cargo.lock FAILS — the case the old guard could not see;
  * a resurrected per-member Cargo.lock FAILS and is named, so the deletion
    cannot quietly undo itself;
  * a member that grows its own `[workspace]` table FAILS instead of going
    unguarded — the shape the old comments wrongly believed was already true;
  * a renamed PoS crate FAILS rather than dropping out of the guard's scope;
  * full mode refuses tracked source edits both unstaged and staged, while an
    untracked CI-output file advances beyond the source-cleanliness checks.
  * full mode accepts a real canonical SHA-256 result, rejects two different
    regular build outputs, and rejects tool failure, short, nonhexadecimal,
    uppercase and multiple-row digest output;
  * full mode really uses two distinct fresh target directories, so the
    target-path normalization regression cannot be hidden by one reused path.

The post-build drift diff (section 3) needs a compiler and a minute of build to
reach, so it is asserted at the source level instead: it must name the root
Cargo.lock and must name no per-member lockfile.

Run: `python3 scripts/pos-release-integrity.selftest.py`
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "pos-release-integrity.sh")

ROOT_MANIFEST = """\
[workspace]
resolver = "2"
members = [
{members}]
"""

CRATE_MANIFEST = """\
[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
"""


def build_fixture(tmp: str, members=("bloch-pos-node", "bloch-pos-committee")) -> str:
    """A minimal, dependency-free stand-in for the real workspace layout."""
    root = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(root, "scripts"))
    shutil.copy(GUARD, os.path.join(root, "scripts", "pos-release-integrity.sh"))
    write_root(root, members)
    for name in members:
        crate = os.path.join(root, "crates", name)
        os.makedirs(os.path.join(crate, "src"))
        write(os.path.join(crate, "Cargo.toml"), CRATE_MANIFEST.format(name=name))
        write(os.path.join(crate, "src", "lib.rs"), "")
    relock(root)
    # A git repo, because the drift assertion the guard shares between sections
    # 1 and 3 is a `git diff` — the very check that used to watch the wrong
    # files. Without a repo it could not be exercised at all.
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "-c", "user.email=selftest@invalid", "-c", "user.name=selftest",
        "commit", "-qm", "fixture")
    return root


def git(root: str, *args: str) -> None:
    subprocess.run(["git", "-C", root, *args], check=True, capture_output=True)


def write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def write_root(root: str, members) -> None:
    body = "".join(f'    "crates/{m}",\n' for m in members)
    write(os.path.join(root, "Cargo.toml"), ROOT_MANIFEST.format(members=body))


def relock(root: str) -> None:
    subprocess.run(
        ["cargo", "generate-lockfile", "--offline"],
        cwd=root, check=True, capture_output=True,
    )


def run_guard(root: str, *, args=None, extra_env=None):
    env = os.environ.copy()
    env.update(extra_env or {})
    build_state = env.get("INTEGRITY_BUILD_STATE")
    if build_state:
        for suffix in (".count", ".first-target"):
            try:
                os.unlink(build_state + suffix)
            except FileNotFoundError:
                pass
    return subprocess.run(
        ["bash", os.path.join(root, "scripts", "pos-release-integrity.sh"),
         *(args if args is not None else ["--locks-only"])],
        cwd=root, capture_output=True, text=True, env=env,
    )


def prepare_full_mode_fixture(tmp: str):
    """Return a clean repo plus fake compiler/build tools for full-mode tests."""
    root = build_fixture(tmp)
    pin = os.path.join(root, "crates", "bloch-pos-node", "rust-toolchain.toml")
    write(pin, '[toolchain]\nchannel = "1.94.1"\n')
    git(root, "add", "crates/bloch-pos-node/rust-toolchain.toml")
    git(root, "-c", "user.email=selftest@invalid", "-c", "user.name=selftest",
        "commit", "-qm", "add toolchain pin")

    tools = os.path.join(tmp, "tools")
    os.makedirs(tools)
    fake_binary = os.path.join(tmp, "fake-bloch-pos")
    write(fake_binary, """#!/usr/bin/env bash
set -euo pipefail
case "${INTEGRITY_VERSION_MODE:-canonical}" in
  canonical)
    printf 'bloch-pos selftest (%s)\\n' "${INTEGRITY_TEST_COMMIT:?}"
    printf '%s\\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    ;;
  exit) exit 75 ;;
  missing-commit)
    printf '%s\\n' 'bloch-pos selftest (unbound)'
    printf '%s\\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    ;;
  undelimited-commit)
    printf 'bloch-pos selftest commit=%s\\n' "${INTEGRITY_TEST_COMMIT:?}"
    printf '%s\\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    ;;
  decoy-third)
    printf '%s\\n' 'bloch-pos selftest (unbound)'
    printf '%s\\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    printf 'decoy (%s)\\n' "${INTEGRITY_TEST_COMMIT:?}"
    ;;
  extra-line)
    printf 'bloch-pos selftest (%s)\\n' "${INTEGRITY_TEST_COMMIT:?}"
    printf '%s\\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    printf '%s\\n' 'unexpected third line'
    ;;
  malformed-source)
    printf 'bloch-pos selftest (%s)\\n' "${INTEGRITY_TEST_COMMIT:?}"
    printf '%s\\n' 'source-digest sha3-256:NOT-LOWERCASE-HEX (1 files, 1 bytes) commit-source:asserted tree:dirty'
    ;;
  missing-final-newline)
    printf 'bloch-pos selftest (%s)\\n' "${INTEGRITY_TEST_COMMIT:?}"
    printf '%s' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    ;;
  trailing-byte)
    printf 'bloch-pos selftest (%s)\\n' "${INTEGRITY_TEST_COMMIT:?}"
    printf '%s\\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    printf x
    ;;
  *) exit 76 ;;
esac
""")

    metadata = json.dumps({
        "workspace_root": root,
        "workspace_members": ["node", "committee"],
        "packages": [
            {"id": "node", "name": "bloch-pos-node",
             "manifest_path": os.path.join(root, "crates", "bloch-pos-node",
                                           "Cargo.toml")},
            {"id": "committee", "name": "bloch-pos-committee",
             "manifest_path": os.path.join(root, "crates", "bloch-pos-committee",
                                           "Cargo.toml")},
        ],
    })
    write(os.path.join(tools, "cargo"), """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  metadata)
    printf '%s\\n' """ + shlex.quote(metadata) + """
    ;;
  build)
    target=
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --target-dir ]; then
        shift
        target="$1"
      fi
      shift
    done
    [ -n "$target" ]
    state="${INTEGRITY_BUILD_STATE:?}"
    count=0
    [ ! -f "$state.count" ] || read -r count < "$state.count"
    count=$((count + 1))
    printf '%s\n' "$count" > "$state.count"
    case "$count:$target" in
      1:*/t1)
        [ ! -e "$target" ] || exit 77
        printf '%s\n' "$target" > "$state.first-target"
        ;;
      2:*/t2)
        [ ! -e "$target" ] || exit 78
        [ "$(cat "$state.first-target")" != "$target" ] || exit 79
        ;;
      *) exit 80 ;;
    esac
    mkdir -p "$target/release"
    case "${INTEGRITY_BINARY_MODE:-canonical}:$count" in
      canonical:*) cp "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos" ;;
      different-second:1) cp "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos" ;;
      different-second:2)
        cp "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos"
        printf '\n# different second build\n' >> "$target/release/bloch-pos"
        ;;
      symlink-first:1) ln -s "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos" ;;
      symlink-second:2) ln -s "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos" ;;
      hardlink-first:1) ln "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos" ;;
      hardlink-second:2) ln "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos" ;;
      symlink-first:*|symlink-second:*|hardlink-first:*|hardlink-second:*)
        cp "$INTEGRITY_FAKE_BINARY" "$target/release/bloch-pos" ;;
      *) exit 74 ;;
    esac
    chmod 0755 "$target/release/bloch-pos"
    ;;
  *) exit 70 ;;
esac
""")
    write(os.path.join(tools, "rustc"), """#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = --version ] || exit 71
printf 'rustc 1.94.1 (selftest)\\n'
""")
    write(os.path.join(tools, "sha256sum"), """#!/usr/bin/env bash
set -euo pipefail
delegate() {
  if [ -n "${REAL_SHA256SUM:-}" ]; then
    exec "$REAL_SHA256SUM" "$@"
  else
    exec "$REAL_SHASUM" -a 256 "$@"
  fi
}
case "${INTEGRITY_SHA_MODE:-canonical}" in
  canonical) delegate "$@" ;;
  exit) exit 72 ;;
  short) printf '%063d  %s\\n' 0 "${1:-input}" ;;
  nonhex) printf '%064d  %s\\n' 0 "${1:-input}" | tr 0 g ;;
  uppercase) printf '%064d  %s\\n' 0 "${1:-input}" | tr 0 A ;;
  multirow)
    printf '%064d  %s\\n' 0 "${1:-input}"
    printf '%064d  second-row\\n' 0
    ;;
  *) exit 73 ;;
esac
""")
    for name in ("cargo", "rustc", "sha256sum"):
        os.chmod(os.path.join(tools, name), 0o755)
    os.chmod(fake_binary, 0o755)

    real_sha256sum = shutil.which("sha256sum") or ""
    real_shasum = shutil.which("shasum") or ""
    if not real_sha256sum and not real_shasum:
        raise RuntimeError("no host SHA-256 implementation is available")
    env = {
        "PATH": tools + os.pathsep + os.environ.get("PATH", ""),
        "REAL_SHA256SUM": real_sha256sum,
        "REAL_SHASUM": real_shasum,
        "INTEGRITY_SHA_MODE": "canonical",
        "INTEGRITY_VERSION_MODE": "canonical",
        "INTEGRITY_FAKE_BINARY": fake_binary,
        "INTEGRITY_BUILD_STATE": os.path.join(tmp, "fake-build-state"),
        "INTEGRITY_TEST_COMMIT": subprocess.run(
            ["git", "-C", root, "rev-parse", "--short=12", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip(),
    }
    return root, env


FAILURES: list[str] = []


def expect_pass(case: str, root: str, must_say: str) -> None:
    res = run_guard(root)
    out = res.stdout + res.stderr
    if res.returncode != 0:
        FAILURES.append(f"{case}: honest tree was rejected (exit {res.returncode})\n{out}")
    elif must_say not in out:
        FAILURES.append(f"{case}: passed, but not for the stated reason "
                        f"(missing {must_say!r})\n{out}")
    else:
        print(f"  ok   {case}")


def expect_fail(case: str, root: str, must_say: str, *, args=None) -> None:
    res = run_guard(root, args=args)
    out = res.stdout + res.stderr
    if res.returncode == 0:
        FAILURES.append(f"{case}: guard PASSED on a tree it must reject\n{out}")
    elif must_say not in out:
        FAILURES.append(f"{case}: failed, but for the wrong reason "
                        f"(missing {must_say!r})\n{out}")
    else:
        print(f"  ok   {case}")


def main() -> int:
    if shutil.which("cargo") is None:
        print("pos-release-integrity.selftest: FAIL — cargo is not on PATH; "
              "this selftest cannot certify the guard without it.", file=sys.stderr)
        return 1

    print("pos-release-integrity.selftest: driving scripts/pos-release-integrity.sh "
          "--locks-only against synthetic workspaces")

    # 1 — honest tree passes, and says the ROOT lock is what governs.
    with tempfile.TemporaryDirectory() as tmp:
        expect_pass("honest workspace", build_fixture(tmp),
                    "root Cargo.lock resolves --locked")

    # 2 — the case the old guard could not see: the root lock no longer matches
    #     the manifests. A third member is added without regenerating the lock.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        crate = os.path.join(root, "crates", "bloch-pos-extra")
        os.makedirs(os.path.join(crate, "src"))
        write(os.path.join(crate, "Cargo.toml"),
              CRATE_MANIFEST.format(name="bloch-pos-extra"))
        write(os.path.join(crate, "src", "lib.rs"), "")
        write_root(root, ("bloch-pos-node", "bloch-pos-committee", "bloch-pos-extra"))
        expect_fail("locked metadata failure", root, "locked metadata resolution failed")

    # 3 — a deleted per-member lockfile comes back.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        shutil.copy(os.path.join(root, "Cargo.lock"),
                    os.path.join(root, "crates", "bloch-pos-committee", "Cargo.lock"))
        expect_fail("resurrected per-member lockfile", root,
                    "crates/bloch-pos-committee/Cargo.lock")

    # 4 — a PoS crate grows its own [workspace] table. It then really would need
    #     its own lock, so the guard must stop rather than keep reporting green.
    #     The split crate is given a lock of its own here on purpose: without
    #     one the guard already dies at the --locked resolve, and it is the
    #     *plausible* variant — split, locked, looks tidy — that has to be
    #     caught by the membership assert rather than sailing through.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        crate = os.path.join(root, "crates", "bloch-pos-node")
        with open(os.path.join(crate, "Cargo.toml"), "a", encoding="utf-8") as fh:
            fh.write("\n[workspace]\n")
        write_root(root, ("bloch-pos-committee",))
        relock(root)
        relock(crate)
        expect_fail("member split into its own workspace", root, "workspace root")

    # 5 — a PoS crate is renamed. The guard must not quietly narrow its scope.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp, members=("bloch-pos-node", "bloch-pos-consensus"))
        expect_fail("renamed PoS crate", root, "is not a member")

    # 6 — the defect itself, behaviourally: a rewritten ROOT Cargo.lock must be
    #     caught. Measured on the real tree before the fix, the guard's drift
    #     diff named crates/bloch-pos-{node,committee}/Cargo.lock and exited 0
    #     on exactly this mutation. A pristine per-member lockfile is planted
    #     alongside so a guard that regressed to the old paths would still see
    #     "no change" and pass — the fixture reproduces the fail-open, not just
    #     the drift.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        shutil.copy(os.path.join(root, "Cargo.lock"),
                    os.path.join(root, "crates", "bloch-pos-node", "Cargo.lock.pristine"))
        with open(os.path.join(root, "Cargo.lock"), "a", encoding="utf-8") as fh:
            fh.write("\n# rewritten by a build\n")
        expect_fail("rewritten root Cargo.lock", root, "root Cargo.lock differs")

    # Staging a changed lock must not hide it from the committed-source check.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        with open(os.path.join(root, "Cargo.lock"), "a", encoding="utf-8") as fh:
            fh.write("\n# staged, but not part of HEAD\n")
        git(root, "add", "Cargo.lock")
        expect_fail("staged root Cargo.lock", root, "root Cargo.lock differs")

    # A full release check must never label locally edited tracked bytes with
    # HEAD. These cases stop after metadata/lock validation and before rustc or
    # either build, so they remain fast and hermetic.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        write(os.path.join(root, "crates", "bloch-pos-node", "src", "lib.rs"),
              "// unstaged release source\n")
        expect_fail("unstaged tracked release source", root,
                    "tracked working tree differs from HEAD", args=[])

    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        source = os.path.join(root, "crates", "bloch-pos-node", "src", "lib.rs")
        write(source, "// staged release source\n")
        git(root, "add", "crates/bloch-pos-node/src/lib.rs")
        expect_fail("staged tracked release source", root,
                    "index differs from HEAD", args=[])

    # Untracked CI output is deliberately outside the source-cleanliness
    # contract. Prove it passes the new checks and reaches the next expected
    # precondition (the minimal fixture intentionally has no toolchain pin).
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        write(os.path.join(root, "untracked-ci-output"), "not a build input\n")
        expect_fail("untracked output remains permitted", root,
                    "rust-toolchain.toml is missing", args=[])

    # Reject ambient build overrides before metadata/compiler execution. Never
    # echo their contents; flags and wrapper paths may contain private values.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        for variable in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                         "CARGO_PROFILE_RELEASE_LTO", "CARGO_BUILD_TARGET",
                         "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"):
            marker = "private-build-override-never-echo"
            result = run_guard(root, args=[], extra_env={variable: marker})
            output = result.stdout + result.stderr
            if (result.returncode == 0 or f"unset build override {variable}" not in output
                    or marker in output):
                FAILURES.append(f"environment override {variable} was not safely refused")
            else:
                print(f"  ok   refuses {variable} without echoing its value")

    # The full guard must not call two identical arbitrary strings proof of
    # byte identity. Fake cargo/rustc avoid a real build, while canonical SHA
    # mode delegates by absolute path to the host implementation. Adversarial
    # modes therefore affect only the real guard's digest observation.
    with tempfile.TemporaryDirectory() as tmp:
        try:
            root, full_env = prepare_full_mode_fixture(tmp)
        except RuntimeError as exc:
            FAILURES.append(f"full-mode SHA fixture: {exc}")
        else:
            canonical = run_guard(root, args=[], extra_env=full_env)
            canonical_output = canonical.stdout + canonical.stderr
            if canonical.returncode != 0:
                FAILURES.append("canonical full-mode SHA was rejected "
                                f"(exit {canonical.returncode})\n{canonical_output}")
            elif "pos-release-integrity: PASS" not in canonical_output:
                FAILURES.append("canonical full-mode SHA passed without the "
                                f"guard success diagnostic\n{canonical_output}")
            else:
                print("  ok   canonical full-mode SHA-256 output passes")

            different = run_guard(
                root, args=[],
                extra_env={**full_env, "INTEGRITY_BINARY_MODE": "different-second"},
            )
            different_output = different.stdout + different.stderr
            if different.returncode == 0:
                FAILURES.append("full mode accepted two different valid build outputs\n"
                                f"{different_output}")
            elif "two clean builds of the same commit differ" not in different_output:
                FAILURES.append("full mode rejected different valid build outputs without "
                                f"the determinism diagnostic\n{different_output}")
            elif "determinism: ok" in different_output:
                FAILURES.append("full mode claimed determinism for different valid outputs\n"
                                f"{different_output}")
            else:
                print("  ok   full mode refuses different valid build outputs")

            binary_cases = {
                "symlink-first": "release build 1 output is not a regular non-symlink file",
                "symlink-second": "release build 2 output is not a regular non-symlink file",
                "hardlink-first": "release build 1 output must have exactly one hard link",
                "hardlink-second": "release build 2 output must have exactly one hard link",
            }
            for mode, expected in binary_cases.items():
                result = run_guard(
                    root, args=[],
                    extra_env={**full_env, "INTEGRITY_BINARY_MODE": mode},
                )
                output = result.stdout + result.stderr
                if result.returncode == 0:
                    FAILURES.append(f"full mode accepted {mode} binary alias\n{output}")
                elif expected not in output:
                    FAILURES.append(f"full mode rejected {mode} binary alias "
                                    f"without {expected!r}\n{output}")
                elif "determinism: ok" in output:
                    FAILURES.append(f"full mode claimed determinism after rejecting "
                                    f"{mode} binary alias\n{output}")
                else:
                    print(f"  ok   full mode refuses {mode} binary alias")

            sha_cases = {
                "exit": "SHA-256 tool failed for release build 1",
                "short": "digest that is not exactly 64 characters for release build 1",
                "nonhex": "non-lowercase hexadecimal digest for release build 1",
                "uppercase": "non-lowercase hexadecimal digest for release build 1",
                "multirow": "non-lowercase hexadecimal digest for release build 1",
            }
            for mode, expected in sha_cases.items():
                result = run_guard(
                    root, args=[],
                    extra_env={**full_env, "INTEGRITY_SHA_MODE": mode},
                )
                output = result.stdout + result.stderr
                if result.returncode == 0:
                    FAILURES.append(f"full mode accepted {mode} SHA-256 output\n{output}")
                elif expected not in output:
                    FAILURES.append(f"full mode rejected {mode} SHA-256 output "
                                    f"without {expected!r}\n{output}")
                elif "determinism: ok" in output:
                    FAILURES.append(f"full mode claimed determinism after rejecting "
                                    f"{mode} SHA-256 output\n{output}")
                else:
                    print(f"  ok   full mode refuses {mode} SHA-256 output")

            version_cases = {
                "exit": "release binary --version failed",
                "missing-commit": "binary version line does not contain (",
                "undelimited-commit": "binary version line does not contain (",
                "decoy-third": "exactly two newline-terminated lines",
                "extra-line": "exactly two newline-terminated lines",
                "malformed-source":
                    "binary source identity line is not the exact asserted clean-source format",
                "missing-final-newline": "exactly two newline-terminated lines",
                "trailing-byte": "exactly two canonical text lines",
            }
            for mode, expected in version_cases.items():
                result = run_guard(
                    root, args=[],
                    extra_env={**full_env, "INTEGRITY_VERSION_MODE": mode},
                )
                output = result.stdout + result.stderr
                if result.returncode == 0:
                    FAILURES.append(f"full mode accepted {mode} version output\n{output}")
                elif expected not in output:
                    FAILURES.append(f"full mode rejected {mode} version output "
                                    f"without {expected!r}\n{output}")
                elif "pos-release-integrity: PASS" in output:
                    FAILURES.append(f"full mode reported PASS after rejecting "
                                    f"{mode} version output\n{output}")
                else:
                    print(f"  ok   full mode refuses {mode} version output")

    # 7 — source assertion for section 3's call site, which needs a real build
    #     to reach: it must go through the shared root-lock assertion and must
    #     not have drifted back to a per-member path.
    with open(GUARD, encoding="utf-8") as fh:
        src = fh.read()
    diff_lines = [ln for ln in src.splitlines() if "git diff --exit-code" in ln]
    if len(diff_lines) != 1:
        FAILURES.append("drift check: expected exactly one `git diff --exit-code` "
                        f"line (inside assert_root_lock_undrifted), found "
                        f"{len(diff_lines)}")
    elif '"$REPO_ROOT/Cargo.lock"' not in diff_lines[0]:
        FAILURES.append("drift check: does not watch the root Cargo.lock: "
                        f"{diff_lines[0].strip()!r}")
    elif re.search(r"/Cargo\.lock", diff_lines[0].replace('"$REPO_ROOT/Cargo.lock"', "")):
        FAILURES.append("drift check: also watches another Cargo.lock; only the "
                        "root lock is written by a build: "
                        f"{diff_lines[0].strip()!r}")
    elif src.count("assert_root_lock_undrifted") < 3:
        FAILURES.append("section 3 no longer calls assert_root_lock_undrifted — "
                        "the post-build drift check is gone or was inlined "
                        "past the selftest's reach.")
    else:
        print("  ok   drift check watches only the root Cargo.lock, from both sections")

    if FAILURES:
        print("\npos-release-integrity.selftest: FAIL", file=sys.stderr)
        for f in FAILURES:
            print(f"\n- {f}", file=sys.stderr)
        return 1
    print("\npos-release-integrity.selftest: PASS — lock/layout drift, tracked "
          "release-source edits, target-dir regressions, different or aliased "
          "build outputs, malformed full-mode digests and noncanonical version "
          "identities fail closed; untracked output remains outside the "
          "cleanliness contract.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
