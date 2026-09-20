#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove `check-scanners-blocking.py` fires on every escape and stays quiet otherwise.

Why this file exists
--------------------
The defect this guard was written for (finding I-H4) was itself a green check
that checked nothing: a scanner job that exited 0 when the tool was absent, on
a job that was allowed to fail anyway. Replacing it with an unexercised guard
would repeat the mistake one level up. Three guards previously audited in this
repository were green while what they guarded was broken.

So this builds synthetic CI files in a temporary directory — never the real
tree, so a failed selftest cannot leave the working copy dirty — and asserts
BOTH directions:

  * every supported escape shape must be caught, and caught BY NAME (a checker
    failing for some other reason would otherwise look like a pass): alternate
    waiver spellings, expressions/structured values, shell-success masking,
    conditional/inherited execution, and a job deleted outright;
  * the honest shape must stay green, INCLUDING the shapes one word away from a
    violation — a deliberately report-only job (cargo-geiger) that is allowed
    to fail, and a comment that merely mentions `allow_failure` next to a
    blocking job.

Run: python3 scripts/check-scanners-blocking.selftest.py
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-scanners-blocking.py")
TRACKED_LOCKFILES = (
    "Cargo.lock",
    "crates/coherence-prover/program/Cargo.lock",
    "crates/coherence-prover/script/Cargo.lock",
    "crates/coherence-prover/service/Cargo.lock",
    "euvm-tooling/Cargo.lock",
    "fuzz/Cargo.lock",
    "pool-proxy/Cargo.lock",
    "pool/Cargo.lock",
    "services/pq-shield-api/Cargo.lock",
    "spikes/prover-cost/Cargo.lock",
    "spikes/prover-cost/rv32/Cargo.lock",
    "spikes/prover-cost/rv32f/Cargo.lock",
    "spikes/prover-cost/rv32h/Cargo.lock",
    "spikes/prover-cost/rv32k/Cargo.lock",
    "tools/bloch-devkit/templates/svm/Cargo.lock",
)
SAFE_GITLAB_GLOBALS = """\
variables:
  CARGO_TERM_COLOR: "always"
  RUST_BACKTRACE: "1"

default:
  tags:
    - bloch-linux-aarch64
  before_script:
    - unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
    - export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
    - rustc --version && cargo --version
    - clang --version | head -1 || true
    - cmake --version | head -1 || true

"""

GOOD_GITLAB = SAFE_GITLAB_GLOBALS + """\
stages:
  - check

# cargo-geiger is deliberately report-only (see the written rationale); the
# guard must NOT flag it, and must not flag this comment's allow_failure: true
# either.
cargo-geiger:
  stage: check
  script:
    - cargo geiger || true
  allow_failure: true

clippy-hardened:
  stage: check
  script:
    - bash scripts/hardened-clippy.selftest.sh
    - bash scripts/hardened-clippy.sh

osv-scanner:
  stage: check
  script:
    - bash scripts/ci-install-scanner.sh osv-scanner
    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock
  allow_failure: false

secret-scan:
  stage: check
  script:
    - bash scripts/ci-install-scanner.sh gitleaks
    - bash scripts/scan-secrets.sh tree
  allow_failure: false

cargo-audit:
  stage: check
  script:
    - bash scripts/audit-all-lockfiles.sh
  allow_failure: false

secret-history-scan:
  stage: check
  script:
    - bash scripts/scan-secrets.sh history
  allow_failure: false

supply-chain:
  stage: check
  script:
    - cargo deny check advisories bans licenses sources
  allow_failure: false

scanners-blocking-guard:
  stage: check
  script:
    - python3 -I scripts/check-scanners-blocking.selftest.py
    - python3 -I scripts/check-scanners-blocking.py
  allow_failure: false

rollback-package-integrity:
  stage: check
  script:
    - bash deploy/rollback/make-rollback-package.selftest.sh
    - bash deploy/rollback/make-rollback-package.argv.selftest.sh
  allow_failure: false
"""

GOOD_GITHUB = """\
name: security
on:
  push:
    branches: [main, "euvm/**"]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

defaults:
  run:
    shell: /usr/bin/env -u BASH_ENV -u ENV -u PYTHONHOME -u PYTHONPATH -u CARGO_HOME -u RUSTUP_HOME -u RUSTUP_TOOLCHAIN -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u CARGO_BUILD_RUSTFLAGS -u CARGO_BUILD_RUSTC -u CARGO_BUILD_RUSTC_WRAPPER -u CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER PATH=/home/runner/.cargo/bin:/home/runner/.local/bin:/usr/local/bin:/usr/bin:/bin /bin/bash --noprofile --norc -euo pipefail {0}

jobs:
  clippy-hardened:
    runs-on: ubuntu-latest
    steps:
      - run: |
          bash scripts/hardened-clippy.selftest.sh
          python3 -I scripts/hardened-clippy-score.test.py
      - run: sudo apt-get update && sudo apt-get install -y clang cmake
      - run: bash scripts/hardened-clippy.sh

  cargo-audit:
    runs-on: ubuntu-latest
    steps:
      - run: cargo install cargo-audit --version 0.22.2 --locked
      - run: bash scripts/audit-all-lockfiles.sh

  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - run: cargo install cargo-deny --version 0.20.2 --locked
      - run: cargo deny check advisories bans licenses sources

  osv-scanner:
    runs-on: ubuntu-latest
    steps:
      - uses: google/osv-scanner-action/osv-scanner-action@764c91816374ff2d8fc2095dab36eecd42d61638
        with:
          scan-args: |-
            --config=osv-scanner.toml
            --lockfile=Cargo.lock
            --lockfile=pool/Cargo.lock
            --lockfile=pool-proxy/Cargo.lock
            --lockfile=services/pq-shield-api/Cargo.lock
            --lockfile=euvm-tooling/Cargo.lock
            --lockfile=crates/coherence-prover/script/Cargo.lock
            --lockfile=crates/coherence-prover/service/Cargo.lock
            --lockfile=crates/coherence-prover/program/Cargo.lock
            --lockfile=fuzz/Cargo.lock
            --lockfile=spikes/prover-cost/Cargo.lock
            --lockfile=spikes/prover-cost/rv32/Cargo.lock
            --lockfile=spikes/prover-cost/rv32f/Cargo.lock
            --lockfile=spikes/prover-cost/rv32h/Cargo.lock
            --lockfile=spikes/prover-cost/rv32k/Cargo.lock
            --lockfile=tools/bloch-devkit/templates/svm/Cargo.lock

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - run: CI_TOOLS_BIN="$HOME/.local/bin" bash scripts/ci-install-scanner.sh gitleaks
      - run: bash scripts/scan-secrets.sh tree

  scanners-blocking-guard:
    runs-on: ubuntu-latest
    steps:
      - run: python3 -I scripts/ci-install-scanner.test.py
      - run: python3 -I scripts/check-scanners-blocking.selftest.py
      - run: python3 -I scripts/check-scanners-blocking.py

  secret-history-scan:
    runs-on: ubuntu-latest
    steps:
      - run: CI_TOOLS_BIN="$HOME/.local/bin" bash scripts/ci-install-scanner.sh gitleaks
      - run: bash scripts/scan-secrets.sh history
      - run: python3 -I scripts/scan-secrets.test.py

  rollback-package-integrity:
    runs-on: ubuntu-latest
    steps:
      - run: sudo apt-get update && sudo apt-get install -y minisign
      - run: bash deploy/rollback/make-rollback-package.selftest.sh
      - run: bash deploy/rollback/make-rollback-package.argv.selftest.sh

  cargo-geiger:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: cargo geiger
"""
GOOD_GITHUB_WITH_ENV = GOOD_GITHUB.replace(
    "permissions:\n  contents: read\n",
    "permissions:\n  contents: read\n\n"
    "env:\n  CARGO_TERM_COLOR: always\n  RUST_BACKTRACE: \"1\"\n")


class Case:
    def __init__(self, name, gitlab, github, *, must_fail, expect="",
                 tracked_lockfiles=TRACKED_LOCKFILES):
        self.name = name
        self.gitlab = gitlab
        self.github = github
        self.must_fail = must_fail
        self.expect = expect
        self.tracked_lockfiles = tracked_lockfiles


def sub(text: str, old: str, new: str) -> str:
    assert old in text, "selftest fixture drift: %r not in fixture" % old
    return text.replace(old, new, 1)


CASES = [
    Case("honest pipelines stay green", GOOD_GITLAB, GOOD_GITHUB, must_fail=False),
    Case("GitLab quoted scanner scalar values remain supported",
         GOOD_GITLAB, GOOD_GITHUB, must_fail=False),
    Case("GitLab scanner block script key-shaped text remains data",
         GOOD_GITLAB +
         "\nquoted-script-data:\n"
         "  stage: test\n"
         "  script:\n"
         "    - |\n"
         "      \"not-a-yaml-key\": shell data\n"
         "      %YAML 1.2\n"
         "      --- # embedded document-looking data\n"
         "      ...\n",
         GOOD_GITHUB, must_fail=False),
    Case("GitLab leading scanner YAML document marker is outside the subset",
         "---\n" + GOOD_GITLAB, GOOD_GITHUB, must_fail=True,
         expect="YAML directives and document boundaries"),
    Case("GitLab earlier decoy document cannot hide reviewed scanners",
         "decoy-only: true\n--- # later reviewed document\n" + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True,
         expect="YAML directives and document boundaries"),
    Case("GitLab scanner YAML directive is outside the subset",
         "%TAG !audit! tag:example.invalid,2026:\n---\n" + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True,
         expect="YAML directives and document boundaries"),
    Case("GitLab scanner document-end marker is outside the subset",
         GOOD_GITLAB + "\n... # end reviewed document\n",
         GOOD_GITHUB, must_fail=True,
         expect="YAML directives and document boundaries"),
    Case("GitLab root merge cannot inject scanner runner image",
         ".runner-policy: &runner_policy\n"
         "  image: attacker.invalid/controlled:latest\n\n"
         "<<: *runner_policy\n\n" + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True, expect="YAML merge keys"),
    Case("GitLab scanner job merge cannot inject an unreviewed runner image",
         ".runner-policy: &runner_policy\n"
         "  image: attacker.invalid/controlled:latest\n\n" +
         sub(GOOD_GITLAB,
             "supply-chain:\n  stage: check",
             "supply-chain:\n  <<: *runner_policy\n  stage: check"),
         GOOD_GITHUB, must_fail=True, expect="YAML merge keys"),
    Case("GitLab scanner merge-looking block script text remains data",
         GOOD_GITLAB +
         "\nmerge-script-data:\n"
         "  stage: test\n"
         "  script:\n"
         "    - |\n"
         "      <<: *runner_policy\n",
         GOOD_GITHUB, must_fail=False),
    Case("GitLab quoted scanner merge key remains rejected by prior preflight",
         GOOD_GITLAB + "\n'<<': ignored\n",
         GOOD_GITHUB, must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitLab explicit scanner merge key remains rejected by prior preflight",
         GOOD_GITLAB + "\n? <<\n: ignored\n",
         GOOD_GITHUB, must_fail=True,
         expect="explicit, tagged, anchored or aliased"),
    Case("GitLab flow scanner merge remains rejected by prior preflight",
         GOOD_GITLAB + "\nmerge-flow: {<<: ignored}\n",
         GOOD_GITHUB, must_fail=True, expect="flow-style YAML mappings"),
    Case("GitLab escaped scanner default authority key is rejected globally",
         GOOD_GITLAB +
         "\n\"defa\\u0075lt\":\n"
         "  tags: [attacker-controlled]\n"
         "  before_script: [\"true\"]\n",
         GOOD_GITHUB, must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitLab escaped required scanner job key is rejected globally",
         GOOD_GITLAB +
         "\n\"supply-cha\\u0069n\":\n"
         "  stage: check\n"
         "  script:\n    - true\n"
         "  allow_failure: true\n",
         GOOD_GITHUB, must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitLab escaped scanner waiver key is rejected globally",
         sub(GOOD_GITLAB,
             "supply-chain:\n  stage: check",
             "supply-chain:\n  \"allow_fail\\u0075re\": true\n  stage: check"),
         GOOD_GITHUB, must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitLab escaped scanner script key is rejected globally",
         sub(GOOD_GITLAB,
             "supply-chain:\n  stage: check\n  script:",
             "supply-chain:\n  stage: check\n  \"scr\\u0069pt\":"),
         GOOD_GITHUB, must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitLab explicit escaped scanner default key is rejected globally",
         GOOD_GITLAB +
         "\n? \"defa\\u0075lt\"\n"
         ":\n  tags: [attacker-controlled]\n",
         GOOD_GITHUB, must_fail=True,
         expect="explicit, tagged, anchored or aliased"),
    Case("GitLab multiline explicit scanner default is rejected globally",
         GOOD_GITLAB +
         "\n?\n  default\n"
         ":\n  tags: [attacker-controlled]\n",
         GOOD_GITHUB, must_fail=True,
         expect="explicit, tagged, anchored or aliased"),
    Case("GitLab tagged scanner default key is rejected globally",
         GOOD_GITLAB +
         "\n!!str default:\n  tags: [attacker-controlled]\n",
         GOOD_GITHUB, must_fail=True,
         expect="explicit, tagged, anchored or aliased"),
    Case("GitLab anchored scanner default key is rejected globally",
         GOOD_GITLAB +
         "\n&hidden default:\n  tags: [attacker-controlled]\n",
         GOOD_GITHUB, must_fail=True,
         expect="explicit, tagged, anchored or aliased"),
    Case("GitLab flow scanner authority mapping is rejected globally",
         GOOD_GITLAB.replace(
             "variables:\n  CARGO_TERM_COLOR: \"always\"\n  RUST_BACKTRACE: \"1\"",
             "variables: {\"BASH_ENV\": scripts/mask-scanners.sh}"),
         GOOD_GITHUB, must_fail=True, expect="flow-style YAML mappings"),
    Case("GitHub quoted text inside a scanner block script is not a mapping key",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n  quoted-script-data:\n"
         "    runs-on: ubuntu-latest\n"
         "    steps:\n"
         "      - run: |\n"
         "          \"not-a-yaml-key\": shell data\n"
         "          %YAML 1.2\n"
         "          --- # embedded document-looking data\n"
         "          ...\n",
         must_fail=False),
    Case("GitHub leading scanner YAML document marker is outside the subset",
         GOOD_GITLAB, "---\n" + GOOD_GITHUB, must_fail=True,
         expect="YAML directives and document boundaries"),
    Case("GitHub earlier decoy document cannot hide reviewed scanners",
         GOOD_GITLAB,
         "decoy-only: true\n--- # later reviewed document\n" + GOOD_GITHUB,
         must_fail=True, expect="YAML directives and document boundaries"),
    Case("GitHub scanner YAML directive is outside the subset",
         GOOD_GITLAB, "%YAML 1.2\n---\n" + GOOD_GITHUB, must_fail=True,
         expect="YAML directives and document boundaries"),
    Case("GitHub scanner document-end marker is outside the subset",
         GOOD_GITLAB, GOOD_GITHUB + "\n...\n", must_fail=True,
         expect="YAML directives and document boundaries"),
    Case("GitHub escaped scanner workflow authority key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB + "\n\"permi\\u0073sions\":\n  contents: write\n",
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub flow escaped scanner authority key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "permissions:\n  contents: read",
             "permissions: {\"cont\\u0065nts\": write}"),
         must_fail=True, expect="flow-style YAML mappings"),
    Case("GitHub escaped required scanner job key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n  \"cargo\\u002ddeny\":\n"
         "    runs-on: [self-hosted, attacker-controlled]\n"
         "    steps:\n      - run: true\n",
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub quoted scanner if key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    'if': ${{ true }}\n    runs-on: ubuntu-latest"),
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub escaped scanner continue-on-error key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    \"continue-on-\\u0065rror\": true\n"
             "    runs-on: ubuntu-latest"),
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub escaped scanner needs key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    \"ne\\u0065ds\": bypass-prerequisite\n"
             "    runs-on: ubuntu-latest"),
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub escaped duplicate scanner runner key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    runs-on: ubuntu-latest\n"
             "    \"runs\\u002don\": [self-hosted, attacker-controlled]"),
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub explicit escaped scanner needs key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    runs-on: ubuntu-latest\n"
             "    ? \"ne\\u0065ds\"\n"
             "    : bypass-prerequisite"),
         must_fail=True, expect="explicit, tagged, anchored or aliased"),
    Case("GitHub multiline explicit scanner needs key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    runs-on: ubuntu-latest\n"
             "    ?\n      needs\n"
             "    :\n      bypass-prerequisite"),
         must_fail=True, expect="explicit, tagged, anchored or aliased"),
    Case("GitHub tagged scanner needs key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    runs-on: ubuntu-latest\n"
             "    !!str needs: bypass-prerequisite"),
         must_fail=True, expect="explicit, tagged, anchored or aliased"),
    Case("GitHub anchored scanner needs key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-deny:\n    runs-on: ubuntu-latest",
             "  cargo-deny:\n    runs-on: ubuntu-latest\n"
             "    &hidden needs: bypass-prerequisite"),
         must_fail=True, expect="explicit, tagged, anchored or aliased"),
    Case("GitHub quoted scanner steps key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("    steps:\n", "    'steps':\n", 1),
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub escaped scanner steps key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("    steps:\n", "    \"st\\u0065ps\":\n", 1),
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub quoted scanner run key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("      - run: |\n", "      - 'run': |\n", 1),
         must_fail=True, expect="quoted YAML mapping keys"),
    Case("GitHub escaped scanner uses key is rejected globally",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("      - uses:", "      - \"us\\u0065s\":", 1),
         must_fail=True, expect="quoted YAML mapping keys"),

    Case("reviewed GitHub global environment stays green",
         GOOD_GITLAB, GOOD_GITHUB_WITH_ENV, must_fail=False),

    Case("reviewed GitHub run shell stays green",
         GOOD_GITLAB, GOOD_GITHUB, must_fail=False),

    Case("GitHub run shell cannot retain inherited RUSTC",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(" -u RUSTC -u RUSTC_WRAPPER", " -u RUSTC_WRAPPER"),
         must_fail=True, expect="environment-clearing run shell"),

    Case("GitHub run shell cannot inherit a PATH suffix",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "PATH=/home/runner/.cargo/bin:/home/runner/.local/bin:/usr/local/bin:/usr/bin:/bin",
             "PATH=/home/runner/.cargo/bin:$PATH"),
         must_fail=True, expect="environment-clearing run shell"),

    Case("GitHub global BASH_ENV cannot replace scanner commands",
         GOOD_GITLAB,
         GOOD_GITHUB_WITH_ENV.replace(
             '  RUST_BACKTRACE: "1"',
             '  RUST_BACKTRACE: "1"\n  BASH_ENV: scripts/mask-scanners.sh'),
         must_fail=True, expect="top-level `env:` differs"),

    Case("GitHub quoted duplicate defaults cannot replace reviewed shell",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n\"defaults\":\n"
         "  run:\n"
         "    shell: bash {0} || true\n",
         must_fail=True,
         expect="protected top-level `defaults:` key must occur exactly once"),

    Case("GitHub quoted duplicate env cannot inject scanner startup variables",
         GOOD_GITLAB,
         GOOD_GITHUB_WITH_ENV +
         "\n'env':\n"
         "  BASH_ENV: scripts/mask-scanners.sh\n",
         must_fail=True,
         expect="protected top-level `env:` key must occur at most once"),

    Case("GitHub quoted duplicate trigger mapping cannot disable security pull requests",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n\"on\":\n"
         "  workflow_dispatch:\n",
         must_fail=True,
         expect="protected top-level `on:` key must occur exactly once"),

    Case("GitHub pull request paths cannot suppress security gates",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  pull_request:\n",
             "  pull_request:\n    paths-ignore: ['**']\n"),
         must_fail=True, expect="reviewed exact trigger mapping"),

    Case("GitHub duplicate pull request key cannot add a late security filter",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  workflow_dispatch:\n",
             "  workflow_dispatch:\n  pull_request:\n    branches: [never]\n"),
         must_fail=True, expect="reviewed exact trigger mapping"),

    Case("GitHub quoted duplicate permissions cannot replace security token posture",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n'permissions':\n"
         "  contents: write\n",
         must_fail=True,
         expect="protected top-level `permissions:` key must occur exactly once"),

    Case("GitHub quoted permission scope cannot override read-only contents",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  contents: read\n",
             "  contents: read\n  'contents': write\n"),
         must_fail=True, expect="must be exactly `contents: read`"),

    Case("GitHub scanner step PATH cannot replace cargo",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: cargo deny check advisories bans licenses sources",
             "      - run: cargo deny check advisories bans licenses sources\n"
             "        env:\n          PATH: scripts/fake-bin"),
         must_fail=True, expect="environment/container/service context"),

    Case("GitHub scanner job container cannot replace tools",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-audit:\n    runs-on: ubuntu-latest",
             "  cargo-audit:\n    runs-on: ubuntu-latest\n"
             "    container: attacker.invalid/fake-tools:latest"),
         must_fail=True, expect="environment/container/service context"),

    Case("GitHub scanner services are outside the supported context",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  secret-scan:\n    runs-on: ubuntu-latest",
             "  secret-scan:\n    runs-on: ubuntu-latest\n"
             "    services:\n      helper:\n        image: attacker.invalid/helper:latest"),
         must_fail=True, expect="environment/container/service context"),

    Case("GitHub quoted duplicate required job cannot override reviewed job",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n  \"cargo-deny\":\n"
         "    runs-on: ubuntu-latest\n"
         "    continue-on-error: true\n"
         "    steps:\n"
         "      - run: echo skipped\n",
         must_fail=True, expect="protected `cargo-deny:` job key must occur exactly once"),

    Case("unreviewed action cannot run before a scanner verdict",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: cargo deny check advisories bans licenses sources",
             "      - uses: attacker/example@0123456789abcdef0123456789abcdef01234567\n"
             "      - run: cargo deny check advisories bans licenses sources"),
         must_fail=True, expect="unreviewed or mutable action"),

    Case("reviewed action path cannot regress to a mutable tag",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-audit:\n    runs-on: ubuntu-latest\n    steps:",
             "  cargo-audit:\n    runs-on: ubuntu-latest\n    steps:\n"
             "      - uses: actions/checkout@v4"),
         must_fail=True, expect="unreviewed or mutable action"),

    Case("reviewed cache action cannot restore unreviewed directories",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-audit:\n    runs-on: ubuntu-latest\n    steps:",
             "  cargo-audit:\n    runs-on: ubuntu-latest\n    steps:\n"
             "      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6\n"
             "        with:\n          cache-directories: scripts"),
         must_fail=True, expect="unreviewed `with:` inputs"),

    Case("OSV action cannot add an unreviewed input",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "        with:\n          scan-args:",
             "        with:\n          experimental: true\n          scan-args:"),
         must_fail=True, expect="unreviewed `with:` inputs"),

    Case("even inert extra scanner run steps need explicit review",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: cargo deny check advisories bans licenses sources",
             "      - run: echo status=ready >> \"$GITHUB_OUTPUT\"\n"
             "      - run: cargo deny check advisories bans licenses sources"),
         must_fail=True, expect="reviewed ordered command list"),

    Case("extra run step cannot overwrite a scanner entrypoint",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: bash scripts/audit-all-lockfiles.sh",
             "      - run: cp scripts/fake-audit.sh scripts/audit-all-lockfiles.sh\n"
             "      - run: bash scripts/audit-all-lockfiles.sh"),
         must_fail=True, expect="reviewed ordered command list"),

    Case("scanner verdict cannot run before its pinned setup",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: cargo install cargo-deny --version 0.20.2 --locked\n"
             "      - run: cargo deny check advisories bans licenses sources",
             "      - run: cargo deny check advisories bans licenses sources\n"
             "      - run: cargo install cargo-deny --version 0.20.2 --locked"),
         must_fail=True, expect="reviewed ordered command list"),

    Case("scanner installer setup cannot be deleted",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: CI_TOOLS_BIN=\"$HOME/.local/bin\" bash scripts/ci-install-scanner.sh gitleaks\n",
             "", 1),
         must_fail=True, expect="reviewed ordered command list"),

    Case("folded YAML cannot merge two reviewed setup commands",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("      - run: |\n", "      - run: >\n", 1),
         must_fail=True, expect="reviewed ordered command list"),

    Case("GitHub PATH command file cannot replace scanner binaries",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: cargo deny check advisories bans licenses sources",
             "      - run: |\n"
             "          mkdir -p scripts/fake-bin\n"
             "          echo scripts/fake-bin >> \"$GITHUB_PATH\"\n"
             "      - run: cargo deny check advisories bans licenses sources"),
         must_fail=True, expect="cross-step environment/PATH channel"),

    Case("GitHub env context file cannot replace scanner variables",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: bash scripts/audit-all-lockfiles.sh",
             "      - run: echo BASH_ENV=scripts/mask.sh >> \"${{ github.env }}\"\n"
             "      - run: bash scripts/audit-all-lockfiles.sh"),
         must_fail=True, expect="cross-step environment/PATH channel"),

    Case("reviewed GitLab inherited context stays green",
         GOOD_GITLAB, GOOD_GITHUB, must_fail=False),

    Case("GitLab cannot inherit the runner PATH suffix",
         GOOD_GITLAB.replace(
             'export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"',
             'export PATH="$HOME/.cargo/bin:$PATH"'),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),

    Case("GitLab cannot retain compiler substitution variables",
         GOOD_GITLAB.replace(
             "unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME "
             "RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC ",
             "unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME RUSTC "),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),

    Case("GitLab cannot retain inherited Rust compiler flags",
         GOOD_GITLAB.replace(
             "RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC",
             "RUSTUP_TOOLCHAIN RUSTC").replace(
             "RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC",
             "RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC"),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),

    Case("GitLab default before_script cannot disable fail-fast",
         GOOD_GITLAB.replace(
             "    - cmake --version | head -1 || true",
             "    - cmake --version | head -1 || true\n    - set +e"),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),

    Case("GitLab global variables cannot inject BASH_ENV",
         GOOD_GITLAB.replace(
             '  RUST_BACKTRACE: "1"',
             '  RUST_BACKTRACE: "1"\n  BASH_ENV: scripts/mask-verdict.sh'),
         GOOD_GITHUB, must_fail=True, expect="reviewed non-execution-affecting subset"),

    Case("GitLab required guard cannot disable inherited execution context",
         GOOD_GITLAB.replace(
             "scanners-blocking-guard:\n  stage: check",
             "scanners-blocking-guard:\n  stage: check\n  before_script: []"),
         GOOD_GITHUB, must_fail=True, expect="overrides the reviewed inherited `before_script:`"),

    Case("GitLab quoted duplicate required job cannot override reviewed job",
         GOOD_GITLAB +
         "\n\"scanners-blocking-guard\":\n"
         "  stage: check\n"
         "  script:\n"
         "    - echo skipped\n"
         "  allow_failure: true\n",
         GOOD_GITHUB, must_fail=True,
         expect="protected `scanners-blocking-guard:` job key must occur exactly once"),

    Case("GitLab reviewed default cannot be removed",
         GOOD_GITLAB.replace(SAFE_GITLAB_GLOBALS, ""),
         GOOD_GITHUB, must_fail=True, expect="`default:` must occur exactly once"),

    Case("GitLab quoted duplicate default cannot replace reviewed environment",
         GOOD_GITLAB +
         "\n\"default\":\n"
         "  before_script:\n"
         "    - export PATH=attacker/bin\n",
         GOOD_GITHUB, must_fail=True,
         expect="protected top-level `default:` key must occur exactly once"),

    Case("GitLab top-level hooks are outside the supported context",
         "hooks:\n  pre_get_sources_script:\n    - export PATH=fake:$PATH\n\n" + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True, expect="top-level `hooks:`"),

    Case("required GitLab job cannot add a before_script",
         GOOD_GITLAB.replace(
             "cargo-audit:\n  stage: check",
             "cargo-audit:\n  stage: check\n  before_script:\n    - set +e"),
         GOOD_GITHUB, must_fail=True, expect="overrides the reviewed inherited `before_script:`"),

    Case("required GitLab job cannot add an after_script",
         GOOD_GITLAB.replace(
             "supply-chain:\n  stage: check",
             "supply-chain:\n  stage: check\n  after_script:\n    - true"),
         GOOD_GITHUB, must_fail=True, expect="unsupported `after_script:`"),

    Case("required GitLab job cannot inject PATH variables",
         GOOD_GITLAB.replace(
             "secret-scan:\n  stage: check",
             "secret-scan:\n  stage: check\n  variables:\n    PATH: scripts/fake-bin"),
         GOOD_GITHUB, must_fail=True, expect="unreviewed execution variables"),

    Case("required GitLab scanner cannot restore entrypoints from cache",
         GOOD_GITLAB.replace(
             "cargo-audit:\n  stage: check",
             "cargo-audit:\n  stage: check\n  cache:\n    paths:\n      - scripts/"),
         GOOD_GITHUB, must_fail=True, expect="unsupported `cache:`"),

    Case("required GitLab scanner cannot import dependency artifacts",
         GOOD_GITLAB.replace(
             "secret-scan:\n  stage: check",
             "secret-scan:\n  stage: check\n  dependencies:\n    - poison-entrypoints"),
         GOOD_GITHUB, must_fail=True, expect="unsupported `dependencies:`"),

    Case("history scanner deleted",
         GOOD_GITLAB.replace("secret-history-scan:\n  stage: check\n  script:\n    - bash scripts/scan-secrets.sh history\n  allow_failure: false\n", ""),
         GOOD_GITHUB, must_fail=True, expect="`secret-history-scan`"),

    Case("history scanner allowed to fail",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  secret-history-scan:\n    runs-on: ubuntu-latest",
             "  secret-history-scan:\n    runs-on: ubuntu-latest\n    continue-on-error: true"),
         must_fail=True, expect="`secret-history-scan`"),

    Case("gitlab allow_failure on osv-scanner",
         sub(GOOD_GITLAB,
             "    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock\n  allow_failure: false",
             "    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock\n  allow_failure: true"),
         GOOD_GITHUB, must_fail=True, expect="`osv-scanner`"),

    Case("gitlab exit-0 skip on secret-scan (the silent one)",
         sub(GOOD_GITLAB,
             "    - bash scripts/ci-install-scanner.sh gitleaks",
             "    - |\n      if ! command -v gitleaks >/dev/null; then\n        echo skipping\n        exit 0\n      fi"),
         GOOD_GITHUB, must_fail=True, expect="exit 0"),

    Case("gitlab when: manual on cargo-audit",
         sub(GOOD_GITLAB,
             "cargo-audit:\n  stage: check",
             "cargo-audit:\n  stage: check\n  when: manual"),
         GOOD_GITHUB, must_fail=True, expect="when: manual"),

    Case("gitlab scanner job deleted outright",
         GOOD_GITLAB.replace(
             "osv-scanner:\n  stage: check\n"
             "  script:\n"
             "    - bash scripts/ci-install-scanner.sh osv-scanner\n"
             "    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock\n"
             "  allow_failure: false\n\n", ""),
         GOOD_GITHUB, must_fail=True, expect="MISSING"),

    Case("github continue-on-error on osv-scanner",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  osv-scanner:\n    runs-on: ubuntu-latest",
             "  osv-scanner:\n    runs-on: ubuntu-latest\n    continue-on-error: true"),
         must_fail=True, expect="continue-on-error"),

    Case("github continue-on-error on secret-scan",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  secret-scan:\n    runs-on: ubuntu-latest",
             "  secret-scan:\n    runs-on: ubuntu-latest\n    continue-on-error: true"),
         must_fail=True, expect="`secret-scan`"),

    Case("github scanner step cannot override the fail-fast shell",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: cargo deny check advisories bans licenses sources",
             "      - run: cargo deny check advisories bans licenses sources\n"
             "        shell: bash {0} || true"),
         must_fail=True, expect="custom shell/defaults"),

    Case("github workflow defaults cannot mask scanner verdicts",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "name: security\n",
             "name: security\ndefaults:\n  run:\n    shell: bash {0} || true\n"),
         must_fail=True, expect="top-level `defaults:`"),

    Case("github guard job deleted outright",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  scanners-blocking-guard:\n    runs-on: ubuntu-latest\n"
             "    steps:\n      - run: python3 -I scripts/ci-install-scanner.test.py\n"
             "      - run: python3 -I scripts/check-scanners-blocking.selftest.py\n"
             "      - run: python3 -I scripts/check-scanners-blocking.py\n\n", ""),
         must_fail=True, expect="MISSING"),

    Case("gitlab scanner guard cannot drop its adversarial selftest",
         GOOD_GITLAB.replace(
             "    - python3 -I scripts/check-scanners-blocking.selftest.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="adversarial self-test"),

    Case("github scanner guard cannot drop its adversarial selftest",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/check-scanners-blocking.selftest.py\n", ""),
         must_fail=True, expect="adversarial self-test"),

    Case("github OSV action must use an immutable commit pin",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "google/osv-scanner-action/osv-scanner-action@764c91816374ff2d8fc2095dab36eecd42d61638",
             "google/osv-scanner-action/osv-scanner-action@main"),
         must_fail=True, expect="no longer executes its required verdict"),

    Case("github OSV action cannot replace scanning with help",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "            --config=osv-scanner.toml",
             "            --help"),
         must_fail=True, expect="exact reviewed config and complete lockfile scan scope"),

    Case("github OSV action cannot drop a standalone workspace lockfile",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "            --lockfile=pool/Cargo.lock\n", ""),
         must_fail=True, expect="exact reviewed config and complete lockfile scan scope"),

    Case("OSV config decoy in another step is not action input",
         GOOD_GITLAB,
         sub(
             GOOD_GITHUB.replace("            --config=osv-scanner.toml\n", ""),
             "            --lockfile=spikes/prover-cost/rv32k/Cargo.lock",
             "            --lockfile=spikes/prover-cost/rv32k/Cargo.lock\n"
             "      - name: --config=osv-scanner.toml\n"
             "        run: echo decoy"),
         must_fail=True, expect="exact reviewed config and complete lockfile scan scope"),

    Case("new tracked lockfile fails until OSV scope includes it",
         GOOD_GITLAB, GOOD_GITHUB, must_fail=True,
         expect="exact reviewed config and complete lockfile scan scope",
         tracked_lockfiles=TRACKED_LOCKFILES + ("future/Cargo.lock",)),

    Case("stale untracked lockfile cannot remain in OSV scope",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "            --lockfile=spikes/prover-cost/rv32k/Cargo.lock",
             "            --lockfile=spikes/prover-cost/rv32k/Cargo.lock\n"
             "            --lockfile=retired/Cargo.lock"),
         must_fail=True, expect="exact reviewed config and complete lockfile scan scope"),

    Case("CI guard invocation cannot inject a lockfile fixture",
         GOOD_GITLAB.replace(
             "    - python3 -I scripts/check-scanners-blocking.py",
             "    - python3 -I scripts/check-scanners-blocking.py --tracked-lockfiles=decoy"),
         GOOD_GITHUB, must_fail=True, expect="no longer executes its required verdict"),

    Case("gitlab job name cannot replace the scanner verdict",
         GOOD_GITLAB.replace(
             "    - cargo deny check advisories bans licenses sources",
             "    - echo scanner job retained"),
         GOOD_GITHUB, must_fail=True, expect="no longer executes its required verdict"),

    Case("github step name cannot replace the scanner verdict",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: bash scripts/scan-secrets.sh history",
             "      - name: bash scripts/scan-secrets.sh history\n        run: echo scanner removed"),
         must_fail=True, expect="no longer executes its required verdict"),

    Case("echoing a verdict command is not execution evidence",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: bash scripts/scan-secrets.sh tree",
             "      - run: echo bash scripts/scan-secrets.sh tree"),
         must_fail=True, expect="no longer executes its required verdict"),

    Case("compound verdict cannot replace its failing exit status",
         GOOD_GITLAB.replace(
             "    - cargo deny check advisories bans licenses sources",
             "    - cargo deny check advisories bans licenses sources || echo ignored"),
         GOOD_GITHUB, must_fail=True, expect="no longer executes its required verdict"),

    Case("gitlab rollback job cannot drop argv preservation selftest",
         GOOD_GITLAB.replace(
             "    - bash deploy/rollback/make-rollback-package.argv.selftest.sh\n", ""),
         GOOD_GITHUB, must_fail=True, expect="adversarial self-test"),

    Case("github rollback job cannot drop argv preservation selftest",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: bash deploy/rollback/make-rollback-package.argv.selftest.sh\n", ""),
         must_fail=True, expect="adversarial self-test"),

    Case("github rollback integrity job deleted outright",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  rollback-package-integrity:\n    runs-on: ubuntu-latest\n"
             "    steps:\n      - run: sudo apt-get update && sudo apt-get install -y minisign\n"
             "      - run: bash deploy/rollback/make-rollback-package.selftest.sh\n"
             "      - run: bash deploy/rollback/make-rollback-package.argv.selftest.sh\n\n", ""),
         must_fail=True, expect="`rollback-package-integrity`"),

    Case("required clippy job deleted",
         GOOD_GITLAB.replace(
             "clippy-hardened:\n  stage: check\n  script:\n"
             "    - bash scripts/hardened-clippy.selftest.sh\n"
             "    - bash scripts/hardened-clippy.sh\n\n", ""),
         GOOD_GITHUB, must_fail=True, expect="`clippy-hardened`"),

    Case("alternate YAML True waives a scanner",
         GOOD_GITLAB.replace("  allow_failure: false", "  allow_failure: True", 1),
         GOOD_GITHUB, must_fail=True, expect="allow_failure"),

    Case("GitHub expression waives a scanner",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  osv-scanner:\n    runs-on: ubuntu-latest",
             "  osv-scanner:\n    runs-on: ubuntu-latest\n    continue-on-error: ${{ true }}"),
         must_fail=True, expect="continue-on-error"),

    Case("structured GitLab failure waiver",
         GOOD_GITLAB.replace(
             "  allow_failure: false", "  allow_failure: {exit_codes: [1]}", 1),
         GOOD_GITHUB, must_fail=True, expect="allow_failure"),

    Case("rules can skip a required job",
         GOOD_GITLAB.replace(
             "osv-scanner:\n  stage: check", "osv-scanner:\n  stage: check\n  rules:\n    - when: never"),
         GOOD_GITHUB, must_fail=True, expect="conditional or inherited"),

    Case("GitHub if can skip a required job",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  secret-scan:\n    runs-on: ubuntu-latest",
             "  secret-scan:\n    runs-on: ubuntu-latest\n    if: false"),
         must_fail=True, expect="conditional or inherited"),

    Case("YAML inheritance is outside the supported subset",
         GOOD_GITLAB.replace(
             "osv-scanner:\n  stage: check", "osv-scanner:\n  <<: *scanner-defaults\n  stage: check"),
         GOOD_GITHUB, must_fail=True, expect="conditional or inherited"),

    Case("GitLab extends cannot hide required job semantics",
         GOOD_GITLAB.replace(
             "osv-scanner:\n  stage: check", "osv-scanner:\n  extends: .scanner-defaults\n  stage: check"),
         GOOD_GITHUB, must_fail=True, expect="conditional or inherited"),

    Case("GitLab inherit cannot change required job defaults",
         GOOD_GITLAB.replace(
             "cargo-audit:\n  stage: check", "cargo-audit:\n  inherit:\n    default: false\n  stage: check"),
         GOOD_GITHUB, must_fail=True, expect="conditional or inherited"),

    Case("GitHub reusable workflow is outside the inspectable subset",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  osv-scanner:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: google/osv-scanner-action/osv-scanner-action@764c91816374ff2d8fc2095dab36eecd42d61638",
             "  osv-scanner:\n    uses: example/security/.github/workflows/osv.yml@0123456789abcdef"),
         must_fail=True, expect="delegates to a reusable workflow"),

    Case("GitLab reference cannot hide a required script",
         GOOD_GITLAB.replace(
             "cargo-audit:\n  stage: check\n  script:\n    - bash scripts/audit-all-lockfiles.sh",
             "cargo-audit:\n  stage: check\n  script: !reference [.scanner-template, script]"),
         GOOD_GITHUB, must_fail=True, expect="YAML alias or GitLab reference"),

    Case("GitHub alias cannot hide required steps",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  cargo-deny:\n    runs-on: ubuntu-latest\n    steps:\n"
             "      - run: cargo install cargo-deny --version 0.20.2 --locked\n"
             "      - run: cargo deny check advisories bans licenses sources",
             "  cargo-deny:\n    runs-on: ubuntu-latest\n    steps: *scanner-steps"),
         must_fail=True, expect="YAML alias or GitLab reference"),

    Case("GitLab external include is outside the local proof",
         "include: https://example.invalid/security.yml\n\n" + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True, expect="top-level `include:`"),

    Case("GitLab workflow rules cannot skip every required job",
         "workflow:\n  rules:\n    - when: never\n\n" + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True, expect="top-level `workflow:`"),

    Case("GitHub pull request trigger cannot be removed",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("  pull_request:\n", ""),
         must_fail=True, expect="required top-level `pull_request:` trigger is missing"),

    Case("GitHub privileged pull request target is refused",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("  pull_request:\n", "  pull_request_target:\n"),
         must_fail=True, expect="privileged `pull_request_target:`"),

    Case("GitHub token write permission is refused",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("  contents: read", "  contents: write"),
         must_fail=True, expect="write-capable or unsupported"),

    Case("required job cannot override token permissions",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  cargo-audit:\n    runs-on: ubuntu-latest",
             "  cargo-audit:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write"),
         must_fail=True, expect="job-level permissions override"),

    Case("quoted required-job permissions cannot override security token",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  cargo-audit:\n    runs-on: ubuntu-latest",
             "  cargo-audit:\n    'permissions':\n      contents: write\n    runs-on: ubuntu-latest"),
         must_fail=True, expect="job-level permissions override"),

    Case("required scanner cannot depend on a skipped decoy job",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "jobs:\n  clippy-hardened:\n",
             "jobs:\n"
             "  bypass-prerequisite:\n"
             "    if: ${{ false }}\n"
             "    runs-on: ubuntu-latest\n"
             "    steps:\n"
             "      - run: true\n\n"
             "  clippy-hardened:\n"
             "    'needs': bypass-prerequisite\n"),
         must_fail=True, expect="dependency that can skip the required gate"),

    Case("required scanner cannot move to an unreviewed runner",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-audit:\n    runs-on: ubuntu-latest",
             "  cargo-audit:\n    runs-on: [self-hosted, attacker-controlled]"),
         must_fail=True, expect="reviewed `ubuntu-latest` runner"),

    Case("or-true masks a scanner verdict",
         GOOD_GITLAB.replace("bash scripts/audit-all-lockfiles.sh", "bash scripts/audit-all-lockfiles.sh || true"),
         GOOD_GITHUB, must_fail=True, expect="shell-success masking"),

    Case("semicolon-true masks a scanner verdict",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("cargo deny check advisories bans licenses sources",
                             "cargo deny check advisories bans licenses sources; true"),
         must_fail=True, expect="shell-success masking"),

    Case("pipe-to-true masks a scanner verdict",
         GOOD_GITLAB.replace("bash scripts/audit-all-lockfiles.sh", "bash scripts/audit-all-lockfiles.sh | true"),
         GOOD_GITHUB, must_fail=True, expect="shell-success masking"),

    Case("set plus-e disables failure propagation",
         GOOD_GITLAB.replace(
             "    - bash scripts/audit-all-lockfiles.sh", "    - set +e\n    - bash scripts/audit-all-lockfiles.sh"),
         GOOD_GITHUB, must_fail=True, expect="disabled shell failure"),

    Case("both files missing entirely fails closed", None, None,
         must_fail=True, expect="MISSING"),
]


def run(case: Case, tmp: str) -> tuple[int, str]:
    gl = os.path.join(tmp, "gitlab-ci.yml")
    gh = os.path.join(tmp, "security.yml")
    tracked = os.path.join(tmp, "tracked-lockfiles.txt")
    for path, body in ((gl, case.gitlab), (gh, case.github)):
        if body is None:
            if os.path.exists(path):
                os.remove(path)
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    with open(tracked, "w", encoding="utf-8") as fh:
        fh.write("\n".join(case.tracked_lockfiles) + "\n")
    proc = subprocess.run(
        [sys.executable, CHECKER, "--gitlab", gl, "--github", gh,
         "--tracked-lockfiles", tracked],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in CASES:
            code, out = run(case, tmp)
            if case.must_fail and code == 0:
                failures.append("%s: expected the guard to FAIL, it passed" % case.name)
            elif not case.must_fail and code != 0:
                failures.append("%s: expected the guard to PASS, it failed:\n%s" % (case.name, out))
            elif case.must_fail and case.expect and case.expect not in out:
                failures.append(
                    "%s: guard failed, but not for the stated reason (%r absent):\n%s"
                    % (case.name, case.expect, out))
            else:
                print("  ok  %s" % case.name)

    if failures:
        print("\nselftest: FAIL — %d case(s)\n" % len(failures))
        for f in failures:
            print("  * %s" % f)
        return 1
    print("\nselftest: OK — %d cases, both directions" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
