#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# CI entry point for the mutation gate (BLOCH-L1-EVM-PQ-TX §9.3).
# Non-zero exit means a mutant survived, which means a test is missing.
set -e
exec python3 "$(dirname "$0")/mutants.py" "$@"
