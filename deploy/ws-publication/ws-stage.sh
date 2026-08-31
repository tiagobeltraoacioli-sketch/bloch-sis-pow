#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ws-stage.sh — the unattended tick of the weak-subjectivity publication
# pipeline (docs/specs/BLOCH-WS-PUBLICATION-PIPELINE.md §3).
#
# Run by bloch-ws-stage.timer (hourly; the epoch is 16 minutes and the
# cadence is 256 epochs ≈ 2.85 days, so hourly is ~68 chances per interval).
# The job is idempotent — bloch-ws-publisher refuses to re-stage different
# bytes and no-ops on identical ones — and it TOUCHES NO KEYS: its terminal
# state is a SIGNING-REQUEST.txt waiting for humans, never a signature.
#
# Reads the node over JSON-RPC only; no SSH, no chain-state access of its
# own. Point WS_RPC at a node you operate (localhost preferred): the stager
# trusts this node's view of finality, which is trust assumption T1 of the
# spec — the published artifact's correctness rests on the signers' own
# verification at signing time, not on this box.
#
# Environment (see ws-publication.env.example):
#   WS_DIR          publication root (staging/ signatures/ publish/)
#   WS_RPC          node JSON-RPC endpoint, e.g. http://127.0.0.1:16400
#   WS_NETWORK_ID   pinned Genesis-4 network id (decimal or 0x-hex)
#   WS_GENESIS_ROOT pinned genesis block root, 64 hex chars
#   WS_PRODUCER     payload-producer command; {epoch} and {out} substituted.
#                   This is the checkpoint tool — the producer of the
#                   canonical 154 payload bytes; the stager only judges it.
#   WS_PUBLISHER    path to bloch-ws-publisher (default: on PATH)
#   WS_GENESIS_UNIX genesis unix time, for the staleness alarm (optional)
#   WS_WEBHOOK      optional URL POSTed one line on STAGED / STALE / EXPIRED

set -euo pipefail

: "${WS_DIR:?set WS_DIR}"
: "${WS_RPC:?set WS_RPC}"
: "${WS_NETWORK_ID:?set WS_NETWORK_ID}"
: "${WS_GENESIS_ROOT:?set WS_GENESIS_ROOT}"
: "${WS_PRODUCER:?set WS_PRODUCER}"
PUBLISHER="${WS_PUBLISHER:-bloch-ws-publisher}"

notify() { # $1 = one-line message; best-effort, never fails the run
  echo "$1"
  if [ -n "${WS_WEBHOOK:-}" ]; then
    curl -sf -m 10 -X POST -H 'content-type: text/plain' --data "$1" "$WS_WEBHOOK" \
      >/dev/null || echo "ws-stage: webhook notify failed (continuing)" >&2
  fi
}

# ── 1. The node's finalized checkpoint ──────────────────────────────────────
info=$(curl -sf -m 30 -X POST "$WS_RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}')
finalized_epoch=$(jq -er '.result.finalized.epoch' <<<"$info")
finalized_root=$(jq -er '.result.finalized.root' <<<"$info")

# ── 2. Stage if the cadence owes a checkpoint ───────────────────────────────
out=$("$PUBLISHER" stage \
  --dir "$WS_DIR" \
  --finalized-epoch "$finalized_epoch" \
  --finalized-root "$finalized_root" \
  --network-id "$WS_NETWORK_ID" \
  --genesis-root "$WS_GENESIS_ROOT" \
  --producer "$WS_PRODUCER")
echo "$out"

case "$out" in
  STAGED*)
    notify "WS checkpoint staged, signing ceremony owed: ${out%%$'\n'*}"
    ;;
  ALREADY_STAGED*)
    # Staged but not sealed: the ceremony is outstanding. Say so every tick —
    # a quiet pipeline and a stuck pipeline must not look alike.
    echo "ws-stage: ceremony outstanding — ${out%%$'\n'*}"
    ;;
esac

# ── 3. Staleness alarm against the wall clock ──────────────────────────────
if [ -n "${WS_GENESIS_UNIX:-}" ]; then
  st=$("$PUBLISHER" status --dir "$WS_DIR" \
    --finalized-epoch "$finalized_epoch" --genesis-unix "$WS_GENESIS_UNIX")
  echo "$st"
  if grep -qE 'STALE|EXPIRED' <<<"$st"; then
    notify "WS publication cadence slipping: $(grep -E 'STALE|EXPIRED' <<<"$st" | head -1)"
  fi
fi
