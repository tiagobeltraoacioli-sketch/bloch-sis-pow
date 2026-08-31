#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ws-publish.sh — fan a SEALED checkpoint out to every publication channel.
#
# Run BY A HUMAN after `bloch-ws-publisher seal` succeeds. Not on the timer,
# deliberately: publication is the moment the Foundation puts its name on an
# artifact, and the multi-channel property below only deters replacement if
# each channel write is a deliberate, logged act.
#
# The channels (spec §2.3 / BLOCH-WS-PUBLICATION-PIPELINE.md §4). The point
# of multiple channels is NOT hosting redundancy — it is that quietly
# REPLACING a published checkpoint requires rewriting all of them at once,
# in public. Every file below is PUBLIC by design (unlike partner
# integration documents, which never go to any of these channels).
#
#   1. R2 bucket -> the downloads host        (stable URLs + latest.json)
#   2. GitHub release  tag ws-checkpoint-e<epoch>
#   3. GitLab release  same tag, second forge, different account system
#   4. Announcement channel — printed template; a human posts it (in
#      English, quoting the 64-hex ws_digest)
#   5. Explorer front page — renders publish/latest.json from channel 1
#
# Usage: ws-publish.sh <epoch>
# Env:   WS_DIR                 publication root (default /var/lib/bloch/ws-publication)
#        WS_R2_BUCKET           R2 bucket name (skip channel 1 if unset)
#        WS_R2_PREFIX           key prefix, default "ws"
#        WS_GH_REPO             owner/repo for gh (skip channel 2 if unset)
#        WS_GITLAB_PROJECT      group/project for glab (skip channel 3 if unset)

set -euo pipefail

epoch="${1:?usage: ws-publish.sh <epoch>}"
WS_DIR="${WS_DIR:-/var/lib/bloch/ws-publication}"
prefix="${WS_R2_PREFIX:-ws}"
src="$WS_DIR/publish/$epoch"
bin="$src/wscheckpoint-$epoch.bin"
json="$src/wscheckpoint-$epoch.json"
latest="$WS_DIR/publish/latest.json"

[ -f "$bin" ] || { echo "no sealed envelope at $bin — run seal first" >&2; exit 1; }
set_file=$(ls "$src"/ws-signer-set-*.bin)
digest=$(bloch-ws-publisher digest --file "$bin")

# Channel-independent integrity sidecars (house rule: file + digest are two
# views of one artifact; sha256 is for mirrors, ws_digest is the identity).
( cd "$src" && shasum -a 256 "$(basename "$bin")" "$(basename "$set_file")" > SHA256SUMS )

echo "publishing epoch $epoch, ws_digest $digest"

# ── 1. R2 (the stable-URL mirror the explorer and latest.json point into) ──
if [ -n "${WS_R2_BUCKET:-}" ]; then
  for f in "$bin" "$json" "$set_file" "$src/SHA256SUMS"; do
    wrangler r2 object put "$WS_R2_BUCKET/$prefix/$epoch/$(basename "$f")" --file "$f"
  done
  # latest.json LAST: a mirror reader that follows it never lands on a
  # half-uploaded epoch.
  wrangler r2 object put "$WS_R2_BUCKET/$prefix/latest.json" --file "$latest"
  echo "channel 1 (R2): done"
fi

# ── 2. GitHub release ──────────────────────────────────────────────────────
if [ -n "${WS_GH_REPO:-}" ]; then
  gh release create "ws-checkpoint-e$epoch" \
    --repo "$WS_GH_REPO" \
    --title "Weak-subjectivity checkpoint — epoch $epoch" \
    --notes "ws_digest: \`$digest\`

Verify before use (docs/specs/BLOCH-WS-PUBLICATION-PIPELINE.md §5):
\`bloch-ws-publisher verify --checkpoint wscheckpoint-$epoch.bin --signer-set $(basename "$set_file") --network-id <pin> --genesis-root <pin>\`" \
    "$bin" "$json" "$set_file" "$src/SHA256SUMS"
  echo "channel 2 (GitHub): done"
fi

# ── 3. GitLab release ──────────────────────────────────────────────────────
if [ -n "${WS_GITLAB_PROJECT:-}" ]; then
  glab release create "ws-checkpoint-e$epoch" \
    --repo "$WS_GITLAB_PROJECT" \
    --name "Weak-subjectivity checkpoint — epoch $epoch" \
    --notes "ws_digest: \`$digest\`" \
    "$bin" "$json" "$set_file" "$src/SHA256SUMS"
  echo "channel 3 (GitLab): done"
fi

# ── 4. Announcement (a human posts this; official language is English) ─────
cat <<EOF

--------------------------------------------------------------------
ANNOUNCEMENT TEMPLATE — post to the announcement channel:

Weak-subjectivity checkpoint for epoch $epoch is published.
ws_digest: $digest
Files: wscheckpoint-$epoch.bin + signer set, on the downloads host,
GitHub and GitLab releases (tag ws-checkpoint-e$epoch).
Verify before booting from it — instructions:
docs/specs/BLOCH-WS-PUBLICATION-PIPELINE.md §5.
--------------------------------------------------------------------
The digest above must appear IN the post body: the announcement channel
is one of the channels a replacement attack would have to rewrite.
EOF
