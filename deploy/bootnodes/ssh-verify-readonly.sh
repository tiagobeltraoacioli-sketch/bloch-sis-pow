#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Root-owned ForceCommand for the dedicated bootnode verification key.
set -euo pipefail

readonly PATH=/usr/bin:/bin
export PATH

if [ "${SSH_ORIGINAL_COMMAND:-}" != "verify" ]; then
  echo "REFUSED: this key can run only the read-only bootnode verification" >&2
  exit 2
fi

# Never evaluate SSH_ORIGINAL_COMMAND. The three operations and their targets
# are fixed here so possession of the key grants no general shell.
if find /home/ubuntu/g4 -name validator.key -print -quit 2>/dev/null | grep -q .; then
  echo "KEY=present"
else
  echo "KEY=absent"
fi

systemctl cat bloch-archival.service 2>/dev/null \
  | grep -oE -- "--transport [a-z0-9]+" \
  | head -1 \
  || true

curl -fsS --max-time 8 -X POST http://127.0.0.1:16400 \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
