#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Regression for INF-10: a published bootnode may expose P2P, never raw RPC.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bootnode-verifier-selftest.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

cp "$HERE/verify-bootnodes.sh" "$WORK/verify-bootnodes.sh"
printf '192.0.2.10:19100\n' > "$WORK/bootnodes.txt"
mkdir "$WORK/bin"
touch "$WORK/verify-ro-key"

# The verifier first probes a closed loopback port to select the macOS/Linux
# netcat spelling. Thereafter the fake exposes only P2P, plus the RPC port named
# by FAKE_OPEN_RPC for the negative case.
cat > "$WORK/bin/nc" <<'SHIM'
#!/usr/bin/env bash
host="${@: -2:1}"
port="${@: -1}"
if [ "$host" = 127.0.0.1 ] && [ "$port" = 1 ]; then
  exit 1
fi
if [ "$port" = 19100 ]; then
  exit 0
fi
if [ -n "${FAKE_OPEN_RPC:-}" ] && [ "$port" = "$FAKE_OPEN_RPC" ]; then
  exit 0
fi
exit 1
SHIM
chmod 0755 "$WORK/bin/nc"

cat > "$WORK/bin/ssh" <<'SHIM'
#!/usr/bin/env bash
args=("$@")
[ "${args[${#args[@]}-2]}" = "ubuntu@192.0.2.10" ] || exit 97
[ "${args[${#args[@]}-1]}" = verify ] || exit 97
found_key=0
for ((i=0; i<${#args[@]}-1; i++)); do
  if [ "${args[$i]}" = -i ] && [ "${args[$((i+1))]}" = "$BLOCH_VERIFY_RO_KEY" ]; then
    found_key=1
  fi
done
[ "$found_key" -eq 1 ] || exit 97
printf '%s\n' 'KEY=absent' '--transport devnet' \
  '{"jsonrpc":"2.0","id":1,"result":{"behind_by_slots":0,"height":10,"finalized_height":9,"epoch":8,"finalized":{"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}'
SHIM
chmod 0755 "$WORK/bin/ssh"

closed=$(cd "$WORK" && PATH="$WORK/bin:$PATH" bash ./verify-bootnodes.sh 2>&1)
printf '%s' "$closed" | grep -q 'public RPC     : closed (8080, 16310, 16400)'
printf '%s' "$closed" | grep -q 'PASS — every published entry is reachable and sound.'

set +e
opened=$(cd "$WORK" && FAKE_OPEN_RPC=8080 PATH="$WORK/bin:$PATH" \
  bash ./verify-bootnodes.sh 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ]
printf '%s' "$opened" | grep -q 'public RPC     : OPEN on 8080'
printf '%s' "$opened" | grep -q 'FAIL — fix or unpublish'

# INF-02: deep verification must not silently reuse the fleet administrator
# credential. The dedicated read-only key is mandatory and the client sends
# only the fixed token accepted by the ForceCommand wrapper.
set +e
missing=$(cd "$WORK" && BLOCH_FLEET_KEY="$WORK/admin-key" PATH="$WORK/bin:$PATH" \
  bash ./verify-bootnodes.sh --deep 2>&1)
missing_rc=$?
set -e
[ "$missing_rc" -ne 0 ]
printf '%s' "$missing" | grep -q 'requires BLOCH_VERIFY_RO_KEY'

deep=$(cd "$WORK" && BLOCH_VERIFY_RO_KEY="$WORK/verify-ro-key" \
  PATH="$WORK/bin:$PATH" bash ./verify-bootnodes.sh --deep 2>&1)
printf '%s' "$deep" | grep -q 'keyless        : yes'
printf '%s' "$deep" | grep -q 'transport      : devnet'
printf '%s' "$deep" | grep -q 'chain          : h=10 finalized=9 epoch=8 behind=0'

echo "verify-bootnodes selftest: PASS — RPC exposure and read-only SSH credential boundaries hold"
