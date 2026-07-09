#!/bin/bash
# Bloch Protocol — Deploy 3 nodes to Akash
# Usage: ./deploy.sh

set -e

KEYNAME="bloch-wallet"
CHAIN_ID="akashnet-2"
NODE="https://rpc.akashnet.net:443"
DSEQ_FILE=".akash_dseqs"

echo "=== Bloch Protocol Akash Deploy ==="
echo ""

# Check dependencies
command -v provider-services >/dev/null || { echo "❌ provider-services not installed"; exit 1; }
command -v docker >/dev/null || { echo "❌ docker not installed"; exit 1; }

ADDR=$(provider-services keys show $KEYNAME -a 2>/dev/null)
if [ -z "$ADDR" ]; then
  echo "❌ Wallet not found. Run: provider-services keys add $KEYNAME"
  exit 1
fi
echo "✅ Wallet: $ADDR"

# Check AKT balance
BALANCE=$(provider-services query bank balances $ADDR --node $NODE -o json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((x['amount'] for x in d.get('balances',[]) if x['denom']=='uakt'), '0'))")
echo "✅ Balance: ${BALANCE} uAKT"

if [ "$1" == "deploy-node1" ]; then
  echo ""
  echo "Deploying node1 (seed node)..."
  provider-services tx deployment create deploy/node1.sdl.yaml \
    --from $KEYNAME \
    --node $NODE \
    --chain-id $CHAIN_ID \
    --gas auto --gas-adjustment 1.25 \
    --gas-prices 0.025uakt \
    -y
  echo "✅ Node1 deployment submitted. Wait ~30s then run: ./deploy.sh lease-node1"

elif [ "$1" == "lease-node1" ]; then
  echo "Fetching bids for node1..."
  sleep 30
  provider-services query market bid list \
    --owner $ADDR \
    --node $NODE \
    -o json | python3 -c "
import sys,json
d=json.load(sys.stdin)
bids = d.get('bids',[])
if bids:
    b = bids[0]['bid']['bid_id']
    print(f'DSEQ: {b[\"dseq\"]}')
    print(f'Provider: {b[\"provider\"]}')
    print(f'Run: ./deploy.sh create-lease-node1 {b[\"dseq\"]} {b[\"provider\"]}')
else:
    print('No bids yet, wait more')
"

elif [ "$1" == "rpc-test" ]; then
  URL="$2"
  echo "Testing RPC at $URL..."
  curl -s -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d '{"method":"getnetworkinfo","id":1}' | python3 -m json.tool
fi
