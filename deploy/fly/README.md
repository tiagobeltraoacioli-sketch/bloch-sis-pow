# Deploying a Bloch-SIS node on Fly.io

Fly.io is the fastest path to a live node: it builds the repo `Dockerfile` and
runs it directly — **no manual `docker push`, no public registry, no bidding**.

## 1. Install + log in

```bash
brew install flyctl          # or: curl -L https://fly.io/install.sh | sh
flyctl auth signup           # or: flyctl auth login
```

(A Fly account requires a card for verification but has a free allowance;
performance VMs for mining are billed.)

## 2. Create the app + a volume

From the repo root (where `fly.toml` and `Dockerfile` live):

```bash
flyctl launch --copy-config --no-deploy      # pick a unique app name + region
flyctl volumes create bloch_data --size 30 --region <your-region>
```

For P2P (raw TCP on 16110) you want a dedicated IPv4 so peers can dial it:

```bash
flyctl ips allocate-v4        # dedicated IPv4 (small monthly cost) — needed for P2P
```

## 3. Deploy

```bash
flyctl deploy                 # builds the Dockerfile remotely + ships
flyctl logs                   # watch the banner, "Miner started", "Block found! h=1",
                              # and the node's peer id ("P2P: 12D3Koo...")
```

## 4. Endpoints

- **RPC:** `https://<app>.fly.dev` (Fly terminates TLS → internal 16210). Point
  **Blochscan** at this URL — HTTPS, so no mixed-content issues.
- **P2P seed multiaddr** (to bootstrap other nodes):
  ```
  /ip4/<dedicated-ipv4>/tcp/16110/p2p/<peer-id>
  ```
  Get the IPv4 with `flyctl ips list`, the peer id from `flyctl logs`.

## Scaling the miner

SIS PoW is CPU-bound. A single Fly machine caps at **16 performance CPUs**
(`cpus = 16` in `fly.toml`). To mine harder, scale out horizontally:

```bash
flyctl scale count 3          # three miner machines
```

## Notes

- `[processes]` in `fly.toml` runs the node with `--mine`. Remove `--mine` for a
  plain RPC/relay node.
- Persistent `/bloch-data` (the volume) keeps the peer id + chain stable across
  restarts.
- **Zero-security testnet build** — do not attach value.
