# Deploying a Bloch-SIS node on Akash

Run a censorship-resistant Bloch-SIS full node on the [Akash](https://akash.network)
decentralized cloud. Three steps: **build** the image, **push** it to a public
registry, **deploy** the SDL.

## 1. Build the image

Requires Docker running. From the repo root:

```bash
docker build -t <REGISTRY>/bloch:0.1 .
```

`<REGISTRY>` is your Docker Hub / GHCR namespace, e.g. `docker.io/youruser`.
The build is heavy (rocksdb, blst, pqcrypto, libp2p) — expect several minutes.

Smoke-test locally:

```bash
docker run --rm -p 16210:16210 -v bloch-data:/bloch-data <REGISTRY>/bloch:0.1
# add  --mine  to the end to mine, or  --peer <multiaddr>  to bootstrap
```

## 2. Push to a public registry

Akash providers pull from a public registry (no private-registry auth in-cluster):

```bash
docker login
docker push <REGISTRY>/bloch:0.1
```

> Privacy: use an account/namespace not tied to your identity if anonymity
> matters — the image name is public.

## 3. Deploy the SDL

Edit [`deploy.yaml`](./deploy.yaml): set `image:` to `<REGISTRY>/bloch:0.1`, and
set `--rpc-api-key` (or remove the RPC expose entry) before exposing RPC globally.

**Console (easiest):** https://console.akash.network → *Deploy* → *Run your own
SDL* → paste `deploy.yaml` → pick a bid → accept. Needs a funded Akash wallet
(~a few AKT for escrow + fees).

**CLI:**

```bash
akash tx deployment create deploy.yaml --from <key> --node <rpc> --chain-id <id> ...
akash query market bid list --owner <addr> ...     # pick a provider bid
akash tx market lease create ...                    # accept the bid
akash provider lease-status ...                     # get the mapped P2P/RPC ports
```

## Notes

- **P2P port mapping:** Akash may remap the container's `16110` to a different
  external port on the provider. Read the mapped port from `lease-status` and
  advertise/connect using `provider-host:mapped-port`.
- **Persistent storage:** the SDL mounts a persistent 30Gi volume at
  `/bloch-data`, so chain data survives container restarts (not provider loss).
- **This is a zero-security testnet build** — do not attach value. See the repo
  README's status caveat.
