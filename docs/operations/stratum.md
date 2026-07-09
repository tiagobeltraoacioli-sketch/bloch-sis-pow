# Operating an Bloch-SIS Protocol (BLOCH) stratum server

This guide covers how to run a stratum V1 mining server on a
Bloch-SIS Protocol node, and how miners connect to it. As of v0.6.0-alpha2
the code is in place but the CLI wiring is pending — the final
user-facing commands below reflect the planned v0.6.0-final flags.

## What stratum gives you

Stratum V1 is the standard mining protocol used by every major
Bitcoin ASIC and software miner. Running a stratum server means:

- External miners can point their rigs at your node URL
  (`stratum+tcp://your-host:3333`) without any custom software
- You're always solo-mining — blocks found pay 100% to the address
  the miner authorized with (pool mode is Sprint AA.2, not yet
  implemented)
- Standard miner clients like `cgminer`, `BFGMiner`, `Braiins OS`,
  and every Antminer firmware work out of the box

## Server side (node operator)

### Planned CLI flags (v0.6.0-final)

```bash
bloch \
  --rpc-bind 0.0.0.0 --rpc-port 16210 \
  --listen /ip4/0.0.0.0/tcp/16110 \
  --data-dir /bloch-data \
  --stratum \
  --stratum-addr 0.0.0.0:3333 \
  --stratum-mode solo \
  --stratum-max-sessions 256
```

### Firewall

Stratum V1 is plaintext JSON-RPC over TCP. Port 3333 must be
reachable from the miners. For production deployments behind a
reverse proxy (recommended), see the TLS section below.

### Monitoring

The metrics endpoint (`--metrics --metrics-port 16310`) exposes
stratum counters when the server is running:

- `stratum_sessions_total` — cumulative accepted connections
- `stratum_sessions_active` — current open sessions
- `stratum_shares_submitted_total{result=ok|stale|low_diff|dup}`
- `stratum_blocks_found_total`

### Logs to watch for

```
stratum: listening on 0.0.0.0:3333
stratum: session 1 accepted from 1.2.3.4:54321 (total: 1)
stratum: session 1 subscribed (extranonce1=3f7a9c21)
stratum: session 1 authorized bloch1q4fbc...
stratum: session 1 BLOCK FOUND h=42 hash=0000...  (by bloch1q4fbc...)
```

If you see `stratum: rejecting <addr> — session cap 256 reached`,
tune `--stratum-max-sessions` upward. The default is generous for
solo deployments; pool operators may need more.

## Client side (miner)

### Miner URL format

```
stratum+tcp://<node-host>:3333
```

### Username = your bech32 address

Every share accepted from your miner pays to the username you
authorize with. The username MUST be a valid Bloch-SIS Protocol address
starting with `bloch1q` (mainnet) or `bloch1t` (testnet).

Example cgminer invocation:

```bash
cgminer \
  -o stratum+tcp://mine.example.com:3333 \
  -u bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45 \
  -p x
```

The password field is ignored by the Bloch-SIS Protocol stratum server —
authorization is purely by address validity. Use any placeholder.

### Invalid address rejection

If the username doesn't parse as a valid bech32 Bloch-SIS Protocol address,
the server returns stratum error code 24 (`Unauthorized`) and the
session stays in `Subscribed` state. The miner client will log
something like "failed to authorize" and retry.

### Antminer / Braiins OS firmware

Configure in the pool settings UI:
- Pool URL: `stratum+tcp://mine.example.com:3333`
- Worker name: your bech32 address
- Password: anything

## TLS reverse proxy (recommended for production)

Stratum V1 has no encryption. A miner connecting over the public
internet leaks their worker address and can be man-in-the-middled.
In production, put nginx in front with TLS termination.

### nginx config

```nginx
stream {
    upstream stratum_backend {
        server 127.0.0.1:3333;
    }

    server {
        listen 3443 ssl;
        proxy_pass stratum_backend;

        ssl_certificate     /etc/letsencrypt/live/mine.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/mine.example.com/privkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;

        proxy_timeout 1h;
        proxy_connect_timeout 10s;
    }
}
```

Miners then connect to `stratum+ssl://mine.example.com:3443`.
Most modern miner clients support TLS stratum; some require
`stratum+tcp+tls://` or a `--ssl` flag — check the docs.

## Known limitations (v0.6.0-alpha2)

**These apply to the scaffolded module; v0.6.0-final addresses
most of them.**

1. **No CLI flag yet** — the server exists in the codebase but isn't
   wired into main.rs. A v0.6.0-alpha2 node ignores stratum config.
   Fixed in v0.6.0-final.

2. **Solo mode only** — pool mode (`--stratum-mode pool`) errors
   out at startup. Share accounting + PPLNS is Sprint AA.2.

3. **No DIFFICULTY per miner** — every session sees the current
   network target. A slow miner pointing at mainnet will submit
   almost no shares. Pool mode (AA.2) will add variable-difficulty
   share targets.

4. **No job refresh on new tip** — (pending v0.6.0-final) template
   regeneration on tip change requires broadcast plumbing from the
   accept_block path. Miners currently work on the template from
   their subscribe time until it's stale.

5. **Plaintext only** — wrap with nginx TLS as shown above.

6. **No extranonce.subscribe support** — the server accepts the
   request silently but doesn't actually rotate extranonce1.
   Acceptable for short-running miners; long-running miners on
   high hashrate may exhaust the extranonce2 space (4 bytes =
   4 billion values × rolling ntime) in weeks. Not a practical
   issue at current hashrates.

## Troubleshooting

**Miner connects, subscribes, but never receives `mining.notify`.**

This is expected in v0.6.0-alpha2 — template generation is not yet
wired to the session lifecycle. Fixed in v0.6.0-final.

**All shares rejected with error code 21 (stale/not found).**

Same cause. Templates aren't being generated, so `find_template`
returns `None` and every submit fails with error-21.

**Shares rejected with code 23 (low difficulty).**

Miner is too slow for the current mainnet target. Expected on CPU
miners; solution is pool mode (AA.2) with variable-difficulty
shares, or faster hardware.

**Shares rejected with code 20 (other) and message mentions "stale-tip".**

A new block arrived between template build and share submission.
Miner continues on the current template and resubmits. Self-resolving.

## Roadmap beyond v0.6.0-final

- Sprint AA.2 — Pool mode with share accounting + PPLNS payout
- Sprint AA.3 — Stratum V2 (encrypted, multi-broker) — under review
- Sprint AA.4 — Getblocktemplate RPC for miner clients that don't
  speak stratum (rare, but some mining farms prefer it)
