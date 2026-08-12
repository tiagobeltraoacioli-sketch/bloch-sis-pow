<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# RPC survival runbook — Genesis-3 halt at height 80,000

**Status: PREPARATION ONLY. Nothing in production was changed while writing
this.** Every command in §2 is read-only and was actually run; every command in
§4–§6 is a proposed change and was NOT run. Execution is the founder's call.

Written 2026-08-11/12 UTC by agent A12. All facts below were measured on
2026-08-12 between 02:35 and 02:42 UTC, not recalled from memory. Where a
measurement contradicts prior notes or the task brief, the contradiction is
called out explicitly.

---

## 1. The problem

The Genesis-3 chain ends at `GENESIS3_TERMINAL_HEIGHT = 80_000`
(`crates/bloch-crypto/src/core/mod.rs:438`; the height 80,000 block itself is
valid, anything above is refused; the terminal-height binary is already
deployed fleet-wide — the running process on every box is `bloch-terminal-*`).
The pool will be decommissioned. The explorer at **blochl1.com** (Cloudflare
Pages project `bloch-explorer`, code in `apps/explorer/`) must keep a working
RPC after that, and must keep serving history for ~6 months until Genesis-4.

**Measured halt ETA.** Tip at measurement: height 36,159 (block timestamp
1786502128 = 2026-08-12T02:35:28Z). Average block time over the last 2,880
blocks (h 33,279→36,159): **31.2 s**. Remaining 43,841 blocks ≈ **15.9 days**,
i.e. terminal height lands around **2026-08-27/28** at current cadence.
*This contradicts the "~12 days" in the task brief — at today's hashrate there
is roughly four days more runway than assumed. If hashrate rises, it shrinks.*

---

## 2. Verified state (2026-08-12 ~02:40 UTC)

### 2.1 DNS

| Hostname | Measured result | Verdict |
|---|---|---|
| `g2rpc.posternpool.com` | A 104.21.18.46 / 172.67.180.98 (Cloudflare-proxied) | **LIVE** — the only working public RPC. Answers `getblockcount` = 44,062+. |
| `g2rpc.blochl1.com` | **NOT NXDOMAIN** — DNS-only CNAME → `3e88eb2e-2901-4030-b56f-73bfa7197663.cfargotunnel.com` | **Dead in practice**: browsers/curl cannot resolve it (`curl: (6)`), because a cfargotunnel CNAME only works when the record is Proxied. *Corrects the brief's "was NXDOMAIN".* |
| `rpc.blochl1.com` | NXDOMAIN | Not provisioned (matches A5's comment in `apps/explorer/src/lib/rpc.ts`). |
| `g2rpc.posternlabs.com` | NXDOMAIN | Confirms: the public RPC is on posternpool.com, not posternlabs.com. |
| `l2rpc.posternlabs.com` | A (proxied), live | L2 EVM devnet, unrelated to this runbook. |
| `blochl1.com` | A 172.66.44.199 / 172.66.47.57 (proxied, Pages) | Explorer live. |

Key identity: the cfargotunnel target of `g2rpc.blochl1.com` is **the same
tunnel ID as the miner-box's `cloudflared.service`** (verified by decoding the
tunnel ID — only the ID, not the secret — from `/etc/cloudflared/token` on
192.248.190.123). So someone already created that record aiming at the right
tunnel; it is dead only because it is DNS-only and (presumably) has no ingress
route for that hostname.

### 2.2 The explorer's RPC chain — what actually works today

`apps/explorer/src/lib/rpc.ts` (built by A5) tries, in order:

1. `https://rpc.blochl1.com/` → **NXDOMAIN** → transport failure → fails over.
2. `/rpc` (Pages Function, `apps/explorer/functions/rpc.js`, read-only
   allowlist) → **HTTP 403, body `error code: 1003`** → non-JSON → fails over.
3. `https://g2rpc.posternpool.com/` → **works**.

So today the whole explorer stands on tier 3 — the endpoint explicitly marked
"DEPRECATED — dies with the pool". Tiers 1 and 2 are both down.

**Why tier 2 is down (verified, not guessed):** `wrangler pages download
config bloch-explorer` shows the project has

```toml
[vars]
BLOCH_RPC_URL = "https://g2rpc.blochl1.com/"
```

i.e. the env var IS set, but to the dead hostname above. A Pages Function
fetching a same-zone cfargotunnel CNAME yields Cloudflare error 1003, which
`functions/rpc.js` passes through as the 403 we measured. This is exactly the
failure mode the file's own header warns about: `BLOCH_RPC_URL` **must not**
be a Cloudflare-proxied (or cfargotunnel) hostname — it needs a direct origin.

Last production deploy of `bloch-explorer`: 1 day ago, commit `fb24825`
(A5's failover code is what is live).

### 2.3 The fleet (all reached over SSH as `ubuntu`, read-only commands only)

All three nodes run with `--archive`, all were in sync with each other and
with the public endpoint (block_count 44,067–44,068, tip_height 36,158–36,159
during the sweep — the ±1 is propagation, not divergence).

| Box | IP / key | Services (running) | Node RPC | Notes |
|---|---|---|---|---|
| **auxpow** | 45.76.89.225, `~/.ssh/edgevana_auxpow` | `bloch-auxpow` (node + solo stratum :3333, `--mine`), `bloch-merged-pool` (:3336), `bloch-pool-proxy`, `bitcoind-mainnet` | `127.0.0.1:16216` | ASIC hashrate lands here. Disk 81% (8.5 G free), g3-data 1.6 G, RAM 7.8 G shared with bitcoind. This box is the pool — most of it is what gets decommissioned. |
| **miner-box / g3** | 192.248.190.123, `~/.ssh/edgevana_miner_new` | `bloch-g3` (node, RPC `127.0.0.1:16216`, P2P :16116), `bloch-gpu-miner`, `bloch-l2` + `cloudflared-l2` (l2rpc), **`cloudflared`** (tunnel `3e88eb2e-…` = g2rpc origin), **`bloch-rpc-bridge`** (socat `:8080 → 127.0.0.1:16226`), **`g2rpc-tunnel`** (ssh `-L 127.0.0.1:16226 → 45.76.89.225:16216`, key `/home/ubuntu/.ssh/g2rpc_tunnel`), 3× stratum passthrough | `127.0.0.1:16216` (own node — NOT what g2rpc serves) | Confirms the brief: public g2rpc = **auxpow's** node through a 3-box chain. |
| **node4** | 136.244.82.226, `~/.ssh/edgevana_node4` | `bloch-g3` only — nothing else | `127.0.0.1:16210` | Archival public peer. P2P :16110 (+:16111). Data 1.9 G. Disk 87% (6.1 G free). ufw: default deny inbound; allows 22, 11434, 16110 only. Uptime 13 days. |

**Today's g2rpc path** (every hop verified live):

```
browser → g2rpc.posternpool.com (CF edge)
        → cloudflared on miner-box (tunnel 3e88eb2e-…)
        → socat :8080 → 127.0.0.1:16226            [bloch-rpc-bridge.service]
        → ssh -L 16226 → auxpow 127.0.0.1:16216    [g2rpc-tunnel.service]
        → auxpow node RPC
```

Three boxes and four services in series; if the auxpow box is retired with
the pool, this dies even though `cloudflared` itself keeps running.

### 2.4 node4 chain completeness (verified, not presumed)

`getblockbyheight` on node4's local RPC returned real blocks at heights
**0, 1, 10,000, 20,000, 30,000, 36,000** (genesis hash `c7522d0e…` at h0), and
`getdaginfo` matched the producer's tip. It runs `--archive` with
`--carryover-snapshot`, peers with both auxpow (:16111) and miner-box
(:16116), and has followed the chain for 13 days unattended. Storage
projection to h 80,000: 1.9 G × (80,000/44,068) ≈ **3.5 G total ≈ +1.6 G**,
against 6.1 G free — fits, with margin, and growth stops forever at the halt.

### 2.5 Node RPC CORS (matters for direct browser use)

`OPTIONS https://g2rpc.posternpool.com/` returns
`access-control-allow-origin: *` (headers come from the node RPC itself), so
a browser on blochl1.com can POST straight to any hostname fronting a Bloch
node RPC. Tier 1 (`rpc.blochl1.com`) therefore needs no proxy logic — only a
route.

---

## 3. Recommendation: node4 (136.244.82.226) becomes the permanent archival RPC

Reasons, in order of weight:

1. **Nothing on it gets decommissioned.** auxpow is the pool box (stratum,
   merged pool, bitcoind, ASIC ingress) — precisely the machine whose future
   is in question. miner-box carries GPU mining and is a 4-service relay hop
   today. node4 runs exactly one service, whose only job is to be the
   archival public peer. Smallest blast radius, fewest reasons ever to touch
   it.
2. **Chain completeness verified** (§2.4), not presumed — archival flag,
   genesis-to-tip samples answered, in sync with the producer.
3. **Disk fits with margin** (§2.4) and stops growing at the halt.
4. It removes the 3-box series circuit: explorer → one box, one service.

Requirement between now and the halt: node4 just has to keep following the
chain to 80,000 (it has for 13 days; `Restart=always` is set). **Halt-day
verification (read-only):** on node4 `getdaginfo` must show
`tip_height == 80000`, and its tip hash must equal the producer's (auxpow
`127.0.0.1:16216` same call). If they differ, the snapshot/producer side is
authoritative and node4 must not be exposed until resynced.

Honest caveat for anything downstream: after the halt this history is no
longer defended by hashrate (the comment block above
`GENESIS3_TERMINAL_HEIGHT`, mod.rs:425-435, says exactly this). The canonical
artifact is the signed snapshot at 80,000; the archival RPC is for the
explorer and for reading history, not for proving it.

---

## 4. The cheapest path — and the answer to "does BLOCH_RPC_URL alone solve it?"

**Almost.** Setting `BLOCH_RPC_URL` correctly fixes the explorer with **zero
DNS changes and zero new Cloudflare infrastructure** — but the value cannot be
any Cloudflare-proxied hostname (that is the 1003 loop we are currently in),
and every node RPC in the fleet binds `127.0.0.1`. So the minimum viable
change is **one additive systemd unit on node4** to expose its RPC on a public
port, plus **one env-var edit + redeploy** on the Pages project. That is the
preferred plan. DNS (§5) is optional polish, not a requirement.

### Step A — expose node4's RPC on :16220 (additive; touches only node4)

```bash
ssh -i ~/.ssh/edgevana_node4 ubuntu@136.244.82.226

sudo tee /etc/systemd/system/bloch-rpc-public.service >/dev/null <<'EOF'
[Unit]
Description=Public read RPC for the archival node (:16220 -> 127.0.0.1:16210)
After=network-online.target bloch-g3.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:16220,fork,reuseaddr TCP:127.0.0.1:16210
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now bloch-rpc-public.service
sudo ufw allow 16220/tcp comment 'Bloch archival RPC (public read)'

# verify from the Mac:
curl -sS -m 10 -X POST http://136.244.82.226:16220/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

(If `socat` is missing: `sudo apt-get install -y socat` — same tool the
miner-box bridge already uses.)

**Rollback A:**

```bash
sudo systemctl disable --now bloch-rpc-public.service
sudo rm /etc/systemd/system/bloch-rpc-public.service
sudo systemctl daemon-reload
sudo ufw delete allow 16220/tcp
```

**Security note, stated rather than hidden:** :16220 is the full
unauthenticated node RPC, not the Function's read-only allowlist. That is the
same surface `g2rpc.posternpool.com` exposes to the internet today (minus
Cloudflare's DDoS front). Post-halt the write-ish methods are inert (blocks
above 80,000 are invalid; mempool txs can never be mined). If the founder
wants the allowlist to be the only public surface, skip browsers-direct (§5)
and let `/rpc` be the sole path; the port still has to be open for the
Function, and Pages egress IPs cannot be usefully pinned in ufw.

### Step B — fix `BLOCH_RPC_URL` and redeploy the Pages project

Dashboard: Workers & Pages → `bloch-explorer` → Settings → Environment
variables → set **`BLOCH_RPC_URL` = `http://136.244.82.226:16220/`**
(production). Pages vars only take effect on the next deployment, so redeploy
the current build:

```bash
cd ~/dev/BlochPOS/apps/explorer      # or the repo the site is deployed from
npm run build
CLOUDFLARE_ACCOUNT_ID=4e44d592d0229f8faa3fdb2f139c611c \
  npx wrangler pages deploy dist --project-name bloch-explorer --branch main --commit-dirty=true

# verify:
curl -sS -m 15 -X POST https://blochl1.com/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
# expect {"id":1,...,"result":<height>} — today this returns "error code: 1003"
```

**Rollback B:** set `BLOCH_RPC_URL` back to `https://g2rpc.blochl1.com/` (the
current, broken-but-harmless value — tier 3 keeps carrying traffic while the
pool lives) and redeploy the same way. No data risk either direction: the
client fails over on any 5xx/non-JSON from `/rpc`.

After A+B the explorer survives the pool decommission: tier 1 warns
(NXDOMAIN, harmless), tier 2 works and terminates on node4, tier 3 can die
whenever the pool does.

---

## 5. Optional: make `rpc.blochl1.com` live (tier 1, direct browser → node)

Nicer latency (no Function hop), and it matches the hostname A5 already put
first in the chain. Cleanest topology is a tunnel **on node4 itself** — do
NOT reuse the miner-box tunnel, that re-creates the relay-box dependency this
runbook exists to remove.

```bash
ssh -i ~/.ssh/edgevana_node4 ubuntu@136.244.82.226
# install cloudflared (same binary/method as the miner-box: /usr/local/bin/cloudflared)
cloudflared tunnel login                       # or create the tunnel in Zero Trust dashboard
cloudflared tunnel create bloch-archival-rpc
cloudflared tunnel route dns bloch-archival-rpc rpc.blochl1.com   # creates the proxied CNAME
# config: ingress rpc.blochl1.com -> http://127.0.0.1:16210, then run as a service:
sudo cloudflared service install <token>
```

CORS is already `*` from the node RPC (§2.5), so the browser path works as-is.

**Rollback:** `sudo systemctl disable --now cloudflared` on node4;
`cloudflared tunnel delete bloch-archival-rpc`; delete the `rpc.blochl1.com`
DNS record in the blochl1.com zone. The client chain tolerates the hostname
disappearing (it just warns and falls to `/rpc`).

Note: even with tier 1 live, `BLOCH_RPC_URL` must still point at the
**direct** origin (`http://136.244.82.226:16220/`), never at
`rpc.blochl1.com` — proxied hostname in the Function = 1003 again.

### What about `g2rpc.blochl1.com`?

It already CNAMEs the miner-box tunnel (§2.1). Flipping it to Proxied and
adding an ingress route would revive the *old* relay path, auxpow dependency
and all. Do not invest in it; delete the record at decommission time
(rollback: recreate the DNS-only CNAME to
`3e88eb2e-2901-4030-b56f-73bfa7197663.cfargotunnel.com`).

---

## 6. Decommission-day order (pool shutdown)

1. Confirm halt reached and node4 verified (§3 halt-day check).
2. Confirm §4 A+B are live (`/rpc` returns real heights).
3. Remove tier 3 from the client: delete the
   `https://g2rpc.posternpool.com/` entry in
   `apps/explorer/src/lib/rpc.ts` (A5 marked it "DELETE this entry when the
   pool is decommissioned"); rebuild + redeploy (same commands as §4-B).
   Rollback: `git revert` + redeploy.
4. Only then stop pool-side services (`bloch-merged-pool`,
   `bloch-pool-proxy`, stratum passthroughs, `bitcoind-mainnet`, and
   eventually the auxpow box). The archival RPC no longer depends on any of
   them. Keep `g2rpc-tunnel.service`/`bloch-rpc-bridge` running until step 3
   is deployed, then they can go too (rollback: `systemctl enable --now` each
   unit — configs stay on disk if you disable rather than delete).
5. node4 stays as-is, plus §4-A (and §5 if chosen). Its `bloch-g3.service`
   has `Restart=always`; the box reboots into a working archival RPC with no
   operator action.

---

## 7. Explorer UI when the chain stops on purpose

Today's behavior at the halt would be: the dashboard's stall banner
(`apps/explorer/src/pages/Dashboard.tsx:84-93`, threshold
`STALL_THRESHOLD_SECS = 20*60` in `src/lib/chain.ts:114`) fires and says
**"Chain appears stalled … a consensus fix is deploying separately"** — copy
that is already stale today and becomes actively wrong at the halt: it frames
the *planned end of the chain* as an outage. "Last block 3 days ago" plus a
red dot reads as "this site is broken" even while every query works.

Proposed change (small, self-contained, in `apps/explorer`):

1. **One constant, one place.** Add to `src/lib/chain.ts`:
   `export const GENESIS3_TERMINAL_HEIGHT = 80_000; // mirror of crates/bloch-crypto/src/core/mod.rs:438 — the Rust constant is the authority`
   (The TS app cannot import the Rust constant; a single commented mirror is
   the least-bad option and `tools/doc-sweep/check_stale.py` can be taught to
   cross-check it.)
2. **Three dashboard states** instead of two, keyed on `tip_height`:
   - `tip_height < 80,000` and fresh → today's normal UI.
   - `tip_height < 80,000` and stale → keep the stall banner but fix the
     copy (drop "a consensus fix is deploying separately"; say "block
     production has paused; data shown is live from the node").
   - **`tip_height >= 80,000` → terminal state, not a warning.** Neutral
     (not red) banner, English per comms policy:

     > **Genesis-3 is complete.** This chain reached its terminal height of
     > 80,000 on {date} and no further blocks will ever be produced — by
     > consensus rule, not by failure. All history remains browsable here.
     > Genesis-4 (proof-of-stake) launches from the signed snapshot taken at
     > this height. Balances carry over.

     With it: swap the live/stale dot for a "final" state, replace the
     "Last block Xs ago" cell with "Final block: {date}", stop showing
     hashrate/mempool as if they were pending (show "— (chain complete)"),
     and drop the 15 s poll (`useAsync(load, [], 15000)` in Dashboard.tsx:58)
     to something like 10 min — the data can no longer change.
3. **Use A5's degraded-state exports.** `rpcIsDegraded()` and
   `activeRpcEndpoint()` exist in `src/lib/rpc.ts` but nothing consumes them
   (verified by grep). A small footer/header chip — "RPC: {endpoint}" — makes
   failover visible instead of silent, which is the difference between a
   debuggable outage and a mystery on decommission day.
4. Pages that are intrinsically about production (`Mining.tsx`,
   `Leaderboard.tsx`, `DagLive.tsx`, the halving card) get a one-line
   historical header in the terminal state rather than being removed —
   history is the product now.

This is a code proposal; implementing it is a normal PR against
`apps/explorer` plus the same deploy command as §4-B, and it should ship
**before** the halt so the terminal state is already in the bundle when
height 80,000 arrives.

---

## 8. What I did NOT do

- Changed nothing: no DNS record, no Cloudflare/Pages setting, no env var, no
  DNS proxy toggle, no systemd unit, no service restart, no deploy. The fleet
  and the site are byte-for-byte as I found them.
- Did not implement the §7 UI changes — proposed with file/line references
  only, since the deliverable is this runbook and the founder may want
  different copy.
- Did not create the :16220 exposure or any tunnel — §4/§5 commands are
  written and rollback-paired but unexecuted, so `blochl1.com/rpc` still
  returns `error code: 1003` as of this writing.
- Did not read the deployed Pages Function bundle itself; I verified the env
  var via `wrangler pages download config` and matched the observed 403/1003
  against the repo's `functions/rpc.js` at commit `fb24825` (the live
  deployment's source commit). The inference chain is labeled in §2.2.
- Did not audit which node-RPC methods beyond the allowlist are dangerous
  post-halt; §4's security note flags the surface but a method-by-method
  sweep was out of scope.
- Did not verify the auxpow box's *intended* fate (full retirement vs. pool
  services only) — §6 is written to be safe under either.
