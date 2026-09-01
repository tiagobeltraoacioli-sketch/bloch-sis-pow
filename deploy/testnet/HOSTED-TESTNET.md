# Genesis-4 hosted public testnet — deployment runbook

Status: **plan + scripts, not yet deployed.** Built on the proven local
testnet (`local-testnet-up.sh`, which ran four validators, finalized, and
carried a real hybrid-signed spend end to end with exact fee conservation).
The hosted variant changes only *where* and *how supervised* — same binary,
same `run` command, same devnet transport, same transition.

## 0. Two binding rules (inherited from the code, do not weaken)

> **The full replay-isolation argument now lives in `REPLAY-ISOLATION.md`**,
> alongside the four tests in `crates/bloch-pos-node/src/genesis.rs` that
> enforce it. Read it before changing anything about how this genesis is
> built. The short version is below; the long version is the one that matters,
> because the guarantee is narrower than it looks.

> **UNCLAIMED WIRE NUMBERS (blocking a real deployment).** The ports below
> (18500-18503 RPC, 19500-19503 mesh, 8788 nginx) and the hostname
> `t4rpc.posternlabs.com` have **not** been claimed from the PMO. They do not
> collide with the mainnet fleet's 16400+i, but that is an observation, not an
> allocation. Claim them before bringing this up on a shared host.

1. **Never seed from the mainnet carryover; never reproduce a mainnet
   allocation tuple.** `spend_signing_root`
   (`crates/bloch-pos-committee/src/transition.rs`) carries no chain id;
   cross-network replay is prevented **only** by outpoint disjointness.
   Identical genesis outpoints would make a testnet-signed spend valid on
   mainnet. The scripts enforce this by construction: `hosted-testnet-up.sh`
   has no carryover flag and allocates only to a key it just generated.
2. **Throwaway keys only.** Every key (validators, faucet, smoke recipient)
   is generated fresh on the testnet host. No mainnet key ever touches this
   machine's `t4` directory, and no testnet key is ever reused on mainnet.

## 1. Host: node4 (136.244.82.226)

`ssh -i ~/.ssh/edgevana_node4 ubuntu@136.244.82.226`

Why node4 (verified 2026-08-31):

- **Not a mainnet-fleet host.** It carries **zero** G4 validators. The only
  chain process on it is `bloch-g3.service` — the Genesis-3 archival peer of
  a chain that has been dead since 2026-08-13. The seven fleet Edgevana
  boxes (nine validators each) are explicitly excluded.
- **Spare capacity:** load average 0.03–0.41, 7.0 GiB RAM available,
  19 GB disk free, 2 vCPU. A fresh 4-validator testnet at 30 s slots is a
  light workload — the local proof ran the same four validators at **1 s**
  slots on one machine. Mainnet's per-box RAM pain came from gigabytes of
  accumulated state; a fresh testnet starts near zero and grows ~30× slower
  than that fleet did.
- Already systemd-disciplined and reachable, with an SSH key on file.

Runner-up, rejected: the AuxPoW box (45.76.89.225) — 79 % disk used and it
still runs pruned `bitcoind`.

**Cleanup while installing:** node4's existing `bloch-rpc-8080.service` is a
socat forward to `127.0.0.1:16422` where **nothing listens** — a live
specimen of the silent-dead-upstream failure this deployment is designed
against. Disable it (`sudo systemctl disable --now bloch-rpc-8080`) so the
box carries no dead forwards.

## 2. Shape: 4 validators, 30 s slots

- **4 validators**, all on node4, mesh on loopback. Four is the proven local
  configuration, tolerates one node down, and fits the box. Co-location is
  deliberate: a node restarted far behind the head does not reliably
  cold-sync on this transport (genesis/README.md, measured 2026-08-14), so
  recovery must be "restart the whole set together" — one host, one
  `systemctl restart bloch-t4.target`.
- **30 s slots — mainnet cadence, fixed.** Epoch = 32 × 30 s = 16 min;
  finality ≈ 2 epochs ≈ 32 min. An exchange rehearsing a withdrawal loop
  gets the real inclusion-to-settlement timing, not a fast devnet's.
- The devnet mesh is **never** exposed publicly (it is unauthenticated by
  design; on mainnet one stale external peer halted all production,
  2026-08-09). `net.rs` binds `127.0.0.1` by default; no `--listen-addr` on
  a public interface, ever. Public access is JSON-RPC through the front only.

## 3. Deployment steps

```
# on the Mac: push the branch commit the testnet runs (this worktree's
# HEAD: e4083f96 + spendkey + genesis --alloc + submit-tx --raw)
# on node4:
sudo systemctl disable --now bloch-rpc-8080          # dead forward, see §1
git clone <repo> ~/bloch-t4-src && cd ~/bloch-t4-src && git checkout <pinned-commit>
curl https://sh.rustup.rs -sSf | sh -s -- -y && . ~/.cargo/env
cargo build --release -p bloch-pos-node              # one-time, ~45–90 min on 2 vCPU
cp target/release/bloch-pos ~/bloch-pos-t4

cp deploy/testnet/{hosted-testnet-up.sh,faucet-drip.sh,t4-health.sh} ~/
chmod +x ~/hosted-testnet-up.sh ~/faucet-drip.sh ~/t4-health.sh
~/hosted-testnet-up.sh /home/ubuntu/t4               # ≈2 h incl. proofs at 30 s slots
```

The bring-up script proves, at mainnet cadence, the same three things the
local one proved: production, finality, and a finalized hybrid-signed spend
(via `faucet-drip.sh`, so the drip tool itself is exercised before any
partner uses it). Then let it **soak 24 h** with the health timer on before
announcing anything.

**Note the binary:** the mainnet fleet binary does NOT have `spendkey`,
`genesis --alloc` or `submit-tx --raw`. The testnet binary is built from
this branch. Consensus code is identical to what the branch inherits from
`e4083f96` (the fleet lineage); the additions are CLI-only.

```
# front + monitor:
sudo apt install nginx
sudo cp deploy/testnet/nginx-t4rpc.conf /etc/nginx/sites-available/t4rpc
sudo ln -s ../sites-available/t4rpc /etc/nginx/sites-enabled/t4rpc
sudo nginx -t && sudo systemctl reload nginx
sudo cp deploy/testnet/bloch-t4-health.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bloch-t4-health.timer
```

## 4. Public endpoint: `t4rpc.posternlabs.com`

Pattern that already works in production (l2rpc, g2rpc): **local forwarder +
Cloudflare tunnel**. Here the forwarder is nginx (not socat) because the
node's RPC emits no CORS and socat cannot add headers — the same reason
g2rpc grew an nginx.

```
node RPCs (127.0.0.1:18500-18503)
   ← nginx upstream, failover + CORS (127.0.0.1:8788)
   ← cloudflared named tunnel "t4rpc"
   ← https://t4rpc.posternlabs.com
```

cloudflared is not on node4 yet:

```
# on node4
curl -fsSL https://pkg.cloudflare.com/cloudflared-linux-amd64.deb -o c.deb && sudo dpkg -i c.deb
cloudflared tunnel login                # Cloudflare account with posternlabs.com
cloudflared tunnel create t4rpc
cloudflared tunnel route dns t4rpc t4rpc.posternlabs.com
# /etc/cloudflared/config.yml: tunnel: t4rpc / url: http://127.0.0.1:8788
sudo cloudflared service install && sudo systemctl enable --now cloudflared
```

### The failure mode this design refuses to repeat

The mainnet g4rpc proxy's upstream list named nodes by bare port; when
validators moved hosts, every entry died **silently**. Countermeasures, all
three, are in the shipped configs:

1. **No cross-host references.** Every upstream is `127.0.0.1:1850x` on the
   same box, ports written by the same script that writes the validator
   units. An upstream cannot "move away" from its front.
2. **Failover, not silence.** nginx `max_fails`/`proxy_next_upstream` skips
   a dead node; a partner sees an answer or an honest 502, never a hang.
3. **Probed by port, publicly.** `t4-health.sh` (5-min systemd timer) hits
   every node's port, cross-checks that all four report the **same finalized
   root**, tracks finality advancement, and writes the verdict to
   `https://t4rpc.posternlabs.com/health`. A dead upstream is a visible
   fact within 5 minutes, not a discovery some partner makes for us.

nginx also serves `/genesis.blg` + `/genesis.blg.sha256` so any party can
verify which testnet genesis they are on. Optional hardening once traffic
warrants: an nginx `limit_req` zone (the RPC has no auth by design; the
Cloudflare edge provides the first line).

## 5. Faucet: manual drip now, and that is the recommendation

`tools/faucet` was assessed and **rejected for adaptation now**: it is
Genesis-3 vintage end to end — `bloch1t…` bech32 addresses and
`validateaddress`, against a G3 RPC surface and a G3 transaction format,
none of which exist on Genesis-4 (G4 is `script_hash`-keyed, hybrid
ML-DSA-65 ‖ Falcon-1024, different canonical bytes). Its own README says
scaffold/unaudited/never run against a live network. Adapting it is a
rewrite of everything except the rate limiter.

Instead: **`faucet-drip.sh`** — ~100 lines over the exact
`getutxos → submit-tx → spendkey --sign → submit-tx` path the local testnet
proved, with exact fee arithmetic at the base-fee floor, single-UTXO
discipline (refuses to drip while a previous drip is uncommitted), and a
wait-for-landing check. **A manual drip is the right faucet for the first
partners** — they number in the single digits, each request is an onboarding
conversation anyway, and it keeps zero web-attack surface on the box that
holds the faucet key. A partner asks (email/Telegram) with their
`script_hash`; the operator runs:

```
~/faucet-drip.sh /home/ubuntu/t4 <script_hash_hex> 100000   # 100k tBLCH
```

A self-service web faucet is a later, separate build (G4-native, reusing
`tools/faucet`'s rate-limit ideas at most) — only worth it when requests
outnumber partners.

## 6. Exchange withdrawal rehearsal — what works today

Fully rehearsable through the public endpoint, remotely:

1. `keygen` + `spendkey` locally → own throwaway key + `script_hash`.
2. Request a drip (§5).
3. Build a withdrawal: `submit-tx --raw` (no `--to` needed) prints the
   signing root; sign with `spendkey --sign` (or their own HSM-side signer —
   the root is the external-signer seam); re-run with `--signature --raw` →
   canonical hex **and txid**.
4. `sendrawtransaction` (hex) via `https://t4rpc.posternlabs.com`.
5. Confirm: `gettxout(txid, vout)` — its `finalized` flag is the settlement
   judgement; ~32 min at real cadence. Balance via `getbalance`/`getutxos`.
   There is deliberately no tx index (`gettransaction` is refused).

`submit-tx --raw` is the one code addition this plan required (this branch,
`main.rs`): it prints canonical bytes + txid instead of requiring access to
the non-public devnet transport port.

## 7. Validator rehearsal — what is and is not possible, and why

**Not yet possible — the deposit lifecycle.** All three staking messages
are refused at mempool admission (`crates/bloch-pos-node/src/engine.rs`,
`admissible()`), each for a stated reason:

- `Deposit` / `Delegate`: bonding is not yet funded from the eUTXO set — a
  deposit names an `amount_sat` and mints stake without destroying coins.
  Measured 2026-08-13: 25,000 BLCH of stake per unauthenticated request;
  ~180 requests would take the chain. Refused until deposits carry real
  eUTXO inputs (wire-format change + flag day).
- `Exit`: the message is unauthenticated — anyone could irreversibly retire
  any validator. Refused until it carries a signature bound to the
  validator's key.
- Withdrawal of a bond: no transaction shape exists yet at all.

So a partner **cannot** yet practice deposit → activation → exit → withdraw,
and no configuration of this testnet changes that: the missing pieces are
consensus wire formats, not deployment. That work (funded deposits,
authenticated exits, a withdrawal shape) is the prerequisite, estimated at
2–3 weeks of protocol work + adversarial review + its own flag day — and
rehearsing **that flag day on this testnet before mainnet** is precisely
what the testnet is for. The constants are already live in
`staking.rs` and will apply unchanged: MIN_DEPOSIT 25,000 tBLCH,
ACTIVATION_DELAY 8 epochs, ≤4 activations/epoch, EXIT_DELAY 32 epochs,
WITHDRAWAL_DELAY 2,048 epochs (≈23 days at 30 s slots — rehearsable only
end-to-end on a testnet, which is an argument for standing this up early).

**Possible today — genesis-cohort operator rehearsal.** At a scheduled
reset, a partner's freshly generated validator pubkey (keygen TSV, public
halves only) is included in the new genesis validator set; they run the
fifth validator on their own machine over **WireGuard** (the mesh is
unauthenticated, so partner access is by keyed WG peer + `--listen-addr` on
the WG interface — never a public port). That rehearses key generation,
node operation, duties/attestation, restart discipline, and what happens to
an absent validator (inactivity leak). Offered on request; ~2 days to set
up including the reset.

## 8. Operations

- **Restart**: always the whole set — `sudo systemctl restart bloch-t4.target`.
- **Health**: `https://t4rpc.posternlabs.com/health`, or
  `systemctl status bloch-t4-health` on the box.
- **Resets**: a testnet resets. ≥72 h notice to partners; a reset is
  `hosted-testnet-up.sh /home/ubuntu/t4 destroy` + a fresh run; new genesis
  digest published at `/genesis.blg.sha256`; all balances gone; partners
  re-request drips.
- **Flag-day caveat**: activation constants are absolute epochs compiled
  into the binary (`params.rs`: TransferV2 + block-bytes-v2 at e800,
  leaked-roster at e1400). A fresh testnet starts at e0, so for ~9 days it
  runs pre-e800 rules — `TransferV1` (what `submit-tx` emits) works from
  slot 1; `TransferV2` is refused until testnet e800. If a partner needs V2
  earlier, lower the constant in a testnet-only build and reset.
- **Partner docs stay private**: onboarding materials are delivered as
  files, never published to the site or as shared artifacts.

## 9. Honest schedule

| When | What |
|---|---|
| Day 0 (½ day) | rustup + release build on node4, deploy binary, disable dead forward |
| Day 0–1 | `hosted-testnet-up.sh` (~2 h proofs at 30 s slots), then 24 h soak with health timer |
| Day 1 | nginx + cloudflared + DNS; external round-trip: drip → remote `--raw` spend → `sendrawtransaction` → `gettxout` finalized |
| Day 2 | Onboarding doc finalized with live endpoint + genesis digest; delivered to first partner |

Start 2026-09-01 → **partner-ready 2026-09-04** (one day of buffer on three
days of work — the 2-vCPU build and the first 30 s-cadence soak are the
uncertain items). Genesis-cohort validator rehearsal: +2 days from a
partner's request. Deposit/exit lifecycle rehearsal: **blocked on the
funded-bonding protocol work** — late September at the earliest; not
promised to partners.
