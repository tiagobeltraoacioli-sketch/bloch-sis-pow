# Terminal-height rollout runbook

Ships the rule that ends the Genesis-3 chain at height **80,000**. The chain
was at ~40,424 on 2026-08-11, so the rule is inert on arrival and stays inert
for about two weeks.

**Branch:** `deploy/g3-terminal-height` — `g3-integration` + the recovered
pool-proxy work + the terminal-height rule + commit stamping. Nothing else.

## Why the order is what it is

Staged by blast radius, least critical first. Each box gets the same binary,
verified by hash, and is watched before the next one is touched.

| # | Box | Role | If it breaks |
|---|---|---|---|
| 1 | node4 `136.244.82.226` | archival peer | Loses a peer. Chain unaffected |
| 2 | miner-box `192.248.190.123` | node + GPU miner + L2 + tunnels | Loses hashrate and the RPC bridge |
| 3 | auxpow `45.76.89.225` | **block producer** + merged pool | **Chain stops producing** |

The producer is last and gets an explicit go/no-go, because it is the one box
whose failure is indistinguishable from the halt this release is designed to
cause — and telling those two apart at 2 a.m. is exactly the situation to avoid.

Only the `bloch` node binary is deployed. `bloch-pool-proxy` and
`bloch-merged-pool` are separate binaries and are **not** touched, even though
this branch carries pool-proxy source changes. Smaller blast radius, and the
recovered pool-proxy work has not been exercised anywhere yet.

## Per-box procedure

```bash
BOX=136.244.82.226; KEY=~/.ssh/edgevana_node4; SVC=bloch-g3
NEW=bloch-terminal-height          # the binary being installed
EXPECT=<sha256 of the built binary>

# 1. verify what is about to run, before it runs
scp -i $KEY target/bloch ubuntu@$BOX:/home/ubuntu/$NEW
ssh -i $KEY ubuntu@$BOX "sha256sum /home/ubuntu/$NEW"      # must equal $EXPECT
ssh -i $KEY ubuntu@$BOX "chmod +x /home/ubuntu/$NEW && /home/ubuntu/$NEW --version"

# 2. record what is running now, so rollback is one command
ssh -i $KEY ubuntu@$BOX "systemctl cat $SVC | grep ExecStart | head -1 | tee ~/rollback-$SVC.txt"

# 3. point the unit at the new binary via a drop-in — never edit the unit file
ssh -i $KEY ubuntu@$BOX "sudo systemctl edit $SVC"          # Environment / ExecStart override
ssh -i $KEY ubuntu@$BOX "sudo systemctl daemon-reload && sudo systemctl restart $SVC"

# 4. verify it is actually the new binary that came up
ssh -i $KEY ubuntu@$BOX "systemctl show $SVC -p ExecMainPID --value | xargs -I{} readlink /proc/{}/exe"
ssh -i $KEY ubuntu@$BOX "journalctl -u $SVC -n 40 --no-pager | tail -20"
```

## What "healthy" means before moving to the next box

Watch for **10 minutes**, not 30 seconds:

- the process stays up (no restart loop — `Restart=always` hides crashes as
  churn; check `systemctl show -p NRestarts`)
- tip height advances, or tracks the network if the box does not produce
- peer count returns to its pre-deploy value
- no `invalid difficulty`, no `consensus rejection` in the log
- **no** `past the terminal height` — at ~40k that message means the constant
  or the chain-id wiring is wrong, and the deploy must stop immediately

## Rollback

The old binary is left in place under its original name on every box. Rollback
is: remove the drop-in, `daemon-reload`, `restart`. Do it at the first
unexplained symptom rather than debugging live — the height is two weeks out,
there is time for a second attempt and no reason to improvise on a producer.

## Verifying the fleet afterwards

```bash
for b in 136.244.82.226:edgevana_node4 192.248.190.123:edgevana_miner_new 45.76.89.225:edgevana_auxpow; do
  ssh -i ~/.ssh/${b#*:} ubuntu@${b%%:*} '/home/ubuntu/bloch-terminal-height --version; sha256sum /home/ubuntu/bloch-terminal-height'
done
```

All three must print the **same** version string and the **same** hash. That
one command is the thing the 2026-08-11 survey could not do, and the reason
this release stamps the commit into the binary.

## The real deadline

The rule must be running on the fleet before height 80,000. Any box still on an
old binary at that height keeps mining past the end and forks. That is
survivable — the canonical record is the signed snapshot, not the longest chain
— but it is avoidable, and avoiding it is the entire point of deploying early.

---

## Rollout record — 2026-08-11

Deployed to all three boxes. Binary `af72aefbc351fc353bc0bb4136cf94c09896c6e019f05b8baf9a2a29e92607fb`,
stamped `bloch 0.3.0-genesis2 (6ec737838cac)`.

| Box | Was | Now | Height after | Restarts |
|---|---|---|---|---|
| node4 | `bloch-p60` `a85b0e0` | `bloch-terminal-height` | 43,110 | 0 |
| miner-box | `bloch-p60` `a85b0e0` | `bloch-terminal-height` | 43,110 | 0 |
| auxpow (producer) | `bloch-p60` `a85b0e0` | `bloch-terminal-height` | 43,111 | 0 |

Producer kept producing across the restart: 7 blocks in 180 s, against 3 in
60 s measured before. No `past the terminal height`, no panics, no consensus
rejections, no `invalid difficulty` on any box. `bloch-merged-pool`,
`bloch-pool-proxy`, `bitcoind-mainnet`, `bloch-gpu-miner`, `bloch-l2`,
`bloch-rpc-bridge` and `cloudflared` were not touched and stayed up.

### Correction to the pre-deploy survey

The survey that preceded this reported "three boxes, three different binaries".
**That was wrong.** It read the `ExecStart` of the *base unit* on each box,
when every box carries a stack of systemd drop-ins — up to sixteen on auxpow —
and the last one alphabetically wins. All three were in fact running the same
binary, `bloch-p60`, sha `dfc6962d…`, built from commit `a85b0e0`.

The fleet was uniform, and better documented than reported: each drop-in
records the commit and sha of the binary it installs, and that convention is
what made this deploy verifiable. The authoritative way to ask what is running
is `readlink /proc/$(systemctl show $SVC -p ExecMainPID --value)/exe`, not
`systemctl cat`.

What survives from the survey: the uncommitted pool-proxy work on auxpow was
real and is now in git, and the version string carried no commit — which is why
identifying `bloch-p60` took md5 comparison rather than one command. That is
fixed; the table above is the proof.
