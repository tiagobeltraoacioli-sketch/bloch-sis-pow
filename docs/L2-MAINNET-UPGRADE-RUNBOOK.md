# Operator runbook — upgrade for the native L2 activation (epoch E)

Companion to the public notice (`docs/L2-MAINNET-ACTIVATION-NOTICE.md`). Placeholders `{{…}}` are filled when the
notice is published. Applies to **validators, archivals / RPC nodes and
bootnodes**; exchange nodes follow the archival path.

- Release: `bloch-pos` {{VERSION}}, commit `{{COMMIT}}` (short `{{COMMIT_SHORT}}`)
- Binary SHA-256: `{{SHA256}}`; signing key `{{bloch-release-YYYYMMDD.pub}}`
- Activation epoch **E = {{E}}** (first slot `32·E`). Epoch start time:
  `2026-08-13T21:31:19.962Z + E × 16 min` (30 s slots, 32 slots per epoch,
  from `genesis/mainnet.manifest`).
- **Deadline: installed and verified before T−2 d ({{DATE}}).**

The new release is **byte-for-byte consensus-compatible with the current
one before epoch E**: it produces and accepts exactly the same blocks and
state roots. You can upgrade at any time in the window without coordinating
with other operators. At E, only the new release follows the chain.

## 0. Order of upgrades

1. **Bootnodes and the published archivals** (139.180.166.5,
   139.180.173.231) first.
2. **Validators**, one host at a time; never stop two validators that share
   a host or an operator at the same moment.
3. **Exchange / RPC / explorer nodes** any time before T−2 d.

Upgraded validators must peer **directly** with other upgraded nodes. A node
whose only path to the network is an old-release relay is partitioned at E
(seen in the mixed-fleet qualification). Check §4 step 5.

## 1. Pre-checks (on each host, before touching anything)

```bash
# 1. The node is healthy and synced on the current release
curl -s -H 'Content-Type: application/json' 127.0.0.1:{{RPC_PORT}} \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' | jq '{slot, finalized, behind_by_slots, transport}'
curl -s -H 'Content-Type: application/json' 127.0.0.1:{{RPC_PORT}} \
  -d '{"jsonrpc":"2.0","id":1,"method":"getbuildinfo","params":[]}' | jq .build_version
```

- `behind_by_slots` ≈ 0, finality advancing (finalized epoch = current − 2
  or so), peers > 0.
- Note the **current** `build_version` and binary path: that is your
  rollback target.
- Free disk ≥ 2 × `blocks.log` (for the pre-E backup in §2) and the usual
  memory headroom; the release does not raise memory use before E.
- The current epoch is **well before E** (`slot / 32`). If you are within
  ~2 epochs of E, do not start a non-urgent upgrade on a validator without
  the coordination channel.
- Validators: confirm the systemd unit (or your supervisor) and its exact
  `ExecStart` arguments. **Do not change arguments**; the release needs none.

## 2. Backups

- **Keep the old binary** (e.g. `/usr/local/bin/bloch-pos.prev-{{OLD_COMMIT}}`).
- **Chain data snapshot** (optional, recommended before E): a copy of
  `blocks.log`, `blocks.idx` (if present), `meta.bin`, `ws_latest.bin` taken
  with the node stopped. It lets you recover quickly if the node ever stores
  blocks of a minority branch after E.
- **Never** copy `validator.key` into a routine backup, and **never restore
  `slashing_protection.bin` from a backup over a newer one**: restoring an
  older watermark reopens the double-signing window
  (`deploy/BACKUP-AND-HOST-LOSS.md`). The chain-data snapshot excludes both.

## 3. Get and verify the release

```bash
mkdir -p ~/bloch-release-{{VERSION}} && cd ~/bloch-release-{{VERSION}}
# download bloch-pos, SHA256SUMS, SHA256SUMS.minisig from {{RELEASE URL}}
minisign -Vm SHA256SUMS -p /etc/bloch/{{bloch-release-YYYYMMDD.pub}}   # key pinned out of band
sha256sum --check SHA256SUMS                                             # bloch-pos: OK
chmod +x bloch-pos
./bloch-pos --version        # must contain {{COMMIT_SHORT}}
./bloch-pos buildinfo | jq '{build_version, commit, tree_state}'
```

Refuse the binary if any of these holds: signature or checksum fails; the
version does not name `{{COMMIT_SHORT}}`; `build_version` contains `+dirty`,
`+devnet…` or `l2-activation-rehearsal` (a rehearsal build refuses the
mainnet manifest anyway). Optional: rebuild from source
(`git checkout {{COMMIT}}; cargo build --release -p bloch-pos-node`) and
compare SHA-256 (see `REPRO.md`).

## 4. Install

```bash
sudo systemctl stop {{UNIT}}                      # clean stop; wait for exit
sudo cp /usr/local/bin/bloch-pos /usr/local/bin/bloch-pos.prev-{{OLD_COMMIT}}
sudo install -m 0755 ~/bloch-release-{{VERSION}}/bloch-pos /usr/local/bin/bloch-pos
sudo systemctl start {{UNIT}}
journalctl -u {{UNIT}} -f                          # watch the restart
```

Replace **only the executable**: same data dir, same arguments, same
`validator.key`, same `slashing_protection.bin`. The node restarts from its
local state cache or replays its block log; on a validator the log shows the
slashing-protection watermark it resumed from.

Then verify:

1. `getbuildinfo.build_version` names `{{COMMIT_SHORT}}`.
2. `getchaininfo`: head advancing, `behind_by_slots` ≈ 0, finality advancing.
3. Validators: the node proposes / attests again (duties in the log; no
   `slashing protection` refusals other than for slots it already signed).
4. `getl2settlement` returns `null` **before E** (expected: no L2 yet).
5. **Peering**: `getchaininfo.transport.peers` > 0, and at least one peer is
   another upgraded node (bootnodes/archivals already upgraded, or an
   upgraded validator you peer with directly). Add upgraded peers to
   `--peers` only through your normal change process.
6. **Report** `build_version` and your validator index to
   {{READINESS CONTACT}} (the readiness count at T−7 d and T−2 d uses it).

## 5. Rollback before E

Safe at any time **before the first slot of epoch E**: both releases are
consensus-identical until then.

```bash
sudo systemctl stop {{UNIT}}
sudo install -m 0755 /usr/local/bin/bloch-pos.prev-{{OLD_COMMIT}} /usr/local/bin/bloch-pos
sudo systemctl start {{UNIT}}
```

Keep the data dir and `slashing_protection.bin` as they are (never an older
copy). Tell {{CONTACT}}: a rolled-back validator does not count toward the
90 % readiness threshold, and **it will stall at E** unless it upgrades again
before E (or the activation is postponed).

**After E there is no rollback**: the old release rejects the first block of
epoch E (`StateRootMismatch`). Fixes after E come as new forward releases.

## 6. If the activation is postponed

A postponement is announced on {{OFFICIAL CHANNELS}} with a **replacement
release** (the epoch is compiled in; there is no flag or config to change).
**Install the replacement before the original epoch E**, exactly as in §3–§4.
A node left on the superseded release would activate the L2 alone at E and
leave the network.

## 7. At and after E

- Around E: watch `getchaininfo` (head and finality continue through the
  first slots of E) and the log (no `StateRootMismatch`).
- After the first block of E: `getl2settlement` reports the L2:
  `profile.activated = true`, `chain_id = 700770`, `asynchronous = true`,
  `withdrawals.delay_blocks = 64`, `large_delay_blocks = 2880`,
  `release_window.blocks = 2880`, `release_window.bps = 1000`,
  `release_window.floor_sat = "1000000000"`, `attested_claim_sat =
  "10000000000"`, `attestor_set = {{ATTESTOR SET HASH}}`.
- Finality of epochs E, E+1, E+2 reached on your node = activation done.

```bash
curl -s -H 'Content-Type: application/json' 127.0.0.1:{{RPC_PORT}} \
  -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' \
  | jq '{chain_id, asynchronous, profile, d: .withdrawals.delay_blocks, D: .withdrawals.large_delay_blocks, w: .withdrawals.release_window, a: .withdrawals.attestor_set}'
```

If your node stopped at E (`StateRootMismatch` in the log, finality frozen):
it is on the old release. Install the new one (§3–§4). If it then refuses
its own block log ("durable block log failed consensus replay"), it stored
minority-branch blocks after E: restore the chain-data snapshot from §2
(keeping the current `validator.key` and `slashing_protection.bin`) or
bootstrap from a snapshot (`docs/SNAPSHOT-BOOTSTRAP.md`), then restart.

## Checklist

- [ ] Pre-checks green; old binary kept; chain-data snapshot (optional)
- [ ] Signature and SHA-256 verified; version names `{{COMMIT_SHORT}}`
- [ ] Installed, restarted, synced; duties resumed (validators)
- [ ] Peers include upgraded nodes
- [ ] Version reported to {{READINESS CONTACT}} before T−2 d
- [ ] After E: `getl2settlement.profile.activated = true`; E..E+2 finalized
