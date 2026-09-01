# Bloch Genesis-4 — validator operator toolkit

Four scripts, in the order you run them. Each one refuses rather than warns
where the mistake is expensive or irreversible; the refusals are the point,
not friction to route around. Full context is in
[`docs/VALIDATOR-RUNBOOK.md`](../../docs/VALIDATOR-RUNBOOK.md).

| # | tool | when | exit codes |
|---|------|------|------------|
| 1 | `blochv-preflight.sh` | before the deposit | 0 ok · 1 warnings · 2 do not proceed |
| 2 | `blochv-keygen.sh` | offline, at a console | 0 ok · 1 refused |
| 3 | `blochv-guard.sh` | before **every** start that carries a key | 0 safe · 1 read the warnings · 2 do not start |
| 4 | `blochv-health.sh` | on a timer, forever | 0 OK · 1 WARN · 2 CRIT |

All four are read-only against the network. Only `blochv-keygen.sh` writes key
material, and it never prints, echoes, or stores a secret byte.

---

## 1. `blochv-preflight.sh` — can this machine do the job

```sh
./blochv-preflight.sh --data-dir /var/lib/bloch/data --peers <ip:port,...>
```

Checks binary identity + `selfcheck`, cores, **available** RAM against the
measured >7.5 GiB cold-start peak, disk, a single-core replay-budget proxy,
NTP *and* a measured clock offset in seconds, open-file limits, port hygiene,
and whether this machine can actually open a TCP connection to a peer.

Refuses (exit 2) on: a `+dirty` or unstamped binary, a failing `selfcheck`,
fewer than 2 cores, RAM below the measured cold-start peak, a disk below the
floor, a clock offset that will cost you duties, a port already in use, and a
bootstrap artifact whose peer list is still unfilled placeholders.

## 2. `blochv-keygen.sh` — two keys, in this order

```sh
# on a cold machine, first
./blochv-keygen.sh --role withdrawal --dir /media/cold/bloch-withdrawal
# then on the (offline) validator machine, at its console
./blochv-keygen.sh --role validator --dir ~/bloch-validator \
                   --withdrawal-credentials <64-hex from the step above>
```

The validator key is hot by construction. The withdrawal credentials are the
one thing a stolen hot key must not be able to redirect, and the deposit makes
them immutable forever — so the tool refuses withdrawal credentials that are
the validator key's own script hash, refuses to run without them at all,
refuses shared/network/tmpfs storage and world-readable paths, and refuses to
overwrite an existing keystore.

## 3. `blochv-guard.sh` — the double-signing gate

```sh
./blochv-guard.sh --data-dir /var/lib/bloch/data --rpc http://127.0.0.1:16400
```

The only tool here whose failure costs stake rather than uptime. Refuses when
the signing history binds a different key than the keystore beside it, when
the chain says this validator is already `active` while this machine has no
signing history (so `--accept-new-signing-history` would be a false claim),
when the key sits on storage a second machine could mount, when another
process already holds the data dir, and when the doppelganger watch is being
disabled without an explicit coordinated-launch acknowledgement.

It can only see *this* machine. Nothing can prove your key is not also running
elsewhere — which is why it will not let you turn the doppelganger watch off
casually.

## 4. `blochv-health.sh` — must not call a forked node healthy

```sh
./blochv-health.sh --rpc http://127.0.0.1:16400 --index <n> \
  --reference http://<someone-else's-node>:16400 \
  --reference http://<a-second-independent-node>:16400
```

`behind_by_slots` is `wall_slot - your own head slot`. A forked node keeps
proposing on its own branch, so that field reads 0 forever while it agrees
with nobody. This tool therefore **refuses to print OK without two
independent references**, and compares `block_id` *and* `state_root` at a
common anchor slot, plus the finalized root at the same finalized epoch.

"Independent" means a different operator, host and network path. Three nodes
in one rack are one reference wearing three hats.
