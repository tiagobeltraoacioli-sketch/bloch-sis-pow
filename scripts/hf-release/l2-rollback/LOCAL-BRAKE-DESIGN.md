# Node-local L2 brake: design (not built)

Status: design only, round 10 (agent 169). No code was written. It answers L1-10's open item "freio
local" with a shape the owner can accept or reject before the December node release.

## What it is

A file on a node that makes **that node**:

1. as proposer, leave out of its blocks L2 withdrawal claims (`0x16`) for leaf indices at or above
   `min_leaf_index`, and optionally all L2 settlement proofs (`0x13`);
2. at the mempool door (RPC `sendrawtransaction` and gossip, which meet at one call,
   `engine.rs:4847`), refuse those same transactions as **state-dependent** (retry later), not as
   `Invalid`, so no peer is penalized and nothing stays barred after the brake is lifted.

It changes nothing in block validation. A block from another proposer that carries a claim is
checked and applied exactly as today. It is **not consensus**, so it cannot split the chain.

## Why it is worth having, and its limit

- **G2b (own settler, honest users):** claims go through the own public RPCs and the own withdraw
  tooling. A brake on the own RPC nodes and own proposers stops nearly all of them. That keeps the
  rollback's head reset reachable (`reset_head` refuses once a leaf beyond the target is claimed,
  `l2_settlement.rs:1710`).
- **G2a (an attacker):** the attacker needs only a few claim transactions per 2,880-block window,
  and any proposer without the brake will include them. If braked stake proposes a share f of the
  slots, the unbraked slots per window are (1 − f)·2,880; at f = 0.99 that is still about 29. **The
  brake does not stop a determined attacker unless f ≈ 1.** It is a speed bump, not a defense. Only
  the consensus options in TABLETOP-R10.md recommendation 1 bound that case.
- **A vote-level brake** (validators refusing to attest blocks with claims) would be a soft fork:
  it splits the chain, or stalls finality, whenever braked stake is below 2/3. It also conflicts
  with the owner's principle against runtime controls. **Rejected.**

## Interface

File `<datadir>/l2-brake.json`, read at most once per slot (mtime check). A missing file means off.
A malformed file means off, with a CRIT log line every slot, so a typo can never censor by accident.

```json
{
  "version": 1,
  "claims_from_leaf_index": 4128,
  "settlements": false,
  "until_epoch": 10700,
  "reason": "G2 2026-12-06: rebuild of L2 block N+1 differs; reset target N"
}
```

- `claims_from_leaf_index` (u64 or null): claims with `L2WithdrawClaim.index` at or above it are
  held back (`transition/l2_claim.rs:143-154`). Set it to `count(N)` so honest leaves at or below
  the reset target still pay. `0` holds every claim. `null` holds none.
- `settlements` (bool): also hold every `L2SettlementAsync`. Use it only in G2a, while the own
  settler is stopped.
- `until_epoch` (u64, required): the brake switches itself off at that epoch, so a forgotten file
  never censors indefinitely. Refused if it is more than 1,350 epochs (two weeks) ahead.
- `reason` (string, required, at most 200 bytes): logged with every held transaction.

## Code points (node crate, about 120 lines plus tests)

| Where | Change |
|---|---|
| `engine.rs` `Config` (`:427`) | `l2_brake_path: Option<PathBuf>`, defaulting to `<datadir>/l2-brake.json` |
| new `engine/l2_brake.rs` | `struct L2Brake { claims_from: Option<u64>, settlements: bool, until_epoch: u64 }`, `load(path, mtime cache)`, and `fn holds(&self, tx, epoch) -> bool` |
| mempool door (`engine.rs:4847`, after `l2_admission_refusal`) | `if brake.holds(&tx, epoch) { return Err(Refusal::StateDependent("L2 brake on this node")) }` |
| proposer (`select_transactions`, `engine.rs:4940-4955`) | `live_l2_proof` skips held settlements; the candidates filter skips held claims |
| `getmempoolinfo` / metrics | `l2_brake: {active, claims_from, settlements, until_epoch, held_since_start}` |
| `getl2settlement` | unchanged (consensus view) |

## Tests to write

1. A held claim at or above the index is not proposed; a claim below it is.
2. A block from another proposer that carries a held claim validates and applies (no consensus effect).
3. RPC submit while held returns `StateDependent`; the same bytes are admitted after `until_epoch` (no bar).
4. Malformed file: brake off, CRIT log line.
5. `until_epoch` in the past: off. More than 1,350 epochs ahead: refused, off.
6. Settlement hold: `live_l2_proof` returns `None` while a held proof is pending.

## Operating it

- **Engage** (own RPC nodes first, then own validators; no restart):
  write the JSON above to each node's datadir with the install user's permissions.
- **Check:** `getmempoolinfo` shows `l2_brake.active = true` on every own node.
- **Lift:** delete the file, or let `until_epoch` pass. Held transactions that clients resubmit are
  admitted again.
- **Optional automation:** the owner's per-settlement rebuild (TABLETOP-R10.md recommendation 3)
  writes the file with `claims_from_leaf_index = count(last matching block)` when it finds a
  mismatch, on the own RPC nodes only. Automation stays node-local: it never touches consensus.

## Public statement (draft)

"Bloch Inc nodes may hold back L2 withdrawal claims above a stated index during an L2 incident,
for at most two weeks. Blocks from other proposers are validated as always. Claims below the
index are not affected."
