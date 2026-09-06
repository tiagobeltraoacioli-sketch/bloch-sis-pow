<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Fleet inventory — Genesis-4 validators

**Why this file exists.** `README.md` and `SECURITY.md` used to state the
genesis validator cohort "sits on five servers" — a specific, memorable, and
as far as this pass could verify, **unmeasured** claim: no file in this
repository ties that number to a host list, and the Round-2/3 audits found
the fleet's actual shape to be considerably more fragmented (a mix of Fly
machines with no public IP and classic boxes, `deploy/FLAG-DAY-EPOCH-800.md`
documents 49 Fly + 15 classic = 64 registered indices, which is not "five
servers" under any grouping this pass could reconstruct). Rather than repeat
an unverified number, this file is the place operators record the real,
current shape of the fleet — with **opaque host identifiers**, not real
hostnames or IPs (this file is expected to be readable in a public repo;
`deploy/SSH-ROLE-SEPARATION.md` and `deploy/BACKUP-AND-HOST-LOSS.md` are
where real identifiers may need to live, access-controlled, if an operator's
process requires it).

**Status of the values below: TO BE FILLED by the operator.** This pass did
not have access to the live fleet (no host, port, or endpoint named anywhere
in this repository was contacted — see the Round-3 audit's own method
notes for the same constraint) and is not asserting any of the placeholder
figures below as measured fact. Populate this table from
`deploy/bootnodes/verify-bootnodes.sh` output and your own fleet records,
and keep it current — a stale inventory is exactly the kind of claim this
file exists to stop making.

## Host inventory

| Opaque host ID | Role | Validator count on this host | Notes |
|---|---|---:|---|
| `HOST-001` | TO BE FILLED (validator / archival / bootnode) | TO BE FILLED | |
| `HOST-002` | TO BE FILLED | TO BE FILLED | |
| `HOST-...` | ... | ... | Add one row per host; do not collapse the fleet back into a round number nobody re-measured. |

**Totals (fill in, do not leave stale):**

| | Count |
|---|---:|
| Hosts | TO BE FILLED |
| Validators (should total 64 — the genesis cohort size, `deploy/FLAG-DAY-EPOCH-800.md`) | TO BE FILLED |
| Validators per host, min/max | TO BE FILLED |

## How to fill this in

1. Run `deploy/bootnodes/verify-bootnodes.sh --deep` (needs a read-only
   verify key, see `deploy/SSH-ROLE-SEPARATION.md`) against every known
   entry, and cross-reference against your own operational records for any
   host not on the public bootnode list.
2. Assign each host an opaque ID (`HOST-001`, `HOST-002`, ...) — pick IDs
   that do not encode role, provider, or location in a guessable pattern,
   since the point is not to publish an attack map alongside the validator
   count.
3. Record how many validator indices run on each host. A host running many
   validators is a concentration fact worth stating plainly (the same
   spirit as `docs/audit/CERTIK-CENTRALIZATION.md`'s treatment of stake
   concentration) — do not round it away.
4. Update the totals row, and re-run this process on any fleet change
   (`deploy/FLAG-DAY-EPOCH-2700.md` and future flag days are natural
   checkpoints to refresh it).

## What this file deliberately does not contain

- Real hostnames, IP addresses, or SSH key filenames — see
  `deploy/RPC-SURVIVAL-RUNBOOK.md`'s redaction notice for the same reasoning
  applied to that document.
- Anything that would let a reader map "opaque host ID" back to a specific
  provider account or physical location. If your fleet's opaque IDs
  accidentally do this (e.g. `AKASH-1`, `FLY-2`), pick different IDs.
