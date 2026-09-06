<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# SSH role separation

**Current state, plainly: one SSH key and one account (`ubuntu@`) reach all
65 hosts** (`deploy/bootnodes/verify-bootnodes.sh` and the fleet rollout
scripts all ssh as `ubuntu@$HOST` with one shared key,
`edgevana_fleet_g4`/`BLOCH_FLEET_KEY`). That key can do anything any of those
65 hosts can do — start or stop a validator, read a keystore's directory
listing, reconfigure a unit file — regardless of whether the task at hand
needed any of that. This document defines the roles that key should be split
into, and what changes on the wire (`sshd_config`, `authorized_keys`) to get
there.

## Roles

| Role | Can do | Cannot do | Typical caller |
|---|---|---|---|
| **observer** | Read-only RPC/health checks over the network; no shell | Log in, read files, run commands | Monitoring, `verify-bootnodes.sh` (see below) |
| **validator-operator** | Start/stop/restart the validator unit; read (never write) its logs; read keystore *directory listing* (not contents) | Read `validator.key` contents; touch other hosts' units; sudo to root | The human or automation that manages one validator host |
| **archival** | Start/stop/restart the archival/RPC-serving unit; read its logs and RPC | Touch validator units or keys anywhere | Whoever operates read-only/archival infrastructure |

No role is "root on everything." A key compromised in one role should cost
the fleet exactly the blast radius of that role, on exactly the hosts it was
issued for — never all 65 hosts, and never a shell at all where a read-only
RPC call would do.

## Per-role keys, not one shared key

- **One key pair per role per host** (or per small host group under one
  operator, if a role legitimately spans a few boxes) — never one key that
  spans roles, and never the same physical key file reused verbatim across
  hosts that are not meant to trust each other interchangeably.
- Key material lives on **hardware tokens** (a FIDO2/U2F-backed
  `ssh-ed25519-sk` or `ssh-ed25519@openssh.com` resident key, or an
  equivalent smartcard-backed key) for any role above `observer` — a key
  file on an operator's laptop disk is a single stolen laptop away from
  fleet-wide validator control today, and a hardware token turns that into
  "the attacker also needed physical possession and a touch/PIN at the
  moment of use."
- `observer` keys may be software keys, since their blast radius is bounded
  to a read-only network call in the first place — the cost of a hardware
  token is not justified by what the key can do if it leaks.

## `sshd_config` / `authorized_keys` restrictions

Every `authorized_keys` entry for a role above `observer` carries, at
minimum:

```
from="<operator's known egress CIDR or a small allowlist, never 0.0.0.0/0>",
no-agent-forwarding,no-X11-forwarding,no-port-forwarding,
command="<role-scoped wrapper script, see below>"
ssh-ed25519-sk AAAA... operator@role@hostclass
```

- **`from=`** restricts which source addresses may even attempt the key,
  independent of whether the key itself is later compromised — a leaked
  private key is useless from outside the allowlisted range without also
  compromising a host inside it.
- **No forwarding of any kind.** Agent forwarding in particular turns "this
  host trusts this key" into "this key can now be used from this host as a
  pivot" — the exact shape of a lateral-movement chain from one compromised
  box to the next.
- **`command=` pins the session to one script**, so the key cannot be used
  interactively for anything the script does not explicitly allow, even by
  someone who legitimately holds it. The role table above becomes a script,
  not a policy document nobody enforces.

### `ForceCommand` for the read-only verify path

`deploy/bootnodes/verify-bootnodes.sh --deep` sshes into each bootnode today
to read three self-reported facts: whether a `validator.key` is present,
which transport flag the unit was started with, and one RPC call's answer
(`getchaininfo` against loopback). None of that needs a shell, and none of
it needs write access to anything. The `observer`/verify key's
`authorized_keys` entry should read:

```
from="<verifier's known address(es)>",no-agent-forwarding,no-X11-forwarding,
no-port-forwarding,no-pty,
command="/opt/bloch/ssh-verify-readonly.sh"
ssh-ed25519 AAAA... verify-ro@fleet
```

where `ssh-verify-readonly.sh` runs **exactly** the three read-only checks
the script needs (a `find` for `validator.key` under the node's data
directory, `systemctl cat` of the unit file grepped for `--transport`, and
one `curl` to loopback RPC) and nothing else — not a shell, not `$SSH_ORIGINAL_COMMAND`
passed through unchecked (which would defeat the whole point by letting the
caller run anything). `verify-bootnodes.sh` itself should be pointed at this
key via a dedicated variable (`BLOCH_VERIFY_RO_KEY`), separate from whatever
key an operator uses to actually manage a validator, so that running the
verify script — including by a third party rehearsing the quickstart, per
`docs/THIRD-PARTY-QUICKSTART.md` — never requires or risks the fleet's
management key.

## Rotation schedule

| Key class | Rotation interval | Trigger for an out-of-schedule rotation |
|---|---|---|
| `observer`/verify-only keys | Annually | Any suspicion the key or its host was exposed |
| `validator-operator` keys | Every 90 days, or on operator personnel change | Immediately on suspected compromise of the operator's workstation |
| `archival` keys | Every 90 days | Same |

Rotation means: generate a new key pair, add its public half to the relevant
`authorized_keys` entries, confirm the new key works end-to-end for its
role's actual task (not merely that it connects), **then** remove the old
key's `authorized_keys` line. Removing the old key before confirming the new
one works is how an operator locks themselves out during an incident, which
is the worst possible time to discover it.

## What this replaces

Today: one key, one account, 65 hosts, no `from=` restriction visible in the
scripts, and a shell (`ssh ... 'find ... ; systemctl cat ... ; curl ...'`) for
what is conceptually three read-only questions. The rollout scripts that
manage validators (`deploy/deploy.sh`, the flag-day rollout tooling) should
migrate onto `validator-operator`-scoped keys following the same pattern —
that migration is out of scope for this document (it touches the rollout
scripts, which this pass did not rewrite) but the role table and restriction
pattern above is the target shape for that follow-up.
