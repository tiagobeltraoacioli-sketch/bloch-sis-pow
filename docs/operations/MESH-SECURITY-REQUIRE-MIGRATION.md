# Moving the mesh from `--mesh-security offer` to `require`

Status: candidate implementation on `codex/l1r18-meshrequire-20261117`. Nothing
here is deployed, and no host or argv has been changed. This note describes the
order of operations once a release carries the change.

Scope: the TCP mesh selected by `--transport devnet` (`net.rs`, `mesh_pq.rs`),
which is the transport mainnet validators run. This is node-local. It changes
which connections a node accepts, never what a valid block or state is, so it
needs no activation epoch and no coordination of a flag day. The cost of a
mistake is connectivity (a node cut off from peers), not a consensus fault.

## What the modes do

| Mode | Dials | Accepts | Against an active attacker |
| --- | --- | --- | --- |
| `plain` (default) | plain | plain | nothing |
| `offer` | handshake, falls back to plain | handshake or plain | nothing: the offer can be stripped and both ends settle on plain |
| `require` | handshake only | handshake only | no plain session can be forced; modified handshakes fail |
| `require` + `--mesh-plain-allow <file>` | as `require`, except to listed addresses, which get `offer` | as `require`, except from listed addresses, which get `offer` | as `require` for unlisted peers; as `offer` for listed ones |

`require` on its own is encryption only. A party on the path can still complete
a full handshake with each side under its own keys, because no identity is
expected. Closing that takes `--mesh-allow` or pinned `--peers`
(`host:port=<identity>`) and then `--mesh-require-authenticated`. That is the
step after this migration, and it is described in the header of `mesh_pq.rs`.

A `require` node and an `offer` node always seal their connection, in either
dial direction. The fleet can therefore be mixed for as long as the migration
takes.

## The exception list

`--mesh-plain-allow <file>`: one IP address per line, `#` starts a comment.

```
# external validators that have not upgraded yet
203.0.113.9      # operator A
2001:db8::17     # operator B
```

- Addresses only. No port, no host name, no prefix length. A peer dialed by
  name must be listed by the address the name resolves to.
- The exception covers every node at that address, so a NAT address excepts
  everything behind it.
- Never list an address of the owner fleet. Those nodes are upgraded together
  and need no exception.
- The file is read at start. A change needs a restart of that node.
- It cannot be combined with `--mesh-require-authenticated`, and it is refused
  under `plain`. Under `offer` it is accepted and has no effect, so a rollback
  is a one-word change (see below).
- A listed address keeps the weakness of `offer`: traffic with it may be plain,
  and an attacker on that path can force plain. The node warns about the list
  at every boot.

## What to watch

Metrics (`/metrics`):

| Series | Meaning |
| --- | --- |
| `bloch_pos_mesh_security_mode` | 0 plain, 1 offer, 2 require |
| `bloch_pos_mesh_sealed_sessions` | sealed sessions open now, both directions |
| `bloch_pos_mesh_plain_sessions_outbound` | plain sessions open now to a `--peers` address |
| `bloch_pos_mesh_plain_sessions_inbound` | plain inbound sessions open now that delivered at least one well-formed frame |
| `bloch_pos_mesh_plain_sessions_{outbound,inbound}_total` | the same, counted since start |
| `bloch_pos_mesh_plain_refused_total` | connections a `require` node refused because the peer did not speak the handshake |

Log lines (stderr, at most one per peer per 10 minutes):

- `net: mesh session to|from <peer> ... is PLAIN, not encrypted: ...` names a
  peer that would be cut off by `require` without an exception.
- `net: mesh session to|from <ip> is sealed although <ip> is listed in
  --mesh-plain-allow` names an exception that is no longer needed.
- `net: mesh handshake to|from <peer> refused: ...` is a refused connection.

The outbound series is exact: it only counts addresses the operator configured.
The inbound series ignores connections that never send a well-formed frame, but
on a public port it still counts tools that speak the plain frame format
(`submit-tx`, for example). `bloch_pos_mesh_plain_refused_total` also counts
port scans on a `require` node, so read it together with the refusal log line,
which names the peer.

"Nobody uses plaintext any more" means: on every owner node both
`bloch_pos_mesh_plain_sessions_*` gauges are 0, the `_total` counters have not
moved over the observation window, and no `is PLAIN` line names a validator.

## Steps

1. **Release and observe (no argv change).** Roll the new binary across the
   owner fleet with `--mesh-security offer` unchanged. Watch for at least one
   full day. Any plain session between two owner nodes is a misconfigured node;
   fix that first. Collect the addresses named by the `is PLAIN` lines: these
   are the peers that still need plaintext.
2. **Write the exception list.** Put every external validator address in it,
   not only the ones seen in plain. An external operator that has upgraded may
   still roll back, and a missing entry cuts that validator off. Distribute the
   same file to every owner node.
3. **Canary.** Change one owner node that carries little stake to
   `--mesh-security require --mesh-plain-allow <file>`. Leave it for several
   epochs. Check that `bloch_pos_peer_count_devnet` is what it was, that the
   node still attests, and that the refusal log names no validator.
4. **Roll the owner fleet**, one host at a time, with the same argv. Wait for
   finality to advance between hosts. Never restart hosts that together carry
   a third of the stake at the same time.
5. **Ask external validators to upgrade** and run `offer` or `require`. As each
   one's sessions become sealed (the `is sealed although ... listed` line, and
   no `is PLAIN` line for that address for several days), remove the address
   from the list and restart the owner nodes on their normal cadence.
6. **Drop the flag** once the list is empty. The fleet is then on plain
   `require`.
7. **Then authenticate**: collect identities, add `--mesh-allow` or pins, and
   finally `--mesh-require-authenticated`.

Notes:

- `submit-tx` and the equivocation injector speak plain frames. A `require`
  node refuses them unless their source address is listed. Submit through the
  JSON-RPC.
- With Bloch Sentinel hooks enabled, a refused inbound peer is reported to
  Sentinel as a handshake failure and counts against that source there. This
  is one more reason to list every external validator before the switch.

## Rollback

Per node, argv only, one restart, no state to repair:

- Change `--mesh-security require` back to `--mesh-security offer`.
  `--mesh-plain-allow` may stay in the argv; under `offer` it has no effect.
- `mesh_identity.bin` is untouched and the node keeps its identity.
- To go back to a binary older than this change, remove `--mesh-plain-allow`
  from the argv as well: an older binary does not implement it.

A node rolled back to `offer` reconnects to every peer whatever mode that peer
runs, so a rollback can be done on one node, one host or the whole fleet, in
any order.
