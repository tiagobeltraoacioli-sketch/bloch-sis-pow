# Changes for the endpoint operator

**For:** the operator of `posternlabs.com/g4rpc` and of the two direct nodes
(`139.180.166.5`, `139.180.173.231`), when rebuilding on the current binary
(`72e5525` or later). **Source:** code-verified against `72e5525`, 2026-09-07;
no live host was contacted to produce this memo. Full evidence for every item
is in `Bloch-G4-Technical-Integration-Reference-v2.md`.

## 1. The node's own RPC now refuses requests it used to accept — check your proxy against this before rebuilding

The current binary adds an HTTP admission gate ahead of the JSON-RPC parser
(`crates/bloch-pos-node/src/rpc.rs:1311-1502`) that did not exist when the
public documentation was last written:

- **Any request carrying an `Origin` header is refused with `403`, regardless
  of its value.** If your proxy's upstream requests to a node ever pass
  through a caller's `Origin` (e.g. because you are fronting a browser-based
  client), those requests will start failing the moment the node behind them
  is rebuilt on this binary. **Action: strip `Origin` from every upstream
  request the proxy makes to a node.**
- **`Content-Type` must be exactly `application/json`** (parameters after `;`
  are ignored, case-insensitive) or the node answers `415`. **Action: confirm
  the proxy always sends this exact header upstream.**
- **`Host` must match the node's bound address, a loopback literal, or an
  entry in `BLOCH_RPC_HOST_ALLOWLIST`.** This is an environment variable read
  once at node process start — there is no CLI flag for it. **Action: before
  rebuilding a node behind the proxy, set `BLOCH_RPC_HOST_ALLOWLIST` on that
  node's process to whatever `Host` value the proxy's upstream requests
  actually carry**, or every proxied read will start failing with `403`
  immediately after the rebuild.
- **Only `POST` is accepted; any other verb, including `OPTIONS`, gets `405`,
  not `204`.** There is no CORS preflight support on the node itself. If the
  public endpoint's own CORS/preflight behaviour is implemented by the proxy
  answering `OPTIONS` itself (never forwarding it upstream), no change is
  needed here — but confirm that is actually the case, since the two
  documents this project has published previously did not distinguish "the
  proxy answers this" from "the node answers this."
- **Chunked transfer-encoding is refused (`411`).** Confirm the proxy does
  not re-chunk a request body before forwarding it.
- **Body cap is 1 MiB, header block cap is 16 KiB, and total concurrent
  connections are capped at 64 (a global cap, not per-IP).** If the proxy
  maintains a connection pool to each node, confirm it stays well under 64
  concurrent connections per node, and that it does not attempt to reuse a
  connection across multiple calls — **every response includes `Connection:
  close`; there is no keep-alive on this surface.**

## 2. `-32010` means two different things — pick one before your documentation ships again

At the node, `-32010` is `TX_REFUSED_SOURCE_CAP` (a mempool per-source
admission cap on `sendrawtransaction`). The public-facing documentation
assigns `-32010` a different meaning at the proxy layer: "no read quorum:
upstreams disagreed." Both are real, but a client that talks to both layers
(reads through the proxy, writes/broadcasts through a direct node, as the
published guidance itself has recommended) cannot tell them apart from the
code alone. **Action: either remap the proxy's own quorum-failure code to a
number the node never uses, or document the collision explicitly in every
integrator-facing document going forward** (this edition's reference document
already does the latter, as a stopgap).

## 3. Confirm or correct the two direct-node `:8080` addresses

This repository's own bootnode-verification tooling and an internal
operational runbook both state, independently, that node RPC binds
`127.0.0.1` fleet-wide, **including these exact two hosts** — which is in
direct tension with publishing them as reachable "Direct node HTTP" JSON-RPC
endpoints. **Action: confirm whether a public-forwarding bridge (the pattern
already used and documented for a different, unrelated archival node in this
project's deploy tooling) exists and is an intended, supported exposure on
these two hosts. If it does not, remove these two addresses from
integrator-facing material or replace them with confirmed-reachable ones.**

## 4. The default RPC port changed in every published sample command

The compiled default RPC port for a node run with no `--rpc-port` flag is
**16310**, not `8080` — `8080` never appears anywhere in this binary's own
default configuration. If any published "run your own node" instructions
still show `127.0.0.1:8080` as the resulting RPC address, or a run command
using `--peer` (singular — not a real flag) instead of `--peers`, or
`--transport dual` without the `--listen <port>` it now requires, or omitting
the now-hard-required `--data-dir`/`--genesis` flags, **that command line will
not produce a running node as written.** Replace it with the corrected command
line in `Bloch-G4-Technical-Integration-Reference-v2.md` §13.2 before
publishing it again.

## 5. Publish a weak-subjectivity checkpoint, or confirm one already exists

The 2016-epoch trust-once window that lets a fresh node sync from the genesis
manifest alone closed on **2026-09-05 07:07:19.962 UTC**. As of the most
recently dated in-repo operator note (2026-09-06), no signed checkpoint
existed and the Phase-A signing ceremony had not been held. **Action:**

- If the ceremony has since run and a checkpoint has been published: publish
  its distribution channel(s) prominently (site, release page, explorer,
  announcement channel) and confirm its digest is consistent across at least
  two of them, since that cross-channel agreement is the verification method
  the node's own boot logic recommends to an operator fetching it.
- If it has not: every third party who tries to stand up their own observer
  node from a fresh clone will hit `ERR_WS_REQUIRE_CHECKPOINT` and be unable
  to proceed. This is a blocking dependency for the "run your own validating
  node" integration path this project's own documentation recommends for
  exchange deposit-crediting — prioritise it accordingly if that path is
  meant to be available in practice, not only in principle.

## 6. Confirm which margin figure is current

Three places in this project state three different confirmation-margin
figures for the same question ("how long past finality before crediting"):
`SECURITY.md` (2026-09-06, the newest) says **~30 epochs**; the RPC source's
own doc comment and an internal integration guide (both 2026-09-05 or older)
say **3 epochs**, and both of the older two also still describe the
quorum-denominator-floor fix as unarmed, which is now stale — it is armed for
2026-09-12. **Action: confirm `SECURITY.md`'s 30-epoch figure is the one the
project wants exchanges building against, and update the RPC source's doc
comment and the internal integration guide to match** — this reference edition
adopts the 30-epoch figure as authoritative in the meantime, on the stated
reasoning that it is the newest and its rationale still holds.

## 7. Update the explorer footer

The project's own deploy configuration
(`apps/explorer/wrangler.toml`) states `explorer.posternlabs.com` is a
**retired** name and `blochl1.com` is the live domain. Public documents that
still list both side by side as current should drop the retired one.
