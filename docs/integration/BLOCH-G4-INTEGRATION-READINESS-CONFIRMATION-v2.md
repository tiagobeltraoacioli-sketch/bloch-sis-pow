# Bloch Genesis-4 — Integration Readiness Confirmation

**Edition 2 · 2026-09-07 · Code revision `72e5525` (branch `main`)**

Restates the three items requested of edition 1 — API documentation, chain
architecture documentation, and RPC node information — against the current
code. **This edition is code-verified, not live-verified**: the environment
that produced it has no network path to `posternlabs.com`, to either direct
node, or to any other running Genesis-4 endpoint. Edition 1's "verified live at
height 42497" and "verified live against the running network" claims are
**not repeated here, for any height** — this document says, item by item,
what was checked and how, and marks every claim **VERIFIED-IN-CODE** (read
directly from the source tree at `72e5525`) or **OPERATOR-ASSERTED**
(an infrastructure fact — a URL, an IP, a proxy's behaviour — this repository
cannot prove or disprove). Full detail and evidence for every row below is in
the accompanying `Bloch-G4-Technical-Integration-Reference-v2.md`.

<div class="warn">

**Before anything else: a fresh node cannot independently join Genesis-4
today, and this bounds which of the three items below can be exercised
first-hand.** The 2016-epoch weak-subjectivity trust window that lets a new
node take the genesis manifest on faith closed on **2026-09-05 07:07:19.962
UTC** (`crates/bloch-pos-committee/src/ws.rs:133-167`, arithmetic over the
genesis manifest's own `genesis_time_ms`). No signed weak-subjectivity
checkpoint exists anywhere in this repository, and per the most recently
dated in-repo operator note (2026-09-06), the signing ceremony that would
produce one has not been held. A node started fresh from an empty data
directory, right now, will sync from genesis and then refuse to complete,
with the code's own message: *"validators who exited and withdrew long ago
can sign a complete forged history at zero cost; beyond the window, nothing
inside the protocol lets a syncing node tell that forgery from the chain the
network actually lived"* (`crates/bloch-pos-node/src/ws_boot.rs:590-609`). A
node that already completed its first sync before that date is unaffected.
**This means item 3 below (RPC node information) can today only be exercised
against the public endpoint or a fleet-operated direct node — not against a
node an exchange stands up from scratch** — until a checkpoint is published.
See item 3 and the accompanying operator memo,
`CHANGES-for-the-endpoint-operator.md`, for what would resolve this.

</div>

---

## 1 — API documentation

| Check | Status | Class | Note |
|---|---|---|---|
| Comprehensive JSON-RPC 2.0 documentation covering every routed method, its parameters, response fields, and error codes | **Confirmed against the code**, with corrections | VERIFIED-IN-CODE | The full reference now lists **all 15** routed methods, including three edition 1 omitted entirely (`getvalidators`, `gettxstatus`, `getbuildinfo`) — the "10 methods" edition 1 listed as "all read methods live and responding" was incomplete against the frozen method registry. |
| Write method (`sendrawtransaction`) documented | **Confirmed, with a field-shape correction** | VERIFIED-IN-CODE | Its response does **not** carry a `txid` field, contrary to a sample response in an internal integration document; compute `txid` client-side. |
| Full field lists and sample responses | **Confirmed with two corrections** | VERIFIED-IN-CODE | (a) `getmempoolinfo` returns **8** fields today, not the 4 edition 1 showed. (b) A block response's `finalized` field is a **boolean**, not the `{epoch, root}` object edition 1's block-format table described — that object shape exists only on the unrelated `getchaininfo` response. |
| Error codes documented | **Confirmed the node defines 11 dedicated codes plus the 5 standard JSON-RPC codes; edition 1 named 5 and misstated one** | VERIFIED-IN-CODE | `-32010` means **two different things** depending on which layer answers: at the node, a mempool per-source cap refusal; at the (unverifiable) public proxy, a read-quorum disagreement per edition 1. `-32008` (terminal) vs. `-32009` (retryable, ~64-minute lapsing bar) is a distinction edition 1 never drew, which the node's own source names as a real, previously-committed integration mistake on this project. |
| Authentication model documented: public read + broadcast, no key required, method allowlist | **Node-level auth model confirmed and materially expanded**; **allowlist itself is proxy-level and OPERATOR-ASSERTED** | VERIFIED-IN-CODE (node) / OPERATOR-ASSERTED (proxy allowlist) | The node's own RPC has no API key and no per-method authorisation *and* (new since edition 1) refuses any request carrying an `Origin` header, requires `Content-Type: application/json`, and validates the `Host` header against an allowlist — none of this existed when edition 1 was written. A read-method allowlist specifically is a **proxy** behaviour this repository does not contain code for. |

**Verdict: item 1 is code-verified as substantially complete, with the field-
and error-code corrections above now folded into the reference document's
Appendix A.**

---

## 2 — Chain structure / architecture

| Check | Status | Class | Note |
|---|---|---|---|
| Consensus: PoS + Casper-FFG explicit finality; 30s slots, 32-slot epochs | **Confirmed** | VERIFIED-IN-CODE | `SLOT_DURATION_SECS=30`, `SLOTS_PER_EPOCH=32` (`params.rs:43,82`); justification at exact ⅔ stake, finalization on two consecutive justified checkpoints (`finality.rs`). |
| Cryptography: hybrid ML-DSA-65 ‖ Falcon-1024, both must verify; SHA3-256/SHAKE-256, domain-separated | **Confirmed, with exact tag bytes now cited** | VERIFIED-IN-CODE | See the reference document §4 for the full domain-tag table. |
| Ledger: extended UTXO; deterministic non-malleable `txid`; conservation as an equality | **Confirmed exactly** | VERIFIED-IN-CODE | `spent_value != created + fee` is checked with `!=`, not a tolerance band. |
| Address format: `bloch1q` + 40 hex + 8 hex SHA3 double-checksum (55 chars); regex and `script_hash` derivation documented | **Confirmed for the case it describes; materially incomplete as a general claim, and its own validation regex was stricter than the code** | VERIFIED-IN-CODE, with corrections | The stated derivation (40-hex hash + 24 zero hex chars) is correct **only** for the legacy-compatible "Carried" `script_hash` form; a distinct, equally valid, full-32-byte "Native" form exists and cannot be expressed by an address string at all. The lowercase-only regex edition 1 gave (`^bloch1q[0-9a-f]{48}$`) is stricter than what the reference parser actually accepts (mixed-case hex). |
| Block format field-by-field; transaction wire tags and fee model | **Confirmed with two material gaps closed** | VERIFIED-IN-CODE | The transaction wire-tag table now includes `0x05 SlashingEvidence` (decodes, gated inert) and `0x06 TransferV2` (**live and active since epoch 800** — a majority of this chain's operating history), both absent from edition 1. **There is no stake-withdrawal transaction on this chain, at any wire tag, and legacy `Deposit`/`Delegate` are refused by consensus at every epoch, structurally and permanently by design** — neither fact appeared in edition 1. |
| Finality: "a block at or below `finalized_height` is irreversible", stated without qualification | **Materially qualified — this is the most important correction in this edition** | VERIFIED-IN-CODE | The node's own RPC source explicitly retracts the stronger, slashing-backed reading of "irreversible": **no stake on Genesis-4 can be slashed today**, for four independent, code-confirmed reasons; the underlying Casper-FFG rule can itself propose a legitimate downward finality cut, mitigated only by a per-node engine latch added 2026-09-05; and a partition holding as little as 6.25% of stake has, on this exact chain's own history, self-finalized a rogue checkpoint before the quorum-denominator-floor fix (armed for 2026-09-12, not yet in force). The accompanying reference document's §11.3 gives the current, explicit crediting recommendation (finalized + ~30 epochs, two independently operated nodes agreeing on the same root and epoch) in place of edition 1's unqualified rule. |
| Weak subjectivity / fresh-node bootstrap | **Not previously documented at all; added in this edition as a load-bearing fact** | VERIFIED-IN-CODE | See the boxed warning above and the reference document §2.6/§13.4. |

**Verdict: item 2's documentation is code-verified as substantially accurate
on cryptography, ledger model, and block/transaction structure, and
materially strengthened on address derivation and finality; the finality
qualification above is the single fact most likely to change an integration
decision an exchange has already made against edition 1's text.**

---

## 3 — RPC node information

| Check | Status | Class | Note |
|---|---|---|---|
| Public RPC endpoint documented, live and reachable | **Not re-verified — see the scope note above** | OPERATOR-ASSERTED | `https://posternlabs.com/g4rpc` is carried forward from edition 1 unchanged; this repository contains no proxy source code and no way to confirm reachability from this environment. |
| Bootnodes published | **Confirmed present in this repository's own operational documentation, at the addresses edition 1 gives** | VERIFIED-IN-CODE (as a document) | `139.180.166.5:19100`, `139.180.173.231:19100`, transport **devnet**, not libp2p — the repository's own bootnode-verification tooling states plainly that `--transport libp2p` against these hosts "exchanges zero frames and leaves you alone on your own fork." |
| Direct node HTTP reachable at `139.180.166.5:8080` / `139.180.173.231:8080` | **Unresolved — flagged for operator confirmation, not confirmed as edition 1 states** | OPERATOR-ASSERTED, with an internal contradiction | This repository's own bootnode-verification script and an operational runbook both state, independently, that node RPC binds `127.0.0.1` **fleet-wide, including these exact two hosts**, and that reaching a loopback-bound RPC from outside requires an explicit forwarding bridge documented elsewhere for a *different* node. Whether these two hosts run such a bridge cannot be confirmed from this repository. **Do not re-assert this item as live without the endpoint operator confirming these two addresses are reachable, or replacing them with confirmed-reachable addresses.** |
| Self-hosted validating-node path available and documented | **The command line edition 1 gives does not work against the current binary; a corrected one is given** | VERIFIED-IN-CODE (as a code fact, both the failure and the fix) | `--peer` (singular) is not a flag; `--transport dual` as given is missing the `--listen <port>` it requires; `--data-dir`/`--genesis` (both hard-required) are absent; the compiled default RPC port is **16310**, not the `8080` edition 1 gives for a self-hosted node. A working command line is given in `Bloch-G4-Technical-Integration-Reference-v2.md` §13.2. |
| Self-hosted node reachable and joinable today | **Blocked, for any node started from now on — see the boxed warning above** | VERIFIED-IN-CODE | The weak-subjectivity gap (above) applies regardless of which command line is used. |
| Rate limits and caching | **Node-level bounds confirmed and expanded; proxy-level TTLs/quorum policy unchanged from edition 1 and unverified** | VERIFIED-IN-CODE (node) / OPERATOR-ASSERTED (proxy) | The node itself has no per-IP rate limit (by design — an anti-exhaustion, not authorisation, posture) but does cap total concurrent connections (64) and body size (1 MiB). Proxy per-method cache TTLs (3–300s) and "quorum ≥ 2" are carried forward unverified; an internal operational note additionally states `getchaininfo` specifically is corroborated only "softly" and can silently answer from a single, uncorroborated node under quorum failure — a caveat edition 1 does not state. |
| Dedicated RPC nodes provisionable on request | **Carried forward unchanged** | OPERATOR-ASSERTED | Not something this repository can confirm or deny. |

**Verdict: item 3's node-level facts (bootnode addresses and transport, the
correct self-hosted command line, node-level rate/connection bounds) are
code-verified; the public-endpoint and direct-node-IP reachability claims are
OPERATOR-ASSERTED and one of them (the two `:8080` direct-node addresses) is
in unresolved tension with this repository's own operational documentation;
and the self-hosted path — while now correctly documented — is currently
blocked for any newly-started node by the weak-subjectivity gap above,
independent of anything the endpoint operator does.**

---

## What the endpoint operator must do before this confirmation can be
## re-asserted live

This edition cannot re-assert "verified live" for any item above, because
this environment has no network access. Before a future edition can, the
endpoint operator (of `posternlabs.com/g4rpc` and of the two direct nodes)
needs to:

1. **Confirm, or correct, the two direct-node `:8080` addresses** — this
   repository's own tooling says fleet RPC binds loopback; either confirm a
   public forwarding bridge exists on these two hosts (and that it is an
   intended, supported exposure, not an ad-hoc leftover) or supply corrected,
   currently-reachable addresses.
2. **Confirm the proxy's Host-allowlist behaviour on its own upstream
   requests to each node** — the node's own RPC now validates the `Host`
   header against an allowlist (`BLOCH_RPC_HOST_ALLOWLIST`); if the proxy's
   upstream requests to a node do not send a `Host` value the node's
   allowlist accepts, every proxied read will start failing the moment the
   fleet runs a binary carrying this gate. Confirm the allowlist is
   configured to include whatever `Host` value the proxy actually sends.
3. **Confirm the proxy never forwards an `Origin` header upstream** — the
   node refuses *any* request carrying one, regardless of value. If the proxy
   passes through a caller's `Origin` (e.g. for a browser-originated request
   it is fronting), every such proxied call will now be refused at the node.
4. **Confirm the proxy's own `Content-Type` on upstream requests is exactly
   `application/json`** — the node refuses anything else with `415`.
5. **Confirm the proxy's listening port and TLS termination**, and publish
   (or correct) the exact per-method cache TTLs and quorum policy this
   document carries forward unverified, ideally as a machine-checkable
   artifact rather than prose, since no RPC method on this surface exposes a
   `getcapabilities`-style flag for a client to branch on.
6. **Publish a signed weak-subjectivity checkpoint**, or confirm one has been
   published since 2026-09-06, so that item 3's "self-hosted node" path is
   actually exercisable for a node started from now on.

See `CHANGES-for-the-endpoint-operator.md` for the concrete, itemized version
of this list, including what changes on a rebuild onto the current binary.
