<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — Weak-subjectivity checkpoint publication pipeline

```
Document:  BLOCH-WS-PUBLICATION-PIPELINE
Status:    DRAFT — implementation shipped (tools/ws-publisher), first
           production ceremony pending the Phase A signer arrangement
Created:   2026-08-31
Follows:   BLOCH-WEAK-SUBJECTIVITY.md (the artifact, window and quorum rule;
           partially superseded in its premises, normative through
           crates/bloch-pos-committee/src/ws.rs), ADR-036
Implements: the recurring half of ws.rs — WS_PUBLICATION_INTERVAL_EPOCHS
Code:      tools/ws-publisher/  (the four stations)
           deploy/ws-publication/  (timer, env, channel fan-out)
```

---

## 0. Why this document exists

`ws.rs` promises a cadence: a checkpoint at every finalized epoch that is a
multiple of `WS_PUBLICATION_INTERVAL_EPOCHS = 256`
(crates/bloch-pos-committee/src/ws.rs:153, ≈ 2.85 days at 32 slots × 30 s).
The verification machinery for that promise is complete — envelope format,
m-of-n hybrid quorum, anti-rollback, boot decision — and **no checkpoint has
ever been published**. A checkpoint that exists once is not a mechanism: the
whole security argument of weak subjectivity is that a fresh node, at any
time, can obtain a *recent* finalized (epoch, root) out of band. "Recent"
is a pipeline property, not an artifact property.

This document is the pipeline: where the artifacts live, who touches what,
what a third party must and must not trust, and how the cadence keeps itself
honest.

The checkpoint payload itself — how the canonical 154 bytes for one
finalized epoch are derived from chain state — is the checkpoint tool's
subject, not this document's. This pipeline consumes that tool as the
**payload producer** (§3, station 1) through a two-placeholder command
contract and judges its output; it never derives chain state itself.

## 1. Artifacts, and which are public

| Artifact | Form | Visibility |
|---|---|---|
| Checkpoint envelope | `wscheckpoint-<epoch>.bin` (`BPOSWSE1`) | **PUBLIC — published as widely as possible** |
| Announcement view | `wscheckpoint-<epoch>.json` + the 64-hex `ws_digest` | **PUBLIC** |
| Signer arrangement | `ws-signer-set-<id>.bin` (`BPOSWSS1`) | **PUBLIC** (also baked into release builds) |
| Well-known index | `publish/latest.json` | **PUBLIC** (carries no authority — §4) |
| Unsigned payload + signing request | `staging/<epoch>/…` | Working state. Not secret, but unpublished: only SEALED artifacts go out |
| Detached signatures | `signatures/<epoch>/sig-<index>.bin` | Working state until sealed into the envelope, which contains them |
| Signer secret keys | keyholder machines only | **NEVER** touches this pipeline's unattended half, never any channel |
| Partner/exchange integration documents | — | **NEVER PUBLISHED** on any channel. This standing rule is orthogonal to checkpoints: checkpoints are public *because* they are consensus artifacts, integration docs are private because they are commercial ones. Do not let the one normalize publishing the other. |

## 2. Trust assumptions, stated plainly

**T0 — The transport is untrusted, and that is the design.** Every channel
in §4 — R2, GitHub, GitLab, the explorer, a Telegram post, a USB stick — is
assumed capable of lying. The artifact is self-verifying: `m`-of-`n` hybrid
ML-DSA-65 ‖ Falcon-1024 signatures over
`SHA3-256("BLCH4:WSCKPT\0\0\0\0" ‖ canonical bytes)` (ws.rs:268), checked
against a signer set the verifier obtained independently, with the network
id and genesis root pinned by the verifier (ws.rs:436 `verify_envelope`). A
malicious mirror cannot forge a checkpoint. What a mirror **can** do is
withhold or serve a *stale but genuinely signed* one; the counters are the
multi-channel rule (§4), the consumer-side freshness rule
(age < `WS_PERIOD_EPOCHS` = 2,016 epochs, ws.rs:140), and the node's own
anti-rollback (`ws_latest`, ws_boot.rs — an older valid envelope never
moves a node backward).

**T1 — The stager trusts one node's view of finality; the signers do not
trust the stager.** The timer-driven station reads `getchaininfo` from a
node the operator runs and judges the producer's payload against it. A
compromised stager (or producer, or node) can therefore stage a *wrong*
payload — and that is where its power ends, because the signing request
(tools/ws-publisher, `signing_request_text`) instructs every keyholder to
recompute the digest from the payload bytes and compare the epoch and roots
against **their own node** before signing. The quorum is not m signatures
on one machine's opinion; it is m independent machines agreeing the epoch
boundary is the one they each finalized. A wrong staged payload dies in the
ceremony, unsigned.

**T2 — The trust root is the signer arrangement, and it is founder-adjacent
today.** Phase A is 2-of-3 with at least one signature from outside the
founding cluster, client-enforced (ws.rs:298–302, `verify_envelope` rule 4).
That is strictly better than one key and it is **not decentralized**; the
honest statement is that a fresh node's first sync trusts this arrangement
exactly as much as a Bitcoin user trusts their binary's checkpoint list.
The arrangement's keys reach a third party out of band: baked into release
builds (which makes the release channel a checkpoint authority in practice
— stated, not hidden, in BLOCH-WEAK-SUBJECTIVITY.md §3), or as a signer-set
file whose SHA-256 is cross-checked across independent channels. The
12-month review clock with a hard stop (ws.rs:161–167) prevents a stale
arrangement from quietly becoming permanent.

**T3 — The signers' maximum power is bounded, and the bound is structural.**
A checkpoint never reorganizes a running node: a node with its own finality
treats a contradicting checkpoint as the loud `WS_CONFLICT` alarm and keeps
following its own chain (engine.rs `enforce_ws_anchor`,
crates/bloch-pos-node/src/engine.rs:820–867). The arrangement's full power
is over a node with **nothing of its own** — a fresh sync — which is
exactly the node that has no alternative under PoS anyway. Compromising the
quorum therefore buys the ability to feed forged history to fresh nodes,
not to rewrite anyone's present.

**T4 — Liveness is an operations property, and it is instrumented.** The
cadence leaves a ~7.8× margin: six consecutive missed ceremonies before the
newest published checkpoint ages past the hard threshold (ws.rs:148–153;
pinned by `publication_cadence_margin`). The timer stages hourly and the
staleness alarm (`status`, wired into ws-stage.sh) turns "ceremony
outstanding" and "cadence slipping" into log lines and webhook pings on
every tick — a quiet pipeline and a stuck pipeline must not look alike.

**T5 — Freshness judgements read a clock.** The artifact deliberately has
no expiry field (ws.rs:206); age is computed by the consumer against wall
time (`wallclock_epoch`, ws.rs:179). A verifier whose clock can be driven
backward can be convinced a stale checkpoint is fresh — the standard NTP
caveat, shared with the node itself.

## 3. The pipeline — four stations, three trust levels

```
        ┌──────────── timer (hourly, unattended, NO KEYS) ────────────┐
        │  ws-stage.sh: getchaininfo ──> due epoch E (multiple of 256)│
        │  producer ──> payload ──> validate ──> staging/E/           │
        │                          SIGNING-REQUEST.txt + webhook ping │
        └──────────────────────────────────────────────────────────────┘
                                    │ human hands the request to keyholders
        ┌──────────── keyholder machines (attended, ONE key each) ────┐
        │  bloch-ws-publisher sign ──> sig-<index>.bin  (detached)    │
        └──────────────────────────────────────────────────────────────┘
                                    │ signatures collected back
        ┌──────────── coordinator (attended, no keys) ────────────────┐
        │  seal: assemble + verify AS A BOOTING NODE WOULD ──>        │
        │        publish/E/ + latest.json + LATEST marker             │
        │  ws-publish.sh <E>: fan out to every channel (§4)           │
        └──────────────────────────────────────────────────────────────┘
```

- **Station 1 — stage** (`bloch-ws-publisher stage`; systemd
  `bloch-ws-stage.timer` → `ws-stage.sh`). Computes the due epoch — the
  latest finalized multiple of 256; when intervals were missed, only the
  latest is staged (back-filling would spend ceremonies on artifacts nobody
  should boot from). Invokes the payload producer (`{epoch}`/`{out}`
  substitution), then refuses anything that is not exactly the artifact
  owed: wrong length or layout (proven against `canonical_serialize`),
  wrong epoch, wrong network/genesis pins, reserved signer-set id, a
  `block_root` disagreeing with the node's finalized root when the epochs
  match, any epoch at or below the newest sealed one (publisher-side
  anti-rollback), and — the sharpest rule — **different bytes for an
  already-staged epoch**: signatures may exist over the staged digest, so
  replacement demands a human deleting the staging directory as explicit
  acknowledgement.
- **Station 2 — sign** (`bloch-ws-publisher sign`, keyholder machines).
  The only station that reads a secret key, and nothing schedules it. The
  signing request is self-contained (payload hex + digest) so the keyholder
  can verify offline; with `--signer-set/--signer-index` the tool refuses a
  signature that does not verify under the keyholder's published key.
  Event-driven off-cadence publications (mass slashing, >5 % stake exit,
  announced ceremony downtime — BLOCH-WEAK-SUBJECTIVITY.md §3) use
  `stage --epoch <E>` and the same ceremony.
- **Station 3 — seal** (`bloch-ws-publisher seal`). Assembles the
  `BPOSWSE1` envelope and runs `ws::verify_envelope` under the real hybrid
  verifier with the same pins a booting node uses — an envelope this
  station writes is one the node accepts, for the same reasons. Writes
  `publish/<E>/`, updates `latest.json` and the `LATEST` anti-rollback
  marker. Surfaces the arrangement-review warning when inside grace.
- **Station 4 — verify** (`bloch-ws-publisher verify`). The third-party
  station; §5 is its manual.

## 4. Publication channels

Everything under `publish/` is served verbatim; per Tokenomics V4 §3.2.2
the checkpoint must be published "widely enough that it cannot be quietly
replaced". The point of multiple channels is **not hosting redundancy — it
is that silently replacing a published checkpoint requires rewriting all of
them at once, in public**, across independently-controlled account systems:

1. **Downloads host (R2)** — stable URLs
   `…/ws/<epoch>/wscheckpoint-<epoch>.bin`, `…/ws/<epoch>/ws-signer-set-<id>.bin`,
   and the well-known `…/ws/latest.json`. `latest.json` is uploaded last so
   a reader following it never lands on a half-published epoch. The index
   carries **no authority**: it merely names the newest epoch and digest,
   and a lie in it is caught by verifying the file it points to — its only
   real power is withholding (T0).
2. **GitHub release**, tag `ws-checkpoint-e<epoch>` — same four files,
   digest in the release notes.
3. **GitLab release**, same tag — a second forge under a separate account
   system.
4. **Announcement channel** — the 64-hex `ws_digest` in the post body
   (English, per the official-language rule). The digest fits in a message
   or a phone call, which is the out-of-band property the mechanism needs.
5. **Explorer front page** (blochl1.com) — renders `latest.json`'s epoch
   and digest from channel 1, giving a fifth surface a replacement attack
   would have to repaint.

Additionally, **every node release bakes in the newest checkpoint at build
time** (spec §3): a freshly downloaded binary is at most release-age stale.
This adds no new trust — whoever runs a binary already trusts its builder —
but it is counted honestly under T2: the release channel is a second
checkpoint authority in practice.

Publication is **human-run** (`ws-publish.sh <epoch>`), not timer-driven:
the multi-channel property only deters replacement if each channel write is
a deliberate, logged act by someone answerable for it.

## 5. Third-party verification — how an exchange confirms a checkpoint

You are about to boot a node from a checkpoint. The transport that handed
it to you is untrusted (T0); these steps make that not matter. Steps 1 and
5 are the two that machines cannot do for you.

**Step 0 — get the tool.** Build from source:
`cargo build --release -p ws-publisher` in the bloch repo (binary at
`target/release/bloch-ws-publisher`). Building from source means the quorum
rule you enforce is the one in the code you can read, not one a binary
asserts.

**Step 1 — obtain the trust root out of band.** You need three values that
must NOT come from the same place as the checkpoint:
- the **signer-set file** `ws-signer-set-<id>.bin`;
- the **network id** and **genesis root** of Genesis-4 mainnet (published
  with the release; the genesis root is the identity of the genesis block
  your node also pins).

Fetch the signer-set file from at least **two** independent channels of §4
and compare their SHA-256 — or take the one baked into a release binary you
already verified by its signed release digest (deploy/RELEASE-INTEGRITY.md).
If the copies disagree, stop: that disagreement is itself the alarm the
multi-channel design exists to raise.

**Step 2 — fetch the checkpoint from anywhere.** Any §4 channel, a peer, a
USB stick — by T0 it genuinely does not matter.

**Step 3 — verify.**

```
bloch-ws-publisher verify \
    --checkpoint wscheckpoint-<epoch>.bin \
    --signer-set  ws-signer-set-<id>.bin \
    --network-id  <pin> \
    --genesis-root <pin> \
    --genesis-unix <genesis unix time>     # enables the freshness verdict
```

Exit 0 prints `GENUINE …` with the quorum breakdown (m signatures, external
minimum met) and a freshness verdict. This is the same `ws::verify_envelope`
judgement the node makes at boot — wrong network, wrong chain, reserved
signer set, expired arrangement, duplicate signer, under-quorum,
founder-only quorum, or any bad signature each refuse with the reason
printed. **Anything but exit 0: do not use the file.**

**Step 4 — check freshness.** The verdict must be `fresh` (age <
1,008 epochs) or, with eyes open, `STALE` (< 2,016). `EXPIRED` means the
checkpoint is older than the weak-subjectivity window and a quorum of
since-exited validators could in principle have signed a forged history at
zero cost — the exact attack the mechanism exists to close. Never boot from
an expired checkpoint; if no fresh one is published anywhere, that is a
protocol-level liveness incident (T4), not something to work around.

**Step 5 — cross-check the digest out of band.** `verify` printed
`ws_digest`. Compare those 64 hex characters against at least two §4
channels (explorer front page, announcement post, a release page). Step 3
proved the quorum signed *this* file; step 5 proves *this* file is the one
the world saw published — the step that turns "validly signed" into
"genuine", and the one that makes a quietly substituted (older, genuinely
signed) artifact visible.

**Step 6 — boot, and let the node re-judge everything.**

```
bloch-pos --data-dir <dir> --ws-checkpoint wscheckpoint-<epoch>.bin \
          [--ws-signer-set ws-signer-set-<id>.bin]   # devnet builds only;
                                                     # releases bake the keys
```

The node re-verifies the envelope independently (ws_boot.rs) — this tool
saying yes is convenience, not authority — anchors finality at the
checkpoint, and will never revert below it. State sync then verifies every
piece against `state_root` / `validator_set_root`: the trust is the 32
bytes of each root, never the peer serving the data.

**Step 7 — after sync, confirm agreement.** `getchaininfo` must show your
node's finalized checkpoint at the artifact's epoch equal to its
`block_root`, and the log must be free of `WS_CONFLICT`. A node that
synced fresh treats a conflict as fatal by design (engine.rs:867ff): if you
ever see it, the chain your peers served contradicts the published
checkpoint — stop and raise it loudly, because one of the two is lying and
both possibilities are incidents.

Credit deposits only against `finalized: true` (BLOCH-RPC-V4.md; rpc.rs
`block_json`) — the checkpoint bounds *history*, finality bounds *now*.

## 6. What this pipeline refuses to automate

- **Signing.** No station holds more than zero production keys except
  `sign`, which a human runs, attended, per keyholder, on the keyholder's
  machine. The unattended half's terminal state is a signing request.
- **Publication.** Fan-out is one human command per ceremony, not a timer
  side effect (§4).
- **Payload replacement.** Re-staging different bytes for an epoch is a
  hard error resolved only by a human deletion (§3, station 1).

## 7. Code and constants referenced

| What | Where |
|---|---|
| Cadence, window, thresholds | crates/bloch-pos-committee/src/ws.rs:140–171 |
| Canonical payload + `ws_digest` | ws.rs:188–276 (`WS_CHECKPOINT_BYTES` 154, `DS_WSCKPT` params.rs:658) |
| Quorum rule + envelope verification | ws.rs:298–516 (`verify_envelope`) |
| Node-side file framing + boot | crates/bloch-pos-node/src/ws_boot.rs (magics `BPOSWSE1`/`BPOSWSS1`) |
| Forward enforcement / WS_CONFLICT | crates/bloch-pos-node/src/engine.rs:820–880 |
| The four stations | tools/ws-publisher/src/lib.rs, src/main.rs |
| Timer, env, channel fan-out | deploy/ws-publication/ |
