# BLOCH-ATTESTATION-GOSSIP — Attestation propagation for Genesis-4 PoS

> **Owner:** A11 (P2P & gossip). **Status:** draft for review.
> **Inputs:** `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §5.1, §6.5, §6.5.2, G10;
> `src/network/mod.rs` (current gossipsub layer); `src/network/sync_rr.rs`
> (directed-pull layer). All line references are to the tree as of 2026-08-11.

---

## 1. Inputs and constraints

From the migration spec:

| Quantity | Value | Source |
|---|---|---|
| Slot duration | 30 s | §5.1 `SLOT_DURATION_SECS` |
| Slots per epoch | 32 (16 min/epoch) | §5.1 |
| Per-slot attesters | 8 (`SLOT_SUBCOMMITTEE_SIZE`) | §5.1, §6.5.2 |
| Epoch-boundary voters | 128 (`COMMITTEE_SIZE`), once per epoch | §5.1, §6.5 |
| Hybrid signature | ≈ 4,589 B (ML-DSA-65 ‖ Falcon-1024) | §6.2 |
| Avg attestation bytes per block | ≈ 53.8 KB | §6.5 (adopted row) |
| Epoch-boundary peak | 128 × 4.6 KB ≈ **588 KB** arriving in ~one slot | §6.5, gate G10 |
| No cryptographic aggregation | sigs are not aggregatable; batching buys nothing in-circuit (cost exactly linear in N, §6.5.1) | §6.5.1 |
| Target validator count at transition | ≥ 200 (G4); fleet peer cap 50 (`max_peers`, `mod.rs:482`) | §11, `mod.rs:454` |

Derived wire figures used throughout (one attestation = `AttestationData`
≈ 124 B + hybrid sig 4,589 B + envelope ≈ **4.8 KB on the wire**):

| Flow | Rate | Payload | Egress per node (mesh degree D ≈ 6) |
|---|---|---|---|
| Slot subcommittee, steady state | 8 msgs / 30 s | 38.4 KB/slot ≈ 1.3 KB/s | ≈ 7.7 KB/s — trivial |
| Epoch boundary, un-mitigated | 128 msgs in ≲ 2 s | ≈ 614 KB | ≈ 3.7 MB in a few seconds (≈ 30 Mbps spike) |
| Epoch boundary, with §5.2 stagger | 128 msgs over 20 s | ≈ 614 KB | ≈ 185 KB/s ≈ 1.5 Mbps — comfortable |
| Boundary block (proposer includes quorum) | 1 msg | ≈ 588 KB body | one gossipsub frame, well under the 4 MiB cap (`mod.rs:640`, `MAX_WIRE_BYTES` `mod.rs:198`) |

Native verification cost is not a bottleneck: ML-DSA-65 + Falcon-1024 verify is
sub-millisecond per attestation on the fleet hardware (the §6.5.1 cycle counts
are *in-circuit* riscv32 figures, ~1000× the native cost). 128 verifications at
the boundary is tens of milliseconds of CPU. The risk scenario is **transport
and scoring behavior**, not CPU — hence this document.

---

## 2. Prior incidents this design is written against

This network has already been taken down by its own gossip layer. Every design
decision below traces to one of these, and the fixes-in-place are load-bearing:

| Incident | Root cause | Fix in tree | Consequence for this design |
|---|---|---|---|
| Mesh collapse #1 (2026-08-07) | `add_explicit_peer()` on every connection — explicit peers are excluded from grafting (libp2p 0.49.5 `behaviour.rs:2224`) and PRUNEd on GRAFT (`:1395`) | Comment block + removal at `mod.rs:1180–1196`; mDNS arm `mod.rs:1392–1395` | Attestation topics MUST rely on normal mesh maintenance; no peer pinning, no per-subcommittee "direct peers" |
| Mesh collapse #2 (2026-08-07) | `TopicScoreParams { ..Default::default() }` inherited P3/P3b (`mesh_message_deliveries_weight −1.0`, threshold 20, activation 5 s); at ~1 block/26 s every meshed peer took ≈ −400 and was graylisted | P3/P3b explicitly zeroed on all three topics, `mod.rs:677–727` | New attestation topics MUST define their own `TopicScoreParams` with P3/P3b explicitly zeroed — see §7, where this is re-derived for the attestation rates |
| yamux connection kill | rr cap 2048 (`sync_rr.rs:220`) vs yamux-0.13 default 512 streams; over the cap yamux **terminates the connection** | `MAX_YAMUX_STREAMS = 4096` + builder, `mod.rs:554–564` | Attestations ride gossipsub (one long-lived substream per peer/direction), so they add ~zero stream pressure; keep them OFF request-response — see §9.1 |
| Backfill flood (2026-08-09) | one stale external node dumped 1,270 old blocks in 5 min and stalled network-wide production | producer posture (listen 127.0.0.1) — operational, not structural | Attestations need a structural equivalent: slot-window acceptance + per-peer rate limits + validate-before-relay, so a stale/hostile node's dump is dropped at the edge — see §8 |
| Duplicate-suppression of *requests* | identical retries hash to the same MessageId and are dropped locally (`mod.rs:98–136`) | nonces on GetBlock/GetHeaders/BlockNotFound | Attestations are **data, not requests**: content-hash dedup is *correct* for them and must NOT be defeated with nonces — see §6 |
| Silent ingest drops | bounded (1000) mpsc + `try_send` dropped frames in silence | drop counter + WARN, `mod.rs:45–71` | Boundary bursts share this channel with block ingest; see §9.2 |

---

## 3. Topic layout

### 3.1 Decision: two new global topics

```
bloch/attest/slot/1     — per-slot subcommittee attestations (8 per slot)
bloch/attest/epoch/1    — epoch-boundary committee attestations (128 per epoch)
```

alongside the existing `bloch/blocks/1`, `bloch/txs/1`, `bloch/sync/1`
(`mod.rs:33–35`). Both are global: every node subscribes to both at startup,
exactly like the existing three (`mod.rs:826–833`), and stays subscribed
forever. The 30 s-heartbeat idempotent re-subscribe (`mod.rs:1566–1574`) covers
them too.

Why two topics and not one:

- The two flows have **opposite traffic shapes** — a smooth 8/slot trickle vs
  a 128-message burst every 32 slots. Separate topics give each its own
  `TopicScoreParams` (rates and decay tuned per shape, §7) and keep a
  boundary burst from competing with the very next slot's fork-choice votes
  inside one topic's send queue.
- Failure isolation and diagnosis: "epoch topic degraded, slot topic healthy"
  is a meaningful line in a log. The existing code's hardest lessons all came
  from ambiguity ("publish sync: Duplicate" hiding five message kinds,
  `mod.rs:1528–1544`).

### 3.2 Rejected: one topic per subcommittee

Ethereum shards attestations across 64 subnets because it has ~32,000
attestations per slot and no node can carry them all. Bloch has **8 per slot**.
Per-subcommittee topics here would mean:

- 32 rotating topics with subscription churn every epoch. Subscriptions
  propagate asynchronously; the current code already fights the
  publish-vs-Subscribe race on *static* topics (on-connect announce racing the
  peer's Subscribe, fixed by re-announcing in the `Subscribed` handler,
  `mod.rs:1301–1343`). Rotating subscriptions would re-open that race 32×/epoch.
- Each topic would carry ~1 message per epoch per subcommittee — an even
  *lower*-rate topic than the block topic whose low rate already interacted
  catastrophically with default scoring. Mesh health metrics (grafting,
  first-deliveries score) are per-topic; fragmenting an 8-msg/slot stream into
  32 near-silent topics destroys every signal gossipsub uses to keep a mesh.
- Every node needs every attestation anyway: LMD-GHOST weight (§6.5.2) is
  computed locally by all full nodes, and the proposer needs the whole quorum
  for inclusion. There is no audience partition to exploit.

One topic per subcommittee is over-engineering borrowed from a chain three
orders of magnitude larger, and on this network it points directly at the two
failure modes we have already paid for. Rejected.

### 3.3 Rejected: reusing `bloch/sync/1` or new `NetworkMessage` variants on existing topics

New variants appended to `NetworkMessage` (`mod.rs:81–152`) would not corrupt
old nodes (bincode decodes existing variants unchanged; unknown variants fall
into the log-only `IgnoreMalformed` path, `mod.rs:409`, `mod.rs:999–1002`) —
but old binaries would still *receive and relay-attempt* multi-KB frames they
cannot use, on topics whose scoring was not sized for them. Separate topics
mean pre-PoS binaries never subscribe and never see a byte of attestation
traffic. During the long hybrid phase (spec §10 Phase 5) the fleet is mixed by
design; this is the clean seam.

---

## 4. Wire format and bounds

New envelope, decoded per-topic (NOT part of `NetworkMessage` — see §3.3):

```text
AttestationMessage {
    version:          u32          // starts at 1
    data: AttestationData {
        slot:             u64      // 8
        head_root:        [u8;32]  // LMD-GHOST vote
        source_epoch:     u64      // justification source (epoch topic)
        source_root:      [u8;32]
        target_epoch:     u64      // justification target (epoch topic)
        target_root:      [u8;32]
    }
    validator_index:  u32          // index into the active set — NO pubkey on
                                   // the wire; the key is read from the
                                   // validator registry committed in state_root
                                   // (§5.5 of the migration spec)
    signature:        HybridSig    // ≈ 4,589 B over
                                   // SHA3-256(DS_ATTEST ‖ ssz(data)) — §6.1 tag
}
```

Signing root uses the `BLCH4:ATTEST` domain tag (§6.1). The slot topic and the
epoch topic carry the same structure; on the slot topic `source/target` MUST
equal the attester's current justified/target view and is checked like any
other field.

Bounds, following the `decode_wire_message` discipline (`mod.rs:175–341` —
"the ONLY correct way to decode wire bytes from a peer"):

| Constant | Value | Rationale |
|---|---|---|
| `MAX_ATTESTATION_WIRE_BYTES` | 8 KB | one attestation is ~4.8 KB; 8 KB is generous headroom, and 500× tighter than the topic-inherited 4 MiB frame cap |
| `MAX_BUNDLE_ATTESTATIONS` | 16 | §5.3; bundle frame ≤ 128 KB |
| `validator_index` | < active-set size read from finalized state | anything else is a protocol violation |

Frames violating these get the existing `WIRE_VIOLATION_PENALTY` treatment
(−100 app score per offense, floor −1000, graylist at 4 offenses —
`mod.rs:225–230`, applied at `mod.rs:986–998` via `WirePenaltyTracker`).
Note the honesty caveat at `mod.rs:991–993` applies here too: if
`with_peer_score` failed at startup (`mod.rs:749–751` warns and continues),
app-score penalties are inert. For PoS that warn should become a **fatal**
startup error — scoring is now a consensus-liveness dependency, not a nicety.

**Message ID.** Reuse the deterministic SHA-256/16 content-hash `msg_id_fn`
(`mod.rs:631–634`, audit M-10). `AttestationMessage` is canonical-serialized
and contains no timestamp or nonce, so a given attestation has exactly one
MessageId network-wide. That is intentional — see §6.

**Layer honesty.** Gossipsub frames are signed with the node's ed25519 libp2p
identity (`MessageAuthenticity::Signed`, `mod.rs:743–746`) — that is transport
anti-spoofing only. Attestation *authenticity* is the embedded hybrid
signature; the PQ boundary is the transport's Kyber handshake
(`transport/upgrade`, `mod.rs:31`) plus the lattice signature inside the
payload. No consensus meaning may ever be attached to the ed25519 frame
signature.

---

## 5. Publish policy

### 5.1 Who publishes

Each validator publishes its **own** attestation, once, on the appropriate
topic, as a single message. There is no relay-side re-packing: gossipsub
relays the original frames, and any intermediary rewrite would break
content-hash dedup and turn every hop into a new message.

### 5.2 Deterministic stagger — the burst flattener

The epoch-boundary cliff (128 × 4.8 KB in the first seconds of slot 0) is a
publisher-side artifact and is fixed at the publisher:

```
delay_ms = SHAKE-256(DS_SORTIT ‖ epoch ‖ validator_index) mod 20_000
```

Each committee member publishes its boundary attestation `delay_ms` into the
boundary slot (uniform over the first 20 s of the 30 s slot). Effects:

- Per-node forwarding load drops from a ~30 Mbps spike to ≈ 1.5 Mbps sustained
  for 20 s (§1 table) — inside any realistic fleet link, and small against the
  4 MiB single-frame ceiling already tolerated for blocks.
- The proposer of boundary-slot+1 still has ≥ 10 s of margin to collect the
  quorum before building.
- Deterministic (hash of public values) so it cannot be gamed for ordering
  advantage, and honest validators do not clump.

Slot-topic attestations need no stagger (8 messages/slot); attesters publish
after observing the slot's block or at the 1/3-slot (10 s) mark, whichever is
earlier — same rule Ethereum uses, scaled to 30 s.

**Inclusion window.** Consensus-side requirement (owned by DEV-1, stated here
because propagation depends on it): boundary attestations MUST be includable
in any of the first 8 slots of the following epoch, and slot attestations in
any of the next 2 slots. Propagation then has a multi-slot budget and a lost
frame degrades participation by one vote instead of stalling finality. Gate
G10's p99 < 5 s target remains the health test; the window is the safety
margin over it.

### 5.3 Bundles — the only "aggregation" there is

True aggregation does not exist for this suite, and §6.5.1 measured batching
as worthless in-circuit. The only packing worth having is transport-level: a
node operating k validator keys (realistic during hybrid: Postern fleet nodes,
staking services) MAY publish one `AttestationBundle` — up to
`MAX_BUNDLE_ATTESTATIONS = 16` attestations sharing identical
`AttestationData`, canonically sorted by `validator_index` — instead of k
frames. This saves k−1 message headers and k−1 mesh-forwarding decisions,
nothing more; it is an optimization, not a protocol layer. Receivers unpack
and dedup per-attestation (§6), so a bundle and its singletons are equivalent.
Bundles obey the stagger of the *lowest* included `validator_index`.

---

## 6. Validation pipeline and deduplication

### 6.1 Explicit validation mode — the structural change

The current layer processes gossip after gossipsub has already relayed it.
Attestation topics MUST instead run gossipsub's explicit validation
(`validate_messages()` on the config; then
`report_message_validation_result(msg_id, propagation_source, acceptance)`),
so nothing is relayed before it is checked. This gives us the missing verb the
score system needs: the difference between *Reject* (penalize) and *Ignore*
(drop silently), which is exactly the graylist-reintroduction control in §7.3.

Pipeline, cheapest test first — signature verification is last because it is
the only expensive step and everything before it is nanoseconds-to-micros:

```
1. size / decode / bounds        → violation: Reject  (+ wire penalty, mod.rs:225)
2. slot window (see §8.1)        → outside:   Ignore  (stale node ≠ attacker)
3. dedup (seen-cache, §6.2)      → seen:      Ignore
4. duty check: is validator_index in this slot's subcommittee / this epoch's
   committee, per sortition on the finalized parent state (§5.5 hard rule:
   committed state only, never local mutable state) 
                                 → not a member: Reject (cannot be honest skew)
5. head_root / target known?     → unknown block: HOLD in pending pool (§6.3),
                                                  Ignore for propagation
6. hybrid signature verify (both halves, AND)   
                                 → invalid:   Reject
                                 → valid:     Accept  (relay + forward to consensus)
```

### 6.2 Dedup policy

Three layers, each bounded:

1. **Gossipsub duplicate cache** — MessageId is a content hash, cache time
   30 s (`duplicate_cache_time`, `mod.rs:653`). One slot of exact-duplicate
   suppression at the transport. The 30 s value was chosen for the PeerTip
   interplay (comment at `mod.rs:641–653`) and stays; do not raise it
   globally.
2. **Application seen-cache** — key `(duty, validator_index,
   SHA3-256(AttestationData))` where duty = (epoch) on the epoch topic and
   (slot) on the slot topic. First occurrence: process. Same key, same data
   hash, again (e.g. after the 30 s transport cache expired): **Ignore** — do
   not relay, do not penalize. Retention 2 epochs; bound = 2 × (32×8 + 128)
   = 768 duty slots ≈ trivially small. This is what makes late re-publishes
   harmless without nonce games.
3. **Equivocation capture** — same key, *different* data hash: this is a
   slashable double vote (§7.4 of the migration spec). Accept and relay **up
   to 2 distinct attestations** per key (both are needed as slashing
   evidence), hand them to the slashing pool, and Ignore any third-plus.
   The cap keeps a malicious validator from using its own equivocations as an
   amplification primitive: it can at most double its own duty's traffic once.

The lesson encoded at `mod.rs:104–107` — "on the sync topic, deduplication is
wrong… a request is not gossip" — cuts the other way here and the design
leans into it: an attestation is pure gossip *data*, two identical copies are
one fact, and content-hash dedup is the correct and load-bearing behavior. No
nonces, no timestamps, anywhere in `AttestationMessage`.

### 6.3 Pending pool (unknown head)

An attestation whose `head_root` we have not yet imported is the ordinary
propagation race (attestation beats block by milliseconds) — **never** a
protocol violation. Hold it in a bounded pending pool keyed by the missing
root (mirror of the block orphan pool; capacity 256 attestations ≈ 1.2 MB,
FIFO eviction, entries expire with the §8.1 window), re-run the pipeline when
the block arrives, and count nothing against the sender. Misclassifying this
case as invalid would graylist honest peers during every boundary — this is
the single most important line in §7.3.

---

## 7. Peer scoring — will the current parameters survive?

### 7.1 The direct answers

**Q1: do the current score parameters survive a per-slot attestation load?**

Yes — with one hard condition. The *global* `PeerScoreParams`
(`app_specific_weight 1.0`, colocation handling incl. `--behind-proxy`,
`decay_interval 60 s`, `decay_to_zero 0.01` — `mod.rs:658–673`) and the
thresholds (−100 gossip / −200 publish / −400 graylist, `mod.rs:735–741`) are
rate-independent and carry over unchanged. The existing three topics never see
attestation traffic (§3), so their params are untouched by construction. The
hard condition: **both attestation topics must ship their own
`TopicScoreParams` with P3/P3b explicitly zeroed**, exactly like
`mod.rs:695–696`. `TopicScoreParams::default()` on the attestation topics
would be *worse* than the incident the block topic survived:

- **Epoch topic with defaults = instant, guaranteed graylist.** The topic is
  silent for 31 of every 32 slots. P3 activates 5 s after graft with
  threshold 20; a meshed peer has delivered 0, takes −1.0 × (20−0)² = −400 ×
  topic_weight immediately, and is pruned — the mesh can never hold anyone,
  every boundary. This is the 26-s-block failure raised to the 16-minute
  scale.
- **Slot topic with defaults = marginal on paper, failing in practice.** The
  aggregate rate (16 msgs/min against threshold 20, decay 0.5/`decay_interval`
  = steady-state ≈ 32) looks survivable — but P3 counts deliveries **per mesh
  peer**, and only duplicates arriving within the milliseconds-scale
  mesh-delivery window after first delivery are credited. A mesh peer that
  loses most first-delivery races is credited a fraction of 16/min, sits
  under the threshold, and bleeds score; any 90-s quiet patch (empty
  subcommittee overlap with a missed slot, our own restart) pushes everyone
  toward the penalty. Same shape as the original incident, slower burn.

P3/P3b are built for topics doing hundreds of messages per second. Nothing on
this chain qualifies, including the new topics. Off, explicitly, both.

**Q2: does an 8-per-slot subcommittee change the traffic pattern enough to
reintroduce the graylist problem?**

Not through rate — through *misclassification*, if we let it. Rate-wise the
slot topic is the healthiest topic this network will have: 8 messages per
30 s is ~8× the block topic's message rate, giving mesh peers a steady
first-message-deliveries income (P1, positive) that the block topic never had;
with P3/P3b off there is **no negative term driven by message rate at all**.
The genuine reintroduction vector is the validation pipeline: at every
boundary, attestations race blocks, and an implementation that scores
"unknown head_root" or "already seen" as an invalid delivery
(`invalid_message_deliveries_weight` is −100 on the proposed params, and 4 ×
−100 = graylist) would graylist honest peers on ordinary propagation timing —
recreating the old symptom ("mesh can't hold anyone") from a new cause. Hence
the Reject/Ignore/Hold split in §6.1 and the pending pool in §6.3: **only
provable protocol violations (bounds, non-membership, bad signature) ever
touch the invalid counter**. With that split enforced, an 8-per-slot pattern
strengthens mesh scoring rather than threatening it.

### 7.2 Proposed `TopicScoreParams`

Following the house pattern (`mod.rs:687–727`), every field that matters
stated explicitly:

```rust
// bloch/attest/slot/1 — steady 8 msgs / 30 s
let slot_attest_params = TopicScoreParams {
    topic_weight: 0.4,                        // below blocks (0.5), above txs (0.3)
    time_in_mesh_weight: 0.1,
    time_in_mesh_quantum: Duration::from_secs(1),
    time_in_mesh_cap: 100.0,
    first_message_deliveries_weight: 0.5,     // higher rate than blocks → lower unit
    first_message_deliveries_decay: 0.97,     //   value, higher cap
    first_message_deliveries_cap: 200.0,
    mesh_message_deliveries_weight: 0.0,      // P3 off — §7.1, mod.rs:677–686
    mesh_failure_penalty_weight:    0.0,      // P3b off — same reason
    invalid_message_deliveries_weight: -100.0, // Reject-class only (§6.1)
    invalid_message_deliveries_decay: 0.5,
    ..Default::default()
};

// bloch/attest/epoch/1 — 128-msg burst / 16 min
let epoch_attest_params = TopicScoreParams {
    topic_weight: 0.4,
    time_in_mesh_weight: 0.1,
    time_in_mesh_quantum: Duration::from_secs(1),
    time_in_mesh_cap: 100.0,
    first_message_deliveries_weight: 0.5,
    first_message_deliveries_decay: 0.9,      // faster decay: bursty income should
    first_message_deliveries_cap: 128.0,      //   not bank a whole epoch of credit
    mesh_message_deliveries_weight: 0.0,      // P3 off — with a 16-min silent period
    mesh_failure_penalty_weight:    0.0,      //   defaults are instant graylist, §7.1
    invalid_message_deliveries_weight: -100.0,
    invalid_message_deliveries_decay: 0.5,
    ..Default::default()
};
```

The `..Default::default()` spread remains for the genuinely inert fields, but
— lesson of 2026-08-07 — a devnet assertion (A3) MUST verify at startup that
`mesh_message_deliveries_weight == 0.0` and `mesh_failure_penalty_weight ==
0.0` on every registered topic, so a future libp2p default change or a
refactor cannot silently re-arm P3. Cheap, permanent insurance.

### 7.3 Score budget sanity check

A well-behaved mesh peer on the slot topic earns up to
(200 × 0.5 + 100 × 0.1) × 0.4 = 44 positive — real headroom against a stray
wire penalty (−100 app-weighted) without masking a true offender: four
deliberate violations still cross −400 regardless of topic income, because
app score is a separate weighted term (`mod.rs:661`). Invalid-delivery
penalties (−100 × 0.4 = −40 each on these topics) graylist a peer emitting
garbage signatures after ~10 frames even with maximal honest income — an
acceptable tolerance given signatures are verified before relay, so invalid
attestations never propagate past the first honest hop anyway.

---

## 8. Flood and backfill protection

The 2026-08-09 incident — one stale node, 1,270 old blocks, five minutes,
network-wide production halt — must be structurally impossible for
attestations, not merely operationally mitigated.

### 8.1 Slot-window acceptance

```
accept iff  current_slot − 64  ≤  att.slot  ≤  current_slot + 1
```

(64 slots = 2 epochs, matching the seen-cache retention and the participation
records committed in state, §5.5.) Outside the window → **Ignore**: no relay,
no processing, no penalty — an out-of-date node replaying its view is the
stale-backfill peer, honest but useless, and the correct response is silence,
not score war. The +1 tolerates one slot of clock skew; more than that fails
the duty check anyway.

This single rule caps a stale node's entire possible impact at "attestations
from the last 32 minutes," which the pipeline absorbs by construction.

### 8.2 Per-peer token bucket

Expected inbound from one honest mesh peer: ≤ 8 first-deliveries per slot on
the slot topic; ≤ 128 per boundary on the epoch topic (plus bundles). Bucket
per (peer, topic): capacity 256, refill 32/slot (slot topic) and capacity 512,
refill 128/boundary-slot (epoch topic) — 2–4× honest maxima. Overflow: drop
frames without validating (protects the signature-verify budget), and after
sustained overflow (> 1 bucket-capacity dropped within an epoch) apply one
`WIRE_VIOLATION_PENALTY` step. Bounded tracking via the existing
`WIRE_PENALTY_TRACK_CAP` pattern (`mod.rs:230`, `mod.rs:373–411`).

The check-order in §6.1 (window and dedup before signature) is itself the DoS
defense: the only path to making us do 4,589-B hybrid verifies is sending
in-window, non-duplicate, committee-member-indexed attestations — and each
invalid one costs the sender −40 topic score toward graylist while costing us
sub-millisecond work.

### 8.3 Producer/validator isolation

The 08-09 incident's deepest lesson is scheduling, not networking: inbound
flood work starved block production. The validator client's signing and
proposal loop MUST NOT share a task (or a lock) with gossip ingest. The swarm
loop already refuses to block on downstream (`try_send` + shed,
`mod.rs:55–71`); the same discipline applies one layer up — attestation
verification runs on its own worker pool, and proposal/attestation duties
preempt it. A validator that misses its slot because it was verifying a
flood has turned a bandwidth problem into a liveness problem.

---

## 9. Transport interactions

### 9.1 yamux and streams

Gossipsub multiplexes every topic over one long-lived substream per peer per
direction — attestation traffic adds ~zero stream pressure. The 4096 cap
(`MAX_YAMUX_STREAMS`, `mod.rs:554`; 2× the sync_rr cap of 2048,
`sync_rr.rs:220`) is untouched by this design, and G10's "no yamux
stream-limit failures" gate is expected to pass trivially *for attestations*.
The corollary is a rule: **attestations never ride request-response**. A
"fetch me the quorum" rr endpoint at the boundary would open O(committee)
streams exactly when sync_rr is busiest — recreating the stream-cap kill from
a new direction. Missing attestations are recovered by gossipsub's IHAVE/IWANT
lazy pull within the topic, and a proposer missing votes near its deadline
simply builds with what it has (the §5.2 inclusion window absorbs the rest).
The one legitimate rr addition is historical: checkpoint-sync fetch of
finalized epochs' quorums (or their §6.5.1 proof), which is IBD's existing
directed-pull pattern (`sync_rr.rs:50`, `mod.rs:1484–1507`) at IBD's existing
concurrency, not a new hot path.

### 9.2 Ingest channel

All gossip lands in one bounded (1000) mpsc via `forward_to_processor`
(`mod.rs:45–71`), where overflow sheds frames — visibly, but a shed GetBlock
reply is re-requested while a shed attestation is a **lost vote**. A boundary
delivers ~128 attestation frames amid block/tx traffic; that fits 1000 slots
comfortably *if the consumer drains promptly*, which is precisely what the
08-09 incident disproved under stress. Two requirements:

1. **Separate bounded channel (cap 512) for attestation frames**, drained by
   the verification pool (§8.3). Consensus votes must not queue behind a
   block-body backfill, and vice versa.
2. Per-topic shed counters (extending `ingest_drops_total`, `mod.rs:48`), so
   "boundary participation dipped" is correlatable to "attestation channel
   shed N" the way orphan stalls are correlatable today (`mod.rs:37–44`).

### 9.3 Boundary block on the blocks topic

The boundary-slot block carrying the 128-signature quorum is a ≈ 588 KB body —
the largest routine frame this network will gossip, but only ~14% of the
4 MiB frame cap (`mod.rs:198`, `mod.rs:640`) and the same order as block
bodies already carried today. The 30 s re-gossip suppression
(`REGOSSIP_SUPPRESS_TTL`, `mod.rs:961`) and receive-side duplicate recording
(`mod.rs:1042–1044`) apply unchanged. No change needed; G10 measures it.

---

## 10. Implementation checklist (DEV-3, with A11 review)

1. Topics `bloch/attest/slot/1` + `bloch/attest/epoch/1`; subscribe at startup
   next to `mod.rs:826–833`; include in the heartbeat re-subscribe loop
   (`mod.rs:1572`).
2. `AttestationMessage` (+ optional `AttestationBundle`) with
   `decode_attestation_wire` mirroring `decode_wire_message` bounds discipline;
   constants from §4.
3. Explicit validation mode on the two topics;
   `report_message_validation_result` wired to the §6.1 pipeline; the
   Reject/Ignore/Hold split is a review blocker (A4) — *no honest-race path
   may reach Reject*.
4. `TopicScoreParams` from §7.2; startup assertion that P3/P3b are 0.0 on all
   topics; `with_peer_score` failure (`mod.rs:749`) promoted from warn to
   fatal.
5. Publisher stagger (§5.2) in the validator client; inclusion-window
   constants agreed with DEV-1.
6. Seen-cache + equivocation capture (§6.2), pending pool (§6.3), slot window
   + token buckets (§8.1–8.2).
7. Dedicated attestation ingest channel + shed counters (§9.2).
8. A3 devnet scenario: 30-node mesh, epoch boundary at full committee, with
   (a) no stagger vs stagger, (b) one stale node replaying 2 old epochs of
   attestations, (c) one peer emitting invalid signatures — asserting mesh
   retention, zero honest graylists, p99 propagation < 5 s (G10).

## 11. Open questions

- **Boundary inclusion-window size** (8 slots proposed, §5.2) is a consensus
  constant → needs a KAT + devnet sweep like every other (§5.1 rule).
- **Bundle canonicalization** (§5.3): whether a bundle's MessageId should be
  defined over the sorted set so that identical bundles from one operator
  dedup across restarts — proposed yes, needs a vector from A1.
- **Hybrid-phase non-binding attestations** (Phase 5) ride the same topics at
  the same rates by design — confirm with A3 that mixed-fleet nodes running
  pre-PoS binaries show no regression from mere topic coexistence (§3.3
  argues none is possible; measure anyway).
