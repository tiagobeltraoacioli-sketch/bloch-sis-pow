# bloch-ffg — static FFG committee + committee-governed activation (foundation)

The **static finality committee** from the validators/BaaS study (**§4-bis**) and the
mechanism that makes it the **activation authority** for consensus upgrades — such as
the native eUTXO VM in `bloch-euvm` (**§5-quater, step 6**).

> **Status: FOUNDATION / reference. NOT wired into node consensus.**
> Standalone library with tests only. Signature verification is a host callback
> ([`SigVerifier`]) so the real ML-DSA-65‖Falcon-1024 verifier plugs in later.
> Unaudited. The empty `[workspace]` in `Cargo.toml` keeps it out of the node build.

## The model (locked decision, §4-bis)

- **Static committee.** A fixed set of **21 named seats** — a known consortium, **no
  rotation**. Seats are **non-transferable**: a seat's key changes only through a
  quorum-approved [`fill_vacancy`].
- **Quorum: 14-of-21.** A checkpoint or an activation is authorized when 14 distinct
  active seats sign it (post-quantum). A seat can never be double-counted; forged or
  inactive-seat signatures never count.
- **Replacement only on exit.** A member who resigns / is long-offline / is removed
  for fault opens a [`Vacancy`] (the seat goes inactive). It is filled from a
  pre-vetted candidate with a **14-of-remaining** supermajority. Slashing on
  removal-for-fault is out of scope for this foundation.
- **Vacancy cap.** If more than [`MAX_VACANCY`] (= 3) seats are vacant, **finality
  pauses** — no quorum is possible until seats are refilled. The base PoW keeps
  running regardless; the committee is an overlay, never the base's liveness.

## Committee-governed activation (the point of "ativação com o comitê FFG")

A consensus feature turns on **only when the committee authorizes it**:

```rust
let act = FeatureActivation { feature: "euvm".into(), activation_height: 1000 };
// nodes accept the feature iff current_height >= 1000 AND a 14-of-21 quorum
// signed activation_message(&act):
is_feature_active(&committee, &act, &seat_sigs, &verifier, current_height)
```

Without 14-of-21, the upgrade **cannot switch on** — the committee is the authority.
This is how the eUTXO VM (`bloch-euvm`) would be activated: coordinated height +
committee quorum, so activation is deliberate and fork-safe.

## What is implemented and tested (7 tests, all green)

Run: `cargo test`.

| Capability | Test |
|---|---|
| 21-seat construction, active count, finality availability | `committee_construction` |
| 14-of-21 finalizes a checkpoint; 13 does not | `quorum_14_of_21` |
| a seat cannot be double-counted | `a_seat_cannot_double_sign` |
| forged signatures and vacant seats do not count | `forged_and_inactive_sigs_do_not_count` |
| **committee-governed feature activation** (height + quorum, else inactive) | `committee_governed_feature_activation` |
| >3 vacancies pause finality | `vacancies_pause_finality` |
| replacement only via 14-of-remaining; seats non-transferable | `replacement_only_via_quorum` |

## API surface

- `Committee`, `Seat`, `SeatSig`, `SigVerifier`
- `count_signers`, `has_quorum` — the quorum core
- `FeatureActivation` + `activation_message` + `is_feature_active` — **activation**
- `Checkpoint` + `checkpoint_message` + `is_finalized` — **finality**
- `ExitReason`, `open_vacancy`, `replacement_message`, `fill_vacancy` — **replacement**

## Mapping to the study

- **§4-bis** — this crate is its implementation: static 21-seat committee, 14-of-21,
  non-transferable seats, replacement-only-on-exit, vacancy-pauses-finality.
- **§5-quater step 6** — `is_feature_active` is the committee-governed switch that
  turns the eUTXO VM on.
- **§5-ter / §5-quinquies** — the same committee is the bridge attestor and the
  shared finality for parallel merge-mined chains; `is_finalized` is that primitive.

## Honest boundaries & what's next

- **Not consensus-wired.** These are pure functions over an in-memory committee, not
  the node's real state or signature stack.
- Not yet modelled here: the on-chain committee registry + its own upgrade path,
  staking/slashing economics, the deterministic waitlist ordering, and the EVM-side
  keyset the bridge (§5-ter) additionally needs.
- **The live-chain integration (step 5) stays a separate, audited effort.** Nothing
  in this crate touches the mining chain.

## Files

- `src/lib.rs` — the whole committee model + activation/finality/replacement + 7 tests.
