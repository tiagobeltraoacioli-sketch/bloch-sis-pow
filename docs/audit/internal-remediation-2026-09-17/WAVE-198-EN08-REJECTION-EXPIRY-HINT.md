# Wave 198 — EN-08 rejection-expiry scan hint

Date: 2026-09-19
Comparison base: `aa231776`

## Reproduced residual

Wave 194 bounded the node-local transition-refusal cache by both count and
canonical-key bytes. Its lazy expiry path nevertheless traversed every retained
entry and recomputed the byte total on every new refusal, even when the
earliest possible expiry was still up to 128 slots in the future. Filling the
4,096-entry cache with small keys in one slot therefore repeatedly scanned a
growing prefix before any entry could possibly expire.

This work was bounded, but avoidable. It is distinct from the still-required
earliest-expiry victim selection under actual count or byte pressure.

## Correction

`Engine::rejected_expiry_hint` records a conservative lower bound on the
earliest retained expiry. Insertion takes the minimum of the prior hint and the
new expiry. Lazy purge traverses the map only when `hint <= slot`, then
recomputes the exact retained-byte total and next expiry in that same pass.

Point removal, replacement and capacity eviction deliberately need not scan to
raise the hint. They may leave an obsolete earlier value, which can cause one
extra safe scan. They cannot leave a value later than a retained expiry, so the
optimization cannot postpone cleanup or keep an expired bar effective.

## Preserved invariants

- expiry remains `slot + REJECTION_TTL_SLOTS`, and equality remains expired;
- `is_rejected` still checks the stored expiry directly and does not trust the
  hint for a refusal decision;
- the 4,096-entry and 16 MiB canonical-key caps, exact byte accounting,
  replacement behavior and earliest-expiry pressure eviction are unchanged;
- hit counting, first-hit logging, RPC rejection count, sweep/proposal paths
  and bar-before-capacity ordering are unchanged;
- no public API, transaction encoding, wire, persistence, consensus,
  activation or peer-verdict behavior changed.

## Adversarial regression

`rejection_expiry_hint_skips_early_scans_and_never_hides_a_boundary` uses a
thread-local test-only scan counter and proves:

- 100 same-slot insertions plus one pre-boundary insertion perform zero expiry
  scans;
- equality at the first expiry performs one scan and removes every entry at
  that boundary while preserving the later survivor and exact byte total;
- replacing the key named by the hint leaves only a conservative early hint;
- reaching that stale hint performs one harmless scan, recomputes the actual
  next boundary, and does not remove either survivor; and
- the following real boundary is still scanned and removed exactly, with byte
  accounting equal to the retained canonical-key sum.

The Wave 194 exact-boundary/replacement test and existing count/TTL/bar tests
continue to exercise the unchanged cache policy. The replay benchmark gains
only the empty hint initializer.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos --offline rejection_expiry_hint_skips_early_scans_and_never_hides_a_boundary -- --nocapture`
  - outside the sandbox for the fixture's localhost socket: 1 passed;
    0 failed; 630 filtered out.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline rejection_ -- --nocapture`
  - outside the sandbox: 7 passed; 0 failed; 624 filtered out, including both
    rejection-cache regressions and the existing count cap.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline the_bar_ -- --nocapture`
  - outside the sandbox: 3 passed; 0 failed; 628 filtered out.
- `cargo check -p bloch-pos-node --bin bloch-pos --offline`
  - passed.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline`
  - outside the sandbox: 612 passed; 0 failed; 19 ignored; 60.62s.

## Residual boundary

When count or byte pressure requires a victim, selecting the earliest expiry
still performs a bounded O(n) scan. A stale conservative hint can trigger one
extra bounded expiry scan after its former entry was replaced or evicted; it
never suppresses a required scan. Canonical-key lookup bytes and map/allocator
overhead remain. The cache remains node-local and non-authoritative. `EN-08`
remains `PARTIAL`.
