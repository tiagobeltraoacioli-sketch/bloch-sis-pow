# Native AMM arithmetic reference

`ustav::amm` calculates pool state transitions; it does not hold funds, sign
transactions, verify LP ownership or modify any native ledger. BLCH is admitted
as an arithmetic asset identity, not imported into Ustav or wrapped. A calculated
BLCH/USDT quote does not establish an executable market or USDT backing.

Pool identity commits a versioned SHA-256 tag, authenticated network domain,
sorted asset IDs, immutable LP fee and creation seed. The fee stays in reserves;
there is no protocol fee recipient. Requests bind pool ID, expected revision and
an inclusive expiry height supplied by the authenticated host. A successful
transition increments revision, allowing the host to reject stale actions.
Recomputing a pure function does not consume an actual UTXO or prevent replay
unless the host atomically commits the returned state.

The private state tracks two u64 reserves and u64 LP supply. Initial shares are
floor(sqrt(amount0 * amount1)), with 1,000 permanently locked shares and a positive
user issuance required. Subsequent adds calculate the minimum proportional LP
issuance; each charged reserve amount rounds up, and unused offered amounts are
returned explicitly as `unused_maximum`. These unused amounts are not another
credit: only `user_debit` must move. Remove burns user shares and rounds both
reserve payouts down, enforces both minima and cannot redeem locked shares.

Exact-input swaps charge the specified input, retain the configured fee, round
output down and enforce minimum output, positive liquidity and nondecreasing
reserve product. All asset deltas are raw integer units in sorted asset order;
there is no decimal conversion, peg assumption or price oracle.

Products of two u64 values use u128. The swap's fee-scaled three-factor numerator
can require 142 bits. Swaps now evaluate that fraction using 64 integer
quotient/remainder steps without materializing the numerator. Each step
maintains the exact division identity; the denominator is below 2^79 and all
intermediate arithmetic is checked. This supports large representable swaps
without floating-point approximations or a wide-integer dependency.
This changes previously rejected large-input behavior in the experimental
library and must not be hot-patched into an activated consensus rule.
Independent arbitrary-precision vectors cover both directions, extreme fee
rates and the u64 boundary.
Addition overflow and dust transitions also fail without changing input state.

## Custody integration still required

Current Ustav outputs require valid PQ owner keys and signatures for every spend.
Do not encode pool IDs as fake PQ keys or exempt them in a signature verifier.
Production integration needs an explicit versioned pool/script lock, real
base-BLCH UTXO accounting and gateway-controlled USDT supply. A sealed combined
state must atomically debit authenticated user inputs, credit recipients, adjust
reserves and mint/burn authenticated LP positions after validating the action.
Only the transition validator may create LP claims; unrestricted issuer minting
would make pool redemption unsafe. The immutable minimum shares have no owner.

The host must bind each actual user's PQ signature to the full action and exact
funding/recipient outputs, authenticate existing pool and LP state, enforce one
continuation, prevent double spends and preserve token charter policies. The
returned `lp_burn` amount is arithmetic, not proof its caller owns those shares.
There is no wallet connection, consensus activation, deposit transaction or live
liquidity added by this module.

Tests cover initial/add/swap/remove conservation, canonical identity, domain and
fee separation, locked shares, stale revisions, expiry, dust, overflow and a
512-step deterministic rounding/invariant campaign. These are arithmetic tests,
not evidence of native custody integration or an independent security audit.

## Persistence and unsigned authorization commitments

`Snapshot` retains version, domain, creation seed, identity, sorted assets, fee,
reserves, total LP supply and revision. `state_root()` hashes every field in a
fixed order with big-endian integers and the `BLOCH-NATIVE-AMM-STATE-v1` tag.
`restore(snapshot, trusted_root)` checks canonical identity, version, root and
necessary reachable-state invariants: an empty pool has zero reserves/supply and
revision zero; funded pools have positive reserves, revision and at least the
locked minimum supply, with reserve product at least squared LP supply. Revision
one must match initial square-root issuance. These checks are not a proof of the
entire transaction history; the root must come from independently authenticated
combined state, never the snapshot submitter.

`Request::signing_hash(&pool, funding_commitment)` (also available on PoolState)
binds the retained network domain, current state root, pool identity, revision,
inclusive deadline, action variant and every amount/minimum, plus a nonzero host
funding commitment. The latter must bind actual resolved inputs, recipient outputs
and the user's LP position in the host's canonical format. Generating this hash
performs no signature verification and moves nothing. Its deadline is checked
at transition execution using authenticated height. LP ownership and atomic
custody remain separate responsibilities; snapshot restoration does not create
such authorization.
