# Wave 65 CR-10/CR-02: explicit pool ownership-proof policies

Base: `6e3328d`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

After the Ustav and disclosure migrations, the next non-consensus product
boundary using generic signature autodetection was the reference pool's
`mining.authorize` ownership proof. The request supplies the payout address,
public key and signature as distinct fields and binds the signature to a fresh
session challenge. Historical miners may still identify with raw legacy keys,
so changing the default to strict envelopes would break compatibility.

The compatible policy now tries explicit matching formats first:

1. strict enveloped compatibility verification;
2. explicit raw legacy hybrid verification;
3. the historical generic verifier only as a final fallback, preserving any
   mixed-format proof previously accepted by this reference implementation.

This ordering repairs the concrete CR-10 false refusal: a genuine raw
signature beginning with `B1 0C` succeeds through the explicit raw verifier
before generic autodetection can mistake its bytes for an envelope.

Operators can opt into `--canonical-auth-proof`. That policy requires explicit
envelopes and canonical Falcon encoding through
`verify_enveloped_canonical`. The default remains compatible. The startup log
states which policy is active.

## Genuine pool-domain fixture

A one-off optimized search over deterministic signing RNG seeds found a valid
pool authorization signature at counter 2,537. The search is not committed or
run in CI. The regression reconstructs the fixture through the real hybrid
backend using:

- hybrid key seed: 32 bytes of `0x65`;
- challenge: 32 bytes of `0x65`;
- message: `bloch-pool-authorize-v1 || challenge`;
- signing RNG seed:
  `9821a8fe2a4aa8343f55a5ae16b8370ab220f2eb4cf051df7ddf98a291635f67`.

The enveloped signature passes both policies. After stripping both suite
headers, the raw signature begins `B1 0C`, verifies through the explicit raw
API, fails generic autodetection, succeeds through the compatible pool policy
and fails the operator-selected canonical policy.

No consensus rule, share accounting, address derivation, default policy,
historical request or wire format changed. No release or deployment occurred.

## Validation

- `cargo test --lib stratum::tests::ownership_policy_accepts_genuine_magic_prefixed_raw_fixture_explicitly --offline`: 1/1 passed.
- `cargo test --offline`: all 49 pool library tests passed; binary and
  doctest targets contain no tests.

## Evidence boundary and residual risk

The fixture is genuine and reproducible for the pinned backend, but is not an
external vector. The final generic fallback intentionally remains in the
compatible policy to preserve the full former accepted set; therefore unusual
mixed encodings still rely on autodetection. Removing that fallback or making
canonical policy the default needs a miner compatibility inventory and an
announced product migration.

CR-10 and CR-02 remain `PARTIAL` for consensus/history-sensitive consumers,
which still require format metadata, activation/replay qualification, external
review and deployment evidence.
