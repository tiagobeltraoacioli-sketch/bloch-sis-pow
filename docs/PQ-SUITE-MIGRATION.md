# PQ suite migration: lattice hybrid to SLH-DSA-128s ‖ Falcon-1024

Status: **prototype, consensus-gated INERT** (branch
`codex/bloch-p9d-migration-20261019`, based on `dd287b6c`). Both new
activation constants are `u64::MAX`; below them every new wire tag is refused
before any field is read, the new state component is empty (no state-root
leaf, no local-cache section), and the spend-freeze check is never evaluated,
so historical replay is byte-identical. Not audited.

Companion work: the suite itself (`SUITE_SLHDSA128S_FALCON1024 = 0x0003`,
sign/verify, the `HF3_SLH_SUITE_EPOCH` gate, `SLHDSA_FALCON_VERIFY_GAS`,
`SignatureVerifier::verify_spend_at_epoch`) is on
`codex/hf3-slhdsa-20261020`. This line (`codex/hf3-tags-20261020`) has its
own gate `HF3_PQ_MIGRATION_EPOCH`, which must be armed at or after
`HF3_SLH_SUITE_EPOCH`; it mirrors the suite id, the SLH verify gas
(`SLH_SUITE_VERIFY_GAS = 1,067,610`) and the maximum enveloped signature
length (`4 + 7856 + 1462`), and declares `verify_spend_at_epoch` with the
identical default body. At merge: keep one trait method, replace the gas
literal with `SLHDSA_FALCON_VERIFY_GAS`, and keep the suite id equal.

Code:
`crates/bloch-pos-committee/src/transition/pq_migration.rs` (rules),
`.../pq_migration/tests.rs` (19 tests, +1 with `local-state-cache`), `params.rs` (gates and parameters),
`state_root.rs` (`TAG_PQ_RESCUE_COMMIT = 0x24`), `transition/local_cache.rs`
(optional `PQ` section), node/indexer dispatch.

---

## 1. What the chain stores today

**Coins.** An output is `(value, script_hash)`. A native `script_hash` is
`SHA3-256(pubkey)`, where `pubkey` is the **enveloped** key
(`B1 0C ‖ suite_id ‖ body`). So an address already commits to *(suite, key)*
and never to a bare key. A carried (Genesis-3) output stores the first 20
bytes of the same hash with the rest zeroed (`transition::owns`). The public
key goes on-chain only when an output is spent (`TransferInput.pubkey`,
`WitnessKey.pubkey`).

**Validator withdrawal credentials.** These are stored in
`ValidatorRecord.withdrawal_credentials` (`interfaces.rs`). They are set once
at registration (`FundedDeposit.withdrawal_credentials: [u8; 32]`, wire
`0x0B`; legacy `Deposit` takes a `Vec<u8>`) and committed in the state root
(`state_root.rs`, validator leaf). Until now no transaction could change them.
`Withdraw` (wire `0x0D`, `transition/lifecycle.rs::withdrawal_plan`) pays the
bond to a single output whose `script_hash` is exactly those 32 bytes. The
credential is a script hash, so its owner is whoever holds the key that hashes
to it. That is not necessarily the validator's consensus key.

Consensus does not look inside a credential. A **new** funded deposit can
already name the script hash of an SLH-suite key. Rotation is only needed for
existing validators.

## 2. Threat model

- The live suite is an AND of two signatures (ML-DSA-65 **and** Falcon-1024).
  A practical break of ML-DSA alone does **not** let anyone forge. The
  emergency in this document is a break or credible weakening of **both**
  lattice families, for example a structural attack on module/NTRU lattices.
- Coins whose public key has never appeared on-chain are protected by SHA3
  preimage resistance: 256 bits for native outputs, 160 bits for carried
  ones. A lattice forger needs the public key first.
- **Exposed** keys are the dangerous class. A key is exposed when its public
  key is already public and value is still locked to it. Examples:
  - address reuse, or change sent back to the same address;
  - validator consensus keys;
  - funding keys of funded deposits and delegations;
  - L2 funding keys.

  Once lattices fall, these can be stolen by anyone, with no race needed.
- **Front-running.** When an owner broadcasts a spend, the key enters the
  mempool. A forger can then build a conflicting spend to its own address.
  It can pay a higher tip, or it can be the proposer. Plain "move your coins
  to SLH" after a break is therefore a race the owner loses.

## 3. Path A: orderly migration (before any break)

This path only needs `HF3_PQ_MIGRATION_EPOCH` (armed with or after
`HF3_SLH_SUITE_EPOCH`) and the
node's CR-03 mempool policy to admit suite `0x0003`. Today
`engine.rs::admissible` refuses any non-hybrid transfer key, and p9a/p9b must
relax that for `0x0003` only.

1. The wallet derives an SLH-suite key from the same seed (domain-separated).
   The address is `SHA3-256(envelope(0x0003, slh_pk ‖ falcon_pk))`.
2. Sweep with an ordinary `Transfer`/`TransferV2`. **One transaction per
   source script.** It must spend **all** outputs of that script (native and
   carried form of the same key) and must send **no change back** to a
   lattice address. The moment one input is signed, every other output of
   that key is exposed.
3. Priority order:
   1. exposed keys (reused addresses, funding keys);
   2. treasury, multisig members and L2 attestor payout scripts;
   3. cold storage, last, because it is unexposed and safe until spent.
4. Validators rotate their withdrawal credential (§5) and register new
   validators with an SLH credential.

The cost is the signature size. A hash-based signature is 7,856 B of
SLH-DSA-128s plus about 1.3 KB of Falcon, against about 4.6 KB for the hybrid.
Signing is slow (hundreds of ms), which suits cold and treasury keys.

## 4. Path B: emergency rescue (after a break)

Gate: `LATTICE_EMERGENCY_ACTIVATION_EPOCH`. It may only be armed at or after
the SLH gate, which is enforced by a `const` assertion. When it binds:

**Freeze.** `Transfer`/`TransferV2` inputs whose key is not the hash-based
suite are refused with `PqMigrationReject::LatticeSpendFrozen`. This covers
raw legacy keys, `0x0001`, `0x0002`, and unknown suites (fail-closed). After
the break a lattice signature proves nothing, and accepting it hands the coin
to the fastest forger.

**Commit (wire `0x19`, `RescueCommit`).** The commitment is
`C = SHA3(DS_RESCUE_SPEND ‖ len‖pubkey ‖ destination ‖ tip)`. Publishing it
reveals nothing about the key.
- It is unauthenticated and fee-free, because a lattice-only holder has
  nothing it can sign or pay with.
- It is priced in gas, each commit costing
  `BLOCK_GAS_LIMIT / RESCUE_COMMITS_PER_BLOCK` (1/16 of a block), and
  **capped per block** by consensus at `RESCUE_COMMITS_MAX_PER_BLOCK = 4`
  (F-9, 2026-10-20). Commits can therefore hold at most a quarter of a
  block's gas; without the cap 16 free commits filled a block and a flood
  excluded every paying transaction. An over-cap block is
  `BlockGasLimitExceeded` from the emergency gate on.
- Node policy (not consensus): all commits share one mempool source, so a
  flood holds at most 64 mempool entries and never evicts a paying
  transaction; the proposer ranks commits after every tipped and zero-tip
  transaction and orders them among themselves by
  `SHA3(domain ‖ parent block id ‖ commitment)`, which cannot be ground
  before the parent exists.
- The first writer keeps its epoch (`CommitmentExists`).
- Commits are pruned after `RESCUE_COMMIT_TTL_EPOCHS = 2,700` (about 30 days).
- The commits are committed under state tag `0x24`.

**Reveal (wire `0x1A`, `RescueReveal`).** A reveal is valid only if all of
the following hold:
- the cited commitment exists, is at least `RESCUE_COMMIT_MIN_DELAY_EPOCHS = 90`
  epochs old (about 1 day), lies in a **finalized** epoch, and has not
  expired;
- the key is lattice (SLH keys just transfer);
- the inputs are strictly ascending and are **exactly all** outputs of
  `SHA3(pk)` and its carried form (`IncompleteSweep` otherwise);
- `tx_bytes` equals the canonical length exactly;
- the output is a single one paying `sum − market fee` to `destination`;
- the hybrid signature is still checked. It is worthless if both families
  fell, but still binding if only one did.

The commitment binds the destination and the tip. `tx_bytes` and the input
set are forced, so a forger cannot redirect, re-price or partially spend an
honest reveal.

**Why the forger cannot front-run.** It learns the key only from the owner's
pending reveal, so its own commitment is necessarily younger. It cannot cite
that commitment for 90 epochs plus finality, and by then the owner's reveal
has swept everything (test
`a_forger_who_learns_the_key_from_the_mempool_cannot_front_run`). Requiring
finality stops a reorg from re-ordering the two commitments.

**Residual risks (stated, not solved):**

1. **Exposed keys are not rescuable.** The forger already knows the key and
   can commit as early as the owner. Consensus cannot tell the two apart. Such
   value must leave **before** the break (Path A), or through Option C below.
2. **Censorship for the full delay** (≥ 90 epochs) lets a forger's later
   commitment mature. Raising the delay trades rescue latency for safety.
3. **Commit spam.** Since F-9 a flood can no longer exclude other
   transactions (at most 4 commits, 1/4 of the gas, per block). It can still
   compete with honest rescuers for those 4 slots: a sustained flood delays
   rescues roughly in proportion to its share of the commit pool, and the
   per-block draw from the parent id only stops it from winning every slot
   by grinding. The remaining fix is "sponsored" commits paid from any SLH
   coin (a commit is only 32 bytes anyone can post); not built.
4. **Consensus itself.** Validator consensus keys are lattice. A lattice break
   lets an attacker forge votes and blocks, and the rescue's finality check
   assumes honest finality. Consensus keys need their own SLH/hash-based path
   (out of scope here; see p9b/p8a).
5. **Other lattice-authorised flows are not yet frozen by this prototype**:
   - `FundedDeposit`, `FundedDelegate`, `FundedUndelegate`,
     `FundedDelegationWithdraw`, `ValidatorCommissionUpdate`;
   - `ExitV2`, `RandaoRecommit`;
   - `L2Deposit`, `L2DataAvailability`, `L2WithdrawClaim`.

   Each needs the same freeze before the emergency gate may be armed.
6. **The emergency flag day is a release.** It must be pre-built and
   qualified so that only the constant changes on the day.

**Option C (designed, not implemented): pre-registered rescue key.** Before a
break, an owner registers `SHA3(DS ‖ slh_rescue_pk)` against a script using
one hybrid-signed transaction, while lattices are still sound. The rescue key
is derived from the wallet seed (`bloch:pq-rescue:v1`). After the break, that
script can be spent only by an SLH signature from the registered key, with no
delay and no race, **even if the lattice key is exposed**. It costs a state
map and one transaction per script, and it is the right tool for exposed keys
that cannot move yet (vesting, multisig in flight).

## 5. Withdrawal-credential rotation (wire `0x18`)

`WithdrawalCredentialRotation { network_domain, epoch, validator,
authorizing_pubkey, new_pubkey, authorizing_signature, new_key_signature }`,
gated by `HF3_PQ_MIGRATION_EPOCH` (hard fork 3; armed at or after the
suite's `HF3_SLH_SUITE_EPOCH`).

Both signatures are checked with `SignatureVerifier::verify_spend_at_epoch`
(the credential keys are spend-authority keys, not consensus keys): the new
key is always suite `0x0003`, which `verify_with_key` refuses at every epoch.
Gas: one hybrid verification (72,748) per lattice signature plus
`SLH_SUITE_VERIFY_GAS` (1,067,610) per `0x0003` signature, on top of the
flat and per-byte terms; no money fee (no input to draw it from).

The rules:
- The network matches and `epoch` equals the inclusion epoch (no replay at an
  unchosen time).
- The bond has not been paid out yet (`staked_sat > 0`). Exited and slashed
  validators may still rotate.
- `SHA3(authorizing_pubkey)` opens the **current** credential (native or
  carried form). Authority comes from the credential owner, **never the
  consensus key**. The consensus key is hot, public and lattice, so letting
  it redirect the bond would turn a lattice forgery into bond theft.
- `new_pubkey` must be the hash-based suite (`NotHashBased` otherwise), so
  rotation is one-way. The new credential is `SHA3(new_pubkey)` and must
  differ from the current one.
- Both keys sign the same root. The new-key signature proves the new
  credential is spendable, so a typo cannot brick a bond.
- After the emergency, a lattice `authorizing_pubkey` must also cite a
  matured, finalized `rescue_credential_commitment(validator, pk,
  new_credential)` posted with `0x19`, and the commitment is consumed. An SLH
  credential keeps rotating directly.

The charge is the staking-transaction capacity charge for two verifications.
No money moves.

## 6. What must be in place BEFORE a break

1. The SLH suite active in consensus and in mempool policy (p9a/p9b), with
   wallets able to derive, sign and sweep.
2. This branch, merged with the emergency gate fully qualified:
   - historical replay;
   - mixed fleet;
   - the freeze extended to every lattice-authorised flow (§4.5);
   - indexer and RPC support for `0x18`–`0x1A`.

   On the day, only the constant changes.
3. Exposed value gone from lattice keys: treasury, attestor payouts, funding
   keys, anything with a revealed key (Path A, or Option C if implemented).
4. Every validator's withdrawal credential rotated to SLH, and new
   registrations using SLH credentials.
5. A plan for consensus keys, which is the deepest dependency.
6. Wallet discipline: no address reuse (diversified addresses already exist),
   and no partial sweeps.
7. A public runbook for the commit-reveal rescue. The owner commits, waits
   for finality plus 90 epochs, then reveals.

## 7. Wire and state summary

| item | value |
|---|---|
| `0x18` | `WithdrawalCredentialRotation`, gate `HF3_PQ_MIGRATION_EPOCH` |
| `0x19` | `RescueCommit`, gate `LATTICE_EMERGENCY_ACTIVATION_EPOCH` |
| `0x1A` | `RescueReveal`, gate `LATTICE_EMERGENCY_ACTIVATION_EPOCH` |
| state tag `0x24` | rescue commitment → inclusion epoch (empty ⇒ no leaf) |
| cache | optional trailing section `BPOSST01:PQ:v1` (only when non-empty) |
| suite id | `0x0003` (must equal p9a) |

Tags `0x18`–`0x1A` and state tag `0x24` follow the HF3 allocation (2026-10-20, `src/wire_alloc.rs`) in
`docs/WIRE-NAMESPACE-REGISTRY.md` (first drafted as `0x17`–`0x19` / `0x22`,
which collided with KES `KesRegister` / `TAG_KES_ROOT`; `0x23` is the
light-client roster). They were swept free on every local head on 2026-10-19 and
are registered in `tests/wire_tag_registry.rs`.

## 8. Tests

Run with
`cargo +1.94.1 test -p bloch-pos-committee --lib pq_migration`, and add
`--features local-state-cache` for the cache round-trip. The tests cover:

- **Gates:** both gates ship inert (tripwire), and all three messages are
  refused and atomic below their gates.
- **Suite classifier:** fails closed, and the address commits to the suite.
- **Rotation:**
  - success, wire round-trip, root change and replay refusal;
  - carried credentials;
  - every reject path, atomic, including "consensus key is not the owner";
  - post-break rotation requires a matured commitment, while an SLH
    credential rotates directly.
- **Freeze:** inert below the gate; after it, lattice, legacy-raw and unknown
  suites are refused through the real dispatch, and one lattice owner freezes
  a whole `TransferV2`.
- **Rescue:**
  - the sweep pays `sum − fee` to the committed destination and consumes the
    commitment;
  - every reject path is atomic (incomplete sweep, foreign coin,
    redirected or re-priced reveal, size, ordering, signature, SLH key,
    immature, not final, expired);
  - the front-running scenario;
  - TTL pruning;
  - commits are root-neutral when empty, keep their first epoch and are
    fee-free.
