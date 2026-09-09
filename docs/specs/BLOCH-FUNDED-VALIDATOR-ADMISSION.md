# Funded validator admission

Status: implemented; `FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH` **armed at
epoch 2700** (founder decision 2026-09-09, together with the four other
ADR-041 lifecycle gates — `docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md`). Below 2700
nothing is active on the running network; from 2700 on, funded registration
is consensus-valid. Arming is not the announcement of public admission — see
the release boundaries below and the runbook's open items.

The legacy `Deposit` (0x02) and `Delegate` (0x04) create bonds without consuming
UTXOs. Their gate remains closed. New registration uses **0x0B**, a fresh wire
assignment, without interpreting any contested 0x07–0x0A format.

## Protocol

A `FundedDeposit` consumes 1–128 existing, strictly ordered, distinct UTXOs
owned by one funding key. It creates a validator record, an activation-queue
entry, and one change UTXO. Input values come from committed state. No RPC
parameter, proof-of-possession statement or genesis-offset allowance can
manufacture the bond.

Two separately domain-separated authorizations cover the entire unsigned
intent:

- **Funding:** the owner authorizes the UTXOs, stake, validator identity,
  withdrawal route, change/refund address and fee budget.
- **Possession:** the operator proves control of the validator key and accepts
  the same terms, including its RANDAO commitment and commission.

Both keys and both signatures require the suite-1 envelope
`b1 0c 01 00`: ML-DSA-65 **AND** Falcon-1024. Each signature must verify both
algorithms. Raw keys, the ML-DSA-only suite and ECDSA are not accepted by this
format. Funding and validator keys may be different; no shared private key or
custodial coordinator is needed.

Each intent includes SHA3-256 of the **canonical genesis manifest**, including
its clock, and an inclusive expiry epoch. Genesis construction retains that
immutable context separately from the historical state-root encoding. This
also distinguishes old BPOSMAN1 networks whose genesis block IDs coincide.
It does not change legacy transfer sighashes or repair their separate replay
protection gate.

The shared staking rules still impose a minimum of **25,000 BLCH** and a
per-validator maximum of `max(25,000 BLCH, 1% of active stake)`, measured by the
transition. Commission is bounded to 0–10,000 basis points. The registration
is for a new public key; it is not a top-up or delegation operation.

### Conservation and fees

Let `B` be the bond, `C` the signed minimum change, `Fmax` the base-fee budget,
`Factual` the base fee at inclusion, and `T` the priority fee:

```
sum(committed input values) = B + C + Fmax + T
created change             = C + Fmax - Factual
charged fees               = Factual + T
```

The transition refuses inclusion above the signed maximum base-fee rate.
The refund always goes to the signed change script. It never becomes a
validator reward. Existing block-level fee distribution/burning then applies.
Both PQ checks and the full reserved transaction size are charged; one funding
signature covers all of this authority's inputs.

The byte declaration is exactly the unsigned encoding plus two signature
length prefixes and two 4,593-byte maximum witnesses. It is deterministic
before either randomized Falcon signature is produced. The actual encoding
cannot exceed the reservation. This avoids a sign/resize/re-sign cycle and
limits over-declaration to this explicit reservation.

Every fallible check, including fee arithmetic, ownership, output collision,
registry-index allocation and both signatures, precedes state mutation. The
outer transition also rejects an invalid block atomically. Funded bonds are
never added to the legacy `unfunded_bonded` supply exception.

### Activation and identity

Registration queues the key; it does not immediately give it voting weight.
The existing queue orders by `(deposit epoch, public-key hash)`, waits at least
**eight epochs**, and admits at most **four validators per epoch**. The resolver
now sorts once and advances directly to eligibility/churn boundaries rather
than rescanning every historical epoch. Differential tests preserve the
previous schedule. Eight epochs are a delay, not a separate proof that the
deposit is finalized; a finality-aware activation policy requires its own
consensus decision.

A joining keystore uses the existing index field's sentinel `4294967295`
(`--index auto`). Each duty resolves its public key in the committed registry
on the relevant branch. Candidates never guess the next free index or need
to rewrite their keystore after another registration wins an ordering race.
Fixed-index keystores retain their existing key/index check.

RANDAO positioning uses the committed reveal count for the resolved identity.
Replay checks the corresponding advanced commitment, so a restart after prior
proposals does not compare the original chain head against an advanced one.
The slashing journal remains bound to the **public-key hash and genesis
digest**, independently of the assigned index. Doppelganger observation and
journal checks remain on the signing path.

## Operator workflow

Production key generation follows the repository's existing offline ceremony.
`keygen` remains a throwaway devnet tool; `keygen --index auto` is useful for
rehearsing a candidate outside the genesis set. Keep the validator's sealed
keystore, its RANDAO seed and the withdrawal authority's backups secure.
Withdrawals must name a script whose PQ spending key the intended recipient
actually controls; registration does not establish that control for them.

1. Query `getvalidatoradmission`. Below the flag day a build reports
   `active: false` and `activation_epoch: 2700` (an unarmed build would say
   `null`), plus its network domain, head epoch, stake bounds,
   queue limits and next base fee. These are quotes from the current head;
   consensus rechecks them at inclusion.
2. Gather spendable UTXOs with `listunspent` for the funding authority. Export
   the two suite-enveloped public keys as hex files and the operator's RANDAO
   commitment from the offline ceremony. No private material enters the draft.
3. Prepare and inspect the draft; sign each role on its own machine. The CLI
   refuses unknown/duplicate options and existing output files. Its input-value
   estimates are never authoritative for consensus.
4. After the protocol is activated, submit the completed file with the existing
   authenticated `sendrawtransaction` RPC. The offline CLI does not broadcast.
5. Query `getvalidatorbykey` with the SHA3-256 public-key hash. It returns the
   existing validator record schema, including assigned index and queued/active
   status. `VALIDATOR_NOT_FOUND` before inclusion is an ordinary pending state.
   Use `gettxstatus` to distinguish inclusion from justification/finalization.
6. Run the candidate with its auto-index keystore and the correct genesis
   manifest. It follows and verifies the chain while waiting for registration
   and activation. No restart is required when the key becomes eligible.

Example argument shapes (replace every placeholder with independently checked
values; the commands construct/sign files and do not move funds):

```sh
bloch-pos validator-deposit prepare \
  --genesis genesis.bin \
  --funding-pubkey funding.pub.hex --validator-pubkey validator.pub.hex \
  --randao <commitment-hex32> --withdrawal <withdrawal-script-hex32> \
  --change <change-script-hex32> --stake 2500000000000 \
  --input <txid-hex32>:<vout>:<value-sat> \
  --max-base-fee <millisat-per-gas> --tip <millisat-per-gas> \
  --expiry <inclusive-epoch> --commission <basis-points> --out draft.hex

bloch-pos validator-deposit inspect --tx draft.hex
bloch-pos validator-deposit sign --tx draft.hex --role funding \
  --dir funding-keystore --out funded.hex
bloch-pos validator-deposit inspect --tx funded.hex
bloch-pos validator-deposit sign --tx funded.hex --role validator \
  --dir validator-keystore --out ready.hex
```

Each signing invocation uses the existing sealed-keystore passphrase sourcing;
there is no passphrase argument. Inspect all inputs, the network domain,
validator hash, withdrawal script, commission and fee budget on each signing
machine. Rebuilding any intent field invalidates both signatures.

## Wire and hash contract

Integers are little-endian. Vectors have a u32 length. The field order is:

| Order | Field | Encoding |
|---|---|---|
| 1 | Tag | u8 = 0x0B |
| 2 | Network domain; expiry | 32 bytes; u64 |
| 3 | Funding public key | u32 length + 3,749 bytes |
| 4 | Funding inputs | u32 count; repeated (32-byte txid, u32 vout) |
| 5 | Validator public key | u32 length + 3,749 bytes |
| 6 | Stake; RANDAO; withdrawal; commission | u128; 32 bytes; 32 bytes; u128 |
| 7 | Minimum change; change/refund script | u64; 32 bytes |
| 8 | Maximum base-fee rate; tip; reserved bytes | u128; u128; u64 |
| 9 | Funding signature; possession signature | two u32-length byte vectors |

The intent root is `SHA3-256("BLOCH:VALIDATOR:DEPOSIT:V1" || fields 1–8)`.
Funding and possession roots are respectively
`SHA3-256("BLOCH:VALIDATOR:FUNDING:V1" || intent_root)` and
`SHA3-256("BLOCH:VALIDATOR:POSSESSION:V1" || intent_root)`.
Use these role-specific roots, not the legacy transfer signing helper.
The transaction ID is the existing `SHA3-256(DS_TXID || intent_root)` and is
independent of witnesses. The decoder bounds every allocation before copying.
Zero-length signatures permit offline drafts to round-trip; all admission and
consensus paths still require complete authorizations.

## Release boundaries and validation

A finite admission epoch changes block validity. Agree and publish it before
that epoch, distribute a reproducible release to all validating nodes, and
rehearse the same activation boundary. No runtime option enables the format.
Historical roots and pre-activation validity remain unchanged.

The admission flag day also refuses unauthenticated legacy `Exit` messages
for every validator. **The admission PR alone did not activate authenticated
exits, withdrawals, slashing evidence or RANDAO recommit**; those paths have
their own gates, and since 2026-09-09 all five are armed at the same epoch
2700 (`docs/specs/BLOCH-VALIDATOR-LIFECYCLE.md`), so admission cannot go live
without them. Admission must not be opened for public funds until the
lifecycle's release dependencies in the runbook are resolved — in
particular, no withdrawal can settle before epoch ≈4780. This is a concrete
limitation of the current code, not a promise of a complete staking lifecycle.

Coverage includes funding conservation/refunds, atomic failures, replay,
network/field substitution, both PQ algorithms in both roles, bounded parsing,
queue equivalence/churn, competing registry order, offline sealed signing and
an activated two-node engine rehearsal with proposal, attestation, replay and
persistent slashing-protection checks. The rehearsal copies the source,
changes only the new compile-time epoch to zero, runs the production paths,
and deletes the copy. It never changes the shipping source or creates a
mainnet activation switch:

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee -p bloch-pos-node
python3 scripts/rehearse-validator-admission.py
bash scripts/hardened-clippy.sh
```

The implementation has not received an independent cryptographic or consensus
audit. It makes no claim of a novel cryptographic primitive or formal proof.

### Shared hardening gate maintenance

The first full hardening run exposed inherited Ustav/Chameleon findings on
this branch's base: seven `expect` sites and unchecked accounting/gas
arithmetic above the existing baseline. The accompanying repair uses checked
registry lookups before mutation, checked output-count arithmetic and
saturating resource-cost calculations. Thresholds and lints are unchanged.
The native reference `ChameleonLedger::export_root` now returns a `Result`;
Rust callers must handle the resource-limit error. Export hashes, proofs,
wire encodings and valid-state accounting remain unchanged.
