# CR-01: spend authorization blocks funded-pool activation

Status: **confirmed, partially mitigated, activation blocked**. Internal remediation review, 2026-09-17.
This change rejects duplicate input positions within one spend, supplies
executable evidence of the remaining authorization flaw, and corrects the
documented security boundary. It does not change note commitments, nullifiers,
public/witness serialization, published guest artifacts/verifier keys or network
activation. Rebuilding the guest incorporates the stricter statement; old guest
artifacts must not be mistaken for that rebuild.

## What the current statement proves

`coherence_core::check_spend` checks the note opening, Merkle membership,
nullifier recomputation under a witness-supplied `nk`, output commitments and
balance. `SpendInput` contains no spending secret or authorization proof, and
there is no relation between `nk` and the committed recipient `note.pk_d`.
The SP1 guest invokes this exact function. Proving that this function accepts
therefore proves a weaker statement than recipient-authorized spending.

A sender knows the plaintext of a note it creates. Given its public membership
path, that sender can choose an arbitrary `nk`, recompute a nullifier, and move
the value to a note naming the sender as recipient. Changing only `nk` gives a
second distinct nullifier, so a correctly implemented global nullifier set does
not identify the two spends as the same note.

There is also a single-witness variant: include the same note and tree position
twice with two chosen `nk` values. Membership succeeds twice, nullifiers differ,
and the previous balance calculation counted the one funded note twice. A
1,000-unit leaf could support a 2,000-unit output. The current remediation now
rejects repeated tree positions before membership work; it deliberately allows
identical commitments at distinct positions because those may represent two
separately funded leaves. This does not fix the cross-transaction attack. This is not
just transaction malleability or missing wallet-side validation.

## Reproduce without an SP1 installation

```sh
cargo test -p coherence-core --test known_unsafe_v1_authorization --offline
```

Two tests deliberately assert the **known-unsafe acceptance** behavior:
plaintext-holder spending and two accepted nullifiers for the same note. Two
additional tests verify rejection of single-witness value duplication and
preservation of separately funded positions. Passing this suite does not mean
authorization has been repaired. The test also shows that the
ordinary `NullifierSet::insert` check accepts both distinct nullifiers.
These are native evaluations of the shared statement, not newly generated SP1
proofs or evidence of exploitation on a deployed chain.

## Why this review does not invent a replacement derivation

[C1 §2](../../docs/specs/COHERENCE-C1.md) requires nullifier-key derivation from
spending authority, but C1 §7 explicitly leaves exact `pk_d`/`nk` derivation
open. The note format and hash domains are frozen. Adding an arbitrary
`nk = H(spending_key)` calculation alone would still not authorize the note:
the circuit must bind that spending authority to the recipient already inside
the commitment. Choosing a hierarchy now would also choose viewing-key
privileges, diversifier semantics and wallet recovery behavior without a
reviewed specification.

## Required versioned upgrade before activation

1. Approve the recipient/spending/nullifier/viewing-key hierarchy and its exact
   domains, serialization and diversifier rules. A note plaintext or a viewing
   key must not grant spending authority. Specify network/pool separation.
2. Introduce explicit V2 note/address and witness/public-statement versions.
   Require proof of knowledge of the recipient's spending authority, bind it
   to the committed `pk_d`, and derive the unique nullifier authority inside
   the statement. An arbitrary prover-supplied `nk` cannot remain authoritative.
3. Bind the statement version to the transaction encoding, public proof inputs
   and accepted SP1 guest/verifier identity. Unknown versions and old V1 proofs
   must fail closed for a V2 pool; do not dispatch solely on witness contents.
4. Retain the duplicate-position check added in this remediation and require
   rebuilt guest/verifier artifacts to include it. This defense-in-depth check
   alone does not repair repeated spends across transactions.
5. Specify existing-note treatment. Do not silently reinterpret V1 commitments
   or replace their nullifiers. Establish whether any funded V1 pool actually
   exists, and require a separately reviewed migration or refuse activation.
6. Run independent cryptographic review and host/guest parity tests, including
   wrong spending key, viewing-key-only and sender-plaintext attempts;
   same-note/same-nullifier invariance; duplicate-input rejection; version
   confusion; and value conservation across successive spends and reorgs.

Do not enable P1 or accept funded shielded deposits on the current statement.
This document is a release-review blocker, not an assertion that a runtime
activation interlock or a production migration has been implemented.
