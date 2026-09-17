# Vault construction follow-up — 2026-09-17

## Explicit separate-deposit construction (BV-01, partial)

`construction::SeparatedDepositV1` is an experimental, opt-in construction for new outputs.
It requires distinct compressed deposit, delayed-spend and recovery public
keys, with a CSV delay of at least 144 blocks. Its deposit script uses the
separate deposit key; the trigger remains the existing branch-A/branch-B
script. Checked unvault construction rejects null outpoints, out-of-range
amounts, fees exceeding the deposit and dust outputs. These public parameters
are immutable after validation.

Persist the construction label `separated-deposit-v1`, the deposit public key
and all trigger parameters with the backup. This label is separate from the
V1/V2/V3 key-derivation selection. No existing derivation, funded address,
legacy script or service default changes. The shield API continues to expose
only its documented legacy construction; this new type is not exposed by HTTP.

The deposit secret must be independently generated offline, not recoverable
from a retained seed, and retained until all required signed transactions and
backup checks are complete. This library neither performs nor verifies that
ceremony. Distinct public keys do not prove independent generation or deletion.
A retained deposit key can bypass the trigger. A quantum attacker seeing its
public key and the revealed preimage may still forge a competing deposit spend;
key deletion is not a Bitcoin covenant and does not prevent that attack.

Regressions use real ECDSA/BIP-143 signatures with the existing narrow script
evaluator: the deposit accepts its separate key and rejects the retained hot
key, while branch A accepts the hot key and rejects the deposit key. These are
not Bitcoin Core/bitcoinconsensus or regtest qualification. Watchtower fee
packages, deletion ceremonies, recovery provenance and external validation
remain outstanding. Do not treat this as a deployable security product.

## Restore against the committed hash (BV-10, partial)

`preimage::restore_recovery_secret_v1` reuses the exact original HKDF domain and
requires the original key material, vault ID and independently retained recovery
hash. A mismatch returns an error; successful output has zeroizing ownership.
The caller must persist the derivation version and context. This does not
prevent reusing a vault ID/preimage or authenticate metadata from an untrusted
backup. Historical inputs are not silently changed during restoration.

Knowing a preimage does not prove possession of a PQ key: the preimage can be
copied, delegated or learned from a witness. Bitcoin checks the preimage hash
and a classical signature, not a PQ signature. Single-use lifecycle enforcement
and a complete authenticated recovery manifest remain separate work.

## Public data exposure (BV-03, still partial)

Even public role keys and unvault intent are sensitive under this design's
quantum-exposure model. Construct locally and do not send them to an untrusted
remote service. Loopback binding, request minimization and TLS do not erase
prior disclosures or establish the claimed quantum property. The optional new
construction does not remove those assumptions.
