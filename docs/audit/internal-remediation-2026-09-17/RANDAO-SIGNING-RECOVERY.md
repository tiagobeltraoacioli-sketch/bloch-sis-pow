# Durable RANDAO recommit signing recovery

The validator lifecycle now persists a recommit signing intent before producing
its signature. The configured recommit activation epoch is **2884**; this is not
an inactive protocol experiment. The signature format and consensus verification
rules remain unchanged. No running validator or production data was migrated by
this audit work.

The existing identity-bound slashing record is upgraded locally to `BPOSSLP3`
on its first guarded recommit, or when the offline recovery floor is initialized.
Ordinary proposal/attestation writes preserve an existing V1/V2 record until then.
V3 retains the validator public-key hash, genesis digest, all proposal/attestation
watermarks, an optional recovery epoch floor, and the last recommit epoch,
generation, commitment and signing root. Its 224-byte record has the existing
SHAKE-256/32 corruption checksum and uses the existing atomic write and fsync path.
The checksum detects damage; it does not authenticate a maliciously replaced file.

The signer refuses a different intent in an already signed epoch, a lower epoch
or generation, or a changed commitment for an already used generation. Repeating
the identical intent is allowed; retrying the same generation and commitment in
a later epoch is allowed. A persistence failure releases no signature. Recovery
floors also prohibit recommits through the epoch containing `min_slot - 1`, which
can conservatively defer recommitting until the next epoch. Proposal and
attestation floor behavior is unchanged.

## Migration and rollback requirements

1. Stop and fence the old signer before changing binaries or moving its data.
2. Back up the complete data directory and export the identity-bound slashing
   record using the matching node version. This export now includes V3 intent
   protection; it must travel with the key and chain data during recovery.
3. Start the upgraded binary against that same directory. Do not copy an older
   watermark file over an upgraded one. There is no retrospective reconstruction
   of recommit signatures issued before this protection existed.
4. Once V3 is written, older binaries reject its unknown record format. This is
   intentional fail-closed behavior. Do not delete the file or downgrade it to
   make an old binary start. Rollback requires a binary that understands and
   enforces V3, or an independently reviewed recovery procedure that preserves
   every signing floor and fences every former signer. A pre-upgrade backup alone
   is not a safe rollback after any new signature has been released.

Offline import validates the complete bounded record before mutation and merges
watermarks/floors monotonically. Importing an old V2 export cannot erase existing
V3 protection. Inconsistent recommit histories are refused. The record protects
one coordinated local signer; independent copies, restored old backups, unknown
past signatures, and an unfenced former host remain operational risks. A new
host-loss floor does not prove that another host has stopped signing.
