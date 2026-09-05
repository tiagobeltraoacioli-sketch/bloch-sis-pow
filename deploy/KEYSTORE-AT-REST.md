# Keystore at rest — rollout note (audit I-H1)

`validator.key` is now **sealed**: Argon2id (64 MiB / t=3 / p=1) derives a key
from a passphrase, XChaCha20-Poly1305 seals the hybrid ML-DSA-65 ‖ Falcon-1024
secret key and the RANDAO seed, and the public header (index, public key, KDF
parameters, salt, nonce) is the AEAD's additional data. Before this, the file
was `BPOSKEY1`: those secrets in the clear behind nothing but mode `0600`.

Mode bits are not a confidentiality boundary. They do not survive a backup, a
snapshot, a volume image, a `tar` run as root, a stolen disk, or an operator
copying a data dir between hosts — and what is behind them is the whole
validator: the signing key *and* the RANDAO seed.

## READ THIS BEFORE DEPLOYING THE BINARY

**Every keystore on the live fleet today is `BPOSKEY1` (plaintext), and the new
binary refuses to load one unless told to.** `Keystore::load` returns
`PermissionDenied`, and the engine treats any non-`NotFound` keystore error as
fatal. A fleet-wide restart onto this binary with no other change is a
**fleet-wide halt**, not a degraded mode.

Pick one *before* the rollout, not during it:

- **Option A — carry the plaintext forward (no key handling, no downtime).**
  Add `Environment=BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1` to each `bloch-nNN` unit,
  or `--allow-plaintext-keystore` to its `ExecStart`. The node boots exactly as
  it does today. The finding is **not closed on that host** — the key is still
  plaintext on disk; the only thing that changed is that the plaintext is now a
  recorded decision instead of an unexamined default. Use this to decouple the
  binary rollout from the key handling, not as the end state.

- **Option B — re-seal (closes the finding).** Per host, with the node stopped:
  back the keystore up offline, re-seal it, restart with the passphrase wired
  into the unit. Sealing an existing key needs a re-seal tool this repo does
  **not** ship — see "Not covered" below.

Never do both halves at once on more than one validator: a host that cannot
open its key does not attest, and enough of them at once moves finality.

## Supplying the passphrase

There is no prompt — a `systemd` unit has no tty. In priority order:

1. `BLOCH_KEYSTORE_PASSPHRASE_FILE=<path>` — a `0600` file, or what
   `LoadCredential=` hands the unit. Preferred: keeps the secret out of
   `/proc/<pid>/environ` and out of the unit file.
2. `BLOCH_KEYSTORE_PASSPHRASE=<passphrase>`.
3. `--allow-plaintext-keystore` / `BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1` — the
   plaintext opt-in, and the *only* way to read or write a `BPOSKEY1` file.

The opt-in is permission to read plaintext, never permission to skip a
passphrase: a sealed keystore still refuses to open without one. And a
plaintext keystore is refused even when a passphrase *is* configured — that
operator asked for a sealed key and was handed a bare one, which is exactly the
mismatch worth stopping on.

## What is already sealed

`deploy/genesis4-key-ceremony.sh` now reads a passphrase at the tty, seals all
64 keystores under it, and verifies each file starts with `BPOSKEY2` before it
will emit `cohort.tsv`. **The passphrase is a separate carry-out from the
keystores**: it is not in `cohort.tsv`, not in `DIGESTS.txt`, and not written to
disk by the script. Lose it and the keystores are unopenable, by anyone.

Devnet harnesses (`devnet.sh`, `scripts/devnet-transporte-misto.sh`,
`scripts/transporte-postura-prova.sh`) export the plaintext opt-in on purpose:
throwaway keys, throwaway chain, a temp dir.

## Not covered by this change

- **No re-seal tool.** Sealing an existing plaintext keystore in place needs a
  command this repo does not have (`keygen` only seals keys it just generated).
  Until it exists, Option B has no supported procedure and Option A is the only
  one an operator can actually execute.
- **No migration on load.** A loader that re-wrote the file it just read would
  be writing into a directory that may be shared, replicated, or mid-backup.
  Re-sealing is an operator action on an operator's schedule.
- **Nothing protects the key in memory from a process-level attacker.** The
  secret, the derived key and the passphrase are `Zeroizing` and the RANDAO
  seed is wiped in `Drop`, which bounds the window in core dumps and freed
  pages. It is not a defence against reading a running node's address space.
