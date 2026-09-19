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

**A `BPOSKEY1` plaintext keystore requires an explicit plaintext opt-in.**
Inspect each host before rollout; this historical note is not an inventory of
currently deployed keystore formats. The loader returns
`PermissionDenied` and the engine stops the boot. A fleet-wide restart onto
this binary with no other change is a **fleet-wide halt**, not a degraded
mode.

Pick one *before* the rollout, not during it:

- **Option A — carry the plaintext forward (no key handling, no downtime).**
  Add `Environment=BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1` to each `bloch-nNN` unit,
  or `--allow-plaintext-keystore` to its `ExecStart`. The node boots exactly as
  it does today. The finding is **not closed on that host** — the key is still
  plaintext on disk; the only thing that changed is that the plaintext is now a
  recorded decision instead of an unexamined default. Use this to decouple the
  binary rollout from the key handling, not as the end state.

- **Option B — re-seal (closes the finding).** Per host, with the node stopped:
  back the keystore up offline, run `bloch-pos keys seal --dir <data-dir>`
  as the owning service account, and restart with the passphrase wired into
  the unit. The command preserves the identity and refuses already-sealed
  keys; it does not rotate an existing sealed passphrase.

Never do both halves at once on more than one validator: a host that cannot
open its key does not attest, and enough of them at once moves finality.

## A halt, and never a silent observer

That halt is the *intended* failure and it matters which one you get. A node
with no `validator.key` at all runs as an **observer** — it follows the chain
and serves RPC, and proposes and attests nothing. That is a legitimate role, so
it is not an error. A node that has a keystore it cannot open must never land
in it: an observer looks healthy, and a validator that came back from a restart
as one is silently absent from finality until somebody counts attestations.

So the rule in `keys.rs` is narrow: **observer mode is selected by the absence
of the file, and by nothing else.** `Keystore::load_optional` returns
`Ok(None)` only when `validator.key` is not there. A keystore that exists but
is plaintext without the opt-in, sealed with no passphrase, sealed with the
wrong passphrase, unreadable, truncated, or whose `BLOCH_KEYSTORE_PASSPHRASE_FILE`
has not been provisioned is an `Err` that names the problem and stops the node.

The last of those is the one that bit: an unmounted `LoadCredential=` path used
to fail with `NotFound`, the engine matched on that error kind to decide
observer mode, and a fully provisioned validator restarted into
`observer mode: no keystore in /var/lib/bloch/nNN` with a good sealed key
sitting in that very directory. Two things now prevent it — the engine no
longer reads an error kind at all, and no configuration refusal is kinded
`NotFound`. Both are covered by tests in `keys.rs`
(`plaintext_without_the_flag_is_loud_and_with_the_flag_still_loads`,
`a_present_keystore_that_will_not_open_is_never_reported_as_absent`,
`only_an_absent_file_selects_observer_mode`,
`a_missing_passphrase_file_cannot_impersonate_a_missing_keystore`).

**What to check after a restart:** the absence of `observer mode:` on a host
that is supposed to validate. If you see it, the node did not find a keystore —
it did not fail to open one.

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
throwaway keys, throwaway chain, a temp dir. So does `tests/cold_start.rs`,
which is a *sync* test on a six-second start window — adding a memory-hard KDF
to every node boot made a known-flaky consensus test flakier (measured: 1 in 5
on `main`, 2 in 5 with sealed keystores) and proved nothing about sync. The
binary's sealed path is proved instead by `tests/keystore_at_rest.rs`, which
drives the real executable and needs no fleet and no clock.

## Not covered by this change

- **Explicit sealing is supported.** `bloch-pos keys inspect` and
  `bloch-pos keys seal` inspect and seal an existing plaintext keystore.
  Use the CLI help for the data-directory and passphrase-file arguments;
  the node must be stopped so the command can acquire the directory lock.
  Preserve a secure backup and verify the resulting public identity before
  restarting. `keygen` refuses to replace an existing validator identity.
  Newly sealed files require at least 12 passphrase characters; existing
  sealed files remain readable under their original passphrase.
- **No migration on load.** A loader that re-wrote the file it just read would
  be writing into a directory that may be shared, replicated, or mid-backup.
  Re-sealing is an operator action on an operator's schedule.
- **Nothing protects the key in memory from a process-level attacker.** The
  secret, the derived key and the passphrase are `Zeroizing` and the RANDAO
  seed is wiped in `Drop`, which bounds the window in core dumps and freed
  pages. It is not a defence against reading a running node's address space.


## Single-use pipe credentials for an offline ceremony (KS-14)

`keygen`, `keygen-public` and `run` also accept
`BLOCH_KEYSTORE_PASSPHRASE_FD=<descriptor-number>` on Unix. The environment
contains only this public descriptor number. The passphrase arrives as raw
UTF-8 bytes through an inherited pipe, with EOF as the terminator; no trailing
newline is removed. The consumer accepts at most 4096 bytes, requires completion
within three seconds, and closes the descriptor on success or read failure.
Standard input (descriptor 0) or a dedicated descriptor >= 3 is accepted;
stdout/stderr, regular files and terminals are refused. Do not combine this
source with `BLOCH_KEYSTORE_PASSPHRASE` or its `_FILE` alternative.

`deploy/genesis4-key-ceremony.sh` uses a fresh anonymous pipe for each child.
It clears inherited credential variables, disables shell tracing before reading
the passphrase, keeps it in an unexported Bash variable, and uses the builtin
`printf` so the secret never enters an external process argument list. The
script unsets the variable after the public exports and on exit; Bash cannot
promise that previous heap allocations, swap or crash dumps are zeroized.
This reduces environment/argv exposure, not the need for an isolated trusted
ceremony machine. Public-key export failure now stops the ceremony rather than
producing a success report containing placeholder identities.

This input path does not change `BPOSKEY1`/`BPOSKEY2`, KDF parameters, key
identities or the existing file/environment compatibility paths. `keys seal`
continues to use its explicit passphrase-file or terminal interface. No live
ceremony or validator migration is implied by these source changes.


### Default KDF resource limits (updated 2026-09-18)

Opening a sealed file applies two default limits before invoking Argon2: at
most 65,536 KiB (64 MiB) for one allocation, and at most 196,608 KiB-passes
of combined `memory_KiB × passes` work. Production is exactly 65,536 KiB × 3
passes. These are resource bounds, not a wall-clock recovery guarantee;
the existing absolute memory, iteration and lane caps also remain in force.

For an independently verified authentic historical file deliberately sealed
above either default limit, first run `bloch-pos keys inspect` without opening
the file and independently confirm the artifact. Recovery then requires both
`BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` and the exact public header tuple in
`BLOCH_KEYSTORE_EXPECT_KDF=<memory_kib,passes,lanes>`. Any missing, malformed
or different tuple is refused before Argon2. A matching tuple restores the
original finite decoding limits (1 GiB memory, 64 passes, 16 lanes); it does
not authorize more expensive new seals, weaken AEAD authentication or change
the file format. Remove both variables after recovery. Weak historical
parameters within the ordinary bounds remain decryptable with the existing
warning.

### Interactive terminal interruptions

The native `keys seal` prompt runs only in the synchronous CLI startup path,
before any threads are created. While echo is disabled it temporarily blocks
INT, TERM, HUP, QUIT and job-control stop signals on that thread, checks pending
signals between readiness waits with a 100 ms timeout, and restores terminal
attributes before restoring the caller's signal mask. It does not replace signal
dispositions: ignored signals remain ignored, previously blocked signals remain
blocked, and default termination still terminates with the original signal.
A stop request restores the terminal before suspension; after continuation the
partial entry is refused and the operator must rerun the command.

This helper must not be moved into the multithreaded node runtime: another thread
could receive a process-directed signal before terminal restoration. SIGKILL and
SIGSTOP cannot be deferred and remain outside this guarantee. The private tty
handle, bounded preallocated zeroizing buffers, and checked normal restoration
remain in use. No interactive input is read through the shared stdin buffer.
The regression `native_passphrase_tty` exercises the real CLI with disposable
PTYs, deliberate confirmation mismatch, termination at both prompts, stop/resume,
and inherited blocked/ignored signal behavior; it creates no keystore.

Zeroizing buffers are wiped during normal Rust cleanup. Fatal asynchronous
termination is not a guarantee that every secret allocation has been wiped;
terminal restoration and process-memory zeroization are separate properties.
