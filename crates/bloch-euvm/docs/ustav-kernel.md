# Ustav v2: executable native-token transition kernel

Status: reference implementation for integration review, not activated in consensus.
Kernel version: **2**. Kirpich ruleset version: **2**.

## Scope and architecture

`bloch_euvm::ustav::Ledger` owns a private registry, supply counters, emission
nonces, policy revisions and UTXOs. `bloch-ustav::BlochVerifier` supplies concrete
cryptography. Callers submit outpoint references; they cannot supply previous
balances, prior supply, validators, freeze flags or KYC roots in a transaction.
The ledger selects the registered modules and commits state only after every
applicable check succeeds. Each transaction concerns one asset.

This establishes the native-asset kernel proposed for L1. General EVM applications
remain a separate L2 integration. No EVM precompile, bridge, validity proof, L2
sequencer, Genesis-4 block field or activation height is introduced here. ADR-040's
existing placement of EVM/Ustav is not silently rewritten by this implementation;
final L1/L2 placement needs an explicit architecture/consensus decision.

## Operation contract

All signatures authorize the complete domain-separated operation digest. Owner
signatures are required for **every input**, regardless of module approvals.
Module order is immutable and defines the witness slots. One module of each kind
is allowed, with exactly one Supply module and a nonempty name.

| Check | Mint (`delta > 0`) | Transfer (`delta = 0`) | Burn (`delta < 0`) | Policy update |
|---|---|---|---|---|
| Owner | Every spent input | Every spent input | Every spent input | No inputs |
| Supply | Issuer signature, cumulative cap, emission nonce | No redeemer | Issuer signature, nonnegative remaining supply | No redeemer |
| TransferPolicy | Authority override when frozen | Authority override when frozen | Authority override when frozen | Authority signature always |
| KYC | Every input/output owner | Every input/output owner | Every input/output owner | Root may change with authorized update |
| Vesting | Height and beneficiary signature if inputs are spent | Height and beneficiary signature | Height and beneficiary signature | No redeemer |
| Governance | Declared quorum | Declared quorum | Declared quorum | Declared quorum |
| Custody | ECDSA AND hybrid PQ | ECDSA AND hybrid PQ | ECDSA AND hybrid PQ | ECDSA AND hybrid PQ |

Absent modules contribute no check. Present but inapplicable modules require an
empty redeemer. TransferPolicy always has one Bytes slot, which may be empty when
unfrozen. Governance has one Bytes slot per signer; empty signatures count as
non-signers. Custody's slots are ECDSA then PQ. KYC's module redeemer is empty;
its typed SMT proofs are in `Witnesses::eligibility`.

Vesting is a **perpetual charter spend gate**, not a one-time claim: the beneficiary
must also authorize subsequent spends after the unlock height. Initial minting
without inputs can distribute locked balances before that height. Freeze means
an additional authority approval, not an absolute prohibition. These are explicit
v2 semantics; changing them requires a new version and migration rules.

## State and replay

`sum(inputs) + delta == sum(outputs)` and
`0 <= prior_supply + delta <= cap` are checked with overflow detection. Inputs
must be unique, strictly sorted outpoints and belong to the registered asset.
Outputs must have positive amounts and admitted hybrid public keys.

Positive issuance uses the asset's next mint nonce, initially zero, and increments
it atomically with balances. Every other transaction requires `mint_nonce = 0`.
Transfers and burns require inputs; consuming outpoints prevents replay. All
operations bind their asset, network domain, expiry and current policy revision.
`height <= valid_until` is inclusive. The host supplies the authenticated height.

`SetFrozen` and `SetKycRoot` are signed administrative transitions. They increment
the policy revision, invalidating previously signed transactions. KYC requires
TransferPolicy as an explicit root-update authority. Configured Governance and
Custody approvals are required **in addition**. The API offers no charter, cap,
key or module replacement. Registration itself requires the issuer's signature;
it does not assert possession of every other configured key.

## Identity and signing format

Let `H` be double SHA-256, `B(x) = u64_le(length(x)) || x`, and `T(tag)` be
`B(ASCII(tag))`. Fixed-size byte fields have no length prefix. Integer widths and
endianness are fixed; `usize`, JSON, debug strings and signature bytes are absent.

`asset_id = H(T("USTAV-ASSET-v2") || domain[32] || kernel:u32_le || ruleset:u32_le ||
nonce[32] || B(token_name) || module_count:u64_le || canonical_modules)`.

Canonical modules preserve declaration order:

| Tag byte | Fields following the tag |
|---|---|
| 1 Supply | cap:u64_le, B(issuer key) |
| 2 TransferPolicy | B(authority key) |
| 3 KYC | none |
| 4 Vesting | unlock:i128_le, B(beneficiary key) |
| 5 Governance | threshold:u32_le, count:u64_le, each B(signer key) |
| 6 Custody | B(ECDSA key), B(PQ key) |

Registration signs `H(T("USTAV-REGISTER-v2") || asset_id || optional_initial_root)`.
An optional hash is byte `0`, or byte `1` followed by 32 bytes. The initial root
is signed and committed in ledger state, but does **not** enter asset identity:
KYC leaf keys bind the asset, and including the root in that identity would create
a circular hash. A different nonce creates a different registration; registering
the same asset again is rejected, including with a different initial root.

Transactions sign `H(T("USTAV-TRANSACTION-v2") || domain || kernel:u32_le || asset ||
input_count:u64_le || each(input_tx_hash[32], index:u32_le) || output_count:u64_le ||
each(B(owner), amount:u64_le) || delta:i128_le || mint_nonce:u64_le ||
policy_revision:u64_le || valid_until:u64_le)`.

Policy updates sign `H(T("USTAV-POLICY-UPDATE-v2") || domain || kernel:u32_le || asset ||
revision:u64_le || valid_until:u64_le || action)`. Action is bytes `[1, frozen]`
with frozen 0/1, or byte `2` followed by the new 32-byte root.

The transaction digest is also its outpoint transaction identifier; witnesses do
not change it. Supply and spend modules execute separately because their VM
context layouts differ. The kernel populates both layouts from authenticated
state and passes the same operation digest to every signature check.

`ustav_kernel::signing_vectors_pin_the_independent_canonical_encoding` pins values
calculated separately with Python `hashlib`/`struct`, including module encoding,
domain/version separation and mint/update digests. These are protocol regression
vectors, not external cryptographic certification.

## KYC proofs

`subject = H(T("USTAV-ELIGIBILITY-v2") || domain || asset || B(owner))`.
Use this 32-byte subject as the key in the existing `SparseMerkleTree`; its own
SHAKE key/leaf/node encoding remains unchanged. The leaf value is the inclusive
expiry height, exactly eight little-endian bytes. Nonmembership is rejected.

Witnesses contain one 256-sibling proof per **distinct** input/output subject,
sorted lexicographically by subject. The kernel checks the exact subject, stored
root, value shape, membership and expiry. Reusing another holder's, another asset's
or a revoked root's proof fails. KYC is public allowlisting in this version, not
anonymous credentials or a zero-knowledge compliance protocol.

## Cryptographic admission

The concrete adapter accepts only the existing Bloch suite 0x0001 envelope:
ML-DSA-65 **and** Falcon-1024. Public key length is 3749 bytes, with a canonical
Falcon header and coefficients below 12289. The verifier calls the project's
existing hybrid implementation. ML-DSA-only suite 0x0002 is not admitted by v2.

Custody keys use canonical 33-byte SEC1 compressed secp256k1 points. ECDSA
signatures are 64-byte `r || s`, low-S, over the 32-byte digest (prehash API).
This proves approval by a Bitcoin-curve key; it does not prove a Bitcoin deposit.
Custom `Verifier` implementations are trusted host code, never transaction input.

## Kirpich and limits

Kirpich is mandatory at registration and restoration. Its report, including
non-blocking warnings, is retained. The dispatcher checks bounds **before**
conflict maps, key copying and emitted-program analysis. KRP-047 covers structural
resource bounds; KRP-046 retains the key-byte bounds. A resource violation returns
one deterministic Deny finding instead of enumerating expensive follow-on findings.
The full audit still compiles twice for its determinism check, and returns the
already audited artifact instead of performing a third compile.

| Bound | Reference value |
|---|---:|
| Token name | 256 bytes |
| Raw charter module count | 64 (v2 admits at most one of each of the six kinds) |
| Raw governance entries | 1024 before allocation; semantic maximum remains 253 |
| Individual / total charter public-key bytes | 8192 / 262144 |
| Conservative charter encoding budget | 270336 bytes |
| Inputs / outputs per transaction | 128 / 128 |
| Individual signature | 8192 bytes |
| Combined witness and output encoding budget | 1 MiB |
| In-memory registry / UTXO count | 1024 / 65536 |

Existing emitted-validator byte/gas limits also apply. They can make the effective
governance size smaller than 253 for large PQ keys. The 1 MiB budget can likewise
reduce the effective count of KYC subjects or owner signatures below 128.
Reference gas charges input bytes, host signature checks, VM execution and SMT
verification before each corresponding expensive validation stage; registration
has a bounded pre-compilation charge. Units have **not** been calibrated as fees.
The store and snapshot-root computation are reference implementations, not a
benchmark of production capacity. The wire decoder must bound lengths **before**
allocating the typed Rust inputs; these APIs cannot undo an upstream allocation.

## Snapshots and integration obligations

Snapshots expose typed transport state, not mutable ledger access. Restore checks
version, resource bounds, canonical ordering, all registrations and keys, asset
identity, output ownership shape and `sum(UTXOs) == supply`, then compares the
recomputed root to an **independently authenticated** expected root. The state root
commits domain/version, registration authorization, emitted charter artifact,
supply, mint nonces, policy revisions, freeze/KYC state and outputs. The reference
root rebuilds an SMT; production persistence needs an equivalent incremental store.

Before chain activation, implement and review:

1. A versioned, bounded wire codec and domain derived from authenticated network
   configuration; bind operation bytes and witnesses into the block body.
2. Canonical block-height delivery, deterministic transaction ordering, aggregate
   block gas/fees, invalid-block rejection and atomic block commit/rollback.
3. Crash-consistent persistence, incremental root updates, reorg journals and
   snapshot/checkpoint authentication. Never trust the snapshot's own root.
4. Wallet/RPC support for outpoints, revisions, signatures and subject proofs,
   plus activation/migration rules. Legacy asset IDs cannot be auto-reinterpreted.
5. Differential/fuzz/property campaigns, resource measurements and independent
   review of compiler/VM/kernel/host composition before an activation proposal.
6. For L2 access: finalized L1 deposit processing, DA/proof or dispute verification,
   withdrawal nullifiers and exit rules, followed by an EVM-facing adapter. An
   authenticated bridge is a separate protocol, not an unchecked mint call.

The existing raw `EuTx`, `minting::policy_asset_id` and compiler
`CompiledToken::policy_id()` remain historical APIs with their historical
identities. They do not access the private v2 ledger. No legacy validator hashes
or serialized VM programs change in this patch. The new namespace avoids
silently treating either legacy identity as a registered v2 native asset.

## Reproduction

From the repository root, using the committed workspace lockfile:

```sh
cargo +1.94.1 test --locked -p bloch-euvm -p bloch-ustav
cargo +1.94.1 test --locked --release -p bloch-euvm -p bloch-ustav --test ustav_kernel --test crypto_kernel
cargo +1.94.1 clippy --locked -p bloch-ustav --all-targets --no-deps -- -D warnings
cargo +1.94.1 run --locked -p bloch-ustav --example lifecycle
```

The Ustav GitHub Actions workflow runs these gates. Existing ignored EUVM
doctest sketches are not counted as executed tests. The tests establish the
listed transition behavior; they do not constitute a formal proof or an external
security audit.
