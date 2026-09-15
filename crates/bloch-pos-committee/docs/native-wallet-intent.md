# Native wallet intent decoding

`transition::native_dex::pool_intent::DecodedIntent` is a read-only integration
boundary for a future wallet review. It is available only with the existing,
default-off `native-dex-rehearsal` feature. It does not add a signing method,
WASM export, browser provider method, RPC endpoint or live transaction variant.

The caller supplies a domain from independently authenticated configuration.
`DecodedIntent::decode` delegates to the existing bounded, canonical pool wire
decoder and then to the selected executor's authorization function. This keeps
wallet-side Rust integration from reimplementing the protocol's signing hashes.
Wrong domains, unknown operations, noncanonical encodings, truncated/trailing
bytes and oversized packets are refused. No state is read or mutated.

The result owns the complete original packet and decoded request. It exposes
only immutable references, so a caller's later changes to its input buffer or
to a cloned request cannot change what the object reports. Amounts retain the
existing integer base-unit types; no labels, decimals or token symbols are
inferred from a website's presentation.

## Data consumers must distinguish

| Accessor | Meaning | Not evidence of |
| --- | --- | --- |
| `operation()` | Structurally decoded operation kind | Safe execution or source finality |
| `request()` | Complete typed operation, including both funding legs and witnesses | Input ownership, sufficient funds or valid signatures |
| `domain()` | Domain matched to the caller's expected value | Authenticity of that expected value |
| `authorization()` | The executor's existing domain-separated signing digest | User consent, authenticated witness tables or a valid signature |
| `packet_hash()` | SHA3-256 of every packet byte, including signatures | Consensus transaction ID or message to sign |
| `matches_packet(bytes)` | Exact equality to the retained packet | Freshness, funding, signature verification or executability |

`operation()` distinguishes import, withdraw, create pair, initialize, add,
swap, remove and close pair. It is a dispatch label, not a sufficient approval
screen. A consumer must inspect the full operation: asset/route identity,
recipient and output owners, input outpoints, amounts, slippage/LP limits,
reserve identity, pool root/revision, expiry heights, declared byte/gas/tip
fields, and the applicable signer roles. Fee totals and spendability require
verified current host state; decoding alone cannot report them.

Changing witnesses can preserve `authorization()` while changing `packet_hash()`.
Filling signatures therefore requires decoding the new packet; it cannot pass
an exact-byte comparison to the earlier packet. Neither matching authorization
digests nor successfully decoding forged signatures makes a packet authorized.
The existing executor remains responsible for all cryptography and transition
checks. This module deliberately supplies no `approve`, `sign` or broadcast API.

## Validation

The pool-wire tests exercise all six pool lifecycle variants, retain exact bytes
and every decoded field, check the existing executor digests, reject every
truncated prefix and malformed boundaries, and distinguish witness changes from
slippage changes. A compile-fail doctest prevents mutable request access.

`bloch-ustav`'s swap and sponsored gateway crypto fixtures now derive the message
through this decoder before signing with real ML-DSA-65 + Falcon-1024 keys.
Existing successful execution, invalid-signature, theft, stale state and bridge
round-trip tests run through that path. Gateway fixtures cover both import and
withdraw. External source events remain simulated and no funds are transferred.

Run with Rust 1.94.1:

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --doc
cargo +1.94.1 test --locked --release -p bloch-ustav --features native-dex-host --test blch_swap_crypto --test joint_gateway_crypto
```

The existing GitHub and GitLab native regression jobs include these commands.
Local results do not imply remote CI success. Browser delivery, verified chain
context, account-specific intent review, explicit approval, native DEX signing,
consensus activation and an operational USDT bridge remain separate work.
