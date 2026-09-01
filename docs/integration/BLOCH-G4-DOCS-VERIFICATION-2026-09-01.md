<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Verification ledger — the two recovered Genesis-4 integration documents

```
Subjects:   docs/integration/BLOCH-G4-RPC.md          (1,213 lines, 2026-08-13)
            docs/integration/BLOCH-G4-TRANSACTIONS.md (1,257 lines, 2026-08-13)
Recovered:  2026-09-01, from worktree-agent-afaacd9bb218fa648 (ef1deeb9)
                        and worktree-agent-a95fe62ba79532310 (42653509)
Verified:   against main @ 737078d1, by reading source only. No node was run.
Verdict:    Both NOT publishable as written. Both worth keeping.
```

## Why this file exists

Both documents were written "from measurement" on 2026-08-13 and never landed.
Each existed on exactly one machine-named branch and on no other ref. That
branch is on a deletion list, so the choice was to land them or lose them.

They were not landed on trust. This repository's characteristic failure this
week has been **a statement that was true when written and false two weeks
later** — a checksum describing a retired file, a caveat naming a dependency
that had since been added, a proof harness asserting its own refutation. A
document that says "measured" carries that risk at full strength, because it
reads as evidence rather than as opinion.

So every falsifiable claim was re-checked. What follows is the result. The
corrections are also inlined in the documents themselves, immediately above
the sections they affect, so a reader who skips this file still cannot follow
a wrong instruction without seeing the correction first.

---

## Part 1 — WRONG (code contradicts the document)

### BLOCH-G4-RPC.md

| # | § | Claim as written | What the code says |
|---|---|---|---|
| R1 | 3.10 | Admission checks only "already pending" and "mempool full"; no signature, balance, fee or double-spend check | `engine.rs:1382` calls `admissible()`; `engine.rs:2711+` refuses `Deposit`, `Delegate`, empty inputs, empty outputs; `engine.rs:2767-2772` verifies every input's hybrid signature. Landed `72de2e93`, `4fd5731c` (2026-08-13), `b9a2b745` (2026-08-18) |
| R2 | 3.10, 3.3 | The worked example — a zero-input, zero-output `Transfer`, 33 bytes — was accepted | Refused today with `-32008`: "transfer has no inputs — it spends nothing and cannot apply" (`engine.rs:2748-2753`). The capture, the `tx_hash`, the duplicate-resubmission capture and §3.3's `size: 1 / bytes: 33` are all unreproducible |
| R3 | 6 | Node error table stops at `-32007` | `rpc.rs:147` `TX_REFUSED = -32008`, emitted at `engine.rs:2094` (`6a7301ea`, 2026-08-22). This is the code a real client hits most, and the document's retry advice sends them to `-32003` instead |
| R4 | 3 | "Ten methods are reachable" | Eleven are routed, twelve names counting `listunspent`. **`gettxout` is undocumented.** Response is exactly `{txid, vout, unspent, utxo, at_slot}` (`rpc.rs:1543-1560`) — **no `finalized` field** |
| R5 | 3.9 | The eUTXO `txid` resolves to nothing; "you cannot pass it to anything" | `gettxout` takes exactly that `txid` (`rpc.rs:894`) |
| R6 | 3.x | `gettransaction`'s `kind` has five values | Six — `rpc.rs:1394-1401` also emits `"transfer_v2"` (`89efc970`, 2026-08-21) |
| R7 | 1.4 | An omitted `jsonrpc` field gives `-32600` at the node, a proxy/node divergence | `rpc.rs:975` only checks the field when present; `rpc/tests.rs:759` pins a successful request that omits it. Not a divergence at all |
| R8 | 6 | All HTTP-level errors carry a JSON-RPC-shaped body | The `503` path writes the bare literal `{"error":"too many connections"}` (`rpc.rs:1023`). `400 Bad Request` is missing from the list entirely (`rpc.rs:1084`, `:1114`) |
| R9 | 4.5 | "We did not diagnose the stall" (production froze at height 69) | Diagnosed the same day, in `72de2e93` — the cause was **this document's own §3.10 transaction**. Both fixes landed. Publishing §4.5 as an open liveness mystery, and §3.10 as a thing to try, is actively harmful |
| R10 | 7 item 6 | "From the source it is not observable: admission does no validation" | Same as R1 |
| R11 | 3.10 | Source reference `engine.rs:663` | That line is now inside `fn rolled_to`. Admission is `engine.rs:1345` / `:2692` |

### BLOCH-G4-TRANSACTIONS.md

| # | § | Claim as written | What the code says |
|---|---|---|---|
| T1 | **10, 12.6 #7** | "No output in existence is spendable"; the entire opening ledger is stranded; a migration spend path "does not exist yet" | **The opposite is true.** `transition.rs:1361-1366` `owns()` accepts a 20-byte prefix match when `script_hash[20..] == [0;12]` — exactly the rule §10.3 predicted. Called at `:2162` (V1) and `:2362` (V2), pinned by `a_carried_output_opens_for_its_genesis3_owner` (`:8851-8905`). Carried and vested outputs are spendable today. Note the security tier the code states: 160 bits, not 256 |
| T2 | 1, 2.2 | "Exactly one transaction variant moves coins"; discriminants stop at `0x05` | Six variants. `TransferV2`, wire tag `0x06` (`transition.rs:370-385`, `:629-651`, `:783-820`) — witness table plus 40-byte inputs, **byte-identical signing root and txid** to V1. Gated on `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH = 800` (`params.rs:301`) — likely already active |
| T3 | 2.4 | "Concatenated, 124 bytes:" | The printed blob is **122** bytes: 30 `22` bytes in the `script_hash` run instead of 32. §8 tells an integrator to assert this string, so a correct implementation fails the document's own KAT. Corrected blob inlined |
| T4 | 3.4 | "preimage (124 bytes):" | The printed blob is **123** bytes, one `22` short. The quoted `signing_root` and `txid` are **correct** — recomputed independently on 2026-09-01 from the true 124-byte preimage and matching to the byte. Only the transcription is wrong. Corrected blob inlined |
| T5 | 4.6 | "The complete reject taxonomy" — 8 variants | 13 (`interfaces.rs:379-463`). Missing: `FormatNotActive`, `BadKeyIndex`, `DuplicateWitnessKey`, `WitnessKeyUnused`, `WitnessTableNotCanonical`. The 8 listed are correct |
| T6 | 7.5 | Mempool admission is only "the bytes decoded"; a transfer in the mempool "has not been authorised by anything" | Admission verifies every signature (`engine.rs:2767-2772`). **The section's advice — wait for a finalized block — still stands**, because admission still applies no fee floor, no per-sender accounting, no replacement policy and no conservation check (`engine.rs:1367-1371`). Keep the conclusion, replace the reasoning |
| T7 | 4.1 | "the block's 256 KiB payload cap" | Epoch-gated: 256 KiB before epoch 800, 512 KiB after (`fee_market.rs:65`, `:85`, `:96-99`; `params.rs:321`) |
| T8 | 11 | The unspent set is written in exactly two places | Three production sites now: genesis opening balances, `apply_transfer` (`transition.rs:2226`), `apply_transfer_v2` (`:2434`) |
| T9 | 13 | Source index line numbers | Roughly two thirds no longer resolve. Current locations listed in the inline correction |
| T10 | header | "branch merge/pos-into-main"; "verified by building this branch" | The tree a reader will check out is `main` @ `737078d1` |
| T11 | 0, 6.4 | "No code path in this repository generates a spending key on a node" | Imprecise: `keys.rs:53-60` `Keystore::generate` calls `generate_keypair()` and writes `validator.key` (0600). Devnet-only and a validator key, but the same suite. Narrow the claim to "no RPC and no CLI subcommand mints a key" |
| T12 | 12.6 #3 | Cites `src/stratum/` comments | Now `legacy/genesis3-node/src/stratum/`. The substance of the finding is unchanged and still open |

---

## Part 2 — Could NOT be verified (and why)

Nothing in this part is asserted to be wrong. It is what source alone cannot
settle. **Anyone publishing either document must re-measure these against a
current node first.**

| Document | § | Why it could not be checked |
|---|---|---|
| RPC | 1.1, 1.4, 6 (proxy), 7 | Everything about the Cloudflare Pages proxy — allowlist contents, the `-32601` "not exposed by this proxy" text, `-32000` upstream-unreachable, the 12 s timeout, the GET-returns-HTML trap, OPTIONS/CORS. `functions/g4rpc.js` lives in `~/dev/posternlabs-deploy`, not in this repository; `grep` for the quoted string finds nothing here. The endpoint URL itself *is* corroborated: `apps/explorer/src/lib/g4.ts:15` |
| RPC | 0, 3.1, 3.6, 4.3, 4.5 | Every live-state number: 52 validators, genesis timestamp `1786637615`, `total_active_stake_sat`, the stake pattern, every captured hash, height 69, the liveness table. Chain state, not code — and invalidated by relaunches the document's own §0 anticipates |
| RPC | 1.3 | The specific measurements `1,200,063 bytes → 413`, `20 KiB header → 431`, chunked → `411`. The **constants** are confirmed; the measurements need a node |
| RPC | 3.6 | `pubkey_bytes: 3749` — the code emits `rec.pubkey.len()` (`rpc.rs:1451`); the value depends on the key |
| RPC | 7 | The Genesis-3 `confirmations` offset 10,768 — quoted from a file that exists, but the G3 chain is not in this tree |
| TX | 2.4, 11 | Signature lengths 4,583 / 4,580 and the full 32-byte `script_hash`: the throwaway key is gone, and Falcon randomisation makes exact re-measurement non-reproducible **by design**. The derived values *are* internally consistent — `33 + 40 + 44 + 3749 + 4583 = 8449` checks out, and the KAT2 root and txid were recomputed and match |
| TX | 7.2, 7.3 | The `submit-tx` console transcripts. Not executed. Every line the transcript shows is the literal string in `main.rs:361-405`, and the `123-byte encoding` figure checks out arithmetically |
| TX | 4, 1 | **Whether `TransferV2` is inert on the live chain right now.** `params.rs:301` gates it at epoch 800; the chain was past epoch 1,400 at the 2026-08-29 flag day, which would make tag `0x06` **live**. Confirm with `getchaininfo` before publishing either statement |
| TX | 12.4 | The live base fee. The floor (`MIN_BASE_FEE_MILLISAT_PER_GAS = 10`, `fee_market.rs:208`) is confirmed; the current value is not readable from source |

---

## Part 3 — What held up

Recorded because it is the reason to keep these documents rather than start over.

**BLOCH-G4-RPC.md.** The whole finality argument in §4 — including the
non-obvious fact that classification is by **slot against the checkpoint
block's slot**, not by epoch (`engine.rs:1905-1923`). Both permanent refusals
in §5, with `-32005` and `-32006` message bodies **byte-identical** to
`rpc.rs:196-241`. The complete field-by-field reference for the other nine
methods — all 19 `getchaininfo` fields in order, all 19 block fields, every
`getvalidator` field including `null`-not-`0` for `effective_stake_sat` off
the active set. Every HTTP and parser limit (`MAX_BODY_BYTES`,
`MAX_HEADER_BYTES`, `MAX_CONNECTIONS`, `IO_TIMEOUT`, `ENGINE_TIMEOUT`,
`MAX_DEPTH`, `MEMPOOL_MAX`, `UTXO_PAGE_MAX`). All four long quoted error
strings. `version: 2970353669` = `0xB10C0005` in a 304-byte header. And the
`>1000 outputs are unreachable` finding, which the code has since reinforced.

Notably, §3.10 **states correctly** that `sendrawtransaction`'s `tx_hash` is a
node-local handle, not a txid, that no other node agrees on — one of the four
statements known to be wrong in sibling documents. This one gets it right.

**BLOCH-G4-TRANSACTIONS.md.** The entire cryptographic core, independently
reproduced: the canonical encoding rules and byte layout, the signing-root
preimage, `txid = SHA3-256(DS_TXID ‖ root)`, both domain tags, the gas formula
`5_000 + tx_bytes·16 + 72_748·n_inputs`, the ceil-rounded fee arithmetic and
its worked example, the `tx_bytes` circularity and the 8,641-byte bound, the
4-byte `B1 0C` suite envelope and why enveloped and raw keys hash differently,
`SIG_SIZE = 4,775 = 4 + 3309 + 1462`, the check order in `apply_transfer`
(cheapest first, signatures last, no mutation before every check passes), and
the whole of §9 on addresses — including the in-tree KAT, which was recomputed
from scratch and matches `legacy/genesis3-node/tests/vectors/kat_address.json`
exactly.

Its §9.4 finding that Rust's `hex::decode` accepts uppercase while the
TypeScript SDK rejects it (`sdk/typescript/src/address.ts:35`) is confirmed and
still open. So are discrepancies #1, #2, #4, #5 and #6.

## Part 4 — The four sibling-document errors

Checked explicitly in both documents, because they are known to be wrong
elsewhere in this tree.

| | Status |
|---|---|
| `gettxout` has no `finalized` field | Neither document mentions `gettxout`. **Not repeated** — but the RPC document must now add it, and correctly: `{txid, vout, unspent, utxo, at_slot}` |
| `sendrawtransaction`'s `tx_hash` is not the txid | **Stated correctly** in BLOCH-G4-RPC.md §3.10 and §5.1 |
| `getutxos` does not carry a landing slot | **Not repeated.** Both give the entry shape as `{txid, vout, value_sat, script_hash}`, matching `rpc.rs:1474-1481` |
| The binary is `bloch-pos`, not `bloch-pos-quatro` | **Not repeated.** BLOCH-G4-TRANSACTIONS.md names it correctly; the RPC document never names a binary. Confirmed at `crates/bloch-pos-node/Cargo.toml:41` |

The one `finalized: true` in BLOCH-G4-TRANSACTIONS.md refers to the *block*
response, which does carry that boolean (`rpc.rs:1341`). Correct as written.
