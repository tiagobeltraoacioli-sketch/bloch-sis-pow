<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Satoshi encoding — the rule, and why it is not the obvious one

Status: normative for Genesis-4. Supersedes `BLOCH-RPC-V4.md` §6 point 1, which
was written against the 21 B nominal and is now wrong on its central number.

## The rule

**A satoshi amount is a decimal string on the JSON wire and an unsigned 64-bit
integer in memory.**

Concretely, and without exception:

1. **Wire form.** Every satoshi-denominated field in every JSON-RPC response is
   a JSON string of base-10 digits: `"satoshis": "1688654952300000000"`. No sign,
   no leading zeros, no decimal point, no exponent, no `0x`. Range `0` ..=
   `TOTAL_SUPPLY_SAT` (`crates/bloch-pos-committee/src/tokenomics_v4.rs`).
2. **Uniformly.** Balances, UTXO values, fees, fee rates, subsidies, stakes,
   rewards, penalties, vesting figures, supply totals — all of them, however
   small the field usually is. A "only the big fields are strings" rule is a
   latent bug in every client, armed and waiting for its first large value.
3. **In memory.** `u64` in Rust, `uint64` in Go (`sdk/go/satoshis.go`), `int` in
   Python, `bigint` in TypeScript. Never a float, in any language, ever — not
   for arithmetic, not for comparison, not "just for display".
4. **Sums are wider.** One balance fits `u64`; the sum of two does not
   necessarily. Every satoshi *sum* inside consensus is `u128` — pinned by the
   compile-time assertions in `tokenomics_v4.rs` (`TOTAL_SUPPLY_SAT * 2 >
   u64::MAX`). Wire width and arithmetic width are separate decisions.
5. **Readers accept both forms.** Live Genesis-3 nodes still emit bare JSON
   numbers. A reader MUST accept the string form and the legacy integer form,
   and MUST parse the legacy form from the raw token rather than through a
   float. Writers MUST emit only the string form.
6. **The `*_bloch` companions stay floats and stay display-only.** They are
   documented as lossy and MUST NOT be used for accounting. They are a
   convenience for humans reading `curl` output, nothing else.

## Why — the part that is easy to get wrong

The trigger was a Go compile obligation. `sdk/go/models.go` typed `Satoshis` as
`int64`, and the Genesis-4 supply moved to 100,000,000,000 BLCH:

| Quantity | Value | Relation to 10^19 sat |
|---|---|---|
| Total supply | 100,000,000,000 BLCH = **10^19 sat** | — |
| `u64::MAX` | 18,446,744,073,709,551,615 | supply is **54.21%** of it |
| `i64::MAX` | 9,223,372,036,854,775,807 | supply is **108.42%** of it — does not fit |
| `Number.MAX_SAFE_INTEGER` (2^53−1) | 9,007,199,254,740,991 | supply is **1,110x** it |

(Measured, not estimated: `node -e` over the exact integers; the supply figure
is `TOTAL_SUPPLY_SAT` in `tokenomics_v4.rs`, itself pinned by
`const _: () = assert!(TOTAL_SUPPLY_SAT > i64::MAX as u128, …)`.)

The obvious fix is to change `int64` to `uint64`. **That fixes Go and leaves the
actual defect in place.**

JavaScript has no integer type in JSON. `JSON.parse` turns every JSON number
into an IEEE-754 double, which is exact only up to 2^53 − 1 =
9,007,199,254,740,991 satoshis ≈ 90,071,992.5 BLCH. Above that, digits are
silently rounded — no exception, no warning, no flag. Measured on node v22.16.0:

```
$ node -e 'console.log(JSON.stringify(JSON.parse(`{"v":9007199254740993}`)))'
{"v":9007199254740992}          # one satoshi gone

$ node -e 'console.log(JSON.stringify(JSON.parse(`{"v":9999999999999999999}`)))'
{"v":10000000000000000000}      # off by 1, at the top of the range

$ node -e 'console.log(JSON.stringify(JSON.parse(`{"v":"9999999999999999999"}`)))'
{"v":"9999999999999999999"}     # string form: byte-identical
```

This is not a hypothetical about the cap. The largest single carried-over
address holds `"1688654952300000000"` sat — 16,886,549,523 BLCH,
`LARGEST_CARRYOVER_ADDRESS_BLOCH` — already **187x** past the JavaScript exact
limit. Any browser wallet, explorer, or exchange front-end that reads that
balance as a JSON number reads a wrong number today, and reads it wrongly and
confidently.

So the ordering is: **the string is the fix; `uint64` is the consequence.** A
JSON number cannot carry a Bloch amount safely no matter how wide the receiving
integer is, because the loss happens in the parser of the largest class of
consumer, not in our struct. Ethereum reached the same conclusion and serializes
quantities as hex strings for the same reason — 256-bit values in a language
with 53-bit integers.

Two things this rule does **not** claim:

- It does not make amounts safe inside a consumer that then does
  `Number(sats)`. It moves the corruption from silent to opt-in — the consumer
  must now write the cast that loses the value. That is the whole gain, and it
  is a real one.
- It does not fix consensus arithmetic. Overflow-free summation is a separate
  invariant (`u128` everywhere), enforced in the node, not on the wire.

## Where it is implemented

| Surface | File | Form |
|---|---|---|
| Contract | `docs/openapi.yaml` — `components.schemas.Satoshis` | `oneOf` [canonical string, legacy uint64], pattern `^(0\|[1-9][0-9]{0,19})$` |
| Node RPC (Genesis-4) | `src/rpc/mod.rs` | emits strings |
| Go SDK | `sdk/go/satoshis.go` (generated from `sdk/codegen/static_assets.py`) | `type Satoshis uint64` + `MarshalJSON`/`UnmarshalJSON`/`ParseSatoshis` |
| Go SDK tests | `sdk/go/satoshis_test.go` | round-trip, supply cap, negative, above-cap, legacy number, JavaScript vectors |
| Python SDK | `sdk/python/blochclient/units.py` | `parse_sats` / `format_sats`, exact `int` |
| TypeScript SDK | `sdk/typescript/src/units.ts` | `bigint` |
| Explorer | `apps/explorer/src/lib/format.ts` | `bigint` |
| Supply constant | `crates/bloch-pos-committee/src/tokenomics_v4.rs` | `TOTAL_SUPPLY_SAT`, with the `i64::MAX` assertion that raised this |

Do not restate the cap in new code — import it, or cite the path above. The Go
and Python SDKs carry a mirrored copy (`MaxSats`, `MAX_SATS`) only because they
cannot link the Rust crate; both name `tokenomics_v4.rs` as the authority in a
comment, and both must be regenerated if it moves.

## Compatibility

Genesis-4 is a fresh chain, so there is no live consumer of the new wire to
break. The migration cost lands entirely on tooling that also talks to the
running Genesis-3 fleet — which is why readers are dual-tolerant (rule 5) and
writers are not. When Genesis-3 halts (height 50,000, per the 2026-08-12 fleet
brief), the legacy branch of every reader becomes dead code and should be
deleted rather than left as a permanent "be liberal" clause.

## Test obligation

Any client claiming conformance carries, at minimum:

1. round-trip of an amount at the supply cap;
2. rejection of a negative amount;
3. rejection of an amount above the supply cap;
4. acceptance of the legacy bare-integer form, parsed exactly;
5. a **fixed-vector** test proving the value survives a JavaScript JSON
   round-trip byte for byte, with the corresponding numeric-form corruption
   pinned alongside it.

(5) is the one that matters and the one most likely to be skipped: it is the
only test that fails if someone "simplifies" the encoding back to a JSON number
in a language where doing so looks harmless. `sdk/go/satoshis_test.go`
implements all five; its JavaScript vectors are measured output from node
v22.16.0, quoted in the test's doc comment with the command that produced them.
