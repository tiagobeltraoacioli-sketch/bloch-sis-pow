# Internal audit remediation, thirteenth wave — 2026-09-17

Base: `806e34d`, implementation commit `6743395`, branch
`fix/internal-audit-20260917`. This is local source evidence, not a fleet
activation or release approval.

## Hybrid-only transfer admission

CR-03 was exact: the generic crypto-agility verifier accepts suite 0x0002
(ML-DSA-65 only), while the live-chain security claim says every authorization
is hybrid ML-DSA-65 and Falcon-1024. Removing 0x0002 from the generic verifier
would break its documented API. Rejecting it in the consensus verifier without
first proving that no committed output names such a key could also strand
funds and change historical validity without a flag day.

The crypto crate now exposes one public-key format predicate owned beside the
suite parser. It recognizes only an exact suite-0x0001 envelope or the exact
legacy raw hybrid key length. The length-first legacy rule is preserved, so an
old raw key whose first bytes happen to equal the envelope magic is not
misclassified.

Both Transfer and TransferV2 admission apply that predicate before pricing,
state-independent table work and signature verification. New suite-0x0002
spends are therefore refused before RPC/gossip can place them in the mempool or
make a proposer select them. A regression covers both transaction encodings
with a verifier that panics if called, proving the suite refusal is cheap-first;
hybrid controls still pass through the real verifier.

This is deliberately a node-local mitigation. A hand-built scheduled proposer
can still put a valid suite-0x0002 spend directly in a block, and consensus will
accept it. Full closure requires an inventory of committed output script hashes,
a protocol decision for any matches, a consensus activation gate and a
coordinated release. CR-03 therefore moves from open to partial, not to
implemented.

## Validation and status

The focused crypto and node regressions each executed and passed. The complete
crypto suite passed 190 tests with four ignored, including doctests; the
complete node suite passed 592 tests with 25 ignored. Details are in
`VALIDATION-WAVE-13.txt`.

The ledger retains all 200 rows: 53 implemented locally, 75 partial, 59 open,
seven base-changed, four protocol decisions, one unarmed candidate and one
refuted by the original audit.
