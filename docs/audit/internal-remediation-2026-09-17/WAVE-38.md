# Internal audit remediation, thirty-eighth wave — 2026-09-18

Base: `8e964c6`; branch `fix/internal-audit-20260917`. This wave reconciles
BV-16 against the current Chameleon reference implementation and its explicit
trust boundary. It makes no production bridge or cryptographic-trapdoor claim.

## BV-16: checkpoint authority is constrained but still trusted

The current feature calls itself **Color-Changing Chameleon**: a native escrow
plus foreign token representation. It does not claim or implement a chameleon
hash, trapdoor collision or token whose code mutates.

Supplying a `TrustedBurnCheckpoint` alone is not sufficient to release an
arbitrary output. A return must also match the registered route and adapter
runtime hash, verify a typed fixed-depth burn inclusion proof and leaf count,
name a valid PQ recipient whose hash is in the burn, carry that recipient's PQ
signature, consume sorted route-specific escrow, remain within backing and
record a permanent `(route, nonce)` nullifier. Snapshot restoration authenticates
the route, locks, exports and nullifiers together.

These controls narrow the original statement that the checkpoint grants an
unbounded standalone forgery primitive. They do not authenticate the foreign
chain. The host is still trusted to supply a canonical finalized checkpoint;
compromise of that source can fabricate burns up to the route's locked backing.
There is no live finality verifier, consensus integration or deployed bridge.
BV-16 is therefore partial.

Twelve state-machine tests and one real-hybrid-authorization test pass. The
ledger retains all 200 rows: 66 implemented, 87 partial, 33 open, seven
base-changed, four protocol decisions, one unarmed candidate, one refuted by
the original audit and one verified positive.
