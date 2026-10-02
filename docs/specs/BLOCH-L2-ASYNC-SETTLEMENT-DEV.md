# Asynchronous L2 settlement development protocol

This protocol requires a fresh, unfunded `BPOSMAN3` development network. It
does not migrate a `BPOSMAN1`/`BPOSMAN2` chain or activate funded bridge flows.
Three validators on one host share one operational failure domain.

The manifest appends a fixed 264-byte L2 configuration: five program/execution
identities, proof policy, chain ID, initial L2 parent and initial state root.
The manifest digest derives the native network identity. The bound genesis
construction derives the native genesis identity without a hash cycle. The
decoder rejects carryover balances, allocations and cohorts in this format.

Transaction `0x0F` carries the existing 590-byte V2 statement and 356-byte
Groth16 proof, with a 32-byte proof-policy identifier. `0x0E` retains its exact
immediate-parent semantics and encoding. Neither mode accepts the other tag.

Before processing transactions, the first transition with a non-genesis parent
pins that parent's hash, slot and committed block height in the settlement
state. The anchor remains unchanged while the prover runs and the native chain
continues. Acceptance verifies the policy, anchor, empty inbox, exact L2
successor and real proof, then consumes the anchor. The following transition
pins the settlement-containing block as the next source. The previous source
commitment and settlement commitment bind successive proofs. Failed proofs
cannot advance either cursor. One proof reserves the entire block gas budget.

The mempool accepts at most one pending asynchronous proof and performs the
same cryptographic/state checks as the transition. `getl2settlement` exposes
only the committed public source and accepted cursor. `getblockraw` exports the
exact canonical envelope for independent proposer, attester, transition and
proof replay. An accepted transaction alone is not finality: the containing
block must lie in the prefix finalized by native FFG. L2 recovery must also
compare the exact statement against persisted canonical execution and body.

Operational qualification remains separate from production activation,
Ethereum `safe`/`finalized` tags, bridge liquidity and checkpoint ceremonies.
