# Dormant canonical BLCH/native pool lifecycle

`NativePool` (`0x12`) carries the existing bounded `pool_wire` format. The
canonical adapter executes CreatePair, Initialize, Add, Swap, Remove and
ClosePair against the existing reserve locks, asset ledger and AMM math. It
rejects Gateway payloads: this tag cannot bypass import or withdrawal admission.
An all-branch `transition.rs` history scan found no prior `0x12` decoder or
encoder allocation. Historical tags are unchanged.

`NATIVE_POOL_ACTIVATION_EPOCH` remains `u64::MAX`. This change arms no network,
creates no production pool and supplies no liquidity or external backing.
Any separate laboratory activation must be isolated from production domains.

Executors now accept a private host context for the candidate block's base fee
and five-byte outer frame. Existing rehearsal callers retain their original
pricing behavior. Consensus stages both ledgers, publishes only on success,
and returns the charge to ordinary block fee settlement; rehearsal fee escrow
never enters the canonical component. Pool authorization, exact reserve inputs,
minimum outputs, expiry, revision and reserve-root freshness remain enforced by
the existing lifecycle implementation.

Tests execute all six lifecycle operations through complete candidate blocks,
check byte/gas fees and BLCH conservation, reject an invalid suffix atomically,
replay the wire, restore native snapshots and refuse the disabled gate. A
separate four-block sequence imports a committee-attested asset, locks it with
BLCH, initializes its pool and swaps BLCH for the imported asset. Each block is
replayed and restored independently. Total native supply and gateway liabilities
remain unchanged by the swap. Adapter tests also reject gateway substitution,
wrong domains and repeated spending without changing the parent state.

The import remains federated attestation, as documented in
[native-gateway-consensus-status.md](native-gateway-consensus-status.md).
Pool execution does not prove source-chain finality or turn release records
into external payments.
