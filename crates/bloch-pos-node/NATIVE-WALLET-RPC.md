# Canonical native wallet API and admission

Build with `--features native-wallet-rpc` for official-network support. This
nondefault feature provides bounded read/build RPCs and native mempool handling;
it does not change consensus activation epochs. All six production native gates
remain disabled. A binary feature, RPC request or local flag cannot arm them.

Every official wallet response requires the state's admission domain to equal
SHA3-256 of the exact loaded manifest encoding, an initialized native component
with that same domain, and native-state activation in the committed epoch. Pool
and withdrawal builders additionally require their respective committed gates.
Replies use the actual `BPOSMAN1` or `BPOSMAN2` format. A laboratory transition
cannot serve an official manifest. `BPOSLAB1` remains available only through the
separate laboratory feature, manifest and loopback policy.

The checked-in existing mainnet manifest has these independently distinct pins:

- Format: `BPOSMAN1`.
- Manifest SHA3-256/domain: `f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966`.
- Canonical genesis header ID: `9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415`.

The node test in `engine/native_wallet_rpc.rs` derives these through the actual
manifest codec. V1's header ID alone does not bind a unique manifest; a client
must pin both the domain and genesis ID. These are local canonical derivations,
not evidence of a newly deployed binary or an activated mainnet route.

## Read and build requests

`getnativewalletview([{ "ownerPublicKeyHex": "..." }])` requires exactly one
valid hybrid owner key for official networks. It uses the script index to select
that owner's base UTXOs, plus every canonical base custody output required to
restore the complete native snapshot. It never scans/exports unrelated holders
or truncates an oversized owner projection. The existing limits remain 4096
combined UTXOs and a 4 MiB native snapshot; exceeding either limit refuses the
request. Custody outputs are not spendable wallet balances. Large owner/native
states will require a separately designed proof or pagination protocol; this API
must not silently drop inputs to appear available.

The response is `{format,domain,genesis,head,height,stateRoot,trust,context}`.
`height` is the consensus slot, not the number of produced blocks. `trust` is
`trusted-host-projection-not-finality-proof`. Context contains
`nativeSnapshotHex`, `nativeCommitmentHex`, `utxos` with
`{txid,vout,value,scriptHash}`, `baseFeeMillisatPerGas`, `blockGasUsed`,
`blockTxBytes`, and `epoch`. All integer values are canonical decimal strings;
hashes have no `0x` prefix. No private key enters an RPC.

`getnativepoolquote` and `getnativewithdrawalquote` preserve the typed request and
result fields documented in [the laboratory API](NATIVE-LAB.md), but official
calls use actual official format/domain and the scoped owner's context. Builders
operate on a bounded private projection rather than cloning/scanning the full
mainnet UTXO ledger. They require the current `expectedHead` and return unsigned
packets; withdrawal issuer/quorum certification remains external and separate
from owner signing. Building a packet does not submit it or establish finality.
`getnativepool([poolId])` reports canonical locked reserves, revision, LP supply
and the common response identity.

`getnativebridgestate([assetId,routeId])` returns:

```text
{format,domain,genesis,head,height,stateRoot,asset,route,
 trust:"trusted-host-projection-not-finality-proof",
 externalSettlementConfirmed:false,
 ledger:{supply,imported,burned,nextReleaseNonce,nativeCommitment}}
```

All ledger integers are decimal strings. Unknown asset/route pairs are refused.
Native accounting never asserts that a source vault has made a payment.
`getnativelabstate` is still laboratory-only and is not an official API alias.

## Admission without activation bypass

Gossip and `sendrawtransaction` use the same native path. An official native
transaction requires matching manifest/state identity, initialized canonical
state and its specific consensus gate at both the committed epoch and proposed
candidate epoch. A future wall clock alone cannot admit a pre-activation
transaction. Admission dry-runs the real typed executor against a private state
with actual candidate-slot fee pricing and the strict native verifier.

Sponsor fee ranking, source limits, declared byte budgeting and base-input
conflicts apply to native transactions. The conservative policy permits only one
pending native operation, avoiding unconfirmed native-input, route-nonce or pool-
revision dependencies. Adoption and reorg revalidate pending native operations;
block proposal and validation still enforce the complete canonical transition.
The generic structural checker continues refusing native packets without this
state-dependent path. No public node was restarted or upgraded for these changes.

## Operator activation profile

The selected target is the existing Bloch mainnet, not a new genesis. Start from
`docs/native-mainnet-activation.template.json` and run:

```sh
python3 scripts/check-native-activation-profile.py PATH_TO_OPERATOR_PROFILE
python3 scripts/check-native-activation-profile.test.py
```

The template intentionally fails until the operator supplies six concrete future
epochs, the exact release commit/binary hash/features, a fresh pinned chain
observation and active-validator roster, and readiness evidence for every active
validator. Artifact references contain relative `path` and SHA-256; paths cannot
escape the profile directory and each JSON file is bounded to 2 MiB. Duplicate
fields, missing evidence, stale/future observations, wrong domains, mismatched
build/gates, duplicate/unknown validators, disabled/past epochs and contradictory
prerequisites are refused. The minimum review lead is four epochs; no actual
epoch is selected by the tool. The profile also pins a `custodyManifest` artifact
using schema `postern.mainnet-custody.v1`; its official domain/genesis, selected
Ethereum route, nonzero native asset/vault and planned state activation epoch
must agree. Detailed custody validity and approval remain the source operator
validator's responsibility. A source observation report is not an activation proof.

The chain observation contains the exact `network` object from the template,
`observedAtUnix`, `headSlot`, `wallSlot`, `head`, `finalizedEpoch` and
`finalizedRoot`. The roster uses the same network and head plus
`activeValidators:[{id,publicKeySha256}]`. Readiness evidence contains that
network, `observedAtUnix`, `validatorId`, `publicKeySha256`, `observedHead`, the
exact `release` and `gateEpochs` objects, `operatorApprovalReference`, and boolean
checks `canonicalReplayPassed`, `historicalRootsUnchanged`, `rollbackPrepared`.
Integers are decimal strings; hashes are lowercase unprefixed hex.

This is an **offline consistency check**, not operator signature verification,
authentication of RPC observations, or deployment authorization. Its successful
output explicitly keeps `activationAuthorized` and `operatorSignaturesVerified`
false. Operators must authenticate their roster, readiness approvals, finality
observations and selected custody manifest independently. The node does not read
this JSON as an activation override. A reviewed coordinated release must set and
validate consensus epochs in code, preserve historical roots, and qualify the
actual fleet before the chosen boundary. Source custody and signed native
asset/route bootstrap remain separate prerequisites; this profile cannot supply
missing authorities or vault configuration.
