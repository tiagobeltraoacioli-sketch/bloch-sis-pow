# Existing-chain disposable wallet funding and live quotes

The previously audited local bridge cycle was preserved. A separate wallet uses
public test seed `07` repeated 32 times; the operator's disposable validator key
is not represented as that wallet. This public seed must never hold real assets.

- Wallet script hash: `5b88a7a3d9f598a77024a4703a70ba938ac98834f144861565015ef71a05d011`.
- Native recipient SHA-256: `7a24d6c86b4badb1393a62968cccb54a060e27063361ef57c6ca3a04333cbe17`.
- Canonical BLCH funding: `4c8c1e44033a22baea0918860aaaa02e82585a2ac565fbe273b10d09d1c75060`, slot 2542, output 1, 10,000,000 sat.
- Second source deposit: nonce 1, amount 100, deposit ID `7d1ee0e2cd75f5cf125c268bb7d4bda87b1b6fbf1ea977073dfcd438babf5854`.
- Canonical import: `b6049655018bdd9171e98e9558f6b4933a14019d9b5824f5be6be267a1a7694f`, slot 2783, native mint nonce 1.

The import runner independently checks the actual local EVM receipt, selected
Deposited log, matching token Transfer, canonical source block, vault runtime
SHA-256, source/genesis identity, amount and recipient. RPC transaction inclusion
and native counters establish imported 200, burned 100, outstanding supply 100.
The second source deposit remains locked. No second source release is claimed.

After restart, the node replayed 403 blocks from the same data directory. The
read-only typed create-pair quote at slot 2871 used 1,000,000 BLCH sat and 60 native
units, returning fee 77,136 sat and reserve ID
`3ecf36498fd81ede8bd5b514ea37c5a8ed64aa65e4d59e5685e4efc859aab8a9`.
That quote did not execute a pool operation. Fresh browser review/signing and
canonical inclusion are a separate validation step. Stale-head quoting was
refused. Recorded public packets and receipts are under
`audit/native-wallet-live-funding/`; no operator keystores are committed.

A restart-only detector issue surfaced: replaying this lab validator's own
historical duty triggered the doppelganger detector before networking duties
started. A process-list check confirmed one local instance. Only this isolated
run was restarted with `--no-doppelganger-check`; production defaults and code
were unchanged. This test workaround is not a production restart recommendation.
