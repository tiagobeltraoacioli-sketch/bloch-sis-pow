# Bounded BLCH/native pool lifecycle transport

The default-off `native-dex-rehearsal` feature exposes `native_dex::pool_wire`
for local binary admission to the existing atomic State methods. This does not
register an HTTP/RPC endpoint, a block transaction type or a wallet signing API.
It does not activate consensus or authorize an external bridge payment.

## Frames and dispatch

`encode` uses the existing canonical request encodings without adding a wrapper.
`decode(bytes, expected_domain)` requires a nonzero domain from trusted host
configuration. `quote_encoded` and `apply_encoded` derive that domain from the
State itself. The host also supplies the execution height and signature verifiers;
the sender cannot select them in the frame.

| Request variant | Magic | Version | State execution |
| --- | --- | --- | --- |
| CreatePair | BLCHPAIR | 1 | execute_paired_custody |
| Initialize | BLCHILIQ | 1 | execute_initial_liquidity |
| Add | BLCHLPAD | 1 | execute_blch_add |
| Swap | BLCHSWAP | 1 | execute_blch_swap |
| Remove | BLCHLPRM | 2 | execute_blch_remove |
| ClosePair | BLCHPCLS | 1 | execute_paired_close |
| Gateway | BLCHGWAY | 1 | execute_gateway |

Creation frames remain compatible with `paired_custody::wire`. Removal version 1
is rejected because it lacks the signed provider identity used by version 2.
ClosePair only closes eligible uninitialized custody; it cannot bypass LP claims.
The [gateway operation](joint-gateway.md) adds jointly signed, BLCH-funded imports
and withdrawals to the same dispatcher. The six original pool encodings remain
unchanged. Older receivers reject Gateway frames and require an update.

## Bounds and authorization

Before allocating decoded base witness tables, the decoder checks the total
envelope limit, section lengths, base transaction shape, operation tail and exact
end of frame. Pool base transactions require one key, bounded nonempty inputs and
bounded outputs; initialization permits no outputs. Gateway permits up to 128
sponsor keys and zero outputs, and uses the bounded gateway envelope decoder
instead of the zero-delta transfer decoder. Public keys and
signatures use the existing 8,192-byte bound. Removal owner bytes are borrowed
until their nonempty length and complete frame have been checked. Native sections
use the existing bounded transfer decoder and must match the outer domain.
Decoded requests must re-encode byte-for-byte to the original frame.

A structurally canonical frame is not an authorized transaction. Fee quoting
only estimates existing full-frame costs. Execution still checks signatures,
funding, expiry, current pool root/revision, slippage, LP ownership and custody
through the existing atomic State methods. Failure cannot publish one asset leg,
fee escrow or an LP update independently. Snapshot and signing versions do not
change in this transport addition.

Tests compare all six encoded operations against direct execution, including
fees, final state and replay rejection. They reject every truncated prefix,
trailing data, hostile lengths, unknown headers, wrong domains, old removal
versions and unauthorized canonical mutations. Existing real PQ integration
tests also compare encoded and direct execution for all six operations.

[`pool_batch`](pool-batches.md) now provides bounded multi-operation simulation
and all-or-nothing application over these frames, with parent-root binding and
aggregate byte/gas accounting. It remains a local rehearsal API.

## Remaining integration

A live host still needs bounded ingress, trusted height/domain configuration,
mempool and block admission, deterministic fee settlement and reorg persistence.
Wallet integration must show and sign the joint intent. USDT support separately
requires verified external custody, finality and bridge authorization. These local
transport tests do not establish production readiness or external USDT backing.
