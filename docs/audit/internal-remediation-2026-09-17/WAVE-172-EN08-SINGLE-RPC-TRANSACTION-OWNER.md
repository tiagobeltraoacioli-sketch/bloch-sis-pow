# Wave 172 — EN-08 single RPC transaction owner

Date: 2026-09-19
Comparison base: `3596a546`

## Residual addressed

The `sendrawtransaction` edge already decoded the request into one owned
`PosTransaction`. The engine then cloned that complete transaction so one
copy could move through admission while the other survived for the success
response. Admission encoded the moved copy into its canonical mempool key;
after success, `submitted_json` encoded the retained copy again to derive the
response byte count and local correlation hash.

The HTTP body is capped at 1 MiB and carries canonical bytes as hexadecimal,
so this remained bounded. It nevertheless duplicated transaction-owned
vectors and performed a second complete canonical encoding on the single
consensus thread for every successful or duplicate RPC submission. Neither
operation added admission, signature or response evidence.

## Correction and invariants

The RPC arm now derives one canonical `Vec<u8>` from the decoded transaction.
A private engine seam moves that same owner through the unchanged duplicate,
bar, capacity, structural, cryptographic, lifecycle, mempool and broadcast
logic. On a successful or duplicate outcome, its callback creates a private
`PreparedSubmission` from the still-borrowed transaction and the same
canonical bytes; the transaction and canonical owner can then move without a
clone, and the prepared fixed-size metadata renders the response afterward.

The callback is deliberately invoked only for `New` or `Duplicate`. Invalid,
limited and capacity-refused submissions therefore do not gain an additional
proportional SHA3 pass from this optimization. Gossip retains its existing
entry point and canonicalizes once with a zero-sized callback result.

`submitted_json` remains available with its existing signature and output for
other callers. The status, kind, byte count, SHA3 correlation handle, warning
text, error mapping, source identity, admission order, mempool key, transport
payload and broadcast rules are unchanged. There is no public API, wire,
disk-format, protocol, activation, verdict or consensus change.

## Adversarial coverage

- `prepared_submission_reuses_large_canonical_owner_with_exact_reply_parity`
  uses a canonical transaction larger than 400 KiB whose hexadecimal form
  remains inside the real RPC body cap. It pins exact canonical bytes and
  complete JSON equality with the former public response oracle.
- `rpc_submission_moves_one_prepared_transaction_and_canonical_owner` pins the
  production arm to exactly one `canonical_bytes` call and the private
  prepared-result path, while rejecting a return of the proportional
  transaction clone or `submitted_json` re-encoding.
- `v2_sweep_enters_by_rpc_and_gossip_and_comes_out_in_selection` retains a
  real signed RPC admission, mempool retention and proposal-selection path,
  with the independent gossip path as control.
- `sendrawtransaction_reply_names_the_kind_and_disclaims_the_hash` retains the
  externally visible accepted/duplicate receipt contract.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  prepared_submission_reuses_large_canonical_owner_with_exact_reply_parity \
  --offline
# 1 passed; 0 failed; 621 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  rpc_submission_moves_one_prepared_transaction_and_canonical_owner --offline
# 1 passed; 0 failed; 621 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  v2_sweep_enters_by_rpc_and_gossip_and_comes_out_in_selection --offline
# 1 passed; 0 failed; 621 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  sendrawtransaction_reply_names_the_kind_and_disclaims_the_hash --offline
# 1 passed; 0 failed; 621 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 603 passed; 0 failed; 19 ignored; 62.69s
```

The signed RPC/gossip focus ran outside the restricted sandbox because its
engine fixture binds a localhost transport.

## Residual boundary

- The canonical mempool key and its distinct transport owner remain required;
  dual transport can still require a second frame owner.
- RPC hex decoding, the decoded transaction's final owned fields, canonical
  encoding, successful-receipt SHA3 and admission cryptography remain.
- The public `submitted_json` convenience function still canonicalizes when
  called independently; the production engine path is the owner-reuse path.
- This removes repository-owned duplicate work, not kernel/libp2p copies or an
  exact heap/RSS quantity.
- Hosted CI, release signing, deployment, rollback and fleet qualification
  remain outside source verification.
