# Official Falcon-1024 round-3 verification vectors

The [Falcon project](https://falcon-sign.info/) publishes its
[round-3 submission archive](https://falcon-sign.info/falcon-round3.zip), including
the NIST API and KAT response files. Downloaded September 17, 2026:

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `falcon-round3.zip` | 4,015,378 | `d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47` |
| `falcon-round3/KAT/falcon1024-KAT.rsp` | 1,757,286 | `036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d` |
| `falcon1024-round3.json` | 32,300 | `b4cbb8c7df88e6eb5e75ed8669c1b95777a4e07cf5b0691fb3ce37818498fbd6` |

`extract-falcon-round3.py` verifies both upstream hashes, selects original counts
0, 1 and 99, and retains only count, message length/message, public key and signed
message length/signed message. Hex is normalized to lowercase without changing
decoded bytes. No signing seeds or secret keys are copied. Reproduce with:

```sh
python3 crates/bloch-crypto/tests/vectors/extract-falcon-round3.py \
  /path/to/falcon-round3.zip \
  crates/bloch-crypto/tests/vectors/falcon1024-round3.json
```

The tests pin the extracted digest and exact case IDs so missing cases cannot
silently turn verification into an empty loop. Expected data comes from the
published archive, never from Bloch's signer.

## Encoding and scope

The archive's `Reference_Implementation/falcon1024/falcon1024int/nist.c` encodes
a signed message as `u16BE(signature length) || nonce40 || message || 0x2a ||
compressed polynomial`. The signature length includes the `0x2a` marker. The
pinned PQClean detached API in `pqcrypto-falcon` expects `0x3a || nonce40 ||
compressed polynomial`. The test checks lengths/message placement/marker and
rearranges those exact public bytes; it does not re-sign or regenerate a vector.

All three external signatures verify through production `crypto::falcon::verify`.
Changed message, nonce or public key and a truncated signature fail. A second
test combines each official Falcon half with a freshly signed ML-DSA half and
exercises production hybrid suite 1; corrupting either half fails. Only the
Falcon half is an official KAT in that combined fixture.

This qualifies these round-3 verification cases on the compiled backend, not all
Falcon implementations, signing/key generation, a future FN-DSA standard, FIPS
certification or overall consensus security. Known historical signature
canonicality and raw-envelope ambiguity questions remain separate. No production
algorithm, signature encoding or activation rule changed.
