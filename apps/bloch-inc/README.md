# Bloch Inc institutional website

Static institutional website for `blochinc.xyz`, based on the September 2026 Bloch Inc institutional overview.

The site intentionally preserves the source material's qualification language:

- Bloch Inc incorporation in Panama is in progress.
- The wallet is described as public beta.
- DEX software is described as a development preview.
- Cross-chain aggregator deployment is unverified.
- Bloch L2 execution components are in development; a complete public node and Bloch L1 settlement are pending.
- ECDSA is described only as the Bloch L2/EVM authorization model; native Bloch L1 authorization remains ML-DSA-65 + Falcon-1024.
- Bridge qualification is in progress and public asset transfers are not enabled.

## Local preview

```sh
python3 -m http.server 4173 --directory apps/bloch-inc
```

## Cloudflare Pages

The site is dependency-free. Deploy `apps/bloch-inc` as the static asset directory.
