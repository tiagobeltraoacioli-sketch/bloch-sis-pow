# Bloch Inc institutional website

Static institutional website for `blochinc.xyz`. The product and services roadmap is based on `Bloch_Inc_Products_Services_EN_v3.pdf` and the current repository status reviewed on 23 September 2026.

The site intentionally preserves the source material's qualification language:

- Bloch Inc incorporation in Panama is in progress.
- The wallet is described as public beta.
- DEX software is described as a development preview.
- Cross-chain aggregator deployment is unverified.
- Bloch L2 execution components are in development; a complete public node and Bloch L1 settlement are pending.
- ECDSA is described only as the Bloch L2/EVM authorization model; native Bloch L1 authorization remains ML-DSA-65 + Falcon-1024.
- Bridge qualification is in progress and public asset transfers are not enabled.
- Bloch Verify has an offline comparison MVP; authenticated operator evidence and a production service remain proposed.
- Bloch Data + Dev Cloud, Treasury + Pay, Bloch Markets and Bloch LatAm are roadmap lines, not activated services.
- Pix, Open Finance, Drex, DvP and PvP are partner-dependent concepts. The site makes no claim of production rail connectivity or regulated authorization.

The roadmap uses four delivery gates: reliable base, data and integration, value workflows, then markets and networks. The global line begins with reconciliation software; the LatAm line begins with observation and authorized-partner pilots.

The complete 16-slide English presentation is `downloads/Bloch_Inc_Products_Services_EN_v4.pdf`. To rebuild it, install ReportLab and run:

```sh
python3 -m pip install reportlab
python3 apps/bloch-inc/build_deck.py
```

## Local preview

```sh
python3 -m http.server 4173 --directory apps/bloch-inc
```

## Cloudflare Pages

The site is dependency-free. Deploy `apps/bloch-inc` as the static asset directory.
