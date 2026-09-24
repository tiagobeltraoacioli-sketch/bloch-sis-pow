# Bloch Inc institutional website

Static institutional website for `blochinc.xyz`. The product and services roadmap is based on `Bloch_Inc_Products_Services_EN_v3.pdf` and the current repository status reviewed on 23 September 2026.

The site intentionally preserves the source material's qualification language:

- Bloch Inc incorporation in Panama is in progress.
- Postern Labs Ltda (Brazil) holds 100% of Bloch Inc's share capital. Postern Labs Ltda is in the process of transforming into Postern Labs S.A. These company-provided details were added on 24 September 2026; neither process is presented as completed.
- Postern Labs Ltda reports holdings of 27 billion Bloch Protocol Tokens (BLCH), or 27,000,000,000 tokens, and is described as a major BLCH holder. This company-provided disclosure was added on 24 September 2026, separately from the 100% equity ownership of Bloch Inc. It is not an independently verified on-chain balance, supply percentage or holder ranking.
- Bloch Ops links to published network entry points and operator guidance. Its delegation setup and managed wallet/PQ Shield interfaces are staged work. The custom domain `ops-blochinc.xyz` is active on the Cloudflare Pages deployment.
- The wallet is described as public beta.
- DEX software is described as a development preview.
- Cross-chain aggregator deployment is unverified.
- Bloch L2 execution components are in development; a complete public node and Bloch L1 settlement are pending.
- ECDSA is described only as the Bloch L2/EVM authorization model; native Bloch L1 authorization remains ML-DSA-65 + Falcon-1024.
- Bridge qualification is in progress and public asset transfers are not enabled.
- Bloch Verify has an offline comparison MVP; authenticated operator evidence and a production service remain proposed.
- Bloch Data + Dev Cloud, Treasury + Pay, Bloch Markets and Bloch LatAm are roadmap lines, not activated services. The `/markets/` page presents Bloch Markets as software infrastructure for eligible digital assets. Ustav's programmable token lifecycle and separate native pair/pool prototypes run locally, but Ustav is not integrated into the live Genesis-4 node and no native Bloch DEX AMM is live.
- Bloch Markets does not offer securities issuance, brokerage, custody, fiat payment rails or operation of a regulated exchange. Its standalone service site is deployed at `blochmarkets.pages.dev`; `blochmarkets.xyz` is the custom domain for that Pages project.
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

## Chain-data platforms — 24 September 2026

The homepage introduces three distinct destinations, linked from the hero, navigation,
current-status ledger, ecosystem links and footer:

- **Bloch Explorer — blochl1.com:** Bloch Genesis-4 / BLCH only; graph atlas, receipts,
  validators, finality, indexed balances and evaluated telemetry models.
- **Bloch Space — bloch.space:** the institutional entry points emphasize Bitcoin/BTC
  and Ethereum, with direct network links. Space also retains its other network views.
- **Bloch Graphus — bloch-graphus.xyz:** bounded public-chain graph and balance analytics
  for BTC, ETH, Ethereum ERC-20 USDT/USDC and BLCH, with Constellation, Oculum and Analytics
  Lab. The old synthetic-only description and legacy Pages URLs have been replaced.
  Synthetic illustrations remain distinct from real source records; production AML
  scoring and ZK proofs are not claimed.

The three platform illustrations are decorative diagrams, not live network snapshots.
Existing downloadable presentations retain their version dates.

The same homepage section also highlights **Bloch Ops — ops-blochinc.xyz** as the
network operations portal, with direct links to its RPC catalog, validator guide,
wallet integration guide and PQ Shield reference work. Ops is also linked from the
closing ecosystem list. Delegation setup, managed wallet APIs and cross-chain PQ
Shield services retain their staged status.

## Red & Blue portal — 24 September 2026

The desktop/mobile navigation, BI-PoRB service card, closing ecosystem list and
footer link directly to `https://rednblue.space/portal/`. The portal provides
invitation-only organization access to Bitcoin, Ethereum and Bloch observations,
graphs, saved analyses, machine learning and scoped APIs. Red describes
sample-relative structural deviation; Blue describes observed-record completeness.
Neither is presented as a validated AML, credit or ownership assessment. The
separate `aml-blochinc.pages.dev` dashboard remains linked as a synthetic risk
preview.
