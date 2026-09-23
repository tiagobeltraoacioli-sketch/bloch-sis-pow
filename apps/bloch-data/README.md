# Bloch Data + Dev Cloud website

Static product-roadmap site for `blochdata.xyz`.

The page distinguishes the public explorer and existing historical records from the proposed managed Data + Dev Cloud service. An EVM-side anchored in-memory canonical indexer core exists in `bloch-products`; it does not provide durable storage, an API, webhooks or a finality proof. Those are delivery milestones, not current service claims.

The financial-market section maps existing portfolio concepts into partner-facing data software: Proof Ledger position and reserve evidence, reconciliation workflows, asset-lifecycle data and DvP/PvP evidence research. The portfolio records Proof Ledger as buildable non-settlement software and asset lifecycle/DvP/PvP as research and partner pilots. The site does not claim regulated operations or live institutional integrations.

Preview locally:

```sh
python3 -m http.server 4174 --directory apps/bloch-data
```

Deploy the directory as a Cloudflare Pages static site.
