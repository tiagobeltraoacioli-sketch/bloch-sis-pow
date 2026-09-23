# Bloch Data + Dev Cloud website

Static product-roadmap site for `blochdata.xyz`.

The page distinguishes the public explorer and existing historical records from the proposed managed Data + Dev Cloud service. An EVM-side anchored in-memory canonical indexer core exists in `bloch-products`; it does not provide durable storage, an API, webhooks or a finality proof. Those are delivery milestones, not current service claims.

Preview locally:

```sh
python3 -m http.server 4174 --directory apps/bloch-data
```

Deploy the directory as a Cloudflare Pages static site.
