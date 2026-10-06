# Postern Labs holding site (posternlabs.com home page)

The posternlabs.com home page presents Postern Labs Ltda as the holding company and treasury of
the group, Bloch Inc as its wholly owned subsidiary and Bloch Protocol as the network, following
the blochinc.xyz layout (`public/holding/bloch-site.css` and `corporate.css` are copies of the
blochinc.xyz stylesheets; `holding.css` adds the group components).

`worker.js` is routed on `posternlabs.com/*`. It serves `/` and `/holding/*` from `public/` and
passes every other path (wallet, protocol, docs, supply, releases, ...) to the existing Pages
project unchanged, so those pages are not redeployed. blochprotocol.io keeps the Pages site.

Corporate facts come from the published blochinc.xyz structure section; product statuses from
the published blochinc.xyz and posternlabs.com pages. Update them there first.

    node --test test/worker.test.mjs
    wrangler deploy --config apps/postern-holding/wrangler.toml

Rollback: `wrangler delete --name posternlabs-holding` (or remove its route); the Pages home page
then serves again.
