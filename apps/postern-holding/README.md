# Postern Labs holding site (posternlabs.com and blochprotocol.io)

The posternlabs.com home page presents Postern Labs Ltda as the holding company and treasury of
the group, Bloch Inc as its wholly owned subsidiary and Bloch Protocol as the network, following
the blochinc.xyz layout (`public/holding/bloch-site.css` and `corporate.css` are copies of the
blochinc.xyz stylesheets; `holding.css` adds the group components).

`worker.js` serves the same homepage, `/upgrades` and `/holding/*` assets on
`posternlabs.com`, `blochprotocol.io` and `www.blochprotocol.io`. Every other path
(wallet, protocol, docs, supply, releases, API routes, ...) passes through to the
existing Pages origin unchanged. The Worker does not redirect either domain.

Corporate facts come from the published blochinc.xyz structure section; product statuses from
the published blochinc.xyz and posternlabs.com pages. Update them there first.

    node --test test/worker.test.mjs
    wrangler deploy --config apps/postern-holding/wrangler.toml

Before deployment, record the active Worker version and route configuration. To
roll back content, use `wrangler rollback <previous-version> --name posternlabs-holding`.
Restore the previous route configuration separately if rolling back a route change.
