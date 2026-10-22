# Postern Labs holding site (posternlabs.com and blochprotocol.io)

The posternlabs.com home page presents Postern Labs Ltda as the holding company and treasury of
the group, Bloch Inc as its wholly owned subsidiary and Bloch Protocol as the network, following
the blochinc.xyz layout (`public/holding/bloch-site.css` and `corporate.css` are copies of the
blochinc.xyz stylesheets; `holding.css` adds the group components).

`worker.js` serves the same homepage, `/upgrades` and `/holding/*` assets on
`posternlabs.com`, `blochprotocol.io` and `www.blochprotocol.io`. Every other path
(wallet, protocol, docs, supply, releases, API routes, ...) passes through to the
existing Pages origin unchanged. The Worker does not redirect either domain.

The original Institutional Dossier 2.0 is also served at the established URL
`/Bloch-SIS-PoW-Institutional-Dossier-EN.pdf`. Its bytes are preserved from the
historical Pages deployment `52b26b60.posternlabs.pages.dev` (13 August 2026
edition): SHA-256 `51f8758cdf3f253c7acfab7542f1b7e0e3a80225d066e51af8f9b917f9cb13d7`.
The homepage identifies it as a historical edition, separate from current releases.

Corporate facts come from the published blochinc.xyz structure section; product statuses from
the published blochinc.xyz and posternlabs.com pages. Update them there first.

    node --test test/worker.test.mjs
    wrangler deploy --config apps/postern-holding/wrangler.toml

Before deployment, record the active Worker version and route configuration. To
roll back content, use `wrangler rollback <previous-version> --name posternlabs-holding`.
Restore the previous route configuration separately if rolling back a route change.
