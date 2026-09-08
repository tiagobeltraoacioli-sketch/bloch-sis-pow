# Deployment notes

## Scope

This project replaces the informational website. It is not a replacement wallet, RPC gateway, block explorer, download server, or validator node. Private Sites publication is a review copy and does not change `posternlabs.com` or its DNS.

Serve the authored `apps/site/` directory on any static host. Use a real HTTP 404 response for missing paths and `404.html` as the body. There is no SPA fallback requirement. Extensionless legacy reference routes can redirect to their corresponding `.html` documents; `_redirects` includes these mappings for compatible hosts. `/products.html` maps to the ecosystem section.

## Preserve existing production resources

| Path or origin | Existing role |
| --- | --- |
| `/apps/postern/` | Existing wallet application and its assets |
| `/g4rpc` | Existing RPC gateway; preserve server-side handling |
| `/dl/` | Existing published extension archives and checksums |
| `/Bloch-SIS-PoW-Institutional-Dossier-EN.pdf` | Existing institutional dossier |
| Other existing PDFs, genesis manifests, and downloads | Existing reference links; retain the deployed artifact set |
| `https://blochl1.com/` | Separate explorer |
| `https://blochprotocol.dev/` | Separate developer portal |

Do not replace the entire existing production document root with this folder or point the production domain at a static-only deployment until these paths are explicitly preserved. Use route-based serving for the informational pages, or migrate the existing services separately. This delivery deliberately uses absolute links to the current production wallet, downloads, and dossier so the private review copy opens the actual resources.

## Headers

`apps/site/_headers` specifies a restrictive content policy, frame restriction, MIME-sniffing protection, and referrer policy on the listed informational routes and assets for compatible hosts. The header rules deliberately exclude the wallet and RPC paths. Other hosts must configure equivalent response headers explicitly. HTML pages also include a CSP meta tag; `frame-ancestors` cannot be enforced by a meta tag and therefore belongs in a response header. The website has no inline scripts, third-party asset requests, or JavaScript network requests.

## Before a production cutover

Confirm release-dependent copy, preserved application routes, downloadable resources, response headers, mobile rendering, keyboard navigation, and the domain's existing redirects. No automatic public deployment or DNS mutation is configured by this repository.
