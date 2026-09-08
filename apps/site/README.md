# Postern Labs website

The approved Postern Labs website lives in `apps/site/`. This is the source for the informational pages of posternlabs.com. The implementation uses static HTML, shared CSS, and a small navigation enhancement; no build step is required.

Run `python3 -m http.server 8080 --directory apps/site` from the repository root. Validate with `python3 scripts/check-postern-site.py` and `node --check apps/site/assets/site.js`.

This directory contains the homepage, protocol, migration, supply, developer guidance, documentation, brand, and missing-page views. It keeps the existing wallet, RPC, explorer, developer portal, and download links. Read `docs/DEPLOYMENT.md` before a production cutover: those services are separate resources.

The approved design uses #101211 ground, #161916 panels, #F2F0E7 text, and #C8FA72 accents. The arch mark is the existing Postern DEX mark; its notice is in THIRD-PARTY-NOTICES.md. Source and historical-content notes are in docs/CONTENT-SOURCES.md.

Changes in this directory do not deploy the production domain. A separate standalone GitHub repository can be created later if desired; this directory is already a complete maintainable source package.
