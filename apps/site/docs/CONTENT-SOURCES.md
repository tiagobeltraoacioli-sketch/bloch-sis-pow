# Content provenance

Reviewed: 2026-09-08. Source statements are not new live network measurements.

| Source | Use |
| --- | --- |
| https://posternlabs.com/ | Existing scope, ecosystem, production wallet and download links |
| https://posternlabs.com/protocol | Hybrid authorization, configured timings, consensus architecture, Coherence limitations |
| https://posternlabs.com/migration | Terminal height, snapshot counts, migration date, automatic carryover |
| https://posternlabs.com/supply | Exact allocations, published vesting correction, historical concentration |
| https://posternlabs.com/build | Historical node-operation context and participation caveats |
| https://posternlabs.com/docs | Dossier, review status and documentation scope |
| https://posternlabs.com/brand | Distinction between the protocol sphere identity and the Postern identity |
| https://github.com/tiagobeltraoacioli-sketch/postern-dex | Approved frontend design, arch asset, preview-only DEX status and EVM authorization boundary |

The DEX repository was observed at `f14ee3d77109c4558793c11f3c8d3c5715a2152b`. Its approved palette and mark were inspected in the available local checkout. The repository is private; links may require access.

## Editorial decisions

- Recast the homepage as the Postern Labs ecosystem entrypoint while retaining protocol, migration, supply, brand, build, and documentation pages.
- Retain exact historical allocation values and their correction: designed vesting was not enforced at genesis. Avoid the older homepage's incompatible vesting wording.
- Keep the 2026-09-05 verification-window date in the past. Do not turn recent validator-development work into an unverified claim that the live network accepts deposits.
- Link to the existing wallet and explorer; do not invent a live DEX URL, liquidity, token price, market cap, RPC status, or network uptime.
- The old homepage includes conflicting read-only/broadcast and wallet-chain statements. Avoid repeating those as current state. Direct operational readers to deployed release and endpoint verification.
- Label the old extension download as an archived developer build, rather than presenting version 0.1.0 as the latest release.
- The hero artwork is original AI-generated abstract brand imagery, not a scientific plot or a depiction of observed network topology.
- Condense legacy technical prose into focused reference pages. Full operational details remain in the existing dossier, code, developer portal, and operator documentation.

## Validation record

The authored site passes local structural and asset checks and JavaScript syntax validation. The allocation values total exactly 100,000,000,000 BLCH. The source website's existing visual design was inspected in the browser. Browser rendering, device emulation, and end-to-end QA of the new website were not performed in this delivery.
