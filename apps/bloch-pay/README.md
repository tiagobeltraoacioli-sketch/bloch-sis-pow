# Bloch Pay

The institutional site at `blochpay.xyz` introduces Bloch as market infrastructure
for payments. The first functional release provides a local invoice workspace and
an integration design studio for banks, regulated PSPs, VASPs/PSAVs, custodians,
FX and liquidity providers, platforms and payment infrastructure operators.

## Available tools

- `/app/`: native BLCH receivables and payables, manually entered payment records,
  partial matches, excess amounts, void invoices, aging, outstanding due schedules
  and counterparty exposure. All financial arithmetic uses integer base units
  with eight decimal places, consistent with the Genesis-4 JavaScript SDK.
- JSON backup export and validated replacement import; invoice JSON and separate
  invoice/payment-record CSV exports. Spreadsheet formula prefixes are escaped.
- An installable PWA with a scoped, versioned offline shell. Invoices are kept in
  local browser storage, never uploaded by this app. There is no account sync or
  encryption layer. Browser clearing can remove the data; retain exported backups.
- `/app/integrations`: a route planner for Pix/BRL, SEPA and SCT Inst/EUR,
  ACH/USD, native BLCH and custom partner rails. It preserves exact source and
  destination amounts, participant roles and a supplied quote reference. Missing
  conversion terms are left unresolved; no FX rate, fee or rail availability is
  inferred. Non-bank digital-asset providers access fiat legs through qualified
  financial institutions, with the settlement partner still to be specified.
- A local sample-event state machine models acceptance, submission, settlement,
  beneficiary credit, failure and returns. It rejects out-of-order transitions
  and conflicting duplicate event IDs. Samples never change the draft's actual
  settlement status, and exported drafts always disable execution.
- `app/payment-api.openapi.json`: an OpenAPI 3.1 **design contract**, describing
  partner-scoped intents, idempotency, signed event ingestion, individual leg
  statuses and returns. No managed API endpoints or webhook receiver are deployed.
  The planner export is a design artifact, not an executable API request.

## Financial and integration boundaries

Payment records and transaction-output references are entered manually, not
independently verified. “Matched records” means the entered amount equals the
invoice amount; it does not assert transfer inclusion, finality or fiat settlement.
The app neither holds keys nor signs, broadcasts, collects or moves funds.

The partner model covers on/off ramps, asset transfers, conversion, liquidity,
funding, settlement and reconciliation. Production connections require participant
onboarding, permission/corridor checks, an agreed identity and transfer-information
model, custody/safeguarding allocation, partner quotes, authenticated server-side
adapters, signed events, replay protection and exception/recovery procedures.
None of those connections is activated in this release.

The responsible institution supplies fiat-rail settlement and beneficiary-credit
evidence. Bloch transaction finality is a separate observation. Credit and settlement
events may be followed by returns; the UI does not portray a chain transaction as
proof of completion of a fiat leg or a cross-border route as an atomic transfer.

Official rail references reviewed on 24 September 2026:

- [EPC scheme participation](https://www.europeanpaymentscouncil.eu/what-we-do/be-involved)
  and [SCT rulebook](https://www.europeanpaymentscouncil.eu/what-we-do/epc-payment-schemes/sepa-credit-transfer-sct/sepa-credit-transfer-rulebook-and).
- [Nacha: how ACH works](https://achdevguide.nacha.org/how-ach-works).
- [BCB: Pix participants and direct/indirect SPI access](https://www.bcb.gov.br/estabilidadefinanceira/participantespix).

These references describe the rails, not a partnership or authorization held by Bloch.

## Storage and validation

Backups require schema/version, network, asset and scale matches. Validation checks
unique invoice/record references, invoice relationships, real calendar dates,
positive bounded integer amounts, complete transaction-output references and no
duplicate output allocation. Limits are 1,000 invoices, 3,000 payment records and
2 MB per workspace. Unknown fields are discarded. Imports replace existing records
only after an explicit confirmation with invoice and record counts.

Failed persistence does not change the in-memory ledger. Stale tabs compare saved
data before writes and refuse to overwrite a newer version. This is a local preview,
not a transactional multi-user accounting database or tamper-resistant audit log.

## Checks

From the repository root:

```sh
node --test apps/bloch-pay/tests/model.test.mjs
node apps/bloch-pay/tests/browser.mjs
```

Browser checks need Playwright and Chrome/Chromium. Set `PLAYWRIGHT_MODULE` to a
module path if it is not installed in the repository and `CHROME_PATH` to an existing
browser executable. `PAY_ARTIFACTS` selects the screenshot/report directory. Without
a URL the script starts a local static server with Pages-style clean URLs. Passing
the preview/production origin runs the same checks in an isolated browser profile;
all mutations remain in that profile's local storage.

Coverage includes exact amounts, partial/excess reconciliation, invalid backups,
duplicate outputs, CSV injection, stale storage, partner/currency validation, event
ordering, export, three screen sizes, HTML escaping and offline reloads.

## Publication

Run `node apps/bloch-pay/stage.mjs /absolute/output/directory` to stage only the
public files. Do not publish tests or build tools. The Pages project is `bloch-pay`
with production branch `main`. The service worker is scoped to `/app/` and caches
only an explicit shell inventory; it never caches an API or partner response.
Cloudflare Pages canonicalizes `/app/integrations.html` to `/app/integrations`.
Increment the service-worker cache version when changing app shell assets after
this release. Updates wait for the user's update action before reloading the app.
