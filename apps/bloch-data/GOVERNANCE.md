# Bloch Data governance and regulatory integration register

Source review: 24 September 2026. This is a scoped implementation register and
starting reference catalog, not a legal determination or compliance certificate.
The institution must validate licenses, activities, data classes, controller and
processor roles, jurisdictions, effective dates, amendments and legal basis.
The register is non-exhaustive; applicable requirements must be added and reviewed.

## Runtime controls and deployment responsibilities

| Area | Implemented in the local workbench | Required institutional integration |
| --- | --- | --- |
| Data movement | Files stay in browser memory; connection requests blocked by CSP; no upload endpoint | Approved workstation/browser, host distribution and change control |
| Data minimization | Fixed module schema; unknown fields rejected; source values displayed locally | Select permitted datasets, tokenize identifiers, classify fields and approve purpose |
| Correctness | Exact decimal/integer comparison, bounded parsing, duplicates always review | Authenticate sources, align cutoffs, determine completeness and operational truth |
| Traceability | Original file digests, rule/configuration version, normalized records, exact report digest and local recomputation verifier | Sign reviews, independently retain evidence, protect time and prevent rollback |
| Exception review | Separate unsigned journal bound to exact report bytes; ordered annotations; original outcomes preserved | Authenticate reviewers, authorize decisions, enforce separation of duties and retain protected history |
| Investigation workflow | Local record/latest-note search, combined filters, full-report charts, explicit queue order and filtered CSV bound to evidence/journal digests | Approve operating priorities, control private exports and independently assess financial exposure; counts are not risk scores |
| Case retention | Single plaintext case with original CSVs, evidence, complete journal, configuration and local receipt; bounded manifest/component verification and recomputation on reopening | Approve storage, encryption, recipients and access; retain independent digests or signed checkpoints; enforce retention and protect against rollback |
| Snapshot comparison | Verify two compatible cases; compare exact normalized record multisets and per-key review histories; retain both case digests and originals | Align source roles, cutoffs and dataset scope; establish chronology and authority; approve corrections and review continuity separately |
| Multi-case oversight | Bounded, fully verified case selection; per-case outcome chart, latest-review matrix and full-set summary exports | Establish common cutoffs/scope, choose intended snapshots, assess exposure independently and protect metadata |
| Access | No hosted private account store or multi-tenant service | SSO/MFA, role separation, authorized exports, tenant isolation and reviewer signatures |
| Retention | No application persistence; manual Clear; optional password-encrypted copy of a complete audit bundle | Institutional key custody, recipient access, legal holds, retention schedules, recovery, rights handling and verifiable disposal |
| Cross-border data | No application transfer of source files | Validate residence, recipients, transfer mechanisms and lawful hosting |
| Incident/continuity | No operational claim | Monitoring, incident register/reporting, response, backup, recovery and testing |
| On-chain | Publication and signing absent; imported receipts compared as observations | Reviewed hiding commitment, approval, signer, payload support, inclusion/canonicality/finality verification |
| Regulatory reports | None submitted | Institution-specific adapters, authorized signoff, supervisory submission and receipt tracking |

Private reports contain source records and configuration metadata. Export is an
explicit local user action, not an anonymization step. A file hash is not a
privacy-preserving public artifact. Do not publish reports, account references,
source digests, retention/legal metadata or commitment openings to a public chain.
A chain txid alone does not bind the report or prove correctness/finality.

The v2 verifier checks local consistency against both original CSV files and
optionally an independently retained report digest. It uses the same versioned
comparison implementation, not a separately certified audit engine. Without a
trusted external reference a coherent replacement of all files can pass. Review
labels and timestamps are self-declared; an unsigned journal can be rewritten or
rolled back outside the app. Its digest must be retained independently if used
for subsequent integrity checks. An explained exception remains a discrepancy.
No signature, regulated approval, immutable log or legal compliance is inferred.

The v3 investigation queue is a view over the existing comparison and latest
review annotations. Filtering and explaining exceptions do not remove them from
the evidence or mark them as matched. Charts always summarize the full report;
filtered exports identify their scope and include private reviewer notes.
Search ignores accents/case only for retrieval, never for record matching. A
filtered CSV is a convenience artifact; retain the complete evidence and review
JSONs and protect them using institutional storage and access controls.

The v4 case file includes private source data in plaintext. Preparing a case is
not anonymization or on-chain publication. Component checksums establish local
integrity relationships; without a trusted retained reference an attacker can
replace a coherent case. Verification recomputes the comparison and checks the
embedded receipt, but does not attest identity, source truth, protected time or
the latest history. Institution-controlled encryption, signatures, approvals,
retention and access remain external integration responsibilities.

The v5 comparator labels baseline and candidate according to user selection,
not trusted chronology. Exact-key additions/removals do not establish economic
continuity or explain missing scope. A transition to Matched is a comparison
outcome, not approval, independent source validation or settlement. Original
records and journals are preserved; review decisions are never copied to another
case automatically. Full comparison JSON contains private data from both cases
and requires the same institutional retention and access controls as its inputs.

## Brazil

- [LGPD, Law 13.709](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm): review purpose, lawful basis, data rights, minimization, security and transfers.
- [ANPD incident rules, Resolution 15/2024](https://www.gov.br/anpd/pt-br/assuntos/noticias/anpd-aprova-o-regulamento-de-comunicacao-de-incidente-de-seguranca): institution incident handling and reporting workflow.
- [ANPD international transfer rules, Resolution 19/2024](https://www.gov.br/anpd/pt-br/assuntos/assuntos-internacionais/transferencia-internacional-de-dados): evaluate transfer mechanisms and recipient scope.
- [CMN 4.893](https://www.bcb.gov.br/estabilidadefinanceira/exibenormativo?numero=4893&tipo=Resolu%C3%A7%C3%A3o+CMN) and [BCB 85](https://www.bcb.gov.br/estabilidadefinanceira/exibenormativo?numero=85&tipo=Resolu%C3%A7%C3%A3o+BCB): determine the applicable cybersecurity/outsourcing scope from consolidated texts. Their covered institutions differ; brokers and DTVMs require specific scope review.
- [CMN 4.968](https://www.bcb.gov.br/estabilidadefinanceira/exibenormativo?numero=4968&tipo=Resolu%C3%A7%C3%A3o+CMN): institutional internal controls; review amendments.
- [CVM 35](https://conteudo.cvm.gov.br/legislacao/resolucoes/resol035.html): securities intermediary rules and procedures.
- [CVM 21](https://conteudo.cvm.gov.br/legislacao/resolucoes/resol021.html): portfolio-manager activities and internal procedures.
- [CVM 175](https://conteudo.cvm.gov.br/legislacao/resolucoes/resol175.html): fund operation, disclosures and applicable annexes.
- [CVM 50](https://conteudo.cvm.gov.br/legislacao/resolucoes/resol050.html): PLD/FTP scope. This workbench does not implement an AML program or filing workflow.

Extend the institution's register with bank secrecy, accounting/COSIF where
applicable, tax/reporting, books-and-records retention, market infrastructure,
B3/BSM and other self-regulatory or contractual requirements. Their applicability
and technical adapters have not been certified here. Imported rail labels do not
activate Pix, STR, Open Finance or B3 access.

## Global

- [GDPR, Regulation 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng): assess territorial scope, processing principles, rights, privacy by design, security and transfers.
- [DORA, Regulation 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng): assess financial-entity scope, ICT resilience and third-party arrangements.

The Global preset is an extensible data contract, not a worldwide legal ruleset.
Add local banking/securities/privacy/recordkeeping and reporting requirements,
with named owners, evidence, review dates and explicit applicability decisions.
The configuration's GDPR flag is an institution declaration, not a legal test.

## LatAm starting profiles

- [Mexico: current LFPDPPP](https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf). Review CNBV/Banxico obligations separately.
- [Colombia: SIC transfer guidance](https://sedeelectronica.sic.gov.co/delegatura/proteccion-de-datos-personales/normas-corporativas-vinculantes) and [general-law scope/exclusions](https://www.sic.gov.co/content/%C2%BF-qu%C3%A9-tipo-de-datos-personales-no-le-son-aplicables-las-disposiciones-de-la-ley-1581-de-2012). Determine Law 1581 versus financial-data Law 1266 scope and financial-supervision duties.
- [Chile: Law 21.719](https://www.bcn.cl/leychile/navegar?i=1209272). Review existing Law 19.628, CMF obligations and the transition taking effect on 1 December 2026.
- [Argentina: Law 25.326](https://www.argentina.gob.ar/normativa/nacional/ley-25326-64790/texto). Add AAIP, BCRA and CNV requirements relevant to the business.

These country profiles implement formatting presets and explanatory context;
sector-rule enforcement for each country remains an institutional integration.
For every additional regulation record: official source, version/effective date,
activity and data scope, applicability owner, required control, implementation,
evidence reference, remaining gap and next review. Review transitions rather than
assuming a newly published rule already applies.

## Source preparation boundary (v6)

Preparation applies explicit, independently configured source-column mappings
and existing module validation to local extracts. Extra-column exclusion needs
fresh acknowledgement after source/mapping/format changes. It preserves row
order and duplicate multiplicity, rejects missing mapped fields, and records
normalization counts plus complete original/prepared row references. There is
no inferred identity, automatic correction or institution-specific source
adapter. File and record limits are bounded in both source and canonical output.

The separate unsigned receipt binds exact original and prepared file hashes,
formats, mappings, exclusions and output configuration. Retain the original
extracts, prepared outputs and receipt together under the institution's controls.
Later evidence/case files bind to prepared CSVs, and do not embed this receipt or
original extracts. The UI states that provenance boundary before loading. This
release supports receipt verification as described below. The receipt has no source
cell values but can still contain sensitive filenames, headers and policy
metadata. Prepared CSVs contain private records and preserve formula-like text.
No retention enforcement, encryption, identity authentication, data-subject
workflow, regulatory certification or Bloch publication is added by preparation.

## Preparation verification boundary (v7)

The local verifier independently recomputes a retained preparation receipt from
its original extracts, requires exact prepared CSV bytes, and validates every
mapping, declared exclusion, normalization count and row reference. Optional
reconciliation evidence must match the full applied configuration, data mode and
prepared source bytes; its outcomes are independently recomputed. Review history
is neither supplied nor verified in this workflow. Existing evidence/case
verification remains the path for retained review journals.

Optional, independently retained preparation and evidence digests bind the check
to specific retained file identities. Without those references, a coherent
replacement can pass. A reproduced mapping does not establish authorized data
exclusion, source completeness, institutional identity or chronology. The graph
represents checked local file relationships, not on-chain transactions or a
signed chain of custody. No publication, retention enforcement, cryptographic
signature, regulatory certification or rollback protection is added.

The new verification receipt records file digests, counts and scoped check
results without raw source records. The original extracts and preparation
receipt remain separate from six-component case files. Loading verified prepared
files creates a new reconciliation input session and does not resume supplied
evidence or review history. Clear/input changes invalidate pending results;
processing remains in browser memory with no data upload or persistence.

## Complete audit bundle boundary (v8)

An audit bundle embeds the unchanged case, unchanged preparation receipt and both
original extracts, plus a freshly recomputed preparation verification receipt.
All component hashes, original/prepared relationships, case rules/outcomes,
configuration and review bindings are checked at creation and on reopening. This
adds a retained artifact for the full lineage without changing existing evidence,
review, preparation or six-component case schemas.

Original columns excluded during preparation are present in the bundle's raw
extracts. The bundle also includes private prepared records and review notes.
It is plaintext, unsigned and unencrypted; its storage, access, retention and
transfer must remain inside the institution's approved controls. Nothing is
published to a network or automatically extracted to the filesystem. The whole
serialized file is limited to 96 MiB, with separately bounded components.

Optional independent case/preparation references gate creation; those checks do
not become assertions of independent references inside the package. Only a
separately retained whole-bundle digest binds a reopening operation to that
external identity. Internal component hashes establish local consistency, not
source identity, completeness, authorized exclusion, approved decisions,
chronology, authenticated custody or on-chain inclusion. The bundle provides no
signature, encryption, rollback prevention or regulatory certification.

Opening resumes the exact case and review journal; subsequent edits in the
workbench do not rewrite the retained bundle. Updated work requires a newly
exported case and bundle. The synthetic example and UI state identify data mode;
that mode remains a declaration, not evidence of institutional provenance.

## Password-encrypted copy boundary (v9)

The optional encrypted envelope protects a retained complete audit bundle using
native Web Crypto AES-256-GCM. Creation first verifies the plaintext bundle;
unlocking authenticates decryption and then verifies all inner components and
relationships again. The exact original bundle/case/evidence/review bytes remain
unchanged. Unencrypted exports remain explicitly labelled and available.

PBKDF2-HMAC-SHA256 derives the nonextractable AES key with 600,000 iterations and
a fresh 32-byte random salt. Each export also has a fresh 12-byte random IV and
128-bit tag. Header fields are authenticated; private names, module, source data,
review notes and plaintext hashes are encrypted. Format and ciphertext length
remain observable. See the [README](README.md#encrypted-format-and-independent-implementation)
for the complete wire format and official technical references. Algorithm choices
are not a claim of FIPS validation or certified institutional security.

The user controls the password and its custody; there is no reset, escrow or
server-side recovery. A retained file permits offline guessing, so password
strength matters. Possession of the password allows decryption and replacement;
authenticated encryption does not identify an institution or reviewer, attest
source truth/completeness, prevent rollback or prove authorized data exclusion.
Optional independently retained ciphertext/plaintext digests identify exact
copies, not their authority or chronology. Institutional identity, recipient
access, revocation, signatures, managed keys and recovery remain external controls.

Passwords and keys are not persisted by application code. Password fields clear
on attempts, and input changes/clear/lock invalidate stale asynchronous results.
Unlocking exposes plaintext in local browser memory. Lock clears only its own
workspace; cases opened elsewhere and downloads persist independently. Buffer
zeroing is best effort, not a secure-erasure guarantee for browser memory. The
feature does not protect against a compromised browser/device or eliminate
original/plaintext copies, legal retention duties or approved storage controls.
No chain publication or regulatory certification is added.

## Multi-case overview boundary (v10)

The dashboard verifies all six components of every selected case, recomputes its
comparison and validates its retained review journal before showing any results.
Independent case digests are optional and reported per case. A bad case or digest
fails the entire selection. Limits are 12 cases, 64 MiB per file and 96 MiB total;
all data remains in browser memory. No private files are uploaded or persisted.

Counts sum observations within each retained case. Different evidence files can
refer to overlapping financial records or periods, so totals are not unique
transactions, account balances, exposure or audit materiality. Modules, regions
and configurations may differ. No amounts, valuations or currencies are added.
Exact duplicate cases and alternate review snapshots of the same evidence are
rejected; the user must choose the intended snapshot. File order and local times
do not establish chronology, protected custody, freshness or equal cutoffs.

The review matrix counts the last retained state per exception, while a separate
journal-entry count retains all annotations. Explained does not mean matched,
settled or approved. Reviewers remain self-declared. Opening a case preserves its
exact retained evidence and journal; later workbench annotations do not update
the overview. The dashboard does not certify original extract preparation; use
complete audit bundles to verify that separate upstream relationship.

Filters change charts and visible metrics. JSON/CSV exports explicitly include
all selected cases. These unsigned, unencrypted summaries contain counts,
filenames, profile identifiers and digests but no raw records or review notes.
Metadata remains subject to institutional handling. Summary and case-set digests
identify bytes/sets, not provenance or authority; retain the original cases.
No source authentication, approval workflow, regulatory certification, financial
risk score, institutional access control or on-chain verification is added.
