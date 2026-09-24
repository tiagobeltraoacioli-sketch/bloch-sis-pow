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
| Access | No hosted private account store or multi-tenant service | SSO/MFA, role separation, authorized exports, tenant isolation and reviewer signatures |
| Retention | No application persistence; manual Clear | Encryption, key custody, legal holds, retention schedules, rights handling and verifiable disposal |
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
