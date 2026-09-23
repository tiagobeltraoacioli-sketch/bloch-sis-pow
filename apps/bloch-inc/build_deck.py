#!/usr/bin/env python3
"""Build the September 2026 Bloch Inc products and roadmap presentation."""
from html import escape
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "downloads" / "Bloch_Inc_Products_Services_EN_v4.pdf"
W, H = 768, 432
DARK = HexColor("#0C100D")
PAPER = HexColor("#F7FAF5")
GREEN = HexColor("#C9FF69")
OLIVE = HexColor("#618243")
WHITE = HexColor("#F8FCF6")
MUTED = HexColor("#AAB8A9")
INK = HexColor("#141B15")
LINE = HexColor("#40513E")
PALE = HexColor("#EAF2E8")

c = canvas.Canvas(str(OUTPUT), pagesize=(W, H), pageCompression=1)
c.setTitle("Bloch Inc — Products, Services and Evidence-Led Roadmap")
c.setAuthor("Bloch Inc")
c.setSubject("Current Bloch ecosystem and proposed global and LatAm roadmap")

def t(x, y, value, size=11, color=WHITE, font="Helvetica"):
    c.setFillColor(color)
    c.setFont(font, size)
    c.drawString(x, y, value)

def para(x, top, width, value, size=12, color=WHITE, leading=None):
    style = ParagraphStyle(
        "body", fontName="Helvetica", fontSize=size,
        leading=leading or size * 1.37, textColor=color, spaceAfter=0,
    )
    p = Paragraph(escape(value), style)
    _, h = p.wrap(width, 1000)
    p.drawOn(c, x, top - h)
    return top - h

def frame(number, label, title, lead, light=False):
    bg, fg, accent = (PAPER, INK, OLIVE) if light else (DARK, WHITE, GREEN)
    c.setFillColor(bg)
    c.rect(0, 0, W, H, stroke=0, fill=1)
    t(46, 391, label.upper(), 10, accent, "Courier")
    t(626, 389, "Bloch Inc", 16, fg, "Helvetica-Bold")
    t(46, 340, title, 27, fg, "Helvetica-Bold")
    para(47, 314, 672, lead, 11.2, HexColor("#596659") if light else MUTED)
    c.setStrokeColor(HexColor("#B8C9B5") if light else LINE)
    c.setLineWidth(.5)
    c.line(46, 28, 722, 28)
    t(46, 14, "STRATEGIC ROADMAP  /  23 SEP 2026", 8,
      HexColor("#6D7B6C") if light else MUTED, "Courier")
    t(677, 14, f"{number:02d} / 16", 8,
      HexColor("#6D7B6C") if light else MUTED, "Courier")

def card(x, y, w, h, tag, title, body, light=False, note=None):
    fill = PALE if light else HexColor("#151E16")
    fg = INK if light else WHITE
    secondary = HexColor("#586758") if light else MUTED
    c.setFillColor(fill)
    c.setStrokeColor(HexColor("#B5C7B1") if light else LINE)
    c.roundRect(x, y, w, h, 9, stroke=1, fill=1)
    t(x + 16, y + h - 25, tag.upper(), 8.7, OLIVE if light else GREEN, "Courier")
    para(x + 16, y + h - 40, w - 32, title, 18, fg, 20)
    bottom = para(x + 16, y + h - 91, w - 32, body, 11, secondary, 15)
    if note:
        para(x + 16, max(y + 31, bottom - 15), w - 32, note, 8.5,
             OLIVE if light else GREEN, 12)

def three(number, label, title, lead, items, light=False):
    frame(number, label, title, lead, light)
    for i, item in enumerate(items):
        card(46 + i * 228, 75, 216, 205, *item, light=light)
    c.showPage()

def two(number, label, title, lead, items, light=False):
    frame(number, label, title, lead, light)
    for i, item in enumerate(items):
        card(46 + i * 344, 75, 332, 205, *item, light=light)
    c.showPage()

# 01 — Cover
c.setFillColor(DARK)
c.rect(0, 0, W, H, stroke=0, fill=1)
t(46, 388, "STRATEGIC VISION / PRODUCTS + SERVICES", 10, GREEN, "Courier")
t(45, 246, "Bloch", 94, WHITE, "Helvetica-Bold")
t(386, 246, "Inc", 94, GREEN, "Helvetica-Bold")
t(46, 188, "The next chapter of Bloch.", 31, WHITE, "Helvetica-Bold")
para(47, 158, 680,
     "What exists today. What Bloch Inc proposes next for Latin America and global markets. A roadmap built around evidence, security and utility.",
     14, MUTED, 19)
t(47, 49, "PRODUCT STAGES AND DELIVERY GATES / ENGLISH", 9, GREEN, "Courier")
c.setStrokeColor(LINE)
c.line(46, 28, 722, 28)
t(46, 14, "STRATEGIC ROADMAP  /  23 SEP 2026", 8, MUTED, "Courier")
t(677, 14, "01 / 16", 8, MUTED, "Courier")
c.showPage()

# 02 — Status ledger
frame(2, "01 / Current landscape", "The ecosystem today",
      "Five product lines, one operating L1 and access infrastructure — at different stages.", True)
rows = [
    ("L1 + Explorer", "Operating / qualify release", "Genesis-4 PoS, node, RPC, public explorer and historical receipts."),
    ("Wallet", "Public beta", "Native authorization, browser extension and a published JS exchange SDK."),
    ("DEX", "Development preview", "Interfaces and external EVM-chain pools; not production liquidity."),
    ("Aggregator", "Deployment unverified", "Route comparison in code; broad deployment has not been verified."),
    ("L2 + Bridge", "Integration / qualification", "Local execution and references; public settlement and transfers pending."),
]
for i, (name, status, body) in enumerate(rows):
    y = 274 - i * 45
    c.setStrokeColor(HexColor("#C0CEC0"))
    c.line(46, y - 12, 722, y - 12)
    t(47, y + 6, f"{i + 1:02d}", 9, OLIVE, "Courier")
    t(86, y + 4, name, 13, INK, "Helvetica-Bold")
    para(240, y + 13, 335, body, 9.4, HexColor("#596759"), 12)
    t(584, y + 5, status, 8.3, OLIVE, "Helvetica-Bold")
c.showPage()

three(3, "02 / What operates now", "A network with public evidence",
      "The foundation is usable; production service guarantees still require independent qualification.", [
          ("GENESIS-4", "Bloch L1", "Proof of stake produces blocks and exposes native transaction, balance and validator data."),
          ("PUBLIC INTERFACE", "Bloch Explorer", "Browse transactions, blocks, validators, finality and read-only historical receipts."),
          ("DEVELOPER ACCESS", "RPC + SDK", "Published JavaScript transfer construction and transaction query API for integrators."),
      ], True)

three(4, "03 / Access layer", "Wallet and exchange integration",
      "Current client capabilities are available at different assurance levels.", [
          ("PUBLIC BETA", "Postern Wallet", "On-device hybrid post-quantum signing for native Bloch. The wallet remains a public beta."),
          ("PUBLISHED SDK", "Genesis-4 JS", "High-level signed transfer bytes, UTXO selection, fee and epoch handling; no exchange-side serializer."),
          ("INTEGRATOR API", "TXID receipts", "Canonical indexed inputs, outputs and sat amounts with height, slot, confirmations and finality."),
      ])

three(5, "04 / Existing product lines", "Trade and cross-network work",
      "Current code and interface previews do not imply live settlement.", [
          ("PREVIEW", "Bloch DEX", "Market interfaces and external EVM-chain pools remain development software."),
          ("UNVERIFIED", "Aggregator", "Route comparison exists in code; broad deployment and partner coverage remain unverified."),
          ("INTEGRATION", "L2 + Bridge", "EVM execution components and bridge references exist; public asset transfers are not enabled."),
      ], True)

three(6, "05 / Strategic thesis", "Turn trust into a product",
      "Build workflows that people and institutions can inspect, control and integrate.", [
          ("01", "Verification", "Evidence for chain state, finality, data origin, software releases and service availability."),
          ("02", "Control", "Explicit authorization, approvals, limits, recovery and auditable operations."),
          ("03", "Integration", "Versioned APIs, SDKs, events, local testing and clear security boundaries."),
      ])

two(7, "06 / P0 proposed service", "Bloch Verify",
    "An evidence layer for exchanges, custodians, validators and risk teams.", [
        ("IMPLEMENTED MVP", "Offline comparison", "The current CLI validates checkpoint bundles and compares independently supplied observations. It does not yet authenticate operators or prove finality."),
        ("PROPOSED SERVICE", "Operator + state evidence", "Signed operator packages, authenticated trust roots, regular checkpoint publication and independently compared finality reports."),
    ], True)

three(8, "07 / P1 proposed service", "Data + Dev Cloud",
      "A recurring service opportunity built on tools that reduce repeated operational work.", [
          ("DATA", "Bloch Data", "Extend the live historical index into complete, provenance-rich transaction and account APIs."),
          ("INTEGRATION", "Webhooks + SDKs", "Versioned clients, idempotent delivery, retries and exchange-ready examples."),
          ("BUILD", "Sandbox", "Local node, fixtures and transaction simulation before live submission."),
      ])

two(9, "08 / P2 proposed services", "Treasury + Pay",
    "Organizational control and payment tools, without claiming initial custody or rail access.", [
        ("DESIGN ONLY", "Bloch Treasury", "Multi-step approvals, limits, allowlisted recipients, audit trail and on-device signing."),
        ("DESIGN ONLY", "Bloch Pay API", "Invoices, reconciliation, finality receipts and webhooks for native BLCH flows."),
    ], True)

three(10, "09 / Global market line", "Bloch Markets",
      "Software for market participants; not an operating exchange or settlement system.", [
          ("START WITH SOFTWARE", "Proof Ledger", "Position reconciliation, reserve evidence and audit export with provenance."),
          ("PARTNER PILOT", "Asset Lifecycle", "Issuance and corporate-action controls only with legal structure and authorized partners."),
          ("RESEARCH + PILOTS", "DvP / PvP Engine", "Coordinated delivery or payment after verified finality, cash leg and risk controls."),
      ])

three(11, "10 / Latin America", "Bloch LatAm",
      "Regional interoperability begins with observation, reconciliation and qualified partners.", [
          ("BR-1 / PARTNERS", "Pix + Open Finance", "Connector design and BRL-flow reconciliation through authorized institutions; no live integration claimed."),
          ("BR-2 / PARTNERS", "Receivables + assets", "Eligibility, lifecycle and audit trails with legal structure and regulated partners."),
          ("LA-3 / PILOT", "Regional corridors", "Controlled cross-border experiments with explicit FX, compliance and settlement."),
      ], True)

three(12, "11 / Cross-network expansion", "Routing with visible risk",
      "Execution follows evidence about cost, custody, backing and settlement.", [
          ("01", "Compare", "Quotes, total costs, expected time and liquidity source are made visible."),
          ("02", "Explain", "Separate EVM ECDSA accounts from native post-quantum authorization and bridge operator risk."),
          ("03", "Qualify", "Public execution only after settlement proof, reserve reconciliation and independent review."),
      ])

frame(13, "12 / Delivery gates", "Four gates before scale",
      "Move forward only when the prior capability has been demonstrated and documented.", True)
gates = [
    ("G0", "Reliable base", "Checkpoint publication, independent node sync, reproducible releases and finality comparison."),
    ("G1", "Data + integration", "Complete index, versioned API, webhooks, SDK, monitoring and support."),
    ("G2", "Value workflows", "Treasury policies, reconciliation, credit rules and controlled pilots."),
    ("G3", "Markets + networks", "Qualified bridge, L2, global-market and LatAm pilots with audit and recovery."),
]
for i, (tag, title, body) in enumerate(gates):
    card(46 + i * 171, 75, 160, 205, tag, title, body, light=True)
c.showPage()

two(14, "13 / Market sequencing", "Two paths, one evidence model",
    "Regional and global programs share verifiable data but require different partners.", [
        ("GLOBAL", "Markets sequence", "Proof Ledger software first; partner asset lifecycle next; DvP/PvP research and limited pilots only after verified finality and licensed participation."),
        ("LATAM", "Regional sequence", "Read-only rail observation first; authorized-partner reconciliation next; cross-border corridors only after legal, FX, compliance and settlement qualification."),
    ])

three(15, "14 / Research and limits", "Keep boundaries explicit",
      "Research is separate from production products; no automatic transfer of L1 guarantees.", [
          ("RESEARCH", "Cryptographic agility", "Plan algorithm rotation and key migration with specification and audit."),
          ("RESEARCH", "Verifiable privacy", "Advance Coherence circuits and proofs without claiming anonymity today."),
          ("SECURITY", "Distinct domains", "ECDSA applies to the L2/EVM domain. Native L1 uses hybrid ML-DSA-65 and Falcon-1024."),
      ], True)

frame(16, "15 / Execution model", "Sell measurable trust",
      "Infrastructure services can be useful before cross-network asset transfers are enabled.")
card(46, 124, 216, 155, "CUSTOMERS", "Who benefits", "Exchanges, custodians, apps, node operators and treasury teams.")
card(274, 124, 216, 155, "SERVICE MODEL", "What to offer", "APIs, support, observability and deployment; routing fees only after qualification.")
card(502, 124, 220, 155, "MEASURES", "What to prove", "Independent nodes, bootstrap time, event integrity, availability and reconciliation errors.")
t(47, 99, "Source: Bloch_Inc_Products_Services_EN_v3.pdf and current product code.", 8.6, GREEN, "Courier")
t(47, 82, "New lines are proposals; Panama incorporation remains in progress.", 8.6, MUTED, "Courier")
t(47, 58, "THE NETWORK REMAINS OPEN; COMPANY SERVICES ARE OPTIONAL.", 9.2, GREEN, "Courier")
c.linkURL("https://blochinc.xyz/", (45, 52, 725, 105), relative=0)
c.showPage()
c.save()
print(f"{OUTPUT} ({OUTPUT.stat().st_size} bytes)")
