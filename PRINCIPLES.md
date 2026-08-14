# Bloch-SIS-PoW — principles

> **Historical — Genesis-3.** This states the principles of the
> proof-of-work chain that stopped permanently at height **39,918** on
> 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots,
> 32-slot epochs, finality by epoch), live since 21:31:19 UTC that day. Kept
> because Genesis-4's opening ledger is derived from Genesis-3. It is not
> what runs.
>
> The preâmbulo, principle 6 and the honesty discipline in 8 stand.
> Principle 1 ("ownerless") is **retracted**
> (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`). Principles 2 and
> 3 — "every node is a seed", "anyone may run a node" — describe a property
> the live network **does not have today**; each is annotated in place. The
> proof-of-work content of principles 4, 5 and 7 describes a consensus that
> has ended. Principle 8's "zero-security testnet" baseline is superseded:
> Genesis-4 is a live mainnet, and the current disclosure is in
> [`SECURITY.md`](./SECURITY.md).

## Preâmbulo

> *A founding statement — the "why", in the author's voice. The articles that
> follow are the "how". Both belong to whoever picks up the code; no one owns
> either.*

Hoje me reencontro com minha formação, com meus ideais e minhas ideias — com um
lobo solitário que já sofreu tudo que esta vida pode impor, mas que não deixa de
pensar na sociedade, no indivíduo que, carregado de seus valores e direitos, só
quer viver uma vida que lhe garanta, como novo Ulisses neste mundo tecnológico, os
direitos e prerrogativas daquilo que um dia se chamou de Constituição. Porque nós,
o povo — mas agora de uma maneira diferente —, escrevemos nossa parte no livro da
história, da evolução dos instrumentos jurídicos, da aquisição de direitos, na
aposição do véu que nos protege da indevida intrusão do Estado em nossas esferas
privadas.

E ainda bem que Marcelo Neves nos fez lembrar do transconstitucionalismo — do
diálogo entre ordens jurídicas que atravessa as fronteiras estatais —, que Gunther
Teubner nos mostrou os fragmentos constitucionais emergindo da própria sociedade,
sem depender do Estado, e que existiu Barlow e a Declaração de Independência do
Ciberespaço; que não dependemos do Estado para ter liberdade: liberdade de
empreender, de executar tarefas, de se autodeterminar, de garantir nosso culto (ou
não), de nos reunirmos, de ser — e de honrar o passado que nos trouxe até aqui, o
presente que reafirmamos com a práxis e com nossas escolhas, e um futuro glorioso
para as futuras gerações, que não se quedarão diante das indevidas violações de
nossos direitos, prerrogativas e virtudes. Porque somos "Nós, o povo" desse novo
constitucionalismo sem barreiras nem fronteiras, unidos por algo que todos temos em
comum: sermos humanos.

Lutar por direitos — ou levar o direito a sério — é isso: não se calar quando não
podemos sucumbir; ajudar a escrever nossa marca no livro da vida, do
constitucionalismo e dos direitos. Porque, sim, somos nós, o povo, princípio e fim
das normas, dos direitos e da liberdade que precedem o Estado. E que lembremos aqui
daquele contrato social que assinaram, assinamos e assinarão, cada qual a seu
jeito, garantindo a estabilidade de algo que chamamos de Direito. Garantidos pelo
*substantive due process of law* — porque, se há uma coisa que temos de levar a
sério, é o direito à vida, à propriedade e à liberdade, que precedem o
Estado-Leviatã e que nos protegem contra esse ente indispensável e, ao mesmo tempo,
perigoso chamado Estado: quanto maior fica, mais sedento fica; e, ao mesmo tempo que
é essencial, precisa ser controlado por regras e por algo que hoje percebo ser maior
que o próprio Estado, chamado Constituição — que já mudou tanto que não depende mais
de Estados, como reconhecido em Barlow, em Neves, em Teubner e em outros. Que esse
novo Ulisses (Jon Elster) nos leve a um caminho melhor, sem esquecer de apor o véu e
de não sucumbir ao canto das sereias neste mar de ilusões chamado Vida.

---

An open-source, **ownerless**, **post-quantum** Proof-of-Work crypto — public
infrastructure whose value is the **private, attestable infrastructure people run
on it**. These are the ideas, stated plainly and honestly.

> *Two words in that sentence no longer describe the project: **ownerless**
> (retracted, ADR-036) and **Proof-of-Work** (Genesis-3, stopped at height
> 39,918). **Post-quantum** stands — hybrid ML-DSA-65 ‖ Falcon-1024 is on
> every Genesis-4 consensus path.*

## 1. Ownerless — like Bitcoin *(RETRACTED)*

> **This principle was retracted in writing**
> (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`) in favour of a
> two-entity foundation structure. It is left standing because it is what the
> project said, and because retracting a claim by deleting it is how a record
> stops being one. Read the paragraph below as the abandoned position, not
> the current one.

No owner. No curator. No foundation. No official website, no official explorer.
The protocol ships as software and a documented **RPC / API** surface — nothing
more. It does not depend on any person or company; not on its author. A community
may steward it; no one controls it. Tools that read the chain (explorers,
dashboards) are **independent products**, the way mempool.space is to Bitcoin —
not "the protocol's explorer."

## 2. Every node is a seed

There are no privileged seed nodes owned by anyone. **Every node — on a phone or a
desktop — is a seed**: it listens, advertises itself, shares its peer list, and
can bootstrap others. The network self-bootstraps from its participants, so it has
**no central point to capture, censor, or switch off**. A project that depends on
someone's servers is a company pretending to be decentralized; this one does not.

> **Not true of the live network today, and stated here rather than left to
> be discovered.** Genesis-4 runs on `--transport devnet`
> (`crates/bloch-pos-node/src/net.rs`): a point-to-point TCP full mesh with a
> **fixed peer list, no discovery and no authentication**. There is no PEX,
> no self-bootstrap, and no address a stranger can dial. All 64 validators
> are operated by a single entity on five servers, so there *is* a central
> point that can switch the network off. This principle is the target, not a
> description. A libp2p/gossipsub layer that would restore it exists in the
> tree (`crates/bloch-pos-node/src/p2p.rs`) and is not what the fleet runs.

## 3. Permissionless — for nodes and for builders

Anyone may run a node. Anyone may **build products on the open code** — Postern
Labs is one builder among many, not the owner of the commons. The base is a
neutral commons; commercial value lives at the edges, in products with owners.
(See `docs/POSTERN-LABS.md` for the products ⟂ protocol boundary.)

> **The "anyone may run a node" half is not true today.** The code is open
> and anyone may build it, but there is no way to connect it to Genesis-4:
> the transport has a fixed peer list and no discovery (principle 2 above),
> and becoming a validator is closed on top of that — `Deposit` and
> `Delegate` are refused at every node's mempool, because bonding is not yet
> funded from the carried-over UTXO set. What is open to a third party today
> is reading the chain (`https://posternlabs.com/g4rpc`) and submitting
> transfers.

## 4. Post-quantum by default

The PoW is a **SHAKE-256 hashcash** (post-quantum because Grover gives only a
quadratic speedup) with a **Module-SIS structural gate** — the gate binds the
work to a lattice form; the security source is the cumulative hash work.
Signatures are hybrid **Falcon‖ML-DSA** (genuinely lattice-based); hashing is
SHAKE-256; the privacy layer (Coherence) uses
**hash-STARK/FRI — no elliptic curves**. The security, and the privacy, are meant
to survive a quantum computer — including "harvest-now, decrypt-later."

## 5. "Useful PoW" — what is true, and what we do not claim

Said precisely, so no one is misled:

- The **mining computation is NOT "useful work."** Making the consensus PoW
  compute something externally useful is a research graveyard (it breaks the
  hard-to-solve / easy-to-verify / non-precomputable requirements). The Bloch-SIS
  PoW stays **arbitrary-but-secure** (cumulative hashcash work) — deliberately. We
  do **not** claim useful-work consensus.
- What **is** useful — and this is the real point — is the **infrastructure the
  network's participants run**: private, hardened, **attestable** nodes and
  devices. The honest, deliverable form of "useful" is a **proof of useful privacy
  *service***: the attestation layer proves a device runs the genuine, unmodified
  privacy build. That is a product seal (needs no token) and, optionally and
  carefully (bound to unique hardware, anti-Sybil), something the network could
  recognize.
- So: **an open-source, post-quantum crypto whose usefulness is the private,
  attestable infrastructure it lets people run** — useful *and* honest *and* not
  yet delivered by anyone through that door.

## 6. Privacy and security are the motto

Not surveillance, not compliance-by-force. The protocol does **not** freeze,
blacklist, or KYC. Privacy is default; disclosure is **opt-in** by the user (view
keys). Security and privacy are the axes everything is judged on.

## 7. Not an asset — a network token, nothing more

**The token is not an asset.** Not an investment, not a store of value, not a
thing to hold and hope on. We promise **nothing** about value — and beyond not
promising, **no listing will be pursued**: the author will make **no effort** to
get it traded, priced, or made valuable. No exchange listing, no price, no profit,
no market-making.

It exists **only to function in the protocol** — mining reward, fees, privacy
operations — never as an instrument to speculate on. Because the protocol is
**ownerless** there is no promoter pledging value, which is also precisely why it
is **not a security**: no expectation of profit derived from the efforts of a
promoter. Whatever value a free market might one day assign is sought and promised
by **no one**. On the zero-security testnet it is worth **nothing**, by design.

> **Read the paragraph above with two corrections; it is the one paragraph in
> this file a counterparty is most likely to act on.**
>
> 1. **The premise is retracted.** "Because the protocol is ownerless there is
>    no promoter" no longer holds: the ownerless thesis was retracted
>    (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`) in favour of a
>    two-entity foundation structure. The founder allocates the genesis
>    validator cohort, all 64 validators are operated by a single entity, and
>    the founder and the Foundation together hold 56.05 B of the 57.15 B BLOCH
>    issued at genesis. **The no-promoter argument stated here is therefore not
>    available as written.** The project still makes no value claim, pursues no
>    listing and ran no token sale; what it can no longer claim is that no
>    identifiable promoter exists. Nothing in this file is legal advice or a
>    legal conclusion.
> 2. **"Mining reward" and "zero-security testnet" are Genesis-3 terms.** There
>    is no mining. Genesis-4 is a live mainnet; the token's function on it is
>    validator emission and fees.

**No token sale. No listing effort. No price. No roadmap-to-riches.** If you came
for an asset, there isn't one here — the point is the *network* and the
*privacy/security infrastructure*, not a ticker.

## 8. Honesty is a principle, not a footnote

Today this is a **zero-security testnet** — unaudited, PoW parameters being
re-derived, no live decentralized network yet. Every claim — for the protocol and
for any product — is **audit-gated** and stated separately. No "100% private," no
"useful mining," no pretending the foundation is the finished product.

> **The discipline stands; the baseline it names does not.** As of 2026-08-13
> this is a **live mainnet** — Genesis-4, proof of stake — not a
> zero-security testnet, and there are no PoW parameters left to re-derive.
> It is still **unaudited**, and it is still not a decentralised network:
> all 64 validators are operated by one entity, 93.94% of the carryover sits
> at one stakeable address, and no third party can join because the transport
> has a fixed peer list and no discovery and bonding is closed at the
> mempool. Applying principle 8 to the chain that actually runs produces
> [`SECURITY.md`](./SECURITY.md); that is the current statement.

---

*These are the ideas. The protocol is a commons; the products (Postern Labs) are
owned and built at the edges; nobody, including the author, owns the base.*
