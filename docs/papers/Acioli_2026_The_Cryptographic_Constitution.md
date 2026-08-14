# The Cryptographic Constitution: Pre-Commitment, Repeated Games, and the Architecture of Civil Cooperation Without a Sovereign

> **Editorial note — scope of this paper within this repository.** This is an
> academic working paper on constitutional theory, first posted **April 2026**.
> It argues a general normative thesis: that mutable in-protocol governance —
> "whether by foundation, multisig, or stake-weighted vote" — is incompatible
> with the constitutional ambitions of cryptographic protocols. **It is
> scholarship, not a description of the Bloch network, and it must not be read
> as a statement of the project's current governance.**
>
> Two developments postdate it and cut against its application to Bloch, and
> are recorded here rather than left for a reader to discover. **(1)** The
> ownerless thesis was **retracted in writing on 2026-08-10**
> (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`), which revokes
> ADR-033 and ADR-034: Bloch has an identified issuer and a sponsoring
> organisation, a Bloch Foundation is to be created holding 29.00% of supply,
> and Postern Labs Ltda builds the software. **(2)** Bloch moved from proof of
> work to **proof of stake** on 2026-08-13 — Genesis-3 stopped permanently at
> height 39,918 and Genesis-4 has been live since 21:31:19 UTC that day.
>
> The paper's argument is unchanged by either fact; the project's position is.
> Where this paper and the decision record disagree about what Bloch is, the
> decision record governs.
>
> One thing the paper's own framework survives to say about the live network,
> and it is not flattering: what binds today is not stake-weighted voting but
> operator concentration — **all 64 Genesis-4 validators are run by a single
> entity**, 93.94% of the carryover sits at one address, and 56.05 B of the
> 57.15 B BLOCH issued at genesis is held by the founder and the Foundation.
> The pre-commitments that *are* enforced by consensus — the supply cap
> (`TransitionError::SupplyCapExceeded`), the vesting functions, the
> genesis-cohort taper — hold because every node checks them; that is the
> paper's mechanism, and it is real. What no consensus rule reaches is who
> holds the coins and who runs the machines.

---

**Tiago Beltrão de Azevedo Tenório Acioli** [^aff]

[^aff]: Post-graduate in Civil Procedural Law, Instituto Brasileiro de Ensino, Desenvolvimento e Pesquisa (IDP), Brasília, Brazil. Entrepreneur and enthusiast of new technologies. *A new Ulysses in this boundless ocean called technology. Constitutionalist.* Correspondence concerning this article may be addressed to the author through the public-research repository in which this paper appears.

**Working Paper — First Posted: April 2026**

---

## Suggested Citation

Acioli, Tiago Beltrão de Azevedo Tenório. *The Cryptographic Constitution: Pre-Commitment, Repeated Games, and the Architecture of Civil Cooperation Without a Sovereign* (Working Paper, April 2026). Available at SSRN.

---

## Abstract

This paper develops a constitutional theory of cryptographic protocols organized around the doctrine of strict pre-commitment. Drawing on Jon Elster's analysis of Ulyssean self-binding, Bodo Pieroth and Bernhard Schlink's *Schranken-Schranken* doctrine, Laurence Tribe's account of the invisible constitution, Marcelo Neves's transconstitutionalism, Karl-Heinz Ladeur's network theory of law, and the game-theoretic contributions of Thomas Schelling, John Nash, Robert Aumann, and Robert Axelrod, the paper argues that the constitutional condition for cryptographic protocols to function as substrates of civil cooperation is the absence of any in-protocol authority capable of altering their fundamental rules. Mutable governance — whether by foundation, multisig, or stake-weighted vote — recapitulates within the cryptographic order the very pathologies of discretion that the post-Bretton-Woods cryptographic project was designed to escape. By contrast, strict pre-commitment, expressed in compiled consensus code beyond the reach of any subset of participants, satisfies simultaneously the four conditions identified by the synthesis of Schelling, Nash, Aumann, and Axelrod as jointly sufficient for cooperation among self-interested agents in indefinitely repeated interaction. The paper applies this framework to the regulation of anti-money-laundering and counter-terrorist-financing (AML/CFT) functions within cryptographic networks, distinguishing between the historically invariant *kernel* of AML/CFT (the prohibition of computational complicity in financing of terror, trafficking of persons, and laundering of identifiable serious-crime proceeds) and its time-bound *forms*. The argument concludes by sketching the contours of a *civitas cryptographica*: a voluntary, dispersed, mathematically-bound civil order organized around financial privacy as a network good, contractual liberty as a fundamental right, and blockchain as the substrate of voluntary association.

**Keywords:** constitutional theory; pre-commitment; cryptographic protocols; blockchain governance; *Schranken-Schranken*; transconstitutionalism; network society; game theory; repeated games; AML/CFT; financial privacy; freedom of contract; civil cooperation.

**JEL Classification:** K10 (Law and Economics, General); K22 (Business and Securities Law); K42 (Illegal Behavior and the Enforcement of Law); D70 (Analysis of Collective Decision-Making, General); C72 (Noncooperative Games); C73 (Stochastic and Dynamic Games; Evolutionary Games; Repeated Games); E42 (Monetary Systems; Standards; Regimes; Government and the Monetary System); L86 (Information and Internet Services).

---

## 1. Introduction

On the fifteenth of August nineteen seventy-one, in a televised address from Camp David, Richard Nixon suspended the convertibility of the United States dollar into gold.[^1] The act was framed as a temporary measure. It was not. The Bretton Woods system, in which a fixed quantity of gold anchored the dollar and the dollar in turn anchored every other currency in the non-Soviet world, ended that evening and has not returned. What followed — what we have lived in for over half a century — is a global monetary order with no anchor, in which money is whatever the issuing state declares it to be, and in which the purchasing power of every saver is silently and continuously eroded by an act of administrative discretion no one ever consented to.

[^1]: For the canonical historical and economic accounts of the 1971 suspension and its consequences, see Allan H. Meltzer, *A History of the Federal Reserve, Volume 2, Book 2: 1970–1986* (Chicago: University of Chicago Press, 2009); Barry Eichengreen, *Globalizing Capital: A History of the International Monetary System*, 2d ed. (Princeton: Princeton University Press, 2008); James Rickards, *The Death of Money: The Coming Collapse of the International Monetary System* (New York: Portfolio, 2014).

This Article is not, primarily, about money. But the post-1971 monetary order is the historical backdrop against which the cryptographic projects of the twenty-first century must be understood. Bitcoin, in 2009, was the first credible technical answer to a question that had been intellectually open since 1971: can a society exit a discretionary monetary regime without overthrowing the state that operates it?[^2] Friedrich Hayek had imagined the question philosophically in *Denationalisation of Money* (1976);[^3] David Chaum had imagined it cryptographically in his work on blind signatures (1983);[^4] but the technical synthesis required by 2009 — a Byzantine-fault-tolerant consensus algorithm reaching agreement among adversarial peers, unforgeable digital scarcity, and a public-verification regime cheaper than a state's central bank — is what made the question operational rather than utopian.[^5]

[^2]: Satoshi Nakamoto, *Bitcoin: A Peer-to-Peer Electronic Cash System* (white paper, October 2008); first Bitcoin block mined 3 January 2009 (Genesis Block).

[^3]: Friedrich A. Hayek, *Denationalisation of Money: The Argument Refined*, 2d ed. (London: Institute of Economic Affairs, 1976).

[^4]: David Chaum, "Blind Signatures for Untraceable Payments," in *Advances in Cryptology — Proceedings of CRYPTO '82*, ed. David Chaum, Ronald L. Rivest, and Alan T. Sherman (Boston: Springer, 1983), 199–203.

[^5]: For an analytic genealogy of the technical preconditions of Nakamoto's synthesis, see Arvind Narayanan and Jeremy Clark, "Bitcoin's Academic Pedigree," *Communications of the ACM* 60, no. 12 (2017): 36–45.

Yet seventeen years on, the cryptographic project has matured into a shape its founders did not anticipate and would not entirely endorse. There are foundations. There are multisigs that "guard" protocols. There are token-weighted votes deciding which addresses live and which are frozen.[^6] There is the slow, depressing accretion of governance — and with it, the slow, depressing accretion of capture. The institutions designed to escape political discretion have, in many cases, replicated it within their own boundaries.

[^6]: For empirical and doctrinal accounts of the governance pathologies of the post-2015 cryptocurrency industry, see Angela Walch, "The Path of the Blockchain Lexicon (and the Law)," *Review of Banking and Financial Law* 36 (2017): 713–765; Wulf A. Kaal, "Decentralized Autonomous Organizations: Internal Governance and External Legal Design," *Annals of Corporate Governance* 5, no. 4 (2021): 237–315; Vitalik Buterin, "Moving Beyond Coin Voting Governance" (blog post, 2021), https://vitalik.ca/general/2021/08/16/voting3.html.

This Article advances a theoretical framework for understanding what is at stake in that drift, and offers a doctrinal architecture — *strict pre-commitment* — for resisting it. The framework draws on six bodies of work: (i) the constitutional theory of self-binding, originating with Lassalle and developed in modern form by Elster; (ii) the doctrine of *Schranken-Schranken* in German constitutional jurisprudence; (iii) Tribe's analysis of the unwritten substrate of constitutional orders; (iv) Ladeur's network theory of law; (v) Neves's *Transconstitucionalismo*, building on Teubner's societal constitutionalism; and (vi) the game-theoretic literature on cooperation without a sovereign, particularly the contributions of Schelling, Nash, Aumann, and Axelrod. The argument's principal claim is that these six bodies of work, properly synthesized, identify cryptographic pre-commitment as the constitutional condition under which civil cooperation among self-interested agents can be sustained at planetary scale, across indefinite time horizons, without any central authority. The argument's principal application is to the regulation of anti-money-laundering and counter-terrorist-financing (AML/CFT) functions within cryptographic protocols — a domain in which the temptations of governance are most acute and the costs of capture most consequential.

The Article proceeds as follows. Part 2 restates Lassalle's nineteenth-century distinction between written and real constitutions and applies it to the cryptocurrency industry's institutional drift. Part 3 develops Elster's account of Ulyssean self-binding as the constitutional response. Part 4 examines Tribe's invisible constitution and identifies four propositions that constitute the unwritten substrate of any cryptographic order. Part 5 develops the *Schranken-Schranken* doctrine and applies it to the architecture of AML/CFT classification. Part 6 examines Ladeur's network theory of law and the constitutional implications of Sarnoff's, Metcalfe's, and Reed's laws. Part 7 turns to the Wittgensteinian problem of semantic drift and the unique anchoring properties of cryptographic code. Part 8 develops the transconstitutional position of cryptographic protocols vis-à-vis state constitutional orders. Part 9 reconstructs the game-theoretic foundations of cooperation without a sovereign, drawing principally on Schelling, Nash, Aumann, and Axelrod. Part 10 articulates the normative project of crypto-civil cooperation organized around financial privacy as a network good, freedom of contract, and blockchain as the substrate of voluntary association. Part 11 specifies the historically invariant kernel of AML/CFT and explains why it can be encoded as permanent pre-commitment. Part 12 examines the empirical record of foundation-governed protocols and concludes that mutable institutional governance is incompatible with the constitutional ambitions of the cryptographic project. Part 13 concludes with a constitutional declaration for the *civitas cryptographica*.

## 2. Lassalle's Question, Restated

In April 1862, in two lectures delivered to a Berlin workers' association, Ferdinand Lassalle put a question to the German bourgeoisie that ought now to be put to the cryptocurrency industry.[^7] *Über Verfassungswesen* — *On the Essence of Constitutions* — observed that every state has, formally, a written constitution; and that every state also has, behind that document, a set of *real factors of power* (*reale Mächte*) — the army, the great landowners, the industrial capital, the church — without whose acquiescence the written constitution is dead letter. The written constitution, Lassalle said, is a piece of paper. The real constitution is *Wirklichkeitsverfassung*, the constitution of reality: who actually has the gun, the bank, and the printing press. A written constitution that does not reflect those real factors will be ignored when convenient and torn up when necessary.

[^7]: Ferdinand Lassalle, *Über Verfassungswesen* (Berlin: G. Jansen, 1862). The two lectures, "Über Verfassungswesen" and "Was nun?", were delivered on 16 April and 17 November 1862 respectively. Modern critical edition: Ferdinand Lassalle, *Reden und Schriften*, ed. Hans Feigl (Frankfurt am Main: Europäische Verlagsanstalt, 1987).

This is the question that ought to be put to every cryptographic protocol that markets itself as decentralized: *who actually has the gun*? Who is the real factor of power, behind the white paper, behind the smart contract, behind the GitHub repository? When the protocol must respond to a sanctions designation, who decides what to do? When a smart contract is hacked, who deploys the patch? When the model that classifies risk needs updating, who signs?

In the dominant institutional model of the post-2017 cryptocurrency industry, the answers are well-known. A foundation, registered in Switzerland or Singapore or the Cayman Islands, holds the trademark, the GitHub admin keys, and a treasury denominated in the protocol's own token. A multisig of named founders, advisors, and one or two exchange representatives can pause contracts, freeze funds, mint or burn tokens, blacklist addresses. A governance forum, in which token-weighted voting nominally decides parameters, in practice ratifies whatever the foundation has already decided.[^8] The white paper says *decentralized*; the constitution of reality says *board of directors with extra steps*.

[^8]: For empirical analysis of token-weighted governance and its capture dynamics, see Aleksander Berentsen and Fabian Schär, "A Short Introduction to the World of Cryptocurrencies," *Federal Reserve Bank of St. Louis Review* 100, no. 1 (2018): 1–16; Joseph Bonneau et al., "SoK: Research Perspectives and Challenges for Bitcoin and Cryptocurrencies," *Proceedings of the 2015 IEEE Symposium on Security and Privacy* (2015): 104–121; Sirio Aramonte, Wenqian Huang, and Andreas Schrimpf, "DeFi Risks and the Decentralisation Illusion," *BIS Quarterly Review* (December 2021): 21–36.

Lassalle's analytical move was to say that the discrepancy between paper and reality is not a contingent failure of any particular constitution; it is the structural condition of constitutionality itself, until and unless the written constitution is binding on the real factors. A constitution becomes operative — becomes *real* in his sense — only when the entities holding power are themselves disabled from rewriting it at will. Until then, the document is decoration.

The cryptographic problem of the twenty-first century is the constitutional problem of the nineteenth century in a new substrate. We must build protocols whose written constitutions — that is, whose source code — are binding on the real factors. We must build systems in which there is no one who can pause, freeze, blacklist, or rewrite, because there is no privileged entity at all. We must, in other words, take seriously the founding intuition of Bitcoin: that the rules should not have authors who continue to author them. This Article calls that condition *strict pre-commitment*, and develops the constitutional architecture for achieving it.

## 3. Ulysses at the Mast

Pre-commitment has a long literature. Its canonical philosophical form is Jon Elster's *Ulysses and the Sirens* (1979) and its sequel *Ulysses Unbound* (2000),[^9] in which Elster generalizes the Homeric figure: a rational agent who, knowing his own future weakness, deliberately disables his own future capacity to act on that weakness. Ulysses orders his sailors to bind him to the mast and to refuse, by oath, to release him no matter how much he pleads, because he knows that when the Sirens sing he will plead, and he knows that the pleading will be sincere, and he knows that his sincere pleading must be defeated if he is to survive. The intelligence of the strategy lies precisely in its anticipation of the weakness it disables.

[^9]: Jon Elster, *Ulysses and the Sirens: Studies in Rationality and Irrationality*, rev. ed. (Cambridge: Cambridge University Press, 1984; orig. 1979); Jon Elster, *Ulysses Unbound: Studies in Rationality, Precommitment, and Constraints* (Cambridge: Cambridge University Press, 2000). For a critical analysis specifically of the constitutional applications, see Stephen Holmes, *Passions and Constraint: On the Theory of Liberal Democracy* (Chicago: University of Chicago Press, 1995), ch. 5.

Elster shows that constitutional law is a vast Ulyssean architecture. Bills of rights, supermajority requirements for constitutional amendment, judicial independence, central bank independence, monetary discipline — these are mechanisms by which a polity binds its future self to refuse the offers it knows itself susceptible to accepting. The framers of the United States Constitution did not include the Bill of Rights because they trusted future congresses; they included it because they did not. The German Basic Law's *Ewigkeitsklausel* (Article 79(3))[^10] — declaring that the federal nature of the state, the dignity of the human person, and the basic structure of democracy may never be amended — is Ulyssean in its purest form: a clause forbidding even unanimous future generations from undoing the lesson Germany learned in 1933 to 1945.

[^10]: Grundgesetz für die Bundesrepublik Deutschland [GG], Art. 79, para. 3 (Federal Republic of Germany), 23 May 1949: "Eine Änderung dieses Grundgesetzes, durch welche die Gliederung des Bundes in Länder, die grundsätzliche Mitwirkung der Länder bei der Gesetzgebung oder die in den Artikeln 1 und 20 niedergelegten Grundsätze berührt werden, ist unzulässig." The constitutional jurisprudence is extensive; see Konrad Hesse, *Grundzüge des Verfassungsrechts der Bundesrepublik Deutschland*, 20th ed. (Heidelberg: C.F. Müller, 1995), §§ 24–25.

The cryptographic application is direct. A protocol that wishes to bind real factors of power must include, in its source code, mechanisms of strict pre-commitment that are resistant to its future operators' temptations. The temptations are predictable: *We need to update the model. We need to freeze that one obviously-criminal address. We need to add a back door for the regulator who is otherwise going to ban us. We need to censor that one transaction because the press will be terrible if we don't.* Each of these temptations, taken individually, can be defended on grounds of urgency and proportionality. The Sirens, too, sing beautifully and individually persuasively. Ulysses' rule — *do not untie me, no matter how much I plead* — is not a rule that says the Sirens are not beautiful. It is a rule that says when the protagonist is hearing the Sirens, his judgment about beauty is not to be trusted, and any institutional architecture that allows him to act on that judgment must be disabled in advance.

The pre-commitment of a properly constituted cryptographic protocol is, accordingly, that no entity — not its founders, not its treasury company, not its bonded oracles, not even its token holders by supermajority — has the in-protocol capacity to rewrite the fundamental rules the protocol enforces. Those rules must be compiled into the consensus. Changing them must require every node operator, individually and consciously, to install new software and choose to follow a new chain. There must be no smart-contract upgrade path. There must be no governance vote with binding effect on consensus. There must be no board override. The rule of the mast must be, in the relevant sense, absolute.

## 4. The Invisible Constitution

Laurence Tribe's *The Invisible Constitution* (Oxford 2008)[^11] extends the constitutional analysis in the direction relevant here. Tribe argued that every written constitution rests upon, and is given meaning by, an unwritten substrate of presuppositions, habits, doctrines, and silent commitments that are nowhere explicit on the page. The text of the United States Constitution does not, for instance, mention judicial review; *Marbury v. Madison* (1803)[^12] read that doctrine into the document. The text does not mention the right to privacy; *Griswold v. Connecticut* (1965)[^13] read it into "penumbras" of enumerated rights. The text does not mention the principle that the Constitution itself is law and not merely policy; that proposition is, Tribe argues, presupposed rather than asserted, and yet without it the entire enterprise is unintelligible.

[^11]: Laurence H. Tribe, *The Invisible Constitution* (New York: Oxford University Press, 2008).

[^12]: *Marbury v. Madison*, 5 U.S. (1 Cranch) 137 (1803).

[^13]: *Griswold v. Connecticut*, 381 U.S. 479 (1965).

The implication for cryptographic constitutionality is profound and frequently missed. A blockchain's consensus rules are not the entire constitution; they are merely the *visible* constitution. Around them lies an invisible constitution of social presuppositions: that the chain with the most accumulated proof-of-work or proof-of-stake is the canonical chain; that node operators who choose to follow it are the relevant interpretive community; that hard forks reflect genuine disagreements rather than capricious whim; that the meaning of a transaction is what the consensus rules at the time of its inclusion say it is. None of this is in the source code. All of it is constitutive of the system being a system at all.

The cryptographic protocol's invisible constitution may, accordingly, be specified in four propositions, none of which is asserted in code but each of which is presupposed by everything in code:

**First, the protocol is a voluntary technical association**, not a state. It binds no one who does not choose to operate a node, hold a token, or interact with a wallet. Sovereign states retain their own jurisdiction over their own residents.

**Second, each node operator is the ultimate arbiter of which chain to follow**. The "majority" of hashpower or stake is not the constitution; it is merely a Schelling point. If the majority chain enacts rules that a node operator finds intolerable, the operator may, and should, refuse to follow it. This is the fundamental power that fair-launch architecture preserves and that foundation-mediated architecture quietly abolishes.

**Third, the visible constitution — the source code — is the Schelling point around which honest disagreement converges**. Hard forks are not failures; they are the system functioning as designed. The historical hard forks of Ethereum (DAO, 2016)[^14] and Bitcoin (Cash, 2017)[^15] are sometimes told as cautionary tales; in fact, they are the constitutional process of cryptographic networks operating exactly as it should. A network that *cannot* hard-fork is a network whose visible constitution has been captured.

[^14]: For doctrinal and technical analysis of the DAO hard fork, see Quinn DuPont, "Experiments in Algorithmic Governance: A History and Ethnography of 'The DAO,' a Failed Decentralized Autonomous Organization," in *Bitcoin and Beyond: Cryptocurrencies, Blockchains, and Global Governance*, ed. Malcolm Campbell-Verduyn (Abingdon: Routledge, 2018), 157–177.

[^15]: For technical and political analysis of the Bitcoin–Bitcoin Cash split of 1 August 2017, see Jonathan Bier, *The Blocksize War: The Battle over Who Controls Bitcoin's Protocol Rules* (self-published, 2021).

**Fourth, reproducibility is the proof of non-discretion**. Any score the protocol attaches to any wallet must be bit-for-bit reproducible by any third party running the open-source attested computation on the same inputs. This property distinguishes a *protocol* from a *service*. A service has discretion; a protocol has only computation. The reproducibility property is what places the system, doctrinally, outside the regulatory category of "professional service" in every jurisdiction whose AML/CFT framework distinguishes between the two — which is every jurisdiction.[^16]

[^16]: For the doctrinal distinction in U.S. law, see *Bank Secrecy Act of 1970*, 31 U.S.C. § 5311 et seq.; FinCEN, "Application of FinCEN's Regulations to Persons Administering, Exchanging, or Using Virtual Currencies," Guidance FIN-2013-G001 (18 March 2013), distinguishing between "users" (not regulated as money services businesses) and "exchangers" or "administrators" (regulated). For the European Union analogue, see Directive (EU) 2015/849 (Fourth AMLD), as amended; Directive (EU) 2018/843 (Fifth AMLD); Regulation (EU) 2023/1113 (Travel Rule).

These four propositions are the invisible constitution of any cryptographic protocol that aspires to constitutional status. They are not enforced by code. They are enforced by the social and technical practices of node operators, by the economic incentives of running a node, and by the dispersion of those operators across jurisdictions. They are exactly as fragile, and exactly as durable, as constitutional propositions in any polity.

## 5. *Schranken-Schranken*: The Limits of Limits

A frequent objection to the strict pre-commitment doctrine is the following. *If the AML/CFT rules are made immutable, what about the cases where the rules turn out to be wrong? What about a wallet incorrectly flagged as high-risk because of bad data? What about a typology that, in retrospect, was over-inclusive? Do the dissident, the journalist, the abuse victim, the political refugee have no recourse?*

This objection has constitutional force, and it is met by the doctrine of *Schranken-Schranken* — "limits on limits" — developed in German constitutional jurisprudence by, among others, Bodo Pieroth and Bernhard Schlink in *Grundrechte: Staatsrecht II*.[^17] The doctrine recognizes that fundamental rights are not absolute; they admit limits, because rights collide with other rights and with public interests. But it also recognizes that the *capacity to limit* a fundamental right is itself a power that must, in turn, be limited — *limited in its limits*. A police power to detain may be necessary; that power must itself be bounded by due process. A regulatory power to restrict speech may be conceivable; that power must itself be bounded by proportionality, *Bestimmtheit* (specificity), and *Verhältnismäßigkeit* (proportionality in the strict sense).[^18] The dialectical structure — right, limit, limit-on-limit — is what gives constitutional rights operative force; without the second-order limit, the first-order limit swallows the right.

[^17]: Bodo Pieroth and Bernhard Schlink, *Grundrechte: Staatsrecht II*, 39th ed. (Heidelberg: C.F. Müller, 2023). The English-language exposition of the doctrine is given in Donald P. Kommers and Russell A. Miller, *The Constitutional Jurisprudence of the Federal Republic of Germany*, 3d ed. (Durham: Duke University Press, 2012).

[^18]: For the *Verhältnismäßigkeitsprinzip* and its three sub-tests (suitability, necessity, proportionality stricto sensu), see Robert Alexy, *A Theory of Constitutional Rights*, trans. Julian Rivers (Oxford: Oxford University Press, 2002); Aharon Barak, *Proportionality: Constitutional Rights and their Limitations*, trans. Doron Kalir (Cambridge: Cambridge University Press, 2012).

Applied to the constitutional architecture proposed here, the structure is as follows.

*The right.* Every wallet enjoys a presumption of legitimate use. The default classification is unrestricted. Privacy is the baseline; financial surveillance is the exception that requires justification.

*The limit.* That presumption is rebuttable by reference to a finite, enumerated catalog of red-flag patterns drawn from the documented historical record of AML/CFT typologies. A wallet with a direct sanctions match, or with a documented trafficking-typology pattern, or with strong terrorist-financing exposure, may be elevated to a higher-risk classification or, in the most extreme case, designated as Sanctioned.

*The limit on the limit.* That elevation is itself bounded by:

- **Bestimmtheit (specificity)**: the catalog is exhaustive, codified, and frozen. New typologies cannot be added by administrative fiat; they require a hard fork accepted by the relevant interpretive community of node operators.
- **Reproducibility**: every elevation must be reproducible by any third party with access to the same inputs. A regulator, a journalist, a researcher, a human-rights observer can independently verify or refute any classification.
- **Time-bounding**: classifications expire within a defined window unless re-attested. The Sanctioned tier alone persists, reflecting the reality that designation under United Nations Security Council resolutions[^19] is not itself time-bounded.
- **Due process**: any wallet may dispute its classification by posting a tier-graduated bond and submitting evidence. The dispute is resolved by a bonded appeal mechanism. A successful dispute slashes the signing oracles and refunds the disputer with a doubling reward; an unsuccessful dispute burns the bond. The asymmetry between the cost of frivolous disputes and the cost of correct disputes is calibrated to ensure that genuine errors are economically rectifiable while the system is not flooded with bad-faith challenges.
- **Tag-only architecture**: the classification is metadata. The protocol does not, and cannot, freeze any wallet, sequester any transaction, or restrict any movement of value. What sovereign states or regulated counterparties choose to do with the metadata is not the protocol's concern; the protocol's commitment is to produce metadata that is reproducible, time-bounded, and disputable.

[^19]: See, e.g., U.N. Security Council Resolution 1267 (15 October 1999) on Al-Qaida and Taliban; U.N. Security Council Resolution 1373 (28 September 2001) on terrorist financing; U.N. Security Council Resolution 2231 (20 July 2015) on Iran. These resolutions are binding on member states under U.N. Charter Art. 25 and have no expiration except by subsequent Security Council action.

Pieroth and Schlink's doctrine is, in this application, both a justification for the existence of the risk-classification component and a constraint on its operation. The protocol does not refuse, in the name of absolute privacy, to encode any AML/CFT signal whatsoever. That position is intellectually pure but operationally indefensible: it would mean that the protocol stands silently complicit while financing of terror, trafficking of persons, and laundering of serious-crime proceeds run through it. The *Schranken-Schranken* structure says: yes, the privacy default is limited at the margins specified by the documented kernel of AML/CFT, and those limits are themselves limited with reproducibility, time-bounding, and due process, so that the limit cannot be weaponized beyond its stated purpose.

The crucial implication is that the limit-on-the-limit must itself be in the source code, not in any external authority. If the dispute mechanism could be paused by a foundation, or if the reproducibility property could be defeated by a closed model, or if the Sanctioned tier could be applied by anyone other than the documented sanctions lists, then the *Schranken-Schranken* collapse and the system becomes, in effect, an arbitrary censor. The pre-commitment doctrine and the *Schranken-Schranken* doctrine are therefore mutually reinforcing: the rules are immutable so that the limits-on-limits cannot be eroded; the limits-on-limits exist so that the immutable rules do not become tyrannical.

## 6. *Soziale Grenzen* and the Network Society

Karl-Heinz Ladeur's work on the network theory of law[^20] provides the third theoretical pillar of the constitutional architecture proposed here. Ladeur observes that the classical liberal model of law — in which a hierarchical state issues commands to atomized individuals, each of whom processes those commands as a sovereign rational agent — has been steadily displaced, since the late twentieth century, by a network model in which legal norms emerge from, and are interpreted within, dense webs of reciprocal observation and mutual adjustment among many semi-autonomous actors. In a network society, *Soziale Grenzen* — social limits, in the sense of limits emerging from the structure of social relations rather than from sovereign command — become as important as legal limits in the classical sense.

[^20]: Karl-Heinz Ladeur, *Postmoderne Rechtstheorie: Selbstreferenz — Selbstorganisation — Prozeduralisierung*, 2d ed. (Berlin: Duncker & Humblot, 1995); Karl-Heinz Ladeur, *Negative Freiheitsrechte und gesellschaftliche Selbstorganisation: Die Erzeugung von Sozialkapital durch Institutionen* (Tübingen: Mohr Siebeck, 2000); Karl-Heinz Ladeur, "The Theory of Autopoiesis as an Approach to a Better Understanding of Postmodern Law," European University Institute Working Paper LAW No. 99/3 (1999). For application to the digital context, see Karl-Heinz Ladeur, "The Evolution of General Administrative Law and the Emergence of Postmodern Administrative Law," European University Institute Working Paper LAW No. 2011/16 (2011).

The relevance of this analysis to a cryptographic protocol is immediate. A blockchain is a literal social network in Ladeur's sense. Its participants are not subjects of a sovereign; they are nodes in a graph, connected by edges of transaction, attestation, observation, and interpretation. The norms that govern the graph emerge from the structure of the graph, not from a central command. When a node operator updates software, that update propagates not by decree but by the social fact of others doing likewise; when a hard fork occurs, the question of "which chain is the real chain" is settled not by a court but by the decentralized act of participants choosing, individually, which chain to extend.

This connects to three classical results in the mathematics of networks that are, properly understood, constitutional facts of the new polity:

*Sarnoff's Law* (David Sarnoff, broadcasting era):[^21] the value of a one-to-many network grows linearly with the number of receivers. *V* ∝ *N*. The model is broadcast: one source, many sinks. State media are Sarnoff. So is, fundamentally, classical regulation: one regulator, many regulated.

[^21]: Sarnoff's Law was articulated in various RCA Annual Reports during Sarnoff's tenure as President and Chairman (1930–1970) and is conventionally cited to those documents. For modern restatement, see Bob Briscoe, Andrew Odlyzko, and Benjamin Tilly, "Metcalfe's Law is Wrong," *IEEE Spectrum* 43, no. 7 (2006): 34–39 (contrasting the three laws).

*Metcalfe's Law* (Robert Metcalfe, 1980):[^22] the value of a many-to-many network grows quadratically with the number of nodes. *V* ∝ *N²*. The model is point-to-point communication: each node can transact with each other. The internet is Metcalfe. So is a payment network.

[^22]: Robert Metcalfe articulated the law in 35mm slide presentations during 1980. For the canonical published statement, see George Gilder, "Metcalfe's Law and Legacy," *Forbes ASAP* (13 September 1993). For empirical evaluation, see Andrew Odlyzko and Benjamin Tilly, "A Refutation of Metcalfe's Law and a Better Estimate for the Value of Networks and Network Interconnections," AT&T Labs–Research (2 March 2005).

*Reed's Law* (David Reed, 1999):[^23] the value of a network capable of forming sub-groups grows exponentially with the number of nodes. *V* ∝ 2*ᴺ*. The model is group-formation: nodes associate into arbitrary subsets, each of which can act as a unit. Social networks are Reed. So, properly understood, is a fully programmable cryptographic protocol.

[^23]: David P. Reed, "That Sneaky Exponential — Beyond Metcalfe's Law to the Power of Community Building," *Context Magazine* (Spring 1999), reprinted in various venues; see http://www.reed.com/dpr/locus/gfn/reedslaw.html.

The constitutional implication is that cryptographic protocols built on Reed's-Law foundations cannot be effectively governed by Sarnoff's-Law institutions. A foundation, operating in the broadcast mode of one-source-many-sinks, cannot keep up with the combinatorial explosion of group-formation that the protocol enables. Any attempt to do so degenerates into some combination of (i) frantic and ineffective enforcement, (ii) corruption as the foundation accepts payments to look the other way, or (iii) capture as the foundation becomes coextensive with the largest economic interests in the protocol. None of these outcomes is desirable. All of them are observed empirically in the cryptocurrency industry.

The pre-commitment doctrine is the architectural answer. If the rules are frozen at the protocol level — if the *Soziale Grenzen* that the protocol enforces are codified in advance and cannot be modified by ordinary politics — then the protocol does not need to be governed at the Sarnoff scale. It governs itself at the Reed scale, through the dispersed, parallel, mutually-observing decisions of its participants. The foundation, if there is one, is not the governor; it is at most the trustee of a treasury and the keeper of a trademark, much as the Linux Foundation does not govern Linux.[^24]

[^24]: For the institutional analogy, see Steven Weber, *The Success of Open Source* (Cambridge, MA: Harvard University Press, 2004); Yochai Benkler, *The Wealth of Networks: How Social Production Transforms Markets and Freedom* (New Haven: Yale University Press, 2006).

## 7. Wittgenstein, Language Games, and the Anchoring Function of Code

Ludwig Wittgenstein's *Philosophische Untersuchungen* (1953)[^25] introduced the concept of *language games* (*Sprachspiele*) — the recognition that the meaning of a term is not fixed by reference to some external essence but is constituted by its use within a particular form of life. The same word, in different language games, may mean different things; and across time, the same language game may shift such that its central terms come to mean something other than they once did.

[^25]: Ludwig Wittgenstein, *Philosophische Untersuchungen / Philosophical Investigations*, 4th ed., trans. G.E.M. Anscombe, P.M.S. Hacker, and Joachim Schulte (Oxford: Wiley-Blackwell, 2009; orig. 1953), §§ 7, 23, 65–67, 199–202.

This is, for legal interpretation, simultaneously a liberation and a problem. It is a liberation because it acknowledges that legal terms are not fossils to be excavated but living instruments to be applied, and that fidelity to the past does not require literalism. It is a problem because it permits, over long enough time horizons, the silent inversion of any term whatsoever. *Privacy* in 1890, when Warren and Brandeis wrote the foundational article,[^26] meant freedom from intrusion by photographic press; *privacy* in 2026 means something at once narrower and broader, with a vast surveillance-capitalism overlay none of the original authors could have anticipated.[^27] *Suspicious activity* in 1970 meant something a banker could recognize from twenty years' acquaintance with a customer; *suspicious activity* in 2026 means a probabilistic output of a machine-learning model trained on terabytes of behavioral data. The terms are nominally continuous; the games have shifted.

[^26]: Samuel D. Warren and Louis D. Brandeis, "The Right to Privacy," *Harvard Law Review* 4, no. 5 (1890): 193–220.

[^27]: For the development of the privacy concept across a century, see Daniel J. Solove, *Understanding Privacy* (Cambridge, MA: Harvard University Press, 2008); Shoshana Zuboff, *The Age of Surveillance Capitalism: The Fight for a Human Future at the New Frontier of Power* (New York: PublicAffairs, 2019); Helen Nissenbaum, *Privacy in Context: Technology, Policy, and the Integrity of Social Life* (Stanford: Stanford University Press, 2010).

The constitutional consequence is that any rule expressed only in natural language is subject to slow drift through the porosity of language games. The kernel that the framers placed beyond ordinary politics may, two generations later, be inverted into its opposite simply because the words now mean different things. This is a real and observed phenomenon; it is the principal mechanism by which constitutional protections that look robust on paper become hollow in practice.[^28]

[^28]: For the historical pattern across constitutional regimes, see Bruce Ackerman, *We the People*, vols. 1–3 (Cambridge, MA: Harvard University Press, 1991, 1998, 2014); David A. Strauss, *The Living Constitution* (New York: Oxford University Press, 2010).

Cryptographic code, properly designed, escapes this problem. The expression `red >= 500 -> Tier::High` does not undergo Wittgensteinian drift. The number 500 in 2026 will be the number 500 in 2500. The constants compiled into the consensus today will execute with the same arithmetic in any year for which the compiler still produces a binary that the protocol can run. This is a remarkable property — perhaps unique among the constitutional substrates available to humanity — and it is the basis on which the strict pre-commitment doctrine can credibly claim to bind future generations.

The asymmetry deserves emphasis. In a purely linguistic constitutional order — even the best of them — the framers cannot bind their grandchildren, because their grandchildren will be playing a different language game and will, if asked, sincerely report that they are following the same constitution while in fact applying inverted rules. In a cryptographic constitutional order, the framers can bind not only their grandchildren but their great-great-grandchildren and their automated agents, because the binding takes the form of arithmetic that does not drift.

This is the most consequential and the most underappreciated property of consensus code. It is what makes possible a kind of pre-commitment that has, in human history, never previously been technically achievable: the long pre-commitment, the multi-generational pre-commitment, the *Verfassung* whose interpretive community is not its own descendants but a deterministic state machine.

A cryptographic protocol's pre-commitment to a frozen catalog of substantive rules — drawn from documented historical sources and compiled into the consensus — is, in this light, an exercise of the unique constitutional capacity that cryptographic code makes possible for the first time.

## 8. Transconstitutionalism and the Interface with State Constitutions

Marcelo Neves's *Transconstitucionalismo* (2009),[^29] drawing on and extending Gunther Teubner's work on societal constitutionalism,[^30] provides the framework for understanding how a cryptographic constitution interfaces with state constitutions without subordinating to either.

[^29]: Marcelo Neves, *Transconstitucionalismo* (São Paulo: Martins Fontes, 2009). English translation: Marcelo Neves, *Transconstitutionalism*, trans. Kevin Mundy (Oxford: Hart Publishing, 2013).

[^30]: Gunther Teubner, *Constitutional Fragments: Societal Constitutionalism and Globalization*, trans. Gareth Norbury (Oxford: Oxford University Press, 2012); Gunther Teubner, "Societal Constitutionalism: Alternatives to State-Centred Constitutional Theory?" in *Transnational Governance and Constitutionalism*, ed. Christian Joerges, Inger-Johanne Sand, and Gunther Teubner (Oxford: Hart Publishing, 2004), 3–28. Teubner's framework descends in significant part from Niklas Luhmann's systems theory; see Niklas Luhmann, *Das Recht der Gesellschaft* (Frankfurt: Suhrkamp, 1993).

Neves's central observation is that twenty-first-century constitutional problems frequently exceed the boundaries of any single constitutional order. A question that arises within Brazilian constitutional law may simultaneously implicate the European Convention on Human Rights, the Inter-American Court of Human Rights, the World Trade Organization regime, and the *lex mercatoria* of international commercial arbitration. None of these orders is hierarchically supreme over the others; each constructs its own answer; the problem cannot be solved by reference to any one of them alone. *Transconstitutionalism* names the practice by which courts and other constitutional actors negotiate these collisions through reciprocal observation, mutual learning, and partial accommodation, without any pretense of unified hierarchy.

For a cryptographic protocol, the transconstitutional position is structural. The protocol is, simultaneously, governed by:

- the constitution of the state in which any particular node operator resides, regulating that operator's behavior as that state's resident;
- the constitution of any state to which any particular wallet's owner is connected by citizenship, residence, or transaction;
- the *lex mercatoria* of cryptographic exchanges through which the protocol's tokens are bought and sold;
- the FATF-mediated soft law that frames the AML/CFT obligations of all jurisdictions;[^31] and
- its own consensus rules, which are constitutional in the sense developed in this Article.

[^31]: Financial Action Task Force, *International Standards on Combating Money Laundering and the Financing of Terrorism & Proliferation: The FATF Recommendations* (Paris: FATF/OECD, 2012, technical revisions 2023). On the soft-law character of FATF norms and their de facto bindingness via mutual evaluation, see Mark T. Nance, "The Regime that FATF Built: An Introduction to the Financial Action Task Force," *Crime, Law and Social Change* 69, no. 2 (2018): 109–129.

These five orders do not stand in hierarchical relation to one another. The protocol's consensus rules cannot override the criminal law of the state where a node operator resides; that state's criminal law cannot override the protocol's consensus rules for a node operator in a different jurisdiction; FATF soft law has no direct legal effect on either. What the orders must do is observe one another, accommodate one another at the margins, and interpret their own commitments in light of their interface with the others.

The practical implication is that the protocol's consensus rules must not attempt to displace state law, and equally must not be displaceable by state law. The protocol does not freeze, sequester, or interfere with the property rights of any wallet, because doing so would be a constitutional encroachment on the property regimes of the various states whose residents the wallets may belong to. Equally, the protocol's classifications are not subject to override by state pressure on a foundation or operator, because there is no foundation or operator with the technical capacity to perform the override. The interface is mediated by the off-protocol decisions of regulated counterparties — exchanges, banks, custodians — who choose, under their own state's law, what to do with the metadata the protocol provides. That is the proper transconstitutional posture: the protocol provides reproducible, time-bounded, disputable metadata; the regulated counterparties operate under their own state's law; the state regulates its own residents; no order pretends to subsume any other.

The pre-commitment doctrine is therefore not a claim of cryptographic sovereignty against state sovereignty. It is a claim about what the protocol's own constitutional commitments are, made in full awareness that the protocol exists alongside, and not above, the constitutional orders of states. The protocol commits not to assist, by computational complicity, in financing terror, trafficking persons, or laundering serious-crime proceeds. It does not commit to enforce any state's particular AML/CFT rules; it commits to a documented historical kernel that every state's AML/CFT framework agrees upon at the center, however much the peripheries may differ.

## 9. Game-Theoretic Foundations: Pre-Commitment, Repetition, and the Architecture of Cooperation Without a Sovereign

The game-theoretic foundation of the strict pre-commitment doctrine lies in four bodies of work: Thomas Schelling's analysis of credible commitment,[^32] John Nash's equilibrium theory,[^33] Robert Aumann's work on repeated games and common knowledge,[^34] and Robert Axelrod's empirical and computational study of the emergence of cooperation in iterated interactions.[^35] Together these four constitute, perhaps unintentionally, the most powerful intellectual case ever made for the proposition that cooperation among self-interested agents can be sustained, robustly and over indefinite horizons, without a central authority. They are accordingly the indispensable theoretical scaffolding for any cryptographic protocol that aspires to be a substrate for civil cooperation rather than an instrument of state command.

[^32]: Thomas C. Schelling, *The Strategy of Conflict* (Cambridge, MA: Harvard University Press, 1960); Thomas C. Schelling, *Arms and Influence* (New Haven: Yale University Press, 1966); Thomas C. Schelling, *Choice and Consequence* (Cambridge, MA: Harvard University Press, 1984).

[^33]: John F. Nash Jr., "Equilibrium Points in N-Person Games," *Proceedings of the National Academy of Sciences* 36, no. 1 (1950): 48–49; John F. Nash Jr., "Non-Cooperative Games," *Annals of Mathematics* 54, no. 2 (1951): 286–295.

[^34]: Robert J. Aumann, "Acceptable Points in General Cooperative *N*-Person Games," in *Contributions to the Theory of Games, Volume IV*, ed. A.W. Tucker and R.D. Luce (Princeton: Princeton University Press, 1959), 287–324; Robert J. Aumann, "Subjectivity and Correlation in Randomized Strategies," *Journal of Mathematical Economics* 1, no. 1 (1974): 67–96; Robert J. Aumann, "Agreeing to Disagree," *Annals of Statistics* 4, no. 6 (1976): 1236–1239.

[^35]: Robert Axelrod, *The Evolution of Cooperation*, rev. ed. (New York: Basic Books, 2006; orig. 1984); Robert Axelrod, *The Complexity of Cooperation: Agent-Based Models of Competition and Collaboration* (Princeton: Princeton University Press, 1997).

### 9.1 Schelling: The Strategic Value of Binding Oneself

Schelling's central insight, applied here, is that an actor who voluntarily restricts his own future options can thereby gain bargaining power. *I cannot turn back; therefore the highway is mine* is a perfectly rational threat for the driver who has visibly torn off his own steering wheel and thrown it out the window, and a hollow one for the driver who has not. The capacity to bind oneself in advance is, paradoxically, a source of strategic strength rather than weakness, because it removes from the bargaining space the equilibria in which one yields.

For a cryptographic protocol seeking to operate at scale across many jurisdictions and many decades, the relevant Schelling problem is as follows. There exists a set of possible equilibria in which the protocol becomes, in effect, a tool of arbitrary state pressure: the foundation accepts every freezing request from every regulator, and the protocol becomes worse, for the user, than the legacy banking system it was meant to escape. There exists another set of equilibria in which the protocol commits, in advance and credibly, to a bounded and historically-grounded AML/CFT kernel and to nothing further: in those equilibria, the protocol is useful both to legitimate users (who benefit from the predictability) and to states (who benefit from the documented kernel of compliance) without becoming a tool of arbitrary capture.

The first set of equilibria is reached by any protocol that retains an in-protocol governance mechanism capable of updating the AML/CFT rules. The mechanism does not need to be exercised; its mere existence is sufficient to admit the bad equilibria, because every state regulator, and every well-funded private actor, can correctly anticipate that pressure on the foundation will eventually produce updates. The second set of equilibria is reached only by protocols that have credibly disabled the mechanism — in Schelling's terms, *visibly thrown the steering wheel out of the window*.

Strict pre-commitment is therefore not a luxury or a romantic gesture. It is the condition on which the protocol can occupy the desirable Schelling point at all. A protocol that retains a foundation multisig has, in effect, kept the steering wheel; its credible commitments are weaker; its equilibria are worse. A protocol that has compiled its fundamental rules into consensus has thrown the steering wheel out of the window; its commitments are credible; its equilibria are better.

### 9.2 Nash: Equilibria as Functions of Belief About the Future

Nash's contribution, layered on top, is the demonstration that under the conditions of repeated play and rational expectations, the equilibria a system reaches depend not only on its current rules but on the beliefs of its participants about what its rules will be in the future. A system whose participants believe that the rules are subject to change at any moment by a foundation will play the system as if every transaction is potentially subject to retrospective reclassification; it will accordingly under-invest in long-term commitments to the system. A system whose participants believe that the rules are frozen will play the system as a stable substrate; it will accordingly support the kinds of long-term economic relations — multi-decade savings, generational wealth transfer, contracts denominated in the protocol's units — that distinguish a serious financial layer from a speculative casino.

The pre-commitment is therefore, simultaneously, a reduction in the protocol's optionality and an increase in the value of the protocol as a substrate. Optionality and substrate value are, in this domain, in opposition; one must be sacrificed to obtain the other.

### 9.3 Aumann: Common Knowledge and the Folk Theorem

Robert Aumann's contributions, awarded the 2005 Bank of Sweden Prize in Economic Sciences alongside Schelling's,[^36] complete the picture in two directions that are decisive for cryptographic protocols.

[^36]: Bank of Sweden Prize in Economic Sciences in Memory of Alfred Nobel 2005, jointly to Robert J. Aumann and Thomas C. Schelling, "for having enhanced our understanding of conflict and cooperation through game-theory analysis."

The first is Aumann's analysis of *common knowledge*, articulated in "Agreeing to Disagree" (1976). A proposition is common knowledge in a group when each member knows it, knows that the others know it, knows that the others know that he knows, and so on indefinitely. Aumann demonstrated, with mathematical precision, that two rational agents whose prior probabilities are common knowledge cannot rationally agree to disagree about the posterior probability of any event, given common knowledge of their posteriors. The result was startling because it implied that genuine persistent disagreement among rational, fully-informed agents requires either differing priors or some breakdown in the common-knowledge structure.[^37]

[^37]: For the technical apparatus and subsequent literature, see John Geanakoplos, "Common Knowledge," *Journal of Economic Perspectives* 6, no. 4 (1992): 53–82; Adam Brandenburger and Eddie Dekel, "Common Knowledge with Probability 1," *Journal of Mathematical Economics* 16, no. 3 (1987): 237–245.

The cryptographic application is foundational. A blockchain's consensus rules, compiled into the binary that every participating node executes, constitute a regime of common knowledge in Aumann's sense. Every node knows the rules; every node knows that the other nodes know the rules; every node knows that the other nodes know that it knows. This common-knowledge structure is what makes Byzantine-fault-tolerant agreement possible at all:[^38] agents who possess common knowledge of the validity criteria for blocks can converge on a single canonical history without any of them needing to trust the others' good faith. The pre-commitment doctrine deepens this property. By placing the AML/CFT rules and the scoring model beyond in-protocol mutability, the protocol guarantees that the common-knowledge structure that holds at block one will hold at block one billion: every participant, at every future point in time, will have the same common knowledge of the rules, because the rules cannot drift. This is not a trivial property; in any system with mutable governance, the common-knowledge structure can erode, since participants must reason not about the rules as written but about the rules as they may become.

[^38]: For the foundational distributed-systems result, see Leslie Lamport, Robert Shostak, and Marshall Pease, "The Byzantine Generals Problem," *ACM Transactions on Programming Languages and Systems* 4, no. 3 (1982): 382–401. For its application to cryptographic consensus, see Christian Cachin and Marko Vukolić, "Blockchain Consensus Protocols in the Wild," in *31st International Symposium on Distributed Computing*, ed. Andréa W. Richa (Schloss Dagstuhl, 2017).

The second Aumann contribution is the *folk theorem* for repeated games (foundational papers 1959 onward),[^39] which establishes that in infinitely repeated games with sufficient patience among the players, almost any individually rational outcome is sustainable as a subgame-perfect equilibrium. The intuition: when interactions repeat indefinitely and the future matters enough relative to the present, players can credibly punish defection by future non-cooperation, and this prospective punishment supports cooperation in the present even among purely self-interested agents. Cooperation does not require altruism or a sovereign enforcer; it requires only that the shadow of the future be long enough, and that the rules of the game be stable enough to make threats credible.

[^39]: Aumann, "Acceptable Points," (n. 34); Drew Fudenberg and Eric Maskin, "The Folk Theorem in Repeated Games with Discounting or with Incomplete Information," *Econometrica* 54, no. 3 (1986): 533–554; James Friedman, "A Non-Cooperative Equilibrium for Supergames," *Review of Economic Studies* 38, no. 1 (1971): 1–12.

The blockchain context maps onto these conditions remarkably cleanly. The "game" played by participants — node operators, oracles, users, exchanges — is indefinitely repeated; there is no last block. The "shadow of the future" is constituted by the persistence of the chain itself: actions taken today are observable to all future participants because they are in the immutable history. The credibility of cooperation-supporting strategies depends critically on the *stability of the rules*: a participant can credibly commit to "cooperate so long as you do" only if the criteria for cooperation will not be redefined under his feet. The pre-commitment doctrine, by freezing those criteria, satisfies the precondition of the folk theorem and makes the cooperative equilibria reachable. A protocol with mutable governance, by contrast, perpetually invites participants to defect now because the rules of cooperation in the future are uncertain; the folk theorem fails, and the equilibria collapse toward defection.

A third Aumann result, *correlated equilibria* (1974), is also relevant. Aumann showed that a public coordinating signal — a Schelling-point broadcast on which all players can condition their strategies — can support equilibria that are unreachable by unilateral randomization. In a blockchain, the block hash and the consensus state are precisely such public signals: every participant observes them, conditions strategy on them, and can therefore reach correlated equilibria that purely independent agents could not. The protocol's role, in this light, is not to dictate behavior but to provide the public coordinating signal around which voluntary cooperation can crystallize.

### 9.4 Axelrod: The Empirical Conditions for Cooperation

If Aumann established the *theoretical possibility* of cooperation without sovereignty, Robert Axelrod established its *empirical conditions*. *The Evolution of Cooperation* (1984) reported the now-famous tournament in which programmed strategies played iterated Prisoner's Dilemmas against each other in round-robin format. The winning strategy, submitted by Anatol Rapoport, was the simplest of all: *tit-for-tat* — cooperate on the first move, then on every subsequent move do whatever the opponent did on the previous move.[^40] Tit-for-tat does not maximize against any single opponent; it maximizes across the population of opponents one will, in fact, encounter, by satisfying four conditions Axelrod identified as together sufficient for the emergence of cooperation:

[^40]: Anatol Rapoport and Albert M. Chammah, *Prisoner's Dilemma: A Study in Conflict and Cooperation* (Ann Arbor: University of Michigan Press, 1965).

1. **Niceness** — never defect first. The strategy gives every counterparty the opportunity to cooperate before treating them as an adversary.
2. **Retaliation** — punish defection promptly and proportionately. The strategy is not exploitable by opportunists; defection has immediate cost.
3. **Forgiveness** — return to cooperation as soon as the counterparty does. The strategy does not hold grudges; a single defection does not condemn an opponent to permanent hostility.
4. **Clarity** — be intelligible to the counterparty. The strategy must be simple enough that the counterparty can correctly predict it; cooperation is impossible to negotiate with an opponent whose responses are mysterious.

Axelrod's argument is that cooperation is not a moral overlay on rational self-interest but an *emergent property* of repeated interaction under these four conditions. Where the conditions are satisfied, cooperation crystallizes among purely self-interested agents; where they are violated, it collapses. Crucially, cooperation does not require a Leviathan;[^41] it requires the right structure of repeated interaction.

[^41]: The contrast with Hobbes is intentional. See Thomas Hobbes, *Leviathan, or The Matter, Forme, and Power of a Common-Wealth Ecclesiasticall and Civill* (London: Andrew Crooke, 1651), ch. XIII–XVIII (the state of nature; the social contract; the necessity of an absolute sovereign). The Aumann/Axelrod synthesis demonstrates that the Hobbesian premise — that cooperation among self-interested agents requires an absolute sovereign — is empirically and theoretically false in indefinitely repeated games meeting the conditions specified.

The cryptographic protocol, examined through Axelrod's lens, can be designed as a tit-for-tat at protocol scale.

- **Niceness**: every wallet is presumed legitimate by default. The protocol does not preemptively suspect or restrict; it elevates a wallet to a higher-risk classification only on demonstrable evidence of risk patterns.
- **Retaliation**: signing oracles who attest fraudulent classifications are mechanically slashed; their stake is reduced in proportion to the offense; the punishment is automatic, immediate, and visible to every participant.
- **Forgiveness**: slashing reduces but does not annihilate. An oracle whose stake has been partially slashed can continue to participate honestly and accumulate reputation; there is no permanent expulsion from the active set except for the most severe offense (equivocation, which the Aumann common-knowledge framework treats as the cardinal violation since it directly attacks the common-knowledge structure). Wallets misclassified can dispute, post bond, present evidence, and have the classification reversed with reward.
- **Clarity**: the rules are compiled into the consensus and published as open-source code. There is no hidden discretionary layer. Any participant can read the source, run the model, reproduce the score, and predict precisely how the protocol will treat any given pattern of behavior. This is the Axelrod condition raised to its highest possible degree: not merely intelligible but *bit-for-bit deterministic*.

The four conditions are simultaneously satisfied. Cooperation is, accordingly, the equilibrium toward which the protocol's design pulls its participants. Not because they are required to cooperate, and not because some sovereign forces them, but because the structure of repeated interaction within the protocol — niceness, retaliation, forgiveness, clarity — makes cooperation the rational response to repeated play.

### 9.5 Synthesis: Cooperation Without a Leviathan

The synthesis of Schelling, Nash, Aumann, and Axelrod yields a thesis that is both more modest and more radical than commonly recognized. *More modest*, because it does not claim that cryptographic protocols can dispense with social trust altogether; trust must exist in the consensus rules, in the open-source review process, in the willingness of node operators to update software when bugs are discovered. *More radical*, because it claims that cooperation among indefinitely many self-interested agents, across indefinitely many jurisdictions, over indefinitely long time horizons, is possible *without a sovereign*, provided that the conditions identified by these four authors are jointly satisfied. The conditions are: credible pre-commitment (Schelling), stability of forward expectations (Nash), common knowledge of rules and adequate shadow of the future (Aumann), and the structural conditions for emergence of cooperation in repeated interaction (Axelrod).

These conditions cannot be satisfied by a protocol with mutable governance. A foundation that can update the rules destroys the credibility of pre-commitment; introduces uncertainty into forward expectations; corrodes the common-knowledge structure (since "the rules" become a moving target); and disrupts the conditions for cooperation by making future retaliation and forgiveness undefined. Mutable governance is, in the deepest sense, anti-cooperative; it converts what could be an indefinitely repeated cooperative game into a series of one-shot games against an unpredictable rule-setter, in which the rational strategy is opportunistic defection rather than principled cooperation.

The pre-commitment doctrine, by contrast, satisfies all four conditions simultaneously and creates the structural conditions under which cooperation is the emergent equilibrium rather than the exception. This is, properly understood, the central argument of this Article. The pre-commitment is not a constraint imposed on the protocol from outside; it is the *enabling condition* for the protocol to function as a substrate for civil cooperation in the absence of a sovereign.

## 10. The New Crypto-Civil Cooperation

If Part 9 established the theoretical possibility of cooperation without sovereignty, the present Part addresses what we are, normatively, building. The cryptographic protocol envisioned here is not merely a technical artifact. It is a constitutional infrastructure for a particular kind of society — a society organized around three interlocking commitments: the right to financial privacy, the freedom of contract, and the use of cryptographic consensus as the substrate of voluntary cooperation.

These three commitments are inseparable. Privacy without contractual liberty becomes mere concealment. Contractual liberty without privacy becomes commercial vulnerability. Either, without a substrate that allows voluntary cooperation among strangers across jurisdictions, becomes parochial — useful only within the narrow circle of those one already knows. Together, they constitute what may be called the *crypto-civil cooperation*: a form of social cooperation made possible by mathematics and made stable by pre-commitment.

### 10.1 Privacy as a Network Good

The dominant twentieth-century framing of privacy was individualist. Warren and Brandeis (1890) defined privacy as "the right to be let alone"; the conceptual frame was a fence around the self. This framing, while powerful and true at its core, missed a structural property of privacy that has become inescapable in the network society: privacy is not, primarily, an individual good; it is a *network good*. The privacy of any individual depends on the prevalence of privacy-using behavior in the population. A dissident who uses an encrypted channel in a society where no one else does is signaling, by the very fact of using it, that he is a dissident. A whistleblower who uses Tor in a network where Tor users are presumptively suspect is exposing himself, not protecting himself. Privacy, like a public park or a clean atmosphere, is sustained or destroyed in aggregate.[^42]

[^42]: For privacy as a collective rather than purely individual good, see Priscilla M. Regan, *Legislating Privacy: Technology, Social Values, and Public Policy* (Chapel Hill: University of North Carolina Press, 1995); Joshua A. T. Fairfield and Christoph Engel, "Privacy as a Public Good," *Duke Law Journal* 65, no. 3 (2015): 385–457; Anita Allen, *Unpopular Privacy: What Must We Hide?* (New York: Oxford University Press, 2011).

This implies an inverted tragedy of the commons. In the classical tragedy,[^43] individually rational use of a common resource exhausts it. In the inverted privacy tragedy, individual abstention from privacy-preserving practices destroys privacy as a common resource — by leaving it usable only by those whose use is presumptively suspicious. The cooperative response is universal use: if privacy-preserving infrastructure is the default for ordinary economic activity, the cost of using it for sensitive activity falls to zero, because such use is no longer a signal.

[^43]: Garrett Hardin, "The Tragedy of the Commons," *Science* 162, no. 3859 (1968): 1243–1248. For the inversion, see Fairfield and Engel, "Privacy as a Public Good" (n. 42).

The cryptographic protocol's commitment to privacy as the default is, in this light, not a libertarian indulgence; it is a contribution to a network good. By being a usable substrate for ordinary commerce — for paying merchants, for receiving wages, for sending remittances, for storing savings — it makes the privacy properties available without singling out the user. The dissident, the whistleblower, the abuse victim, the political refugee benefit not from a separate dissident-only system that marks them out, but from a general-purpose system in which their use is indistinguishable from the use made by millions of ordinary participants. This is the cooperative architecture of privacy: the more people who use it for ordinary purposes, the more usable it is for extraordinary purposes by those who genuinely need its protections.

The implication is that privacy-by-default is itself a cooperative good in Axelrod's sense. Each participant's voluntary use of the protocol contributes to the privacy of every other participant. The cooperation is automatic; no one is required to cooperate, but cooperation emerges as the structural consequence of widespread use. This is, properly understood, an instance of the folk-theorem cooperation that Aumann described: the aggregate equilibrium in which every participant's privacy is preserved is sustained by the indefinite repetition of voluntary use, with no central enforcer required.

### 10.2 Freedom of Contract as a Fundamental Right

The second pillar of the crypto-civil cooperation is the freedom of contract. The doctrinal genealogy is well-known. Locke (*Second Treatise*, 1689)[^44] grounded political society in voluntary covenant; Kant (*Metaphysik der Sitten*, 1797)[^45] located human dignity in the capacity to be the author of one's own obligations; Maine (*Ancient Law*, 1861)[^46] traced the historical movement of progressive societies "from status to contract"; Atiyah (*The Rise and Fall of Freedom of Contract*, 1979)[^47] documented both the high-water mark of the classical doctrine and its twentieth-century retreat in favor of regulatory intervention in private agreements.

[^44]: John Locke, *Two Treatises of Government*, ed. Peter Laslett, student ed. (Cambridge: Cambridge University Press, 1988; orig. 1689), particularly *Second Treatise*, §§ 95–122.

[^45]: Immanuel Kant, *Die Metaphysik der Sitten / The Metaphysics of Morals*, trans. Mary Gregor (Cambridge: Cambridge University Press, 1996; orig. 1797), particularly *Rechtslehre*, §§ 18–31.

[^46]: Henry Sumner Maine, *Ancient Law: Its Connection with the Early History of Society and its Relation to Modern Ideas* (London: John Murray, 1861), ch. 5 ("from status to contract").

[^47]: P. S. Atiyah, *The Rise and Fall of Freedom of Contract* (Oxford: Clarendon Press, 1979).

The post-1971 monetary order, combined with the post-2008 regulatory expansion, has produced a peculiar contemporary condition: the formal legal capacity to contract is preserved, but the practical substrate on which contracts are denominated is unstable, and the practical capacity to execute contracts at the margins is increasingly subject to administrative override. A contract denominated in fiat currency in 1971 was a contract denominated in something with stable purchasing power; a contract denominated in fiat currency in 2026 is a contract denominated in something whose value depends on the discretionary decisions of a central bank that may, with no public deliberation and no individual notice, alter the supply of the unit. A contract for cross-border payment in 1971 could be reliably executed through correspondent banks; a contract for cross-border payment in 2026 may be executed, or refused, depending on the political relations between the originating and receiving jurisdictions and the AML/CFT compliance posture of every intermediating bank.

The cryptographic substrate restores the conditions on which the classical freedom of contract presupposes. A contract denominated in a token whose supply is governed by consensus rules that cannot be altered by any in-protocol authority is a contract whose unit of account is stable in the sense Locke and Kant presupposed. A contract executed through cryptographic consensus, with finality measured in minutes and counterparty risk reduced to the cryptographic strength of the underlying primitives, is a contract whose execution does not depend on the political relations of states. The freedom of contract, hollow in the late-modern fiat regime, recovers operative meaning in the cryptographic substrate.

This is not a libertarian-utopian claim. It does not mean that all contracts will be enforced by the protocol — most contracts (employment, marriage, real-property transfer) involve obligations that cannot be reduced to on-chain operations. It means that the *financial dimension* of contractual life — the storing and transferring of value — recovers a stability and a transnational availability that the post-1971 fiat order has failed to provide. Within that financial dimension, the protocol offers what Maine described as the most progressive condition of social cooperation: voluntary covenant among free agents on terms they themselves have chosen, with stable units of account, predictable execution, and resistance to retrospective administrative override.

Contractual liberty in this restored sense is not anti-state. It is a complement to the state, in domains where the state has structurally failed. The state retains its full jurisdiction over its residents; the protocol does not displace any law, any tribunal, any tax authority. What the protocol provides is a substrate on which voluntary cooperation can occur without the failures of the post-1971 order being imported by default. The state may regulate, prohibit, or compel disclosure as its constitutional order permits; what it cannot do, because the protocol's pre-commitments make it cryptographically infeasible, is silently devalue the unit, retrospectively reclassify a transaction, or freeze a wallet by administrative fiat against the consensus rules. The state's authority over its residents is preserved; the residents' substrate for cooperation is also preserved. Both are, in the proper sense, sovereign in their respective domains.

### 10.3 Blockchain as the Substrate of Voluntary Association

The third pillar is the use of cryptographic consensus as the *substrate* of voluntary cooperation — not as its replacement, not as its sovereign, but as the medium through which it occurs. The phrase is precise. A substrate is what supports without dictating; it is the floor on which the activity rests, not the program that the activity executes. Roads are a substrate of commerce; they do not dictate where commerce goes. Currency is a substrate of exchange; it does not dictate what is exchanged. The cryptographic consensus is the substrate of digital cooperation; it does not dictate what cooperators do with the substrate, only that they can do it without trusting one another individually and without trusting a central authority.

The civil-society analogue is illuminating. Tocqueville (*Democracy in America*, 1835/1840)[^48] observed that the strength of American democracy lay not in its political institutions narrowly considered but in its dense network of voluntary associations — churches, clubs, mutual-aid societies, cooperatives — through which citizens organized collective life without state mediation. Putnam (*Bowling Alone*, 2000)[^49] documented the late-twentieth-century erosion of those associations and the social pathologies that accompanied their decline. The diagnosis common to both is that civil cooperation does not arise spontaneously; it requires *infrastructure of association* — buildings, communication channels, customary norms, financial instruments — that allow individuals to coordinate around shared purposes without requiring a sovereign to coordinate them.

[^48]: Alexis de Tocqueville, *De la démocratie en Amérique*, vols. I (1835) and II (1840). Modern English translation: *Democracy in America*, trans. Harvey C. Mansfield and Delba Winthrop (Chicago: University of Chicago Press, 2000).

[^49]: Robert D. Putnam, *Bowling Alone: The Collapse and Revival of American Community* (New York: Simon & Schuster, 2000).

The cryptographic substrate is the twenty-first-century infrastructure of voluntary association at planetary scale. A diaspora community can pool funds for a mutual-aid initiative across twelve jurisdictions without depending on banks in any of them. A group of researchers can fund open-source software development through micropayments from anyone, anywhere, without intermediating institutions. A cooperative of small producers can settle accounts with their customers in a unit of value that does not lose purchasing power between the time of sale and the time of withdrawal. None of this requires permission, registration, or recognition by any state. The activities themselves remain subject to whatever law their participants are subject to under their own jurisdictions; the *substrate* on which they coordinate is provided by the protocol.

This is the renewed civil cooperation that the cryptographic project is designed to support: not a libertarian fantasy of state-displacement, but a Tocquevillean revival of voluntary association on a substrate adequate to the twenty-first-century scale. The pre-commitment doctrine is, in this framing, the constitutional condition under which the substrate can perform its substrate function. A substrate that is mutable by some authority is not a substrate; it is a service, with all the contingency that services entail. Only a substrate fixed by mathematical commitment can support the indefinite-horizon, planetary-scale, jurisdiction-spanning voluntary cooperation that the late-modern condition both makes possible and makes necessary.

### 10.4 The *Civitas Cryptographica*

What emerges from these three commitments — privacy as a network good, freedom of contract on a stable substrate, voluntary association mediated by mathematics — is what may be called the *civitas cryptographica*: a civil order constituted not by territorial sovereignty but by participation in a cryptographic protocol. Citizenship in this *civitas* is voluntary and operational: one is a participant by virtue of running a node, holding a key, signing a transaction; one ceases to be a participant by ceasing those acts. There is no nationality, no naturalization, no expulsion. Every participant is, in the relevant sense, a citizen by the same act, on the same terms, with the same rights and obligations as every other.

The *civitas cryptographica* is not a state. It does not claim a monopoly on legitimate force;[^50] indeed it claims no force at all. Its authority extends only to the validity of blocks, the application of consensus rules, the deterministic execution of transactions. It cannot tax; it cannot conscript; it cannot punish in any sense beyond the slashing of bonded stake. It is, in the precise sense, a *civil* society — a society of voluntary cooperators, sharing a substrate, governed by rules they themselves have committed to in advance and that none of them can unilaterally alter.

[^50]: Compare Max Weber, *Wirtschaft und Gesellschaft* (Tübingen: Mohr, 1922), ch. 1 (defining the modern state as the human community that successfully claims the monopoly of the legitimate use of physical force within a given territory). The *civitas cryptographica* claims no such monopoly and is not a competitor to the Weberian state in this regard; it is a parallel infrastructure for civil cooperation in a domain where the Weberian state's primary functions (territorial governance, criminal jurisdiction) do not apply.

Yet for all its modesty, the *civitas cryptographica* accomplishes something the modern state has, in the post-1971 order, conspicuously failed to accomplish: it provides a stable monetary substrate, a credible commitment to non-arbitrary treatment, and permission-less access to financial cooperation across the boundaries of states. The modern state has, in many places, withdrawn from these functions or performed them poorly; the *civitas cryptographica* supplies them by means that do not depend on the state's continued capacity or willingness. This is not a hostile takeover; it is, more accurately, a parallel infrastructure made available wherever the primary infrastructure has degraded.

The cooperation that this *civitas* supports is not utopian. It is bounded by the same human imperfections and adversarial realities as any cooperation. Some participants will attempt to defraud; some will attempt to launder; some will attempt to capture. The architecture of pre-commitment, slashing, dispute resolution, and tag-only AML/CFT classification is calibrated to make these adversarial behaviors costly and, in the long run, unprofitable, while preserving the privacy-by-default and freedom-by-default that legitimate use requires. The four Axelrod conditions — niceness, retaliation, forgiveness, clarity — are simultaneously the structure that supports cooperation and the structure that contains the predictable failures.

## 11. The AML/CFT Kernel as Permanent Pre-Commitment

The objection arises immediately: *how can it be claimed that any specific catalog of AML/CFT rules will be appropriate in 2050, in 2300, in 2500? Surely the right rules in 2026 are not the right rules in any of those years?*

The answer requires distinguishing between the *kernel* and the *forms*. The kernel of AML/CFT is the prohibition of computational assistance to: (i) the financing of terrorism, (ii) the trafficking of persons, and (iii) the laundering of identifiable proceeds of serious crime. This kernel was already operative, in substance, in the early twentieth century. The 1908 establishment of the United States Bureau of Investigation (later the Federal Bureau of Investigation) was directly motivated by the federal government's inability to prosecute interstate financial fraud — that is, money laundering, although the term had not yet been coined.[^51] The 1929 Geneva Convention for the Suppression of Counterfeiting Currency[^52] was, in substance, an early international AML instrument. Meyer Lansky's industrial-scale laundering of Prohibition-era proceeds through Cuban casinos in the 1930s and 1940s is the classic case study in every contemporary AML curriculum.[^53] The 1989 founding of the Financial Action Task Force, the 1990 publication of the original Forty Recommendations, the post-2001 Special Recommendations on Terrorist Financing, the successive European Union AML Directives of 1991, 2001, 2005, 2015, and 2018[^54] — all of these refine the *forms* of the regulatory response, but the *kernel* has been stable.

[^51]: For the institutional history, see Athan G. Theoharis et al., *The FBI: A Comprehensive Reference Guide* (Phoenix: Oryx Press, 1999); Tim Weiner, *Enemies: A History of the FBI* (New York: Random House, 2012).

[^52]: International Convention for the Suppression of Counterfeiting Currency, opened for signature 20 April 1929, 112 League of Nations Treaty Series 371.

[^53]: For the Lansky case, see Robert Lacey, *Little Man: Meyer Lansky and the Gangster Life* (Boston: Little, Brown, 1991); Thomas Naylor, *Wages of Crime: Black Markets, Illegal Finance, and the Underworld Economy*, rev. ed. (Ithaca: Cornell University Press, 2004), ch. 1.

[^54]: Council Directive 91/308/EEC (10 June 1991) (First AMLD); Directive 2001/97/EC (Second AMLD); Directive 2005/60/EC (Third AMLD); Directive (EU) 2015/849 (Fourth AMLD); Directive (EU) 2018/843 (Fifth AMLD).

Why? Because the kernel reflects categorical moral judgments that do not depend on the empirical particulars of any era. *Financing the deliberate killing of civilians for political effect is not a legitimate use of the financial system* is a judgment available to a thoughtful actor in 1900 and in 2500 in the same form. *Laundering the proceeds of trafficking persons for forced labor is not a legitimate use of the financial system* likewise. The forms by which financing-of-terror is accomplished change — gold couriers in 1900, hawala in 1950, shell corporations in 1990, mixers in 2020, perhaps post-quantum-confidential transactions in 2050 — but each instantiation is recognizable as the same kernel applied to a new substrate.

The cryptographic protocol's approach is therefore to encode the *kernel* — not the forms. The risk-classification components are not "any address that has ever interacted with a mixer." They are: direct sanctions match (a stable concept since U.N. Resolution 1267 of 1999); structuring patterns (a stable concept since 18 U.S.C. § 5324 of 1986); rapid pass-through patterns (a stable concept since the Visa transit-account heuristics of the 1990s); trafficking typologies (a stable concept since the Palermo Protocol of 2000);[^55] ransom-collection patterns (a stable concept since the Egmont Group typologies of the late 2010s).[^56] Each component is calibrated to the *abstract* pattern, not to any specific instantiation thereof. A 2050 implementation of a structuring scheme will be recognizable to the 2026-encoded structuring component, because the abstract pattern — many small transfers below a reporting threshold to evade detection — is what is encoded.

[^55]: Protocol to Prevent, Suppress and Punish Trafficking in Persons, Especially Women and Children, supplementing the U.N. Convention against Transnational Organized Crime, opened for signature 15 November 2000, 2237 U.N.T.S. 319.

[^56]: Egmont Group of Financial Intelligence Units, *FIU's in Action — 100 Cases from the Egmont Group*, periodic typology series (1996–present).

This is the same logic by which constitutional rights survive the centuries. The Fourth Amendment's prohibition on "unreasonable searches and seizures" was drafted in 1791 with quill pens and tricorn hats in mind; it applies in 2026 to telephone wiretaps, satellite imagery, mobile-phone location data, and (mutatis mutandis) blockchain-analytic deanonymization.[^57] The kernel — *the state must not, without due process, invade the secure boundaries of personal life* — is invariant; the forms shift. A constitutional protection that was tied to specific forms would expire with those forms; a protection tied to a kernel survives them.

[^57]: For the doctrinal trajectory, see *Olmstead v. United States*, 277 U.S. 438 (1928) (telephone wiretap, originally not "search"); *Katz v. United States*, 389 U.S. 347 (1967) (overruling *Olmstead*; "reasonable expectation of privacy" test); *Kyllo v. United States*, 533 U.S. 27 (2001) (thermal imaging); *United States v. Jones*, 565 U.S. 400 (2012) (GPS tracking); *Riley v. California*, 573 U.S. 373 (2014) (cell-phone search incident to arrest); *Carpenter v. United States*, 138 S. Ct. 2206 (2018) (cell-site location information).

The frozen scoring constants compiled into a properly designed cryptographic AML/CFT layer are accordingly not a snapshot of 2026 practice; they are an attempt to encode the kernel that has been stable for over a century and that there is every reason to expect will remain stable for centuries more. If the encoding is incorrect — if it has captured forms when it should have captured kernel — it is wrong, and a hard fork will eventually correct it. But the strategy is to err on the side of the kernel, and the historical record of AML/CFT thought is sufficient to identify it.

## 12. Why a Foundation Must Not Govern

The empirical record of foundation-governed cryptocurrency protocols is mixed. The Tezos Foundation lawsuits of 2017–2020[^58] demonstrated that a Swiss-domiciled foundation with treasury control becomes, in effect, a target for litigation by economically interested parties seeking to influence protocol development. The Cardano Foundation governance disputes of 2018–2020[^59] demonstrated that a foundation can become the focus of a power struggle between commercially interested parties to the disadvantage of the protocol's user base. Various other foundations have, at various times, been the site of internal capture, regulatory accommodation, public-relations management, and quiet mutation of the protocol's stated principles to fit the foundation's evolving situation.

[^58]: For the litigation record, see *In re Tezos Securities Litigation*, No. 17-cv-06779 (N.D. Cal., consolidated 2017–2020); for press analysis, see Nathaniel Popper, "Tezos Sees Big Investors Turn Against It," *New York Times* (19 October 2017).

[^59]: For analysis of the Cardano Foundation disputes, see Sebastien Guillemot, "Cardano Foundation: A Brief History," *IOHK Blog* (various dates 2018–2020); for academic context, see Philipp Sandner et al., "Decentralised Autonomous Organizations in Blockchain Networks: Legal and Governance Issues," *Frankfurt School Blockchain Center Working Paper Series* (2019).

These outcomes are not failures of any particular foundation. They are the foreseeable consequences of any institutional structure in which a small, identifiable, legally incorporated group holds discretionary power over a large, valuable, decentralized network. The structure invites every actor with a non-trivial stake in the protocol to direct his attention at the structure: regulators, hostile states, well-funded litigants, exchange operators, large token holders, journalist-activists, and, at the margins, criminals with resources sufficient to attempt influence. Each of these actors is rational; each can correctly identify the foundation as the leverage point; each will, accordingly, apply pressure. The foundation's ability to resist pressure is a function of its individual members' fortitude — which, in any sufficiently large organization over a sufficiently long time, regresses to the population mean.

The pre-commitment doctrine resolves the problem at the source. If there is no foundation with discretionary power over the protocol, there is no leverage point. The treasury company described in the design proposed here — a profit-seeking corporation organized in whatever jurisdiction is most convenient (C-Corporation in Delaware, *Limitada* or *Sociedade Anônima* in Brazil, *Société à Responsabilité Limitée* in France, Limited Liability Company in any common-law jurisdiction)[^60] — is structurally different from a foundation in three crucial respects.

[^60]: For the institutional analogy in cryptocurrency, the closest existing model is Ava Labs, Inc., the Delaware corporation that develops the Avalanche protocol but does not govern it. See Avalanche Foundation and Ava Labs, "Avalanche: A Native Network for Internet of Finance" (white paper, 2020); for legal analysis of similar structures, see Carla L. Reyes, "Conceptualizing Cryptolaw," *Nebraska Law Review* 96, no. 2 (2017): 384–445.

*First*, the corporation is not a steward of principles. It is a contractor. It custodies the treasury, manages the trademark, executes operational tasks (legal, brand, infrastructure, grants disbursement), but it does not claim authority over what the protocol *is*. If the community wishes to replace it, the community can fund a successor; the trademark and the treasury are the only assets it controls, and both are separable from the consensus rules.

*Second*, it has a normal corporate purpose: pursuit of profit on behalf of its shareholders. This is in no way disreputable; it is the structure under which most useful work in the world is performed. By contrast, a foundation's purpose is *the protocol*, which means that its decisions are perpetually open to the question "is this what the protocol was meant to be?" — a question without a stable answer and therefore a permanent invitation to capture. A corporation does not have to answer that question; it has to deliver the services it has been contracted to deliver.

*Third*, the relevant analogue is not the Linux Foundation but Avalanche's Ava Labs, Inc. — a for-profit company that develops and supports the protocol but does not own it, and could in principle be replaced by another developer without loss of continuity. The protocol is the consensus code; the company is one (currently the leading) developer of nodes and infrastructure for that code. The asymmetry between protocol-as-code and developer-as-company is what permits the protocol to persist through commercial reorganizations, acquisitions, dissolutions, and even outright failures of any particular developer.

The cryptographic protocol contemplated in this Article accordingly has no foundation. The treasury corporation that exists, or that will be incorporated, is a contractor. The percentage of the genesis token allocation reserved for it is not a perpetual ownership stake; it is an operational grant that funds the company's services for the period during which those services are needed, and that becomes increasingly diluted as block rewards accrue to mining and ordinary economic activity. If the company performs poorly, the community can fund a successor; if the company tries to assert authority over the protocol, the community can ignore it; the consensus code does not, and cannot, recognize the company as a privileged entity.

## 13. Conclusion: The Constitution of the *Civitas Cryptographica*

Thirty years ago, in February 1996, John Perry Barlow published *A Declaration of the Independence of Cyberspace*.[^61] It was a beautiful, intemperate, prophetic, and in many places empirically incorrect document. Barlow declared that the governments of the industrial world had no sovereignty in cyberspace, that they had no moral right to rule the new domain, and that cyberspace's inhabitants had built themselves a different world. Three decades later, the empirical claim is laughable: governments rule cyberspace much as they rule everywhere else; surveillance is more pervasive than Barlow could have imagined; the user has been thoroughly commercialized.[^62] Yet the *normative* core of Barlow's declaration — that cyberspace is, or could be, a domain in which traditional sovereignty does not perfectly translate, and in which different constitutional commitments are possible — was correct and remains correct.

[^61]: John Perry Barlow, "A Declaration of the Independence of Cyberspace" (Davos, 8 February 1996), https://www.eff.org/cyberspace-independence.

[^62]: For the post-Snowden empirical correction, see Bruce Schneier, *Data and Goliath: The Hidden Battles to Collect Your Data and Control Your World* (New York: W. W. Norton, 2015); Glenn Greenwald, *No Place to Hide: Edward Snowden, the NSA, and the U.S. Surveillance State* (New York: Metropolitan Books, 2014).

The argument of this Article is more modest in ambition than Barlow's declaration but, perhaps for that reason, more durable. The cryptographic protocol does not claim independence from sovereign states. It is built and used by people who live under states and who are subject to those states' laws. It does not claim moral authority over those laws. What it claims, and only what it claims, is that *its own consensus rules* are constitutional commitments, made in advance, binding on every operator who chooses to run a node, and not subject to alteration by any in-protocol authority. It claims, in other words, the *Schranken-Schranken* — the limits-on-limits — that allow it to operate as a substrate for legitimate use without becoming, simultaneously, a substrate for crime or a tool of arbitrary state pressure.

Within those self-imposed limits, the protocol is offered to anyone who wishes to use it: to merchants in countries with unstable currencies who need a stable medium of exchange; to writers in regimes that censor their work who need an unblockable channel of remuneration; to dissidents in regimes that surveil their finances who need a private medium of payment; to migrant workers sending home their savings without the friction of correspondent banking; to families across borders sharing wealth without the lottery of capital controls; to ordinary citizens of ordinary countries who simply prefer that their financial life not be a matter of public record. To them, the protocol offers privacy by default, finality by computation, and stability by pre-commitment.

It does not offer, and refuses to offer, computational assistance to those who would finance the deliberate killing of civilians for political effect, traffic in persons for forced labor or sexual exploitation, or launder identifiable proceeds of serious crime. The kernel of AML/CFT, distilled from a century of documented self-regulation by payment networks and inter-state soft law, is encoded into consensus and frozen there. It cannot be lifted by any in-protocol authority; it cannot be extended by any in-protocol authority; it is what it is, the same in 2026 as in 2500, the same for the founder as for the user, the same in jurisdictions friendly to cryptography as in those hostile.

This is the constitution proposed in this Article. It is not a state; it is not a foundation; it is not a board of directors. It is a set of permanent rules, enforced by mathematics, witnessed by every node that chooses to follow them, and binding on every entity within them by their voluntary act of participation. The Roman question — *quis custodiet ipsos custodes?* — has, in cryptographic constitutional law, an answer: the consensus does. There are no custodians above the rules, because the rules are above all custodians.

The synthesis of Lassalle, Elster, Tribe, Pieroth-Schlink, Ladeur, Wittgenstein, Neves-Teubner, Schelling, Nash, Aumann, and Axelrod yields, in its constructive form, the architecture of a *civitas cryptographica*: a civil order in which cooperation among indefinitely many self-interested agents, across indefinitely many jurisdictions, over indefinitely long time horizons, is sustained without a sovereign — sustained by the four conditions of cooperation in repeated interaction, by the common-knowledge structure of compiled consensus, by the credible pre-commitment that comes with discarded steering wheels, and by the *Schranken-Schranken* that prevent the limits from swallowing the rights. This is a constitutional possibility that did not exist before cryptography made it possible, and that exists now in the precise sense that Lassalle would recognize: as a written constitution that is binding on the real factors of power because no real factor can rewrite it.

It is offered, freely and without warranty, to anyone who chooses to operate within it, and to no one who does not.

---

## References

Ackerman, Bruce. *We the People*. 3 vols. Cambridge, MA: Harvard University Press, 1991, 1998, 2014.

Alexy, Robert. *A Theory of Constitutional Rights*. Translated by Julian Rivers. Oxford: Oxford University Press, 2002.

Allen, Anita. *Unpopular Privacy: What Must We Hide?* New York: Oxford University Press, 2011.

Aramonte, Sirio, Wenqian Huang, and Andreas Schrimpf. "DeFi Risks and the Decentralisation Illusion." *BIS Quarterly Review* (December 2021): 21–36.

Atiyah, P. S. *The Rise and Fall of Freedom of Contract*. Oxford: Clarendon Press, 1979.

Aumann, Robert J. "Acceptable Points in General Cooperative *N*-Person Games." In *Contributions to the Theory of Games, Volume IV*, edited by A.W. Tucker and R.D. Luce, 287–324. Princeton: Princeton University Press, 1959.

Aumann, Robert J. "Subjectivity and Correlation in Randomized Strategies." *Journal of Mathematical Economics* 1, no. 1 (1974): 67–96.

Aumann, Robert J. "Agreeing to Disagree." *Annals of Statistics* 4, no. 6 (1976): 1236–1239.

Axelrod, Robert. *The Evolution of Cooperation*. Revised edition. New York: Basic Books, 2006. Originally published 1984.

Axelrod, Robert. *The Complexity of Cooperation: Agent-Based Models of Competition and Collaboration*. Princeton: Princeton University Press, 1997.

Barak, Aharon. *Proportionality: Constitutional Rights and their Limitations*. Translated by Doron Kalir. Cambridge: Cambridge University Press, 2012.

Barlow, John Perry. "A Declaration of the Independence of Cyberspace." Davos, 8 February 1996.

Benkler, Yochai. *The Wealth of Networks: How Social Production Transforms Markets and Freedom*. New Haven: Yale University Press, 2006.

Berentsen, Aleksander, and Fabian Schär. "A Short Introduction to the World of Cryptocurrencies." *Federal Reserve Bank of St. Louis Review* 100, no. 1 (2018): 1–16.

Bier, Jonathan. *The Blocksize War: The Battle over Who Controls Bitcoin's Protocol Rules*. Self-published, 2021.

Bonneau, Joseph, et al. "SoK: Research Perspectives and Challenges for Bitcoin and Cryptocurrencies." *Proceedings of the 2015 IEEE Symposium on Security and Privacy* (2015): 104–121.

Brandenburger, Adam, and Eddie Dekel. "Common Knowledge with Probability 1." *Journal of Mathematical Economics* 16, no. 3 (1987): 237–245.

Briscoe, Bob, Andrew Odlyzko, and Benjamin Tilly. "Metcalfe's Law is Wrong." *IEEE Spectrum* 43, no. 7 (2006): 34–39.

Buterin, Vitalik. "Moving Beyond Coin Voting Governance." Blog post, 2021.

Cachin, Christian, and Marko Vukolić. "Blockchain Consensus Protocols in the Wild." In *31st International Symposium on Distributed Computing*, edited by Andréa W. Richa. Schloss Dagstuhl, 2017.

Chaum, David. "Blind Signatures for Untraceable Payments." In *Advances in Cryptology — Proceedings of CRYPTO '82*, edited by David Chaum, Ronald L. Rivest, and Alan T. Sherman, 199–203. Boston: Springer, 1983.

DuPont, Quinn. "Experiments in Algorithmic Governance: A History and Ethnography of 'The DAO,' a Failed Decentralized Autonomous Organization." In *Bitcoin and Beyond: Cryptocurrencies, Blockchains, and Global Governance*, edited by Malcolm Campbell-Verduyn, 157–177. Abingdon: Routledge, 2018.

Eichengreen, Barry. *Globalizing Capital: A History of the International Monetary System*. 2d ed. Princeton: Princeton University Press, 2008.

Elster, Jon. *Ulysses and the Sirens: Studies in Rationality and Irrationality*. Revised edition. Cambridge: Cambridge University Press, 1984. Originally 1979.

Elster, Jon. *Ulysses Unbound: Studies in Rationality, Precommitment, and Constraints*. Cambridge: Cambridge University Press, 2000.

Fairfield, Joshua A. T., and Christoph Engel. "Privacy as a Public Good." *Duke Law Journal* 65, no. 3 (2015): 385–457.

Financial Action Task Force. *International Standards on Combating Money Laundering and the Financing of Terrorism & Proliferation: The FATF Recommendations*. Paris: FATF/OECD, 2012, technical revisions 2023.

Friedman, James. "A Non-Cooperative Equilibrium for Supergames." *Review of Economic Studies* 38, no. 1 (1971): 1–12.

Fudenberg, Drew, and Eric Maskin. "The Folk Theorem in Repeated Games with Discounting or with Incomplete Information." *Econometrica* 54, no. 3 (1986): 533–554.

Geanakoplos, John. "Common Knowledge." *Journal of Economic Perspectives* 6, no. 4 (1992): 53–82.

Gilder, George. "Metcalfe's Law and Legacy." *Forbes ASAP* (13 September 1993).

Greenwald, Glenn. *No Place to Hide: Edward Snowden, the NSA, and the U.S. Surveillance State*. New York: Metropolitan Books, 2014.

Hardin, Garrett. "The Tragedy of the Commons." *Science* 162, no. 3859 (1968): 1243–1248.

Hayek, Friedrich A. *Denationalisation of Money: The Argument Refined*. 2d ed. London: Institute of Economic Affairs, 1976.

Hesse, Konrad. *Grundzüge des Verfassungsrechts der Bundesrepublik Deutschland*. 20th ed. Heidelberg: C.F. Müller, 1995.

Hobbes, Thomas. *Leviathan, or The Matter, Forme, and Power of a Common-Wealth Ecclesiasticall and Civill*. London: Andrew Crooke, 1651.

Holmes, Stephen. *Passions and Constraint: On the Theory of Liberal Democracy*. Chicago: University of Chicago Press, 1995.

Kaal, Wulf A. "Decentralized Autonomous Organizations: Internal Governance and External Legal Design." *Annals of Corporate Governance* 5, no. 4 (2021): 237–315.

Kant, Immanuel. *Die Metaphysik der Sitten / The Metaphysics of Morals*. Translated by Mary Gregor. Cambridge: Cambridge University Press, 1996. Originally 1797.

Kommers, Donald P., and Russell A. Miller. *The Constitutional Jurisprudence of the Federal Republic of Germany*. 3d ed. Durham: Duke University Press, 2012.

Lacey, Robert. *Little Man: Meyer Lansky and the Gangster Life*. Boston: Little, Brown, 1991.

Ladeur, Karl-Heinz. *Postmoderne Rechtstheorie: Selbstreferenz — Selbstorganisation — Prozeduralisierung*. 2d ed. Berlin: Duncker & Humblot, 1995.

Ladeur, Karl-Heinz. *Negative Freiheitsrechte und gesellschaftliche Selbstorganisation: Die Erzeugung von Sozialkapital durch Institutionen*. Tübingen: Mohr Siebeck, 2000.

Lamport, Leslie, Robert Shostak, and Marshall Pease. "The Byzantine Generals Problem." *ACM Transactions on Programming Languages and Systems* 4, no. 3 (1982): 382–401.

Lassalle, Ferdinand. *Über Verfassungswesen*. Berlin: G. Jansen, 1862.

Lessig, Lawrence. *Code: Version 2.0*. New York: Basic Books, 2006.

Locke, John. *Two Treatises of Government*. Edited by Peter Laslett, student edition. Cambridge: Cambridge University Press, 1988. Originally 1689.

Luhmann, Niklas. *Das Recht der Gesellschaft*. Frankfurt: Suhrkamp, 1993.

Maine, Henry Sumner. *Ancient Law: Its Connection with the Early History of Society and its Relation to Modern Ideas*. London: John Murray, 1861.

Meltzer, Allan H. *A History of the Federal Reserve, Volume 2, Book 2: 1970–1986*. Chicago: University of Chicago Press, 2009.

Nakamoto, Satoshi. *Bitcoin: A Peer-to-Peer Electronic Cash System*. White paper, October 2008.

Nance, Mark T. "The Regime that FATF Built: An Introduction to the Financial Action Task Force." *Crime, Law and Social Change* 69, no. 2 (2018): 109–129.

Narayanan, Arvind, and Jeremy Clark. "Bitcoin's Academic Pedigree." *Communications of the ACM* 60, no. 12 (2017): 36–45.

Nash, John F., Jr. "Equilibrium Points in N-Person Games." *Proceedings of the National Academy of Sciences* 36, no. 1 (1950): 48–49.

Nash, John F., Jr. "Non-Cooperative Games." *Annals of Mathematics* 54, no. 2 (1951): 286–295.

Naylor, Thomas. *Wages of Crime: Black Markets, Illegal Finance, and the Underworld Economy*. Revised edition. Ithaca: Cornell University Press, 2004.

Neves, Marcelo. *Transconstitucionalismo*. São Paulo: Martins Fontes, 2009.

Neves, Marcelo. *Transconstitutionalism*. Translated by Kevin Mundy. Oxford: Hart Publishing, 2013.

Nissenbaum, Helen. *Privacy in Context: Technology, Policy, and the Integrity of Social Life*. Stanford: Stanford University Press, 2010.

Odlyzko, Andrew, and Benjamin Tilly. "A Refutation of Metcalfe's Law and a Better Estimate for the Value of Networks and Network Interconnections." AT&T Labs–Research (2 March 2005).

Pieroth, Bodo, and Bernhard Schlink. *Grundrechte: Staatsrecht II*. 39th ed. Heidelberg: C.F. Müller, 2023.

Putnam, Robert D. *Bowling Alone: The Collapse and Revival of American Community*. New York: Simon & Schuster, 2000.

Rapoport, Anatol, and Albert M. Chammah. *Prisoner's Dilemma: A Study in Conflict and Cooperation*. Ann Arbor: University of Michigan Press, 1965.

Reed, David P. "That Sneaky Exponential — Beyond Metcalfe's Law to the Power of Community Building." *Context Magazine* (Spring 1999).

Regan, Priscilla M. *Legislating Privacy: Technology, Social Values, and Public Policy*. Chapel Hill: University of North Carolina Press, 1995.

Reyes, Carla L. "Conceptualizing Cryptolaw." *Nebraska Law Review* 96, no. 2 (2017): 384–445.

Rickards, James. *The Death of Money: The Coming Collapse of the International Monetary System*. New York: Portfolio, 2014.

Schelling, Thomas C. *The Strategy of Conflict*. Cambridge, MA: Harvard University Press, 1960.

Schelling, Thomas C. *Arms and Influence*. New Haven: Yale University Press, 1966.

Schelling, Thomas C. *Choice and Consequence*. Cambridge, MA: Harvard University Press, 1984.

Schneier, Bruce. *Data and Goliath: The Hidden Battles to Collect Your Data and Control Your World*. New York: W. W. Norton, 2015.

Solove, Daniel J. *Understanding Privacy*. Cambridge, MA: Harvard University Press, 2008.

Strauss, David A. *The Living Constitution*. New York: Oxford University Press, 2010.

Teubner, Gunther. "Societal Constitutionalism: Alternatives to State-Centred Constitutional Theory?" In *Transnational Governance and Constitutionalism*, edited by Christian Joerges, Inger-Johanne Sand, and Gunther Teubner, 3–28. Oxford: Hart Publishing, 2004.

Teubner, Gunther. *Constitutional Fragments: Societal Constitutionalism and Globalization*. Translated by Gareth Norbury. Oxford: Oxford University Press, 2012.

Theoharis, Athan G., et al. *The FBI: A Comprehensive Reference Guide*. Phoenix: Oryx Press, 1999.

Tocqueville, Alexis de. *Democracy in America*. Translated by Harvey C. Mansfield and Delba Winthrop. Chicago: University of Chicago Press, 2000. Originally *De la démocratie en Amérique*, vols. I (1835) and II (1840).

Tribe, Laurence H. *The Invisible Constitution*. New York: Oxford University Press, 2008.

Walch, Angela. "The Path of the Blockchain Lexicon (and the Law)." *Review of Banking and Financial Law* 36 (2017): 713–765.

Warren, Samuel D., and Louis D. Brandeis. "The Right to Privacy." *Harvard Law Review* 4, no. 5 (1890): 193–220.

Weber, Max. *Wirtschaft und Gesellschaft*. Tübingen: Mohr, 1922.

Weber, Steven. *The Success of Open Source*. Cambridge, MA: Harvard University Press, 2004.

Weiner, Tim. *Enemies: A History of the FBI*. New York: Random House, 2012.

Wittgenstein, Ludwig. *Philosophische Untersuchungen / Philosophical Investigations*. 4th ed. Translated by G.E.M. Anscombe, P.M.S. Hacker, and Joachim Schulte. Oxford: Wiley-Blackwell, 2009. Originally 1953.

Zuboff, Shoshana. *The Age of Surveillance Capitalism: The Fight for a Human Future at the New Frontier of Power*. New York: PublicAffairs, 2019.

---

*The author thanks the open-source cryptographic research community whose work made the technical possibilities discussed in this paper feasible. All errors of doctrine and analysis are the author's own. This paper presents the author's personal scholarly views and does not necessarily reflect the position of any institution with which the author is affiliated.*

*Document version: 1.0 — April 2026.*
