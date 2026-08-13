//! DIFFICULTY-ANCESTRY boundary lab (frente ASSIMETRIA-DIFICULDADE, 2026-08-09).
//!
//! Reproduz, contra o GhostDAG REAL (`with_default_k()`, mesmo código do
//! caminho de aceitação) e Storage REAL (RocksDB temporário, mesmo
//! `put_block`/`CF_TIMESTAMPS`/`current_bits` do nó), o incidente de
//! 2026-08-09 em h=28080: uma fronteira de retarget com DOIS tips abertos em
//! h-1 produziu TRÊS opiniões de `expected bits` para o mesmo bloco —
//!
//!   0x1a0abb83  legado, estado local do produtor ANTES do 2º tip em 28079
//!               (e também node4 sob o binário stopgap fd29400);
//!   0x1a0abee4  legado, o MESMO nó DEPOIS que o 2º tip reescreveu
//!               CF_TIMESTAMPS[28079] (last-write-wins) — foi o que o template
//!               stratum estampou;
//!   0x1a0ac909  ancestry sobre o conjunto de pais {tip1, tip2} — o que o
//!               validador (accept_block) do produtor E do node4 exigiam.
//!
//! O produtor minerava e auto-rejeitava todo bloco: ~50 min de mainnet parada.
//!
//! O lab monta a MESMA topologia (irmãos na abertura E no fecho da janela de
//! retarget) em DOIS nós que aceitam os irmãos em ordens opostas, e prova:
//!
//!   1. o caminho LEGADO diverge entre os nós (o congelamento de seguidores) e
//!      diverge da regra ancestry (o auto-reject do produtor) — três valores;
//!   2. a regra ancestry (`genesis2_expected_bits_for_parents`) é uma função
//!      PURA do conjunto de pais: idêntica nos dois nós, invariante à ordem de
//!      aceitação E à ordem do slice;
//!   3. produtor e validador que passam o MESMO `header.parents` obtêm o MESMO
//!      valor por construção;
//!   4. fora de fronteira e em fronteira de tip único, ancestry == legado —
//!      por isso o flag-day 27600 passou limpo e o mid-window é o ponto seguro
//!      de ativação;
//!   5. os casos de ancestralidade ilegível FALHAM FECHADO (erro explícito),
//!      nunca um valor silenciosamente errado.
//!
//! Rodar: cargo test --test difficulty_ancestry_boundary_lab -- --nocapture

use bloch::consensus::GhostDAG;
use bloch::core::{
    retarget_bits_g2, Block, BlockHeader, Transaction, TxInput, TxOutput, GENESIS2_BITS,
    GENESIS2_RETARGET_WINDOW,
};
use bloch::pow::{
    genesis2_expected_bits, genesis2_expected_bits_for_parents,
    genesis2_expected_bits_for_parents_gated, ExpectedBitsError,
};
use bloch::storage::Storage;
use tempfile::TempDir;

const T0: u64 = 1_000_000;

/// Bloco mínimo mas REAL (round-trip pelo wire format do put_block): um
/// coinbase único por (altura, timestamp) para que irmãos tenham hashes
/// distintos e determinísticos.
fn mk_block(height: u64, parents: Vec<[u8; 32]>, ts: u64, bits: u32) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("height:{}:ts:{}", height, ts).into_bytes(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: 50, script_pubkey: vec![0x42; 20] }],
        locktime: 0,
    };
    let txs = vec![coinbase];
    Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: Transaction::merkle_root(&txs),
            timestamp: ts,
            bits,
            nonce: 0,
        },
        transactions: txs,
        blue_score: 0,
        height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

/// Um "nó": Storage RocksDB real + GhostDAG real. `accept()` espelha o que
/// accept_block persiste e que os dois caminhos de bits leem: put_block
/// (corpo + CF_TIMESTAMPS[altura] last-write-wins) + meta current_bits +
/// add_block no DAG.
struct LabNode {
    _tmp: TempDir,
    store: Storage,
    dag: GhostDAG,
}

impl LabNode {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let store = Storage::open(tmp.path()).expect("rocksdb open");
        let dag = GhostDAG::with_default_k();
        LabNode { _tmp: tmp, store, dag }
    }

    fn accept_genesis(&mut self, b: &Block) {
        let h = b.block_hash();
        self.store.put_block(b).expect("put genesis");
        self.store
            .put_meta("current_bits", &b.header.bits.to_le_bytes())
            .expect("meta");
        self.dag.add_genesis(h, b.header.timestamp);
    }

    fn accept(&mut self, b: &Block) {
        let h = b.block_hash();
        self.store.put_block(b).expect("put block");
        // accept_block grava current_bits em TODO bloco aceito (main.rs).
        self.store
            .put_meta("current_bits", &b.header.bits.to_le_bytes())
            .expect("meta");
        self.dag
            .add_block(h, b.header.parents.clone(), b.header.timestamp, 1_000)
            .expect("dag add_block");
    }
}

/// Monta a cadeia do cenário e devolve os blocos na ordem canônica.
/// Topologia (janela W=60, fronteira em 2W=120):
///   g(h0) — c1..c59 — {s60a, s60b}(h60) — c61(pais: ambos irmãos) — c62..c118
///   — {t119a, t119b}(h119)
/// O bloco em h=120 teria parents = {t119a, t119b}: exatamente a forma do
/// incidente (irmãos abertos na fronteira E na abertura da janela, cujo
/// CF_TIMESTAMPS[60] e [119] ficam last-write-wins).
struct Scenario {
    genesis: Block,
    chain_1_59: Vec<Block>,
    s60a: Block,
    s60b: Block,
    chain_61_118: Vec<Block>,
    t119a: Block,
    t119b: Block,
}

fn build_scenario() -> Scenario {
    let w = GENESIS2_RETARGET_WINDOW; // 60
    assert_eq!(w, 60, "o cenário assume a janela G2/G3 de 60 blocos");

    let genesis = mk_block(0, vec![], T0, GENESIS2_BITS);
    let mut prev = genesis.block_hash();

    let mut chain_1_59 = Vec::new();
    for i in 1..=59u64 {
        let b = mk_block(i, vec![prev], T0 + 30 * i, GENESIS2_BITS);
        prev = b.block_hash();
        chain_1_59.push(b);
    }

    // Irmãos na ABERTURA da janela (h60): timestamps distintos → o `first` do
    // retarget legado depende de quem foi aceito por último.
    let s60a = mk_block(60, vec![prev], T0 + 1_810, GENESIS2_BITS);
    let s60b = mk_block(60, vec![prev], T0 + 2_110, GENESIS2_BITS);

    // h61 funde os dois irmãos (DAG real), depois cadeia linear até h118.
    let mut chain_61_118 = Vec::new();
    let b61 = mk_block(
        61,
        vec![s60a.block_hash(), s60b.block_hash()],
        T0 + 30 * 61,
        GENESIS2_BITS,
    );
    prev = b61.block_hash();
    chain_61_118.push(b61);
    for i in 62..=118u64 {
        let b = mk_block(i, vec![prev], T0 + 30 * i, GENESIS2_BITS);
        prev = b.block_hash();
        chain_61_118.push(b);
    }

    // DOIS tips abertos na fronteira-1 (h119) — a condição do incidente.
    // Elapsed (last-first) para as 4 combinações: 1590, 1290, 1798, 1498 s —
    // todos distintos e < 1800 s (sem clamp, sem teto de pow-limit), logo
    // quatro retargets distintos.
    let t119a = mk_block(119, vec![prev], T0 + 3_400, GENESIS2_BITS);
    let t119b = mk_block(119, vec![prev], T0 + 3_608, GENESIS2_BITS);

    Scenario { genesis, chain_1_59, s60a, s60b, chain_61_118, t119a, t119b }
}

/// Replica em `node` a aceitação da cadeia com a ordem dos irmãos escolhida
/// por nível: `sib60`/`sib119` são (primeiro, segundo) — o SEGUNDO é quem
/// fica em CF_TIMESTAMPS (last-write-wins).
fn populate(node: &mut LabNode, sc: &Scenario, sib60: (&Block, &Block), sib119: (&Block, &Block)) {
    node.accept_genesis(&sc.genesis);
    for b in &sc.chain_1_59 {
        node.accept(b);
    }
    node.accept(sib60.0);
    node.accept(sib60.1);
    for b in &sc.chain_61_118 {
        node.accept(b);
    }
    node.accept(sib119.0);
    node.accept(sib119.1);
}

/// O irmão que o GhostDAG escolhe como selected parent no empate de
/// blue_work/blue_score: o de HASH maior (mesmo comparador de
/// `GhostDAG::select_parent`).
fn hash_winner<'a>(a: &'a Block, b: &'a Block) -> (&'a Block, &'a Block) {
    if a.block_hash() > b.block_hash() {
        (a, b) // (winner, loser)
    } else {
        (b, a)
    }
}

#[test]
fn boundary_with_two_tips_three_opinions_and_the_fix() {
    let sc = build_scenario();
    let (w60, l60) = hash_winner(&sc.s60a, &sc.s60b);
    let (w119, l119) = hash_winner(&sc.t119a, &sc.t119b);

    // Ordens de aceitação ADAPTATIVAS para reproduzir o triângulo do
    // incidente (três valores distintos):
    //   nó A: last-write = winner em 60, loser em 119  → legado_A usa
    //         (l119.ts − w60.ts)
    //   nó B: last-write = loser em 60, winner em 119  → legado_B usa
    //         (w119.ts − l60.ts)
    //   ancestry (ambos os nós): (w119.ts − w60.ts) — só dados de consenso.
    let mut node_a = LabNode::new();
    populate(&mut node_a, &sc, (l60, w60), (w119, l119));
    let mut node_b = LabNode::new();
    populate(&mut node_b, &sc, (w60, l60), (l119, w119));

    let parents = vec![sc.t119a.block_hash(), sc.t119b.block_hash()];
    let parents_rev: Vec<[u8; 32]> = parents.iter().rev().cloned().collect();

    // ── O bug legado, vivo: os dois nós discordam entre si ───────────────────
    let legacy_a = genesis2_expected_bits(&node_a.store, 120);
    let legacy_b = genesis2_expected_bits(&node_b.store, 120);
    assert_ne!(
        legacy_a, legacy_b,
        "legado DEVE divergir entre nós que aceitaram irmãos em ordens opostas \
         (é o congelamento de seguidores em produção; se isto falhar o cenário \
         não reproduz o incidente)"
    );

    // ── A regra ancestry: pura, idêntica nos dois nós, invariante à ordem ────
    let anc_a = genesis2_expected_bits_for_parents_gated(
        &node_a.store, &node_a.dag, &parents, 120, 0,
    )
    .expect("ancestry nó A");
    let anc_b = genesis2_expected_bits_for_parents_gated(
        &node_b.store, &node_b.dag, &parents_rev, 120, 0,
    )
    .expect("ancestry nó B");
    assert_eq!(
        anc_a, anc_b,
        "ancestry deve ser função pura do conjunto de pais — mesma resposta em \
         nós com ordens de aceitação opostas e slices em ordens opostas"
    );

    // Valor fechado: retarget sobre o selected-parent chain (winner119 ←
    // ... ← winner60), nunca sobre o índice por altura.
    let expected = retarget_bits_g2(
        GENESIS2_BITS,
        w119.header.timestamp - w60.header.timestamp,
    );
    assert_eq!(anc_a, expected, "ancestry deve seguir o selected-parent chain");

    // ── O triângulo do incidente: TRÊS opiniões para o mesmo bloco ───────────
    assert_ne!(anc_a, legacy_a, "produtor: template legado != validador ancestry (auto-reject)");
    assert_ne!(anc_a, legacy_b, "seguidor stopgap: legado local != ancestry");
    println!(
        "três opiniões reproduzidas: legado_A=0x{:08x} legado_B=0x{:08x} ancestry=0x{:08x}",
        legacy_a, legacy_b, anc_a
    );

    // ── Produtor e validador unificados: mesmo slice ⇒ mesmo valor ──────────
    // O template estampa `parents` + `anc_a`; o validador recomputa sobre
    // header.parents do bloco montado. Mesma função, mesmo slice — igual por
    // construção, em qualquer nó.
    let assembled = mk_block(120, parents.clone(), T0 + 3_700, anc_a);
    let validator_a = genesis2_expected_bits_for_parents_gated(
        &node_a.store, &node_a.dag, &assembled.header.parents, assembled.height, 0,
    )
    .expect("validador nó A");
    let validator_b = genesis2_expected_bits_for_parents_gated(
        &node_b.store, &node_b.dag, &assembled.header.parents, assembled.height, 0,
    )
    .expect("validador nó B");
    assert_eq!(assembled.header.bits, validator_a, "produtor == validador (nó A)");
    assert_eq!(assembled.header.bits, validator_b, "produtor == validador (nó B)");

    // ── Abaixo do flag-day o wrapper de produção continua legado verbatim ───
    // (120 < DIFFICULTY_ANCESTRY_FORK_HEIGHT): equivalência com o stopgap —
    // história assentada permanece válida.
    let below = genesis2_expected_bits_for_parents(&node_a.store, &node_a.dag, &parents, 120)
        .expect("abaixo do flag-day nunca é Err");
    assert_eq!(below, legacy_a, "abaixo do flag-day o choke point delega ao legado");
}

#[test]
fn single_tip_boundary_and_off_boundary_agree_with_legacy() {
    let sc = build_scenario();
    let (w60, l60) = hash_winner(&sc.s60a, &sc.s60b);
    let (w119, l119) = hash_winner(&sc.t119a, &sc.t119b);
    let mut node = LabNode::new();
    populate(&mut node, &sc, (l60, w60), (l119, w119));

    // Fronteira h=60 com UM tip (h59): ancestry == legado — a razão de o
    // flag-day 27600 ter passado limpo com tip único.
    let p59 = vec![sc.chain_1_59.last().unwrap().block_hash()];
    let anc60 = genesis2_expected_bits_for_parents_gated(&node.store, &node.dag, &p59, 60, 0)
        .expect("ancestry h60");
    let leg60 = genesis2_expected_bits(&node.store, 60);
    assert_eq!(anc60, leg60, "fronteira com tip único: ancestry == legado");

    // Fora de fronteira (h=90, meio de janela): ancestry devolve os bits do
    // selected parent == current_bits do legado. É o que torna um flag-day
    // MID-WINDOW (30_030) um ponto de ativação sem salto: as duas regras
    // coincidem no instante da troca.
    let p89 = vec![sc.chain_61_118[89 - 61].block_hash()];
    let anc90 = genesis2_expected_bits_for_parents_gated(&node.store, &node.dag, &p89, 90, 0)
        .expect("ancestry h90");
    let leg90 = genesis2_expected_bits(&node.store, 90);
    assert_eq!(anc90, leg90, "fora de fronteira: ancestry == legado (== bits em vigor)");
}

#[test]
fn unreadable_ancestry_fails_closed_never_a_guess() {
    let sc = build_scenario();
    let (w60, l60) = hash_winner(&sc.s60a, &sc.s60b);
    let (w119, l119) = hash_winner(&sc.t119a, &sc.t119b);
    let mut node = LabNode::new();
    populate(&mut node, &sc, (l60, w60), (l119, w119));

    let t119a_h = sc.t119a.block_hash();

    // 1. Pai listado sem dados no DAG (a visão parcial do node4): tem de ser
    //    ERRO — a versão antiga fazia filter_map e computava o argmax sobre um
    //    SUBCONJUNTO, elegendo o selected parent errado em silêncio.
    let unknown = [0xEE_u8; 32];
    let err = genesis2_expected_bits_for_parents_gated(
        &node.store, &node.dag, &[t119a_h, unknown], 120, 0,
    )
    .unwrap_err();
    assert_eq!(err, ExpectedBitsError::ParentDataMissing(unknown));

    // 2. Selected parent sem corpo no storage (tip header-only): erro, não
    //    fallback silencioso para o valor legado local.
    let ghost = mk_block(119, vec![sc.chain_61_118.last().unwrap().block_hash()], T0 + 9_999, GENESIS2_BITS);
    let ghost_h = ghost.block_hash();
    node.dag
        .add_block(ghost_h, ghost.header.parents.clone(), ghost.header.timestamp, u64::MAX as u128)
        .expect("dag add ghost"); // blue_work máximo → vira o selected parent
    let err = genesis2_expected_bits_for_parents_gated(
        &node.store, &node.dag, &[t119a_h, ghost_h], 120, 0,
    )
    .unwrap_err();
    assert_eq!(err, ExpectedBitsError::SelectedParentBlockMissing(ghost_h));

    // 3. Altura declarada incoerente com os pais (a caminhada não fecha na
    //    altura-alvo): erro explícito, não um retarget sobre janela errada.
    let err = genesis2_expected_bits_for_parents_gated(
        &node.store, &node.dag, &[t119a_h], 180, 0,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExpectedBitsError::AncestryIncomplete { .. }),
        "altura incoerente deve falhar fechado, obteve: {:?}", err
    );

    // 4. Slice vazio: erro.
    let err = genesis2_expected_bits_for_parents_gated(&node.store, &node.dag, &[], 120, 0)
        .unwrap_err();
    assert_eq!(err, ExpectedBitsError::NoParents);
}
