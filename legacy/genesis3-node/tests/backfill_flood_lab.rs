//! BACKFILL-FLOOD lab (frente BACKFILL-FLOOD, 2026-08-08).
//!
//! Reproduz, contra o GhostDAG REAL (mesmo código e mesmo lock do caminho de
//! aceitação em src/main.rs), o incidente de 2026-08-09: um peer atrasado
//! (12D3KooWBZeik…, h≈10.8k) empurrou ~1.270 blocos antigos em 5 min para o
//! produtor (tip ≈ 27.391) e a produção de blocos parou.
//!
//! Três experimentos:
//!   A) custo de `add_block` por profundidade do fork — mede o trabalho
//!      não-limitado por bloco antigo (compute_past O(altura) + coloração
//!      Legacy abaixo de CORRECTED_COLORING_ACTIVATION_HEIGHT=21430);
//!   B) inanição de leitores — enquanto uma thread ingere o backfill (como o
//!      message-processor faz), outra thread tenta `dag.read()` (o que o loop
//!      de mineração/stratum/RPC fazem) e mede a latência de espera;
//!   C) o "reorg em looping" — irmãos de mesma altura sob template obsoleto
//!      alternam ForkLoser / reorg-de-1 pelo tie-break de hash em
//!      `selected_tip()`.
//!
//! Rodar: cargo test --release --test backfill_flood_lab -- --nocapture --test-threads=1
//! (números só fazem sentido em --release)

use bloch::consensus::GhostDAG;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Altura do tip no incidente (produtor em h≈27.391).
const TIP_HEIGHT: u64 = 27_400;
/// Altura do fork do peer atrasado (net_ingest_block height=10844…).
const FORK_HEIGHT: u64 = 10_844;
/// Blocos antigos ingeridos na janela de 5 min do incidente.
const FLOOD_LEN: u64 = 1_270;

/// Hash determinístico: derivado do índice; `salt` distingue famílias
/// (cadeia principal, ramo, irmãos) e controla o tie-break lexicográfico.
fn h(salt: u8, i: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = salt;
    out[1..9].copy_from_slice(&i.to_be_bytes());
    // espalha para não ficar tudo em prefixo comum
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(salt as u64);
    for b in out[9..17].iter_mut() {
        x = x.rotate_left(13).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        *b = (x >> 56) as u8;
    }
    out
}

/// Monta a cadeia principal linear: genesis + TIP_HEIGHT blocos.
/// Igual ao live: `with_default_k()` (Legacy + gate 21430 armado → índice de
/// reachability mantido; coloração Legacy abaixo do gate, Fast acima).
fn build_mainchain() -> (GhostDAG, Vec<[u8; 32]>) {
    let mut dag = GhostDAG::with_default_k();
    let g = h(0, 0);
    dag.add_genesis(g, 1_000_000);
    let mut hashes = Vec::with_capacity(TIP_HEIGHT as usize + 1);
    hashes.push(g);
    let t0 = Instant::now();
    let mut window = Instant::now();
    for i in 1..=TIP_HEIGHT {
        let hash = h(1, i);
        dag.add_block(hash, vec![hashes[(i - 1) as usize]], 1_000_000 + i * 30, 1)
            .expect("mainchain add_block");
        hashes.push(hash);
        if i % 5_000 == 0 {
            println!(
                "  build: h={:6}  últimos 5000 em {:>8.2?}  ({:.2?}/bloco)",
                i,
                window.elapsed(),
                window.elapsed() / 5_000
            );
            window = Instant::now();
        }
    }
    println!(
        "cadeia principal construída: {} blocos em {:.2?}",
        TIP_HEIGHT,
        t0.elapsed()
    );
    (dag, hashes)
}

#[test]
fn backfill_flood_lab() {
    println!("\n════ LAB BACKFILL-FLOOD ════");
    println!(
        "tip={} fork={} flood={}  (gate de coloração Fast em 21430)\n",
        TIP_HEIGHT, FORK_HEIGHT, FLOOD_LEN
    );

    let (mut dag, chain) = build_mainchain();

    // ── Experimento A.1: custo por bloco vs ponto de inserção ────────────────
    println!("\n── A.1: custo de add_block por profundidade ──");
    // extensão do tip (o que um bloco NOVO custa)
    let t = Instant::now();
    let tip_ext = h(2, 1);
    dag.add_block(tip_ext, vec![chain[TIP_HEIGHT as usize]], 9_000_000, 1)
        .unwrap();
    let cost_tip = t.elapsed();
    println!("  extensão do tip (h={}):            {:>10.2?}", TIP_HEIGHT + 1, cost_tip);
    dag.remove_block(&tip_ext);

    // side-block raso na zona Fast (h=25.000)
    let t = Instant::now();
    let side_fast = h(3, 1);
    dag.add_block(side_fast, vec![chain[25_000]], 9_000_001, 1).unwrap();
    let cost_fast = t.elapsed();
    println!("  side-block zona Fast (h=25001):    {:>10.2?}", cost_fast);
    dag.remove_block(&side_fast);

    // side-block na zona Legacy (h=15.000)
    let t = Instant::now();
    let side_leg = h(4, 1);
    dag.add_block(side_leg, vec![chain[15_000]], 9_000_002, 1).unwrap();
    let cost_leg15k = t.elapsed();
    println!("  side-block zona Legacy (h=15001):  {:>10.2?}", cost_leg15k);
    dag.remove_block(&side_leg);

    // side-block no fork do incidente (h=10.845, zona Legacy)
    let t = Instant::now();
    let side_incident = h(5, 1);
    dag.add_block(side_incident, vec![chain[FORK_HEIGHT as usize]], 9_000_003, 1)
        .unwrap();
    let cost_leg_fork = t.elapsed();
    println!("  side-block fork incidente (h={}): {:>8.2?}", FORK_HEIGHT + 1, cost_leg_fork);
    dag.remove_block(&side_incident);

    // ── Experimento A.2 + B: replay do flood sob o lock de produção ─────────
    // Writer = message-processor ingerindo o ramo do atrasado.
    // Reader = loop de mineração/stratum tentando dag.read() a cada 5 ms.
    println!("\n── A.2/B: replay do flood (ramo de {} blocos a partir de h={}) ──", FLOOD_LEN, FORK_HEIGHT);
    let dag = Arc::new(RwLock::new(dag));
    let stop = Arc::new(AtomicBool::new(false));

    let reader = {
        let dag = dag.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut waits: Vec<Duration> = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let t = Instant::now();
                let _tip = dag.read().selected_tip(); // o que o miner/RPC fazem
                waits.push(t.elapsed());
                std::thread::sleep(Duration::from_millis(5));
            }
            waits
        })
    };

    let mut per_block: Vec<Duration> = Vec::with_capacity(FLOOD_LEN as usize);
    let mut parent = chain[FORK_HEIGHT as usize];
    let t_flood = Instant::now();
    for i in 0..FLOOD_LEN {
        let hash = h(6, i);
        let t = Instant::now();
        dag.write()
            .add_block(hash, vec![parent], 2_000_000 + i * 30, 1)
            .expect("flood add_block");
        per_block.push(t.elapsed());
        parent = hash;
    }
    let flood_total = t_flood.elapsed();
    stop.store(true, Ordering::Relaxed);
    let mut waits = reader.join().unwrap();

    per_block.sort();
    let p = |v: &Vec<Duration>, q: f64| v[((v.len() - 1) as f64 * q) as usize];
    println!(
        "  flood: {} blocos em {:.2?}  (mediana {:.2?}/bloco, p99 {:.2?}, max {:.2?})",
        FLOOD_LEN,
        flood_total,
        p(&per_block, 0.5),
        p(&per_block, 0.99),
        per_block.last().unwrap()
    );
    println!(
        "  → taxa máxima que UM peer impõe de graça: {:.1} blocos antigos/s",
        FLOOD_LEN as f64 / flood_total.as_secs_f64()
    );
    waits.sort();
    println!(
        "  leitor (dag.read() a cada 5ms): {} amostras — p50 {:.2?}, p99 {:.2?}, max {:.2?}",
        waits.len(),
        p(&waits, 0.5),
        p(&waits, 0.99),
        waits.last().unwrap()
    );

    // ── Experimento A.3: bloco-merge do atrasado (mergeset grande, Legacy) ──
    // Um bloco do peer antigo que referencia o ramo E a cadeia principal:
    // selected_parent vira o bloco da main (mais blue_work) e o mergeset são
    // os N blocos do ramo — coloração Legacy com anticone×is_ancestor.
    println!("\n── A.3: bloco-merge (mergeset = ramo inteiro, zona Legacy) ──");
    let merge_parent_main = chain[12_200]; // h≈12.2k, ainda < 21430 ⇒ Legacy
    let t = Instant::now();
    let merge_block = h(7, 1);
    dag.write()
        .add_block(merge_block, vec![parent, merge_parent_main], 2_100_000, 1)
        .expect("merge add_block");
    let cost_merge = t.elapsed();
    println!(
        "  UM bloco com mergeset≈{}: {:.2?}  (equivalente a {:.0}× um bloco de tip)",
        FLOOD_LEN,
        cost_merge,
        cost_merge.as_secs_f64() / cost_tip.as_secs_f64().max(1e-9)
    );

    // ── Experimento C: irmãos de mesma altura = ForkLoser / reorg-de-1 ──────
    // Template obsoleto ⇒ o minerador entrega M1, M2, M3 todos filhos do MESMO
    // parent. blue_work idêntico ⇒ tie-break lexicográfico de hash em
    // selected_tip(): hash maior "rouba" o tip (= reorg rollback 1 / apply 1),
    // hash menor vira "accepted into fork (not selected tip)".
    println!("\n── C: irmãos sob template obsoleto (tie-break de hash) ──");
    let real_tip = dag.read().selected_tip().unwrap();
    let mine_parent = chain[TIP_HEIGHT as usize];
    assert_eq!(real_tip, mine_parent, "sanidade: tip ainda é a main chain");
    let mut flips = 0;
    let mut fork_losers = 0;
    let mut cur_tip = real_tip;
    for i in 0..6u64 {
        let m = h(8, i * 7919); // hashes em ordem pseudo-aleatória
        dag.write().add_block(m, vec![mine_parent], 9_100_000 + i, 1).unwrap();
        let new_tip = dag.read().selected_tip().unwrap();
        if new_tip == m {
            if cur_tip != mine_parent {
                flips += 1; // tip trocou de um irmão para outro ⇒ reorg 1/1
                println!("  irmão {}: FLIP de tip (reorg rollback 1 / apply 1)", i);
            } else {
                println!("  irmão {}: extensão normal", i);
            }
            cur_tip = new_tip;
        } else {
            fork_losers += 1;
            println!("  irmão {}: accepted into fork (not selected tip)", i);
        }
    }
    println!(
        "  resultado: {} flips de tip + {} fork-losers em 6 irmãos — altura NUNCA avançou",
        flips, fork_losers
    );
    assert!(flips + fork_losers >= 4, "esperado: maioria dos irmãos flipa ou perde");
    // a altura selecionada não avançou além de TIP_HEIGHT+1 em nenhum momento
    let final_tip = dag.read().selected_tip().unwrap();
    let final_h = dag.read().get_block_data(&final_tip).unwrap().height;
    assert_eq!(final_h, TIP_HEIGHT + 1, "irmãos não estendem a cadeia");

    println!("\n════ fim do lab ════\n");
}
