//! PROPAGAÇÃO-CHURN lab (frente PROPAGAÇÃO-CHURN, 2026-08-09).
//!
//! Reproduz, em localhost, o incidente de 2026-08-09: com o flag-day de
//! dificuldade resolvido (zero `invalid difficulty`), a rede NÃO converge —
//! node4 639 blocos atrás, miner-box 1.239 atrás, conexões que morrem no
//! mesmo segundo, `wire violation … MAX_WIRE_ADDR_LEN … app score → -100`,
//! multiaddrs com `/p2p/` repetido até 15×, known_peers.json de 94 KB.
//!
//! CADEIA CAUSAL provada aqui (medida em produção antes do lab):
//!   1. `ConnectionEstablished` (braço Dialer) fazia
//!      `format!("{}/p2p/{}", address, peer_id)` sobre o endereço DISCADO —
//!      que já termina em `/p2p/<id>` — e persistia o resultado em
//!      known_peers. Cada ciclo de discagem bem-sucedida acrescenta um
//!      componente: `/p2p/<id>/p2p/<id>/…` (histograma real do node4:
//!      cadeias até 15 repetições).
//!   2. `is_valid_public_multiaddr` aceitava a forma encadeada (só exige
//!      "contém P2p"), então nem prune nem PEX-ingress filtravam.
//!   3. Com id base58 de ~52 chars, ≥9 componentes `/p2p/` estouram
//!      MAX_WIRE_ADDR_LEN = 512. A resposta PEX (PeerRequest→PeerExchange)
//!      envia known_peers VERBATIM: uma única entrada >512 faz o RECEPTOR
//!      rejeitar o frame inteiro (`Bounds("address string longer than
//!      MAX_WIRE_ADDR_LEN")`) e aplicar app score −100 CUMULATIVO ao
//!      remetente.
//!   4. Na 4ª/5ª violação o score cruza graylist_threshold (−400) e o
//!      gossipsub passa a IGNORAR tudo que o remetente publica — inclusive
//!      NewBlock e PeerTip. TCP fica de pé (ss mostra 10 conexões), mas
//!      zero anúncios de tip: o blackhole observado. (Journal do node4:
//!      5 violações do produtor em 12 h → score −500 → graylist.)
//!   5. Braço Listener do mesmo handler persistia `send_back_addr` — o
//!      socket EFÊMERO do remoto (/tcp/55964 etc.), nunca discável:
//!      226 das 265 entradas do node4 eram esse lixo, desperdiçando os 20
//!      slots de PEX_BATCH_LIMIT por mensagem e inflando o arquivo.
//!
//! Rodar: cargo test -p bloch --test peer_addr_churn_lab -- --nocapture --test-threads=1
//! (os testes `live_` sobem NetworkNode::run REAL em loopback e esperam o
//!  tick de save_peers de 60 s; contam ~3 min no total)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bloch::consensus::GhostDAG;
use bloch::network::pex_validator::is_valid_public_multiaddr;
use bloch::network::{
    canonical_peer_addr, decode_wire_message, NetworkConfig, NetworkMessage, NetworkNode,
    WirePenaltyTracker, WireReaction, MAX_WIRE_ADDR_LEN,
};
use bloch::sync::peer_state::PeerStateTable;
use parking_lot::RwLock;
use tokio::sync::mpsc;

const GENESIS: [u8; 32] = [0xCA; 32];

/// PeerId determinístico para os testes sem swarm.
fn some_peer_id() -> libp2p::PeerId {
    let key = libp2p::identity::Keypair::ed25519_from_bytes([7u8; 32]).unwrap();
    key.public().to_peer_id()
}

// ═════════════════════════════════════════════════════════════════════════
// PARTE 1 — determinística, sem swarm: a cadeia causal completa nas
// funções REAIS de produção.
// ═════════════════════════════════════════════════════════════════════════

/// (1)+(2): a concatenação pré-fix cresce sem limite E o validador aceitava
/// cada passo. Pós-fix: o validador REJEITA qualquer forma encadeada, e
/// `canonical_peer_addr` é idempotente (o que mata o crescimento na origem).
#[test]
fn validator_rejects_p2p_chain_and_canonical_is_idempotent() {
    let pid = some_peer_id();
    let base = format!("/ip4/45.77.140.150/tcp/16110/p2p/{}", pid);
    assert!(is_valid_public_multiaddr(&base, false), "forma canônica deve ser aceita");

    // Reconstrução EXATA do braço Dialer pré-fix:
    // addr_to_remember = format!("{}/p2p/{}", address_discado, peer_id)
    let mut chained = base.clone();
    let mut first_overflow = None;
    for i in 2..=10 {
        chained = format!("{}/p2p/{}", chained, pid); // o bug, literalmente
        assert!(
            chained.parse::<libp2p::Multiaddr>().is_ok(),
            "a forma encadeada parseia como Multiaddr válido (por isso discava)"
        );
        // REGRESSÃO (pré-fix isto FALHAVA: o validador aceitava a cadeia,
        // known_peers crescia, e o passo 3 abaixo ficava alcançável):
        assert!(
            !is_valid_public_multiaddr(&chained, false),
            "validador deve rejeitar /p2p/ repetido ({}x): {}",
            i,
            &chained[..60]
        );
        if chained.len() > MAX_WIRE_ADDR_LEN && first_overflow.is_none() {
            first_overflow = Some(i);
        }
    }
    // (3): o estouro de 512 acontece com ~9 componentes — exatamente a faixa
    // medida no known_peers.json real (max len 885 = 15 componentes).
    let n = first_overflow.expect("a cadeia estoura MAX_WIRE_ADDR_LEN");
    println!("cadeia estoura MAX_WIRE_ADDR_LEN={} com {} componentes /p2p/", MAX_WIRE_ADDR_LEN, n);
    assert!(n <= 10);

    // Pós-fix: canonical_peer_addr normaliza QUALQUER forma observada para a
    // canônica — idempotente, então reobservação nunca cresce.
    let ma: libp2p::Multiaddr = chained.parse().unwrap();
    let canon = canonical_peer_addr(&ma, &pid);
    assert_eq!(canon, base, "canonical de forma encadeada = forma canônica");
    let canon2 = canonical_peer_addr(&canon.parse().unwrap(), &pid);
    assert_eq!(canon2, canon, "idempotente");
    assert!(is_valid_public_multiaddr(&canon, false));

    // N ciclos de reobservação (o loop dial→connect→persist→dial da vida
    // real): o comprimento é CONSTANTE e sempre abaixo de MAX_WIRE_ADDR_LEN.
    // Pré-fix cada ciclo somava ~57 bytes (um /p2p/<id>) e cruzava 512 no 9º.
    let mut reobserved = canon.clone();
    for cycle in 1..=20 {
        reobserved = canonical_peer_addr(&reobserved.parse().unwrap(), &pid);
        assert_eq!(reobserved, base, "ciclo {}: endereço não cresce", cycle);
        assert!(reobserved.len() <= MAX_WIRE_ADDR_LEN);
    }

    // Defesa em profundidade: entrada individual acima do limite de wire
    // nunca é válida, seja qual for a forma.
    let long = format!("/dns4/{}.example.com/tcp/16110/p2p/{}", "a".repeat(500), pid);
    assert!(!is_valid_public_multiaddr(&long, false), "entrada >512 rejeitada");
}

/// (3)+(4): uma ÚNICA entrada >512 numa PeerExchange derruba o frame inteiro
/// no receptor e o remetente acumula −100 por frame até o graylist (−400).
/// Este é o mecanismo que transformou o produtor num blackhole no node4
/// (5 violações → −500, medido no journal).
#[test]
fn oversized_pex_entry_penalizes_sender_to_graylist() {
    let pid = some_peer_id();
    // Entrada com 9 componentes /p2p/ — como as 11 entradas >512 reais do node4.
    let mut poisoned = format!("/ip4/45.77.140.150/tcp/16110/p2p/{}", pid);
    for _ in 0..8 {
        poisoned = format!("{}/p2p/{}", poisoned, pid);
    }
    assert!(poisoned.len() > MAX_WIRE_ADDR_LEN);

    // known_peers real tinha ~700 entradas; basta UMA >512 no meio.
    let mut peers: Vec<String> = (0..19)
        .map(|i| format!("/ip4/45.77.140.{}/tcp/16110/p2p/{}", i + 1, pid))
        .collect();
    peers.push(poisoned);
    let frame = bincode::serde::encode_to_vec(
        &NetworkMessage::PeerExchange { peers },
        bincode::config::standard(),
    )
    .unwrap();

    // O receptor rejeita o frame INTEIRO com o erro exato do journal.
    let err = decode_wire_message(&frame).unwrap_err();
    assert!(
        format!("{:?}", err).contains("MAX_WIRE_ADDR_LEN"),
        "erro esperado do journal, obtido: {:?}",
        err
    );

    // E o WirePenaltyTracker (o mesmo objeto usado por run()) acumula −100
    // por frame até cruzar graylist_threshold (−400) na 4ª violação.
    let mut tracker = WirePenaltyTracker::new();
    let sender = some_peer_id();
    let mut last = 0.0;
    for i in 1..=5 {
        match tracker.classify(sender, &frame) {
            WireReaction::Penalize { score, .. } => {
                last = score;
                println!("violação {} → app score {}", i, score);
            }
            other => panic!("esperava Penalize, obtive {:?}", other),
        }
    }
    assert!(last <= -400.0, "score {} deve cruzar graylist_threshold −400", last);
}

// ═════════════════════════════════════════════════════════════════════════
// PARTE 2 — AO VIVO: dois NetworkNode::run reais em loopback.
// ═════════════════════════════════════════════════════════════════════════

struct Harness {
    peer_id: libp2p::PeerId,
    addr: libp2p::Multiaddr,
    dag: Arc<RwLock<GhostDAG>>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    #[allow(dead_code)]
    gossip_seen: Arc<AtomicU64>,
    dir: tempfile::TempDir,
}

fn full_addr(h: &Harness) -> String {
    format!("{}/p2p/{}", h.addr, h.peer_id)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct SimPayload {
    hash: [u8; 32],
    parents: Vec<[u8; 32]>,
    timestamp: u64,
    work: u128,
}

/// Igual ao spawn_node de sprint_ee_transport_convergence.rs, mais um
/// `pre_seed_known_peers`: conteúdo gravado em known_peers.json ANTES do
/// boot (simula um datadir envenenado como os da frota).
async fn spawn_node(bootstrap_peers: Vec<String>, pre_seed_known_peers: Option<Vec<String>>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    if let Some(seed) = pre_seed_known_peers {
        std::fs::write(
            dir.path().join("known_peers.json"),
            serde_json::to_string(&seed).unwrap(),
        )
        .unwrap();
    }
    let cfg = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers,
        dns_seeds: vec![],
        max_peers: 8,
        data_dir: dir.path().to_path_buf(),
        allow_private_peers: true,
        behind_proxy: true,
        enable_mdns: false,
        archive: false,
    };
    let node = NetworkNode::new(cfg).expect("NetworkNode::new");
    let peer_id = node.peer_id;

    let dag = Arc::new(RwLock::new(GhostDAG::with_k(3)));
    dag.write().add_genesis(GENESIS, 0);
    let peer_state = Arc::new(PeerStateTable::new());
    let store = Arc::new(bloch::storage::Storage::open(&dir.path().join("db")).expect("store"));

    let (block_tx, mut block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, mut addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();

    {
        let dag = dag.clone();
        let peer_state = peer_state.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let _ = node.run(block_tx, outbound_rx, dag, peer_state, store, Some(addr_tx)).await;
        });
    }

    let gossip_seen = Arc::new(AtomicU64::new(0));
    {
        let dag = dag.clone();
        let seen = gossip_seen.clone();
        tokio::spawn(async move {
            while let Some(msg) = block_rx.recv().await {
                if !matches!(msg, NetworkMessage::PeerCount { .. }) {
                    seen.fetch_add(1, Ordering::Relaxed);
                }
                if let NetworkMessage::NewBlock { block_data, .. } = msg {
                    if let Ok((p, _)) = bincode::serde::decode_from_slice::<SimPayload, _>(
                        &block_data,
                        bincode::config::standard(),
                    ) {
                        let mut d = dag.write();
                        if !d.has_block(&p.hash) && p.parents.iter().all(|h| d.has_block(h)) {
                            let _ = d.add_block(p.hash, p.parents.clone(), p.timestamp, p.work);
                        }
                    }
                }
            }
        });
    }

    let addr = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let a = addr_rx.recv().await.expect("listen_report closed");
            let s = a.to_string();
            if s.starts_with("/ip4/127.0.0.1/tcp/") && !s.contains("/ws") {
                return a;
            }
        }
    })
    .await
    .expect("listen addr");

    Harness { peer_id, addr, dag, outbound_tx, gossip_seen, dir }
}

fn read_known_peers(h: &Harness) -> Vec<String> {
    let p = h.dir.path().join("known_peers.json");
    match std::fs::read_to_string(&p) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// AO VIVO (1)+(5): depois de um ciclo real de conexão + tick de save (60 s),
/// o known_peers.json de A deve conter APENAS a forma canônica do endereço de
/// B (exatamente um /p2p/, sufixo do peer id) — e o de B NÃO deve conter o
/// socket efêmero de A.
///
/// PRÉ-FIX este teste FALHA nos dois asserts:
///   - A grava "/ip4/127.0.0.1/tcp/<port>/p2p/<B>/p2p/<B>" (concatenação);
///   - B grava "/ip4/127.0.0.1/tcp/<efêmera>/p2p/<A>" (lixo do Listener).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_connection_persists_only_canonical_addrs() {
    let b = spawn_node(vec![], None).await;
    let a = spawn_node(vec![full_addr(&b)], None).await;

    // conexão + 1º tick de save_peers (60 s) dos dois lados
    tokio::time::sleep(Duration::from_secs(70)).await;

    let a_peers = read_known_peers(&a);
    println!("known_peers de A: {:?}", a_peers);
    assert!(!a_peers.is_empty(), "A conectou a B e deve ter persistido o endereço");
    let b_canon = full_addr(&b);
    for e in &a_peers {
        assert_eq!(
            e.matches("/p2p/").count(),
            1,
            "PRÉ-FIX FALHA AQUI (concatenação): {}",
            e
        );
        assert_eq!(e, &b_canon, "única entrada esperada é a forma canônica de B");
    }

    let b_peers = read_known_peers(&b);
    println!("known_peers de B: {:?}", b_peers);
    let b_listen_port = format!("/tcp/{}", b.addr.to_string().rsplit('/').next().unwrap());
    let _ = b_listen_port;
    for e in &b_peers {
        // B só conheceu A por conexão INBOUND: send_back_addr é o socket
        // efêmero de A e não é discável — não pode ser persistido.
        assert!(
            !e.contains(&a.peer_id.to_string()),
            "PRÉ-FIX FALHA AQUI (lixo de porta efêmera do Listener): {}",
            e
        );
    }
}

/// AO VIVO (4): o blackhole em si — 5 frames com violação de wire (cada um
/// com bytes DISTINTOS, como as respostas PEX reais, cujo conteúdo muda
/// entre uma e outra) levam o score de A em B para −500 < graylist (−400) e
/// o gossipsub de B passa a IGNORAR os NewBlock de A com o TCP de pé.
///
/// Este teste vale PRÉ e PÓS-fix (a regra de wire não muda — quem envia
/// entrada >512 DEVE ser penalizado): ele fixa o mecanismo que transformou o
/// produtor num blackhole no node4 (journal: 5 violações → −500 → 2 eventos
/// de tip em 2 h). A injeção via outbound_tx contorna o known_peers de A —
/// exatamente como um binário antigo/poisonado faria.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_wire_violations_graylist_blackhole() {
    let pid = some_peer_id();
    let b = spawn_node(vec![], None).await;
    let a = spawn_node(vec![full_addr(&b)], None).await;
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Controle: com a mesh limpa, um bloco de A chega em B.
    let block1 = [0xD1; 32];
    let p1 = SimPayload { hash: block1, parents: vec![GENESIS], timestamp: 1, work: 1 };
    a.outbound_tx
        .send(NetworkMessage::NewBlock {
            block_hash: block1,
            block_data: bincode::serde::encode_to_vec(&p1, bincode::config::standard()).unwrap(),
            height: 1,
            blue_score: 1,
        })
        .await
        .unwrap();
    let ok1 = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if b.dag.read().has_block(&block1) { return true; }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(ok1, "controle: mesh limpa deve entregar block1");

    // 5 PeerExchange com uma entrada >512 cada, bytes distintos (octeto varia).
    for i in 0..5u8 {
        let mut poisoned = format!("/ip4/127.0.0.{}/tcp/45001/p2p/{}", i + 1, pid);
        for _ in 0..8 {
            poisoned = format!("{}/p2p/{}", poisoned, pid);
        }
        assert!(poisoned.len() > MAX_WIRE_ADDR_LEN);
        a.outbound_tx
            .send(NetworkMessage::PeerExchange { peers: vec![poisoned] })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Agora B tem A em graylist: block2 NUNCA chega (o sintoma de produção:
    // TCP de pé, zero anúncios).
    let block2 = [0xD2; 32];
    let p2 = SimPayload { hash: block2, parents: vec![block1], timestamp: 2, work: 1 };
    a.outbound_tx
        .send(NetworkMessage::NewBlock {
            block_hash: block2,
            block_data: bincode::serde::encode_to_vec(&p2, bincode::config::standard()).unwrap(),
            height: 2,
            blue_score: 2,
        })
        .await
        .unwrap();
    let ok2 = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if b.dag.read().has_block(&block2) { return true; }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        !ok2,
        "após 5 violações de wire, B deve ter A em graylist e block2 não chega"
    );
    println!("blackhole reproduzido: block1 entregue, 5 violações, block2 blackholed");
}

/// AO VIVO (2)..(4) + autocura: A bota com um known_peers.json envenenado
/// (uma entrada com 9× /p2p/, >512 bytes — cópia do padrão real da frota).
///
/// PÓS-FIX: prune_invalid remove a entrada no load; as respostas PEX de A
/// ficam limpas; B nunca penaliza A; um NewBlock publicado por A CHEGA ao
/// DAG de B mesmo sob rajada de PeerRequest (que pré-fix gerava uma resposta
/// envenenada por pedido).
///
/// PRÉ-FIX este teste FALHA: cada PeerRequest de B arranca de A uma
/// PeerExchange com a entrada >512 → B aplica −100 cumulativo → graylist na
/// 4ª → o NewBlock de A é ignorado pelo gossipsub de B (blackhole idêntico
/// ao node4: TCP de pé, zero blocos).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_poisoned_known_peers_self_heals_and_blocks_flow() {
    let pid = some_peer_id();
    let mut poisoned = format!("/ip4/127.0.0.1/tcp/45001/p2p/{}", pid);
    for _ in 0..8 {
        poisoned = format!("{}/p2p/{}", poisoned, pid);
    }
    assert!(poisoned.len() > MAX_WIRE_ADDR_LEN);

    let b = spawn_node(vec![], None).await;
    let a = spawn_node(vec![full_addr(&b)], Some(vec![poisoned])).await;

    // conexão estabelecida + mesh formada
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Rajada de PeerRequest de B (pré-fix: cada um arranca uma PeerExchange
    // envenenada de A = −100 em A no scoring de B; 5 > limiar de graylist).
    for _ in 0..5 {
        b.outbound_tx.send(NetworkMessage::PeerRequest).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // A publica um bloco novo; pré-fix B está com A em graylist e o ignora.
    let child = [0xCB; 32];
    let payload = SimPayload { hash: child, parents: vec![GENESIS], timestamp: 1, work: 1 };
    let block_data = bincode::serde::encode_to_vec(&payload, bincode::config::standard()).unwrap();
    a.outbound_tx
        .send(NetworkMessage::NewBlock {
            block_hash: child,
            block_data,
            height: 1,
            blue_score: 1,
        })
        .await
        .unwrap();

    let arrived = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if b.dag.read().has_block(&child) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        arrived,
        "PRÉ-FIX FALHA AQUI: B graylistou A pelas PeerExchange envenenadas e o \
         NewBlock nunca chegou (o blackhole do node4/miner-box). Pós-fix o \
         datadir envenenado é limpo no load e o bloco flui."
    );

    // E o arquivo de A, após o tick de save, não pode reter a entrada >512.
    tokio::time::sleep(Duration::from_secs(55)).await;
    let a_peers = read_known_peers(&a);
    println!("known_peers de A pós-cura: {:?}", a_peers);
    assert!(
        a_peers.iter().all(|e| e.len() <= MAX_WIRE_ADDR_LEN && e.matches("/p2p/").count() == 1),
        "nenhuma entrada encadeada/oversized pode sobreviver: {:?}",
        a_peers
    );
}
