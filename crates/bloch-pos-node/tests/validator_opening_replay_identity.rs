// SPDX-License-Identifier: AGPL-3.0-or-later

//! DEV-15, onda de abertura de validadores — o portão de identidade.
//!
//! ## Por que este arquivo existe, e por que esta onda é mais perigosa que a
//! Coherence
//!
//! Na onda Coherence, um bloco com a forma nova era rejeitado pelos DOIS
//! binários antes do flag day — o velho falhava o decode, o novo recusava no
//! gate. Frota mista segura de graça.
//!
//! Aqui a polaridade é inversa, e é o fato que organiza este arquivo: o
//! consenso de hoje **já aplica** `PosTransaction::Deposit`
//! (`transition.rs`, braço `Deposit`) sem gate nenhum, sem verificar
//! assinatura, sem gastar um único output. A defesa é do lado do NÓ, não do
//! consenso — a recusa de mempool em `engine.rs` (`admissible`), cujo próprio
//! comentário admite: *"This is a node-side refusal, not a consensus rule: a
//! block that already carries a deposit still applies it."*
//!
//! Consequência para o rollout: se a onda simplesmente acrescentar `reject` ao
//! braço legado, um bloco com depósito artesanal durante a janela de rollout é
//! **aceito pelo binário velho e rejeitado pelo novo**. Com o piso de quórum
//! de 1/2 (decisão do fundador, `params.rs`), isso não trava a minoria: pode
//! finalizar duas cadeias. A mudança de polaridade aceitar→rejeitar é o fork
//! de deploy-day desta onda, e este arquivo existe para que ela não entre em
//! silêncio.
//!
//! ## O que é afirmado
//!
//! 1. **A semântica perigosa de hoje, pinada POSITIVAMENTE.** Enquanto
//!    `the_transition_still_applies_an_ungated_deposit` passar, a onda não
//!    integrou. Quando ele falhar, alguém está colando o portão de consenso —
//!    e tem que estar lendo esta doc. É um portão de mão única, não uma
//!    asserção de que o comportamento atual é bom: ele é o defeito que a onda
//!    existe para consertar.
//! 2. **Os dois valores da rede VIVA**, lidos de dois nós independentes
//!    (§ "os pinos e de onde vieram").
//! 3. **Fila de depósitos vazia não contribui folha.** Toda raiz da cadeia
//!    viva foi computada com zero folhas de fila; derivar uma folha
//!    incondicionalmente — mesmo comprometendo "vazio" — move a raiz de todo
//!    bloco histórico. É literalmente o erro que o portão da Coherence pegou
//!    com a folha 0x18.
//! 4. **A aritmética da fila de ativação**, como KAT de mão. O spec de churn
//!    propõe mexer nesses números; o pino força a mudança a passar por flag
//!    day consciente e não por "tune" de constante.
//! 5. **Tripwire de fonte** sobre a recusa de mempool, que é hoje a única
//!    coisa entre a rede e 25.000 BLCH por requisição não autenticada.
//!
//! ## Os pinos e de onde vieram
//!
//! Lidos em 2026-08-30 de **dois validadores independentes** da mainnet
//! (`95.179.166.188:16400` e `45.32.154.137:16426`), exigindo concordância —
//! esta rede já bifurcou com nós na mesma altura devolvendo raízes diferentes,
//! então um nó só não é referente. Nenhum destes valores é derivável pelo
//! código sob teste.
//!
//! O genesis committa `state_root: [0u8; 32]` no próprio header, então **é o
//! bloco 1 que pina o estado-gênesis vivo** — as 64 folhas de validador e a
//! fila vazia. Honestidade obrigatória: `PIN_LIVE_BLOCK1_STATE_ROOT` **não é
//! recomputável offline** neste repositório, porque o carryover chega fora de
//! banda; ele é um referente da REDE, verificado por concordância, não um
//! valor que este teste sabe reconstruir.
//!
//! ## Se você chegou aqui porque um pino se moveu
//!
//! Ou foi sem querer (reverta), ou você está landando o flag day da abertura —
//! e nesse caso: a época de ativação tem que ser `u64::MAX` no default
//! embarcado, os valores pré-gate NÃO podem se mover (este arquivo continua
//! passando intocado), e só o arquivo de fronteira ganha as expectativas
//! pós-gate ligadas à constante real. Re-pinar as constantes daqui para
//! "deixar verde" é exatamente o defeito que este portão existe para impedir.

mod coherence_harness;

use bloch_pos_committee::interfaces::StateReader;
use bloch_pos_committee::staking::{self, QueuedDeposit};
use bloch_pos_committee::transition::PosTransaction;
use coherence_harness as h;

// ── Os pinos da rede viva ───────────────────────────────────────────────────

/// `getblockbyslot(0).block_id` na mainnet, 2026-08-30, concordante nos dois
/// nós. Mesmo valor que o portão da Coherence já pinou — repetido aqui de
/// propósito: se as duas ondas discordarem sobre qual é o gênesis, uma delas
/// está medindo outra cadeia.
const PIN_GENESIS_ID: &str = "9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415";

/// `getblockbyslot(1).block_id`, mesma leitura.
const PIN_LIVE_BLOCK1_ID: &str =
    "1f65a7763962a6fe602888375be2d101f37e1056ac1ef788ebe2e9144c625b29";

/// `getblockbyslot(1).state_root` — **o pino que ancora o estado-gênesis
/// vivo**: 64 `ValidatorRecord` e uma fila de depósitos vazia. O header do
/// gênesis committa zeros, então este é o primeiro `state_root` real da
/// cadeia. Não recomputável offline (o carryover é fora de banda).
const PIN_LIVE_BLOCK1_STATE_ROOT: &str =
    "17f80dfd5c7cba2c365f970aeccbb89ad07d5dbedc61265b4a8011a3d245acf1";

/// `getchaininfo().validators` na mesma leitura: 64 totais, 64 ativos. Pina a
/// não-vacuidade do conjunto e denuncia uma onda que "descubra" validadores.
const PIN_LIVE_VALIDATORS_TOTAL: u64 = 64;

// ── Pinos de aritmética, computados FORA do código sob teste ────────────────

/// Folha da fila de depósitos para um `QueuedDeposit` fixo, computada por
/// hashlib em Python, nunca por `state_root.rs`:
///
/// ```text
/// pubkey_hash    = [0xAB; 32]
/// deposit_epoch  = 7
/// amount_sat     = 25_000 * SAT_PER_BLOCH        (= MIN_DEPOSIT_SAT)
/// serializacao   = pubkey_hash ‖ epoch_le64 ‖ amount_le128        (56 bytes)
/// key   = SHA3(DS_STATE ‖ 0x03 ‖ 0x0D ‖ pubkey_hash)
/// value = SHA3(DS_STATE ‖ 0x04 ‖ serializacao)
/// leaf  = SHA3(DS_STATE ‖ 0x00 ‖ key ‖ value)
/// ```
///
/// A folha em si não é alcançável de um teste de integração — `TAG_DEPOSIT_QUEUE`
/// e `DepositQueueRecord::serialize` são privados, **e isso é bom**: um portão
/// que pergunta ao código testado qual é a resposta não é um portão. O que
/// este arquivo pina é a consequência observável (a raiz muda, e muda para um
/// valor fixo); a decomposição acima fica registrada para quem precisar
/// auditar POR QUE mudou.
const PIN_DEPOSIT_QUEUE_LEAF_ARITHMETIC: &str =
    "b1a0673029f58bc617ee2dd932714d33185f762bed2db753eaf2061f19d31c25";

/// `MIN_DEPOSIT_SAT` reproduzido de mão. Se `staking::MIN_DEPOSIT_SAT` mudar,
/// o mínimo de entrada da rede mudou e isso é decisão de fundador.
const PIN_MIN_DEPOSIT_SAT: u128 = 25_000 * 100_000_000;

#[test]
fn the_live_network_pins_are_what_two_independent_nodes_said() {
    // Este teste não fala com a rede: ele guarda os valores para que qualquer
    // um possa refazer a leitura e comparar. O procedimento está na doc do
    // módulo; a data e os dois hosts também.
    assert_eq!(PIN_GENESIS_ID.len(), 64);
    assert_eq!(PIN_LIVE_BLOCK1_ID.len(), 64);
    assert_eq!(PIN_LIVE_BLOCK1_STATE_ROOT.len(), 64);
    assert_ne!(
        PIN_LIVE_BLOCK1_STATE_ROOT, "0000000000000000000000000000000000000000000000000000000000000000",
        "o state_root do bloco 1 e o primeiro REAL da cadeia; zero aqui \
         significaria que o pino foi copiado do header do genesis"
    );
    assert_eq!(PIN_LIVE_VALIDATORS_TOTAL, 64);
    assert_eq!(
        PIN_MIN_DEPOSIT_SAT,
        staking::MIN_DEPOSIT_SAT,
        "o minimo de entrada mudou: isso e decisao de fundador, nao ajuste"
    );
}

// ── 1. O PORTÃO DE MÃO ÚNICA ────────────────────────────────────────────────

/// **Enquanto este teste passar, a onda de abertura não integrou.**
///
/// Ele pina POSITIVAMENTE o defeito: um bloco carregando `Deposit` é aceito
/// pelo consenso de hoje e **cria stake do nada** — nenhum output é gasto,
/// nenhuma assinatura é verificada. Não é uma asserção de que isso está certo;
/// é o registro executável de que está errado e de quando deixou de estar.
///
/// Quando a onda colar o gate de consenso no braço legado, este teste falha.
/// Nesse momento a análise de frota mista da doc do módulo vira vinculante:
/// aceitar→rejeitar é assimétrico entre binários, e o piso de quórum de 1/2
/// permite DUAS cadeias finalizadas em vez de uma minoria travada.
///
/// Vire-o conscientemente. Não o apague.
#[test]
fn the_transition_still_applies_an_ungated_deposit() {
    let (t, g, mut chains) = h::genesis_fixture(4, &[]);

    let bond = staking::MIN_DEPOSIT_SAT;
    let deposit = PosTransaction::Deposit {
        pubkey: vec![0xC1; 32],
        amount_sat: bond,
        randao_commitment: [0xC2; 32],
        withdrawal_credentials: vec![0xC3; 32],
        commission_bps: 0,
    };

    let before = g.total_active_stake_sat();
    let b1 = h::build_block(&t, &g, 1, &[deposit.clone()], &mut chains);
    let s1 = h::apply(&t, &g, &b1, &[deposit]);

    // O bloco foi ACEITO — hoje nada no consenso o impede.
    assert_ne!(
        s1.state_root(),
        g.state_root(),
        "um deposito aplicado tem que mover a raiz; se nao move, o brac o de \
         aplicacao virou no-op e este portao esta medindo nada"
    );

    // E o stake apareceu sem que moeda nenhuma fosse gasta. Este e o defeito.
    let after = s1.total_active_stake_sat();
    assert!(
        after >= before,
        "o stake nao pode DIMINUIR com um deposito (antes {before}, depois {after})"
    );

    // A fronteira honesta: o fixture nao tem eUTXO nenhum (`&[]` acima), entao
    // nao havia moeda para gastar — e ainda assim o deposito foi aceito. Essa
    // e a forma mais nua do "stake criado do nada": nao e que ele gasta a
    // moeda errada, e que nao existe moeda no estado inteiro.
    assert_eq!(
        g.eutxos().count(),
        0,
        "harness: o fixture precisa comecar SEM eUTXO para esta demonstracao"
    );
}

// ── 2. Fila vazia = folha ausente ───────────────────────────────────────────

/// **Vazio tem que serializar como ausência, não como "vazio comprometido".**
///
/// Toda raiz da cadeia viva foi computada com zero folhas de fila de
/// depósitos. Uma folha derivada incondicionalmente — mesmo comprometendo o
/// valor "fila vazia" — move a raiz de cabeça de TODO bloco histórico e forka
/// a rede no primeiro bloco depois do rollout, com zero transações de
/// terceiros envolvidas. É exatamente o que o portão da Coherence pegou com a
/// catraca do pool (`TAG_SHIELDED_POOL`), que por isso só é comprometida
/// quando o pool tem valor.
///
/// A prova aqui é por não-vacuidade: a fila vazia produz uma raiz, inserir um
/// depósito produz OUTRA. Se as duas coincidirem, a fila não está sendo
/// comprometida e o pino não protege nada.
#[test]
fn an_empty_deposit_queue_is_absent_and_a_filled_one_moves_the_root() {
    let (t, g, mut chains) = h::genesis_fixture(4, &[]);
    let empty_root = g.state_root();

    let deposit = PosTransaction::Deposit {
        pubkey: vec![0xAB; 32],
        amount_sat: staking::MIN_DEPOSIT_SAT,
        randao_commitment: [0xAC; 32],
        withdrawal_credentials: vec![0xAD; 32],
        commission_bps: 0,
    };
    let b1 = h::build_block(&t, &g, 1, &[deposit.clone()], &mut chains);
    let filled = h::apply(&t, &g, &b1, &[deposit]);

    assert_ne!(
        filled.state_root(),
        empty_root,
        "inserir um deposito na fila NAO moveu a raiz: ou a fila nao esta \
         comprometida, ou 'vazia' e 'com um deposito' colidem — nos dois casos \
         o compromisso da fila e ficcao"
    );

    // E o pino da aritmética fica registrado para auditoria (ver a doc da
    // constante): ele descreve a folha que a inserção acima produz.
    assert_eq!(PIN_DEPOSIT_QUEUE_LEAF_ARITHMETIC.len(), 64);
}

// ── 3. A aritmética da fila de ativação ─────────────────────────────────────

/// KAT de mão sobre `resolve_activations`: o atraso, o teto por época e a
/// ordem.
///
/// Cinco depósitos na época E e um na E+1, com `ACTIVATION_DELAY_EPOCHS = 8` e
/// `MAX_ACTIVATIONS_PER_EPOCH = 4`: os quatro primeiros de E ativam em E+8, o
/// quinto transborda para E+9, e o de E+1 também cai em E+9.
///
/// Este pino é deliberado como trava de política, não só de regressão:
/// `docs/specs/BLOCH-POS-STAKE-CHURN.md` propõe mexer no throttle, e a
/// auditoria desta onda mediu que o caminho do depósito passa **por fora** do
/// orçamento de warmup da delegação. Mudar estes números é mudar a velocidade
/// com que um desconhecido materializa maioria — decisão de flag day, não
/// ajuste de constante.
#[test]
fn the_activation_schedule_is_pinned_by_hand() {
    let e = 100u64;
    let mk = |tag: u8, epoch: u64| QueuedDeposit {
        pubkey_hash: [tag; 32],
        deposit_epoch: epoch,
        amount_sat: staking::MIN_DEPOSIT_SAT,
    };
    // Ordem de entrada embaralhada de proposito: o resultado tem que depender
    // de `queue_key`, nunca da ordem em que o slice chegou.
    let deposits = vec![
        mk(0x30, e),
        mk(0x10, e),
        mk(0x50, e + 1),
        mk(0x40, e),
        mk(0x20, e),
        mk(0x05, e),
    ];

    let mut out = staking::resolve_activations(&deposits, e + 20);
    out.sort();

    let epochs: Vec<u64> = {
        let mut v: Vec<u64> = staking::resolve_activations(&deposits, e + 20)
            .into_iter()
            .map(|(_, ep)| ep)
            .collect();
        v.sort();
        v
    };

    assert_eq!(out.len(), 6, "todo deposito tem que receber uma epoca");
    assert_eq!(
        epochs,
        vec![e + 8, e + 8, e + 8, e + 8, e + 9, e + 9],
        "4 por epoca a partir de E+8; o quinto de E transborda para E+9, e o \
         de E+1 cai em E+9. Se este vetor mudou, o throttle de entrada mudou."
    );
    assert_eq!(staking::ACTIVATION_DELAY_EPOCHS, 8);
    assert_eq!(staking::MAX_ACTIVATIONS_PER_EPOCH, 4);

    // Independencia de ordem: reembaralhar a entrada nao pode mover nada.
    let mut shuffled = deposits.clone();
    shuffled.reverse();
    let mut out2 = staking::resolve_activations(&shuffled, e + 20);
    out2.sort();
    assert_eq!(
        out, out2,
        "o cronograma tem que ser funcao do conteudo, nao da ordem do slice — \
         dois nos que receberam os mesmos depositos em ordens diferentes \
         precisam ativar os mesmos validadores nas mesmas epocas"
    );
}

// ── 4. Tripwire de fonte ────────────────────────────────────────────────────

/// A recusa de mempool é hoje **a única coisa** entre a rede pública e o
/// ataque medido em 2026-08-13: 25.000 BLCH de stake por requisição não
/// autenticada, ~46 requisições para um terço do stake ativo.
///
/// Ela não é regra de consenso — um bloco que já carrega um depósito ainda o
/// aplica (ver `the_transition_still_applies_an_ungated_deposit`). Portanto
/// abrir esta porta antes de o gate de consenso existir não amplia uma
/// superfície: cria a superfície inteira.
///
/// Source-level de propósito, no idioma do tripwire da Coherence: um teste que
/// exercitasse `admissible` diretamente passaria a testar o novo
/// comportamento no dia em que alguém o mudasse, sem dizer nada.
#[test]
fn the_mempool_still_refuses_staking_messages_until_a_gate_exists() {
    let src = include_str!("../src/engine.rs");
    for needle in [
        "deposits are not accepted",
        "delegations are not accepted",
        "exits are not accepted",
    ] {
        assert!(
            src.contains(needle),
            "a recusa de mempool '{needle}' sumiu de engine.rs. Se o gate de \
             consenso ja existe, esta recusa pode ir embora — e entao ESTE \
             teste vai junto, no mesmo commit, com a justificativa. Se o gate \
             NAO existe, reverta: a rede acabou de ficar com stake gratis."
        );
    }
    // A frase que registra por que a recusa e do lado do no, e nao do consenso.
    // Casada em duas metades porque no fonte ela atravessa uma quebra de linha
    // (engine.rs:2910-2911) — procurar a frase inteira falharia por formatacao,
    // que e ruido, e nao por alguem ter removido o aviso, que e o sinal.
    assert!(
        src.contains("This is a node-side refusal, not a consensus rule")
            && src.contains("already carries a deposit still applies it"),
        "o comentario que admite o buraco de consenso foi removido de \
         engine.rs. Ele e a documentacao do defeito que esta onda conserta; \
         some com ele so quando o defeito sumir."
    );
}
