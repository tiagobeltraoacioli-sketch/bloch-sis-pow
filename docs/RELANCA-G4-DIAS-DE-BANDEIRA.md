<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Relançamento da Genesis-4 — os dois portões que preservam a história

Runbook operacional para armar `ANCESTRY_SEED_ACTIVATION_EPOCH` e
`LEAK_RECOVERY_ACTIVATION_EPOCH` (`crates/bloch-pos-committee/src/params.rs`,
linhas 544 e 560 em `relanca/e1400`), hoje os dois em `u64::MAX` — inertes.

Este arquivo é **irmão** de `docs/LEAKED-ROSTER-FLAG-DAY.md`, não substituto.
Aquele descreve o dia de bandeira E=1400, já armado e já rolado na frota; este
descreve os dois portões que vieram depois, no commit `7b9cb6c6`. Onde os dois
divergem, a divergência está marcada e explicada — o runbook do E=1400
continua correto no que ele descreve, e obsoleto na fórmula de margem (§2.2).

Substitui a tentativa anterior, `pmo/runbook-relanca-gates @ 91a978b5`. Aquele
ramo saiu de `7fa37474` e **não contém `7b9cb6c6`**: as constantes que ele
documenta existiam lá apenas como modificação não commitada, e todas as
referências de linha dele apontam para um worktree, não para um commit. Texto
dele foi aproveitado; nenhuma afirmação dele foi aproveitada sem reconferência
contra `relanca/e1400`.

---

> ## ⚠ Se você veio aqui para ROLAR A FROTA, leia isto primeiro
>
> **O título desta página está desatualizado por projeto.** Ela nasceu para
> dois portões; depois da integração de consenso de 2026-08-31 existem
> **nove**, e quatro deles são novos e inertes. O mapa completo — todos os
> nove, a ordem entre eles, e o que cada um exige para ser armado — é a
> **§11**. As §§0–10 continuam corretas no que descrevem (os portões
> `ANCESTRY_SEED` e `LEAK_RECOVERY`) e **não** descrevem os outros sete.
>
> **E uma coisa muda sem portão nenhum, só de trocar o binário:** blocos com
> as tags de staking `0x02`/`0x03`/`0x04` passam a ser rejeitados por
> consenso em toda época. Isso tem uma pré-condição obrigatória que **expira**
> — rodar o scanner `scan_block_log_for_staking_tags` contra um `blocks.log`
> **atual** da mainnet, no dia do rollout, não confiando no resultado zero de
> 2026-08-31. Se ele falhar e você rolar mesmo assim, **todo nó atualizado
> para no primeiro bloco com essas tags**. Comando e critério: **§11.0**.

---

## 0. Versionar ANTES de armar. Isto é a seção 0 por um motivo

O runbook do E=1400 foi commitado em `04ee1888` — **depois** de 64 nós já terem
sido armados a partir dele. Durante essa janela, a constante em `params.rs`
apontava, por nome, para um arquivo que não existia em nenhum commit. A cópia
não rastreada continua no worktree principal até hoje (`git status` em
`/Users/tiagoacioli/dev/BlochPOS` mostra `?? docs/LEAKED-ROSTER-FLAG-DAY.md`).

Um valor armado que só existe num disco é um valor que ninguém pode auditar,
reproduzir ou refutar. A regra é uma:

> **A constante, o tripwire e este arquivo entram no MESMO commit.** Se o
> commit não tem os três, o release não está armado — está acidentado.

O diff de armamento está versionado ao lado deste arquivo como
`RELANCA-G4-DIAS-DE-BANDEIRA.activation.patch`, com o placeholder `__E_STAR__`
— sem substituir, não compila, de propósito. Ele troca exatamente três coisas:
as duas constantes e o tripwire de inércia (que vira o tripwire armado mais o
teste do §2.5). Aplicação no dia do tag:

```sh
E=<E* escolhido pela fórmula do §2.2, no instante do tag>
sed "s/__E_STAR__/$E/g" docs/RELANCA-G4-DIAS-DE-BANDEIRA.activation.patch | git apply
cargo test -p bloch-pos-committee --lib   # o tripwire armado agora pina $E
```

> **Este patch APODRECE, e o apodrecimento é silencioso.** Ele casa por
> contexto dentro de `transition.rs` — um arquivo que hoje está sendo editado
> por mais de uma esteira ao mesmo tempo. Verificado limpo
> (`git apply --check`, RC=0) em **2026-08-31, sobre `a8df1a45`**, com o
> `__E_STAR__` substituído por um valor de teste. Isso NÃO é uma garantia
> para o dia do tag: **re-rode o `--check` antes de confiar nele**, e se
> falhar, re-derive o diff a partir das três coisas que ele troca (as duas
> constantes e o tripwire) em vez de forçar o apply. Um patch que não aplica
> é melhor que um que aplica torto; o pior dos três é descobrir isso no dia.

```sh
# antes de confiar no patch, sempre:
sed "s/__E_STAR__/9999/g" docs/RELANCA-G4-DIAS-DE-BANDEIRA.activation.patch \
  | git apply --check && echo "aplica limpo" || echo "APODRECEU — re-derive"
```

---

## 1. O que cada portão muda no COMPORTAMENTO do nó

Não no que o nome sugere. O que segue foi lido em `transition.rs`,
`committees.rs` e `finality.rs` em `relanca/e1400`.

### 1.1 `ANCESTRY_SEED_ACTIVATION_EPOCH` — a semente

O código, dentro de `CommittedState::seed_for_epoch` (`transition.rs`), que
desde a unificação lê a regra de **um único lugar**,
`params::seed_lookahead_at`:

```rust
// params.rs — a ÚNICA grafia da regra F6:
pub fn seed_lookahead_at(epoch: u64) -> u64 {
    if epoch < ancestry_seed_gate_epoch() { 0 }        // regra antiga: back = 1
    else { crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS } // regra nova: back = 2
}
// transition.rs::seed_for_epoch:
let back = 1 + crate::params::seed_lookahead_at(epoch);
```

`MIN_SEED_LOOKAHEAD_EPOCHS = 1` (`committees.rs`). A unificação não é
cosmética: o juiz de gossip do nó (`engine.rs::seed_for_attestation`) carregava
uma **cópia própria e não-portada** da aritmética — escrita na janela em que o
portão tinha sido deletado — e por isso julgava atestações chegando por gossip
contra os comitês do fechamento de `E−2` enquanto a transição (e o dever do
próprio atestador) usava `E−1`. Voto honesto respondido com
`Reject(NotInCommittee)`, penalidade para o peer que retransmitiu, e pool de
proponente magro. As duas pontas agora chamam `seed_lookahead_at`, e o teste
`the_judge_accepts_the_attestation_the_duty_path_produces` (`engine.rs`) fica
vermelho se voltarem a divergir. Então:

| | abaixo do portão | a partir do portão |
|---|---|---|
| `back` | 1 | 2 |
| semente da época `E` | mistura do **fechamento de `E−1`** | mistura do **fechamento de `E−2`** |

**O que um operador observa.** A semente entra em dois lugares e só dois:
`schedule::proposer` (o sorteio de proponente) e `committees::epoch_committees`
(a partição do comitê). Chamadores em `transition.rs:2738` (partição do voto no
fechamento), `:2966` (partição da próxima época) e `:3223` (a época do bloco
sendo aplicado). Portanto, a partir da primeira fronteira `≥ E*`:

- o **proponente sorteado muda já no primeiro slot da época** (`32·E*`). Não é
  garantia por slot — a permutação nova pode coincidir com a antiga num slot
  qualquer — é o primeiro slot *exposto* à semente divergente. O corpo do
  commit `7b9cb6c6` diz exatamente isso, e é a formulação honesta;
- a composição dos comitês muda na mesma fronteira;
- **nada mais muda.** Não muda quem é elegível: desde 2026-08-24
  `epoch_committees` não filtra mais por stake, então a *pertinência* ao comitê
  é função pura de `(semente, época, conjunto de índices)` e o stake decide só
  peso (`docs/RELANCA-G4-DECISOES.md` §1). O portão da semente mexe na
  permutação, nunca no conjunto.

**O que ele fecha** é F6, moagem de proponente: com `back = 1`, os últimos
proponentes de `E−1` veem a partição que a própria revelação deles produz antes
de terem que publicá-la, e podem re-sortear `E` retendo a revelação. Com
`back = 2` não veem. A janela de retenção do RANDAO já cobre isso
(`RANDAO_BOUNDARIES_RETAINED = 2`), então **este portão não muda a raiz de
estado pelo lado da retenção** — muda pelo lado da partição, que decide quais
atestações são admitidas, que é commitado.

**Onde ele quebra o replay se for armado no passado: época 1.** `seed_epoch(1)`
é `None` sob a regra nova, que então toma a mistura do gênese, enquanto a regra
antiga toma `boundary_mixes[0]` — o fechamento da época 0, que não é a mistura
do gênese assim que a época 0 produziu um bloco. Só a época 0 é terreno comum.
Pinado por `below_its_flag_day_the_seed_is_the_original_rule`
(`transition.rs:6947`).

### 1.2 `LEAK_RECOVERY_ACTIVATION_EPOCH` — o leak e o piso

Este portão controla **duas** regras que estão em lugares diferentes de
`finality.rs::process_epoch`, e é importante saber que são duas:

**(a) O piso do denominador** (`finality.rs::process_epoch`):

```rust
} else if votes.epoch < crate::params::leak_recovery_gate_epoch() {
    leak_adjusted                                   // sem piso — a aritmética de hoje
} else {
    let floor = unleaked_total * MIN_QUORUM_DENOMINATOR_NUM / MIN_QUORUM_DENOMINATOR_DEN;
    leak_adjusted.max(floor)
}
```

**(b) A recuperação do acumulador** (`finality.rs::process_epoch`):

```rust
if votes.epoch >= crate::params::leak_recovery_gate_epoch() && !Self::leak_recovery_disabled() {
    // leaked -= max(leaked / INACTIVITY_LEAK_RECOVERY_QUOTIENT, 1), entrada REMOVIDA no zero
}
```

(`params::leak_recovery_gate_epoch()` devolve a constante em qualquer binário
de produção — `#[inline]`, dobra em tempo de compilação; em build de teste ela
pode ser movida por thread via `rehearsal::gates_armed_at_guard`, que é o que
torna a COSTURA — inerte abaixo de `E*`, armada a partir dele — testável em vez
de só os dois extremos.)

`INACTIVITY_LEAK_RECOVERY_QUOTIENT = 16` (`params.rs:110`);
`MIN_QUORUM_DENOMINATOR = 1/2` (`params.rs:147-149`).

**O que um operador observa, item por item:**

1. **O acumulador de leak passa a drenar.** Antes, `leaked` só tinha um caminho
   de escrita (`+= bite`): sem decaimento, sem reset, sem remoção. Uma partição
   colapsava o denominador **permanentemente**, e o relançamento herdaria esse
   colapso, porque a "armazenagem" é o log de blocos e o acumulador é
   re-derivado do zero a cada boot. A partir de `E*` um validador que volta a
   votar recupera 1/16 do saldo por época — o acumulador cai pela metade a cada
   ~11 épocas e drena em número finito de épocas (o `max(·,1)` garante que
   termina).
2. **A recuperação funciona DURANTE a paralisia.** Isto é o ponto de projeto e
   é o que o nome do portão não conta: a regra é discharge **por participação**,
   não por saúde da finalidade. Enquanto a cadeia está vazando, quem votou nesta
   época recupera e quem não votou vaza; quando a cadeia volta a finalizar,
   todos recuperam. A versão "recupera quando a finalidade está boa" trava:
   recuperação espera finalidade, finalidade espera um denominador que o leak
   colapsou.
3. **Um minoritário abaixo de 1/3 do stake original deixa de conseguir
   justificar.** Com o piso, a condição de 2/3 para `p < 1/2` vira `3p ≥ 1`,
   isto é `p ≥ 1/3`. As partições de 2026-08-24 eram de 4 em 64.
4. **E — o que ninguém quer descobrir depois — uma partição 50/50 fica PIOR,
   não melhor.** Cada metade detém 50% ≥ 33,3%, logo cada metade justifica a
   própria raiz assim que o leak drena o denominador. O piso é profilático, não
   curativo: uma vez justificadas, as duas ficam ancoradas. `RELANCA-G4-DECISOES.md`
   §6 registra isto como o **resíduo aceito** — não como bug.
5. **Uma vez recuperado, o estado é idêntico ao de quem nunca vazou.** As
   entradas são removidas no zero, não deixadas em zero, então acumulador
   vazio serializa como comprimento zero. É por isso que tudo antes da primeira
   mordida replaya idêntico, e o ponto de ruptura deste portão é **a primeira
   fronteira de época que acumula mordida** — não a época 1.

**Decisão do CEO, registrada como dele.** O piso é `1/2`, e não `3/4`.
Tiago Acioli, **2026-08-24** — commits `2f477fa2` (19:28:29 −0300) e o merge
`56a06fd5` (19:48:51 −0300), com a fundamentação em `params.rs:113-149`. O que
foi escolhido: `1/2` limita a divergência a **no máximo três conjuntos disjuntos
de um terço cada**, mas não torna a raiz justificada única; `3/4` a tornaria
única, ao preço de nunca recuperar de uma queda de mais de metade do stake.
Segurança contra vivacidade, e a escolha foi por vivacidade. Não é detalhe de
implementação e não deve ser mudado sem ele.

### 1.3 O que NÃO está atrás destes portões

Vale escrever porque na hora do incidente alguém vai atribuir errado:

| regra | portão? |
|---|---|
| roteiro unificado (remoção do filtro pré-shuffle em `epoch_committees`) | **não** — em cadeia sem validador zerado a partição é idêntica dos dois jeitos |
| leak alcançando o roteiro de deveres (`consensus_roster_at`) | sim, mas o **outro**: `LEAKED_ROSTER_ACTIVATION_EPOCH = 1400`, `transition.rs:1662` |
| divergência por slashing no meio da época | **não** — está viva na mainnet hoje, fora de qualquer portão (`RELANCA-G4-DECISOES.md` §5) |
| viés de peso na fork choice | **não**, e deliberadamente não tocado |

---

## 2. Como escolher E\*

### 2.1 O relógio é de parede, e chega faça o que fizer a frota

```
gênese mainnet = 1786656679962 ms = 2026-08-13T21:31:19.962Z
slot   = (agora_ms − 1786656679962) / 30000      (SLOT_DURATION_SECS = 30, params.rs:34)
epoch  = slot / 32                               (SLOTS_PER_EPOCH  = 32, params.rs:30)
época  = 32 × 30 s = 960 s = 16 min   →   90 épocas por dia
utc(E) = 2026-08-13T21:31:19.962Z + E × 960 s
slot(E)= E × 32
```

Confira sempre, com a época já armada como controle:

```sh
python3 - <<'PY'
import datetime, time
g = 1786656679962
utc = lambda E: datetime.datetime.fromtimestamp((g + E*32*30000)/1000, datetime.UTC).isoformat()
now = int(time.time()*1000); slot = (now-g)//30000
print("agora: slot", slot, "época", slot//32)
for E in (1130, 1220, 1400):        # 1130 = prazo, 1220 = decisão, 1400 = já armado
    print(E, utc(E), "slot", E*32)
PY
```

Rodado em **2026-08-25T01:50:35Z**: slot 32.198, época de parede **1006**.
E=1400 → `2026-08-29T10:51:19.962Z`, slot 44.800 — bate com o registrado em
`params.rs`.

Escolhido E\*, o instante é conhecido ao segundo. Prontidão é **pré-condição
para armar**, não meta a perseguir depois de taguear.

### 2.2 A fórmula, com o termo de rollout DERIVADO da medição

A fórmula do runbook do E=1400 é `E = arredonda_100(época_no_tag + 900)`, com
`900 = 270 rollout + 90 soak + 180 decisão + 360 contingência`. **As 270 estão
obsoletas.** Elas eram 12 caixas × ~6 h de replay = 3 dias. O replay hoje é
**~7 min por nó** — a medida está no aviso do próprio script de rollout que a
frota usou (`~/bloch-rollout/rollout-classico-e1400.sh`, "replay terminar (o
binário loga `replay N/M (x%)`, ~7 min)"), e `params.rs` registra o mesmo
número junto com o ganho de 22,2×. Com isso o rollout inteiro é da ordem de uma
hora, não de três dias.

A correção não é trocar 900 por outro número fixo. É **derivar o termo**:

```
R  = teto( N_nós × (t_replay + t_conferência) / 960 s )     ← MEDIDO, re-medir a cada arme
S  = 90     soak de 24 h com o predicado do §3 valendo
D  = 180    margem de decisão (adiar ou seguir) em E*−180, 48 h
C  = R + S + D                       contingência ≈ 1× o plano
E* = arredonda_para_cima_100( época_no_tag + 2·(R + S + D) )
```

`t_replay` **tem que ser re-medido por quem armar**, num host real da frota, e é
a única entrada que não é política. As outras três (S, D, C) são escolhas de
risco e podem ficar como estão.

**A conta com os números de hoje** (2026-08-25, época de parede 1006):

| termo | valor | de onde vem |
|---|---:|---|
| `t_replay` | 7 min | medido, `rollout-classico-e1400.sh` |
| `t_conferência` | 5 min | conferir `block_id`/`state_root` contra um nó de referência e ver a finalidade voltar (§3) |
| `N_nós` = 64, rollout **serializado** | R = 48 | 64 × 12 min = 12 h 48 = 48 épocas |
| `N_nós` = 64, um replay por caixa em paralelo | R ≈ 5 | ~18 caixas × 12 min ≈ 3 h 36. **A concorrência do replay não foi medida** — não use este número sem medir |
| soak | S = 90 | 24 h |
| decisão | D = 180 | 48 h |
| contingência | C = 318 | 1× o plano, com R = 48 |
| **total** `2·(R+S+D)` | **636** | ~7,1 dias |

`E* = arredonda_100(1006 + 636) = 1700` → **2026-09-01T18:51:19.962Z**, slot
54.400. Arredondar para múltiplo de 100 custa no máximo ~26 h e faz o valor
ficar legível em anúncio e em linha de log.

> **Re-rodado em 2026-08-31T16:38Z** (época de parede **1601**): o 1700 acima
> está VENCIDO — restam ~99 épocas, menos que o soak sozinho. Com a mesma
> fórmula e os mesmos R/S/D: `E* = arredonda_100(1601 + 636) = 2300` →
> **2026-09-08T10:51:19.962Z**, slot 73.600; ponto de decisão `E*−180 = 2120` →
> 2026-09-06T10:51:19Z. Vale enquanto o tag sair até a época **1664**
> (2026-09-01 ≈ 14:20 UTC); depois disso, re-rode a conta — é para isso que
> ela é uma fórmula e não um número.

Compare com a fórmula obsoleta: `arredonda_100(1006 + 900) = 2000`, isto é
**300 épocas — 3,3 dias — a mais**, todas elas pagando por um replay que não
existe mais. É por isso que o termo tem que ser derivado, e não herdado.

> **Nota sobre o próprio 1400, para não ser mal-lido.** `params.rs` documenta
> que 1400 **não** saiu da fórmula do runbook (que daria 1900, a partir da
> época 909 do tag) e que ele se sustenta pelo argumento acima: com R ≈ 4, o
> requisito é da ordem de 274 épocas e 1400 deixa 491 de margem. Note que 274
> é `R+S+D` **sem** dobrar a contingência; com a contingência dobrada daria
> `909 + 548 = 1457 → 1500`. Os dois cálculos são defensáveis e o valor armado
> está entre eles. **Não "conserte" 1400** — mudá-lo é outro dia de bandeira
> nos 64 nós, com rollout, anúncio e runbook próprios.

### 2.3 E\* tem que ser ESTRITAMENTE futuro, medido no `git tag`

Uma época já passada arma **em silêncio**: a comparação `epoch < E` simplesmente
nunca é verdadeira e a regra passa a valer para a história inteira. Não há erro,
não há aviso. É o modo de falha que deixou 1.600.000 BLCH escaparem de uma baixa
que nunca disparou, e aqui a consequência é pior: o binário aplica a regra nova
ao log histórico, e o replay para nos 64 nós ao mesmo tempo (§6).

Medido **no instante do `git tag`**, não no instante da reunião. Uma hora são
3,75 épocas.

### 2.4 E\* tem que cair DEPOIS do fim do rollout

Num relançamento coordenado os 64 param, recebem o mesmo armazenamento e o mesmo
binário e sobem juntos. Basta **um** nó que não voltou, ou que voltou com o
binário antigo, para a rede partir em `utc(E*)`: ele calcula outra partição,
outro sorteio e outra raiz. Numa frota que acabou de reiniciar em bloco, "um nó
que não voltou" não é hipótese; é o caso normal de reiniciar 64 processos.

### 2.5 Um único E\* para os dois portões

Valores diferentes dariam duas fronteiras de consenso para observar, duas
janelas em que um nó atrasado pode discordar, e dois tripwires que podem sair de
sincronia com este arquivo. O ganho de escalonar seria isolar qual regra causou
um fork — e isso já é isolável sem custo: as duas têm testes separados, o
detector de divergência de fronteira nomeia a época
(`transition.rs:974` / `:1006`), e o ensaio do §3.7 roda cada regra sozinha.

Pine isso num teste, no commit que arma:

```rust
#[test]
fn os_dois_portoes_de_replay_compartilham_um_dia_de_bandeira() {
    assert_eq!(
        crate::params::ANCESTRY_SEED_ACTIVATION_EPOCH,
        crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH,
    );
}
```

### 2.6 A interação com E=1400, que já está armado

`LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` dispara em **2026-08-29T10:51:19Z**,
tenha o relançamento acontecido ou não.

1. **E\* > 1400 é obrigatório** se o relançamento cair depois de 28/08. Com a
   época 1006 e a fórmula do §2.2, E\* = 1700 > 1400 — a ordem sai certa, mas
   sai por coincidência, e coincidência não é argumento. **Confira.**
2. **Não re-arme 1400 para frente** depois que existir um bloco de época ≥ 1400
   no log preservado. `consensus_roster_at` alimenta o sorteio de proponente, e
   sorteio de proponente é regra de validade: mudar a época depois do fato
   invalida blocos hoje válidos e o replay para — a mesma falha do §6, por outra
   porta.
3. Se o relançamento acontecer **antes** de 29/08, o log preservado não tem
   nenhum bloco ≥ 1400 e o 1400 volta a ser um dia de bandeira futuro comum.
4. **Ninguém examinou se os dois dias de bandeira interagem** — ordenação entre
   eles, e um roteiro se movendo sob uma baixa lastreada. Registrado como aberto
   em `RELANCA-G4-DECISOES.md` §16. **Não verificado.**

---

## 3. Pré-condições de armamento — o predicado nos 64 nós

Tudo abaixo, simultaneamente verdadeiro, **até E\*−180 (48 h antes)**.

**A lição de hoje vem primeiro, porque é a que custou:**

> ### 0. O binário armado tem que estar NA FROTA ANTES do arme, não depois.
>
> A ordem que funciona é: (i) compilar o binário com as constantes armadas;
> (ii) distribuir e subir nos 64; (iii) conferir os itens 1–6; (iv) só então o
> valor de E\* pode estar num tag público. Antes de E\* o binário armado é
> **idêntico ao inerte** — o ensaio em devnet do E=1400 produziu os mesmos 143
> blocos dos dois lados antes da fronteira — então não existe risco em rolar
> cedo, e não existe dois-estágios a de-arriscar. O que existe é o risco
> oposto: um E\* publicado numa frota que ainda não recebeu o binário é um
> relógio correndo contra um rollout que ainda não começou.

1. **Entrada idêntica.** `sha256sum` do log de blocos instalado igual nos 64,
   **antes** do start. O log é append-only (`store.rs`), então isto é digest de
   arquivo, não snapshot semântico.
2. **Binário idêntico, no PROCESSO.** Em cada host:
   ```sh
   sha256sum /proc/$(pgrep -f "bloch-pos-e1400 run --data-dir /home/ubuntu/g4/nNN " | head -1)/exe
   ```
   Este é o check do próprio `rollout-classico-e1400.sh`, e o comentário dele diz
   por quê: *"um binário trocado sob um processo velho é exatamente a falha que
   conferir o disco deixa passar."* Hash do arquivo em disco **não** serve.
3. **Replay terminou em todos, e nenhum estacionou.** A linha final
   `replayed N blocks: head slot …, state root …, justified eX, finalized eY`
   (`engine.rs:2352`) apareceu nos 64, e `getchaininfo.behind_by_slots` é pequeno
   e não cresce. Ver §6 para a detecção.
4. **A dobra bateu — este é o item que substitui "uma cabeça só".** Numa MESMA
   altura amostrada, `getchaininfo` devolve `state_root` **e** `block_id` byte a
   byte iguais nos 64. Duas cabeças iguais podem vir de dobras diferentes que
   ainda não divergiram; duas raízes iguais na mesma altura, com o mesmo log e o
   mesmo binário, não podem. Se duas raízes diferem aí, a dobra não é
   determinística e **nada pode ser armado**.
5. **Sem divergência de fronteira.** Nenhuma linha
   `BLOCH-CONSENSUS-DIVERGENCE boundary_partition_dropped_votes` no stderr do
   replay, exceto as explicáveis por slashing no meio de época — a única causa
   legítima conhecida. O detector é incondicional e não fatal (está no binário de
   release, sem `cfg`) e é limitado por backoff de potência de dois: as 8
   primeiras ocorrências saem, depois cada dobra. **Uma linha já é o evento.**
   ```sh
   grep -c "BLOCH-CONSENSUS-DIVERGENCE" /home/ubuntu/g4/nNN/node.log
   ```
6. **Soak de 90 épocas (24 h)** com 1–5 valendo e **nenhum nó reiniciado** na
   janela.
7. **Ensaiado, com controle**, antes do tag: um devnet de dois nós
   (`--slot-ms 500`, manifesto com `genesis_time_ms` no passado) onde o log é
   **produzido sob a regra ANTIGA** e depois replayado inteiro pelo binário
   armado, sem parar, cruzando E\* sem fork. A metade de controle é o mesmo
   devnet com as constantes inertes. **Ensaio sem controle prova só que o devnet
   roda** — é a regra de teste deste repositório e foi ela que validou o E=1400
   (armado e inerte produziram os mesmos 143 blocos; só o lado armado moveu a
   ocupação de slot depois da fronteira, 68,1% → 72,8%).

**Se o predicado falhar em E\*−180**, há duas opções honestas — e note que a
primeira do runbook do E=1400 ("seguir mesmo assim, se os prontos detêm > 2/3")
é **mais fraca aqui**: num relançamento, um nó que não voltou não é um
retardatário com pouco stake, é um nó que falhou ao subir do **mesmo insumo** que
os outros, o que é sinal de defeito no insumo.

- **Seguir** — só se a causa do nó faltante for conhecida, local e não
  relacionada à dobra (host morto, disco cheio) e os prontos detiverem > 2/3 do
  stake pós-leak. Se a causa foi raiz divergente (item 4): **nunca**.
- **Adiar** — §5.

Não existe terceira opção. Deixar E\* disparar numa frota metade armada parte a
mainnet em duas cadeias que finalizam histórias diferentes.

### Débitos que bloqueiam o tag

1. **RESOLVIDO — testes de costura para o portão do leak/piso.** Três testes em
   `finality.rs` colocam a época de ativação DENTRO do alcance da dobra
   (`rehearsal::gates_armed_at_guard`) e pinam a costura pelos dois lados:
   `arming_the_leak_gate_changes_nothing_below_it` (o binário armado dobra a
   história do incidente de 2026-08-24 idêntica ao inerte, quórum falso
   incluído — a propriedade de que o rollout antecipado depende),
   `the_leak_gate_floor_binds_at_its_epoch_and_not_before` e
   `leak_recovery_starts_exactly_at_the_gate`. Do lado da semente, além do
   `below_its_flag_day_the_seed_is_the_original_rule` que já existia:
   `arming_the_seed_gate_changes_nothing_below_it` (cadeia real, cabeça a
   cabeça, bit a bit) e `the_seed_gate_binds_exactly_at_its_epoch` (a cadeia
   CRUZA a fronteira viva; a época `E*` é semeada pelo fechamento de `E*−2`,
   que a retenção ainda segura).
2. **RESOLVIDO — a suíte sob portão inerte compila e passa, mas NÃO estava
   verde.** Rodar `cargo test -p bloch-pos-committee --lib` inteiro (o que a
   duração do teste de SMT desencoraja) revelou **5 testes do harness
   `prova.rs` vermelhos em HEAD, deterministicamente** — não por causa dos
   portões: o braço `PRE_FIX_FILTER` de `partition_step8` chamava
   `epoch_committees` puro, e quando o fix de 2026-08-24 REMOVEU o filtro
   pré-shuffle da produção (deixando-o só atrás do switch de ensaio
   `RESTORE_ZERO_STAKE_FILTER`), o braço "quebrado" virou silenciosamente o
   braço curado e toda asserção "a mutação morde" falhou. Corrigido: o braço
   ON re-arma o filtro pelo mesmo switch thread-local; os 9 testes de
   `prova.rs` passam, e o resto da suíte (290 testes, incluindo o SMT lento)
   passou na mesma rodada completa que expôs os 5.
3. **RESOLVIDO PELA METADE — `leaked` agora é legível por RPC.**
   `getchaininfo` devolve `leaked_total_sat`
   (`CommittedState::leaked_total_sat`, projeção somente-leitura do
   acumulador). É a métrica direta do §4.4: catraca antes de `E*`, dívida
   tendendo a zero depois. `BOUNDARY_VOTE_DROPS` continua sem RPC — a
   conferência segue sendo `grep BLOCH-CONSENSUS-DIVERGENCE` no log.

---

## 4. Verificação pós-arme — e como não confundir a frota com a sua janela

### 4.1 O RPC público é `g4rpc`, e ele fala por 18 de 64

`https://posternlabs.com/g4rpc` é um Cloudflare Worker
(`~/dev/posternlabs-deploy/functions/g4rpc.js`), não um nó. Ele:

- consulta uma lista de upstreams, `QUORUM_WAVE = 3` na primeira leva;
- exige `QUORUM_MIN = 2` **respostas idênticas** para métodos sensíveis a ramo
  (`getchaininfo`, `getblockcount`, `getblockbyslot`, `getblockbyid`,
  `getbalance`, `getutxos`, `listunspent`, `gettxout`);
- devolve `-32010` quando não há quórum — código **dele**, não do nó: significa
  "os nós responderam e discordaram", que não é outage e não é saldo;
- **exceto** para `getchaininfo`, que é "soft": a corroboração é feita sobre uma
  **projeção**, o checkpoint **finalizado**, e entre os que concordam nele ganha
  o de **maior altura**. Se ninguém concorda, ele devolve a resposta mais
  assentada **sem corroboração**.

Leitura do dia a dia:

```sh
~/bloch-rollout/chain-info.sh                          # via g4rpc (18 upstreams)
~/bloch-rollout/chain-info.sh http://45.76.89.225.nip.io:8080/   # um nó específico
```

(`chain-info.sh` existe porque parsear com `sed` é guloso e casa a última
ocorrência de `"epoch"` — a de dentro de `justified`. Em 23/08 isso fez reportar
"atraso 1, finalidade saudável" quando o atraso real era 23. Use o script, não
`sed`.)

### 4.2 "A frota concorda" ≠ "a minha janela concorda"

A cadeia está fragmentada. Dois números medidos, ambos do próprio `g4rpc.js`:

- com **um** upstream por caixa, o proxy via **6 de 62** nós e esses 6 deram
  **cinco pontos finalizados distintos**; só a dupla mais atrasada formava
  quórum, e o endpoint **congelou 222 slots atrás do relógio**;
- por isso foram acrescentados 2026-08-24 mais dois nós por caixa (portas 8880 e
  2052, socat), levando o grupo majoritário de 2 para 5 testemunhas.

E `RELANCA-G4-DECISOES.md` §7 registra a cadeia dividida em **12 ramos**. (O
número exato de visões distintas **hoje** não é verificável a partir do
repositório — se você precisa dele, meça com o §4.3. **Não verificado.**)

Consequência operacional, e é a armadilha:

> **`g4rpc` respondendo `getchaininfo` normalmente NÃO é evidência de que os 64
> concordam.** Ele é soft para esse método: pode estar devolvendo a resposta de
> um único nó, sem corroboração. E `-32010` **também não** é evidência de fork
> novo — pode ser só três upstreams lentos. Nenhum dos dois é sinal de consenso.

### 4.3 A conferência que vale: os 64, um a um, na MESMA altura

O único procedimento que distingue as duas coisas é ignorar o proxy e amostrar
cada nó diretamente, na mesma altura, nos slots `32·E*` e `32·E*+31`:

```sh
# Cada nó expõe RPC em 16400+índice, com --rpc-bind 0.0.0.0 (rollout-classico-e1400.sh).
for ip_idx in "95.179.166.188 0" "95.179.166.188 1" "136.244.82.226 10" \
              "45.76.82.134 15" "45.76.89.225 21" "136.244.95.190 24" \
              "45.32.154.137 26" "192.248.190.123 35" "45.76.138.60 39" \
              "45.76.138.60 41" "104.238.158.109 54" ; do
  set -- $ip_idx
  echo -n "v$2@$1  "
  curl -s -m 10 -X POST "http://$1:$((16400+$2))" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' \
    | python3 -c 'import json,sys; d=json.load(sys.stdin)["result"]; print(d["height"], d["block_id"][:16], d["state_root"][:16], "e%s/f%s"%(d["epoch"],d["finalized"]["epoch"]))'
done | sort -k2 | uniq -c -f1
```

O `uniq -c -f1` no fim é o que responde a pergunta: **quantas visões distintas
existem, e quantos nós em cada uma.** Uma linha = a frota concorda. Cinco linhas
= você está olhando cinco cadeias.

> **NÃO VERIFICADO:** o laço acima é construído a partir de partes verificadas
> (a lista ip/índice e a porta `16400+idx` saem de
> `~/bloch-rollout/rollout-classico-e1400.sh`; os campos `block_id`,
> `state_root`, `height`, `epoch`, `finalized` saem de
> `crates/bloch-pos-node/src/rpc.rs:1192-1241`) mas o laço em si não foi
> executado. A alcançabilidade da porta 16400+idx a partir de fora depende do
> `ufw` de cada caixa e **não foi conferida** — se der timeout, use os upstreams
> `:8080`/`:8880`/`:2052` listados em `g4rpc.js`, ou rode
> `~/bloch-rollout/varredura-portas.sh --classicos`, que é somente leitura.

A lista de 11 índices acima cobre os hosts clássicos. **Os outros ~48
validadores migraram para caixas Edgevana e o inventário deles não está neste
ramo** — `net.rs` ainda fala em Fly, que está desligado. Levante o inventário
real com `varredura-portas.sh` antes de dizer "os 64".

### 4.4 O que observar, a partir da primeira fronteira ≥ E\*

Meça o controle **antes**: nas três épocas imediatamente anteriores a E\*,
registre a tabela do §4.3 mais ocupação de slot. Sem o antes, o depois não prova
nada.

- **Tripwire de fork (o mais importante).** §4.3 nos slots `32·E*` e
  `32·E*+31`. Qualquer divergência de `state_root` na mesma altura: **pare** os
  nós minoritários. Um nó forkeado é ignorado pela maioria, mas um nó parado não
  fofoca um cronograma concorrente enquanto você diagnostica.
- **Semente ligou.** Evidência positiva: o `proposer_index` do bloco do slot
  `32·E*` difere do que a regra antiga sortearia. Confira sem parar nada rodando
  `the_two_rules_first_draw_a_different_proposer_at` com `--nocapture` e
  comparando (comando no §7 — **não executado aqui**).
- **Leak recuperando.** O atraso de finalidade deve **fechar**, e a ocupação de
  slot subir. **Não estimo o alvo**: quanto sobe depende de quanto stake volta a
  participar, e isso não é constante do código. O que se afirma é a direção e o
  alarme: um atraso que **aumenta** depois de E\* significa que a composição do
  comitê andou contra um nó que discorda — trate como sinal de fork, não jitter.
- **`BOUNDARY_VOTE_DROPS` em zero.** Sem RPC (débito 3), a conferência é
  `grep BLOCH-CONSENSUS-DIVERGENCE` no log de cada nó.
- **Nenhum `apply refused:`** depois de E\*. Ver §6.

---

## 5. Como desarmar, e o gatilho

**Desarmar é trocar o número de volta por `u64::MAX` e re-rolar a frota.** Só é
possível **antes** de existir um bloco de época ≥ E\* no log. Depois disso não
é desarme, é outro dia de bandeira (§7).

### 5.1 O gatilho que já existe, herdado do E=1400

Já há um prazo em vigor, e ele **não é deste runbook** — é do E=1400, e está
codificado no pré-check do script de rollout (`rollout-classico-e1400.sh`, que
aborta com `epoca >= 1130`):

> Se o relançamento não ocorrer até a **época 1130 — 2026-08-26T10:51:19Z**,
> `LEAKED_ROSTER_ACTIVATION_EPOCH` volta a `u64::MAX`.

O raciocínio é o soak: rolar depois da 1130 quebra as 90 épocas (24 h) de
estabilidade que o predicado exige antes do ponto de decisão da 1220
(2026-08-27T10:51:19Z), e a partir daí não há mais como afirmar que a frota está
pronta para a 1400. Hoje (época 1006) restam **124 épocas**, ~33 h.

### 5.2 Os gatilhos deste runbook

Desarme E\* — os dois portões juntos, §2.5 — em qualquer um destes:

1. **Item 4 do §3 falhou**: dois nós com o mesmo log e o mesmo binário dando
   `state_root` diferente na mesma altura. Este é incondicional: a dobra não é
   determinística e nada pode ser armado.
2. **O predicado não fecha em E\*−180** e a causa do nó faltante é a dobra (§3).
3. **O soak foi quebrado** por reinício de qualquer nó dentro das 90 épocas e
   não sobra janela para refazê-lo antes de E\*−180.
4. **O prazo do §5.1 passou** sem relançamento — desarme os dois e o 1400 junto,
   na mesma leva.

### 5.3 O procedimento

```
E' = arredonda_para_cima_100( época_agora + 2·(R + S + D) )    # §2.2, com R re-medido
```

1. Um commit único que leva: as duas constantes de volta a `u64::MAX`, o
   tripwire de volta à forma inerte
   (`the_replay_compatibility_gates_are_inert_until_armed`,
   `transition.rs:6919`), e a atualização deste arquivo. Os três juntos (§0).
2. Re-roll de **todos** os nós já armados — é outra rodada inteira de replay, e é
   por isso que a contingência do §2.2 é 1× o plano.
3. **Anuncie o desarme com a mesma visibilidade do arme.** Um E\* publicado e
   silenciosamente desarmado deixa quem estiver fora da frota esperando uma
   fronteira que não vem.

> **Desarmar não é grátis nem neutro.** Cada re-roll é um replay em 64 nós e uma
> nova janela em que a frota está heterogênea. A margem do §2.2 existe para que
> só um incidente real force isto.

---

## 6. O modo de falha que já aconteceu: o nó estacionado, em silêncio

**Mudar regra de dobra invalida o log de blocos.** O boot é replay: `store.rs`
guarda um log append-only e o boot re-ingere tudo (`engine.rs:2331`, dentro do
laço que imprime `replaying N blocks from the log`). Cada bloco passa pelo
`apply_block` real, que revalida a raiz contra o cabeçalho
(`TransitionError::StateRootMismatch`, `transition.rs:3423`).

E o `ingest` **rejeita-e-continua**: quando `apply_block` devolve erro, o caminho
imprime `apply refused: {e}` e retorna `false` (`engine.rs:1432`). Sem panic, sem
alarme, sem sair do processo. E o laço de replay em `engine.rs:2331` chama
`engine.ingest(env)` **descartando o retorno**.

> **O nó para de avançar numa altura velha, e não consegue seguir a rede viva
> tampouco.** Ele responde `getchaininfo` normalmente. Quem monitora só o RPC
> não distingue "estacionado" de "rede parada". A linha `apply refused:` vai
> para **stderr**, nunca para o RPC.

### Como detectar em minutos, não em horas

Três checks, do mais barato ao mais caro. O primeiro resolve quase sempre.

**1. A linha. Um `grep`, e é conclusivo.**

```sh
grep -c "apply refused" /home/ubuntu/g4/nNN/node.log
```

Qualquer valor > 0 depois do boot é o sintoma. `apply refused` só aparece nesse
caminho.

**2. O replay terminou ou truncou?** O contador de progresso sai a cada 10 s
(`REPLAY_PROGRESS_INTERVAL`, `engine.rs:2116`), no formato
`replay done/total (x%) — head slot S, R blocks/s, ~N min left`
(`engine.rs:2342`), e o fim é uma linha única
(`replayed N blocks: head slot …, state root …, justified eX, finalized eY`,
`engine.rs:2352`).

```sh
tail -5 /home/ubuntu/g4/nNN/node.log | grep -E "^replay(ed)? "
```

Contador que para no meio e nunca vira a linha `replayed` = truncou. Como sai a
cada 10 s, **20 segundos de log já respondem**.

**3. O relógio, se você só tem RPC.** `behind_by_slots` (`rpc.rs:1241`) é
`wall_slot − slot`. Amostre duas vezes com 60 s de intervalo:

```sh
for i in 1 2; do
  curl -s -m 10 -X POST "http://<IP>:$((16400+IDX))" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' \
    | python3 -c 'import json,sys; d=json.load(sys.stdin)["result"]; print(d["height"], d["behind_by_slots"])'
  [ $i = 1 ] && sleep 60
done
```

`behind_by_slots` crescendo **+2 por minuto** (um slot a cada 30 s) com `height`
parado = estacionado. `behind_by_slots` alto mas estável, com `height` andando =
o nó está atrás mas vivo. **São dois estados diferentes e este é o teste que os
separa.**

> **NÃO VERIFICADO:** os dois laços `curl` acima não foram executados (ver o
> aviso de alcançabilidade do §4.3). O `grep` e o `tail` são leitura de arquivo
> local, com o formato lido do código citado.

### Por que isto vale para os dois portões

- **Semente**: a ruptura é na **época 1**. Sem portão, o nó novo para quase no
  começo da cadeia — o que, perversamente, é a versão *fácil* de detectar,
  porque a altura fica absurdamente baixa.
- **Leak/piso**: a ruptura é na **primeira fronteira que acumula mordida**, que
  pode estar em qualquer lugar do log. Esta é a versão difícil: o nó para numa
  altura plausível.

Por isso o check 1 (`grep -c "apply refused"`) é o que se roda primeiro, sempre:
ele não depende de você saber onde a ruptura deveria estar.

---

## 7. O que o tripwire NÃO pega

O tripwire vigente é `leaked_roster_armed_epoch_matches_the_runbook`
(`transition.rs:6838`):

```rust
assert_eq!(
    crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH,
    1400,
    "the armed epoch must match docs/LEAKED-ROSTER-FLAG-DAY.md; changing it again is a new flag day"
);
```

O irmão inerte, para as duas constantes deste runbook, é
`the_replay_compatibility_gates_are_inert_until_armed` (`transition.rs:6919`),
que percorre as duas e exige `u64::MAX`.

**Leia o que ele compara.** O `1400` da direita é um **literal em
`transition.rs`** — uma cópia da constante que está em `params.rs`. É um teste de
igualdade entre duas cópias do mesmo número, no mesmo repositório, escritas pela
mesma pessoa no mesmo dia.

**O que ele pega, e é real:** alteração **silenciosa** da constante. Alguém edita
`params.rs` e não `transition.rs` → suíte vermelha. Isso é útil e o teste deve
continuar.

**O que ele NÃO pega — e o próximo não pode confiar demais:**

1. **A época estar errada desde o início.** Se as duas cópias forem escritas
   erradas no mesmo commit, o tripwire fica verde. Foi **exatamente** o que
   aconteceu com o 1400: `params.rs` documenta que ele não veio da fórmula do
   runbook, que a fórmula daria 1900 e o exemplo trabalhado do runbook daria
   1600, e que **o runbook nunca menciona 1400 em lugar nenhum**. A suíte esteve
   verde o tempo todo. A doc do próprio `params.rs` diz isso com todas as
   letras: *"It cannot catch the epoch having been wrong from the start."*
2. **A época já estar no passado.** Nada no teste conhece o relógio. `epoch < E`
   com E passado nunca é verdadeiro, a regra vale para a história inteira, e o
   arme falha em silêncio (§2.3, §6). A mensagem de erro do tripwire inerte
   **pede** que quem armar confira isso — mas é um pedido em prosa para um
   humano, não uma asserção.
3. **O valor bater com este arquivo.** Nada lê o `.md`. O vínculo entre a
   constante e o runbook é a string na mensagem de falha. Se o `.md` disser 1700
   e as duas cópias disserem 1600, tudo passa.
4. **O portão ler a época certa.** O tripwire compara números, não caminhos de
   código. Quem prova que o portão lê a época **do bloco** e não um relógio local
   é outro teste — `the_block_cap_gate_reads_the_epoch_from_the_blocks_own_header`
   (`transition.rs:4939`) — e o argumento estrutural de que a crate não tem fonte
   de tempo (`grep -rn "now_ms\|wall_slot" crates/bloch-pos-committee/src/`
   **está vazio**, conferido em `relanca/e1400`; `SystemTime::now` aparece uma
   única vez, num comentário em `schedule.rs:18` que cita o fork de
   `expected_bits` de 2026-08-08 como o motivo da regra).

**Portanto, três coisas que TÊM que ser feitas por gente, porque nenhum teste as
faz:**

- rodar a aritmética do §2.1 no instante do `git tag` e conferir que
  `E* > época_de_parede`;
- conferir com os olhos que o número no tripwire, o número em `params.rs` e o
  número **neste arquivo** são o mesmo;
- preencher a tabela do §9 **antes** de taguear.

E, no commit que arma, o teste de inércia é substituído por **um tripwire por
constante**, cada um citando este arquivo pelo caminho:

```rust
#[test]
fn ancestry_seed_armed_epoch_matches_the_runbook() {
    assert_eq!(
        crate::params::ANCESTRY_SEED_ACTIVATION_EPOCH,
        1700, // ← E*, o valor da tabela do §9
        "a época armada tem que bater com docs/RELANCA-G4-DIAS-DE-BANDEIRA.md; \
         mudá-la de novo é um novo dia de bandeira"
    );
}

#[test]
fn leak_recovery_armed_epoch_matches_the_runbook() {
    assert_eq!(
        crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH,
        1700,
        "a época armada tem que bater com docs/RELANCA-G4-DIAS-DE-BANDEIRA.md; \
         mudá-la de novo é um novo dia de bandeira"
    );
}
```

Comandos a rodar no mesmo commit — **não executados aqui**, ver §8:

```sh
cargo test -p bloch-pos-committee armed_epoch_matches_the_runbook
cargo test -p bloch-pos-committee os_dois_portoes_de_replay_compartilham_um_dia_de_bandeira
cargo test -p bloch-pos-committee below_its_flag_day
cargo test -p bloch-pos-committee the_two_rules_first_draw_a_different_proposer_at -- --nocapture
cargo test --workspace --no-run                       # o portão que teria pego as entregas falsas de hoje
```

E a regra de medição deste repositório, que vale para qualquer número de
desempenho que entre na fórmula do §2.2: as suítes `replay_hotpath_perf` (6 de 6)
e `replay_bench` (3 de 3) são **inteiramente `#[ignore]`d**. Rodadas do jeito
normal elas reportam `ok` **sem ter executado nada**.

```sh
cargo test -p bloch-pos-node --release -- --include-ignored replay_bench
```

**Sem `--include-ignored`, não mediu.** Isso inclui o 22,2× e o "~7 min" — o
22,2× aparece só como afirmação em `RELANCA-G4-DECISOES.md` §8/§16, e o §17 do
mesmo arquivo avisa que ele precisa ser re-verificado dessa forma. O "~7 min"
vem do aviso operacional do `rollout-classico-e1400.sh`, que é um número de
campo, não de bancada. **Re-meça antes de usar na fórmula.**

---

## 8. Não há rollback depois do primeiro bloco

Assim que existir um bloco pós-E\*, a dobra que o produziu é história de
consenso. Re-subir a constante é, ela mesma, uma mudança de consenso — outro dia
de bandeira, com rollout próprio — e órfã todo bloco pós-E\*. Problemas depois de
E\* se consertam para a frente.

É a mesma assimetria de todo dia de bandeira, dita aqui porque a época de relógio
de parede faz E\* parecer um valor de configuração em vez do precipício que é.

---

## 9. Preencher no tag, ANTES de taguear

| campo | valor |
|---|---|
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | *(E\*)* |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | *(o MESMO E\*, §2.5)* |
| `utc(E*)` | *(gênese 2026-08-13T21:31:19.962Z + E\* × 960 s)* |
| `slot(E*)` = E\* × 32 | |
| época de parede no instante do `git tag` | |
| `E* − época_no_tag` (≥ `2·(R+S+D)`, §2.2) | |
| `t_replay` **re-medido**, host e data | |
| R, S, D, C usados na fórmula | |
| tag do release | |
| sha256 do binário | |
| sha256 do log de blocos instalado nos 64 | |
| altura / `state_root` da cabeça após o replay (iguais nos 64) | |
| nº de visões distintas na varredura do §4.3 (tem que ser 1) | |
| commit que carrega constante + tripwire + este arquivo | |

Um tag sem esta tabela preenchida não é um release armado; é um acidente
esperando `utc(E*)`.

---

## 10. O que este runbook NÃO estabelece

- **Não compilei nem rodei nada.** Todo `cargo` aqui é instrução, não resultado.
  Os débitos do §3 saem de leitura de código.
- **O inventário da frota não está neste ramo.** `net.rs` ainda fala em Fly, que
  foi desligado. A lista do §4.3 cobre os hosts clássicos, tirada de
  `~/bloch-rollout/rollout-classico-e1400.sh`; os ~48 validadores restantes vivem
  em caixas Edgevana cujo mapeamento não está aqui. Levante com
  `~/bloch-rollout/varredura-portas.sh --classicos` (somente leitura).
  *Nota lateral:* os comentários `# FALTA CHAVE` naquele script estão
  **desatualizados** — as chaves existem em `~/.ssh` e o mapa ip→chave,
  conferido 2026-08-22, está no bloco `BOXES` de `varredura-portas.sh`.
- **A concorrência do replay não foi medida.** A linha "R ≈ 5" do §2.2 supõe um
  replay por caixa em paralelo. Medir uma vez, num host real, troca uma
  suposição por um fato — e é a entrada mais sensível da fórmula.
- **O número de visões distintas na frota hoje não foi medido.** O §4.2 traz dois
  números verificados (5 pontos finalizados distintos entre 6 upstreams; 12 ramos
  registrados em `RELANCA-G4-DECISOES.md` §7) e nenhum deles é a contagem de
  hoje.
- **A interação entre E\* e o dia de bandeira 1400 foi examinada uma vez**
  (§2.6, item 4; análise no commit dos testes de costura). Resumo: a
  recuperação pós-`E*` devolve peso ao roteiro que o 1400 já lê, então stake
  AUSENTE que recupera (todos recuperam quando a cadeia finaliza) volta a
  ganhar sorteios de proponente e a ocupação de slot pode CAIR um degrau — a
  dente-de-serra documentada em `params.rs` no
  `INACTIVITY_LEAK_RECOVERY_QUOTIENT`. A amplitude é limitada pela fração
  ausente; com 60/64 vivos hoje é pequena, mas é por isso que o predicado do
  §3 precisa registrar, durante o soak, o stake ATESTANTE contra o denominador
  que o piso imporá: a finalidade continua em `E*` sse
  `3·atestante ≥ 2·max(total_ajustado_por_leak, total_sem_leak/2)` — no limite
  (ausentes totalmente vazados), atestante ≥ 1/3 do total sem leak. Abaixo
  disso o piso congela a finalidade em `E*` até esse stake voltar ou sair do
  registro — comportamento desejado por projeto, mas que ninguém quer
  descobrir na fronteira. Sem exame de segunda pessoa — confira.
- ~~Não há teste de "abaixo da bandeira" para o portão do leak/piso~~ —
  resolvido, §3 débito 1.

---

## 11. Calendário consolidado dos dias de bandeira (todos os nove portões)

Escrito na integração de consenso de 2026-08-31, que juntou seis worktrees e
introduziu **quatro** constantes de ativação novas. As seções 0–10 acima
descrevem dois portões (`ANCESTRY_SEED` e `LEAK_RECOVERY`) e continuam
válidas no que descrevem; esta seção é o mapa de todos eles, porque a partir
de agora a pergunta "o que está armado neste binário" tem nove respostas, não
duas.

**Nada aqui está armado.** As quatro constantes novas nascem `u64::MAX`. Esta
seção não arma nada: ela diz o que *seria* preciso para armar cada uma, e em
que ordem.

### 11.0 A coisa que muda HOJE, sem portão nenhum — leia antes de trocar binário

Uma única mudança de aceitação entra **na troca do binário**, sem dia de
bandeira: blocos que carreguem as codificações de staking não autenticadas —
tags `0x02` (`Deposit`), `0x03` (`Exit`), `0x04` (`Delegate`) — passam a ser
rejeitados por consenso, em toda época, em todo nó.

Antes, a única recusa era a do mempool, que **o próprio proponente nunca
consulta**: um membro do comitê podia incluir um `Deposit` no seu próprio
bloco e cunhar stake vinculado do nada, ou um `Exit` por índice para cada
validador ativo e esvaziar o roteiro irreversivelmente. É um APERTO: o
binário velho aplica esses blocos, o novo os rejeita inteiros
(`TransitionError::Transaction`). Os dois divergem exatamente nos blocos que
só um insider consegue produzir — que é o ponto.

Está isolada no commit `337bdd9f`, sozinha, para poder ser revertida sem
tocar nos sucessores.

> **PRÉ-CONDIÇÃO DE CUTOVER — obrigatória, e ela EXPIRA.**
>
> Antes de reconstruir a frota, rode o scanner contra um `blocks.log`
> **atual** da mainnet:
>
> ```sh
> mkdir -p /tmp/mainnet-scan
> cp /tmp/mainnet-blocks.log /tmp/mainnet-scan/blocks.log   # cópia SOMENTE LEITURA de um host da frota
> SCAN_BLOCKS_LOG=/tmp/mainnet-scan cargo test -p bloch-pos-node --bins \
>     scan_block_log_for_staking_tags -- --ignored --nocapture
> ```
>
> Ele lê o log pela máquina do próprio nó (`Store::read_all` +
> `PosTransaction::from_canonical_bytes` — o mesmo decode que o replay usa,
> nunca um grep de bytes, senão um `0x02` dentro de uma tabela de testemunhas
> seria contado como mensagem de staking) e **falha** se qualquer bloco
> carregar `0x02`/`0x03`/`0x04`.
>
> Se ele falhar, **não role a frota**: a rejeição em toda época faria todo nó
> atualizado parar no primeiro desses blocos, e a mudança teria de ser
> reemitida atrás de um portão armado ACIMA do último deles.
>
> O resultado zero conhecido é de **2026-08-31** e **não vale para o dia do
> rollout**. Um log só ganha blocos; um único bloco novo com essas tags
> inverte a resposta. Rode de novo, no dia. O custo é um teste; o custo de
> não rodar é a frota inteira parada num bloco do passado.

### 11.1 Os nove portões

Cadência: um slot = 30 s, 32 slots = uma época ⇒ **1 época ≈ 16 min ≈ 90
épocas/dia**. Qualquer conversão época→data abaixo usa essa taxa a partir da
época **1.599, medida em 2026-08-31** (slot 51.184). São aritmética, não
promessa: a cadeia não fecha épocas em ritmo constante quando a finalidade
tropeça.

| # | Constante | Valor | O que arma | Carregador na rede? |
|---|---|---|---|---|
| 1 | `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | **800** (armado) | `TransferV2`, tag `0x06` | sim |
| 2 | `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | **800** (armado) | teto de 512 KiB de payload | n/a |
| 3 | `LEAKED_ROSTER_ACTIVATION_EPOCH` | **1400** (armado, rolado) | roteiro pelo stake pós-leak | n/a |
| 4 | `ANCESTRY_SEED_ACTIVATION_EPOCH` | `u64::MAX` | look-ahead F6 da semente (§1) | n/a |
| 5 | `LEAK_RECOVERY_ACTIVATION_EPOCH` | `u64::MAX` | recuperação do leak + piso de quórum (§1) | n/a |
| 6 | `VESTING_LOCK_ACTIVATION_EPOCH` | `u64::MAX` | semeadura única das travas de vesting | n/a |
| 7 | `FUNDED_STAKING_ACTIVATION_EPOCH` | `u64::MAX` | `DepositV2` (tag `0x07`) + delegação financiada | **parcial** |
| 8 | `SIGNED_EXIT_ACTIVATION_EPOCH` | `u64::MAX` | saída voluntária assinada (`ExitV2`, tag `0x09` → `apply_exit`) | sim |
| 9 | `WITHDRAWAL_ACTIVATION_EPOCH` | `u64::MAX` | `Withdraw` (tag `0x08`), trava de 4.096 épocas, ordem evidência-antes-de-saque | sim |

A coluna "carregador na rede" é a que quase ninguém pergunta, e é a que
decide se armar um portão faz alguma coisa:

- **#8 ganhou carregador NESTE merge.** Era o portão sem estrada: `apply_exit`
  não tinha ponto de chamada de produção, então armar `SIGNED_EXIT` não mudava
  nada. `PosTransaction::ExitV2` (tag `0x09`) fecha isso — o braço de
  `apply_transaction` lê o portão pela época COMMITADA e entrega o
  `staking::ExitTx` a `apply_exit`. O portão continua **inerte**
  (`u64::MAX`); o que mudou é que armá-lo deixou de ser um no-op, e por isso
  a segunda pré-condição da §11.3 (o limite de vazão de saída) passou de
  observação a bloqueio real.
- **#7 é parcial.** `DepositV2` (tag `0x07`) tem codec, portão e verificação
  completos — armar torna depósitos financiados reais. Mas `apply_delegation`
  está atrás da MESMA constante e **também não tem ponto de chamada de
  produção**: delegação financiada continua inalcançável até ganhar o seu
  próprio formato de wire. Uma constante, dois caminhos, só um alcançável.
- **#6 não semeia nada na cadeia atual.** A semeadura só reescreve outpoints
  de alocação **ainda não gastos**, e os cinco foram medidos **GASTOS** em
  2026-08-31 (`gettxout` responde `unspent: false` para todos; o saldo do
  script do fundador estava em ~37,94 bi contra os ~56,05 bi de abertura).
  Armar #6 hoje trava zero satoshi. Os usos honestos que restam são (a) uma
  génese futura cujo manifesto carregue `unlock_epoch` reais e (b) um
  re-comprometimento negociado em que os baldes voltem primeiro para
  outpoints novos, fixados aqui antes de armar. Nenhum dos dois é mudança
  unilateral de código.

### 11.1.1 O que cada portão IMPRIME antes de abrir — e por que não é uniforme

Se você está diagnosticando uma divergência num dia de bandeira, **procure
pelo PORTÃO, não pela string**. As recusas pré-ativação não usam um nome só,
e isso é um fato do código hoje, não um plano:

| caminho | constante | veredito pré-ativação |
|---|---|---|
| `DepositV2` (braço de wire, tag `0x07`) | `FUNDED_STAKING` | `TxReject::Transfer(FormatNotActive)` |
| `apply_delegation` | `FUNDED_STAKING` | `TxReject::StakingNotActive` |
| `ExitV2` (braço de wire, tag `0x09`) | `SIGNED_EXIT` | `TxReject::StakingNotActive` |
| `apply_exit` | `SIGNED_EXIT` | `TxReject::StakingNotActive` |
| `Withdraw` (braço de wire, tag `0x08`) | `WITHDRAWAL` | `TxReject::StakingRule` |

Repare na primeira e na segunda linha: **é o MESMO portão, o mesmo
`deposit_funding_active`, imprimindo dois eventos diferentes conforme a
porta por onde a mensagem entrou.** O par do `SIGNED_EXIT` é o único
internamente consistente.

As **cinco** linhas são o código de hoje: o carregador do `ExitV2` entrou
neste commit, e esta linha deixou de ser promessa no mesmo commit em que
virou código. Esta tabela deve ficar um merge ATRÁS do código, nunca à
frente — uma doc que promete um caminho que ainda não existe é o mesmo
defeito de sempre, virado do avesso.

Isso é **diagnóstico, não consenso**: qualquer `Err` invalida o bloco no
mesmo índice (`TransitionError::Transaction(i)`), então nenhum veredito aqui
muda o que a rede aceita. Está registrado em vez de corrigido de propósito —
uniformizar quatro vereditos enquanto duas esteiras reencenam merges nestes
mesmos arquivos é como nasce colisão (a de tag `0x07` nasceu assim). Quando a
convergência fechar e a árvore estiver parada, o par `ExitV2`/`apply_exit` é
o modelo a seguir.

**Para quem for mexer:** não "conserte" um veredito isolado. Cada um destes
está afirmado em teste de outra esteira; mudar um sozinho fica vermelho em
lugar que você não está olhando.

### 11.2 A ordem — e por que duas dessas setas são erro de compilação

```
        #7 FUNDED_STAKING ─────┐
                               ├──> #9 WITHDRAWAL
        #8 SIGNED_EXIT ────────┘
```

As duas arestas são verificadas **em tempo de compilação** (`params.rs`, dois
`const _: () = assert!`), porque o modo de falha é uma edição de constante
daqui a semanas — e uma linha de runbook é exatamente o que já foi pulado uma
vez:

- **`WITHDRAWAL >= FUNDED_STAKING`.** Pagar vínculo que nunca foi financiado
  pelo conjunto eUTXO é **cunhagem**. Enquanto depósitos não gastarem moedas,
  depósito → saída → saque é uma impressora.
- **`WITHDRAWAL >= SIGNED_EXIT`.** O saque consome um registro **SAÍDO**, e
  depois do fechamento do §11.0 a saída assinada é a única coisa capaz de
  fazer um registro sair. Armar o pagamento primeiro entrega uma porta sem
  estrada até ela.

Verificado quebrando, não lendo: pondo `WITHDRAWAL_ACTIVATION_EPOCH = 5000`
com as outras em `u64::MAX`, o build falha com `E0080` nas duas asserções,
com essas mensagens. Não é um teste que alguém precise lembrar de rodar; é o
`cargo build`.

Os portões #4 e #5 são independentes destes e um do outro; a ordem deles está
nas §§1–5. O #6 é independente de todos.

### 11.3 Pré-condições de armamento, por portão

Valem para todos, sem exceção, as regras da §0 e da §3: **versionar antes de
armar**; época **estritamente no futuro** no momento do tag (uma época já
passada arma em silêncio — foi assim que 1.600.000 BLCH escaparam de um
write-off que nunca disparou); frota reconstruída ANTES de baixar a
constante. Além disso:

- **#6 `VESTING_LOCK`** — go/no-go no dia: confirmar por `gettxout` que os
  outpoints de alocação estão **não gastos**. Medição de 2026-08-31: todos
  gastos ⇒ armar não faz nada. Não arme "para deixar pronto": a semeadura é
  única e roda na fronteira que ABRE a época (igualdade, não `>=`), então uma
  época escolhida errado gasta o mecanismo sem efeito.
- **#7 `FUNDED_STAKING`** — (a) frota reconstruída; (b) carteira ou
  ferramenta capaz de montar um `DepositV2` conservante: a igualdade
  `soma(entradas) == amount + troco + taxa` é **estrita**, e uma carteira que
  erre por um satoshi produz transação recusada, não transação com troco
  errado; (c) aceitar, e comunicar, que delegação financiada continua
  inalcançável até ter carregador.
- **#8 `SIGNED_EXIT`** — duas pré-condições, e a segunda é uma DECISÃO, não
  uma verificação:
  1. o carregador de wire (tag `0x09`) precisa existir e estar na frota.
     **Existe** desde este merge (`PosTransaction::ExitV2`); o que falta é a
     metade operacional — a frota reconstruída com um binário que o linke.
     Um nó sem o braço recusa o bloco inteiro no decode (`UnknownTag(0x09)`),
     então armar antes do rollout parte a rede em vez de habilitar a saída.
  2. **decidir se pode haver saída sem limite de vazão.** Não existe
     throttle de saída em lugar nenhum: entrada tem
     `MAX_ACTIVATIONS_PER_EPOCH = 4`, saída não tem nada (procurado por
     `max_exits|exit_churn|exits_per_epoch|MAX_EXIT` no crate inteiro:
     zero ocorrências; os docs de `ws.rs` já registram o fato — "o
     conjunto auto-vinculado inteiro pode sair numa época"). A assimetria,
     em números:

     | | ritmo |
     |---|---|
     | **esvaziar** | o conjunto inteiro pede saída em **1 época**; deveres param `EXIT_DELAY_EPOCHS` = 32 épocas depois (~8,5 h) |
     | **repor** | `MAX_ACTIVATIONS_PER_EPOCH` = 4 ⇒ ≥ **16 épocas** de admissões para 64 validadores, mais `ACTIVATION_DELAY_EPOCHS` = 8 |

     Esvazia em uma época, repõe em dezesseis — e todo vínculo drenado
     fica preso por `WITHDRAWAL_DELAY_EPOCHS` = 2.048 de qualquer forma.
     Isso é parâmetro de **vivacidade**, então é decisão do fundador:
     ou se arma aceitando a assimetria, ou o limite de vazão de saída
     entra ANTES do armamento (e aí é consenso, com dia de bandeira
     próprio). O que não pode é armar sem que alguém tenha decidido —
     é por isso que está escrito aqui e na doc da própria constante.
- **#9 `WITHDRAWAL`** — o mais caro, e o único cuja pré-condição **não é de
  código**:
  1. `FUNDED_STAKING` e `SIGNED_EXIT` armados antes (o compilador garante);
  2. **auditoria da oferta da génese.** O saque paga o vínculo em moedas sem
     tocar `issued_sat`, tratando aquele valor como já emitido. Isso é
     verdade para vínculo financiado e para juros compostos, e **não foi
     verificado** para o `staked_sat` da coorte de lançamento: se aquele
     stake não estava dentro de `GENESIS_ISSUED_SAT`, o primeiro saque da
     coorte cria moeda que o teto de oferta não contava. É um fato da
     cerimônia de génese, não uma linha de código, e precisa ser auditado
     antes do primeiro saque **da coorte** — não antes do primeiro saque
     qualquer.

### 11.4 Como saber o que um binário sabe

Um binário publicado que precede um armamento **segue a regra velha naquela
época e bifurca**, em silêncio — foi o defeito do `genesis4-node-20260814`.
Quem responde isso é `bloch-pos selfcheck` (e `selfcheck --json` para páginas
de release e varredura de frota), que imprime os portões que o binário linka
e um digest do conjunto. Dois binários são compatíveis na época E sse as
listas concordam em todo portão com época ≤ E.

Essa ferramenta vem do fluxo irmão de integridade de release (worktree
`a26bcc84e23ca2e0e`), e o teste `gate_table_mirrors_params_exactly` casa a
tabela dela com as constantes de `params.rs`, falhando por **omissão** — um
portão novo que a declaração de compatibilidade não mencione. Quando as duas
integrações convergirem, a tabela precisa ganhar as quatro constantes desta
seção (todas inertes); o digest muda **por projeto** (um conjunto de portões
diferente É uma declaração de compatibilidade diferente) e
`knows_gates_through_epoch` continua 1400, porque nenhuma das quatro está
armada.

### 11.5 O que esta seção NÃO estabelece

- **Nenhuma data aqui é decisão.** São conversões época→data a 90 épocas/dia
  a partir de uma medição de 2026-08-31. Quem arma escolhe E\* pela §2, não
  por esta tabela.
- **Não medi a cadeia para escrever isto.** Os números de cadeia citados
  (época 1.599, slot 51.184, outpoints gastos, saldo do fundador) são
  medições de 2026-08-31 herdadas das peças integradas, não leituras minhas.
  Reconfira antes de agir sobre qualquer uma — a §11.0 existe justamente
  porque medição de cadeia envelhece.
- **A interação entre #6 e o resto não foi examinada.** A semeadura reescreve
  outpoints, o que move a raiz de estado na fronteira; que isso não interaja
  mal com um armamento simultâneo de #4/#5 é suposição, não resultado. Não
  arme dois portões na mesma fronteira sem examinar isso primeiro.
- **A ordem entre #7/#8/#9 é garantida; o espaçamento não.** As asserções
  proíbem inverter, não escolher épocas próximas demais para a frota rolar
  entre elas. Esse julgamento é da §2.
