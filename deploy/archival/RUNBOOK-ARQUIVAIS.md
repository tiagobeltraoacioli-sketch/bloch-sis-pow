# Runbook — roll dos dois arquivais da Genesis-4

Os dois arquivais (`139.180.166.5`, `139.180.173.231`) são as duas primeiras
entradas da lista de upstreams do RPC público. Eles **não são validadores**: a
`Description` da própria unit diz `no validator key`. Não propõem, não atestam,
não têm memória de voto.

O `rollout-release.sh` já manda rolá-los **manualmente, depois da frota**. Este
runbook é o "como", e a razão de ele ser um documento separado é que quase todas
as regras do rollout de validador **não valem aqui** — e duas regras novas
valem.

---

## 0. O que foi medido em 31/08/2026, antes de escrever qualquer script

**A exposição declarada era de consenso. Ela não é.**

| binário | commit | onde roda |
|---|---|---|
| `bloch-pos-quatro` | `0a3a436a2d18+dirty` | **os dois arquivais** |
| `bloch-pos-cinco`  | `46133196-varredura` | a frota (63 validadores) |
| `bloch-pos-seis`   | `bed1b9ce` (fix de catch-up) | o release que vem |

O diff `quatro → cinco` é de **quatro commits e quatro arquivos**, e todos os
quatro estão em `crates/bloch-pos-node`:

```
crates/bloch-pos-node/src/engine.rs              | 753 +++++-
crates/bloch-pos-node/src/engine/replay_bench.rs |   6 +
crates/bloch-pos-node/src/rpc.rs                 |  11 +
crates/bloch-pos-node/src/rpc/tests.rs           |   8 +-
```

`crates/bloch-pos-committee` e `crates/bloch-crypto` — onde moram as regras de
consenso — são **byte-a-byte idênticos**. As cinco constantes de ativação são as
mesmas nos três binários, `LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` inclusive, e o
digesto do conjunto é o mesmo:

```
$ bash digesto-portoes.sh 0a3a436a 46133196 bed1b9ce
  gates_digest = a03bccc3e460ae15e7b233637334ab09610a684b66f77540ac88b1b7cc34876f
IGUAIS — mesmo conjunto de portoes, mesma declaracao de compatibilidade.
```

E a cadeia **já passou** por esse dia de bandeira: a leitura de 31/08 mostra os
dois arquivais e a frota na **época 1635**, com `finalized` e `justified`
idênticos. O E=1400 não é mais um risco datado — ele já aconteceu, e os
arquivais atravessaram porque sempre souberam a regra.

O que o diff realmente traz é **higiene de mempool**: `sweep_mempool`,
`reject_transaction`, `is_rejected`, `note_bar` e dois campos novos de RPC
(`barred`, `barred_hits`). A varredura é chamada de `apply_canonical`, mas mexe
em `self.mempool`/`self.pool` — não em `state_root`, não em validação de bloco.
Num validador ela antecipa o drop loop; **num observador ela é a única coisa que
esvazia a pool** (190 transações presas num deles em 30/08). Útil para um
arquival. Não é consenso.

### Então qual é o risco real

Três, e nenhum é o que estava no enunciado:

1. **O catch-up.** É o defeito que o `seis` corrige: um nó que religa muito
   atrás da cabeça trava em definitivo. Os arquivais rodam o binário **com** o
   defeito. Logo o passo perigoso é o próprio `systemctl restart` — a operação
   que este runbook executa duas vezes. A janela de espera e o `REVERTER`
   existem exatamente para isso.
2. **O quorum público.** Os dois arquivais são os dois primeiros upstreams e
   `QUORUM_MIN` é 2, então **eles sozinhos constituíam um quorum**. Rolar os
   dois juntos era o caminho para publicar um ramo errado com selo de
   corroborado. Corrigido em `functions/g4rpc.js` (seção 4 abaixo) e mitigado
   pela sequência (seção 2).
3. **O próximo dia de bandeira, esse sim.** O ramo de consenso tem **9**
   portões, não 5 — `VESTING_LOCK`, `FUNDED_STAKING`, `SIGNED_EXIT`,
   `WITHDRAWAL`, hoje todos `u64::MAX`. Quando qualquer um deles for armado, o
   `gates_digest` muda e um arquival atrasado **fica consenso-morto naquela
   época**. É aí que a exposição do enunciado passa a ser real — e é por isso
   que a checagem de portões (seção 5) importa mais do que este roll.

---

## 1. O que muda em relação ao rollout de validador

| regra do `rollout-release.sh` | aqui |
|---|---|
| guarda de **duas épocas** entre PARAR e SUBIR | **não existe** — sem chave, nada pode assinar em duplicata |
| snapshot pré-roll **nunca restaurado por script** | **pode ser restaurado** — `meta.bin`/`ws_latest.bin` de um nó sem chave não carregam voto |
| lotes de 6, um nó por caixa | **um arquival por vez**, e só |
| prova = `block_id`/`state_root` num slot comum | **igual, e é a única coisa que conta** |
| `pkill` proibido, só `systemctl` por nome | **igual** |
| — | **novo:** sair do quorum público **antes** de parar o nó |
| — | **novo:** conferir o `gates_digest` do binário que entra |

---

## 2. A sequência, e por que ela detecta em vez de servir

O proxy exige **duas leituras concordando**. Se os dois arquivais forem rolados
juntos e um divergir, as leituras falham; se os dois divergirem **igual** —
mesmo binário, mesma tarde, mesmo defeito — eles concordam **no ramo errado** e
o proxy serve isso como corroborado. A sequência abaixo torna os dois casos
impossíveis:

```
para cada arquival, um de cada vez:

  1. PROVAR ANTES         raiz idêntica à frota. Não se rola um nó já bifurcado.
  2. SAIR DO QUORUM       systemctl stop bloch-rpc-8080
                          → o proxy falha o fetch, esfria este destino e passa a
                            ler do OUTRO arquival + das 7 caixas. Sem deploy,
                            sem mudar env. O nó fica INVISÍVEL para o público
                            durante todo o resto do procedimento.
  3. conferir o público   posternlabs.com/g4rpc ainda responde  ← se não, aborta
  4. parar + fotografar   snapshot de blocks.log/meta.bin/ws_latest.bin
  5. trocar o binário     só o token do caminho na unit; guarda unit.preroll
  6. subir + esperar      behind_by_slots ≤ 2 (ou alcançar a frota, no binário
                          velho, que não expõe o campo)
  7. PROVAR DEPOIS        block_id E state_root idênticos, num slot ASSENTADO,
                          contra ≥2 caixas de validador distintas
  8. VOLTAR AO QUORUM     systemctl start bloch-rpc-8080  ← só se 7 passou
  9. esperar 1 época      (~16 min) antes de tocar no outro
```

**O passo 2 é o que responde à pergunta.** Enquanto um arquival está sendo
rolado ele não é upstream, então uma divergência dele não pode ser servida: ela
é *provada contra a frota* no passo 7, com o nó ainda fora do ar público. E
como só um sai por vez, o quorum público nunca cai abaixo de **1 arquival + 7
caixas de validador = 8 upstreams**.

**Ordem obrigatória** (o script recusa outra):

1. `139.180.173.231` — já tem `bloch-pos-cinco` em disco, então tem **dois**
   degraus de reversão (`cinco`, depois `quatro`) em vez de um.
2. `139.180.166.5` — só depois que o primeiro estiver provado e de volta no
   8080 por uma época inteira.

`behind_by_slots` **não é prova**. Um nó que virou cabeça de si mesmo anda na
própria bifurcação e marca `behind=0` — limite medido no ensaio de 31/08. Ele é
condição de parada da espera; quem decide é a raiz.

---

## 3. Comandos

```sh
export ROLLOUT_CONF=$HOME/bloch-rollout/rollout-release/rollout.conf.mainnet

# --- leitura, seguro a qualquer momento ---
bash rolar-arquivais.sh inventario
bash rolar-arquivais.sh checar
bash rolar-arquivais.sh provar 139.180.173.231
bash digesto-portoes.sh 0a3a436a 46133196 bed1b9ce

# --- ensaio: imprime cada comando que rodaria, sem tocar em nada ---
bash rolar-arquivais.sh rolar 139.180.173.231

# --- para valer ---
EXECUTAR=1 bash rolar-arquivais.sh rolar 139.180.173.231
#   ... uma época ...
EXECUTAR=1 bash rolar-arquivais.sh rolar 139.180.166.5
bash rolar-arquivais.sh verificar
```

**Sem `EXECUTAR=1` nada é alterado.** Toda escrita passa por uma função única
que, no modo padrão, imprime o `ssh` que rodaria em vez de rodá-lo.

### Rollback

```sh
EXECUTAR=1 bash rolar-arquivais.sh reverter 139.180.173.231
```

Ele tira do quorum, para, restaura `bloch-archival.service.preroll` (que aponta
para o `bloch-pos-quatro` que **nunca foi sobrescrito** — é por isso que o
binário novo tem nome próprio, `bloch-pos-seis`), sobe, espera e **prova**. Só
devolve ao 8080 se a prova passar.

Se reverter e ainda divergir, o degrau seguinte é a store — seguro aqui porque o
nó não tem chave:

```sh
sudo systemctl stop bloch-archival
cp -a /home/ubuntu/g4/archival.preroll/. /home/ubuntu/g4/archival/
sudo systemctl start bloch-archival
```

### Verificação de cada passo

| passo | comando que prova |
|---|---|
| antes de tudo | `bash rolar-arquivais.sh checar` |
| binário certo no alvo | sha256 de ida e volta + `--version` contém `ESPERADO` + `gates_digest` |
| nó na cadeia | `bash rolar-arquivais.sh provar <host>` → `PROVADO no slot N` |
| público vivo | `curl -s -X POST https://posternlabs.com/g4rpc -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'` |
| fim | `bash rolar-arquivais.sh verificar` |

---

## 4. O quorum público

`functions/g4rpc.js` **não** protegia contra isto, e o defeito é estrutural, não
hipotético: `orderUpstreams` preserva a ordem configurada, os dois arquivais são
os dois primeiros, `QUORUM_WAVE` é 3 — então a primeira onda era
`[arquival, arquival, uma caixa]`, e para um método **sem projeção**
(`getbalance`, `getutxos`, `listunspent`, `gettxout`, `getblockby*`) o código
retornava assim que dois concordassem, **sem nunca perguntar às sete caixas de
validador**. Um saldo de dois arquivais bifurcados saía carimbado de
`corroborated` e ia para o cache.

Pior no `getchaininfo`: a regra do "mais avançado" fazia dois arquivais num ramo
mais **alto** vencerem a frota inteira.

A correção não mexe em `QUORUM_MIN`; ela troca *quantidade* por
**independência** — a frota é a cadeia, um arquival corrobora, dois arquivais
não constituem:

1. a primeira onda sempre alcança ao menos uma caixa de validador (mesmo número
   de chamadas: troca-se o último da onda);
2. a saída antecipada só vale se o grupo vencedor tiver testemunha de validador;
3. um grupo sem nenhuma testemunha de validador não vence um grupo que tenha —
   nem por pluralidade, nem por "mais avançado";
4. se **só** os arquivais responderem, a resposta **sai** — disponibilidade é
   requisito duro — mas `corroborated: false`, o que a mantém **fora do cache**
   (a escrita exige `corroborated !== false`), então não é republicada a
   ninguém;
5. `corroboration.fleet_witnesses` passa a dizer quantas das testemunhas são
   caixas de validador.

Sete testes novos em `functions/tests/g4rpc-quorum.test.mjs`, os quatro
primeiros vermelhos antes da correção (`node functions/tests/g4rpc-quorum.test.mjs`
→ 32 passam).

---

## 5. A checagem que fica de pé

Hoje não dá para perguntar a um binário de produção o que ele acha do consenso:
`quatro`, `cinco` e `seis` respondem `selfcheck` com uma linha de passa/falha e
ignoram `--json`.

`selfcheck --json`, com `gates_digest`, existe em `758ac1a8` (ramos
`agent/testnet-deliver`, `converge/ws-tool`, `integ/validator-opening`) — e
**não está no `bed1b9ce`** que a frota vai receber. **Coordenação necessária:**
se o `seis` for cortado sem essa peça, os arquivais serão rolados e continuarão
sem poder ser checados. O release do roll deveria carregar as duas coisas — o
fix de catch-up **e** o digesto.

Até lá, `digesto-portoes.sh` responde a mesma pergunta pelo fonte, ancorado no
commit que o `--version` imprime, e produz **a mesma string** que o binário
produziria (mesma serialização canônica, mesmo SHA3-256, mesma ordenação por
nome). Ele já está ligado ao `rolar`: se o binário que entra souber se declarar,
o `gates_digest` tem que bater com o canônico ou o roll aborta.

**Quando o conjunto de portões mudar** — os 9 do ramo de consenso — o digesto
canônico neste script e em `rolar-arquivais.sh` (`DIGESTO_CANONICO`) muda junto,
**de propósito**. Um digesto que precisa ser atualizado é o teste funcionando.
