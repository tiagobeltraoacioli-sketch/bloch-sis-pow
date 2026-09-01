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

## 0. O que foi medido — e a correção de 01/09/2026

**A leitura de 31/08 estava errada no ponto que mais importa, e a correção
inverte a conclusão.** Fica registrada em vez de apagada, porque o erro é
instrutivo: ele veio de tratar `quatro → cinco → seis` como uma progressão.

| binário | commit | onde roda |
|---|---|---|
| `bloch-pos-quatro` | `0a3a436a` | **os dois arquivais** |
| `bloch-pos-cinco`  | `46133196` | a frota (63 validadores) |
| `bloch-pos-seis`   | `bed1b9ce` | o único binário Linux montado — **e não serve** |

### Não são três versões. São três ramos.

```
$ git merge-base 46133196 bed1b9ce
1aacab47                                  # 24/08 — ANTES do `quatro`
$ git merge-base --is-ancestor 0a3a436a 46133196   # quatro está em cinco?
sim
$ git merge-base --is-ancestor 0a3a436a bed1b9ce   # quatro está em seis?
NÃO
```

`seis` saiu do tronco **antes** do `quatro`. Ele não é `cinco` mais um
conserto: é outro ramo, e lhe falta `47f7644b` — "as quatro correções sobre o
que a frota roda". A frota tem essas correções. `seis` não.

Uma delas vale **hoje, em toda época**, e não está atrás de portão nenhum:

```rust
// cinco (46133196) — o que a frota roda
let lookahead = if epoch < params::ANCESTRY_SEED_ACTIVATION_EPOCH { 0 }
                else { committees::MIN_SEED_LOOKAHEAD_EPOCHS };
match epoch.checked_sub(lookahead) { ... }

// seis (bed1b9ce) — sem portão, uma fronteira de distância
match epoch.checked_sub(committees::MIN_SEED_LOOKAHEAD_EPOCHS) { ... }
```

`ANCESTRY_SEED_ACTIVATION_EPOCH` é `u64::MAX`, então na cadeia de hoje `cinco`
usa `lookahead = 0` e `seis` usa `1`. **Comitês diferentes.**

### Por que isso alcança um arquival, que não propõe

`Engine::judge` chama `seed_for_attestation` (engine.rs:2174 no `cinco`). Um
arquival **julga atestação** mesmo sem chave — é assim que ele calcula
justificado e finalizado. Julgar contra outro comitê muda o finalizado, que é
**exatamente o campo sobre o qual o `getchaininfo` do proxy público
corrobora** (`QUORUM_PROJECTION`).

A outra correção ungated do `47f7644b`, o filtro de inclusão
(`derive::validate_included_attestation`), essa sim é inerte aqui: seus únicos
chamadores não-teste estão em `produce.rs`, e um arquival não produz. A boa
notícia do enunciado se confirma — **eles não podem se auto-bifurcar**. Mas
"não pode propor um bloco errado" não é "não pode publicar a cadeia errada".
Um arquival no `seis` responde, atesta nada, parece saudável, e serve outro
finalizado para o RPC público.

### E o `gates_digest` não pega isso

```
$ bash digesto-portoes.sh 0a3a436a 46133196 bed1b9ce
  gates_digest = a03bccc3e460ae15e7b233637334ab09610a684b66f77540ac88b1b7cc34876f
IGUAIS — mesmo conjunto de portoes, mesma declaracao de compatibilidade.
```

Os três dão a mesma string. O digesto é sobre o **conjunto de portões** —
nomes e épocas — e não sobre o comportamento atrás deles. Uma correção atrás
de um portão que já existe é invisível para ele; uma correção **sem** portão,
mais invisível ainda.

Isso não invalida o `digesto-portoes.sh`: ele responde bem a pergunta que
promete responder, que é a do dia em que um dos 9 portões for armado (§5). O
que ele não pode ser é a **única** pergunta. A checagem que faltava — e que
`rolar-arquivais.sh` agora faz — é de **linhagem**, não de digesto.

### O release certo existe e é barato

```
$ git merge-tree --write-tree 46133196 bed1b9ce
6aad5401a3cca90f3a88bb4f19750bb718c9b519      # ZERO conflitos
```

Correções de consenso da frota **mais** o fix de catch-up, sem conflito. É esse
o binário que os arquivais devem receber. (Com o `758ac1a8`, que traz o
`selfcheck --json`, o merge dá **um** conflito, em `engine.rs` — resolvível,
mas precisa de um humano.)

**Enquanto ele não for montado, o roll está travado por construção:**
`rolar-arquivais.sh` recusa qualquer `ESPERADO` fora de `LINHAGEM_APROVADA`
(hoje `46133196`) e sai com código 4 antes de tocar em qualquer host.

### O risco que sobra, e que continua real

1. **O catch-up.** Os arquivais rodam o binário **com** o defeito, então o
   passo perigoso segue sendo o `systemctl restart`. A espera e o `reverter`
   existem para isso.
2. **O quórum público.** Os dois arquivais são os dois primeiros upstreams e
   `QUORUM_MIN` é 2: **eles sozinhos constituíam um quórum**. Corrigido em
   `functions/g4rpc.js` (§4) e mitigado pela sequência (§2).
3. **O próximo dia de bandeira.** O ramo de consenso tem **9** portões, não 5.
   Quando qualquer um for armado, o `gates_digest` muda e um arquival atrasado
   fica consenso-morto naquela época. Aí o digesto é a ferramenta certa.


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

1. `139.180.173.231` — tem `bloch-pos-cinco` **e** `bloch-pos-quatro` em disco.
   O `reverter` automático volta para o `quatro` da unit pré-roll nos dois
   hosts; o que este ganha é um degrau manual a mais (o `cinco` que a frota
   rodou e que, portanto, é sabidamente bom) se o `quatro` também falhar.
2. `139.180.166.5` — só tem `quatro`. Vai por último, quando o procedimento já
   tiver sido exercido uma vez de verdade, e só depois que o primeiro estiver
   provado e de volta no 8080 por uma época inteira.

`behind_by_slots` **não é prova**. Um nó que virou cabeça de si mesmo anda na
própria bifurcação e marca `behind=0` — limite medido no ensaio de 31/08. Ele é
condição de parada da espera; quem decide é a raiz.

---

## 3. Comandos

**Hoje todos estes comandos saem com código 4 antes de tocar em qualquer host**,
porque a conf de mainnet aponta para `bed1b9ce` e a trava de linhagem recusa
(§0). Isso é o estado correto: o roll está bloqueado até o binário certo ser
montado. Para ler o motivo, basta rodar qualquer subcomando.

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

Quem é arquival é **nomeado por URL**, não por índice — a ordem dos upstreams
muda por env sem tocar no código, e um índice fixo apontaria para outra máquina
no dia em que ela mudar. `DEFAULT_ARCHIVALS` traz os dois; `env.G4_RPC_ARCHIVALS`
sobrescreve, e uma string **vazia** desliga a regra por configuração.

Oito testes novos em `functions/tests/g4rpc-quorum.test.mjs`. **Sete deles são
vermelhos sem a correção** — verificado neutralizando o conjunto de arquivais,
que por construção reproduz a semântica anterior:

```
$ node functions/tests/g4rpc-quorum.test.mjs
33 passaram, 0 falharam

$ # com o conjunto de arquivais vazio (= comportamento pré-correção)
26 passaram, 7 falharam
```

O oitavo (`sem arquivais declarados, nada muda`) é verde nos dois lados de
propósito: é ele que garante que os 25 testes anteriores continuam válidos.

**O que isto NÃO cobre:** o acesso direto a `:8080` não passa pelo proxy e
portanto não passa por nada disto. Um arquival bifurcado continua respondendo
a quem o consultar diretamente. O proxy protege o público; ele não conserta o
nó.

---

## 5. A checagem que fica de pé

Hoje não dá para perguntar a um binário de produção o que ele acha do consenso:
`quatro`, `cinco` e `seis` respondem `selfcheck` com uma linha de passa/falha e
ignoram `--json`.

`selfcheck --json`, com `gates_digest`, existe em `758ac1a8` (ramos
`agent/testnet-deliver`, `converge/ws-tool`, `integ/validator-opening`) — e
**não está no `bed1b9ce`**.

**Coordenação necessária, e ela mudou de forma em 01/09.** O `758ac1a8`
descende do `bed1b9ce`, ou seja, **está no mesmo ramo errado** (§0): ele
também não tem o `47f7644b`. Cortar o release a partir dele resolveria a
checagem e manteria o defeito que a checagem existe para pegar — e, pior, o
`gates_digest` que ele passaria a emitir sairia **idêntico** ao da frota,
carimbando exatamente a divergência que ninguém quer.

O release do roll precisa das **três** coisas, nesta ordem de prioridade:
a linhagem da frota (`46133196`), o fix de catch-up (`bed1b9ce`) e o
`selfcheck --json` (`758ac1a8`). As duas primeiras fecham sem conflito
(`git merge-tree 46133196 bed1b9ce` → árvore `6aad5401`, zero conflitos); a
terceira custa **um** conflito em `crates/bloch-pos-node/src/engine.rs`
(`git merge-tree 46133196 758ac1a8`), que é onde os dois ramos mexeram no
mesmo arquivo. É um conflito, num arquivo, e vale pagá-lo: é ele que fecha
esta lacuna de checagem para sempre.

**Um pedido para esse workstream:** que o `selfcheck --json` publique também o
**commit** e não só o `gates_digest`. O digesto responde "conheço os mesmos
portões"; ele não responde "descendo do que a frota roda", e foi a segunda
pergunta que faltou aqui. Enquanto ele não existir, quem responde é a
`LINHAGEM_APROVADA` do `rolar-arquivais.sh`, contra a substring que o
`--version` imprime.

Até lá, `digesto-portoes.sh` responde a mesma pergunta pelo fonte, ancorado no
commit que o `--version` imprime, e produz **a mesma string** que o binário
produziria (mesma serialização canônica, mesmo SHA3-256, mesma ordenação por
nome). Ele já está ligado ao `rolar`: se o binário que entra souber se declarar,
o `gates_digest` tem que bater com o canônico ou o roll aborta.

**Quando o conjunto de portões mudar** — os 9 do ramo de consenso — o digesto
canônico neste script e em `rolar-arquivais.sh` (`DIGESTO_CANONICO`) muda junto,
**de propósito**. Um digesto que precisa ser atualizado é o teste funcionando.

---

## 6. A ordem em relação ao roll dos validadores — confirmada, por outro motivo

O `rollout-release.sh` manda rolar os arquivais **depois** da frota. **Isso está
certo**, mas a justificativa que se costuma dar para isso ("eles são o caso
menos arriscado, então ficam para o fim") não é a que sustenta a decisão — e se
ela fosse a única razão, o argumento oposto venceria: um arquival não pode se
auto-bifurcar, logo poderia ir na frente como cobaia barata.

Duas razões, medidas, mantêm a ordem:

**1. A prova exige uma frota parada.** A única prova que conta aqui é identidade
de `block_id` **e** `state_root` contra a frota, e `prova_de_raiz` requer **duas
caixas de validador concordando entre si** antes de julgar o arquival. Durante o
roll dos validadores as caixas estão em binários mistos e reiniciando: as
referências discordam, e a função devolve **3 — "a FROTA está partida"**, não um
veredito sobre o arquival. Um roll de arquival no meio do roll de validador é um
roll **sem prova disponível**. Não é mais arriscado; é *inverificável*, que é
pior, porque parece ter passado.

**2. Um arquival nunca pode ser a primeira população num comportamento novo.**
Eles são os dois primeiros upstreams do RPC público. Se forem os primeiros a
receber um binário que julga atestação de outro jeito — que é precisamente o que
`cinco` e `seis` fazem diferente (§0) —, eles divergem da frota *legitimamente*,
e o que o público lê é a visão minoritária, publicada pelas duas máquinas em que
o proxy mais confia. A frota define a cadeia; o arquival a espelha. Espelho vai
depois.

**A incapacidade de se auto-bifurcar é o que os torna seguros de rolar — não o
que os tornaria seguros de rolar primeiro.** Ela dispensa a guarda de duas
épocas, autoriza restaurar a store por script e permite `reverter` sem medo de
assinatura dupla (§1). Nada disso diz nada sobre *quando*.

**Consequência operacional:** entre o fim do roll da frota e o início do roll dos
arquivais, exija uma frota convergida — `bash rolar-arquivais.sh checar` tem que
sair sem nenhum `RUIM`, o que inclui as duas caixas de referência concordando.
Só então o primeiro arquival sai do quórum.
