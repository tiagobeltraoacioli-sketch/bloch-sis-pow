# AVISO — Ativação do L2 nativo da Bloch na mainnet (atualização obrigatória de nós)

> **MODELO — ainda não publicado.** Todo `{{…}}` é um campo a preencher antes
> da publicação. Publicar somente quando tudo isto for verdade
> (docs/L2-MAINNET-ACTIVATION.md, "What remains before arming"): conjunto de
> atestadores commitado (`mainnet::ATTESTOR_SET`), programa SP1 e gênese do L2
> commitados (`mainnet::PROGRAM`), replay arquival do histórico da mainnet
> PASS e `scripts/l2-activation/final-qualification.sh` PASS no commit final.
> O aviso deve sair **pelo menos 14 dias antes da época E**. Versão em inglês:
> `L2-MAINNET-ACTIVATION-NOTICE.md`; manter as duas em sincronia.

| | |
| --- | --- |
| Publicado em | {{DATA DE PUBLICAÇÃO, UTC}} (T−14 dias ou antes) |
| Época de ativação **E** | **{{E}}** — primeiro slot {{32·E}}, previsto para {{DATA/HORA UTC}} (slots de 30 s, 32 slots por época; vale o número da época, não o horário) |
| Release | `bloch-pos` {{VERSÃO}}, commit `{{COMMIT COMPLETO, 40 HEX}}` |
| SHA-256 do binário (Linux x86-64) | `{{SHA256}}` |
| Chave de assinatura | `{{bloch-release-AAAAMMDD.pub}}` (minisign), fingerprint `{{KEY ID}}` |
| Download | `{{URL DA RELEASE}}` e `releases/bloch-pos-{{AAAA-MM-DD}}/` no repositório |
| Quem precisa agir | **todos** os validadores, nós arquivais / RPC, bootnodes, exploradores, indexadores e nós de exchanges |

## 1. Resumo

No primeiro bloco da época **E**, a mainnet Genesis-4 ativa a **camada de
liquidação L2 nativa** (L2 compatível com EVM, chain id **700770**). É uma
**mudança de consenso (hard fork)**: a partir desse bloco, a raiz de estado do
L1 passa a ter um componente L2. Um nó não atualizado **rejeita esse bloco
(`StateRootMismatch`) e para de seguir a cadeia na época E.** Não existe
chave em tempo de execução nem como optar por não participar na mainnet.

Nada muda antes da época E: a nova release se comporta exatamente como a
atual, produz blocos e raízes de estado idênticos e recusa toda transação de
L2 até E. Atualizar cedo é seguro e é o que pedimos.

## 2. O que muda na época E

- **Instalação do L2.** A fronteira para a época E instala o L2 com a
  política fixada na release; o primeiro bloco de E é a altura nativa 1 do L2.
  Blocos e raízes históricos não mudam.
- **Novos tipos de transação L1 passam a ser válidos**: liquidações L2
  assíncronas (0x13), depósitos nativos na inbox do L2 (0x14),
  disponibilidade de dados do L2 (0x15) e saques do L2 (0x16). Antes de E
  são recusados pelo mempool e inválidos em blocos. Liquidações síncronas
  (0x12) continuam recusadas pelo nó.
- **Modo de liquidação: assíncrono.** Depósitos e saques só existem nesse
  modo; cada lote do L2 é publicado no L1 (disponibilidade de dados) e
  liquidado com prova sucinta contra o programa SP1 fixado
  (`{{HASH DO PROGRAMA / ELF}}`, gênese do L2 `{{ESTADO INICIAL DO L2}}`).
- **Conjunto de atestadores, fixo na ativação**: **3-de-5** chaves híbridas
  pós-quânticas (ML-DSA-65 + Falcon-1024), cinco operadores em hosts
  distintos. Hash do conjunto `{{HASH DO CONJUNTO}}`. Definido uma única vez:
  sem rotação, sem chave de administrador e sem outra forma de mudança que não
  uma nova ativação anunciada publicamente.
- **Escrow.** O BLCH depositado no L2 fica num escrow de consenso no L1; a
  conservação do escrow é verificada por todo nó em todo bloco.

## 3. Regras de saque (L2 → L1)

Todo saque exige que a liquidação que contém a retirada esteja
**finalizada (FFG)** no L1; os atrasos abaixo somam-se à finalidade.

| Valor do saque | Requisito | Atraso após a liquidação da retirada |
| --- | --- | --- |
| **< 100 BLCH** | prova contra liquidação finalizada | **64 blocos** (duas épocas, ≈ 32 min com todos os slots ocupados) |
| **≥ 100 BLCH** | o acima **mais assinaturas de 3 dos 5 atestadores** | **2 880 blocos** (≈ 24 h com todos os slots ocupados) |

**Janela de liberação (limite de vazão).** Em cada janela de **2 880 blocos**
o total liberado para o L1 é limitado a **10 % do escrow, com piso de
10 BLCH**. Só o primeiro saque atestado de uma janela pode exceder o limite.
Um saque que excederia o limite espera a próxima janela; não se perde.

Atestadores só assinam raízes que eles próprios reconstruíram a partir dos
lotes de disponibilidade de dados do L1. Esses limites são constantes de
consenso desta release e só mudam com uma nova ativação anunciada.

## 4. O que você precisa fazer

1. **Atualizar antes da época E** para `bloch-pos` {{VERSÃO}} (commit
   `{{COMMIT}}`), seguindo `docs/L2-MAINNET-UPGRADE-RUNBOOK.md`. Recomendado:
   assim que sair o release candidate (T−7 dias); **obrigatório: antes de
   T−2 dias**, para que a verificação de prontidão abaixo conte você.
2. **Verificar o binário** antes de instalar:

   ```bash
   minisign -Vm SHA256SUMS -p {{bloch-release-AAAAMMDD.pub}}
   sha256sum --check SHA256SUMS          # deve imprimir: bloch-pos: OK
   ./bloch-pos --version                 # deve citar o commit {{COMMIT_CURTO}}
   ./bloch-pos buildinfo                 # build_version sem marcador "+devnet" / "rehearsal"
   ```

   Build reprodutível: `git checkout {{COMMIT}} && cargo build --release -p
   bloch-pos-node` e comparar com o SHA-256 publicado (ver `REPRO.md`). Nunca
   instale binário cujo checksum ou assinatura não confira, nem binário
   recebido por mensagem privada.
3. **Informar sua versão** (validadores): envie a saída de `getbuildinfo`
   (ou `bloch-pos --version`) e o índice do seu validador para
   {{CONTATO / FORMULÁRIO DE PRONTIDÃO}}, para que seu stake seja contado.
4. **Bootnodes e arquivais atualizam primeiro.** Validadores atualizados
   precisam se conectar diretamente entre si, não apenas via relays ainda não
   atualizados (o teste de frota mista mostrou que um nó atualizado ligado só
   por um relay antigo fica isolado em E).
5. **Exchanges e custodiantes**: atualizem seus nós; depósitos e saques de
   BLCH no L1 continuam funcionando sem mudança. Recomendamos pausar depósitos
   e saques de BLCH da época **E−1** até a época **E+2** estar finalizada no
   seu nó atualizado, creditando só blocos finalizados nesse período. Não
   credite ativos do L2 até o seu próprio nó mostrar o L2 instalado
   (`getl2settlement` → `profile.activated = true`).

## 5. O que acontece com nós não atualizados

Seguem a cadeia normalmente até o último bloco antes da época E. **Rejeitam o
primeiro bloco da época E** com `StateRootMismatch`, não finalizam nada em E
ou depois e ficam num ramo morto. Um validador no binário antigo deixa de
receber recompensas e fica sujeito às penalidades de inatividade da rede a
partir daí. Foi o que a qualificação de frota mista observou: o binário
antigo e um build não armado divergiram exatamente no primeiro bloco da época
de ativação, enquanto o lado atualizado (3 de 4 do stake) seguiu finalizando.

Recuperação depois de E: instale a nova release e reinicie. Se o nó antigo
apenas parou em E, a nova release continua do último bloco válido. Se ele
gravou blocos de um ramo minoritário (release antiga) depois de E, a nova
release se recusa a reaplicá-los ("durable block log failed consensus
replay"): restaure o diretório de dados de um backup feito antes de E (o
runbook pede um) ou faça bootstrap por snapshot (`docs/SNAPSHOT-BOOTSTRAP.md`).
Atualizar antes de E evita tudo isso.

## 6. Cronograma

| Quando | O quê |
| --- | --- |
| **T−14 d** ({{DATA}}) | Este aviso. Época E, hash do conjunto de atestadores, identidade do programa e política são finais. |
| **T−7 d** ({{DATA}}) | **Release candidate**, idêntico em consenso à release final (mesma época, mesma política). Bootnodes, arquivais e validadores podem instalá-lo. Primeira contagem de prontidão. |
| **T−2 d** ({{DATA}}) | **Binário final** (assinado, checksums). **Go / no-go**: verificação de prontidão (§7). |
| **E** ({{DATA/HORA UTC}}) | Ativação no primeiro bloco da época E. |
| E → E+2 | Monitoramento: finalidade de E, E+1, E+2 nos nós atualizados; `getl2settlement` mostra o L2 instalado. |

O release candidate e o binário final têm **a mesma época de ativação e a
mesma política**. Se for necessária qualquer mudança de consenso depois do
release candidate, a época é adiada (§7), nunca comprimida.

## 7. Go / no-go e adiamento

- **Limite de prontidão: pelo menos 90 % do stake ativo na nova release em
  T−2 d** (o patamar usual de prontidão em hard forks coordenados; a cadeia
  precisa de > 2/3 para finalizar, a margem cobre quedas e operadores
  atrasados). Bootnodes e os dois arquivais publicados também precisam estar
  atualizados.
- **Se o limite não for atingido em T−2 d, ou se surgir um defeito
  bloqueante, a ativação é adiada.** Como a época está compilada no binário
  (sem override em tempo de execução), adiar significa uma **release
  substituta** que move a trava para uma época posterior ou a desarma. Ela é
  construída e assinada junto com o binário final para poder ser publicada
  imediatamente; **todo nó já atualizado precisa instalar a substituta antes
  da época E**. Uma nova época é então anunciada com novo aviso de pelo menos
  14 dias.
- **Sem rollback depois de E.** Uma vez finalizado o primeiro bloco da época
  E, o L2 faz parte do histórico de consenso; a correção de um defeito depois
  de E é uma nova release para frente, não a volta ao binário antigo. Antes
  de E, voltar ao binário anterior é seguro (ver o runbook).
- Decisões e eventuais adiamentos são publicados em {{CANAIS OFICIAIS}} e
  assinados com a chave de release.

## 8. Contatos

- Anúncios: {{CANAL(IS) OFICIAL(IS)}}
- Coordenação de operadores / relatos de prontidão: {{CONTATO}}
- Segurança (privado): {{CONTATO DE SEGURANÇA}} (ver `SECURITY.md`)
- Exchanges: {{CONTATO PARA EXCHANGES}}

Somente mensagens nos canais acima, assinadas com a chave de release, valem.
Nunca pediremos chaves, senhas ou material de seed.
