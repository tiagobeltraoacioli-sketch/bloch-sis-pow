<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Coherence — achados da revisao adversarial de 2026-08-29

```
Documento:  COHERENCE-FINDINGS-2026-08-29
Status:     ACHADOS. Nenhum e exploravel hoje — o pool esta inerte e
            provadamente vazio. TODOS viram reais no dia da ativacao.
Base:       HEAD af2f12e5 / 2e9544b8
Metodo:     revisao adversarial multi-agente + verificacao pontual na fonte.
            Cada achado abaixo foi confirmado no codigo, nao inferido.
```

## Por que este documento existe

A janela em que o pool esta inerte e a unica em que estes defeitos custam
barato. Depois da ativacao, F1 e F2 sao cunhagem e duplo-gasto.

---

## F1 — `check_spend` nao exige nulificadores distintos (ALTO)

`crates/coherence-core/src/lib.rs:409-432`. A funcao itera os inputs somando
valor e conferindo `public.nullifiers[i] == nf` posicao a posicao. **Nunca
verifica que os nulificadores sao distintos entre si.**

Cenario: `SpendWitness { inputs: [A, A] }` com a MESMA nota na MESMA posicao.
Os dois inputs produzem o mesmo `nf`; `public.nullifiers = [nf, nf]` (len 2,
casa com a witness); `in_sum = 2 x v(A)`. A prova valida um gasto do dobro do
valor da nota.

O statement provado NAO oferece protecao contra isso — ela e 100% delegada ao
conjunto global no no. Um aplicador que "ajude" deduplicando a lista antes de
inserir cunha `v(A)` sem lastro.

**Correcao:** exigir nulificadores distintos dentro do statement. Barato e
local. **Cuidado:** `check_spend` e o statement congelado que o ELF pinado
prova — mexer nele muda a vkey. Dois agentes chegaram a este achado
independentemente; um deles ja implementou a checagem no statement NOVO do
unshield (`DuplicateNullifier`) e deliberadamente NAO tocou no congelado, que e
a decisao certa: a correcao do `check_spend` entra no mesmo re-pino que a ponte
ja exige.

## F2 — `NullifierSet` desserializa sem impor a invariante de ordenacao (ALTO)

`crates/coherence-core/src/lib.rs:122-127`. O tipo deriva `Deserialize` e o
campo `keys` e privado justamente porque todo metodo assume que esta ordenado:
`contains`/`insert`/`remove` usam `binary_search` (`:150-177`), e
`root`/`subtree_root`/`non_membership_proof` usam `partition_point` supondo que
a run de bit-0 precede a de bit-1 (`:206,227`). O `derive(Deserialize)` popula
`keys` verbatim, sem `sort`/`dedup`.

Cenario: um payload de state-sync (ou snapshot) com `keys` desordenadas faz
`root()` computar raiz errada E `contains()` dar falso-negativo — liberando
duplo-gasto, sem panico. Exatamente a superficie "forged snapshot" que o resto
do codigo teme.

**Correcao:** `Deserialize` manual que ordena e deduplica, ou rejeita entrada
nao-canonica.

Nota correlata: o teste `root_depends_on_the_set_not_the_order` (`:598-611`)
passa mas e quase tautologico — `from_iter` e `insert` ja mantem `keys`
ordenado, entao ele nunca poderia falhar. Ele nao cobre a fonte real de
dependencia-de-ordem, que e justamente o buraco de F2.

## F3 — `insert`/`remove` devolvem o cheque de duplo-gasto sem `#[must_use]` (MEDIO)

`lib.rs:156` e `:169`. O doc diz "callers must not ignore it", mas nada no tipo
forca. Um aplicador escrevendo `set.insert(nf);` como statement elimina
silenciosamente a deteccao de duplo-gasto. Anotar `#[must_use]` transforma o
erro em falha de compilacao.

## F4 — o statement nao valida o `anchor`; a defesa vive toda fora dele (FRONTEIRA)

`check_spend` verifica o path contra o `anchor` recebido, mas nao checa que ele
e raiz historica real da cadeia (`lib.rs:412`). Um provador pode montar a
propria arvore, usar a raiz dela como `anchor`, provar membership e "gastar"
nota que nunca esteve no pool.

Isto nao e defeito do core — e a demarcacao do que o no PRECISA impor:
(a) `anchor` pertence ao conjunto de ancoras validas; (b) `nf` ausente do
conjunto global corrente. Registrado aqui para nao ser assumido como coberto.

## F5 — `VERIFY_VK=false` desliga a whitelist de recursao (ALTO, no verificador)

`sp1-prover-4.2.1/src/lib.rs:208-209`. Com essa variavel de ambiente, o SDK
carrega `vk_map_dummy.bin` e **pula a checagem de pertinencia do `compress_vk`**
no `recursion_vk_map`. Sem a whitelist, um atacante pode provar um programa de
recursao proprio que emite o `sp1_vk_digest` correto sem verificar nada.

E a mesma classe de enfraquecimento-por-ambiente que o `407cffc` eliminou ao
banir `ProverClient::from_env()` / `SP1_PROVER=mock` — e passou despercebida.
Em 6.5.0 o equivalente esta ao menos atras da feature `experimental`.

**Requisito:** o verificador deve forcar `VERIFY_VK=true` antes de construir o
client E afirmar `client.inner().vk_verification == true` no startup, recusando
ativar caso contrario.

## F6 — o verificador entra em panico com bytes hostis, antes de verificar (ALTO)

Contradiz a afirmacao "never panics" do `407cffc`. No 4.2.1:
- envelope `Core(vec![])` → `proof.last().unwrap()` panica
  (`sp1-sdk-4.2.1/src/prover.rs:113`) ANTES de qualquer verificacao — crash
  remoto trivial de construir;
- `public_values.as_slice().borrow()` panica com comprimento errado;
- `assert_recursion_public_values_valid` usa `assert_eq!`/`zip_eq`
  (`sp1-prover-4.2.1/src/utils.rs:73-81`).

**Requisito:** embrulhar a chamada em `catch_unwind` → false. O 6.5.0 corrigiu
quase tudo — mais um argumento para ativar na linha 6.x.

## F7 — a checagem Core-only e larga demais (PROJETO)

O `407cffc` faz `matches!(proof.proof, SP1Proof::Core(_))`, recusando
`Compressed` junto com Plonk e Groth16. Mas a C1 §3 proibe **emparelhamentos**,
nao recursao: `verify_compressed` nao toca simbolo bn254 nenhum
(`sp1-prover-6.5.0/src/verify.rs:527-580`) e nao baixa artefato em tempo de
verificacao — ao contrario do caminho Plonk/Groth16, que chama
`try_install_circuit_artifacts`.

Com a medicao (core 5,32x o bloco, compressed 2,43x, tamanho fixo), a
recomendacao da revisao e **Compressed-only**, nao "Core ou Compressed": duas
codificacoes aceitas para o mesmo statement sao dois caminhos de consenso.

## F8 — o ELF nao reproduz nem no mesmo toolchain (ALTO, reprodutibilidade)

Tres tamanhos medidos para o MESMO fonte: 193.600 B (toolchain 2026-08-26,
primeira build), 201.632 B (mesma toolchain, apos alinhar SDK), 201.816 B
(mesma maquina, mesmo toolchain, dia seguinte). Causa direta: `Cargo.lock` do
guest nao commitado — corrigido em 2e9544b8. Agravante: o `sp1up` sobrescreve
um toolchain rustup chamado so "succinct", sem versao no nome — dois devs, um
nome, compiladores diferentes.

**Caminho canonico:** `cargo prove build --docker --tag v6.5.0 --locked`,
registrando o **digest** da imagem, e reproducao numa segunda maquina antes de
congelar. Um pino que ninguem reproduziu e um numero, nao um pino.

**Pino triplo, nao so o ELF:** (a) shake256 do ELF; (b) hash da vkey conferido
apos `setup()` — pega deriva de SDK que o pino do ELF nao ve, ja que
vkey = f(ELF, SDK); (c) `SP1_CIRCUIT_VERSION` esperado, compilado e afirmado no
startup.

## F9 — a versao do sp1-sdk E regra de consenso (ESTRUTURAL)

Nao e so a checagem de string: uma prova 6.5.0 nem desserializa sob a maquina
4.2.1 (BabyBear vs KoalaBear, FRI vs Basefold, envelope diferente). Logo
**upgrade de SDK = hard fork**, e o cronograma de releases da Succinct entra no
cronograma de flag-days do projeto.

Migracao possivel com a maquinaria que a cadeia ja usa: verificador versionado
por epoca, mantendo o antigo compilado para replay.

## F10 — dois guests que podem divergir (MEDIO)

`crates/coherence-prover/program/src/main.rs` e
`crates/coherence-prover/measure/guest/src/main.rs` sao byte a byte identicos
hoje. Dois guests que podem divergir e a forma exata do hard fork silencioso
que o pino existe para impedir. **Unificar.**

---

## O que NAO e defeito (verificado, para nao re-auditarem)

- **Arvore DOM_MT sem separacao folha/no interno**: seguro porque a folha nunca
  e bytes crus arbitrarios — `check_spend` sempre recomputa
  `cm = SHAKE(DOM_CM ‖ …)`, e `merkle_parent` usa `DOM_MT`. Tags distintas. Se
  algum caminho futuro aceitar folha crua, quebra.
- **Aritmetica de profundidade do NFSET**: indices consistentes com
  `nfset_empty_roots` (257 entradas); `nfset_bit` MSB-first bate com a
  particao.
- **Binds C2 de contagem** e o espelho no guest: casam.
- **Overflows**: `checked_add` em u128 sobre somas de u64.
- **Consenso vivo** (`coherence_binding`, `expected_coherence`, folhas
  0x07/0x08): sem defeito enquanto o pool for inerte.
