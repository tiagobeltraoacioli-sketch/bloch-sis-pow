<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Spike — custo de prova in-circuit da assinatura híbrida

**Data:** 2026-08-10 · **Alvo:** §6.5.1 de `BLOCH-POS-SHA3-LATTICE-MIGRATION.md`
**Pergunta:** a agregação por época (prova FRI sobre o quórum) é viável, ou o
comitê fica preso em 64 e os ~310 GB/ano são permanentes?

---

## Resultado em uma linha

Verificar **uma assinatura híbrida completa** (ML-DSA-65 ‖ Falcon-1024) dentro
do zkVM custa **7.222.352 instruções RV32IM**. Com o desenho atual (comitê 64
atestando **por slot** de 30 s), isso exige **~15,4 milhões de ciclos/segundo
sustentados**.

| Metade | Instruções | Permutações Keccak | Dentro do Keccak |
|---|---|---|---|
| ML-DSA-65 | 5.909.451 | 208 | 3.408.288 (57,7%) |
| Falcon-1024 | 1.312.901 | 31 | 504.370 (38,4%) |
| **Híbrido** | **7.222.352** | **239** | **3.912.658 (54,2%)** |

Ambas as metades verificaram assinaturas reais do PQClean (`a0 = 1`), não
caminhos triviais. O custo por permutação Keccak saiu praticamente igual nas
duas implementações independentes (16.386 vs 16.270 instruções) — um
cross-check de que a medição é consistente.

Achado lateral: **Falcon-1024 verifica 4,5× mais barato que ML-DSA-65**. O
gargalo do híbrido é o lado padronizado pelo NIST, não o exótico.

---

## O que foi medido, e como

Sem toolchain SP1 instalado e sem emulador RISC-V disponível (o `qemu-user` não
existe em macOS), a medição foi feita compilando o verificador para a ISA do
zkVM e contando instruções num interpretador RV32IM escrito para este spike
(`emu/rv32.py`). SP1 cobra aproximadamente **um ciclo por instrução RISC-V
retirada**, então a contagem é um proxy independente de hardware.

A contagem é um **teto pessimista**: aqui o SHAKE-256 roda como instruções
RV32IM comuns, enquanto o SP1 substituiria cada permutação Keccak por um
precompile muito mais barato.

### Gate 1 — o verificador Rust puro aceita as assinaturas atuais?

Necessário porque o stack atual (`pqcrypto-mldsa`, `pqcrypto-falcon`) é **C do
PQClean via FFI** — 1.124 arquivos `.c` cada — e o clang da Apple não tem alvo
RISC-V. Sem um verificador em Rust puro, não há caminho in-circuit sem instalar
um cross-compiler C.

| | Resultado |
|---|---|
| ML-DSA-65: assina com PQClean (C), verifica com `fips204` (Rust puro), **mesmos bytes** | **PASSA** — `ctx` vazio, pk 1952 B, sig 3309 B |
| Falcon-1024: assina com PQClean (C), verifica com `tide-fn-dsa-vrfy` (Rust puro), perfil `FalconProfile::PqClean` | **PASSA** — pk 1793 B, sig 1274 B, e **rejeita** assinatura adulterada (controle negativo) |

Os crates `fn-dsa` e `falcon-rs` implementam FN-DSA/FIPS 206, cujo formato
difere do Falcon original; o `tide-fn-dsa-vrfy` foi o único com perfil PQClean
explícito. O controle negativo importa: um verificador que sempre retornasse
`true` também "passaria" no teste positivo.

### Gate 2 — compila para a ISA do zkVM?

`fips204` com `default-features = false`, alvo `riscv32im-unknown-none-elf`,
`no_std`: **compila**. ELF bare-metal de 84 KB.

O Falcon precisou de um bump allocator no binário bare-metal (o crate usa
`alloc`) — mesma forma do allocator que o guest do SP1 usa.

### Gate 3 — quantas instruções?

```
ML-DSA-65    5.909.451 instrucoes   a0=1   OP 33,0% OP-IMM 27,0% LOAD 18,0% STORE 15,6%
Falcon-1024  1.312.901 instrucoes   a0=1   OP 39,9% OP-IMM 28,1% LOAD 13,3% STORE 10,9%
```

`a0 = 1` em ambos: verificaram de verdade, não caíram num atalho.

### Gate 4 — quanto disso é hashing?

Contando instruções executadas **dentro** do símbolo da permutação Keccak
(`keccak::p1600` no ML-DSA, `KeccakState::process` no Falcon):

| | ML-DSA-65 | Falcon-1024 | Híbrido |
|---|---|---|---|
| Permutações Keccak-f1600 | 208 | 31 | 239 |
| Instruções dentro do Keccak | 3.408.288 | 504.370 | 3.912.658 |
| Fração do custo | 57,7% | 38,4% | **54,2%** |
| Piso (resto: NTT, aritmética, decode) | 2.501.163 | 808.531 | **3.309.694** |

O precompile Keccak do SP1 ataca 54,2% do custo do híbrido. O piso, mesmo com
Keccak inteiramente gratuito, é **~3,3M instruções por assinatura**.

---

## Gate 5 — o custo escala linearmente? (N assinaturas num guest só)

Medido com **quatro pares híbridos distintos** (chaves e assinaturas
diferentes, não a mesma repetida):

| N (assinaturas híbridas) | Instruções | Δ marginal |
|---|---|---|
| 1 | 7.236.608 | — |
| 2 | 14.531.272 | 7.294.664 |
| 3 | 21.796.278 | 7.265.006 |
| 4 | 29.061.154 | 7.264.876 |

**Marginal: 7.274.849 instruções por assinatura híbrida**, com dispersão de
0,41% entre os pares. O overhead fixo é **−38 mil** — ou seja, zero dentro do
ruído.

Consequência: **não há amortização no guest.** Verificar N assinaturas custa
exatamente N vezes verificar uma. Qualquer economia de batching tem que vir do
sistema de provas (recursão, folding), nunca de rodar mais verificações no
mesmo programa.

---

## O que isso exige do provador — cenários de cadência

Custo marginal 7.274.849 instr/assinatura; slot 30 s; época 32 slots (16 min);
assinatura híbrida 4.589 B.

| Cenário | Ciclos/s | Piso (Keccak grátis) | Assinaturas/ano | Por bloco (média) |
|---|---|---|---|---|
| **A.** 64 por slot — *desenho original* | 15,52 M | 7,11 M | 308,7 GB | 286,8 KB |
| **B.** 64 só na época | 0,48 M | 0,22 M | 9,6 GB | 9,0 KB |
| **C.** 128 só na época | 0,97 M | 0,44 M | 19,3 GB | 17,9 KB |
| **D.** 8 por slot + 128 na época | 2,91 M | 1,33 M | 57,9 GB | 53,8 KB |
| **E.** 16 por slot + 256 na época | 5,82 M | 2,67 M | 115,8 GB | 107,6 KB |

O cenário **C dobra o comitê** (128 contra 64) e ainda assim custa **16× menos
prova e 16× menos armazenamento** que o desenho original. Essa é a troca que a
medição destravou.

### A ressalva que não pode ser varrida

Voto **exclusivamente** na fronteira de época remove o peso de atestação por
slot — e é ele que o LMD-GHOST usa para escolher garfo. Sem ele, reorganizações
*dentro* da época ficam baratas: a ordenação intra-época passa a depender só da
ordem de slot e da assinatura do proposer.

Vale notar que o Ethereum **não** faz isso: lá cada validador vota uma vez por
época, mas o conjunto é fatiado em 32 comitês, um por slot — então todo slot
tem peso de atestação. "Voto por época" no sentido literal (tudo na fronteira)
é uma coisa diferente, e mais frágil.

O cenário **D** restaura o sinal por slot com um subcomitê pequeno (8) e mantém
o comitê cheio (128) na fronteira para finalidade — a 2,91 M ciclos/s, ainda
**5,3× mais barato** que o original. É a opção defensável sem abrir mão de
proteção contra reorg intra-época.

---

## Leitura honesta

- **Com o desenho original (voto por slot), a agregação parece inviável hoje.**
  15,5M ciclos/s sustentados está bem acima do que provadores STARK entregam em
  hardware acessível.
- **Mudando a cadência, a agregação deixa de ser necessária.** No cenário C o
  armazenamento de assinaturas cai de 308,7 GB/ano para 19,3 GB/ano — e é isso
  que a agregação existia para resolver. **O §6.5.1 deve ser rebaixado de
  "estrutural, obrigatório" para "otimização opcional"**: a mudança de cadência
  entrega o mesmo resultado sem depender de pesquisa de fronteira.
- Ou seja, o spike não achou um jeito de pagar o custo — achou um jeito de
  **não incorrer nele**.
- Isto **confirma de forma independente** a classificação do próprio repo: a Fase 3
  do `docs/ZK-LEDGER.md` já colocava "verificação in-circuit de ML-DSA/Falcon"
  como *frontier*, pesquisa. A medição concorda.

### O que ainda não foi medido

1. **Custo real do precompile Keccak no SP1** — a linha "piso" assume Keccak
   gratuito, o que é otimista.
2. **Overhead de recursão/agregação** — provar N verificações não é N × provar uma.
3. **Vazão real do SP1** em GPU acessível — precisa do toolchain instalado.
4. `1 ciclo ≈ 1 instrução` é aproximação; o SP1 tem custos por região de memória
   e por tabela que este interpretador não modela.

---

## Reproduzir

```bash
cd spikes/prover-cost
cargo run --release -- --dump-kat          # Gate 1 + gera vetores KAT
cd rv32  && cargo build --release && cd ..  # ML-DSA-65,  ELF bare-metal RV32IM
cd rv32f && cargo build --release && cd ..  # Falcon-1024, idem

python3 emu/symcount.py <elf>              # endereco+tamanho do simbolo Keccak
python3 emu/rv32.py <elf> <addr> <addr>:<size>
```

O símbolo Keccak é `keccak::p1600` no ELF do ML-DSA e
`tide_fn_dsa_comm::shake::KeccakState::process` no do Falcon; os endereços
mudam a cada rebuild, por isso o `symcount.py`.

## Próximos passos, em ordem de valor

1. Decidir entre **voto por slot** e **voto por época** — a medição diz que essa
   escolha, e não a otimização do provador, é o que decide a viabilidade.
2. Instalar o toolchain SP1 e converter ciclos em segundos reais, com o
   precompile Keccak ligado.
3. Avaliar `tide-fn-dsa-vrfy` como dependência de consenso: é um verificador de
   terceiro, não auditado por este projeto, e passaria a ser caminho crítico.
