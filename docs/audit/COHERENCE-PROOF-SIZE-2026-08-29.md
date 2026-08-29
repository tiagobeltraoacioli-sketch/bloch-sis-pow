<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Coherence — tamanho da prova SP1, medido

```
Documento:  COHERENCE-PROOF-SIZE-2026-08-29
Status:     MEDICAO. Nao e decisao; e o numero que as decisoes pendentes
            precisavam e nao tinham.
Harness:    crates/coherence-prover/measure/  (reproduzivel; ver o README)
Ambiente:   SP1 6.5.0, cargo-prove 92b8eab (2026-08-26), provador de CPU,
            8 nucleos, 16 GB. protoc 36.0.
Statement:  o guest real de crates/coherence-prover/program, compilado a
            partir de coherence-core (check_spend, C1 §2).
```

## 1. Os numeros

| Configuracao | Ciclos | Core | Compressed |
|---|---:|---:|---:|
| 2 entradas / 2 saidas | 1.042.629 | 2.791.567 B (2,66 MiB) em 83,3 s | 1.272.753 B (1,21 MiB) em 214,8 s |
| 8 entradas / 8 saidas | 4.117.538 | 2.831.511 B (2,70 MiB) em 161,9 s | 1.273.137 B (1,21 MiB) em 289,3 s |

ELF do guest: 201.632 bytes. Tamanho = `bincode::serialize` do
`SP1ProofWithPublicValues`, que e o envelope que o verificador decodifica.

## 2. Nenhum dos modos cabe num bloco

`MAX_BLOCK_TX_BYTES_V2 = 524.288` (`fee_market.rs:85`; o V1 e 262.144).

| | vs. bloco inteiro |
|---|---:|
| Core | **5,32x** |
| Compressed | **2,43x** |

Para UMA transacao blindada. A recursao FRI funciona — corta 54% — e e
pos-quantica, entao nao e o wrap proibido pela C1 §3. Mas 1,21 MiB continua
sendo 2,4 vezes o bloco.

**O desenho da C1 §3, "FRI cru no corpo do bloco", nao e viavel nos limites
atuais.** As saidas:

1. Subir o cap para ~1,5 MiB. E 2,4x o V2, que ja era o dobro do V1, numa frota
   cuja cadencia medida e 13% e onde rotacionar binario ja tira no do quorum.
2. Tirar a prova do corpo do bloco (disponibilidade de dados; o scaffold existe
   em `c5d01f3` do branch `feat/zk-ledger`).
3. Groth16/PLONK — resolveria o tamanho e continua **proibido**: emparelhamentos.

Nao falta ajustar constante. Falta decidir arquitetura.

## 3. A prova compressed e de tamanho fixo

Quadruplicar o trabalho — 1,04 M para 4,12 M de ciclos — aumentou a prova core
em 1,4% e a **compressed em 0,03% (384 bytes)**.

Estrutural: o statement ocupa 6,2% de um shard de 2^24 ciclos na configuracao
menor e 24,5% na maior (`MAX_SHARD_SIZE = 1 << 24`,
`sp1-core-executor/src/opts.rs:9`), e uma prova FRI e dimensionada pelo traco
preenchido ate a proxima potencia de dois, nao pelo numero de saidas. A recursao
normaliza o resto.

Duas consequencias:

- **`MAX_TX_OUTPUTS` e o tamanho da prova nao competem por espaco.** Qualquer
  analise que os troque um pelo outro parte de premissa falsa. A fronteira do
  shard esta a 4x de distancia da configuracao de 8 saidas.
- **`SHIELDED_VERIFY_GAS_PROVISIONAL` deixa de ser um chute a medir.** Sendo o
  tamanho praticamente constante, a verificacao e precificavel como constante.
  `fee_market.rs:151-155` diz que a spec proibe ativar com o numero nao medido;
  o numero agora existe.

## 4. Tempo de prova

83 s (core) e 215 s (compressed) para 2-em-2, em 8 nucleos de CPU sem GPU. A
memoria aguentou: compressed NAO estourou os 16 GB. Se a cadeia exigir o modo
menor, **3,6 minutos** e o numero a usar ao dimensionar a janela de ancoras —
nao os "minutos" genericos que as analises vinham assumindo.

## 5. O que isto corrige no que estava escrito

- O litepaper dizia "centenas de KB contra centenas de bytes". Errado por uma
  ordem de grandeza; corrigido na §16.3 com esta tabela.
- A hipotese de que compressed resolveria o problema de tamanho: **falsa por
  medicao**. Ela ajuda e nao basta.
- "Shard unico implica prova pequena": falso. O statement e de shard unico e a
  prova core e de 2,66 MiB.

## 6. O que esta medicao NAO diz

- Nada sobre soundness, e nada sobre o verificador — que continua fail-closed e
  sem ELF pinado.
- Nada sobre custo de prova do lado do cliente em hardware de usuario; 8 nucleos
  de desktop nao e um celular.
- Nada sobre o modo `compressed` ser aceitavel ao verificador portado: o
  `407cffc` rejeita tudo que nao seja `Core` (`matches!(proof.proof,
  SP1Proof::Core(_))`). Se compressed for o caminho, essa checagem precisa ser
  reaberta deliberadamente — ela e larga demais hoje, porque recursao FRI e
  pos-quantica e esta sendo recusada junto com os wraps que nao sao.
