# coherence-proof-size — mede a prova SP1 do spend da Coherence

Harness que gera uma prova REAL do statement C1 e reporta ciclos e o tamanho
serializado nos dois modos pos-quanticos: **Core** (FRI cru) e **Compressed**
(recursao FRI). Groth16/PLONK nao entram: usam emparelhamentos e a C1 §3 os
proibe.

Existe porque o custo da prova era, ate 2026-08-29, uma estimativa qualitativa
("centenas de KB") que ninguem tinha exercitado — e ela errou por uma ordem de
grandeza. Resultados e consequencias:
`docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md`.

## Rodar

```sh
cd guest && cargo prove build          # gera o ELF
cd ../host && cargo run --release      # 2 entradas / 2 saidas (default)
cargo run --release -- 8               # 8 entradas / 8 saidas
```

## Os cinco pre-requisitos que a arvore nao documenta

Todos descobertos por tentativa, nao por leitura. Sem eles nao se reproduz a
propria prova do projeto:

1. **Toolchain SP1 pinado.** `sp1up` sem versao instala um `cargo-prove` que
   emite ELF **riscv64**; o `sp1-sdk = "4"` que `../program` e `../script`
   declaram recusa com `must be a 32-bit elf`. E o toolchain contemporaneo do
   4.2.1 (2025-05) e velho demais para os crates atuais — morre compilando
   `proc-macro2`. Este harness pina `=6.5.0` nas duas pontas.
2. **`Cargo.lock` do guest.** Nao existe em `../program`, que alem disso esta
   fora do workspace (`Cargo.toml:40`). Sem lock, dois builds honestos divergem
   → ELF diferente → vkey diferente → hard fork silencioso.
3. **`protoc`.** `sp1-prover-types` gera codigo de `.proto` no build script.
   `brew install protobuf` (medido com libprotoc 36.0).
4. **`default-features = false` no `sp1-sdk`.** Nao e higiene de dependencia: com
   as features default o SDK arrasta `alloy-consensus 0.14`, que nao compila
   contra serde >= 1.0.228. O build morre antes de chegar perto de uma prova.
5. **Caminho do ELF.** `../script/src/main.rs` e `../service/src/main.rs` fazem
   `include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf")`. Dois erros
   no mesmo literal: o SP1 atual escreve em
   `target/elf-compilation/riscv64im-succinct-zkvm-elf/release/<pacote>`.

`REPRO.md` nao cobre nenhum deles, e o `deploy/sp1-prover/Dockerfile` ja admitia
por escrito que o `SP1UP_VERSION` estava por pinar.

## Por que separado de `../program`

O guest aqui e um espelho de `../program/src/main.rs` com versoes pinadas. Nao
alterei `../program`, `../script` nem `../service`: qual SDK o projeto adota e
decisao em aberto, e um harness de medicao nao deve decidi-la por atalho. As
tres crates originais continuam sem compilar, e isso esta documentado em vez de
consertado silenciosamente.
