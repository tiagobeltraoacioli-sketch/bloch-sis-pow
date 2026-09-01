//! Mede o tempo de VERIFICACAO da prova SP1 (Core e Compressed) — o numero que
//! o replay do no paga por bloco se blocos carregarem provas e o boot re-verificar.
//! ADVISOR-E, onda Coherence, 2026-08-29. N entradas/saidas de argv[1] (default 2).

use coherence_core::{check_spend, CommitmentTree, Note, SpendInput, SpendPublic, SpendWitness};
use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin};
use sp1_sdk::ProvingKey as _;

const ELF: &[u8] = include_bytes!(
    "../../../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coherence-spend-measure-guest"
);

fn note(v: u64, seed: u8) -> Note {
    Note { v, pk_d: [seed; 32], rho: [seed ^ 0xAA; 32], psi: [seed ^ 0x55; 32] }
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(2);
    let fee: u64 = 100;
    let ins: Vec<Note> = (0..n).map(|i| note(1000 + 100 * i as u64, i as u8 + 1)).collect();
    let in_sum: u64 = ins.iter().map(|x| x.v).sum();
    let out_total = in_sum - fee;
    let mut outs: Vec<Note> = (0..n - 1).map(|i| note(1000, i as u8 + 100)).collect();
    outs.push(note(out_total - 1000 * (n as u64 - 1), 200));

    let mut tree = CommitmentTree::new();
    for x in &ins { tree.append(x.commitment()); }
    let anchor = tree.root();
    let nk = [0x77u8; 32];
    let witness = SpendWitness {
        inputs: ins.iter().enumerate().map(|(i, x)| SpendInput {
            note: x.clone(), position: i as u64, path: tree.path(i as u64).unwrap(), nk,
        }).collect(),
        outputs: outs.clone(),
    };
    let public = SpendPublic {
        anchor,
        nullifiers: ins.iter().enumerate().map(|(i, x)| x.nullifier(&nk, i as u64)).collect(),
        out_commitments: outs.iter().map(|o| o.commitment()).collect(),
        fee,
    };
    check_spend(&public, &witness).expect("testemunha invalida");

    let mk_stdin = || {
        let mut s = SP1Stdin::new();
        s.write(&public);
        s.write(&witness);
        s
    };

    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::Static(ELF)).expect("setup falhou");

    for (nome, modo) in [("CORE", SP1ProofMode::Core), ("COMPRESSED", SP1ProofMode::Compressed)] {
        let t = std::time::Instant::now();
        match client.prove(&pk, mk_stdin()).mode(modo).run() {
            Ok(p) => {
                println!("{nome}: prova gerada em {:.1}s", t.elapsed().as_secs_f64());
                // warm-up
                client.verify(&p, pk.verifying_key(), None).expect("verify falhou (warmup)");
                let iters = 10u32;
                let t = std::time::Instant::now();
                for _ in 0..iters {
                    client.verify(&p, pk.verifying_key(), None).expect("verify falhou");
                }
                let each = t.elapsed() / iters;
                println!("{nome}: VERIFY = {:.4?} por prova (media de {iters})", each);
            }
            Err(e) => println!("{nome} FALHOU: {e:?}"),
        }
    }
}
