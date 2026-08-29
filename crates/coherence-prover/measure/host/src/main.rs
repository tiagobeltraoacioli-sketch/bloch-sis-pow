//! Mede tamanho da prova SP1 do spend da Coherence, com N entradas e N saidas.
//! N vem de argv[1] (default 8). Core (FRI cru) e Compressed (recursao FRI).

use coherence_core::{check_spend, CommitmentTree, Note, SpendInput, SpendPublic, SpendWitness};
use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin};

const ELF: &[u8] = include_bytes!(
    "../../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coherence-spend-measure-guest"
);

fn note(v: u64, seed: u8) -> Note {
    Note { v, pk_d: [seed; 32], rho: [seed ^ 0xAA; 32], psi: [seed ^ 0x55; 32] }
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    let fee: u64 = 100;

    // entradas: 1000, 1100, 1200, ...
    let ins: Vec<Note> = (0..n).map(|i| note(1000 + 100 * i as u64, i as u8 + 1)).collect();
    let in_sum: u64 = ins.iter().map(|x| x.v).sum();

    // saidas: n-1 de 1000, a ultima absorve o resto
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
    println!("=== {n} entradas / {n} saidas — statement valido OK ===");

    let mk_stdin = || {
        let mut s = SP1Stdin::new();
        s.write(&public);
        s.write(&witness);
        s
    };

    let client = ProverClient::builder().cpu().build();
    let (_pv, report): (sp1_sdk::SP1PublicValues, _) =
        client.execute(Elf::Static(ELF), mk_stdin()).run().expect("execute falhou");
    let cycles = report.total_instruction_count();
    println!("CICLOS: {cycles}  ({:.2}% de um shard de 2^24)", cycles as f64 / 16777216.0 * 100.0);

    let pk = client.setup(Elf::Static(ELF)).expect("setup falhou");

    for (nome, modo) in [("CORE", SP1ProofMode::Core), ("COMPRESSED", SP1ProofMode::Compressed)] {
        let t = std::time::Instant::now();
        match client.prove(&pk, mk_stdin()).mode(modo).run() {
            Ok(p) => {
                let b = bincode::serialize(&p).expect("serialize");
                println!("{nome}: {} bytes ({:.1} KiB) em {:.1}s",
                         b.len(), b.len() as f64 / 1024.0, t.elapsed().as_secs_f64());
            }
            Err(e) => println!("{nome} FALHOU: {e:?}"),
        }
    }
}
