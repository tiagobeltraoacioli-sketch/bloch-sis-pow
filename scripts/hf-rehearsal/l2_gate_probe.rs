// SPDX-License-Identifier: AGPL-3.0-or-later
// REHEARSAL ONLY (scripts/hf-rehearsal/crossing-build.sh copies this into
// bloch-l2-evm/integrations/settlement-recovery/examples). Re-applies the
// canonical chain the L2 native follower verified (its --state dir: `index`
// plus blocks/<id>.bin) with the follower's own native transition,
// Transition<NativeConsensusVerifierV1>, from the flag-day genesis of a
// private BPOSMAN2 network, and prints one line per epoch: the state root,
// finality, and the L2 settlement leaf's CHECKPOINT-ROOTS section (HF1 claim
// finality), with whether the finalized checkpoint root equals the chain's
// own recorded root. Any block that does not re-apply to its header state
// root halts the probe (exit 3).
//
// usage: l2_gate_probe MANIFEST NETWORK_PIN FOLLOWER_STATE_DIR
use bloch_pos_committee::{
    epoch_of,
    interfaces::{ProposalEnvelope, StateReader, StateTransition},
    transition::{PosTransaction, Transition},
};
use bloch_settlement_recovery::{history::load_flag_day_manifest, native::NativeConsensusVerifierV1};
use std::io::BufRead;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 4 {
        eprintln!("usage: l2_gate_probe MANIFEST NETWORK_PIN FOLLOWER_STATE_DIR");
        std::process::exit(2);
    }
    let pin: alloy_primitives::B256 = a[2].parse().expect("pin");
    let (_, mut st) = load_flag_day_manifest(a[1].as_ref(), None, pin, 1_048_576).expect("flag-day genesis");
    let dir = std::path::Path::new(&a[3]);
    let index = std::io::BufReader::new(std::fs::File::open(dir.join("index")).expect("index"));
    let t = Transition::new(NativeConsensusVerifierV1);
    let tag = b"BLOCH:NATIVE:L2:CHECKPOINT-ROOTS:1";
    let report = |st: &bloch_pos_committee::transition::CommittedState, n: usize| {
        let e = epoch_of(st.slot());
        let f = st.finality();
        match st.l2_settlement() {
            None => println!(
                "block {n} slot {} e{e} root {} l2=none just=e{} fin=e{}",
                st.slot(), hexs(&st.state_root()), f.justified.epoch, f.finalized.epoch
            ),
            Some(l2) => {
                let bytes = l2.committed_bytes();
                let has = bytes.windows(tag.len()).any(|w| w == tag);
                let keys: Vec<u64> = l2.checkpoint_roots().keys().copied().collect();
                let fin_own = l2.checkpoint_root(f.finalized.epoch).map(|r| r == f.finalized.root);
                println!(
                    "block {n} slot {} e{e} root {} l2=yes leaf_bytes={} CHECKPOINT-ROOTS={has} keys={keys:?} just=e{} fin=e{} fin_root_matches_own={fin_own:?}",
                    st.slot(), hexs(&st.state_root()), bytes.len(), f.justified.epoch, f.finalized.epoch
                );
            }
        }
    };
    let mut n = 0usize;
    let mut last_epoch = u64::MAX;
    for line in index.lines() {
        let id = line.expect("index line");
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        let bytes = std::fs::read(dir.join("blocks").join(format!("{}.bin", id.trim_start_matches("0x")))).expect("block");
        let env = bloch_pos_node::codec::decode_envelope(&bytes).expect("decode");
        let txs: Vec<PosTransaction> =
            env.body.transactions.iter().map(|b| PosTransaction::from_canonical_bytes(b).expect("tx")).collect();
        let pe = ProposalEnvelope { header: env.header, proposer_sig: env.proposer_sig };
        let slot = pe.header.slot;
        match t.apply_block(&st, &pe, &env.body.attestations, &txs) {
            Ok(s) => st = s,
            Err(e) => {
                println!("HALT block {n} slot {slot} e{}: {e:?}", epoch_of(slot));
                report(&st, n);
                std::process::exit(3);
            }
        }
        n += 1;
        let e = epoch_of(st.slot());
        if e != last_epoch {
            last_epoch = e;
            report(&st, n);
        }
    }
    println!("END blocks={n}");
    report(&st, n);
}
