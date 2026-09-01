// SPDX-License-Identifier: AGPL-3.0-or-later
//! Print the Genesis-4 fleet memory projection, recomputed from the live
//! fleet's own kernel-measured numbers.
//!
//!   cargo run -p bloch-memoria-projecao                 # default snapshot
//!   cargo run -p bloch-memoria-projecao -- --reserve 2048
//!   BLOCH_FLEET_OBSERVATIONS=/path/to.tsv cargo run -p bloch-memoria-projecao
//!
//! Refresh the snapshot first, read-only, with scripts/fleet-memory-observe.sh.

use bloch_memoria_projecao::{project, Snapshot, RESERVE_MIB_DEFAULT};

fn main() -> std::process::ExitCode {
    let mut reserve = RESERVE_MIB_DEFAULT;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reserve" | "--reserve-mib" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<f64>().ok()) {
                    Some(v) if v >= 0.0 => reserve = v,
                    _ => {
                        eprintln!("memoria-projecao: --reserve needs a non-negative number of MiB");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            "-h" | "--help" => {
                println!(
                    "memoria-projecao [--reserve MIB]\n\n\
                     Recomputes the Genesis-4 box-exhaustion dates from\n\
                     scripts/fleet-memory-observations.tsv. Refresh that file with\n\
                     scripts/fleet-memory-observe.sh (read-only; it touches no validator).\n\
                     BLOCH_FLEET_OBSERVATIONS overrides the snapshot path."
                );
                return std::process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("memoria-projecao: unknown argument {other:?}");
                return std::process::ExitCode::from(2);
            }
        }
        i += 1;
    }

    let snap = match Snapshot::load_default() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("memoria-projecao: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    print!("{}", project(&snap, reserve).report(&snap));
    std::process::ExitCode::SUCCESS
}
