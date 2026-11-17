// SPDX-License-Identifier: AGPL-3.0-or-later

//! Replay a log and check the index against consensus, block by block.
//!
//! The per-block ledger cross-check in `Index::try_apply` compares output
//! counts, because that is what a serving index can afford. This audit compares
//! the values, owners, balances and history as well, and reconciles the native
//! L2 escrow, so a kind whose effect is modelled wrongly cannot pass by keeping
//! the count right.

use std::collections::BTreeMap;
use std::path::Path;

use crate::index::Index;
use crate::log::LogReader;
use crate::model::TxRow;
use crate::{hex32, opening_ledger};

/// Every kind a production L2 needs the index to follow.
const L2_KINDS: [&str; 3] = ["l2_deposit", "l2_data_availability", "l2_withdraw_claim"];

#[derive(Default, Debug)]
pub struct AuditReport {
    pub blocks: u64,
    pub comparisons: u64,
    pub tip_slot: u64,
    pub tip_block: [u8; 32],
    pub live_outputs: usize,
    pub unspent_sat: u128,
    pub scripts_with_balance: usize,
    /// Transactions by kind name.
    pub kinds: BTreeMap<String, u64>,
    pub escrow_in_sat: u128,
    pub escrow_out_sat: u128,
    pub fees_on_l2_kinds_sat: u128,
    pub escrow_opening_sat: u128,
    pub escrow_consensus_sat: u128,
}

impl AuditReport {
    pub fn describe(&self) -> String {
        let mut text = format!(
            "audit-ledger PASS: {} blocks, {} full comparisons against the replayed state\n\
             tip slot {} block {}\n\
             live outputs {}, unspent {} sat, scripts with a balance {}\n\
             L2 escrow: opening {} + in {} - out {} = consensus {} sat; fees on L2 kinds {} sat\n",
            self.blocks, self.comparisons, self.tip_slot, hex32(&self.tip_block), self.live_outputs,
            self.unspent_sat, self.scripts_with_balance, self.escrow_opening_sat, self.escrow_in_sat,
            self.escrow_out_sat, self.escrow_consensus_sat, self.fees_on_l2_kinds_sat,
        );
        for (kind, count) in &self.kinds {
            text.push_str(&format!("  {kind}: {count}\n"));
        }
        text
    }

    /// Refuse a log that did not exercise the L2 kinds: a clean audit of a
    /// chain with no claim says nothing about claims.
    pub fn require_all_l2_kinds(&self) -> Result<(), String> {
        let settled = self.kinds.get("l2_settlement").copied().unwrap_or(0)
            + self.kinds.get("l2_settlement_async").copied().unwrap_or(0);
        if settled == 0 {
            return Err("the log holds no L2 settlement".into());
        }
        for kind in L2_KINDS {
            if self.kinds.get(kind).copied().unwrap_or(0) == 0 {
                return Err(format!("the log holds no {kind}"));
            }
        }
        Ok(())
    }
}

/// `inputs + escrow_out == outputs + escrow_in + stake + fee` for one L2 row.
fn check_conservation(t: &TxRow) -> Result<(), String> {
    let inputs: u128 = t.input_values.iter().map(|u| u.value_sat as u128).sum();
    let outputs: u128 = t.outputs.iter().map(|(value, _)| *value as u128).sum();
    let fee = t.fee_sat.ok_or_else(|| format!("{} has no fee", hex32(&t.txid)))?;
    if inputs + t.l2_escrow_out_sat != outputs + t.l2_escrow_in_sat + t.stake_sat + fee {
        return Err(format!(
            "{} ({}): inputs {inputs} + escrow out {} != outputs {outputs} + escrow in {} + fee {fee}",
            hex32(&t.txid), t.kind.name(), t.l2_escrow_out_sat, t.l2_escrow_in_sat));
    }
    Ok(())
}

/// Replay `log` from genesis. Compares the whole index with the consensus state
/// every `every` blocks, after every block holding an L2 kind, and at the tip.
pub fn audit_log(log: &Path, manifest: &Path, carryover: &Path, every: u64) -> Result<AuditReport, String> {
    let (manifest, genesis_id, outputs) =
        opening_ledger(manifest, carryover).map_err(|e| format!("opening ledger: {e}"))?;
    let mut reader = LogReader::open(log).map_err(|e| format!("opening log: {e}"))?;
    let mut ix = Index::new(genesis_id, outputs, 128);
    let genesis_state = manifest.genesis_state();
    let mut report = AuditReport {
        escrow_opening_sat: genesis_state.l2_settlement().map_or(0, |l2| l2.escrow_sat()),
        ..AuditReport::default()
    };
    ix.replay = Some(genesis_state);
    ix.audit_against_replay().map_err(|e| format!("at genesis: {e}"))?;
    report.comparisons += 1;
    let every = every.max(1);
    for frame in 0..reader.len() {
        let envelope = reader.envelope_at(frame).map_err(|e| format!("frame {frame}: {e}"))?;
        let first_row = ix.txs.len();
        ix.try_apply(&envelope, reader.frames()[frame].len)
            .map_err(|e| format!("slot {}: {e}", envelope.header.slot))?;
        report.blocks += 1;
        let mut has_l2 = false;
        for row in &ix.txs[first_row..] {
            *report.kinds.entry(row.kind.name()).or_insert(0) += 1;
            if row.kind.is_l2() {
                has_l2 = true;
                check_conservation(row)?;
                report.escrow_in_sat += row.l2_escrow_in_sat;
                report.escrow_out_sat += row.l2_escrow_out_sat;
                report.fees_on_l2_kinds_sat += row.fee_sat.unwrap_or(0);
            }
        }
        if has_l2 || report.blocks % every == 0 || frame + 1 == reader.len() {
            ix.audit_against_replay()
                .map_err(|e| format!("after slot {}: {e}", envelope.header.slot))?;
            report.comparisons += 1;
            let escrow = ix.replay.as_ref().and_then(|s| s.l2_settlement()).map_or(0, |l2| l2.escrow_sat());
            if report.escrow_opening_sat + report.escrow_in_sat != escrow + report.escrow_out_sat {
                return Err(format!(
                    "after slot {}: escrow opening {} + in {} - out {} != consensus {escrow}",
                    envelope.header.slot, report.escrow_opening_sat, report.escrow_in_sat, report.escrow_out_sat));
            }
            report.escrow_consensus_sat = escrow;
        }
    }
    let tip = ix.tip();
    report.tip_slot = tip.slot;
    report.tip_block = tip.block_id;
    report.live_outputs = ix.utxo.len();
    report.unspent_sat = ix.eutxo_total_sat();
    report.scripts_with_balance = ix.balance.values().filter(|v| **v > 0).count();
    Ok(report)
}
