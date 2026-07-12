// SPDX-License-Identifier: MIT OR Apache-2.0
//! The checkpoint/anchor SDK: the [`Anchoring`] trait and a concrete
//! [`AnchorClient`] implementing it against the Bloch JSON-RPC.
//!
//! ## The DA boundary (read this)
//!
//! > **Bloch anchors *commitments*, not bulk data.** Your data availability is
//! > **yours** (roadmap §2.2). Put your blocks / batches / proofs in your own DA
//! > layer (an L2 DA, an external DA network, IPFS, S3, a validity-proof system,
//! > whatever) and anchor only the 32-byte [`Commitment`] that fingerprints
//! > them. Bloch gives that digest an ordering, a timestamp, and PoW-depth
//! > immutability — and **settles nothing about your system's internal
//! > validity.** Bring your own architecture.
//!
//! ## Signing is yours too
//!
//! This SDK is agnostic about *how* you fund and sign the anchor transaction.
//! It builds the anchor's carrier outputs (via the [`crate::convention`]) and
//! hands them to a [`TxSigner`] you provide. In production that signer wraps
//! `bloch-crypto`'s `WalletCore` (coin selection via `getutxos`, hybrid
//! Falcon-1024 ‖ ML-DSA-65 signing — roadmap §1.4) to emit the exact consensus
//! wire bytes. Here we ship a [`MockSigner`] so the flow runs offline.

use crate::anchor::{Anchor, InclusionReference, Txid};
use crate::commitment::Commitment;
use crate::convention::{self, AnchorOutput, DEFAULT_DUST_SATS};
use crate::error::{AnchorError, Result};
use crate::rpc::{BlochRpc, RpcTransport};

/// Builds a funded, signed raw transaction that includes the given anchor
/// carrier outputs. Implemented by *your* wallet.
///
/// The signer owns coin selection, change, fees (in BLCH), and the hybrid
/// signature. It MUST place the `anchor_outputs` in the transaction in order and
/// contiguously (the [`crate::convention`] decoder relies on the second carrier
/// immediately following the magic-prefixed first).
pub trait TxSigner {
    /// Return the hex-encoded raw transaction ready for `sendrawtransaction`.
    fn build_anchor_tx(&self, anchor_outputs: &[AnchorOutput]) -> Result<String>;
}

/// How long to poll while waiting for confirmations.
#[derive(Clone, Copy, Debug)]
pub struct WaitPolicy {
    /// Max number of polls before giving up.
    pub max_polls: u32,
    /// Delay between polls, in milliseconds.
    pub poll_interval_ms: u64,
}

impl Default for WaitPolicy {
    fn default() -> Self {
        // ~10 minutes of patience at 5s cadence — tune per your block time.
        WaitPolicy {
            max_polls: 120,
            poll_interval_ms: 5_000,
        }
    }
}

/// The core anchoring capability any L2 / finality gadget / RWA system needs.
pub trait Anchoring {
    /// Submit a commitment: build → sign → `sendrawtransaction`. Returns the
    /// anchor at `0` confirmations (still in mempool).
    fn submit_commitment(&self, commitment: &Commitment) -> Result<Anchor>;

    /// Block until the anchor tx has at least `n` confirmations, polling per
    /// `policy`. Returns the updated [`Anchor`].
    fn wait_for_confirmations(&self, txid: &Txid, n: u32, policy: WaitPolicy) -> Result<Anchor>;

    /// Retrieve the anchor tx by txid and recover + verify its commitment.
    fn prove_by_txid(&self, txid: &Txid) -> Result<InclusionReference>;

    /// Retrieve anchors mined at a specific block height. Requires a
    /// height→txids resolver (see [`AnchorClient::prove_by_height`]).
    fn prove_by_height(&self, height: u64, txids: &[Txid]) -> Result<Vec<InclusionReference>>;
}

/// Concrete anchoring client: a [`BlochRpc`] transport + a [`TxSigner`].
pub struct AnchorClient<T: RpcTransport, S: TxSigner> {
    rpc: BlochRpc<T>,
    signer: S,
    dust: u64,
}

impl<T: RpcTransport, S: TxSigner> AnchorClient<T, S> {
    /// Build a client with the default per-carrier dust burn.
    pub fn new(rpc: BlochRpc<T>, signer: S) -> Self {
        AnchorClient {
            rpc,
            signer,
            dust: DEFAULT_DUST_SATS,
        }
    }

    /// Override the per-carrier dust value.
    pub fn with_dust(mut self, dust: u64) -> Self {
        self.dust = dust;
        self
    }

    /// Access the RPC client (e.g. to read the tip or drive a mock).
    pub fn rpc(&self) -> &BlochRpc<T> {
        &self.rpc
    }

    fn build_reference(&self, txid: &Txid) -> Result<InclusionReference> {
        let tx = self.rpc.get_transaction(txid)?;
        let (commitment, carriers) = convention::decode(&tx.output_scripts)?;
        Ok(InclusionReference {
            commitment,
            anchor: Anchor {
                txid: *txid,
                height: tx.height,
                confirmations: tx.confirmations,
            },
            carrier_scripts: carriers,
        })
    }
}

impl<T: RpcTransport, S: TxSigner> Anchoring for AnchorClient<T, S> {
    fn submit_commitment(&self, commitment: &Commitment) -> Result<Anchor> {
        let outputs = convention::encode(commitment, self.dust);
        let raw_hex = self.signer.build_anchor_tx(&outputs)?;
        let txid = self.rpc.send_raw_transaction(&raw_hex)?;
        Ok(Anchor {
            txid,
            height: None,
            confirmations: 0,
        })
    }

    fn wait_for_confirmations(&self, txid: &Txid, n: u32, policy: WaitPolicy) -> Result<Anchor> {
        let mut last_seen = 0u64;
        for _ in 0..policy.max_polls {
            let status = self.rpc.get_tx_status(txid)?;
            last_seen = status.confirmations;
            if status.confirmations >= n as u64 {
                return Ok(Anchor {
                    txid: *txid,
                    height: status.height,
                    confirmations: status.confirmations,
                });
            }
            if policy.poll_interval_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(policy.poll_interval_ms));
            }
        }
        Err(AnchorError::ConfirmationTimeout {
            attempts: policy.max_polls,
            wanted: n,
            seen: last_seen,
        })
    }

    fn prove_by_txid(&self, txid: &Txid) -> Result<InclusionReference> {
        self.build_reference(txid)
    }

    fn prove_by_height(&self, height: u64, txids: &[Txid]) -> Result<Vec<InclusionReference>> {
        // Bloch's read RPC is txid-addressed; the caller supplies the candidate
        // txids at `height` (e.g. from `gettxsbyblock`/`getblockbyheight`, or
        // their own index). We verify each actually carries an anchor and sits
        // at the requested height.
        let mut out = Vec::new();
        for txid in txids {
            let reference = self.build_reference(txid)?;
            if reference.anchor.height == Some(height) {
                out.push(reference);
            }
        }
        Ok(out)
    }
}

/// A deterministic no-crypto signer for the reference example and tests.
///
/// It emits a syntactically-valid [`crate::tx::Transaction`] hex carrying the
/// anchor outputs (plus a placeholder change output), but it does **no real
/// coin selection and no signing**. NEVER use it against a live node — swap in a
/// `bloch-crypto` `WalletCore`-backed signer.
pub struct MockSigner {
    /// A fake 20-byte change address to make the tx look realistic.
    pub change_script: [u8; 20],
    /// Fake change value.
    pub change_value: u64,
}

impl Default for MockSigner {
    fn default() -> Self {
        MockSigner {
            change_script: [0x11; 20],
            change_value: 1000,
        }
    }
}

impl TxSigner for MockSigner {
    fn build_anchor_tx(&self, anchor_outputs: &[AnchorOutput]) -> Result<String> {
        use crate::tx::{Transaction, TxInput, TxOutput};

        let mut outputs = vec![TxOutput {
            value: self.change_value,
            script_pubkey: self.change_script.to_vec(),
        }];
        for a in anchor_outputs {
            outputs.push(TxOutput {
                value: a.value,
                script_pubkey: a.script_pubkey.to_vec(),
            });
        }

        // A single placeholder input; a real signer selects funded UTXOs.
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0xEE; 32],
                prev_index: 0,
                script_sig: vec![], // "signed" is a no-op here
                sequence: 0xffff_ffff,
            }],
            outputs,
            locktime: 0,
        };
        Ok(tx.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::MockTransport;

    fn client() -> AnchorClient<MockTransport, MockSigner> {
        AnchorClient::new(BlochRpc::new(MockTransport::new(500)), MockSigner::default())
    }

    #[test]
    fn full_submit_wait_prove_flow() {
        let c = client();
        let commitment = Commitment::hash_payload(b"L2 state root @ epoch 3");

        // Submit.
        let anchor = c.submit_commitment(&commitment).unwrap();
        assert_eq!(anchor.confirmations, 0);

        // Confirm (mock mines on submit → already 1 conf; no sleeping).
        let policy = WaitPolicy {
            max_polls: 3,
            poll_interval_ms: 0,
        };
        let confirmed = c
            .wait_for_confirmations(&anchor.txid, 1, policy)
            .unwrap();
        assert!(confirmed.has_confirmations(1));

        // Prove by txid — recovers the exact commitment.
        let reference = c.prove_by_txid(&anchor.txid).unwrap();
        assert_eq!(reference.commitment, commitment);
        assert_eq!(reference.carrier_scripts.len(), 2);
    }

    #[test]
    fn wait_times_out_when_unconfirmed() {
        let c = client();
        let unknown = Txid::from_bytes([7u8; 32]);
        let policy = WaitPolicy {
            max_polls: 2,
            poll_interval_ms: 0,
        };
        let err = c.wait_for_confirmations(&unknown, 5, policy).unwrap_err();
        assert!(matches!(err, AnchorError::ConfirmationTimeout { .. }));
    }

    #[test]
    fn prove_by_height_filters() {
        let c = client();
        let commitment = Commitment::hash_payload(b"batch #99");
        let anchor = c.submit_commitment(&commitment).unwrap();
        // Learn the mined height.
        let reference = c.prove_by_txid(&anchor.txid).unwrap();
        let h = reference.anchor.height.unwrap();

        let hits = c.prove_by_height(h, &[anchor.txid]).unwrap();
        assert_eq!(hits.len(), 1);
        let misses = c.prove_by_height(h + 999, &[anchor.txid]).unwrap();
        assert!(misses.is_empty());
    }
}
