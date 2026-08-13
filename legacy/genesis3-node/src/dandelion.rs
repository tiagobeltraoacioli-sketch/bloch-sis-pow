//! Dandelion++ transaction-relay privacy (Coherence P3).
//!
//! Even with shielded amounts, plain diffusion gossip leaks *who* originated a
//! transaction (first node to broadcast ≈ the source IP). Dandelion++ fixes the
//! metadata leak: a new tx first travels a **stem** — relayed to a single peer,
//! hop by hop — and only later **fluffs** into normal flood gossip, so the fluff
//! origin is decoupled from the true source.
//!
//! This module is the pure routing core (decision + epoch stem-successor + the
//! anti-blackhole embargo timer), unit-tested without the network. Wiring it into
//! the gossip/relay path is the integration step.

use std::collections::HashMap;

/// What to do with a stem-phase transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route<P> {
    /// Relay to exactly one peer (privacy-preserving stem hop).
    Stem(P),
    /// Broadcast normally (diffusion) — the tx "fluffs".
    Fluff,
}

#[derive(Debug, Clone)]
pub struct DandelionConfig {
    /// Per-relay probability of switching stem → fluff (Dandelion++ `q`).
    pub fluff_probability: f64,
    /// Fluff a stemmed tx if it isn't seen fluffing within this many ms
    /// (anti-blackhole: a malicious stem relay can't silently drop it).
    pub embargo_ms: u64,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        // ~10% fluff per hop → an ~10-hop expected stem; 10s embargo.
        Self { fluff_probability: 0.1, embargo_ms: 10_000 }
    }
}

/// Dandelion++ router. `P` is the peer type (e.g. a libp2p PeerId).
pub struct Dandelion<P: Clone + Eq + std::hash::Hash> {
    cfg: DandelionConfig,
    epoch_seed: u64,
    stem_successor: Option<P>,
    /// Stemmed txs awaiting fluff confirmation → deadline (ms).
    embargo: HashMap<[u8; 32], u64>,
}

impl<P: Clone + Eq + std::hash::Hash> Dandelion<P> {
    pub fn new(cfg: DandelionConfig) -> Self {
        Self { cfg, epoch_seed: 0, stem_successor: None, embargo: HashMap::new() }
    }

    pub fn stem_successor(&self) -> Option<&P> {
        self.stem_successor.as_ref()
    }

    /// Begin a new epoch: pick ONE stem successor from `outbound` peers,
    /// deterministically from `seed`. A single per-epoch successor (rather than a
    /// fresh choice per tx) is what resists intersection/graph-learning attacks.
    pub fn new_epoch(&mut self, outbound: &[P], seed: u64) {
        self.epoch_seed = seed;
        self.stem_successor = if outbound.is_empty() {
            None
        } else {
            Some(outbound[(seed as usize) % outbound.len()].clone())
        };
    }

    /// Route a local or stem-received tx. Fluffs with probability `q` (a coin
    /// derived from the tx id + epoch seed) or when there is no stem successor;
    /// otherwise relays one stem hop and arms the tx's embargo timer.
    pub fn route(&mut self, tx_id: &[u8; 32], now_ms: u64) -> Route<P> {
        let fluff = self.stem_successor.is_none() || self.coin(tx_id) < self.cfg.fluff_probability;
        if fluff {
            self.embargo.remove(tx_id);
            Route::Fluff
        } else {
            self.embargo.entry(*tx_id).or_insert(now_ms + self.cfg.embargo_ms);
            Route::Stem(self.stem_successor.clone().expect("checked Some"))
        }
    }

    /// A tx observed fluffing (seen via diffusion) → cancel its embargo.
    pub fn observed_fluff(&mut self, tx_id: &[u8; 32]) {
        self.embargo.remove(tx_id);
    }

    /// Stemmed txs whose embargo has expired → must be fluffed now. Draining.
    pub fn expired(&mut self, now_ms: u64) -> Vec<[u8; 32]> {
        let due: Vec<[u8; 32]> = self
            .embargo
            .iter()
            .filter(|(_, &deadline)| deadline <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            self.embargo.remove(id);
        }
        due
    }

    pub fn pending_embargo(&self) -> usize {
        self.embargo.len()
    }

    /// Deterministic per-tx coin in [0,1) from `tx_id ⊕ epoch_seed` (splitmix64).
    fn coin(&self, tx_id: &[u8; 32]) -> f64 {
        let mut x = self.epoch_seed;
        for chunk in tx_id.chunks(8) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            x ^= u64::from_le_bytes(b);
        }
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The action the network loop should take for a transaction (Dandelion++).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAction<P> {
    /// Relay to exactly ONE peer (stem hop) — a unicast send. The unicast
    /// transport is the remaining integration piece; gossipsub is broadcast-only.
    StemTo(P, [u8; 32]),
    /// Broadcast normally (diffusion) — a gossipsub publish (works today).
    Fluff([u8; 32]),
}

/// Integration adapter over `Dandelion`: the network loop calls `on_tx`/`tick`
/// and executes the returned `RelayAction`s (Fluff → gossipsub publish;
/// StemTo → unicast to the one peer). Keeps the routing state (epoch successor +
/// embargo) out of the network loop.
pub struct DandelionRelay<P: Clone + Eq + std::hash::Hash> {
    inner: Dandelion<P>,
}

impl<P: Clone + Eq + std::hash::Hash> DandelionRelay<P> {
    pub fn new(cfg: DandelionConfig) -> Self {
        Self { inner: Dandelion::new(cfg) }
    }

    /// Reselect the epoch's single stem successor from the current outbound peers.
    pub fn rotate_epoch(&mut self, outbound: &[P], seed: u64) {
        self.inner.new_epoch(outbound, seed);
    }

    /// Route a locally-originated or stem-received tx into a concrete action.
    pub fn on_tx(&mut self, tx_id: [u8; 32], now_ms: u64) -> RelayAction<P> {
        match self.inner.route(&tx_id, now_ms) {
            Route::Stem(p) => RelayAction::StemTo(p, tx_id),
            Route::Fluff => RelayAction::Fluff(tx_id),
        }
    }

    /// A tx observed fluffing on the network → cancel its embargo.
    pub fn observed_fluff(&mut self, tx_id: &[u8; 32]) {
        self.inner.observed_fluff(tx_id);
    }

    /// Embargo tick: stemmed txs past their deadline that must now be fluffed.
    pub fn tick(&mut self, now_ms: u64) -> Vec<RelayAction<P>> {
        self.inner.expired(now_ms).into_iter().map(RelayAction::Fluff).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txid(b: u8) -> [u8; 32] { [b; 32] }
    fn peers(n: usize) -> Vec<u32> { (0..n as u32).collect() }

    #[test]
    fn no_successor_always_fluffs() {
        let mut d = Dandelion::<u32>::new(DandelionConfig::default());
        // no epoch / no peers → no stem successor
        assert_eq!(d.route(&txid(1), 0), Route::Fluff);
        assert_eq!(d.pending_embargo(), 0);
    }

    #[test]
    fn epoch_picks_deterministic_successor() {
        let mut d = Dandelion::new(DandelionConfig::default());
        d.new_epoch(&peers(4), 42);
        assert_eq!(d.stem_successor(), Some(&(42u32 % 4)));
        // same seed → same successor (stable within an epoch)
        let mut d2 = Dandelion::new(DandelionConfig::default());
        d2.new_epoch(&peers(4), 42);
        assert_eq!(d.stem_successor(), d2.stem_successor());
    }

    #[test]
    fn stems_and_arms_embargo_then_expires() {
        // fluff_probability 0 → always stem (when a successor exists)
        let mut d = Dandelion::new(DandelionConfig { fluff_probability: 0.0, embargo_ms: 100 });
        d.new_epoch(&peers(3), 1);
        let t = txid(7);
        assert!(matches!(d.route(&t, 1_000), Route::Stem(_)));
        assert_eq!(d.pending_embargo(), 1);
        // not yet due
        assert!(d.expired(1_050).is_empty());
        // due → fluff it, embargo cleared
        assert_eq!(d.expired(1_100), vec![t]);
        assert_eq!(d.pending_embargo(), 0);
    }

    #[test]
    fn observed_fluff_cancels_embargo() {
        let mut d = Dandelion::new(DandelionConfig { fluff_probability: 0.0, embargo_ms: 100 });
        d.new_epoch(&peers(3), 1);
        let t = txid(9);
        let _ = d.route(&t, 0);
        assert_eq!(d.pending_embargo(), 1);
        d.observed_fluff(&t);
        assert_eq!(d.pending_embargo(), 0);
        assert!(d.expired(1_000).is_empty());
    }

    #[test]
    fn fluff_probability_one_always_fluffs() {
        let mut d = Dandelion::new(DandelionConfig { fluff_probability: 1.0, embargo_ms: 100 });
        d.new_epoch(&peers(3), 1);
        for b in 0..20u8 {
            assert_eq!(d.route(&txid(b), 0), Route::Fluff);
        }
        assert_eq!(d.pending_embargo(), 0);
    }

    #[test]
    fn relay_adapter_maps_actions_and_fluffs_on_embargo() {
        // Always-stem config so on_tx yields StemTo and arms the embargo.
        let mut rly = DandelionRelay::new(DandelionConfig { fluff_probability: 0.0, embargo_ms: 100 });
        rly.rotate_epoch(&peers(3), 1);
        let t = txid(5);
        match rly.on_tx(t, 1_000) {
            RelayAction::StemTo(_, id) => assert_eq!(id, t),
            other => panic!("expected StemTo, got {other:?}"),
        }
        // Not yet due → no forced fluff.
        assert!(rly.tick(1_050).is_empty());
        // Past the embargo → the network loop is told to fluff it.
        assert_eq!(rly.tick(1_100), vec![RelayAction::Fluff(t)]);
        // Observing a fluff cancels a pending embargo.
        let t2 = txid(6);
        let _ = rly.on_tx(t2, 2_000);
        rly.observed_fluff(&t2);
        assert!(rly.tick(9_999).is_empty());
    }

    #[test]
    fn relay_adapter_fluffs_when_no_successor() {
        let mut rly = DandelionRelay::<u32>::new(DandelionConfig::default());
        // No epoch set → no stem successor → must fluff.
        assert_eq!(rly.on_tx(txid(1), 0), RelayAction::Fluff(txid(1)));
    }
}
