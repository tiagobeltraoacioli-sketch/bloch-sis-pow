// SPDX-License-Identifier: AGPL-3.0-or-later
//! Does this node hold the KES tree the chain has registered for its
//! validator? (audit L1C-61)
//!
//! Before KES binds, a registered validator signs with its static key and
//! nothing compares the registered tree with `validator.kes`. From the bind
//! on, a node whose file is another tree (or is absent) refuses every duty,
//! and the registration cannot be corrected: it is once-only, and the static
//! key may replace a tree only after it expires. The mistake is made, and can
//! only be repaired cheaply, BEFORE the bind, so that is when the node has to
//! say so: loudly at boot, again every epoch, and in `getkes`.
//!
//! Node-local and read-only: nothing here signs, evolves or moves a key, and
//! nothing is read by consensus.

use super::*;
use bloch_pos_committee::kes::KesPublic;

/// How this node's KES key files relate to its validator's committed entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KesLocalStatus {
    /// The chain has no KES tree for this validator. Nothing to compare.
    NotRegistered,
    /// `validator.kes` is the tree in force on chain.
    Match,
    /// The tree in force is this node's sealed successor
    /// (`validator.kes.next`); the node swaps to it at its next duty.
    MatchSuccessor,
    /// The tree in force is the replaced key this node still keeps
    /// (`validator.kes.retired`, a handover that was reorganized out); the
    /// node swaps back at its next duty.
    MatchReplaced,
    /// The chain has a tree and this node has no `validator.kes`.
    MissingKey,
    /// The chain has a tree and `validator.kes` is a different one.
    Mismatch,
    /// `validator.kes` is the registered tree but was generated for another
    /// validator index; the signer refuses it.
    WrongValidator,
}

impl KesLocalStatus {
    /// The node can sign this validator's KES duties with what it holds.
    pub(crate) fn matches(self) -> bool {
        matches!(self, Self::Match | Self::MatchSuccessor | Self::MatchReplaced)
    }

    /// A registered tree this node cannot sign with.
    pub(crate) fn is_mismatch(self) -> bool {
        matches!(self, Self::MissingKey | Self::Mismatch | Self::WrongValidator)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotRegistered => "not_registered",
            Self::Match => "match",
            Self::MatchSuccessor => "match_successor",
            Self::MatchReplaced => "match_replaced",
            Self::MissingKey => "missing_local_key",
            Self::Mismatch => "mismatch",
            Self::WrongValidator => "wrong_validator",
        }
    }
}

/// The comparison itself, over public values only. `key_for_validator` is
/// whether the key file's own index is this validator's (or automatic).
pub(crate) fn kes_local_status(
    in_force: Option<&KesPublic>,
    key: Option<&KesPublic>,
    key_for_validator: bool,
    next: Option<&KesPublic>,
    replaced: Option<&KesPublic>,
) -> KesLocalStatus {
    let Some(in_force) = in_force else {
        return KesLocalStatus::NotRegistered;
    };
    let Some(key) = key else {
        return KesLocalStatus::MissingKey;
    };
    if key.same_tree(in_force) {
        return if key_for_validator { KesLocalStatus::Match } else { KesLocalStatus::WrongValidator };
    }
    if next.is_some_and(|next| next.same_tree(in_force)) {
        return KesLocalStatus::MatchSuccessor;
    }
    if next.is_none() && replaced.is_some_and(|old| old.same_tree(in_force)) {
        return KesLocalStatus::MatchReplaced;
    }
    KesLocalStatus::Mismatch
}

/// What `getkes` reports about this node's own validator, and what the
/// warning is built from. Public values only: roots and depths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KesLocalView {
    pub(crate) validator: u32,
    pub(crate) status: KesLocalStatus,
    /// `validator.kes`: depth and root.
    pub(crate) local_key: Option<(u8, [u8; 32])>,
    /// `validator.kes.next`, if sealed.
    pub(crate) local_next: Option<(u8, [u8; 32])>,
    /// The tree in force on chain at the head's period.
    pub(crate) chain_key: Option<(u8, [u8; 32])>,
    /// The epoch KES binds (or bound) on chain, once decided.
    pub(crate) enforced_from: Option<u64>,
    /// The head epoch the comparison was made at.
    pub(crate) head_epoch: u64,
}

impl KesLocalView {
    /// The `local` object of `getkes`.
    pub(crate) fn json(&self) -> rpc::Json {
        use rpc::Json;
        let root = |key: &Option<(u8, [u8; 32])>| key.map_or(Json::Null, |(_, root)| Json::hex(&root));
        let depth = |key: &Option<(u8, [u8; 32])>| key.map_or(Json::Null, |(depth, _)| Json::u(u64::from(depth)));
        Json::obj(vec![
            ("validator", Json::u(u64::from(self.validator))),
            ("key_loaded", Json::Bool(self.local_key.is_some())),
            ("local_key_root", root(&self.local_key)),
            ("local_key_depth", depth(&self.local_key)),
            ("local_next_root", root(&self.local_next)),
            ("chain_root", root(&self.chain_key)),
            ("chain_depth", depth(&self.chain_key)),
            // `null` while the chain has nothing to compare with.
            (
                "local_key_matches",
                if self.status == KesLocalStatus::NotRegistered { Json::Null } else { Json::Bool(self.status.matches()) },
            ),
            ("status", Json::s(self.status.as_str())),
        ])
    }

    /// The operator warning, when the registered tree is one this node
    /// cannot sign with.
    pub(crate) fn warning(&self) -> Option<String> {
        if !self.status.is_mismatch() {
            return None;
        }
        let v = self.validator;
        let chain = self.chain_key.map_or_else(String::new, |(depth, root)| {
            format!("tree {} (depth {depth})", crate::codec::hex32(&root))
        });
        let held = match (self.status, self.local_key) {
            (KesLocalStatus::WrongValidator, _) => {
                format!("this node's {} holds that tree but was generated for another validator index", crate::kes_key::FILE_NAME)
            }
            (_, Some((depth, root))) => format!(
                "this node's {} is tree {} (depth {depth})",
                crate::kes_key::FILE_NAME,
                crate::codec::hex32(&root)
            ),
            (_, None) => format!("this node has no {}", crate::kes_key::FILE_NAME),
        };
        let consequence = match self.enforced_from {
            Some(from) if self.head_epoch >= from => format!(
                "KES is enforced since epoch {from}: EVERY DUTY OF THIS VALIDATOR IS REFUSED until the registered key file is restored."
            ),
            Some(from) => format!(
                "KES binds at epoch {from} (head epoch {}): from then on this validator CANNOT SIGN ANY DUTY.",
                self.head_epoch
            ),
            None => "The validator still signs with its static key, but from the KES bind on it CANNOT SIGN ANY DUTY, \
                     and it already counts toward the registered stake that fires the bind."
                .to_string(),
        };
        Some(format!(
            "KES KEY MISMATCH: v{v} has {chain} registered on chain, but {held}. {consequence} Registration is \
             once-only: the static key cannot register another tree until the registered one expires (years), and \
             the only other way out is exit and re-join. Restore the {} that was registered (compare `bloch-pos kes \
             inspect` with `getkes`) BEFORE the bind, and do not register further validators until every unit \
             reports `local_key_matches: true`.",
            crate::kes_key::FILE_NAME
        ))
    }
}

impl Engine {
    /// This node's validator, its key files and its committed KES entry at
    /// the head, compared. `None` for a node that is not a registered
    /// validator on this head (an observer, or a keystore the state does not
    /// know yet).
    pub(crate) fn kes_local_view(&self) -> Option<KesLocalView> {
        let validator = self.duty_index(&self.state)?;
        Some(self.kes_local_view_in(
            validator,
            self.state.kes_roots().get(&validator),
            self.state.kes_enforced_from(),
            epoch_of(self.state.slot()),
        ))
    }

    /// [`Self::kes_local_view`] over the things it reads from the head
    /// state: the validator's committed entry, the bind epoch and the head
    /// epoch. Split out so the comparison can be exercised with a real key
    /// file against an entry the node crate cannot plant in a state.
    pub(crate) fn kes_local_view_in(
        &self,
        validator: u32,
        entry: Option<&bloch_pos_committee::kes::KesEntry>,
        enforced_from: Option<u64>,
        head_epoch: u64,
    ) -> KesLocalView {
        let period = bloch_pos_committee::params::kes_period(head_epoch).unwrap_or(0);
        let in_force = entry.map(|entry| entry.in_force(period));
        let key = self.kes.as_ref().map(|kes| kes.key.public());
        let next = self.kes.as_ref().and_then(|kes| kes.next.as_ref().map(|next| next.public()));
        let replaced = self.kes.as_ref().and_then(|kes| kes.retired.as_ref().map(|old| old.public()));
        let key_for_validator = self.kes.as_ref().is_some_and(|kes| {
            kes.key.index() == validator || kes.key.index() == crate::keys::AUTO_VALIDATOR_INDEX
        });
        let pair = |public: KesPublic| (public.depth, public.root);
        KesLocalView {
            validator,
            status: kes_local_status(in_force.as_ref(), key.as_ref(), key_for_validator, next.as_ref(), replaced.as_ref()),
            local_key: key.map(pair),
            local_next: next.map(pair),
            chain_key: in_force.map(pair),
            enforced_from,
            head_epoch,
        }
    }

    /// `getkes`: the chain's view plus this node's own key comparison
    /// (`local`, `null` on a node that is not a validator on this head).
    pub(crate) fn kes_rpc_json(&self) -> rpc::Json {
        let local = self.kes_local_view().map_or(rpc::Json::Null, |view| view.json());
        match rpc::kes_json(&self.state) {
            rpc::Json::Obj(mut fields) => {
                fields.push(("local".to_string(), local));
                rpc::Json::Obj(fields)
            }
            other => other,
        }
    }

    /// Print the mismatch warning, if there is one; returns whether it did.
    /// Called once at boot and once per wall epoch by the slot loop.
    pub(crate) fn warn_kes_local_mismatch(&self, at_boot: bool) -> bool {
        let Some(view) = self.kes_local_view() else {
            return false;
        };
        let Some(warning) = view.warning() else {
            return false;
        };
        eprintln!("{}{warning}", if at_boot { "AT BOOT: " } else { "" });
        crate::sentinel::note_kes_error("kes_local_key", view.validator, &warning);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(tag: u8) -> KesPublic {
        KesPublic::new(12, [tag; 32], 0)
    }

    #[test]
    fn the_comparison_names_every_case() {
        let chain = tree(0xBB);
        let same_later_start = KesPublic::new(12, [0xBB; 32], 7);
        let other = tree(0x11);
        use KesLocalStatus::*;
        assert_eq!(kes_local_status(None, None, false, None, None), NotRegistered);
        assert_eq!(kes_local_status(None, Some(&other), true, None, None), NotRegistered);
        assert_eq!(kes_local_status(Some(&chain), None, false, None, None), MissingKey);
        assert_eq!(kes_local_status(Some(&chain), Some(&other), true, None, None), Mismatch);
        assert_eq!(kes_local_status(Some(&chain), Some(&same_later_start), true, None, None), Match, "the tree, whatever the start");
        assert_eq!(kes_local_status(Some(&chain), Some(&chain), false, None, None), WrongValidator);
        assert_eq!(kes_local_status(Some(&chain), Some(&other), true, Some(&chain), None), MatchSuccessor);
        assert_eq!(kes_local_status(Some(&chain), Some(&other), true, None, Some(&chain)), MatchReplaced);
        // A depth that differs is another tree even with the same root.
        assert_eq!(kes_local_status(Some(&chain), Some(&KesPublic::new(8, [0xBB; 32], 0)), true, None, None), Mismatch);
        for status in [NotRegistered, Match, MatchSuccessor, MatchReplaced, MissingKey, Mismatch, WrongValidator] {
            assert!(!(status.matches() && status.is_mismatch()));
            assert_eq!(status.is_mismatch(), matches!(status, MissingKey | Mismatch | WrongValidator));
        }
    }

    /// The mainnet shape of the finding, with the node's real signer and a
    /// real key file: the chain registered tree B before the bind, the node
    /// holds tree A. Before the fix every hook accepted this in silence
    /// until the bind refused every duty.
    #[test]
    fn a_registered_tree_the_node_does_not_hold_is_reported_before_the_bind() {
        use crate::keys::{KdfParams, Unlock};
        let (mut engine, dir) = perf_support::proposing_engine();
        let kes_dir = dir.0.join("kes");
        std::fs::create_dir_all(&kes_dir).unwrap();
        let unlock = || Unlock::passphrase_with("kes-local-check", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
        let validator = engine.duty_index(&engine.state).expect("the fixture's validator");
        // No key file, nothing registered: quiet, and `getkes` says so.
        let quiet = engine.kes_local_view().expect("a validator node");
        assert_eq!((quiet.status, quiet.local_key, quiet.chain_key), (KesLocalStatus::NotRegistered, None, None));
        assert!(!engine.warn_kes_local_mismatch(true));
        let mut json = String::new();
        engine.kes_rpc_json().write(&mut json);
        assert!(json.contains("\"registered\":[]"), "the chain view is unchanged: {json}");
        assert!(json.contains("\"local\":{") && json.contains("\"status\":\"not_registered\""), "{json}");

        let on_chain: bloch_pos_committee::kes::KesEntry = KesPublic::new(12, [0xBB; 32], 0).into();
        let today = 9_100u64;
        // The chain has a tree and the node has no validator.kes at all.
        let missing = engine.kes_local_view_in(validator, Some(&on_chain), None, today);
        assert_eq!(missing.status, KesLocalStatus::MissingKey);
        assert!(missing.warning().is_some());

        // The node holds another tree (a restored backup, a copied data dir).
        let held = crate::kes_key::KesKey::generate(validator, 2, |_| {}).unwrap();
        held.save(&kes_dir, &unlock()).unwrap();
        let held_public = held.public();
        engine.kes = Some(KesSigner::new(held, kes_dir, unlock()));
        let before_bind = engine.kes_local_view_in(validator, Some(&on_chain), None, today);
        assert_eq!(before_bind.status, KesLocalStatus::Mismatch);
        assert_eq!(before_bind.local_key, Some((held_public.depth, held_public.root)));
        assert_eq!(before_bind.chain_key, Some((12, [0xBB; 32])));
        let warning = before_bind.warning().expect("reported before the bind, while it can still be repaired");
        assert!(warning.contains(&crate::codec::hex32(&held_public.root)) && warning.contains(&crate::codec::hex32(&[0xBB; 32])), "{warning}");
        let mut json = String::new();
        before_bind.json().write(&mut json);
        assert!(json.contains("\"local_key_matches\":false"), "{json}");

        // The registered tree is the one the node holds: quiet.
        let own: bloch_pos_committee::kes::KesEntry = KesPublic::new(held_public.depth, held_public.root, 0).into();
        let matching = engine.kes_local_view_in(validator, Some(&own), None, today);
        assert_eq!(matching.status, KesLocalStatus::Match);
        assert_eq!(matching.warning(), None);
        // Still nothing registered on this head: the node-level call is quiet.
        assert_eq!(engine.kes_local_view().unwrap().status, KesLocalStatus::NotRegistered);
        assert!(!engine.warn_kes_local_mismatch(false));
    }

    fn view(status: KesLocalStatus, local: Option<u8>, enforced_from: Option<u64>) -> KesLocalView {
        KesLocalView {
            validator: 13,
            status,
            local_key: local.map(|tag| (12, [tag; 32])),
            local_next: None,
            chain_key: (status != KesLocalStatus::NotRegistered).then_some((12, [0xBB; 32])),
            enforced_from,
            head_epoch: 8_800,
        }
    }

    #[test]
    fn only_a_registered_tree_the_node_cannot_sign_with_warns() {
        use KesLocalStatus::*;
        for quiet in [NotRegistered, Match, MatchSuccessor, MatchReplaced] {
            assert_eq!(view(quiet, Some(0xBB), None).warning(), None, "{quiet:?}");
        }
        let before = view(Mismatch, Some(0x11), None).warning().expect("mismatch warns");
        assert!(before.starts_with("KES KEY MISMATCH: v13 has tree bbbbbbbb"), "{before}");
        assert!(before.contains("is tree 11111111"), "{before}");
        assert!(before.contains("still signs with its static key") && before.contains("CANNOT SIGN ANY DUTY"), "{before}");
        assert!(before.contains("once-only"), "{before}");
        let missing = view(MissingKey, None, Some(8_900)).warning().expect("missing key warns");
        assert!(missing.contains("this node has no validator.kes"), "{missing}");
        assert!(missing.contains("KES binds at epoch 8900"), "{missing}");
        let bound = view(Mismatch, Some(0x11), Some(8_700)).warning().unwrap();
        assert!(bound.contains("enforced since epoch 8700") && bound.contains("EVERY DUTY OF THIS VALIDATOR IS REFUSED"), "{bound}");
        assert!(view(WrongValidator, Some(0xBB), None).warning().unwrap().contains("another validator index"));
    }

    #[test]
    fn getkes_local_reports_roots_and_the_match() {
        let mut out = String::new();
        view(KesLocalStatus::Mismatch, Some(0x11), None).json().write(&mut out);
        for field in [
            "\"validator\":13",
            "\"key_loaded\":true",
            "\"local_key_matches\":false",
            "\"status\":\"mismatch\"",
            "\"local_key_depth\":12",
            "\"chain_depth\":12",
        ] {
            assert!(out.contains(field), "{field} missing from {out}");
        }
        assert!(out.contains(&format!("\"local_key_root\":\"{}\"", crate::codec::hex32(&[0x11; 32]))), "{out}");
        assert!(out.contains(&format!("\"chain_root\":\"{}\"", crate::codec::hex32(&[0xBB; 32]))), "{out}");
        let mut out = String::new();
        view(KesLocalStatus::Match, Some(0xBB), None).json().write(&mut out);
        assert!(out.contains("\"local_key_matches\":true") && out.contains("\"status\":\"match\""), "{out}");
        let mut out = String::new();
        view(KesLocalStatus::NotRegistered, Some(0x11), None).json().write(&mut out);
        assert!(out.contains("\"local_key_matches\":null") && out.contains("\"chain_root\":null"), "{out}");
        let mut out = String::new();
        view(KesLocalStatus::MissingKey, None, None).json().write(&mut out);
        assert!(out.contains("\"key_loaded\":false") && out.contains("\"local_key_root\":null"), "{out}");
    }
}
