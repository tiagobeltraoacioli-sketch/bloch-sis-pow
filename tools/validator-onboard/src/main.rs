// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-onboard` — the newcomer's deposit-construction path.
//!
//! Scope, stated up front, because the gap between what this builds and what
//! a validator bond ought to be is the whole finding:
//!
//! At the release tag `g4-node-20260901` the chain's deposit is
//! `PosTransaction::Deposit`, wire tag `0x02`. Its apply arm
//! (`transition.rs::apply_transaction`) performs FOUR checks — key not
//! already registered, amount >= MIN_DEPOSIT_SAT, amount <= the 1% cap, and
//! nothing else. It does NOT call `staking::validate_deposit`, so there is no
//! proof-of-possession check. It consumes NO inputs, so the stake is minted
//! rather than bonded. It does not constrain `withdrawal_credentials`, which
//! is an unvalidated `Vec<u8>`.
//!
//! This tool therefore does two separable things:
//!
//!   1. Builds the `0x02` deposit the shipped chain accepts, and labels it
//!      honestly in its own output (`unfunded`, `unauthenticated`).
//!   2. Derives and CHECKS the key and address material that the `0x02` arm
//!      does not check — the part where a stranger loses money — and computes
//!      the proof-of-possession over `staking::DepositTx::signing_root`, which
//!      the released crate already defines even though the released apply arm
//!      never verifies it. That PoP is carried in the plan so the artifact is
//!      forward-compatible with the funded, authenticated shape being ported
//!      separately.
//!
//! It assigns NO wire tag to the funded shape. The requirement is stated in
//! `deposit --funded`'s refusal and the number is the founder's to pick.

use std::path::PathBuf;

use bloch_crypto::address::{Address, Network};
use bloch_pos_committee::staking::{
    self, DepositTx, HYBRID_PK_BYTES, MIN_DEPOSIT_SAT, SUITE_MLDSA65_FALCON1024,
};
use bloch_pos_committee::transition::PosTransaction;
use sha3::{Digest, Sha3_256};

// ── Errors ──────────────────────────────────────────────────────────────────
// Every refusal names the check it failed and what the operator should do.
// A tool that says "invalid" teaches a stranger nothing and gets worked
// around; the working-around is the accident.

#[derive(Debug)]
struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

macro_rules! refuse {
    ($($a:tt)*) => { return Err(Refusal(format!($($a)*))) };
}

type R<T> = Result<T, Refusal>;

// ── Keystore (public halves only unless a PoP is asked for) ─────────────────
// `bloch-pos-node` is a binary crate with no lib target, so `keys::Keystore`
// cannot be imported. The on-disk format is re-read here against the
// authoritative writer (`crates/bloch-pos-node/src/keys.rs`):
//   "BPOSKEY1" ‖ index:u32le ‖ len:u32le‖pubkey ‖ len:u32le‖secret ‖ seed[32]

const KEYSTORE_MAGIC: &[u8; 8] = b"BPOSKEY1";

struct Keystore {
    index: u32,
    pubkey: Vec<u8>,
    secret: Vec<u8>,
    randao_seed: [u8; 32],
}

impl Keystore {
    fn load(dir: &PathBuf) -> R<Keystore> {
        let path = dir.join("validator.key");
        let b = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => refuse!(
                "cannot read {}: {e}\n  \
                 Generate a throwaway one with: bloch-pos keygen --dir <dir> --index <i>",
                path.display()
            ),
        };
        let mut o = 0usize;
        let take = |b: &[u8], o: &mut usize, n: usize, what: &str| -> R<Vec<u8>> {
            if b.len() < *o + n {
                refuse!("truncated keystore: wanted {n} bytes of {what} at offset {o}");
            }
            let v = b[*o..*o + n].to_vec();
            *o += n;
            Ok(v)
        };
        let magic = take(&b, &mut o, 8, "magic")?;
        if magic.as_slice() != KEYSTORE_MAGIC {
            refuse!(
                "not a bloch-pos keystore ({}): magic is {:?}, expected {:?}",
                path.display(),
                String::from_utf8_lossy(&magic),
                String::from_utf8_lossy(KEYSTORE_MAGIC)
            );
        }
        let index = u32::from_le_bytes(take(&b, &mut o, 4, "index")?.try_into().unwrap());
        let mut lenpfx = |b: &[u8], o: &mut usize, what: &str| -> R<Vec<u8>> {
            let n = u32::from_le_bytes(take(b, o, 4, what)?.try_into().unwrap()) as usize;
            take(b, o, n, what)
        };
        let pubkey = lenpfx(&b, &mut o, "pubkey")?;
        let secret = lenpfx(&b, &mut o, "secret")?;
        let seed_v = take(&b, &mut o, 32, "randao seed")?;
        let mut randao_seed = [0u8; 32];
        randao_seed.copy_from_slice(&seed_v);
        Ok(Keystore { index, pubkey, secret, randao_seed })
    }
}

// ── Identity derivation ─────────────────────────────────────────────────────

/// Everything the chain and the operator can know about a key, derived once
/// from ONE digest so the relationships are visible rather than asserted.
struct Identity {
    index: u32,
    pubkey: Vec<u8>,
    /// `SHA3-256(pubkey)`. This single value is THREE things at once, which is
    /// why it is computed once here: the registry's identity for the validator
    /// (`apply_transaction`'s `pubkey_hash`), the NATIVE `script_hash` that
    /// `transition::owns` opens on an all-32-bytes-equal comparison, and the
    /// source of the 20-byte address hash.
    pubkey_sha3: [u8; 32],
    address: Address,
    randao_commitment: [u8; 32],
}

impl Identity {
    fn derive(ks: &Keystore, network: Network) -> R<Identity> {
        check_hybrid_pubkey(&ks.pubkey)?;
        let pubkey_sha3: [u8; 32] = Sha3_256::digest(&ks.pubkey).into();
        // Derived through bloch-crypto, NOT restated here: `Address::from_pubkey`
        // is SHA3-256(pubkey)[..20]. A signer that reaches for Bitcoin's
        // hash160 (RIPEMD160(SHA256(pk))) derives different bytes and a
        // different address, and the chain will never pay it.
        let address = Address::from_pubkey(&ks.pubkey, network);
        // Cross-check the two derivations agree. They must, by construction;
        // pinning it here is what turns "by construction" into a fact this
        // binary re-establishes every run.
        if address.hash_bytes()[..] != pubkey_sha3[..20] {
            refuse!(
                "INTERNAL: address hash is not SHA3-256(pubkey)[..20] — \
                 bloch-crypto's derivation and this tool's disagree; do not proceed"
            );
        }
        let randao_commitment =
            bloch_pos_committee::beacon::RandaoChain::generate(ks.randao_seed).commitment();
        Ok(Identity {
            index: ks.index,
            pubkey: ks.pubkey.clone(),
            pubkey_sha3,
            address,
            randao_commitment,
        })
    }

    /// `SHA3-256(pubkey)`, all 32 bytes. What every Genesis-4 output uses.
    fn script_hash_native(&self) -> [u8; 32] {
        self.pubkey_sha3
    }

    /// `SHA3-256(pubkey)[..20] ‖ 12 zero bytes` — the carried form
    /// `transition::owns` accepts for balances minted under the Genesis-3
    /// convention. Same key, 160 bits of preimage resistance instead of 256.
    fn script_hash_carried(&self) -> [u8; 32] {
        carried_from_hash20(self.address.hash_bytes())
    }
}

fn carried_from_hash20(h: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..20].copy_from_slice(h);
    out
}

/// The hybrid public key must be the suite the staking path names. The
/// released `0x02` arm accepts ANY `Vec<u8>` as a pubkey — its own test
/// registers `vec![0xAA; 8]` and activates it — so this check exists here
/// precisely because consensus does not make it.
fn check_hybrid_pubkey(pk: &[u8]) -> R<()> {
    if pk.len() == HYBRID_PK_BYTES {
        return Ok(());
    }
    // The key may be suite-enveloped; accept the envelope whose body is the
    // hybrid key, and reject anything else by length with the arithmetic shown.
    if let Some((suite, body)) = bloch_crypto::crypto::split_envelope(pk) {
        if suite == SUITE_MLDSA65_FALCON1024 && body.len() == HYBRID_PK_BYTES {
            return Ok(());
        }
        refuse!(
            "public key is not the staking suite: envelope suite 0x{suite:04x}, body {} bytes.\n  \
             Staking requires suite 0x{:04x} (ML-DSA-65 ‖ Falcon-1024) with a {}-byte body \
             ({} + {}).",
            body.len(),
            SUITE_MLDSA65_FALCON1024,
            HYBRID_PK_BYTES,
            staking::MLDSA65_PK_BYTES,
            staking::FALCON1024_PK_BYTES
        );
    }
    refuse!(
        "public key is {} bytes; the staking suite is {} bytes ({} ML-DSA-65 + {} Falcon-1024).\n  \
         NOTE: the shipped chain does NOT enforce this — `PosTransaction::Deposit` accepts any \
         byte string as a pubkey. A key that fails here would be registered by consensus and \
         could never sign a block.",
        pk.len(),
        HYBRID_PK_BYTES,
        staking::MLDSA65_PK_BYTES,
        staking::FALCON1024_PK_BYTES
    );
}

// ── Withdrawal credentials ──────────────────────────────────────────────────

/// Turn an operator-supplied `bloch1q…` / `bloch1t…` string into the 32-byte
/// credentials, refusing the two ways this silently goes wrong.
fn credentials_from_address(s: &str, expect: Network) -> R<([u8; 32], Address)> {
    let addr = match Address::parse(s) {
        Ok(a) => a,
        Err(e) => refuse!(
            "cannot parse withdrawal address: {e}\n  \
             An address is a literal prefix plus 48 hex characters \
             (20-byte hash ‖ 4-byte checksum) — it is NOT bech32, so it has no \
             error-correction and a typo is simply a different address."
        ),
    };
    // THE MONEY GUARD. The checksum is SHA3-256(SHA3-256(hash20))[0..4] over
    // the HASH ONLY — the network prefix is stripped before it is computed and
    // is not covered by it. A mainnet payload therefore parses cleanly as a
    // testnet address and vice versa: the checksum cannot catch it, so this
    // must, and the operator must state the network explicitly.
    if addr.network() != expect {
        refuse!(
            "NETWORK MISMATCH: address is {}, you asked for {}.\n  \
             The 4-byte checksum covers the 20-byte hash ONLY, not the prefix, so this \
             address is checksum-VALID on both networks and nothing downstream will catch \
             it. Re-check the prefix character by character.",
            net_name(addr.network()),
            net_name(expect)
        );
    }
    Ok((carried_from_hash20(addr.hash_bytes()), addr))
}

fn net_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet (bloch1q)",
        Network::Testnet => "testnet (bloch1t)",
    }
}

/// Credentials must be exactly 32 bytes. The released `ValidatorRecord`
/// declares `withdrawal_credentials: Vec<u8>` and its own doc comment calls
/// the width an open point; the `0x02` apply arm stores whatever it is handed
/// (its test stores 4 bytes). Enforced here so that whenever a withdrawal path
/// does land, the record it reads is already the right shape.
fn check_credentials(c: &[u8]) -> R<()> {
    if c.len() != 32 {
        refuse!(
            "withdrawal_credentials is {} bytes; it must be 32 (a script_hash).\n  \
             The chain does NOT enforce this today — `ValidatorRecord::withdrawal_credentials` \
             is an unvalidated `Vec<u8>` — so a wrong width is committed to state silently and \
             is unfixable without a withdrawal path that does not yet exist.",
            c.len()
        );
    }
    Ok(())
}

// ── Deposit construction ────────────────────────────────────────────────────

struct Plan {
    identity: Identity,
    amount_sat: u128,
    commission_bps: u128,
    credentials: [u8; 32],
    withdrawal_addr: Address,
    pop: Vec<u8>,
    pop_root: [u8; 32],
    raw_tx: Vec<u8>,
}

fn build_deposit(
    ks: &Keystore,
    network: Network,
    amount_sat: u128,
    commission_bps: u128,
    withdrawal: &str,
) -> R<Plan> {
    let identity = Identity::derive(ks, network)?;
    let (credentials, withdrawal_addr) = credentials_from_address(withdrawal, network)?;
    check_credentials(&credentials)?;

    // The floor consensus DOES enforce (`apply_transaction`: amount_sat <
    // MIN_DEPOSIT_SAT => TxReject::StakingRule).
    if amount_sat < MIN_DEPOSIT_SAT {
        refuse!(
            "amount {} sat is below MIN_DEPOSIT_SAT ({} sat = {} BLCH). \
             Consensus rejects this deposit.",
            amount_sat,
            MIN_DEPOSIT_SAT,
            MIN_DEPOSIT_SAT / staking::SAT_PER_BLOCH
        );
    }
    // The ceiling consensus enforces is 1% of COMMITTED ACTIVE STAKE, floored
    // at MIN_DEPOSIT_SAT. It is a function of live chain state, so this tool
    // cannot check it offline and does not pretend to: it reports the rule.

    // Proof of possession over the released signing root. `DepositTx` here is
    // `staking::DepositTx`, whose `withdrawal_addr` is a fixed `[u8; 32]` —
    // note that this is a DIFFERENT type from `interfaces::DepositTx`, whose
    // `withdrawal_credentials` is an opaque `Vec<u8>`. Both ship at the tag.
    // The fixed-width one is the one with a signing root, so it is the one a
    // signature can be bound to.
    let mut pk_arr = [0u8; HYBRID_PK_BYTES];
    let body: &[u8] = if ks.pubkey.len() == HYBRID_PK_BYTES {
        &ks.pubkey
    } else {
        bloch_crypto::crypto::split_envelope(&ks.pubkey).map(|(_, b)| b).unwrap_or(&ks.pubkey)
    };
    if body.len() != HYBRID_PK_BYTES {
        refuse!("INTERNAL: hybrid key body is {} bytes after envelope strip", body.len());
    }
    pk_arr.copy_from_slice(body);

    let unsigned = DepositTx {
        suite: SUITE_MLDSA65_FALCON1024,
        amount_sat,
        validator_pubkey: pk_arr,
        randao_commitment: identity.randao_commitment,
        withdrawal_addr: credentials,
        proof_of_possession: Vec::new(),
    };
    let pop_root = unsigned.signing_root();
    let pop = match bloch_crypto::crypto::sign(&ks.secret, &pop_root) {
        Ok(s) => s,
        Err(e) => refuse!("proof-of-possession signing failed: {e}"),
    };
    // Verify what we just produced, against the same verifier a validating
    // node would use. Signing and not checking is how a bond is lost to a
    // corrupted keystore.
    if !bloch_crypto::crypto::verify(&ks.pubkey, &pop_root, &pop) {
        refuse!(
            "the proof-of-possession this tool just produced does not verify against its own \
             public key. The keystore is inconsistent — DO NOT submit anything."
        );
    }

    // The transaction the SHIPPED chain accepts: wire tag 0x02.
    let tx = PosTransaction::Deposit {
        pubkey: ks.pubkey.clone(),
        amount_sat,
        randao_commitment: identity.randao_commitment,
        withdrawal_credentials: credentials.to_vec(),
        commission_bps,
    };
    let raw_tx = tx.canonical_bytes();
    // Round-trip through the real decoder before handing an operator bytes to
    // broadcast. `canonical_bytes` is what `body_root` commits to, so a shape
    // that does not decode is a block nobody can validate.
    match PosTransaction::from_canonical_bytes(&raw_tx) {
        Ok(back) if back == tx => {}
        Ok(_) => refuse!("INTERNAL: deposit did not round-trip to an equal transaction"),
        Err(e) => refuse!("INTERNAL: deposit did not decode: {e:?}"),
    }
    if raw_tx.first() != Some(&0x02) {
        refuse!("INTERNAL: expected wire tag 0x02, got {:?}", raw_tx.first());
    }

    Ok(Plan {
        identity,
        amount_sat,
        commission_bps,
        credentials,
        withdrawal_addr,
        pop,
        pop_root,
        raw_tx,
    })
}

// ── Output ──────────────────────────────────────────────────────────────────

/// The exact string `engine.rs::admissible()` returns for a deposit, quoted so
/// this tool and the node cannot drift apart silently.
const NODE_DEPOSIT_REFUSAL: &str =
    "deposits are not accepted: bonding is not yet funded from the UTXO set, \
     so a deposit would create stake without spending coins";

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn print_identity(id: &Identity) {
    println!("{{");
    println!("  \"validator_index\": {},", id.index);
    println!("  \"pubkey_bytes\": {},", id.pubkey.len());
    println!("  \"pubkey_sha3_256\": \"{}\",", hx(&id.pubkey_sha3));
    println!("  \"_pubkey_sha3_256_is\": \"the registry identity, AND the native script_hash\",");
    println!("  \"address\": \"{}\",", id.address);
    println!("  \"address_hash20\": \"{}\",", hx(id.address.hash_bytes()));
    println!("  \"script_hash_native\": \"{}\",", hx(&id.script_hash_native()));
    println!("  \"script_hash_carried\": \"{}\",", hx(&id.script_hash_carried()));
    println!("  \"randao_commitment\": \"{}\"", hx(&id.randao_commitment));
    println!("}}");
}

fn print_plan(p: &Plan) {
    println!("{{");
    println!("  \"wire_tag\": \"0x02\",");
    println!("  \"format\": \"PosTransaction::Deposit (the shipped, unfunded deposit)\",");
    println!("  \"validator_index_requested\": {},", p.identity.index);
    println!("  \"_validator_index_note\": \"IGNORED by consensus: the index is assigned by the");
    println!("    registry as max(existing)+1 when the deposit applies, not chosen here.\",");
    println!("  \"pubkey_sha3_256\": \"{}\",", hx(&p.identity.pubkey_sha3));
    println!("  \"amount_sat\": \"{}\",", p.amount_sat);
    println!("  \"amount_blch\": \"{}\",", p.amount_sat / staking::SAT_PER_BLOCH);
    println!("  \"commission_bps\": \"{}\",", p.commission_bps);
    println!("  \"withdrawal_address\": \"{}\",", p.withdrawal_addr);
    println!("  \"withdrawal_credentials\": \"{}\",", hx(&p.credentials));
    println!("  \"_withdrawal_credentials_form\": \"carried: hash20 || 12 zero bytes\",");
    println!("  \"proof_of_possession_root\": \"{}\",", hx(&p.pop_root));
    println!("  \"proof_of_possession\": \"{}\",", hx(&p.pop));
    println!("  \"_proof_of_possession_note\": \"COMPUTED AND SELF-VERIFIED, BUT NOT CARRIED:");
    println!("    wire tag 0x02 has no field for it and the shipped apply arm never checks one.");
    println!("    It is emitted so this plan is forward-compatible with the funded shape.\",");
    println!("  \"raw_tx_hex\": \"{}\",", hx(&p.raw_tx));
    println!("  \"raw_tx_bytes\": {},", p.raw_tx.len());
    println!("  \"submittable\": false,");
    println!("  \"submit_refusal\": \"{}\",", NODE_DEPOSIT_REFUSAL);
    println!("  \"_submit_note\": \"THESE BYTES CANNOT BE SUBMITTED TO ANY NODE RUNNING THE");
    println!("    RELEASED BINARY. engine.rs::admissible() refuses PosTransaction::Deposit");
    println!("    outright, and on_transaction calls it (engine.rs:1787) on BOTH the RPC");
    println!("    sendrawtransaction path and the gossip path. Delegate (0x04) and Exit (0x03)");
    println!("    are refused the same way. Only Transfer/TransferV2 are admitted. This is a");
    println!("    NODE-SIDE refusal, not a consensus rule: a block that already carries a");
    println!("    deposit still applies it -- but no proposer on the released binary will ever");
    println!("    put one in. The bytes are emitted for a future flag day and for testing.\",");
    println!("  \"activation_delay_epochs\": {},", staking::ACTIVATION_DELAY_EPOCHS);
    println!("  \"max_activations_per_epoch\": {},", staking::MAX_ACTIVATIONS_PER_EPOCH);
    println!("  \"WHAT_THIS_DEPOSIT_IS_NOT\": [");
    println!("    \"NOT FUNDED: wire tag 0x02 consumes no inputs. The stake is minted by the");
    println!("     apply arm, not moved from your balance. Nothing is debited.\",");
    println!("    \"NOT AUTHENTICATED: the apply arm never calls staking::validate_deposit, so");
    println!("     the proof-of-possession above is not verified by consensus.\",");
    println!("    \"NOT REVERSIBLE: there is no Withdraw transaction on this lineage. A bond");
    println!("     placed here is one-way.\",");
    println!("    \"NOT EXIT-PROTECTED: wire tag 0x03 (Exit) carries only a u32 validator index");
    println!("     and no signature. Anyone can exit your validator.\"");
    println!("  ]");
    println!("}}");
}

// ── CLI ─────────────────────────────────────────────────────────────────────

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn need(args: &[String], name: &str) -> R<String> {
    match arg(args, name) {
        Some(v) => Ok(v),
        None => refuse!("{name} is required"),
    }
}

fn network_of(args: &[String]) -> R<Network> {
    match need(args, "--network")?.as_str() {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        other => refuse!(
            "--network must be 'mainnet' or 'testnet', got '{other}'. \
             There is no default: the address checksum does not cover the network, so a \
             default here would be a way to lose money quietly."
        ),
    }
}

const USAGE: &str = "\
bloch-onboard — construct a Genesis-4 validator deposit against the release lineage

  bloch-onboard identity    --keystore <dir> --network <mainnet|testnet>
  bloch-onboard credentials --address <bloch1q…> --network <mainnet|testnet>
  bloch-onboard deposit     --keystore <dir> --network <mainnet|testnet> \\
                            --amount-sat <n> --withdrawal-address <bloch1q…> \\
                            [--commission-bps <n>]
  bloch-onboard deposit --funded ...   (refuses; states the requirement)

Generate a throwaway keystore first:
  bloch-pos keygen --dir <dir> --index 0
";

fn run() -> R<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("identity") => {
            let ks = Keystore::load(&PathBuf::from(need(&args, "--keystore")?))?;
            print_identity(&Identity::derive(&ks, network_of(&args)?)?);
            Ok(())
        }
        Some("credentials") => {
            let net = network_of(&args)?;
            let (c, a) = credentials_from_address(&need(&args, "--address")?, net)?;
            check_credentials(&c)?;
            println!("{{");
            println!("  \"address\": \"{a}\",");
            println!("  \"network\": \"{}\",", net_name(net));
            println!("  \"hash20\": \"{}\",", hx(a.hash_bytes()));
            println!("  \"withdrawal_credentials\": \"{}\"", hx(&c));
            println!("}}");
            Ok(())
        }
        Some("deposit") => {
            if args.iter().any(|a| a == "--funded") {
                refuse!(
                    "the funded, authenticated deposit is NOT on this lineage and this tool will \
                     not invent it.\n\n  \
                     REQUIREMENT, for whoever lands it:\n  \
                     - a new PosTransaction variant carrying inputs (Vec<UtxoRef>), the hybrid \
                     proof-of-possession, and 32-byte withdrawal credentials;\n  \
                     - an apply arm that calls staking::validate_deposit and DEBITS the inputs;\n  \
                     - an epoch-gated activation constant, u64::MAX until a flag day is armed.\n\n  \
                     WIRE TAG: deliberately unassigned. 0x01-0x06 are taken on this lineage \
                     (0x06 = TransferV2). Off-lineage work has independently claimed 0x07 for \
                     DepositV2 and 0x07 (then 0x08) for Withdraw. The number is the founder's to \
                     pick; this tool refuses rather than guess, because a guess that reaches a \
                     flag day is a chain split."
                );
            }
            let ks = Keystore::load(&PathBuf::from(need(&args, "--keystore")?))?;
            let amount: u128 = match need(&args, "--amount-sat")?.parse() {
                Ok(v) => v,
                Err(e) => refuse!("--amount-sat is not a u128: {e}"),
            };
            let commission: u128 = match arg(&args, "--commission-bps") {
                Some(s) => match s.parse() {
                    Ok(v) => v,
                    Err(e) => refuse!("--commission-bps is not a u128: {e}"),
                },
                None => 0,
            };
            let plan = build_deposit(
                &ks,
                network_of(&args)?,
                amount,
                commission,
                &need(&args, "--withdrawal-address")?,
            )?;
            print_plan(&plan);
            Ok(())
        }
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("refused: {e}");
        std::process::exit(1);
    }
}
