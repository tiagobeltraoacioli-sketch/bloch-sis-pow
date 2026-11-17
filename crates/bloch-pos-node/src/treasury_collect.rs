// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-pos treasury-collect`: list the L1 protocol treasury's unspent
//! outputs from two endpoints and build an UNSIGNED consolidation or payment
//! the owner signs offline. This command never opens a key, never signs and
//! never broadcasts. The offline logic and every refusal are in
//! [`crate::treasury_spend`]; this file is the command line and the
//! two-endpoint read.

use crate::{
    codec,
    equivocation_watch::{normalize_addr, rpc_call, with_retry, RpcErr},
    genesis::Manifest,
    rpc::Json,
    treasury_spend::{
        self, build_plan, compiled_treasury_script, inspect, parse_destination,
        protected_outpoints, EndpointRead, Exclusion, Intent, Observation, MAX_INPUTS,
        MAX_OBSERVATION_BYTES,
    },
};
use bloch_pos_committee::{
    params::SLOTS_PER_EPOCH,
    state_root::EutxoEntry,
    transition::{PosTransaction, TransferOutput},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

pub const HELP: &str = "L1 protocol-treasury collection (never signs, never broadcasts)

treasury-collect observe --rpc HOST:PORT --rpc HOST:PORT --genesis MANIFEST
                         [--treasury ADDRESS_OR_SCRIPT] [--limit N]
                         [--outpoint TXID:VOUT ...] --out NEW_FILE
    The only online step. Reads, from BOTH endpoints: getchaininfo (head and
    finalized checkpoint), getmempoolinfo (next base fee), and either one
    listunspent page of the treasury script (default; at most 1000 outputs,
    the node has no cursor) or gettxout for each --outpoint. Refuses unless
    the two endpoints are distinct, name the same finalized checkpoint before
    and after the read, are within 4 slots of each other, quote the same base
    fee, and agree on every output they both report. Writes only what both
    agree on.

treasury-collect prepare --observation FILE --genesis MANIFEST --pubkey HEX_FILE
                         --tip MILLISAT_PER_GAS --max-fee SAT [--max-inputs N]
                         [--pay DESTINATION:SAT ...] [--change-to DESTINATION]
                         --out NEW_FILE
    Offline. Builds ONE unsigned TransferV2: one witness key (the treasury
    key's PUBLIC half, raw form), every eligible observed output as an input,
    the --pay outputs in order, and the remainder to --change-to (default: the
    treasury itself; with no --pay this is a consolidation). Left out and
    listed: genesis allocation outpoints (never spent by this tool), outputs
    worth no more than the fee they add, outputs past --max-inputs.

treasury-collect inspect --observation FILE --genesis MANIFEST --tx FILE
                         --max-fee SAT [--expected-root HEX32]
    Offline. Re-derives every input, output and the exact fee of a draft or a
    signed transaction from the observation; verifies a present signature
    with the consensus spend verifier.

DESTINATION is a bloch1q... mainnet address or a 64-hex-digit script.
MANIFEST is the trusted genesis file (genesis/mainnet.manifest on mainnet).
Sign on the offline machine with examples/sign-treasury-spend.rs, which runs
the same inspection before and after the signature. Submit the signed hex with
sendrawtransaction yourself. A draft is valid only at the observed base fee.";

/// Endpoints whose heads are further apart than this are not reading the
/// same chain state closely enough to be compared output by output.
pub const MAX_HEAD_GAP_SLOTS: u64 = 4;

struct Args(BTreeMap<String, Vec<String>>);
impl Args {
    fn parse(args: &[String], single: &[&str], repeatable: &[&str]) -> Result<Self, String> {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let is_single = single.contains(&flag.as_str());
            if !is_single && !repeatable.contains(&flag.as_str()) {
                return Err(format!("unknown option {flag}"));
            }
            let value = iter
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?;
            let slot = values.entry(flag.clone()).or_default();
            if is_single && !slot.is_empty() {
                return Err(format!("duplicate option {flag}"));
            }
            slot.push(value.clone());
        }
        Ok(Self(values))
    }
    fn opt(&self, flag: &str) -> Option<&str> {
        self.0.get(flag).and_then(|v| v.first()).map(String::as_str)
    }
    fn get(&self, flag: &str) -> Result<&str, String> {
        self.opt(flag).ok_or_else(|| format!("missing {flag}"))
    }
    fn all(&self, flag: &str) -> &[String] {
        self.0.get(flag).map(Vec::as_slice).unwrap_or(&[])
    }
    fn number<T: std::str::FromStr>(&self, flag: &str) -> Result<T, String> {
        self.get(flag)?
            .parse()
            .map_err(|_| format!("invalid integer for {flag}"))
    }
}

fn read_bounded(path: &str, limit: u64) -> Result<String, String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(|e| format!("{path}: {e}"))?
        .take(limit.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|e| format!("{path}: {e}"))?;
    if text.len() as u64 > limit {
        return Err(format!("{path}: larger than {limit} bytes"));
    }
    Ok(text)
}
fn write_new(path: &str, text: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("{path}: {e} (refusing to overwrite)"))?;
    file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
fn load_genesis(path: &str) -> Result<(Manifest, [u8; 32]), String> {
    Manifest::load(Path::new(path)).map_err(|e| format!("genesis {path}: {e}"))
}
fn h32(j: Option<&Json>, what: &str) -> Result<[u8; 32], String> {
    let text = j
        .and_then(Json::as_str)
        .ok_or_else(|| format!("{what}: missing"))?;
    codec::unhex(text)?
        .try_into()
        .map_err(|_| format!("{what}: not 32 bytes"))
}
fn u64_of(j: Option<&Json>, what: &str) -> Result<u64, String> {
    j.and_then(Json::as_u64)
        .ok_or_else(|| format!("{what}: missing or not an integer"))
}
fn sat_of(j: Option<&Json>, what: &str) -> Result<u128, String> {
    match j {
        Some(Json::Str(s)) | Some(Json::Num(s)) => {
            s.parse().map_err(|_| format!("{what}: not an integer"))
        }
        _ => Err(format!("{what}: missing")),
    }
}
fn parse_outpoint(text: &str) -> Result<([u8; 32], u32), String> {
    let (txid, vout) = text
        .split_once(':')
        .ok_or_else(|| format!("outpoint {text}: expected TXID:VOUT"))?;
    let txid: [u8; 32] = codec::unhex(txid)?
        .try_into()
        .map_err(|_| format!("outpoint {text}: txid is not 32 bytes"))?;
    Ok((
        txid,
        vout.parse()
            .map_err(|_| format!("outpoint {text}: bad vout"))?,
    ))
}

/// One endpoint's answers, as parsed (no network in here: testable).
#[derive(Clone, Debug)]
pub struct EndpointSnapshot {
    pub read: EndpointRead,
    pub epoch: u64,
    pub base_fee: u128,
    pub total: u64,
    pub utxos: Vec<EutxoEntry>,
}

/// `getchaininfo` -> the read point and the inclusion epoch (wall clock). Refuses a node that cannot place its
/// finalized checkpoint on its own chain (`finalized_height: null`, the
/// documented "halt" signal for integrators).
pub fn parse_chain_info(addr: &str, j: &Json) -> Result<(EndpointRead, u64), String> {
    if matches!(j.get("finalized_height"), Some(Json::Null) | None) {
        return Err(format!("{addr}: finalized_height is null: the node cannot place its finalized checkpoint; halt"));
    }
    let fin = j
        .get("finalized")
        .ok_or_else(|| format!("{addr}: getchaininfo without `finalized`"))?;
    let head_slot = u64_of(j.get("slot"), "getchaininfo.slot")?;
    // The inclusion epoch is the NEXT block's, which follows the wall clock,
    // not the head (a head can sit in an earlier epoch after empty slots).
    let wall_slot = u64_of(j.get("wall_slot"), "getchaininfo.wall_slot")?;
    Ok((
        EndpointRead {
            addr: addr.to_string(),
            head_slot,
            head_block: h32(j.get("block_id"), "getchaininfo.block_id")?,
            finalized_epoch: u64_of(fin.get("epoch"), "getchaininfo.finalized.epoch")?,
            finalized_root: h32(fin.get("root"), "getchaininfo.finalized.root")?,
        },
        wall_slot.max(head_slot) / SLOTS_PER_EPOCH,
    ))
}

/// `listunspent` page -> outputs. Refuses an answer about another script.
pub fn parse_utxo_page(j: &Json, treasury: &[u8; 32]) -> Result<(u64, Vec<EutxoEntry>), String> {
    if &h32(j.get("script_hash"), "listunspent.script_hash")? != treasury {
        return Err("listunspent answered for another script".into());
    }
    let total = u64_of(j.get("total"), "listunspent.total")?;
    let Some(Json::Arr(items)) = j.get("utxos") else {
        return Err("listunspent without `utxos`".into());
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        out.push(EutxoEntry {
            txid: h32(it.get("txid"), "utxo.txid")?,
            vout: u32::try_from(u64_of(it.get("vout"), "utxo.vout")?)
                .map_err(|_| "utxo.vout too large")?,
            value: u64::try_from(sat_of(it.get("value_sat"), "utxo.value_sat")?)
                .map_err(|_| "utxo.value_sat too large")?,
            script_hash: h32(it.get("script_hash"), "utxo.script_hash")?,
        });
    }
    Ok((total, out))
}

/// `gettxout` -> the output if unspent.
pub fn parse_txout(j: &Json, outpoint: ([u8; 32], u32)) -> Result<Option<EutxoEntry>, String> {
    if h32(j.get("txid"), "gettxout.txid")? != outpoint.0
        || u64_of(j.get("vout"), "gettxout.vout")? != u64::from(outpoint.1)
    {
        return Err("gettxout answered for another outpoint".into());
    }
    match j.get("unspent") {
        Some(Json::Bool(false)) => Ok(None),
        Some(Json::Bool(true)) => {
            let u = j.get("utxo").ok_or("gettxout without `utxo`")?;
            Ok(Some(EutxoEntry {
                txid: outpoint.0,
                vout: outpoint.1,
                value: u64::try_from(sat_of(u.get("value_sat"), "gettxout.value_sat")?)
                    .map_err(|_| "value too large")?,
                script_hash: h32(u.get("script_hash"), "gettxout.script_hash")?,
            }))
        }
        _ => Err("gettxout without a boolean `unspent`".into()),
    }
}

/// What two endpoints agree on. Every rule that lets the owner believe the
/// list is here; the network calls only fill the two snapshots.
pub fn agree(
    treasury: [u8; 32],
    genesis_sha3: [u8; 32],
    a: EndpointSnapshot,
    b: EndpointSnapshot,
) -> Result<(Observation, Vec<String>), String> {
    let mut notes = Vec::new();
    if a.read.addr == b.read.addr {
        return Err("the two --rpc endpoints must be different nodes".into());
    }
    if (a.read.finalized_epoch, a.read.finalized_root)
        != (b.read.finalized_epoch, b.read.finalized_root)
    {
        return Err(format!(
            "endpoints disagree on the finalized checkpoint: {} epoch {} root {} vs {} epoch {} root {}",
            a.read.addr,
            a.read.finalized_epoch,
            codec::hex32(&a.read.finalized_root),
            b.read.addr,
            b.read.finalized_epoch,
            codec::hex32(&b.read.finalized_root)
        ));
    }
    if a.read.head_slot.abs_diff(b.read.head_slot) > MAX_HEAD_GAP_SLOTS {
        return Err(format!(
            "endpoint heads are {} slots apart (more than {MAX_HEAD_GAP_SLOTS}): one is behind; read again",
            a.read.head_slot.abs_diff(b.read.head_slot)
        ));
    }
    if a.base_fee != b.base_fee {
        return Err(format!(
            "endpoints quote different next base fees ({} vs {}); read again",
            a.base_fee, b.base_fee
        ));
    }
    let theirs: BTreeMap<([u8; 32], u32), &EutxoEntry> =
        b.utxos.iter().map(|u| ((u.txid, u.vout), u)).collect();
    let mut agreed = Vec::new();
    let mut seen = BTreeSet::new();
    for u in &a.utxos {
        if !seen.insert((u.txid, u.vout)) {
            return Err(format!(
                "{} reported {}:{} twice",
                a.read.addr,
                codec::hex32(&u.txid),
                u.vout
            ));
        }
        match theirs.get(&(u.txid, u.vout)) {
            Some(v) if *v == u => agreed.push(u.clone()),
            Some(v) => {
                return Err(format!(
                    "endpoints disagree on output {}:{}: {} sat / {} vs {} sat / {}",
                    codec::hex32(&u.txid),
                    u.vout,
                    u.value,
                    codec::hex32(&u.script_hash),
                    v.value,
                    codec::hex32(&v.script_hash)
                ))
            }
            None => notes.push(format!(
                "left out {}:{} ({} sat): reported by {} only",
                codec::hex32(&u.txid),
                u.vout,
                u.value,
                a.read.addr
            )),
        }
    }
    let ours: BTreeSet<([u8; 32], u32)> = a.utxos.iter().map(|u| (u.txid, u.vout)).collect();
    for v in &b.utxos {
        if !ours.contains(&(v.txid, v.vout)) {
            notes.push(format!(
                "left out {}:{} ({} sat): reported by {} only",
                codec::hex32(&v.txid),
                v.vout,
                v.value,
                b.read.addr
            ));
        }
    }
    for u in &agreed {
        if u.script_hash != treasury {
            return Err(format!(
                "both endpoints report {}:{} under another script",
                codec::hex32(&u.txid),
                u.vout
            ));
        }
    }
    if agreed.len() > MAX_INPUTS {
        return Err(format!("more than {MAX_INPUTS} agreed outputs"));
    }
    let epoch = a.epoch.max(b.epoch);
    let obs = Observation {
        treasury,
        genesis_sha3,
        epoch,
        base_fee: a.base_fee,
        endpoints: vec![a.read, b.read],
        page_total: a.total,
        utxos: agreed,
    };
    obs.check_agreement()?;
    Ok((obs, notes))
}

fn call(addr: &str, method: &str, params: Vec<Json>) -> Result<Json, String> {
    with_retry(|| rpc_call(addr, method, params.clone())).map_err(|e| match e {
        RpcErr::Node(code, msg) => format!("{addr} {method}: node error {code}: {msg}"),
        RpcErr::Transport(msg) => format!("{method}: {msg}"),
    })
}

fn snapshot(
    addr: &str,
    treasury: &[u8; 32],
    limit: u64,
    outpoints: &[([u8; 32], u32)],
) -> Result<EndpointSnapshot, String> {
    let (read, epoch) = parse_chain_info(addr, &call(addr, "getchaininfo", vec![])?)?;
    let base_fee = sat_of(
        call(addr, "getmempoolinfo", vec![])?.get("next_base_fee_millisat_per_gas"),
        "getmempoolinfo.next_base_fee_millisat_per_gas",
    )?;
    let (total, utxos) = if outpoints.is_empty() {
        parse_utxo_page(
            &call(
                addr,
                "listunspent",
                vec![Json::hex(treasury), Json::u(limit)],
            )?,
            treasury,
        )?
    } else {
        let mut found = Vec::new();
        for op in outpoints {
            let j = call(
                addr,
                "gettxout",
                vec![Json::hex(&op.0), Json::u(u64::from(op.1))],
            )?;
            match parse_txout(&j, *op)? {
                Some(u) => found.push(u),
                None => {
                    return Err(format!(
                        "{addr}: {}:{} is spent or unknown",
                        codec::hex32(&op.0),
                        op.1
                    ))
                }
            }
        }
        (0, found)
    };
    Ok(EndpointSnapshot {
        read,
        epoch,
        base_fee,
        total,
        utxos,
    })
}

fn observe(args: &[String]) -> Result<(), String> {
    let a = Args::parse(
        args,
        &["--genesis", "--treasury", "--limit", "--out"],
        &["--rpc", "--outpoint"],
    )?;
    let out = a.get("--out")?.to_string();
    if std::fs::symlink_metadata(&out).is_ok() {
        return Err(format!("{out} exists; refusing to overwrite"));
    }
    let rpcs: Vec<String> = a.all("--rpc").iter().map(|s| normalize_addr(s)).collect();
    if rpcs.len() != 2 {
        return Err("exactly two --rpc endpoints (two different nodes) are required".into());
    }
    let (manifest, genesis_sha3) = load_genesis(a.get("--genesis")?)?;
    let treasury = match a.opt("--treasury") {
        Some(t) => parse_destination(t)?,
        None => compiled_treasury_script(),
    };
    let limit: u64 = match a.opt("--limit") {
        Some(_) => a.number("--limit")?,
        None => MAX_INPUTS as u64,
    };
    if limit == 0 || limit > MAX_INPUTS as u64 {
        return Err(format!("--limit must be 1 to {MAX_INPUTS}"));
    }
    let outpoints: Vec<([u8; 32], u32)> = a
        .all("--outpoint")
        .iter()
        .map(|s| parse_outpoint(s))
        .collect::<Result<_, _>>()?;
    let sa = snapshot(&rpcs[0], &treasury, limit, &outpoints)?;
    let sb = snapshot(&rpcs[1], &treasury, limit, &outpoints)?;
    // Bracket the ledger reads: the finalized checkpoint each endpoint named
    // before must still be the one it names after.
    for (addr, before) in [(&rpcs[0], &sa.read), (&rpcs[1], &sb.read)] {
        let (after, _) = parse_chain_info(addr, &call(addr, "getchaininfo", vec![])?)?;
        if (after.finalized_epoch, after.finalized_root)
            != (before.finalized_epoch, before.finalized_root)
        {
            return Err(format!(
                "{addr}: finality moved during the read; observe again"
            ));
        }
    }
    let (obs, notes) = agree(treasury, genesis_sha3, sa, sb)?;
    let protected = protected_outpoints(&manifest, &treasury);
    println!("Treasury script: {}", codec::hex32(&treasury));
    if let Some(addr) = treasury_spend::carried_address(&treasury) {
        println!("Treasury address: {addr}");
    }
    println!("Genesis manifest SHA3-256: {}", codec::hex32(&genesis_sha3));
    println!(
        "Genesis allocation outpoints at this script (never spent by this tool): {}",
        protected.len()
    );
    for n in &notes {
        println!("{n}");
    }
    let sum: u128 = obs.utxos.iter().map(|u| u128::from(u.value)).sum();
    let protected_here = obs
        .utxos
        .iter()
        .filter(|u| protected.contains(&(u.txid, u.vout)))
        .count();
    println!(
        "Agreed outputs: {} ({} sat), of which genesis allocations: {}; treasury total per {}: {} outputs{}",
        obs.utxos.len(),
        sum,
        protected_here,
        obs.endpoints[0].addr,
        obs.page_total,
        if outpoints.is_empty() && obs.page_total > obs.utxos.len() as u64 {
            " (one page; the node has no cursor: collect this page, wait for finality, observe again)"
        } else {
            ""
        }
    );
    println!(
        "Inclusion epoch {}, next base fee {} millisat/gas",
        obs.epoch, obs.base_fee
    );
    println!("Observation SHA3-256: {}", codec::hex32(&obs.digest()));
    write_new(&out, &obs.encode())
}

fn load_observation(
    path: &str,
    genesis: &str,
) -> Result<(Observation, BTreeSet<([u8; 32], u32)>), String> {
    let obs = Observation::parse(&read_bounded(path, MAX_OBSERVATION_BYTES)?)?;
    let (manifest, digest) = load_genesis(genesis)?;
    if digest != obs.genesis_sha3 {
        return Err(format!(
            "genesis {genesis} (SHA3-256 {}) is not the manifest the observation was made with ({})",
            codec::hex32(&digest),
            codec::hex32(&obs.genesis_sha3)
        ));
    }
    let protected = protected_outpoints(&manifest, &obs.treasury);
    Ok((obs, protected))
}

fn read_tx(path: &str) -> Result<PosTransaction, String> {
    let bytes = codec::unhex(read_bounded(path, 4 * 1024 * 1024)?.trim())?;
    let tx = PosTransaction::from_canonical_bytes(&bytes)
        .map_err(|e| format!("invalid transaction: {e:?}"))?;
    if tx.canonical_bytes() != bytes {
        return Err("non-canonical transaction bytes".into());
    }
    Ok(tx)
}

/// `DESTINATION:SAT`. The address or script is everything before the LAST
/// colon, so a hex script or a bloch1q address both parse.
pub fn parse_payment(text: &str) -> Result<TransferOutput, String> {
    let (dest, sat) = text
        .rsplit_once(':')
        .ok_or_else(|| format!("--pay {text}: expected DESTINATION:SAT"))?;
    Ok(TransferOutput {
        script_hash: parse_destination(dest)?,
        value: sat
            .parse()
            .map_err(|_| format!("--pay {text}: bad amount"))?,
    })
}

fn prepare(args: &[String]) -> Result<(), String> {
    let a = Args::parse(
        args,
        &[
            "--observation",
            "--genesis",
            "--pubkey",
            "--tip",
            "--max-fee",
            "--max-inputs",
            "--change-to",
            "--out",
        ],
        &["--pay"],
    )?;
    let out = a.get("--out")?.to_string();
    if std::fs::symlink_metadata(&out).is_ok() {
        return Err(format!("{out} exists; refusing to overwrite"));
    }
    let (obs, protected) = load_observation(a.get("--observation")?, a.get("--genesis")?)?;
    let pubkey = codec::unhex(read_bounded(a.get("--pubkey")?, 65_536)?.trim())?;
    let intent = Intent {
        pay: a
            .all("--pay")
            .iter()
            .map(|p| parse_payment(p))
            .collect::<Result<_, _>>()?,
        change_to: match a.opt("--change-to") {
            Some(d) => parse_destination(d)?,
            None => obs.treasury,
        },
        tip: a.number("--tip")?,
        max_fee_sat: a.number("--max-fee")?,
        max_inputs: match a.opt("--max-inputs") {
            Some(_) => a.number("--max-inputs")?,
            None => MAX_INPUTS,
        },
    };
    let plan = build_plan(&obs, &protected, &pubkey, &intent)?;
    for (u, why) in &plan.excluded {
        let why = match why {
            Exclusion::GenesisAllocation => {
                "genesis allocation outpoint (kept unspent)".to_string()
            }
            Exclusion::Uneconomic { marginal_fee_sat } => {
                format!("worth no more than the {marginal_fee_sat} sat its input adds to the fee")
            }
            Exclusion::InputCap => "beyond --max-inputs (next draft)".to_string(),
        };
        println!(
            "  left out {}:{} {} sat: {why}",
            codec::hex32(&u.txid),
            u.vout,
            u.value
        );
    }
    let shown = inspect(&obs, &protected, &plan.tx, intent.max_fee_sat)?;
    // The builder's own numbers and the independent inspection must agree.
    if shown.txid != plan.txid
        || shown.signing_root != plan.signing_root
        || shown.fee_sat != plan.fee_sat
        || shown.input_sum_sat != plan.input_sum_sat
        || shown.inputs != plan.inputs
    {
        return Err("internal: the draft and its inspection disagree; nothing written".into());
    }
    print!("{}", treasury_spend::render(&obs, &shown));
    println!(
        "UNSIGNED draft written to {out}. Approve the signing root above on the signing machine."
    );
    write_new(
        &out,
        &format!("{}\n", codec::hex(&plan.tx.canonical_bytes())),
    )
}

fn inspect_cmd(args: &[String]) -> Result<(), String> {
    let a = Args::parse(
        args,
        &[
            "--observation",
            "--genesis",
            "--tx",
            "--max-fee",
            "--expected-root",
        ],
        &[],
    )?;
    let (obs, protected) = load_observation(a.get("--observation")?, a.get("--genesis")?)?;
    let tx = read_tx(a.get("--tx")?)?;
    let shown = inspect(&obs, &protected, &tx, a.number("--max-fee")?)?;
    print!("{}", treasury_spend::render(&obs, &shown));
    if let Some(expected) = a.opt("--expected-root") {
        let expected: [u8; 32] = codec::unhex(expected)?
            .try_into()
            .map_err(|_| "--expected-root needs 32 bytes".to_string())?;
        if expected != shown.signing_root {
            return Err("signing root does not match --expected-root".into());
        }
        println!("Signing root matches --expected-root.");
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        println!("{HELP}");
        return Ok(());
    };
    match command.as_str() {
        "help" | "--help" => {
            println!("{HELP}");
            Ok(())
        }
        "observe" => observe(rest),
        "prepare" => prepare(rest),
        "inspect" => inspect_cmd(rest),
        _ => Err("expected observe, prepare, inspect or --help".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(
        addr: &str,
        slot: u64,
        fin: u64,
        fee: u128,
        utxos: Vec<EutxoEntry>,
    ) -> EndpointSnapshot {
        EndpointSnapshot {
            read: EndpointRead {
                addr: addr.into(),
                head_slot: slot,
                head_block: [slot as u8; 32],
                finalized_epoch: fin,
                finalized_root: [fin as u8; 32],
            },
            epoch: slot / SLOTS_PER_EPOCH,
            base_fee: fee,
            total: utxos.len() as u64,
            utxos,
        }
    }
    fn u(t: u8, v: u64, s: [u8; 32]) -> EutxoEntry {
        EutxoEntry {
            txid: [t; 32],
            vout: 0,
            value: v,
            script_hash: s,
        }
    }

    #[test]
    fn agreement_keeps_only_what_both_endpoints_report_identically() {
        let t = compiled_treasury_script();
        let a = snap(
            "a:1",
            300_000,
            9_370,
            10,
            vec![u(1, 5_000, t), u(2, 7_000, t)],
        );
        let b = snap(
            "b:1",
            300_002,
            9_370,
            10,
            vec![u(2, 7_000, t), u(3, 9_000, t)],
        );
        let (obs, notes) = agree(t, [0; 32], a, b).unwrap();
        assert_eq!(obs.utxos, vec![u(2, 7_000, t)]);
        assert_eq!(notes.len(), 2);
        assert_eq!(obs.epoch, 300_002 / SLOTS_PER_EPOCH);
    }

    #[test]
    fn agreement_refuses_every_disagreement() {
        let t = compiled_treasury_script();
        let base = || snap("a:1", 300_000, 9_370, 10, vec![u(1, 5_000, t)]);
        let other = |f: &dyn Fn(&mut EndpointSnapshot)| {
            let mut b = snap("b:1", 300_001, 9_370, 10, vec![u(1, 5_000, t)]);
            f(&mut b);
            b
        };
        let cases: Vec<(&str, EndpointSnapshot)> = vec![
            ("same node", other(&|b| b.read.addr = "a:1".into())),
            (
                "finalized epoch",
                other(&|b| b.read.finalized_epoch = 9_369),
            ),
            ("finalized root", other(&|b| b.read.finalized_root[0] ^= 1)),
            ("head gap", other(&|b| b.read.head_slot = 300_005)),
            ("base fee", other(&|b| b.base_fee = 11)),
            ("value", other(&|b| b.utxos[0].value = 5_001)),
            ("script", other(&|b| b.utxos[0].script_hash[0] ^= 1)),
        ];
        for (name, b) in cases {
            assert!(
                agree(t, [0; 32], base(), b).is_err(),
                "{name} must be refused"
            );
        }
        // Both report the same output under a foreign script: refused.
        let f = [0x55; 32];
        let a = snap("a:1", 300_000, 9_370, 10, vec![u(1, 5_000, f)]);
        let b = snap("b:1", 300_000, 9_370, 10, vec![u(1, 5_000, f)]);
        assert!(agree(t, [0; 32], a, b)
            .unwrap_err()
            .contains("another script"));
    }

    #[test]
    fn chain_info_with_a_null_finalized_height_is_a_halt() {
        let j = crate::rpc::parse_json(
            r#"{"block_id":"0101010101010101010101010101010101010101010101010101010101010101","slot":5,"wall_slot":5,"finalized_height":null,"finalized":{"epoch":0,"root":"0202020202020202020202020202020202020202020202020202020202020202"}}"#,
        )
        .unwrap();
        assert!(parse_chain_info("x:1", &j).unwrap_err().contains("halt"));
    }

    #[test]
    fn payments_parse_addresses_and_scripts() {
        let p =
            parse_payment("bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073:1000").unwrap();
        assert_eq!(
            (p.script_hash, p.value),
            (compiled_treasury_script(), 1_000)
        );
        let p = parse_payment(&format!("{}:2500", "33".repeat(32))).unwrap();
        assert_eq!((p.script_hash, p.value), ([0x33; 32], 2_500));
        assert!(parse_payment("33:1").is_err());
        assert!(parse_payment(&format!("{}:x", "33".repeat(32))).is_err());
    }
}
