use super::*;
use bloch_pos_committee::{state_root::EutxoEntry, transition::native_dex::wallet_projection};
use serde_json::{json, Value};
use std::{cell::RefCell, collections::BTreeMap};
use zeroize::Zeroize;
const MAX: usize = 16 * 1024 * 1024;
thread_local! {static SESSION:RefCell<Option<Session>>=const{RefCell::new(None)};static BUFFERS:RefCell<BTreeMap<usize,Box<[u8]>>>=RefCell::new(BTreeMap::new());}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str, &'static str> {
    v.get(k).and_then(Value::as_str).ok_or("missing string")
}
fn number<T: std::str::FromStr>(v: &Value, k: &str) -> Result<T, &'static str> {
    let s = string(v, k)?;
    if s.is_empty()
        || s.len() > 39
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical integer");
    }
    s.parse().map_err(|_| "integer overflow")
}
fn bytes(v: &Value, k: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    let s = string(v, k)?;
    if s.len() > max * 2
        || s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid hex");
    }
    hex::decode(s).map_err(|_| "invalid hex")
}
fn hash(v: &Value, k: &str) -> Result<[u8; 32], &'static str> {
    bytes(v, k, 32)?.try_into().map_err(|_| "invalid hash")
}
fn context(v: &Value, domain: [u8; 32]) -> Result<State, &'static str> {
    let rows = v
        .get("utxos")
        .and_then(Value::as_array)
        .ok_or("missing utxos")?;
    if rows.len() > 4096 {
        return Err("utxo limit");
    }
    let utxos = rows
        .iter()
        .map(|u| {
            Ok(EutxoEntry {
                txid: hash(u, "txid")?,
                vout: number(u, "vout")?,
                value: number(u, "value")?,
                script_hash: hash(u, "scriptHash")?,
            })
        })
        .collect::<Result<Vec<_>, &str>>()?;
    let base = wallet_projection::base(
        domain,
        &utxos,
        number(v, "baseFeeMillisatPerGas")?,
        number(v, "blockGasUsed")?,
        number(v, "blockTxBytes")?,
        number(v, "epoch")?,
    )
    .map_err(|_| "invalid base projection")?;
    State::wallet_review_projection(
        base,
        &bytes(v, "nativeSnapshotHex", 4 * 1024 * 1024)?,
        hash(v, "nativeCommitmentHex")?,
        &Hybrid,
    )
    .map_err(|_| "invalid native snapshot")
}
pub(crate) fn dispatch(mut request: Value) -> Result<Value, &'static str> {
    let result = dispatch_inner(&mut request);
    if let Some(Value::String(seed)) = request.get_mut("args").and_then(|a| a.get_mut("seedHex")) {
        seed.zeroize();
    }
    if result.is_err() {
        SESSION.with(|s| {
            if let Some(session) = s.borrow_mut().as_mut() {
                session.cancel();
            }
        });
    }
    result
}
fn dispatch_inner(request: &mut Value) -> Result<Value, &'static str> {
    let method = string(&request, "method")?.to_owned();
    let args = request.get_mut("args").ok_or("missing args")?;
    if method == "open" {
        SESSION.with(|s| *s.borrow_mut() = None);
        let domain = hash(args, "domainHex")?;
        let seed = Zeroizing::new(bytes(args, "seedHex", 32)?);
        if let Some(Value::String(raw)) = args.get_mut("seedHex") {
            raw.zeroize();
        }
        let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| "invalid seed")?;
        let session = Session::open(seed, domain)?;
        let result = json!({"publicKeyHex":hex::encode(session.public_key()),"domainHex":hex::encode(domain)});
        SESSION.with(|s| *s.borrow_mut() = Some(session));
        return Ok(result);
    }
    SESSION.with(|cell|{
  let mut slot=cell.borrow_mut();
  if method=="lock"{*slot=None;return Ok(json!({"locked":true}))}
  let session=slot.as_mut().ok_or("locked")?;
  if method=="cancel"{session.cancel();return Ok(json!({"cancelled":true}))}
  if method!="review"&&method!="sign"{return Err("unsupported method")}
  // Any malformed follow-up consumes the pending review as well.
  let parsed=(||Ok((context(args.get("context").ok_or("missing context")?,session.domain)?,bytes(args,"transactionHex",262144)?,number::<u64>(args,"height")?)))();
  let (state,packet,height)=match parsed{Ok(p)=>p,Err(e)=>{session.cancel();return Err(e)}};
  if method=="review"{
   let r=session.prepare(&state,&packet,height)?;
   Ok(json!({"id":hex::encode(r.id),"authorization":hex::encode(r.authorization),"stateRoot":hex::encode(r.state_root),"publicKeyHex":hex::encode(r.public_key),"gas":r.gas.to_string(),"feeSat":r.fee_sat.to_string(),"expires":r.expires.to_string(),"fundingSats":r.funding_sats.to_string(),"walletOutputsSats":r.wallet_outputs_sats.to_string(),"packetHex":hex::encode(r.packet),"contextTrust":"host-authenticated-projection","finalityVerified":false}))
  }else{
   let id=match hash(args,"reviewId"){Ok(id)=>id,Err(e)=>{session.cancel();return Err(e)}};
   let signed=session.sign(id,&state,&packet,height,args.get("confirmed")==Some(&Value::Bool(true)))?;
   Ok(json!({"transactionHex":hex::encode(signed)}))
  }
 })
}
#[no_mangle]
pub extern "C" fn nw_alloc(len: u32) -> usize {
    if len == 0 || len as usize > MAX {
        return 0;
    }
    if !BUFFERS.with(|b| {
        let map = b.borrow();
        map.len() < 4 && map.values().map(|v| v.len()).sum::<usize>() + len as usize <= 2 * MAX
    }) {
        return 0;
    }
    let mut bytes = vec![0; len as usize].into_boxed_slice();
    let ptr = bytes.as_mut_ptr() as usize;
    BUFFERS.with(|b| b.borrow_mut().insert(ptr, bytes));
    ptr
}
#[no_mangle]
pub extern "C" fn nw_free(ptr: usize, len: u32) {
    BUFFERS.with(|b| {
        let mut map = b.borrow_mut();
        if map.get(&ptr).is_some_and(|v| v.len() == len as usize) {
            if let Some(mut bytes) = map.remove(&ptr) {
                bytes.zeroize();
            }
        }
    });
}
#[no_mangle]
pub extern "C" fn nw_call(ptr: usize, len: u32) -> u64 {
    let request = BUFFERS.with(|b| {
        let map = b.borrow();
        let bytes = map
            .get(&ptr)
            .filter(|v| v.len() == len as usize)
            .ok_or("invalid request buffer")?;
        serde_json::from_slice(bytes).map_err(|_| "invalid JSON")
    });
    let response = match request.and_then(dispatch) {
        Ok(result) => json!({"ok":true,"result":result}),
        Err(error) => json!({"ok":false,"error":error}),
    };
    if response.get("ok") == Some(&Value::Bool(false)) {
        SESSION.with(|s| {
            if let Some(session) = s.borrow_mut().as_mut() {
                session.cancel();
            }
        });
    }
    let encoded = serde_json::to_vec(&response).expect("JSON response");
    let len = encoded.len() as u32;
    let ptr = nw_alloc(len);
    BUFFERS.with(|b| {
        b.borrow_mut()
            .get_mut(&ptr)
            .expect("response allocation")
            .copy_from_slice(&encoded)
    });
    ((ptr as u64) << 32) | u64::from(len)
}
