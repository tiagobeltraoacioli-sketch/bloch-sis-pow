//! rehearsal-miner — a tiny multi-threaded SHA-256d Stratum miner for the
//! merged-mining REGTEST rehearsal (`scripts/regtest-merged-rehearsal.sh`).
//! NOT for production — it exists so the rehearsal has a CPU miner without an
//! external `minerd` build. It reuses the proxy's own (tested) share
//! reconstruction, so what it hashes is byte-identical to what the pool checks.
//!
//! Accepts minerd-style args: `-o stratum+tcp://host:port -u <user> [-p x]`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use bloch_pool_proxy::jobstore::{parse_notify_full, FullJob};
use bloch_pool_proxy::validator::{
    difficulty_to_target, hex_to_bytes, meets, sha256d, walk_merkle_branch,
};

#[derive(Clone)]
struct Work {
    job: FullJob,
    en1: Vec<u8>,
    en2_size: usize,
    ntime: u32,
    share_target: [u8; 32],
    gen: u64,
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (mut url, mut user) = (String::new(), String::from("x"));
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "-o" | "--url" => { url = a.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            "-u" | "--user" => { user = a.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            _ => { i += 1; }
        }
    }
    let addr = url.replace("stratum+tcp://", "").replace("stratum+tcp:", "");
    eprintln!("[miner] connecting to {addr} as {}", &user[..user.len().min(16)]);
    let stream = TcpStream::connect(&addr).expect("connect");
    stream.set_nodelay(true).ok();
    let mut wr = stream.try_clone().unwrap();
    let mut rd = BufReader::new(stream);
    let send = |w: &mut TcpStream, s: String| { let _ = w.write_all(s.as_bytes()); let _ = w.write_all(b"\n"); };

    send(&mut wr, r#"{"id":1,"method":"mining.subscribe","params":["rehearsal-miner"]}"#.into());

    // Shared current work + a submit channel drained by a writer thread.
    let work: Arc<Mutex<Option<Work>>> = Arc::new(Mutex::new(None));
    let gen = Arc::new(AtomicU64::new(0));
    let (subtx, subrx) = mpsc::channel::<String>();
    {
        let mut wr2 = wr.try_clone().unwrap();
        thread::spawn(move || { for line in subrx { send(&mut wr2, line); } });
    }

    // Worker threads: each scans nonces for its own extranonce2 lane.
    let threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4).max(2);
    eprintln!("[miner] {threads} hashing threads");
    for lane in 0..threads {
        let work = work.clone();
        let gen = gen.clone();
        let subtx = subtx.clone();
        let user = user.clone();
        thread::spawn(move || mine_lane(lane as u32, threads as u32, work, gen, subtx, user));
    }

    let mut en1: Vec<u8> = vec![];
    let mut en2_size = 4usize;
    let mut share_diff = 1.0f64;
    let mut line = String::new();
    loop {
        line.clear();
        if rd.read_line(&mut line).unwrap_or(0) == 0 { break; }
        let l = line.trim();
        if l.is_empty() { continue; }
        // subscribe result: {"id":1,"result":[[...],"<en1>",<en2size>],...}
        if l.contains("\"id\":1") && l.contains("\"result\"") {
            if let Some(v) = serde_json::from_str::<serde_json::Value>(l).ok() {
                if let Some(res) = v.get("result").and_then(|r| r.as_array()) {
                    if let Some(e1) = res.get(1).and_then(|x| x.as_str()) { en1 = hex_to_bytes(e1).unwrap_or_default(); }
                    if let Some(sz) = res.get(2).and_then(|x| x.as_u64()) { en2_size = sz as usize; }
                }
            }
            send(&mut wr, format!(r#"{{"id":2,"method":"mining.authorize","params":["{user}","x"]}}"#));
            continue;
        }
        if l.contains("mining.set_difficulty") {
            if let Some(v) = serde_json::from_str::<serde_json::Value>(l).ok() {
                if let Some(d) = v.get("params").and_then(|p| p.get(0)).and_then(|x| x.as_f64()) {
                    share_diff = d.max(1e-9);
                }
            }
            continue;
        }
        if l.contains("mining.notify") {
            if let Some(job) = parse_notify_full(l) {
                let ntime = serde_json::from_str::<serde_json::Value>(l).ok()
                    .and_then(|v| v.get("params").and_then(|p| p.get(7)).and_then(|x| x.as_str()).map(str::to_string))
                    .and_then(|s| u32::from_str_radix(s.trim(), 16).ok())
                    .unwrap_or(0);
                let g = gen.fetch_add(1, Ordering::SeqCst) + 1;
                *work.lock().unwrap() = Some(Work {
                    job, en1: en1.clone(), en2_size, ntime,
                    share_target: difficulty_to_target(share_diff), gen: g,
                });
                eprintln!("[miner] new job, share_diff={share_diff}");
            }
            continue;
        }
        // submit acks
        if l.contains("\"result\":true") { eprintln!("[miner] share accepted"); }
    }
}

fn mine_lane(
    lane: u32, stride: u32,
    work: Arc<Mutex<Option<Work>>>, gen: Arc<AtomicU64>,
    subtx: mpsc::Sender<String>, user: String,
) {
    let idle = AtomicBool::new(false);
    let mut en2_ctr: u64 = lane as u64;
    loop {
        let w = { work.lock().unwrap().clone() };
        let w = match w { Some(w) => w, None => { std::thread::sleep(std::time::Duration::from_millis(50)); continue; } };
        // Build coinbase with this lane's extranonce2, then scan the nonce space.
        let mut en2 = vec![0u8; w.en2_size];
        for (k, b) in en2.iter_mut().enumerate() { *b = ((en2_ctr >> (8 * k)) & 0xff) as u8; }
        en2_ctr += stride as u64;

        let mut coinbase = Vec::with_capacity(w.job.coinb1.len() + w.en1.len() + en2.len() + w.job.coinb2.len());
        coinbase.extend_from_slice(&w.job.coinb1);
        coinbase.extend_from_slice(&w.en1);
        coinbase.extend_from_slice(&en2);
        coinbase.extend_from_slice(&w.job.coinb2);
        let merkle_root = walk_merkle_branch(sha256d(&coinbase), &w.job.merkle_branch);

        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&w.job.version.to_le_bytes());
        header[4..36].copy_from_slice(&w.job.prevhash_raw);
        header[36..68].copy_from_slice(&merkle_root);
        header[68..72].copy_from_slice(&w.ntime.to_le_bytes());
        header[72..76].copy_from_slice(&w.job.nbits.to_le_bytes());

        let en2_hex = hex::encode(&en2);
        let ntime_hex = format!("{:08x}", w.ntime);
        // Scan a chunk of the nonce space for this (lane, en2); a fresh job aborts.
        for nonce in 0u32..=u32::MAX {
            if nonce & 0x3ffff == 0 && gen.load(Ordering::SeqCst) != w.gen { break; }
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
            let h = sha256d(&header);
            if meets(&h, &w.share_target, true) {
                let nonce_hex = format!("{nonce:08x}");
                let msg = format!(
                    r#"{{"id":4,"method":"mining.submit","params":["{user}","{}","{en2_hex}","{ntime_hex}","{nonce_hex}"]}}"#,
                    w.job.job_id
                );
                let _ = subtx.send(msg);
            }
        }
        let _ = &idle;
    }
}
