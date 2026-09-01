// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cold-node test: **a new node builds the chain itself, from genesis.**
//!
//! This is the one test that answers the question an exchange asks before it
//! will credit a deposit:
//!
//! > *"As an exchange we must run our own validating node — we cannot credit
//! > customer deposits based on a chain view we did not verify ourselves."*
//!
//! On Genesis-3 the answer is no, permanently: `docs/CARRYOVER.md` says syncing
//! from genesis is unsupported, and the block bodies such a sync would need
//! were dropped network-wide before the retention fix. A node bootstrapped from
//! the producer's datadir has verified nothing, and no test can change that.
//!
//! Here, three real `bloch-pos` processes run over the **libp2p transport**.
//! Two are validators and start at genesis. The third starts late with a data
//! dir that is **empty** — no keystore, no `blocks.log`, no `meta.bin`, nothing
//! copied from anyone. An empty data dir is **observer mode**, which
//! `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` §7.5 calls "the
//! right mode for an exchange": the node applies every block through the same
//! `Transition::apply_block` the validators ran, serves reads, and signs
//! nothing. It must reach the same chain by asking peers for history and
//! validating every block that comes back.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! REWRITTEN 2026-09-01. What the previous version did, why it was not
//! measuring what it claimed, and what replaced it. Read this before
//! "simplifying" anything below.
//!
//! ## 1. It judged by scraping stdout, and stdout does not report a reorg.
//!
//! The old assertions parsed `[slot N] applied <id> by vX — head root <root>`
//! out of each node's log and compared the two maps. But `apply_canonical`
//! (engine.rs) prints that line and **`do_reorg` does not** — a branch adopted
//! by fork choice prints one summary line, `REORG: adopted branch of N blocks
//! at ancestor …`, and no per-slot line for any block in it. So every block a
//! node acquired by reorg was invisible to the test.
//!
//! MEASURED, 2026-09-01, this machine, three-validator scenario, run 2 of 3:
//!     RPC:  cold node canonical blocks start at slot 4, 75 slots in common
//!           with the founder, ZERO disagreements on (block_id, state_root)
//!     LOG:  cold node's first `applied` line is slot 5
//!     => the old assertion `first_cold_slot <= first_founder_slot` FAILED
//!        (5 vs 4) on a node that was byte-for-byte on the founder's chain.
//! Slot 4 was adopted by `REORG: adopted branch of 1 blocks at ancestor
//! 9953da73 (head slot 22 -> 4)` and therefore never printed.
//!
//! The replacement asks the node, over its own JSON-RPC, what its canonical
//! chain *is* — `getblockbyslot` reads `self.chain`, so it is reorg-aware by
//! construction and cannot drift from consensus the way a log line can.
//!
//! ## 2. It ran entirely inside a window where fork choice has no weight, so
//!    its result was a coin flip on a hash comparison.
//!
//! The old test stopped at slot 45. `SLOTS_PER_EPOCH` is 32, and a validator's
//! attestation duty is once per epoch — with the genesis manifest putting slot
//! 0 six seconds out and PQ keygen eating most of that, the founders boot at
//! slot ~4, past their epoch-0 duty slots. MEASURED: in every run, the first
//! attestation on the whole network is at slot 32. Epoch 0 therefore carries
//! **zero votes**.
//!
//! With zero votes every subtree weight is 0, and `FcStore::head`
//! (forkchoice.rs) breaks a weight tie on `*child > best` — the
//! lexicographically largest child id. So during epoch 0 the canonical chain
//! is decided by a hash comparison, and a node that publishes a fresh block on
//! genesis wins roughly half the time no matter how much chain already exists.
//!
//! MEASURED, 2026-09-01, three-validator scenario, 2 runs of 3: the late node
//! proposed on genesis at slot 22 (it is a validator; nothing had reached it
//! yet), its block's id beat the existing branch's, and **both founders
//! reorged from head slot 21 back to genesis**, discarding thirteen blocks.
//! `REORG: adopted branch of 1 blocks at ancestor 9953da73 (head slot 21 ->
//! 22)`. Afterwards no node anywhere held a block below slot 22, so the old
//! test's "the cold node walked history" assertion failed on a network that
//! no longer had any history to walk.
//!
//! That is correct LMD-GHOST behaviour for an unvoted, unfinalised chain, not
//! a consensus defect — nothing was finalised, so nothing was protected. But
//! it makes any assertion taken inside epoch 0 a coin flip, which is why one
//! reviewer measured this test passing and two measured it failing.
//!
//! The replacement removes both halves of that:
//!   * the late node is an **observer** — it holds no key, so it cannot
//!     propose a competing block on genesis. That is also the configuration
//!     the integration book tells an exchange to run, so the test now models
//!     the claim actually being made to a third party.
//!   * every assertion is anchored to a **finalised** checkpoint. Finalised
//!     history can never be reorganised out (engine.rs §5.5), so a comparison
//!     over the finalised prefix is settled rather than racing the tip.
//!
//! ## 3. It compared the two `blocks.log` files byte-for-byte.
//!
//! Deleted. The previous version's own comment recorded it failing 1 run in 10
//! on two nodes that agreed about every block they shared, and correctly
//! diagnosed why: the founder rewrites its log whole on every reorg
//! (`Store::rewrite`) while a syncing node appends. Same chain, different write
//! order, different bytes. An assertion known to be false is not coverage.
//! State-root equality at every common slot is the stronger claim and it is
//! asserted below.
//!
//! ## 4. It stopped at a wall-clock slot and compared whatever had landed.
//!
//! Replaced by polling to a condition with a deadline. A healthy node converges
//! and the test passes as soon as it has; an unhealthy one never converges and
//! the test fails with the whole picture printed. Nothing depends on how much
//! chain a debug build with hybrid ML-DSA-65 ‖ Falcon-1024 signing managed to
//! produce on a loaded machine, which was the old test's other flake source.
//!
//! ## What this test does NOT cover, stated so nobody assumes it does
//!
//! * **A cold-starting VALIDATOR.** Covered until this rewrite, badly: see
//!   §2. A validator joining an unfinalised chain can drag it back to genesis,
//!   and that is a real property of the fork choice worth its own test with a
//!   finalised chain to join. It is not this test and it is not what the
//!   exchange is being told to run.
//! * **Cold sync at any real length.** This test builds ~160 blocks. §7.4 of
//!   the integration book says cold sync over `--transport devnet` does not
//!   complete and fails silently, reproduced at height 556 against a network
//!   at 1,511 — and `--transport devnet` is what its own run command uses.
//!   MEASURED 2026-09-01 on an idle 2-core host, this same scenario switched
//!   to `--transport devnet`, twice: the observer cold-synced cleanly, 160
//!   slots in common, zero disagreements, all three nodes finalising the same
//!   epoch-3 root. So the book's failure is about LENGTH, not about the
//!   transport's mechanism, and no run this short can reach it. **Do not read
//!   a pass here as evidence that cold sync works at mainnet height.** The
//!   ~26h-versus-16min gap between network sync and local replay is the thing
//!   that would have to close first, and it is being worked separately.
//! * **The `devnet` transport, in this test.** It runs libp2p, because that is
//!   what the previous version ran and switching it is a change of subject.
//!   Given the paragraph above, a devnet twin of this test is cheap and worth
//!   having.
//! * **Transactions.** Every block here is empty. State roots still move (the
//!   transition advances slots, RANDAO and attestation records), so root
//!   equality is a real check, but it is not evidence that a cold node
//!   reproduces UTXO state under load.
//!
//! ## Measured, 2026-09-01
//!
//! Old test, this laptop: 2 passes / 1 failure in 3. Reported elsewhere the
//! same week, same test: 1 pass in 4, and separately 0 in 3.
//!
//! New test, 15 runs, no failures:
//!   idle 2-core host            5/5   104.69, 104.81, 104.85, 104.73, 104.92 s
//!   same host, 4 busy loops     3/3   117.04, 118.13, 118.24 s   (load ~4.8)
//!   8-core laptop, load 31/15   2/2   144.95, 111.66 s
//!   idle host, earlier draft    5/5   110.61-111.09 s
//! A spread of 0.23 s across five idle runs is not luck: the test stops at a
//! condition (both nodes finalised the same checkpoint), not at a clock, so
//! the run ends when the chain is ready rather than when a timer says so.
//! `CONVERGE_DEADLINE` is therefore ~3.5x the worst time ever measured, not a
//! number tuned until the test went green.
//!
//! ## The controls it was verified against
//!
//! A test that only ever passes proves nothing, so each assertion was checked
//! by breaking what it watches. All three ran on the idle host:
//!   1. Observer isolated (it and the validators given peer lists that exclude
//!      each other) -> FAILS: "never converged", observer head slot 0, 0
//!      canonical blocks, validator at slot 255 finalised e5.
//!   2. Observer handed a manifest for a DIFFERENT chain (its own validator
//!      set, so a different genesis state root) -> FAILS the same way.
//!   3. One state root altered in the validator's reading before comparison
//!      -> FAILS at the per-slot assertion: "disagree at slot 4".
//! (A fourth attempt — giving the observer the same keys with a different
//! `--start-in` — correctly PASSED: that is the same chain with a clock
//! offset, not a different one. It is recorded because it is the mistake a
//! reader is likely to repeat.)
//! ─────────────────────────────────────────────────────────────────────────

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");

/// Slot cadence for the test chain. Fast enough to finish, slow enough that a
/// debug build with hybrid ML-DSA-65 ‖ Falcon-1024 signing keeps up.
const SLOT_MS: u64 = 1000;
/// Seconds the genesis manifest puts between `genesis` and slot 0.
const GENESIS_START_IN_SECS: u64 = 6;
/// How long after launching the validators the observer is started, in seconds.
const COLD_START_DELAY_SECS: u64 = 18;
/// The slot the chain has reached when the observer's process begins. Blocks
/// at earlier slots cannot have been gossiped to it live — it can only have
/// them by asking a peer for history and validating what came back.
const COLD_JOIN_SLOT: u64 = (COLD_START_DELAY_SECS - GENESIS_START_IN_SECS) * 1000 / SLOT_MS;
/// How long to wait for the observer to reach a finalised checkpoint that the
/// validator has also finalised.
///
/// Not a cadence estimate. Finality needs two consecutive justified epochs, so
/// ~3 × 32 slots at best, and this build signs post-quantum on a machine that
/// may be doing anything else. The number is deliberately far past that: the
/// claim under test is that the observer converges, so the only honest failure
/// is "it never did", and a deadline tight enough to be a race would put back
/// exactly the flakiness this rewrite removed.
const CONVERGE_DEADLINE: Duration = Duration::from_secs(420);
/// Slots the two nodes must have in common before the comparison means
/// anything. One epoch's worth of a chain that fills a fraction of its slots.
const MIN_COMMON_SLOTS: usize = 12;

struct Fleet(Vec<Child>);

impl Drop for Fleet {
    fn drop(&mut self) {
        // A panicking assertion must not leave validator processes running.
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn tmp_root() -> PathBuf {
    let d = std::env::temp_dir().join(format!("bloch-pos-coldstart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create test root");
    d
}

fn run_to_completion(args: &[&str]) -> String {
    let out = Command::new(BIN).args(args).output().expect("spawn bloch-pos");
    assert!(
        out.status.success(),
        "bloch-pos {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

// ── The node's own account of its canonical chain, over its own RPC ─────────
//
// Deliberately hand-rolled rather than pulled from the node crate: `bloch-pos`
// is a binary crate, so nothing in `src/` is reachable from `tests/`. It is
// also the point — this asks the node the same way an exchange's monitoring
// would, over the wire, with no shared code that could agree with a bug.
//
// The server is documented (rpc.rs) as the subset of HTTP/1.1 a JSON-RPC
// client uses: POST, `Content-Length`, no chunked encoding, no keep-alive. It
// answers `Connection: close`, so read-to-end is the whole body.

fn rpc(port: u16, method: &str, params: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(10))).ok()?;
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

/// The string value of `"<key>":"…"`, searched from `from`. Enough for a
/// response whose every field of interest is a hex string or a small integer;
/// this crate has no JSON dependency and one is not worth adding for four
/// fields.
fn field<'a>(json: &'a str, key: &str, from: usize) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let at = json[from..].find(&needle)? + from + needle.len();
    let rest = &json[at..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(&stripped[..end])
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if end == 0 {
            None
        } else {
            Some(&rest[..end])
        }
    }
}

/// `finalized` is a nested object, so its `epoch`/`root` must be read from
/// after the key rather than from the top of the response — `epoch` and `root`
/// both appear several times in `getchaininfo`.
fn finalized(json: &str) -> Option<(u64, String)> {
    let at = json.find("\"finalized\":{")?;
    let epoch = field(json, "epoch", at)?.parse().ok()?;
    let root = field(json, "root", at)?.to_string();
    Some((epoch, root))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Chain {
    /// `slot -> (block id, post-state root)`, the node's canonical chain as
    /// `getblockbyslot` reports it. That method reads `self.chain`, which is
    /// what fork choice maintains — so a block adopted by reorg is here, and a
    /// block on an abandoned branch is not.
    blocks: BTreeMap<u64, (String, String)>,
    head_slot: u64,
    finalized_epoch: u64,
    finalized_root: String,
}

/// The node's canonical chain, read one slot at a time up to its own head.
///
/// Bounded by the head the node just reported, NOT by a fixed ceiling. Every
/// `getblockbyslot` crosses the engine channel — the same single thread that
/// runs consensus — so a scan wider than the chain is not merely wasted work,
/// it is load applied to the thing under measurement. An earlier draft swept a
/// fixed 4,096 slots and spent roughly 180,000 round trips per run doing it.
fn chain_of(port: u16) -> Option<Chain> {
    let info = rpc(port, "getchaininfo", "[]")?;
    let head_slot: u64 = field(&info, "slot", 0)?.parse().ok()?;
    let (finalized_epoch, finalized_root) = finalized(&info)?;
    let mut blocks = BTreeMap::new();
    for slot in 1..=head_slot {
        let Some(resp) = rpc(port, "getblockbyslot", &format!("[{slot}]")) else {
            continue;
        };
        // A slot with no canonical block answers with its own error code and
        // is the ordinary proof-of-stake case (a missed proposal), not a fault.
        let Some(id) = field(&resp, "block_id", 0) else {
            continue;
        };
        let Some(root) = field(&resp, "state_root", 0) else {
            continue;
        };
        blocks.insert(slot, (id.to_string(), root.to_string()));
    }
    Some(Chain { blocks, head_slot, finalized_epoch, finalized_root })
}

fn spawn_node(dir: &Path, genesis: &Path, listen: u16, rpc_port: u16, peers: &[u16], log: &Path) -> Child {
    let peer_list = peers
        .iter()
        .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
        .collect::<Vec<_>>()
        .join(",");
    let out = std::fs::File::create(log).expect("create log");
    let err = out.try_clone().expect("dup log");
    Command::new(BIN)
        .args([
            "run",
            "--data-dir",
            dir.to_str().unwrap(),
            "--genesis",
            genesis.to_str().unwrap(),
            "--transport",
            "libp2p",
            "--p2p-listen",
            &format!("/ip4/127.0.0.1/tcp/{listen}"),
            "--p2p-peer",
            &peer_list,
            // Three nodes on one machine: the RPC's default port is a single
            // number, so leaving it on would have two of them fail to bind and
            // exit. A real operator gives each node its own; the test does the
            // same rather than disabling the server and testing less. The RPC
            // is now also how this test reads consensus, so it is load-bearing.
            //
            // Allocated by `free_port`, NOT derived as `listen + 1000`, which
            // is what this used to do and is why the test failed roughly one
            // run in five. `free_port` returns an OS-chosen EPHEMERAL port; on
            // macOS that range is 49152-65535, so `listen + 1000` overflows
            // u16 whenever the OS hands out anything above 64535 and the test
            // panics with "attempt to add with overflow" before a single node
            // starts.
            "--rpc-port",
            &rpc_port.to_string(),
            // The two validators are a chain launch orchestrated by one
            // operator — the documented case for disabling the doppelganger
            // watch. (The 6-second genesis head start is eaten by PQ keygen,
            // so they boot a few slots past slot 0 and the default watch would
            // silence the fleet for two epochs.) The observer holds no key, so
            // the flag is inert for it and passed uniformly.
            "--doppelganger-epochs",
            "0",
        ])
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn node")
}

#[test]
fn a_cold_node_builds_the_same_chain_from_genesis_without_a_donated_datadir() {
    let root = tmp_root();
    let genesis = root.join("genesis.bin");

    // Two validator keystores. `keygen` is explicitly throwaway devnet key
    // material; nothing here generates or touches a production key.
    for i in 0..2 {
        let dir = root.join(format!("d{i}"));
        run_to_completion(&["keygen", "--dir", dir.to_str().unwrap(), "--index", &i.to_string()]);
    }
    let keys = (0..2)
        .map(|i| root.join(format!("d{i}")).to_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join(",");
    run_to_completion(&[
        "genesis",
        "--keys",
        &keys,
        "--out",
        genesis.to_str().unwrap(),
        "--slot-ms",
        &SLOT_MS.to_string(),
        "--start-in",
        &GENESIS_START_IN_SECS.to_string(),
    ]);

    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let rpc_ports: Vec<u16> = (0..3).map(|_| free_port()).collect();

    let mut fleet = Fleet(Vec::new());
    for i in 0..2 {
        fleet.0.push(spawn_node(
            &root.join(format!("d{i}")),
            &genesis,
            ports[i],
            rpc_ports[i],
            &ports,
            &root.join(format!("n{i}.log")),
        ));
    }

    // The observer joins late. Its data dir is EMPTY — no keystore, no block
    // log, no meta marker, no state. That is the whole point: it is not handed
    // a database, it is handed a genesis manifest and a set of peers, exactly
    // like an exchange standing up a node today.
    std::thread::sleep(Duration::from_secs(COLD_START_DELAY_SECS));
    let cold_dir = root.join("d2");
    std::fs::create_dir_all(&cold_dir).expect("create observer dir");
    let cold_files: Vec<String> = std::fs::read_dir(&cold_dir)
        .expect("read cold dir")
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    assert!(
        cold_files.is_empty(),
        "the observer's data dir must be empty, not a donated database: found {cold_files:?}"
    );
    fleet.0.push(spawn_node(
        &cold_dir,
        &genesis,
        ports[2],
        rpc_ports[2],
        &ports,
        &root.join("n2.log"),
    ));

    let logs = || -> String {
        (0..3)
            .map(|i| {
                let name = if i == 2 { "observer" } else { "validator" };
                format!(
                    "\n--- n{i} ({name}) ---\n{}",
                    std::fs::read_to_string(root.join(format!("n{i}.log"))).unwrap_or_default()
                )
            })
            .collect()
    };

    // The observer must actually be in observer mode. If a keystore ever
    // appeared in that directory the rest of this test would be measuring a
    // different scenario, so it is checked against the node's own banner
    // rather than assumed from the empty dir.
    {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let log = std::fs::read_to_string(root.join("n2.log")).unwrap_or_default();
            if log.contains("observer mode: no keystore") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "n2 never announced observer mode; it is not the node this test claims to \
                 be testing{}",
                logs()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    // ── Poll to a settled condition, rather than stopping at a wall slot and
    //    comparing whatever happened to have landed. ─────────────────────────
    //
    // The condition is finality, because finality is the only point at which
    // "these two nodes are on the same chain" stops being a statement about a
    // racing tip. Once both have finalised the same (epoch, root), the prefix
    // below it is settled on both by the consensus rules themselves.
    let deadline = Instant::now() + CONVERGE_DEADLINE;
    let mut last = String::from("(never got a full reading from both nodes)");
    let (founder, cold) = loop {
        if Instant::now() >= deadline {
            panic!(
                "the observer never converged with the validator within {:?}.\n\
                 last reading: {last}\n\
                 THIS IS THE FAILURE THAT MATTERS: a node handed nothing but a genesis \
                 manifest and a peer list did not reach the network's chain. Do not \
                 relax this test to make it pass.{}",
                CONVERGE_DEADLINE,
                logs()
            );
        }
        // Any node that died took the answer with it; say so instead of
        // timing out on a corpse.
        for (i, c) in fleet.0.iter_mut().enumerate() {
            if let Ok(Some(status)) = c.try_wait() {
                panic!("n{i} exited early with {status}{}", logs());
            }
        }
        std::thread::sleep(Duration::from_secs(5));

        // Read the observer FIRST and the validator second. Both readings walk
        // a live chain, so the later one is always at least as far along;
        // reading the observer first means any skew makes the observer look
        // BEHIND, never ahead, and a test that could be fooled by skew would
        // be fooled in the direction of passing.
        let Some(c) = chain_of(rpc_ports[2]) else { continue };
        let Some(f) = chain_of(rpc_ports[0]) else { continue };

        let common: Vec<u64> = c.blocks.keys().filter(|s| f.blocks.contains_key(s)).copied().collect();
        let history: Vec<u64> = c.blocks.keys().filter(|s| **s < COLD_JOIN_SLOT).copied().collect();
        last = format!(
            "observer head slot {} ({} canonical blocks, finalized e{} {}), \
             validator head slot {} ({} blocks, finalized e{} {}), \
             {} slots in common, {} of them from before the observer existed",
            c.head_slot,
            c.blocks.len(),
            c.finalized_epoch,
            &c.finalized_root[..c.finalized_root.len().min(12)],
            f.head_slot,
            f.blocks.len(),
            f.finalized_epoch,
            &f.finalized_root[..f.finalized_root.len().min(12)],
            common.len(),
            history.len(),
        );

        // Settled: both have finalised something past genesis, they agree on
        // what, and there is enough common chain to compare.
        if c.finalized_epoch > 0
            && c.finalized_epoch == f.finalized_epoch
            && c.finalized_root == f.finalized_root
            && common.len() >= MIN_COMMON_SLOTS
            && !history.is_empty()
        {
            break (f, c);
        }
    };

    let common: Vec<u64> = cold
        .blocks
        .keys()
        .filter(|s| founder.blocks.contains_key(s))
        .copied()
        .collect();
    let ctx = || {
        format!(
            "\nobserver: {} canonical blocks, head slot {}, finalized e{} ({})\
             \nvalidator: {} canonical blocks, head slot {}, finalized e{} ({})\
             \ncommon slots: {common:?}{}",
            cold.blocks.len(),
            cold.head_slot,
            cold.finalized_epoch,
            cold.finalized_root,
            founder.blocks.len(),
            founder.head_slot,
            founder.finalized_epoch,
            founder.finalized_root,
            logs()
        )
    };

    // 1. It walked history: it holds canonical blocks from slots that had
    //    already passed when its process started. Those cannot have reached it
    //    by live gossip — it can only have them by asking a peer and
    //    validating what came back through `Transition::apply_block`.
    let history: Vec<u64> = cold.blocks.keys().filter(|s| **s < COLD_JOIN_SLOT).copied().collect();
    assert!(
        !history.is_empty(),
        "the observer holds no canonical block from before slot {COLD_JOIN_SLOT}, when its \
         process started — nothing here proves it synced history rather than followed the \
         live tip{}",
        ctx()
    );

    // 2. Where both nodes hold a canonical block for the same slot, they must
    //    agree on which block it was AND on the state it produced. This is
    //    state-root equality at a common point, which is what "we verified it
    //    ourselves and got the same answer" means.
    //
    //    Compared per slot rather than at the head on purpose: the two nodes
    //    are read microseconds apart on a live chain and the last block can
    //    legitimately be on one and not the other, so a head comparison would
    //    be a race. The finalised prefix is not a race, and it is a subset of
    //    what is compared here.
    assert!(
        common.len() >= MIN_COMMON_SLOTS,
        "only {} slots in common — not enough to compare{}",
        common.len(),
        ctx()
    );
    for slot in &common {
        assert_eq!(
            cold.blocks[slot],
            founder.blocks[slot],
            "observer and validator disagree at slot {slot}: the independently rebuilt state \
             is not the same state{}",
            ctx()
        );
    }

    // 3. They finalised the same checkpoint. This is the assertion the other
    //    two rest on: a finalised root can never be reorganised out, so slot
    //    agreement below it is permanent rather than a snapshot of two tips
    //    that happen to line up. It is also exactly the check
    //    `~/bloch-rollout/detecta-bifurcado.sh` runs against the live fleet —
    //    a forked node answers, attests and reads `behind_by_slots = 0`, and
    //    the finalised root is what gives it away.
    assert_eq!(
        (cold.finalized_epoch, &cold.finalized_root),
        (founder.finalized_epoch, &founder.finalized_root),
        "observer and validator finalised different checkpoints{}",
        ctx()
    );
    assert!(
        cold.finalized_epoch > 0,
        "nothing was ever finalised, so nothing here is settled{}",
        ctx()
    );

    let _ = std::fs::remove_dir_all(&root);
}
