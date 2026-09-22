//! Coherence shielded-spend prover service (SP1 / hash-STARK / FRI).
//!
//! Experimental candidate service requiring a separately built SP1 guest.
//! It produces raw core proofs of the implemented check_spend relation only.
//! See ../AUTHORIZATION-BLOCKER.md: the relation does not establish complete
//! spend authorization, and this service does not activate node verification.
//! Helper/unit codec tests are not an actual SP1 proof qualification.
//!
//! SECURITY (Round-2 audit P123):
//! - P-2: the prover client is built EXPLICITLY (`.cpu()` / `.cuda()`), never
//!   from the environment, and `SP1_PROVER=mock` in the environment aborts
//!   startup — a mock prover would mint "proofs" that env-driven verifiers
//!   accept.
//! - P-3: auth is FAIL-CLOSED — the service refuses to start without a real
//!   `PROVER_AUTH_TOKEN` (placeholders like `CHANGE_ME…` are rejected as
//!   missing); and because `/prove` carries the FULL PRIVATE WITNESS, requests
//!   must arrive over TLS: the service rejects any request whose
//!   `x-forwarded-proto` is not `https` (set by Fly's force_https edge and by
//!   the Akash caddy TLS sidecar). Debug builds may opt out with
//!   `PROVER_ALLOW_UNAUTHENTICATED=1` / `PROVER_ALLOW_PLAINTEXT=1` for local
//!   testing; release builds refuse those overrides.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use coherence_core::{check_spend, SpendPublic, SpendWitness};
use serde::{Deserialize, Serialize};
use sp1_sdk::{Prover, ProverClient, SP1Stdin};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
mod request_guard;
mod wire;
use request_guard::{AccessPolicy, guarded_routes, run_bounded};
#[cfg(test)]
use request_guard::{forwarded_proto_is_https, token_matches};

/// P-4 fix: pre-decode ceiling on the base64 wire form of a `/verify` proof,
/// checked BEFORE any base64 decode is attempted (cheapest-check-first). Sized
/// generously above [`MAX_VERIFY_PROOF_BYTES`] to account for base64 expansion
/// (~4/3) plus JSON/whitespace overhead.
const MAX_VERIFY_B64_LEN: usize = 24 * 1024 * 1024; // 24 MiB
/// P-4 fix: ceiling on the DECODED proof bytes handed to `bincode`. bincode 1.x's
/// default configuration applies no byte limit. The configured limit bounds
/// bytes consumed, not all allocations or CPU work caused by decoded structures.
const MAX_VERIFY_PROOF_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
/// P-4 fix: wall-clock deadline for `/verify` — cheap relative to `/prove`, so a
/// short HTTP timeout is appropriate. A timed-out native worker continues;
/// its separate worker permit remains held until it actually exits.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// P-4 fix: wall-clock deadline for `/prove`. Generous — CPU proving of a real
/// spend circuit can legitimately take minutes. This bounds response waiting,
/// not native computation. Worker-owned slots prevent timed-out work piling up.
const PROVE_TIMEOUT: Duration = Duration::from_secs(1800); // 30 min
/// P-4 fix: per-route concurrency ceiling. `fly.toml` already runs one machine
/// (`hard_limit = 1`), so this is defence in depth against a future deployment
/// profile that raises it, and it bounds in-process concurrent GPU/CPU work
/// regardless of the caller's identity — a coarser, always-on backstop to the
/// per-token limiting a future iteration could add.
const MAX_CONCURRENT_PROVES: usize = 2;
const MAX_CONCURRENT_VERIFIES: usize = 8;

/// The guest ELF, built by `cargo prove build` in ../program (baked at image
/// build time).
#[cfg(not(test))]
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

// Unit helpers never set up or prove this placeholder. Production still requires the ELF.
#[cfg(test)]
const ELF: &[u8] = &[];

/// EXPLICIT prover backend — never `ProverClient::from_env()` (audit P123 P-2:
/// `SP1_PROVER=mock` must not be able to select a proof-fabricating backend).
#[cfg(feature = "cuda")]
type ProverImpl = sp1_sdk::CudaProver;
#[cfg(not(feature = "cuda"))]
type ProverImpl = sp1_sdk::CpuProver;

fn build_prover() -> ProverImpl {
    #[cfg(feature = "cuda")]
    {
        ProverClient::builder().cuda().build()
    }
    #[cfg(not(feature = "cuda"))]
    {
        ProverClient::builder().cpu().build()
    }
}

struct AppState {
    client: ProverImpl,
    pk: sp1_sdk::SP1ProvingKey,
    vk: sp1_sdk::SP1VerifyingKey,
    prove_slots: Arc<tokio::sync::Semaphore>,
    verify_slots: Arc<tokio::sync::Semaphore>,
}

// ── pure, unit-tested security decisions (audit P123 P-2/P-3) ─────────────────

/// Refuse to run at all under `SP1_PROVER=mock`: the explicit builder ignores
/// the env, but an operator who set it believes mock proving is active — abort
/// loudly instead of silently proving for real (or worse, a future refactor
/// reintroducing an env-driven client going unnoticed).
fn mock_env_error(sp1_prover_env: Option<&str>) -> Option<String> {
    match sp1_prover_env.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("mock") => Some(
            "SP1_PROVER=mock refused: mock proofs are fabrications that env-driven \
             verifiers accept. Unset SP1_PROVER (the backend is chosen explicitly)."
                .into(),
        ),
        _ => None,
    }
}

/// Validate the auth-token configuration, FAIL-CLOSED.
/// Ok(Some(token)) = real token; Ok(None) = explicit debug-only unauthenticated
/// opt-out; Err = refuse to start.
fn required_auth_token(
    token_env: Option<String>,
    allow_unauth_env: Option<&str>,
    debug_build: bool,
) -> Result<Option<String>, String> {
    let opt_out = allow_unauth_env.map(str::trim) == Some("1");
    match token_env.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()) {
        Some(t) if t.starts_with("CHANGE_ME") || t.to_ascii_uppercase().contains("CHANGEME") => {
            Err("PROVER_AUTH_TOKEN is a placeholder (CHANGE_ME…). Set a real token: \
                 openssl rand -hex 32"
                .into())
        }
        Some(t) if t.len() < 32 => {
            Err("PROVER_AUTH_TOKEN too short (< 32 chars). Set a real token: \
                 openssl rand -hex 32"
                .into())
        }
        Some(t) => Ok(Some(t)),
        None if opt_out && debug_build => Ok(None),
        None if opt_out => Err(
            "PROVER_ALLOW_UNAUTHENTICATED=1 is refused in release builds. Set \
             PROVER_AUTH_TOKEN (openssl rand -hex 32)."
                .into(),
        ),
        None => Err(
            "PROVER_AUTH_TOKEN unset — refusing to serve /prove unauthenticated \
             (fail-closed). Set it: openssl rand -hex 32"
                .into(),
        ),
    }
}

/// TLS requirement configuration: plaintext opt-out is debug-build-only.
fn require_tls(allow_plain_env: Option<&str>, debug_build: bool) -> Result<bool, String> {
    match allow_plain_env.map(str::trim) {
        Some("1") if debug_build => Ok(false),
        Some("1") => Err(
            "PROVER_ALLOW_PLAINTEXT=1 is refused in release builds: /prove carries \
             the full private witness and MUST arrive over TLS."
                .into(),
        ),
        _ => Ok(true),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Some(err) = mock_env_error(std::env::var("SP1_PROVER").ok().as_deref()) {
        eprintln!("{err}");
        std::process::exit(1);
    }
    let auth_token = match required_auth_token(
        std::env::var("PROVER_AUTH_TOKEN").ok(),
        std::env::var("PROVER_ALLOW_UNAUTHENTICATED").ok().as_deref(),
        cfg!(debug_assertions),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if auth_token.is_none() {
        tracing::warn!("PROVER_ALLOW_UNAUTHENTICATED=1 (debug build): /prove is UNAUTHENTICATED");
    }
    let req_tls = match require_tls(
        std::env::var("PROVER_ALLOW_PLAINTEXT").ok().as_deref(),
        cfg!(debug_assertions),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    // EXPLICIT backend — never from_env (audit P123 P-2).
    let client = build_prover();
    let (pk, vk) = client.setup(ELF);
    tracing::info!(vkey = %sp1_sdk::HashableKey::bytes32(&vk), "guest vkey (pin this in the node)");

    let policy = Arc::new(AccessPolicy { auth_token, require_tls: req_tls });
    let state = Arc::new(AppState { client, pk, vk,
        prove_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROVES)),
        verify_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFIES)) });

    let app = guarded_routes(
        post(prove)
            .layer::<_, std::convert::Infallible>(DefaultBodyLimit::max(64 * 1024 * 1024))
            .layer::<_, std::convert::Infallible>(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, PROVE_TIMEOUT))
            .layer::<_, std::convert::Infallible>(ConcurrencyLimitLayer::new(MAX_CONCURRENT_PROVES)),
        post(verify)
            .layer::<_, std::convert::Infallible>(DefaultBodyLimit::max(MAX_VERIFY_B64_LEN + 4096))
            .layer::<_, std::convert::Infallible>(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, VERIFY_TIMEOUT))
            .layer::<_, std::convert::Infallible>(ConcurrencyLimitLayer::new(MAX_CONCURRENT_VERIFIES)),
        policy,
    ).with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let addr = format!("0.0.0.0:{port}");
    tracing::info!("coherence-prover-service listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

#[derive(Deserialize)]
struct ProveReq {
    public: SpendPublic,
    witness: SpendWitness,
}

#[derive(Serialize)]
struct ProveResp {
    /// Raw FRI proof bytes (base64) → goes into ShieldedTx.proof on the wire.
    proof_b64: String,
}

#[derive(Deserialize)]
struct VerifyReq {
    proof_b64: String,
    /// P-5 fix: which statement the caller is asking about. Without this, the
    /// endpoint could only answer "some valid spend proof exists for this
    /// guest", not "this proof authorises the spend you are asking about" —
    /// any caller gating a decision on `/verify` was trivially fooled by
    /// replaying any previously issued proof.
    public: SpendPublic,
}

#[derive(Serialize)]
struct VerifyResp {
    valid: bool,
}

async fn prove(
    State(state): State<Arc<AppState>>, Json(req): Json<ProveReq>,
) -> Result<Json<ProveResp>, (StatusCode, String)> {
    run_bounded(state.prove_slots.clone(), move || prove_sync(&state, req)).await?
}

fn prove_sync(state: &AppState, req: ProveReq) -> Result<Json<ProveResp>, (StatusCode, String)> {
    // Fail fast: don't burn GPU minutes on a witness that won't satisfy the
    // statement (the guest would abort anyway).
    if let Err(e) = check_spend(&req.public, &req.witness) {
        return Err((StatusCode::BAD_REQUEST, format!("spend statement violated: {e:?}")));
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&req.public);
    stdin.write(&req.witness);

    let (client, pk) = (&state.client, &state.pk);
    // POST-QUANTUM: the CORE STARK/FRI proof. Never .groth16()/.plonk().
    let proof = client.prove(pk, &stdin).core().run()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove failed: {e}")))?;

    let bytes = bincode_proof(&proof).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(ProveResp { proof_b64: B64.encode(bytes) }))
}

async fn verify(
    State(state): State<Arc<AppState>>, Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    run_bounded(state.verify_slots.clone(), move || verify_sync(&state, req)).await?
}

fn verify_sync(state: &AppState, req: VerifyReq) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    // P-4 fix: cheapest check first — reject an oversized wire payload before
    // spending a single cycle on base64.
    if req.proof_b64.len() > MAX_VERIFY_B64_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("proof_b64 exceeds {MAX_VERIFY_B64_LEN} bytes"),
        ));
    }
    let bytes = B64
        .decode(req.proof_b64.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad base64: {e}")))?;
    // P-4 fix: independent cap on the DECODED bytes (defence in depth — base64
    // decoding cannot expand, but this keeps the invariant explicit rather than
    // implied by the encoded-length check above).
    if bytes.len() as u64 > MAX_VERIFY_PROOF_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("decoded proof exceeds {MAX_VERIFY_PROOF_BYTES} bytes"),
        ));
    }
    let proof = unbincode_proof_bounded(&bytes).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Raw core STARK only — a mock/wrapped proof is invalid by shape (P-6/P-7:
    // cheap, before the expensive cryptographic verify below).
    let is_core = matches!(&proof.proof, sp1_sdk::SP1Proof::Core(shards) if !shards.is_empty());
    if !is_core {
        return Ok(Json(VerifyResp { valid: false }));
    }

    // P-5 fix: bind the proof to the caller's claimed statement BEFORE running
    // the expensive cryptographic verify — a byte-exact comparison of the
    // proof's committed public values against the canonical (bincode) encoding
    // of `req.public`. This is the SAME encoding `SP1PublicValues::write`
    // (called by the guest's `sp1_zkvm::io::commit(&public)`) produces, so a
    // proof that genuinely commits to `req.public` always matches here; nothing
    // about this comparison is cryptographic on its own (an attacker can put
    // anything in `proof.public_values`), but the follow-up `client.verify`
    // call is what actually proves the STARK ties the two together — this
    // check exists so a MISMATCHED (proof, public) pair is rejected without
    // ever reaching that expensive call.
    let expected_public = bincode::serialize(&req.public)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("encode public: {e}")))?;
    if proof.public_values.as_slice() != expected_public.as_slice() {
        return Ok(Json(VerifyResp { valid: false }));
    }

    // The expensive cryptographic check, run LAST (cheapest-check-first): only
    // reached once the proof has already passed every cheap structural and
    // statement-identity check above.
    let valid = state.client.verify(&proof, &state.vk).is_ok();
    Ok(Json(VerifyResp { valid }))
}

// SP1 proofs are serializable; bincode v1 wire format (the node reads the same).
fn bincode_proof(p: &sp1_sdk::SP1ProofWithPublicValues) -> Result<Vec<u8>, String> {
    wire::encode_bounded(p, MAX_VERIFY_PROOF_BYTES)
}

/// P-4 fix: decode with an explicit size limit. bincode 1.x's default
/// (`bincode::deserialize`, used here previously) applies NO length limit, so a
/// decoding budget is expressed in bytes consumed; it is not a total allocator
/// or CPU budget. Fixed-int encoding matches bincode::serialize; trailing bytes
/// are rejected explicitly.
fn unbincode_proof_bounded(b: &[u8]) -> Result<sp1_sdk::SP1ProofWithPublicValues, String> {
    wire::decode_bounded(b, MAX_VERIFY_PROOF_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_sp1_container_uses_existing_fixed_int_wire() {
        // A codec fixture only: empty Core shards are intentionally NOT a valid proof.
        let proof = sp1_sdk::SP1ProofWithPublicValues {
            proof: sp1_sdk::SP1Proof::Core(vec![]),
            public_values: sp1_sdk::SP1PublicValues::from(&[1, 2, 3]),
            sp1_version: "codec-fixture".into(), tee_proof: None,
        };
        let encoded = bincode_proof(&proof).unwrap();
        let decoded = unbincode_proof_bounded(&encoded).unwrap();
        assert_eq!(bincode_proof(&decoded).unwrap(), encoded);
        assert_eq!(decoded.public_values.as_slice(), &[1, 2, 3]);
        let mut trailing = encoded; trailing.push(0);
        assert!(unbincode_proof_bounded(&trailing).is_err());
    }

    // ── P-2: mock env refused ────────────────────────────────────────────────
    #[test]
    fn mock_env_is_refused() {
        assert!(mock_env_error(Some("mock")).is_some());
        assert!(mock_env_error(Some("MOCK")).is_some());
        assert!(mock_env_error(Some(" mock ")).is_some());
        assert!(mock_env_error(Some("cpu")).is_none());
        assert!(mock_env_error(None).is_none());
    }

    // ── P-3: fail-closed auth ────────────────────────────────────────────────
    #[test]
    fn missing_token_fails_closed() {
        assert!(required_auth_token(None, None, false).is_err());
        assert!(required_auth_token(None, None, true).is_err());
        assert!(required_auth_token(Some("".into()), None, true).is_err());
        // Release build refuses the unauthenticated opt-out too.
        assert!(required_auth_token(None, Some("1"), false).is_err());
        // Debug build + explicit opt-out only.
        assert_eq!(required_auth_token(None, Some("1"), true), Ok(None));
    }

    #[test]
    fn placeholder_and_weak_tokens_are_rejected() {
        assert!(required_auth_token(Some("CHANGE_ME_openssl_rand_hex_32".into()), None, false).is_err());
        assert!(required_auth_token(Some("change_me".to_uppercase()), None, true).is_err());
        assert!(required_auth_token(Some("short".into()), None, false).is_err());
        let real = "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c";
        assert_eq!(required_auth_token(Some(real.into()), None, false), Ok(Some(real.into())));
    }

    #[test]
    fn token_compare_is_exact() {
        assert!(token_matches("abcd", "abcd"));
        assert!(!token_matches("abcd", "abce"));
        assert!(!token_matches("abcd", "abc"));
        assert!(!token_matches("abcd", ""));
    }

    // ── P-3: TLS required ────────────────────────────────────────────────────
    #[test]
    fn plaintext_is_rejected_unless_debug_opt_out() {
        assert_eq!(require_tls(None, false), Ok(true));
        assert_eq!(require_tls(None, true), Ok(true));
        assert_eq!(require_tls(Some("1"), true), Ok(false));
        assert!(require_tls(Some("1"), false).is_err()); // refused in release
    }

    #[test]
    fn forwarded_proto_must_be_https() {
        assert!(forwarded_proto_is_https(Some("https")));
        assert!(forwarded_proto_is_https(Some("HTTPS")));
        assert!(forwarded_proto_is_https(Some("https, http")));
        assert!(!forwarded_proto_is_https(Some("http")));
        assert!(!forwarded_proto_is_https(Some("http, https")));
        assert!(!forwarded_proto_is_https(None));
        assert!(!forwarded_proto_is_https(Some("")));
    }
}
