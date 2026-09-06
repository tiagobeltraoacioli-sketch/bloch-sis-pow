//! Coherence shielded-spend prover service (SP1 / hash-STARK / FRI).
//!
//! Deployed on a server with the SP1 toolchain (Fly.io / Akash GPU). A wallet
//! POSTs the public inputs + private witness to `/prove` and gets back a RAW
//! FRI proof (post-quantum) that `check_spend` held — never a Groth16/PLONK
//! wrap. `/verify` checks a proof (the node verifies FRI locally in production;
//! this endpoint is for tooling/tests).
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

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use coherence_core::{check_spend, SpendPublic, SpendWitness};
use serde::{Deserialize, Serialize};
use sp1_sdk::{Prover, ProverClient, SP1Stdin};

/// The guest ELF, built by `cargo prove build` in ../program (baked at image
/// build time).
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

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
    /// Bearer token guarding `/prove`. `None` ONLY via the debug-build
    /// `PROVER_ALLOW_UNAUTHENTICATED=1` opt-out.
    auth_token: Option<String>,
    /// When false (debug-build `PROVER_ALLOW_PLAINTEXT=1` opt-out), the
    /// `x-forwarded-proto: https` requirement is skipped.
    require_tls: bool,
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

/// TRUE iff the request arrived over TLS according to the fronting proxy
/// (`x-forwarded-proto: https`, possibly a list — first value wins, as set by
/// the edge). Absent or non-https ⇒ plaintext ⇒ reject when TLS is required.
fn forwarded_proto_is_https(header: Option<&str>) -> bool {
    header
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .is_some_and(|v| v.eq_ignore_ascii_case("https"))
}

/// Constant-time-ish bearer-token check (no early exit on content mismatch).
fn token_matches(expected: &str, presented: &str) -> bool {
    let (a, b) = (expected.as_bytes(), presented.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.auth_token {
        None => true, // debug-only explicit opt-out
        Some(tok) => headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|presented| token_matches(tok, presented))
            .unwrap_or(false),
    }
}

fn tls_ok(state: &AppState, headers: &HeaderMap) -> bool {
    !state.require_tls
        || forwarded_proto_is_https(
            headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()),
        )
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

    let state = Arc::new(AppState { client, pk, vk, auth_token, require_tls: req_tls });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/prove", post(prove))
        .route("/verify", post(verify))
        // Witnesses + proofs are large; allow a generous body.
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .with_state(state);

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
}

#[derive(Serialize)]
struct VerifyResp {
    valid: bool,
}

async fn prove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProveReq>,
) -> Result<Json<ProveResp>, (StatusCode, String)> {
    if !tls_ok(&state, &headers) {
        // The private witness must never transit plaintext (audit P123 P-3).
        return Err((
            StatusCode::UPGRADE_REQUIRED,
            "TLS required: /prove carries the private witness; use https".into(),
        ));
    }
    if !authorized(&state, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "bad or missing bearer token".into()));
    }
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
    let proof = tokio::task::block_in_place(|| client.prove(pk, &stdin).core().run())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove failed: {e}")))?;

    let bytes = bincode_proof(&proof).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(ProveResp { proof_b64: B64.encode(bytes) }))
}

async fn verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    if !tls_ok(&state, &headers) {
        return Err((StatusCode::UPGRADE_REQUIRED, "TLS required; use https".into()));
    }
    let bytes = B64
        .decode(req.proof_b64.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad base64: {e}")))?;
    let proof = unbincode_proof(&bytes).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // Raw core STARK only — a mock/wrapped proof is invalid by shape.
    let is_core = matches!(&proof.proof, sp1_sdk::SP1Proof::Core(shards) if !shards.is_empty());
    let valid = is_core && state.client.verify(&proof, &state.vk).is_ok();
    Ok(Json(VerifyResp { valid }))
}

// SP1 proofs are serializable; bincode v1 wire format (the node reads the same).
fn bincode_proof(p: &sp1_sdk::SP1ProofWithPublicValues) -> Result<Vec<u8>, String> {
    bincode::serialize(p).map_err(|e| format!("serialize proof: {e}"))
}
fn unbincode_proof(b: &[u8]) -> Result<sp1_sdk::SP1ProofWithPublicValues, String> {
    bincode::deserialize(b).map_err(|e| format!("deserialize proof: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
