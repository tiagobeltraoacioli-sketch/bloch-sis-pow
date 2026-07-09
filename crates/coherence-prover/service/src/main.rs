//! Coherence shielded-spend prover service (SP1 / hash-STARK / FRI).
//!
//! Deployed on a server with the SP1 toolchain (Fly.io GPU). A wallet POSTs the
//! public inputs + private witness to `/prove` and gets back a RAW FRI proof
//! (post-quantum) that `check_spend` held — never a Groth16/PLONK wrap. `/verify`
//! checks a proof (the node verifies FRI locally in production; this endpoint is
//! for tooling/tests). Bearer-token auth guards the compute-heavy `/prove`.
//!
//! API shapes follow the SP1 SDK; pin the SP1 version and confirm the
//! prove/verify surface for that version before deploying.

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
use sp1_sdk::{ProverClient, SP1Stdin};

/// The guest ELF, built by `cargo prove build` in ../program (baked at image
/// build time).
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

struct AppState {
    client: ProverClient,
    pk: sp1_sdk::SP1ProvingKey,
    vk: sp1_sdk::SP1VerifyingKey,
    /// Optional bearer token; when set, `/prove` requires it.
    auth_token: Option<String>,
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let auth_token = std::env::var("PROVER_AUTH_TOKEN").ok().filter(|s| !s.is_empty());
    if auth_token.is_none() {
        tracing::warn!("PROVER_AUTH_TOKEN unset — /prove is UNAUTHENTICATED");
    }

    let state = Arc::new(AppState { client, pk, vk, auth_token });

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

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.auth_token {
        None => true,
        Some(tok) => headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|h| h == format!("Bearer {tok}"))
            .unwrap_or(false),
    }
}

async fn prove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProveReq>,
) -> Result<Json<ProveResp>, (StatusCode, String)> {
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
    let proof = tokio::task::block_in_place(|| client.prove(pk, stdin).core().run())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove failed: {e}")))?;

    let bytes = bincode_proof(&proof)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(ProveResp { proof_b64: B64.encode(bytes) }))
}

async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    let bytes = B64.decode(req.proof_b64.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad base64: {e}")))?;
    let proof = unbincode_proof(&bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let valid = state.client.verify(&proof, &state.vk).is_ok();
    Ok(Json(VerifyResp { valid }))
}

// SP1 proofs are serializable; use the SDK's own (de)serialization if it differs
// in your pinned version.
fn bincode_proof(p: &sp1_sdk::SP1ProofWithPublicValues) -> Result<Vec<u8>, String> {
    bincode::serialize(p).map_err(|e| format!("serialize proof: {e}"))
}
fn unbincode_proof(b: &[u8]) -> Result<sp1_sdk::SP1ProofWithPublicValues, String> {
    bincode::deserialize(b).map_err(|e| format!("deserialize proof: {e}"))
}
