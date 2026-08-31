//! Coherence shielded-spend DELEGATED prover service (SP1 / hash-STARK / FRI).
//!
//! # PRIVACY — read before deploying or using
//!
//! `/prove` receives the FULL SPEND WITNESS: every input note (value, pk_d,
//! rho, psi), every output note, the Merkle paths and the NULLIFIER KEY `nk`.
//! Whoever operates this box can see amounts and link spends of every wallet
//! that delegates to it — and with `nk`, link that wallet's PAST AND FUTURE
//! spends too. Delegated proving is a convenience for wallets that cannot
//! prove locally; it is NOT private with respect to the operator. Run it
//! yourself or accept that trust. (COHERENCE-C1 §"prover delegation".)
//!
//! # What it is
//!
//! A wallet POSTs the public inputs + private witness to `/prove` and gets
//! back a RAW FRI proof (post-quantum) that `check_spend` held — never a
//! Groth16/PLONK wrap (elliptic curves — Shor-breakable, COHERENCE-C1 §3).
//! `/verify` checks a proof (the node verifies FRI locally in production; this
//! endpoint is for tooling/tests). Bearer-token auth guards the compute-heavy
//! `/prove`.
//!
//! Pinned to sp1-sdk =6.5.0 (blocking API). The prover is constructed
//! EXPLICITLY (`ProverClient::builder().cpu()`/`.cuda()`), never the
//! env-sensitive `from_env()`/old `::new()`: on a box with `SP1_PROVER=mock`
//! those silently hand back a mock prover, and `/verify` would answer
//! `valid: true` for mock proofs.

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
use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin};
use sp1_sdk::{ProvingKey, SP1Proof, SP1ProofWithPublicValues};

/// The guest ELF, built by `cargo prove build` in ../program with the pinned
/// toolchain (`sp1up --version v6.5.0`); baked in at image build time. This is
/// where SP1 6.x writes it — the old `../program/elf/riscv32im-...` is gone.
const ELF: &[u8] = include_bytes!(
    "../../program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coherence-spend-program"
);

/// Explicit prover selection at compile time — never from the environment.
#[cfg(not(feature = "cuda"))]
type Client = sp1_sdk::blocking::CpuProver;
#[cfg(feature = "cuda")]
type Client = sp1_sdk::blocking::CudaProver;

type Pk = <Client as Prover>::ProvingKey;

struct AppState {
    client: Client,
    pk: Pk,
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

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Build the prover and run setup OUTSIDE the tokio runtime: the blocking
    // SP1 API drives its own internal runtime and must not be entered from
    // within another one.
    #[cfg(not(feature = "cuda"))]
    let client: Client = ProverClient::builder().cpu().build();
    #[cfg(feature = "cuda")]
    let client: Client = ProverClient::builder().cuda().build();

    let pk = client.setup(Elf::Static(ELF)).expect("SP1 setup failed");

    let auth_token = std::env::var("PROVER_AUTH_TOKEN").ok().filter(|s| !s.is_empty());
    if auth_token.is_none() {
        tracing::warn!("PROVER_AUTH_TOKEN unset — /prove is UNAUTHENTICATED");
    }

    let state = Arc::new(AppState { client, pk, auth_token });

    // Multi-thread runtime is required: /prove uses tokio::task::block_in_place.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(serve(state));
}

async fn serve(state: Arc<AppState>) {
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
    // Fail fast: don't burn prover minutes on a witness that won't satisfy the
    // statement (the guest would abort anyway).
    if let Err(e) = check_spend(&req.public, &req.witness) {
        return Err((StatusCode::BAD_REQUEST, format!("spend statement violated: {e:?}")));
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&req.public);
    stdin.write(&req.witness);

    // POST-QUANTUM: the CORE STARK/FRI proof. Never .groth16()/.plonk().
    // block_in_place: proving is minutes of CPU/GPU; don't stall the runtime.
    let proof = tokio::task::block_in_place(|| {
        state.client.prove(&state.pk, stdin).mode(SP1ProofMode::Core).run()
    })
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove failed: {e}")))?;

    // Belt over suspenders: never hand out anything but a raw FRI core proof.
    if !matches!(proof.proof, SP1Proof::Core(_)) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "prover returned a non-Core proof; refusing to serve it".into(),
        ));
    }

    let bytes = bincode_proof(&proof).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(ProveResp { proof_b64: B64.encode(bytes) }))
}

async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    let bytes = B64
        .decode(req.proof_b64.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad base64: {e}")))?;
    let proof = unbincode_proof(&bytes).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // Fail closed, mirroring the node's verifier: only the raw FRI core proof
    // is the post-quantum object consensus accepts. A Compressed/Groth16/Plonk
    // (or mock) envelope is `valid: false` here even if it would verify.
    let valid = matches!(proof.proof, SP1Proof::Core(_))
        && state.client.verify(&proof, state.pk.verifying_key(), None).is_ok();
    Ok(Json(VerifyResp { valid }))
}

fn bincode_proof(p: &SP1ProofWithPublicValues) -> Result<Vec<u8>, String> {
    bincode::serialize(p).map_err(|e| format!("serialize proof: {e}"))
}
fn unbincode_proof(b: &[u8]) -> Result<SP1ProofWithPublicValues, String> {
    bincode::deserialize(b).map_err(|e| format!("deserialize proof: {e}"))
}
