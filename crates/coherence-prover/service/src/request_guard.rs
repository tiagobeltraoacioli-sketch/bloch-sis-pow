//! HTTP authorization before body extraction and slots held by actual native work.
use std::sync::Arc;
use axum::{extract::{Request, State}, http::{HeaderMap, StatusCode}, middleware::Next, response::Response};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub(crate) struct AccessPolicy {
    pub auth_token: Option<String>,
    pub require_tls: bool,
}

pub(crate) fn forwarded_proto_is_https(header: Option<&str>) -> bool {
    header.and_then(|value| value.split(',').next()).map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

pub(crate) fn token_matches(expected: &str, presented: &str) -> bool {
    let (a, b) = (expected.as_bytes(), presented.as_bytes());
    if a.len() != b.len() { return false; }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl AccessPolicy {
    fn check(&self, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
        // This header is trustworthy only behind an access-controlled TLS proxy.
        // Direct untrusted access to the listener can spoof it.
        if self.require_tls && !forwarded_proto_is_https(headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok())) {
            return Err((StatusCode::UPGRADE_REQUIRED, "TLS required; use https".into()));
        }
        if let Some(expected) = &self.auth_token {
            let authorized = headers.get("authorization").and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|presented| token_matches(expected, presented));
            if !authorized { return Err((StatusCode::UNAUTHORIZED, "bad or missing bearer token".into())); }
        }
        Ok(())
    }
}

/// The production route composition keeps both expensive endpoints protected;
/// health is added afterward and intentionally remains public.
pub(crate) fn guarded_routes<S: Clone + Send + Sync + 'static>(
    prove: axum::routing::MethodRouter<S>, verify: axum::routing::MethodRouter<S>,
    policy: Arc<AccessPolicy>,
) -> axum::Router<S> {
    axum::Router::new().route("/prove", prove).route("/verify", verify)
        .route_layer(axum::middleware::from_fn_with_state(policy, authorize_before_body))
        .route("/health", axum::routing::get(|| async { "ok" }))
}

pub(crate) async fn authorize_before_body(
    State(policy): State<Arc<AccessPolicy>>, request: Request, next: Next,
) -> Result<Response, (StatusCode, String)> {
    policy.check(request.headers())?;
    Ok(next.run(request).await)
}

/// Timing out/dropping the awaiter never frees this slot while its worker runs.
/// Native work cannot be forcibly cancelled; shutdown may wait for it to finish.
pub(crate) async fn run_bounded<T: Send + 'static>(
    slots: Arc<Semaphore>, work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, (StatusCode, String)> {
    let permit = slots.try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "native worker capacity exhausted".into()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    }).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "native worker failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::post, Json};
    use tower::ServiceExt;

    #[tokio::test]
    async fn authorization_precedes_json_extraction() {
        let policy = Arc::new(AccessPolicy { auth_token: Some("synthetic-test-token".into()), require_tls: true });
        let handler = post(|Json(_): Json<serde_json::Value>| async { "ok" });
        let app = guarded_routes(handler.clone(), handler, policy);
        let request = |route: &str, token: Option<&str>, tls: bool| {
            let mut builder = axum::http::Request::post(route).header("content-type", "application/json");
            if tls { builder = builder.header("x-forwarded-proto", "https"); }
            if let Some(token) = token { builder = builder.header("authorization", token); }
            builder.body(Body::from("not-json")).unwrap()
        };
        for route in ["/prove", "/verify"] {
            assert_eq!(app.clone().oneshot(request(route, None, false)).await.unwrap().status(), StatusCode::UPGRADE_REQUIRED);
            assert_eq!(app.clone().oneshot(request(route, None, true)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
            assert_eq!(app.clone().oneshot(request(route, Some("Bearer synthetic-test-token"), true)).await.unwrap().status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(app.oneshot(axum::http::Request::get("/health").body(Body::empty()).unwrap()).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn panicking_worker_returns_error_and_releases_capacity() {
        let slots = Arc::new(Semaphore::new(1));
        assert_eq!(run_bounded(slots.clone(), || panic!("synthetic worker failure"))
            .await.unwrap_err().0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_request_retains_slot_until_native_worker_finishes() {
        let slots = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_slots = slots.clone();
        let pending = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_millis(5), run_bounded(worker_slots, move || {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
            })).await
        });
        started_rx.await.unwrap();
        assert!(pending.await.unwrap().is_err(), "the request deadline must return while native work runs");
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(run_bounded(slots.clone(), || ()).await.unwrap_err().0, StatusCode::TOO_MANY_REQUESTS);
        release_tx.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(2), slots.clone().acquire_owned()).await.unwrap().unwrap();
        drop(permit);
        assert!(run_bounded(slots, || 7).await.is_ok());
    }
}
