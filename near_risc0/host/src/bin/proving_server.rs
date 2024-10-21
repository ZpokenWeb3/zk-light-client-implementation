use near_primitives_core::borsh::to_vec;

use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use clap::Parser;
use host::service::{generate_epoch_proof, generate_random_proof};
use host::types::{EpochProvingTask,RandomProvingTask};
use log::{error, info};

use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

#[derive(Parser)]
struct Cli {
    /// Address of this server.
    #[arg(short, long)]
    addr: String,
}

#[derive(Clone)]
struct ServerState {
    active_requests: Arc<AtomicUsize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = env::var("EPOCH_SERVER_ADDRESS").unwrap_or_else(|_| "127.0.0.1:1337".to_string());

    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let state = ServerState {
        active_requests: Arc::new(AtomicUsize::new(0)),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/epoch/proof", post(epoch_proof))
        .route("/random/proof", post(random_proof))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            count_requests_middleware,
        ))
        .with_state(state);

    info!("Server running on {}", addr);

    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

async fn epoch_proof(
    State(_state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = serde_json::from_slice::<EpochProvingTask>(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let payload = res.unwrap();

    let res = {
        info!("Start proving epoch block");
        generate_epoch_proof(&payload).await.map_err(|err| {
            error!("Failed to generate epoch change proof: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }?;
    info!("Generated epoch output: {res:?}");

    let json_response = serde_json::to_vec(&res).map_err(|err| {
        error!("Failed to serialize response to JSON: {err}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(json_response))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn random_proof(
    State(_state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = serde_json::from_slice::<RandomProvingTask>(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let payload = res.unwrap();

    let res = {
        info!("Start proving epoch block");
        generate_random_proof(&payload).await.map_err(|err| {
            error!("Failed to generate epoch change proof: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }?;
    info!("Generated random output: {res:?}");

    let json_response = serde_json::to_vec(&res).map_err(|err| {
        error!("Failed to serialize response to JSON: {err}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(json_response))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}

async fn ready_check(State(state): State<ServerState>) -> impl IntoResponse {
    let active_requests = state.active_requests.load(Ordering::SeqCst);
    if active_requests > 0 {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    }
}

async fn count_requests_middleware(
    State(state): State<ServerState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let is_ready = req.uri().path() != "/ready";
    // Check if the request is for the ready endpoint.
    if is_ready {
        // Increment the active requests counter.
        state.active_requests.fetch_add(1, Ordering::SeqCst);
    }

    // Proceed with the request.
    let response = next.run(req).await;

    // Decrement the active requests counter if not a ready check.
    if is_ready {
        state.active_requests.fetch_sub(1, Ordering::SeqCst);
    }

    Ok(response)
}
