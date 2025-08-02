use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use log::info;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

// --- Data Models ---

#[derive(Deserialize, Debug, Clone)]
struct TcpSignature {
    source_ip: String,
    signature: String,
}

#[derive(Deserialize, Debug, Clone)]
struct HttpSignature {
    source_ip_port: String,
    signature: String,
}

#[derive(Deserialize, Debug, Clone)]
struct TlsSignature {
    correlation_id: String,
    ja4_fingerprint: String,
}

#[derive(Serialize, Clone, Debug, Default)]
struct Profile {
    id: String,
    tcp_signature: Option<String>,
    http_signature: Option<String>,
    tls_fingerprint: Option<String>,
    first_seen: DateTime<Utc>,
    last_updated: DateTime<Utc>,
}

// --- Application State ---

#[derive(Clone)]
struct AppState {
    profiles: Arc<DashMap<String, Profile>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            profiles: Arc::new(DashMap::new()),
        }
    }
}

// --- Main Logic and API ---

#[tokio::main]
async fn main() {
    env_logger::init();
    let state = AppState::new();

    let app = Router::new()
        .route("/api/ingest/tcp", post(ingest_tcp))
        .route("/api/ingest/http", post(ingest_http))
        .route("/api/ingest/tls", post(ingest_tls))
        .route("/api/profiles", get(get_all_profiles))
        .route("/api/profiles/:id", get(get_profile_by_id))
        .route("/api/stats", get(get_stats))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    info!("Profile assembler listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}

// --- API Handlers ---

async fn ingest_tcp(
    State(state): State<AppState>,
    Json(payload): Json<TcpSignature>,
) -> StatusCode {
    info!("Received TCP signature for {}", payload.source_ip);
    let mut profile = state.profiles.entry(payload.source_ip.clone()).or_insert_with(|| Profile {
        id: payload.source_ip.clone(),
        first_seen: Utc::now(),
        ..Default::default()
    });
    profile.tcp_signature = Some(payload.signature);
    profile.last_updated = Utc::now();
    StatusCode::OK
}

async fn ingest_http(
    State(state): State<AppState>,
    Json(payload): Json<HttpSignature>,
) -> StatusCode {
    info!("Received HTTP signature for {}", payload.source_ip_port);
    let ip = payload.source_ip_port.split(':').next().unwrap_or("").to_string();
    if ip.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    let mut profile = state.profiles.entry(ip.clone()).or_insert_with(|| Profile {
        id: ip,
        first_seen: Utc::now(),
        ..Default::default()
    });
    profile.http_signature = Some(payload.signature);
    profile.last_updated = Utc::now();
    StatusCode::OK
}

async fn ingest_tls(
    State(state): State<AppState>,
    Json(payload): Json<TlsSignature>,
) -> StatusCode {
    info!("Received TLS fingerprint for {}", payload.correlation_id);
    let ip = payload.correlation_id.split(':').next().unwrap_or("").to_string();
    if ip.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    let mut profile = state.profiles.entry(ip.clone()).or_insert_with(|| Profile {
        id: ip,
        first_seen: Utc::now(),
        ..Default::default()
    });
    profile.tls_fingerprint = Some(payload.ja4_fingerprint);
    profile.last_updated = Utc::now();
    StatusCode::OK
}

async fn get_all_profiles(
    State(state): State<AppState>,
) -> Json<Vec<Profile>> {
    let profiles = state.profiles.iter().map(|entry| entry.value().clone()).collect();
    Json(profiles)
}

async fn get_profile_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Profile>, StatusCode> {
    state.profiles.get(&id)
        .map(|profile| Json(profile.clone()))
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Serialize)]
struct AppStats {
    profiles_count: usize,
}

async fn get_stats(
    State(state): State<AppState>,
) -> Json<AppStats> {
    let stats = AppStats {
        profiles_count: state.profiles.len(),
    };
    Json(stats)
} 