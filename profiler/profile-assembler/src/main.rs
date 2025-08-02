use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TcpSignature {
    os: String,
    browser: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HttpSignature {
    browser: String,
    os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsSignature {
    ja4: String,
}

#[derive(Debug, Clone, Serialize)]
struct Profile {
    timestamp: DateTime<Utc>,
    tcp_signature: Option<TcpSignature>,
    http_signature: Option<HttpSignature>,
    tls_fingerprint: Option<TlsSignature>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            tcp_signature: None,
            http_signature: None,
            tls_fingerprint: None,
        }
    }
}

type AppState = Arc<DashMap<String, Profile>>;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Initializing Profile Assembler");

    let state = AppState::new(DashMap::new());

    let app = Router::new()
        .route("/api/ingest/tcp", post(ingest_tcp))
        .route("/api/ingest/http", post(ingest_http))
        .route("/api/ingest/tls", post(ingest_tls))
        .route("/api/profiles", get(get_profiles).delete(clear_profiles))
        .route("/api/profiles/:id", get(get_profile_by_id))
        .route("/api/stats", get(get_stats))
        .route("/health", get(health_check))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    info!("🚀 Profile Assembler listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> StatusCode {
    StatusCode::OK
}

#[derive(Serialize)]
struct ProfilesResponse {
    profiles: HashMap<String, Profile>,
}

async fn get_profiles(State(state): State<AppState>) -> Json<ProfilesResponse> {
    info!("Fetching all profiles");
    let profiles = state
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect();
    Json(ProfilesResponse { profiles })
}

async fn get_profile_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Profile>, StatusCode> {
    info!("Fetching profile for ID: {}", id);
    match state.get(&id) {
        Some(profile) => Ok(Json(profile.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn clear_profiles(State(state): State<AppState>) -> StatusCode {
    info!("Clearing all profiles");
    state.clear();
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
struct TcpIngest {
    source_ip: String,
    signature: TcpSignature,
}

#[derive(Debug, Deserialize)]
struct HttpIngest {
    source_ip: String,
    signature: HttpSignature,
}

#[derive(Debug, Deserialize)]
struct TlsIngest {
    correlation_id: String, // source_ip:port
    ja4: String,
}

async fn ingest_tcp(
    State(state): State<AppState>,
    Json(payload): Json<TcpIngest>,
) -> StatusCode {
    info!("Ingesting TCP data for {}", payload.source_ip);
    let mut entry = state.entry(payload.source_ip).or_default();
    entry.tcp_signature = Some(payload.signature);
    entry.timestamp = Utc::now();
    StatusCode::OK
}

async fn ingest_http(
    State(state): State<AppState>,
    Json(payload): Json<HttpIngest>,
) -> StatusCode {
    info!("Ingesting HTTP data for {}", payload.source_ip);
    let mut entry = state.entry(payload.source_ip).or_default();
    entry.http_signature = Some(payload.signature);
    entry.timestamp = Utc::now();
    StatusCode::OK
}

async fn ingest_tls(
    State(state): State<AppState>,
    Json(payload): Json<TlsIngest>,
) -> StatusCode {
    info!("Ingesting TLS data for {}", payload.correlation_id);
    let ip = payload.correlation_id.split(':').next().unwrap_or("");
    if !ip.is_empty() {
        let mut entry = state.entry(ip.to_string()).or_default();
        entry.tls_fingerprint = Some(TlsSignature { ja4: payload.ja4 });
        entry.timestamp = Utc::now();
    }
    StatusCode::OK
}


#[derive(Serialize)]
struct AppStats {
    total_profiles: usize,
    tcp_profiles: usize,
    http_profiles: usize,
    tls_profiles: usize,
    complete_profiles: usize,
}

async fn get_stats(State(state): State<AppState>) -> Json<AppStats> {
    info!("Calculating statistics");
    let profiles = state.iter().map(|entry| entry.value().clone()).collect::<Vec<_>>();
    let stats = AppStats {
        total_profiles: profiles.len(),
        tcp_profiles: profiles.iter().filter(|p| p.tcp_signature.is_some()).count(),
        http_profiles: profiles.iter().filter(|p| p.http_signature.is_some()).count(),
        tls_profiles: profiles.iter().filter(|p| p.tls_fingerprint.is_some()).count(),
        complete_profiles: profiles
            .iter()
            .filter(|p| p.tcp_signature.is_some() && p.http_signature.is_some() && p.tls_fingerprint.is_some())
            .count(),
    };
    Json(stats)
} 