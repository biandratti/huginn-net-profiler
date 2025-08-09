use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Deserialize, Debug)]
struct TcpIngest {
    id: String,
    timestamp: u64,
    tcp_signature: String,
    os: String,
    nat: bool,
}

#[derive(Deserialize, Debug)]
struct HttpIngest {
    id: String,
    timestamp: u64,
    http_signature: String,
    os: String,
    browser: String,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct TlsClient {
    pub id: String,
    pub timestamp: u64,
    pub ja4: String,
    pub ja4_raw: String,
    pub ja4_original: String,
    pub ja4_original_raw: String,
    pub observed: TlsClientObserved,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct TlsClientObserved {
    pub version: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

// TlsIngest is the same as TlsClient for simplicity
type TlsIngest = TlsClient;

#[derive(Serialize, Clone, Debug)]
struct TcpSignature {
    timestamp: u64,
    tcp_signature: String,
    os: String,
    nat: bool,
}

#[derive(Serialize, Clone, Debug)]
struct HttpSignature {
    timestamp: u64,
    http_signature: String,
    os: String,
    browser: String,
}

#[derive(Serialize, Clone, Debug)]
struct Profile {
    id: String,
    timestamp: u64,
    tcp_signature: Option<TcpSignature>,
    http_signature: Option<HttpSignature>,
    tls_client: Option<TlsClient>,
    last_seen: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(),
            timestamp: 0,
            tcp_signature: None,
            http_signature: None,
            tls_client: None,
            last_seen: String::new(),
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
        .route("/api/clear", post(clear_profiles))
        .route("/api/my-profile", get(get_my_profile))
        .route("/health", get(health_check))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    info!("Profile Assembler listening on {}", addr);
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

async fn get_my_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Profile>, StatusCode> {
    let client_ip = headers
        .get("X-Real-Ip")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    
    if let Some(ip) = client_ip {
        info!("Fetching profile for client IP from headers: {}", ip);
        if let Some(profile) = state.get(&ip) {
            Ok(Json(profile.value().clone()))
        } else {
            warn!("No profile found for client IP: {}", ip);
            Err(StatusCode::NOT_FOUND)
        }
    } else {
        warn!("X-Real-Ip or X-Forwarded-For header not found or invalid.");
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn get_profile_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Profile>, StatusCode> {
    info!("Fetching profile for ID: {}", id);
    if let Some(profile) = state.get(&id) {
        Ok(Json(profile.value().clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn clear_profiles(State(state): State<AppState>) -> StatusCode {
    info!("Clearing all profiles");
    state.clear();
    StatusCode::OK
}

async fn ingest_tcp(State(state): State<AppState>, Json(ingest): Json<TcpIngest>) {
    let ip = ingest.id.split(':').next().unwrap_or("").to_string();
    if ip.is_empty() {
        warn!("Received TCP ingest with invalid ID: {}", ingest.id);
        return;
    }
    info!("Received TCP data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    profile.tcp_signature = Some(TcpSignature {
        timestamp: ingest.timestamp,
        tcp_signature: ingest.tcp_signature,
        os: ingest.os,
        nat: ingest.nat,
    });
    profile.last_seen = now_rfc3339();
}

async fn ingest_http(State(state): State<AppState>, Json(ingest): Json<HttpIngest>) {
    let ip = ingest.id.split(':').next().unwrap_or("").to_string();
    if ip.is_empty() {
        warn!("Received HTTP ingest with invalid ID: {}", ingest.id);
        return;
    }
    info!("Received HTTP data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    profile.http_signature = Some(HttpSignature {
        timestamp: ingest.timestamp,
        http_signature: ingest.http_signature,
        os: ingest.os,
        browser: ingest.browser,
    });
    profile.last_seen = now_rfc3339();
}

async fn ingest_tls(State(state): State<AppState>, Json(ingest): Json<TlsIngest>) {
    let ip = ingest.id.clone();
    info!("Received TLS data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    
    // Store the TLS client data directly - contains all the information
    profile.tls_client = Some(ingest);
    profile.last_seen = now_rfc3339();
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
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
        tls_profiles: profiles.iter().filter(|p| p.tls_client.is_some()).count(),
        complete_profiles: profiles
            .iter()
            .filter(|p| p.tcp_signature.is_some() && p.http_signature.is_some() && p.tls_client.is_some())
            .count(),
    };
    Json(stats)
} 