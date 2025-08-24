use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SynPacketData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub os_detected: OsDetection,
    pub signature: String,
    pub observed: TcpObserved,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsDetection {
    pub os: String,
    pub quality: f32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpObserved {
    pub version: String,
    pub initial_ttl: String,
    pub options_length: u8,
    pub mss: Option<u16>,
    pub window_size: String,
    pub window_scale: Option<u8>,
    pub options_layout: String,
    pub quirks: String,
    pub payload_class: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SynAckPacketData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub os_detected: OsDetection,
    pub signature: String,
    pub observed: TcpObserved,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MtuData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub link: String,
    pub mtu_value: u16,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UptimeData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub uptime_seconds: u64,
    pub up_mod_days: u32,
    pub freq: f64,
    pub timestamp: u64,
}

type SynIngest = SynPacketData;
type SynAckIngest = SynAckPacketData;
type MtuIngest = MtuData;
type UptimeIngest = UptimeData;

type HttpRequestIngest = HttpRequestData;
type HttpResponseIngest = HttpResponseData;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrowserDetection {
    pub browser: String,
    pub quality: f32,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpRequestObserved {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub diagnostic: String,
    pub method: Option<String>,
    pub version: String,
    pub headers: String,
    pub uri: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpRequestData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub observed: HttpRequestObserved,
    pub signature: String,
    pub browser: BrowserDetection,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebServerDetection {
    pub web_server: String,
    pub quality: f32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpResponseObserved {
    pub server: Option<String>,
    pub version: String,
    pub headers: String,
    pub status_code: Option<u16>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpResponseData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub observed: HttpResponseObserved,
    pub signature: String,
    pub web_server: WebServerDetection,
    pub timestamp: u64,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct TlsClient {
    pub timestamp: u64,
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
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

type TlsIngest = TlsClient;

#[derive(Serialize, Clone, Debug, Default)]
struct Profile {
    id: String,
    timestamp: u64,
    syn: Option<SynPacketData>,
    syn_ack: Option<SynAckPacketData>,
    mtu: Option<MtuData>,
    uptime: Option<UptimeData>,
    http_request: Option<HttpRequestData>,
    http_response: Option<HttpResponseData>,
    tls_client: Option<TlsClient>,
    last_seen: String,
}

type AppState = Arc<DashMap<String, Profile>>;

const MAX_PROFILES: usize = 100;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Initializing Profile Assembler");

    let state = AppState::new(DashMap::new());

    let app = Router::new()
        .route("/api/ingest/syn", post(ingest_syn))
        .route("/api/ingest/syn_ack", post(ingest_syn_ack))
        .route("/api/ingest/mtu", post(ingest_mtu))
        .route("/api/ingest/uptime", post(ingest_uptime))
        .route("/api/ingest/http_request", post(ingest_http_request))
        .route("/api/ingest/http_response", post(ingest_http_response))
        .route("/api/ingest/tls", post(ingest_tls))
        .route("/api/profiles", get(get_profiles))
        .route("/api/profiles/{id}", get(get_profile_by_id))
        .route("/api/stats", get(get_stats))
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

async fn ingest_syn(State(state): State<AppState>, Json(ingest): Json<SynIngest>) {
    let ip = ingest.source.ip.clone();
    info!("Received SYN data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    profile.syn = Some(ingest);
    profile.last_seen = now_rfc3339();
    drop(profile); // Release the lock before cleanup
    enforce_profile_limit(&state);
}

async fn ingest_syn_ack(State(state): State<AppState>, Json(ingest): Json<SynAckIngest>) {
    let client_ip = ingest.destination.ip.clone();
    info!("Received SYN-ACK data for client {}", client_ip);
    let mut profile = state.entry(client_ip.clone()).or_default();
    profile.id = client_ip;
    profile.syn_ack = Some(ingest);
    profile.last_seen = now_rfc3339();
    drop(profile);
    enforce_profile_limit(&state);
}

async fn ingest_mtu(State(state): State<AppState>, Json(ingest): Json<MtuIngest>) {
    let ip = ingest.source.ip.clone();
    info!("Received MTU data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    profile.mtu = Some(ingest);
    profile.last_seen = now_rfc3339();
    drop(profile);
    enforce_profile_limit(&state);
}

async fn ingest_uptime(State(state): State<AppState>, Json(ingest): Json<UptimeIngest>) {
    let ip = ingest.destination.ip.clone();
    info!("Received uptime data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    profile.uptime = Some(ingest);
    profile.last_seen = now_rfc3339();
    drop(profile);
    enforce_profile_limit(&state);
}

async fn ingest_http_request(State(state): State<AppState>, Json(ingest): Json<HttpRequestIngest>) {
    let ip = ingest.source.ip.clone();
    info!("Received HTTP request data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    profile.http_request = Some(ingest);
    profile.last_seen = now_rfc3339();
    drop(profile);
    enforce_profile_limit(&state);
}

async fn ingest_http_response(
    State(state): State<AppState>,
    Json(ingest): Json<HttpResponseIngest>,
) {
    let client_ip = ingest.destination.ip.clone();
    info!("Received HTTP response data for client {}", client_ip);
    let mut profile = state.entry(client_ip.clone()).or_default();
    profile.id = client_ip;
    profile.http_response = Some(ingest);
    profile.last_seen = now_rfc3339();
    drop(profile);
    enforce_profile_limit(&state);
}

async fn ingest_tls(State(state): State<AppState>, Json(ingest): Json<TlsIngest>) {
    let ip = ingest.source.ip.clone();
    info!("Received TLS data for {}", ip);
    let mut profile = state.entry(ip.clone()).or_default();
    profile.id = ip;
    profile.tls_client = Some(ingest);
    profile.last_seen = now_rfc3339();
    drop(profile);
    enforce_profile_limit(&state);
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn enforce_profile_limit(state: &AppState) {
    if state.len() <= MAX_PROFILES {
        return;
    }

    let mut profiles: Vec<(String, String)> = state
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().last_seen.clone()))
        .collect();

    profiles.sort_by(|a, b| a.1.cmp(&b.1));

    let to_remove = state.len() - MAX_PROFILES;
    for (ip, _) in profiles.iter().take(to_remove) {
        state.remove(ip);
        debug!(
            "Removed old profile for {} to maintain limit of {}",
            ip, MAX_PROFILES
        );
    }
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
    let profiles = state
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    let stats = AppStats {
        total_profiles: profiles.len(),
        tcp_profiles: profiles
            .iter()
            .filter(|p| {
                p.syn.is_some() || p.syn_ack.is_some() || p.mtu.is_some() || p.uptime.is_some()
            })
            .count(),
        http_profiles: profiles
            .iter()
            .filter(|p| p.http_request.is_some() || p.http_response.is_some())
            .count(),
        tls_profiles: profiles.iter().filter(|p| p.tls_client.is_some()).count(),
        complete_profiles: profiles
            .iter()
            .filter(|p| {
                (p.http_request.is_some() || p.http_response.is_some()) && p.tls_client.is_some()
            })
            .count(),
    };
    Json(stats)
}
