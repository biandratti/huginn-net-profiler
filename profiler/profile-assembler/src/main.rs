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

// --- Modelos de Datos ---

#[derive(Serialize, Clone, Debug)]
struct AppStats {
    waiting_room_count: usize,
    profiles_count: usize,
}

#[derive(Deserialize, Debug)]
struct TlsIngest {
    correlation_id: String,
    ja4_fingerprint: String,
}

#[derive(Deserialize, Debug)]
struct HttpIngest {
    source_ip_port: String,
    http_signature: String,
}

#[derive(Serialize, Clone, Debug)]
struct IncompleteProfile {
    ja4_fingerprint: Option<String>,
    http_signature: Option<String>,
    timestamp: DateTime<Utc>,
}

#[derive(Serialize, Clone, Debug)]
struct CompleteProfile {
    id: Uuid,
    correlation_id: String,
    ja4_fingerprint: String,
    http_signature: String,
    timestamp: DateTime<Utc>,
}

// --- Estado de la Aplicación ---

#[derive(Clone)]
struct AppState {
    // "Salón de espera" para perfiles que aún no tienen ambas partes (TLS y HTTP)
    waiting_room: Arc<DashMap<String, IncompleteProfile>>,
    // Almacén final de perfiles completos
    profiles: Arc<DashMap<Uuid, CompleteProfile>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            waiting_room: Arc::new(DashMap::new()),
            profiles: Arc::new(DashMap::new()),
        }
    }
}

// --- Lógica Principal y API ---

#[tokio::main]
async fn main() {
    env_logger::init();
    let state = AppState::new();

    let app = Router::new()
        .route("/api/ingest/tls", post(ingest_tls))
        .route("/api/ingest/http-sig", post(ingest_http_sig))
        .route("/api/profiles", get(get_all_profiles))
        .route("/api/profiles/:id", get(get_profile_by_id))
        .route("/api/stats", get(get_stats))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    info!("Profile assembler listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}

// --- Manejadores de API ---

async fn ingest_tls(
    State(state): State<AppState>,
    Json(payload): Json<TlsIngest>,
) -> StatusCode {
    info!("Received TLS info for {}", payload.correlation_id);
    
    let correlation_key = payload.correlation_id.clone();
    let mut entry = state.waiting_room.entry(correlation_key.clone()).or_insert_with(|| IncompleteProfile {
        ja4_fingerprint: None,
        http_signature: None,
        timestamp: Utc::now(),
    });
    entry.ja4_fingerprint = Some(payload.ja4_fingerprint);

    // Attempt to assemble if HTTP part is already present
    if let Some(http_sig) = entry.http_signature.clone() {
        if let Some(ja4) = entry.ja4_fingerprint.clone() {
            let profile_id = Uuid::new_v4();
            let complete_profile = CompleteProfile {
                id: profile_id,
                correlation_id: correlation_key.clone(),
                ja4_fingerprint: ja4,
                http_signature: http_sig,
                timestamp: entry.timestamp,
            };
            
            info!("Assembled complete profile {} for {}", profile_id, complete_profile.correlation_id);
            state.profiles.insert(profile_id, complete_profile);
            state.waiting_room.remove(&correlation_key);
            return StatusCode::CREATED;
        }
    }

    StatusCode::ACCEPTED // Accepted, waiting for other part
}

async fn ingest_http_sig(
    State(state): State<AppState>,
    Json(payload): Json<HttpIngest>,
) -> StatusCode {
    info!("Received HTTP signature for {}", payload.source_ip_port);

    let correlation_key = payload.source_ip_port.clone();
    let mut entry = state.waiting_room.entry(correlation_key.clone()).or_insert_with(|| IncompleteProfile {
        ja4_fingerprint: None,
        http_signature: None,
        timestamp: Utc::now(),
    });
    entry.http_signature = Some(payload.http_signature);

    // Attempt to assemble if TLS part is already present
    if let Some(ja4) = entry.ja4_fingerprint.clone() {
        if let Some(http_sig) = entry.http_signature.clone() {
            let profile_id = Uuid::new_v4();
            let complete_profile = CompleteProfile {
                id: profile_id,
                correlation_id: correlation_key.clone(),
                ja4_fingerprint: ja4,
                http_signature: http_sig,
                timestamp: entry.timestamp,
            };
            
            info!("Assembled complete profile {} for {}", profile_id, complete_profile.correlation_id);
            state.profiles.insert(profile_id, complete_profile);
            state.waiting_room.remove(&correlation_key);
            return StatusCode::CREATED;
        }
    }

    StatusCode::ACCEPTED // Accepted, waiting for other part
}

async fn get_all_profiles(
    State(state): State<AppState>,
) -> Json<Vec<CompleteProfile>> {
    let profiles = state.profiles.iter().map(|entry| entry.value().clone()).collect();
    Json(profiles)
}

async fn get_profile_by_id(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CompleteProfile>, StatusCode> {
    state.profiles.get(&id)
        .map(|profile| Json(profile.clone()))
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_stats(
    State(state): State<AppState>,
) -> Json<AppStats> {
    let stats = AppStats {
        waiting_room_count: state.waiting_room.len(),
        profiles_count: state.profiles.len(),
    };
    Json(stats)
} 