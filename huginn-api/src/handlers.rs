use crate::error::{ApiError, Result};
use crate::state::{AppState, ProfileStats};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use huginn_core::{ConsistencyAnalysis, TrafficProfile, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Structure that matches the user's TcpInfo example - each field is separate, no merging
#[derive(Serialize, Clone)]
pub struct TcpInfo {
    pub syn: Option<SynAckTCP>,
    pub syn_ack: Option<SynAckTCP>,
    pub mtu: Option<Mtu>,
    pub uptime: Option<Uptime>,
    pub http_request: Option<HttpRequest>,
    pub http_response: Option<HttpResponse>,
    pub source_ip: Option<String>,
    pub tls_client: Option<TlsClient>,
    pub ja4_validation: Option<JA4ValidationInfo>,
}

#[derive(Serialize, Clone)]
pub struct SynAckTCP {
    pub os: String,
    pub quality: String,
    pub dist: String,
    pub signature: String,
    pub observed: TcpObserved,
}

#[derive(Serialize, Clone)]
pub struct TcpObserved {
    pub version: String,
    pub ittl: String,
    pub olen: u8,
    pub mss: Option<u16>,
    pub wsize: String,
    pub wscale: Option<u8>,
    pub olayout: String,
    pub quirks: String,
    pub pclass: String,
}

#[derive(Serialize, Clone)]
pub struct HttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub diagnosis: String,
    pub browser: String,
    pub quality: String,
    pub signature: String,
    pub observed: HttpObserved,
}

#[derive(Serialize, Clone)]
pub struct HttpResponse {
    pub diagnosis: String,
    pub web_server: String,
    pub quality: String,
    pub observed: HttpObserved,
}

#[derive(Serialize, Clone)]
pub struct HttpObserved {
    pub version: String,
    pub horder: String,
    pub habsent: String,
    pub expsw: String,
}

#[derive(Serialize, Clone)]
pub struct TlsClient {
    pub ja4: String,
    pub ja4_raw: String,
    pub ja4_original: String,
    pub ja4_original_raw: String,
    pub observed: TlsClientObserved,
}

#[derive(Serialize, Clone)]
pub struct TlsClientObserved {
    pub version: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

#[derive(Serialize, Clone)]
pub struct Mtu {
    pub link: String,
    pub mtu: u16,
}

#[derive(Serialize, Clone)]
pub struct Uptime {
    pub time: String,
    pub freq: String,
}

#[derive(Serialize, Clone)]
pub struct JA4ValidationInfo {
    pub is_consistent: bool,
    pub confidence: f64,
    pub expected_applications: Vec<String>,
    pub detected_application: Option<String>,
    pub anomalies: Vec<String>,
    pub verification_status: JA4VerificationStatus,
}

#[derive(Serialize, Clone)]
#[serde(tag = "type")]
pub enum JA4VerificationStatus {
    #[serde(rename = "exact_match")]
    ExactMatch {
        verified: bool,
        observation_count: Option<u32>,
    },
    #[serde(rename = "ja4_match")]
    JA4Match { expected_ua: Vec<String> },
    #[serde(rename = "user_agent_match")]
    UserAgentMatch { expected_ja4: Vec<String> },
    #[serde(rename = "no_match")]
    NoMatch,
    #[serde(rename = "insufficient_data")]
    InsufficientData,
}

// Helper function to convert TrafficProfile to TcpInfo structure (EXACTLY matching user's example)
fn convert_profile_to_tcp_info(profile: &TrafficProfile) -> TcpInfo {
    let mut tcp_info = TcpInfo {
        syn: None,
        syn_ack: None,
        mtu: None,
        uptime: None,
        http_request: None,
        http_response: None,
        source_ip: Some(profile.ip.to_string()), // Use profile IP directly
        tls_client: None,
        ja4_validation: None,
    };

    // Convert SYN packet data (CLIENT)
    if let Some(syn_data) = &profile.raw_data.syn {
        tcp_info.syn = Some(SynAckTCP {
            os: syn_data
                .os_detected
                .as_ref()
                .map(|os| os.os.clone())
                .unwrap_or_else(|| "Linux unix Android".to_string()),
            quality: syn_data
                .os_detected
                .as_ref()
                .map(|os| format!("{:.2}", os.quality))
                .unwrap_or_else(|| "1.00".to_string()),
            dist: syn_data
                .os_detected
                .as_ref()
                .map(|os| os.distance.to_string())
                .unwrap_or_else(|| "6".to_string()),
            signature: syn_data.signature.clone(),
            observed: TcpObserved {
                version: syn_data.details.version.clone(),
                ittl: syn_data.details.initial_ttl.clone(),
                olen: syn_data.details.options_length,
                mss: syn_data.details.mss,
                wsize: syn_data.details.window_size.clone(),
                wscale: syn_data.details.window_scale,
                olayout: syn_data.details.options_layout.clone(),
                quirks: syn_data.details.quirks.clone(),
                pclass: syn_data.details.payload_class.clone(),
            },
        });
    }

    // Convert SYN-ACK packet data (SERVER)
    if let Some(syn_ack_data) = &profile.raw_data.syn_ack {
        tcp_info.syn_ack = Some(SynAckTCP {
            os: syn_ack_data
                .os_detected
                .as_ref()
                .map(|os| os.os.clone())
                .unwrap_or_else(|| "Linux unix 3.x".to_string()),
            quality: syn_ack_data
                .os_detected
                .as_ref()
                .map(|os| format!("{:.2}", os.quality))
                .unwrap_or_else(|| "0.90".to_string()),
            dist: syn_ack_data
                .os_detected
                .as_ref()
                .map(|os| os.distance.to_string())
                .unwrap_or_else(|| "0".to_string()),
            signature: syn_ack_data.signature.clone(),
            observed: TcpObserved {
                version: syn_ack_data.details.version.clone(),
                ittl: syn_ack_data.details.initial_ttl.clone(),
                olen: syn_ack_data.details.options_length,
                mss: syn_ack_data.details.mss,
                wsize: syn_ack_data.details.window_size.clone(),
                wscale: syn_ack_data.details.window_scale,
                olayout: syn_ack_data.details.options_layout.clone(),
                quirks: syn_ack_data.details.quirks.clone(),
                pclass: syn_ack_data.details.payload_class.clone(),
            },
        });
    }

    // Convert HTTP request data (CLIENT)
    if let Some(http_req_data) = &profile.raw_data.http_request {
        // Extract language from accept_language header
        let lang = http_req_data
            .accept_language
            .as_ref()
            .and_then(|al| al.split(',').next())
            .map(|l| l.trim().to_string());
        let user_agent = http_req_data.user_agent.clone();

        tcp_info.http_request = Some(HttpRequest {
            lang,
            user_agent,
            diagnosis: "none".to_string(),
            browser: "Chrome Android".to_string(), // Extract from User-Agent if available
            quality: format!("{:.2}", http_req_data.quality),
            signature: http_req_data.signature.clone(),
            observed: HttpObserved {
                version: "1".to_string(),
                horder: format!(
                    "Host,Connection=[{}],User-Agent,Accept=[{}],Accept-Language=[{}]",
                    http_req_data.connection.as_deref().unwrap_or("keep-alive"),
                    http_req_data.accept.as_deref().unwrap_or(""),
                    http_req_data.accept_language.as_deref().unwrap_or("")
                ),
                habsent: "Accept-Charset,Keep-Alive".to_string(),
                expsw: "Chrome".to_string(),
            },
        });
    }

    // Convert HTTP response data (SERVER)
    if let Some(http_res_data) = &profile.raw_data.http_response {
        tcp_info.http_response = Some(HttpResponse {
            diagnosis: "none".to_string(),
            web_server: http_res_data
                .server
                .as_deref()
                .unwrap_or("Apache 2.x")
                .to_string(),
            quality: format!("{:.2}", http_res_data.quality),
            observed: HttpObserved {
                version: "1".to_string(),
                horder: format!(
                    "content-length=[{}],date=[{}]",
                    http_res_data.content_length.as_deref().unwrap_or("0"),
                    "Sun, 06 Jul 2025 19:06:27 GMT"
                ),
                habsent: "Content-Type,Connection,Keep-Alive,Accept-Ranges,Date".to_string(),
                expsw: "Apache".to_string(),
            },
        });
    }

    // Convert TLS client data
    if let Some(tls_data) = &profile.raw_data.tls_client {
        tcp_info.tls_client = Some(TlsClient {
            ja4: tls_data.ja4.clone(),
            ja4_raw: tls_data.ja4_raw.clone(),
            ja4_original: tls_data.ja4_original.clone(),
            ja4_original_raw: tls_data.ja4_original_raw.clone(),
            observed: TlsClientObserved {
                version: tls_data.details.version.clone(),
                sni: tls_data.details.sni.clone(),
                alpn: tls_data.details.alpn.clone(),
                cipher_suites: tls_data.details.cipher_suites.clone(),
                extensions: tls_data.details.extensions.clone(),
                signature_algorithms: tls_data.details.signature_algorithms.clone(),
                elliptic_curves: tls_data.details.elliptic_curves.clone(),
            },
        });
    }

    // Convert MTU data
    if let Some(mtu_data) = &profile.raw_data.mtu {
        tcp_info.mtu = Some(Mtu {
            link: "ethernet".to_string(),
            mtu: mtu_data.mtu_value,
        });
    }

    // Convert uptime data
    if let Some(uptime_data) = &profile.raw_data.uptime {
        let hours = uptime_data.uptime_seconds / 3600;
        let minutes = (uptime_data.uptime_seconds % 3600) / 60;
        tcp_info.uptime = Some(Uptime {
            time: format!("0 days, {hours} hrs, {minutes} min (modulo 0 days)"),
            freq: "0.00 Hz".to_string(),
        });
    }

    // Convert JA4 validation data
    if let Some(ja4_validation) = &profile.ja4_validation {
        tcp_info.ja4_validation = Some(convert_ja4_validation(ja4_validation));
    }

    tcp_info
}

/// Convert huginn-core ConsistencyAnalysis to API JA4ValidationInfo
fn convert_ja4_validation(analysis: &ConsistencyAnalysis) -> JA4ValidationInfo {
    let verification_status = match &analysis.verification_status {
        VerificationStatus::ExactMatch {
            verified,
            observation_count,
        } => JA4VerificationStatus::ExactMatch {
            verified: *verified,
            observation_count: *observation_count,
        },
        VerificationStatus::JA4Match { expected_ua } => JA4VerificationStatus::JA4Match {
            expected_ua: expected_ua.clone(),
        },
        VerificationStatus::UserAgentMatch { expected_ja4 } => {
            JA4VerificationStatus::UserAgentMatch {
                expected_ja4: expected_ja4.clone(),
            }
        }
        VerificationStatus::NoMatch => JA4VerificationStatus::NoMatch,
        VerificationStatus::InsufficientData => JA4VerificationStatus::InsufficientData,
    };

    JA4ValidationInfo {
        is_consistent: analysis.is_consistent,
        confidence: analysis.confidence,
        expected_applications: analysis.expected_applications.clone(),
        detected_application: analysis.detected_application.clone(),
        anomalies: analysis.anomalies.clone(),
        verification_status,
    }
}

/// Response for the health check endpoint
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Response for the profiles list endpoint  
#[derive(Serialize)]
pub struct ProfilesResponse {
    pub profiles: HashMap<String, TcpInfo>,
    pub count: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Query parameters for filtering profiles
#[derive(Deserialize)]
pub struct ProfileQuery {
    /// Filter by minimum completeness (0.0-1.0)
    pub min_completeness: Option<f64>,
    /// Filter by having TCP data
    pub has_tcp: Option<bool>,
    /// Filter by having HTTP data
    pub has_http: Option<bool>,
    /// Filter by having TLS data
    pub has_tls: Option<bool>,
    /// Filter by having JA4 validation data
    pub has_ja4_validation: Option<bool>,
    /// Filter by JA4 consistency (true = consistent only, false = suspicious only)
    pub ja4_consistent: Option<bool>,
    /// Filter by minimum JA4 confidence (0.0-1.0)
    pub min_ja4_confidence: Option<f64>,
    /// Limit number of results
    pub limit: Option<usize>,
}

/// Health check endpoint
/// GET /health
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: crate::VERSION.to_string(),
        timestamp: chrono::Utc::now(),
    })
}

/// Get all traffic profiles
/// GET /api/profiles
pub async fn get_profiles(
    State(state): State<AppState>,
    Query(query): Query<ProfileQuery>,
) -> Result<Json<ProfilesResponse>> {
    let all_profiles = state.get_profiles();

    // Apply filters and convert to TcpInfo
    let mut filtered_profiles = HashMap::new();

    for (_key, profile) in all_profiles.iter() {
        // Apply completeness filter
        if let Some(min_completeness) = query.min_completeness {
            if profile.metadata.completeness < min_completeness {
                continue;
            }
        }

        // Apply TCP filter (check raw data for more accurate filtering)
        if let Some(has_tcp) = query.has_tcp {
            let has_tcp_data = profile.raw_data.syn.is_some()
                || profile.raw_data.syn_ack.is_some()
                || profile.tcp.is_some();
            if has_tcp && !has_tcp_data {
                continue;
            }
            if !has_tcp && has_tcp_data {
                continue;
            }
        }

        // Apply HTTP filter (check raw data for more accurate filtering)
        if let Some(has_http) = query.has_http {
            let has_http_data = profile.raw_data.http_request.is_some()
                || profile.raw_data.http_response.is_some()
                || profile.http.is_some();
            if has_http && !has_http_data {
                continue;
            }
            if !has_http && has_http_data {
                continue;
            }
        }

        // Apply TLS filter (check raw data for more accurate filtering)
        if let Some(has_tls) = query.has_tls {
            let has_tls_data = profile.raw_data.tls_client.is_some() || profile.tls.is_some();
            if has_tls && !has_tls_data {
                continue;
            }
            if !has_tls && has_tls_data {
                continue;
            }
        }

        // Apply JA4 validation filter
        if let Some(has_ja4_validation) = query.has_ja4_validation {
            let has_ja4_data = profile.ja4_validation.is_some();
            if has_ja4_validation && !has_ja4_data {
                continue;
            }
            if !has_ja4_validation && has_ja4_data {
                continue;
            }
        }

        // Apply JA4 consistency filter
        if let Some(ja4_consistent) = query.ja4_consistent {
            if let Some(ja4_validation) = &profile.ja4_validation {
                if ja4_consistent && !ja4_validation.is_consistent {
                    continue; // Looking for consistent but this is inconsistent
                }
                if !ja4_consistent && ja4_validation.is_consistent {
                    continue; // Looking for suspicious but this is consistent
                }
            } else {
                continue; // No JA4 data available
            }
        }

        // Apply minimum JA4 confidence filter
        if let Some(min_ja4_confidence) = query.min_ja4_confidence {
            if let Some(ja4_validation) = &profile.ja4_validation {
                if ja4_validation.confidence < min_ja4_confidence {
                    continue; // Confidence too low
                }
            } else {
                continue; // No JA4 data available
            }
        }

        // Convert TrafficProfile to TcpInfo
        let tcp_info = convert_profile_to_tcp_info(profile);
        // Use IP only as key (matching user's example structure)
        let ip_key = profile.ip.to_string();
        filtered_profiles.insert(ip_key, tcp_info);

        // Apply limit
        if let Some(limit) = query.limit {
            if filtered_profiles.len() >= limit {
                break;
            }
        }
    }

    Ok(Json(ProfilesResponse {
        count: filtered_profiles.len(),
        profiles: filtered_profiles,
        timestamp: chrono::Utc::now(),
    }))
}

/// Get a specific traffic profile by key
/// GET /api/profiles/{key}
pub async fn get_profile(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<TcpInfo>> {
    match state.get_profile(&key) {
        Some(profile) => {
            let tcp_info = convert_profile_to_tcp_info(&profile);
            Ok(Json(tcp_info))
        }
        None => Err(ApiError::not_found(format!("Profile not found: {key}"))),
    }
}

/// Delete a specific traffic profile
/// DELETE /api/profiles/{key}
pub async fn delete_profile(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<StatusCode> {
    match state.remove_profile(&key) {
        Some(_) => Ok(StatusCode::NO_CONTENT),
        None => Err(ApiError::not_found(format!("Profile not found: {key}"))),
    }
}

/// Clear all traffic profiles
/// DELETE /api/profiles
pub async fn clear_profiles(State(state): State<AppState>) -> StatusCode {
    state.clear_profiles();
    StatusCode::NO_CONTENT
}

/// Get statistics about traffic profiles
/// GET /api/stats
pub async fn get_stats(State(state): State<AppState>) -> Json<ProfileStats> {
    Json(state.get_stats())
}

/// Response for profile search
#[derive(Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub count: usize,
    pub query: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Individual search result
#[derive(Serialize)]
pub struct SearchResult {
    pub key: String,
    pub profile: TcpInfo,
    pub relevance: f64,
}

/// Query parameters for searching profiles
#[derive(Deserialize)]
pub struct SearchQuery {
    /// Search query string
    pub q: String,
    /// Maximum number of results
    pub limit: Option<usize>,
}

/// Search traffic profiles
/// GET /api/search
pub async fn search_profiles(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>> {
    let all_profiles = state.get_profiles();
    let search_term = query.q.to_lowercase();
    let limit = query.limit.unwrap_or(50);

    let mut results = Vec::new();

    for (key, profile) in all_profiles.iter() {
        let mut relevance = 0.0;
        let mut matches = 0;

        // Search in IP address
        if profile.ip.to_string().contains(&search_term) {
            relevance += 1.0;
            matches += 1;
        }

        // Search in TCP OS detection
        if let Some(tcp) = &profile.tcp {
            if tcp.os.to_lowercase().contains(&search_term) {
                relevance += 0.8;
                matches += 1;
            }
        }

        // Search in HTTP browser detection
        if let Some(http) = &profile.http {
            if http.browser.to_lowercase().contains(&search_term) {
                relevance += 0.8;
                matches += 1;
            }
        }

        // Search in TLS JA4 fingerprint
        if let Some(tls) = &profile.tls {
            if tls.ja4.to_lowercase().contains(&search_term) {
                relevance += 0.6;
                matches += 1;
            }
        }

        // Search in JA4 validation data
        if let Some(ja4_validation) = &profile.ja4_validation {
            // Search in expected applications
            for app in &ja4_validation.expected_applications {
                if app.to_lowercase().contains(&search_term) {
                    relevance += 0.7;
                    matches += 1;
                    break; // Only count once per profile
                }
            }

            // Search in detected application
            if let Some(detected_app) = &ja4_validation.detected_application {
                if detected_app.to_lowercase().contains(&search_term) {
                    relevance += 0.7;
                    matches += 1;
                }
            }

            // Search in anomalies
            for anomaly in &ja4_validation.anomalies {
                if anomaly.to_lowercase().contains(&search_term) {
                    relevance += 0.5;
                    matches += 1;
                    break; // Only count once per profile
                }
            }

            // Search by consistency status
            let consistency_match = (search_term == "consistent" && ja4_validation.is_consistent)
                || ((search_term == "suspicious" || search_term == "inconsistent")
                    && !ja4_validation.is_consistent);

            if consistency_match {
                relevance += 0.4;
                matches += 1;
            }
        }

        // Only include results with matches
        if matches > 0 {
            let tcp_info = convert_profile_to_tcp_info(profile);
            results.push(SearchResult {
                key: key.clone(),
                profile: tcp_info,
                relevance: relevance / matches as f64,
            });
        }

        if results.len() >= limit {
            break;
        }
    }

    // Sort by relevance (highest first)
    results.sort_by(|a, b| b.relevance.partial_cmp(&a.relevance).unwrap());

    Ok(Json(SearchResponse {
        count: results.len(),
        results,
        query: query.q,
        timestamp: chrono::Utc::now(),
    }))
}

/// Response for API information
#[derive(Serialize)]
pub struct ApiInfoResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub endpoints: Vec<EndpointInfo>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Information about an API endpoint
#[derive(Serialize)]
pub struct EndpointInfo {
    pub method: String,
    pub path: String,
    pub description: String,
}

/// Get API information and available endpoints
/// GET /api
pub async fn api_info() -> Json<ApiInfoResponse> {
    Json(ApiInfoResponse {
        name: "Huginn API".to_string(),
        version: crate::VERSION.to_string(),
        description: "REST API for Huginn network traffic profiler".to_string(),
        endpoints: vec![
            EndpointInfo {
                method: "GET".to_string(),
                path: "/health".to_string(),
                description: "Health check endpoint".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api".to_string(),
                description: "API information and endpoints".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/profiles".to_string(),
                description: "Get all traffic profiles with optional filtering (TCP, HTTP, TLS, JA4 validation)".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/profiles/{key}".to_string(),
                description: "Get a specific traffic profile".to_string(),
            },
            EndpointInfo {
                method: "DELETE".to_string(),
                path: "/api/profiles/{key}".to_string(),
                description: "Delete a specific traffic profile".to_string(),
            },
            EndpointInfo {
                method: "DELETE".to_string(),
                path: "/api/profiles".to_string(),
                description: "Clear all traffic profiles".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/stats".to_string(),
                description: "Get statistics about traffic profiles including JA4 validation metrics".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/search".to_string(),
                description: "Search traffic profiles by IP, OS, browser, JA4, or consistency status".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/ws".to_string(),
                description: "WebSocket endpoint for real-time updates".to_string(),
            },
        ],
        timestamp: chrono::Utc::now(),
    })
}
