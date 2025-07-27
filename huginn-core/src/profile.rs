use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::ja4::ConsistencyAnalysis;

/// Complete traffic profile for a network endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficProfile {
    /// Source IP address
    pub ip: IpAddr,
    /// Source port
    pub port: u16,
    /// When this profile was created/updated
    pub timestamp: DateTime<Utc>,
    /// Raw fingerprint data (separated by source)
    pub raw_data: RawFingerprintData,
    /// TCP analysis results (legacy - for backwards compatibility)
    pub tcp: Option<TcpAnalysis>,
    /// TCP analysis from client packets (SYN) - for backwards compatibility
    pub tcp_client: Option<TcpAnalysis>,
    /// TCP analysis from server packets (SYN-ACK) - for backwards compatibility  
    pub tcp_server: Option<TcpAnalysis>,
    /// HTTP analysis results (legacy - for backwards compatibility)
    pub http: Option<HttpAnalysis>,
    /// TLS analysis results (legacy - for backwards compatibility)
    pub tls: Option<TlsAnalysis>,
    /// JA4 validation results (if JA4 database is available)
    pub ja4_validation: Option<ConsistencyAnalysis>,
    /// Additional metadata
    pub metadata: ProfileMetadata,
}

/// Raw fingerprint data separated by source type
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawFingerprintData {
    /// SYN packet (from client)
    pub syn: Option<SynPacketData>,
    /// SYN-ACK packet (from server)
    pub syn_ack: Option<SynAckPacketData>,
    /// MTU detection data
    pub mtu: Option<MtuData>,
    /// Uptime detection data
    pub uptime: Option<UptimeData>,
    /// HTTP request (from client)
    pub http_request: Option<HttpRequestData>,
    /// HTTP response (from server)
    pub http_response: Option<HttpResponseData>,
    /// TLS client data
    pub tls_client: Option<TlsClientData>,
    /// Source IP (if available)
    pub source_ip: Option<String>,
}

/// SYN packet data (from client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynPacketData {
    /// Source IP and port
    pub source: NetworkEndpoint,
    /// OS detection result
    pub os_detected: Option<OsDetection>,
    /// TCP signature
    pub signature: String,
    /// Raw packet details
    pub details: TcpDetails,
    /// When this was detected
    pub timestamp: DateTime<Utc>,
}

/// SYN-ACK packet data (from server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynAckPacketData {
    /// Source (server) IP and port
    pub source: NetworkEndpoint,
    /// Destination (client) IP and port
    pub destination: NetworkEndpoint,
    /// OS detection result
    pub os_detected: Option<OsDetection>,
    /// TCP signature
    pub signature: String,
    /// Raw packet details
    pub details: TcpDetails,
    /// When this was detected
    pub timestamp: DateTime<Utc>,
}

/// MTU detection data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtuData {
    /// Source IP and port
    pub source: NetworkEndpoint,
    /// Detected MTU value
    pub mtu_value: u16,
    /// When this was detected
    pub timestamp: DateTime<Utc>,
}

/// Uptime detection data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeData {
    /// Source IP and port
    pub source: NetworkEndpoint,
    /// Detected uptime in seconds
    pub uptime_seconds: u64,
    /// When this was detected
    pub timestamp: DateTime<Utc>,
}

/// TLS client data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientData {
    /// Source IP and port
    pub source: NetworkEndpoint,
    /// JA4 fingerprint
    pub ja4: String,
    /// JA4 raw fingerprint
    pub ja4_raw: String,
    /// JA4 original fingerprint
    pub ja4_original: String,
    /// JA4 original raw fingerprint
    pub ja4_original_raw: String,
    /// TLS details
    pub details: TlsDetails,
    /// When this was detected
    pub timestamp: DateTime<Utc>,
}

/// Network endpoint (IP + port)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
}

/// OS detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetection {
    /// Operating system name
    pub os: String,
    /// Detection quality/confidence
    pub quality: f64,
    /// Network distance (hops)
    pub distance: u8,
}

/// TCP connection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpAnalysis {
    /// Operating system detection
    pub os: String,
    /// Detection quality/confidence
    pub quality: f64,
    /// Network distance (hops)
    pub distance: u8,
    /// TCP signature string
    pub signature: String,
    /// Detailed TCP characteristics
    pub details: TcpDetails,
}

/// HTTP request/response analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAnalysis {
    /// Browser/server detection
    pub browser: String,
    /// Detection quality/confidence
    pub quality: f64,
    /// Language detection
    pub language: Option<String>,
    /// Diagnosis information
    pub diagnosis: String,
    /// HTTP signature
    pub signature: String,
    /// Detailed HTTP characteristics
    pub details: HttpDetails,
    /// Request-specific data (from client)
    pub request: Option<HttpRequestData>,
    /// Response-specific data (from server)
    pub response: Option<HttpResponseData>,
}

/// HTTP request data (from client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestData {
    /// User-Agent header
    pub user_agent: Option<String>,
    /// Accept headers
    pub accept: Option<String>,
    /// Accept-Language header
    pub accept_language: Option<String>,
    /// Accept-Encoding header
    pub accept_encoding: Option<String>,
    /// Connection type
    pub connection: Option<String>,
    /// Request method
    pub method: Option<String>,
    /// Host header
    pub host: Option<String>,
    /// Request signature
    pub signature: String,
    /// Quality score for request analysis
    pub quality: f64,
}

/// HTTP response data (from server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseData {
    /// Server header
    pub server: Option<String>,
    /// Content-Type header
    pub content_type: Option<String>,
    /// Content-Length header
    pub content_length: Option<String>,
    /// Set-Cookie headers
    pub set_cookie: Option<String>,
    /// Cache-Control header
    pub cache_control: Option<String>,
    /// Response status
    pub status: Option<String>,
    /// Response signature
    pub signature: String,
    /// Quality score for response analysis
    pub quality: f64,
}

/// TLS connection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAnalysis {
    /// JA4 fingerprint (full)
    pub ja4: String,
    /// JA4 raw fingerprint
    pub ja4_raw: String,
    /// JA4 original fingerprint
    pub ja4_original: String,
    /// JA4 original raw fingerprint
    pub ja4_original_raw: String,
    /// Detailed TLS characteristics
    pub details: TlsDetails,
}

/// Detailed TCP characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpDetails {
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

/// Detailed HTTP characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDetails {
    pub version: String,
    pub header_order: String,
    pub headers_absent: String,
    pub expected_software: String,
}

/// Detailed TLS characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsDetails {
    pub version: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

/// Additional profile metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    /// First time this IP was seen
    pub first_seen: DateTime<Utc>,
    /// Last time this IP was updated
    pub last_updated: DateTime<Utc>,
    /// Number of packets analyzed
    pub packet_count: u64,
    /// Profile completeness (0.0 - 1.0)
    pub completeness: f64,
}

impl TrafficProfile {
    /// Create a new traffic profile
    pub fn new(ip: IpAddr, port: u16) -> Self {
        let now = Utc::now();
        Self {
            ip,
            port,
            timestamp: now,
            raw_data: RawFingerprintData::default(),
            tcp: None,
            tcp_client: None,
            tcp_server: None,
            http: None,
            tls: None,
            ja4_validation: None,
            metadata: ProfileMetadata {
                first_seen: now,
                last_updated: now,
                packet_count: 0,
                completeness: 0.0,
            },
        }
    }

    /// Update the profile with new analysis data
    pub fn update_tcp(&mut self, tcp: TcpAnalysis) {
        self.tcp = Some(tcp);
        self.update_metadata();
    }

    /// Update the profile with TCP client analysis (from SYN packets)
    pub fn update_tcp_client(&mut self, tcp: TcpAnalysis) {
        self.tcp_client = Some(tcp);
        self.update_metadata();
    }

    /// Update the profile with TCP server analysis (from SYN-ACK packets)
    pub fn update_tcp_server(&mut self, tcp: TcpAnalysis) {
        self.tcp_server = Some(tcp);
        self.update_metadata();
    }

    /// Update the profile with HTTP analysis
    pub fn update_http(&mut self, http: HttpAnalysis) {
        if let Some(existing_http) = &mut self.http {
            // Merge request and response data
            if http.request.is_some() {
                existing_http.request = http.request;
            }
            if http.response.is_some() {
                existing_http.response = http.response;
            }
            // Update other fields if they have better quality
            if http.quality > existing_http.quality {
                existing_http.browser = http.browser;
                existing_http.quality = http.quality;
                existing_http.language = http.language;
                existing_http.diagnosis = http.diagnosis;
                existing_http.signature = http.signature;
                existing_http.details = http.details;
            }
        } else {
            self.http = Some(http);
        }
        self.update_metadata();
    }

    /// Update the profile with TLS analysis
    pub fn update_tls(&mut self, tls: TlsAnalysis) {
        self.tls = Some(tls);
        self.update_metadata();
    }

    /// Update the profile with JA4 validation results
    pub fn update_ja4_validation(&mut self, validation: ConsistencyAnalysis) {
        self.ja4_validation = Some(validation);
        self.update_metadata();
    }

    /// Calculate and update profile completeness
    fn update_metadata(&mut self) {
        self.metadata.last_updated = Utc::now();
        self.metadata.packet_count += 1;

        // Calculate completeness based on available data
        let mut score = 0.0;
        if self.tcp.is_some() || self.tcp_client.is_some() || self.tcp_server.is_some() {
            score += 0.4;
        }
        if self.http.is_some() {
            score += 0.3;
        }
        if self.tls.is_some() {
            score += 0.3;
        }

        self.metadata.completeness = score;
    }

    /// Check if profile has any analysis data
    pub fn is_empty(&self) -> bool {
        self.tcp.is_none()
            && self.tcp_client.is_none()
            && self.tcp_server.is_none()
            && self.http.is_none()
            && self.tls.is_none()
            && self.ja4_validation.is_none()
    }

    /// Get a summary string of available data
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.tcp.is_some() {
            parts.push("TCP");
        }
        if self.tcp_client.is_some() {
            parts.push("TCP-Client");
        }
        if self.tcp_server.is_some() {
            parts.push("TCP-Server");
        }
        if self.http.is_some() {
            parts.push("HTTP");
        }
        if self.tls.is_some() {
            parts.push("TLS");
        }
        if self.ja4_validation.is_some() {
            parts.push("JA4-Validated");
        }

        if parts.is_empty() {
            "No data".to_string()
        } else {
            parts.join(" + ")
        }
    }
}
