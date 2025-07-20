use crate::error::{HuginnError, Result};
use crate::events::{EventDispatcher, TrafficEvent};
use crate::ja4::JA4Database;
use crate::profile::{
    HttpAnalysis, HttpDetails, MtuData, NetworkEndpoint, OsDetection, SynAckPacketData,
    SynPacketData, TcpAnalysis, TcpDetails, TlsAnalysis, TlsClientData, TlsDetails, TrafficProfile,
    UptimeData,
};
use chrono::Utc;
use huginn_net::fingerprint_result::*;
use huginn_net::tcp::{IpVersion, PayloadSize, WindowSize};
use huginn_net::ObservableTcp;
use huginn_net::Ttl;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::debug;

/// Configuration for the Huginn analyzer
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalyzerConfig {
    /// Whether to enable TCP analysis
    pub enable_tcp: bool,
    /// Whether to enable HTTP analysis
    pub enable_http: bool,
    /// Whether to enable TLS analysis
    pub enable_tls: bool,
    /// Minimum quality threshold for results
    pub min_quality: f64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            enable_http: true,
            enable_tls: true,
            min_quality: 0.0,
        }
    }
}

/// Main analyzer that converts huginn-net results to our data structures
pub struct HuginnAnalyzer {
    config: AnalyzerConfig,
    event_dispatcher: EventDispatcher,
    ja4_database: Option<JA4Database>,
}

impl HuginnAnalyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: AnalyzerConfig::default(),
            event_dispatcher: EventDispatcher::new(),
            ja4_database: None,
        }
    }

    /// Create a new analyzer with custom configuration
    pub fn with_config(config: AnalyzerConfig) -> Self {
        Self {
            config,
            event_dispatcher: EventDispatcher::new(),
            ja4_database: None,
        }
    }

    /// Set the JA4 database for TLS client validation
    pub fn set_ja4_database(&mut self, ja4_database: JA4Database) {
        self.ja4_database = Some(ja4_database);
    }

    /// Get a mutable reference to the event dispatcher
    pub fn event_dispatcher_mut(&mut self) -> &mut EventDispatcher {
        &mut self.event_dispatcher
    }

    /// Analyze a fingerprint result and return a traffic profile
    pub fn analyze(&self, result: FingerprintResult) -> Result<Option<TrafficProfile>> {
        // Debug logging to understand what huginn-net is sending
        tracing::info!(
            "🔍 ANALYZING FingerprintResult: SYN:{} SYN-ACK:{} HTTP-REQ:{} HTTP-RES:{} TLS:{} MTU:{} UPTIME:{}",
            result.syn.is_some(),
            result.syn_ack.is_some(),
            result.http_request.is_some(),
            result.http_response.is_some(),
            result.tls_client.is_some(),
            result.mtu.is_some(),
            result.uptime.is_some()
        );

        // Show detailed content for each type
        if let Some(syn) = &result.syn {
            debug!(
                "SYN data: source={}:{}, has_os_match={}",
                syn.source.ip,
                syn.source.port,
                syn.os_matched.is_some()
            );
        }
        if let Some(syn_ack) = &result.syn_ack {
            debug!(
                "SYN-ACK data: source={}:{}, dest={}:{}, has_os_match={}",
                syn_ack.source.ip,
                syn_ack.source.port,
                syn_ack.destination.ip,
                syn_ack.destination.port,
                syn_ack.os_matched.is_some()
            );
        }
        if let Some(http_req) = &result.http_request {
            debug!(
                "HTTP-REQ data: source={}:{}, has_browser_match={}",
                http_req.source.ip,
                http_req.source.port,
                http_req.browser_matched.is_some()
            );
        }
        if let Some(http_res) = &result.http_response {
            debug!(
                "HTTP-RES data: source={}:{}, dest={}:{}, has_server_match={}",
                http_res.source.ip,
                http_res.source.port,
                http_res.destination.ip,
                http_res.destination.port,
                http_res.web_server_matched.is_some()
            );
        }
        if let Some(tls_client) = &result.tls_client {
            debug!(
                "TLS data: source={}:{}",
                tls_client.source.ip, tls_client.source.port
            );
        }
        if let Some(mtu) = &result.mtu {
            debug!("MTU data: source={}:{}", mtu.source.ip, mtu.source.port);
        }
        if let Some(uptime) = &result.uptime {
            debug!(
                "UPTIME data: source={}:{}",
                uptime.source.ip, uptime.source.port
            );
        }

        // Extract primary IP from the result (for profile key - grouped by IP only, not port)
        let ip = match self.extract_primary_ip(&result) {
            Ok(ip) => {
                debug!("Primary IP: {}", ip);
                ip
            }
            Err(e) => {
                debug!("No valid IP found in result: {}", e);
                return Ok(None);
            }
        };

        // Create traffic profile (use port 0 as default since we group by IP only)
        let mut profile = TrafficProfile::new(ip, 0);

        // Store the source IP in raw data for reference
        profile.raw_data.source_ip = Some(ip.to_string());

        // Process SYN packets (client data)
        if let Some(syn) = &result.syn {
            debug!(
                "Processing SYN packet from {}:{} (CLIENT)",
                syn.source.ip, syn.source.port
            );
            let syn_data = self.process_syn_packet(syn)?;
            profile.raw_data.syn = Some(syn_data);

            // Create legacy TCP client analysis for backwards compatibility
            if self.config.enable_tcp {
                if let Some(tcp_analysis) = self.analyze_tcp_syn(syn)? {
                    debug!(
                        "TCP CLIENT analysis: OS={}, Quality={:.2}",
                        tcp_analysis.os, tcp_analysis.quality
                    );
                    profile.update_tcp_client(tcp_analysis.clone());
                    profile.update_tcp(tcp_analysis); // Also update general tcp field for backwards compatibility
                    self.emit_tcp_event(&profile, syn);
                }
            }
        }

        // Process SYN-ACK packets (server data)
        if let Some(syn_ack) = &result.syn_ack {
            debug!(
                "Processing SYN-ACK packet from {}:{} to {}:{} (SERVER)",
                syn_ack.source.ip,
                syn_ack.source.port,
                syn_ack.destination.ip,
                syn_ack.destination.port
            );
            let syn_ack_data = self.process_syn_ack_packet(syn_ack)?;
            profile.raw_data.syn_ack = Some(syn_ack_data);

            // Create legacy TCP server analysis for backwards compatibility
            if self.config.enable_tcp {
                if let Some(tcp_analysis) = self.analyze_tcp_syn_ack(syn_ack)? {
                    debug!(
                        "TCP SERVER analysis: OS={}, Quality={:.2}",
                        tcp_analysis.os, tcp_analysis.quality
                    );
                    profile.update_tcp_server(tcp_analysis.clone());
                    // DON'T update general tcp field here to avoid overwriting client data
                    self.emit_tcp_event_syn_ack(&profile, syn_ack);
                }
            }
        }

        // Process HTTP requests (client data)
        if let Some(http_req) = &result.http_request {
            debug!(
                "Processing HTTP request from {}:{} (CLIENT)",
                http_req.source.ip, http_req.source.port
            );
            let http_req_data = self.process_http_request(http_req)?;
            profile.raw_data.http_request = Some(http_req_data);

            // Also create legacy HTTP analysis for backwards compatibility
            if self.config.enable_http {
                if let Some(http_analysis) = self.analyze_http_request(http_req)? {
                    profile.update_http(http_analysis);
                    self.emit_http_event(&profile, http_req);
                }
            }
        }

        // Process HTTP responses (server data)
        if let Some(http_res) = &result.http_response {
            debug!(
                "Processing HTTP response from {}:{} to {}:{} (SERVER)",
                http_res.source.ip,
                http_res.source.port,
                http_res.destination.ip,
                http_res.destination.port
            );
            let http_res_data = self.process_http_response(http_res)?;
            profile.raw_data.http_response = Some(http_res_data);
        }

        // Process TLS client data
        if let Some(tls_client) = &result.tls_client {
            debug!(
                "Processing TLS client from {}:{}",
                tls_client.source.ip, tls_client.source.port
            );
            let tls_data = self.process_tls_client(tls_client)?;
            profile.raw_data.tls_client = Some(tls_data);

            // Also create legacy TLS analysis for backwards compatibility
            if self.config.enable_tls {
                if let Some(tls_analysis) = self.analyze_tls_client(tls_client)? {
                    profile.update_tls(tls_analysis);
                    self.emit_tls_event(&profile, tls_client);
                }
            }
        }

        // Process MTU data
        if let Some(mtu) = &result.mtu {
            debug!(
                "Processing MTU data from {}:{}",
                mtu.source.ip, mtu.source.port
            );
            let mtu_data = self.process_mtu_data(mtu)?;
            profile.raw_data.mtu = Some(mtu_data);
        }

        // Process uptime data
        if let Some(uptime) = &result.uptime {
            debug!(
                "Processing uptime data from {}:{}",
                uptime.source.ip, uptime.source.port
            );
            let uptime_data = self.process_uptime_data(uptime)?;
            profile.raw_data.uptime = Some(uptime_data);
        }

        // Note: source_ip field doesn't exist in FingerprintResult
        // Will be determined from the individual packet data

        // JA4 validation is performed later when profiles are combined/updated
        // since TLS and HTTP data may arrive in separate packets

        // Only return profile if it has some data
        if profile.is_empty() {
            debug!("Profile is empty, not creating");
            Ok(None)
        } else {
            debug!(
                "Created profile for {}:{} with data: {}",
                profile.ip,
                profile.port,
                profile.summary()
            );
            // Note: ProfileCreated events are handled by the collector layer
            Ok(Some(profile))
        }
    }

    /// Extract primary IP from fingerprint result (for profile key - grouped by IP only)
    fn extract_primary_ip(&self, result: &FingerprintResult) -> Result<IpAddr> {
        if let Some(syn) = &result.syn {
            // SYN packet: source is the client
            debug!("Extracting IP from SYN packet");
            let ip = IpAddr::from_str(&syn.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {e}")))?;
            Ok(ip)
        } else if let Some(syn_ack) = &result.syn_ack {
            // SYN-ACK packet: destination is the client that initiated the connection
            debug!("Extracting IP from SYN-ACK packet");
            let ip = IpAddr::from_str(&syn_ack.destination.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {e}")))?;
            Ok(ip)
        } else if let Some(http_req) = &result.http_request {
            // HTTP request: source is the client
            debug!("Extracting IP from HTTP request");
            let ip = IpAddr::from_str(&http_req.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {e}")))?;
            Ok(ip)
        } else if let Some(http_res) = &result.http_response {
            // HTTP response: destination is the client that made the request
            debug!("Extracting IP from HTTP response");
            let ip = IpAddr::from_str(&http_res.destination.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {e}")))?;
            Ok(ip)
        } else if let Some(tls_client) = &result.tls_client {
            // TLS client: source is the client
            debug!("Extracting IP from TLS client");
            let ip = IpAddr::from_str(&tls_client.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {e}")))?;
            Ok(ip)
        } else if let Some(mtu) = &result.mtu {
            // MTU detection: source is the client
            debug!("Extracting IP from MTU data");
            let ip = IpAddr::from_str(&mtu.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {e}")))?;
            Ok(ip)
        } else if let Some(uptime) = &result.uptime {
            // Uptime detection: source is the client
            debug!("Extracting IP from uptime data");
            let ip = IpAddr::from_str(&uptime.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {e}")))?;
            Ok(ip)
        } else {
            debug!("No valid data found in FingerprintResult");
            Err(HuginnError::invalid_data("No valid IP found in result"))
        }
    }

    // New methods for processing raw fingerprint data

    /// Process SYN packet data
    fn process_syn_packet(&self, syn: &SynTCPOutput) -> Result<SynPacketData> {
        let os_detected = syn.os_matched.as_ref().map(|m| OsDetection {
            os: self.extract_os_string(&m.os),
            quality: m.quality as f64,
            distance: self.extract_distance(&syn.sig.ittl),
        });

        Ok(SynPacketData {
            source: NetworkEndpoint {
                ip: syn.source.ip.to_string(),
                port: syn.source.port,
            },
            os_detected,
            signature: syn.sig.to_string(),
            details: self.convert_tcp_details(&syn.sig),
            timestamp: Utc::now(),
        })
    }

    /// Process SYN-ACK packet data
    fn process_syn_ack_packet(&self, syn_ack: &SynAckTCPOutput) -> Result<SynAckPacketData> {
        let os_detected = syn_ack.os_matched.as_ref().map(|m| OsDetection {
            os: self.extract_os_string(&m.os),
            quality: m.quality as f64,
            distance: self.extract_distance(&syn_ack.sig.ittl),
        });

        Ok(SynAckPacketData {
            source: NetworkEndpoint {
                ip: syn_ack.source.ip.to_string(),
                port: syn_ack.source.port,
            },
            destination: NetworkEndpoint {
                ip: syn_ack.destination.ip.to_string(),
                port: syn_ack.destination.port,
            },
            os_detected,
            signature: syn_ack.sig.to_string(),
            details: self.convert_tcp_details(&syn_ack.sig),
            timestamp: Utc::now(),
        })
    }

    /// Process HTTP request data
    fn process_http_request(
        &self,
        http_req: &HttpRequestOutput,
    ) -> Result<crate::profile::HttpRequestData> {
        let horder_strings: Vec<String> =
            http_req.sig.horder.iter().map(|h| h.to_string()).collect();

        Ok(crate::profile::HttpRequestData {
            user_agent: self.extract_user_agent_from_signature(&http_req.sig.to_string()),
            accept: self.extract_header_value_from_horder(&horder_strings, "accept"),
            accept_language: self
                .extract_header_value_from_horder(&horder_strings, "accept-language"),
            accept_encoding: self
                .extract_header_value_from_horder(&horder_strings, "accept-encoding"),
            connection: self.extract_header_value_from_horder(&horder_strings, "connection"),
            method: Some("GET".to_string()),
            host: self.extract_header_value_from_horder(&horder_strings, "host"),
            signature: http_req.sig.to_string(),
            quality: http_req
                .browser_matched
                .as_ref()
                .map(|m| m.quality as f64)
                .unwrap_or(0.0),
        })
    }

    /// Process HTTP response data
    fn process_http_response(
        &self,
        http_res: &HttpResponseOutput,
    ) -> Result<crate::profile::HttpResponseData> {
        let horder_strings: Vec<String> =
            http_res.sig.horder.iter().map(|h| h.to_string()).collect();

        Ok(crate::profile::HttpResponseData {
            server: self.extract_header_value_from_horder(&horder_strings, "server"),
            content_type: self.extract_header_value_from_horder(&horder_strings, "content-type"),
            content_length: self
                .extract_header_value_from_horder(&horder_strings, "content-length"),
            set_cookie: self.extract_header_value_from_horder(&horder_strings, "set-cookie"),
            cache_control: self.extract_header_value_from_horder(&horder_strings, "cache-control"),
            status: Some("200".to_string()),
            signature: http_res.sig.to_string(),
            quality: http_res
                .web_server_matched
                .as_ref()
                .map(|m| m.quality as f64)
                .unwrap_or(0.0),
        })
    }

    /// Process TLS client data
    fn process_tls_client(&self, tls_client: &TlsClientOutput) -> Result<TlsClientData> {
        let details = TlsDetails {
            version: tls_client.sig.version.to_string(),
            sni: tls_client.sig.sni.as_ref().map(|s| s.to_string()),
            alpn: tls_client.sig.alpn.as_ref().map(|s| s.to_string()),
            cipher_suites: tls_client.sig.cipher_suites.clone(),
            extensions: tls_client.sig.extensions.clone(),
            signature_algorithms: tls_client.sig.signature_algorithms.clone(),
            elliptic_curves: tls_client.sig.elliptic_curves.clone(),
        };

        Ok(TlsClientData {
            source: NetworkEndpoint {
                ip: tls_client.source.ip.to_string(),
                port: tls_client.source.port,
            },
            ja4: tls_client.sig.ja4.full.value().to_string(),
            ja4_raw: tls_client.sig.ja4.raw.value().to_string(),
            details,
            timestamp: Utc::now(),
        })
    }

    /// Process MTU data
    fn process_mtu_data(&self, mtu: &MTUOutput) -> Result<MtuData> {
        Ok(MtuData {
            source: NetworkEndpoint {
                ip: mtu.source.ip.to_string(),
                port: mtu.source.port,
            },
            mtu_value: mtu.mtu,
            timestamp: Utc::now(),
        })
    }

    /// Process uptime data
    fn process_uptime_data(&self, uptime: &UptimeOutput) -> Result<UptimeData> {
        // Calculate total seconds from available fields
        let total_seconds = (uptime.days as u64 * 24 * 3600)
            + (uptime.hours as u64 * 3600)
            + (uptime.min as u64 * 60);

        Ok(UptimeData {
            source: NetworkEndpoint {
                ip: uptime.source.ip.to_string(),
                port: uptime.source.port,
            },
            uptime_seconds: total_seconds,
            timestamp: Utc::now(),
        })
    }

    /// Analyze TCP SYN packet
    fn analyze_tcp_syn(&self, syn: &SynTCPOutput) -> Result<Option<TcpAnalysis>> {
        let quality = syn
            .os_matched
            .as_ref()
            .map(|m| m.quality as f64)
            .unwrap_or(0.0);

        if quality < self.config.min_quality {
            return Ok(None);
        }

        let os = syn
            .os_matched
            .as_ref()
            .map(|m| self.extract_os_string(&m.os))
            .unwrap_or_else(|| "Unknown".to_string());

        let distance = self.extract_distance(&syn.sig.ittl);
        let details = self.convert_tcp_details(&syn.sig);

        Ok(Some(TcpAnalysis {
            os,
            quality,
            distance,
            signature: syn.sig.to_string(),
            details,
        }))
    }

    /// Analyze TCP SYN-ACK packet
    fn analyze_tcp_syn_ack(&self, syn_ack: &SynAckTCPOutput) -> Result<Option<TcpAnalysis>> {
        let quality = syn_ack
            .os_matched
            .as_ref()
            .map(|m| m.quality as f64)
            .unwrap_or(0.0);

        if quality < self.config.min_quality {
            return Ok(None);
        }

        let os = syn_ack
            .os_matched
            .as_ref()
            .map(|m| self.extract_os_string(&m.os))
            .unwrap_or_else(|| "Unknown".to_string());

        let distance = self.extract_distance(&syn_ack.sig.ittl);
        let details = self.convert_tcp_details(&syn_ack.sig);

        Ok(Some(TcpAnalysis {
            os,
            quality,
            distance,
            signature: syn_ack.sig.to_string(),
            details,
        }))
    }

    /// Analyze HTTP request
    fn analyze_http_request(&self, http_req: &HttpRequestOutput) -> Result<Option<HttpAnalysis>> {
        let quality = http_req
            .browser_matched
            .as_ref()
            .map(|m| m.quality as f64)
            .unwrap_or(0.0);

        if quality < self.config.min_quality {
            return Ok(None);
        }

        let browser = http_req
            .browser_matched
            .as_ref()
            .map(|m| self.extract_browser_string(&m.browser))
            .unwrap_or_else(|| "Unknown".to_string());

        let details = HttpDetails {
            version: http_req.sig.version.to_string(),
            header_order: http_req
                .sig
                .horder
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            headers_absent: http_req
                .sig
                .habsent
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            expected_software: http_req.sig.expsw.clone(),
        };

        // Extract request-specific data from headers
        let horder_strings: Vec<String> =
            http_req.sig.horder.iter().map(|h| h.to_string()).collect();

        let request_data = crate::profile::HttpRequestData {
            user_agent: self.extract_user_agent_from_signature(&http_req.sig.to_string()),
            accept: self.extract_header_value_from_horder(&horder_strings, "accept"),
            accept_language: self
                .extract_header_value_from_horder(&horder_strings, "accept-language"),
            accept_encoding: self
                .extract_header_value_from_horder(&horder_strings, "accept-encoding"),
            connection: self.extract_header_value_from_horder(&horder_strings, "connection"),
            method: Some("GET".to_string()), // Default, could be extracted from signature
            host: self.extract_header_value_from_horder(&horder_strings, "host"),
            signature: http_req.sig.to_string(),
            quality,
        };

        Ok(Some(HttpAnalysis {
            browser,
            quality,
            language: http_req.lang.as_ref().map(|l| l.to_string()),
            diagnosis: http_req.diagnosis.to_string(),
            signature: http_req.sig.to_string(),
            details,
            request: Some(request_data),
            response: None,
        }))
    }

    /// Analyze TLS client
    fn analyze_tls_client(&self, tls_client: &TlsClientOutput) -> Result<Option<TlsAnalysis>> {
        let details = TlsDetails {
            version: tls_client.sig.version.to_string(),
            sni: tls_client.sig.sni.as_ref().map(|s| s.to_string()),
            alpn: tls_client.sig.alpn.as_ref().map(|s| s.to_string()),
            cipher_suites: tls_client.sig.cipher_suites.clone(),
            extensions: tls_client.sig.extensions.clone(),
            signature_algorithms: tls_client.sig.signature_algorithms.clone(),
            elliptic_curves: tls_client.sig.elliptic_curves.clone(),
        };

        Ok(Some(TlsAnalysis {
            ja4: tls_client.sig.ja4.full.value().to_string(),
            ja4_raw: tls_client.sig.ja4.raw.value().to_string(),
            ja4_original: tls_client.sig.ja4_original.full.value().to_string(),
            ja4_original_raw: tls_client.sig.ja4_original.raw.value().to_string(),
            details,
        }))
    }

    // Helper methods for extracting and converting data
    fn extract_os_string(&self, os: &OperativeSystem) -> String {
        let mut parts = vec![os.name.clone()];
        if let Some(family) = &os.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &os.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    }

    fn extract_browser_string(&self, browser: &Browser) -> String {
        let mut parts = vec![browser.name.clone()];
        if let Some(family) = &browser.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &browser.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    }

    /// Extract header value from horder field
    /// horder contains strings like "user-agent=[Mozilla/5.0...]" or "content-type=[application/json]"
    fn extract_header_value_from_horder(
        &self,
        horder: &[String],
        header_name: &str,
    ) -> Option<String> {
        for header in horder {
            if let Some(eq_pos) = header.find('=') {
                let (name, value_part) = header.split_at(eq_pos);
                if name.to_lowercase() == header_name.to_lowercase() {
                    // Remove the '=' and extract value between brackets
                    let value_part = &value_part[1..]; // Remove '='
                    if value_part.starts_with('[') && value_part.ends_with(']') {
                        return Some(value_part[1..value_part.len() - 1].to_string());
                    } else {
                        return Some(value_part.to_string());
                    }
                }
            }
        }
        None
    }

    /// Extract User-Agent from HTTP signature: "version:headers:absent_headers:user_agent"
    fn extract_user_agent_from_signature(&self, signature: &str) -> Option<String> {
        let parts: Vec<&str> = signature.split(':').collect();
        if parts.len() >= 4 {
            // User-Agent is typically in the last part after the third colon
            let user_agent_part = parts[3..].join(":");
            if !user_agent_part.is_empty() && user_agent_part != "???" {
                Some(user_agent_part.trim().to_string())
            } else {
                None
            }
        } else {
            None
        }
    }

    fn extract_distance(&self, ttl: &Ttl) -> u8 {
        match ttl {
            Ttl::Distance(_, hops) => *hops,
            _ => 0,
        }
    }

    fn convert_tcp_details(&self, sig: &ObservableTcp) -> TcpDetails {
        TcpDetails {
            version: match sig.version {
                IpVersion::V4 => "IPv4".to_string(),
                IpVersion::V6 => "IPv6".to_string(),
                IpVersion::Any => "Unknown".to_string(),
            },
            initial_ttl: match sig.ittl {
                Ttl::Distance(_, hops) => format!("Distance*{hops}"),
                Ttl::Value(value) => format!("Value*{value}"),
                Ttl::Bad(value) => format!("Bad*{value}"),
                Ttl::Guess(value) => format!("Guess*{value}"),
            },
            options_length: sig.olen,
            mss: sig.mss,
            window_size: match sig.wsize {
                WindowSize::Mod(val) => format!("MOD*{val}"),
                WindowSize::Mss(val) => format!("MSS*{val}"),
                WindowSize::Mtu(val) => format!("MTU*{val}"),
                WindowSize::Value(val) => format!("Value*{val}"),
                WindowSize::Any => "Any".to_string(),
            },
            window_scale: sig.wscale,
            options_layout: sig
                .olayout
                .iter()
                .map(|opt| format!("{opt:?}"))
                .collect::<Vec<_>>()
                .join(","),
            quirks: sig
                .quirks
                .iter()
                .map(|quirk| format!("{quirk:?}"))
                .collect::<Vec<_>>()
                .join(","),
            payload_class: match sig.pclass {
                PayloadSize::Zero => "0".to_string(),
                PayloadSize::NonZero => "+".to_string(),
                PayloadSize::Any => "*".to_string(),
            },
        }
    }

    // Event emission methods
    fn emit_tcp_event(&self, profile: &TrafficProfile, _syn: &SynTCPOutput) {
        if let Some(tcp) = &profile.tcp {
            self.event_dispatcher.dispatch(TrafficEvent::TcpAnalyzed {
                ip: profile.ip,
                port: profile.port,
                os: tcp.os.clone(),
                quality: tcp.quality,
                timestamp: Utc::now(),
            });
        }
    }

    fn emit_tcp_event_syn_ack(&self, profile: &TrafficProfile, _syn_ack: &SynAckTCPOutput) {
        if let Some(tcp) = &profile.tcp {
            self.event_dispatcher.dispatch(TrafficEvent::TcpAnalyzed {
                ip: profile.ip,
                port: profile.port,
                os: tcp.os.clone(),
                quality: tcp.quality,
                timestamp: Utc::now(),
            });
        }
    }

    fn emit_http_event(&self, profile: &TrafficProfile, _http_req: &HttpRequestOutput) {
        if let Some(http) = &profile.http {
            self.event_dispatcher.dispatch(TrafficEvent::HttpAnalyzed {
                ip: profile.ip,
                port: profile.port,
                browser: http.browser.clone(),
                quality: http.quality,
                timestamp: Utc::now(),
            });
        }
    }

    fn emit_tls_event(&self, profile: &TrafficProfile, _tls_client: &TlsClientOutput) {
        if let Some(tls) = &profile.tls {
            self.event_dispatcher.dispatch(TrafficEvent::TlsAnalyzed {
                ip: profile.ip,
                port: profile.port,
                ja4: tls.ja4.clone(),
                timestamp: Utc::now(),
            });
        }
    }

    /// Perform JA4 validation if JA4 database is available and we have both TLS and HTTP data
    pub fn perform_ja4_validation(&self, profile: &mut TrafficProfile) {
        // Check if JA4 database is available
        let ja4_database = match &self.ja4_database {
            Some(db) => db,
            None => {
                tracing::info!("JA4 database not available, skipping validation");
                return;
            }
        };

        // Extract JA4 fingerprint from TLS data (raw data first, then legacy fallback)
        let ja4 = match &profile.raw_data.tls_client {
            Some(tls_data) => &tls_data.ja4,
            None => {
                // Fallback to legacy TLS data
                if let Some(tls) = &profile.tls {
                    &tls.ja4
                } else {
                    tracing::info!("No TLS data available for JA4 validation - raw_data.tls_client: {:?}, tls: {:?}, raw_data summary: syn={:?}, tls_client={:?}", 
                           profile.raw_data.tls_client.is_some(), 
                           profile.tls.is_some(),
                           profile.raw_data.syn.is_some(),
                           profile.raw_data.tls_client.is_some());
                    return;
                }
            }
        };

        // Extract User-Agent from HTTP data (raw data first, then legacy fallback)
        let user_agent = match &profile.raw_data.http_request {
            Some(http_data) => match &http_data.user_agent {
                Some(ua) => ua,
                None => {
                    tracing::info!("No User-Agent in HTTP request data");
                    return;
                }
            },
            None => {
                // Fallback to legacy HTTP data
                if let Some(http) = &profile.http {
                    if let Some(request) = &http.request {
                        match &request.user_agent {
                            Some(ua) => ua,
                            None => {
                                tracing::info!("No User-Agent in legacy HTTP request data");
                                return;
                            }
                        }
                    } else {
                        tracing::info!("No HTTP request in legacy HTTP data");
                        return;
                    }
                } else {
                    tracing::info!(
                        "No HTTP data available for JA4 validation - raw_data: {:?}, http: {:?}",
                        profile.raw_data.http_request.is_some(),
                        profile.http.is_some()
                    );
                    return;
                }
            }
        };

        tracing::info!(
            "Performing JA4 validation for {}:{} - JA4: {} UA: {}",
            profile.ip,
            profile.port,
            ja4,
            user_agent.chars().take(50).collect::<String>()
        );

        // Extract needed values before performing validation to avoid borrow conflicts
        let ip = profile.ip;
        let port = profile.port;
        let ja4_clone = ja4.clone();
        let user_agent_clone = user_agent.clone();

        // Perform validation
        let validation_result = ja4_database.validate_consistency(ja4, user_agent);

        tracing::info!(
            "JA4 validation result for {}:{} - Consistent: {}, Confidence: {:.2}, Anomalies: {}",
            ip,
            port,
            validation_result.is_consistent,
            validation_result.confidence,
            validation_result.anomalies.len()
        );

        // Update profile with validation results
        profile.update_ja4_validation(validation_result.clone());

        // Emit JA4 validation event
        self.event_dispatcher.dispatch(TrafficEvent::JA4Validated {
            ip,
            port,
            ja4: ja4_clone,
            user_agent: user_agent_clone,
            is_consistent: validation_result.is_consistent,
            confidence: validation_result.confidence,
            timestamp: Utc::now(),
        });
    }
}

impl Default for HuginnAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
