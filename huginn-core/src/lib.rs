//! # Huginn Core
//!
//! Core library for Huginn network traffic analysis.
//! Provides common data structures, traits, and utilities for network traffic profiling.

pub mod analyzer;
pub mod error;
pub mod events;
pub mod ja4;
pub mod profile;

// Re-export main types
pub use analyzer::{AnalyzerConfig, HuginnAnalyzer};
pub use error::{HuginnError, Result};
pub use events::{EventHandler, LoggingEventHandler, TrafficEvent};
pub use ja4::{ConsistencyAnalysis, JA4Database, JA4DatabaseStats, JA4Entry, VerificationStatus};
pub use profile::{HttpAnalysis, TcpAnalysis, TlsAnalysis, TrafficProfile};

// Re-export huginn-net types for convenience
pub use huginn_net::fingerprint_result::FingerprintResult;
pub use huginn_net::{HuginnNet, ObservableTcp, ObservableTlsClient};

/// Version of huginn-core
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_version_is_set() {
        assert!(VERSION.contains('.'));
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = HuginnAnalyzer::new();
        // This should not panic
        drop(analyzer);
    }

    #[test]
    fn test_analyzer_with_config() {
        let config = AnalyzerConfig {
            enable_tcp: true,
            enable_http: false,
            enable_tls: true,
            min_quality: 0.8,
        };
        let analyzer = HuginnAnalyzer::with_config(config);
        // This should not panic
        drop(analyzer);
    }

    #[test]
    fn test_traffic_profile_creation() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let profile = TrafficProfile::new(ip, 80);

        assert_eq!(profile.ip, ip);
        assert_eq!(profile.port, 80);
        assert!(profile.is_empty());
        assert_eq!(profile.summary(), "No data");
    }

    #[test]
    fn test_analyzer_config_default() {
        let config = AnalyzerConfig::default();
        assert!(config.enable_tcp);
        assert!(config.enable_http);
        assert!(config.enable_tls);
        assert_eq!(config.min_quality, 0.0);
    }

    #[test]
    fn test_huginn_error_creation() {
        let error = HuginnError::invalid_data("test error");
        assert!(error.to_string().contains("test error"));
    }
}
