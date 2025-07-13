//! # Huginn Collector
//!
//! Network traffic collection and analysis module for Huginn.
//! Provides network packet capture and real-time traffic analysis capabilities.

pub mod bridge;
pub mod collector;
pub mod config;
pub mod error;

// Re-export main types
pub use bridge::ChannelBridge;
pub use collector::{CollectorHandle, NetworkCollector, NetworkCollectorBuilder};
pub use config::CollectorConfig;
pub use error::{CollectorError, Result};

/// Version of huginn-collector
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_set() {
        assert!(VERSION.contains('.'));
    }

    #[test]
    fn test_collector_config_default() {
        let config = CollectorConfig::default();
        assert!(!config.interface.is_empty());
        assert!(config.buffer_size > 0);
        assert!(config.channel_buffer_size > 0);
    }

    #[test]
    fn test_collector_config_new() {
        let config = CollectorConfig::new("eth0".to_string());
        assert_eq!(config.interface, "eth0");
        assert!(config.buffer_size > 0);
        assert!(config.channel_buffer_size > 0);
    }

    #[test]
    fn test_collector_error_creation() {
        let error = CollectorError::collection("test error");
        assert!(error.to_string().contains("test error"));
    }

    #[test]
    fn test_collector_error_config() {
        let error = CollectorError::configuration("config failed");
        assert!(error.to_string().contains("config failed"));
    }

    #[test]
    fn test_collector_config_validation() {
        let config = CollectorConfig::default();
        assert!(config.validate().is_ok());

        let invalid_config = CollectorConfig::new("".to_string());
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_collector_config_builder() {
        let config = CollectorConfig::new("wlan0".to_string())
            .with_buffer_size(200)
            .with_channel_buffer_size(2000)
            .with_verbose(true);

        assert_eq!(config.interface, "wlan0");
        assert_eq!(config.buffer_size, 200);
        assert_eq!(config.channel_buffer_size, 2000);
        assert!(config.verbose);
    }
}
