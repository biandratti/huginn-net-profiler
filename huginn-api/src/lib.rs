//! # Huginn API
//!
//! Web API server for Huginn network traffic analysis.
//! Provides REST endpoints and WebSocket support for real-time traffic monitoring.

pub mod error;
pub mod handlers;
pub mod server;
pub mod state;
pub mod websocket;

// Re-export main types
pub use error::{ApiError, Result};
pub use server::{ApiServer, ApiServerConfig};
pub use state::AppState;

/// Version of huginn-api
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_version_is_set() {
        assert!(VERSION.contains('.'));
    }

    #[test]
    fn test_server_config_default() {
        let config = ApiServerConfig::default();
        assert!(config.bind_addr.port() > 0);
        assert!(!config.interface.is_empty());
    }

    #[test]
    fn test_server_config_interface() {
        let config = ApiServerConfig {
            interface: "wlan0".to_string(),
            ..ApiServerConfig::default()
        };
        assert_eq!(config.interface, "wlan0");
    }

    #[test]
    fn test_api_server_creation() {
        let config = ApiServerConfig::default();
        let server = ApiServer::new(config);

        drop(server);
    }

    #[test]
    fn test_api_error_creation() {
        let error = ApiError::internal("test error");
        assert!(error.to_string().contains("test error"));
    }

    #[test]
    fn test_api_error_configuration() {
        let error = ApiError::configuration("config error");
        assert!(error.to_string().contains("config error"));
    }

    #[test]
    fn test_app_state_creation() {
        let state = AppState::new();
        // This should not panic
        drop(state);
    }

    #[test]
    fn test_socket_addr_parsing() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(addr.port(), 8080);
        assert!(addr.ip().is_loopback());
    }
}
