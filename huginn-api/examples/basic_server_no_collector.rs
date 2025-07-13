use huginn_api::server::{run_server_with_config, ApiServerConfig};
use huginn_collector::CollectorConfig;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create configuration without collector
    let collector_config = CollectorConfig::default();

    let config = ApiServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        interface: "wlp0s20f3".to_string(),
        enable_collector: false, // Disable collector for testing
        static_dir: Some("static".to_string()),
        enable_cors: true,
        collector_config,
    };

    tracing::info!("Starting Huginn API server (without network collector)...");
    tracing::info!("Server will be available at: http://127.0.0.1:3000");
    tracing::info!("API documentation: http://127.0.0.1:3000/api");
    tracing::info!("Available endpoints:");
    tracing::info!("  GET  http://127.0.0.1:3000/health");
    tracing::info!("  GET  http://127.0.0.1:3000/api");
    tracing::info!("  GET  http://127.0.0.1:3000/api/profiles");
    tracing::info!("  GET  http://127.0.0.1:3000/api/stats");

    // Run the server
    run_server_with_config(config).await?;

    Ok(())
}
