use huginn_api::server::{run_server_with_config, ApiServerConfig};
use huginn_collector::CollectorConfig;
use huginn_core::AnalyzerConfig;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let collector_config = CollectorConfig {
        interface: "wlp0s20f3".to_string(),
        buffer_size: 500,
        channel_buffer_size: 1000,
        analyzer: AnalyzerConfig {
            enable_tcp: true,
            enable_http: true,
            enable_tls: true,
            min_quality: 0.3,
        },
        ..CollectorConfig::default()
    };

    let config = ApiServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        interface: "wlp0s20f3".to_string(),
        enable_collector: true,
        static_dir: Some("static".to_string()),
        enable_cors: true,
        collector_config,
    };

    tracing::info!("Starting Huginn API server...");
    tracing::info!("Server will be available at: http://127.0.0.1:3000");
    tracing::info!("WebSocket endpoint: ws://127.0.0.1:3000/ws");
    tracing::info!("API documentation: http://127.0.0.1:3000/api");

    // Run the server
    run_server_with_config(config).await?;

    Ok(())
}
