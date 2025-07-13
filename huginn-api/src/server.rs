use crate::{
    error::{ApiError, Result},
    handlers::*,
    state::AppState,
    // websocket::websocket_handler,
};
use axum::{routing::get, Router};
use clap::Parser;
use huginn_collector::{CollectorConfig, NetworkCollector};
use std::net::SocketAddr;
// use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{debug, error, info, warn};

/// Configuration for the API server
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// Server bind address
    pub bind_addr: SocketAddr,
    /// Network interface to monitor
    pub interface: String,
    /// Enable collector (if false, only serves static profiles)
    pub enable_collector: bool,
    /// Static files directory
    pub static_dir: Option<String>,
    /// Enable CORS
    pub enable_cors: bool,
    /// Collector configuration
    pub collector_config: CollectorConfig,
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
            interface: "eth0".to_string(),
            enable_collector: true,
            static_dir: Some("static".to_string()),
            enable_cors: true,
            collector_config: CollectorConfig::default(),
        }
    }
}

/// Command-line arguments for the API server
#[derive(Parser, Debug)]
#[command(name = "huginn-api")]
#[command(about = "Huginn Network Profiler API Server")]
pub struct ApiServerArgs {
    /// Network interface to monitor
    #[arg(short = 'i', long, default_value = "eth0")]
    pub interface: String,

    /// Server bind address
    #[arg(short = 'b', long, default_value = "127.0.0.1:3000")]
    pub bind: String,

    /// Disable network collector (serve static profiles only)
    #[arg(long)]
    pub no_collector: bool,

    /// Static files directory
    #[arg(long, default_value = "static")]
    pub static_dir: String,

    /// Disable CORS
    #[arg(long)]
    pub no_cors: bool,

    /// Enable TCP analysis
    #[arg(long, default_value = "true")]
    pub enable_tcp: bool,

    /// Enable HTTP analysis
    #[arg(long, default_value = "true")]
    pub enable_http: bool,

    /// Enable TLS analysis
    #[arg(long, default_value = "true")]
    pub enable_tls: bool,

    /// Quality threshold for analysis results
    #[arg(long, default_value = "0.5")]
    pub quality_threshold: f64,

    /// Buffer size for profile processing
    #[arg(long, default_value = "1000")]
    pub buffer_size: usize,
}

impl From<ApiServerArgs> for ApiServerConfig {
    fn from(args: ApiServerArgs) -> Self {
        let bind_addr = args
            .bind
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 3000)));

        let collector_config = CollectorConfig {
            interface: args.interface.clone(),
            buffer_size: args.buffer_size,
            channel_buffer_size: args.buffer_size,
            analyzer: huginn_core::AnalyzerConfig {
                enable_tcp: args.enable_tcp,
                enable_http: args.enable_http,
                enable_tls: args.enable_tls,
                min_quality: args.quality_threshold,
            },
            ..CollectorConfig::default()
        };

        Self {
            bind_addr,
            interface: args.interface,
            enable_collector: !args.no_collector,
            static_dir: if args.static_dir.is_empty() {
                None
            } else {
                Some(args.static_dir)
            },
            enable_cors: !args.no_cors,
            collector_config,
        }
    }
}

/// Main API server
pub struct ApiServer {
    config: ApiServerConfig,
    state: AppState,
}

impl ApiServer {
    /// Create a new API server with configuration
    pub fn new(config: ApiServerConfig) -> Self {
        let state = AppState::new();

        Self { config, state }
    }

    /// Create API server from command line arguments
    pub fn from_args(args: ApiServerArgs) -> Self {
        let config = ApiServerConfig::from(args);
        Self::new(config)
    }

    /// Start the API server
    pub async fn start(mut self) -> Result<()> {
        info!("Starting Huginn API server on {}", self.config.bind_addr);

        // Start network collector if enabled
        if self.config.enable_collector {
            info!(
                "Starting network collector on interface: {}",
                self.config.interface
            );

            match self.start_collector().await {
                Ok(()) => info!("Network collector started successfully"),
                Err(e) => {
                    error!("Failed to start network collector: {}", e);
                    warn!("Continuing without network collector");
                }
            }
        } else {
            info!("Network collector disabled");
        }

        // Build the router
        let app = self.build_router();

        // Start the server
        let listener = tokio::net::TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| {
                ApiError::configuration(format!(
                    "Failed to bind to {}: {}",
                    self.config.bind_addr, e
                ))
            })?;

        info!("Huginn API server listening on {}", self.config.bind_addr);
        info!(
            "API documentation available at: http://{}/api",
            self.config.bind_addr
        );
        info!(
            "WebSocket endpoint available at: ws://{}/ws",
            self.config.bind_addr
        );

        axum::serve(listener, app)
            .await
            .map_err(|e| ApiError::internal(format!("Server error: {e}")))?;

        Ok(())
    }

    /// Start the network collector
    async fn start_collector(&mut self) -> Result<()> {
        let collector = NetworkCollector::new(self.config.collector_config.clone())?;

        // Start the collector
        let collector_handle = collector.start()?;

        // Update state with collector handle
        self.state = AppState::with_collector(collector_handle);

        // Start profile polling task
        let state_clone = self.state.clone();
        let collector_handle_clone = self.state.collector_handle.as_ref().unwrap().clone();

        tokio::spawn(async move {
            info!("Starting profile polling task");

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

            loop {
                interval.tick().await;

                // Check if collector is still running
                if !collector_handle_clone.is_running() {
                    warn!("Collector stopped, ending profile polling");
                    break;
                }

                // Get profiles from the collector
                match collector_handle_clone.get_profiles().await {
                    Ok(profiles) => {
                        if !profiles.is_empty() {
                            debug!("Retrieved {} profiles from collector", profiles.len());
                            state_clone.update_profiles(profiles);
                        } else {
                            debug!("No profiles available from collector");
                        }
                    }
                    Err(e) => {
                        error!("Failed to get profiles from collector: {}", e);
                    }
                }
            }

            warn!("Profile polling task ended");
        });

        Ok(())
    }

    /// Build the Axum router
    fn build_router(&self) -> Router {
        let mut router = Router::new()
            // Health check
            .route("/health", get(health))
            // API endpoints
            .route("/api", get(api_info))
            .route("/api/profiles", get(get_profiles).delete(clear_profiles))
            .route(
                "/api/profiles/{key}",
                get(get_profile).delete(delete_profile),
            )
            .route("/api/stats", get(get_stats))
            .route("/api/search", get(search_profiles))
            // WebSocket endpoint (temporarily disabled)
            // .route("/ws", get(websocket_handler))
            // Add state
            .with_state(self.state.clone());

        // Add middleware layers
        router = router.layer(TraceLayer::new_for_http());

        // Add CORS if enabled
        if self.config.enable_cors {
            router = router.layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any),
            );
        }

        // Add static file serving if configured
        if let Some(static_dir) = &self.config.static_dir {
            router = router.fallback_service(ServeDir::new(static_dir));
        }

        router
    }
}

/// Run the API server with command line arguments
pub async fn run_server() -> Result<()> {
    let args = ApiServerArgs::parse();
    let server = ApiServer::from_args(args);
    server.start().await
}

/// Run the API server with custom configuration
pub async fn run_server_with_config(config: ApiServerConfig) -> Result<()> {
    let server = ApiServer::new(config);
    server.start().await
}
