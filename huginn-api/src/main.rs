use huginn_api::server::run_server;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Run the server with command line arguments
    if let Err(e) = run_server().await {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}
