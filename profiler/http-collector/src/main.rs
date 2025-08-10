use clap::Parser;
use huginn_net::AnalysisConfig;

use huginn_net::{db::Database, fingerprint_result::FingerprintResult, HuginnNet};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    interface: Option<String>,
    #[clap(
        short,
        long,
        value_parser,
        default_value = "http://localhost:8000/api/ingest"
    )]
    assembler_endpoint: String,
}

// HTTP structures
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
}

/// HTTP request data (from client)
#[derive(Serialize, Deserialize, Debug)]
pub struct HttpRequestData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub user_agent: Option<String>,
    pub accept: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub connection: Option<String>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub signature: String,
    pub quality: f64,
    pub timestamp: u64,
}

/// HTTP response data (from server)
#[derive(Serialize, Deserialize, Debug)]
pub struct HttpResponseData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    pub set_cookie: Option<String>,
    pub cache_control: Option<String>,
    pub status: Option<String>,
    pub signature: String,
    pub quality: f64,
    pub timestamp: u64,
}

// Different types for different HTTP data
type HttpRequestIngest = HttpRequestData;
type HttpResponseIngest = HttpResponseData;

fn main() {
    env_logger::init();
    let args = Args::parse();
    let interface = args
        .interface
        .unwrap_or_else(|| env::var("PROFILER_INTERFACE").unwrap_or("wlp0s20f3".to_string()));
    let assembler_endpoint = args.assembler_endpoint;

    info!(
        "Booting http-collector on interface {} pointed to {}",
        interface, assembler_endpoint
    );

    let (sync_tx, sync_rx) = std_mpsc::channel::<FingerprintResult>();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    thread::spawn(move || {
        while let Ok(item) = sync_rx.recv() {
            if async_tx.blocking_send(item).is_err() {
                error!("Failed to send fingerprint to async processor. Channel closed.");
                break;
            }
        }
    });

    let analysis_interface = interface.clone();
    thread::spawn(move || loop {
        info!("Starting new HTTP analysis loop on interface {}...", analysis_interface);
        let db = Box::leak(Box::new(Database::default()));
        let mut huginn = HuginnNet::new(Some(db), 1024, Some(AnalysisConfig{
            http_enabled: true,
            tcp_enabled: false,
            tls_enabled: false,
        }));

        if let Err(e) = huginn.analyze_network(&analysis_interface, sync_tx.clone()) {
            error!(
                "Huginn-net (HTTP) analysis failed: {}. Restarting in 5 seconds...",
                e
            );
            thread::sleep(Duration::from_secs(5));
        } else {
            info!("HTTP analysis loop finished cleanly. Restarting immediately.");
        }
    });

    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = reqwest::Client::new();
        info!("Starting HTTP result processor...");

        while let Some(result) = async_rx.recv().await {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();


            // Process HTTP requests (client data)
            if let Some(http_req) = result.http_request {
                let ingest = HttpRequestIngest {
                    source: NetworkEndpoint {
                        ip: http_req.source.ip.to_string(),
                        port: http_req.source.port,
                    },
                    destination: NetworkEndpoint { ip: http_req.destination.ip.to_string(), port: http_req.destination.port },
                    user_agent: None, // Would need to extract from signature
                    accept: None,
                    accept_language: None,
                    accept_encoding: None,
                    connection: None,
                    method: Some("GET".to_string()), // Default
                    host: None,
                    signature: http_req.sig.to_string(),
                    quality: http_req.browser_matched.as_ref().map(|m| m.quality as f64).unwrap_or(0.0),
                    timestamp: now,
                };
                send_http_request_to_assembler(ingest, &client, &assembler_endpoint).await;
            }

            // Process HTTP responses (server data)
            if let Some(http_res) = result.http_response {
                let ingest = HttpResponseIngest {
                    source: NetworkEndpoint {
                        ip: http_res.source.ip.to_string(),
                        port: http_res.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: http_res.destination.ip.to_string(),
                        port: http_res.destination.port,
                    },
                    server: None, // Would need to extract from signature
                    content_type: None,
                    content_length: None,
                    set_cookie: None,
                    cache_control: None,
                    status: Some("200".to_string()), // Default
                    signature: http_res.sig.to_string(),
                    quality: http_res.web_server_matched.as_ref().map(|m| m.quality as f64).unwrap_or(0.0),
                    timestamp: now,
                };
                send_http_response_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
        }
    });
}



async fn send_http_request_to_assembler(data: HttpRequestIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending HTTP request data for {}:{}", data.source.ip, data.source.port);
    let url = format!("{}/http_request", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!("Failed to send HTTP request data, status: {}", response.status());
            }
        }
        Err(e) => error!("Failed to send HTTP request data: {}", e),
    }
}

async fn send_http_response_to_assembler(data: HttpResponseIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending HTTP response data for {}:{} -> {}:{}", 
          data.source.ip, data.source.port, data.destination.ip, data.destination.port);
    let url = format!("{}/http_response", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!("Failed to send HTTP response data, status: {}", response.status());
            }
        }
        Err(e) => error!("Failed to send HTTP response data: {}", e),
    }
}
