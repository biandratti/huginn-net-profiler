use clap::Parser;
use huginn_net::AnalysisConfig;

use huginn_net::{db::Database, fingerprint_result::FingerprintResult, HuginnNet};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
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

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpRequestData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub accept: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub connection: Option<String>,
    pub host: Option<String>,
    pub signature: String,
    pub quality: f64,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpResponseData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    pub set_cookie: Option<String>,
    pub cache_control: Option<String>,
    pub signature: String,
    pub quality: f64,
    pub timestamp: u64,
}

type HttpRequestIngest = HttpRequestData;
type HttpResponseIngest = HttpResponseData;

fn extract_header_value_from_horder(horder: &[String], header_name: &str) -> Option<String> {
    for header in horder {
        if let Some(eq_pos) = header.find('=') {
            let (name, value_part) = header.split_at(eq_pos);
            if name.to_lowercase() == header_name.to_lowercase() {
                let value_part = &value_part[1..];
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

// TODO: This is a hack to get the client IP from the raw headers.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnectionKey {
    source_ip: String,
    source_port: u16,
    dest_ip: String,
    dest_port: u16,
}

const MAX_CONNECTIONS: usize = 100;

#[derive(Debug, Clone)]
struct ConnectionInfo {
    real_ip: String,
    timestamp: std::time::Instant,
}

type ConnectionMap = Arc<Mutex<HashMap<ConnectionKey, ConnectionInfo>>>;

fn extract_client_ip_from_raw_headers(
    raw_headers: &std::collections::HashMap<String, String>,
    fallback_ip: &str,
) -> String {
    raw_headers
        .get("x-real-ip")
        .or_else(|| raw_headers.get("X-Real-IP"))
        .or_else(|| raw_headers.get("X-Real-Ip"))
        .cloned()
        .unwrap_or_else(|| fallback_ip.to_string())
}

fn enforce_connection_limit(connection_map: &ConnectionMap) {
    let mut map = connection_map.lock().unwrap();
    if map.len() <= MAX_CONNECTIONS {
        return;
    }

    let mut connections: Vec<(ConnectionKey, std::time::Instant)> = map
        .iter()
        .map(|(key, info)| (key.clone(), info.timestamp))
        .collect();

    connections.sort_by(|a, b| a.1.cmp(&b.1));

    let to_remove = map.len() - MAX_CONNECTIONS;
    for (key, _) in connections.iter().take(to_remove) {
        map.remove(key);
    }
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let interface = args
        .interface
        .unwrap_or_else(|| env::var("PROFILER_INTERFACE").unwrap_or("wlp0s20f3".to_string()));
    let assembler_endpoint = args.assembler_endpoint;

    info!("Booting http-collector on interface {interface} pointed to {assembler_endpoint}");

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
        info!("Starting new HTTP analysis loop on interface {analysis_interface}...");
        let db = Box::leak(Box::new(Database::default()));
        let mut huginn = HuginnNet::new(
            Some(db),
            1024,
            Some(AnalysisConfig {
                http_enabled: true,
                tcp_enabled: false,
                tls_enabled: false,
            }),
        );

        if let Err(e) = huginn.analyze_network(&analysis_interface, sync_tx.clone()) {
            error!("Huginn-net (HTTP) analysis failed: {e}. Restarting in 5 seconds...");
            thread::sleep(Duration::from_secs(5));
        } else {
            info!("HTTP analysis loop finished cleanly. Restarting immediately.");
        }
    });

    let connection_map: ConnectionMap = Arc::new(Mutex::new(HashMap::new()));

    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = reqwest::Client::new();
        info!("Starting HTTP result processor...");

        while let Some(result) = async_rx.recv().await {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if let Some(http_req) = result.http_request {
                let horder_strings: Vec<String> =
                    http_req.sig.horder.iter().map(|h| h.to_string()).collect();

                let real_client_ip = extract_client_ip_from_raw_headers(
                    &http_req.sig.raw_headers,
                    &http_req.source.ip.to_string(),
                );

                // Store connection mapping for responses
                let conn_key = ConnectionKey {
                    source_ip: http_req.source.ip.to_string(),
                    source_port: http_req.source.port,
                    dest_ip: http_req.destination.ip.to_string(),
                    dest_port: http_req.destination.port,
                };

                if let Ok(mut map) = connection_map.lock() {
                    map.insert(
                        conn_key,
                        ConnectionInfo {
                            real_ip: real_client_ip.clone(),
                            timestamp: std::time::Instant::now(),
                        },
                    );
                }
                enforce_connection_limit(&connection_map);

                let ingest = HttpRequestIngest {
                    source: NetworkEndpoint {
                        ip: real_client_ip,
                        port: http_req.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: http_req.destination.ip.to_string(),
                        port: http_req.destination.port,
                    },
                    user_agent: http_req.sig.user_agent.clone(),
                    lang: extract_header_value_from_horder(&horder_strings, "accept-language"),
                    accept: extract_header_value_from_horder(&horder_strings, "accept"),
                    accept_language: extract_header_value_from_horder(
                        &horder_strings,
                        "accept-language",
                    ),
                    accept_encoding: extract_header_value_from_horder(
                        &horder_strings,
                        "accept-encoding",
                    ),
                    connection: extract_header_value_from_horder(&horder_strings, "connection"),
                    host: extract_header_value_from_horder(&horder_strings, "host"),
                    signature: http_req.sig.to_string(),
                    quality: http_req
                        .browser_matched
                        .as_ref()
                        .map(|m| m.quality as f64)
                        .unwrap_or(0.0),
                    timestamp: now,
                };
                send_http_request_to_assembler(ingest, &client, &assembler_endpoint).await;
            }

            if let Some(http_res) = result.http_response {
                let horder_strings: Vec<String> =
                    http_res.sig.horder.iter().map(|h| h.to_string()).collect();

                let conn_key = ConnectionKey {
                    source_ip: http_res.destination.ip.to_string(),
                    source_port: http_res.destination.port,
                    dest_ip: http_res.source.ip.to_string(),
                    dest_port: http_res.source.port,
                };

                let real_client_ip = if let Ok(map) = connection_map.lock() {
                    map.get(&conn_key)
                        .map(|info| info.real_ip.clone())
                        .unwrap_or_else(|| http_res.destination.ip.to_string())
                } else {
                    http_res.destination.ip.to_string()
                };

                let ingest = HttpResponseIngest {
                    source: NetworkEndpoint {
                        ip: http_res.source.ip.to_string(),
                        port: http_res.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: real_client_ip,
                        port: http_res.destination.port,
                    },
                    server: extract_header_value_from_horder(&horder_strings, "server"),
                    content_type: extract_header_value_from_horder(&horder_strings, "content-type"),
                    content_length: extract_header_value_from_horder(
                        &horder_strings,
                        "content-length",
                    ),
                    set_cookie: extract_header_value_from_horder(&horder_strings, "set-cookie"),
                    cache_control: extract_header_value_from_horder(
                        &horder_strings,
                        "cache-control",
                    ),
                    signature: http_res.sig.to_string(),
                    quality: http_res
                        .web_server_matched
                        .as_ref()
                        .map(|m| m.quality as f64)
                        .unwrap_or(0.0),
                    timestamp: now,
                };
                send_http_response_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
        }
    });
}

async fn send_http_request_to_assembler(
    data: HttpRequestIngest,
    client: &reqwest::Client,
    endpoint: &str,
) {
    info!(
        "Sending HTTP request data for {}:{}",
        data.source.ip, data.source.port
    );
    let url = format!("{endpoint}/http_request");
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!(
                    "Failed to send HTTP request data, status: {}",
                    response.status()
                );
            }
        }
        Err(e) => error!("Failed to send HTTP request data: {e}"),
    }
}

async fn send_http_response_to_assembler(
    data: HttpResponseIngest,
    client: &reqwest::Client,
    endpoint: &str,
) {
    info!(
        "Sending HTTP response data for {}:{} -> {}:{}",
        data.source.ip, data.source.port, data.destination.ip, data.destination.port
    );
    let url = format!("{endpoint}/http_response");
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!(
                    "Failed to send HTTP response data, status: {}",
                    response.status()
                );
            }
        }
        Err(e) => error!("Failed to send HTTP response data: {e}"),
    }
}
