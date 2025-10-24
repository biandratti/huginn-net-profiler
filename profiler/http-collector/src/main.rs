use clap::Parser;
use huginn_net_db::{Database, MatchQualityType};
use huginn_net_http::http_common::HttpHeader;
use huginn_net_http::{HttpAnalysisResult, HuginnNetHttp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrowserDetection {
    pub browser: String,
    pub quality: f32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpRequestObserved {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub diagnostic: String,
    pub method: Option<String>,
    pub version: String,
    pub headers: String,
    pub cookies: String,
    pub referer: Option<String>,
    pub uri: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpRequestData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub observed: HttpRequestObserved,
    pub signature: String,
    pub browser: BrowserDetection,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebServerDetection {
    pub web_server: String,
    pub quality: f32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpResponseObserved {
    pub server: Option<String>,
    pub version: String,
    pub headers: String,
    pub status_code: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpResponseData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub observed: HttpResponseObserved,
    pub signature: String,
    pub web_server: WebServerDetection,
    pub timestamp: u64,
}

type HttpRequestIngest = HttpRequestData;
type HttpResponseIngest = HttpResponseData;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnectionKey {
    source_ip: String,
    source_port: u16,
    dest_ip: String,
    dest_port: u16,
}

#[derive(Debug, Clone)]
struct ConnectionInfo {
    real_ip: String,
    timestamp: std::time::Instant,
}

type ConnectionMap = Arc<Mutex<HashMap<ConnectionKey, ConnectionInfo>>>;

const MAX_CONNECTIONS: usize = 100;

fn extract_client_ip_from_headers(headers: &[HttpHeader], fallback_ip: &str) -> String {
    headers
        .iter()
        .find(|h| {
            let header_name = h.name.to_lowercase();
            header_name == "x-real-ip"
                || header_name == "x-forwarded-for"
                || header_name == "x-client-ip"
        })
        .and_then(|h| h.value.as_ref())
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
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let args = Args::parse();
    let interface = args
        .interface
        .unwrap_or_else(|| env::var("PROFILER_INTERFACE").unwrap_or("wlp0s20f3".to_string()));
    let assembler_endpoint = args.assembler_endpoint;

    info!("Booting http-collector on interface {interface} pointed to {assembler_endpoint}");

    let (sender, receiver): (Sender<HttpAnalysisResult>, Receiver<HttpAnalysisResult>) =
        mpsc::channel();

    let cancel_signal = Arc::new(AtomicBool::new(false));
    let ctrl_c_signal = cancel_signal.clone();
    let thread_cancel_signal = cancel_signal.clone();

    if let Err(e) = ctrlc::set_handler(move || {
        info!("Received signal, initiating graceful shutdown...");
        ctrl_c_signal.store(true, Ordering::Relaxed);
    }) {
        error!("Error setting signal handler: {e}");
        return;
    }

    let analysis_interface = interface.clone();
    thread::spawn(move || {
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                error!("Failed to load default database: {}", e);
                return;
            }
        };
        debug!("Loaded database: {:?}", db);

        let mut analyzer = match HuginnNetHttp::new(Some(&db), 1000) {
            Ok(analyzer) => analyzer,
            Err(e) => {
                error!("Failed to create HuginnNetHttp analyzer: {}", e);
                return;
            }
        };

        info!(
            "Starting HTTP live capture on interface: {}",
            analysis_interface
        );
        if let Err(e) =
            analyzer.analyze_network(&analysis_interface, sender, Some(thread_cancel_signal))
        {
            error!("HTTP analysis failed: {e}");
        }
    });

    // Health check endpoint
    thread::spawn(|| {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};

        fn handle_health_request(mut stream: TcpStream) {
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            let _ = stream.write_all(response.as_bytes());
        }

        if let Ok(listener) = TcpListener::bind("0.0.0.0:9001") {
            for stream in listener.incoming().flatten() {
                handle_health_request(stream);
            }
        }
    });

    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);
    let connection_map: ConnectionMap = Arc::new(Mutex::new(HashMap::new()));

    // Bridge thread to move from sync to async
    thread::spawn(move || {
        while let Ok(item) = receiver.recv() {
            if cancel_signal.load(Ordering::Relaxed) {
                info!("Shutdown signal received in bridge thread");
                break;
            }
            if async_tx.blocking_send(item).is_err() {
                error!("Failed to send data to async processor. Channel closed.");
                break;
            }
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

            if let Some(http_request) = result.http_request {
                let real_client_ip = extract_client_ip_from_headers(
                    &http_request.sig.headers,
                    &http_request.source.ip.to_string(),
                );

                // Store connection mapping for responses
                let conn_key = ConnectionKey {
                    source_ip: http_request.source.ip.to_string(),
                    source_port: http_request.source.port,
                    dest_ip: http_request.destination.ip.to_string(),
                    dest_port: http_request.destination.port,
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
                        port: http_request.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: http_request.destination.ip.to_string(),
                        port: http_request.destination.port,
                    },
                    signature: http_request.sig.to_string(),
                    observed: HttpRequestObserved {
                        user_agent: http_request.sig.user_agent,
                        lang: http_request.lang,
                        diagnostic: http_request.diagnosis.to_string(),
                        method: http_request.sig.method,
                        uri: http_request.sig.uri,
                        version: http_request.sig.matching.version.to_string(),
                        headers: http_request
                            .sig
                            .headers
                            .iter()
                            .map(|header| {
                                format!(
                                    "{}: {}",
                                    header.name,
                                    header.value.as_deref().unwrap_or("")
                                )
                            })
                            .collect::<Vec<String>>()
                            .join(", "),
                        cookies: http_request
                            .sig
                            .cookies
                            .iter()
                            .map(|cookie| {
                                format!(
                                    "{}: {}",
                                    cookie.name,
                                    cookie.value.as_deref().unwrap_or("")
                                )
                            })
                            .collect::<Vec<String>>()
                            .join(", "),
                        referer: http_request.sig.referer,
                    },
                    browser: http_request
                        .browser_matched
                        .browser
                        .as_ref()
                        .map(|m| BrowserDetection {
                            browser: format!(
                                "{}/{}/{}",
                                m.name,
                                m.family.as_deref().unwrap_or("???"),
                                m.variant.as_deref().unwrap_or("???")
                            ),
                            quality: match http_request.browser_matched.quality {
                                MatchQualityType::Matched(score) => score,
                                MatchQualityType::NotMatched => 0.0,
                                MatchQualityType::Disabled => 0.0,
                            },
                        })
                        .unwrap_or_else(|| BrowserDetection {
                            browser: "unknown".to_string(),
                            quality: 0.0,
                        }),
                    timestamp: now,
                };
                send_http_request_to_assembler(ingest, &client, &assembler_endpoint).await;
            }

            if let Some(http_response) = result.http_response {
                let conn_key = ConnectionKey {
                    source_ip: http_response.destination.ip.to_string(),
                    source_port: http_response.destination.port,
                    dest_ip: http_response.source.ip.to_string(),
                    dest_port: http_response.source.port,
                };

                let real_client_ip = if let Ok(map) = connection_map.lock() {
                    map.get(&conn_key)
                        .map(|info| info.real_ip.clone())
                        .unwrap_or_else(|| http_response.destination.ip.to_string())
                } else {
                    http_response.destination.ip.to_string()
                };

                let ingest = HttpResponseIngest {
                    source: NetworkEndpoint {
                        ip: http_response.source.ip.to_string(),
                        port: http_response.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: real_client_ip,
                        port: http_response.destination.port,
                    },
                    observed: HttpResponseObserved {
                        server: http_response
                            .sig
                            .headers
                            .iter()
                            .find(|h| h.name.to_lowercase() == "server")
                            .and_then(|h| h.value.as_ref().cloned()),
                        version: http_response.sig.matching.version.to_string(),
                        headers: http_response
                            .sig
                            .headers
                            .iter()
                            .map(|header| {
                                format!(
                                    "{}: {}",
                                    header.name,
                                    header.value.as_deref().unwrap_or("")
                                )
                            })
                            .collect::<Vec<String>>()
                            .join(", "),
                        status_code: http_response.sig.status_code,
                    },
                    signature: http_response.sig.to_string(),
                    web_server: http_response
                        .web_server_matched
                        .web_server
                        .as_ref()
                        .map(|m| WebServerDetection {
                            web_server: format!(
                                "{}/{}/{}",
                                m.name,
                                m.family.as_deref().unwrap_or("???"),
                                m.variant.as_deref().unwrap_or("???")
                            ),
                            quality: match http_response.web_server_matched.quality {
                                MatchQualityType::Matched(score) => score,
                                MatchQualityType::NotMatched => 0.0,
                                MatchQualityType::Disabled => 0.0,
                            },
                        })
                        .unwrap_or_else(|| WebServerDetection {
                            web_server: "unknown".to_string(),
                            quality: 0.0,
                        }),
                    timestamp: now,
                };
                send_http_response_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
        }
    });

    info!("Analysis shutdown completed");
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
