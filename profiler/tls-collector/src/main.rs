use clap::Parser;
use huginn_net_tls::{HuginnNetTls, TlsClientOutput};
use serde::Serialize;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{error, info, Level};
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
        default_value = "http://localhost:8000/api/ingest/tls"
    )]
    assembler_endpoint: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct TlsClient {
    pub timestamp: u64,
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub ja4: String,
    pub ja4_raw: String,
    pub ja4_original: String,
    pub ja4_original_raw: String,
    pub observed: TlsClientObserved,
}

#[derive(Serialize, Clone, Debug)]
pub struct TlsClientObserved {
    pub version: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

#[derive(Serialize, Clone, Debug)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
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

    info!("Booting tls-collector on interface {interface} pointed to {assembler_endpoint}");

    let cancel_signal = Arc::new(AtomicBool::new(false));
    let ctrl_c_signal = cancel_signal.clone();
    let processing_cancel_signal = cancel_signal.clone();

    if let Err(e) = ctrlc::set_handler(move || {
        info!("Received shutdown signal, initiating graceful shutdown...");
        ctrl_c_signal.store(true, Ordering::Relaxed);
    }) {
        error!("Error setting signal handler: {e}");
        return;
    }

    let (sync_tx, sync_rx) = std_mpsc::channel::<TlsClientOutput>();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);
    
    thread::spawn(move || {
        while let Ok(item) = sync_rx.recv() {
            if processing_cancel_signal.load(Ordering::Relaxed) {
                info!("Shutdown signal received, stopping sync-to-async bridge");
                break;
            }
            if async_tx.blocking_send(item).is_err() {
                error!("Failed to send fingerprint to async processor. Channel closed.");
                break;
            }
        }
    });

    let analysis_interface = interface.clone();
    let analysis_cancel_signal = cancel_signal.clone();
    
    thread::spawn(move || {
        info!("Starting TLS analysis on interface {analysis_interface}...");
        let mut tls_analyzer = HuginnNetTls::new();

        if let Err(e) = tls_analyzer.analyze_network(&analysis_interface, sync_tx, Some(analysis_cancel_signal)) {
            error!("Huginn-net-tls analysis failed: {e}");
        } else {
            info!("TLS analysis finished cleanly.");
        }
    });

    thread::spawn(|| {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};

        fn handle_health_request(mut stream: TcpStream) {
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            let _ = stream.write_all(response.as_bytes());
        }

        if let Ok(listener) = TcpListener::bind("0.0.0.0:9003") {
            for stream in listener.incoming().flatten() {
                handle_health_request(stream);
            }
        }
    });

    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = reqwest::Client::new();
        info!("Starting TLS result processor...");

        while let Some(tls_data) = async_rx.recv().await {
            if cancel_signal.load(Ordering::Relaxed) {
                info!("Shutdown signal received, stopping result processing");
                break;
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let ingest: TlsClient = TlsClient {
                timestamp: now,
                source: NetworkEndpoint {
                    ip: tls_data.source.ip.to_string(),
                    port: tls_data.source.port,
                },
                destination: NetworkEndpoint {
                    ip: tls_data.destination.ip.to_string(),
                    port: tls_data.destination.port,
                },
                ja4: tls_data.sig.ja4.full.value().to_string(),
                ja4_raw: tls_data.sig.ja4.raw.value().to_string(),
                ja4_original: tls_data.sig.ja4_original.full.value().to_string(),
                ja4_original_raw: tls_data.sig.ja4_original.raw.value().to_string(),
                observed: TlsClientObserved {
                    version: tls_data.sig.version.to_string(),
                    sni: tls_data.sig.sni.as_ref().map(|s| s.to_string()),
                    alpn: tls_data.sig.alpn.as_ref().map(|s| s.to_string()),
                    cipher_suites: tls_data.sig.cipher_suites.clone(),
                    extensions: tls_data.sig.extensions.clone(),
                    signature_algorithms: tls_data.sig.signature_algorithms.clone(),
                    elliptic_curves: tls_data.sig.elliptic_curves.clone(),
                },
            };
            send_tls_to_assembler(ingest, &client, &assembler_endpoint).await;
        }
        
        info!("TLS collector shutdown completed");
    });
}

async fn send_tls_to_assembler(data: TlsClient, client: &reqwest::Client, endpoint: &str) {
    info!("Sending TLS data for {}", data.source.ip);
    match client.post(endpoint).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!(
                    "Failed to send TLS data for {}. Status: {}, Body: {:?}",
                    data.source.ip,
                    response.status(),
                    response.text().await
                );
            }
        }
        Err(e) => {
            error!("Error sending TLS data for {}: {:?}", data.source.ip, e);
        }
    }
}
