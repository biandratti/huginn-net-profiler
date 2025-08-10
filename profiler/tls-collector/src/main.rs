use clap::Parser;
use huginn_net::{db::Database, fingerprint_result::FingerprintResult, AnalysisConfig, HuginnNet};
use log::{error, info};
use serde::Serialize;
use std::env;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub id: String,
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
    env_logger::init();
    let args = Args::parse();
    let interface = args.interface.unwrap_or_else(|| {
        env::var("PROFILER_INTERFACE").unwrap_or("wlp0s20f3".to_string())
    });
    let assembler_endpoint = args.assembler_endpoint;

    info!(
        "Booting tls-collector on interface {} pointed to {}",
        interface, assembler_endpoint
    );

    // Create a channel for sync communication (huginn-net to our bridge)
    let (sync_tx, sync_rx) = std_mpsc::channel::<FingerprintResult>();

    // Create a channel for async communication (our bridge to tokio tasks)
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    // Bridge the sync and async worlds
    thread::spawn(move || {
        while let Ok(item) = sync_rx.recv() {
            if async_tx.blocking_send(item).is_err() {
                error!("Failed to send fingerprint to async processor. Channel closed.");
                break;
            }
        }
    });

    // Start the network analysis in its own thread
    let analysis_interface = interface.clone();
    thread::spawn(move || loop {
        info!("Starting new TLS analysis loop on interface {}...", analysis_interface);
        let db = Box::leak(Box::new(Database::default()));
        let mut huginn = HuginnNet::new(Some(db), 1024, Some(AnalysisConfig{
            http_enabled: false,
            tcp_enabled: false,
            tls_enabled: true,
        }));

        if let Err(e) = huginn.analyze_network(&analysis_interface, sync_tx.clone()) {
            error!(
                "Huginn-net (TLS) analysis failed: {}. Restarting in 5 seconds...",
                e
            );
            thread::sleep(Duration::from_secs(5));
        } else {
            info!("TLS analysis loop finished cleanly. Restarting immediately.");
        }
    });

    // Create a tokio runtime to process results
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = reqwest::Client::new();
        info!("Starting TLS result processor...");

        while let Some(result) = async_rx.recv().await {
            if let Some(tls_data) = result.tls_client {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let ingest: TlsClient = TlsClient {
                    id: tls_data.source.ip.to_string(),
                    timestamp: now,
                    source: NetworkEndpoint { ip: tls_data.source.ip.to_string(), port: tls_data.source.port },
                    destination: NetworkEndpoint { ip: tls_data.destination.ip.to_string(), port: tls_data.destination.port },
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
        }
    });
}

async fn send_tls_to_assembler(data: TlsClient, client: &reqwest::Client, endpoint: &str) {
    info!("Sending TLS data for {}", data.id);
    match client.post(endpoint).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!(
                    "Failed to send TLS data for {}. Status: {}, Body: {:?}",
                    data.id,
                    response.status(),
                    response.text().await
                );
            }
        }
        Err(e) => {
            error!("Error sending TLS data for {}: {:?}", data.id, e);
        }
    }
} 