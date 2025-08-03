use clap::Parser;
use huginn_net::{db::Database, fingerprint_result::FingerprintResult, HuginnNet};
use log::{error, info};
use serde::{Deserialize, Serialize};
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
        default_value = "http://profile-assembler:8000/api/ingest/tls"
    )]
    assembler_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TlsIngest {
    id: String,
    timestamp: u64,
    ja4_fingerprint: String,
    ja4_hash: String,
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
        let mut huginn = HuginnNet::new(Some(db), 1024, None);

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

                let ingest = TlsIngest {
                    id: format!("{}:{}", tls_data.source.ip, tls_data.source.port),
                    timestamp: now,
                    ja4_fingerprint: tls_data.sig.ja4.full.value().to_string(),
                    ja4_hash: tls_data.sig.ja4.ja4_a.to_string(),
                };
                send_tls_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
        }
    });
}

async fn send_tls_to_assembler(data: TlsIngest, client: &reqwest::Client, endpoint: &str) {
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