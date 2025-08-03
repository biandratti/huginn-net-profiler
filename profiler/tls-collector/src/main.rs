use anyhow::Result;
use clap::Parser;
use huginn_net::{db::Database, fingerprint_result::FingerprintResult, HuginnNet};
use log::{error, info, warn};
use serde::Serialize;
use std::sync::mpsc as std_mpsc;
use tokio::signal;
use tokio::sync::mpsc as tokio_mpsc;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value = "wlp0s20f3")]
    interface: String,
    #[clap(
        short,
        long,
        value_parser,
        default_value = "http://localhost:8000/api/ingest/tls"
    )]
    assembler_endpoint: String,
}

#[derive(Serialize)]
struct TlsIngest {
    correlation_id: String,
    ja4: String,
}

fn spawn_channel_bridge(
    sync_rx: std_mpsc::Receiver<FingerprintResult>,
    async_tx: tokio_mpsc::Sender<FingerprintResult>,
) {
    std::thread::spawn(move || {
        for result in sync_rx.iter() {
            if async_tx.blocking_send(result).is_err() {
                error!("Failed to bridge event: async channel closed.");
                break;
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    info!("Starting TLS collector on interface {}", args.interface);

    let (sync_tx, sync_rx) = std_mpsc::channel();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    spawn_channel_bridge(sync_rx, async_tx);

    let interface = args.interface.clone();
    std::thread::spawn(move || {
        loop {
            info!("Starting new TLS analysis loop on interface {}...", interface);
            let db = Box::leak(Box::new(Database::default()));
            let mut huginn = HuginnNet::new(Some(db), 1024, None);

            if let Err(e) = huginn.analyze_network(&interface, sync_tx.clone()) {
                error!("Huginn-net (TLS) analysis failed: {}. Restarting in 5 seconds...", e);
            } else {
                info!("Huginn-net (TLS) analysis finished. Restarting in 5 seconds...");
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });

    let client = reqwest::Client::new();
    let assembler_endpoint = args.assembler_endpoint;

    let processing_task = tokio::spawn(async move {
        while let Some(result) = async_rx.recv().await {
            if let Some(tls_data) = result.tls_client {
                let tls_ingest = TlsIngest {
                    correlation_id: format!("{}:{}", tls_data.source.ip, tls_data.source.port),
                    ja4: tls_data.sig.ja4.full.value().to_string(),
                };
                send_tls_to_assembler(tls_ingest, &client, &assembler_endpoint).await;
            }
        }
    });
    
    info!("TLS collector is running. Press Ctrl+C to stop.");
    signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    info!("Ctrl+C received, shutting down.");
    
    processing_task.abort();
    Ok(())
}

async fn send_tls_to_assembler(data: TlsIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending TLS data for {}", data.correlation_id);
    match client.post(endpoint).json(&data).send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!("Successfully sent TLS data for {}.", data.correlation_id);
            } else {
                warn!(
                    "Failed to send TLS data for {}. Status: {}",
                    data.correlation_id,
                    response.status()
                );
            }
        }
        Err(e) => {
            error!("Error sending TLS data for {}: {:?}", data.correlation_id, e);
        }
    }
} 