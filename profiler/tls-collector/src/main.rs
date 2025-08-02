use huginn_net::{
    db::Database,
    fingerprint_result::FingerprintResult,
    HuginnNet,
};
use log::{error, info};
use reqwest::Client;
use serde::Serialize;
use std::env;
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::signal;

#[derive(Serialize)]
struct TlsIngest {
    correlation_id: String,
    ja4_fingerprint: String,
}

#[derive(Clone)]
struct Config {
    assembler_endpoint: String,
    http_client: Client,
}

/// Bridges events from a standard sync MPSC channel to a Tokio async Mpsc channel.
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
async fn main() {
    env_logger::init();

    let config = Config {
        assembler_endpoint: env::var("ASSEMBLER_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:8000/api/ingest/tls".to_string()),
        http_client: Client::new(),
    };
    
    let interface = env::var("INTERFACE_NAME").unwrap_or_else(|_| "any".to_string());
    
    info!("Starting TLS collector on interface: {}", interface);

    let (sync_tx, sync_rx) = std_mpsc::channel();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    spawn_channel_bridge(sync_rx, async_tx);

    std::thread::spawn(move || {
        loop {
            info!("Starting new TLS analysis loop...");
            let db = Box::leak(Box::new(Database::default()));
            let mut huginn = HuginnNet::new(Some(db), 1024, None);

            if let Err(e) = huginn.analyze_network(&interface, sync_tx.clone()) {
                error!("Huginn-net (TLS) analysis failed: {}. Restarting in 5 seconds...", e);
            } else {
                info!("Huginn-net (TLS) analysis finished without error. Restarting in 5 seconds...");
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });

    let processing_task = tokio::spawn(async move {
        while let Some(result) = async_rx.recv().await {
            if let Some(tls_data) = result.tls_client {
                let tls_info = TlsIngest {
                    correlation_id: format!("{}:{}", tls_data.source.ip, tls_data.source.port),
                    ja4_fingerprint: tls_data.sig.ja4.full.value().to_string(),
                };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = send_to_assembler(tls_info, &config).await {
                        error!("Error sending TLS info to assembler: {}", e);
                    }
                });
            }
        }
    });

    info!("TLS collector is running. Press Ctrl+C to stop.");
    signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    info!("Ctrl+C received, shutting down.");

    processing_task.abort();
}

async fn send_to_assembler(data: TlsIngest, config: &Config) -> Result<(), String> {
    let res = config.http_client.post(&config.assembler_endpoint)
        .json(&data)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        info!("Successfully sent TLS info for {}", data.correlation_id);
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        error!(
            "Failed to send TLS info. Status: {}. Body: {}",
            status, text
        );
    }

    Ok(())
} 