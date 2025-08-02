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
struct TcpSignature {
    source_ip: String,
    signature: String,
}

#[derive(Serialize)]
struct HttpSignature {
    source_ip_port: String,
    signature: String,
}

#[derive(Clone)]
struct Config {
    assembler_endpoint_tcp: String,
    assembler_endpoint_http: String,
    http_client: Client,
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
async fn main() {
    env_logger::init();

    let assembler_base = env::var("ASSEMBLER_ENDPOINT")
        .unwrap_or_else(|_| "http://host.docker.internal:8000/api/ingest".to_string());
    
    let config = Config {
        assembler_endpoint_tcp: format!("{}/tcp", assembler_base),
        assembler_endpoint_http: format!("{}/http", assembler_base),
        http_client: Client::new(),
    };
    
    let interface = env::var("INTERFACE_NAME").unwrap_or_else(|_| "any".to_string());
    
    info!("Starting HTTP/TCP collector on interface: {}", interface);

    let (sync_tx, sync_rx) = std_mpsc::channel();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    spawn_channel_bridge(sync_rx, async_tx);

    std::thread::spawn(move || {
        loop {
            info!("Starting new HTTP/TCP analysis loop...");
            let db = Box::leak(Box::new(Database::default()));
            let mut huginn = HuginnNet::new(Some(db), 1024, None);
        
            if let Err(e) = huginn.analyze_network(&interface, sync_tx.clone()) {
                error!("Huginn-net (HTTP/TCP) analysis failed: {}. Restarting in 5 seconds...", e);
            } else {
                info!("Huginn-net (HTTP/TCP) analysis finished without error. Restarting in 5 seconds...");
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });

    let processing_task = tokio::spawn(async move {
        while let Some(result) = async_rx.recv().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Some(tcp_data) = result.syn {
                    let tcp_sig = TcpSignature {
                        source_ip: tcp_data.source.ip.to_string(),
                        signature: tcp_data.sig.to_string(),
                    };
                    if let Err(e) = send_tcp_to_assembler(tcp_sig, &config).await {
                        error!("Error sending TCP signature to assembler: {}", e);
                    }
                }
                if let Some(http_data) = result.http_request {
                    let http_sig = HttpSignature {
                        source_ip_port: format!("{}:{}", http_data.source.ip, http_data.source.port),
                        signature: http_data.sig.to_string(),
                    };
                    if let Err(e) = send_http_to_assembler(http_sig, &config).await {
                        error!("Error sending HTTP signature to assembler: {}", e);
                    }
                }
            });
        }
    });

    info!("HTTP/TCP collector is running. Press Ctrl+C to stop.");
    signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    info!("Ctrl+C received, shutting down.");

    processing_task.abort();
}

async fn send_tcp_to_assembler(data: TcpSignature, config: &Config) -> Result<(), String> {
    let res = config.http_client.post(&config.assembler_endpoint_tcp)
        .json(&data)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        info!("Successfully sent TCP signature for {}", data.source_ip);
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        error!(
            "Failed to send TCP signature. Status: {}. Body: {}",
            status, text
        );
    }
    Ok(())
}

async fn send_http_to_assembler(data: HttpSignature, config: &Config) -> Result<(), String> {
    let res = config.http_client.post(&config.assembler_endpoint_http)
        .json(&data)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        info!("Successfully sent HTTP signature for {}", data.source_ip_port);
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        error!(
            "Failed to send HTTP signature. Status: {}. Body: {}",
            status, text
        );
    }
    Ok(())
} 