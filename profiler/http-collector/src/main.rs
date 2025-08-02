use anyhow::Result;
use clap::Parser;
use huginn_net::{db::Database, fingerprint_result::FingerprintResult, HuginnNet};
use log::{error, info, warn};
use serde::Serialize;
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::signal;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value = "eth0")]
    interface: String,
    #[clap(
        short,
        long,
        value_parser,
        default_value = "http://localhost:8000/api/ingest"
    )]
    assembler_endpoint: String,
}

#[derive(Serialize, Debug)]
struct HttpIngest {
    source_ip: String,
    signature: HttpSignature,
}

#[derive(Serialize, Debug)]
struct HttpSignature {
    browser: String,
    os: String,
}

#[derive(Serialize, Debug)]
struct TcpIngest {
    source_ip: String,
    signature: TcpSignature,
}

#[derive(Serialize, Debug)]
struct TcpSignature {
    os: String,
    browser: String,
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

    info!("Starting HTTP/TCP collector on interface {}", args.interface);

    let (sync_tx, sync_rx) = std_mpsc::channel();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    spawn_channel_bridge(sync_rx, async_tx);

    let interface = args.interface.clone();
    std::thread::spawn(move || {
        loop {
            info!("Starting new HTTP/TCP analysis loop on interface {}...", interface);
            let db = Box::leak(Box::new(Database::default()));
            let mut huginn = HuginnNet::new(Some(db), 1024, None);
        
            if let Err(e) = huginn.analyze_network(&interface, sync_tx.clone()) {
                error!("Huginn-net (HTTP/TCP) analysis failed: {}. Restarting in 5 seconds...", e);
            } else {
                info!("Huginn-net (HTTP/TCP) analysis finished. Restarting in 5 seconds...");
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });

    let client = reqwest::Client::new();
    let assembler_endpoint_http = format!("{}/http", args.assembler_endpoint);
    let assembler_endpoint_tcp = format!("{}/tcp", args.assembler_endpoint);

    let processing_task = tokio::spawn(async move {
        while let Some(result) = async_rx.recv().await {
            
            if let Some(tcp_data) = result.syn {
                if let Some(os_match) = tcp_data.os_matched {
                    let tcp_ingest = TcpIngest {
                        source_ip: tcp_data.source.ip.to_string(),
                        signature: TcpSignature {
                            os: os_match.os.name.to_string(),
                            browser: "".to_string(), // TCP doesn't provide browser info
                        },
                    };
                    send_data(&client, &assembler_endpoint_tcp, tcp_ingest).await;
                }
            }
            if let Some(http_data) = result.http_request {
                if let Some(browser_match) = http_data.browser_matched {
                    let http_ingest = HttpIngest {
                        source_ip: http_data.source.ip.to_string(),
                        signature: HttpSignature {
                            os: "".to_string(), // OS info comes from TCP fingerprint
                            browser: browser_match.browser.name.to_string(),
                        },
                    };
                    send_data(&client, &assembler_endpoint_http, http_ingest).await;
                }
            }
        }
    });

    info!("HTTP/TCP collector is running. Press Ctrl+C to stop.");
    signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    info!("Ctrl+C received, shutting down.");

    processing_task.abort();
    Ok(())
}

async fn send_data<T: Serialize>(client: &reqwest::Client, endpoint: &str, data: T) {
    let source_ip_for_log = serde_json::to_string(&data).unwrap_or_default();
    info!("Sending data to assembler {}: {}", endpoint, source_ip_for_log);
    match client.post(endpoint).json(&data).send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!("Successfully sent data for {}.", source_ip_for_log);
            } else {
                warn!(
                    "Failed to send data for {}. Status: {}",
                   source_ip_for_log,
                    response.status()
                );
            }
        }
        Err(e) => {
            error!("Error sending data for {}: {:?}", source_ip_for_log, e);
        }
    }
} 