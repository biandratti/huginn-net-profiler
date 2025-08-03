use clap::Parser;
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
        default_value = "http://profile-assembler:8000/api/ingest"
    )]
    assembler_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TcpIngest {
    id: String,
    timestamp: u64,
    tcp_signature: String,
    os: String,
    nat: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct HttpIngest {
    id: String,
    timestamp: u64,
    http_signature: String,
    os: String,
    browser: String,
}

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
        let mut huginn = HuginnNet::new(Some(db), 1024, None);

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

            if let Some(tcp_data) = result.syn {
                if let Some(os_match) = tcp_data.os_matched {
                    let ingest = TcpIngest {
                        id: format!("{}:{}", tcp_data.source.ip, tcp_data.source.port),
                        timestamp: now,
                        tcp_signature: tcp_data.sig.to_string(),
                        os: os_match.os.name.to_string(),
                        nat: false, // NAT info not available in this struct
                    };
                    send_tcp_to_assembler(ingest, &client, &assembler_endpoint).await;
                }
            }

            if let Some(http_data) = result.http_request {
                if let Some(browser_match) = http_data.browser_matched {
                    let ingest = HttpIngest {
                        id: format!("{}:{}", http_data.source.ip, http_data.source.port),
                        timestamp: now,
                        http_signature: http_data.sig.to_string(),
                        os: "".to_string(), // OS info comes from TCP fingerprint
                        browser: browser_match.browser.name.to_string(),
                    };
                    send_http_to_assembler(ingest, &client, &assembler_endpoint).await;
                }
            }
        }
    });
}

async fn send_tcp_to_assembler(data: TcpIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending TCP data for {}", data.id);
    let url = format!("{}/tcp", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!(
                    "Failed to send TCP data for {}. Status: {}, Body: {:?}",
                    data.id,
                    response.status(),
                    response.text().await
                );
            }
        }
        Err(e) => error!("Error sending TCP data for {}: {:?}", data.id, e),
    }
}

async fn send_http_to_assembler(data: HttpIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending HTTP data for {}", data.id);
    let url = format!("{}/http", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!(
                    "Failed to send HTTP data for {}. Status: {}, Body: {:?}",
                    data.id,
                    response.status(),
                    response.text().await
                );
            }
        }
        Err(e) => error!("Error sending HTTP data for {}: {:?}", data.id, e),
    }
} 