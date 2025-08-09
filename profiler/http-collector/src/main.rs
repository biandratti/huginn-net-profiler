use clap::Parser;
use huginn_net::AnalysisConfig;
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
        default_value = "http://localhost:8000/api/ingest"
    )]
    assembler_endpoint: String,
}

// TCP structures matching huginn-core
#[derive(Serialize, Deserialize, Debug)]
pub struct SynPacketData {
    pub source: NetworkEndpoint,
    pub os_detected: Option<OsDetection>,
    pub signature: String,
    pub details: TcpDetails,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsDetection {
    pub os: String,
    pub quality: f64,
    pub distance: u8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpDetails {
    pub version: String,
    pub initial_ttl: String,
    pub options_length: u8,
    pub mss: Option<u16>,
    pub window_size: String,
    pub window_scale: Option<u8>,
    pub options_layout: String,
    pub quirks: String,
    pub payload_class: String,
}

/// SYN-ACK packet data (from server)
#[derive(Serialize, Deserialize, Debug)]
pub struct SynAckPacketData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub os_detected: Option<OsDetection>,
    pub signature: String,
    pub details: TcpDetails,
    pub timestamp: u64,
}

/// MTU detection data
#[derive(Serialize, Deserialize, Debug)]
pub struct MtuData {
    pub source: NetworkEndpoint,
    pub mtu_value: u16,
    pub timestamp: u64,
}

/// Uptime detection data
#[derive(Serialize, Deserialize, Debug)]
pub struct UptimeData {
    pub source: NetworkEndpoint,
    pub uptime_seconds: u64,
    pub timestamp: u64,
}

type SynIngest = SynPacketData;
type SynAckIngest = SynAckPacketData;
type MtuIngest = MtuData;
type UptimeIngest = UptimeData;

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
        let mut huginn = HuginnNet::new(Some(db), 1024, Some(AnalysisConfig{
            http_enabled: true,
            tcp_enabled: true,
            tls_enabled: false,
        }));

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

            // Process SYN packets (client data)
            if let Some(syn_data) = result.syn {
                let ingest = SynIngest {
                    source: NetworkEndpoint {
                        ip: syn_data.source.ip.to_string(),
                        port: syn_data.source.port,
                    },
                    os_detected: syn_data.os_matched.as_ref().map(|m| OsDetection {
                        os: m.os.name.clone(),
                        quality: m.quality as f64,
                        distance: 0, // Will be extracted from TTL if available
                    }),
                    signature: syn_data.sig.to_string(),
                    details: TcpDetails {
                        version: "IPv4".to_string(), // Default, could extract from syn_data.sig
                        initial_ttl: syn_data.sig.ittl.to_string(),
                        options_length: syn_data.sig.olen,
                        mss: syn_data.sig.mss,
                        window_size: syn_data.sig.wsize.to_string(),
                        window_scale: syn_data.sig.wscale,
                        options_layout: syn_data.sig.olayout.iter().map(|o| format!("{:?}", o)).collect::<Vec<_>>().join(","),
                        quirks: syn_data.sig.quirks.iter().map(|q| format!("{:?}", q)).collect::<Vec<_>>().join(","),
                        payload_class: syn_data.sig.pclass.to_string(),
                    },
                    timestamp: now,
                };
                send_syn_to_assembler(ingest, &client, &assembler_endpoint).await;
            }

            // Process SYN-ACK packets (server data)
            if let Some(syn_ack_data) = result.syn_ack {
                let ingest = SynAckIngest {
                    source: NetworkEndpoint {
                        ip: syn_ack_data.source.ip.to_string(),
                        port: syn_ack_data.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: syn_ack_data.destination.ip.to_string(),
                        port: syn_ack_data.destination.port,
                    },
                    os_detected: syn_ack_data.os_matched.as_ref().map(|m| OsDetection {
                        os: m.os.name.clone(),
                        quality: m.quality as f64,
                        distance: 0,
                    }),
                    signature: syn_ack_data.sig.to_string(),
                    details: TcpDetails {
                        version: "IPv4".to_string(),
                        initial_ttl: syn_ack_data.sig.ittl.to_string(),
                        options_length: syn_ack_data.sig.olen,
                        mss: syn_ack_data.sig.mss,
                        window_size: syn_ack_data.sig.wsize.to_string(),
                        window_scale: syn_ack_data.sig.wscale,
                        options_layout: syn_ack_data.sig.olayout.iter().map(|o| format!("{:?}", o)).collect::<Vec<_>>().join(","),
                        quirks: syn_ack_data.sig.quirks.iter().map(|q| format!("{:?}", q)).collect::<Vec<_>>().join(","),
                        payload_class: syn_ack_data.sig.pclass.to_string(),
                    },
                    timestamp: now,
                };
                send_syn_ack_to_assembler(ingest, &client, &assembler_endpoint).await;
            }

            // Process MTU data
            if let Some(mtu_data) = result.mtu {
                let ingest = MtuIngest {
                    source: NetworkEndpoint {
                        ip: mtu_data.source.ip.to_string(),
                        port: mtu_data.source.port,
                    },
                    mtu_value: mtu_data.mtu,
                    timestamp: now,
                };
                send_mtu_to_assembler(ingest, &client, &assembler_endpoint).await;
            }

            // Process uptime data
            if let Some(uptime_data) = result.uptime {
                let total_seconds = (uptime_data.days as u64 * 24 * 3600)
                    + (uptime_data.hours as u64 * 3600)
                    + (uptime_data.min as u64 * 60);
                
                let ingest = UptimeIngest {
                    source: NetworkEndpoint {
                        ip: uptime_data.source.ip.to_string(),
                        port: uptime_data.source.port,
                    },
                    uptime_seconds: total_seconds,
                    timestamp: now,
                };
                send_uptime_to_assembler(ingest, &client, &assembler_endpoint).await;
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

async fn send_syn_to_assembler(data: SynIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending SYN data for {}:{}", data.source.ip, data.source.port);
    let url = format!("{}/syn", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!("Failed to send SYN data, status: {}", response.status());
            }
        }
        Err(e) => error!("Failed to send SYN data: {}", e),
    }
}

async fn send_syn_ack_to_assembler(data: SynAckIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending SYN-ACK data for {}:{} -> {}:{}", 
          data.source.ip, data.source.port, data.destination.ip, data.destination.port);
    let url = format!("{}/syn_ack", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!("Failed to send SYN-ACK data, status: {}", response.status());
            }
        }
        Err(e) => error!("Failed to send SYN-ACK data: {}", e),
    }
}

async fn send_mtu_to_assembler(data: MtuIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending MTU data for {}:{}", data.source.ip, data.source.port);
    let url = format!("{}/mtu", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!("Failed to send MTU data, status: {}", response.status());
            }
        }
        Err(e) => error!("Failed to send MTU data: {}", e),
    }
}

async fn send_uptime_to_assembler(data: UptimeIngest, client: &reqwest::Client, endpoint: &str) {
    info!("Sending uptime data for {}:{}", data.source.ip, data.source.port);
    let url = format!("{}/uptime", endpoint);
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!("Failed to send uptime data, status: {}", response.status());
            }
        }
        Err(e) => error!("Failed to send uptime data: {}", e),
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