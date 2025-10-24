use clap::Parser;
use huginn_net_db::{Database, MatchQualityType};
use huginn_net_tcp::OperativeSystem;
use huginn_net_tcp::{HuginnNetTcp, TcpAnalysisResult};
use serde::{Deserialize, Serialize};
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
        default_value = "http://localhost:8000/api/ingest"
    )]
    assembler_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsDetection {
    pub os: String,
    pub quality: f32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpObserved {
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

#[derive(Serialize, Deserialize, Debug)]
pub struct SynPacketData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub os_detected: OsDetection,
    pub signature: String,
    pub observed: TcpObserved,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SynAckPacketData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub os_detected: OsDetection,
    pub signature: String,
    pub observed: TcpObserved,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MtuData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub link: String,
    pub mtu_value: u16,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UptimeData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub uptime_seconds: u64,
    pub up_mod_days: u32,
    pub freq: f64,
    pub timestamp: u64,
}

type SynIngest = SynPacketData;
type SynAckIngest = SynAckPacketData;
type MtuIngest = MtuData;
type UptimeIngest = UptimeData;

fn format_os(os: &OperativeSystem) -> String {
    let mut parts = vec![os.name.as_str()];

    if let Some(family) = &os.family {
        parts.push(family.as_str());
    }

    if let Some(variant) = &os.variant {
        parts.push(variant.as_str());
    }

    parts.join(" / ")
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

    info!("Booting tcp-collector on interface {interface} pointed to {assembler_endpoint}");

    // Setup graceful shutdown
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

    let (sync_tx, sync_rx) = std_mpsc::channel::<TcpAnalysisResult>();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    thread::spawn(move || {
        while let Ok(item) = sync_rx.recv() {
            if processing_cancel_signal.load(Ordering::Relaxed) {
                info!("Shutdown signal received, stopping sync-to-async bridge");
                break;
            }
            if async_tx.blocking_send(item).is_err() {
                error!("async channel closed");
                break;
            }
        }
    });

    let analysis_interface = interface.clone();
    let analysis_cancel_signal = cancel_signal.clone();

    thread::spawn(move || {
        info!("Starting TCP analysis on interface {analysis_interface}...");

        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                error!("Failed to load default database: {}", e);
                return;
            }
        };

        let mut tcp_analyzer = match HuginnNetTcp::new(Some(&db), 1000) {
            Ok(analyzer) => analyzer,
            Err(e) => {
                error!("Failed to create HuginnNetTcp analyzer: {}", e);
                return;
            }
        };

        if let Err(e) =
            tcp_analyzer.analyze_network(&analysis_interface, sync_tx, Some(analysis_cancel_signal))
        {
            error!("Huginn-net-tcp analysis failed: {e}");
        } else {
            info!("TCP analysis finished cleanly.");
        }
    });

    thread::spawn(|| {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};

        fn handle_health_request(mut stream: TcpStream) {
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            let _ = stream.write_all(response.as_bytes());
        }

        if let Ok(listener) = TcpListener::bind("0.0.0.0:9002") {
            for stream in listener.incoming().flatten() {
                handle_health_request(stream);
            }
        }
    });

    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let client = reqwest::Client::new();
        info!("Starting TCP result processor...");

        while let Some(tcp_result) = async_rx.recv().await {
            if cancel_signal.load(Ordering::Relaxed) {
                info!("Shutdown signal received, stopping result processing");
                break;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if let Some(syn) = tcp_result.syn {
                let ingest = SynIngest {
                    source: NetworkEndpoint {
                        ip: syn.source.ip.to_string(),
                        port: syn.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: syn.destination.ip.to_string(),
                        port: syn.destination.port,
                    },
                    os_detected: OsDetection {
                        os: syn
                            .os_matched
                            .os
                            .map(|o| format_os(&o))
                            .unwrap_or_else(|| "unknown".to_string()),
                        quality: match syn.os_matched.quality {
                            MatchQualityType::Matched(score) => score,
                            MatchQualityType::NotMatched => 0.0,
                            MatchQualityType::Disabled => 0.0,
                        },
                    },
                    signature: syn.sig.to_string(),
                    observed: to_details(&syn.sig),
                    timestamp: now,
                };
                send_syn_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
            if let Some(syn_ack) = tcp_result.syn_ack {
                let ingest = SynAckIngest {
                    source: NetworkEndpoint {
                        ip: syn_ack.source.ip.to_string(),
                        port: syn_ack.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: syn_ack.destination.ip.to_string(),
                        port: syn_ack.destination.port,
                    },
                    os_detected: OsDetection {
                        os: syn_ack
                            .os_matched
                            .os
                            .map(|o| format_os(&o))
                            .unwrap_or_else(|| "unknown".to_string()),
                        quality: match syn_ack.os_matched.quality {
                            MatchQualityType::Matched(score) => score,
                            MatchQualityType::NotMatched => 0.0,
                            MatchQualityType::Disabled => 0.0,
                        },
                    },
                    signature: syn_ack.sig.to_string(),
                    observed: to_details(&syn_ack.sig),
                    timestamp: now,
                };
                send_syn_ack_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
            if let Some(mtu) = tcp_result.mtu {
                let ingest = MtuIngest {
                    source: NetworkEndpoint {
                        ip: mtu.source.ip.to_string(),
                        port: mtu.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: mtu.destination.ip.to_string(),
                        port: mtu.destination.port,
                    },
                    link: format!("{:?}", mtu.link.link),
                    mtu_value: mtu.mtu,
                    timestamp: now,
                };
                send_mtu_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
            if let Some(uptime) = tcp_result.uptime {
                let total_seconds = (uptime.days as u64 * 24 * 3600)
                    + (uptime.hours as u64 * 3600)
                    + (uptime.min as u64 * 60);
                let ingest = UptimeIngest {
                    source: NetworkEndpoint {
                        ip: uptime.source.ip.to_string(),
                        port: uptime.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: uptime.destination.ip.to_string(),
                        port: uptime.destination.port,
                    },
                    uptime_seconds: total_seconds,
                    up_mod_days: uptime.up_mod_days,
                    freq: uptime.freq,
                    timestamp: now,
                };
                send_uptime_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
        }

        info!("TCP collector shutdown completed");
    });
}

fn to_details(sig: &huginn_net_tcp::ObservableTcp) -> TcpObserved {
    TcpObserved {
        version: format!("{}", sig.matching.version),
        initial_ttl: format!("{}", sig.matching.ittl),
        options_length: sig.matching.olen,
        mss: sig.matching.mss,
        window_size: format!("{}", sig.matching.wsize),
        window_scale: sig.matching.wscale,
        options_layout: sig
            .matching
            .olayout
            .iter()
            .map(|o| format!("{o:?}"))
            .collect::<Vec<_>>()
            .join(","),
        quirks: sig
            .matching
            .quirks
            .iter()
            .map(|q| format!("{q:?}"))
            .collect::<Vec<_>>()
            .join(","),
        payload_class: format!("{}", sig.matching.pclass),
    }
}

async fn send_syn_to_assembler(data: SynIngest, client: &reqwest::Client, endpoint: &str) {
    info!(
        "Sending SYN data for {}:{}",
        data.source.ip, data.source.port
    );
    let url = format!("{endpoint}/syn");
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                error!("Failed to send SYN data, status: {status} body: {body}");
            }
        }
        Err(e) => error!("Failed to send SYN data: {e}"),
    }
}

async fn send_syn_ack_to_assembler(data: SynAckIngest, client: &reqwest::Client, endpoint: &str) {
    info!(
        "Sending SYN-ACK data for {}:{} -> {}:{}",
        data.source.ip, data.source.port, data.destination.ip, data.destination.port
    );
    let url = format!("{endpoint}/syn_ack");
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                error!("Failed to send SYN-ACK data, status: {status} body: {body}");
            }
        }
        Err(e) => error!("Failed to send SYN-ACK data: {e}"),
    }
}

async fn send_mtu_to_assembler(data: MtuIngest, client: &reqwest::Client, endpoint: &str) {
    info!(
        "Sending MTU data for {}:{}",
        data.source.ip, data.source.port
    );
    let url = format!("{endpoint}/mtu");
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                error!("Failed to send MTU data, status: {status} body: {body}");
            }
        }
        Err(e) => error!("Failed to send MTU data: {e}"),
    }
}

async fn send_uptime_to_assembler(data: UptimeIngest, client: &reqwest::Client, endpoint: &str) {
    info!(
        "Sending uptime data for {}:{}",
        data.source.ip, data.source.port
    );
    let url = format!("{endpoint}/uptime");
    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                error!("Failed to send uptime data, status: {status} body: {body}");
            }
        }
        Err(e) => error!("Failed to send uptime data: {e}"),
    }
}
