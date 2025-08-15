use clap::Parser;
use huginn_net::fingerprint_result::OSQualityMatched;
use huginn_net::{
    db::Database, fingerprint_result::FingerprintResult, AnalysisConfig, HuginnNet, Ttl,
};
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

#[derive(Serialize, Deserialize, Debug)]
pub struct SynPacketData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub os_detected: Option<OsDetection>,
    pub signature: String,
    pub details: TcpDetails,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SynAckPacketData {
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub os_detected: Option<OsDetection>,
    pub signature: String,
    pub details: TcpDetails,
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

fn main() {
    env_logger::init();
    let args = Args::parse();
    let interface = args
        .interface
        .unwrap_or_else(|| env::var("PROFILER_INTERFACE").unwrap_or("wlp0s20f3".to_string()));
    let assembler_endpoint = args.assembler_endpoint;

    info!("Booting tcp-collector on interface {interface} pointed to {assembler_endpoint}");

    let (sync_tx, sync_rx) = std_mpsc::channel::<FingerprintResult>();
    let (async_tx, mut async_rx) = tokio_mpsc::channel(1000);

    thread::spawn(move || {
        while let Ok(item) = sync_rx.recv() {
            if async_tx.blocking_send(item).is_err() {
                error!("async channel closed");
                break;
            }
        }
    });

    let analysis_interface = interface.clone();
    thread::spawn(move || loop {
        info!("Starting TCP analysis loop on {analysis_interface}...");
        let db = Box::leak(Box::new(Database::default()));
        let mut huginn = HuginnNet::new(
            Some(db),
            1024,
            Some(AnalysisConfig {
                http_enabled: false,
                tcp_enabled: true,
                tls_enabled: false,
            }),
        );
        if let Err(e) = huginn.analyze_network(&analysis_interface, sync_tx.clone()) {
            error!("Huginn-net (TCP) analysis failed: {e}. Restarting in 5s...");
            thread::sleep(Duration::from_secs(5));
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
        while let Some(result) = async_rx.recv().await {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if let Some(syn) = result.syn {
                let ingest = SynIngest {
                    source: NetworkEndpoint {
                        ip: syn.source.ip.to_string(),
                        port: syn.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: syn.destination.ip.to_string(),
                        port: syn.destination.port,
                    },
                    os_detected: syn.os_matched.as_ref().map(|m| OsDetection {
                        os: format_os_detection(m),
                        quality: m.quality,
                    }),
                    signature: syn.sig.to_string(),
                    details: to_details(&syn.sig),
                    timestamp: now,
                };
                send_syn_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
            if let Some(syn_ack) = result.syn_ack {
                let ingest = SynAckIngest {
                    source: NetworkEndpoint {
                        ip: syn_ack.source.ip.to_string(),
                        port: syn_ack.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: syn_ack.destination.ip.to_string(),
                        port: syn_ack.destination.port,
                    },
                    os_detected: syn_ack.os_matched.as_ref().map(|m| OsDetection {
                        os: format_os_detection(m),
                        quality: m.quality,
                    }),
                    signature: syn_ack.sig.to_string(),
                    details: to_details(&syn_ack.sig),
                    timestamp: now,
                };
                send_syn_ack_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
            if let Some(mtu) = result.mtu {
                let ingest = MtuIngest {
                    source: NetworkEndpoint {
                        ip: mtu.source.ip.to_string(),
                        port: mtu.source.port,
                    },
                    destination: NetworkEndpoint {
                        ip: mtu.destination.ip.to_string(),
                        port: mtu.destination.port,
                    },
                    link: mtu.link,
                    mtu_value: mtu.mtu,
                    timestamp: now,
                };
                send_mtu_to_assembler(ingest, &client, &assembler_endpoint).await;
            }
            if let Some(uptime) = result.uptime {
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
    });
}

fn to_details(sig: &huginn_net::ObservableTcp) -> TcpDetails {
    TcpDetails {
        version: sig.version.to_string(),
        initial_ttl: extract_ttl(&sig.ittl),
        options_length: sig.olen,
        mss: sig.mss,
        window_size: sig.wsize.to_string(),
        window_scale: sig.wscale,
        options_layout: sig
            .olayout
            .iter()
            .map(|o| format!("{o:?}"))
            .collect::<Vec<_>>()
            .join(","),
        quirks: sig
            .quirks
            .iter()
            .map(|q| format!("{q:?}"))
            .collect::<Vec<_>>()
            .join(","),
        payload_class: sig.pclass.to_string(),
    }
}

fn extract_ttl(ttl: &Ttl) -> String {
    match ttl {
        Ttl::Value(v) => format!("{v}"),
        Ttl::Distance(ttl_value, hops) => format!("{ttl_value} ({hops} hops)"),
        Ttl::Guess(v) => format!("{v}+"),
        Ttl::Bad(v) => format!("{v}-"),
    }
}

fn format_os_detection(os_match: &OSQualityMatched) -> String {
    let mut parts = vec![os_match.os.name.clone()];

    if let Some(family) = &os_match.os.family {
        if !family.is_empty() {
            parts.push(family.clone());
        }
    }

    if let Some(variant) = &os_match.os.variant {
        if !variant.is_empty() {
            parts.push(variant.clone());
        }
    }

    parts.join("/")
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
