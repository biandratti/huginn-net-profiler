use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::debug;

/// Events that can occur during traffic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrafficEvent {
    /// New traffic profile created
    ProfileCreated {
        ip: IpAddr,
        port: u16,
        timestamp: DateTime<Utc>,
    },

    /// Traffic profile updated with new data
    ProfileUpdated {
        ip: IpAddr,
        port: u16,
        data_type: String, // "tcp", "http", "tls"
        timestamp: DateTime<Utc>,
    },

    /// TCP analysis completed
    TcpAnalyzed {
        ip: IpAddr,
        port: u16,
        os: String,
        quality: f64,
        timestamp: DateTime<Utc>,
    },

    /// HTTP analysis completed
    HttpAnalyzed {
        ip: IpAddr,
        port: u16,
        browser: String,
        quality: f64,
        timestamp: DateTime<Utc>,
    },

    /// TLS analysis completed
    TlsAnalyzed {
        ip: IpAddr,
        port: u16,
        ja4: String,
        timestamp: DateTime<Utc>,
    },

    /// JA4 validation completed
    JA4Validated {
        ip: IpAddr,
        port: u16,
        ja4: String,
        user_agent: String,
        is_consistent: bool,
        confidence: f64,
        timestamp: DateTime<Utc>,
    },

    /// Analysis error occurred
    AnalysisError {
        ip: IpAddr,
        port: u16,
        error: String,
        timestamp: DateTime<Utc>,
    },
}

/// Trait for handling traffic events
pub trait EventHandler: Send + Sync {
    /// Handle a traffic event
    fn handle_event(&self, event: TrafficEvent) -> Result<()>;
}

/// Simple event handler that logs events
pub struct LoggingEventHandler;

impl EventHandler for LoggingEventHandler {
    fn handle_event(&self, event: TrafficEvent) -> Result<()> {
        match event {
            TrafficEvent::ProfileCreated { ip, port, .. } => {
                tracing::info!("New profile created for {}:{}", ip, port);
            }
            TrafficEvent::ProfileUpdated {
                ip,
                port,
                data_type,
                ..
            } => {
                tracing::info!(
                    "Profile updated for {}:{} with {} data",
                    ip,
                    port,
                    data_type
                );
            }
            TrafficEvent::TcpAnalyzed {
                ip,
                port,
                os,
                quality,
                ..
            } => {
                tracing::debug!(
                    "TCP analysis for {}:{} - OS: {} (quality: {:.2})",
                    ip,
                    port,
                    os,
                    quality
                );
            }
            TrafficEvent::HttpAnalyzed {
                ip,
                port,
                browser,
                quality,
                ..
            } => {
                tracing::debug!(
                    "HTTP analysis for {}:{} - Browser: {} (quality: {:.2})",
                    ip,
                    port,
                    browser,
                    quality
                );
            }
            TrafficEvent::TlsAnalyzed { ip, port, ja4, .. } => {
                tracing::debug!("TLS analysis for {}:{} - JA4: {}", ip, port, ja4);
            }
            TrafficEvent::JA4Validated {
                ip,
                port,
                ja4,
                user_agent,
                is_consistent,
                confidence,
                ..
            } => {
                let status = if is_consistent {
                    "✅ CONSISTENT"
                } else {
                    "⚠️ SUSPICIOUS"
                };
                debug!(
                    "JA4 validation for {}:{} - {} (confidence: {:.1}%) JA4: {} UA: {}",
                    ip,
                    port,
                    status,
                    confidence * 100.0,
                    ja4,
                    user_agent.chars().take(50).collect::<String>()
                );
            }
            TrafficEvent::AnalysisError {
                ip, port, error, ..
            } => {
                tracing::error!("Analysis error for {}:{} - {}", ip, port, error);
            }
        }
        Ok(())
    }
}

/// Event dispatcher that can handle multiple event handlers
pub struct EventDispatcher {
    handlers: Vec<Box<dyn EventHandler>>,
}

impl EventDispatcher {
    /// Create a new event dispatcher
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Add an event handler
    pub fn add_handler<H: EventHandler + 'static>(&mut self, handler: H) {
        self.handlers.push(Box::new(handler));
    }

    /// Dispatch an event to all handlers
    pub fn dispatch(&self, event: TrafficEvent) {
        for handler in &self.handlers {
            if let Err(e) = handler.handle_event(event.clone()) {
                tracing::error!("Event handler error: {}", e);
            }
        }
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficEvent {
    /// Get the IP address from any event
    pub fn ip(&self) -> IpAddr {
        match self {
            TrafficEvent::ProfileCreated { ip, .. } => *ip,
            TrafficEvent::ProfileUpdated { ip, .. } => *ip,
            TrafficEvent::TcpAnalyzed { ip, .. } => *ip,
            TrafficEvent::HttpAnalyzed { ip, .. } => *ip,
            TrafficEvent::TlsAnalyzed { ip, .. } => *ip,
            TrafficEvent::JA4Validated { ip, .. } => *ip,
            TrafficEvent::AnalysisError { ip, .. } => *ip,
        }
    }

    /// Get the port from any event
    pub fn port(&self) -> u16 {
        match self {
            TrafficEvent::ProfileCreated { port, .. } => *port,
            TrafficEvent::ProfileUpdated { port, .. } => *port,
            TrafficEvent::TcpAnalyzed { port, .. } => *port,
            TrafficEvent::HttpAnalyzed { port, .. } => *port,
            TrafficEvent::TlsAnalyzed { port, .. } => *port,
            TrafficEvent::JA4Validated { port, .. } => *port,
            TrafficEvent::AnalysisError { port, .. } => *port,
        }
    }

    /// Get the timestamp from any event
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            TrafficEvent::ProfileCreated { timestamp, .. } => *timestamp,
            TrafficEvent::ProfileUpdated { timestamp, .. } => *timestamp,
            TrafficEvent::TcpAnalyzed { timestamp, .. } => *timestamp,
            TrafficEvent::HttpAnalyzed { timestamp, .. } => *timestamp,
            TrafficEvent::TlsAnalyzed { timestamp, .. } => *timestamp,
            TrafficEvent::JA4Validated { timestamp, .. } => *timestamp,
            TrafficEvent::AnalysisError { timestamp, .. } => *timestamp,
        }
    }
}
