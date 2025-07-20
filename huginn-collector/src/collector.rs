use crate::bridge::create_bridge;
use crate::config::CollectorConfig;
use crate::error::{CollectorError, Result};
use huginn_core::{HuginnAnalyzer, LoggingEventHandler, TrafficProfile};
use huginn_net::fingerprint_result::FingerprintResult;
use huginn_net::{db::Database, HuginnNet};
use std::collections::HashMap;
use tokio::sync::{mpsc as async_mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Commands that can be sent to the collector
#[derive(Debug)]
pub enum CollectorCommand {
    /// Get all profiles
    GetProfiles(oneshot::Sender<HashMap<String, TrafficProfile>>),
    /// Get a specific profile by key
    GetProfile(String, oneshot::Sender<Option<TrafficProfile>>),
    /// Get profile count
    GetProfileCount(oneshot::Sender<usize>),
    /// Clear all profiles
    ClearProfiles,
    /// Set JA4 database for validation
    SetJA4Database(huginn_core::JA4Database),
}

/// Handle for controlling a running network collector
pub struct CollectorHandle {
    /// Handle to the huginn-net analyzer thread
    analyzer_handle: Option<std::thread::JoinHandle<()>>,
    /// Handle to the channel bridge thread
    bridge_handle: Option<std::thread::JoinHandle<Result<()>>>,
    /// Handle to the profile processor task
    processor_handle: Option<JoinHandle<Result<()>>>,
    /// Channel to send shutdown signal
    shutdown_sender: Option<async_mpsc::Sender<()>>,
    /// Channel to send commands to the collector
    command_sender: async_mpsc::Sender<CollectorCommand>,
}

impl CollectorHandle {
    /// Get all profiles from the collector
    pub async fn get_profiles(&self) -> Result<HashMap<String, TrafficProfile>> {
        let (tx, rx) = oneshot::channel();

        self.command_sender
            .send(CollectorCommand::GetProfiles(tx))
            .await
            .map_err(|_| CollectorError::channel("Failed to send get_profiles command"))?;

        rx.await
            .map_err(|_| CollectorError::channel("Failed to receive profiles response"))
    }

    /// Get a specific profile by key
    pub async fn get_profile(&self, key: &str) -> Result<Option<TrafficProfile>> {
        let (tx, rx) = oneshot::channel();

        self.command_sender
            .send(CollectorCommand::GetProfile(key.to_string(), tx))
            .await
            .map_err(|_| CollectorError::channel("Failed to send get_profile command"))?;

        rx.await
            .map_err(|_| CollectorError::channel("Failed to receive profile response"))
    }

    /// Get the number of profiles
    pub async fn get_profile_count(&self) -> Result<usize> {
        let (tx, rx) = oneshot::channel();

        self.command_sender
            .send(CollectorCommand::GetProfileCount(tx))
            .await
            .map_err(|_| CollectorError::channel("Failed to send get_profile_count command"))?;

        rx.await
            .map_err(|_| CollectorError::channel("Failed to receive profile count response"))
    }

    /// Clear all profiles
    pub async fn clear_profiles(&self) -> Result<()> {
        self.command_sender
            .send(CollectorCommand::ClearProfiles)
            .await
            .map_err(|_| CollectorError::channel("Failed to send clear_profiles command"))
    }

    /// Set JA4 database for validation
    pub async fn set_ja4_database(&self, ja4_database: huginn_core::JA4Database) -> Result<()> {
        self.command_sender
            .send(CollectorCommand::SetJA4Database(ja4_database))
            .await
            .map_err(|_| CollectorError::channel("Failed to send set_ja4_database command"))
    }

    /// Stop the collector gracefully
    pub async fn stop(mut self) -> Result<()> {
        info!("Stopping network collector");

        // Send shutdown signal
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(()).await;
        }

        // Wait for processor to finish
        if let Some(handle) = self.processor_handle.take() {
            match handle.await {
                Ok(result) => result?,
                Err(e) => {
                    error!("Processor task join error: {}", e);
                    return Err(CollectorError::Join(e));
                }
            }
        }

        // Wait for bridge to finish
        if let Some(handle) = self.bridge_handle.take() {
            match handle.join() {
                Ok(result) => result?,
                Err(e) => {
                    error!("Bridge thread join error: {e:?}");
                    return Err(CollectorError::Unknown(format!(
                        "Bridge thread panic: {e:?}"
                    )));
                }
            }
        }

        // Note: We don't wait for the analyzer thread as it's blocking on network capture
        // and will stop when the process terminates
        if let Some(handle) = self.analyzer_handle.take() {
            // Just detach it, huginn-net will handle cleanup
            std::mem::drop(handle);
        }

        info!("Network collector stopped successfully");
        Ok(())
    }

    /// Check if the collector is still running
    pub fn is_running(&self) -> bool {
        self.processor_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }
}

/// Network traffic collector
///
/// This struct orchestrates the entire collection process:
/// 1. Starts huginn-net to capture network packets
/// 2. Bridges between sync and async channels
/// 3. Processes fingerprint results using huginn-core
/// 4. Maintains a cache of traffic profiles
pub struct NetworkCollector {
    config: CollectorConfig,
    analyzer: HuginnAnalyzer,
    profiles: HashMap<String, TrafficProfile>,
}

impl NetworkCollector {
    /// Create a new network collector with the given configuration
    pub fn new(config: CollectorConfig) -> Result<Self> {
        // Validate configuration
        config.validate().map_err(CollectorError::configuration)?;

        // Create analyzer with the configured settings
        let mut analyzer = HuginnAnalyzer::with_config(config.analyzer.clone());

        // Add logging event handler
        analyzer
            .event_dispatcher_mut()
            .add_handler(LoggingEventHandler);

        Ok(Self {
            config,
            analyzer,
            profiles: HashMap::new(),
        })
    }

    /// Start the network collector
    ///
    /// This method starts all the necessary components:
    /// - huginn-net analyzer in a separate thread
    /// - Channel bridge in a separate thread  
    /// - Profile processor as an async task
    pub fn start(self) -> Result<CollectorHandle> {
        info!(
            "Starting network collector on interface: {}",
            self.config.interface
        );

        // Create the channel bridge
        let (sync_sender, async_receiver, bridge) = create_bridge(self.config.channel_buffer_size);

        // Start the bridge in a separate thread
        let bridge_handle = bridge.start_in_thread()?;

        // Create huginn-net database
        let db = Box::leak(Box::new(Database::default()));

        // Start huginn-net analyzer in a separate thread
        let interface = self.config.interface.clone();
        let buffer_size = self.config.buffer_size;
        let analyzer_handle = std::thread::spawn(move || {
            info!("Starting huginn-net analyzer on interface: {}", interface);

            match HuginnNet::new(Some(db), buffer_size, None)
                .analyze_network(&interface, sync_sender)
            {
                Ok(_) => {
                    info!("Huginn-net analyzer finished successfully");
                }
                Err(e) => {
                    error!("Huginn-net analyzer error: {}", e);
                }
            }
        });

        // Create shutdown channel
        let (shutdown_sender, shutdown_receiver) = async_mpsc::channel(1);

        // Create command channel
        let (command_sender, command_receiver) = async_mpsc::channel(100);

        // Start the profile processor
        let processor_handle = tokio::spawn(async move {
            self.process_profiles(async_receiver, shutdown_receiver, command_receiver)
                .await
        });

        Ok(CollectorHandle {
            analyzer_handle: Some(analyzer_handle),
            bridge_handle: Some(bridge_handle),
            processor_handle: Some(processor_handle),
            shutdown_sender: Some(shutdown_sender),
            command_sender,
        })
    }

    /// Process fingerprint results and maintain traffic profiles
    async fn process_profiles(
        mut self,
        mut receiver: async_mpsc::Receiver<FingerprintResult>,
        mut shutdown: async_mpsc::Receiver<()>,
        mut command_receiver: async_mpsc::Receiver<CollectorCommand>,
    ) -> Result<()> {
        info!("Starting profile processor");

        loop {
            tokio::select! {
                // Process incoming fingerprint results
                Some(result) = receiver.recv() => {
                    if let Err(e) = self.process_fingerprint_result(result).await {
                        error!("Error processing fingerprint result: {}", e);
                    }
                }

                // Handle commands from the API
                Some(command) = command_receiver.recv() => {
                    match command {
                        CollectorCommand::GetProfiles(tx) => {
                            let profiles = self.profiles.clone();
                            let _ = tx.send(profiles);
                        }
                        CollectorCommand::GetProfile(key, tx) => {
                            let profile = self.profiles.get(&key).cloned();
                            let _ = tx.send(profile);
                        }
                        CollectorCommand::GetProfileCount(tx) => {
                            let count = self.profiles.len();
                            let _ = tx.send(count);
                        }
                        CollectorCommand::ClearProfiles => {
                            self.profiles.clear();
                            info!("Cleared all profiles");
                        }
                        CollectorCommand::SetJA4Database(ja4_database) => {
                            self.analyzer.set_ja4_database(ja4_database);
                            info!("JA4 database configured in collector");
                        }
                    }
                }

                // Handle shutdown signal
                _ = shutdown.recv() => {
                    info!("Profile processor received shutdown signal");
                    break;
                }

                // Handle receiver closed
                else => {
                    warn!("Fingerprint result receiver closed");
                    break;
                }
            }
        }

        info!("Profile processor stopped");
        Ok(())
    }

    /// Process a single fingerprint result
    async fn process_fingerprint_result(&mut self, result: FingerprintResult) -> Result<()> {
        debug!("Processing fingerprint result");

        // Analyze the result using huginn-core
        match self.analyzer.analyze(result) {
            Ok(Some(profile)) => {
                let key = profile.ip.to_string(); // Group by IP only, not IP:port

                // Check if this is a new profile or an update
                let is_new_profile = !self.profiles.contains_key(&key);

                if is_new_profile {
                    // Insert new profile
                    debug!("Creating new profile for {}", key);
                    self.profiles.insert(key, profile);
                } else {
                    // Merge the new profile data into existing profile
                    debug!("Updating existing profile for {}", key);

                    // Extract profile from HashMap to avoid borrow checker issues
                    let mut existing = self.profiles.remove(&key).unwrap();
                    Self::merge_profiles(&mut existing, profile);

                    // Perform JA4 validation after merging (TLS and HTTP may arrive separately)
                    self.analyzer.perform_ja4_validation(&mut existing);

                    // Reinsert the validated profile
                    self.profiles.insert(key, existing);
                }

                debug!(
                    "Profile cache now contains {} profiles",
                    self.profiles.len()
                );
            }
            Ok(None) => {
                debug!("Analysis returned no profile (likely filtered out)");
            }
            Err(e) => {
                error!("Analysis error: {}", e);
                return Err(CollectorError::Core(e));
            }
        }

        Ok(())
    }

    /// Merge new profile data into existing profile
    fn merge_profiles(existing: &mut TrafficProfile, new: TrafficProfile) {
        // Update TCP data if new profile has it
        if new.tcp.is_some() {
            existing.tcp = new.tcp;
        }

        // Update TCP client data if new profile has it
        if new.tcp_client.is_some() {
            existing.tcp_client = new.tcp_client;
        }

        // Update TCP server data if new profile has it
        if new.tcp_server.is_some() {
            existing.tcp_server = new.tcp_server;
        }

        // Update HTTP data if new profile has it
        if new.http.is_some() {
            existing.http = new.http;
        }

        // Update TLS data if new profile has it
        if new.tls.is_some() {
            existing.tls = new.tls;
        }

        // Update JA4 validation data if new profile has it
        if new.ja4_validation.is_some() {
            existing.ja4_validation = new.ja4_validation;
        }

        // Update raw data (no merge, just replace)
        if new.raw_data.syn.is_some() {
            existing.raw_data.syn = new.raw_data.syn;
        }
        if new.raw_data.syn_ack.is_some() {
            existing.raw_data.syn_ack = new.raw_data.syn_ack;
        }
        if new.raw_data.http_request.is_some() {
            existing.raw_data.http_request = new.raw_data.http_request;
        }
        if new.raw_data.http_response.is_some() {
            existing.raw_data.http_response = new.raw_data.http_response;
        }
        if new.raw_data.tls_client.is_some() {
            existing.raw_data.tls_client = new.raw_data.tls_client;
        }
        if new.raw_data.mtu.is_some() {
            existing.raw_data.mtu = new.raw_data.mtu;
        }
        if new.raw_data.uptime.is_some() {
            existing.raw_data.uptime = new.raw_data.uptime;
        }
        if new.raw_data.source_ip.is_some() {
            existing.raw_data.source_ip = new.raw_data.source_ip;
        }

        // Update metadata
        existing.timestamp = new.timestamp;
        existing.metadata.last_updated = new.metadata.last_updated;
        existing.metadata.packet_count += new.metadata.packet_count;

        // Recalculate completeness
        let mut score = 0.0;
        if existing.tcp.is_some() || existing.tcp_client.is_some() || existing.tcp_server.is_some()
        {
            score += 0.4;
        }
        if existing.http.is_some() {
            score += 0.3;
        }
        if existing.tls.is_some() {
            score += 0.3;
        }
        existing.metadata.completeness = score;
    }

    /// Get a copy of all current profiles
    pub fn get_profiles(&self) -> HashMap<String, TrafficProfile> {
        self.profiles.clone()
    }

    /// Get a specific profile by IP:port key
    pub fn get_profile(&self, key: &str) -> Option<&TrafficProfile> {
        self.profiles.get(key)
    }

    /// Get the number of profiles in cache
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Clear all profiles from cache
    pub fn clear_profiles(&mut self) {
        self.profiles.clear();
    }
}

/// Builder for creating a NetworkCollector with custom configuration
pub struct NetworkCollectorBuilder {
    config: CollectorConfig,
}

impl NetworkCollectorBuilder {
    /// Create a new builder with the specified interface
    pub fn new(interface: String) -> Self {
        Self {
            config: CollectorConfig::new(interface),
        }
    }

    /// Set the buffer size for huginn-net
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.config = self.config.with_buffer_size(size);
        self
    }

    /// Set the channel buffer size
    pub fn channel_buffer_size(mut self, size: usize) -> Self {
        self.config = self.config.with_channel_buffer_size(size);
        self
    }

    /// Set the minimum quality threshold
    pub fn min_quality(mut self, quality: f64) -> Self {
        self.config.analyzer.min_quality = quality;
        self
    }

    /// Enable or disable TCP analysis
    pub fn enable_tcp(mut self, enable: bool) -> Self {
        self.config.analyzer.enable_tcp = enable;
        self
    }

    /// Enable or disable HTTP analysis
    pub fn enable_http(mut self, enable: bool) -> Self {
        self.config.analyzer.enable_http = enable;
        self
    }

    /// Enable or disable TLS analysis
    pub fn enable_tls(mut self, enable: bool) -> Self {
        self.config.analyzer.enable_tls = enable;
        self
    }

    /// Enable verbose logging
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.config = self.config.with_verbose(verbose);
        self
    }

    /// Build the NetworkCollector
    pub fn build(self) -> Result<NetworkCollector> {
        NetworkCollector::new(self.config)
    }
}
