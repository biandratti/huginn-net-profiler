use crate::error::{CollectorError, Result};
use huginn_net::fingerprint_result::FingerprintResult;
use std::sync::mpsc;
use tokio::sync::mpsc as async_mpsc;
use tracing::{debug, error, warn};

/// Bridge between synchronous and asynchronous channels
///
/// This struct handles the conversion between std::sync::mpsc (used by huginn-net)
/// and tokio::sync::mpsc (used by async code)
pub struct ChannelBridge {
    // Synchronous receiver from huginn-net
    sync_receiver: mpsc::Receiver<FingerprintResult>,
    // Asynchronous sender to the rest of the application
    async_sender: async_mpsc::Sender<FingerprintResult>,
}

impl ChannelBridge {
    /// Create a new channel bridge
    pub fn new(
        sync_receiver: mpsc::Receiver<FingerprintResult>,
        async_sender: async_mpsc::Sender<FingerprintResult>,
    ) -> Self {
        Self {
            sync_receiver,
            async_sender,
        }
    }

    /// Start the bridge in a blocking thread
    ///
    /// This method will block the current thread and continuously forward
    /// messages from the synchronous receiver to the asynchronous sender
    pub fn start_blocking(self) -> Result<()> {
        debug!("Starting channel bridge in blocking mode");

        loop {
            match self.sync_receiver.recv() {
                Ok(result) => {
                    debug!("Bridge received fingerprint result");

                    // Try to send to async channel
                    match self.async_sender.blocking_send(result) {
                        Ok(_) => {
                            debug!("Bridge forwarded result to async channel");
                        }
                        Err(e) => {
                            error!("Bridge failed to send to async channel: {e}");
                            return Err(CollectorError::channel(format!(
                                "Failed to send to async channel: {e}"
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Bridge sync receiver disconnected: {}", e);
                    break;
                }
            }
        }

        debug!("Channel bridge stopped");
        Ok(())
    }

    /// Start the bridge in a separate thread
    ///
    /// This method spawns a new thread and starts the bridge there,
    /// returning immediately
    pub fn start_in_thread(self) -> Result<std::thread::JoinHandle<Result<()>>> {
        debug!("Starting channel bridge in separate thread");

        let handle = std::thread::spawn(move || self.start_blocking());

        Ok(handle)
    }
}

/// Create a channel bridge with the specified buffer size
///
/// Returns:
/// - sync_sender: Send end for huginn-net to use
/// - async_receiver: Receive end for async code to use
/// - bridge: The bridge that needs to be started
pub fn create_bridge(
    buffer_size: usize,
) -> (
    mpsc::Sender<FingerprintResult>,
    async_mpsc::Receiver<FingerprintResult>,
    ChannelBridge,
) {
    // Create synchronous channel
    let (sync_sender, sync_receiver) = mpsc::channel();

    // Create asynchronous channel
    let (async_sender, async_receiver) = async_mpsc::channel(buffer_size);

    // Create bridge
    let bridge = ChannelBridge::new(sync_receiver, async_sender);

    (sync_sender, async_receiver, bridge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use huginn_net::fingerprint_result::FingerprintResult;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_bridge_forwards_messages() {
        let (sync_sender, mut async_receiver, bridge) = create_bridge(10);

        // Start bridge in separate thread
        let _handle = bridge.start_in_thread().unwrap();

        // Create a dummy fingerprint result
        let result = FingerprintResult {
            syn: None,
            syn_ack: None,
            mtu: None,
            uptime: None,
            http_request: None,
            http_response: None,
            tls_client: None,
        };

        // Send through sync channel
        sync_sender.send(result).unwrap();

        // Receive through async channel
        let received = timeout(Duration::from_millis(100), async_receiver.recv())
            .await
            .expect("Timeout waiting for message")
            .expect("Channel closed");

        // Verify it's the same result (basic check)
        assert!(received.syn.is_none()); // Default result has no syn
    }

    #[tokio::test]
    async fn test_bridge_handles_sender_drop() {
        let (sync_sender, mut async_receiver, bridge) = create_bridge(10);

        // Start bridge in separate thread
        let handle = bridge.start_in_thread().unwrap();

        // Drop the sender
        drop(sync_sender);

        // Bridge should stop gracefully
        let result = handle.join().unwrap();
        assert!(result.is_ok());

        // Async receiver should be closed
        let received = async_receiver.recv().await;
        assert!(received.is_none());
    }
}
