use crate::state::{AppState, ProfileUpdate};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde_json;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// WebSocket handler for real-time profile updates
/// GET /ws
pub async fn websocket_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

/// Handle WebSocket connection
async fn handle_websocket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to profile updates
    let mut updates_rx = state.subscribe_updates();

    info!("WebSocket client connected");

    // Send initial data
    let initial_profiles = state.get_profiles();
    let initial_message = serde_json::json!({
        "type": "initial_data",
        "profiles": *initial_profiles,
        "stats": state.get_stats(),
        "timestamp": chrono::Utc::now()
    });

    if let Ok(msg) = serde_json::to_string(&initial_message) {
        if sender.send(Message::Text(msg.into())).await.is_err() {
            warn!("Failed to send initial data to WebSocket client");
            return;
        }
    }

    // Handle incoming messages and outgoing updates
    loop {
        tokio::select! {
            // Handle incoming WebSocket messages
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        debug!("Received WebSocket message: {}", text);

                        // Handle client commands
                        if let Err(e) = handle_client_message(&text, &state, &mut sender).await {
                            error!("Error handling client message: {}", e);
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("WebSocket client disconnected");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if sender.send(Message::Pong(data)).await.is_err() {
                            warn!("Failed to send pong to WebSocket client");
                            break;
                        }
                    }
                    Some(Ok(_)) => {
                        // Ignore other message types
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                    None => {
                        info!("WebSocket stream ended");
                        break;
                    }
                }
            }

            // Handle profile updates
            update = updates_rx.recv() => {
                match update {
                    Ok(update) => {
                        let message = serde_json::json!({
                            "type": "profile_update",
                            "update": Box::new(update),
                            "stats": state.get_stats(),
                            "timestamp": chrono::Utc::now()
                        });

                        if let Ok(msg) = serde_json::to_string(&message) {
                            if sender.send(Message::Text(msg.into())).await.is_err() {
                                warn!("Failed to send update to WebSocket client");
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("WebSocket client lagged, skipped {} updates", skipped);

                        // Send current state to catch up
                        let catch_up_message = serde_json::json!({
                            "type": "catch_up",
                            "profiles": *state.get_profiles(),
                            "stats": state.get_stats(),
                            "skipped_updates": skipped,
                            "timestamp": chrono::Utc::now()
                        });

                        if let Ok(msg) = serde_json::to_string(&catch_up_message) {
                            if sender.send(Message::Text(msg.into())).await.is_err() {
                                warn!("Failed to send catch-up data to WebSocket client");
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("Update channel closed");
                        break;
                    }
                }
            }
        }
    }

    info!("WebSocket connection closed");
}

/// Handle client messages
async fn handle_client_message(
    text: &str,
    state: &AppState,
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let message: serde_json::Value = serde_json::from_str(text)?;

    match message.get("type").and_then(|v| v.as_str()) {
        Some("ping") => {
            // Respond to ping
            let pong = serde_json::json!({
                "type": "pong",
                "timestamp": chrono::Utc::now()
            });

            let msg = serde_json::to_string(&pong)?;
            sender.send(Message::Text(msg.into())).await?;
        }

        Some("get_stats") => {
            // Send current statistics
            let stats_message = serde_json::json!({
                "type": "stats",
                "stats": state.get_stats(),
                "timestamp": chrono::Utc::now()
            });

            let msg = serde_json::to_string(&stats_message)?;
            sender.send(Message::Text(msg.into())).await?;
        }

        Some("get_profiles") => {
            // Send current profiles
            let profiles_message = serde_json::json!({
                "type": "profiles",
                "profiles": *state.get_profiles(),
                "timestamp": chrono::Utc::now()
            });

            let msg = serde_json::to_string(&profiles_message)?;
            sender.send(Message::Text(msg.into())).await?;
        }

        Some("clear_profiles") => {
            // Clear all profiles
            state.clear_profiles();

            let response = serde_json::json!({
                "type": "profiles_cleared",
                "timestamp": chrono::Utc::now()
            });

            let msg = serde_json::to_string(&response)?;
            sender.send(Message::Text(msg.into())).await?;
        }

        Some("subscribe") => {
            // Client wants to subscribe to specific updates
            let filters = message.get("filters");
            debug!("Client subscription request: {:?}", filters);

            // For now, we send all updates
            // In the future, we could implement filtering here
            let response = serde_json::json!({
                "type": "subscribed",
                "message": "Subscribed to all updates",
                "timestamp": chrono::Utc::now()
            });

            let msg = serde_json::to_string(&response)?;
            sender.send(Message::Text(msg.into())).await?;
        }

        _ => {
            // Unknown message type
            let error_response = serde_json::json!({
                "type": "error",
                "message": format!("Unknown message type: {:?}", message.get("type")),
                "timestamp": chrono::Utc::now()
            });

            let msg = serde_json::to_string(&error_response)?;
            sender.send(Message::Text(msg.into())).await?;
        }
    }

    Ok(())
}

/// WebSocket message types that clients can send
#[derive(serde::Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "ping")]
    Ping,

    #[serde(rename = "get_stats")]
    GetStats,

    #[serde(rename = "get_profiles")]
    GetProfiles,

    #[serde(rename = "clear_profiles")]
    ClearProfiles,

    #[serde(rename = "subscribe")]
    Subscribe {
        filters: Option<SubscriptionFilters>,
    },
}

/// Filters for WebSocket subscriptions
#[derive(serde::Deserialize)]
pub struct SubscriptionFilters {
    /// Only send updates for profiles with minimum completeness
    pub min_completeness: Option<f64>,
    /// Only send updates for specific update types
    pub update_types: Option<Vec<String>>,
    /// Only send updates for specific IP addresses
    pub ip_addresses: Option<Vec<String>>,
}

/// WebSocket message types that server can send
#[derive(serde::Serialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "initial_data")]
    InitialData {
        profiles: std::collections::HashMap<String, huginn_core::TrafficProfile>,
        stats: crate::state::ProfileStats,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "profile_update")]
    ProfileUpdate {
        update: Box<ProfileUpdate>,
        stats: crate::state::ProfileStats,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "catch_up")]
    CatchUp {
        profiles: std::collections::HashMap<String, huginn_core::TrafficProfile>,
        stats: crate::state::ProfileStats,
        skipped_updates: u64,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "pong")]
    Pong {
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "stats")]
    Stats {
        stats: crate::state::ProfileStats,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "profiles")]
    Profiles {
        profiles: std::collections::HashMap<String, huginn_core::TrafficProfile>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "profiles_cleared")]
    ProfilesCleared {
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "subscribed")]
    Subscribed {
        message: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    #[serde(rename = "error")]
    Error {
        message: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}
