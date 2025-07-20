use arc_swap::ArcSwap;
use huginn_collector::CollectorHandle;
use huginn_core::{JA4Database, TrafficProfile};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Traffic profiles cache (thread-safe)
    pub profiles: Arc<ArcSwap<HashMap<String, TrafficProfile>>>,
    /// Broadcast channel for real-time updates
    pub updates_tx: broadcast::Sender<ProfileUpdate>,
    /// Optional collector handle for management
    pub collector_handle: Option<Arc<CollectorHandle>>,
    /// Optional JA4 database for validation
    pub ja4_database: Option<Arc<JA4Database>>,
}

/// Update event for real-time notifications
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileUpdate {
    /// Type of update
    pub update_type: UpdateType,
    /// Profile key (IP:port)
    pub key: String,
    /// Updated profile (for new/updated events)
    pub profile: Option<TrafficProfile>,
    /// Timestamp of the update
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Type of profile update
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateType {
    /// New profile created
    ProfileCreated,
    /// Existing profile updated
    ProfileUpdated,
    /// Profile removed
    ProfileRemoved,
    /// Statistics updated
    StatsUpdated,
}

impl AppState {
    /// Create a new application state
    pub fn new() -> Self {
        let (updates_tx, _) = broadcast::channel(1000);

        Self {
            profiles: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            updates_tx,
            collector_handle: None,
            ja4_database: None,
        }
    }

    /// Create application state with collector handle
    pub fn with_collector(collector_handle: CollectorHandle) -> Self {
        let mut state = Self::new();
        state.collector_handle = Some(Arc::new(collector_handle));
        state
    }

    /// Set JA4 database for validation
    pub fn set_ja4_database(&mut self, ja4_database: JA4Database) {
        self.ja4_database = Some(Arc::new(ja4_database));
    }

    /// Get all profiles
    pub fn get_profiles(&self) -> Arc<HashMap<String, TrafficProfile>> {
        self.profiles.load_full()
    }

    /// Get a specific profile by key
    pub fn get_profile(&self, key: &str) -> Option<TrafficProfile> {
        self.profiles.load().get(key).cloned()
    }

    /// Update profiles and notify subscribers
    pub fn update_profiles(&self, new_profiles: HashMap<String, TrafficProfile>) {
        let old_profiles = self.profiles.load_full();

        // Find new and updated profiles
        for (key, profile) in &new_profiles {
            match old_profiles.get(key) {
                Some(old_profile) => {
                    // Check if profile was actually updated
                    if old_profile.timestamp != profile.timestamp {
                        self.notify_update(ProfileUpdate {
                            update_type: UpdateType::ProfileUpdated,
                            key: key.clone(),
                            profile: Some(profile.clone()),
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
                None => {
                    // New profile
                    self.notify_update(ProfileUpdate {
                        update_type: UpdateType::ProfileCreated,
                        key: key.clone(),
                        profile: Some(profile.clone()),
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
        }

        // Find removed profiles
        for key in old_profiles.keys() {
            if !new_profiles.contains_key(key) {
                self.notify_update(ProfileUpdate {
                    update_type: UpdateType::ProfileRemoved,
                    key: key.clone(),
                    profile: None,
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        // Update the profiles
        self.profiles.store(Arc::new(new_profiles));
    }

    /// Add or update a single profile
    pub fn upsert_profile(&self, key: String, profile: TrafficProfile) {
        let current = self.profiles.load_full();
        let mut new_profiles = current.as_ref().clone();

        let update_type = if new_profiles.contains_key(&key) {
            UpdateType::ProfileUpdated
        } else {
            UpdateType::ProfileCreated
        };

        new_profiles.insert(key.clone(), profile.clone());
        self.profiles.store(Arc::new(new_profiles));

        // Notify subscribers
        self.notify_update(ProfileUpdate {
            update_type,
            key,
            profile: Some(profile),
            timestamp: chrono::Utc::now(),
        });
    }

    /// Remove a profile
    pub fn remove_profile(&self, key: &str) -> Option<TrafficProfile> {
        let current = self.profiles.load_full();
        let mut new_profiles = current.as_ref().clone();

        let removed = new_profiles.remove(key);
        if removed.is_some() {
            self.profiles.store(Arc::new(new_profiles));

            // Notify subscribers
            self.notify_update(ProfileUpdate {
                update_type: UpdateType::ProfileRemoved,
                key: key.to_string(),
                profile: None,
                timestamp: chrono::Utc::now(),
            });
        }

        removed
    }

    /// Clear all profiles
    pub fn clear_profiles(&self) {
        let current = self.profiles.load_full();

        // Notify removal of each profile
        for key in current.keys() {
            self.notify_update(ProfileUpdate {
                update_type: UpdateType::ProfileRemoved,
                key: key.clone(),
                profile: None,
                timestamp: chrono::Utc::now(),
            });
        }

        self.profiles.store(Arc::new(HashMap::new()));
    }

    /// Get profile count
    pub fn profile_count(&self) -> usize {
        self.profiles.load().len()
    }

    /// Subscribe to profile updates
    pub fn subscribe_updates(&self) -> broadcast::Receiver<ProfileUpdate> {
        self.updates_tx.subscribe()
    }

    /// Get statistics about profiles
    pub fn get_stats(&self) -> ProfileStats {
        let profiles = self.profiles.load();

        let mut tcp_count = 0;
        let mut http_count = 0;
        let mut tls_count = 0;
        let mut complete_count = 0;

        for profile in profiles.values() {
            if profile.tcp.is_some() {
                tcp_count += 1;
            }
            if profile.http.is_some() {
                http_count += 1;
            }
            if profile.tls.is_some() {
                tls_count += 1;
            }
            if profile.metadata.completeness >= 1.0 {
                complete_count += 1;
            }
        }

        ProfileStats {
            total_profiles: profiles.len(),
            tcp_profiles: tcp_count,
            http_profiles: http_count,
            tls_profiles: tls_count,
            complete_profiles: complete_count,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Send update notification
    fn notify_update(&self, update: ProfileUpdate) {
        // Ignore errors if no subscribers
        let _ = self.updates_tx.send(update);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about traffic profiles
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileStats {
    /// Total number of profiles
    pub total_profiles: usize,
    /// Number of profiles with TCP data
    pub tcp_profiles: usize,
    /// Number of profiles with HTTP data
    pub http_profiles: usize,
    /// Number of profiles with TLS data
    pub tls_profiles: usize,
    /// Number of complete profiles (all data types)
    pub complete_profiles: usize,
    /// When these stats were generated
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
