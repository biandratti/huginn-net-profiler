use crate::error::{HuginnError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Entry from JA4 database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JA4Entry {
    pub application: Option<String>,
    pub library: Option<String>,
    pub device: Option<String>,
    pub os: Option<String>,
    pub user_agent_string: Option<String>,
    pub certificate_authority: Option<String>,
    pub observation_count: Option<u32>,
    pub verified: bool,
    pub notes: Option<String>,
    pub ja4_fingerprint: Option<String>,
    pub ja4_fingerprint_string: Option<String>,
    pub ja4s_fingerprint: Option<String>,
    pub ja4h_fingerprint: Option<String>,
    pub ja4x_fingerprint: Option<String>,
    pub ja4t_fingerprint: Option<String>,
    pub ja4ts_fingerprint: Option<String>,
    pub ja4tscan_fingerprint: Option<String>,
}

/// JA4 database for validation
#[derive(Debug, Clone)]
pub struct JA4Database {
    /// Map: JA4 fingerprint -> Vec<JA4Entry>
    pub ja4_to_entries: HashMap<String, Vec<JA4Entry>>,
    /// Map: User-Agent -> Vec<JA4Entry>  
    pub ua_to_entries: HashMap<String, Vec<JA4Entry>>,
    /// Map: Application -> Vec<JA4Entry>
    pub app_to_entries: HashMap<String, Vec<JA4Entry>>,
    /// Total number of entries
    pub total_entries: usize,
}

/// Consistency analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyAnalysis {
    /// Whether TLS JA4 and HTTP User-Agent are consistent
    pub is_consistent: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Expected applications based on JA4
    pub expected_applications: Vec<String>,
    /// Detected application from User-Agent
    pub detected_application: Option<String>,
    /// List of potential anomalies
    pub anomalies: Vec<String>,
    /// Verification status from database
    pub verification_status: VerificationStatus,
}

/// Verification status for the match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Exact match found in database (JA4 + User-Agent)
    ExactMatch {
        verified: bool,
        observation_count: Option<u32>,
    },
    /// JA4 found but different User-Agent
    JA4Match { expected_ua: Vec<String> },
    /// User-Agent found but different JA4
    UserAgentMatch { expected_ja4: Vec<String> },
    /// Neither JA4 nor User-Agent found in database
    NoMatch,
    /// Insufficient data for validation
    InsufficientData,
}

impl JA4Database {
    /// Parse JA4 database from JSON string
    pub fn from_json(json_data: &str) -> Result<Self> {
        let entries: Vec<JA4Entry> = serde_json::from_str(json_data)
            .map_err(|e| HuginnError::invalid_data(format!("Failed to parse JA4 JSON: {e}")))?;

        let mut ja4_to_entries = HashMap::new();
        let mut ua_to_entries = HashMap::new();
        let mut app_to_entries = HashMap::new();

        for entry in &entries {
            // Index by JA4 fingerprint
            if let Some(ja4) = &entry.ja4_fingerprint {
                ja4_to_entries
                    .entry(ja4.clone())
                    .or_insert_with(Vec::new)
                    .push(entry.clone());
            }

            // Index by User-Agent
            if let Some(ua) = &entry.user_agent_string {
                if !ua.is_empty() {
                    ua_to_entries
                        .entry(ua.clone())
                        .or_insert_with(Vec::new)
                        .push(entry.clone());
                }
            }

            // Index by Application
            if let Some(app) = &entry.application {
                if !app.is_empty() {
                    app_to_entries
                        .entry(app.clone())
                        .or_insert_with(Vec::new)
                        .push(entry.clone());
                }
            }
        }

        Ok(JA4Database {
            ja4_to_entries,
            ua_to_entries,
            app_to_entries,
            total_entries: entries.len(),
        })
    }

    /// Validate consistency between JA4 fingerprint and User-Agent
    pub fn validate_consistency(&self, ja4: &str, user_agent: &str) -> ConsistencyAnalysis {
        // Create empty vectors for fallback
        let empty_vec = vec![];

        // Find entries matching JA4
        let ja4_entries = self.ja4_to_entries.get(ja4).unwrap_or(&empty_vec);

        // Find entries matching User-Agent
        let ua_entries = self.ua_to_entries.get(user_agent).unwrap_or(&empty_vec);

        // Check for exact match (same JA4 and User-Agent)
        if let Some(exact_match) = self.find_exact_match(ja4, user_agent) {
            return ConsistencyAnalysis {
                is_consistent: true,
                confidence: if exact_match.verified { 0.95 } else { 0.8 },
                expected_applications: exact_match.application.clone().into_iter().collect(),
                detected_application: self.extract_application_from_ua(user_agent),
                anomalies: vec![],
                verification_status: VerificationStatus::ExactMatch {
                    verified: exact_match.verified,
                    observation_count: exact_match.observation_count,
                },
            };
        }

        // Analyze partial matches
        let (is_consistent, confidence, anomalies, verification_status) =
            self.analyze_partial_matches(ja4_entries, ua_entries, user_agent);

        // Extract expected applications from JA4 matches
        let expected_applications: Vec<String> = ja4_entries
            .iter()
            .filter_map(|e| e.application.clone())
            .collect();

        ConsistencyAnalysis {
            is_consistent,
            confidence,
            expected_applications,
            detected_application: self.extract_application_from_ua(user_agent),
            anomalies,
            verification_status,
        }
    }

    /// Find exact match for JA4 and User-Agent combination
    fn find_exact_match(&self, ja4: &str, user_agent: &str) -> Option<&JA4Entry> {
        self.ja4_to_entries.get(ja4)?.iter().find(|entry| {
            entry
                .user_agent_string
                .as_ref()
                .is_some_and(|ua| ua == user_agent)
        })
    }

    /// Analyze partial matches between JA4 and User-Agent
    fn analyze_partial_matches(
        &self,
        ja4_entries: &[JA4Entry],
        ua_entries: &[JA4Entry],
        _user_agent: &str,
    ) -> (bool, f64, Vec<String>, VerificationStatus) {
        let mut anomalies = vec![];
        let mut is_consistent = false;

        // Case 1: JA4 found but different User-Agent
        if !ja4_entries.is_empty() && ua_entries.is_empty() {
            let expected_uas: Vec<String> = ja4_entries
                .iter()
                .filter_map(|e| e.user_agent_string.clone())
                .collect();

            let confidence = 0.3;
            anomalies.push("JA4 fingerprint known but User-Agent not expected".to_string());

            return (
                is_consistent,
                confidence,
                anomalies,
                VerificationStatus::JA4Match {
                    expected_ua: expected_uas,
                },
            );
        }

        // Case 2: User-Agent found but different JA4
        if ja4_entries.is_empty() && !ua_entries.is_empty() {
            let expected_ja4s: Vec<String> = ua_entries
                .iter()
                .filter_map(|e| e.ja4_fingerprint.clone())
                .collect();

            let confidence = 0.3;
            anomalies.push("User-Agent known but JA4 fingerprint not expected".to_string());

            return (
                is_consistent,
                confidence,
                anomalies,
                VerificationStatus::UserAgentMatch {
                    expected_ja4: expected_ja4s,
                },
            );
        }

        // Case 3: Both found but inconsistent applications
        if !ja4_entries.is_empty() && !ua_entries.is_empty() {
            let ja4_apps: Vec<String> = ja4_entries
                .iter()
                .filter_map(|e| e.application.clone())
                .collect();
            let ua_apps: Vec<String> = ua_entries
                .iter()
                .filter_map(|e| e.application.clone())
                .collect();

            // Check if there's any application overlap
            let has_overlap = ja4_apps.iter().any(|app| ua_apps.contains(app));

            let confidence = if has_overlap {
                is_consistent = true;
                0.7
            } else {
                anomalies.push(format!(
                    "Application mismatch: JA4 suggests {ja4_apps:?}, User-Agent suggests {ua_apps:?}"
                ));
                0.2
            };

            return (
                is_consistent,
                confidence,
                anomalies,
                VerificationStatus::NoMatch,
            );
        }

        // Case 4: Neither found
        (
            false,
            0.1,
            vec!["Unknown JA4 and User-Agent combination".to_string()],
            VerificationStatus::NoMatch,
        )
    }

    /// Extract application name from User-Agent string
    fn extract_application_from_ua(&self, user_agent: &str) -> Option<String> {
        let ua_lower = user_agent.to_lowercase();

        if ua_lower.contains("chrome") {
            Some("Chrome".to_string())
        } else if ua_lower.contains("firefox") {
            Some("Firefox".to_string())
        } else if ua_lower.contains("safari") && !ua_lower.contains("chrome") {
            Some("Safari".to_string())
        } else if ua_lower.contains("edge") {
            Some("Edge".to_string())
        } else if ua_lower.contains("opera") {
            Some("Opera".to_string())
        } else {
            None
        }
    }

    /// Get statistics about the database
    pub fn get_stats(&self) -> JA4DatabaseStats {
        JA4DatabaseStats {
            total_entries: self.total_entries,
            unique_ja4_fingerprints: self.ja4_to_entries.len(),
            unique_user_agents: self.ua_to_entries.len(),
            unique_applications: self.app_to_entries.len(),
            verified_entries: self
                .ja4_to_entries
                .values()
                .flatten()
                .filter(|e| e.verified)
                .count(),
        }
    }
}

/// Statistics about the JA4 database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JA4DatabaseStats {
    pub total_entries: usize,
    pub unique_ja4_fingerprints: usize,
    pub unique_user_agents: usize,
    pub unique_applications: usize,
    pub verified_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_json() {
        let result = JA4Database::from_json("[]");
        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.total_entries, 0);
    }

    #[test]
    fn test_extract_application_from_ua() {
        let db = JA4Database::from_json("[]").unwrap();

        assert_eq!(
            db.extract_application_from_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"),
            Some("Chrome".to_string())
        );

        assert_eq!(
            db.extract_application_from_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"),
            Some("Firefox".to_string())
        );
    }
}
