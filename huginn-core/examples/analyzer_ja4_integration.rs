use huginn_core::profile::{HttpAnalysis, HttpDetails, HttpRequestData, TlsAnalysis, TlsDetails};
use huginn_core::{
    AnalyzerConfig, EventHandler, HuginnAnalyzer, JA4Database, TrafficEvent, TrafficProfile,
};

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

/// Custom event handler that captures events for demonstration
#[derive(Debug, Default, Clone)]
pub struct TestEventHandler {
    events: Arc<Mutex<Vec<TrafficEvent>>>,
}

impl TestEventHandler {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_events(&self) -> Vec<TrafficEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn clear_events(&self) {
        self.events.lock().unwrap().clear();
    }
}

impl EventHandler for TestEventHandler {
    fn handle_event(&self, event: TrafficEvent) -> huginn_core::Result<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("Huginn Analyzer with JA4 Integration Demo");
    println!("===========================================\n");

    // 1. Create JA4 database
    println!("Setting up JA4 database...");
    let ja4_database = create_test_ja4_database()?;
    let stats = ja4_database.get_stats();
    println!("   Loaded {} entries", stats.total_entries);
    println!(
        "   {} unique JA4 fingerprints",
        stats.unique_ja4_fingerprints
    );
    println!("   {} unique User-Agents\n", stats.unique_user_agents);

    // 2. Create analyzer with JA4 database
    println!("Creating analyzer with JA4 integration...");
    let config = AnalyzerConfig {
        enable_tcp: true,
        enable_http: true,
        enable_tls: true,
        min_quality: 0.0, // Allow all quality for demo
    };

    let mut analyzer = HuginnAnalyzer::with_config(config);
    analyzer.set_ja4_database(ja4_database.clone());

    // Add event handler to capture events
    let event_handler = TestEventHandler::new();
    analyzer
        .event_dispatcher_mut()
        .add_handler(event_handler.clone());

    println!("   Analyzer configured with JA4 database\n");

    // 3. Test Case 1: Consistent TLS + HTTP (Chrome)
    println!("Test Case 1: Consistent Chrome Browser");
    println!("   Expected: JA4 validation should PASS");
    let mut chrome_profile = create_chrome_profile();
    perform_ja4_validation(&mut chrome_profile, &ja4_database);
    test_profile_validation(&chrome_profile, "Chrome")?;

    // 4. Test Case 2: Suspicious TLS + HTTP mismatch
    println!("\nTest Case 2: Suspicious JA4/User-Agent Mismatch");
    println!("   Expected: JA4 validation should FAIL");
    let mut suspicious_profile = create_suspicious_profile();
    perform_ja4_validation(&mut suspicious_profile, &ja4_database);
    test_profile_validation(&suspicious_profile, "Suspicious")?;

    // 5. Test Case 3: Missing HTTP data (no validation)
    println!("\nTest Case 3: TLS Only (No HTTP User-Agent)");
    println!("   Expected: JA4 validation should be SKIPPED");
    let mut tls_only_profile = create_tls_only_profile();
    perform_ja4_validation(&mut tls_only_profile, &ja4_database);
    test_profile_validation(&tls_only_profile, "TLS-Only")?;

    // 6. Test the JA4 database directly
    println!("\nDirect JA4 Database Validation Tests:");
    test_ja4_database_directly()?;

    println!("\nDemo completed successfully!");

    Ok(())
}

fn create_test_ja4_database() -> std::result::Result<JA4Database, Box<dyn std::error::Error>> {
    let ja4_json = r#"[
        {
            "application": "Chrome Browser",
            "library": null,
            "device": null,
            "os": "Windows",
            "user_agent_string": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "certificate_authority": null,
            "observation_count": 50,
            "verified": true,
            "notes": "Common Chrome signature",
            "ja4_fingerprint": "t13d1517h2_8daaf6152771_b0da82dd1658",
            "ja4_fingerprint_string": null,
            "ja4s_fingerprint": null,
            "ja4h_fingerprint": null,
            "ja4x_fingerprint": null,
            "ja4t_fingerprint": null,
            "ja4ts_fingerprint": null,
            "ja4tscan_fingerprint": null
        },
        {
            "application": "Firefox Browser",
            "library": null,
            "device": null,
            "os": "Windows",
            "user_agent_string": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "certificate_authority": null,
            "observation_count": 30,
            "verified": true,
            "notes": "Common Firefox signature",
            "ja4_fingerprint": "t13d190ah2_9c3b2b4f1234_a1b2c3d4e5f6",
            "ja4_fingerprint_string": null,
            "ja4s_fingerprint": null,
            "ja4h_fingerprint": null,
            "ja4x_fingerprint": null,
            "ja4t_fingerprint": null,
            "ja4ts_fingerprint": null,
            "ja4tscan_fingerprint": null
        }
    ]"#;

    Ok(JA4Database::from_json(ja4_json)?)
}

fn create_chrome_profile() -> TrafficProfile {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let mut profile = TrafficProfile::new(ip, 54321);

    // Add TLS analysis with Chrome JA4
    let tls_analysis = TlsAnalysis {
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658".to_string(),
        ja4_raw: "t13d1517h2_8daaf6152771_b0da82dd1658_raw".to_string(),
        ja4_original: "t13d1517h2_8daaf6152771_b0da82dd1658".to_string(),
        ja4_original_raw: "t13d1517h2_8daaf6152771_b0da82dd1658_raw".to_string(),
        details: TlsDetails {
            version: "TLS 1.3".to_string(),
            sni: Some("www.google.com".to_string()),
            alpn: Some("h2".to_string()),
            cipher_suites: vec![4865, 4866, 4867],
            extensions: vec![0, 5, 10, 11, 13, 16, 18, 21, 23, 27, 35, 43, 45, 51],
            signature_algorithms: vec![1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537],
            elliptic_curves: vec![29, 23, 24],
        },
    };

    // Add HTTP analysis with Chrome User-Agent
    let http_request = HttpRequestData {
        user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".to_string()),
        accept: Some("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8".to_string()),
        accept_language: Some("en-US,en;q=0.5".to_string()),
        accept_encoding: Some("gzip, deflate, br".to_string()),
        connection: Some("keep-alive".to_string()),
        method: Some("GET".to_string()),
        host: Some("www.google.com".to_string()),
        signature: "GET / HTTP/1.1\\r\\nHost: www.google.com\\r\\n...".to_string(),
        quality: 0.95,
    };

    let http_analysis = HttpAnalysis {
        browser: "Chrome".to_string(),
        quality: 0.95,
        language: Some("en-US".to_string()),
        diagnosis: "Chrome browser detected".to_string(),
        signature: "GET / HTTP/1.1\\r\\nHost: www.google.com\\r\\n...".to_string(),
        details: HttpDetails {
            version: "1.1".to_string(),
            header_order: "Host,User-Agent,Accept,Accept-Language,Accept-Encoding,Connection"
                .to_string(),
            headers_absent: "".to_string(),
            expected_software: "Chrome".to_string(),
        },
        request: Some(http_request),
        response: None,
    };

    profile.update_tls(tls_analysis);
    profile.update_http(http_analysis);

    profile
}

fn create_suspicious_profile() -> TrafficProfile {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));
    let mut profile = TrafficProfile::new(ip, 54322);

    // Use Chrome JA4 fingerprint
    let tls_analysis = TlsAnalysis {
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658".to_string(), // Chrome JA4
        ja4_raw: "t13d1517h2_8daaf6152771_b0da82dd1658_raw".to_string(),
        ja4_original: "t13d1517h2_8daaf6152771_b0da82dd1658".to_string(),
        ja4_original_raw: "t13d1517h2_8daaf6152771_b0da82dd1658_raw".to_string(),
        details: TlsDetails {
            version: "TLS 1.3".to_string(),
            sni: Some("www.google.com".to_string()),
            alpn: Some("h2".to_string()),
            cipher_suites: vec![4865, 4866, 4867],
            extensions: vec![0, 5, 10, 11, 13, 16, 18, 21, 23, 27, 35, 43, 45, 51],
            signature_algorithms: vec![1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537],
            elliptic_curves: vec![29, 23, 24],
        },
    };

    // But use Firefox User-Agent (mismatch!)
    let http_request = HttpRequestData {
        user_agent: Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
                .to_string(),
        ),
        accept: Some("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
        accept_language: Some("en-US,en;q=0.5".to_string()),
        accept_encoding: Some("gzip, deflate".to_string()),
        connection: Some("keep-alive".to_string()),
        method: Some("GET".to_string()),
        host: Some("www.google.com".to_string()),
        signature: "GET / HTTP/1.1\\r\\nHost: www.google.com\\r\\n...".to_string(),
        quality: 0.90,
    };

    let http_analysis = HttpAnalysis {
        browser: "Firefox".to_string(),
        quality: 0.90,
        language: Some("en-US".to_string()),
        diagnosis: "Firefox browser detected".to_string(),
        signature: "GET / HTTP/1.1\\r\\nHost: www.google.com\\r\\n...".to_string(),
        details: HttpDetails {
            version: "1.1".to_string(),
            header_order: "Host,User-Agent,Accept,Accept-Language,Accept-Encoding".to_string(),
            headers_absent: "".to_string(),
            expected_software: "Firefox".to_string(),
        },
        request: Some(http_request),
        response: None,
    };

    profile.update_tls(tls_analysis);
    profile.update_http(http_analysis);

    profile
}

fn create_tls_only_profile() -> TrafficProfile {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102));
    let mut profile = TrafficProfile::new(ip, 54323);

    // Only TLS data, no HTTP
    let tls_analysis = TlsAnalysis {
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658".to_string(),
        ja4_raw: "t13d1517h2_8daaf6152771_b0da82dd1658_raw".to_string(),
        ja4_original: "t13d1517h2_8daaf6152771_b0da82dd1658".to_string(),
        ja4_original_raw: "t13d1517h2_8daaf6152771_b0da82dd1658_raw".to_string(),
        details: TlsDetails {
            version: "TLS 1.3".to_string(),
            sni: Some("api.example.com".to_string()),
            alpn: Some("h2".to_string()),
            cipher_suites: vec![4865, 4866, 4867],
            extensions: vec![0, 5, 10, 11, 13, 16, 18, 21, 23, 27, 35, 43, 45, 51],
            signature_algorithms: vec![1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537],
            elliptic_curves: vec![29, 23, 24],
        },
    };

    profile.update_tls(tls_analysis);
    // No HTTP data - this should skip JA4 validation

    profile
}

fn test_profile_validation(
    profile: &TrafficProfile,
    test_name: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("   Test: {test_name}");
    println!("   Profile created for {}", profile.ip);
    println!("   Profile data: {}", profile.summary());

    // Check JA4 validation results
    if let Some(ja4_validation) = &profile.ja4_validation {
        let status = if ja4_validation.is_consistent {
            "CONSISTENT"
        } else {
            "SUSPICIOUS"
        };
        println!(
            "   JA4 Validation: {} (confidence: {:.1}%)",
            status,
            ja4_validation.confidence * 100.0
        );

        if !ja4_validation.anomalies.is_empty() {
            println!("   Anomalies detected: {:?}", ja4_validation.anomalies);
        }

        println!("   Verification: {:?}", ja4_validation.verification_status);
    } else {
        println!("   No JA4 validation performed (missing TLS or HTTP data)");
    }

    Ok(())
}

fn test_ja4_database_directly() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let ja4_database = create_test_ja4_database()?;

    // Test Case 1: Exact match
    println!("1. Exact Match Test:");
    let ja4_1 = "t13d1517h2_8daaf6152771_b0da82dd1658";
    let ua_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
    let analysis_1 = ja4_database.validate_consistency(ja4_1, ua_1);
    print_analysis("Exact Match", &analysis_1);

    // Test Case 2: JA4 known but different User-Agent
    println!("2. JA4 Known, Different User-Agent:");
    let ja4_2 = "t13d1517h2_8daaf6152771_b0da82dd1658";
    let ua_2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0";
    let analysis_2 = ja4_database.validate_consistency(ja4_2, ua_2);
    print_analysis("JA4 Known, Different UA", &analysis_2);

    // Test Case 3: Unknown combination
    println!("3. Unknown Combination:");
    let ja4_3 = "t13d1234h2_unknown123_abcd567890ef";
    let ua_3 = "CustomBot/1.0 (Unknown)";
    let analysis_3 = ja4_database.validate_consistency(ja4_3, ua_3);
    print_analysis("Unknown Combination", &analysis_3);

    Ok(())
}

fn print_analysis(test_name: &str, analysis: &huginn_core::ConsistencyAnalysis) {
    println!("  Test: {test_name}");
    println!(
        "  Consistent: {} (confidence: {:.2})",
        analysis.is_consistent, analysis.confidence
    );

    if !analysis.expected_applications.is_empty() {
        println!("  Expected apps: {:?}", analysis.expected_applications);
    }

    if let Some(detected) = &analysis.detected_application {
        println!("  Detected app: {detected}");
    }

    if !analysis.anomalies.is_empty() {
        println!("  Anomalies: {:?}", analysis.anomalies);
    }

    println!("  Status: {:?}", analysis.verification_status);
    println!();
}

/// Simulates the JA4 validation performed by the analyzer
fn perform_ja4_validation(profile: &mut TrafficProfile, ja4_database: &JA4Database) {
    // Extract JA4 fingerprint from TLS data
    let ja4 = match &profile.tls {
        Some(tls_analysis) => &tls_analysis.ja4,
        None => return, // No TLS data available
    };

    // Extract User-Agent from HTTP data
    let user_agent = match &profile.http {
        Some(http_analysis) => match &http_analysis.request {
            Some(request) => match &request.user_agent {
                Some(ua) => ua,
                None => return, // No User-Agent available
            },
            None => return, // No request data available
        },
        None => return, // No HTTP data available
    };

    // Perform validation using the JA4 database
    let validation_result = ja4_database.validate_consistency(ja4, user_agent);

    // Update the profile with validation results
    profile.update_ja4_validation(validation_result);
}
