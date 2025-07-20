use huginn_core::{ConsistencyAnalysis, JA4Database};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ejemplo de JSON de la base de datos JA4 (versión simplificada)
    let ja4_json = r#"[
        {
            "application": "Chromium Browser",
            "library": null,
            "device": null,
            "os": null,
            "user_agent_string": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "certificate_authority": null,
            "observation_count": 1,
            "verified": true,
            "notes": "",
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
            "application": "Python",
            "library": "Python",
            "device": null,
            "os": null,
            "user_agent_string": null,
            "certificate_authority": null,
            "observation_count": 1,
            "verified": true,
            "notes": "",
            "ja4_fingerprint": "t13i181000_85036bcba153_d41ae481755e",
            "ja4_fingerprint_string": null,
            "ja4s_fingerprint": null,
            "ja4h_fingerprint": null,
            "ja4x_fingerprint": null,
            "ja4t_fingerprint": null,
            "ja4ts_fingerprint": null,
            "ja4tscan_fingerprint": null
        }
    ]"#;

    println!("Parsing JA4 Database...");
    let ja4_db = JA4Database::from_json(ja4_json)?;

    let stats = ja4_db.get_stats();
    println!("Database Stats:");
    println!("  Total entries: {}", stats.total_entries);
    println!(
        "  Unique JA4 fingerprints: {}",
        stats.unique_ja4_fingerprints
    );
    println!("  Unique User-Agents: {}", stats.unique_user_agents);
    println!("  Verified entries: {}", stats.verified_entries);
    println!();

    // Test Case 1: Exact match (should be consistent)
    println!("Test Case 1: Exact Match");
    let ja4_1 = "t13d1517h2_8daaf6152771_b0da82dd1658";
    let ua_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

    let analysis_1 = ja4_db.validate_consistency(ja4_1, ua_1);
    print_analysis("Exact Match", &analysis_1);

    // Test Case 2: JA4 known but different User-Agent (suspicious)
    println!("Test Case 2: JA4 Known, Different User-Agent");
    let ja4_2 = "t13d1517h2_8daaf6152771_b0da82dd1658";
    let ua_2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0";

    let analysis_2 = ja4_db.validate_consistency(ja4_2, ua_2);
    print_analysis("JA4 Known, Different UA", &analysis_2);

    // Test Case 3: Unknown combination (new/suspicious)
    println!("Test Case 3: Unknown Combination");
    let ja4_3 = "t13d1234h2_unknown123_abcd567890ef";
    let ua_3 = "CustomBot/1.0 (Unknown)";

    let analysis_3 = ja4_db.validate_consistency(ja4_3, ua_3);
    print_analysis("Unknown Combination", &analysis_3);

    println!("\nJA4 validation example completed!");
    Ok(())
}

fn print_analysis(test_name: &str, analysis: &ConsistencyAnalysis) {
    println!("  Test: {}", test_name);
    println!(
        "  Consistent: {} (confidence: {:.2})",
        analysis.is_consistent, analysis.confidence
    );

    if !analysis.expected_applications.is_empty() {
        println!("  Expected apps: {:?}", analysis.expected_applications);
    }

    if let Some(detected) = &analysis.detected_application {
        println!("  Detected app: {}", detected);
    }

    if !analysis.anomalies.is_empty() {
        println!("  Anomalies: {:?}", analysis.anomalies);
    }

    println!("  Status: {:?}", analysis.verification_status);
    println!();
}
