#![allow(clippy::uninlined_format_args)]
//! Security analysis example
//!
//! This example demonstrates how to perform security analysis on binary files,
//! including vulnerability detection and malware indicators.

use std::env;
use std::fs;
use threatflux_binary_analysis::{
    analysis::security::{SecurityAnalyzer, SecurityConfig},
    utils::patterns::{PatternCategory, PatternMatcher},
    BinaryFile,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    // Get binary file path from command line arguments using iterator
    let mut args_iter = env::args();
    let program_name = args_iter
        .next()
        .unwrap_or_else(|| "security_analysis".to_string());
    let file_path = args_iter.next();

    if file_path.is_none() {
        eprintln!("Usage: {} <binary_file>", program_name);
        std::process::exit(1);
    }

    let file_path = file_path.unwrap();
    println!("Performing security analysis on: {}", file_path);

    // Read and parse the binary file
    let data = fs::read(&file_path)?;
    let binary = BinaryFile::parse(&data)?;

    println!("Binary format: {:?}", binary.format());
    println!("Architecture: {:?}", binary.architecture());
    println!("File size: {} bytes", data.len());

    // Create security analyzer
    let config = SecurityConfig {
        detect_suspicious_apis: true,
        detect_anti_debug: true,
        detect_anti_vm: true,
        detect_crypto: true,
        detect_network: true,
        detect_filesystem: true,
        detect_registry: true,
        min_string_length: 4,
    };

    let analyzer = SecurityAnalyzer::with_config(binary.architecture(), config);

    // Perform security analysis
    println!("\n=== Security Analysis ===");
    match analyzer.analyze(&binary) {
        Ok(results) => {
            print_security_results(&results);
        }
        Err(e) => {
            eprintln!("Security analysis failed: {}", e);
            return Err(e.into());
        }
    }

    // Perform pattern matching analysis
    println!("\n=== Pattern Analysis ===");
    let mut pattern_matcher = PatternMatcher::new();

    // Load built-in patterns
    let categories = vec![
        PatternCategory::FileFormat,
        PatternCategory::Compiler,
        PatternCategory::Packer,
        PatternCategory::Crypto,
        PatternCategory::Malware,
        PatternCategory::Api,
    ];

    pattern_matcher.load_builtin_patterns(&categories);

    match pattern_matcher.search(&data) {
        Ok(search_results) => {
            print_pattern_results(&search_results);
        }
        Err(e) => {
            eprintln!("Pattern matching failed: {}", e);
        }
    }

    Ok(())
}

/// Print security analysis results
fn print_security_results(
    results: &threatflux_binary_analysis::analysis::security::SecurityAnalysisResult,
) {
    println!("Risk Score: {:.1}/100", results.risk_score);

    let risk_level = match results.risk_score {
        0.0..=25.0 => "Low",
        25.1..=50.0 => "Medium",
        50.1..=75.0 => "High",
        _ => "Critical",
    };

    println!("Risk Level: {}", risk_level);

    // Print security features
    println!("\n--- Security Features ---");
    let features = &results.features;
    println!(
        "NX/DEP Enabled: {}",
        if features.nx_bit { "✓" } else { "✗" }
    );
    println!("ASLR Enabled: {}", if features.aslr { "✓" } else { "✗" });
    println!(
        "Stack Canary: {}",
        if features.stack_canary { "✓" } else { "✗" }
    );
    println!("CFI Enabled: {}", if features.cfi { "✓" } else { "✗" });
    println!("PIE Enabled: {}", if features.pie { "✓" } else { "✗" });
    println!("RELRO: {}", if features.relro { "✓" } else { "✗" });
    println!("Code Signed: {}", if features.signed { "✓" } else { "✗" });

    // Print security indicators
    println!("\n--- Security Indicators ---");
    let indicators = &results.indicators;

    if !indicators.suspicious_apis.is_empty() {
        println!("Suspicious APIs ({}):", indicators.suspicious_apis.len());
        for api in &indicators.suspicious_apis {
            println!("  • {}", api);
        }
    }

    if !indicators.anti_debug.is_empty() {
        println!(
            "\nAnti-debugging techniques ({}):",
            indicators.anti_debug.len()
        );
        for technique in &indicators.anti_debug {
            println!("  • {}", technique);
        }
    }

    if !indicators.anti_vm.is_empty() {
        println!("\nAnti-VM techniques ({}):", indicators.anti_vm.len());
        for technique in &indicators.anti_vm {
            println!("  • {}", technique);
        }
    }

    if !indicators.crypto_indicators.is_empty() {
        println!(
            "\nCryptographic functions ({}):",
            indicators.crypto_indicators.len()
        );
        for crypto in &indicators.crypto_indicators {
            println!("  • {}", crypto);
        }
    }

    if !indicators.network_indicators.is_empty() {
        println!(
            "\nNetwork functions ({}):",
            indicators.network_indicators.len()
        );
        for network in &indicators.network_indicators {
            println!("  • {}", network);
        }
    }

    if !indicators.filesystem_indicators.is_empty() {
        println!(
            "\nFilesystem functions ({}):",
            indicators.filesystem_indicators.len()
        );
        for fs in &indicators.filesystem_indicators {
            println!("  • {}", fs);
        }
    }

    if !indicators.registry_indicators.is_empty() {
        println!(
            "\nRegistry functions ({}):",
            indicators.registry_indicators.len()
        );
        for reg in &indicators.registry_indicators {
            println!("  • {}", reg);
        }
    }

    // Print detailed findings
    println!("\n--- Detailed Findings ---");
    if results.findings.is_empty() {
        println!("No specific security findings.");
    } else {
        // Group findings by severity
        let mut by_severity = std::collections::HashMap::new();
        for finding in &results.findings {
            by_severity
                .entry(&finding.severity)
                .or_insert_with(Vec::new)
                .push(finding);
        }

        // Print in severity order
        for severity in [
            threatflux_binary_analysis::analysis::security::Severity::Critical,
            threatflux_binary_analysis::analysis::security::Severity::High,
            threatflux_binary_analysis::analysis::security::Severity::Medium,
            threatflux_binary_analysis::analysis::security::Severity::Low,
            threatflux_binary_analysis::analysis::security::Severity::Info,
        ] {
            if let Some(findings) = by_severity.get(&severity) {
                println!("\n{:?} ({}):", severity, findings.len());
                for finding in findings {
                    print!("  • {}", finding.description);
                    if let Some(location) = &finding.location {
                        print!(" [{}]", location);
                    }
                    println!();
                }
            }
        }
    }
}

/// Print pattern matching results
fn print_pattern_results(results: &threatflux_binary_analysis::utils::patterns::SearchResults) {
    println!("Found {} pattern matches", results.matches.len());
    println!(
        "Searched {} bytes in {} ms",
        results.bytes_searched, results.duration_ms
    );

    if results.matches.is_empty() {
        println!("No patterns detected.");
        return;
    }

    // Print matches by category
    for (category, matches) in &results.by_category {
        println!("\n{:?} patterns ({}):", category, matches.len());

        for (i, pattern_match) in matches.iter().enumerate().take(5) {
            println!(
                "  {}. {} at offset 0x{:x} (confidence: {:.2})",
                i + 1,
                pattern_match.pattern.name,
                pattern_match.offset,
                pattern_match.confidence
            );

            if !pattern_match.pattern.description.is_empty() {
                println!("     {}", pattern_match.pattern.description);
            }

            // Show matched data (limited)
            if pattern_match.data.len() <= 16 {
                let hex_data = pattern_match
                    .data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("     Data: {}", hex_data);
            }
        }

        if matches.len() > 5 {
            println!("  ... and {} more matches", matches.len() - 5);
        }
    }

    // Summary statistics
    println!("\n--- Pattern Summary ---");
    let mut category_counts: Vec<_> = results.by_category.iter().collect();
    category_counts.sort_by_key(|(_, matches)| std::cmp::Reverse(matches.len()));

    for (category, matches) in category_counts {
        println!("{:?}: {} matches", category, matches.len());
    }
}
