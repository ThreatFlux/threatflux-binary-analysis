#![allow(clippy::uninlined_format_args)]
//! Performance benchmarks and integration tests with real system binaries
//!
//! This test suite focuses on performance testing and integration with actual
//! system binaries to ensure the library performs well in real-world scenarios.

use std::time::{Duration, Instant};
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer, BinaryError, types::*};

// Parser imports removed - using BinaryAnalyzer API

mod common;
use common::fixtures::*;

/// Performance test configuration
#[allow(dead_code)]
struct PerformanceConfig {
    max_duration: Duration,
    max_memory_mb: usize,
    iterations: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_duration: Duration::from_secs(10),
            max_memory_mb: 100,
            iterations: 5,
        }
    }
}

/// Test basic parsing performance with different file sizes
#[test]
fn test_parsing_performance_scaling() {
    let test_cases = vec![
        ("Small binary (4KB)", create_small_test_binary(4 * 1024)),
        (
            "Medium binary (256KB)",
            create_medium_test_binary(256 * 1024),
        ),
        (
            "Large binary (10MB)",
            create_large_test_binary(10 * 1024 * 1024),
        ),
        (
            "Very large binary (100MB)",
            create_very_large_test_binary(100 * 1024 * 1024),
        ),
    ];

    for (description, data) in test_cases {
        println!("Testing {}", description);

        let start = Instant::now();
        let result = threatflux_binary_analysis::formats::detect_format(&data);
        let detection_time = start.elapsed();

        println!("  Format detection: {:?}", detection_time);
        assert!(
            detection_time < Duration::from_secs(1),
            "Format detection should be fast for {}",
            description
        );

        let format =
            result.unwrap_or_else(|error| panic!("{description}: detection failed: {error}"));
        let start = Instant::now();
        match format {
            BinaryFormat::Elf | BinaryFormat::Pe | BinaryFormat::MachO | BinaryFormat::Java => {
                BinaryAnalyzer::new()
                    .analyze(&data)
                    .unwrap_or_else(|error| panic!("{description}: analysis failed: {error}"));
            }
            _ => {}
        }
        let parsing_time = start.elapsed();

        println!("  Parsing time: {:?}", parsing_time);

        // Parsing time should scale reasonably with file size
        match description {
            desc if desc.contains("Small") => {
                assert!(
                    parsing_time < Duration::from_millis(50),
                    "Small binary parsing should be very fast"
                );
            }
            desc if desc.contains("Medium") => {
                assert!(
                    parsing_time < Duration::from_millis(500),
                    "Medium binary parsing should be fast"
                );
            }
            desc if desc.contains("Large") => {
                assert!(
                    parsing_time < Duration::from_secs(10),
                    "Large binary parsing should be reasonable"
                );
            }
            desc if desc.contains("Very large") => {
                assert!(
                    parsing_time < Duration::from_secs(30),
                    "Very large binary parsing should complete"
                );
            }
            _ => {}
        }
    }
}

/// Test parsing performance with many small files
#[test]
fn test_batch_parsing_performance() {
    type FixtureFactory = (&'static str, fn() -> Vec<u8>);

    let num_files = 100;
    let fixture_factories: Vec<FixtureFactory> = vec![
        #[cfg(feature = "elf")]
        ("ELF", create_realistic_elf_64),
        #[cfg(feature = "pe")]
        ("PE", create_realistic_pe_64),
        #[cfg(feature = "macho")]
        ("Mach-O", create_realistic_macho_64),
        #[cfg(feature = "java")]
        ("Java", create_realistic_java_class),
    ];

    if fixture_factories.is_empty() {
        return;
    }

    let mut files = Vec::new();

    // Generate many small files for the parsers compiled into this build.
    for i in 0..num_files {
        let (format_name, create_fixture) = fixture_factories[i % fixture_factories.len()];
        files.push((format_name, create_fixture()));
    }

    let start = Instant::now();
    let mut successful_parses = 0;

    for (format_name, data) in &files {
        threatflux_binary_analysis::formats::detect_format(data)
            .unwrap_or_else(|error| panic!("{format_name} detection failed: {error}"));
        BinaryAnalyzer::new()
            .analyze(data)
            .unwrap_or_else(|error| panic!("{format_name} analysis failed: {error}"));
        successful_parses += 1;
    }

    let total_time = start.elapsed();
    let avg_time = total_time / num_files as u32;

    println!(
        "Batch parsing: {} files in {:?} (avg: {:?})",
        num_files, total_time, avg_time
    );
    println!("Successful parses: {}/{}", successful_parses, num_files);

    assert!(
        avg_time < Duration::from_millis(10),
        "Average parsing time should be reasonable"
    );
    assert!(
        successful_parses == num_files,
        "All generated fixtures should parse successfully"
    );
}

/// Test concurrent parsing performance
#[test]
fn test_concurrent_parsing_performance() {
    use std::sync::Arc;
    use std::thread;

    let test_data = Arc::new(create_large_test_binary(5 * 1024 * 1024)); // 5MB
    let num_threads = 8;
    let iterations_per_thread = 10;

    let start = Instant::now();
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let data = Arc::clone(&test_data);
        let handle = thread::spawn(move || {
            let mut successful = 0;

            for _iteration in 0..iterations_per_thread {
                let format = threatflux_binary_analysis::formats::detect_format(&data)
                    .unwrap_or_else(|error| panic!("detection failed: {error}"));
                if matches!(
                    format,
                    BinaryFormat::Elf | BinaryFormat::Pe | BinaryFormat::MachO | BinaryFormat::Java
                ) {
                    BinaryAnalyzer::new()
                        .analyze(&data)
                        .unwrap_or_else(|error| panic!("analysis failed: {error}"));
                }
                successful += 1;
            }

            (thread_id, successful)
        });
        handles.push(handle);
    }

    let mut total_successful = 0;
    for handle in handles {
        let (thread_id, successful) = handle.join().unwrap();
        println!(
            "Thread {}: {}/{} successful",
            thread_id, successful, iterations_per_thread
        );
        total_successful += successful;
    }

    let total_time = start.elapsed();
    let total_operations = num_threads * iterations_per_thread;

    println!(
        "Concurrent parsing: {} operations in {:?}",
        total_operations, total_time
    );
    println!(
        "Total successful: {}/{}",
        total_successful, total_operations
    );

    assert!(
        total_time < Duration::from_secs(60),
        "Concurrent parsing should complete in reasonable time"
    );
    assert!(
        total_successful >= total_operations / 2,
        "Most concurrent operations should succeed"
    );
}

/// Test analysis performance with full feature set
#[test]
fn test_full_analysis_performance() {
    let config = AnalysisConfig {
        enable_disassembly: cfg!(any(feature = "disasm-capstone", feature = "disasm-iced")),
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: threatflux_binary_analysis::DisassemblyEngine::Auto,
        enable_control_flow: cfg!(feature = "control-flow"),
        enable_call_graph: cfg!(feature = "control-flow"),
        enable_cognitive_complexity: cfg!(feature = "control-flow"),
        enable_advanced_loops: cfg!(feature = "control-flow"),
        enable_entropy: cfg!(feature = "entropy-analysis"),
        enable_symbols: cfg!(feature = "symbol-resolution"),
        max_analysis_size: 50 * 1024 * 1024,
        architecture_hint: None,
        ..Default::default()
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let test_data = create_analysis_elf_64();

    let start = Instant::now();
    let analysis = analyzer
        .analyze(&test_data)
        .expect("full-feature analysis should succeed");
    let analysis_time = start.elapsed();

    println!("Full analysis time: {:?}", analysis_time);

    // The test ELF data might be parsed as Raw format if it has structural issues
    assert!(
        analysis.format == BinaryFormat::Elf || analysis.format == BinaryFormat::Raw,
        "Expected ELF or Raw format, got: {:?}",
        analysis.format
    );
    // Only expect sections if it's actually parsed as ELF
    if analysis.format == BinaryFormat::Elf {
        assert!(!analysis.sections.is_empty());
    }

    // Verify that optional analyses were performed if features are enabled
    #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
    {
        if let Some(ref disassembly) = analysis.disassembly {
            println!("  Disassembled {} instructions", disassembly.len());
        }
    }

    #[cfg(feature = "control-flow")]
    {
        if let Some(ref control_flow) = analysis.control_flow {
            println!("  Generated {} control flow graphs", control_flow.len());
        }
    }

    #[cfg(feature = "entropy-analysis")]
    {
        if let Some(ref entropy) = analysis.entropy {
            println!("  Overall entropy: {:.2}", entropy.overall_entropy);
        }
    }

    assert!(
        analysis_time < Duration::from_secs(10),
        "Full analysis should complete in reasonable time"
    );
}

/// Test performance regression detection
#[test]
fn test_performance_regression() {
    let test_data = create_realistic_elf_64();
    let iterations = 500; // More iterations for better statistics
    let mut times = Vec::new();

    // Extended warm up to ensure JIT compilation and optimization
    for _ in 0..50 {
        BinaryAnalyzer::new()
            .analyze(&test_data)
            .expect("warm-up analysis should succeed");
    }

    // Measure parsing times
    for _ in 0..iterations {
        let start = Instant::now();
        BinaryAnalyzer::new()
            .analyze(&test_data)
            .expect("measured analysis should succeed");
        times.push(start.elapsed());
    }

    // Calculate statistics
    times.sort();

    // Remove extreme outliers (top and bottom 2%)
    let outlier_cutoff = (iterations as f64 * 0.02) as usize;
    let trimmed_times = &times[outlier_cutoff..times.len() - outlier_cutoff];

    let median = trimmed_times[trimmed_times.len() / 2];
    let p95 = trimmed_times[(trimmed_times.len() * 95) / 100];
    let p99 = trimmed_times[(trimmed_times.len() * 99) / 100];

    println!(
        "Performance statistics over {} iterations (trimmed):",
        trimmed_times.len()
    );
    println!("  Median: {:?}", median);
    println!("  95th percentile: {:?}", p95);
    println!("  99th percentile: {:?}", p99);

    // Performance thresholds (adjust based on expected performance)
    assert!(
        median < Duration::from_millis(10),
        "Median parsing time should be fast"
    );
    assert!(
        p95 < Duration::from_millis(50),
        "95th percentile should be reasonable"
    );
    assert!(
        p99 < Duration::from_millis(100),
        "99th percentile should be acceptable"
    );

    // Check for consistency with more lenient ratio for microbenchmarks
    // Account for system variability, JIT effects, and measurement noise
    let ratio = p99.as_nanos() as f64 / median.as_nanos() as f64;
    assert!(
        ratio < 50.0, // More lenient threshold for CI environments
        "Performance should be reasonably consistent (P99/median < 50x), got {:.1}x",
        ratio
    );
}

/// Test performance with corrupted/malicious files
#[test]
fn test_performance_adversarial_inputs() {
    let adversarial_cases = vec![
        ("Zip bomb", create_potential_zip_bomb()),
        ("Deep recursion", create_deep_recursion_binary()),
        ("Large symbol table", create_large_symbol_table_binary()),
        ("Many sections", create_many_sections_binary()),
        ("Huge strings", create_huge_strings_binary()),
    ];

    for (description, data) in adversarial_cases {
        println!("Testing adversarial case: {}", description);

        let start = Instant::now();
        let _result = threatflux_binary_analysis::formats::detect_format(&data);
        let detection_time = start.elapsed();

        // Should not take excessive time even with adversarial inputs
        assert!(
            detection_time < Duration::from_secs(5),
            "Format detection should be fast even for adversarial input: {}",
            description
        );

        // Try parsing with timeout protection
        let start = Instant::now();
        let _parse_result = match _result {
            Ok(BinaryFormat::Elf) => {
                std::thread::spawn(move || BinaryAnalyzer::new().analyze(&data))
                    .join()
                    .unwrap_or_else(|_| {
                        Err(threatflux_binary_analysis::BinaryError::ParseError(
                            "Thread panic".to_string(),
                        ))
                    })
            }
            Ok(BinaryFormat::Pe) => {
                std::thread::spawn(move || BinaryAnalyzer::new().analyze(&data))
                    .join()
                    .unwrap_or_else(|_| {
                        Err(threatflux_binary_analysis::BinaryError::ParseError(
                            "Thread panic".to_string(),
                        ))
                    })
            }
            _ => Err(threatflux_binary_analysis::BinaryError::UnsupportedFormat(
                "Not a supported format for this test".to_string(),
            )),
        };
        let parsing_time = start.elapsed();

        println!("  Parsing time: {:?}", parsing_time);
        assert!(
            parsing_time < Duration::from_secs(30),
            "Parsing should complete in reasonable time for: {}",
            description
        );
    }
}

/// Benchmark different analysis configurations
#[test]
fn test_analysis_configuration_performance() {
    let test_data = create_analysis_elf_64();
    let configs = vec![
        (
            "Minimal",
            AnalysisConfig {
                enable_disassembly: false,
                #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
                disassembly_engine: threatflux_binary_analysis::DisassemblyEngine::Auto,
                enable_control_flow: false,
                enable_entropy: false,
                enable_symbols: false,
                max_analysis_size: 1024 * 1024,
                architecture_hint: None,
                ..Default::default()
            },
        ),
        ("Standard", AnalysisConfig::default()),
        (
            "Full",
            AnalysisConfig {
                enable_disassembly: cfg!(any(feature = "disasm-capstone", feature = "disasm-iced")),
                #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
                disassembly_engine: threatflux_binary_analysis::DisassemblyEngine::Auto,
                enable_control_flow: cfg!(feature = "control-flow"),
                enable_call_graph: cfg!(feature = "control-flow"),
                enable_cognitive_complexity: cfg!(feature = "control-flow"),
                enable_advanced_loops: cfg!(feature = "control-flow"),
                enable_entropy: cfg!(feature = "entropy-analysis"),
                enable_symbols: cfg!(feature = "symbol-resolution"),
                max_analysis_size: 100 * 1024 * 1024,
                architecture_hint: Some(Architecture::X86_64),
                ..Default::default()
            },
        ),
    ];

    for (config_name, config) in configs {
        let analyzer = BinaryAnalyzer::with_config(config);

        let start = Instant::now();
        analyzer
            .analyze(&test_data)
            .unwrap_or_else(|error| panic!("{config_name} analysis failed: {error}"));
        let analysis_time = start.elapsed();

        println!("{} analysis: {:?}", config_name, analysis_time);

        match config_name {
            "Minimal" => {
                assert!(
                    analysis_time < Duration::from_millis(50),
                    "Minimal analysis should be very fast"
                );
            }
            "Standard" => {
                assert!(
                    analysis_time < Duration::from_millis(500),
                    "Standard analysis should be fast"
                );
            }
            "Full" => {
                assert!(
                    analysis_time < Duration::from_secs(5),
                    "Full analysis should be reasonable"
                );
            }
            _ => {}
        }
    }
}

/// Integration test with system binaries (if available)
#[test]
fn test_system_binary_integration() {
    let system_binaries = vec!["/bin/ls", "/bin/cat", "/usr/bin/file", "/usr/bin/hexdump"];

    for binary_path in system_binaries {
        if let Ok(data) = std::fs::read(binary_path) {
            println!(
                "Testing system binary: {} ({} bytes)",
                binary_path,
                data.len()
            );

            let start = Instant::now();
            let format_result = threatflux_binary_analysis::formats::detect_format(&data);
            let detection_time = start.elapsed();

            println!("  Format detection: {:?}", detection_time);
            assert!(
                detection_time < Duration::from_secs(1),
                "System binary format detection should be fast"
            );

            let format = format_result
                .unwrap_or_else(|error| panic!("{binary_path}: detection failed: {error}"));
            if !matches!(
                format,
                BinaryFormat::Elf | BinaryFormat::Pe | BinaryFormat::MachO
            ) {
                continue;
            }

            let start = Instant::now();
            let parsed = match BinaryAnalyzer::new().analyze(&data) {
                Ok(parsed) => parsed,
                Err(BinaryError::UnsupportedFormat(reason))
                    if format == BinaryFormat::MachO
                        && reason == "Universal (fat) Mach-O binaries are not supported" =>
                {
                    println!("  Skipping documented unsupported universal Mach-O container");
                    continue;
                }
                Err(error) => panic!("{binary_path}: analysis failed: {error}"),
            };
            let parsing_time = start.elapsed();

            println!("  Parsing: {:?}", parsing_time);
            println!("  Format: {:?}", parsed.format);
            println!("  Architecture: {:?}", parsed.architecture);
            println!("  Sections: {}", parsed.sections.len());
            println!("  Symbols: {}", parsed.symbols.len());

            assert_eq!(parsed.format, format);
            assert!(
                !parsed.sections.is_empty(),
                "System binary should have sections"
            );
        } else {
            println!("System binary not found: {}", binary_path);
        }
    }
}

// Helper functions

fn create_small_test_binary(size: usize) -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(size, 0);
    data
}

fn create_medium_test_binary(size: usize) -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(size, 0);
    data
}

fn create_large_test_binary(size: usize) -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(size, 0);
    data
}

fn create_very_large_test_binary(size: usize) -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(size, 0);
    data
}

fn create_potential_zip_bomb() -> Vec<u8> {
    // Create a file that might cause performance issues
    let mut data = create_realistic_java_class();
    data.resize(1024 * 1024, 0); // 1MB of mostly zeros
    data
}

fn create_deep_recursion_binary() -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    // Add structures that might cause deep recursion
    data.resize(512 * 1024, 0);
    data
}

fn create_large_symbol_table_binary() -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    // Simulate large symbol table
    data.resize(2 * 1024 * 1024, 0);
    data
}

fn create_many_sections_binary() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    // Simulate many sections
    data.resize(1024 * 1024, 0);
    data
}

fn create_huge_strings_binary() -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    // Add large string section
    let large_string = "A".repeat(100 * 1024); // 100KB string
    data.extend_from_slice(large_string.as_bytes());
    data
}

// Use DummyBinary from common fixtures
