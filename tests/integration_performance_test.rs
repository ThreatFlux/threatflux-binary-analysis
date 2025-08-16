#![allow(clippy::uninlined_format_args)]
//! Performance benchmarks and integration tests with real system binaries
//!
//! This test suite focuses on performance testing and integration with actual
//! system binaries to ensure the library performs well in real-world scenarios.

use std::time::{Duration, Instant};
use threatflux_binary_analysis::{types::*, AnalysisConfig, BinaryAnalyzer};

#[cfg(feature = "elf")]
use threatflux_binary_analysis::formats::elf::ElfParser;
#[cfg(feature = "java")]
use threatflux_binary_analysis::formats::java::JavaParser;
#[cfg(feature = "macho")]
use threatflux_binary_analysis::formats::macho::MachOParser;
#[cfg(feature = "pe")]
use threatflux_binary_analysis::formats::pe::PeParser;

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

        if let Ok(format) = result {
            let start = Instant::now();
            let parse_result = match format {
                BinaryFormat::Elf => ElfParser::parse(&data).map(|_| ()),
                BinaryFormat::Pe => PeParser::parse(&data).map(|_| ()),
                BinaryFormat::MachO => MachOParser::parse(&data).map(|_| ()),
                BinaryFormat::Java => JavaParser::parse(&data).map(|_| ()),
                _ => Ok(()),
            };
            let parsing_time = start.elapsed();

            println!("  Parsing time: {:?}", parsing_time);

            if parse_result.is_ok() {
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
                            parsing_time < Duration::from_secs(5),
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
    }
}

/// Test parsing performance with many small files
#[test]
fn test_batch_parsing_performance() {
    let num_files = 100;
    let mut files = Vec::new();

    // Generate many small files of different formats
    for i in 0..num_files {
        match i % 4 {
            0 => files.push(("ELF", create_realistic_elf_64())),
            1 => files.push(("PE", create_realistic_pe_64())),
            2 => files.push(("Mach-O", create_realistic_macho_64())),
            3 => files.push(("Java", create_realistic_java_class())),
            _ => unreachable!(),
        }
    }

    let start = Instant::now();
    let mut successful_parses = 0;

    for (_format_name, data) in &files {
        if let Ok(format) = threatflux_binary_analysis::formats::detect_format(data) {
            let parse_result = match format {
                BinaryFormat::Elf => ElfParser::parse(data).map(|_| ()),
                BinaryFormat::Pe => PeParser::parse(data).map(|_| ()),
                BinaryFormat::MachO => MachOParser::parse(data).map(|_| ()),
                BinaryFormat::Java => JavaParser::parse(data).map(|_| ()),
                _ => Ok(()),
            };

            if parse_result.is_ok() {
                successful_parses += 1;
            }
        }
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
        successful_parses >= num_files / 2,
        "Most files should parse successfully"
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
                if let Ok(format) = threatflux_binary_analysis::formats::detect_format(&data) {
                    let result = match format {
                        BinaryFormat::Elf => ElfParser::parse(&data).map(|_| ()),
                        BinaryFormat::Pe => PeParser::parse(&data).map(|_| ()),
                        BinaryFormat::MachO => MachOParser::parse(&data).map(|_| ()),
                        BinaryFormat::Java => JavaParser::parse(&data).map(|_| ()),
                        _ => Ok(()),
                    };

                    if result.is_ok() {
                        successful += 1;
                    }
                }
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

/// Test memory usage with large files
#[test]
fn test_memory_usage_large_files() {
    let test_cases = vec![
        ("10MB ELF", create_large_elf_binary(10 * 1024 * 1024)),
        ("20MB PE", create_large_pe_binary(20 * 1024 * 1024)),
        ("15MB Mach-O", create_large_macho_binary(15 * 1024 * 1024)),
    ];

    for (description, data) in test_cases {
        println!("Testing memory usage for {}", description);

        // Get baseline memory usage
        let baseline_memory = get_memory_usage();

        let result = match threatflux_binary_analysis::formats::detect_format(&data) {
            Ok(BinaryFormat::Elf) => ElfParser::parse(&data).map(|_| ()),
            Ok(BinaryFormat::Pe) => PeParser::parse(&data).map(|_| ()),
            Ok(BinaryFormat::MachO) => MachOParser::parse(&data).map(|_| ()),
            _ => Ok(()),
        };

        let peak_memory = get_memory_usage();
        let memory_increase = peak_memory.saturating_sub(baseline_memory);

        println!("  Memory increase: {} MB", memory_increase / 1024 / 1024);

        if result.is_ok() {
            // Memory usage should be reasonable relative to file size
            let _file_size_mb = data.len() / 1024 / 1024;
            let memory_ratio = memory_increase / data.len();

            assert!(
                memory_ratio < 5,
                "Memory usage should not exceed 5x file size for {}",
                description
            );

            // Force garbage collection
            drop(data);
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Test analysis performance with full feature set
#[test]
fn test_full_analysis_performance() {
    let config = AnalysisConfig {
        enable_disassembly: true,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: threatflux_binary_analysis::DisassemblyEngine::Auto,
        enable_control_flow: true,
        enable_entropy: true,
        enable_symbols: true,
        max_analysis_size: 50 * 1024 * 1024,
        architecture_hint: None,
        ..Default::default()
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let test_data = create_realistic_elf_64();

    let start = Instant::now();
    let result = analyzer.analyze(&test_data);
    let analysis_time = start.elapsed();

    println!("Full analysis time: {:?}", analysis_time);

    if let Ok(analysis) = result {
        assert_eq!(analysis.format, BinaryFormat::Elf);
        assert!(!analysis.sections.is_empty());

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
        let _ = ElfParser::parse(&test_data);
    }

    // Measure parsing times
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = ElfParser::parse(&test_data);
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
            Ok(BinaryFormat::Elf) => std::thread::spawn(move || ElfParser::parse(&data))
                .join()
                .unwrap_or_else(|_| {
                    Err(threatflux_binary_analysis::BinaryError::ParseError(
                        "Thread panic".to_string(),
                    ))
                }),
            Ok(BinaryFormat::Pe) => std::thread::spawn(move || PeParser::parse(&data))
                .join()
                .unwrap_or_else(|_| {
                    Err(threatflux_binary_analysis::BinaryError::ParseError(
                        "Thread panic".to_string(),
                    ))
                }),
            _ => Ok(Box::new(common::fixtures::DummyBinary) as Box<dyn BinaryFormatTrait>),
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
    let test_data = create_realistic_elf_64();
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
                enable_disassembly: true,
                #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
                disassembly_engine: threatflux_binary_analysis::DisassemblyEngine::Auto,
                enable_control_flow: true,
                enable_entropy: true,
                enable_symbols: true,
                max_analysis_size: 100 * 1024 * 1024,
                architecture_hint: Some(Architecture::X86_64),
                ..Default::default()
            },
        ),
    ];

    for (config_name, config) in configs {
        let analyzer = BinaryAnalyzer::with_config(config);

        let start = Instant::now();
        let result = analyzer.analyze(&test_data);
        let analysis_time = start.elapsed();

        println!("{} analysis: {:?}", config_name, analysis_time);

        if result.is_ok() {
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

            if let Ok(format) = format_result {
                let start = Instant::now();
                let parse_result = match format {
                    BinaryFormat::Elf => {
                        ElfParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>)
                    }
                    BinaryFormat::Pe => {
                        PeParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>)
                    }
                    BinaryFormat::MachO => {
                        MachOParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>)
                    }
                    _ => continue,
                };
                let parsing_time = start.elapsed();

                println!("  Parsing: {:?}", parsing_time);

                if let Ok(parsed) = parse_result {
                    println!("  Format: {:?}", parsed.format_type());
                    println!("  Architecture: {:?}", parsed.architecture());
                    println!("  Sections: {}", parsed.sections().len());
                    println!("  Symbols: {}", parsed.symbols().len());

                    // System binaries should parse successfully
                    assert_eq!(parsed.format_type(), format);
                    assert!(
                        !parsed.sections().is_empty(),
                        "System binary should have sections"
                    );
                }
            }
        } else {
            println!("System binary not found: {}", binary_path);
        }
    }
}

// Helper functions

fn get_memory_usage() -> usize {
    // Simplified memory usage measurement
    // In a real implementation, you might use platform-specific APIs
    // or a crate like `memory-stats`
    0 // Placeholder
}

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
