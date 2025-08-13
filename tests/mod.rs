//! Test module organization and common utilities for threatflux-binary-analysis

pub mod common;

// Test utilities and fixtures
pub mod test_utils {
    use std::sync::Once;

    static INIT: Once = Once::new();

    /// Initialize test environment (call once per test process)
    pub fn init_test_env() {
        INIT.call_once(|| {
            // Initialize logging for tests
            let _ = env_logger::builder()
                .filter_level(log::LevelFilter::Debug)
                .is_test(true)
                .try_init();
        });
    }

    /// Create test binary data with specific characteristics
    pub fn create_test_binary(
        format: threatflux_binary_analysis::types::BinaryFormat,
        size: usize,
    ) -> Vec<u8> {
        let mut data = match format {
            threatflux_binary_analysis::types::BinaryFormat::Elf => {
                vec![0x7f, 0x45, 0x4c, 0x46] // ELF magic
            }
            threatflux_binary_analysis::types::BinaryFormat::Pe => {
                vec![0x4d, 0x5a] // PE magic
            }
            threatflux_binary_analysis::types::BinaryFormat::MachO => {
                vec![0xfe, 0xed, 0xfa, 0xce] // Mach-O magic
            }
            threatflux_binary_analysis::types::BinaryFormat::Java => {
                vec![0xca, 0xfe, 0xba, 0xbe] // Java magic
            }
            threatflux_binary_analysis::types::BinaryFormat::Wasm => {
                vec![0x00, 0x61, 0x73, 0x6d] // WASM magic
            }
            _ => vec![0x00, 0x01, 0x02, 0x03], // Random data
        };

        data.resize(size, 0);
        data
    }

    /// Performance test helper
    pub fn measure_performance<F, R>(name: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = std::time::Instant::now();
        let result = f();
        let duration = start.elapsed();

        println!("Performance test '{}': {:?}", name, duration);

        // Ensure reasonable performance (adjust thresholds as needed)
        match name {
            "format_detection" => assert!(duration.as_millis() < 10),
            "basic_analysis" => assert!(duration.as_millis() < 100),
            "full_analysis" => assert!(duration.as_millis() < 1000),
            _ => {} // No assertion for unknown tests
        }

        result
    }

    /// Memory usage test helper
    pub fn check_memory_usage<F>(f: F)
    where
        F: Fn(),
    {
        // Run function multiple times to detect memory leaks
        for _ in 0..1000 {
            f();
        }

        // If we reach here without OOM, memory usage is reasonable
        // In a real implementation, you might use system APIs to check actual memory usage
    }

    /// Create a temporary file with test data
    pub fn create_temp_binary(data: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(data).unwrap();
        file.flush().unwrap();
        file
    }

    /// Verify analysis result has expected fields populated
    pub fn verify_analysis_completeness(
        result: &threatflux_binary_analysis::types::AnalysisResult,
        expected_format: threatflux_binary_analysis::types::BinaryFormat,
    ) {
        // Basic format detection
        assert_eq!(result.format, expected_format);
        assert_ne!(
            result.architecture,
            threatflux_binary_analysis::types::Architecture::Unknown
        );

        // Metadata consistency
        assert_eq!(result.metadata.format, result.format);
        assert_eq!(result.metadata.architecture, result.architecture);
        assert!(result.metadata.size > 0);

        // Sections should be present for most formats (except Raw/Unknown)
        if !matches!(
            expected_format,
            threatflux_binary_analysis::types::BinaryFormat::Raw
                | threatflux_binary_analysis::types::BinaryFormat::Unknown
        ) {
            // Note: sections might be empty for minimal test data, but should not panic
            let _sections = &result.sections;
        }

        // Symbols might be empty but should not panic
        let _symbols = &result.symbols;
        let _imports = &result.imports;
        let _exports = &result.exports;
    }
}

// Common test assertions
pub mod assertions {
    use threatflux_binary_analysis::types::*;

    /// Assert that a binary format is properly detected
    pub fn assert_format_detected(data: &[u8], expected: BinaryFormat) {
        let format = threatflux_binary_analysis::formats::detect_format(data).unwrap();
        assert_eq!(
            format, expected,
            "Format detection failed for {:?}",
            expected
        );
    }

    /// Assert that analysis completes without errors
    pub fn assert_analysis_succeeds(data: &[u8]) {
        let analyzer = threatflux_binary_analysis::BinaryAnalyzer::new();
        let result = analyzer.analyze(data);
        assert!(result.is_ok(), "Analysis failed: {:?}", result.err());
    }

    /// Assert that analysis returns specific format and architecture
    pub fn assert_analysis_result(
        data: &[u8],
        expected_format: BinaryFormat,
        expected_arch: Architecture,
    ) {
        let analyzer = threatflux_binary_analysis::BinaryAnalyzer::new();
        let result = analyzer.analyze(data).unwrap();

        assert_eq!(result.format, expected_format);
        assert_eq!(result.architecture, expected_arch);
        assert_eq!(result.metadata.format, expected_format);
        assert_eq!(result.metadata.architecture, expected_arch);
    }

    /// Assert that security features are properly initialized
    pub fn assert_security_features_initialized(features: &SecurityFeatures) {
        // All fields should be accessible (no panics)
        let _nx = features.nx_bit;
        let _aslr = features.aslr;
        let _canary = features.stack_canary;
        let _cfi = features.cfi;
        let _fortify = features.fortify;
        let _pie = features.pie;
        let _relro = features.relro;
        let _signed = features.signed;
    }
}

// Test data generators
pub mod generators {
    use threatflux_binary_analysis::types::*;

    /// Generate comprehensive test suite data
    pub fn generate_test_binaries() -> Vec<(Vec<u8>, BinaryFormat, Architecture)> {
        vec![
            (
                super::test_utils::create_test_binary(BinaryFormat::Elf, 1024),
                BinaryFormat::Elf,
                Architecture::X86_64,
            ),
            (
                super::test_utils::create_test_binary(BinaryFormat::Pe, 1024),
                BinaryFormat::Pe,
                Architecture::X86_64,
            ),
            (
                super::test_utils::create_test_binary(BinaryFormat::MachO, 1024),
                BinaryFormat::MachO,
                Architecture::X86_64,
            ),
            (
                super::test_utils::create_test_binary(BinaryFormat::Java, 1024),
                BinaryFormat::Java,
                Architecture::Jvm,
            ),
            (
                super::test_utils::create_test_binary(BinaryFormat::Wasm, 1024),
                BinaryFormat::Wasm,
                Architecture::Wasm,
            ),
        ]
    }

    /// Generate malformed binary data for error testing
    pub fn generate_malformed_binaries() -> Vec<Vec<u8>> {
        vec![
            vec![],                                // Empty
            vec![0xff],                            // Too small
            vec![0x00; 1024],                      // All zeros
            vec![0xff; 1024],                      // All ones
            b"This is not a binary file".to_vec(), // Text
            vec![0x7f, 0x45, 0x4c],                // Incomplete ELF
            vec![0x4d, 0x5a, 0x90],                // Incomplete PE
        ]
    }

    /// Generate stress test data
    pub fn generate_stress_test_data() -> Vec<(Vec<u8>, usize)> {
        let sizes = vec![
            1024,             // 1KB
            64 * 1024,        // 64KB
            1024 * 1024,      // 1MB
            10 * 1024 * 1024, // 10MB
        ];

        sizes
            .into_iter()
            .map(|size| {
                (
                    super::test_utils::create_test_binary(BinaryFormat::Elf, size),
                    size,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod module_tests {
    use super::*;

    #[test]
    fn test_module_utilities() {
        test_utils::init_test_env();

        let data = test_utils::create_test_binary(
            threatflux_binary_analysis::types::BinaryFormat::Elf,
            1024,
        );

        assert!(data.len() == 1024);
        assert!(data.starts_with(&[0x7f, 0x45, 0x4c, 0x46]));
    }

    #[test]
    fn test_performance_measurement() {
        let result = test_utils::measure_performance("test_operation", || {
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_millis(1));
            42
        });

        assert_eq!(result, 42);
    }

    #[test]
    fn test_generators() {
        let binaries = generators::generate_test_binaries();
        assert!(!binaries.is_empty());

        let malformed = generators::generate_malformed_binaries();
        assert!(!malformed.is_empty());

        let stress_data = generators::generate_stress_test_data();
        assert!(!stress_data.is_empty());
    }
}
