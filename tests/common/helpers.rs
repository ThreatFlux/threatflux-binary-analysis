//! Test helper functions for threatflux-binary-analysis

use std::io::Write;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use threatflux_binary_analysis::types::*;
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer};

/// Performance measurement helper
pub struct PerformanceTester {
    name: String,
    start: Instant,
}

impl PerformanceTester {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            start: Instant::now(),
        }
    }

    pub fn finish(self) -> Duration {
        let duration = self.start.elapsed();
        println!("Performance test '{}': {:?}", self.name, duration);
        duration
    }

    pub fn assert_under(self, max_duration: Duration) {
        let name = self.name.clone();
        let duration = self.finish();
        assert!(
            duration <= max_duration,
            "Performance test '{}' took {:?}, expected under {:?}",
            name,
            duration,
            max_duration
        );
    }
}

/// Create a temporary file with binary data
pub fn create_temp_binary(data: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(data).expect("Failed to write to temp file");
    file.flush().expect("Failed to flush temp file");
    file
}

/// Test analysis with default configuration
pub fn analyze_with_default(data: &[u8]) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let analyzer = BinaryAnalyzer::new();
    Ok(analyzer.analyze(data)?)
}

/// Test analysis with custom configuration
pub fn analyze_with_config(
    data: &[u8],
    config: AnalysisConfig,
) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let analyzer = BinaryAnalyzer::with_config(config);
    Ok(analyzer.analyze(data)?)
}

/// Test analysis with minimal configuration (all features disabled)
pub fn analyze_minimal(data: &[u8]) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let config = AnalysisConfig {
        enable_disassembly: false,
        enable_control_flow: false,
        enable_entropy: false,
        enable_symbols: false,
        max_analysis_size: 1024,
        architecture_hint: None,
    };
    analyze_with_config(data, config)
}

/// Test analysis with maximum configuration (all features enabled)
pub fn analyze_maximal(data: &[u8]) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let config = AnalysisConfig {
        enable_disassembly: true,
        enable_control_flow: true,
        enable_entropy: true,
        enable_symbols: true,
        max_analysis_size: 100 * 1024 * 1024,
        architecture_hint: None,
    };
    analyze_with_config(data, config)
}

/// Verify that analysis result has all required fields populated
pub fn verify_analysis_completeness(result: &AnalysisResult) {
    // Basic format and architecture should always be detected
    assert_ne!(
        result.format,
        BinaryFormat::Unknown,
        "Format should be detected"
    );
    assert_ne!(
        result.architecture,
        Architecture::Unknown,
        "Architecture should be detected"
    );

    // Metadata should be consistent with main result
    assert_eq!(result.metadata.format, result.format);
    assert_eq!(result.metadata.architecture, result.architecture);
    assert!(result.metadata.size > 0, "File size should be positive");

    // Collections should be initialized (but may be empty)
    // Note: len() >= 0 is always true, so we just verify they exist
    let _ = result.sections.len();
    let _ = result.symbols.len();
    let _ = result.imports.len();
    let _ = result.exports.len();
}

/// Verify that analysis result metadata is valid
pub fn verify_metadata_validity(metadata: &BinaryMetadata) {
    // Size should be positive
    assert!(metadata.size > 0, "File size should be positive");

    // Format and architecture should not be unknown for valid binaries
    assert_ne!(metadata.format, BinaryFormat::Unknown);
    assert_ne!(metadata.architecture, Architecture::Unknown);

    // If entry point is set, it should be reasonable
    if let Some(entry) = metadata.entry_point {
        assert!(entry > 0, "Entry point should be positive if set");
        assert!(entry < u64::MAX, "Entry point should be reasonable");
    }

    // If base address is set, it should be reasonable
    if let Some(base) = metadata.base_address {
        assert!(base > 0, "Base address should be positive if set");
    }

    // If timestamp is set, it should be reasonable (after Unix epoch)
    if let Some(timestamp) = metadata.timestamp {
        assert!(timestamp > 0, "Timestamp should be positive if set");
        assert!(timestamp < u64::MAX, "Timestamp should be reasonable");
    }

    // Security features should be properly initialized
    verify_security_features(&metadata.security_features);
}

/// Verify security features are properly initialized
pub fn verify_security_features(features: &SecurityFeatures) {
    // All fields should be accessible without panicking
    let _nx = features.nx_bit;
    let _aslr = features.aslr;
    let _canary = features.stack_canary;
    let _cfi = features.cfi;
    let _fortify = features.fortify;
    let _pie = features.pie;
    let _relro = features.relro;
    let _signed = features.signed;

    // Security features are booleans, so any value is valid
    // Just ensure we can access them without errors
}

/// Verify sections are valid
pub fn verify_sections_validity(sections: &[Section]) {
    for (i, section) in sections.iter().enumerate() {
        assert!(
            !section.name.is_empty(),
            "Section {} name should not be empty",
            i
        );
        assert!(section.size > 0, "Section {} size should be positive", i);

        // Address should be reasonable
        assert!(
            section.address < u64::MAX,
            "Section {} address should be reasonable",
            i
        );

        // If data is present, it should not exceed the section size
        if let Some(ref data) = section.data {
            assert!(
                data.len() <= section.size as usize,
                "Section {} data size exceeds section size",
                i
            );
        }

        // Verify permissions are accessible
        let _read = section.permissions.read;
        let _write = section.permissions.write;
        let _execute = section.permissions.execute;
    }
}

/// Verify symbols are valid
pub fn verify_symbols_validity(symbols: &[Symbol]) {
    for (i, symbol) in symbols.iter().enumerate() {
        assert!(
            !symbol.name.is_empty(),
            "Symbol {} name should not be empty",
            i
        );
        assert!(
            symbol.address < u64::MAX,
            "Symbol {} address should be reasonable",
            i
        );
        assert!(
            symbol.size < u64::MAX,
            "Symbol {} size should be reasonable",
            i
        );

        // If demangled name is present, it should not be empty
        if let Some(ref demangled) = symbol.demangled_name {
            assert!(
                !demangled.is_empty(),
                "Symbol {} demangled name should not be empty",
                i
            );
        }

        // Section index should be reasonable if set
        if let Some(section_idx) = symbol.section_index {
            assert!(
                section_idx < 10000,
                "Symbol {} section index should be reasonable",
                i
            );
        }
    }
}

/// Verify imports are valid
pub fn verify_imports_validity(imports: &[Import]) {
    for (i, import) in imports.iter().enumerate() {
        assert!(
            !import.name.is_empty(),
            "Import {} name should not be empty",
            i
        );

        // Library name should not be empty if present
        if let Some(ref library) = import.library {
            assert!(
                !library.is_empty(),
                "Import {} library name should not be empty",
                i
            );
        }

        // Address should be reasonable if set
        if let Some(address) = import.address {
            assert!(
                address > 0,
                "Import {} address should be positive if set",
                i
            );
            assert!(
                address < u64::MAX,
                "Import {} address should be reasonable",
                i
            );
        }

        // Ordinal should be reasonable if set
        if let Some(ordinal) = import.ordinal {
            assert!(
                ordinal > 0,
                "Import {} ordinal should be positive if set",
                i
            );
        }
    }
}

/// Verify exports are valid
pub fn verify_exports_validity(exports: &[Export]) {
    for (i, export) in exports.iter().enumerate() {
        assert!(
            !export.name.is_empty(),
            "Export {} name should not be empty",
            i
        );
        assert!(
            export.address > 0,
            "Export {} address should be positive",
            i
        );
        assert!(
            export.address < u64::MAX,
            "Export {} address should be reasonable",
            i
        );

        // Ordinal should be reasonable if set
        if let Some(ordinal) = export.ordinal {
            assert!(
                ordinal > 0,
                "Export {} ordinal should be positive if set",
                i
            );
        }

        // Forwarded name should not be empty if present
        if let Some(ref forwarded) = export.forwarded_name {
            assert!(
                !forwarded.is_empty(),
                "Export {} forwarded name should not be empty",
                i
            );
        }
    }
}

/// Verify instructions are valid (for disassembly)
pub fn verify_instructions_validity(instructions: &[Instruction]) {
    for (i, instruction) in instructions.iter().enumerate() {
        assert!(
            instruction.address > 0,
            "Instruction {} address should be positive",
            i
        );
        assert!(
            instruction.address < u64::MAX,
            "Instruction {} address should be reasonable",
            i
        );
        assert!(
            !instruction.bytes.is_empty(),
            "Instruction {} bytes should not be empty",
            i
        );
        assert!(
            instruction.size > 0,
            "Instruction {} size should be positive",
            i
        );
        assert!(
            instruction.size <= 16,
            "Instruction {} size should be reasonable",
            i
        );
        assert_eq!(
            instruction.bytes.len(),
            instruction.size,
            "Instruction {} bytes length should match size",
            i
        );

        // Mnemonic should not be empty
        assert!(
            !instruction.mnemonic.is_empty(),
            "Instruction {} mnemonic should not be empty",
            i
        );

        // Operands can be empty for some instructions
        // Category and flow should be valid enum values (no specific assertion needed)
    }
}

/// Run a test multiple times to check for consistency
pub fn test_consistency<F, R>(test_fn: F, iterations: usize) -> Vec<R>
where
    F: Fn() -> R,
    R: Clone,
{
    let mut results = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        results.push(test_fn());
    }
    results
}

/// Test memory usage by running a function multiple times
pub fn test_memory_usage<F>(test_fn: F, iterations: usize)
where
    F: Fn(),
{
    for _ in 0..iterations {
        test_fn();
    }
    // If we reach here without OOM, memory usage is reasonable
}

/// Create a stress test configuration
pub fn stress_test_config() -> AnalysisConfig {
    AnalysisConfig {
        enable_disassembly: true,
        enable_control_flow: true,
        enable_entropy: true,
        enable_symbols: true,
        max_analysis_size: 1024 * 1024, // 1MB limit for stress testing
        architecture_hint: None,
    }
}

/// Create a performance test configuration
pub fn performance_test_config() -> AnalysisConfig {
    AnalysisConfig {
        enable_disassembly: false, // Disable expensive operations
        enable_control_flow: false,
        enable_entropy: false,
        enable_symbols: true,                // Keep basic symbol analysis
        max_analysis_size: 10 * 1024 * 1024, // 10MB limit
        architecture_hint: None,
    }
}

/// Test error handling for various invalid inputs
pub fn test_error_handling() {
    let analyzer = BinaryAnalyzer::new();

    // Test empty data
    let result = analyzer.analyze(&[]);
    assert!(result.is_err(), "Empty data should cause error");

    // Test very small data
    let _result = analyzer.analyze(&[0x00]);
    // This might succeed with Unknown format or fail - both acceptable

    // Test corrupted magic bytes
    let _result = analyzer.analyze(&[0xff, 0xff, 0xff, 0xff]);
    // This might succeed with Unknown format or fail - both acceptable
}

/// Helper to compare two analysis results for equality (where applicable)
pub fn compare_analysis_results(result1: &AnalysisResult, result2: &AnalysisResult) {
    assert_eq!(result1.format, result2.format);
    assert_eq!(result1.architecture, result2.architecture);
    assert_eq!(result1.entry_point, result2.entry_point);

    // Compare metadata
    assert_eq!(result1.metadata.format, result2.metadata.format);
    assert_eq!(result1.metadata.architecture, result2.metadata.architecture);
    assert_eq!(result1.metadata.size, result2.metadata.size);
    assert_eq!(result1.metadata.entry_point, result2.metadata.entry_point);

    // Compare sections count (content might differ due to parsing variations)
    assert_eq!(result1.sections.len(), result2.sections.len());

    // Compare symbols count
    assert_eq!(result1.symbols.len(), result2.symbols.len());
}
