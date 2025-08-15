//! Tests for the main BinaryAnalyzer functionality

use threatflux_binary_analysis::types::*;
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer, BinaryFile};

// Helper function to create mock ELF data
fn create_mock_elf_data() -> Vec<u8> {
    let mut data = vec![
        0x7f, 0x45, 0x4c, 0x46, // ELF magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // Current version
        0x00, // Generic ABI
    ];

    // Pad to minimum ELF header size
    data.resize(64, 0);

    // Set some basic ELF header fields
    data[16] = 0x02; // Executable file type
    data[17] = 0x00;
    data[18] = 0x3e; // x86-64 machine type
    data[19] = 0x00;
    data[24] = 0x00; // Entry point (8 bytes, little endian)
    data[25] = 0x10;
    data[26] = 0x00;
    data[27] = 0x00;
    data[28] = 0x00;
    data[29] = 0x00;
    data[30] = 0x00;
    data[31] = 0x00;

    // Add some padding for sections
    data.resize(1024, 0);
    data
}

// Helper function to create mock PE data
fn create_mock_pe_data() -> Vec<u8> {
    let mut data = vec![
        0x4d, 0x5a, // MZ magic
    ];

    data.resize(0x3c + 4, 0);
    data[0x3c] = 0x80; // PE header offset
    data[0x3d] = 0x00;

    data.resize(0x84, 0);
    data[0x80] = 0x50; // PE signature
    data[0x81] = 0x45;
    data[0x82] = 0x00;
    data[0x83] = 0x00;

    // Add COFF header
    data.resize(0x88, 0);
    data[0x84] = 0x64; // x86-64 machine type
    data[0x85] = 0x86;

    data.resize(1024, 0);
    data
}

#[test]
fn test_analyzer_creation() {
    let analyzer = BinaryAnalyzer::new();
    assert!(analyzer.config().enable_disassembly);
    assert!(analyzer.config().enable_control_flow);
    assert!(analyzer.config().enable_entropy);
    assert!(analyzer.config().enable_symbols);
    assert_eq!(analyzer.config().max_analysis_size, 100 * 1024 * 1024);
    assert!(analyzer.config().architecture_hint.is_none());
}

#[test]
fn test_analyzer_with_custom_config() {
    let config = AnalysisConfig {
        enable_disassembly: false,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: threatflux_binary_analysis::DisassemblyEngine::Auto,
        enable_control_flow: true,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 1024,
        architecture_hint: Some(Architecture::X86_64),
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    assert!(!analyzer.config().enable_disassembly);
    assert!(analyzer.config().enable_control_flow);
    assert!(!analyzer.config().enable_entropy);
    assert!(analyzer.config().enable_symbols);
    assert_eq!(analyzer.config().max_analysis_size, 1024);
    assert_eq!(
        analyzer.config().architecture_hint,
        Some(Architecture::X86_64)
    );
}

#[test]
fn test_analyze_elf_binary() {
    let data = create_mock_elf_data();
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data);
    assert!(result.is_ok(), "Analysis should succeed for valid ELF data");

    let analysis = result.unwrap();
    assert_eq!(analysis.format, BinaryFormat::Elf);
    assert_eq!(analysis.architecture, Architecture::X86_64);
    assert!(analysis.entry_point.is_some());
}

#[test]
fn test_analyze_pe_binary() {
    let data = create_mock_pe_data();
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data);
    assert!(result.is_ok(), "Analysis should succeed for valid PE data");

    let analysis = result.unwrap();
    assert_eq!(analysis.format, BinaryFormat::Pe);
    assert_eq!(analysis.architecture, Architecture::X86_64);
}

#[test]
fn test_analyze_invalid_binary() {
    let data = vec![0x00, 0x01, 0x02, 0x03]; // Random invalid data
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data);
    // Depending on implementation, this might succeed with Unknown format
    // or fail with an error - either is acceptable
    if let Ok(analysis) = result {
        assert!(matches!(
            analysis.format,
            BinaryFormat::Unknown | BinaryFormat::Raw
        ));
    }
}

#[test]
fn test_analyze_empty_data() {
    let data = vec![];
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data);
    assert!(result.is_err(), "Analysis should fail for empty data");
}

#[test]
fn test_binary_file_parsing() {
    let data = create_mock_elf_data();

    let binary_file = BinaryFile::parse(&data);
    assert!(binary_file.is_ok(), "Binary file parsing should succeed");

    let binary = binary_file.unwrap();
    assert_eq!(binary.format(), BinaryFormat::Elf);
    assert_eq!(binary.architecture(), Architecture::X86_64);
    assert!(binary.entry_point().is_some());
    assert!(!binary.data().is_empty());
}

#[test]
fn test_binary_file_sections() {
    let data = create_mock_elf_data();
    let binary = BinaryFile::parse(&data).unwrap();

    let _sections = binary.sections();
    // Mock data might not have actual sections, but should not panic
    // Sections are available (len >= 0 is always true)
}

#[test]
fn test_binary_file_symbols() {
    let data = create_mock_elf_data();
    let binary = BinaryFile::parse(&data).unwrap();

    let _symbols = binary.symbols();
    // Mock data might not have actual symbols, but should not panic
    // Symbols are available (len >= 0 is always true)
}

#[test]
fn test_binary_file_imports() {
    let data = create_mock_elf_data();
    let binary = BinaryFile::parse(&data).unwrap();

    let _imports = binary.imports();
    // Imports are available (len >= 0 is always true)
}

#[test]
fn test_binary_file_exports() {
    let data = create_mock_elf_data();
    let binary = BinaryFile::parse(&data).unwrap();

    let _exports = binary.exports();
    // Exports are available (len >= 0 is always true)
}

#[test]
fn test_binary_file_metadata() {
    let data = create_mock_elf_data();
    let binary = BinaryFile::parse(&data).unwrap();

    let metadata = binary.metadata();
    assert_eq!(metadata.format, BinaryFormat::Elf);
    assert_eq!(metadata.architecture, Architecture::X86_64);
    assert!(metadata.size > 0);
}

#[test]
fn test_analysis_config_default() {
    let config = AnalysisConfig::default();
    assert!(config.enable_disassembly);
    assert!(config.enable_control_flow);
    assert!(config.enable_entropy);
    assert!(config.enable_symbols);
    assert_eq!(config.max_analysis_size, 100 * 1024 * 1024);
    assert!(config.architecture_hint.is_none());
}

#[test]
fn test_analyzer_default() {
    let analyzer1 = BinaryAnalyzer::default();
    let analyzer2 = BinaryAnalyzer::new();

    // Both should have same configuration
    assert_eq!(
        analyzer1.config().enable_disassembly,
        analyzer2.config().enable_disassembly
    );
    assert_eq!(
        analyzer1.config().enable_control_flow,
        analyzer2.config().enable_control_flow
    );
    assert_eq!(
        analyzer1.config().enable_entropy,
        analyzer2.config().enable_entropy
    );
    assert_eq!(
        analyzer1.config().enable_symbols,
        analyzer2.config().enable_symbols
    );
}

#[test]
fn test_large_file_analysis() {
    let mut data = create_mock_elf_data();
    data.resize(5 * 1024 * 1024, 0); // 5MB file

    let config = AnalysisConfig {
        max_analysis_size: 1024 * 1024, // 1MB limit
        ..Default::default()
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data);

    // Should still work but might be limited by max_analysis_size
    assert!(result.is_ok());
}

#[test]
fn test_architecture_hint() {
    let data = create_mock_elf_data();

    let config = AnalysisConfig {
        architecture_hint: Some(Architecture::Arm64),
        ..Default::default()
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data);

    assert!(result.is_ok());
    // The hint might not override actual detection, but should not cause errors
}

#[test]
fn test_disabled_analysis_features() {
    let data = create_mock_elf_data();

    let config = AnalysisConfig {
        enable_disassembly: false,
        enable_control_flow: false,
        enable_entropy: false,
        enable_symbols: false,
        ..Default::default()
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data);

    assert!(result.is_ok());
    let analysis = result.unwrap();

    // Optional analyses should be None when disabled
    assert!(analysis.disassembly.is_none());
    assert!(analysis.control_flow.is_none());
    assert!(analysis.entropy.is_none());
}

#[test]
fn test_concurrent_analysis() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(create_mock_elf_data());
    let mut handles = vec![];

    for _ in 0..5 {
        let data_clone = Arc::clone(&data);
        let handle = thread::spawn(move || {
            let analyzer = BinaryAnalyzer::new();
            analyzer.analyze(&data_clone)
        });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.format, BinaryFormat::Elf);
    }
}

#[test]
fn test_analysis_result_completeness() {
    let data = create_mock_elf_data();
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data).unwrap();

    // Verify all required fields are present
    assert_ne!(result.format, BinaryFormat::Unknown);
    assert_ne!(result.architecture, Architecture::Unknown);

    // Metadata should be populated
    assert_eq!(result.metadata.format, result.format);
    assert_eq!(result.metadata.architecture, result.architecture);
    assert!(result.metadata.size > 0);
}

#[test]
fn test_error_handling() {
    let analyzer = BinaryAnalyzer::new();

    // Test various error conditions
    let empty_data = vec![];
    assert!(analyzer.analyze(&empty_data).is_err());

    // Test corrupted data
    let corrupt_data = vec![0xff; 10];
    let result = analyzer.analyze(&corrupt_data);
    // Might succeed with Unknown format or fail - both acceptable
    if let Ok(analysis_result) = result {
        let format = analysis_result.format;
        assert!(matches!(format, BinaryFormat::Unknown | BinaryFormat::Raw));
    }
}

#[test]
fn test_analysis_performance() {
    let data = create_mock_elf_data();
    let analyzer = BinaryAnalyzer::new();

    let start = std::time::Instant::now();
    let result = analyzer.analyze(&data);
    let duration = start.elapsed();

    assert!(result.is_ok());
    assert!(duration.as_millis() < 1000); // Should complete within 1 second
}
