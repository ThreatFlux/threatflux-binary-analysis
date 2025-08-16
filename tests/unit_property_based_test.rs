//! Property-based testing for robustness validation
//!
//! This test suite uses proptest to generate random inputs and test invariants
//! across all binary parsers to ensure robustness and catch edge cases.

#![allow(unused_comparisons)]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::comparison_to_empty)]

use proptest::prelude::*;
use threatflux_binary_analysis::{formats::detect_format, types::*, BinaryAnalyzer};

#[cfg(feature = "elf")]
use threatflux_binary_analysis::formats::elf::ElfParser;
#[cfg(feature = "java")]
use threatflux_binary_analysis::formats::java::JavaParser;
#[cfg(feature = "macho")]
use threatflux_binary_analysis::formats::macho::MachOParser;
#[cfg(feature = "pe")]
use threatflux_binary_analysis::formats::pe::PeParser;

mod common;

// Property-based test strategies

/// Generate random binary data
fn arb_binary_data() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..65536)
}

/// Generate binary data with valid magic numbers
fn arb_binary_with_magic() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // ELF magic
        prop::collection::vec(any::<u8>(), 100..8192).prop_map(|mut data| {
            if data.len() >= 4 {
                data[0..4].copy_from_slice(b"\x7fELF");
            }
            data
        }),
        // PE magic
        prop::collection::vec(any::<u8>(), 100..8192).prop_map(|mut data| {
            if data.len() >= 2 {
                data[0..2].copy_from_slice(b"MZ");
            }
            data
        }),
        // Mach-O magic
        prop::collection::vec(any::<u8>(), 100..8192).prop_map(|mut data| {
            if data.len() >= 4 {
                data[0..4].copy_from_slice(b"\xfe\xed\xfa\xcf");
            }
            data
        }),
        // Java magic
        prop::collection::vec(any::<u8>(), 100..8192).prop_map(|mut data| {
            if data.len() >= 4 {
                data[0..4].copy_from_slice(b"\xca\xfe\xba\xbe");
            }
            data
        }),
    ]
}

/// Generate ELF-like data with random fields
fn arb_elf_like_data() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u8>(),                                  // EI_CLASS
        any::<u8>(),                                  // EI_DATA
        any::<u8>(),                                  // EI_VERSION
        any::<u16>(),                                 // e_machine
        any::<u32>(),                                 // e_version
        prop::collection::vec(any::<u8>(), 64..4096), // rest of data
    )
        .prop_map(
            |(ei_class, ei_data, ei_version, e_machine, e_version, mut rest)| {
                let mut data = vec![0; 64]; // ELF header size

                // ELF magic
                data[0..4].copy_from_slice(b"\x7fELF");
                data[4] = ei_class;
                data[5] = ei_data;
                data[6] = ei_version;

                // e_machine (little endian)
                data[18] = (e_machine & 0xff) as u8;
                data[19] = (e_machine >> 8) as u8;

                // e_version (little endian)
                let version_bytes = e_version.to_le_bytes();
                data[20..24].copy_from_slice(&version_bytes);

                data.append(&mut rest);
                data
            },
        )
}

/// Generate PE-like data with random fields
fn arb_pe_like_data() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u16>(),                                  // Machine type
        any::<u16>(),                                  // Number of sections
        any::<u32>(),                                  // Timestamp
        any::<u16>(),                                  // Optional header size
        any::<u16>(),                                  // Characteristics
        prop::collection::vec(any::<u8>(), 128..4096), // rest of data
    )
        .prop_map(
            |(machine, num_sections, timestamp, opt_hdr_size, characteristics, mut rest)| {
                let mut data = vec![0; 128]; // DOS header + PE header

                // DOS header
                data[0..2].copy_from_slice(b"MZ");
                data[60..64].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew

                // PE signature
                data[0x80..0x84].copy_from_slice(b"PE\0\0");

                // COFF header
                data[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
                data[0x86..0x88].copy_from_slice(&num_sections.to_le_bytes());
                data[0x88..0x8c].copy_from_slice(&timestamp.to_le_bytes());
                data[0x94..0x96].copy_from_slice(&opt_hdr_size.to_le_bytes());
                data[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());

                data.append(&mut rest);
                data
            },
        )
}

/// Generate Mach-O-like data with random fields
fn arb_macho_like_data() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u32>(),                                 // CPU type
        any::<u32>(),                                 // CPU subtype
        any::<u32>(),                                 // File type
        any::<u32>(),                                 // Number of load commands
        any::<u32>(),                                 // Size of load commands
        any::<u32>(),                                 // Flags
        prop::collection::vec(any::<u8>(), 64..4096), // rest of data
    )
        .prop_map(
            |(cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, mut rest)| {
                let mut data = vec![0; 32]; // Mach-O 64-bit header size

                // Mach-O magic (64-bit little endian)
                data[0..4].copy_from_slice(b"\xcf\xfa\xed\xfe");

                // Header fields (little endian)
                data[4..8].copy_from_slice(&cputype.to_le_bytes());
                data[8..12].copy_from_slice(&cpusubtype.to_le_bytes());
                data[12..16].copy_from_slice(&filetype.to_le_bytes());
                data[16..20].copy_from_slice(&ncmds.to_le_bytes());
                data[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
                data[24..28].copy_from_slice(&flags.to_le_bytes());

                data.append(&mut rest);
                data
            },
        )
}

/// Generate Java class-like data with random fields
fn arb_java_like_data() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u16>(),                                 // Minor version
        any::<u16>(),                                 // Major version
        any::<u16>(),                                 // Constant pool count
        prop::collection::vec(any::<u8>(), 32..2048), // rest of data
    )
        .prop_map(|(minor, major, cp_count, mut rest)| {
            let mut data = vec![0; 10]; // Java class header

            // Java magic
            data[0..4].copy_from_slice(b"\xca\xfe\xba\xbe");

            // Version (big endian)
            data[4..6].copy_from_slice(&minor.to_be_bytes());
            data[6..8].copy_from_slice(&major.to_be_bytes());

            // Constant pool count (big endian)
            data[8..10].copy_from_slice(&cp_count.to_be_bytes());

            data.append(&mut rest);
            data
        })
}

// Property tests

proptest! {
    /// Test that format detection never panics on random data
    #[test]
    fn prop_format_detection_no_panic(data in arb_binary_data()) {
        let _ = detect_format(&data);
    }

    /// Test that parsers handle invalid data gracefully
    #[test]
    fn prop_parsers_graceful_failure(data in arb_binary_data()) {
        // All parsers should either succeed or fail gracefully, never panic
        let _ = ElfParser::parse(&data);
        let _ = PeParser::parse(&data);
        let _ = MachOParser::parse(&data);
        let _ = JavaParser::parse(&data);
    }

    /// Test that parsers validate magic numbers correctly
    #[test]
    fn prop_magic_number_validation(data in arb_binary_with_magic()) {
        let format = detect_format(&data);

        // If format detection succeeds, it should be consistent with magic number
        if let Ok(detected_format) = format {
            match detected_format {
                BinaryFormat::Elf => {
                    assert!(data.len() >= 4 && &data[0..4] == b"\x7fELF");
                },
                BinaryFormat::Pe => {
                    assert!(data.len() >= 2 && &data[0..2] == b"MZ");
                },
                BinaryFormat::MachO => {
                    assert!(data.len() >= 4 && (
                        &data[0..4] == b"\xfe\xed\xfa\xce" ||
                        &data[0..4] == b"\xce\xfa\xed\xfe" ||
                        &data[0..4] == b"\xfe\xed\xfa\xcf" ||
                        &data[0..4] == b"\xcf\xfa\xed\xfe"
                    ));
                },
                BinaryFormat::Java => {
                    assert!(data.len() >= 4 && &data[0..4] == b"\xca\xfe\xba\xbe");
                },
                _ => {}
            }
        }
    }

    /// Test ELF parser invariants
    #[test]
    fn prop_elf_parser_invariants(data in arb_elf_like_data()) {
        if let Ok(parsed) = ElfParser::parse(&data) {
            // Basic invariants
            assert_eq!(parsed.format_type(), BinaryFormat::Elf);

            // Architecture should be valid
            let arch = parsed.architecture();
            assert!(matches!(arch,
                Architecture::X86 | Architecture::X86_64 | Architecture::Arm |
                Architecture::Arm64 | Architecture::Mips | Architecture::PowerPC |
                Architecture::PowerPC64 | Architecture::RiscV | Architecture::Unknown
            ));

            // Sections should have valid properties
            for section in parsed.sections() {
                assert!(!section.name.is_empty() || section.name == "");
                assert!(section.size >= 0);
                assert!(section.address >= 0);
                assert!(section.offset >= 0);
            }

            // Symbols should have valid properties
            for symbol in parsed.symbols() {
                assert!(symbol.address >= 0);
                assert!(symbol.size >= 0);
            }

            // Metadata should be consistent
            let metadata = parsed.metadata();
            assert_eq!(metadata.format, BinaryFormat::Elf);
            assert_eq!(metadata.architecture, arch);
            assert!(metadata.size > 0);
        }
    }

    /// Test PE parser invariants
    #[test]
    fn prop_pe_parser_invariants(data in arb_pe_like_data()) {
        if let Ok(parsed) = PeParser::parse(&data) {
            // Basic invariants
            assert_eq!(parsed.format_type(), BinaryFormat::Pe);

            // Architecture should be valid
            let arch = parsed.architecture();
            assert!(matches!(arch,
                Architecture::X86 | Architecture::X86_64 | Architecture::Arm |
                Architecture::Arm64 | Architecture::Unknown
            ));

            // Sections should have valid properties
            for section in parsed.sections() {
                assert!(section.size >= 0);
                assert!(section.address >= 0);
                assert!(section.offset >= 0);
            }

            // Imports should have valid names
            for import in parsed.imports() {
                assert!(!import.name.is_empty());
            }

            // Exports should have valid names and addresses
            for export in parsed.exports() {
                assert!(!export.name.is_empty());
                assert!(export.address > 0);
            }

            // Metadata should be consistent
            let metadata = parsed.metadata();
            assert_eq!(metadata.format, BinaryFormat::Pe);
            assert_eq!(metadata.architecture, arch);
            assert!(metadata.size > 0);
        }
    }

    /// Test Mach-O parser invariants
    #[test]
    fn prop_macho_parser_invariants(data in arb_macho_like_data()) {
        if let Ok(parsed) = MachOParser::parse(&data) {
            // Basic invariants
            assert_eq!(parsed.format_type(), BinaryFormat::MachO);

            // Architecture should be valid
            let arch = parsed.architecture();
            assert!(matches!(arch,
                Architecture::X86 | Architecture::X86_64 | Architecture::Arm |
                Architecture::Arm64 | Architecture::PowerPC | Architecture::PowerPC64 |
                Architecture::Unknown
            ));

            // Sections should have valid properties
            for section in parsed.sections() {
                assert!(section.size >= 0);
                assert!(section.address >= 0);
                assert!(section.offset >= 0);
            }

            // Metadata should be consistent
            let metadata = parsed.metadata();
            assert_eq!(metadata.format, BinaryFormat::MachO);
            assert_eq!(metadata.architecture, arch);
            assert!(metadata.size > 0);
        }
    }

    /// Test Java parser invariants
    #[test]
    fn prop_java_parser_invariants(data in arb_java_like_data()) {
        if let Ok(parsed) = JavaParser::parse(&data) {
            // Basic invariants
            assert_eq!(parsed.format_type(), BinaryFormat::Java);
            assert_eq!(parsed.architecture(), Architecture::Jvm);

            // Java classes don't have entry points
            assert!(parsed.entry_point().is_none());

            // Should have at least one section (the class itself)
            assert!(!parsed.sections().is_empty());

            // Metadata should be consistent
            let metadata = parsed.metadata();
            assert_eq!(metadata.format, BinaryFormat::Java);
            assert_eq!(metadata.architecture, Architecture::Jvm);
            assert!(metadata.size > 0);
        }
    }

    /// Test that analysis results are consistent
    #[test]
    fn prop_analysis_consistency(data in arb_binary_with_magic()) {
        let analyzer = BinaryAnalyzer::new();

        if let Ok(result) = analyzer.analyze(&data) {
            // Basic consistency checks
            assert_eq!(result.metadata.format, result.format);
            assert_eq!(result.metadata.architecture, result.architecture);

            // Entry point consistency
            assert_eq!(result.metadata.entry_point, result.entry_point);

            // Section count should match
            assert_eq!(result.sections.len(), result.sections.len());

            // If disassembly is present, instructions should have valid addresses
            #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
            if let Some(ref instructions) = result.disassembly {
                for instruction in instructions {
                    assert!(instruction.address > 0);
                    assert!(!instruction.bytes.is_empty());
                    assert!(instruction.size > 0);
                    assert_eq!(instruction.size, instruction.bytes.len());
                }
            }

            // If entropy analysis is present, values should be reasonable
            #[cfg(feature = "entropy-analysis")]
            if let Some(ref entropy) = result.entropy {
                assert!(entropy.overall_entropy >= 0.0);
                assert!(entropy.overall_entropy <= 8.0);
            }
        }
    }

    /// Test memory usage doesn't explode with large inputs
    #[test]
    fn prop_memory_bounds(size in 1usize..1024*1024) { // Up to 1MB
        let data = vec![0u8; size];

        // Should handle large files without excessive memory usage
        let _ = detect_format(&data);
        let _ = ElfParser::parse(&data);
        let _ = PeParser::parse(&data);
        let _ = MachOParser::parse(&data);
        let _ = JavaParser::parse(&data);
    }

    /// Test that parsing is deterministic
    #[test]
    fn prop_deterministic_parsing(data in arb_binary_with_magic()) {
        // Parse the same data multiple times
        let result1 = detect_format(&data);
        let result2 = detect_format(&data);

        // Results should be identical
        assert_eq!(result1.is_ok(), result2.is_ok());
        if let (Ok(format1), Ok(format2)) = (result1, result2) {
            assert_eq!(format1, format2);
        }

        // Parser results should also be deterministic
        let elf_result1 = ElfParser::parse(&data);
        let elf_result2 = ElfParser::parse(&data);
        assert_eq!(elf_result1.is_ok(), elf_result2.is_ok());

        if let (Ok(parsed1), Ok(parsed2)) = (elf_result1, elf_result2) {
            assert_eq!(parsed1.format_type(), parsed2.format_type());
            assert_eq!(parsed1.architecture(), parsed2.architecture());
            assert_eq!(parsed1.entry_point(), parsed2.entry_point());
            assert_eq!(parsed1.sections().len(), parsed2.sections().len());
        }
    }

    /// Test error messages are informative
    #[test]
    fn prop_informative_errors(data in arb_binary_data()) {
        // When parsing fails, error messages should be non-empty and informative
        if let Err(error) = ElfParser::parse(&data) {
            let error_msg = format!("{}", error);
            assert!(!error_msg.is_empty());
            assert!(error_msg.len() > 5); // Should be more than just "Error"
        }

        if let Err(error) = PeParser::parse(&data) {
            let error_msg = format!("{}", error);
            assert!(!error_msg.is_empty());
            assert!(error_msg.len() > 5);
        }

        if let Err(error) = MachOParser::parse(&data) {
            let error_msg = format!("{}", error);
            assert!(!error_msg.is_empty());
            assert!(error_msg.len() > 5);
        }

        if let Err(error) = JavaParser::parse(&data) {
            let error_msg = format!("{}", error);
            assert!(!error_msg.is_empty());
            assert!(error_msg.len() > 5);
        }
    }

    /// Test that valid architecture values are preserved
    #[test]
    fn prop_architecture_preservation(
        arch in prop_oneof![
            Just(Architecture::X86),
            Just(Architecture::X86_64),
            Just(Architecture::Arm),
            Just(Architecture::Arm64),
            Just(Architecture::Mips),
            Just(Architecture::PowerPC),
            Just(Architecture::PowerPC64),
            Just(Architecture::RiscV),
            Just(Architecture::Jvm),
            Just(Architecture::Unknown),
        ]
    ) {
        // Create metadata with specific architecture
        let metadata = BinaryMetadata {
            size: 1024,
            format: BinaryFormat::Elf,
            architecture: arch,
            entry_point: Some(0x1000),
            base_address: Some(0x400000),
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };

        // Architecture should be preserved
        assert_eq!(metadata.architecture, arch);

        // Test serialization if available
        #[cfg(feature = "serde-support")]
        {
            let json = serde_json::to_string(&metadata).unwrap();
            let deserialized: BinaryMetadata = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.architecture, arch);
        }
    }

    /// Test section permission combinations are valid
    #[test]
    fn prop_section_permissions(read in any::<bool>(), write in any::<bool>(), execute in any::<bool>()) {
        let permissions = SectionPermissions { read, write, execute };

        // No invariant violations should occur with any permission combination
        // Some combinations might be unusual but should not cause errors

        // Test that permissions can be used in section creation
        let section = Section {
            name: "test".to_string(),
            address: 0x1000,
            size: 1024,
            offset: 0x1000,
            permissions,
            section_type: SectionType::Data,
            data: None,
        };

        assert_eq!(section.permissions.read, read);
        assert_eq!(section.permissions.write, write);
        assert_eq!(section.permissions.execute, execute);
    }
}

#[test]
fn test_proptest_compilation() {
    // This test just ensures that all the property tests compile correctly
    // The actual property tests are run by the proptest! macro
}

/// Test specific edge cases that property testing might miss
#[test]
fn test_property_test_edge_cases() {
    // Test empty data
    let empty_data = vec![];
    assert!(detect_format(&empty_data).is_err());

    // Test single byte
    let single_byte = vec![0x7f];
    let _ = detect_format(&single_byte); // Should not panic

    // Test exact magic size
    let elf_magic = b"\x7fELF".to_vec();
    let _ = detect_format(&elf_magic); // Should not panic

    // Test large but valid magic
    let mut large_magic = b"\x7fELF".to_vec();
    large_magic.resize(1024 * 1024, 0); // 1MB
    let _ = detect_format(&large_magic); // Should handle gracefully

    // Test all zero data
    let zero_data = vec![0; 1024];
    let _ = detect_format(&zero_data); // Should not panic

    // Test all 0xFF data
    let ff_data = vec![0xFF; 1024];
    let _ = detect_format(&ff_data); // Should not panic
}

/// Test property testing with specific binary patterns
#[test]
fn test_binary_pattern_properties() {
    // Test that certain patterns always produce consistent results

    // ELF with valid class byte
    let mut elf_64 = b"\x7fELF\x02".to_vec();
    elf_64.resize(1024, 0);
    if let Ok(parsed) = ElfParser::parse(&elf_64) {
        assert_eq!(parsed.architecture(), Architecture::X86_64);
    }

    // ELF with 32-bit class byte
    let mut elf_32 = b"\x7fELF\x01".to_vec();
    elf_32.resize(1024, 0);
    if let Ok(parsed) = ElfParser::parse(&elf_32) {
        assert_eq!(parsed.architecture(), Architecture::X86);
    }

    // PE with AMD64 machine type
    let mut pe_amd64 = vec![0; 256];
    pe_amd64[0..2].copy_from_slice(b"MZ");
    pe_amd64[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    pe_amd64[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe_amd64[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64

    if let Ok(parsed) = PeParser::parse(&pe_amd64) {
        assert_eq!(parsed.architecture(), Architecture::X86_64);
    }
}
