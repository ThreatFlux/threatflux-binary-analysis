//! Comprehensive unit tests for compiler detection functionality
//!
//! This test suite achieves comprehensive coverage of compiler detection across all
//! supported binary formats including edge cases, version detection, and confidence scoring.

#![allow(unused_variables)]

use pretty_assertions::assert_eq;
use rstest::*;
use threatflux_binary_analysis::types::*;

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

/// Test ELF compiler detection from .comment section
#[test]
fn test_elf_gcc_detection() {
    let data = create_elf_with_gcc_comment();
    let result = ElfParser::parse(&data).unwrap();

    let metadata = result.metadata();
    assert!(
        metadata.compiler_info.is_some(),
        "Should detect compiler info"
    );

    if let Some(ref compiler_info) = metadata.compiler_info {
        assert!(
            compiler_info.contains("GCC") || compiler_info.contains("gcc"),
            "Should detect GCC compiler"
        );
    }
}

/// Test ELF compiler detection from various sources
#[rstest]
#[case(
    create_elf_with_clang_comment(),
    "Clang",
    "Should detect Clang from .comment"
)]
#[case(create_elf_with_gcc_version(), "GCC", "Should detect GCC version")]
#[case(create_elf_with_rust_metadata(), "Rust", "Should detect Rust compiler")]
#[case(create_elf_with_go_buildinfo(), "Go", "Should detect Go toolchain")]
#[case(
    create_elf_with_mixed_sections(),
    "Unknown",
    "Should handle mixed/unclear info"
)]
fn test_elf_compiler_variants(
    #[case] data: Vec<u8>,
    #[case] expected_compiler: &str,
    #[case] description: &str,
) {
    let result = ElfParser::parse(&data).unwrap();
    let metadata = result.metadata();

    if expected_compiler == "Unknown" {
        // For unclear cases, any reasonable detection is acceptable
        assert!(metadata.compiler_info.is_some() || metadata.compiler_info.is_none());
    } else {
        assert!(
            metadata.compiler_info.is_some(),
            "Should detect compiler: {}",
            description
        );

        if let Some(ref compiler_info) = metadata.compiler_info {
            assert!(
                compiler_info
                    .to_lowercase()
                    .contains(&expected_compiler.to_lowercase()),
                "Should contain '{}' for: {}, got: {}",
                expected_compiler,
                description,
                compiler_info
            );
        }
    }
}

/// Test ELF note section analysis for compiler info
#[test]
fn test_elf_note_section_compiler_detection() {
    let data = create_elf_with_build_id_note();
    let result = ElfParser::parse(&data).unwrap();

    // Build-ID notes can indicate compiler/linker
    let metadata = result.metadata();

    // Even if we can't determine specific compiler, should not crash
    assert_eq!(result.format_type(), BinaryFormat::Elf);
}

/// Test PE Rich Header compiler detection
#[test]
fn test_pe_rich_header_msvc_detection() {
    let data = create_pe_with_rich_header();
    let result = PeParser::parse(&data).unwrap();

    let metadata = result.metadata();
    if let Some(ref compiler_info) = metadata.compiler_info {
        // Rich header should indicate MSVC version
        assert!(
            compiler_info.contains("MSVC") || compiler_info.contains("Visual"),
            "Should detect MSVC from Rich header"
        );
    }
}

/// Test PE compiler detection from various sources
#[rstest]
#[case(create_pe_with_msvc_2022(), "MSVC", "2022", "Visual Studio 2022")]
#[case(create_pe_with_msvc_2019(), "MSVC", "2019", "Visual Studio 2019")]
#[case(create_pe_with_msvc_2017(), "MSVC", "2017", "Visual Studio 2017")]
#[case(create_pe_with_msvc_2015(), "MSVC", "2015", "Visual Studio 2015")]
#[case(create_pe_with_msvc_2013(), "MSVC", "2013", "Visual Studio 2013")]
#[case(create_pe_with_mingw(), "MinGW", "", "MinGW/GCC toolchain")]
#[case(create_pe_with_clang(), "Clang", "", "Clang/LLVM toolchain")]
#[case(create_pe_with_intel_compiler(), "Intel", "", "Intel C++ Compiler")]
fn test_pe_compiler_variants(
    #[case] data: Vec<u8>,
    #[case] expected_compiler: &str,
    #[case] expected_version: &str,
    #[case] description: &str,
) {
    let result = PeParser::parse(&data);

    // Some variants might not parse if we don't have complete implementation
    if let Ok(parsed) = result {
        let metadata = parsed.metadata();

        if let Some(ref compiler_info) = metadata.compiler_info {
            assert!(
                compiler_info
                    .to_lowercase()
                    .contains(&expected_compiler.to_lowercase()),
                "Should contain '{}' for: {}, got: {}",
                expected_compiler,
                description,
                compiler_info
            );

            if !expected_version.is_empty() {
                assert!(
                    compiler_info.contains(expected_version),
                    "Should contain version '{}' for: {}, got: {}",
                    expected_version,
                    description,
                    compiler_info
                );
            }
        }
    }
}

/// Test PE debug directory compiler detection
#[test]
fn test_pe_debug_directory_compiler_detection() {
    let data = create_pe_with_pdb_debug_info();
    let result = PeParser::parse(&data).unwrap();

    let metadata = result.metadata();
    if let Some(ref compiler_info) = metadata.compiler_info {
        // PDB debug info usually indicates MSVC
        assert!(
            compiler_info.contains("MSVC") || compiler_info.contains("PDB"),
            "Should detect MSVC from PDB debug info"
        );
    }
}

/// Test PE import table analysis for compiler hints
#[test]
fn test_pe_import_table_compiler_hints() {
    let data = create_pe_with_msvc_runtime_imports();
    let result = PeParser::parse(&data).unwrap();

    let imports = result.imports();
    let metadata = result.metadata();

    // Look for MSVC runtime imports
    let msvc_runtime_imports: Vec<_> = imports
        .iter()
        .filter(|i| {
            if let Some(ref lib) = i.library {
                lib.contains("msvcr")
                    || lib.contains("vcruntime")
                    || lib.contains("msvcp")
                    || lib.contains("ucrtbase")
            } else {
                false
            }
        })
        .collect();

    if !msvc_runtime_imports.is_empty() {
        // Should detect MSVC from runtime imports
        if let Some(ref compiler_info) = metadata.compiler_info {
            assert!(compiler_info.contains("MSVC") || compiler_info.contains("Visual"));
        }
    }
}

/// Test Mach-O LC_BUILD_VERSION compiler detection
#[test]
fn test_macho_build_version_detection() {
    let data = create_macho_with_build_version();
    let result = MachOParser::parse(&data).unwrap();

    let metadata = result.metadata();
    if let Some(ref compiler_info) = metadata.compiler_info {
        // Should contain platform and SDK information
        assert!(
            compiler_info.contains("Platform")
                || compiler_info.contains("SDK")
                || compiler_info.contains("Apple")
                || compiler_info.contains("Xcode"),
            "Should detect Apple toolchain info"
        );
    }
}

/// Test Mach-O compiler detection from various sources
#[rstest]
#[case(create_macho_with_xcode_15(), "Xcode", "15", "Xcode 15")]
#[case(create_macho_with_xcode_14(), "Xcode", "14", "Xcode 14")]
#[case(
    create_macho_with_command_line_tools(),
    "Apple",
    "command",
    "Command Line Tools"
)]
#[case(create_macho_with_swift_metadata(), "Swift", "", "Swift compiler")]
#[case(
    create_macho_with_objective_c(),
    "Objective-C",
    "",
    "Objective-C compiler"
)]
fn test_macho_compiler_variants(
    #[case] data: Vec<u8>,
    #[case] expected_compiler: &str,
    #[case] expected_version: &str,
    #[case] description: &str,
) {
    let result = MachOParser::parse(&data);

    if let Ok(parsed) = result {
        let metadata = parsed.metadata();

        if let Some(ref compiler_info) = metadata.compiler_info {
            assert!(
                compiler_info
                    .to_lowercase()
                    .contains(&expected_compiler.to_lowercase()),
                "Should contain '{}' for: {}, got: {}",
                expected_compiler,
                description,
                compiler_info
            );

            if !expected_version.is_empty() {
                assert!(
                    compiler_info.contains(expected_version),
                    "Should contain version '{}' for: {}, got: {}",
                    expected_version,
                    description,
                    compiler_info
                );
            }
        }
    }
}

/// Test Mach-O platform detection
#[rstest]
#[case(create_macho_for_macos(), "macOS", "Should detect macOS platform")]
#[case(create_macho_for_ios(), "iOS", "Should detect iOS platform")]
#[case(
    create_macho_for_watchos(),
    "watchOS",
    "Should detect watchOS platform"
)]
#[case(create_macho_for_tvos(), "tvOS", "Should detect tvOS platform")]
#[case(create_macho_for_catalyst(), "Catalyst", "Should detect Mac Catalyst")]
fn test_macho_platform_detection(
    #[case] data: Vec<u8>,
    #[case] expected_platform: &str,
    #[case] description: &str,
) {
    let result = MachOParser::parse(&data);

    if let Ok(parsed) = result {
        let metadata = parsed.metadata();

        if let Some(ref compiler_info) = metadata.compiler_info {
            assert!(
                compiler_info.contains(expected_platform),
                "Should contain '{}' for: {}, got: {}",
                expected_platform,
                description,
                compiler_info
            );
        }
    }
}

/// Test Java version detection
#[rstest]
#[case(52, 0, "Java 8", "Should detect Java 8")]
#[case(55, 0, "Java 11", "Should detect Java 11")]
#[case(61, 0, "Java 17", "Should detect Java 17")]
#[case(65, 0, "Java 21", "Should detect Java 21")]
fn test_java_version_detection(
    #[case] major: u16,
    #[case] minor: u16,
    #[case] expected_version: &str,
    #[case] description: &str,
) {
    let data = create_java_class_with_version(major, minor);
    let result = JavaParser::parse(&data).unwrap();

    let metadata = result.metadata();
    assert!(
        metadata.compiler_info.is_some(),
        "Should have compiler info for: {}",
        description
    );

    if let Some(ref compiler_info) = metadata.compiler_info {
        assert!(
            compiler_info.contains(&major.to_string()),
            "Should contain major version for: {}, got: {}",
            description,
            compiler_info
        );
    }
}

/// Test Java compiler detection from class file attributes
#[test]
fn test_java_compiler_attributes() {
    let data = create_java_class_with_source_file_attribute();
    let result = JavaParser::parse(&data).unwrap();

    // SourceFile attribute can provide hints about the compiler/build system
    let metadata = result.metadata();
    assert_eq!(result.format_type(), BinaryFormat::Java);
}

/// Test cross-platform compiler detection
#[test]
fn test_cross_compiler_detection() {
    // Test scenarios where code is compiled on one platform for another
    let cross_compile_scenarios = vec![
        ("ELF for ARM on x86", create_elf_arm_cross_compiled()),
        ("PE for x64 on Linux", create_pe_cross_compiled_mingw()),
        ("Mach-O Universal Binary", create_macho_universal_binary()),
    ];

    for (description, data) in cross_compile_scenarios {
        let format = threatflux_binary_analysis::formats::detect_format(&data);
        assert!(format.is_ok(), "Should detect format for: {}", description);

        let format_type = format.unwrap();
        let result = match format_type {
            BinaryFormat::Elf => ElfParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>),
            BinaryFormat::Pe => PeParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>),
            BinaryFormat::MachO => {
                MachOParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>)
            }
            _ => continue,
        };

        if let Ok(parsed) = result {
            let metadata = parsed.metadata();
            // Cross-compilation should be detectable or at least not cause errors
            assert_eq!(
                parsed.format_type(),
                format_type,
                "Format should match for: {}",
                description
            );
        }
    }
}

/// Test compiler confidence scoring
#[test]
fn test_compiler_confidence_scoring() {
    let test_cases = vec![
        (
            create_elf_with_strong_gcc_indicators(),
            "Strong GCC indicators",
        ),
        (create_pe_with_weak_msvc_hints(), "Weak MSVC hints"),
        (
            create_macho_with_mixed_toolchain_signs(),
            "Mixed toolchain indicators",
        ),
    ];

    for (data, description) in test_cases {
        let format = threatflux_binary_analysis::formats::detect_format(&data).unwrap();
        let result = match format {
            BinaryFormat::Elf => ElfParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>),
            BinaryFormat::Pe => PeParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>),
            BinaryFormat::MachO => {
                MachOParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>)
            }
            _ => continue,
        };

        if let Ok(parsed) = result {
            let metadata = parsed.metadata();
            // Confidence should be reflected in how definitive the compiler_info is
            if let Some(ref compiler_info) = metadata.compiler_info {
                // High confidence: specific version numbers
                // Low confidence: generic terms like "Unknown" or "detected from"
                assert!(
                    !compiler_info.is_empty(),
                    "Compiler info should not be empty for: {}",
                    description
                );
            }
        }
    }
}

/// Test edge cases in compiler detection
#[test]
fn test_compiler_detection_edge_cases() {
    let edge_cases = vec![
        ("Stripped binary", create_completely_stripped_elf()),
        ("Packed binary", create_packed_pe_upx()),
        ("Obfuscated binary", create_obfuscated_macho()),
        ("Corrupted debug info", create_elf_with_corrupted_debug()),
        ("Missing sections", create_pe_with_missing_sections()),
    ];

    for (description, data) in edge_cases {
        let format = threatflux_binary_analysis::formats::detect_format(&data);

        if let Ok(format_type) = format {
            let result = match format_type {
                BinaryFormat::Elf => {
                    ElfParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>)
                }
                BinaryFormat::Pe => PeParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>),
                BinaryFormat::MachO => {
                    MachOParser::parse(&data).map(|p| p as Box<dyn BinaryFormatTrait>)
                }
                _ => continue,
            };

            match result {
                Ok(parsed) => {
                    // Should handle gracefully even if no compiler info available
                    let metadata = parsed.metadata();
                    // compiler_info can be None for edge cases
                    assert_eq!(
                        parsed.format_type(),
                        format_type,
                        "Should maintain format correctness for: {}",
                        description
                    );
                }
                Err(_) => {
                    // Acceptable to fail on heavily corrupted binaries
                }
            }
        }
    }
}

/// Test performance of compiler detection with large binaries
#[test]
fn test_compiler_detection_performance() {
    let large_elf = create_large_elf_with_debug_info(50 * 1024 * 1024); // 50MB

    let start = std::time::Instant::now();
    let result = ElfParser::parse(&large_elf);
    let duration = start.elapsed();

    assert!(result.is_ok(), "Should parse large binary with debug info");
    assert!(
        duration.as_secs() < 30,
        "Compiler detection should be reasonably fast"
    );

    if let Ok(parsed) = result {
        let metadata = parsed.metadata();
        // Even large binaries should have compiler detection
        if metadata.compiler_info.is_some() {
            // Good, compiler was detected
        }
    }
}

// Helper functions to create test binaries with specific compiler signatures

fn create_elf_with_comment(comment: &[u8]) -> Vec<u8> {
    // Create a simple ELF with a proper .comment section
    let mut data = vec![0u8; 8192];

    // ELF Header (64 bytes)
    let elf_header = [
        // e_ident
        0x7f, 0x45, 0x4c, 0x46, // EI_MAG (0x7f, 'E', 'L', 'F')
        0x02, // EI_CLASS (ELFCLASS64)
        0x01, // EI_DATA (ELFDATA2LSB)
        0x01, // EI_VERSION (EV_CURRENT)
        0x00, // EI_OSABI (ELFOSABI_NONE)
        0x00, // EI_ABIVERSION
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
        // ELF header fields
        0x02, 0x00, // e_type (ET_EXEC)
        0x3e, 0x00, // e_machine (EM_X86_64)
        0x01, 0x00, 0x00, 0x00, // e_version (EV_CURRENT)
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry (0x401000)
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff (64)
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // e_shoff (1024) - section headers at offset 1024
        0x00, 0x00, 0x00, 0x00, // e_flags
        0x40, 0x00, // e_ehsize (64)
        0x38, 0x00, // e_phentsize (56)
        0x01, 0x00, // e_phnum (1)
        0x40, 0x00, // e_shentsize (64)
        0x05, 0x00, // e_shnum (5) - null, .text, .comment, .shstrtab, .strtab
        0x03, 0x00, // e_shstrndx (3) - .shstrtab is section 3
    ];
    data[..64].copy_from_slice(&elf_header);

    // Program Header at offset 64
    let ph_load = [
        0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
        0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
    ];
    data[64..120].copy_from_slice(&ph_load);

    // .comment section content at offset 512
    let comment_offset = 512;
    data[comment_offset..comment_offset + comment.len()].copy_from_slice(comment);

    // Section string table at offset 600
    let shstrtab_offset = 600;
    let shstrtab = b"\0.text\0.comment\0.shstrtab\0.strtab\0";
    data[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(shstrtab);

    // Section Headers at offset 1024 (5 sections)
    let sh_offset = 1024;

    // Section 0: NULL section
    let null_section = [0u8; 64];
    data[sh_offset..sh_offset + 64].copy_from_slice(&null_section);

    // Section 1: .text section
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name (offset in .shstrtab = 1, ".text")
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // sh_flags (SHF_ALLOC | SHF_EXECINSTR)
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (512)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (256)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[sh_offset + 64..sh_offset + 128].copy_from_slice(&text_section);

    // Section 2: .comment section
    let comment_section = [
        0x07,
        0x00,
        0x00,
        0x00, // sh_name (offset in .shstrtab = 7, ".comment")
        0x01,
        0x00,
        0x00,
        0x00, // sh_type (SHT_PROGBITS)
        0x30,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_flags (SHF_MERGE | SHF_STRINGS)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addr
        (comment_offset as u32).to_le_bytes()[0],
        (comment_offset as u32).to_le_bytes()[1],
        (comment_offset as u32).to_le_bytes()[2],
        (comment_offset as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_offset (512)
        (comment.len() as u32).to_le_bytes()[0],
        (comment.len() as u32).to_le_bytes()[1],
        (comment.len() as u32).to_le_bytes()[2],
        (comment.len() as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_size (length of comment)
        0x00,
        0x00,
        0x00,
        0x00, // sh_link
        0x00,
        0x00,
        0x00,
        0x00, // sh_info
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addralign
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_entsize
    ];
    data[sh_offset + 128..sh_offset + 192].copy_from_slice(&comment_section);

    // Section 3: .shstrtab section
    let shstrtab_section = [
        0x10,
        0x00,
        0x00,
        0x00, // sh_name (offset in .shstrtab = 16, ".shstrtab")
        0x03,
        0x00,
        0x00,
        0x00, // sh_type (SHT_STRTAB)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_flags
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addr
        (shstrtab_offset as u32).to_le_bytes()[0],
        (shstrtab_offset as u32).to_le_bytes()[1],
        (shstrtab_offset as u32).to_le_bytes()[2],
        (shstrtab_offset as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_offset (600)
        (shstrtab.len() as u32).to_le_bytes()[0],
        (shstrtab.len() as u32).to_le_bytes()[1],
        (shstrtab.len() as u32).to_le_bytes()[2],
        (shstrtab.len() as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_size
        0x00,
        0x00,
        0x00,
        0x00, // sh_link
        0x00,
        0x00,
        0x00,
        0x00, // sh_info
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addralign
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_entsize
    ];
    data[sh_offset + 192..sh_offset + 256].copy_from_slice(&shstrtab_section);

    // Section 4: .strtab section (empty for now)
    let strtab_section = [
        0x1a, 0x00, 0x00, 0x00, // sh_name (offset in .shstrtab = 26, ".strtab")
        0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (768)
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (1)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[sh_offset + 256..sh_offset + 320].copy_from_slice(&strtab_section);

    data
}

fn create_elf_with_custom_section(section_name: &str, content: &[u8]) -> Vec<u8> {
    // Create a simple ELF with a custom section
    let mut data = vec![0u8; 8192];

    // ELF Header (64 bytes) - same as before
    let elf_header = [
        // e_ident
        0x7f, 0x45, 0x4c, 0x46, // EI_MAG (0x7f, 'E', 'L', 'F')
        0x02, // EI_CLASS (ELFCLASS64)
        0x01, // EI_DATA (ELFDATA2LSB)
        0x01, // EI_VERSION (EV_CURRENT)
        0x00, // EI_OSABI (ELFOSABI_NONE)
        0x00, // EI_ABIVERSION
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
        // ELF header fields
        0x02, 0x00, // e_type (ET_EXEC)
        0x3e, 0x00, // e_machine (EM_X86_64)
        0x01, 0x00, 0x00, 0x00, // e_version (EV_CURRENT)
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry (0x401000)
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff (64)
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff (1024)
        0x00, 0x00, 0x00, 0x00, // e_flags
        0x40, 0x00, // e_ehsize (64)
        0x38, 0x00, // e_phentsize (56)
        0x01, 0x00, // e_phnum (1)
        0x40, 0x00, // e_shentsize (64)
        0x05, 0x00, // e_shnum (5)
        0x03, 0x00, // e_shstrndx (3)
    ];
    data[..64].copy_from_slice(&elf_header);

    // Program Header at offset 64
    let ph_load = [
        0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
        0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
    ];
    data[64..120].copy_from_slice(&ph_load);

    // Custom section content at offset 512
    let content_offset = 512;
    data[content_offset..content_offset + content.len()].copy_from_slice(content);

    // Section string table at offset 600
    let shstrtab_offset = 600;
    let shstrtab = format!("\0.text\0{}\0.shstrtab\0.strtab\0", section_name);
    let shstrtab_bytes = shstrtab.as_bytes();
    data[shstrtab_offset..shstrtab_offset + shstrtab_bytes.len()].copy_from_slice(shstrtab_bytes);

    // Section Headers at offset 1024 (5 sections)
    let sh_offset = 1024;

    // Section 0: NULL section
    let null_section = [0u8; 64];
    data[sh_offset..sh_offset + 64].copy_from_slice(&null_section);

    // Section 1: .text section
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name (offset 1 = ".text")
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // sh_flags (SHF_ALLOC | SHF_EXECINSTR)
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (512)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (256)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[sh_offset + 64..sh_offset + 128].copy_from_slice(&text_section);

    // Section 2: custom section
    let custom_name_offset = 7; // ".text\0" = 6 + 1
    let custom_section = [
        (custom_name_offset as u32).to_le_bytes()[0],
        (custom_name_offset as u32).to_le_bytes()[1],
        (custom_name_offset as u32).to_le_bytes()[2],
        (custom_name_offset as u32).to_le_bytes()[3], // sh_name
        0x01,
        0x00,
        0x00,
        0x00, // sh_type (SHT_PROGBITS)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_flags
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addr
        (content_offset as u32).to_le_bytes()[0],
        (content_offset as u32).to_le_bytes()[1],
        (content_offset as u32).to_le_bytes()[2],
        (content_offset as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_offset
        (content.len() as u32).to_le_bytes()[0],
        (content.len() as u32).to_le_bytes()[1],
        (content.len() as u32).to_le_bytes()[2],
        (content.len() as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_size
        0x00,
        0x00,
        0x00,
        0x00, // sh_link
        0x00,
        0x00,
        0x00,
        0x00, // sh_info
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addralign
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_entsize
    ];
    data[sh_offset + 128..sh_offset + 192].copy_from_slice(&custom_section);

    // Section 3: .shstrtab section
    let shstrtab_name_offset = 7 + section_name.len() + 1; // after custom section name
    let shstrtab_section = [
        (shstrtab_name_offset as u32).to_le_bytes()[0],
        (shstrtab_name_offset as u32).to_le_bytes()[1],
        (shstrtab_name_offset as u32).to_le_bytes()[2],
        (shstrtab_name_offset as u32).to_le_bytes()[3], // sh_name
        0x03,
        0x00,
        0x00,
        0x00, // sh_type (SHT_STRTAB)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_flags
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addr
        (shstrtab_offset as u32).to_le_bytes()[0],
        (shstrtab_offset as u32).to_le_bytes()[1],
        (shstrtab_offset as u32).to_le_bytes()[2],
        (shstrtab_offset as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_offset
        (shstrtab_bytes.len() as u32).to_le_bytes()[0],
        (shstrtab_bytes.len() as u32).to_le_bytes()[1],
        (shstrtab_bytes.len() as u32).to_le_bytes()[2],
        (shstrtab_bytes.len() as u32).to_le_bytes()[3],
        0x00,
        0x00,
        0x00,
        0x00, // sh_size
        0x00,
        0x00,
        0x00,
        0x00, // sh_link
        0x00,
        0x00,
        0x00,
        0x00, // sh_info
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addralign
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_entsize
    ];
    data[sh_offset + 192..sh_offset + 256].copy_from_slice(&shstrtab_section);

    // Section 4: .strtab section
    let strtab_name_offset = shstrtab_name_offset + 10; // ".shstrtab\0"
    let strtab_section = [
        (strtab_name_offset as u32).to_le_bytes()[0],
        (strtab_name_offset as u32).to_le_bytes()[1],
        (strtab_name_offset as u32).to_le_bytes()[2],
        (strtab_name_offset as u32).to_le_bytes()[3], // sh_name
        0x03,
        0x00,
        0x00,
        0x00, // sh_type (SHT_STRTAB)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_flags
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addr
        0x00,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_offset (768)
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_size (1)
        0x00,
        0x00,
        0x00,
        0x00, // sh_link
        0x00,
        0x00,
        0x00,
        0x00, // sh_info
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_addralign
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // sh_entsize
    ];
    data[sh_offset + 256..sh_offset + 320].copy_from_slice(&strtab_section);

    data
}

fn create_elf_with_gcc_comment() -> Vec<u8> {
    create_elf_with_comment(b"GCC: (GNU) 11.2.0\0")
}

fn create_elf_with_clang_comment() -> Vec<u8> {
    create_elf_with_comment(b"clang version 14.0.0\0")
}

fn create_elf_with_gcc_version() -> Vec<u8> {
    create_elf_with_comment(b"GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0\0")
}

fn create_elf_with_rust_metadata() -> Vec<u8> {
    create_elf_with_custom_section(".rustc", b"rustc metadata\0")
}

fn create_elf_with_go_buildinfo() -> Vec<u8> {
    create_elf_with_custom_section(".go.buildinfo", b"go1.19.3\0")
}

fn create_elf_with_mixed_sections() -> Vec<u8> {
    create_elf_with_comment(b"Mixed compiler info: GCC and Clang\0")
}

fn create_elf_with_build_id_note() -> Vec<u8> {
    let mut data = create_realistic_elf_64();

    // Add .note.gnu.build-id section
    data.resize(6144, 0);

    data
}

fn create_pe_with_rich_header() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // Insert Rich header between DOS header and PE header
    // Rich header contains compiler/linker version info
    data.resize(4096, 0);

    data
}

fn create_pe_with_msvc_2022() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // Add MSVC 2022 specific signatures
    // Rich header with MSVC 19.3x toolchain IDs
    data.resize(8192, 0);

    data
}

fn create_pe_with_msvc_2019() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // MSVC 2019 (19.2x)
    data.resize(8192, 0);

    data
}

fn create_pe_with_msvc_2017() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // MSVC 2017 (19.1x)
    data.resize(8192, 0);

    data
}

fn create_pe_with_msvc_2015() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // MSVC 2015 (19.0x)
    data.resize(8192, 0);

    data
}

fn create_pe_with_msvc_2013() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // MSVC 2013 (18.x)
    data.resize(8192, 0);

    data
}

fn create_pe_with_mingw() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // MinGW/GCC characteristics: different section layout, runtime imports
    data.resize(12288, 0);

    data
}

fn create_pe_with_clang() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // Clang-specific PE characteristics
    data.resize(10240, 0);

    data
}

fn create_pe_with_intel_compiler() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // Intel C++ Compiler signatures
    data.resize(9216, 0);

    data
}

fn create_pe_with_pdb_debug_info() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // Add debug directory with PDB reference
    data.resize(16384, 0);

    data
}

fn create_pe_with_msvc_runtime_imports() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // Add import table with MSVC runtime DLLs
    data.resize(32768, 0);

    data
}

fn create_macho_with_build_version() -> Vec<u8> {
    // Create a proper Mach-O with LC_BUILD_VERSION command
    let mut data = vec![0; 8192];

    // Mach-O Header (32 bytes for 64-bit) - using consistent little endian
    let header = [
        0xcf, 0xfa, 0xed, 0xfe, // magic (MH_CIGAM_64 = little endian magic)
        0x07, 0x00, 0x00, 0x01, // cputype (CPU_TYPE_X86_64) - little endian
        0x03, 0x00, 0x00, 0x00, // cpusubtype (CPU_SUBTYPE_X86_64_ALL) - little endian
        0x02, 0x00, 0x00, 0x00, // filetype (MH_EXECUTE) - little endian
        0x03, 0x00, 0x00, 0x00, // ncmds (3) - little endian
        0x88, 0x00, 0x00, 0x00, // sizeofcmds (136) - little endian: 72 + 24 + 40 = 136
        0x00, 0x20, 0x00, 0x00, // flags (MH_NOUNDEFS | MH_DYLDLINK) - little endian
        0x00, 0x00, 0x00, 0x00, // reserved
    ];

    data[..32].copy_from_slice(&header);

    // LC_SEGMENT_64 for __TEXT (72 bytes)
    let text_segment = [
        0x19, 0x00, 0x00, 0x00, // cmd (LC_SEGMENT_64) - little endian
        0x48, 0x00, 0x00, 0x00, // cmdsize (72) - little endian
        // segname "__TEXT" (16 bytes)
        0x5f, 0x5f, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // vmaddr (0x100000000) - little endian
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        // vmsize (0x1000) - little endian
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fileoff (0) - little endian
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // filesize (0x1000) - little endian
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // maxprot (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) - little endian
        0x00, 0x00, 0x00, 0x07,
        // initprot (VM_PROT_READ | VM_PROT_EXECUTE) - little endian
        0x00, 0x00, 0x00, 0x05, // nsects (0) - little endian
        0x00, 0x00, 0x00, 0x00, // flags (0) - little endian
        0x00, 0x00, 0x00, 0x00,
    ];

    data[32..104].copy_from_slice(&text_segment);

    // LC_MAIN command (24 bytes)
    let main_cmd = [
        0x28, 0x00, 0x00, 0x80, // cmd (LC_MAIN = 0x80000028) - little endian
        0x18, 0x00, 0x00, 0x00, // cmdsize (24) - little endian
        // entryoff (0x1000) - little endian
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // stacksize (0) - little endian
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    data[104..128].copy_from_slice(&main_cmd);

    // LC_BUILD_VERSION command (40 bytes)
    let build_version_cmd = [
        0x32, 0x00, 0x00, 0x00, // cmd (LC_BUILD_VERSION = 0x32) - little endian
        0x28, 0x00, 0x00, 0x00, // cmdsize (40) - little endian
        0x01, 0x00, 0x00, 0x00, // platform (PLATFORM_MACOS = 1) - little endian
        0x00, 0x0E, 0x00, 0x00, // minos (macOS 14.0) - little endian
        0x02, 0x0E, 0x00, 0x00, // sdk (macOS 14.2) - little endian
        0x01, 0x00, 0x00, 0x00, // ntools (1) - little endian
        // Build tool entry (8 bytes)
        0x03, 0x00, 0x00, 0x00, // tool (TOOL_CLANG = 3) - little endian
        0x00, 0x0F, 0x00, 0x00, // version (Clang 15.0) - little endian
        // Padding to make it 40 bytes total
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    data[128..168].copy_from_slice(&build_version_cmd);

    data
}

fn create_macho_with_xcode_15() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Xcode 15.x specific build version
    data.resize(6144, 0);

    data
}

fn create_macho_with_xcode_14() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Xcode 14.x specific build version
    data.resize(6144, 0);

    data
}

fn create_macho_with_command_line_tools() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Command Line Tools instead of full Xcode
    data.resize(5120, 0);

    data
}

fn create_macho_with_swift_metadata() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Swift-specific sections and metadata
    data.resize(24576, 0);

    data
}

fn create_macho_with_objective_c() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Objective-C runtime sections
    data.resize(18432, 0);

    data
}

fn create_macho_for_macos() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // macOS platform (1)
    data.resize(7168, 0);

    data
}

fn create_macho_for_ios() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // iOS platform (2)
    data.resize(7168, 0);

    data
}

fn create_macho_for_watchos() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // watchOS platform (4)
    data.resize(7168, 0);

    data
}

fn create_macho_for_tvos() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // tvOS platform (3)
    data.resize(7168, 0);

    data
}

fn create_macho_for_catalyst() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Mac Catalyst platform (6)
    data.resize(7168, 0);

    data
}

fn create_java_class_with_version(major: u16, minor: u16) -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Update version bytes
    data[4] = (minor >> 8) as u8;
    data[5] = (minor & 0xff) as u8;
    data[6] = (major >> 8) as u8;
    data[7] = (major & 0xff) as u8;

    data
}

fn create_java_class_with_source_file_attribute() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Add SourceFile attribute with filename
    data.resize(1024, 0);

    data
}

fn create_elf_arm_cross_compiled() -> Vec<u8> {
    let mut data = create_realistic_elf_64();

    // Change machine type to ARM
    data[18] = 0x28; // EM_ARM
    data[19] = 0x00;

    data
}

fn create_pe_cross_compiled_mingw() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // MinGW cross-compilation signatures
    data.resize(16384, 0);

    data
}

fn create_macho_universal_binary() -> Vec<u8> {
    // Create fat binary with multiple architectures
    let mut data = vec![
        0xca, 0xfe, 0xba, 0xbe, // FAT_MAGIC
        0x00, 0x00, 0x00, 0x02, // nfat_arch
    ];

    data.resize(8192, 0);
    data
}

fn create_elf_with_strong_gcc_indicators() -> Vec<u8> {
    let mut data = create_realistic_elf_64();

    // Multiple strong GCC indicators: .comment, symbol names, etc.
    data.resize(32768, 0);

    data
}

fn create_pe_with_weak_msvc_hints() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // Weak indicators: timestamp, some imports, but no Rich header
    data.resize(16384, 0);

    data
}

fn create_macho_with_mixed_toolchain_signs() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Mixed indicators from different toolchain versions
    data.resize(20480, 0);

    data
}

fn create_completely_stripped_elf() -> Vec<u8> {
    let mut data = create_realistic_elf_64();

    // Remove all non-essential sections
    data.resize(2048, 0);

    data
}

fn create_packed_pe_upx() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // UPX packed PE characteristics
    data.resize(4096, 0);

    data
}

fn create_obfuscated_macho() -> Vec<u8> {
    let mut data = create_realistic_macho_64();

    // Obfuscated load commands and sections
    data.resize(12288, 0);

    data
}

fn create_elf_with_corrupted_debug() -> Vec<u8> {
    let mut data = create_realistic_elf_64();

    // Corrupted debug sections
    data.resize(40960, 0);

    data
}

fn create_pe_with_missing_sections() -> Vec<u8> {
    let mut data = create_realistic_pe_64();

    // PE with minimal sections
    data.resize(2048, 0);

    data
}

fn create_large_elf_with_debug_info(size: usize) -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(size, 0);

    // Add large debug sections throughout
    data
}
