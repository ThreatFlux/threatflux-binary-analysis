#![allow(clippy::uninlined_format_args)]
//! Tests for binary format detection

use threatflux_binary_analysis::formats;
use threatflux_binary_analysis::types::*;

// ELF magic bytes
#[cfg(feature = "elf")]
const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46]; // "\x7fELF"

// PE magic bytes (MZ header)
#[cfg(feature = "pe")]
const PE_MAGIC: [u8; 2] = [0x4d, 0x5a]; // "MZ"

// Mach-O magic bytes
#[cfg(feature = "macho")]
const MACHO_32_MAGIC: [u8; 4] = [0xfe, 0xed, 0xfa, 0xce];
#[cfg(feature = "macho")]
const MACHO_64_MAGIC: [u8; 4] = [0xfe, 0xed, 0xfa, 0xcf];

// Java class file magic
#[cfg(feature = "java")]
const JAVA_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];

// WebAssembly magic
#[cfg(feature = "wasm")]
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d]; // "\0asm"

fn create_test_data(magic: &[u8]) -> Vec<u8> {
    let mut data = magic.to_vec();
    data.extend_from_slice(&[0u8; 1024]); // Pad with zeros
    data
}

#[test]
#[cfg(feature = "elf")]
fn test_detect_elf_format() {
    let data = create_test_data(&ELF_MAGIC);
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Elf);
}

#[test]
#[cfg(feature = "pe")]
fn test_detect_pe_format() {
    let mut data = create_test_data(&PE_MAGIC);
    // Add PE signature at offset 0x3c
    data[0x3c] = 0x80; // PE header offset
    data[0x3d] = 0x00;
    data[0x80] = 0x50; // "PE\0\0"
    data[0x81] = 0x45;
    data[0x82] = 0x00;
    data[0x83] = 0x00;

    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Pe);
}

#[test]
#[cfg(feature = "macho")]
fn test_detect_macho_32_format() {
    let data = create_test_data(&MACHO_32_MAGIC);
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::MachO);
}

#[test]
#[cfg(feature = "macho")]
fn test_detect_macho_64_format() {
    let data = create_test_data(&MACHO_64_MAGIC);
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::MachO);
}

#[test]
#[cfg(feature = "java")]
fn test_detect_java_format() {
    let data = create_test_data(&JAVA_MAGIC);
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Java);
}

#[test]
#[cfg(feature = "java")]
fn test_detect_java_jar_format() {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        zip.start_file("Test.class", FileOptions::default())
            .unwrap();
        zip.write_all(b"\xca\xfe\xba\xbe").unwrap();
        zip.finish().unwrap();
    }
    let data = cursor.into_inner();
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Java);
}

#[test]
#[cfg(feature = "wasm")]
fn test_detect_wasm_format() {
    let data = create_test_data(&WASM_MAGIC);
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Wasm);
}

#[test]
fn test_detect_unknown_format() {
    let data = vec![0x00, 0x01, 0x02, 0x03]; // Random bytes
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Raw);
}

#[test]
fn test_detect_empty_data() {
    let data = vec![];
    let result = formats::detect_format(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_too_small_data() {
    let data = vec![0x7f]; // Too small for any magic
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Raw);
}

#[test]
#[cfg(all(feature = "elf", feature = "pe"))]
fn test_format_precedence() {
    // Test that PE is detected when MZ magic is at the beginning
    let mut data = create_test_data(&ELF_MAGIC);
    data[0] = 0x4d; // Overwrite with MZ signature
    data[1] = 0x5a;

    let format = formats::detect_format(&data).unwrap();
    // Should detect as PE since MZ magic comes first in detection order
    assert_eq!(format, BinaryFormat::Pe);
}

#[test]
fn test_partial_magic_bytes() {
    // Test partial ELF magic (should not match)
    let data = vec![0x7f, 0x45, 0x4c]; // Missing 'F'
    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Raw);
}

#[test]
#[cfg(feature = "pe")]
fn test_pe_without_signature() {
    // PE header without proper PE signature
    let data = create_test_data(&PE_MAGIC);
    let format = formats::detect_format(&data).unwrap();
    // Current implementation detects PE based on MZ magic alone
    assert_eq!(format, BinaryFormat::Pe);
}

#[test]
#[cfg(feature = "pe")]
fn test_corrupted_pe_header() {
    let mut data = create_test_data(&PE_MAGIC);
    data[0x3c] = 0xff; // Invalid PE header offset
    data[0x3d] = 0xff;

    let format = formats::detect_format(&data).unwrap();
    // Current implementation detects PE based on MZ magic alone
    assert_eq!(format, BinaryFormat::Pe);
}

#[test]
#[cfg(feature = "java")]
fn test_java_version_variants() {
    // Test different Java class file versions
    let mut data = create_test_data(&JAVA_MAGIC);

    // Set version bytes (major/minor version)
    data[4] = 0x00; // Minor version
    data[5] = 0x03;
    data[6] = 0x00; // Major version
    data[7] = 0x34; // Java 8

    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Java);
}

#[test]
#[cfg(feature = "wasm")]
fn test_wasm_version() {
    let mut data = create_test_data(&WASM_MAGIC);

    // Add version bytes
    data[4] = 0x01; // Version 1
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = 0x00;

    let format = formats::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Wasm);
}

#[test]
#[cfg(feature = "elf")]
fn test_format_confidence_scoring() {
    // Test that format detection considers multiple factors
    let mut elf_data = create_test_data(&ELF_MAGIC);

    // Add valid ELF header fields
    elf_data[4] = 0x02; // 64-bit
    elf_data[5] = 0x01; // Little endian
    elf_data[6] = 0x01; // Current version
    elf_data[7] = 0x00; // Generic ABI

    let format = formats::detect_format(&elf_data).unwrap();
    assert_eq!(format, BinaryFormat::Elf);
}

#[test]
fn test_archive_format_detection() {
    // Test that archive formats are not confused with executables
    let ar_magic = b"!<arch>\n";
    let data = create_test_data(ar_magic);

    let format = formats::detect_format(&data).unwrap();
    // Should be detected as raw since we don't support archive formats
    assert_eq!(format, BinaryFormat::Raw);
}

#[test]
fn test_text_file_detection() {
    // Test that plain text files are properly handled
    let text_data = b"#!/bin/bash\necho 'Hello World'\n";

    let format = formats::detect_format(text_data).unwrap();
    assert_eq!(format, BinaryFormat::Raw);
}

#[test]
fn test_binary_data_patterns() {
    // Test various binary patterns that could be mistaken for valid formats
    let patterns = vec![
        vec![0x50, 0x4b, 0x03, 0x04], // ZIP magic
        vec![0x1f, 0x8b, 0x08, 0x00], // GZIP magic
        vec![0x42, 0x5a, 0x68, 0x39], // BZIP2 magic
        vec![0xff, 0xd8, 0xff, 0xe0], // JPEG magic
        vec![0x89, 0x50, 0x4e, 0x47], // PNG magic
    ];

    for pattern in patterns {
        let data = create_test_data(&pattern);
        let format = formats::detect_format(&data).unwrap();
        assert_eq!(format, BinaryFormat::Raw);
    }
}

#[test]
#[cfg(any(feature = "elf", feature = "pe", feature = "macho"))]
fn test_minimum_file_sizes() {
    // Test that format detection handles minimum file size requirements

    #[cfg(feature = "elf")]
    {
        // ELF requires at least ELF header size
        let small_elf = ELF_MAGIC.to_vec();
        let format = formats::detect_format(&small_elf).unwrap();
        assert_eq!(format, BinaryFormat::Elf); // Should still detect basic magic
    }

    #[cfg(feature = "pe")]
    {
        // PE requires DOS header + PE header
        let small_pe = PE_MAGIC.to_vec();
        let format = formats::detect_format(&small_pe).unwrap();
        assert_eq!(format, BinaryFormat::Pe); // Should detect basic MZ magic
    }
}

#[test]
#[cfg(feature = "macho")]
fn test_endianness_detection() {
    // Test that endianness variants are properly handled

    // Mach-O little endian (32-bit)
    let macho_le = vec![0xce, 0xfa, 0xed, 0xfe];
    let format = formats::detect_format(&macho_le).unwrap();
    assert_eq!(format, BinaryFormat::MachO);

    // Mach-O big endian (32-bit)
    let macho_be = vec![0xfe, 0xed, 0xfa, 0xce];
    let format = formats::detect_format(&macho_be).unwrap();
    assert_eq!(format, BinaryFormat::MachO);
}

#[test]
#[cfg(feature = "elf")]
fn test_format_detection_performance() {
    // Test that format detection is efficient for large files
    let mut large_data = create_test_data(&ELF_MAGIC);
    large_data.resize(10 * 1024 * 1024, 0); // 10MB file

    let start = std::time::Instant::now();
    let format = formats::detect_format(&large_data).unwrap();
    let duration = start.elapsed();

    assert_eq!(format, BinaryFormat::Elf);
    assert!(duration.as_millis() < 100); // Should be fast (< 100ms)
}

#[test]
#[cfg(feature = "elf")]
fn test_concurrent_format_detection() {
    use std::sync::Arc;
    use std::thread;

    let test_data = Arc::new(create_test_data(&ELF_MAGIC));
    let mut handles = vec![];

    for _ in 0..10 {
        let data = Arc::clone(&test_data);
        let handle = thread::spawn(move || formats::detect_format(&data).unwrap());
        handles.push(handle);
    }

    for handle in handles {
        let format = handle.join().unwrap();
        assert_eq!(format, BinaryFormat::Elf);
    }
}
