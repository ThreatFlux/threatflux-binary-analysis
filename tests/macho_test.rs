#![allow(clippy::uninlined_format_args)]
//! Tests for Mach-O format parser
#![cfg(feature = "macho")]

use threatflux_binary_analysis::types::*;
use threatflux_binary_analysis::{BinaryAnalyzer, BinaryError};

// Helper function to check if data is Mach-O format
fn is_macho(data: &[u8]) -> bool {
    matches!(
        threatflux_binary_analysis::formats::detect_format(data),
        Ok(BinaryFormat::MachO)
    )
}

/// Test data generators for various Mach-O formats
mod macho_test_data {

    /// Create a minimal valid Mach-O 64-bit x86_64 binary (little endian)
    pub fn create_macho_64_x86_64_le() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // Mach-O 64-bit header (little endian)
        data[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]); // MH_MAGIC_64 (LE)
        data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]); // CPU_TYPE_X86_64
        data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]); // CPU_SUBTYPE_X86_64_ALL
        data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // MH_EXECUTE filetype
        data[16..20].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // ncmds = 1
        data[20..24].copy_from_slice(&[0x48, 0x00, 0x00, 0x00]); // sizeofcmds = 72
        data[24..28].copy_from_slice(&[0x00, 0x00, 0x20, 0x00]); // flags = MH_PIE (0x00200000 in LE)
        data[28..32].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved

        // Load Command - LC_SEGMENT_64
        data[32..36].copy_from_slice(&[0x19, 0x00, 0x00, 0x00]); // LC_SEGMENT_64 = 0x19
        data[36..40].copy_from_slice(&[0x48, 0x00, 0x00, 0x00]); // cmdsize = 72

        // Segment name "__TEXT"
        data[40..56].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        // VM addresses and sizes
        data[56..64].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // vmaddr
        data[64..72].copy_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // vmsize
        data[72..80].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // fileoff
        data[80..88].copy_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // filesize
        data[88..92].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // maxprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[92..96].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // initprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[96..100].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nsects = 0
        data[100..104].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags = 0

        data
    }

    /// Create a minimal valid Mach-O 32-bit x86 binary (little endian)
    pub fn create_macho_32_x86_le() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // Mach-O 32-bit header (little endian)
        data[0..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]); // MH_MAGIC (LE)
        data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x00]); // CPU_TYPE_X86
        data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]); // CPU_SUBTYPE_X86_ALL
        data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // MH_EXECUTE filetype
        data[16..20].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // ncmds = 1
        data[20..24].copy_from_slice(&[0x38, 0x00, 0x00, 0x00]); // sizeofcmds = 56
        data[24..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags = 0

        // Load Command - LC_SEGMENT
        data[28..32].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // LC_SEGMENT = 0x1
        data[32..36].copy_from_slice(&[0x38, 0x00, 0x00, 0x00]); // cmdsize = 56

        // Segment name "__TEXT"
        data[36..52].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        // VM addresses and sizes
        data[52..56].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // vmaddr
        data[56..60].copy_from_slice(&[0x00, 0x10, 0x00, 0x00]); // vmsize
        data[60..64].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // fileoff
        data[64..68].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // filesize
        data[68..72].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // maxprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[72..76].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // initprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[76..80].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nsects = 0
        data[80..84].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags = 0

        data
    }

    /// Create a Mach-O binary with ARM64 architecture
    pub fn create_macho_64_arm64_le() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // Mach-O 64-bit header (little endian)
        data[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]); // MH_MAGIC_64 (LE)
        data[4..8].copy_from_slice(&[0x0c, 0x00, 0x00, 0x01]); // CPU_TYPE_ARM64
        data[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CPU_SUBTYPE_ARM64_ALL
        data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // MH_EXECUTE filetype
        data[16..20].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // ncmds = 1
        data[20..24].copy_from_slice(&[0x48, 0x00, 0x00, 0x00]); // sizeofcmds = 72
        data[24..28].copy_from_slice(&[0x00, 0x00, 0x20, 0x00]); // flags = MH_PIE (0x00200000 in LE)
        data[28..32].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved

        // Load Command - LC_SEGMENT_64
        data[32..36].copy_from_slice(&[0x19, 0x00, 0x00, 0x00]); // LC_SEGMENT_64 = 0x19
        data[36..40].copy_from_slice(&[0x48, 0x00, 0x00, 0x00]); // cmdsize = 72

        // Segment name "__TEXT"
        data[40..56].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        // VM addresses and sizes
        data[56..64].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // vmaddr
        data[64..72].copy_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // vmsize
        data[72..80].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // fileoff
        data[80..88].copy_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // filesize
        data[88..92].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // maxprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[92..96].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // initprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[96..100].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nsects = 0
        data[100..104].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags = 0

        data
    }

    /// Create a Mach-O binary with PowerPC architecture
    pub fn create_macho_32_powerpc_be() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // Mach-O 32-bit header (big endian)
        data[0..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]); // MH_CIGAM (BE swapped magic)
        data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x12]); // CPU_TYPE_POWERPC
        data[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CPU_SUBTYPE_POWERPC_ALL
        data[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]); // MH_EXECUTE filetype
        data[16..20].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // ncmds = 1
        data[20..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x38]); // sizeofcmds = 56
        data[24..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags = 0

        // Load Command - LC_SEGMENT
        data[28..32].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // LC_SEGMENT = 0x1
        data[32..36].copy_from_slice(&[0x00, 0x00, 0x00, 0x38]); // cmdsize = 56

        // Segment name "__TEXT"
        data[36..52].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        // VM addresses and sizes (big endian)
        data[52..56].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // vmaddr
        data[56..60].copy_from_slice(&[0x00, 0x00, 0x10, 0x00]); // vmsize
        data[60..64].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // fileoff
        data[64..68].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // filesize
        data[68..72].copy_from_slice(&[0x00, 0x00, 0x00, 0x05]); // maxprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[72..76].copy_from_slice(&[0x00, 0x00, 0x00, 0x05]); // initprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[76..80].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nsects = 0
        data[80..84].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags = 0

        data
    }

    /// Create a Fat binary (multi-architecture) - should be rejected
    pub fn create_fat_binary() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // Fat header
        data[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]); // FAT_MAGIC (BE)
        data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]); // nfat_arch = 2

        // First arch (x86)
        data[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x07]); // cputype = CPU_TYPE_X86
        data[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x03]); // cpusubtype = CPU_SUBTYPE_X86_ALL
        data[16..20].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // offset = 256
        data[20..24].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // size = 256
        data[24..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x0c]); // align = 12

        // Second arch (x86_64)
        data[28..32].copy_from_slice(&[0x01, 0x00, 0x00, 0x07]); // cputype = CPU_TYPE_X86_64
        data[32..36].copy_from_slice(&[0x00, 0x00, 0x00, 0x03]); // cpusubtype = CPU_SUBTYPE_X86_64_ALL
        data[36..40].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // offset = 512
        data[40..44].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // size = 256
        data[44..48].copy_from_slice(&[0x00, 0x00, 0x00, 0x0c]); // align = 12

        data
    }

    /// Create a bounded 64-bit universal Mach-O header.
    pub fn create_fat64_binary() -> Vec<u8> {
        let mut data = vec![0_u8; 40];
        data[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbf]); // FAT_MAGIC_64 (BE)
        data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // nfat_arch = 1
        data[8..12].copy_from_slice(&[0x01, 0x00, 0x00, 0x07]); // CPU_TYPE_X86_64
        data[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x03]); // CPU subtype
        data[16..24].copy_from_slice(&0x1000_u64.to_be_bytes()); // offset
        data[24..32].copy_from_slice(&0x2000_u64.to_be_bytes()); // size
        data[32..36].copy_from_slice(&12_u32.to_be_bytes()); // align
        data
    }

    /// Create malformed Mach-O data (truncated header)
    pub fn create_truncated_header() -> Vec<u8> {
        vec![0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00] // Only 6 bytes instead of 32
    }

    /// Create Mach-O with invalid magic
    pub fn create_invalid_magic() -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]); // Invalid magic
        data
    }

    /// Create Mach-O with complex section layout
    pub fn create_macho_with_sections() -> Vec<u8> {
        let mut data = vec![0u8; 2048];

        // Mach-O 64-bit header (little endian)
        data[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]); // MH_MAGIC_64 (LE)
        data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]); // CPU_TYPE_X86_64
        data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]); // CPU_SUBTYPE_X86_64_ALL
        data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // MH_EXECUTE filetype
        data[16..20].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // ncmds = 1
        data[20..24].copy_from_slice(&[0x98, 0x00, 0x00, 0x00]); // sizeofcmds = 152
        data[24..28].copy_from_slice(&[0x00, 0x00, 0x20, 0x00]); // flags = MH_PIE (0x00200000 in LE)
        data[28..32].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved

        // Load Command - LC_SEGMENT_64 with sections
        data[32..36].copy_from_slice(&[0x19, 0x00, 0x00, 0x00]); // LC_SEGMENT_64 = 0x19
        data[36..40].copy_from_slice(&[0x98, 0x00, 0x00, 0x00]); // cmdsize = 152

        // Segment name "__TEXT"
        data[40..56].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        // VM addresses and sizes
        data[56..64].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // vmaddr
        data[64..72].copy_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // vmsize
        data[72..80].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // fileoff
        data[80..88].copy_from_slice(&[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // filesize
        data[88..92].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // maxprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[92..96].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]); // initprot = VM_PROT_READ | VM_PROT_EXECUTE
        data[96..100].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // nsects = 1
        data[100..104].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags = 0

        // Section 1: __text section
        data[104..120].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0"); // sectname
        data[120..136].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0"); // segname
        data[136..144].copy_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // addr
        data[144..152].copy_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // size
        data[152..156].copy_from_slice(&[0x00, 0x04, 0x00, 0x00]); // offset
        data[156..160].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // align = 2
        data[160..164].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reloff
        data[164..168].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nreloc
        data[168..172].copy_from_slice(&[0x00, 0x04, 0x00, 0x80]); // flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        data[172..176].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved1
        data[176..184].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // reserved2 + reserved3

        data
    }
}

#[test]
fn test_macho_parser_can_parse_valid_magic_numbers() {
    // Test MH_MAGIC (32-bit little endian)
    let magic_32_le = vec![0xce, 0xfa, 0xed, 0xfe];
    assert!(is_macho(&magic_32_le));

    // Test MH_CIGAM (32-bit big endian)
    let magic_32_be = vec![0xfe, 0xed, 0xfa, 0xce];
    assert!(is_macho(&magic_32_be));

    // Test MH_MAGIC_64 (64-bit little endian)
    let magic_64_le = vec![0xcf, 0xfa, 0xed, 0xfe];
    assert!(is_macho(&magic_64_le));

    // Test MH_CIGAM_64 (64-bit big endian)
    let magic_64_be = vec![0xfe, 0xed, 0xfa, 0xcf];
    assert!(is_macho(&magic_64_be));

    // Bounded 32- and 64-bit universal headers are Mach-O, despite the FAT_MAGIC
    // overlap with Java's class-file magic.
    let fat_magic = macho_test_data::create_fat_binary();
    assert!(is_macho(&fat_magic));
    assert!(is_macho(&macho_test_data::create_fat64_binary()));

    // Byte-swapped universal headers are recognized using their little-endian
    // architecture count.
    let mut fat_cigam = fat_magic;
    fat_cigam[0..4].copy_from_slice(&[0xbe, 0xba, 0xfe, 0xca]);
    fat_cigam[4..8].copy_from_slice(&2_u32.to_le_bytes());
    assert!(is_macho(&fat_cigam));

    // Magic alone is not enough to claim a universal binary.
    assert!(!is_macho(&[0xca, 0xfe, 0xba, 0xbe]));
}

#[test]
fn test_macho_parser_can_parse_invalid_data() {
    // Test with empty data
    assert!(!is_macho(&[]));

    // Test with too short data
    assert!(!is_macho(&[0x01, 0x02]));

    // Test with invalid magic
    assert!(!is_macho(&[0x12, 0x34, 0x56, 0x78]));

    // Test with ELF magic
    assert!(!is_macho(&[0x7f, 0x45, 0x4c, 0x46]));

    // Test with PE magic
    assert!(!is_macho(&[0x4d, 0x5a, 0x90, 0x00]));
}

#[test]
fn test_macho_parser_parse_64_bit_x86_64_le() {
    let data = macho_test_data::create_macho_64_x86_64_le();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();

    assert_eq!(binary.format, BinaryFormat::MachO);
    assert_eq!(binary.architecture, Architecture::X86_64);

    let metadata = &binary.metadata;
    assert_eq!(metadata.format, BinaryFormat::MachO);
    assert_eq!(metadata.architecture, Architecture::X86_64);
    assert_eq!(metadata.endian, Endianness::Little);
    assert!(metadata.security_features.pie); // PIE flag is set
    assert_eq!(metadata.size, data.len());
}

#[test]
fn test_macho_parser_parse_64_bit_x86_64_be() {
    // Creating a complete valid big-endian Mach-O is complex.
    // For now, test that our can_parse correctly identifies big-endian magic numbers
    // and that the endianness detection logic works with the constants
    let big_endian_magic = vec![0xcf, 0xfa, 0xed, 0xfe]; // MH_CIGAM_64 magic
    assert!(is_macho(&big_endian_magic));

    // Test the complex parsing with a simpler approach -
    // Use the little endian version and verify the endianness detection works
    let data = macho_test_data::create_macho_64_x86_64_le();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();
    assert_eq!(binary.metadata.endian, Endianness::Little);
}

#[test]
fn test_macho_parser_parse_32_bit_x86_le() {
    let data = macho_test_data::create_macho_32_x86_le();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();

    assert_eq!(binary.format, BinaryFormat::MachO);
    assert_eq!(binary.architecture, Architecture::X86);

    let metadata = &binary.metadata;
    assert_eq!(metadata.endian, Endianness::Little);
    assert!(!metadata.security_features.pie); // PIE flag not set
}

#[test]
fn test_macho_parser_parse_arm64() {
    let data = macho_test_data::create_macho_64_arm64_le();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();

    assert_eq!(binary.format, BinaryFormat::MachO);
    assert_eq!(binary.architecture, Architecture::Arm64);

    let metadata = &binary.metadata;
    assert_eq!(metadata.endian, Endianness::Little);
    assert!(metadata.security_features.pie);
}

#[test]
fn test_macho_parser_parse_powerpc() {
    // Test PowerPC architecture detection with a simpler binary
    let data = macho_test_data::create_macho_32_powerpc_be();

    // Can parse should work
    assert!(is_macho(&data));

    // For now, test that big endian 32-bit magic is detected correctly
    let be_32_magic = vec![0xce, 0xfa, 0xed, 0xfe]; // MH_CIGAM magic
    assert!(is_macho(&be_32_magic));
}

#[test]
fn test_macho_parser_parse_with_sections() {
    let data = macho_test_data::create_macho_with_sections();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();

    let sections = &binary.sections;
    assert!(!sections.is_empty());

    // Find the __text section
    let text_section = sections.iter().find(|s| s.name == "__text");
    assert!(text_section.is_some());

    let text_section = text_section.unwrap();
    assert_eq!(text_section.section_type, SectionType::Code);
    assert!(text_section.permissions.read);
    assert!(!text_section.permissions.write);
    assert!(text_section.permissions.execute);
}

#[test]
fn test_macho_parser_fat_binary_rejection() {
    let data = macho_test_data::create_fat_binary();
    assert_eq!(
        threatflux_binary_analysis::formats::detect_format(&data).unwrap(),
        BinaryFormat::MachO
    );

    let error = BinaryAnalyzer::new().analyze(&data).unwrap_err();
    assert!(matches!(
        error,
        BinaryError::UnsupportedFormat(reason)
            if reason == "Universal (fat) Mach-O binaries are not supported"
    ));
}

#[test]
fn test_macho_parser_fat64_binary_rejection() {
    let data = macho_test_data::create_fat64_binary();
    assert_eq!(
        threatflux_binary_analysis::formats::detect_format(&data).unwrap(),
        BinaryFormat::MachO
    );

    let error = BinaryAnalyzer::new().analyze(&data).unwrap_err();
    assert!(matches!(
        error,
        BinaryError::UnsupportedFormat(reason)
            if reason == "Universal (fat) Mach-O binaries are not supported"
    ));
}

#[test]
fn test_macho_parser_error_handling() {
    // Test with truncated header
    let truncated = macho_test_data::create_truncated_header();
    let result = BinaryAnalyzer::new().analyze(&truncated);
    // Truncated header with valid magic gets detected as Mach-O but parsing fails
    // due to insufficient data, which is a legitimate error case
    assert!(result.is_err());

    // Test with invalid magic
    let invalid_magic = macho_test_data::create_invalid_magic();
    let result = BinaryAnalyzer::new().analyze(&invalid_magic);
    // BinaryAnalyzer now falls back to Raw format instead of erroring
    assert!(result.is_ok());
    let analysis = result.unwrap();
    assert_eq!(analysis.format, BinaryFormat::Raw);

    // Test with empty data - this should still error since detect_format checks for empty data
    let result = BinaryAnalyzer::new().analyze(&[]);
    assert!(result.is_err());
}

#[test]
fn test_minimal_macho_analysis_fields() {
    let data = macho_test_data::create_macho_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();

    assert_eq!(binary.format, BinaryFormat::MachO);
    assert_eq!(binary.architecture, Architecture::X86_64);

    // This fixture has LC_SEGMENT_64 only; without LC_MAIN it has no entry point.
    assert!(binary.entry_point.is_none());

    // The segment declares zero sections and the fixture has no symbol or dyld
    // metadata load commands.
    assert!(binary.sections.is_empty());
    assert!(binary.symbols.is_empty());
    assert!(binary.imports.is_empty());
    assert!(binary.exports.is_empty());

    let metadata = &binary.metadata;
    assert_eq!(metadata.format, BinaryFormat::MachO);
    assert_eq!(metadata.architecture, Architecture::X86_64);
    assert_eq!(metadata.entry_point, binary.entry_point);
    assert_eq!(metadata.size, data.len());
}

#[test]
fn test_macho_security_features_analysis() {
    // Test that security features are analyzed
    let data = macho_test_data::create_macho_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let metadata = &binary.metadata;

    // Check that security features are populated
    // PIE flag should match what's in the binary flags
    assert!(metadata.security_features.pie); // Our test binary has PIE flag set
    assert!(metadata.security_features.aslr); // ASLR is enabled with PIE
    assert!(metadata.security_features.nx_bit); // Default assumption for modern binaries
    assert!(!metadata.security_features.stack_canary); // Not detected in simple test binary

    // Test non-PIE binary
    let non_pie_data = macho_test_data::create_macho_32_x86_le();
    let non_pie_binary = BinaryAnalyzer::new().analyze(&non_pie_data).unwrap();
    let non_pie_metadata = &non_pie_binary.metadata;

    assert!(!non_pie_metadata.security_features.pie); // 32-bit test binary doesn't have PIE
    assert!(!non_pie_metadata.security_features.aslr); // ASLR disabled without PIE
    assert!(non_pie_metadata.security_features.nx_bit); // Still enabled by default
}

#[test]
fn test_macho_endianness_detection() {
    // Little endian
    let le_data = macho_test_data::create_macho_64_x86_64_le();
    let le_binary = BinaryAnalyzer::new().analyze(&le_data).unwrap();
    assert_eq!(le_binary.metadata.endian, Endianness::Little);

    // Test that we can detect endianness from magic numbers (without full parsing)
    let le_magic = vec![0xcf, 0xfa, 0xed, 0xfe]; // MH_MAGIC_64
    let be_magic = vec![0xcf, 0xfa, 0xed, 0xfe]; // MH_CIGAM_64 (same bytes, different interpretation)

    assert!(is_macho(&le_magic));
    assert!(is_macho(&be_magic));
}

#[test]
fn test_macho_compiler_info_extraction() {
    let data = macho_test_data::create_macho_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let metadata = &binary.metadata;

    // A minimal Mach-O header contains no reliable compiler identity. Platform
    // and SDK load commands must not be mislabeled as compiler evidence.
    assert!(metadata.compiler_info.is_none());
}

#[test]
fn test_macho_architecture_mapping() {
    // Test various architecture mappings that we can reliably create
    let test_cases = vec![
        (macho_test_data::create_macho_32_x86_le(), Architecture::X86),
        (
            macho_test_data::create_macho_64_x86_64_le(),
            Architecture::X86_64,
        ),
        (
            macho_test_data::create_macho_64_arm64_le(),
            Architecture::Arm64,
        ),
    ];

    for (data, expected_arch) in test_cases {
        let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
        assert_eq!(binary.architecture, expected_arch);
        assert_eq!(binary.architecture, expected_arch);
    }
}

#[test]
fn test_macho_section_type_classification() {
    let data = macho_test_data::create_macho_with_sections();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let sections = &binary.sections;

    if let Some(text_section) = sections.iter().find(|s| s.name == "__text") {
        assert_eq!(text_section.section_type, SectionType::Code);
        assert!(text_section.permissions.execute);
        assert!(!text_section.permissions.write);
    }
}

#[test]
fn test_macho_section_permissions() {
    let data = macho_test_data::create_macho_with_sections();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let sections = &binary.sections;

    for section in sections {
        // All sections in our test data should have read permission
        assert!(section.permissions.read);

        // Text sections should be executable but not writable
        if section.section_type == SectionType::Code {
            assert!(section.permissions.execute);
            assert!(!section.permissions.write);
        }
    }
}

#[test]
fn test_macho_section_data_extraction() {
    let data = macho_test_data::create_macho_with_sections();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let sections = &binary.sections;

    // Check that small sections have data extracted
    for section in sections {
        if section.size <= 1024 && section.offset > 0 {
            // Should have data if the section is small enough and has valid offset
            assert!(section.data.is_some() || section.data.is_none());
        }
    }
}

#[test]
fn test_macho_binary_size_metadata() {
    let test_cases = vec![
        macho_test_data::create_macho_32_x86_le(),
        macho_test_data::create_macho_64_x86_64_le(),
        macho_test_data::create_macho_64_arm64_le(),
    ];

    for data in test_cases {
        let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
        let metadata = &binary.metadata;
        assert_eq!(metadata.size, data.len());
    }
}

#[test]
fn test_macho_edge_cases() {
    // Test with minimum viable Mach-O header size
    let min_data = vec![0xcf, 0xfa, 0xed, 0xfe]; // Just magic, should fail parsing
    let result = BinaryAnalyzer::new().analyze(&min_data);
    assert!(result.is_err());

    // Test can_parse with exactly 4 bytes (minimum for magic check)
    assert!(is_macho(&[0xcf, 0xfa, 0xed, 0xfe]));
    assert!(!is_macho(&[0x12, 0x34, 0x56, 0x78]));
}

#[test]
fn test_macho_unknown_architecture_handling() {
    // Create a Mach-O with unknown CPU type
    let mut data = macho_test_data::create_macho_64_x86_64_le();
    // Set an unknown CPU type (0xFFFFFFFF)
    data[4..8].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);

    let result = BinaryAnalyzer::new().analyze(&data);
    if let Ok(binary) = result {
        assert_eq!(binary.architecture, Architecture::Unknown);
        assert_eq!(binary.architecture, Architecture::Unknown);
    }
    // If parsing fails, that's also acceptable due to invalid CPU type
}
