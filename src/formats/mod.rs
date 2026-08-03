//! Binary format parsers and detection

use crate::{BinaryError, BinaryFormat as Format, BinaryFormatParser, Result};
#[cfg(any(feature = "elf", feature = "macho", feature = "pe"))]
use std::ops::Range;

#[cfg(any(feature = "elf", feature = "macho", feature = "pe"))]
const INLINE_SECTION_DATA_LIMIT: u64 = 1024;

/// Maximum structural records materialized by one format parser.
///
/// The cap prevents compact tables from amplifying into unbounded owned output.
pub const MAX_PARSED_RECORDS: usize = 100_000;

/// Maximum bytes copied into names by one format parser.
pub const MAX_OWNED_NAME_BYTES: usize = 32 * 1024 * 1024;

/// Maximum accepted byte length of one parsed name.
pub const MAX_NAME_BYTES: usize = 4 * 1024;

const JAVA_CLASS_MAGIC: &[u8; 4] = b"\xca\xfe\xba\xbe";
const JAVA_CLASS_HEADER_SIZE: usize = 10;
const MIN_JAVA_CLASS_MAJOR_VERSION: u16 = 45;
const FAT_HEADER_SIZE: usize = 8;
const FAT_ARCH_32_SIZE: usize = 20;
const FAT_ARCH_64_SIZE: usize = 32;
const MAX_FAT_ARCHITECTURES: usize = 32;

fn is_java_class_header(data: &[u8]) -> bool {
    data.len() >= JAVA_CLASS_HEADER_SIZE
        && data.starts_with(JAVA_CLASS_MAGIC)
        && u16::from_be_bytes([data[6], data[7]]) >= MIN_JAVA_CLASS_MAJOR_VERSION
        && u16::from_be_bytes([data[8], data[9]]) != 0
}

fn is_bounded_universal_macho(data: &[u8]) -> bool {
    let Some(header) = data.get(..FAT_HEADER_SIZE) else {
        return false;
    };
    let magic = [header[0], header[1], header[2], header[3]];
    let count = [header[4], header[5], header[6], header[7]];
    let (architecture_count, record_size) = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => (u32::from_be_bytes(count), FAT_ARCH_32_SIZE),
        [0xbe, 0xba, 0xfe, 0xca] => (u32::from_le_bytes(count), FAT_ARCH_32_SIZE),
        [0xca, 0xfe, 0xba, 0xbf] => (u32::from_be_bytes(count), FAT_ARCH_64_SIZE),
        [0xbf, 0xba, 0xfe, 0xca] => (u32::from_le_bytes(count), FAT_ARCH_64_SIZE),
        _ => return false,
    };
    let Ok(architecture_count) = usize::try_from(architecture_count) else {
        return false;
    };
    if !(1..=MAX_FAT_ARCHITECTURES).contains(&architecture_count) {
        return false;
    }
    record_size
        .checked_mul(architecture_count)
        .and_then(|size| FAT_HEADER_SIZE.checked_add(size))
        .is_some_and(|end| end <= data.len())
}

/// Shared allocation budget for parser-owned records and names.
#[cfg(any(
    feature = "elf",
    feature = "java",
    feature = "macho",
    feature = "pe",
    feature = "wasm"
))]
#[derive(Default)]
pub(super) struct ParseOutputBudget {
    records: usize,
    name_bytes: usize,
}

#[cfg(any(
    feature = "elf",
    feature = "java",
    feature = "macho",
    feature = "pe",
    feature = "wasm"
))]
impl ParseOutputBudget {
    pub(super) fn claim_records(&mut self, additional: usize, context: &str) -> Result<()> {
        let next = self.records.checked_add(additional).ok_or_else(|| {
            BinaryError::invalid_data("Parsed structural record count overflows usize")
        })?;
        if next > MAX_PARSED_RECORDS {
            return Err(BinaryError::invalid_data(format!(
                "{context} exceeds the parser record limit of {MAX_PARSED_RECORDS}"
            )));
        }
        self.records = next;
        Ok(())
    }

    pub(super) fn reserve_record<T>(&mut self, output: &mut Vec<T>, context: &str) -> Result<()> {
        self.claim_records(1, context)?;
        output.try_reserve(1).map_err(|error| {
            BinaryError::invalid_data(format!("Unable to reserve {context} output: {error}"))
        })?;
        Ok(())
    }

    pub(super) fn copy_name(&mut self, value: &str, context: &str) -> Result<String> {
        self.copy_name_parts(&[value], context)
    }

    pub(super) fn copy_name_parts(&mut self, parts: &[&str], context: &str) -> Result<String> {
        let length = parts.iter().try_fold(0_usize, |total, part| {
            total.checked_add(part.len()).ok_or_else(|| {
                BinaryError::invalid_data(format!("{context} length overflows usize"))
            })
        })?;
        if length > MAX_NAME_BYTES {
            return Err(BinaryError::invalid_data(format!(
                "{context} is {length} bytes; per-name limit is {MAX_NAME_BYTES}"
            )));
        }

        let next = self.name_bytes.checked_add(length).ok_or_else(|| {
            BinaryError::invalid_data("Owned parser-name byte count overflows usize")
        })?;
        if next > MAX_OWNED_NAME_BYTES {
            return Err(BinaryError::invalid_data(format!(
                "Parsed names exceed the aggregate limit of {MAX_OWNED_NAME_BYTES} bytes"
            )));
        }

        let mut owned = String::new();
        owned.try_reserve_exact(length).map_err(|error| {
            BinaryError::invalid_data(format!("Unable to reserve {context}: {error}"))
        })?;
        for part in parts {
            owned.push_str(part);
        }
        self.name_bytes = next;
        Ok(owned)
    }
}

/// Return an owned copy of a small, in-bounds file range.
///
/// Format headers contain attacker-controlled 64-bit offsets and lengths. Keeping
/// the conversion and checked addition in one place avoids both integer wraparound
/// and truncation on 32-bit targets.
#[cfg(any(feature = "elf", feature = "macho", feature = "pe"))]
pub(super) fn inline_section_data(data: &[u8], offset: u64, size: u64) -> Option<Vec<u8>> {
    if size > INLINE_SECTION_DATA_LIMIT {
        return None;
    }

    checked_file_range(data, offset, size).map(|range| data[range].to_vec())
}

#[cfg(any(feature = "elf", feature = "macho", feature = "pe"))]
pub(super) fn checked_file_range(data: &[u8], offset: u64, size: u64) -> Option<Range<usize>> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    let end = start.checked_add(len)?;
    (end <= data.len()).then_some(start..end)
}

#[cfg(feature = "elf")]
pub mod elf;
#[cfg(feature = "java")]
pub mod java;
#[cfg(feature = "macho")]
pub mod macho;
#[cfg(feature = "pe")]
pub mod pe;
#[cfg(feature = "wasm")]
pub mod wasm;

pub mod raw;

/// Detect binary format from data
pub fn detect_format(data: &[u8]) -> Result<Format> {
    if data.is_empty() {
        return Err(BinaryError::invalid_data("Empty data"));
    }

    // Check for ELF magic
    #[cfg(feature = "elf")]
    if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
        return Ok(Format::Elf);
    }

    // MZ alone identifies a DOS executable, not necessarily a PE image. Require
    // the checked e_lfanew offset and PE signature before claiming PE support.
    #[cfg(feature = "pe")]
    if pe::PeParser::can_parse(data) {
        return Ok(Format::Pe);
    }

    // Universal Mach-O must be recognized even when its parser is absent: its
    // canonical 32-bit magic is also Java's class-file magic.
    if is_bounded_universal_macho(data) {
        return Ok(Format::MachO);
    }

    // Check thin and bounded universal Mach-O headers before Java because the
    // canonical 32-bit universal magic is also the Java class-file magic.
    #[cfg(feature = "macho")]
    if macho::MachOParser::can_parse(data) {
        return Ok(Format::MachO);
    }

    // A class file has a cheap, feature-independent fixed-header check so the
    // dispatcher can report a missing Java parser instead of treating it as raw.
    if is_java_class_header(data) {
        return Ok(Format::Java);
    }

    // A ZIP file is
    // Java input only when the bounded JAR inspection finds a class entry.
    // Generic ZIP files remain raw data.
    #[cfg(feature = "java")]
    if java::JavaParser::can_parse(data) {
        return Ok(Format::Java);
    }

    // Check for WebAssembly magic
    if data.len() >= 4 && &data[0..4] == b"\x00asm" {
        return Ok(Format::Wasm);
    }

    // Default to raw binary for any data that doesn't match known formats
    Ok(Format::Raw)
}

/// Parse binary data using the appropriate parser
pub fn parse_binary(data: &[u8], format: Format) -> crate::types::ParseResult {
    match format {
        #[cfg(feature = "elf")]
        Format::Elf => elf::ElfParser::parse(data),
        #[cfg(not(feature = "elf"))]
        Format::Elf => Err(BinaryError::unsupported_format("ELF".to_string())),

        #[cfg(feature = "pe")]
        Format::Pe => pe::PeParser::parse(data),
        #[cfg(not(feature = "pe"))]
        Format::Pe => Err(BinaryError::unsupported_format("PE".to_string())),

        #[cfg(feature = "macho")]
        Format::MachO => macho::MachOParser::parse(data),
        #[cfg(not(feature = "macho"))]
        Format::MachO => Err(BinaryError::unsupported_format("MachO".to_string())),

        #[cfg(feature = "java")]
        Format::Java => java::JavaParser::parse(data),
        #[cfg(not(feature = "java"))]
        Format::Java => Err(BinaryError::unsupported_format("Java".to_string())),
        #[cfg(feature = "wasm")]
        Format::Wasm => wasm::WasmParser::parse(data),
        #[cfg(not(feature = "wasm"))]
        Format::Wasm => Err(BinaryError::unsupported_format("Wasm".to_string())),
        Format::Raw => raw::RawParser::parse(data),
        Format::Unknown => Err(BinaryError::unsupported_format("Unknown".to_string())),
    }
}

#[cfg(test)]
mod detection_tests {
    use super::{Format, detect_format};

    #[test]
    fn java_class_header_is_detected_without_relying_on_the_parser() {
        let class_header = b"\xca\xfe\xba\xbe\0\0\0\x34\0\x01";
        assert_eq!(detect_format(class_header).unwrap(), Format::Java);
    }

    #[test]
    fn bounded_fat_macho_wins_over_java_magic() {
        let mut universal = vec![0_u8; 8 + 20];
        universal[..4].copy_from_slice(b"\xca\xfe\xba\xbe");
        universal[4..8].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(detect_format(&universal).unwrap(), Format::MachO);
    }
}

#[cfg(all(test, any(feature = "elf", feature = "macho", feature = "pe")))]
mod tests {
    use super::{
        MAX_NAME_BYTES, MAX_OWNED_NAME_BYTES, MAX_PARSED_RECORDS, ParseOutputBudget,
        checked_file_range, inline_section_data,
    };

    #[test]
    fn inline_section_data_rejects_overflow_and_out_of_bounds_ranges() {
        let data = b"section";

        assert_eq!(inline_section_data(data, 0, 7), Some(data.to_vec()));
        assert!(inline_section_data(data, u64::MAX, 2).is_none());
        assert!(inline_section_data(data, 6, u64::MAX).is_none());
        assert!(inline_section_data(data, 6, 2).is_none());
        assert!(inline_section_data(data, 0, 1025).is_none());
        assert_eq!(checked_file_range(data, 2, 3), Some(2..5));
        assert!(checked_file_range(data, u64::MAX, 2).is_none());
    }

    #[test]
    fn parser_output_budget_enforces_record_and_name_limits() {
        let mut records = Vec::<()>::new();
        let mut budget = ParseOutputBudget {
            records: MAX_PARSED_RECORDS - 1,
            name_bytes: 0,
        };
        budget.reserve_record(&mut records, "test records").unwrap();
        assert!(budget.reserve_record(&mut records, "test records").is_err());

        let mut budget = ParseOutputBudget {
            records: 0,
            name_bytes: MAX_OWNED_NAME_BYTES - 2,
        };
        assert_eq!(budget.copy_name("ok", "test name").unwrap(), "ok");
        assert!(budget.copy_name("x", "test name").is_err());
        assert!(
            budget
                .copy_name(&"x".repeat(MAX_NAME_BYTES + 1), "test name")
                .is_err()
        );
    }
}
