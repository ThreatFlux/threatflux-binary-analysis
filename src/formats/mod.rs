//! Binary format parsers and detection

use crate::{BinaryError, BinaryFormat as Format, BinaryFormatParser, BinaryFormatTrait, Result};

#[cfg(feature = "elf")]
pub mod elf;
#[cfg(feature = "macho")]
pub mod macho;
#[cfg(feature = "pe")]
pub mod pe;
// Note: Java and WebAssembly format parsers not yet implemented
// Format detection is supported but parsing returns UnsupportedFormat error

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

    // Check for PE magic
    #[cfg(feature = "pe")]
    if data.len() >= 2 && &data[0..2] == b"MZ" {
        return Ok(Format::Pe);
    }

    // Check for Mach-O magic (handle both endiannesses)
    #[cfg(feature = "macho")]
    if data.len() >= 4 {
        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic_le {
            0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe => {
                return Ok(Format::MachO);
            }
            _ => {}
        }
        match magic_be {
            0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe => {
                return Ok(Format::MachO);
            }
            _ => {}
        }
    }

    // Check for Java class magic
    if data.len() >= 4 && &data[0..4] == b"\xca\xfe\xba\xbe" {
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
pub fn parse_binary(data: &[u8], format: Format) -> Result<Box<dyn BinaryFormatTrait>> {
    match format {
        #[cfg(feature = "elf")]
        Format::Elf => elf::ElfParser::parse(data),

        #[cfg(feature = "pe")]
        Format::Pe => pe::PeParser::parse(data),

        #[cfg(feature = "macho")]
        Format::MachO => macho::MachOParser::parse(data),

        Format::Java => Err(BinaryError::unsupported_format("Java".to_string())),
        Format::Wasm => Err(BinaryError::unsupported_format("Wasm".to_string())),
        Format::Raw => raw::RawParser::parse(data),
        Format::Unknown => Err(BinaryError::unsupported_format("Unknown".to_string())),
    }
}
