//! Binary format parsers and detection

use crate::{BinaryError, BinaryFormat as Format, BinaryFormatParser, BinaryFormatTrait, Result};

#[cfg(feature = "elf")]
pub mod elf;
#[cfg(feature = "macho")]
pub mod macho;
#[cfg(feature = "pe")]
pub mod pe;
// TODO: Implement these formats
// #[cfg(feature = "java")]
// pub mod java;
// #[cfg(feature = "wasm")]
// pub mod wasm;

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

    // Check for Mach-O magic
    #[cfg(feature = "macho")]
    if data.len() >= 4 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match magic {
            0xfeedface | 0xfeedfacf | 0xcafebabe | 0xcafebabf => {
                return Ok(Format::MachO);
            }
            _ => {}
        }
    }

    // Check for Java class magic
    #[cfg(feature = "java")]
    if data.len() >= 4 && &data[0..4] == b"\xca\xfe\xba\xbe" {
        return Ok(Format::Java);
    }

    // Check for WebAssembly magic
    #[cfg(feature = "wasm")]
    if data.len() >= 8 && &data[0..8] == b"\x00asm\x01\x00\x00\x00" {
        return Ok(Format::Wasm);
    }

    // Default to raw binary
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

        // TODO: Implement these formats
        // #[cfg(feature = "java")]
        // Format::Java => java::JavaParser::parse(data),
        //
        // #[cfg(feature = "wasm")]
        // Format::Wasm => wasm::WasmParser::parse(data),
        Format::Raw => raw::RawParser::parse(data),

        _ => Err(BinaryError::unsupported_format(format!("{:?}", format))),
    }
}
