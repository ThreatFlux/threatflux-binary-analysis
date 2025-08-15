//! PE (Portable Executable) format parser for Windows binaries

use crate::{
    BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol,
    },
};
use goblin::pe::{PE, dll_characteristic::*};

/// PE format parser
pub struct PeParser;

impl BinaryFormatParser for PeParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        let pe = PE::parse(data)?;
        Ok(Box::new(PeBinary::new(pe, data)?))
    }

    fn can_parse(data: &[u8]) -> bool {
        // Check for DOS header signature "MZ"
        if data.len() < 2 || &data[0..2] != b"MZ" {
            return false;
        }

        // Check for PE signature
        if data.len() >= 0x3c + 4 {
            let pe_offset =
                u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;

            if pe_offset + 4 <= data.len() {
                return &data[pe_offset..pe_offset + 4] == b"PE\0\0";
            }
        }

        false
    }
}

/// Parsed PE binary
pub struct PeBinary {
    #[allow(dead_code)]
    pe: PE<'static>,
    #[allow(dead_code)]
    data: Vec<u8>,
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl PeBinary {
    fn new(pe: PE<'_>, data: &[u8]) -> Result<Self> {
        let data = data.to_vec();

        // Convert architecture
        let architecture = match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86 => Architecture::X86,
            goblin::pe::header::COFF_MACHINE_X86_64 => Architecture::X86_64,
            goblin::pe::header::COFF_MACHINE_ARM => Architecture::Arm,
            goblin::pe::header::COFF_MACHINE_ARM64 => Architecture::Arm64,
            _ => Architecture::Unknown,
        };

        // PE is always little endian
        let endian = Endianness::Little;

        // Analyze security features
        let security_features = analyze_security_features(&pe);

        // Get base address and entry point from optional header
        let (base_address, entry_point) = if let Some(optional_header) = &pe.header.optional_header
        {
            (
                Some(optional_header.windows_fields.image_base),
                Some(
                    optional_header.standard_fields.address_of_entry_point as u64
                        + optional_header.windows_fields.image_base,
                ),
            )
        } else {
            (None, None)
        };

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Pe,
            architecture,
            entry_point,
            base_address,
            timestamp: Some(pe.header.coff_header.time_date_stamp as u64),
            compiler_info: extract_compiler_info(&pe),
            endian,
            security_features,
        };

        // Parse sections
        let sections = parse_sections(&pe, &data)?;

        // Parse symbols
        let symbols = parse_symbols(&pe, &data)?;

        // Parse imports and exports
        let (imports, exports) = parse_imports_exports(&pe)?;

        // Handle lifetime issues with PE struct
        let pe_owned = unsafe { std::mem::transmute::<PE<'_>, PE<'static>>(pe) };

        Ok(Self {
            pe: pe_owned,
            data,
            metadata,
            sections,
            symbols,
            imports,
            exports,
        })
    }
}

impl BinaryFormatTrait for PeBinary {
    fn format_type(&self) -> Format {
        Format::Pe
    }

    fn architecture(&self) -> Architecture {
        self.metadata.architecture
    }

    fn entry_point(&self) -> Option<u64> {
        self.metadata.entry_point
    }

    fn sections(&self) -> &[Section] {
        &self.sections
    }

    fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    fn imports(&self) -> &[Import] {
        &self.imports
    }

    fn exports(&self) -> &[Export] {
        &self.exports
    }

    fn metadata(&self) -> &BinaryMetadata {
        &self.metadata
    }
}

fn parse_sections(pe: &PE, data: &[u8]) -> Result<Vec<Section>> {
    let mut sections = Vec::new();

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        // Determine section type based on characteristics
        let section_type =
            if section.characteristics & goblin::pe::section_table::IMAGE_SCN_CNT_CODE != 0 {
                SectionType::Code
            } else if section.characteristics
                & goblin::pe::section_table::IMAGE_SCN_CNT_INITIALIZED_DATA
                != 0
            {
                if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
                    SectionType::Data
                } else {
                    SectionType::ReadOnlyData
                }
            } else if section.characteristics
                & goblin::pe::section_table::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                != 0
            {
                SectionType::Bss
            } else {
                SectionType::Other("PE_SECTION".to_string())
            };

        let permissions = SectionPermissions {
            read: section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0,
            write: section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
            execute: section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
                != 0,
        };

        // Extract small section data
        let section_data = if section.size_of_raw_data <= 1024 && section.pointer_to_raw_data > 0 {
            let start = section.pointer_to_raw_data as usize;
            let end = start + section.size_of_raw_data as usize;
            if end <= data.len() {
                Some(data[start..end].to_vec())
            } else {
                None
            }
        } else {
            None
        };

        sections.push(Section {
            name,
            address: section.virtual_address as u64,
            size: section.virtual_size as u64,
            offset: section.pointer_to_raw_data as u64,
            permissions,
            section_type,
            data: section_data,
        });
    }

    Ok(sections)
}

fn parse_symbols(_pe: &PE, _data: &[u8]) -> Result<Vec<Symbol>> {
    // For now, return empty symbols as goblin 0.10 has changed the symbol API significantly
    // NOTE: Symbol parsing API changed significantly in goblin 0.10
    Ok(Vec::new())
}

fn parse_imports_exports(pe: &PE) -> Result<(Vec<Import>, Vec<Export>)> {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // Parse imports
    for import in &pe.imports {
        imports.push(Import {
            name: import.name.to_string(),
            library: Some(import.dll.to_string()),
            address: Some(import.rva as u64),
            ordinal: Some(import.ordinal),
        });
    }

    // Parse exports
    for export in &pe.exports {
        if let Some(name) = &export.name {
            exports.push(Export {
                name: name.to_string(),
                address: export.rva as u64,
                ordinal: None, // PE exports don't have ordinals in goblin 0.10
                forwarded_name: export.reexport.as_ref().map(|r| match r {
                    goblin::pe::export::Reexport::DLLName { export, lib } => {
                        format!("{}.{}", lib, export)
                    }
                    goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib } => {
                        format!("{}.#{}", lib, ordinal)
                    }
                }),
            });
        }
    }

    Ok((imports, exports))
}

fn analyze_security_features(pe: &PE) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    if let Some(optional_header) = &pe.header.optional_header {
        let characteristics = optional_header.windows_fields.dll_characteristics;

        // DEP/NX bit
        features.nx_bit = characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0;

        // ASLR
        features.aslr = characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0;

        // High entropy ASLR
        let _high_entropy = characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0;

        // CFI (Control Flow Guard)
        features.cfi = characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0;

        // Position Independent Executable (requires relocation table removal)
        features.pie = features.aslr; // Simplified check
    }

    // Check for stack canaries (would need more complex analysis)
    // This would require analyzing the binary for __security_cookie references
    features.stack_canary = false;

    // Check if binary is signed (would need to parse certificate table)
    features.signed = !pe.certificates.is_empty();

    features
}

fn extract_compiler_info(pe: &PE) -> Option<String> {
    // Look for compiler strings in debug info or rich header
    // This is a simplified implementation
    if pe.header.coff_header.number_of_symbol_table > 0 {
        Some("MSVC (detected from symbols)".to_string())
    } else {
        None
    }
}
