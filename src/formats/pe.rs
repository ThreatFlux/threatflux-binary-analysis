//! PE (Portable Executable) format parser for Windows binaries

use crate::{
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding, SymbolType,
        SymbolVisibility,
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

            return pe_offset
                .checked_add(4)
                .and_then(|end| data.get(pe_offset..end))
                .is_some_and(|signature| signature == b"PE\0\0");
        }

        false
    }
}

/// Parsed PE binary
pub struct PeBinary {
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl PeBinary {
    fn new(pe: PE<'_>, data: &[u8]) -> Result<Self> {
        let mut output_budget = super::ParseOutputBudget::default();

        // Convert architecture
        let architecture = match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86 => Architecture::X86,
            goblin::pe::header::COFF_MACHINE_X86_64 => Architecture::X86_64,
            goblin::pe::header::COFF_MACHINE_ARM
            | goblin::pe::header::COFF_MACHINE_ARMNT
            | goblin::pe::header::COFF_MACHINE_THUMB => Architecture::Arm,
            goblin::pe::header::COFF_MACHINE_ARM64 => Architecture::Arm64,
            goblin::pe::header::COFF_MACHINE_MIPS16
            | goblin::pe::header::COFF_MACHINE_MIPSFPU
            | goblin::pe::header::COFF_MACHINE_MIPSFPU16
            | goblin::pe::header::COFF_MACHINE_R4000
            | goblin::pe::header::COFF_MACHINE_WCEMIPSV2 => Architecture::Mips,
            goblin::pe::header::COFF_MACHINE_POWERPC
            | goblin::pe::header::COFF_MACHINE_POWERPCFP => Architecture::PowerPC,
            goblin::pe::header::COFF_MACHINE_RISCV32 => Architecture::RiscV,
            goblin::pe::header::COFF_MACHINE_RISCV64 => Architecture::RiscV64,
            _ => Architecture::Unknown,
        };

        // PE is always little endian
        let endian = Endianness::Little;

        // Analyze security features
        let security_features = analyze_security_features(&pe);

        // Get base address and entry point from optional header
        let (base_address, entry_point) = if let Some(optional_header) = &pe.header.optional_header
        {
            let image_base = optional_header.windows_fields.image_base;
            let entry_rva = optional_header.standard_fields.address_of_entry_point;
            let entry_point = if entry_rva == 0 {
                None
            } else {
                Some(
                    image_base
                        .checked_add(u64::from(entry_rva))
                        .ok_or_else(|| {
                            BinaryError::invalid_data("PE entry point address overflows u64")
                        })?,
                )
            };
            (Some(image_base), entry_point)
        } else {
            (None, None)
        };

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Pe,
            architecture,
            entry_point,
            base_address,
            timestamp: (pe.header.coff_header.time_date_stamp != 0)
                .then_some(u64::from(pe.header.coff_header.time_date_stamp)),
            compiler_info: None,
            endian,
            security_features,
        };

        // Parse sections
        let sections = parse_sections(&pe, data, &mut output_budget)?;

        // Parse symbols
        let symbols = parse_symbols(&pe, data, &mut output_budget)?;

        // Parse imports and exports
        let (imports, exports) = parse_imports_exports(&pe, &mut output_budget)?;

        Ok(Self {
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

fn parse_sections(
    pe: &PE,
    data: &[u8],
    output_budget: &mut super::ParseOutputBudget,
) -> Result<Vec<Section>> {
    let mut sections = Vec::new();

    for section in &pe.sections {
        output_budget.reserve_record(&mut sections, "PE sections")?;
        let decoded_name = String::from_utf8_lossy(&section.name);
        let name =
            output_budget.copy_name(decoded_name.trim_end_matches('\0'), "PE section name")?;

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

        let has_file_data = section.size_of_raw_data != 0;
        if has_file_data
            && super::checked_file_range(
                data,
                u64::from(section.pointer_to_raw_data),
                u64::from(section.size_of_raw_data),
            )
            .is_none()
        {
            return Err(BinaryError::invalid_data(format!(
                "PE section '{name}' range {}..+{} exceeds the file",
                section.pointer_to_raw_data, section.size_of_raw_data
            )));
        }

        // Extract small section data
        let section_data = if has_file_data {
            super::inline_section_data(
                data,
                u64::from(section.pointer_to_raw_data),
                u64::from(section.size_of_raw_data),
            )
        } else {
            None
        };

        sections.push(Section {
            name,
            address: pe
                .image_base
                .checked_add(u64::from(section.virtual_address))
                .ok_or_else(|| BinaryError::invalid_data("PE section address overflows u64"))?,
            size: u64::from(if section.virtual_size == 0 {
                section.size_of_raw_data
            } else {
                section.virtual_size
            }),
            offset: section.pointer_to_raw_data as u64,
            file_size: u64::from(section.size_of_raw_data),
            permissions,
            section_type,
            data: section_data,
        });
    }

    Ok(sections)
}

fn parse_symbols(
    pe: &PE,
    data: &[u8],
    output_budget: &mut super::ParseOutputBudget,
) -> Result<Vec<Symbol>> {
    use goblin::pe::symbol::{
        COFF_SYMBOL_SIZE, IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_EXTERNAL_DEF,
        IMAGE_SYM_CLASS_FILE, IMAGE_SYM_CLASS_SECTION, IMAGE_SYM_CLASS_STATIC,
        IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_UNDEFINED,
    };

    let coff = &pe.header.coff_header;
    let table_offset = usize::try_from(coff.pointer_to_symbol_table)
        .map_err(|_| BinaryError::invalid_data("COFF symbol table offset exceeds usize"))?;
    let table_size = usize::try_from(coff.number_of_symbol_table)
        .ok()
        .and_then(|count| count.checked_mul(COFF_SYMBOL_SIZE))
        .ok_or_else(|| BinaryError::invalid_data("COFF symbol table size overflows usize"))?;

    if table_offset == 0 {
        return Ok(Vec::new());
    }
    if table_offset
        .checked_add(table_size)
        .is_none_or(|end| end > data.len())
    {
        return Err(BinaryError::invalid_data(
            "COFF symbol table extends beyond the file",
        ));
    }

    let Some(table) = coff.symbols(data)? else {
        return Ok(Vec::new());
    };
    let strings = coff.strings(data)?;
    let mut symbols = Vec::new();

    for (index, inline_name, native) in table.iter() {
        let parsed_name = match inline_name {
            Some(name) => name,
            None => native.name(strings.as_ref().ok_or_else(|| {
                BinaryError::invalid_data("COFF symbol requires a missing string table")
            })?)?,
        };
        if parsed_name.is_empty() {
            continue;
        }
        output_budget.reserve_record(&mut symbols, "PE symbols")?;
        let name = output_budget.copy_name(parsed_name, "PE symbol name")?;

        let section_index = usize::try_from(native.section_number)
            .ok()
            .and_then(|ordinal| ordinal.checked_sub(1));
        let address = if let Some(section_index) = section_index {
            let section = pe.sections.get(section_index).ok_or_else(|| {
                BinaryError::invalid_data(format!(
                    "COFF symbol '{name}' references missing section {}",
                    native.section_number
                ))
            })?;
            pe.image_base
                .checked_add(u64::from(section.virtual_address))
                .and_then(|base| base.checked_add(u64::from(native.value)))
                .ok_or_else(|| {
                    BinaryError::invalid_data(format!(
                        "COFF symbol '{name}' virtual address overflows u64"
                    ))
                })?
        } else {
            u64::from(native.value)
        };

        let symbol_type = if native.is_function_definition()
            || native.derived_type() == IMAGE_SYM_DTYPE_FUNCTION
        {
            SymbolType::Function
        } else if native.is_file() || native.storage_class == IMAGE_SYM_CLASS_FILE {
            SymbolType::File
        } else if native.is_section_definition() || native.storage_class == IMAGE_SYM_CLASS_SECTION
        {
            SymbolType::Section
        } else if native.section_number == IMAGE_SYM_UNDEFINED && native.value != 0 {
            SymbolType::Common
        } else {
            SymbolType::Object
        };

        let binding = if native.is_weak_external() {
            SymbolBinding::Weak
        } else if matches!(
            native.storage_class,
            IMAGE_SYM_CLASS_EXTERNAL | IMAGE_SYM_CLASS_EXTERNAL_DEF
        ) {
            SymbolBinding::Global
        } else if native.storage_class == IMAGE_SYM_CLASS_STATIC {
            SymbolBinding::Local
        } else {
            SymbolBinding::Other(format!("COFF_STORAGE_CLASS_{}", native.storage_class))
        };

        let size = if native.is_function_definition() && native.number_of_aux_symbols != 0 {
            table
                .aux_function_definition(index + 1)
                .map_or(0, |aux| u64::from(aux.total_size))
        } else {
            0
        };

        symbols.push(Symbol {
            name,
            demangled_name: None,
            address,
            size,
            symbol_type,
            binding,
            visibility: SymbolVisibility::Default,
            section_index,
        });
    }

    Ok(symbols)
}

fn parse_imports_exports(
    pe: &PE,
    output_budget: &mut super::ParseOutputBudget,
) -> crate::types::ImportExportResult {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // Parse imports
    for import in &pe.imports {
        output_budget.reserve_record(&mut imports, "PE imports")?;
        let rva = u64::try_from(import.rva)
            .map_err(|_| BinaryError::invalid_data("PE import RVA exceeds u64"))?;
        imports.push(Import {
            name: output_budget.copy_name(&import.name, "PE import name")?,
            library: Some(output_budget.copy_name(import.dll, "PE import library")?),
            address: Some(
                pe.image_base
                    .checked_add(rva)
                    .ok_or_else(|| BinaryError::invalid_data("PE import address overflows u64"))?,
            ),
            ordinal: Some(import.ordinal),
        });
    }

    // Parse exports
    for export in &pe.exports {
        if let Some(name) = &export.name {
            output_budget.reserve_record(&mut exports, "PE exports")?;
            let rva = u64::try_from(export.rva)
                .map_err(|_| BinaryError::invalid_data("PE export RVA exceeds u64"))?;
            let forwarded_name =
                match export.reexport.as_ref() {
                    Some(goblin::pe::export::Reexport::DLLName { export, lib }) => Some(
                        output_budget
                            .copy_name_parts(&[lib, ".", export], "PE forwarded export name")?,
                    ),
                    Some(goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib }) => {
                        let ordinal = ordinal.to_string();
                        Some(output_budget.copy_name_parts(
                            &[lib, ".#", &ordinal],
                            "PE forwarded export ordinal",
                        )?)
                    }
                    None => None,
                };
            exports.push(Export {
                name: output_budget.copy_name(name, "PE export name")?,
                address: pe
                    .image_base
                    .checked_add(rva)
                    .ok_or_else(|| BinaryError::invalid_data("PE export address overflows u64"))?,
                ordinal: None, // PE exports don't have ordinals in goblin 0.10
                forwarded_name,
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
