//! PE (Portable Executable) format parser for Windows binaries

use crate::{
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
    static_metadata::{
        AuthenticodeHash, FieldOutcome, PeStaticMetadata, ResourceIdentifier, ResourceLeaf,
        RichHeader, RichHeaderEntry, hex_lower,
    },
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding, SymbolType,
        SymbolVisibility,
    },
};
use goblin::pe::{
    PE,
    dll_characteristic::*,
    import::SyntheticImportLookupTableEntry::{HintNameTableRVA, OrdinalNumber},
};
use md5::{Digest as _, Md5};
use sha2::Sha256;
use std::collections::HashSet;

/// PE format parser
pub struct PeParser;

impl BinaryFormatParser for PeParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        let pe = PE::parse(data)?;
        Ok(Box::new(PeBinary::new(&pe, data)?))
    }

    fn can_parse(data: &[u8]) -> bool {
        super::has_bounded_pe_signature(data)
    }
}

impl PeParser {
    pub(crate) fn parse_enriched(
        data: &[u8],
    ) -> Result<(Box<dyn BinaryFormatTrait>, FieldOutcome<PeStaticMetadata>)> {
        let mut output_budget = super::ParseOutputBudget::default();
        let sanitized = without_rich_marker(data);
        let mut options = goblin::pe::options::ParseOptions::default();
        options.parse_attribute_certificates = false;
        options.parse_resources = false;
        let pe = PE::parse_with_opts(&sanitized, &options)?;
        let binary = PeBinary::new_with_budget(&pe, data, &mut output_budget)?;
        let metadata = PeStaticMetadata {
            imphash: extract_imphash(&pe, &mut output_budget),
            authentihash: extract_authentihash(&pe, data),
            rich_header: extract_rich_header(data, &mut output_budget),
            resources: extract_resources(&pe, data, &mut output_budget),
        };
        Ok((Box::new(binary), FieldOutcome::Present { value: metadata }))
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
    fn new(pe: &PE<'_>, data: &[u8]) -> Result<Self> {
        let mut output_budget = super::ParseOutputBudget::default();
        Self::new_with_budget(pe, data, &mut output_budget)
    }

    fn new_with_budget(
        pe: &PE<'_>,
        data: &[u8],
        output_budget: &mut super::ParseOutputBudget,
    ) -> Result<Self> {
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
        let security_features = analyze_security_features(pe);

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
        let sections = parse_sections(pe, data, output_budget)?;

        // Parse symbols
        let symbols = parse_symbols(pe, data, output_budget)?;

        // Parse imports and exports
        let (imports, exports) = parse_imports_exports(pe, output_budget)?;

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

fn extract_imphash(
    pe: &PE<'_>,
    output_budget: &mut super::ParseOutputBudget,
) -> FieldOutcome<String> {
    let Some(import_data) = pe.import_data.as_ref() else {
        return FieldOutcome::Absent;
    };

    let mut normalized = String::new();
    let mut count = 0_usize;
    for descriptor in &import_data.import_data {
        let Some(lookup) = descriptor.import_lookup_table.as_ref() else {
            return FieldOutcome::Invalid {
                reason: "ordinary import descriptor has no lookup table".to_string(),
            };
        };
        let bounded_library =
            match output_budget.copy_name(descriptor.name, "PE imphash import library") {
                Ok(library) => library,
                Err(error) => return budget_outcome(error),
            };
        let library = normalize_import_library(&bounded_library);
        if library.is_empty() {
            return FieldOutcome::Invalid {
                reason: "ordinary import descriptor has an empty library name".to_string(),
            };
        }
        for entry in lookup {
            if let Err(error) = output_budget.claim_records(1, "PE imphash imports") {
                return budget_outcome(error);
            }
            let symbol = match entry {
                HintNameTableRVA((_, hint_name)) => hint_name.name.to_lowercase(),
                OrdinalNumber(ordinal) => resolve_import_ordinal(&library, *ordinal),
            };
            if symbol.is_empty() {
                return FieldOutcome::Invalid {
                    reason: "ordinary import has an empty symbol name".to_string(),
                };
            }
            let item = match output_budget.copy_name_parts(
                &[library.as_str(), ".", symbol.as_str()],
                "PE imphash entry",
            ) {
                Ok(item) => item,
                Err(error) => return budget_outcome(error),
            };
            if let Err(error) = normalized.try_reserve(item.len().saturating_add(1)) {
                return FieldOutcome::Invalid {
                    reason: format!("unable to reserve PE imphash input: {error}"),
                };
            }
            if count != 0 {
                normalized.push(',');
            }
            normalized.push_str(&item);
            count = count.saturating_add(1);
        }
    }

    if count == 0 {
        FieldOutcome::Absent
    } else {
        FieldOutcome::Present {
            value: hex_lower(&Md5::digest(normalized.as_bytes())),
        }
    }
}

fn normalize_import_library(library: &str) -> String {
    let lower = library.to_lowercase();
    [".dll", ".sys", ".ocx"]
        .iter()
        .find_map(|extension| lower.strip_suffix(extension).map(str::to_string))
        .unwrap_or(lower)
}

fn resolve_import_ordinal(library: &str, ordinal: u16) -> String {
    super::pe_ordinals::lookup(library, ordinal)
        .map(str::to_string)
        .unwrap_or_else(|| format!("ord{ordinal}"))
}

fn extract_rich_header(
    data: &[u8],
    output_budget: &mut super::ParseOutputBudget,
) -> FieldOutcome<RichHeader> {
    let header = match goblin::pe::header::RichHeader::parse(data) {
        Ok(Some(header)) => header,
        Ok(None) => return FieldOutcome::Absent,
        Err(error) => {
            return FieldOutcome::Invalid {
                reason: format!("invalid Rich Header: {error}"),
            };
        }
    };

    let mut entries = Vec::new();
    for metadata in header.metadatas() {
        if let Err(error) = output_budget.reserve_record(&mut entries, "PE Rich records") {
            return budget_outcome(error);
        }
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                return FieldOutcome::Invalid {
                    reason: format!("invalid Rich record: {error}"),
                };
            }
        };
        entries.push(RichHeaderEntry {
            product_id: metadata.product,
            build: metadata.build,
            use_count: metadata.use_count,
        });
    }

    FieldOutcome::Present {
        value: RichHeader {
            xor_key: header.key,
            entries,
        },
    }
}

fn without_rich_marker(data: &[u8]) -> Vec<u8> {
    let mut sanitized = data.to_vec();
    let scan_end = data
        .get(0x3c..0x40)
        .map(|pointer| u32::from_le_bytes([pointer[0], pointer[1], pointer[2], pointer[3]]))
        .and_then(|offset| usize::try_from(offset).ok())
        .unwrap_or(data.len())
        .min(data.len());
    if let Some(stub) = data.get(0x40..scan_end) {
        for (relative, window) in stub.windows(4).enumerate() {
            if window == b"Rich" {
                let start = 0x40 + relative;
                sanitized[start..start + 4].fill(0);
            }
        }
    }
    sanitized
}

fn budget_outcome<T>(error: BinaryError) -> FieldOutcome<T> {
    let message = error.to_string();
    if message.contains("limit") || message.contains("exceed") {
        FieldOutcome::LimitExceeded { limit: message }
    } else {
        FieldOutcome::Invalid { reason: message }
    }
}

fn extract_authentihash(pe: &PE<'_>, data: &[u8]) -> FieldOutcome<AuthenticodeHash> {
    match checked_authentihash(pe, data) {
        Ok(digest) => FieldOutcome::Present {
            value: AuthenticodeHash {
                algorithm: "sha256".to_string(),
                digest,
            },
        },
        Err(failure) => failure.into_outcome(),
    }
}

fn checked_authentihash(pe: &PE<'_>, data: &[u8]) -> std::result::Result<String, FieldFailure> {
    let optional = pe.header.optional_header.as_ref().ok_or_else(|| {
        FieldFailure::Unsupported("COFF objects do not have a PE optional header".to_string())
    })?;
    if optional.windows_fields.number_of_rva_and_sizes < 5 {
        return Err(FieldFailure::Unsupported(
            "optional header does not contain the Certificate Table directory slot".to_string(),
        ));
    }

    let pe_offset = usize::try_from(pe.header.dos_header.pe_pointer)
        .map_err(|_| FieldFailure::Invalid("PE header offset exceeds usize".to_string()))?;
    let optional_offset = pe_offset
        .checked_add(goblin::pe::header::SIZEOF_PE_MAGIC)
        .and_then(|offset| offset.checked_add(goblin::pe::header::SIZEOF_COFF_HEADER))
        .ok_or_else(|| {
            FieldFailure::Invalid("optional-header offset overflows usize".to_string())
        })?;
    let optional_end = optional_offset
        .checked_add(usize::from(pe.header.coff_header.size_of_optional_header))
        .ok_or_else(|| FieldFailure::Invalid("optional-header size overflows usize".to_string()))?;
    let checksum_start = optional_offset
        .checked_add(64)
        .ok_or_else(|| FieldFailure::Invalid("checksum offset overflows usize".to_string()))?;
    let checksum_end = checksum_start
        .checked_add(4)
        .ok_or_else(|| FieldFailure::Invalid("checksum range overflows usize".to_string()))?;
    let certificate_entry_start = match optional.standard_fields.magic {
        goblin::pe::optional_header::MAGIC_32 => optional_offset.checked_add(128),
        goblin::pe::optional_header::MAGIC_64 => optional_offset.checked_add(144),
        magic => {
            return Err(FieldFailure::Unsupported(format!(
                "optional-header magic {magic:#x} is not PE32 or PE32+"
            )));
        }
    }
    .ok_or_else(|| {
        FieldFailure::Invalid("Certificate Table directory offset overflows usize".to_string())
    })?;
    let certificate_entry_end = certificate_entry_start.checked_add(8).ok_or_else(|| {
        FieldFailure::Invalid("Certificate Table directory range overflows usize".to_string())
    })?;
    let header_end = usize::try_from(optional.windows_fields.size_of_headers)
        .map_err(|_| FieldFailure::Invalid("SizeOfHeaders exceeds usize".to_string()))?;
    let section_table_size = usize::from(pe.header.coff_header.number_of_sections)
        .checked_mul(goblin::pe::section_table::SIZEOF_SECTION_TABLE)
        .ok_or_else(|| {
            FieldFailure::Invalid("PE section-header table size overflows usize".to_string())
        })?;
    let section_table_end = optional_end
        .checked_add(section_table_size)
        .ok_or_else(|| {
            FieldFailure::Invalid("PE section-header table range overflows usize".to_string())
        })?;

    if !(checksum_start < checksum_end
        && checksum_end <= certificate_entry_start
        && certificate_entry_end <= optional_end
        && section_table_end <= header_end
        && header_end <= data.len())
    {
        return Err(FieldFailure::Invalid(
            "PE header hashing ranges are out of bounds or overlap".to_string(),
        ));
    }

    let mut sections = pe
        .sections
        .iter()
        .filter(|section| section.size_of_raw_data != 0)
        .collect::<Vec<_>>();
    sections.sort_by_key(|section| section.pointer_to_raw_data);

    let mut image_tail = header_end;
    let mut section_ranges = Vec::with_capacity(sections.len());
    for section in sections {
        let start = usize::try_from(section.pointer_to_raw_data)
            .map_err(|_| FieldFailure::Invalid("section file offset exceeds usize".to_string()))?;
        let size = usize::try_from(section.size_of_raw_data)
            .map_err(|_| FieldFailure::Invalid("section file size exceeds usize".to_string()))?;
        let end = start.checked_add(size).ok_or_else(|| {
            FieldFailure::Invalid("section file range overflows usize".to_string())
        })?;
        if end > data.len() {
            return Err(FieldFailure::Invalid(
                "section selected for Authenticode hashing exceeds the file".to_string(),
            ));
        }
        if start != image_tail {
            return Err(FieldFailure::Unsupported(format!(
                "non-contiguous section layout at file offset {start:#x}"
            )));
        }
        section_ranges.push(start..end);
        image_tail = end;
    }

    let certificate = optional.data_directories.get_certificate_table().copied();
    let certificate_range = match certificate {
        Some(directory) if directory.virtual_address == 0 && directory.size == 0 => None,
        Some(directory) if directory.virtual_address == 0 || directory.size == 0 => {
            return Err(FieldFailure::Invalid(
                "Certificate Table offset and size must both be zero or non-zero".to_string(),
            ));
        }
        Some(directory) => {
            let start = usize::try_from(directory.virtual_address).map_err(|_| {
                FieldFailure::Invalid("Certificate Table file offset exceeds usize".to_string())
            })?;
            let size = usize::try_from(directory.size).map_err(|_| {
                FieldFailure::Invalid("Certificate Table size exceeds usize".to_string())
            })?;
            let end = start.checked_add(size).ok_or_else(|| {
                FieldFailure::Invalid("Certificate Table file range overflows usize".to_string())
            })?;
            if start < image_tail || end > data.len() || start % 8 != 0 {
                return Err(FieldFailure::Invalid(
                    "Certificate Table is not an aligned, file-backed trailing range".to_string(),
                ));
            }
            Some(start..end)
        }
        None => None,
    };

    let mut hasher = Sha256::new();
    hasher.update(&data[..checksum_start]);
    hasher.update(&data[checksum_end..certificate_entry_start]);
    hasher.update(&data[certificate_entry_end..header_end]);
    for range in section_ranges {
        hasher.update(&data[range]);
    }

    match certificate_range {
        Some(range) => {
            hasher.update(&data[image_tail..range.start]);
            hasher.update(&data[range.end..]);
        }
        None => hasher.update(&data[image_tail..]),
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn extract_resources(
    pe: &PE<'_>,
    data: &[u8],
    output_budget: &mut super::ParseOutputBudget,
) -> FieldOutcome<Vec<ResourceLeaf>> {
    let Some(optional) = pe.header.optional_header.as_ref() else {
        return FieldOutcome::Unsupported {
            reason: "COFF objects do not have a PE optional header".to_string(),
        };
    };
    let Some(directory) = optional.data_directories.get_resource_table().copied() else {
        return FieldOutcome::Absent;
    };
    if directory.virtual_address == 0 && directory.size == 0 {
        return FieldOutcome::Absent;
    }
    if directory.virtual_address == 0 || directory.size == 0 {
        return FieldOutcome::Invalid {
            reason: "resource directory RVA and size must both be zero or non-zero".to_string(),
        };
    }

    match checked_resources(pe, data, directory, output_budget) {
        Ok(resources) => FieldOutcome::Present { value: resources },
        Err(failure) => failure.into_outcome(),
    }
}

fn checked_resources(
    pe: &PE<'_>,
    data: &[u8],
    directory: goblin::pe::data_directories::DataDirectory,
    output_budget: &mut super::ParseOutputBudget,
) -> std::result::Result<Vec<ResourceLeaf>, FieldFailure> {
    let table_range = rva_file_range(pe, data, directory.virtual_address, directory.size)?
        .ok_or_else(|| {
            FieldFailure::Invalid("resource directory is not fully file-backed".to_string())
        })?;
    let mut resources = Vec::new();
    let mut path = Vec::with_capacity(3);
    let mut ancestors = HashSet::new();
    walk_resource_directory(
        pe,
        data,
        table_range.start,
        table_range.len(),
        0,
        &mut path,
        &mut ancestors,
        &mut resources,
        output_budget,
    )?;
    Ok(resources)
}

#[allow(clippy::too_many_arguments)]
fn walk_resource_directory(
    pe: &PE<'_>,
    data: &[u8],
    table_start: usize,
    table_size: usize,
    directory_offset: usize,
    path: &mut Vec<ResourceIdentifier>,
    ancestors: &mut HashSet<usize>,
    resources: &mut Vec<ResourceLeaf>,
    output_budget: &mut super::ParseOutputBudget,
) -> std::result::Result<(), FieldFailure> {
    if path.len() >= 3 {
        return Err(FieldFailure::Invalid(
            "resource directory exceeds the type/name/language depth".to_string(),
        ));
    }
    if !ancestors.insert(directory_offset) {
        return Err(FieldFailure::Invalid(format!(
            "resource directory cycle at relative offset {directory_offset:#x}"
        )));
    }

    let header = relative_table_range(table_start, table_size, directory_offset, 16)?;
    let named = usize::from(read_u16(data, header.start + 12)?);
    let ids = usize::from(read_u16(data, header.start + 14)?);
    let count = named.checked_add(ids).ok_or_else(|| {
        FieldFailure::Invalid("resource directory entry count overflows usize".to_string())
    })?;
    output_budget
        .claim_records(count, "PE resource directory entries")
        .map_err(FieldFailure::from_budget)?;
    let entries_size = count.checked_mul(8).ok_or_else(|| {
        FieldFailure::Invalid("resource directory table size overflows usize".to_string())
    })?;
    let entries_offset = directory_offset.checked_add(16).ok_or_else(|| {
        FieldFailure::Invalid("resource directory entry offset overflows usize".to_string())
    })?;
    let entries = relative_table_range(table_start, table_size, entries_offset, entries_size)?;

    for index in 0..count {
        let entry = entries
            .start
            .checked_add(index.checked_mul(8).ok_or_else(|| {
                FieldFailure::Invalid("resource entry index overflows usize".to_string())
            })?)
            .ok_or_else(|| {
                FieldFailure::Invalid("resource entry offset overflows usize".to_string())
            })?;
        let name_or_id = read_u32(data, entry)?;
        let target = read_u32(data, entry + 4)?;
        let is_named = name_or_id & 0x8000_0000 != 0;
        if (index < named) != is_named {
            return Err(FieldFailure::Invalid(
                "resource named and numeric entry counts do not match directory order".to_string(),
            ));
        }
        let identifier =
            read_resource_identifier(data, table_start, table_size, name_or_id, output_budget)?;
        let target_offset = usize::try_from(target & 0x7fff_ffff).map_err(|_| {
            FieldFailure::Invalid("resource target offset exceeds usize".to_string())
        })?;
        let is_directory = target & 0x8000_0000 != 0;

        if path.len() < 2 {
            if !is_directory {
                return Err(FieldFailure::Invalid(
                    "resource leaf appears before the language level".to_string(),
                ));
            }
            path.push(identifier);
            walk_resource_directory(
                pe,
                data,
                table_start,
                table_size,
                target_offset,
                path,
                ancestors,
                resources,
                output_budget,
            )?;
            path.pop();
            continue;
        }

        if is_directory {
            return Err(FieldFailure::Invalid(
                "resource directory continues below the language level".to_string(),
            ));
        }
        let data_entry = relative_table_range(table_start, table_size, target_offset, 16)?;
        let data_rva = read_u32(data, data_entry.start)?;
        let size_bytes = read_u32(data, data_entry.start + 4)?;
        let code_page = read_u32(data, data_entry.start + 8)?;
        if rva_file_range(pe, data, data_rva, size_bytes)?.is_none() {
            return Err(FieldFailure::Invalid(format!(
                "resource payload RVA {data_rva:#x} size {size_bytes} is not file-backed"
            )));
        }
        let resource_type =
            clone_resource_identifier(&path[0], output_budget, "PE resource leaf type name")?;
        let resource_name =
            clone_resource_identifier(&path[1], output_budget, "PE resource leaf resource name")?;
        resources.try_reserve(1).map_err(|error| {
            FieldFailure::Invalid(format!("unable to reserve PE resource output: {error}"))
        })?;
        resources.push(ResourceLeaf {
            r#type: resource_type,
            name: resource_name,
            language: identifier,
            data_rva,
            size_bytes,
            code_page,
        });
    }

    ancestors.remove(&directory_offset);
    Ok(())
}

fn clone_resource_identifier(
    identifier: &ResourceIdentifier,
    output_budget: &mut super::ParseOutputBudget,
    context: &str,
) -> std::result::Result<ResourceIdentifier, FieldFailure> {
    match identifier {
        ResourceIdentifier::Id { id } => Ok(ResourceIdentifier::Id { id: *id }),
        ResourceIdentifier::Name { name } => output_budget
            .copy_name(name, context)
            .map(|name| ResourceIdentifier::Name { name })
            .map_err(FieldFailure::from_budget),
    }
}

fn read_resource_identifier(
    data: &[u8],
    table_start: usize,
    table_size: usize,
    name_or_id: u32,
    output_budget: &mut super::ParseOutputBudget,
) -> std::result::Result<ResourceIdentifier, FieldFailure> {
    if name_or_id & 0x8000_0000 == 0 {
        return Ok(ResourceIdentifier::Id { id: name_or_id });
    }
    let offset = usize::try_from(name_or_id & 0x7fff_ffff)
        .map_err(|_| FieldFailure::Invalid("resource name offset exceeds usize".to_string()))?;
    let length_range = relative_table_range(table_start, table_size, offset, 2)?;
    let units = usize::from(read_u16(data, length_range.start)?);
    let byte_length = units
        .checked_mul(2)
        .ok_or_else(|| FieldFailure::Invalid("resource name length overflows usize".to_string()))?;
    if byte_length > super::MAX_NAME_BYTES {
        return Err(FieldFailure::Limit(format!(
            "PE resource UTF-16 name is {byte_length} bytes; per-name limit is {}",
            super::MAX_NAME_BYTES
        )));
    }
    let value_offset = offset
        .checked_add(2)
        .ok_or_else(|| FieldFailure::Invalid("resource name offset overflows usize".to_string()))?;
    let value_range = relative_table_range(table_start, table_size, value_offset, byte_length)?;
    let utf16 = data[value_range]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect::<Vec<_>>();
    let decoded = String::from_utf16(&utf16)
        .map_err(|_| FieldFailure::Invalid("resource name contains invalid UTF-16".to_string()))?;
    let name = output_budget
        .copy_name(&decoded, "PE resource name")
        .map_err(FieldFailure::from_budget)?;
    Ok(ResourceIdentifier::Name { name })
}

fn relative_table_range(
    table_start: usize,
    table_size: usize,
    offset: usize,
    size: usize,
) -> std::result::Result<std::ops::Range<usize>, FieldFailure> {
    let end = offset.checked_add(size).ok_or_else(|| {
        FieldFailure::Invalid("resource-relative range overflows usize".to_string())
    })?;
    if end > table_size {
        return Err(FieldFailure::Invalid(
            "resource-relative range exceeds the resource directory".to_string(),
        ));
    }
    let start = table_start
        .checked_add(offset)
        .ok_or_else(|| FieldFailure::Invalid("resource file offset overflows usize".to_string()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| FieldFailure::Invalid("resource file range overflows usize".to_string()))?;
    Ok(start..end)
}

fn rva_file_range(
    pe: &PE<'_>,
    data: &[u8],
    rva: u32,
    size: u32,
) -> std::result::Result<Option<std::ops::Range<usize>>, FieldFailure> {
    let rva = u64::from(rva);
    let size = u64::from(size);
    let mut mapping = None;
    let mut candidates = 0_usize;
    if let Some(optional) = pe.header.optional_header.as_ref() {
        let headers = u64::from(optional.windows_fields.size_of_headers);
        let end = rva
            .checked_add(size)
            .ok_or_else(|| FieldFailure::Invalid("RVA range overflows u64".to_string()))?;
        if rva <= headers && end <= headers {
            let range = super::checked_file_range(data, rva, size).ok_or_else(|| {
                FieldFailure::Invalid("header RVA range is not file-backed".to_string())
            })?;
            mapping = Some(range);
            candidates = 1;
        }
    }
    for section in &pe.sections {
        let start_rva = u64::from(section.virtual_address);
        let raw_size = u64::from(section.size_of_raw_data);
        let Some(delta) = rva.checked_sub(start_rva) else {
            continue;
        };
        let end_delta = delta.checked_add(size).ok_or_else(|| {
            FieldFailure::Invalid("section-relative RVA range overflows u64".to_string())
        })?;
        if delta <= raw_size && end_delta <= raw_size {
            let file_offset = u64::from(section.pointer_to_raw_data)
                .checked_add(delta)
                .ok_or_else(|| {
                    FieldFailure::Invalid("mapped resource file offset overflows u64".to_string())
                })?;
            let range = super::checked_file_range(data, file_offset, size).ok_or_else(|| {
                FieldFailure::Invalid("mapped resource range is not file-backed".to_string())
            })?;
            candidates = candidates.saturating_add(1);
            if candidates > 1 {
                return Err(FieldFailure::Invalid(format!(
                    "RVA {rva:#x} size {size} maps to multiple file-backed ranges"
                )));
            }
            mapping = Some(range);
        }
    }
    Ok(mapping)
}

fn read_u16(data: &[u8], offset: usize) -> std::result::Result<u16, FieldFailure> {
    let bytes = data
        .get(
            offset..offset.checked_add(2).ok_or_else(|| {
                FieldFailure::Invalid("u16 file range overflows usize".to_string())
            })?,
        )
        .ok_or_else(|| FieldFailure::Invalid("u16 file range exceeds the input".to_string()))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> std::result::Result<u32, FieldFailure> {
    let bytes = data
        .get(
            offset..offset.checked_add(4).ok_or_else(|| {
                FieldFailure::Invalid("u32 file range overflows usize".to_string())
            })?,
        )
        .ok_or_else(|| FieldFailure::Invalid("u32 file range exceeds the input".to_string()))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

enum FieldFailure {
    Invalid(String),
    Unsupported(String),
    Limit(String),
}

impl FieldFailure {
    fn from_budget(error: BinaryError) -> Self {
        let message = error.to_string();
        if message.contains("limit") || message.contains("exceed") {
            Self::Limit(message)
        } else {
            Self::Invalid(message)
        }
    }

    fn into_outcome<T>(self) -> FieldOutcome<T> {
        match self {
            Self::Invalid(reason) => FieldOutcome::Invalid { reason },
            Self::Unsupported(reason) => FieldOutcome::Unsupported { reason },
            Self::Limit(limit) => FieldOutcome::LimitExceeded { limit },
        }
    }
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

    // Presence only: this is not a cryptographic trust decision.
    features.signed = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|header| header.data_directories.get_certificate_table())
        .is_some_and(|directory| directory.virtual_address != 0 && directory.size != 0);

    features
}

#[cfg(test)]
mod enrichment_tests {
    use super::*;
    use crate::{BinaryAnalyzer, EnrichedBinaryFile};

    const PE_OFFSET: usize = 0x80;
    const HEADERS_SIZE: usize = 0x200;
    const SECTION_SIZE: usize = 0x200;

    #[derive(Clone, Copy)]
    enum PeWidth {
        Pe32,
        Pe64,
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_section(
        data: &mut [u8],
        offset: usize,
        name: &[u8],
        virtual_address: u32,
        raw_offset: usize,
        characteristics: u32,
    ) {
        data[offset..offset + name.len()].copy_from_slice(name);
        put_u32(data, offset + 8, SECTION_SIZE as u32);
        put_u32(data, offset + 12, virtual_address);
        put_u32(data, offset + 16, SECTION_SIZE as u32);
        put_u32(data, offset + 20, raw_offset as u32);
        put_u32(data, offset + 36, characteristics);
    }

    fn put_resource_directory(data: &mut [u8], offset: usize, named: u16, ids: u16) {
        put_u16(data, offset + 12, named);
        put_u16(data, offset + 14, ids);
    }

    fn put_resource_entry(data: &mut [u8], offset: usize, name_or_id: u32, target: u32) {
        put_u32(data, offset, name_or_id);
        put_u32(data, offset + 4, target);
    }

    fn put_resource_name(data: &mut [u8], offset: usize, value: &str) {
        let utf16 = value.encode_utf16().collect::<Vec<_>>();
        put_u16(data, offset, utf16.len() as u16);
        for (index, unit) in utf16.into_iter().enumerate() {
            put_u16(data, offset + 2 + index * 2, unit);
        }
    }

    fn put_thunk(data: &mut [u8], offset: usize, width: PeWidth, value: u64) {
        match width {
            PeWidth::Pe32 => put_u32(data, offset, value as u32),
            PeWidth::Pe64 => put_u64(data, offset, value),
        }
    }

    fn build_fixture(width: PeWidth, signed: bool, overlay: bool, section_gap: bool) -> Vec<u8> {
        let optional_size = match width {
            PeWidth::Pe32 => 0xe0,
            PeWidth::Pe64 => 0xf0,
        };
        let optional = PE_OFFSET + 24;
        let section_table = optional + optional_size;
        let text_raw = HEADERS_SIZE;
        let idata_raw = if section_gap { 0x500 } else { 0x400 };
        let resource_raw = if section_gap { 0x700 } else { 0x600 };
        let image_end = resource_raw + SECTION_SIZE;
        let certificate_size = if signed { 16 } else { 0 };
        let overlay_size = if overlay { 7 } else { 0 };
        let mut data = vec![0_u8; image_end + overlay_size + certificate_size];

        data[..2].copy_from_slice(b"MZ");
        put_u32(&mut data, 0x3c, PE_OFFSET as u32);
        data[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        put_u16(
            &mut data,
            PE_OFFSET + 4,
            match width {
                PeWidth::Pe32 => goblin::pe::header::COFF_MACHINE_X86,
                PeWidth::Pe64 => goblin::pe::header::COFF_MACHINE_X86_64,
            },
        );
        put_u16(&mut data, PE_OFFSET + 6, 3);
        put_u16(&mut data, PE_OFFSET + 20, optional_size as u16);
        put_u16(&mut data, PE_OFFSET + 22, 0x0002);

        match width {
            PeWidth::Pe32 => {
                put_u16(&mut data, optional, goblin::pe::optional_header::MAGIC_32);
                put_u32(&mut data, optional + 16, 0x1000);
                put_u32(&mut data, optional + 20, 0x1000);
                put_u32(&mut data, optional + 24, 0x2000);
                put_u32(&mut data, optional + 28, 0x0040_0000);
                put_u32(&mut data, optional + 72, 0x10_0000);
                put_u32(&mut data, optional + 76, 0x1000);
                put_u32(&mut data, optional + 80, 0x10_0000);
                put_u32(&mut data, optional + 84, 0x1000);
                put_u32(&mut data, optional + 92, 16);
            }
            PeWidth::Pe64 => {
                put_u16(&mut data, optional, goblin::pe::optional_header::MAGIC_64);
                put_u32(&mut data, optional + 16, 0x1000);
                put_u32(&mut data, optional + 20, 0x1000);
                put_u64(&mut data, optional + 24, 0x0000_0001_4000_0000);
                put_u64(&mut data, optional + 72, 0x10_0000);
                put_u64(&mut data, optional + 80, 0x1000);
                put_u64(&mut data, optional + 88, 0x10_0000);
                put_u64(&mut data, optional + 96, 0x1000);
                put_u32(&mut data, optional + 108, 16);
            }
        }
        put_u32(&mut data, optional + 4, SECTION_SIZE as u32);
        put_u32(&mut data, optional + 8, (SECTION_SIZE * 2) as u32);
        put_u32(&mut data, optional + 32, 0x1000);
        put_u32(&mut data, optional + 36, SECTION_SIZE as u32);
        put_u16(&mut data, optional + 40, 6);
        put_u16(&mut data, optional + 48, 6);
        put_u32(&mut data, optional + 56, 0x4000);
        put_u32(&mut data, optional + 60, HEADERS_SIZE as u32);
        put_u16(&mut data, optional + 68, 3);

        let directories = optional
            + match width {
                PeWidth::Pe32 => 96,
                PeWidth::Pe64 => 112,
            };
        put_u32(&mut data, directories + 8, 0x2000);
        put_u32(&mut data, directories + 12, 60);
        put_u32(&mut data, directories + 16, 0x3000);
        put_u32(&mut data, directories + 20, SECTION_SIZE as u32);
        if signed {
            put_u32(
                &mut data,
                directories + 32,
                (image_end + overlay_size) as u32,
            );
            put_u32(&mut data, directories + 36, certificate_size as u32);
        }

        put_section(
            &mut data,
            section_table,
            b".text",
            0x1000,
            text_raw,
            0x6000_0020,
        );
        put_section(
            &mut data,
            section_table + 40,
            b".idata",
            0x2000,
            idata_raw,
            0x4000_0040,
        );
        put_section(
            &mut data,
            section_table + 80,
            b".rsrc",
            0x3000,
            resource_raw,
            0x4000_0040,
        );
        data[text_raw] = 0xc3;

        let rich_key = 0xa5a5_5a5a;
        put_u32(&mut data, 0x40, 0x536e_6144 ^ rich_key);
        put_u32(&mut data, 0x44, rich_key);
        put_u32(&mut data, 0x48, rich_key);
        put_u32(&mut data, 0x4c, rich_key);
        put_u32(&mut data, 0x50, ((1_u32 << 16) | 2) ^ rich_key);
        put_u32(&mut data, 0x54, 3 ^ rich_key);
        put_u32(&mut data, 0x58, ((4_u32 << 16) | 5) ^ rich_key);
        put_u32(&mut data, 0x5c, 6 ^ rich_key);
        data[0x60..0x64].copy_from_slice(b"Rich");
        put_u32(&mut data, 0x64, rich_key);

        let thunk_size = match width {
            PeWidth::Pe32 => 4,
            PeWidth::Pe64 => 8,
        };
        put_u32(&mut data, idata_raw, 0x2040);
        put_u32(&mut data, idata_raw + 12, 0x2080);
        put_u32(&mut data, idata_raw + 16, 0x2060);
        put_u32(&mut data, idata_raw + 20, 0x20c0);
        put_u32(&mut data, idata_raw + 32, 0x2100);
        put_u32(&mut data, idata_raw + 36, 0x20e0);
        let ordinal_flag = match width {
            PeWidth::Pe32 => u64::from(goblin::pe::import::IMPORT_BY_ORDINAL_32),
            PeWidth::Pe64 => goblin::pe::import::IMPORT_BY_ORDINAL_64,
        };
        for base in [idata_raw + 0x40, idata_raw + 0x60] {
            put_thunk(&mut data, base, width, 0x2090);
            put_thunk(&mut data, base + thunk_size, width, ordinal_flag | 24);
            put_thunk(&mut data, base + thunk_size * 2, width, 0x2090);
        }
        for base in [idata_raw + 0xc0, idata_raw + 0xe0] {
            put_thunk(&mut data, base, width, ordinal_flag | 2);
            put_thunk(&mut data, base + thunk_size, width, ordinal_flag | 500);
        }
        data[idata_raw + 0x80..idata_raw + 0x8b].copy_from_slice(b"WS2_32.dll\0");
        data[idata_raw + 0x92..idata_raw + 0x9f].copy_from_slice(b"GetAddrInfoW\0");
        data[idata_raw + 0x100..idata_raw + 0x10d].copy_from_slice(b"OLEAUT32.dll\0");

        put_resource_directory(&mut data, resource_raw, 1, 1);
        put_resource_entry(&mut data, resource_raw + 0x10, 0x8000_0180, 0x8000_0060);
        put_resource_entry(&mut data, resource_raw + 0x18, 10, 0x8000_0020);
        put_resource_directory(&mut data, resource_raw + 0x20, 0, 1);
        put_resource_entry(&mut data, resource_raw + 0x30, 1, 0x8000_0040);
        put_resource_directory(&mut data, resource_raw + 0x40, 0, 2);
        put_resource_entry(&mut data, resource_raw + 0x50, 1033, 0xa0);
        put_resource_entry(&mut data, resource_raw + 0x58, 1031, 0xb0);
        put_resource_directory(&mut data, resource_raw + 0x60, 1, 0);
        put_resource_entry(&mut data, resource_raw + 0x70, 0x8000_0190, 0x8000_0080);
        put_resource_directory(&mut data, resource_raw + 0x80, 0, 1);
        put_resource_entry(&mut data, resource_raw + 0x90, 1033, 0xc0);
        for (entry, rva, value) in [
            (0xa0, 0x30d0, *b"NUM1"),
            (0xb0, 0x30d4, *b"NUM2"),
            (0xc0, 0x30d8, *b"NAME"),
        ] {
            put_u32(&mut data, resource_raw + entry, rva);
            put_u32(&mut data, resource_raw + entry + 4, 4);
            put_u32(&mut data, resource_raw + entry + 8, 1200);
            data[resource_raw + usize::try_from(rva - 0x3000).unwrap()
                ..resource_raw + usize::try_from(rva - 0x3000).unwrap() + 4]
                .copy_from_slice(&value);
        }
        put_resource_name(&mut data, resource_raw + 0x180, "CUSTOM");
        put_resource_name(&mut data, resource_raw + 0x190, "1");

        if overlay {
            data[image_end..image_end + 7].copy_from_slice(b"OVERLAY");
        }
        if signed {
            let certificate = image_end + overlay_size;
            put_u32(&mut data, certificate, certificate_size as u32);
            put_u16(&mut data, certificate + 4, 0x0200);
            put_u16(&mut data, certificate + 6, 0x0002);
            data[certificate + 8..certificate + 16].copy_from_slice(b"TESTCERT");
        }
        data
    }

    fn present_pe(data: &[u8]) -> PeStaticMetadata {
        match PeParser::parse_enriched(data).unwrap().1 {
            FieldOutcome::Present { value } => value,
            outcome => panic!("expected PE metadata, got {outcome:?}"),
        }
    }

    fn parse_for_authentihash(data: &[u8]) -> PE<'_> {
        let mut options = goblin::pe::options::ParseOptions::default()
            .with_parse_imports(false)
            .with_parse_resources(false);
        options.parse_attribute_certificates = false;
        PE::parse_with_opts(data, &options).unwrap()
    }

    #[test]
    fn frozen_pefile_ordinals_cover_mixed_case_and_fallbacks() {
        assert_eq!(
            super::super::pe_ordinals::lookup("ws2_32", 24),
            Some("getaddrinfow")
        );
        assert_eq!(
            super::super::pe_ordinals::lookup("wsock32", 24),
            Some("getaddrinfow")
        );
        assert_eq!(
            super::super::pe_ordinals::lookup("oleaut32", 2),
            Some("sysallocstring")
        );
        assert_eq!(super::super::pe_ordinals::lookup("oleaut32", 500), None);
    }

    #[test]
    fn imphash_matches_pinned_pefile_order_ordinals_and_duplicates() {
        for width in [PeWidth::Pe32, PeWidth::Pe64] {
            let metadata = present_pe(&build_fixture(width, false, false, false));
            assert_eq!(
                metadata.imphash,
                FieldOutcome::Present {
                    value: "7684b36d94140192cfc39dac79e7a5fa".to_string()
                }
            );
        }
    }

    #[test]
    fn rich_header_and_resources_preserve_order_names_ids_and_languages() {
        let metadata = present_pe(&build_fixture(PeWidth::Pe64, false, false, false));
        assert_eq!(
            metadata.rich_header,
            FieldOutcome::Present {
                value: RichHeader {
                    xor_key: 0xa5a5_5a5a,
                    entries: vec![
                        RichHeaderEntry {
                            product_id: 1,
                            build: 2,
                            use_count: 3,
                        },
                        RichHeaderEntry {
                            product_id: 4,
                            build: 5,
                            use_count: 6,
                        },
                    ],
                }
            }
        );
        let FieldOutcome::Present { value: resources } = metadata.resources else {
            panic!("expected resources");
        };
        assert_eq!(resources.len(), 3);
        assert_eq!(
            resources[0].r#type,
            ResourceIdentifier::Name {
                name: "CUSTOM".to_string()
            }
        );
        assert_eq!(
            resources[0].name,
            ResourceIdentifier::Name {
                name: "1".to_string()
            }
        );
        assert_eq!(resources[1].r#type, ResourceIdentifier::Id { id: 10 });
        assert_eq!(resources[1].language, ResourceIdentifier::Id { id: 1033 });
        assert_eq!(resources[2].language, ResourceIdentifier::Id { id: 1031 });

        let mut empty_rich = build_fixture(PeWidth::Pe64, false, false, false);
        empty_rich[0x50..0x68].fill(0);
        empty_rich[0x50..0x54].copy_from_slice(b"Rich");
        put_u32(&mut empty_rich, 0x54, 0xa5a5_5a5a);
        assert_eq!(
            present_pe(&empty_rich).rich_header,
            FieldOutcome::Present {
                value: RichHeader {
                    xor_key: 0xa5a5_5a5a,
                    entries: Vec::new(),
                }
            }
        );

        let mut missing_rich = build_fixture(PeWidth::Pe64, false, false, false);
        missing_rich[0x60..0x64].fill(0);
        assert_eq!(present_pe(&missing_rich).rich_header, FieldOutcome::Absent);
    }

    #[test]
    fn byte_and_parsed_enriched_entry_points_are_equivalent() {
        let data = build_fixture(PeWidth::Pe64, false, false, false);
        let analyzer = BinaryAnalyzer::new();
        let from_bytes = analyzer.analyze_enriched(&data).unwrap();
        let parsed = EnrichedBinaryFile::parse(&data).unwrap();
        let from_parsed = analyzer.analyze_enriched_binary(&parsed).unwrap();
        assert_eq!(from_bytes.static_metadata, from_parsed.static_metadata);
        assert_eq!(from_bytes.analysis.format, Format::Pe);
        assert_eq!(
            from_bytes
                .static_metadata
                .provenance
                .input_sha256
                .as_deref(),
            Some("e9da6dad7eacd36b9b6aa1796e5b8e3f5c18b587468309996ea85a8907a2d9d0")
        );
        assert!(
            from_bytes
                .static_metadata
                .provenance
                .feature_profile
                .as_ref()
                .is_some_and(|features| features.iter().any(|feature| feature == "pe"))
        );
    }

    #[test]
    fn missing_imports_are_absent_and_failed_enumeration_is_invalid() {
        let mut absent = build_fixture(PeWidth::Pe64, false, false, false);
        let directories = PE_OFFSET + 24 + 112;
        put_u32(&mut absent, directories + 8, 0);
        put_u32(&mut absent, directories + 12, 0);
        assert_eq!(present_pe(&absent).imphash, FieldOutcome::Absent);

        let mut fallback = build_fixture(PeWidth::Pe64, false, false, false);
        put_u32(&mut fallback, 0x400, 0);
        assert_eq!(
            present_pe(&fallback).imphash,
            FieldOutcome::Present {
                value: "7684b36d94140192cfc39dac79e7a5fa".to_string()
            }
        );

        let mut invalid = build_fixture(PeWidth::Pe64, false, false, false);
        invalid[0x480] = 0;
        assert!(matches!(
            present_pe(&invalid).imphash,
            FieldOutcome::Invalid { .. }
        ));

        let mut oversized_library = build_fixture(PeWidth::Pe64, false, false, false);
        oversized_library.resize(0x1800, 0);
        oversized_library[0x414..0x428].fill(0);
        put_u64(&mut oversized_library, 0x440, 0);
        oversized_library[0x480..0x480 + super::super::MAX_NAME_BYTES + 1].fill(b'A');
        oversized_library[0x480 + super::super::MAX_NAME_BYTES + 1] = 0;
        assert!(matches!(
            present_pe(&oversized_library).imphash,
            FieldOutcome::LimitExceeded { .. }
        ));
    }

    #[test]
    fn malformed_rich_and_resources_remain_field_scoped() {
        let mut rich = build_fixture(PeWidth::Pe64, false, false, false);
        put_u32(&mut rich, 0x40, 0);
        let metadata = present_pe(&rich);
        assert!(matches!(metadata.rich_header, FieldOutcome::Invalid { .. }));
        assert!(matches!(metadata.imphash, FieldOutcome::Present { .. }));

        let mut two_markers = build_fixture(PeWidth::Pe64, false, false, false);
        two_markers[0x50..0x54].copy_from_slice(b"Rich");
        put_u32(&mut two_markers, 0x54, 0);
        let metadata = present_pe(&two_markers);
        assert!(matches!(metadata.rich_header, FieldOutcome::Invalid { .. }));
        assert!(matches!(metadata.resources, FieldOutcome::Present { .. }));

        let mut cycle = build_fixture(PeWidth::Pe64, false, false, false);
        put_resource_entry(&mut cycle, 0x600 + 0x30, 1, 0x8000_0020);
        let metadata = present_pe(&cycle);
        assert!(matches!(metadata.resources, FieldOutcome::Invalid { .. }));
        assert!(matches!(
            metadata.authentihash,
            FieldOutcome::Present { .. }
        ));

        let mut payload = build_fixture(PeWidth::Pe64, false, false, false);
        put_u32(&mut payload, 0x600 + 0xa0, 0xffff_f000);
        let metadata = present_pe(&payload);
        assert!(matches!(metadata.resources, FieldOutcome::Invalid { .. }));
        assert!(matches!(metadata.imphash, FieldOutcome::Present { .. }));
    }

    #[test]
    fn resources_distinguish_absent_empty_limits_and_ambiguous_rvas() {
        let mut absent = build_fixture(PeWidth::Pe64, false, false, false);
        let directories = PE_OFFSET + 24 + 112;
        put_u32(&mut absent, directories + 16, 0);
        put_u32(&mut absent, directories + 20, 0);
        assert_eq!(present_pe(&absent).resources, FieldOutcome::Absent);

        let mut empty = build_fixture(PeWidth::Pe64, false, false, false);
        put_resource_directory(&mut empty, 0x600, 0, 0);
        assert_eq!(
            present_pe(&empty).resources,
            FieldOutcome::Present { value: Vec::new() }
        );

        let mut oversized_name = build_fixture(PeWidth::Pe64, false, false, false);
        put_u16(&mut oversized_name, 0x600 + 0x180, u16::MAX);
        assert!(matches!(
            present_pe(&oversized_name).resources,
            FieldOutcome::LimitExceeded { .. }
        ));

        let mut invalid_name = build_fixture(PeWidth::Pe64, false, false, false);
        put_u16(&mut invalid_name, 0x600 + 0x180, 1);
        put_u16(&mut invalid_name, 0x600 + 0x182, 0xd800);
        assert!(matches!(
            present_pe(&invalid_name).resources,
            FieldOutcome::Invalid { .. }
        ));

        let mut empty_name = build_fixture(PeWidth::Pe64, false, false, false);
        put_u16(&mut empty_name, 0x600 + 0x180, 0);
        let FieldOutcome::Present { value: resources } = present_pe(&empty_name).resources else {
            panic!("expected resources with an empty name");
        };
        assert_eq!(
            resources[0].r#type,
            ResourceIdentifier::Name {
                name: String::new()
            }
        );

        let fixture = build_fixture(PeWidth::Pe64, false, false, false);
        let options = goblin::pe::options::ParseOptions::default().with_parse_resources(false);
        let pe = PE::parse_with_opts(&fixture, &options).unwrap();
        let mut budget = super::super::ParseOutputBudget {
            records: super::super::MAX_PARSED_RECORDS - 1,
            name_bytes: 0,
        };
        assert!(matches!(
            extract_resources(&pe, &fixture, &mut budget),
            FieldOutcome::LimitExceeded { .. }
        ));

        let named = ResourceIdentifier::Name {
            name: "named".to_string(),
        };
        let mut clone_budget = super::super::ParseOutputBudget {
            records: 0,
            name_bytes: super::super::MAX_OWNED_NAME_BYTES - 5,
        };
        assert_eq!(
            clone_resource_identifier(&named, &mut clone_budget, "test resource clone").ok(),
            Some(named.clone())
        );
        assert!(matches!(
            clone_resource_identifier(&named, &mut clone_budget, "test resource clone"),
            Err(FieldFailure::Limit(_))
        ));

        let mut ambiguous = build_fixture(PeWidth::Pe64, false, false, false);
        let idata_section = PE_OFFSET + 24 + 0xf0 + 40;
        put_u32(&mut ambiguous, idata_section + 12, 0x3000);
        let options = goblin::pe::options::ParseOptions::default()
            .with_parse_resources(false)
            .with_parse_imports(false);
        let pe = PE::parse_with_opts(&ambiguous, &options).unwrap();
        let mut budget = super::super::ParseOutputBudget::default();
        assert!(matches!(
            extract_resources(&pe, &ambiguous, &mut budget),
            FieldOutcome::Invalid { .. }
        ));
    }

    #[test]
    fn authentihash_matches_lief_goldens_and_excludes_terminal_certificate() {
        let pe32 = present_pe(&build_fixture(PeWidth::Pe32, false, false, false));
        let pe64 = present_pe(&build_fixture(PeWidth::Pe64, false, false, false));
        let signed = present_pe(&build_fixture(PeWidth::Pe64, true, false, false));
        let overlay = present_pe(&build_fixture(PeWidth::Pe64, false, true, false));

        assert_eq!(
            pe32.authentihash,
            FieldOutcome::Present {
                value: AuthenticodeHash {
                    algorithm: "sha256".to_string(),
                    digest: "7e0bd00a7d1fec5675722ab51006f0c540dca3f969de66b0592f892058ef6f2e"
                        .to_string()
                }
            }
        );
        assert_eq!(
            pe64.authentihash,
            FieldOutcome::Present {
                value: AuthenticodeHash {
                    algorithm: "sha256".to_string(),
                    digest: "1f3c262a4dd40a4c1bf14f328ee07913a031cffdcb6f3c1c7bc7b23f8ac41e15"
                        .to_string()
                }
            }
        );
        assert_eq!(signed.authentihash, pe64.authentihash);
        let signed_analysis = BinaryAnalyzer::new()
            .analyze_enriched(&build_fixture(PeWidth::Pe64, true, false, false))
            .unwrap();
        assert!(signed_analysis.analysis.metadata.security_features.signed);
        assert_eq!(
            overlay.authentihash,
            FieldOutcome::Present {
                value: AuthenticodeHash {
                    algorithm: "sha256".to_string(),
                    digest: "93232b0c786b5111217c721596dba9da653983886e9bc0a3b81b45a0975f1ac2"
                        .to_string()
                }
            }
        );
    }

    #[test]
    fn authentihash_rejects_gap_overlap_and_non_file_backed_sections() {
        let gap = build_fixture(PeWidth::Pe64, false, false, true);
        let gap_pe = parse_for_authentihash(&gap);
        assert!(matches!(
            extract_authentihash(&gap_pe, &gap),
            FieldOutcome::Unsupported { .. }
        ));

        let mut overlap = build_fixture(PeWidth::Pe64, false, false, false);
        let second_section = PE_OFFSET + 24 + 0xf0 + 40;
        put_u32(&mut overlap, second_section + 20, 0x300);
        let overlap_pe = parse_for_authentihash(&overlap);
        assert!(matches!(
            extract_authentihash(&overlap_pe, &overlap),
            FieldOutcome::Unsupported { .. }
        ));

        let mut outside = build_fixture(PeWidth::Pe64, false, false, false);
        let third_section = second_section + 40;
        put_u32(&mut outside, third_section + 20, 0xffff_f000);
        let outside_pe = parse_for_authentihash(&outside);
        assert!(matches!(
            extract_authentihash(&outside_pe, &outside),
            FieldOutcome::Invalid { .. }
        ));
    }
}
