//! Mach-O format parser for macOS/iOS binaries

use crate::{
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding, SymbolType,
        SymbolVisibility,
    },
};
use goblin::mach::{Mach, MachO};
use goblin::mach::{
    exports::{
        EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, EXPORT_SYMBOL_FLAGS_KIND_MASK,
        ExportInfo as MachExportInfo,
    },
    header,
    load_command::CommandVariant,
};

mod dyld_preflight;
mod load_command_preflight;

const FAT_MAGIC_32: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
const FAT_CIGAM_32: [u8; 4] = [0xbe, 0xba, 0xfe, 0xca];
const FAT_MAGIC_64: [u8; 4] = [0xca, 0xfe, 0xba, 0xbf];
const FAT_CIGAM_64: [u8; 4] = [0xbf, 0xba, 0xfe, 0xca];
const FAT_HEADER_SIZE: usize = 8;
const FAT_ARCH_32_SIZE: usize = 20;
const FAT_ARCH_64_SIZE: usize = 32;
const MAX_FAT_ARCHITECTURES: usize = 32;

/// Mach-O format parser
pub struct MachOParser;

impl BinaryFormatParser for MachOParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        if is_universal_macho(data) {
            return Err(BinaryError::unsupported_format(
                "Universal (fat) Mach-O binaries are not supported",
            ));
        }

        // Goblin 0.10 uses unchecked host-sized arithmetic for selected load
        // command strings, nlist names, and LC_MAIN address construction.
        // Validate those operands from the raw bytes before invoking it.
        load_command_preflight::validate(data)?;
        let mach = Mach::parse(data)?;
        match mach {
            Mach::Binary(macho) => Ok(Box::new(MachOBinary::new(macho, data)?)),
            Mach::Fat(_) => Err(BinaryError::unsupported_format(
                "Universal (fat) Mach-O binaries are not supported",
            )),
        }
    }

    fn can_parse(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        matches!(
            magic,
            goblin::mach::header::MH_MAGIC
                | goblin::mach::header::MH_CIGAM
                | goblin::mach::header::MH_MAGIC_64
                | goblin::mach::header::MH_CIGAM_64
        ) || is_universal_macho(data)
    }
}

fn is_universal_macho(data: &[u8]) -> bool {
    let Some(header) = data.get(..FAT_HEADER_SIZE) else {
        return false;
    };

    let magic = [header[0], header[1], header[2], header[3]];
    let count_bytes = [header[4], header[5], header[6], header[7]];
    let (architecture_count, architecture_size) = match magic {
        FAT_MAGIC_32 => (u32::from_be_bytes(count_bytes), FAT_ARCH_32_SIZE),
        FAT_CIGAM_32 => (u32::from_le_bytes(count_bytes), FAT_ARCH_32_SIZE),
        FAT_MAGIC_64 => (u32::from_be_bytes(count_bytes), FAT_ARCH_64_SIZE),
        FAT_CIGAM_64 => (u32::from_le_bytes(count_bytes), FAT_ARCH_64_SIZE),
        _ => return false,
    };

    let Ok(architecture_count) = usize::try_from(architecture_count) else {
        return false;
    };
    if !(1..=MAX_FAT_ARCHITECTURES).contains(&architecture_count) {
        return false;
    }

    architecture_size
        .checked_mul(architecture_count)
        .and_then(|table_size| FAT_HEADER_SIZE.checked_add(table_size))
        .is_some_and(|table_end| table_end <= data.len())
}

/// Parsed Mach-O binary
pub struct MachOBinary {
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl MachOBinary {
    fn new(macho: MachO<'_>, data: &[u8]) -> Result<Self> {
        let mut output_budget = super::ParseOutputBudget::default();
        dyld_preflight::validate(&macho, data)?;

        // Convert architecture
        let architecture = match macho.header.cputype() {
            goblin::mach::constants::cputype::CPU_TYPE_X86 => Architecture::X86,
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => Architecture::X86_64,
            goblin::mach::constants::cputype::CPU_TYPE_ARM => Architecture::Arm,
            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => Architecture::Arm64,
            goblin::mach::constants::cputype::CPU_TYPE_POWERPC => Architecture::PowerPC,
            goblin::mach::constants::cputype::CPU_TYPE_POWERPC64 => Architecture::PowerPC64,
            _ => Architecture::Unknown,
        };

        // Determine endianness from the original data parsing
        // Goblin normalizes magic numbers, so we need to check the raw bytes
        let endian = if data.len() >= 4 {
            let raw_magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

            // Check for big endian magic (raw bytes match canonical form)
            if raw_magic_be == header::MH_MAGIC || raw_magic_be == header::MH_MAGIC_64 {
                Endianness::Big
            } else {
                // All other cases (including CIGAM variants) are little endian
                Endianness::Little
            }
        } else {
            Endianness::Little // Default for malformed data
        };

        // Analyze security features
        let security_features = analyze_security_features(&macho);

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::MachO,
            architecture,
            entry_point: find_entry_point(&macho),
            base_address: preferred_base_address(&macho),
            timestamp: None, // Not readily available in Mach-O
            compiler_info: None,
            endian,
            security_features,
        };

        // Parse sections
        let sections = parse_sections(&macho, data, &mut output_budget)?;

        // Parse symbols
        let symbols = parse_symbols(&macho, &mut output_budget)?;

        // Parse imports and exports
        let (imports, exports) = parse_imports_exports(&macho, &mut output_budget)?;

        Ok(Self {
            metadata,
            sections,
            symbols,
            imports,
            exports,
        })
    }
}

impl BinaryFormatTrait for MachOBinary {
    fn format_type(&self) -> Format {
        Format::MachO
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
    macho: &MachO,
    data: &[u8],
    output_budget: &mut super::ParseOutputBudget,
) -> Result<Vec<Section>> {
    use goblin::mach::constants::{
        S_ATTR_DEBUG, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL, S_ZEROFILL, SECTION_TYPE,
    };

    let mut sections = Vec::new();

    for segment in &macho.segments {
        for (section, _) in &segment.sections()? {
            output_budget.reserve_record(&mut sections, "Mach-O sections")?;
            let name = output_budget
                .copy_name(section.name().unwrap_or("unknown"), "Mach-O section name")?;

            // Determine section type based on native flags before applying name
            // heuristics. Zero-fill sections have no bytes in the file.
            let native_section_type = section.flags & SECTION_TYPE;
            let is_zero_fill = matches!(
                native_section_type,
                S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
            );
            let section_type = if is_zero_fill {
                SectionType::Bss
            } else if section.flags & S_ATTR_DEBUG != 0 {
                SectionType::Debug
            } else if section.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS != 0
                || name.starts_with("__text")
            {
                SectionType::Code
            } else if name.starts_with("__data") {
                SectionType::Data
            } else if name.starts_with("__const") || name.starts_with("__rodata") {
                SectionType::ReadOnlyData
            } else if name.starts_with("__bss") {
                SectionType::Bss
            } else if name.starts_with("__debug") {
                SectionType::Debug
            } else {
                SectionType::Other("MACHO_SECTION".to_string())
            };

            // Mach-O section permissions are inherited from segment
            let permissions = SectionPermissions {
                read: segment.initprot & 0x1 != 0,    // VM_PROT_READ
                write: segment.initprot & 0x2 != 0,   // VM_PROT_WRITE
                execute: segment.initprot & 0x4 != 0, // VM_PROT_EXECUTE
            };

            let has_file_data = !is_zero_fill && section.size != 0;
            if has_file_data
                && super::checked_file_range(data, u64::from(section.offset), section.size)
                    .is_none()
            {
                return Err(BinaryError::invalid_data(format!(
                    "Mach-O section '{name}' range {}..+{} exceeds the file",
                    section.offset, section.size
                )));
            }

            // Extract small section data
            let section_data = if has_file_data {
                super::inline_section_data(data, u64::from(section.offset), section.size)
            } else {
                None
            };

            sections.push(Section {
                name,
                address: section.addr,
                size: section.size,
                offset: section.offset as u64,
                file_size: if has_file_data { section.size } else { 0 },
                permissions,
                section_type,
                data: section_data,
            });
        }
    }

    Ok(sections)
}

fn parse_symbols(
    macho: &MachO,
    output_budget: &mut super::ParseOutputBudget,
) -> Result<Vec<Symbol>> {
    use goblin::mach::symbols::{N_FUN, N_OSO, N_PEXT, N_SECT, N_SO, N_SOL, N_STAB, N_UNDF};

    let mut symbols = Vec::new();

    for entry in macho.symbols() {
        let (name, native) = entry?;
        if name.is_empty() {
            continue;
        }
        output_budget.reserve_record(&mut symbols, "Mach-O symbols")?;

        let symbol_type = if native.n_type & N_STAB != 0 {
            match native.n_type {
                N_FUN => SymbolType::Function,
                N_SO | N_OSO | N_SOL => SymbolType::File,
                other => SymbolType::Other(format!("N_STAB_{other:#04x}")),
            }
        } else {
            match native.get_type() {
                N_SECT => SymbolType::Other("N_SECT".to_string()),
                N_UNDF => SymbolType::Other("N_UNDF".to_string()),
                other => SymbolType::Other(format!("MACH_N_TYPE_{other:#04x}")),
            }
        };

        let binding = if native.is_weak() {
            SymbolBinding::Weak
        } else if native.is_global() {
            SymbolBinding::Global
        } else {
            SymbolBinding::Local
        };

        symbols.push(Symbol {
            name: output_budget.copy_name(name, "Mach-O symbol name")?,
            demangled_name: None,
            address: native.n_value,
            // Mach-O nlist records do not carry symbol sizes.
            size: 0,
            symbol_type,
            binding,
            visibility: if native.n_type & N_PEXT != 0 {
                SymbolVisibility::Internal
            } else {
                SymbolVisibility::Default
            },
            // Mach-O section ordinals are one-based; the public representation
            // uses zero-based vector indexes like the other parsers.
            section_index: native.n_sect.checked_sub(1),
        });
    }

    Ok(symbols)
}

fn parse_imports_exports(
    macho: &MachO,
    output_budget: &mut super::ParseOutputBudget,
) -> crate::types::ImportExportResult {
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let image_base = preferred_base_address(macho).unwrap_or(0);

    // Parse imports from bind info
    for import in &macho.imports()? {
        output_budget.reserve_record(&mut imports, "Mach-O imports")?;
        imports.push(Import {
            name: output_budget.copy_name(import.name, "Mach-O import name")?,
            library: Some(output_budget.copy_name(import.dylib, "Mach-O import library")?),
            address: Some(import.address),
            ordinal: None,
        });
    }

    // Parse exports from export info
    for export in &macho.exports()? {
        output_budget.reserve_record(&mut exports, "Mach-O exports")?;
        let name = output_budget.copy_name(&export.name, "Mach-O export name")?;
        let (relative_address, should_rebase, forwarded_name) = match &export.info {
            MachExportInfo::Regular { flags, .. } => (
                export.offset,
                flags & EXPORT_SYMBOL_FLAGS_KIND_MASK != EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,
                None,
            ),
            MachExportInfo::Stub { stub_offset, .. } => (u64::from(*stub_offset), true, None),
            MachExportInfo::Reexport {
                lib,
                lib_symbol_name,
                ..
            } => (
                0,
                false,
                Some(macho_reexport_name(
                    output_budget,
                    lib,
                    *lib_symbol_name,
                    name.as_str(),
                )?),
            ),
        };
        let address = if forwarded_name.is_some() {
            0
        } else {
            resolved_export_address(image_base, relative_address, should_rebase, &name)?
        };

        exports.push(Export {
            name,
            address,
            ordinal: None,
            forwarded_name,
        });
    }

    Ok((imports, exports))
}

fn resolved_export_address(
    image_base: u64,
    address: u64,
    should_rebase: bool,
    name: &str,
) -> Result<u64> {
    if !should_rebase {
        return Ok(address);
    }

    image_base.checked_add(address).ok_or_else(|| {
        BinaryError::invalid_data(format!("Mach-O export '{name}' address overflows u64"))
    })
}

fn macho_reexport_name(
    output_budget: &mut super::ParseOutputBudget,
    lib: &str,
    symbol_name: Option<&str>,
    exported_name: &str,
) -> Result<String> {
    output_budget.copy_name_parts(
        &[lib, ":", symbol_name.unwrap_or(exported_name)],
        "Mach-O reexport name",
    )
}

fn analyze_security_features(macho: &MachO) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // Check file type and flags for security features
    let flags = macho.header.flags;

    // PIE (Position Independent Executable)
    features.pie = flags & goblin::mach::header::MH_PIE != 0;

    // ASLR is generally enabled with PIE on macOS
    features.aslr = features.pie;

    // The absence of MH_ALLOW_STACK_EXECUTION requests a non-executable stack;
    // MH_NO_HEAP_EXECUTION independently requests a non-executable heap.
    features.nx_bit =
        flags & header::MH_ALLOW_STACK_EXECUTION == 0 || flags & header::MH_NO_HEAP_EXECUTION != 0;

    // Check for stack canaries (would need more complex analysis)
    features.stack_canary = false; // Would need to analyze for __stack_chk_guard

    // This records the presence of a code-signature load command. It does not
    // cryptographically validate the signature or establish trust.
    features.signed = macho
        .load_commands
        .iter()
        .any(|load_command| matches!(&load_command.command, CommandVariant::CodeSignature(_)));

    features
}

fn find_entry_point(macho: &MachO) -> Option<u64> {
    (macho.entry != 0).then_some(macho.entry)
}

fn preferred_base_address(macho: &MachO) -> Option<u64> {
    macho
        .segments
        .iter()
        .find_map(|segment| {
            (segment.filesize != 0 && segment.name().is_ok_and(|name| name == "__TEXT"))
                .then(|| segment.vmaddr.checked_sub(segment.fileoff))
                .flatten()
        })
        .or_else(|| {
            macho
                .segments
                .iter()
                .filter(|segment| segment.filesize != 0)
                .filter_map(|segment| segment.vmaddr.checked_sub(segment.fileoff))
                .min()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn universal_header(magic: [u8; 4], count: u32, little_endian: bool, is_64: bool) -> Vec<u8> {
        let record_size = if is_64 {
            FAT_ARCH_64_SIZE
        } else {
            FAT_ARCH_32_SIZE
        };
        let mut data = vec![0; FAT_HEADER_SIZE + record_size * count as usize];
        data[..4].copy_from_slice(&magic);
        let count_bytes = if little_endian {
            count.to_le_bytes()
        } else {
            count.to_be_bytes()
        };
        data[4..8].copy_from_slice(&count_bytes);
        data
    }

    fn macho_with_segments(segments: &[(&str, u64, u64, u64)]) -> Vec<u8> {
        const HEADER_SIZE: usize = 32;
        const SEGMENT_COMMAND_SIZE: usize = 72;

        let commands_size = SEGMENT_COMMAND_SIZE * segments.len();
        let mut data = vec![0_u8; HEADER_SIZE + commands_size];
        data[..4].copy_from_slice(&header::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
        data[8..12].copy_from_slice(&3_u32.to_le_bytes());
        data[12..16].copy_from_slice(&2_u32.to_le_bytes());
        data[16..20].copy_from_slice(&(segments.len() as u32).to_le_bytes());
        data[20..24].copy_from_slice(&(commands_size as u32).to_le_bytes());

        for (index, (name, vmaddr, fileoff, filesize)) in segments.iter().enumerate() {
            let offset = HEADER_SIZE + index * SEGMENT_COMMAND_SIZE;
            data[offset..offset + 4].copy_from_slice(&0x19_u32.to_le_bytes());
            data[offset + 4..offset + 8]
                .copy_from_slice(&(SEGMENT_COMMAND_SIZE as u32).to_le_bytes());
            data[offset + 8..offset + 8 + name.len()].copy_from_slice(name.as_bytes());
            data[offset + 24..offset + 32].copy_from_slice(&vmaddr.to_le_bytes());
            data[offset + 32..offset + 40].copy_from_slice(&0x1000_u64.to_le_bytes());
            data[offset + 40..offset + 48].copy_from_slice(&fileoff.to_le_bytes());
            data[offset + 48..offset + 56].copy_from_slice(&filesize.to_le_bytes());
        }

        let required_file_size = segments
            .iter()
            .filter_map(|(_, _, fileoff, filesize)| fileoff.checked_add(*filesize))
            .filter_map(|end| usize::try_from(end).ok())
            .max()
            .unwrap_or(data.len());
        data.resize(data.len().max(required_file_size), 0);

        data
    }

    fn parse_thin_macho(data: &[u8]) -> MachO<'_> {
        match Mach::parse(data).expect("test Mach-O must parse") {
            Mach::Binary(macho) => macho,
            Mach::Fat(_) => panic!("expected a thin Mach-O"),
        }
    }

    #[test]
    fn universal_header_recognition_is_bounded_and_supports_both_widths() {
        assert!(is_universal_macho(&universal_header(
            FAT_MAGIC_32,
            2,
            false,
            false
        )));
        assert!(is_universal_macho(&universal_header(
            FAT_CIGAM_32,
            2,
            true,
            false
        )));
        assert!(is_universal_macho(&universal_header(
            FAT_MAGIC_64,
            1,
            false,
            true
        )));
        assert!(is_universal_macho(&universal_header(
            FAT_CIGAM_64,
            1,
            true,
            true
        )));

        assert!(!is_universal_macho(&FAT_MAGIC_32));
        assert!(!is_universal_macho(&universal_header(
            FAT_MAGIC_32,
            0,
            false,
            false
        )));
        assert!(!is_universal_macho(&universal_header(
            FAT_MAGIC_32,
            (MAX_FAT_ARCHITECTURES + 1) as u32,
            false,
            false
        )));
    }

    #[test]
    fn preferred_base_uses_file_backed_text_segment() {
        let data = macho_with_segments(&[
            ("__PAGEZERO", 0, 0, 0),
            ("__DATA", 0x9000, 0x1000, 0x100),
            ("__TEXT", 0x1_0000_4000, 0x4000, 0x100),
        ]);
        let macho = parse_thin_macho(&data);

        assert_eq!(preferred_base_address(&macho), Some(0x1_0000_0000));
    }

    #[test]
    fn preferred_base_falls_back_to_lowest_file_backed_segment() {
        let data = macho_with_segments(&[
            ("__PAGEZERO", 0, 0, 0),
            ("__LINKEDIT", 0xa000, 0x1000, 0x100),
            ("__DATA", 0x9000, 0x1000, 0x100),
        ]);
        let macho = parse_thin_macho(&data);

        assert_eq!(preferred_base_address(&macho), Some(0x8000));
    }

    #[test]
    fn export_addresses_are_rebased_with_checked_arithmetic() {
        assert_eq!(
            resolved_export_address(0x1_0000_0000, 0x1234, true, "_entry").unwrap(),
            0x1_0000_1234
        );
        assert_eq!(
            resolved_export_address(0x1_0000_0000, 0x1234, false, "_absolute").unwrap(),
            0x1234
        );
        assert!(resolved_export_address(u64::MAX, 1, true, "_overflow").is_err());
    }

    #[test]
    fn reexports_retain_library_and_target_symbol() {
        let mut output_budget = crate::formats::ParseOutputBudget::default();
        assert_eq!(
            macho_reexport_name(
                &mut output_budget,
                "/usr/lib/libSystem.B.dylib",
                Some("_malloc"),
                "_alloc"
            )
            .unwrap(),
            "/usr/lib/libSystem.B.dylib:_malloc"
        );
        assert_eq!(
            macho_reexport_name(
                &mut output_budget,
                "/usr/lib/libSystem.B.dylib",
                None,
                "_malloc"
            )
            .unwrap(),
            "/usr/lib/libSystem.B.dylib:_malloc"
        );
    }
}
