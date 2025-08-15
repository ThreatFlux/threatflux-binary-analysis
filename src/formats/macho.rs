//! Mach-O format parser for macOS/iOS binaries

use crate::{
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol,
    },
};
use goblin::mach::{Mach, MachO};

/// Mach-O format parser
pub struct MachOParser;

impl BinaryFormatParser for MachOParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        let mach = Mach::parse(data)?;
        match mach {
            Mach::Binary(macho) => Ok(Box::new(MachOBinary::new(macho, data)?)),
            Mach::Fat(_) => Err(BinaryError::unsupported_format(
                "Fat binaries not yet supported",
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
                | goblin::mach::fat::FAT_MAGIC
                | goblin::mach::fat::FAT_CIGAM
        )
    }
}

/// Parsed Mach-O binary
pub struct MachOBinary {
    #[allow(dead_code)]
    macho: MachO<'static>,
    #[allow(dead_code)]
    data: Vec<u8>,
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl MachOBinary {
    fn new(macho: MachO<'_>, data: &[u8]) -> Result<Self> {
        let data = data.to_vec();

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

        // Determine endianness from magic
        let endian = match macho.header.magic {
            goblin::mach::header::MH_MAGIC | goblin::mach::header::MH_MAGIC_64 => {
                Endianness::Little
            }
            goblin::mach::header::MH_CIGAM | goblin::mach::header::MH_CIGAM_64 => Endianness::Big,
            _ => Endianness::Little, // Default
        };

        // Analyze security features
        let security_features = analyze_security_features(&macho);

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::MachO,
            architecture,
            entry_point: find_entry_point(&macho),
            base_address: None, // Mach-O uses ASLR, no fixed base
            timestamp: None,    // Not readily available in Mach-O
            compiler_info: extract_compiler_info(&macho),
            endian,
            security_features,
        };

        // Parse sections
        let sections = parse_sections(&macho, &data)?;

        // Parse symbols
        let symbols = parse_symbols(&macho)?;

        // Parse imports and exports
        let (imports, exports) = parse_imports_exports(&macho)?;

        // Handle lifetime issues with MachO struct
        let macho_owned = unsafe { std::mem::transmute::<MachO<'_>, MachO<'static>>(macho) };

        Ok(Self {
            macho: macho_owned,
            data,
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

fn parse_sections(macho: &MachO, data: &[u8]) -> Result<Vec<Section>> {
    let mut sections = Vec::new();

    for segment in &macho.segments {
        for (section, _) in &segment.sections()? {
            let name = section.name().unwrap_or("unknown").to_string();

            // Determine section type based on section name and flags
            let section_type = if section.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS
                != 0
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

            // Extract small section data
            let section_data = if section.size <= 1024 && section.offset > 0 {
                let start = section.offset as usize;
                let end = start + section.size as usize;
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
                address: section.addr,
                size: section.size,
                offset: section.offset as u64,
                permissions,
                section_type,
                data: section_data,
            });
        }
    }

    Ok(sections)
}

fn parse_symbols(_macho: &MachO) -> Result<Vec<Symbol>> {
    let symbols = Vec::new();

    // NOTE: Symbol parsing API changed in goblin 0.10, requires implementation update
    // The symbol API has changed in goblin 0.10
    // For now, create empty symbols vector
    // symbols = vec![];

    Ok(symbols)
}

fn parse_imports_exports(macho: &MachO) -> Result<(Vec<Import>, Vec<Export>)> {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // Parse imports from bind info
    for import in &macho.imports()? {
        imports.push(Import {
            name: import.name.to_string(),
            library: Some(import.dylib.to_string()),
            address: Some(import.address),
            ordinal: None,
        });
    }

    // Parse exports from export info
    for export in &macho.exports()? {
        exports.push(Export {
            name: export.name.to_string(),
            address: export.offset,
            ordinal: None,
            forwarded_name: None, // Mach-O doesn't have forwarded exports like PE
        });
    }

    Ok((imports, exports))
}

fn analyze_security_features(macho: &MachO) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // Check file type and flags for security features
    let flags = macho.header.flags;

    // PIE (Position Independent Executable)
    features.pie = flags & goblin::mach::header::MH_PIE != 0;

    // ASLR is generally enabled with PIE on macOS
    features.aslr = features.pie;

    // NX bit (No-Execute) is typically enabled on modern macOS
    features.nx_bit = true; // Default assumption for modern binaries

    // Check for stack canaries (would need more complex analysis)
    features.stack_canary = false; // Would need to analyze for __stack_chk_guard

    // Check load commands for additional security features
    for _load_command in &macho.load_commands {
        // NOTE: LoadCommand variants changed in goblin 0.10, awaiting API stabilization
        // LoadCommand::CodeSignature(_, _) => {
        //     features.signed = true;
        // }
    }

    features
}

fn find_entry_point(macho: &MachO) -> Option<u64> {
    // Look for LC_MAIN or LC_UNIX_THREAD load commands
    for _load_command in &macho.load_commands {
        // NOTE: LoadCommand variants changed in goblin 0.10, awaiting API stabilization
        // LoadCommand::Main(entry) => {
        //     return Some(entry.entryoff);
        // }
        // LoadCommand::UnixThread(_) => {
        //     // Entry point is in the thread state
        //     // This is architecture-specific parsing
        //     return Some(0); // Placeholder - would need arch-specific parsing
        // }
    }
    None
}

fn extract_compiler_info(macho: &MachO) -> Option<String> {
    // Look for build version or version min load commands
    for _load_command in &macho.load_commands {
        // NOTE: LoadCommand variants changed in goblin 0.10, awaiting API stabilization
        // LoadCommand::BuildVersion(build) => {
        //     return Some(format!(
        //         "Platform: {}, SDK: {}.{}.{}",
        //         build.platform,
        //         build.sdk >> 16,
        //         (build.sdk >> 8) & 0xff,
        //         build.sdk & 0xff
        //     ));
        // }
    }
    Some("Unknown Apple toolchain".to_string())
}
