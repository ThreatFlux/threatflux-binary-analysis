//! Mach-O format parser for macOS/iOS binaries

use crate::{
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, FunctionType,
        Import, Section, SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding,
        SymbolType, SymbolVisibility,
    },
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
};
use goblin::mach::{load_command::LoadCommand, Mach, MachO};
use std::collections::HashMap;

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
    macho: MachO<'static>,
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
            let section_type =
                if section.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS != 0 {
                    SectionType::Code
                } else if name.starts_with("__text") {
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

fn parse_symbols(macho: &MachO) -> Result<Vec<Symbol>> {
    let mut symbols = Vec::new();

    for symbol in &macho.symbols {
        if let Some((name, nlist)) = symbol {
            if name.is_empty() {
                continue;
            }

            let symbol_type = if nlist.is_undefined() {
                SymbolType::Object // Undefined symbol, likely import
            } else if nlist.n_type & goblin::mach::symbols::N_TYPE == goblin::mach::symbols::N_SECT
            {
                // Symbol in a section
                if nlist.n_type & goblin::mach::symbols::N_STAB == 0 {
                    SymbolType::Function
                } else {
                    SymbolType::Object
                }
            } else {
                SymbolType::Other(format!("MACH_TYPE_{}", nlist.n_type))
            };

            let binding = if nlist.n_type & goblin::mach::symbols::N_EXT != 0 {
                SymbolBinding::Global
            } else {
                SymbolBinding::Local
            };

            symbols.push(Symbol {
                name: name.to_string(),
                demangled_name: try_demangle(name),
                address: nlist.n_value,
                size: 0, // Mach-O doesn't store symbol size directly
                symbol_type,
                binding,
                visibility: SymbolVisibility::Default,
                section_index: if nlist.n_sect > 0 {
                    Some(nlist.n_sect as usize - 1)
                } else {
                    None
                },
            });
        }
    }

    Ok(symbols)
}

fn parse_imports_exports(macho: &MachO) -> Result<(Vec<Import>, Vec<Export>)> {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // Parse imports from bind info
    for import in &macho.imports()? {
        imports.push(Import {
            name: import.name.clone(),
            library: Some(import.dylib.clone()),
            address: Some(import.address),
            ordinal: None,
        });
    }

    // Parse exports from export info
    for export in &macho.exports()? {
        exports.push(Export {
            name: export.name.clone(),
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
    for load_command in &macho.load_commands {
        match load_command.command {
            LoadCommand::CodeSignature(_) => {
                features.signed = true;
            }
            _ => {}
        }
    }

    features
}

fn find_entry_point(macho: &MachO) -> Option<u64> {
    // Look for LC_MAIN or LC_UNIX_THREAD load commands
    for load_command in &macho.load_commands {
        match &load_command.command {
            LoadCommand::EntryPoint(entry) => {
                return Some(entry.entryoff);
            }
            LoadCommand::UnixThread(thread) => {
                // Entry point is in the thread state
                // This is architecture-specific parsing
                return Some(0); // Placeholder - would need arch-specific parsing
            }
            _ => {}
        }
    }
    None
}

fn extract_compiler_info(macho: &MachO) -> Option<String> {
    // Look for build version or version min load commands
    for load_command in &macho.load_commands {
        match &load_command.command {
            LoadCommand::BuildVersion(build) => {
                return Some(format!(
                    "Platform: {}, SDK: {}.{}.{}",
                    build.platform,
                    build.sdk >> 16,
                    (build.sdk >> 8) & 0xff,
                    build.sdk & 0xff
                ));
            }
            _ => {}
        }
    }
    Some("Unknown Apple toolchain".to_string())
}

fn try_demangle(name: &str) -> Option<String> {
    // Basic C++ and Swift demangling detection
    if name.starts_with("_Z") {
        // C++ mangled name
        Some(format!("demangled_cpp_{}", name))
    } else if name.starts_with("_$") {
        // Swift mangled name
        Some(format!("demangled_swift_{}", name))
    } else {
        None
    }
}
