//! ELF format parser

use crate::{
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding, SymbolType,
        SymbolVisibility,
    },
    BinaryFormatParser, BinaryFormatTrait, Result,
};
use goblin::elf::Elf;

/// ELF format parser
pub struct ElfParser;

impl BinaryFormatParser for ElfParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        let elf = Elf::parse(data)?;
        Ok(Box::new(ElfBinary::new(elf, data)?))
    }

    fn can_parse(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == b"\x7fELF"
    }
}

/// Parsed ELF binary
pub struct ElfBinary {
    #[allow(dead_code)]
    elf: Elf<'static>,
    #[allow(dead_code)]
    data: Vec<u8>,
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl ElfBinary {
    fn new(elf: Elf<'_>, data: &[u8]) -> Result<Self> {
        let data = data.to_vec();

        // Convert architecture
        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_386 => Architecture::X86,
            goblin::elf::header::EM_X86_64 => Architecture::X86_64,
            goblin::elf::header::EM_ARM => Architecture::Arm,
            goblin::elf::header::EM_AARCH64 => Architecture::Arm64,
            goblin::elf::header::EM_MIPS => Architecture::Mips,
            goblin::elf::header::EM_PPC => Architecture::PowerPC,
            goblin::elf::header::EM_PPC64 => Architecture::PowerPC64,
            goblin::elf::header::EM_RISCV => Architecture::RiscV,
            _ => Architecture::Unknown,
        };

        // Detect endianness
        let endian = match elf.header.endianness()? {
            goblin::container::Endian::Little => Endianness::Little,
            goblin::container::Endian::Big => Endianness::Big,
        };

        // Analyze security features
        let security_features = analyze_security_features(&elf, &data);

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Elf,
            architecture,
            entry_point: if elf.entry != 0 {
                Some(elf.entry)
            } else {
                None
            },
            base_address: None, // ELF doesn't have a fixed base address
            timestamp: None,    // Not available in ELF headers
            compiler_info: extract_compiler_info(&elf),
            endian,
            security_features,
        };

        // Parse sections
        let sections = parse_sections(&elf, &data)?;

        // Parse symbols
        let symbols = parse_symbols(&elf)?;

        // Parse imports and exports
        let (imports, exports) = parse_imports_exports(&elf)?;

        // We need to handle lifetime issues with the Elf struct
        // For now, we'll store the essential data and reconstruct what we need
        let elf_owned = unsafe { std::mem::transmute::<Elf<'_>, Elf<'static>>(elf) };

        Ok(Self {
            elf: elf_owned,
            data,
            metadata,
            sections,
            symbols,
            imports,
            exports,
        })
    }
}

impl BinaryFormatTrait for ElfBinary {
    fn format_type(&self) -> Format {
        Format::Elf
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

fn parse_sections(elf: &Elf, data: &[u8]) -> Result<Vec<Section>> {
    let mut sections = Vec::new();

    for (i, section_header) in elf.section_headers.iter().enumerate() {
        let name = elf
            .shdr_strtab
            .get_at(section_header.sh_name)
            .unwrap_or(&format!(".section_{}", i))
            .to_string();

        let section_type = match section_header.sh_type {
            goblin::elf::section_header::SHT_PROGBITS => {
                if section_header.sh_flags & (goblin::elf::section_header::SHF_EXECINSTR as u64)
                    != 0
                {
                    SectionType::Code
                } else if section_header.sh_flags & (goblin::elf::section_header::SHF_WRITE as u64)
                    != 0
                {
                    SectionType::Data
                } else {
                    SectionType::ReadOnlyData
                }
            }
            goblin::elf::section_header::SHT_NOBITS => SectionType::Bss,
            goblin::elf::section_header::SHT_SYMTAB => SectionType::Symbol,
            goblin::elf::section_header::SHT_STRTAB => SectionType::String,
            goblin::elf::section_header::SHT_RELA | goblin::elf::section_header::SHT_REL => {
                SectionType::Relocation
            }
            goblin::elf::section_header::SHT_DYNAMIC => SectionType::Dynamic,
            goblin::elf::section_header::SHT_NOTE => SectionType::Note,
            _ => SectionType::Other(format!("SHT_{}", section_header.sh_type)),
        };

        let permissions = SectionPermissions {
            read: true, // ELF sections are generally readable
            write: section_header.sh_flags & (goblin::elf::section_header::SHF_WRITE as u64) != 0,
            execute: section_header.sh_flags & (goblin::elf::section_header::SHF_EXECINSTR as u64)
                != 0,
        };

        // Extract small section data
        let section_data = if section_header.sh_size <= 1024
            && section_header.sh_type != goblin::elf::section_header::SHT_NOBITS
        {
            let start = section_header.sh_offset as usize;
            let end = start + section_header.sh_size as usize;
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
            address: section_header.sh_addr,
            size: section_header.sh_size,
            offset: section_header.sh_offset,
            permissions,
            section_type,
            data: section_data,
        });
    }

    Ok(sections)
}

fn parse_symbols(elf: &Elf) -> Result<Vec<Symbol>> {
    let mut symbols = Vec::new();

    for sym in &elf.syms {
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .unwrap_or("unknown")
            .to_string();

        // Skip empty names
        if name.is_empty() {
            continue;
        }

        let symbol_type = match sym.st_type() {
            goblin::elf::sym::STT_FUNC => SymbolType::Function,
            goblin::elf::sym::STT_OBJECT => SymbolType::Object,
            goblin::elf::sym::STT_SECTION => SymbolType::Section,
            goblin::elf::sym::STT_FILE => SymbolType::File,
            goblin::elf::sym::STT_COMMON => SymbolType::Common,
            goblin::elf::sym::STT_TLS => SymbolType::Thread,
            _ => SymbolType::Other(format!("STT_{}", sym.st_type())),
        };

        let binding = match sym.st_bind() {
            goblin::elf::sym::STB_LOCAL => SymbolBinding::Local,
            goblin::elf::sym::STB_GLOBAL => SymbolBinding::Global,
            goblin::elf::sym::STB_WEAK => SymbolBinding::Weak,
            _ => SymbolBinding::Other(format!("STB_{}", sym.st_bind())),
        };

        let visibility = match sym.st_visibility() {
            goblin::elf::sym::STV_DEFAULT => SymbolVisibility::Default,
            goblin::elf::sym::STV_INTERNAL => SymbolVisibility::Internal,
            goblin::elf::sym::STV_HIDDEN => SymbolVisibility::Hidden,
            goblin::elf::sym::STV_PROTECTED => SymbolVisibility::Protected,
            _ => SymbolVisibility::Default,
        };

        let section_index = if sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize) {
            None
        } else {
            Some(sym.st_shndx)
        };

        symbols.push(Symbol {
            name: name.clone(),
            demangled_name: try_demangle(&name),
            address: sym.st_value,
            size: sym.st_size,
            symbol_type,
            binding,
            visibility,
            section_index,
        });
    }

    Ok(symbols)
}

fn parse_imports_exports(elf: &Elf) -> Result<(Vec<Import>, Vec<Export>)> {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // Parse dynamic symbols for imports/exports
    for sym in &elf.dynsyms {
        let name = elf
            .dynstrtab
            .get_at(sym.st_name)
            .unwrap_or("unknown")
            .to_string();

        if name.is_empty() {
            continue;
        }

        if sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize) {
            // This is an import
            imports.push(Import {
                name,
                library: None, // Library name would need to be resolved from dynamic entries
                address: None,
                ordinal: None,
            });
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL {
            // This is an export
            exports.push(Export {
                name,
                address: sym.st_value,
                ordinal: None,
                forwarded_name: None,
            });
        }
    }

    Ok((imports, exports))
}

fn analyze_security_features(elf: &Elf, _data: &[u8]) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // Check for NX bit (GNU_STACK segment)
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_GNU_STACK {
            features.nx_bit = (phdr.p_flags & goblin::elf::program_header::PF_X) == 0;
        }
    }

    // Check for PIE (Position Independent Executable)
    features.pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    // Check for RELRO
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_GNU_RELRO {
            features.relro = true;
        }
    }

    // Other features would need more complex analysis
    features.aslr = features.pie; // PIE enables ASLR

    features
}

fn extract_compiler_info(elf: &Elf) -> Option<String> {
    // Look for compiler information in .comment section
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name == ".comment" {
                // This would need access to the raw section data
                return Some("Unknown compiler".to_string());
            }
        }
    }
    None
}

fn try_demangle(name: &str) -> Option<String> {
    // Basic C++ demangling detection
    if name.starts_with("_Z") {
        // This is a mangled C++ name, but we'd need a proper demangler
        Some(format!("demangled_{}", name))
    } else {
        None
    }
}
