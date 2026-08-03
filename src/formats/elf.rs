//! ELF format parser

use crate::{
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding, SymbolType,
        SymbolVisibility,
    },
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
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl ElfBinary {
    fn new(elf: Elf<'_>, data: &[u8]) -> Result<Self> {
        let mut output_budget = super::ParseOutputBudget::default();

        // Convert architecture
        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_386 => Architecture::X86,
            goblin::elf::header::EM_X86_64 => Architecture::X86_64,
            goblin::elf::header::EM_ARM => Architecture::Arm,
            goblin::elf::header::EM_AARCH64 => Architecture::Arm64,
            goblin::elf::header::EM_MIPS | goblin::elf::header::EM_MIPS_RS3_LE => {
                if elf.is_64 {
                    Architecture::Mips64
                } else {
                    Architecture::Mips
                }
            }
            goblin::elf::header::EM_PPC => Architecture::PowerPC,
            goblin::elf::header::EM_PPC64 => Architecture::PowerPC64,
            goblin::elf::header::EM_RISCV => {
                if elf.is_64 {
                    Architecture::RiscV64
                } else {
                    Architecture::RiscV
                }
            }
            _ => Architecture::Unknown,
        };

        // Detect endianness
        let endian = match elf.header.endianness()? {
            goblin::container::Endian::Little => Endianness::Little,
            goblin::container::Endian::Big => Endianness::Big,
        };

        // Analyze security features
        let security_features = analyze_security_features(&elf);

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Elf,
            architecture,
            entry_point: if elf.entry != 0 {
                Some(elf.entry)
            } else {
                None
            },
            base_address: preferred_base_address(&elf),
            timestamp: None, // Not available in ELF headers
            compiler_info: extract_compiler_info(&elf, data, &mut output_budget)?,
            endian,
            security_features,
        };

        // Parse sections
        let sections = parse_sections(&elf, data, &mut output_budget)?;

        // Parse symbols
        let symbols = parse_symbols(&elf, &mut output_budget)?;

        // Parse imports and exports
        let (imports, exports) = parse_imports_exports(&elf, &mut output_budget)?;

        Ok(Self {
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

fn parse_sections(
    elf: &Elf,
    data: &[u8],
    output_budget: &mut super::ParseOutputBudget,
) -> Result<Vec<Section>> {
    let mut sections = Vec::new();

    for (i, section_header) in elf.section_headers.iter().enumerate() {
        output_budget.reserve_record(&mut sections, "ELF sections")?;
        let fallback_name;
        let parsed_name = if let Some(name) = elf.shdr_strtab.get_at(section_header.sh_name) {
            name
        } else {
            fallback_name = format!(".section_{i}");
            &fallback_name
        };
        let name = output_budget.copy_name(parsed_name, "ELF section name")?;

        let section_type = match section_header.sh_type {
            goblin::elf::section_header::SHT_PROGBITS => {
                // Check for debug sections by name first
                if name.starts_with(".debug_") || name.starts_with(".zdebug_") {
                    SectionType::Debug
                } else if section_header.sh_flags
                    & (goblin::elf::section_header::SHF_EXECINSTR as u64)
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

        let has_file_data = section_header.sh_type != goblin::elf::section_header::SHT_NOBITS
            && section_header.sh_size != 0;
        if has_file_data
            && super::checked_file_range(data, section_header.sh_offset, section_header.sh_size)
                .is_none()
        {
            return Err(crate::BinaryError::invalid_data(format!(
                "ELF section '{name}' range {}..+{} exceeds the file",
                section_header.sh_offset, section_header.sh_size
            )));
        }

        // Extract small section data
        let section_data = if has_file_data {
            super::inline_section_data(data, section_header.sh_offset, section_header.sh_size)
        } else {
            None
        };

        sections.push(Section {
            name,
            address: section_header.sh_addr,
            size: section_header.sh_size,
            offset: section_header.sh_offset,
            file_size: if has_file_data {
                section_header.sh_size
            } else {
                0
            },
            permissions,
            section_type,
            data: section_data,
        });
    }

    Ok(sections)
}

fn parse_symbols(elf: &Elf, output_budget: &mut super::ParseOutputBudget) -> Result<Vec<Symbol>> {
    let mut symbols = Vec::new();

    for sym in &elf.syms {
        let parsed_name = elf.strtab.get_at(sym.st_name).unwrap_or("unknown");

        // Skip empty names
        if parsed_name.is_empty() {
            continue;
        }
        output_budget.reserve_record(&mut symbols, "ELF symbols")?;
        let name = output_budget.copy_name(parsed_name, "ELF symbol name")?;

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
            name,
            // Demangling is intentionally left to the optional symbol-resolution
            // pass. Returning a fabricated name here would be a false result.
            demangled_name: None,
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

fn parse_imports_exports(
    elf: &Elf,
    output_budget: &mut super::ParseOutputBudget,
) -> crate::types::ImportExportResult {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // Parse dynamic symbols for imports/exports
    for sym in &elf.dynsyms {
        let parsed_name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("unknown");

        if parsed_name.is_empty() {
            continue;
        }

        if sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize) {
            // This is an import
            output_budget.reserve_record(&mut imports, "ELF imports")?;
            imports.push(Import {
                name: output_budget.copy_name(parsed_name, "ELF import name")?,
                library: None, // Library name would need to be resolved from dynamic entries
                address: None,
                ordinal: None,
            });
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL {
            // This is an export
            output_budget.reserve_record(&mut exports, "ELF exports")?;
            exports.push(Export {
                name: output_budget.copy_name(parsed_name, "ELF export name")?,
                address: sym.st_value,
                ordinal: None,
                forwarded_name: None,
            });
        }
    }

    Ok((imports, exports))
}

fn analyze_security_features(elf: &Elf) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // Check for NX bit (GNU_STACK segment)
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_GNU_STACK {
            features.nx_bit = (phdr.p_flags & goblin::elf::program_header::PF_X) == 0;
        }
    }

    // Check for PIE (Position Independent Executable)
    features.pie = elf.header.e_type == goblin::elf::header::ET_DYN
        && (!elf.is_lib || elf.interpreter.is_some());

    // Check for RELRO
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_GNU_RELRO {
            features.relro = true;
        }
    }

    features.stack_canary = elf.dynsyms.iter().any(|symbol| {
        elf.dynstrtab
            .get_at(symbol.st_name)
            .is_some_and(|name| name == "__stack_chk_fail" || name == "__stack_chk_guard")
    });
    features.fortify = elf.dynsyms.iter().any(|symbol| {
        elf.dynstrtab
            .get_at(symbol.st_name)
            .is_some_and(|name| name.ends_with("_chk"))
    });

    features.aslr = features.pie; // PIE enables ASLR

    features
}

fn preferred_base_address(elf: &Elf) -> Option<u64> {
    elf.program_headers
        .iter()
        .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|header| header.p_vaddr)
        .min()
}

fn extract_compiler_info(
    elf: &Elf,
    data: &[u8],
    output_budget: &mut super::ParseOutputBudget,
) -> Result<Option<String>> {
    // Look for compiler information in .comment section
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name)
            && name == ".comment"
            && let Some(section_data) = section_range(data, section.sh_offset, section.sh_size)
        {
            if section_data.len() > super::MAX_NAME_BYTES {
                return Err(BinaryError::invalid_data(format!(
                    "ELF compiler comment is {} bytes; limit is {}",
                    section_data.len(),
                    super::MAX_NAME_BYTES
                )));
            }
            // Parse null-terminated strings from the comment section
            let comment_str = String::from_utf8_lossy(section_data);
            let comment = comment_str.trim_end_matches('\0').trim();

            if !comment.is_empty() {
                return output_budget
                    .copy_name(comment, "ELF compiler comment")
                    .map(Some);
            }
        }
    }

    // Also look for Go build info
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name)
            && (name == ".go.buildinfo" || name.contains("go."))
        {
            return output_budget
                .copy_name("Go compiler", "ELF compiler label")
                .map(Some);
        }
    }

    // Look for Rust-specific sections
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name)
            && (name.starts_with(".rustc") || name.contains("rust"))
        {
            return output_budget
                .copy_name("Rust compiler", "ELF compiler label")
                .map(Some);
        }
    }

    Ok(None)
}

fn section_range(data: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    super::checked_file_range(data, offset, size).map(|range| &data[range])
}
