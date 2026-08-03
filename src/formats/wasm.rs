//! WebAssembly (Wasm) format parser

use crate::{
    BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol,
    },
};

use wasmparser::{Parser, Payload, Validator};

/// WebAssembly format parser
pub struct WasmParser;

impl BinaryFormatParser for WasmParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        Ok(Box::new(WasmBinary::parse(data)?))
    }

    fn can_parse(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == b"\0asm"
    }
}

/// Parsed WebAssembly binary
pub struct WasmBinary {
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

fn preflight_wasm_structure(data: &[u8]) -> Result<()> {
    let mut budget = super::ParseOutputBudget::default();

    for payload in Parser::new(0).parse_all(data) {
        let payload = payload?;
        let records = match &payload {
            Payload::TypeSection(section) => usize::try_from(section.count()).unwrap_or(usize::MAX),
            Payload::ImportSection(section) => {
                usize::try_from(section.count()).unwrap_or(usize::MAX)
            }
            Payload::FunctionSection(section) => {
                usize::try_from(section.count()).unwrap_or(usize::MAX)
            }
            Payload::TableSection(section) => {
                usize::try_from(section.count()).unwrap_or(usize::MAX)
            }
            Payload::MemorySection(section) => {
                usize::try_from(section.count()).unwrap_or(usize::MAX)
            }
            Payload::TagSection(section) => usize::try_from(section.count()).unwrap_or(usize::MAX),
            Payload::GlobalSection(section) => {
                usize::try_from(section.count()).unwrap_or(usize::MAX)
            }
            Payload::ExportSection(section) => {
                usize::try_from(section.count()).unwrap_or(usize::MAX)
            }
            Payload::ElementSection(section) => {
                usize::try_from(section.count()).unwrap_or(usize::MAX)
            }
            Payload::DataSection(section) => usize::try_from(section.count()).unwrap_or(usize::MAX),
            Payload::DataCountSection { count, .. } | Payload::CodeSectionStart { count, .. } => {
                usize::try_from(*count).unwrap_or(usize::MAX)
            }
            Payload::StartSection { .. }
            | Payload::CustomSection(_)
            | Payload::UnknownSection { .. } => 1,
            Payload::Version { .. } | Payload::CodeSectionEntry(_) | Payload::End(_) => 0,
            _ => 1,
        };
        budget.claim_records(records, "WebAssembly structural records")?;
    }

    Ok(())
}

impl WasmBinary {
    fn parse(data: &[u8]) -> Result<Self> {
        preflight_wasm_structure(data)?;

        // `Parser::parse_all` outlines function bodies without validating their
        // instructions or cross-section semantics. Validate the complete module
        // before publishing structural metadata as a successful parse.
        Validator::new().validate_all(data)?;

        let parser = Parser::new(0);
        let mut output_budget = super::ParseOutputBudget::default();
        let mut sections = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        for payload in parser.parse_all(data) {
            let payload = payload?;
            match payload {
                Payload::Version { .. } => {}
                // A WebAssembly start value is a function index, not a virtual
                // address, so it must not be reported through `entry_point`.
                Payload::StartSection { .. } => {}
                Payload::ImportSection(s) => {
                    let range = s.range();
                    for import in s {
                        let import = import?;
                        output_budget.reserve_record(&mut imports, "WebAssembly imports")?;
                        imports.push(Import {
                            name: output_budget
                                .copy_name(import.name, "WebAssembly import name")?,
                            library: Some(
                                output_budget
                                    .copy_name(import.module, "WebAssembly import module")?,
                            ),
                            address: None,
                            ordinal: None,
                        });
                    }
                    output_budget.reserve_record(&mut sections, "WebAssembly sections")?;
                    sections.push(Section {
                        name: output_budget.copy_name("import", "WebAssembly section name")?,
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
                        file_size: (range.end - range.start) as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: false,
                            execute: false,
                        },
                        section_type: SectionType::Other(
                            output_budget.copy_name("Import", "WebAssembly section type")?,
                        ),
                        data: None,
                    });
                }
                Payload::ExportSection(s) => {
                    let range = s.range();
                    for export in s {
                        let export = export?;
                        output_budget.reserve_record(&mut exports, "WebAssembly exports")?;
                        exports.push(Export {
                            name: output_budget
                                .copy_name(export.name, "WebAssembly export name")?,
                            address: 0,
                            ordinal: None,
                            forwarded_name: None,
                        });
                    }
                    output_budget.reserve_record(&mut sections, "WebAssembly sections")?;
                    sections.push(Section {
                        name: output_budget.copy_name("export", "WebAssembly section name")?,
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
                        file_size: (range.end - range.start) as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: false,
                            execute: false,
                        },
                        section_type: SectionType::Other(
                            output_budget.copy_name("Export", "WebAssembly section type")?,
                        ),
                        data: None,
                    });
                }
                Payload::CodeSectionStart { range, .. } => {
                    output_budget.reserve_record(&mut sections, "WebAssembly sections")?;
                    sections.push(Section {
                        name: output_budget.copy_name("code", "WebAssembly section name")?,
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
                        file_size: (range.end - range.start) as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: false,
                            execute: true,
                        },
                        section_type: SectionType::Code,
                        data: None,
                    });
                }
                Payload::DataSection(s) => {
                    let range = s.range();
                    // Consume section entries
                    for entry in s {
                        entry?;
                    }
                    output_budget.reserve_record(&mut sections, "WebAssembly sections")?;
                    sections.push(Section {
                        name: output_budget.copy_name("data", "WebAssembly section name")?,
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
                        file_size: (range.end - range.start) as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: true,
                            execute: false,
                        },
                        section_type: SectionType::Data,
                        data: None,
                    });
                }
                Payload::CustomSection(section) => {
                    output_budget.reserve_record(&mut sections, "WebAssembly sections")?;
                    let name = output_budget
                        .copy_name(section.name(), "WebAssembly custom-section name")?;
                    let section_type_name = output_budget
                        .copy_name(section.name(), "WebAssembly custom-section type")?;
                    sections.push(Section {
                        name,
                        address: 0,
                        size: section.data().len() as u64,
                        offset: section.data_offset() as u64,
                        file_size: section.data().len() as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: false,
                            execute: false,
                        },
                        section_type: SectionType::Other(section_type_name),
                        data: None,
                    });
                }
                _ => {}
            }
        }

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Wasm,
            architecture: Architecture::Wasm,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };

        Ok(Self {
            metadata,
            sections,
            imports,
            exports,
        })
    }
}

impl BinaryFormatTrait for WasmBinary {
    fn format_type(&self) -> Format {
        Format::Wasm
    }

    fn architecture(&self) -> Architecture {
        Architecture::Wasm
    }

    fn entry_point(&self) -> Option<u64> {
        self.metadata.entry_point
    }

    fn sections(&self) -> &[Section] {
        &self.sections
    }

    fn symbols(&self) -> &[Symbol] {
        &[]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u32_leb(mut value: u32, output: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn malformed_data_entries_are_not_silently_ignored() {
        let malformed = b"\0asm\x01\0\0\0\x0b\x02\x01\xff";
        assert!(WasmParser::parse(malformed).is_err());
    }

    #[test]
    fn malformed_function_body_is_not_silently_ignored() {
        // Structurally complete type/function/code sections whose single body
        // contains an unknown opcode and no terminating `end` instruction.
        let malformed =
            b"\0asm\x01\0\0\0\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x0a\x04\x01\x02\x00\xff";
        assert!(WasmParser::parse(malformed).is_err());
    }

    #[test]
    fn oversized_structural_count_is_rejected_before_validation() {
        let mut count = Vec::new();
        push_u32_leb((super::super::MAX_PARSED_RECORDS + 1) as u32, &mut count);

        let mut module = b"\0asm\x01\0\0\0".to_vec();
        module.push(2); // import section
        push_u32_leb(count.len() as u32, &mut module);
        module.extend_from_slice(&count);

        let error = WasmParser::parse(&module)
            .err()
            .expect("oversized structural count must fail");
        assert!(error.to_string().contains("parser record limit"));
    }

    #[test]
    fn oversized_owned_name_is_rejected() {
        let name = "x".repeat(super::super::MAX_NAME_BYTES + 1);
        let module = wat::parse_str(format!(r#"(module (import "m" "{name}" (func)))"#)).unwrap();

        let error = WasmParser::parse(&module)
            .err()
            .expect("oversized output name must fail");
        assert!(error.to_string().contains("per-name limit"));
    }

    #[test]
    fn start_function_index_is_not_reported_as_an_address() {
        let module = wat::parse_str("(module (func) (start 0))").unwrap();
        let parsed = WasmParser::parse(&module).unwrap();

        assert_eq!(parsed.entry_point(), None);
        assert_eq!(parsed.metadata().entry_point, None);
    }
}
