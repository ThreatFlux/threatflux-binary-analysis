//! WebAssembly (Wasm) format parser

use crate::{
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol,
    },
    BinaryFormatParser, BinaryFormatTrait, Result,
};

use wasmparser::{Parser, Payload};

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
    #[allow(dead_code)]
    data: Vec<u8>,
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl WasmBinary {
    fn parse(data: &[u8]) -> Result<Self> {
        let parser = Parser::new(0);
        let mut sections = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        let mut start_fn: Option<u64> = None;

        for payload in parser.parse_all(data) {
            let payload = payload?;
            match payload {
                Payload::Version { .. } => {}
                Payload::StartSection { func, .. } => {
                    start_fn = Some(func as u64);
                }
                Payload::ImportSection(s) => {
                    let range = s.range();
                    for import in s {
                        let import = import?;
                        imports.push(Import {
                            name: import.name.to_string(),
                            library: Some(import.module.to_string()),
                            address: None,
                            ordinal: None,
                        });
                    }
                    sections.push(Section {
                        name: "import".to_string(),
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: false,
                            execute: false,
                        },
                        section_type: SectionType::Other("Import".to_string()),
                        data: None,
                    });
                }
                Payload::ExportSection(s) => {
                    let range = s.range();
                    for export in s {
                        let export = export?;
                        exports.push(Export {
                            name: export.name.to_string(),
                            address: 0,
                            ordinal: None,
                            forwarded_name: None,
                        });
                    }
                    sections.push(Section {
                        name: "export".to_string(),
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: false,
                            execute: false,
                        },
                        section_type: SectionType::Other("Export".to_string()),
                        data: None,
                    });
                }
                Payload::CodeSectionStart { range, .. } => {
                    sections.push(Section {
                        name: "code".to_string(),
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
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
                    for _ in s {} // iterating to ensure parser advances
                    sections.push(Section {
                        name: "data".to_string(),
                        address: 0,
                        size: (range.end - range.start) as u64,
                        offset: range.start as u64,
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
                    let name = section.name().to_string();
                    sections.push(Section {
                        name: name.clone(),
                        address: 0,
                        size: section.data().len() as u64,
                        offset: section.data_offset() as u64,
                        permissions: SectionPermissions {
                            read: true,
                            write: false,
                            execute: false,
                        },
                        section_type: SectionType::Other(name),
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
            entry_point: start_fn,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };

        Ok(Self {
            data: data.to_vec(),
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
