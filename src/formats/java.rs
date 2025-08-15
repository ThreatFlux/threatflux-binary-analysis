//! Java class and JAR file parser

use crate::{
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding, SymbolType,
        SymbolVisibility,
    },
};

type ParseResult = Result<Box<dyn BinaryFormatTrait>>;

/// Java binary format parser (class files and JAR archives)
pub struct JavaParser;

impl JavaParser {
    fn parse_class(data: &[u8]) -> ParseResult {
        if data.len() < 4 || &data[0..4] != b"\xca\xfe\xba\xbe" {
            return Err(BinaryError::invalid_data("Invalid Java class magic"));
        }

        let minor = if data.len() >= 6 {
            u16::from_be_bytes([data[4], data[5]])
        } else {
            0
        };
        let major = if data.len() >= 8 {
            u16::from_be_bytes([data[6], data[7]])
        } else {
            0
        };

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Java,
            architecture: Architecture::Jvm,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: Some(format!("Java class version {}.{}", major, minor)),
            endian: Endianness::Big,
            security_features: SecurityFeatures::default(),
        };

        let sections = vec![Section {
            name: "class".to_string(),
            address: 0,
            size: data.len() as u64,
            offset: 0,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            section_type: SectionType::Data,
            data: None,
        }];

        Ok(Box::new(JavaBinary {
            metadata,
            sections,
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
        }))
    }

    fn parse_jar(data: &[u8]) -> ParseResult {
        use std::io::Cursor;
        use zip::ZipArchive;

        let reader = Cursor::new(data);
        let mut archive =
            ZipArchive::new(reader).map_err(|e| BinaryError::parse(format!("Zip error: {e}")))?;
        let mut symbols = Vec::new();

        for i in 0..archive.len() {
            let file = archive
                .by_index(i)
                .map_err(|e| BinaryError::parse(format!("Zip entry error: {e}")))?;
            if file.name().ends_with(".class") {
                symbols.push(Symbol {
                    name: file.name().to_string(),
                    demangled_name: None,
                    address: 0,
                    size: file.size(),
                    symbol_type: SymbolType::Object,
                    binding: SymbolBinding::Global,
                    visibility: SymbolVisibility::Default,
                    section_index: None,
                });
            }
        }

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Java,
            architecture: Architecture::Jvm,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: Some("Java archive".to_string()),
            endian: Endianness::Big,
            security_features: SecurityFeatures::default(),
        };

        let sections = vec![Section {
            name: "jar".to_string(),
            address: 0,
            size: data.len() as u64,
            offset: 0,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            section_type: SectionType::Data,
            data: None,
        }];

        Ok(Box::new(JavaBinary {
            metadata,
            sections,
            symbols,
            imports: Vec::new(),
            exports: Vec::new(),
        }))
    }
}

impl BinaryFormatParser for JavaParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        if data.starts_with(b"\xca\xfe\xba\xbe") {
            Self::parse_class(data)
        } else if data.starts_with(b"PK\x03\x04") {
            Self::parse_jar(data)
        } else {
            Err(BinaryError::invalid_data("Unknown Java binary format"))
        }
    }

    fn can_parse(data: &[u8]) -> bool {
        data.starts_with(b"\xca\xfe\xba\xbe") || data.starts_with(b"PK\x03\x04")
    }
}

/// Java binary representation
pub struct JavaBinary {
    metadata: BinaryMetadata,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

impl BinaryFormatTrait for JavaBinary {
    fn format_type(&self) -> Format {
        Format::Java
    }

    fn architecture(&self) -> Architecture {
        Architecture::Jvm
    }

    fn entry_point(&self) -> Option<u64> {
        None
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
