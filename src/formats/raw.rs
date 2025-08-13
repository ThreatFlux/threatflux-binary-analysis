//! Raw binary format parser

use crate::{
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol,
    },
    BinaryFormatParser, BinaryFormatTrait, Result,
};

/// Raw binary format parser
pub struct RawParser;

impl BinaryFormatParser for RawParser {
    fn parse(data: &[u8]) -> Result<Box<dyn BinaryFormatTrait>> {
        Ok(Box::new(RawBinary::new(data)))
    }

    fn can_parse(_data: &[u8]) -> bool {
        true // Raw parser can handle any data
    }
}

/// Raw binary representation
pub struct RawBinary {
    data: Vec<u8>,
    metadata: BinaryMetadata,
    sections: Vec<Section>,
}

impl RawBinary {
    fn new(data: &[u8]) -> Self {
        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Raw,
            architecture: Architecture::Unknown,
            entry_point: None,
            base_address: Some(0),
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };

        // Create a single section for the entire data
        let sections = vec![Section {
            name: ".data".to_string(),
            address: 0,
            size: data.len() as u64,
            offset: 0,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            section_type: SectionType::Data,
            data: if data.len() <= 1024 {
                Some(data.to_vec())
            } else {
                None
            },
        }];

        Self {
            data: data.to_vec(),
            metadata,
            sections,
        }
    }
}

impl BinaryFormatTrait for RawBinary {
    fn format_type(&self) -> Format {
        Format::Raw
    }

    fn architecture(&self) -> Architecture {
        Architecture::Unknown
    }

    fn entry_point(&self) -> Option<u64> {
        None
    }

    fn sections(&self) -> &[Section] {
        &self.sections
    }

    fn symbols(&self) -> &[Symbol] {
        &[] // No symbols in raw binary
    }

    fn imports(&self) -> &[Import] {
        &[] // No imports in raw binary
    }

    fn exports(&self) -> &[Export] {
        &[] // No exports in raw binary
    }

    fn metadata(&self) -> &BinaryMetadata {
        &self.metadata
    }
}
