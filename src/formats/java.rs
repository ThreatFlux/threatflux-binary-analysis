//! Java class and JAR file parser

use crate::{
    BinaryError, BinaryFormatParser, BinaryFormatTrait, Result,
    types::{
        Architecture, BinaryFormat as Format, BinaryMetadata, Endianness, Export, Import, Section,
        SectionPermissions, SectionType, SecurityFeatures, Symbol, SymbolBinding, SymbolType,
        SymbolVisibility,
    },
};
use std::io::{Cursor, Read, Seek, SeekFrom};

type ParseResult = Result<Box<dyn BinaryFormatTrait>>;

/// Upper bound for central-directory entries inspected by the default JAR
/// parser. Entry contents are not decompressed by this module.
pub const MAX_JAR_ENTRIES: usize = 50_000;

const ZIP_EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const ZIP_EOCD_MIN_SIZE: usize = 22;
const JAVA_CLASS_MAGIC: &[u8; 4] = b"\xca\xfe\xba\xbe";
const JAVA_CLASS_HEADER_SIZE: usize = 10;
const MIN_JAVA_CLASS_MAJOR_VERSION: u16 = 45;

#[derive(Debug, Clone, Copy)]
struct JarPreflight {
    eocd_offset: usize,
}

/// Read/seek view that hides EOCD-shaped byte sequences after the verified ZIP
/// footer's magic. `zip` performs its own backwards signature scan, so
/// validating the real footer alone is insufficient for attacker-controlled
/// footer fields and comments.
struct VerifiedJarReader<'a> {
    cursor: Cursor<&'a [u8]>,
    eocd_offset: usize,
    mask_next_eocd: bool,
}

impl<'a> VerifiedJarReader<'a> {
    fn new(data: &'a [u8], preflight: JarPreflight) -> Self {
        Self {
            cursor: Cursor::new(data),
            eocd_offset: preflight.eocd_offset,
            mask_next_eocd: false,
        }
    }
}

impl Read for VerifiedJarReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let start = usize::try_from(self.cursor.position()).unwrap_or(usize::MAX);
        let read = self.cursor.read(buffer)?;
        if self.mask_next_eocd && read != 0 && start > self.eocd_offset {
            buffer[0] = 0;
        }
        self.mask_next_eocd = false;

        Ok(read)
    }
}

impl Seek for VerifiedJarReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let new_position = self.cursor.seek(position)?;
        self.mask_next_eocd = usize::try_from(new_position).ok().is_some_and(|offset| {
            offset > self.eocd_offset
                && self
                    .cursor
                    .get_ref()
                    .get(offset..offset.saturating_add(ZIP_EOCD_SIGNATURE.len()))
                    == Some(ZIP_EOCD_SIGNATURE)
        });
        Ok(new_position)
    }
}

/// Java binary format parser (class files and JAR archives)
pub struct JavaParser;

impl JavaParser {
    fn parse_class(data: &[u8]) -> ParseResult {
        if !data.starts_with(JAVA_CLASS_MAGIC) {
            return Err(BinaryError::invalid_data("Invalid Java class magic"));
        }
        if data.len() < JAVA_CLASS_HEADER_SIZE {
            return Err(BinaryError::invalid_data(
                "Truncated Java class header (expected at least 10 bytes)",
            ));
        }
        let major_version = u16::from_be_bytes([data[6], data[7]]);
        if major_version < MIN_JAVA_CLASS_MAJOR_VERSION {
            return Err(BinaryError::invalid_data(format!(
                "Invalid Java class major version {major_version}; expected at least {MIN_JAVA_CLASS_MAJOR_VERSION}"
            )));
        }
        let constant_pool_count = u16::from_be_bytes([data[8], data[9]]);
        if constant_pool_count == 0 {
            return Err(BinaryError::invalid_data(
                "Invalid Java class constant_pool_count 0; expected at least 1",
            ));
        }

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Java,
            architecture: Architecture::Jvm,
            entry_point: None,
            base_address: None,
            timestamp: None,
            // Class-file versions identify a VM format level, not the source
            // language or compiler that emitted the bytecode.
            compiler_info: None,
            endian: Endianness::Big,
            security_features: SecurityFeatures::default(),
        };

        let sections = vec![Section {
            name: "class".to_string(),
            address: 0,
            size: data.len() as u64,
            offset: 0,
            file_size: data.len() as u64,
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
        use zip::ZipArchive;

        let mut output_budget = super::ParseOutputBudget::default();
        let preflight = preflight_jar_archive(data)?;
        let reader = VerifiedJarReader::new(data, preflight);
        let mut archive =
            ZipArchive::new(reader).map_err(|e| BinaryError::parse(format!("Zip error: {e}")))?;
        if archive.len() > MAX_JAR_ENTRIES {
            return Err(BinaryError::invalid_data(format!(
                "JAR contains {} entries; limit is {MAX_JAR_ENTRIES}",
                archive.len()
            )));
        }
        let mut symbols = Vec::new();
        let mut contains_class = false;

        for i in 0..archive.len() {
            let file = archive
                .by_index(i)
                .map_err(|e| BinaryError::parse(format!("Zip entry error: {e}")))?;
            if file.is_file() && file.name().ends_with(".class") {
                contains_class = true;
                output_budget.reserve_record(&mut symbols, "JAR class entries")?;
                symbols.push(Symbol {
                    name: output_budget.copy_name(file.name(), "JAR class entry name")?,
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

        if !contains_class {
            return Err(BinaryError::invalid_data(
                "ZIP archive contains no Java class entries",
            ));
        }

        let metadata = BinaryMetadata {
            size: data.len(),
            format: Format::Java,
            architecture: Architecture::Jvm,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Big,
            security_features: SecurityFeatures::default(),
        };

        let sections = vec![Section {
            name: "jar".to_string(),
            address: 0,
            size: data.len() as u64,
            offset: 0,
            file_size: data.len() as u64,
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
        if data.starts_with(JAVA_CLASS_MAGIC) {
            Self::parse_class(data)
        } else if data.starts_with(b"PK\x03\x04") {
            Self::parse_jar(data)
        } else {
            Err(BinaryError::invalid_data("Unknown Java binary format"))
        }
    }

    fn can_parse(data: &[u8]) -> bool {
        is_java_class_header(data) || jar_contains_class(data)
    }
}

fn is_java_class_header(data: &[u8]) -> bool {
    data.len() >= JAVA_CLASS_HEADER_SIZE
        && data.starts_with(JAVA_CLASS_MAGIC)
        && u16::from_be_bytes([data[6], data[7]]) >= MIN_JAVA_CLASS_MAJOR_VERSION
        && u16::from_be_bytes([data[8], data[9]]) != 0
}

fn jar_contains_class(data: &[u8]) -> bool {
    if !data.starts_with(b"PK\x03\x04") {
        return false;
    }
    let Ok(preflight) = preflight_jar_archive(data) else {
        return false;
    };

    let Ok(mut archive) = zip::ZipArchive::new(VerifiedJarReader::new(data, preflight)) else {
        return false;
    };
    if archive.len() > MAX_JAR_ENTRIES {
        return false;
    }

    (0..archive.len()).any(|index| {
        archive
            .by_index(index)
            .is_ok_and(|file| file.is_file() && file.name().ends_with(".class"))
    })
}

/// Inspect the fixed-size end-of-central-directory record before `zip` allocates
/// its file table. ZIP64 is rejected because its 64-bit entry count would need a
/// separate pre-allocation budget path.
fn preflight_jar_archive(data: &[u8]) -> Result<JarPreflight> {
    let eocd_offset = find_zip_eocd(data)
        .ok_or_else(|| BinaryError::invalid_data("ZIP end-of-central-directory record missing"))?;
    let eocd = &data[eocd_offset..eocd_offset + ZIP_EOCD_MIN_SIZE];

    let disk_number = u16::from_le_bytes([eocd[4], eocd[5]]);
    let central_directory_disk = u16::from_le_bytes([eocd[6], eocd[7]]);
    let entries_on_disk = u16::from_le_bytes([eocd[8], eocd[9]]);
    let total_entries = u16::from_le_bytes([eocd[10], eocd[11]]);
    let central_directory_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]);
    let central_directory_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]);
    let comment_length = usize::from(u16::from_le_bytes([eocd[20], eocd[21]]));

    if disk_number == u16::MAX
        || central_directory_disk == u16::MAX
        || entries_on_disk == u16::MAX
        || total_entries == u16::MAX
        || central_directory_size == u32::MAX
        || central_directory_offset == u32::MAX
    {
        return Err(BinaryError::invalid_data(
            "ZIP64 JAR archives are not supported by the bounded parser",
        ));
    }

    if disk_number != 0 || central_directory_disk != 0 || entries_on_disk != total_entries {
        return Err(BinaryError::invalid_data(
            "multi-disk ZIP/JAR archives are not supported",
        ));
    }

    let entry_count = usize::from(total_entries);
    if entry_count > MAX_JAR_ENTRIES {
        return Err(BinaryError::invalid_data(format!(
            "JAR declares {entry_count} entries; limit is {MAX_JAR_ENTRIES}"
        )));
    }

    let record_end = eocd_offset
        .checked_add(ZIP_EOCD_MIN_SIZE)
        .and_then(|end| end.checked_add(comment_length))
        .ok_or_else(|| BinaryError::invalid_data("ZIP footer length overflows usize"))?;
    if record_end != data.len() {
        return Err(BinaryError::invalid_data(
            "ZIP end-of-central-directory record does not end at EOF",
        ));
    }

    Ok(JarPreflight { eocd_offset })
}

fn find_zip_eocd(data: &[u8]) -> Option<usize> {
    let latest = data.len().checked_sub(ZIP_EOCD_MIN_SIZE)?;
    let earliest = data
        .len()
        .saturating_sub(ZIP_EOCD_MIN_SIZE + usize::from(u16::MAX));

    (earliest..=latest).rev().find(|&offset| {
        let Some(eocd) = data.get(offset..offset + ZIP_EOCD_MIN_SIZE) else {
            return false;
        };
        if &eocd[..4] != ZIP_EOCD_SIGNATURE {
            return false;
        }

        let comment_length = usize::from(u16::from_le_bytes([eocd[20], eocd[21]]));
        let record_ends_at_eof = offset
            .checked_add(ZIP_EOCD_MIN_SIZE)
            .and_then(|end| end.checked_add(comment_length))
            == Some(data.len());
        if !record_ends_at_eof {
            return false;
        }

        // A JAR must contain at least one entry. Requiring its central-directory
        // signature prevents an EOCD-shaped byte sequence exactly 22 bytes from
        // the end of an archive comment from shadowing the real footer.
        let total_entries = u16::from_le_bytes([eocd[10], eocd[11]]);
        let central_directory_size =
            usize::try_from(u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]])).ok();
        let central_directory_offset =
            usize::try_from(u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]])).ok();

        total_entries != 0
            && central_directory_offset
                .zip(central_directory_size)
                .is_some_and(|(directory_offset, directory_size)| {
                    directory_offset.checked_add(directory_size) == Some(offset)
                        && data.get(directory_offset..directory_offset.saturating_add(4))
                            == Some(ZIP_CENTRAL_DIRECTORY_SIGNATURE)
                })
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::{ZipWriter, write::FileOptions};

    #[test]
    fn generic_zip_is_not_claimed_as_java() {
        let mut output = Cursor::new(Vec::new());
        {
            let mut archive = ZipWriter::new(&mut output);
            archive
                .start_file("README.txt", FileOptions::default())
                .unwrap();
            archive.write_all(b"not a class").unwrap();
            archive.finish().unwrap();
        }
        let data = output.into_inner();

        assert!(!JavaParser::can_parse(&data));
        assert!(JavaParser::parse(&data).is_err());
    }

    #[test]
    fn truncated_class_header_is_rejected() {
        let data = b"\xca\xfe\xba\xbe\0\0\0\x34";
        let error = JavaParser::parse(data).err().expect("parse must fail");
        assert!(error.to_string().contains("Truncated Java class header"));
    }

    #[test]
    fn class_header_requires_valid_version_and_constant_pool_count() {
        let invalid_version = b"\xca\xfe\xba\xbe\0\0\0\x2c\0\x01";
        assert!(!JavaParser::can_parse(invalid_version));
        assert!(
            JavaParser::parse(invalid_version)
                .err()
                .expect("invalid version must be rejected")
                .to_string()
                .contains("major version 44")
        );

        let empty_constant_pool = b"\xca\xfe\xba\xbe\0\0\0\x34\0\0";
        assert!(!JavaParser::can_parse(empty_constant_pool));
        assert!(
            JavaParser::parse(empty_constant_pool)
                .err()
                .expect("empty constant pool must be rejected")
                .to_string()
                .contains("constant_pool_count 0")
        );
    }

    #[test]
    fn forged_eocd_count_is_rejected_before_zip_archive_construction() {
        let mut output = Cursor::new(Vec::new());
        {
            let mut archive = ZipWriter::new(&mut output);
            archive
                .start_file("Main.class", FileOptions::default())
                .unwrap();
            archive.write_all(b"\xca\xfe\xba\xbe").unwrap();
            archive.finish().unwrap();
        }
        let mut data = output.into_inner();
        let eocd = find_zip_eocd(&data).expect("test ZIP has EOCD");
        let forged_count = u16::try_from(MAX_JAR_ENTRIES + 1).unwrap().to_le_bytes();
        data[eocd + 8..eocd + 10].copy_from_slice(&forged_count);
        data[eocd + 10..eocd + 12].copy_from_slice(&forged_count);

        let error = preflight_jar_archive(&data).unwrap_err();
        assert!(error.to_string().contains("declares 50001 entries"));
        assert!(!JavaParser::can_parse(&data));
    }

    #[test]
    fn eocd_signature_inside_archive_comment_is_ignored() {
        let mut output = Cursor::new(Vec::new());
        {
            let mut archive = ZipWriter::new(&mut output);
            archive
                .start_file("Main.class", FileOptions::default())
                .unwrap();
            archive.write_all(b"\xca\xfe\xba\xbe").unwrap();
            let mut comment = b"prefixPK\x05\x06".to_vec();
            comment.extend_from_slice(&[0_u8; ZIP_EOCD_MIN_SIZE]);
            archive.set_raw_comment(comment);
            archive.finish().unwrap();
        }
        let data = output.into_inner();

        assert!(JavaParser::can_parse(&data));
        assert!(JavaParser::parse(&data).is_ok());
    }

    #[test]
    fn eocd_signature_crossing_into_archive_comment_is_ignored() {
        let mut output = Cursor::new(Vec::new());
        {
            let mut archive = ZipWriter::new(&mut output);
            archive
                .start_file("Main.class", FileOptions::default())
                .unwrap();
            archive.write_all(b"\xca\xfe\xba\xbe").unwrap();

            // Length 0x5003 puts `P` in the high comment-length byte. The first
            // three comment bytes complete a forged EOCD signature beginning
            // one byte before the comment itself.
            let mut comment = vec![0_u8; 0x5003];
            comment[..3].copy_from_slice(b"K\x05\x06");
            archive.set_raw_comment(comment);
            archive.finish().unwrap();
        }
        let data = output.into_inner();

        assert!(JavaParser::can_parse(&data));
        assert!(JavaParser::parse(&data).is_ok());
    }
}
