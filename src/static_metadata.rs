//! Versioned, producer-owned static metadata reports.
//!
//! This module is additive to the legacy [`crate::AnalysisResult`] API. It
//! intentionally projects metadata only: no input bytes, section previews,
//! disassembly bytes, or resource payloads are retained here.

use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

use crate::{AnalysisResult, BinaryError};

/// Schema revision emitted by this crate for static metadata reports.
pub const STATIC_METADATA_SCHEMA_REVISION: u32 = 1;

/// Algorithm revision for PE schema-v1 extraction rules.
///
/// Revision 1 freezes the pinned pefile import-hash/ordinal behavior, the
/// SHA-256 PE image-hash ranges, ordered Rich records, and bounded ordered
/// resource-leaf traversal. Zero means unknown historical behavior.
pub const STATIC_METADATA_ALGORITHM_REVISION: u32 = 1;

/// Producer identity and input binding carried by every enriched operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct ReportProvenance {
    /// Cargo package name of the producer, or `None` for historical data.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub analyzer: Option<String>,
    /// Cargo package version of the producer, or `None` for historical data.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub analyzer_version: Option<String>,
    /// Sorted Cargo feature names compiled into the producer, when known.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub feature_profile: Option<Vec<String>>,
    /// Lowercase SHA-256 of the complete caller-supplied input, when known.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub input_sha256: Option<String>,
}

impl ReportProvenance {
    pub(crate) fn for_data(data: &[u8]) -> Self {
        Self {
            analyzer: Some(env!("CARGO_PKG_NAME").to_string()),
            analyzer_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            feature_profile: Some(effective_feature_profile()),
            input_sha256: Some(sha256_hex(data)),
        }
    }
}

/// An additive result containing legacy analysis and the versioned report.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Deserialize))]
#[non_exhaustive]
pub struct EnrichedAnalysisResult {
    /// The unchanged legacy analysis projection.
    pub analysis: AnalysisResult,
    /// Versioned metadata that is safe to persist as an allowlisted projection.
    pub static_metadata: StaticMetadataReport,
}

impl EnrichedAnalysisResult {
    /// Read a current enriched envelope or archived 0.3.x `AnalysisResult` JSON.
    ///
    /// This reader is deliberately deserialize-only. A legacy value retains
    /// every ordinary analysis field while adding an unknown-provenance,
    /// `not_evaluated` metadata report.
    #[cfg(feature = "serde-support")]
    pub fn from_compatible_json(input: &str) -> std::result::Result<Self, serde_json::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum CompatibleAnalysis {
            Current(Box<EnrichedAnalysisResult>),
            Legacy(Box<AnalysisResult>),
        }

        serde_json::from_str(input).map(|analysis| match analysis {
            CompatibleAnalysis::Current(enriched) => *enriched,
            CompatibleAnalysis::Legacy(analysis) => {
                let static_metadata = StaticMetadataReport::from_legacy_analysis(&analysis);
                Self {
                    analysis: *analysis,
                    static_metadata,
                }
            }
        })
    }
}

/// Versioned static metadata report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct StaticMetadataReport {
    /// Wire schema revision. Revision 1 is defined by KAN-2979.
    pub schema_revision: u32,
    /// Frozen extraction-algorithm revision, or zero for migrated legacy data.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub algorithm_revision: u32,
    /// Producer and whole-input identity.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub provenance: ReportProvenance,
    /// PE-specific metadata, or an explicit applicability/capability outcome.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub pe: FieldOutcome<PeStaticMetadata>,
}

impl StaticMetadataReport {
    pub(crate) fn new(provenance: ReportProvenance, pe: FieldOutcome<PeStaticMetadata>) -> Self {
        Self {
            schema_revision: STATIC_METADATA_SCHEMA_REVISION,
            algorithm_revision: STATIC_METADATA_ALGORITHM_REVISION,
            provenance,
            pe,
        }
    }

    /// Convert an archived legacy analysis into an explicit unevaluated report.
    ///
    /// The legacy projection is inspected but not embedded, so section previews
    /// and optional instruction bytes cannot leak into this metadata report.
    pub fn from_legacy_analysis(_legacy: &AnalysisResult) -> Self {
        Self {
            schema_revision: STATIC_METADATA_SCHEMA_REVISION,
            algorithm_revision: 0,
            provenance: ReportProvenance::default(),
            pe: FieldOutcome::NotEvaluated,
        }
    }

    /// Read either a schema-v1 report or archived 0.3.x `AnalysisResult` JSON.
    ///
    /// This report-only projection intentionally discards ordinary legacy
    /// fields. Use [`EnrichedAnalysisResult::from_compatible_json`] when those
    /// fields must be retained. Legacy JSON produces unknown provenance and
    /// `not_evaluated` PE state.
    #[cfg(feature = "serde-support")]
    pub fn from_compatible_json(input: &str) -> std::result::Result<Self, serde_json::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum CompatibleReport {
            Current(Box<StaticMetadataReport>),
            Legacy(Box<AnalysisResult>),
        }

        serde_json::from_str(input).map(|report| match report {
            CompatibleReport::Current(report) => *report,
            CompatibleReport::Legacy(legacy) => Self::from_legacy_analysis(&legacy),
        })
    }
}

/// Typed outcome for an enrichment block or field.
///
/// Missing fields in archived JSON deserialize as [`Self::NotEvaluated`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde-support",
    serde(tag = "status", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum FieldOutcome<T> {
    /// The field was evaluated and has a value.
    Present {
        /// Typed field value.
        value: T,
    },
    /// The field was evaluated successfully and is not present in the image.
    Absent,
    /// The field does not apply to the detected input format.
    NotApplicable,
    /// The field or layout is outside this producer's supported profile.
    Unsupported {
        /// Stable human-readable explanation.
        reason: String,
    },
    /// The operation was deliberately skipped or was absent from legacy data.
    #[default]
    NotEvaluated,
    /// The field structure or a referenced file span is invalid.
    Invalid {
        /// Stable human-readable diagnostic.
        reason: String,
    },
    /// The field exceeded a documented parser budget.
    LimitExceeded {
        /// Name of the shared limit that was reached.
        limit: String,
    },
    /// A future outcome unknown to this reader.
    #[cfg_attr(feature = "serde-support", serde(other))]
    Unknown,
}

/// PE metadata fields defined by static report schema revision 1.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct PeStaticMetadata {
    /// Pefile-compatible MD5 import hash for the ordinary import directory.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub imphash: FieldOutcome<String>,
    /// Microsoft PE image hash using SHA-256.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub authentihash: FieldOutcome<AuthenticodeHash>,
    /// Decoded Rich Header records.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub rich_header: FieldOutcome<RichHeader>,
    /// Ordered type/name/language resource leaves.
    #[cfg_attr(feature = "serde-support", serde(default))]
    pub resources: FieldOutcome<Vec<ResourceLeaf>>,
}

/// A qualified Authenticode PE image hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct AuthenticodeHash {
    /// Digest algorithm. Revision 1 always emits `sha256`.
    pub algorithm: String,
    /// Lowercase hexadecimal image digest.
    pub digest: String,
}

/// Decoded PE Rich Header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct RichHeader {
    /// XOR key stored after the `Rich` marker.
    pub xor_key: u32,
    /// Records in physical file order, including duplicates.
    pub entries: Vec<RichHeaderEntry>,
}

/// One decoded Rich Header record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct RichHeaderEntry {
    /// Microsoft product/tool identifier claimed by the image.
    pub product_id: u16,
    /// Tool build number claimed by the image.
    pub build: u16,
    /// Claimed tool-use count.
    pub use_count: u32,
}

/// Numeric or textual component of a PE resource path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-support", serde(untagged, deny_unknown_fields))]
#[non_exhaustive]
pub enum ResourceIdentifier {
    /// Numeric resource identifier.
    Id {
        /// Identifier value.
        id: u32,
    },
    /// UTF-16 resource name decoded without loss.
    Name {
        /// Decoded name.
        name: String,
    },
}

/// Metadata for one file-backed PE resource leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct ResourceLeaf {
    /// First-level resource type.
    pub r#type: ResourceIdentifier,
    /// Second-level resource name.
    pub name: ResourceIdentifier,
    /// Third-level resource language.
    pub language: ResourceIdentifier,
    /// RVA of the resource payload.
    pub data_rva: u32,
    /// Declared payload size.
    pub size_bytes: u32,
    /// Declared resource code page.
    pub code_page: u32,
}

/// Error returned by enriched entry points.
///
/// Unlike legacy entry points, failures retain the producer/profile/input
/// receipt so callers can attribute a parser-level rejection.
#[derive(Debug, Error)]
#[error("{source}")]
pub struct EnrichedAnalysisError {
    /// Producer and input identity for the failed operation.
    pub provenance: ReportProvenance,
    /// Underlying parser or analysis error.
    #[source]
    pub source: BinaryError,
}

impl EnrichedAnalysisError {
    pub(crate) fn new(provenance: ReportProvenance, source: BinaryError) -> Box<Self> {
        Box::new(Self { provenance, source })
    }
}

/// Result type for enriched analysis entry points.
pub type EnrichedResult<T> = std::result::Result<T, Box<EnrichedAnalysisError>>;

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&Sha256::digest(data))
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn effective_feature_profile() -> Vec<String> {
    const FEATURES: &[(&str, bool)] = &[
        ("compression", cfg!(feature = "compression")),
        ("control-flow", cfg!(feature = "control-flow")),
        ("disasm-capstone", cfg!(feature = "disasm-capstone")),
        ("disasm-iced", cfg!(feature = "disasm-iced")),
        ("elf", cfg!(feature = "elf")),
        ("entropy-analysis", cfg!(feature = "entropy-analysis")),
        ("java", cfg!(feature = "java")),
        ("macho", cfg!(feature = "macho")),
        ("pe", cfg!(feature = "pe")),
        ("serde-support", cfg!(feature = "serde-support")),
        ("symbol-resolution", cfg!(feature = "symbol-resolution")),
        ("visualization", cfg!(feature = "visualization")),
        ("wasm", cfg!(feature = "wasm")),
    ];
    FEATURES
        .iter()
        .filter(|(_, enabled)| *enabled)
        .map(|(name, _)| (*name).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde-support")]
    use crate::types::{Endianness, SectionPermissions, SectionType};
    #[cfg(feature = "serde-support")]
    use crate::{BinaryFormat, Import, Section};

    #[cfg(feature = "serde-support")]
    #[test]
    fn legacy_json_preserves_analysis_and_marks_enrichment_unknown() {
        let mut legacy = AnalysisResult {
            format: BinaryFormat::Pe,
            metadata: crate::BinaryMetadata {
                size: 321,
                format: BinaryFormat::Pe,
                endian: Endianness::Little,
                ..crate::BinaryMetadata::default()
            },
            ..AnalysisResult::default()
        };
        legacy.sections.push(Section {
            name: ".text".to_string(),
            address: 0x401000,
            size: 3,
            offset: 0x200,
            file_size: 3,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            section_type: SectionType::Code,
            data: Some(vec![0x90, 0x90, 0xc3]),
        });
        legacy.imports.push(Import {
            name: "ExitProcess".to_string(),
            library: Some("KERNEL32.dll".to_string()),
            address: Some(0x402000),
            ordinal: None,
        });

        let json = serde_json::to_string(&legacy).unwrap();
        let enriched = EnrichedAnalysisResult::from_compatible_json(&json).unwrap();
        assert_eq!(enriched.analysis.format, BinaryFormat::Pe);
        assert_eq!(enriched.analysis.metadata.size, 321);
        assert_eq!(
            enriched.analysis.sections[0].data,
            Some(vec![0x90, 0x90, 0xc3])
        );
        assert_eq!(enriched.analysis.imports[0].name, "ExitProcess");
        assert_eq!(enriched.static_metadata.algorithm_revision, 0);
        assert_eq!(
            enriched.static_metadata.provenance,
            ReportProvenance::default()
        );
        assert_eq!(enriched.static_metadata.pe, FieldOutcome::NotEvaluated);
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn report_wire_defaults_and_resource_identifiers_are_backward_compatible() {
        let migrated: StaticMetadataReport = serde_json::from_str(
            r#"{
                "schema_revision": 1,
                "provenance": {},
                "pe": {"status": "not_evaluated"}
            }"#,
        )
        .unwrap();
        assert_eq!(migrated.algorithm_revision, 0);
        assert_eq!(migrated.provenance, ReportProvenance::default());

        let fields: PeStaticMetadata = serde_json::from_str("{}").unwrap();
        assert_eq!(fields.imphash, FieldOutcome::NotEvaluated);
        assert_eq!(fields.authentihash, FieldOutcome::NotEvaluated);
        assert_eq!(fields.rich_header, FieldOutcome::NotEvaluated);
        assert_eq!(fields.resources, FieldOutcome::NotEvaluated);

        assert_eq!(
            serde_json::to_value(ResourceIdentifier::Id { id: 7 }).unwrap(),
            serde_json::json!({"id": 7})
        );
        assert_eq!(
            serde_json::to_value(ResourceIdentifier::Name {
                name: "7".to_string()
            })
            .unwrap(),
            serde_json::json!({"name": "7"})
        );
        let future: FieldOutcome<String> =
            serde_json::from_str(r#"{"status":"future_state"}"#).unwrap();
        assert_eq!(future, FieldOutcome::Unknown);
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn metadata_report_serialization_contains_no_legacy_raw_bytes() {
        let report = StaticMetadataReport::new(
            ReportProvenance::for_data(b"benign"),
            FieldOutcome::NotApplicable,
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("section"));
        assert!(!json.contains("disassembly"));
        assert!(!json.contains("instruction_bytes"));
        assert_eq!(
            report.algorithm_revision,
            STATIC_METADATA_ALGORITHM_REVISION
        );
    }

    #[cfg(not(feature = "pe"))]
    #[test]
    fn pe_signature_is_unsupported_when_parser_feature_is_disabled() {
        let mut data = vec![0_u8; 0x88];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let parsed = crate::EnrichedBinaryFile::parse(&data).unwrap();
        assert!(matches!(
            parsed.static_metadata().pe,
            FieldOutcome::Unsupported { .. }
        ));
        assert_eq!(parsed.binary().format(), crate::BinaryFormat::Raw);
    }
}
