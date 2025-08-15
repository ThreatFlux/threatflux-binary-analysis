use crate::{error::BinaryError, Result};
#[cfg(feature = "serde-support")]
use serde::{de::DeserializeOwned, Serialize};

/// Serialize a value to a JSON string.
#[cfg(feature = "serde-support")]
pub fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| BinaryError::internal(e.to_string()))
}

/// Deserialize a value from a JSON string.
#[cfg(feature = "serde-support")]
pub fn from_json<T: DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|e| BinaryError::internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AnalysisResult, BinaryFormat};

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_json_roundtrip() {
        let result = AnalysisResult {
            format: BinaryFormat::Elf,
            ..Default::default()
        };
        let json = to_json(&result).unwrap();
        assert!(json.contains("\"Elf\""));
        let de: AnalysisResult = from_json(&json).unwrap();
        assert_eq!(de.format, BinaryFormat::Elf);
    }
}
