//! Entropy analysis for binary files

use crate::{
    types::{EntropyAnalysis, EntropyRegion, ObfuscationLevel, PackingIndicators},
    BinaryFile, Result,
};
use std::collections::HashMap;

// Note: Advanced statistical analysis planned for future entropy features
// #[cfg(feature = "entropy-analysis")]
// use statrs::statistics::Statistics;

/// Analyze entropy of a binary file
pub fn analyze_binary(binary: &BinaryFile) -> Result<EntropyAnalysis> {
    let data = binary.data();

    // Calculate overall entropy
    let overall_entropy = calculate_entropy(data);

    // Calculate section-wise entropy
    let mut section_entropy = HashMap::new();
    for section in binary.sections() {
        let start = section.offset as usize;
        let end = (section.offset + section.size) as usize;

        if start < data.len() && end <= data.len() && start < end {
            let section_data = &data[start..end];
            let entropy = calculate_entropy(section_data);
            section_entropy.insert(section.name.clone(), entropy);
        }
    }

    // Find high entropy regions
    let high_entropy_regions = find_high_entropy_regions(data)?;

    // Analyze packing indicators
    let packing_indicators = analyze_packing_indicators(data, &section_entropy);

    Ok(EntropyAnalysis {
        overall_entropy,
        section_entropy,
        high_entropy_regions,
        packing_indicators,
    })
}

/// Calculate Shannon entropy for data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    // Calculate entropy
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Find regions with high entropy
fn find_high_entropy_regions(data: &[u8]) -> Result<Vec<EntropyRegion>> {
    let mut regions = Vec::new();
    let chunk_size = 1024; // Analyze in 1KB chunks
    let high_entropy_threshold = 7.5; // Threshold for high entropy

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let entropy = calculate_entropy(chunk);

        if entropy > high_entropy_threshold {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, data.len());

            let description = classify_high_entropy_region(chunk, entropy);

            regions.push(EntropyRegion {
                start: start as u64,
                end: end as u64,
                entropy,
                description,
            });
        }
    }

    Ok(regions)
}

/// Classify what might cause high entropy in a region
fn classify_high_entropy_region(data: &[u8], entropy: f64) -> String {
    if entropy > 7.9 {
        "Likely encrypted or compressed data".to_string()
    } else if entropy > 7.5 {
        // Check for patterns that might indicate specific types
        if has_crypto_constants(data) {
            "Possible cryptographic constants".to_string()
        } else if has_compression_signature(data) {
            "Possible compressed data".to_string()
        } else {
            "High entropy region - possible obfuscation".to_string()
        }
    } else {
        "Moderately high entropy".to_string()
    }
}

/// Check for cryptographic constants
fn has_crypto_constants(data: &[u8]) -> bool {
    // Look for common crypto constants (simplified)
    #[allow(clippy::type_complexity)]
    const CRYPTO_CONSTANTS: &[&[u8]] = &[
        b"\x67\x45\x23\x01", // MD5 constant
        b"\x01\x23\x45\x67", // Another common constant
        b"\x89\xab\xcd\xef", // Another common constant
    ];

    for &constant in CRYPTO_CONSTANTS {
        if data.windows(constant.len()).any(|w| w == constant) {
            return true;
        }
    }

    false
}

/// Check for compression signatures
fn has_compression_signature(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check for common compression signatures
    matches!(&data[0..2], b"\x1f\x8b") || // GZIP
    matches!(&data[0..4], b"PK\x03\x04") || // ZIP
    matches!(&data[0..3], b"BZh") || // BZIP2
    matches!(&data[0..4], b"\xfd7zXZ") // XZ
}

/// Analyze indicators of packing/obfuscation
fn analyze_packing_indicators(
    data: &[u8],
    section_entropy: &HashMap<String, f64>,
) -> PackingIndicators {
    let mut indicators = PackingIndicators::default();

    // Check overall entropy
    let overall_entropy = calculate_entropy(data);

    // High overall entropy suggests packing
    if overall_entropy > 7.5 {
        indicators.is_packed = true;
    }

    // Check for high entropy in code sections
    let mut high_entropy_code = false;
    for (name, &entropy) in section_entropy {
        if (name.contains("text") || name.contains("code")) && entropy > 7.0 {
            high_entropy_code = true;
            break;
        }
    }

    if high_entropy_code {
        indicators.is_packed = true;
    }

    // Estimate compression ratio (simplified)
    if indicators.is_packed {
        // This is a very rough estimate
        indicators.compression_ratio = Some(overall_entropy / 8.0);
    }

    // Determine obfuscation level
    indicators.obfuscation_level = if overall_entropy > 7.8 {
        ObfuscationLevel::High
    } else if overall_entropy > 7.5 {
        ObfuscationLevel::Medium
    } else if overall_entropy > 7.0 {
        ObfuscationLevel::Low
    } else {
        ObfuscationLevel::None
    };

    // Try to identify specific packers (simplified)
    indicators.packer_name = detect_packer(data);

    indicators
}

/// Attempt to detect specific packers
fn detect_packer(data: &[u8]) -> Option<String> {
    // This is a very simplified packer detection
    // In practice, this would use a database of packer signatures

    if data.len() < 1024 {
        return None;
    }

    // Check for common packer strings (simplified)
    let data_str = String::from_utf8_lossy(&data[..std::cmp::min(1024, data.len())]);

    if data_str.contains("UPX") {
        Some("UPX".to_string())
    } else if data_str.contains("VMProtect") {
        Some("VMProtect".to_string())
    } else if data_str.contains("Themida") {
        Some("Themida".to_string())
    } else if data_str.contains("ASPack") {
        Some("ASPack".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Test with uniform data (low entropy)
        let uniform_data = vec![0u8; 1024];
        let entropy = calculate_entropy(&uniform_data);
        assert!(entropy < 1.0);

        // Test with random-like data (high entropy)
        let random_data: Vec<u8> = (0..1024).map(|i| (i * 7 + 13) as u8).collect();
        let entropy = calculate_entropy(&random_data);
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_crypto_constants_detection() {
        let data = b"\x67\x45\x23\x01some other data";
        assert!(has_crypto_constants(data));

        let data = b"no crypto constants here";
        assert!(!has_crypto_constants(data));
    }

    #[test]
    fn test_compression_signature_detection() {
        // Test GZIP signature
        let gzip_data = b"\x1f\x8b\x08\x00";
        assert!(has_compression_signature(gzip_data));

        // Test ZIP signature
        let zip_data = b"PK\x03\x04";
        assert!(has_compression_signature(zip_data));

        // Test no compression
        let normal_data = b"normal data";
        assert!(!has_compression_signature(normal_data));
    }
}
