//! Pattern matching utilities for binary analysis
//!
//! This module provides advanced pattern matching capabilities for identifying
//! specific byte sequences, strings, and structural patterns in binary data.

use crate::{BinaryError, Result};
use std::collections::HashMap;

/// Pattern matcher for binary data
pub struct PatternMatcher {
    patterns: Vec<Pattern>,
    config: MatchConfig,
}

/// Pattern matching configuration
#[derive(Debug, Clone)]
pub struct MatchConfig {
    /// Case sensitive string matching
    pub case_sensitive: bool,
    /// Maximum number of matches to find
    pub max_matches: usize,
    /// Enable wildcard matching
    pub enable_wildcards: bool,
    /// Minimum pattern length
    pub min_pattern_length: usize,
}

impl Default for MatchConfig {
    fn default() -> Self {
        Self {
            case_sensitive: true,
            max_matches: 1000,
            enable_wildcards: true,
            min_pattern_length: 3,
        }
    }
}

/// A pattern to search for
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Pattern name/identifier
    pub name: String,
    /// Pattern type
    pub pattern_type: PatternType,
    /// Pattern data
    pub data: PatternData,
    /// Pattern category
    pub category: PatternCategory,
    /// Description
    pub description: String,
}

/// Types of patterns
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternType {
    /// Exact byte sequence
    Bytes,
    /// String pattern
    String,
    /// Regular expression
    Regex,
    /// Hex pattern with wildcards
    HexWildcard,
    /// Magic signature
    Magic,
    /// Structural pattern
    Structural,
}

/// Pattern data
#[derive(Debug, Clone)]
pub enum PatternData {
    /// Raw bytes
    Bytes(Vec<u8>),
    /// String data
    String(String),
    /// Hex pattern with wildcards (? for wildcard)
    HexWildcard(String),
    /// Regular expression pattern
    Regex(String),
}

/// Pattern categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatternCategory {
    /// File format signatures
    FileFormat,
    /// Compiler signatures
    Compiler,
    /// Packer signatures
    Packer,
    /// Cryptographic constants
    Crypto,
    /// Malware signatures
    Malware,
    /// API strings
    Api,
    /// Debug information
    Debug,
    /// Copyright/version strings
    Metadata,
    /// Network protocols
    Network,
    /// Custom patterns
    Custom,
}

/// Pattern match result
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Pattern that matched
    pub pattern: Pattern,
    /// Offset where match was found
    pub offset: usize,
    /// Length of the match
    pub length: usize,
    /// Matched data
    pub data: Vec<u8>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

/// Pattern search results
#[derive(Debug, Clone)]
pub struct SearchResults {
    /// All matches found
    pub matches: Vec<PatternMatch>,
    /// Matches grouped by category
    pub by_category: crate::types::PatternMatchMap,
    /// Total bytes searched
    pub bytes_searched: usize,
    /// Search duration
    pub duration_ms: u64,
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            config: MatchConfig::default(),
        }
    }

    /// Create pattern matcher with configuration
    pub fn with_config(config: MatchConfig) -> Self {
        Self {
            patterns: Vec::new(),
            config,
        }
    }

    /// Add a pattern to search for
    pub fn add_pattern(&mut self, pattern: Pattern) {
        self.patterns.push(pattern);
    }

    /// Add multiple patterns
    pub fn add_patterns(&mut self, patterns: Vec<Pattern>) {
        self.patterns.extend(patterns);
    }

    /// Load built-in pattern sets
    pub fn load_builtin_patterns(&mut self, categories: &[PatternCategory]) {
        for category in categories {
            let patterns = get_builtin_patterns(category);
            self.add_patterns(patterns);
        }
    }

    /// Search for all patterns in the given data
    pub fn search(&self, data: &[u8]) -> Result<SearchResults> {
        let start_time = std::time::Instant::now();
        let mut matches = Vec::new();
        let mut by_category: crate::types::PatternMatchMap = HashMap::new();

        for pattern in &self.patterns {
            let pattern_matches = self.search_pattern(data, pattern)?;

            for pattern_match in pattern_matches {
                by_category
                    .entry(pattern_match.pattern.category.clone())
                    .or_default()
                    .push(pattern_match.clone());

                matches.push(pattern_match);

                if matches.len() >= self.config.max_matches {
                    break;
                }
            }

            if matches.len() >= self.config.max_matches {
                break;
            }
        }

        let duration = start_time.elapsed();

        Ok(SearchResults {
            matches,
            by_category,
            bytes_searched: data.len(),
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// Search for a specific pattern in data
    fn search_pattern(&self, data: &[u8], pattern: &Pattern) -> Result<Vec<PatternMatch>> {
        match &pattern.pattern_type {
            PatternType::Bytes => self.search_bytes(data, pattern),
            PatternType::String => self.search_string(data, pattern),
            PatternType::HexWildcard => self.search_hex_wildcard(data, pattern),
            PatternType::Magic => self.search_magic(data, pattern),
            PatternType::Regex => self.search_regex(data, pattern),
            PatternType::Structural => self.search_structural(data, pattern),
        }
    }

    /// Search for exact byte sequences
    fn search_bytes(&self, data: &[u8], pattern: &Pattern) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();

        if let PatternData::Bytes(pattern_bytes) = &pattern.data {
            if pattern_bytes.len() < self.config.min_pattern_length {
                return Ok(matches);
            }

            let mut start = 0;
            while start + pattern_bytes.len() <= data.len() {
                if let Some(pos) = data[start..]
                    .windows(pattern_bytes.len())
                    .position(|window| window == pattern_bytes)
                {
                    let offset = start + pos;
                    matches.push(PatternMatch {
                        pattern: pattern.clone(),
                        offset,
                        length: pattern_bytes.len(),
                        data: data[offset..offset + pattern_bytes.len()].to_vec(),
                        confidence: 1.0,
                    });

                    start = offset + 1;

                    if matches.len() >= self.config.max_matches {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        Ok(matches)
    }

    /// Search for string patterns
    fn search_string(&self, data: &[u8], pattern: &Pattern) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();

        if let PatternData::String(pattern_str) = &pattern.data {
            if pattern_str.len() < self.config.min_pattern_length {
                return Ok(matches);
            }

            let search_str = if self.config.case_sensitive {
                pattern_str.clone()
            } else {
                pattern_str.to_lowercase()
            };

            let search_bytes = search_str.as_bytes();

            // Convert data to string for searching
            if let Ok(data_str) = String::from_utf8(data.to_vec()) {
                let search_data = if self.config.case_sensitive {
                    data_str
                } else {
                    data_str.to_lowercase()
                };

                let mut start = 0;
                while let Some(pos) = search_data[start..].find(&search_str) {
                    let offset = start + pos;
                    matches.push(PatternMatch {
                        pattern: pattern.clone(),
                        offset,
                        length: search_bytes.len(),
                        data: data[offset..offset + search_bytes.len()].to_vec(),
                        confidence: 1.0,
                    });

                    start = offset + 1;

                    if matches.len() >= self.config.max_matches {
                        break;
                    }
                }
            }
        }

        Ok(matches)
    }

    /// Search for hex patterns with wildcards
    fn search_hex_wildcard(&self, data: &[u8], pattern: &Pattern) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();

        if let PatternData::HexWildcard(hex_pattern) = &pattern.data {
            let compiled_pattern = compile_hex_wildcard(hex_pattern)?;

            let mut start = 0;
            while start + compiled_pattern.len() <= data.len() {
                if hex_wildcard_matches(
                    &data[start..start + compiled_pattern.len()],
                    &compiled_pattern,
                ) {
                    matches.push(PatternMatch {
                        pattern: pattern.clone(),
                        offset: start,
                        length: compiled_pattern.len(),
                        data: data[start..start + compiled_pattern.len()].to_vec(),
                        confidence: 1.0,
                    });

                    if matches.len() >= self.config.max_matches {
                        break;
                    }
                }
                start += 1;
            }
        }

        Ok(matches)
    }

    /// Search for magic signatures
    fn search_magic(&self, data: &[u8], pattern: &Pattern) -> Result<Vec<PatternMatch>> {
        // Magic signatures are typically at the beginning of files
        let mut matches = Vec::new();

        if let PatternData::Bytes(magic_bytes) = &pattern.data {
            if data.len() >= magic_bytes.len() && &data[..magic_bytes.len()] == magic_bytes {
                matches.push(PatternMatch {
                    pattern: pattern.clone(),
                    offset: 0,
                    length: magic_bytes.len(),
                    data: magic_bytes.clone(),
                    confidence: 1.0,
                });
            }
        }

        Ok(matches)
    }

    /// Search using regular expressions
    fn search_regex(&self, _data: &[u8], _pattern: &Pattern) -> Result<Vec<PatternMatch>> {
        // Regex support would require the regex crate
        // For now, return empty matches
        Ok(Vec::new())
    }

    /// Search for structural patterns
    fn search_structural(&self, _data: &[u8], _pattern: &Pattern) -> Result<Vec<PatternMatch>> {
        // Structural pattern matching would be more complex
        // For now, return empty matches
        Ok(Vec::new())
    }
}

/// Compile hex wildcard pattern
fn compile_hex_wildcard(pattern: &str) -> crate::types::HexPatternResult {
    let mut compiled = Vec::new();
    let clean_pattern = pattern.replace(" ", "").replace("\n", "");

    if clean_pattern.len() % 2 != 0 {
        return Err(BinaryError::invalid_data(
            "Hex pattern must have even length",
        ));
    }

    for i in (0..clean_pattern.len()).step_by(2) {
        let hex_byte = &clean_pattern[i..i + 2];

        if hex_byte == "??" {
            compiled.push(None); // Wildcard
        } else {
            let byte_value = u8::from_str_radix(hex_byte, 16).map_err(|_| {
                BinaryError::invalid_data(format!("Invalid hex byte: {}", hex_byte))
            })?;
            compiled.push(Some(byte_value));
        }
    }

    Ok(compiled)
}

/// Check if data matches hex wildcard pattern
fn hex_wildcard_matches(data: &[u8], pattern: &crate::types::HexPattern) -> bool {
    if data.len() != pattern.len() {
        return false;
    }

    for (i, &byte) in data.iter().enumerate() {
        match pattern[i] {
            Some(expected) if expected != byte => return false,
            None => continue, // Wildcard matches anything
            _ => continue,
        }
    }

    true
}

/// Get built-in patterns for a category
fn get_builtin_patterns(category: &PatternCategory) -> Vec<Pattern> {
    match category {
        PatternCategory::FileFormat => get_file_format_patterns(),
        PatternCategory::Compiler => get_compiler_patterns(),
        PatternCategory::Packer => get_packer_patterns(),
        PatternCategory::Crypto => get_crypto_patterns(),
        PatternCategory::Malware => get_malware_patterns(),
        PatternCategory::Api => get_api_patterns(),
        _ => Vec::new(),
    }
}

/// File format signature patterns
fn get_file_format_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "PE_MZ".to_string(),
            pattern_type: PatternType::Magic,
            data: PatternData::Bytes(b"MZ".to_vec()),
            category: PatternCategory::FileFormat,
            description: "DOS/PE executable signature".to_string(),
        },
        Pattern {
            name: "ELF".to_string(),
            pattern_type: PatternType::Magic,
            data: PatternData::Bytes(b"\x7fELF".to_vec()),
            category: PatternCategory::FileFormat,
            description: "ELF executable signature".to_string(),
        },
        Pattern {
            name: "Mach_O_32".to_string(),
            pattern_type: PatternType::Magic,
            data: PatternData::Bytes(vec![0xfe, 0xed, 0xfa, 0xce]),
            category: PatternCategory::FileFormat,
            description: "Mach-O 32-bit signature".to_string(),
        },
        Pattern {
            name: "Mach_O_64".to_string(),
            pattern_type: PatternType::Magic,
            data: PatternData::Bytes(vec![0xfe, 0xed, 0xfa, 0xcf]),
            category: PatternCategory::FileFormat,
            description: "Mach-O 64-bit signature".to_string(),
        },
    ]
}

/// Compiler signature patterns
fn get_compiler_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "GCC".to_string(),
            pattern_type: PatternType::String,
            data: PatternData::String("GCC:".to_string()),
            category: PatternCategory::Compiler,
            description: "GCC compiler signature".to_string(),
        },
        Pattern {
            name: "MSVC".to_string(),
            pattern_type: PatternType::String,
            data: PatternData::String("Microsoft C/C++".to_string()),
            category: PatternCategory::Compiler,
            description: "Microsoft Visual C++ signature".to_string(),
        },
    ]
}

/// Packer signature patterns
fn get_packer_patterns() -> Vec<Pattern> {
    vec![Pattern {
        name: "UPX".to_string(),
        pattern_type: PatternType::String,
        data: PatternData::String("UPX!".to_string()),
        category: PatternCategory::Packer,
        description: "UPX packer signature".to_string(),
    }]
}

/// Cryptographic constants patterns
fn get_crypto_patterns() -> Vec<Pattern> {
    vec![Pattern {
        name: "MD5_Init".to_string(),
        pattern_type: PatternType::Bytes,
        data: PatternData::Bytes(vec![0x01, 0x23, 0x45, 0x67]), // MD5 initial value
        category: PatternCategory::Crypto,
        description: "MD5 initialization constants".to_string(),
    }]
}

/// Malware signature patterns
fn get_malware_patterns() -> Vec<Pattern> {
    vec![Pattern {
        name: "Suspicious_API".to_string(),
        pattern_type: PatternType::String,
        data: PatternData::String("VirtualAllocEx".to_string()),
        category: PatternCategory::Malware,
        description: "Suspicious Windows API call".to_string(),
    }]
}

/// API string patterns
fn get_api_patterns() -> Vec<Pattern> {
    vec![Pattern {
        name: "CreateProcess".to_string(),
        pattern_type: PatternType::String,
        data: PatternData::String("CreateProcessA".to_string()),
        category: PatternCategory::Api,
        description: "Windows CreateProcess API".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==============================
    // Pattern Matcher Creation Tests
    // ==============================

    #[test]
    fn test_pattern_matcher_creation() {
        let matcher = PatternMatcher::new();
        assert_eq!(matcher.patterns.len(), 0);
        assert!(matcher.config.case_sensitive);
        assert_eq!(matcher.config.max_matches, 1000);
        assert!(matcher.config.enable_wildcards);
        assert_eq!(matcher.config.min_pattern_length, 3);
    }

    #[test]
    fn test_pattern_matcher_default() {
        let matcher = PatternMatcher::default();
        assert_eq!(matcher.patterns.len(), 0);
    }

    #[test]
    fn test_pattern_matcher_with_config() {
        let config = MatchConfig {
            case_sensitive: false,
            max_matches: 500,
            enable_wildcards: false,
            min_pattern_length: 5,
        };
        let matcher = PatternMatcher::with_config(config.clone());
        assert_eq!(matcher.config.case_sensitive, false);
        assert_eq!(matcher.config.max_matches, 500);
        assert_eq!(matcher.config.enable_wildcards, false);
        assert_eq!(matcher.config.min_pattern_length, 5);
    }

    #[test]
    fn test_match_config_default() {
        let config = MatchConfig::default();
        assert!(config.case_sensitive);
        assert_eq!(config.max_matches, 1000);
        assert!(config.enable_wildcards);
        assert_eq!(config.min_pattern_length, 3);
    }

    // ==============================
    // Pattern Addition Tests
    // ==============================

    #[test]
    fn test_add_single_pattern() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"test".to_vec()),
        );

        matcher.add_pattern(pattern);
        assert_eq!(matcher.patterns.len(), 1);
        assert_eq!(matcher.patterns[0].name, "test");
    }

    #[test]
    fn test_add_multiple_patterns() {
        let mut matcher = PatternMatcher::new();
        let patterns = vec![
            create_test_pattern(
                "test1",
                PatternType::Bytes,
                PatternData::Bytes(b"test1".to_vec()),
            ),
            create_test_pattern(
                "test2",
                PatternType::String,
                PatternData::String("test2".to_string()),
            ),
        ];

        matcher.add_patterns(patterns);
        assert_eq!(matcher.patterns.len(), 2);
    }

    // ==============================
    // Hex Wildcard Compilation Tests
    // ==============================

    #[test]
    fn test_hex_wildcard_compilation() {
        let pattern = "48 65 ?? 6c 6f";
        let compiled = compile_hex_wildcard(pattern).unwrap();

        assert_eq!(compiled.len(), 5);
        assert_eq!(compiled[0], Some(0x48));
        assert_eq!(compiled[1], Some(0x65));
        assert_eq!(compiled[2], None);
        assert_eq!(compiled[3], Some(0x6c));
        assert_eq!(compiled[4], Some(0x6f));
    }

    #[test]
    fn test_hex_wildcard_compilation_no_spaces() {
        let pattern = "48656c6f";
        let compiled = compile_hex_wildcard(pattern).unwrap();

        assert_eq!(compiled.len(), 4);
        assert_eq!(compiled[0], Some(0x48));
        assert_eq!(compiled[1], Some(0x65));
        assert_eq!(compiled[2], Some(0x6c));
        assert_eq!(compiled[3], Some(0x6f));
    }

    #[test]
    fn test_hex_wildcard_compilation_with_newlines() {
        let pattern = "48 65\n?? 6c\n6f";
        let compiled = compile_hex_wildcard(pattern).unwrap();

        assert_eq!(compiled.len(), 5);
        assert_eq!(compiled[2], None);
    }

    #[test]
    fn test_hex_wildcard_compilation_error_odd_length() {
        let pattern = "48 65 6";
        let result = compile_hex_wildcard(pattern);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_wildcard_compilation_error_invalid_hex() {
        let pattern = "48 65 XY 6c";
        let result = compile_hex_wildcard(pattern);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_wildcard_compilation_all_wildcards() {
        let pattern = "?? ?? ??";
        let compiled = compile_hex_wildcard(pattern).unwrap();

        assert_eq!(compiled.len(), 3);
        assert_eq!(compiled[0], None);
        assert_eq!(compiled[1], None);
        assert_eq!(compiled[2], None);
    }

    #[test]
    fn test_hex_wildcard_matching() {
        let data = &[0x48, 0x65, 0x78, 0x6c, 0x6f]; // "Hexlo"
        let pattern = vec![Some(0x48), Some(0x65), None, Some(0x6c), Some(0x6f)];

        assert!(hex_wildcard_matches(data, &pattern));

        let wrong_pattern = vec![Some(0x48), Some(0x65), None, Some(0x6c), Some(0x70)];
        assert!(!hex_wildcard_matches(data, &wrong_pattern));
    }

    #[test]
    fn test_hex_wildcard_matching_length_mismatch() {
        let data = &[0x48, 0x65, 0x78];
        let pattern = vec![Some(0x48), Some(0x65), None, Some(0x6c)];

        assert!(!hex_wildcard_matches(data, &pattern));
    }

    #[test]
    fn test_hex_wildcard_matching_empty() {
        let data = &[];
        let pattern = vec![];

        assert!(hex_wildcard_matches(data, &pattern));
    }

    // ==============================
    // Byte Pattern Search Tests
    // ==============================

    #[test]
    fn test_byte_pattern_search() {
        let mut matcher = PatternMatcher::new();

        let pattern = Pattern {
            name: "test".to_string(),
            pattern_type: PatternType::Bytes,
            data: PatternData::Bytes(b"hello".to_vec()),
            category: PatternCategory::Custom,
            description: "Test pattern".to_string(),
        };

        matcher.add_pattern(pattern);

        let data = b"This is a hello world test";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].offset, 10);
        assert_eq!(results.matches[0].length, 5);
        assert_eq!(results.matches[0].data, b"hello");
        assert_eq!(results.matches[0].confidence, 1.0);
    }

    #[test]
    fn test_byte_pattern_search_multiple_matches() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"abc".to_vec()),
        );
        matcher.add_pattern(pattern);

        let data = b"abcabcabc";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 3); // Non-overlapping matches
    }

    #[test]
    fn test_byte_pattern_search_overlapping_matches() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"aaa".to_vec()),
        );
        matcher.add_pattern(pattern);

        let data = b"aaaaa";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 3); // Overlapping matches at positions 0, 1, 2
    }

    #[test]
    fn test_byte_pattern_search_no_match() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"xyz".to_vec()),
        );
        matcher.add_pattern(pattern);

        let data = b"hello world";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0);
    }

    #[test]
    fn test_byte_pattern_search_too_short() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"ab".to_vec()),
        );
        matcher.add_pattern(pattern);

        let data = b"hello world";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0); // Pattern too short (< min_pattern_length)
    }

    #[test]
    fn test_byte_pattern_search_max_matches_limit() {
        let config = MatchConfig {
            max_matches: 2,
            ..Default::default()
        };
        let mut matcher = PatternMatcher::with_config(config);
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"test".to_vec()),
        );
        matcher.add_pattern(pattern);

        let data = b"test test test test";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 2); // Limited by max_matches
    }

    // ==============================
    // String Pattern Search Tests
    // ==============================

    #[test]
    fn test_string_pattern_search_case_sensitive() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::String,
            PatternData::String("Hello".to_string()),
        );
        matcher.add_pattern(pattern);

        let data = b"Say Hello to the world";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].offset, 4);
    }

    #[test]
    fn test_string_pattern_search_case_insensitive() {
        let config = MatchConfig {
            case_sensitive: false,
            ..Default::default()
        };
        let mut matcher = PatternMatcher::with_config(config);
        let pattern = create_test_pattern(
            "test",
            PatternType::String,
            PatternData::String("HELLO".to_string()),
        );
        matcher.add_pattern(pattern);

        let data = b"Say hello to the world";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].offset, 4);
    }

    #[test]
    fn test_string_pattern_search_invalid_utf8() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::String,
            PatternData::String("test".to_string()),
        );
        matcher.add_pattern(pattern);

        let data = &[0xFF, 0xFE, 0xFD, 0xFC]; // Invalid UTF-8
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0); // No matches for invalid UTF-8
    }

    #[test]
    fn test_string_pattern_search_too_short() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::String,
            PatternData::String("ab".to_string()),
        );
        matcher.add_pattern(pattern);

        let data = b"hello ab world";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0); // Pattern too short
    }

    // ==============================
    // Hex Wildcard Pattern Search Tests
    // ==============================

    #[test]
    fn test_hex_wildcard_pattern_search() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::HexWildcard,
            PatternData::HexWildcard("48 65 ?? 6c 6f".to_string()),
        );
        matcher.add_pattern(pattern);

        let data = b"Hello"; // 48 65 6c 6c 6f
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].offset, 0);
        assert_eq!(results.matches[0].length, 5);
    }

    #[test]
    fn test_hex_wildcard_pattern_search_invalid_pattern() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::HexWildcard,
            PatternData::HexWildcard("48 65 X".to_string()),
        );
        matcher.add_pattern(pattern);

        let data = b"Hello";
        let results = matcher.search(data);

        assert!(results.is_err()); // Invalid hex pattern should error
    }

    // ==============================
    // Magic Pattern Search Tests
    // ==============================

    #[test]
    fn test_magic_pattern_search_match() {
        let mut matcher = PatternMatcher::new();
        let pattern =
            create_test_pattern("PE", PatternType::Magic, PatternData::Bytes(b"MZ".to_vec()));
        matcher.add_pattern(pattern);

        let data = b"MZ\x90\x00\x03\x00"; // PE header start
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].offset, 0);
        assert_eq!(results.matches[0].length, 2);
    }

    #[test]
    fn test_magic_pattern_search_no_match_wrong_position() {
        let mut matcher = PatternMatcher::new();
        let pattern =
            create_test_pattern("PE", PatternType::Magic, PatternData::Bytes(b"MZ".to_vec()));
        matcher.add_pattern(pattern);

        let data = b"XXMZ"; // Magic not at beginning
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0); // Magic patterns only match at offset 0
    }

    #[test]
    fn test_magic_pattern_search_too_short() {
        let mut matcher = PatternMatcher::new();
        let pattern =
            create_test_pattern("PE", PatternType::Magic, PatternData::Bytes(b"MZ".to_vec()));
        matcher.add_pattern(pattern);

        let data = b"M"; // Too short
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0);
    }

    // ==============================
    // Regex and Structural Pattern Tests (Empty implementations)
    // ==============================

    #[test]
    fn test_regex_pattern_search_returns_empty() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Regex,
            PatternData::Regex("test.*".to_string()),
        );
        matcher.add_pattern(pattern);

        let data = b"test pattern";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0); // Regex not implemented yet
    }

    #[test]
    fn test_structural_pattern_search_returns_empty() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Structural,
            PatternData::Bytes(b"test".to_vec()),
        );
        matcher.add_pattern(pattern);

        let data = b"test pattern";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0); // Structural not implemented yet
    }

    // ==============================
    // Built-in Pattern Tests
    // ==============================

    #[test]
    fn test_builtin_patterns() {
        let patterns = get_file_format_patterns();
        assert!(!patterns.is_empty());

        // Check for PE signature
        let pe_pattern = patterns.iter().find(|p| p.name == "PE_MZ");
        assert!(pe_pattern.is_some());
    }

    #[test]
    fn test_file_format_patterns() {
        let patterns = get_file_format_patterns();
        assert!(patterns.len() >= 4);

        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"PE_MZ"));
        assert!(names.contains(&"ELF"));
        assert!(names.contains(&"Mach_O_32"));
        assert!(names.contains(&"Mach_O_64"));
    }

    #[test]
    fn test_compiler_patterns() {
        let patterns = get_compiler_patterns();
        assert!(!patterns.is_empty());

        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"GCC"));
        assert!(names.contains(&"MSVC"));
    }

    #[test]
    fn test_packer_patterns() {
        let patterns = get_packer_patterns();
        assert!(!patterns.is_empty());

        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"UPX"));
    }

    #[test]
    fn test_crypto_patterns() {
        let patterns = get_crypto_patterns();
        assert!(!patterns.is_empty());

        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"MD5_Init"));
    }

    #[test]
    fn test_malware_patterns() {
        let patterns = get_malware_patterns();
        assert!(!patterns.is_empty());

        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"Suspicious_API"));
    }

    #[test]
    fn test_api_patterns() {
        let patterns = get_api_patterns();
        assert!(!patterns.is_empty());

        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"CreateProcess"));
    }

    #[test]
    fn test_get_builtin_patterns_unknown_category() {
        let patterns = get_builtin_patterns(&PatternCategory::Debug);
        assert!(patterns.is_empty()); // Debug not implemented

        let patterns = get_builtin_patterns(&PatternCategory::Network);
        assert!(patterns.is_empty()); // Network not implemented
    }

    #[test]
    fn test_load_builtin_patterns() {
        let mut matcher = PatternMatcher::new();
        let categories = vec![
            PatternCategory::FileFormat,
            PatternCategory::Compiler,
            PatternCategory::Packer,
        ];

        matcher.load_builtin_patterns(&categories);
        assert!(matcher.patterns.len() > 0);

        // Verify patterns from all categories are loaded
        let format_count = matcher
            .patterns
            .iter()
            .filter(|p| p.category == PatternCategory::FileFormat)
            .count();
        let compiler_count = matcher
            .patterns
            .iter()
            .filter(|p| p.category == PatternCategory::Compiler)
            .count();
        let packer_count = matcher
            .patterns
            .iter()
            .filter(|p| p.category == PatternCategory::Packer)
            .count();

        assert!(format_count > 0);
        assert!(compiler_count > 0);
        assert!(packer_count > 0);
    }

    // ==============================
    // Search Results Tests
    // ==============================

    #[test]
    fn test_search_results_structure() {
        let mut matcher = PatternMatcher::new();
        let pattern1 = create_test_pattern(
            "test1",
            PatternType::Bytes,
            PatternData::Bytes(b"test".to_vec()),
        );
        let pattern2 = create_test_pattern(
            "test2",
            PatternType::String,
            PatternData::String("hello".to_string()),
        );

        matcher.add_pattern(pattern1);
        matcher.add_pattern(pattern2);

        let data = b"This is a test and hello world";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 2);
        assert_eq!(results.bytes_searched, data.len());
        assert!(results.duration_ms < 10000); // Should complete quickly in tests
        assert_eq!(results.by_category.len(), 1); // Both patterns are Custom category
        assert_eq!(results.by_category[&PatternCategory::Custom].len(), 2);
    }

    #[test]
    fn test_search_results_empty() {
        let matcher = PatternMatcher::new();
        let data = b"test data";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0);
        assert_eq!(results.bytes_searched, data.len());
        assert!(results.by_category.is_empty());
    }

    #[test]
    fn test_search_results_category_grouping() {
        let mut matcher = PatternMatcher::new();
        let pattern1 = Pattern {
            name: "pe".to_string(),
            pattern_type: PatternType::Magic,
            data: PatternData::Bytes(b"MZ".to_vec()),
            category: PatternCategory::FileFormat,
            description: "PE header".to_string(),
        };
        let pattern2 = Pattern {
            name: "gcc".to_string(),
            pattern_type: PatternType::String,
            data: PatternData::String("GCC".to_string()),
            category: PatternCategory::Compiler,
            description: "GCC compiler".to_string(),
        };

        matcher.add_pattern(pattern1);
        matcher.add_pattern(pattern2);

        let data = b"MZ This binary was compiled with GCC";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 2);
        assert_eq!(results.by_category.len(), 2);
        assert!(
            results
                .by_category
                .contains_key(&PatternCategory::FileFormat)
        );
        assert!(results.by_category.contains_key(&PatternCategory::Compiler));
    }

    // ==============================
    // Pattern Data Type Tests
    // ==============================

    #[test]
    fn test_pattern_types_equality() {
        assert_eq!(PatternType::Bytes, PatternType::Bytes);
        assert_ne!(PatternType::Bytes, PatternType::String);
    }

    #[test]
    fn test_pattern_categories_equality() {
        assert_eq!(PatternCategory::FileFormat, PatternCategory::FileFormat);
        assert_ne!(PatternCategory::FileFormat, PatternCategory::Compiler);
    }

    // ==============================
    // Edge Cases and Error Handling Tests
    // ==============================

    #[test]
    fn test_search_empty_data() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"test".to_vec()),
        );
        matcher.add_pattern(pattern);

        let data = b"";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 0);
        assert_eq!(results.bytes_searched, 0);
    }

    #[test]
    fn test_search_large_data() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"needle".to_vec()),
        );
        matcher.add_pattern(pattern);

        let mut data = vec![b'X'; 100000];
        data.extend_from_slice(b"needle");
        data.extend_from_slice(&vec![b'Y'; 100000]);

        let results = matcher.search(&data).unwrap();

        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].offset, 100000);
    }

    #[test]
    fn test_pattern_match_structure() {
        let mut matcher = PatternMatcher::new();
        let pattern = create_test_pattern(
            "test",
            PatternType::Bytes,
            PatternData::Bytes(b"test".to_vec()),
        );
        matcher.add_pattern(pattern.clone());

        let data = b"find test here";
        let results = matcher.search(data).unwrap();

        assert_eq!(results.matches.len(), 1);
        let m = &results.matches[0];
        assert_eq!(m.pattern.name, pattern.name);
        assert_eq!(m.offset, 5);
        assert_eq!(m.length, 4);
        assert_eq!(m.data, b"test");
        assert_eq!(m.confidence, 1.0);
    }

    #[test]
    fn test_multiple_pattern_types_search() {
        let mut matcher = PatternMatcher::new();

        // Add different pattern types
        matcher.add_pattern(create_test_pattern(
            "bytes",
            PatternType::Bytes,
            PatternData::Bytes(b"test".to_vec()),
        ));
        matcher.add_pattern(create_test_pattern(
            "string",
            PatternType::String,
            PatternData::String("hello".to_string()),
        ));
        matcher.add_pattern(create_test_pattern(
            "magic",
            PatternType::Magic,
            PatternData::Bytes(b"MZ".to_vec()),
        ));
        matcher.add_pattern(create_test_pattern(
            "hex",
            PatternType::HexWildcard,
            PatternData::HexWildcard("77 6F ?? 6C 64".to_string()),
        ));

        let data = b"MZ test hello world";
        let results = matcher.search(data).unwrap();

        assert!(results.matches.len() >= 3); // At least bytes, string, magic should match
    }

    // ==============================
    // Helper Functions
    // ==============================

    fn create_test_pattern(name: &str, pattern_type: PatternType, data: PatternData) -> Pattern {
        Pattern {
            name: name.to_string(),
            pattern_type,
            data,
            category: PatternCategory::Custom,
            description: format!("Test pattern: {}", name),
        }
    }
}
