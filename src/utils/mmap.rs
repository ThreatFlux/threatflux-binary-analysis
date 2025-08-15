//! Memory mapping utilities for efficient binary analysis
//!
//! This module provides safe memory mapping functionality for reading large binary files
//! efficiently without loading them entirely into memory.

use crate::{BinaryError, Result};
use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::ops::{Deref, Range};
use std::path::Path;

/// Memory-mapped binary file
#[derive(Debug)]
pub struct MappedBinary {
    _file: File,
    mmap: Mmap,
    size: usize,
}

impl MappedBinary {
    /// Create a new memory-mapped binary from a file path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)
            .map_err(|e| BinaryError::memory_map(format!("Failed to open file: {}", e)))?;

        let mmap = unsafe {
            MmapOptions::new().map(&file).map_err(|e| {
                BinaryError::memory_map(format!("Failed to create memory map: {}", e))
            })?
        };

        let size = mmap.len();

        Ok(Self {
            _file: file,
            mmap,
            size,
        })
    }

    /// Create a memory-mapped binary from an open file
    pub fn from_file(file: File) -> Result<Self> {
        let mmap = unsafe {
            MmapOptions::new().map(&file).map_err(|e| {
                BinaryError::memory_map(format!("Failed to create memory map: {}", e))
            })?
        };

        let size = mmap.len();

        Ok(Self {
            _file: file,
            mmap,
            size,
        })
    }

    /// Get the size of the mapped file
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a slice of the mapped data
    pub fn slice(&self, range: Range<usize>) -> crate::types::ByteSliceResult<'_> {
        if range.end > self.size {
            return Err(BinaryError::memory_map(
                "Range exceeds file size".to_string(),
            ));
        }

        Ok(&self.mmap[range])
    }

    /// Get data at a specific offset with a given length
    pub fn read_at(&self, offset: usize, length: usize) -> crate::types::ByteSliceResult<'_> {
        if offset + length > self.size {
            return Err(BinaryError::memory_map(
                "Read exceeds file size".to_string(),
            ));
        }

        Ok(&self.mmap[offset..offset + length])
    }

    /// Read a specific number of bytes starting from an offset
    pub fn read_bytes(&self, offset: usize, count: usize) -> Result<Vec<u8>> {
        let data = self.read_at(offset, count)?;
        Ok(data.to_vec())
    }

    /// Read a u8 value at the specified offset
    pub fn read_u8(&self, offset: usize) -> Result<u8> {
        if offset >= self.size {
            return Err(BinaryError::memory_map(
                "Offset exceeds file size".to_string(),
            ));
        }
        Ok(self.mmap[offset])
    }

    /// Read a u16 value at the specified offset (little endian)
    pub fn read_u16_le(&self, offset: usize) -> Result<u16> {
        let bytes = self.read_at(offset, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a u16 value at the specified offset (big endian)
    pub fn read_u16_be(&self, offset: usize) -> Result<u16> {
        let bytes = self.read_at(offset, 2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a u32 value at the specified offset (little endian)
    pub fn read_u32_le(&self, offset: usize) -> Result<u32> {
        let bytes = self.read_at(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a u32 value at the specified offset (big endian)
    pub fn read_u32_be(&self, offset: usize) -> Result<u32> {
        let bytes = self.read_at(offset, 4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a u64 value at the specified offset (little endian)
    pub fn read_u64_le(&self, offset: usize) -> Result<u64> {
        let bytes = self.read_at(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a u64 value at the specified offset (big endian)
    pub fn read_u64_be(&self, offset: usize) -> Result<u64> {
        let bytes = self.read_at(offset, 8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a null-terminated string at the specified offset
    pub fn read_cstring(&self, offset: usize, max_length: usize) -> Result<String> {
        let mut end = offset;
        let limit = (offset + max_length).min(self.size);

        while end < limit && self.mmap[end] != 0 {
            end += 1;
        }

        let bytes = &self.mmap[offset..end];
        String::from_utf8(bytes.to_vec())
            .map_err(|e| BinaryError::memory_map(format!("Invalid UTF-8 string: {}", e)))
    }

    /// Find the first occurrence of a pattern in the mapped data
    pub fn find_pattern(&self, pattern: &[u8]) -> Option<usize> {
        self.mmap
            .windows(pattern.len())
            .position(|window| window == pattern)
    }

    /// Find all occurrences of a pattern in the mapped data
    pub fn find_all_patterns(&self, pattern: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        let mut start = 0;

        while start + pattern.len() <= self.size {
            if let Some(pos) = self.mmap[start..]
                .windows(pattern.len())
                .position(|window| window == pattern)
            {
                positions.push(start + pos);
                start += pos + 1;
            } else {
                break;
            }
        }

        positions
    }

    /// Check if the mapped data starts with a specific magic signature
    pub fn starts_with(&self, signature: &[u8]) -> bool {
        if signature.len() > self.size {
            return false;
        }

        &self.mmap[..signature.len()] == signature
    }

    /// Get a hexdump of a specific region
    pub fn hexdump(&self, offset: usize, length: usize) -> Result<String> {
        let data = self.read_at(offset, length)?;
        Ok(format_hexdump(data, offset))
    }

    /// Create a safe view into a portion of the mapped data
    pub fn view(&self, range: Range<usize>) -> Result<MappedView<'_>> {
        if range.end > self.size {
            return Err(BinaryError::memory_map(
                "Range exceeds file size".to_string(),
            ));
        }

        Ok(MappedView {
            data: &self.mmap[range.clone()],
            offset: range.start,
        })
    }
}

impl Deref for MappedBinary {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mmap
    }
}

/// A view into a portion of a memory-mapped binary
#[derive(Debug)]
pub struct MappedView<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> MappedView<'a> {
    /// Get the offset of this view within the original file
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Get the size of this view
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Convert to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.data.to_vec()
    }
}

impl<'a> Deref for MappedView<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

/// Format data as a hexdump
fn format_hexdump(data: &[u8], base_offset: usize) -> String {
    let mut result = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = base_offset + i * 16;
        result.push_str(&format!("{:08x}: ", offset));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x} ", byte));
        }

        // Padding for incomplete lines
        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }

        // ASCII representation
        result.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }
        result.push_str("|\n");
    }

    result
}

/// Memory mapping configuration
#[derive(Debug, Clone, Default)]
pub struct MmapConfig {
    /// Whether to use huge pages if available
    pub use_huge_pages: bool,
    /// Whether to populate the mapping (fault pages immediately)
    pub populate: bool,
    /// Whether to lock the mapping in memory
    pub lock_memory: bool,
}

/// Advanced memory mapping with configuration
#[derive(Debug)]
pub struct AdvancedMmap {
    _file: File,
    mmap: Mmap,
    config: MmapConfig,
}

impl AdvancedMmap {
    /// Create an advanced memory map with configuration
    pub fn new<P: AsRef<Path>>(path: P, config: MmapConfig) -> Result<Self> {
        let file = File::open(path)
            .map_err(|e| BinaryError::memory_map(format!("Failed to open file: {}", e)))?;

        let mut options = MmapOptions::new();

        if config.populate {
            options.populate();
        }

        let mmap = unsafe {
            options.map(&file).map_err(|e| {
                BinaryError::memory_map(format!("Failed to create memory map: {}", e))
            })?
        };

        Ok(Self {
            _file: file,
            mmap,
            config,
        })
    }

    /// Get the underlying mapped data
    pub fn data(&self) -> &[u8] {
        &self.mmap
    }

    /// Get the configuration used
    pub fn config(&self) -> &MmapConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"Hello, World! This is a test file.")
            .unwrap();
        file.flush().unwrap();
        file
    }

    fn create_binary_test_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        // Create binary data with various byte values including null terminators
        let data = vec![
            0x12, 0x34, 0x56, 0x78, // u32 little endian: 0x78563412, big endian: 0x12345678
            0xAB, 0xCD, 0xEF, 0x01, // u32 continuation
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, // "Hello\0"
            0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, // "World\0"
            0xFF, 0xFE, 0xFD, 0xFC, // More binary data
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes for u64 test
            0x41, 0x42, 0x43, // "ABC"
            0x80, 0x81, 0x82, 0x83, // Non-ASCII bytes
        ];
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        file
    }

    fn create_empty_file() -> NamedTempFile {
        NamedTempFile::new().unwrap()
    }

    #[test]
    fn test_mapped_binary_creation() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path());
        assert!(mapped.is_ok());

        let mapped = mapped.unwrap();
        assert_eq!(mapped.size(), 34);
    }

    #[test]
    fn test_mapped_binary_from_file() {
        let temp_file = create_test_file();
        let file = File::open(temp_file.path()).unwrap();
        let mapped = MappedBinary::from_file(file);
        assert!(mapped.is_ok());

        let mapped = mapped.unwrap();
        assert_eq!(mapped.size(), 34);
        assert_eq!(&mapped[0..5], b"Hello");
    }

    #[test]
    fn test_mapped_binary_deref() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test Deref implementation
        assert_eq!(&mapped[0..5], b"Hello");
        assert_eq!(mapped.len(), 34);
    }

    #[test]
    fn test_slice_method() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test successful slice
        let slice = mapped.slice(0..5).unwrap();
        assert_eq!(slice, b"Hello");

        let slice = mapped.slice(7..12).unwrap();
        assert_eq!(slice, b"World");

        // Test error case - range exceeds file size
        let result = mapped.slice(0..100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Range exceeds file size"));
    }

    #[test]
    fn test_read_operations() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test read_at
        let data = mapped.read_at(0, 5).unwrap();
        assert_eq!(data, b"Hello");

        // Test read_bytes
        let bytes = mapped.read_bytes(7, 5).unwrap();
        assert_eq!(bytes, b"World".to_vec());

        // Test read_u8
        let byte = mapped.read_u8(0).unwrap();
        assert_eq!(byte, b'H');
    }

    #[test]
    fn test_read_operations_errors() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test read_at with out of bounds
        let result = mapped.read_at(0, 100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Read exceeds file size"));

        // Test read_at with offset out of bounds
        let result = mapped.read_at(50, 5);
        assert!(result.is_err());

        // Test read_bytes with out of bounds
        let result = mapped.read_bytes(0, 100);
        assert!(result.is_err());

        // Test read_u8 with offset out of bounds
        let result = mapped.read_u8(100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Offset exceeds file size"));
    }

    #[test]
    fn test_integer_read_operations() {
        let file = create_binary_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test u16 reads (bytes 0-1: 0x12, 0x34)
        let val_le = mapped.read_u16_le(0).unwrap();
        assert_eq!(val_le, 0x3412); // Little endian

        let val_be = mapped.read_u16_be(0).unwrap();
        assert_eq!(val_be, 0x1234); // Big endian

        // Test u32 reads (bytes 0-3: 0x12, 0x34, 0x56, 0x78)
        let val_le = mapped.read_u32_le(0).unwrap();
        assert_eq!(val_le, 0x78563412); // Little endian

        let val_be = mapped.read_u32_be(0).unwrap();
        assert_eq!(val_be, 0x12345678); // Big endian

        // Test u64 reads at position 24 where our 8-byte sequence 0x00..0x07 is located
        let val_le = mapped.read_u64_le(24).unwrap();
        assert_eq!(val_le, 0x0706050403020100); // Little endian

        let val_be = mapped.read_u64_be(24).unwrap();
        assert_eq!(val_be, 0x0001020304050607); // Big endian
    }

    #[test]
    fn test_integer_read_operations_errors() {
        let file = create_binary_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();
        let file_size = mapped.size();

        // Test u16 read errors
        assert!(mapped.read_u16_le(file_size).is_err());
        assert!(mapped.read_u16_be(file_size - 1).is_err());

        // Test u32 read errors
        assert!(mapped.read_u32_le(file_size).is_err());
        assert!(mapped.read_u32_be(file_size - 3).is_err());

        // Test u64 read errors
        assert!(mapped.read_u64_le(file_size).is_err());
        assert!(mapped.read_u64_be(file_size - 7).is_err());
    }

    #[test]
    fn test_read_cstring() {
        let file = create_binary_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test reading "Hello\0" starting at byte 8
        let s = mapped.read_cstring(8, 10).unwrap();
        assert_eq!(s, "Hello");

        // Test reading "World\0" starting at byte 14
        let s = mapped.read_cstring(14, 10).unwrap();
        assert_eq!(s, "World");

        // Test with max_length limit
        let s = mapped.read_cstring(8, 3).unwrap();
        assert_eq!(s, "Hel");

        // Test reading from offset that would go beyond file
        let result = mapped.read_cstring(8, 1000);
        assert!(result.is_ok()); // Should succeed but be limited by file size
    }

    #[test]
    fn test_read_cstring_errors() {
        let mut file = NamedTempFile::new().unwrap();
        // Create data with invalid UTF-8
        file.write_all(&[0xFF, 0xFE, 0x00]).unwrap();
        file.flush().unwrap();

        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test invalid UTF-8 string
        let result = mapped.read_cstring(0, 10);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid UTF-8 string"));
    }

    #[test]
    fn test_pattern_finding() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test find_pattern
        let pos = mapped.find_pattern(b"World");
        assert_eq!(pos, Some(7));

        let pos = mapped.find_pattern(b"xyz");
        assert_eq!(pos, None);

        // Test find_pattern with single byte pattern
        let pos = mapped.find_pattern(b"H");
        assert_eq!(pos, Some(0));
    }

    #[test]
    fn test_find_all_patterns() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"ababcabab").unwrap();
        file.flush().unwrap();

        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test find_all_patterns with multiple occurrences
        let positions = mapped.find_all_patterns(b"ab");
        assert_eq!(positions, vec![0, 2, 5, 7]);

        // Test with single occurrence
        let positions = mapped.find_all_patterns(b"abc");
        assert_eq!(positions, vec![2]);

        // Test with no occurrences
        let positions = mapped.find_all_patterns(b"xyz");
        assert_eq!(positions, vec![]);

        // Test with single byte pattern
        let positions = mapped.find_all_patterns(b"a");
        assert_eq!(positions, vec![0, 2, 5, 7]);
    }

    #[test]
    fn test_pattern_edge_cases() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test pattern longer than file
        let long_pattern = vec![b'A'; 1000];
        let result = mapped.find_pattern(&long_pattern);
        assert_eq!(result, None);

        // Test pattern at end of file
        let result = mapped.find_pattern(b"file.");
        assert!(result.is_some());
    }

    #[test]
    fn test_starts_with() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        assert!(mapped.starts_with(b"Hello"));
        assert!(!mapped.starts_with(b"World"));
        assert!(mapped.starts_with(b"")); // Empty pattern should match

        // Test with signature longer than file
        let mut long_signature = vec![0; 100];
        long_signature[0] = b'H';
        assert!(!mapped.starts_with(&long_signature));
    }

    #[test]
    fn test_hexdump_method() {
        let file = create_binary_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test hexdump method
        let hexdump = mapped.hexdump(0, 8).unwrap();
        assert!(hexdump.contains("00000000:"));
        assert!(hexdump.contains("12 34 56 78"));

        // Test error case
        let result = mapped.hexdump(0, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_view_creation() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        let view = mapped.view(0..5).unwrap();
        assert_eq!(view.size(), 5);
        assert_eq!(view.offset(), 0);
        assert_eq!(&*view, b"Hello");

        // Test error case
        let result = mapped.view(0..100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Range exceeds file size"));
    }

    #[test]
    fn test_mapped_view_methods() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        let view = mapped.view(7..12).unwrap();
        assert_eq!(view.offset(), 7);
        assert_eq!(view.size(), 5);

        // Test to_vec method
        let vec = view.to_vec();
        assert_eq!(vec, b"World".to_vec());

        // Test Deref implementation
        assert_eq!(&*view, b"World");
        assert_eq!(view.len(), 5);
    }

    #[test]
    fn test_hexdump_function() {
        // Test basic hexdump
        let data = b"Hello, World!";
        let hexdump = format_hexdump(data, 0);
        assert!(hexdump.contains("48 65 6c 6c 6f 2c 20 57"));
        assert!(hexdump.contains("Hello, W"));

        // Test empty data
        let hexdump = format_hexdump(&[], 0);
        assert_eq!(hexdump, "");

        // Test data with non-printable characters
        let data = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let hexdump = format_hexdump(data, 0x1000);
        assert!(hexdump.contains("00001000:"));
        assert!(hexdump.contains("00 01 02 03 04 05 06 07"));
        assert!(hexdump.contains("................"));

        // Test data longer than 16 bytes
        let data = b"This is a longer string that spans multiple lines";
        let hexdump = format_hexdump(data, 0);
        let lines: Vec<&str> = hexdump.lines().collect();
        assert!(lines.len() > 1); // Should have multiple lines

        // Test data with mixed printable and non-printable
        let data = &[b'A', b'B', 0xFF, b'C', b'D'];
        let hexdump = format_hexdump(data, 0);
        assert!(hexdump.contains("AB.CD"));
    }

    #[test]
    fn test_empty_file_handling() {
        let file = create_empty_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        assert_eq!(mapped.size(), 0);

        // Test operations on empty file
        assert!(mapped.read_u8(0).is_err());
        assert!(mapped.read_at(0, 1).is_err());
        assert_eq!(mapped.find_pattern(b"test"), None);
        assert_eq!(mapped.find_all_patterns(b"test"), vec![]);
        assert!(mapped.starts_with(b"")); // Empty pattern should match empty file
        assert!(!mapped.starts_with(b"test"));

        let result = mapped.view(0..1);
        assert!(result.is_err());
    }

    #[test]
    fn test_mmap_config_default() {
        let config = MmapConfig::default();
        assert!(!config.use_huge_pages);
        assert!(!config.populate);
        assert!(!config.lock_memory);
    }

    #[test]
    fn test_mmap_config_debug() {
        let config = MmapConfig {
            use_huge_pages: true,
            populate: false,
            lock_memory: true,
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("use_huge_pages: true"));
        assert!(debug_str.contains("populate: false"));
        assert!(debug_str.contains("lock_memory: true"));
    }

    #[test]
    fn test_mmap_config_clone() {
        let config = MmapConfig {
            use_huge_pages: true,
            populate: true,
            lock_memory: false,
        };
        let cloned = config.clone();
        assert!(cloned.use_huge_pages);
        assert!(cloned.populate);
        assert!(!cloned.lock_memory);
    }

    #[test]
    fn test_advanced_mmap() {
        let file = create_test_file();
        let config = MmapConfig::default();
        let advanced = AdvancedMmap::new(file.path(), config.clone()).unwrap();

        assert_eq!(advanced.data().len(), 34);
        assert_eq!(advanced.data()[0..5], *b"Hello");

        let returned_config = advanced.config();
        assert_eq!(returned_config.use_huge_pages, config.use_huge_pages);
        assert_eq!(returned_config.populate, config.populate);
        assert_eq!(returned_config.lock_memory, config.lock_memory);
    }

    #[test]
    fn test_advanced_mmap_with_populate() {
        let file = create_test_file();
        let config = MmapConfig {
            use_huge_pages: false,
            populate: true,
            lock_memory: false,
        };
        let advanced = AdvancedMmap::new(file.path(), config).unwrap();

        assert_eq!(advanced.data().len(), 34);
        assert!(advanced.config().populate);
    }

    #[test]
    fn test_file_not_found_error() {
        let result = MappedBinary::new("/nonexistent/file/path");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to open file"));
    }

    #[test]
    fn test_advanced_mmap_file_not_found_error() {
        let config = MmapConfig::default();
        let result = AdvancedMmap::new("/nonexistent/file/path", config);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to open file"));
    }

    #[test]
    fn test_large_data_operations() {
        let mut file = NamedTempFile::new().unwrap();
        let large_data = vec![0xAB; 10000]; // 10KB of 0xAB
        file.write_all(&large_data).unwrap();
        file.flush().unwrap();

        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test reading from various positions
        assert_eq!(mapped.read_u8(5000).unwrap(), 0xAB);
        assert_eq!(mapped.read_bytes(1000, 100).unwrap().len(), 100);

        // Test pattern finding in large data
        let positions = mapped.find_all_patterns(&[0xAB, 0xAB]);
        assert!(positions.len() > 1000); // Should find many overlapping patterns

        // Test hexdump with large offset
        let hexdump = mapped.hexdump(8000, 32).unwrap();
        assert!(hexdump.contains("00001f40:")); // 8000 in hex
    }

    #[test]
    fn test_boundary_conditions() {
        let file = create_test_file(); // 34 bytes: "Hello, World! This is a test file."
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test reading at exact file boundary
        assert!(mapped.read_u8(33).is_ok()); // Last byte
        assert!(mapped.read_u8(34).is_err()); // One past end

        // Test reading exactly to the end
        assert!(mapped.read_at(30, 4).is_ok()); // Last 4 bytes
        assert!(mapped.read_at(30, 5).is_err()); // One byte too many

        // Test slice at boundary
        assert!(mapped.slice(0..34).is_ok()); // Entire file
        assert!(mapped.slice(0..35).is_err()); // One byte too many

        // Test view at boundary
        assert!(mapped.view(0..34).is_ok()); // Entire file
        assert!(mapped.view(0..35).is_err()); // One byte too many
    }
}
