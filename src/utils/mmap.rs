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
    pub fn slice(&self, range: Range<usize>) -> Result<&[u8]> {
        if range.end > self.size {
            return Err(BinaryError::memory_map(
                "Range exceeds file size".to_string(),
            ));
        }

        Ok(&self.mmap[range])
    }

    /// Get data at a specific offset with a given length
    pub fn read_at(&self, offset: usize, length: usize) -> Result<&[u8]> {
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
    pub fn view(&self, range: Range<usize>) -> Result<MappedView> {
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

    #[test]
    fn test_mapped_binary_creation() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path());
        assert!(mapped.is_ok());

        let mapped = mapped.unwrap();
        assert_eq!(mapped.size(), 34);
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
    fn test_pattern_finding() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        // Test find_pattern
        let pos = mapped.find_pattern(b"World");
        assert_eq!(pos, Some(7));

        let pos = mapped.find_pattern(b"xyz");
        assert_eq!(pos, None);
    }

    #[test]
    fn test_starts_with() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        assert!(mapped.starts_with(b"Hello"));
        assert!(!mapped.starts_with(b"World"));
    }

    #[test]
    fn test_view_creation() {
        let file = create_test_file();
        let mapped = MappedBinary::new(file.path()).unwrap();

        let view = mapped.view(0..5).unwrap();
        assert_eq!(view.size(), 5);
        assert_eq!(view.offset(), 0);
        assert_eq!(&*view, b"Hello");
    }

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World!";
        let hexdump = format_hexdump(data, 0);
        assert!(hexdump.contains("48 65 6c 6c 6f 2c 20 57"));
        assert!(hexdump.contains("Hello, W"));
    }
}
