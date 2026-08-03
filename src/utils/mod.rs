//! Utility functions for binary analysis

/// Memory-mapped file utilities
pub mod mmap;

/// Byte pattern matching utilities
pub mod patterns;

#[cfg(feature = "compression")]
pub mod compression;

#[cfg(feature = "serde-support")]
pub mod serde_utils;
