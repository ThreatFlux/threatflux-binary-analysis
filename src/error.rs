//! Error types for binary analysis operations

use thiserror::Error;

/// Result type for binary analysis operations
pub type Result<T> = std::result::Result<T, BinaryError>;

/// Errors that can occur during binary analysis
#[derive(Error, Debug)]
pub enum BinaryError {
    /// Failed to parse binary format
    #[error("Failed to parse binary format: {0}")]
    ParseError(String),

    /// Unsupported binary format
    #[error("Unsupported binary format: {0}")]
    UnsupportedFormat(String),

    /// Unsupported architecture
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    /// Invalid binary data
    #[error("Invalid binary data: {0}")]
    InvalidData(String),

    /// Disassembly error
    #[error("Disassembly failed: {0}")]
    DisassemblyError(String),

    /// Control flow analysis error
    #[error("Control flow analysis failed: {0}")]
    ControlFlowError(String),

    /// Symbol resolution error
    #[error("Symbol resolution failed: {0}")]
    SymbolError(String),

    /// Entropy analysis error
    #[error("Entropy analysis failed: {0}")]
    EntropyError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Memory mapping error
    #[error("Memory mapping error: {0}")]
    MemoryMapError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Feature not available
    #[error("Feature not available: {0} (try enabling the corresponding feature flag)")]
    FeatureNotAvailable(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<goblin::error::Error> for BinaryError {
    fn from(err: goblin::error::Error) -> Self {
        BinaryError::ParseError(err.to_string())
    }
}

#[cfg(feature = "disasm-capstone")]
impl From<capstone::Error> for BinaryError {
    fn from(err: capstone::Error) -> Self {
        BinaryError::DisassemblyError(err.to_string())
    }
}

#[cfg(feature = "wasmparser")]
impl From<wasmparser::BinaryReaderError> for BinaryError {
    fn from(err: wasmparser::BinaryReaderError) -> Self {
        BinaryError::ParseError(format!("WASM parse error: {}", err))
    }
}

impl BinaryError {
    /// Create a new parse error
    pub fn parse<S: Into<String>>(msg: S) -> Self {
        Self::ParseError(msg.into())
    }

    /// Create a new unsupported format error
    pub fn unsupported_format<S: Into<String>>(format: S) -> Self {
        Self::UnsupportedFormat(format.into())
    }

    /// Create a new unsupported architecture error
    pub fn unsupported_arch<S: Into<String>>(arch: S) -> Self {
        Self::UnsupportedArchitecture(arch.into())
    }

    /// Create a new invalid data error
    pub fn invalid_data<S: Into<String>>(msg: S) -> Self {
        Self::InvalidData(msg.into())
    }

    /// Create a new disassembly error
    pub fn disassembly<S: Into<String>>(msg: S) -> Self {
        Self::DisassemblyError(msg.into())
    }

    /// Create a new control flow error
    pub fn control_flow<S: Into<String>>(msg: S) -> Self {
        Self::ControlFlowError(msg.into())
    }

    /// Create a new symbol error
    pub fn symbol<S: Into<String>>(msg: S) -> Self {
        Self::SymbolError(msg.into())
    }

    /// Create a new entropy error
    pub fn entropy<S: Into<String>>(msg: S) -> Self {
        Self::EntropyError(msg.into())
    }

    /// Create a new memory map error
    pub fn memory_map<S: Into<String>>(msg: S) -> Self {
        Self::MemoryMapError(msg.into())
    }

    /// Create a new configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::ConfigError(msg.into())
    }

    /// Create a new feature not available error
    pub fn feature_not_available<S: Into<String>>(feature: S) -> Self {
        Self::FeatureNotAvailable(feature.into())
    }

    /// Create a new internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Self::Internal(msg.into())
    }
}
