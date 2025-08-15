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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io;

    #[test]
    fn test_binary_error_parse_creation() {
        let error = BinaryError::parse("test message");
        assert!(matches!(error, BinaryError::ParseError(_)));
        assert_eq!(
            error.to_string(),
            "Failed to parse binary format: test message"
        );
    }

    #[test]
    fn test_binary_error_parse_creation_string() {
        let msg = String::from("dynamic string");
        let error = BinaryError::parse(msg);
        assert!(matches!(error, BinaryError::ParseError(_)));
        assert_eq!(
            error.to_string(),
            "Failed to parse binary format: dynamic string"
        );
    }

    #[test]
    fn test_binary_error_unsupported_format_creation() {
        let error = BinaryError::unsupported_format("CUSTOM");
        assert!(matches!(error, BinaryError::UnsupportedFormat(_)));
        assert_eq!(error.to_string(), "Unsupported binary format: CUSTOM");
    }

    #[test]
    fn test_binary_error_unsupported_arch_creation() {
        let error = BinaryError::unsupported_arch("ARM32");
        assert!(matches!(error, BinaryError::UnsupportedArchitecture(_)));
        assert_eq!(error.to_string(), "Unsupported architecture: ARM32");
    }

    #[test]
    fn test_binary_error_invalid_data_creation() {
        let error = BinaryError::invalid_data("corrupt header");
        assert!(matches!(error, BinaryError::InvalidData(_)));
        assert_eq!(error.to_string(), "Invalid binary data: corrupt header");
    }

    #[test]
    fn test_binary_error_disassembly_creation() {
        let error = BinaryError::disassembly("unable to decode instruction");
        assert!(matches!(error, BinaryError::DisassemblyError(_)));
        assert_eq!(
            error.to_string(),
            "Disassembly failed: unable to decode instruction"
        );
    }

    #[test]
    fn test_binary_error_control_flow_creation() {
        let error = BinaryError::control_flow("circular dependency detected");
        assert!(matches!(error, BinaryError::ControlFlowError(_)));
        assert_eq!(
            error.to_string(),
            "Control flow analysis failed: circular dependency detected"
        );
    }

    #[test]
    fn test_binary_error_symbol_creation() {
        let error = BinaryError::symbol("undefined reference");
        assert!(matches!(error, BinaryError::SymbolError(_)));
        assert_eq!(
            error.to_string(),
            "Symbol resolution failed: undefined reference"
        );
    }

    #[test]
    fn test_binary_error_entropy_creation() {
        let error = BinaryError::entropy("insufficient data");
        assert!(matches!(error, BinaryError::EntropyError(_)));
        assert_eq!(
            error.to_string(),
            "Entropy analysis failed: insufficient data"
        );
    }

    #[test]
    fn test_binary_error_memory_map_creation() {
        let error = BinaryError::memory_map("permission denied");
        assert!(matches!(error, BinaryError::MemoryMapError(_)));
        assert_eq!(error.to_string(), "Memory mapping error: permission denied");
    }

    #[test]
    fn test_binary_error_config_creation() {
        let error = BinaryError::config("invalid configuration value");
        assert!(matches!(error, BinaryError::ConfigError(_)));
        assert_eq!(
            error.to_string(),
            "Configuration error: invalid configuration value"
        );
    }

    #[test]
    fn test_binary_error_feature_not_available_creation() {
        let error = BinaryError::feature_not_available("disasm-capstone");
        assert!(matches!(error, BinaryError::FeatureNotAvailable(_)));
        assert_eq!(
            error.to_string(),
            "Feature not available: disasm-capstone (try enabling the corresponding feature flag)"
        );
    }

    #[test]
    fn test_binary_error_internal_creation() {
        let error = BinaryError::internal("unexpected state");
        assert!(matches!(error, BinaryError::Internal(_)));
        assert_eq!(error.to_string(), "Internal error: unexpected state");
    }

    #[test]
    fn test_binary_error_display_all_variants() {
        let test_cases = vec![
            (
                BinaryError::ParseError("parse issue".to_string()),
                "Failed to parse binary format: parse issue",
            ),
            (
                BinaryError::UnsupportedFormat("UNKNOWN".to_string()),
                "Unsupported binary format: UNKNOWN",
            ),
            (
                BinaryError::UnsupportedArchitecture("SPARC".to_string()),
                "Unsupported architecture: SPARC",
            ),
            (
                BinaryError::InvalidData("malformed".to_string()),
                "Invalid binary data: malformed",
            ),
            (
                BinaryError::DisassemblyError("decode failed".to_string()),
                "Disassembly failed: decode failed",
            ),
            (
                BinaryError::ControlFlowError("analysis failed".to_string()),
                "Control flow analysis failed: analysis failed",
            ),
            (
                BinaryError::SymbolError("not found".to_string()),
                "Symbol resolution failed: not found",
            ),
            (
                BinaryError::EntropyError("low entropy".to_string()),
                "Entropy analysis failed: low entropy",
            ),
            (
                BinaryError::MemoryMapError("map failed".to_string()),
                "Memory mapping error: map failed",
            ),
            (
                BinaryError::ConfigError("bad config".to_string()),
                "Configuration error: bad config",
            ),
            (
                BinaryError::FeatureNotAvailable("test-feature".to_string()),
                "Feature not available: test-feature (try enabling the corresponding feature flag)",
            ),
            (
                BinaryError::Internal("bug detected".to_string()),
                "Internal error: bug detected",
            ),
        ];

        for (error, expected) in test_cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn test_binary_error_debug_formatting() {
        let error = BinaryError::ParseError("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("ParseError"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let binary_err: BinaryError = io_err.into();

        assert!(matches!(binary_err, BinaryError::IoError(_)));
        assert!(binary_err.to_string().contains("I/O error"));
        assert!(binary_err.to_string().contains("file not found"));
    }

    #[test]
    fn test_from_goblin_error() {
        let goblin_err = goblin::error::Error::Malformed("invalid header".to_string());
        let binary_err: BinaryError = goblin_err.into();

        assert!(matches!(binary_err, BinaryError::ParseError(_)));
        assert!(binary_err
            .to_string()
            .contains("Failed to parse binary format"));
        assert!(binary_err.to_string().contains("invalid header"));
    }

    #[test]
    fn test_error_source_chain_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let binary_err: BinaryError = io_err.into();

        // Test that the error source chain is properly maintained
        assert!(binary_err.source().is_some());
        let source = binary_err.source().unwrap();
        assert!(source.to_string().contains("access denied"));
    }

    #[test]
    fn test_error_source_chain_root() {
        let parse_err = BinaryError::ParseError("test".to_string());
        assert!(parse_err.source().is_none());
    }

    #[test]
    fn test_result_type_alias() {
        fn test_function() -> Result<i32> {
            Ok(42)
        }

        let result = test_function();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_type_alias_error() {
        fn test_function() -> Result<i32> {
            Err(BinaryError::parse("test error"))
        }

        let result = test_function();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, BinaryError::ParseError(_)));
    }

    // Test conditional compilation features
    #[cfg(feature = "disasm-capstone")]
    #[test]
    fn test_from_capstone_error() {
        use capstone::Error as CapstoneError;

        let capstone_err = CapstoneError::InvalidHandle;
        let binary_err: BinaryError = capstone_err.into();

        assert!(matches!(binary_err, BinaryError::DisassemblyError(_)));
        assert!(binary_err.to_string().contains("Disassembly failed"));
    }

    #[cfg(feature = "wasmparser")]
    #[test]
    fn test_from_wasmparser_error() {
        use wasmparser::BinaryReader;

        // Create an invalid WASM binary to trigger a parse error
        let invalid_wasm = vec![0x00, 0x61, 0x73]; // Truncated WASM data
        let mut reader = BinaryReader::new(&invalid_wasm, 0);

        // Try to read a u32 from truncated data to trigger an error
        let wasm_result = reader.read_u32();
        assert!(wasm_result.is_err());

        let wasm_err = wasm_result.unwrap_err();
        let binary_err: BinaryError = wasm_err.into();

        assert!(matches!(binary_err, BinaryError::ParseError(_)));
        assert!(binary_err
            .to_string()
            .contains("Failed to parse binary format"));
        assert!(binary_err.to_string().contains("WASM parse error"));
    }

    // Test error propagation in realistic scenarios
    #[test]
    fn test_error_propagation_chain() {
        fn inner_function() -> std::io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated file",
            ))
        }

        fn outer_function() -> Result<()> {
            inner_function()?;
            Ok(())
        }

        let result = outer_function();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, BinaryError::IoError(_)));
        assert!(error.source().is_some());
    }

    #[test]
    fn test_error_equality_and_comparison() {
        let err1 = BinaryError::ParseError("test".to_string());
        let err2 = BinaryError::ParseError("test".to_string());
        let err3 = BinaryError::ParseError("different".to_string());
        let err4 = BinaryError::InvalidData("test".to_string());

        // Note: BinaryError doesn't implement PartialEq, so we test the string representations
        assert_eq!(err1.to_string(), err2.to_string());
        assert_ne!(err1.to_string(), err3.to_string());
        assert_ne!(err1.to_string(), err4.to_string());
    }

    #[test]
    fn test_error_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<BinaryError>();
        assert_sync::<BinaryError>();
    }

    #[test]
    fn test_comprehensive_constructor_parameters() {
        // Test that constructors accept both &str and String
        let _e1 = BinaryError::parse("str literal");
        let _e2 = BinaryError::parse(String::from("owned string"));
        let _e3 = BinaryError::parse("str reference".to_string());

        // Test empty strings
        let _e4 = BinaryError::internal("");
        assert_eq!(_e4.to_string(), "Internal error: ");

        // Test unicode strings
        let _e5 = BinaryError::config("配置错误");
        assert!(_e5.to_string().contains("配置错误"));
    }

    #[test]
    fn test_error_in_threaded_context() {
        use std::thread;

        let handle = thread::spawn(|| {
            let error = BinaryError::parse("thread error");
            error.to_string()
        });

        let result = handle.join().unwrap();
        assert_eq!(result, "Failed to parse binary format: thread error");
    }
}
