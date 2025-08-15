#![allow(clippy::uninlined_format_args)]
//! # ThreatFlux Binary Analysis Library
//!
//! A comprehensive binary analysis framework for security research, reverse engineering,
//! and threat detection. Supports multiple binary formats with advanced analysis capabilities.
//!
//! ## Features
//!
//! - **Multi-format Support**: ELF, PE, Mach-O, Java, WASM
//! - **Disassembly**: Multi-architecture support via Capstone and iced-x86
//! - **Control Flow Analysis**: CFG construction, complexity metrics, anomaly detection
//! - **Symbol Resolution**: Debug info parsing, demangling, cross-references
//! - **Entropy Analysis**: Statistical analysis, packing detection
//! - **Security Analysis**: Vulnerability patterns, malware indicators
//!
//! ## Quick Start
//!
//! ```rust
//! use threatflux_binary_analysis::BinaryAnalyzer;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Example with minimal data - analysis may fail for incomplete binaries
//! let data = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
//!
//! let analyzer = BinaryAnalyzer::new();
//! match analyzer.analyze(&data) {
//!     Ok(analysis) => {
//!         println!("Format: {:?}", analysis.format);
//!         println!("Architecture: {:?}", analysis.architecture);
//!     }
//!     Err(e) => {
//!         println!("Analysis failed: {}", e);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod analysis;
pub mod error;
pub mod formats;
pub mod types;

#[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
pub mod disasm;

pub mod utils;

// Re-export main types
#[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
pub use disasm::DisassemblyEngine;
pub use error::{BinaryError, Result};
pub use types::{
    AnalysisResult, Architecture, BasicBlock, BinaryFormat, BinaryFormatParser, BinaryFormatTrait,
    BinaryMetadata, ComplexityMetrics, ControlFlowGraph, EntropyAnalysis, Export, Function, Import,
    Instruction, Section, SecurityIndicators, Symbol,
};

/// Main entry point for binary analysis
pub struct BinaryAnalyzer {
    config: AnalysisConfig,
}

/// Configuration for binary analysis
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Enable disassembly analysis
    pub enable_disassembly: bool,
    /// Preferred disassembly engine
    #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
    pub disassembly_engine: DisassemblyEngine,
    /// Enable control flow analysis
    pub enable_control_flow: bool,
    /// Enable entropy analysis
    pub enable_entropy: bool,
    /// Enable symbol resolution
    pub enable_symbols: bool,
    /// Maximum bytes to analyze for large files
    pub max_analysis_size: usize,
    /// Architecture hint (None for auto-detection)
    pub architecture_hint: Option<Architecture>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_disassembly: true,
            #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
            disassembly_engine: DisassemblyEngine::Auto,
            enable_control_flow: true,
            enable_entropy: true,
            enable_symbols: true,
            max_analysis_size: 100 * 1024 * 1024, // 100MB
            architecture_hint: None,
        }
    }
}

impl BinaryAnalyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(AnalysisConfig::default())
    }

    /// Create a new analyzer with custom configuration
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self { config }
    }

    /// Get a reference to the analysis configuration
    pub fn config(&self) -> &AnalysisConfig {
        &self.config
    }

    /// Analyze a binary file from raw data
    pub fn analyze(&self, data: &[u8]) -> Result<AnalysisResult> {
        let binary_file = BinaryFile::parse(data)?;
        self.analyze_binary(&binary_file)
    }

    /// Analyze a parsed binary file
    pub fn analyze_binary(&self, binary: &BinaryFile) -> Result<AnalysisResult> {
        #[allow(unused_mut)] // mut needed when optional analysis features are enabled
        let mut result = AnalysisResult {
            format: binary.format(),
            architecture: binary.architecture(),
            entry_point: binary.entry_point(),
            sections: binary.sections().to_vec(),
            symbols: binary.symbols().to_vec(),
            imports: binary.imports().to_vec(),
            exports: binary.exports().to_vec(),
            metadata: binary.metadata().clone(),
            ..Default::default()
        };

        // Perform optional analyses based on configuration
        if self.config.enable_disassembly {
            #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
            {
                result.disassembly = Some(self.perform_disassembly(binary)?);
            }
        }

        if self.config.enable_control_flow {
            #[cfg(feature = "control-flow")]
            {
                result.control_flow = Some(self.perform_control_flow_analysis(binary)?);
            }
        }

        if self.config.enable_entropy {
            #[cfg(feature = "entropy-analysis")]
            {
                result.entropy = Some(self.perform_entropy_analysis(binary)?);
            }
        }

        #[cfg(feature = "symbol-resolution")]
        {
            if self.config.enable_symbols {
                analysis::symbols::demangle_symbols(&mut result.symbols);
            }
        }

        Ok(result)
    }

    #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
    fn perform_disassembly(&self, binary: &BinaryFile) -> Result<Vec<Instruction>> {
        disasm::disassemble_binary(binary, &self.config)
    }

    #[cfg(feature = "control-flow")]
    fn perform_control_flow_analysis(&self, binary: &BinaryFile) -> Result<Vec<ControlFlowGraph>> {
        analysis::control_flow::analyze_binary(binary)
    }

    #[cfg(feature = "entropy-analysis")]
    fn perform_entropy_analysis(&self, binary: &BinaryFile) -> Result<EntropyAnalysis> {
        analysis::entropy::analyze_binary(binary)
    }
}

impl Default for BinaryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed binary file representation
pub struct BinaryFile {
    data: Vec<u8>,
    parsed: Box<dyn BinaryFormatTrait>,
}

impl BinaryFile {
    /// Parse binary data and detect format
    pub fn parse(data: &[u8]) -> Result<Self> {
        let format = formats::detect_format(data)?;
        let parsed = formats::parse_binary(data, format)?;

        Ok(Self {
            data: data.to_vec(),
            parsed,
        })
    }

    /// Get the binary format type
    pub fn format(&self) -> BinaryFormat {
        self.parsed.format_type()
    }

    /// Get the target architecture
    pub fn architecture(&self) -> Architecture {
        self.parsed.architecture()
    }

    /// Get the entry point address
    pub fn entry_point(&self) -> Option<u64> {
        self.parsed.entry_point()
    }

    /// Get binary sections
    pub fn sections(&self) -> &[Section] {
        self.parsed.sections()
    }

    /// Get symbol table
    pub fn symbols(&self) -> &[Symbol] {
        self.parsed.symbols()
    }

    /// Get imports
    pub fn imports(&self) -> &[Import] {
        self.parsed.imports()
    }

    /// Get exports
    pub fn exports(&self) -> &[Export] {
        self.parsed.exports()
    }

    /// Get binary metadata
    pub fn metadata(&self) -> &BinaryMetadata {
        self.parsed.metadata()
    }

    /// Get raw binary data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = BinaryAnalyzer::new();
        assert!(analyzer.config.enable_disassembly);
        assert!(analyzer.config.enable_control_flow);
        assert!(analyzer.config.enable_entropy);
        assert!(analyzer.config.enable_symbols);
    }

    #[test]
    fn test_custom_config() {
        let config = AnalysisConfig {
            enable_disassembly: false,
            enable_control_flow: true,
            enable_entropy: false,
            enable_symbols: true,
            max_analysis_size: 1024,
            architecture_hint: Some(Architecture::X86_64),
        };

        let analyzer = BinaryAnalyzer::with_config(config);
        assert!(!analyzer.config.enable_disassembly);
        assert!(analyzer.config.enable_control_flow);
        assert!(!analyzer.config.enable_entropy);
        assert!(analyzer.config.enable_symbols);
        assert_eq!(analyzer.config.max_analysis_size, 1024);
    }
}
