//! Structural binary parsing and opt-in static-analysis primitives.
//!
//! [`BinaryFile`] detects and parses enabled ELF, PE, Mach-O, Java, and
//! WebAssembly formats into a shared representation. [`BinaryAnalyzer`] adds
//! feature-gated disassembly, control-flow, entropy, and symbol-demangling
//! passes when explicitly enabled through [`AnalysisConfig`]. Unrecognized,
//! non-empty input is represented as [`BinaryFormat::Raw`].
//!
//! Results are best-effort structural facts and heuristics. They are not a
//! malware verdict, an execution sandbox, or proof that an input is safe.
//!
//! # Quick start
//!
//! ```rust
//! use threatflux_binary_analysis::{BinaryAnalyzer, BinaryFormat, Result};
//!
//! fn inspect(bytes: &[u8]) -> Result<BinaryFormat> {
//!     let result = BinaryAnalyzer::new().analyze(bytes)?;
//!     Ok(result.format)
//! }
//!
//! assert_eq!(inspect(b"unrecognized bytes")?, BinaryFormat::Raw);
//! # Ok::<(), threatflux_binary_analysis::BinaryError>(())
//! ```
//!
//! # Untrusted input
//!
//! The analyzer rejects input larger than [`AnalysisConfig::max_analysis_size`],
//! which defaults to 100 MiB. Callers must still bound reads before allocating
//! the input and should isolate hostile-file analysis with operating-system CPU,
//! memory, privilege, and wall-time limits.

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
    BinaryMetadata, CallGraph, CallGraphConfig, CallGraphEdge, CallGraphNode, CallGraphStatistics,
    ComplexityMetrics, ControlFlowGraph, EnhancedControlFlowAnalysis, EntropyAnalysis, Export,
    Function, HalsteadMetrics, Import, Instruction, Loop, LoopType, NodeType, Section,
    SecurityIndicators, Symbol,
};

/// Main entry point for binary analysis
pub struct BinaryAnalyzer {
    config: AnalysisConfig,
}

/// Configuration for binary analysis
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Enable disassembly analysis. Disabled by default.
    pub enable_disassembly: bool,
    /// Preferred disassembly engine
    #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
    pub disassembly_engine: DisassemblyEngine,
    /// Enable control flow analysis. Disabled by default.
    pub enable_control_flow: bool,
    /// Enable call graph analysis. Disabled by default.
    pub enable_call_graph: bool,
    /// Enable cognitive complexity calculation. Disabled by default.
    pub enable_cognitive_complexity: bool,
    /// Enable advanced loop analysis. Disabled by default.
    pub enable_advanced_loops: bool,
    /// Enable entropy analysis. Disabled by default.
    pub enable_entropy: bool,
    /// Enable symbol demangling. Disabled by default.
    pub enable_symbols: bool,
    /// Maximum accepted input size and high-level disassembly byte budget.
    ///
    /// [`BinaryAnalyzer::analyze`] and [`BinaryAnalyzer::analyze_binary`] return
    /// [`BinaryError::InputTooLarge`] when the input exceeds this value.
    pub max_analysis_size: usize,
    /// Maximum number of instructions returned by high-level disassembly.
    ///
    /// This is independent of [`Self::max_analysis_size`] so an allowed input
    /// cannot expand into an unbounded instruction/result allocation.
    pub max_disassembly_instructions: usize,
    /// Architecture hint (None for auto-detection)
    pub architecture_hint: Option<Architecture>,
    /// Call graph configuration
    pub call_graph_config: Option<CallGraphConfig>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_disassembly: false,
            #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
            disassembly_engine: DisassemblyEngine::Auto,
            enable_control_flow: false,
            enable_call_graph: false,
            enable_cognitive_complexity: false,
            enable_advanced_loops: false,
            enable_entropy: false,
            enable_symbols: false,
            max_analysis_size: 100 * 1024 * 1024, // 100MB
            max_disassembly_instructions: 10_000,
            architecture_hint: None,
            call_graph_config: None,
        }
    }
}

impl AnalysisConfig {
    /// Validate that every requested runtime analysis was compiled into the crate.
    ///
    /// Cargo features are compile-time capabilities; setting a runtime boolean
    /// cannot enable a missing implementation. Analysis entry points call this
    /// method automatically and return [`BinaryError::FeatureNotAvailable`] for
    /// an unavailable request.
    pub fn validate(&self) -> Result<()> {
        #[cfg(not(any(feature = "disasm-capstone", feature = "disasm-iced")))]
        if self.enable_disassembly {
            return Err(BinaryError::feature_not_available(
                "disassembly (enable disasm-capstone or disasm-iced)",
            ));
        }

        #[cfg(not(feature = "control-flow"))]
        if self.enable_control_flow
            || self.enable_call_graph
            || self.enable_cognitive_complexity
            || self.enable_advanced_loops
        {
            return Err(BinaryError::feature_not_available("control-flow"));
        }

        #[cfg(not(feature = "entropy-analysis"))]
        if self.enable_entropy {
            return Err(BinaryError::feature_not_available("entropy-analysis"));
        }

        #[cfg(not(feature = "symbol-resolution"))]
        if self.enable_symbols {
            return Err(BinaryError::feature_not_available("symbol-resolution"));
        }

        Ok(())
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
        self.config.validate()?;
        self.validate_input_size(data.len())?;
        let binary_file = BinaryFile::parse(data)?;
        self.analyze_binary(&binary_file)
    }

    /// Analyze a parsed binary file
    pub fn analyze_binary(&self, binary: &BinaryFile) -> Result<AnalysisResult> {
        self.config.validate()?;
        self.validate_input_size(binary.data().len())?;

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

        #[cfg(feature = "control-flow")]
        {
            let enhanced_control_flow_requested =
                self.config.enable_cognitive_complexity || self.config.enable_advanced_loops;
            if self.config.enable_control_flow || enhanced_control_flow_requested {
                let control_flow_graphs = self.perform_control_flow_analysis(binary)?;
                match (
                    self.config.enable_control_flow,
                    enhanced_control_flow_requested,
                ) {
                    (true, true) => {
                        result.control_flow = Some(control_flow_graphs.clone());
                        result.enhanced_control_flow =
                            Some(Self::summarize_enhanced_control_flow(control_flow_graphs));
                    }
                    (true, false) => result.control_flow = Some(control_flow_graphs),
                    (false, true) => {
                        result.enhanced_control_flow =
                            Some(Self::summarize_enhanced_control_flow(control_flow_graphs));
                    }
                    (false, false) => {}
                }
            }

            if self.config.enable_call_graph {
                result.call_graph = Some(self.perform_call_graph_analysis(binary)?);
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

    fn validate_input_size(&self, actual: usize) -> Result<()> {
        if actual > self.config.max_analysis_size {
            return Err(BinaryError::input_too_large(
                actual,
                self.config.max_analysis_size,
            ));
        }

        Ok(())
    }

    #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
    fn perform_disassembly(&self, binary: &BinaryFile) -> Result<Vec<Instruction>> {
        disasm::disassemble_binary(binary, &self.config)
    }

    #[cfg(feature = "control-flow")]
    fn perform_control_flow_analysis(&self, binary: &BinaryFile) -> Result<Vec<ControlFlowGraph>> {
        let analyzer = analysis::control_flow::ControlFlowAnalyzer::with_config(
            binary.architecture(),
            self.control_flow_analysis_config(),
        );
        analyzer.analyze_binary(binary)
    }

    #[cfg(feature = "control-flow")]
    fn control_flow_analysis_config(&self) -> analysis::control_flow::AnalysisConfig {
        analysis::control_flow::AnalysisConfig {
            detect_loops: true,
            calculate_metrics: true,
            enable_cognitive_complexity: self.config.enable_cognitive_complexity,
            enable_advanced_loops: self.config.enable_advanced_loops,
            ..analysis::control_flow::AnalysisConfig::default()
        }
    }

    #[cfg(feature = "control-flow")]
    fn perform_call_graph_analysis(&self, binary: &BinaryFile) -> Result<CallGraph> {
        let config = self.config.call_graph_config.clone().unwrap_or_default();
        analysis::call_graph::analyze_binary_with_config(binary, config)
    }

    #[cfg(feature = "control-flow")]
    fn summarize_enhanced_control_flow(
        control_flow_graphs: Vec<ControlFlowGraph>,
    ) -> EnhancedControlFlowAnalysis {
        // Compute summary statistics
        let mut total_cognitive_complexity = 0_u64;
        let mut max_cognitive_complexity = 0_u32;
        let mut most_complex_function = None;
        let mut functions_analyzed = 0_usize;

        let mut total_loops = 0_usize;
        let mut natural_loops = 0_usize;
        let mut irreducible_loops = 0_usize;
        let mut nested_loops = 0_usize;
        let mut max_nesting_depth = 0_u32;
        let mut loops_by_type = std::collections::HashMap::new();

        for cfg in &control_flow_graphs {
            functions_analyzed = functions_analyzed.saturating_add(1);

            // Cognitive complexity stats
            let cognitive = cfg.complexity.cognitive_complexity;
            total_cognitive_complexity =
                total_cognitive_complexity.saturating_add(u64::from(cognitive));
            if cognitive > max_cognitive_complexity {
                max_cognitive_complexity = cognitive;
                most_complex_function = Some(cfg.function.name.clone());
            }

            // Loop stats
            total_loops = total_loops.saturating_add(cfg.loops.len());
            for loop_info in &cfg.loops {
                match loop_info.loop_type {
                    LoopType::Natural => natural_loops = natural_loops.saturating_add(1),
                    LoopType::Irreducible => {
                        irreducible_loops = irreducible_loops.saturating_add(1);
                    }
                    _ => {}
                }

                if loop_info.nesting_level > 1 {
                    nested_loops = nested_loops.saturating_add(1);
                }

                if loop_info.nesting_level > max_nesting_depth {
                    max_nesting_depth = loop_info.nesting_level;
                }

                let count = loops_by_type
                    .entry(loop_info.loop_type.clone())
                    .or_insert(0_usize);
                *count = count.saturating_add(1);
            }
        }

        let average_cognitive_complexity = if functions_analyzed > 0 {
            total_cognitive_complexity as f64 / functions_analyzed as f64
        } else {
            0.0
        };

        let cognitive_complexity_summary = types::CognitiveComplexityStats {
            total_cognitive_complexity: u32::try_from(total_cognitive_complexity)
                .unwrap_or(u32::MAX),
            average_cognitive_complexity,
            max_cognitive_complexity,
            most_complex_function,
            functions_analyzed,
        };

        let loop_analysis_summary = types::LoopAnalysisStats {
            total_loops,
            natural_loops,
            irreducible_loops,
            nested_loops,
            max_nesting_depth,
            loops_by_type,
        };

        EnhancedControlFlowAnalysis {
            control_flow_graphs,
            cognitive_complexity_summary,
            loop_analysis_summary,
        }
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
        assert!(!analyzer.config.enable_disassembly);
        assert!(!analyzer.config.enable_control_flow);
        assert!(!analyzer.config.enable_call_graph);
        assert!(!analyzer.config.enable_cognitive_complexity);
        assert!(!analyzer.config.enable_advanced_loops);
        assert!(!analyzer.config.enable_entropy);
        assert!(!analyzer.config.enable_symbols);
    }

    #[test]
    fn test_custom_config() {
        let config = AnalysisConfig {
            enable_disassembly: false,
            #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
            disassembly_engine: DisassemblyEngine::Auto,
            enable_control_flow: true,
            enable_call_graph: true,
            enable_cognitive_complexity: false,
            enable_advanced_loops: true,
            enable_entropy: false,
            enable_symbols: true,
            max_analysis_size: 1024,
            max_disassembly_instructions: 256,
            architecture_hint: Some(Architecture::X86_64),
            call_graph_config: Some(CallGraphConfig::default()),
        };

        let analyzer = BinaryAnalyzer::with_config(config);
        assert!(!analyzer.config.enable_disassembly);
        assert!(analyzer.config.enable_control_flow);
        assert!(analyzer.config.enable_call_graph);
        assert!(!analyzer.config.enable_cognitive_complexity);
        assert!(analyzer.config.enable_advanced_loops);
        assert!(!analyzer.config.enable_entropy);
        assert!(analyzer.config.enable_symbols);
        assert_eq!(analyzer.config.max_analysis_size, 1024);
        assert_eq!(analyzer.config.max_disassembly_instructions, 256);
        assert!(analyzer.config.call_graph_config.is_some());
    }

    #[test]
    #[cfg(feature = "control-flow")]
    fn high_level_control_flow_flags_map_to_low_level_semantics() {
        let base_only = BinaryAnalyzer::with_config(AnalysisConfig {
            enable_control_flow: true,
            ..AnalysisConfig::default()
        });
        let base_config = base_only.control_flow_analysis_config();
        assert!(base_config.detect_loops);
        assert!(base_config.calculate_metrics);
        assert!(!base_config.enable_cognitive_complexity);
        assert!(!base_config.enable_advanced_loops);

        let enhanced = BinaryAnalyzer::with_config(AnalysisConfig {
            enable_cognitive_complexity: true,
            enable_advanced_loops: true,
            ..AnalysisConfig::default()
        });
        let enhanced_config = enhanced.control_flow_analysis_config();
        assert!(enhanced_config.enable_cognitive_complexity);
        assert!(enhanced_config.enable_advanced_loops);
    }

    #[test]
    #[cfg(feature = "control-flow")]
    fn enhanced_summary_uses_wide_accumulator_for_averages() {
        let graph = |name: &str| ControlFlowGraph {
            function: Function {
                name: name.to_string(),
                start_address: 0,
                end_address: 0,
                size: 0,
                function_type: types::FunctionType::Normal,
                calling_convention: None,
                parameters: Vec::new(),
                return_type: None,
            },
            basic_blocks: Vec::new(),
            complexity: ComplexityMetrics {
                cognitive_complexity: u32::MAX,
                ..ComplexityMetrics::default()
            },
            loops: Vec::new(),
        };

        let summary =
            BinaryAnalyzer::summarize_enhanced_control_flow(vec![graph("first"), graph("second")]);

        assert_eq!(
            summary
                .cognitive_complexity_summary
                .total_cognitive_complexity,
            u32::MAX
        );
        assert_eq!(
            summary
                .cognitive_complexity_summary
                .average_cognitive_complexity,
            f64::from(u32::MAX)
        );
    }

    #[test]
    fn input_size_limit_is_enforced() {
        let analyzer = BinaryAnalyzer::with_config(AnalysisConfig {
            max_analysis_size: 3,
            ..AnalysisConfig::default()
        });

        let error = analyzer.analyze(&[0_u8; 4]).unwrap_err();
        assert!(matches!(
            error,
            BinaryError::InputTooLarge {
                actual: 4,
                limit: 3
            }
        ));
    }

    #[test]
    fn input_at_size_limit_is_accepted() {
        let analyzer = BinaryAnalyzer::with_config(AnalysisConfig {
            max_analysis_size: 4,
            ..AnalysisConfig::default()
        });

        let result = analyzer.analyze(&[0_u8; 4]).unwrap();
        assert_eq!(result.format, BinaryFormat::Raw);
    }

    #[test]
    fn default_configuration_is_valid() {
        AnalysisConfig::default().validate().unwrap();
    }

    #[cfg(not(any(feature = "disasm-capstone", feature = "disasm-iced")))]
    #[test]
    fn unavailable_disassembly_is_reported() {
        let config = AnalysisConfig {
            enable_disassembly: true,
            ..AnalysisConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(BinaryError::FeatureNotAvailable(_))
        ));
    }
}
