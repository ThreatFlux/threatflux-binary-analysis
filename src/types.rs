//! Core types and data structures for binary analysis

use std::collections::HashMap;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

// Type aliases to reduce complexity
pub type BinaryResult<T> = crate::Result<T>;
pub type ParsedBinary = Box<dyn BinaryFormatTrait>;
pub type ParseResult = BinaryResult<ParsedBinary>;
pub type ImportExportResult = BinaryResult<(Vec<Import>, Vec<Export>)>;
pub type ByteSliceResult<'a> = BinaryResult<&'a [u8]>;
pub type PatternMatchMap =
    HashMap<crate::utils::patterns::PatternCategory, Vec<crate::utils::patterns::PatternMatch>>;
pub type HexPatternResult = BinaryResult<Vec<Option<u8>>>;
pub type HexPattern = Vec<Option<u8>>;

/// Supported binary formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum BinaryFormat {
    /// Executable and Linkable Format (Linux/Unix)
    Elf,
    /// Portable Executable (Windows)
    Pe,
    /// Mach Object (macOS/iOS)
    MachO,
    /// Java Class file
    Java,
    /// WebAssembly
    Wasm,
    /// Raw binary data
    Raw,
    /// Unknown format
    #[default]
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::Elf => write!(f, "ELF"),
            BinaryFormat::Pe => write!(f, "PE"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::Java => write!(f, "Java"),
            BinaryFormat::Wasm => write!(f, "WebAssembly"),
            BinaryFormat::Raw => write!(f, "Raw"),
            BinaryFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Supported architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum Architecture {
    /// x86 32-bit
    X86,
    /// x86 64-bit
    X86_64,
    /// ARM 32-bit
    Arm,
    /// ARM 64-bit
    Arm64,
    /// MIPS
    Mips,
    /// MIPS 64-bit
    Mips64,
    /// PowerPC
    PowerPC,
    /// PowerPC 64-bit
    PowerPC64,
    /// RISC-V
    RiscV,
    /// RISC-V 64-bit
    RiscV64,
    /// WebAssembly
    Wasm,
    /// Java Virtual Machine
    Jvm,
    /// Unknown architecture
    #[default]
    Unknown,
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::X86 => write!(f, "x86"),
            Architecture::X86_64 => write!(f, "x86-64"),
            Architecture::Arm => write!(f, "ARM"),
            Architecture::Arm64 => write!(f, "ARM64"),
            Architecture::Mips => write!(f, "MIPS"),
            Architecture::Mips64 => write!(f, "MIPS64"),
            Architecture::PowerPC => write!(f, "PowerPC"),
            Architecture::PowerPC64 => write!(f, "PowerPC64"),
            Architecture::RiscV => write!(f, "RISC-V"),
            Architecture::RiscV64 => write!(f, "RISC-V64"),
            Architecture::Wasm => write!(f, "WebAssembly"),
            Architecture::Jvm => write!(f, "JVM"),
            Architecture::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Binary metadata
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct BinaryMetadata {
    /// File size in bytes
    pub size: usize,
    /// Detected format
    pub format: BinaryFormat,
    /// Target architecture
    pub architecture: Architecture,
    /// Entry point address
    pub entry_point: Option<u64>,
    /// Base address for loading
    pub base_address: Option<u64>,
    /// Compilation timestamp
    pub timestamp: Option<u64>,
    /// Compiler information
    pub compiler_info: Option<String>,
    /// Endianness
    pub endian: Endianness,
    /// Security features
    pub security_features: SecurityFeatures,
}

/// Endianness
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum Endianness {
    Little,
    Big,
}

/// Security features detected in the binary
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct SecurityFeatures {
    /// Data Execution Prevention / No-Execute bit
    pub nx_bit: bool,
    /// Address Space Layout Randomization
    pub aslr: bool,
    /// Stack canaries / stack protection
    pub stack_canary: bool,
    /// Control Flow Integrity
    pub cfi: bool,
    /// Fortify source
    pub fortify: bool,
    /// Position Independent Executable
    pub pie: bool,
    /// Relocation Read-Only
    pub relro: bool,
    /// Signed binary
    pub signed: bool,
}

/// Binary section information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Section {
    /// Section name
    pub name: String,
    /// Virtual address
    pub address: u64,
    /// Size in bytes
    pub size: u64,
    /// File offset
    pub offset: u64,
    /// Section permissions
    pub permissions: SectionPermissions,
    /// Section type
    pub section_type: SectionType,
    /// Raw data (optional, for small sections)
    pub data: Option<Vec<u8>>,
}

/// Section permissions
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct SectionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Section types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum SectionType {
    Code,
    Data,
    ReadOnlyData,
    Bss,
    Debug,
    Symbol,
    String,
    Relocation,
    Dynamic,
    Note,
    Other(String),
}

/// Symbol information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Demangled name (if applicable)
    pub demangled_name: Option<String>,
    /// Address
    pub address: u64,
    /// Size
    pub size: u64,
    /// Symbol type
    pub symbol_type: SymbolType,
    /// Binding
    pub binding: SymbolBinding,
    /// Visibility
    pub visibility: SymbolVisibility,
    /// Section index
    pub section_index: Option<usize>,
}

/// Symbol types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum SymbolType {
    Function,
    Object,
    Section,
    File,
    Common,
    Thread,
    Other(String),
}

/// Symbol binding
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Other(String),
}

/// Symbol visibility
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum SymbolVisibility {
    Default,
    Internal,
    Hidden,
    Protected,
}

/// Import information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Import {
    /// Function or symbol name
    pub name: String,
    /// Library name
    pub library: Option<String>,
    /// Address (if resolved)
    pub address: Option<u64>,
    /// Ordinal (for PE files)
    pub ordinal: Option<u16>,
}

/// Export information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Export {
    /// Function or symbol name
    pub name: String,
    /// Address
    pub address: u64,
    /// Ordinal (for PE files)
    pub ordinal: Option<u16>,
    /// Forwarded name (if applicable)
    pub forwarded_name: Option<String>,
}

/// Disassembled instruction
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Instruction {
    /// Instruction address
    pub address: u64,
    /// Raw instruction bytes
    pub bytes: Vec<u8>,
    /// Assembly mnemonic
    pub mnemonic: String,
    /// Operand string
    pub operands: String,
    /// Instruction category
    pub category: InstructionCategory,
    /// Control flow information
    pub flow: ControlFlow,
    /// Size in bytes
    pub size: usize,
}

/// Instruction categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum InstructionCategory {
    Arithmetic,
    Logic,
    Memory,
    Control,
    System,
    Crypto,
    Vector,
    Float,
    Unknown,
}

/// Control flow information
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum ControlFlow {
    /// Normal sequential flow
    Sequential,
    /// Unconditional jump
    Jump(u64),
    /// Conditional jump
    ConditionalJump(u64),
    /// Function call
    Call(u64),
    /// Function return
    Return,
    /// Interrupt/system call
    Interrupt,
    /// Unknown/indirect
    Unknown,
}

/// Basic block in control flow graph
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct BasicBlock {
    /// Block ID
    pub id: usize,
    /// Start address
    pub start_address: u64,
    /// End address
    pub end_address: u64,
    /// Instructions in this block
    pub instructions: Vec<Instruction>,
    /// Successor blocks
    pub successors: Vec<usize>,
    /// Predecessor blocks
    pub predecessors: Vec<usize>,
    /// Block type classification
    pub block_type: BlockType,
    /// Dominator block ID (if computed)
    pub dominator: Option<usize>,
    /// Dominance frontier block IDs
    pub dominance_frontier: Vec<usize>,
}

/// Control flow graph
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ControlFlowGraph {
    /// Function information
    pub function: Function,
    /// Basic blocks
    pub basic_blocks: Vec<BasicBlock>,
    /// Complexity metrics
    pub complexity: ComplexityMetrics,
    /// Detected loops (enhanced analysis)
    pub loops: Vec<Loop>,
}

/// Function information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Function {
    /// Function name
    pub name: String,
    /// Start address
    pub start_address: u64,
    /// End address
    pub end_address: u64,
    /// Size in bytes
    pub size: u64,
    /// Function type
    pub function_type: FunctionType,
    /// Calling convention
    pub calling_convention: Option<String>,
    /// Parameters (if available)
    pub parameters: Vec<Parameter>,
    /// Return type (if available)
    pub return_type: Option<String>,
}

/// Function types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum FunctionType {
    Normal,
    Constructor,
    Destructor,
    Operator,
    Main,
    Entrypoint,
    Import,
    Export,
    Thunk,
    Unknown,
}

/// Function parameter
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Parameter {
    /// Parameter name
    pub name: Option<String>,
    /// Parameter type
    pub param_type: String,
    /// Register or stack location
    pub location: ParameterLocation,
}

/// Parameter location
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum ParameterLocation {
    Register(String),
    Stack(i64),
    Unknown,
}

/// Complexity metrics for control flow
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ComplexityMetrics {
    /// Cyclomatic complexity
    pub cyclomatic_complexity: u32,
    /// Number of basic blocks
    pub basic_block_count: u32,
    /// Number of edges
    pub edge_count: u32,
    /// Depth of nesting
    pub nesting_depth: u32,
    /// Number of loops
    pub loop_count: u32,
    /// Cognitive complexity (different from cyclomatic)
    pub cognitive_complexity: u32,
    /// Halstead metrics (if calculated)
    pub halstead_metrics: Option<HalsteadMetrics>,
    /// Maintainability index (if calculated)
    pub maintainability_index: Option<f64>,
}

/// Halstead metrics for software complexity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct HalsteadMetrics {
    /// Number of distinct operators
    pub n1: u32,
    /// Number of distinct operands
    pub n2: u32,
    /// Total number of operators
    pub capital_n1: u32,
    /// Total number of operands
    pub capital_n2: u32,
    /// Program vocabulary
    pub vocabulary: u32,
    /// Program length
    pub length: u32,
    /// Calculated length
    pub calculated_length: f64,
    /// Volume
    pub volume: f64,
    /// Difficulty
    pub difficulty: f64,
    /// Effort
    pub effort: f64,
    /// Time required to program
    pub time: f64,
    /// Number of delivered bugs
    pub bugs: f64,
}

/// Loop types for enhanced control flow analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum LoopType {
    /// Single entry point (reducible)
    Natural,
    /// Multiple entry points
    Irreducible,
    /// Test at end
    DoWhile,
    /// Test at beginning
    While,
    /// Counted loop with induction variable
    For,
    /// No clear exit condition
    Infinite,
    /// Unknown loop type
    Unknown,
}

/// Loop information for control flow analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Loop {
    /// Loop header block ID
    pub header_block: usize,
    /// Loop body block IDs
    pub body_blocks: Vec<usize>,
    /// Loop exit block IDs
    pub exit_blocks: Vec<usize>,
    /// Loop type classification
    pub loop_type: LoopType,
    /// Induction variables (if detected)
    pub induction_variables: Vec<String>,
    /// Whether this is a natural loop
    pub is_natural: bool,
    /// Nesting level
    pub nesting_level: u32,
}

/// Basic block types for enhanced classification
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum BlockType {
    Entry,
    Exit,
    Normal,
    LoopHeader,
    LoopBody,
    LoopExit,
    Conditional,
    Call,
    Return,
    Exception,
}

/// Entropy analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct EntropyAnalysis {
    /// Overall entropy score (0.0 - 8.0)
    pub overall_entropy: f64,
    /// Section-wise entropy
    pub section_entropy: HashMap<String, f64>,
    /// High entropy regions
    pub high_entropy_regions: Vec<EntropyRegion>,
    /// Packing indicators
    pub packing_indicators: PackingIndicators,
}

/// High entropy region
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct EntropyRegion {
    /// Start offset
    pub start: u64,
    /// End offset
    pub end: u64,
    /// Entropy value
    pub entropy: f64,
    /// Possible explanation
    pub description: String,
}

/// Packing indicators
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct PackingIndicators {
    /// Likely packed
    pub is_packed: bool,
    /// Detected packer (if any)
    pub packer_name: Option<String>,
    /// Compression ratio estimate
    pub compression_ratio: Option<f64>,
    /// Obfuscation indicators
    pub obfuscation_level: ObfuscationLevel,
}

/// Obfuscation level
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum ObfuscationLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Extreme,
}

/// Security indicators
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct SecurityIndicators {
    /// Suspicious API calls
    pub suspicious_apis: Vec<String>,
    /// Anti-debugging techniques
    pub anti_debug: Vec<String>,
    /// Anti-VM techniques
    pub anti_vm: Vec<String>,
    /// Cryptographic indicators
    pub crypto_indicators: Vec<String>,
    /// Network indicators
    pub network_indicators: Vec<String>,
    /// File system indicators
    pub filesystem_indicators: Vec<String>,
    /// Registry indicators (Windows)
    pub registry_indicators: Vec<String>,
}

/// Call graph analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CallGraph {
    /// Call graph nodes (functions)
    pub nodes: Vec<CallGraphNode>,
    /// Call graph edges (calls)
    pub edges: Vec<CallGraphEdge>,
    /// Entry point function addresses
    pub entry_points: Vec<u64>,
    /// Unreachable function addresses
    pub unreachable_functions: Vec<u64>,
    /// Call graph statistics
    pub statistics: CallGraphStatistics,
}

/// Call graph node representing a function
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CallGraphNode {
    /// Function address
    pub function_address: u64,
    /// Function name
    pub function_name: String,
    /// Node type classification
    pub node_type: NodeType,
    /// Function complexity
    pub complexity: u32,
    /// Number of callers
    pub in_degree: u32,
    /// Number of callees
    pub out_degree: u32,
    /// Whether function is recursive
    pub is_recursive: bool,
    /// Distance from entry point
    pub call_depth: Option<u32>,
}

/// Call graph node types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum NodeType {
    /// Program entry point (main, _start, DllMain)
    EntryPoint,
    /// Standard library function
    Library,
    /// User-defined function
    Internal,
    /// Imported function
    External,
    /// Function pointer or indirect call
    Indirect,
    /// C++ virtual method
    Virtual,
    /// Unknown function type
    Unknown,
}

/// Call graph edge representing a function call
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CallGraphEdge {
    /// Calling function address
    pub caller: u64,
    /// Called function address
    pub callee: u64,
    /// Type of call
    pub call_type: CallType,
    /// All call sites for this edge
    pub call_sites: Vec<CallSite>,
}

/// Types of function calls
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum CallType {
    /// Direct call (call 0x401000)
    Direct,
    /// Indirect call (call \[eax\], call rax)
    Indirect,
    /// Tail call optimization (jmp)
    TailCall,
    /// C++ virtual method call
    Virtual,
    /// Recursive call (self-calling)
    Recursive,
    /// Call inside conditional block
    Conditional,
}

/// Individual call site information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CallSite {
    /// Address of the call instruction
    pub address: u64,
    /// Raw instruction bytes
    pub instruction_bytes: Vec<u8>,
    /// Call context
    pub context: CallContext,
}

/// Context in which a call occurs
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum CallContext {
    Normal,
    Exception,
    Loop,
    Conditional,
}

/// Call graph statistics
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CallGraphStatistics {
    /// Total number of functions
    pub total_functions: usize,
    /// Total number of calls
    pub total_calls: usize,
    /// Direct function calls
    pub direct_calls: usize,
    /// Indirect function calls
    pub indirect_calls: usize,
    /// Recursive functions
    pub recursive_functions: usize,
    /// Leaf functions (make no calls)
    pub leaf_functions: usize,
    /// Number of entry points
    pub entry_points: usize,
    /// Number of unreachable functions
    pub unreachable_functions: usize,
    /// Maximum call depth
    pub max_call_depth: u32,
    /// Average call depth
    pub average_call_depth: f64,
    /// Number of cyclic dependencies
    pub cyclic_dependencies: usize,
}

/// Configuration for call graph analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CallGraphConfig {
    /// Analyze indirect calls (function pointers)
    pub analyze_indirect_calls: bool,
    /// Detect tail call optimizations
    pub detect_tail_calls: bool,
    /// Resolve virtual calls (C++)
    pub resolve_virtual_calls: bool,
    /// Follow import thunks
    pub follow_import_thunks: bool,
    /// Maximum call depth to analyze
    pub max_call_depth: Option<u32>,
    /// Include library function calls
    pub include_library_calls: bool,
}

impl Default for CallGraphConfig {
    fn default() -> Self {
        Self {
            analyze_indirect_calls: true,
            detect_tail_calls: true,
            resolve_virtual_calls: false,
            follow_import_thunks: true,
            max_call_depth: Some(50),
            include_library_calls: false,
        }
    }
}

/// Complete analysis result
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct AnalysisResult {
    /// Binary format
    pub format: BinaryFormat,
    /// Target architecture
    pub architecture: Architecture,
    /// Entry point
    pub entry_point: Option<u64>,
    /// Binary metadata
    pub metadata: BinaryMetadata,
    /// Sections
    pub sections: Vec<Section>,
    /// Symbols
    pub symbols: Vec<Symbol>,
    /// Imports
    pub imports: Vec<Import>,
    /// Exports
    pub exports: Vec<Export>,
    /// Disassembly (optional)
    pub disassembly: Option<Vec<Instruction>>,
    /// Control flow graphs (optional)
    pub control_flow: Option<Vec<ControlFlowGraph>>,
    /// Entropy analysis (optional)
    pub entropy: Option<EntropyAnalysis>,
    /// Security indicators (optional)
    pub security: Option<SecurityIndicators>,
    /// Call graph analysis (optional)
    pub call_graph: Option<CallGraph>,
    /// Enhanced control flow analysis (optional)
    pub enhanced_control_flow: Option<EnhancedControlFlowAnalysis>,
}

/// Enhanced control flow analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct EnhancedControlFlowAnalysis {
    /// Control flow graphs with enhanced features
    pub control_flow_graphs: Vec<ControlFlowGraph>,
    /// Cognitive complexity summary
    pub cognitive_complexity_summary: CognitiveComplexityStats,
    /// Loop analysis summary
    pub loop_analysis_summary: LoopAnalysisStats,
}

/// Cognitive complexity statistics
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CognitiveComplexityStats {
    /// Total cognitive complexity across all functions
    pub total_cognitive_complexity: u32,
    /// Average cognitive complexity per function
    pub average_cognitive_complexity: f64,
    /// Maximum cognitive complexity in a single function
    pub max_cognitive_complexity: u32,
    /// Function with highest cognitive complexity
    pub most_complex_function: Option<String>,
    /// Number of functions analyzed
    pub functions_analyzed: usize,
}

/// Loop analysis statistics
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct LoopAnalysisStats {
    /// Total number of loops detected
    pub total_loops: usize,
    /// Natural loops count
    pub natural_loops: usize,
    /// Irreducible loops count
    pub irreducible_loops: usize,
    /// Nested loops count
    pub nested_loops: usize,
    /// Maximum nesting depth
    pub max_nesting_depth: u32,
    /// Loops by type
    pub loops_by_type: HashMap<LoopType, usize>,
}

impl Default for BinaryMetadata {
    fn default() -> Self {
        Self {
            size: 0,
            format: BinaryFormat::Unknown,
            architecture: Architecture::Unknown,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        }
    }
}

/// Trait for binary format parsers
pub trait BinaryFormatParser {
    /// Parse binary data
    fn parse(data: &[u8]) -> ParseResult;

    /// Check if this parser can handle the data
    fn can_parse(data: &[u8]) -> bool;
}

/// Trait implemented by all binary formats
pub trait BinaryFormatTrait: Send + Sync {
    /// Get format type
    fn format_type(&self) -> BinaryFormat;

    /// Get target architecture
    fn architecture(&self) -> Architecture;

    /// Get entry point
    fn entry_point(&self) -> Option<u64>;

    /// Get sections
    fn sections(&self) -> &[Section];

    /// Get symbols
    fn symbols(&self) -> &[Symbol];

    /// Get imports
    fn imports(&self) -> &[Import];

    /// Get exports
    fn exports(&self) -> &[Export];

    /// Get metadata
    fn metadata(&self) -> &BinaryMetadata;
}
