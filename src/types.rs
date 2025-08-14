//! Core types and data structures for binary analysis

use std::collections::HashMap;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

/// Supported binary formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum ObfuscationLevel {
    None,
    Low,
    Medium,
    High,
    Extreme,
}

impl Default for ObfuscationLevel {
    fn default() -> Self {
        ObfuscationLevel::None
    }
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
}

impl Default for BinaryFormat {
    fn default() -> Self {
        BinaryFormat::Unknown
    }
}

impl Default for Architecture {
    fn default() -> Self {
        Architecture::Unknown
    }
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
    fn parse(data: &[u8]) -> crate::Result<Box<dyn BinaryFormatTrait>>;

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
