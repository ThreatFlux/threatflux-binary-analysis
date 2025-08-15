# ThreatFlux Binary Analysis API Reference

This document provides a comprehensive reference for the ThreatFlux Binary Analysis library API.

## Table of Contents

- [Core API](#core-api)
- [Binary Analysis](#binary-analysis)
- [Format-Specific APIs](#format-specific-apis)
- [Disassembly APIs](#disassembly-apis)
- [Analysis Modules](#analysis-modules)
- [Utility APIs](#utility-apis)
- [Error Handling](#error-handling)
- [Configuration](#configuration)
- [Feature Flags](#feature-flags)

## Core API

### BinaryAnalyzer

The main entry point for binary analysis operations.

```rust
pub struct BinaryAnalyzer {
    config: AnalysisConfig,
}

impl BinaryAnalyzer {
    /// Create a new analyzer with the given configuration
    pub fn new(config: AnalysisConfig) -> Self;
    
    /// Analyze a file by path
    pub async fn analyze_file<P: AsRef<Path>>(&self, path: P) -> Result<BinaryAnalysis>;
    
    /// Analyze raw binary data
    pub async fn analyze_bytes(&self, data: &[u8]) -> Result<BinaryAnalysis>;
    
    /// Analyze using memory-mapped file
    pub async fn analyze_mmap<P: AsRef<Path>>(&self, path: P) -> Result<BinaryAnalysis>;
    
    /// Get supported formats
    pub fn supported_formats(&self) -> Vec<BinaryFormat>;
    
    /// Detect binary format without full analysis
    pub fn detect_format(&self, data: &[u8]) -> Result<BinaryFormat>;
    
    /// Quick analysis with minimal parsing
    pub async fn quick_analyze<P: AsRef<Path>>(&self, path: P) -> Result<QuickAnalysis>;
}
```

### BinaryAnalysis

The main result structure containing comprehensive analysis results.

```rust
pub struct BinaryAnalysis {
    /// Basic file information
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub endianness: Endianness,
    pub entry_point: u64,
    pub base_address: u64,
    pub file_size: u64,
    pub file_path: Option<PathBuf>,
    
    /// Parsed structures
    pub headers: Headers,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Relocation>,
    
    /// Analysis results
    pub strings: Vec<ExtractedString>,
    pub metadata: BinaryMetadata,
    pub security_features: SecurityFeatures,
    pub entropy_analysis: Option<EntropyAnalysis>,
    pub disassembly: Option<DisassemblyResults>,
    pub control_flow: Option<ControlFlowGraph>,
    
    /// Timing information
    pub analysis_duration: Duration,
    pub timestamp: SystemTime,
}

impl BinaryAnalysis {
    /// Get section by name
    pub fn get_section(&self, name: &str) -> Option<&Section>;
    
    /// Get section by virtual address
    pub fn get_section_at_va(&self, va: u64) -> Option<&Section>;
    
    /// Get symbol by name
    pub fn get_symbol(&self, name: &str) -> Option<&Symbol>;
    
    /// Get symbol by address
    pub fn get_symbol_at(&self, address: u64) -> Option<&Symbol>;
    
    /// Check if address is executable
    pub fn is_executable_address(&self, address: u64) -> bool;
    
    /// Translate virtual address to file offset
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64>;
    
    /// Translate file offset to virtual address
    pub fn file_offset_to_va(&self, offset: u64) -> Option<u64>;
    
    /// Get data at virtual address
    pub fn get_data_at_va(&self, va: u64, size: usize) -> Option<&[u8]>;
    
    /// Get imports by library
    pub fn get_imports_by_library(&self, library: &str) -> Vec<&Import>;
    
    /// Get all imported libraries
    pub fn get_imported_libraries(&self) -> Vec<String>;
    
    /// Check for specific security features
    pub fn has_security_feature(&self, feature: SecurityFeature) -> bool;
    
    /// Export to JSON
    #[cfg(feature = "serde-support")]
    pub fn to_json(&self) -> Result<String>;
    
    /// Export to pretty JSON
    #[cfg(feature = "serde-support")]
    pub fn to_json_pretty(&self) -> Result<String>;
}
```

## Format-Specific APIs

### PE (Portable Executable) Analysis

```rust
use threatflux_binary_analysis::formats::pe::*;

pub struct PeAnalyzer {
    config: PeAnalysisConfig,
}

impl PeAnalyzer {
    pub fn new() -> Self;
    pub fn with_config(config: PeAnalysisConfig) -> Self;
    
    /// Parse PE file
    pub async fn analyze<P: AsRef<Path>>(&self, path: P) -> Result<PeAnalysis>;
    
    /// Parse PE from bytes
    pub fn parse_bytes(&self, data: &[u8]) -> Result<PeAnalysis>;
    
    /// Quick header-only parsing
    pub fn parse_headers(&self, data: &[u8]) -> Result<PeHeaders>;
    
    /// Validate PE structure
    pub fn validate(&self, data: &[u8]) -> Result<ValidationResult>;
}

pub struct PeAnalysis {
    /// PE-specific headers
    pub dos_header: DosHeader,
    pub pe_header: PeHeader,
    pub optional_header: OptionalHeader,
    pub section_headers: Vec<SectionHeader>,
    
    /// PE-specific structures
    pub import_directory: Vec<ImportDescriptor>,
    pub export_directory: Option<ExportDirectory>,
    pub resource_directory: Option<ResourceDirectory>,
    pub security_directory: Option<SecurityDirectory>,
    pub relocation_directory: Vec<RelocationBlock>,
    pub debug_directory: Vec<DebugEntry>,
    pub tls_directory: Option<TlsDirectory>,
    pub load_config: Option<LoadConfig>,
    
    /// Analysis results
    pub timestamp: SystemTime,
    pub subsystem: Subsystem,
    pub dll_characteristics: DllCharacteristics,
    pub machine_type: MachineType,
    pub checksum_valid: bool,
    pub digital_signatures: Vec<DigitalSignature>,
    pub version_info: Option<VersionInfo>,
    pub manifest: Option<Manifest>,
    
    /// Security features
    pub aslr_enabled: bool,
    pub dep_enabled: bool,
    pub seh_enabled: bool,
    pub cfg_enabled: bool,
    pub authenticode_signed: bool,
}

impl PeAnalysis {
    /// Get import by name
    pub fn get_import(&self, name: &str) -> Option<&ImportedFunction>;
    
    /// Get imports from specific DLL
    pub fn get_dll_imports(&self, dll: &str) -> Vec<&ImportedFunction>;
    
    /// Get export by name
    pub fn get_export(&self, name: &str) -> Option<&ExportedFunction>;
    
    /// Get resource by type and name
    pub fn get_resource(&self, res_type: ResourceType, name: &str) -> Option<&Resource>;
    
    /// Check if packed
    pub fn is_packed(&self) -> bool;
    
    /// Detect packer
    pub fn detect_packer(&self) -> Option<PackerType>;
    
    /// Get overlay data
    pub fn get_overlay(&self) -> Option<&[u8]>;
}
```

### ELF Analysis

```rust
use threatflux_binary_analysis::formats::elf::*;

pub struct ElfAnalyzer {
    config: ElfAnalysisConfig,
}

impl ElfAnalyzer {
    pub fn new() -> Self;
    pub fn with_config(config: ElfAnalysisConfig) -> Self;
    
    /// Parse ELF file
    pub async fn analyze<P: AsRef<Path>>(&self, path: P) -> Result<ElfAnalysis>;
    
    /// Parse ELF from bytes
    pub fn parse_bytes(&self, data: &[u8]) -> Result<ElfAnalysis>;
    
    /// Parse headers only
    pub fn parse_headers(&self, data: &[u8]) -> Result<ElfHeaders>;
    
    /// Validate ELF structure
    pub fn validate(&self, data: &[u8]) -> Result<ValidationResult>;
}

pub struct ElfAnalysis {
    /// ELF headers
    pub elf_header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    
    /// Symbol tables
    pub symbol_table: Vec<Symbol>,
    pub dynamic_symbols: Vec<DynamicSymbol>,
    
    /// Dynamic information
    pub dynamic_entries: Vec<DynamicEntry>,
    pub needed_libraries: Vec<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub soname: Option<String>,
    
    /// Relocations
    pub relocations: Vec<Relocation>,
    pub plt_relocations: Vec<PltRelocation>,
    
    /// Debug information
    pub debug_info: Option<DebugInfo>,
    pub build_id: Option<Vec<u8>>,
    pub gnu_hash: Option<GnuHash>,
    
    /// Analysis results
    pub elf_type: ElfType,
    pub machine: Machine,
    pub is_stripped: bool,
    pub is_pie: bool,
    pub has_stack_canary: bool,
    pub has_nx_bit: bool,
    pub has_relro: bool,
    pub fortify_source: bool,
}

impl ElfAnalysis {
    /// Get section by name
    pub fn get_section(&self, name: &str) -> Option<&ElfSection>;
    
    /// Get segment by type
    pub fn get_segment(&self, seg_type: SegmentType) -> Option<&ProgramHeader>;
    
    /// Get symbol by name
    pub fn get_symbol(&self, name: &str) -> Option<&Symbol>;
    
    /// Get dynamic symbol by name
    pub fn get_dynamic_symbol(&self, name: &str) -> Option<&DynamicSymbol>;
    
    /// Check for specific protection
    pub fn has_protection(&self, protection: ElfProtection) -> bool;
    
    /// Get interpreter
    pub fn get_interpreter(&self) -> Option<&str>;
    
    /// Get all notes
    pub fn get_notes(&self) -> Vec<&Note>;
}
```

### Mach-O Analysis

```rust
use threatflux_binary_analysis::formats::macho::*;

pub struct MachOAnalyzer {
    config: MachOAnalysisConfig,
}

impl MachOAnalyzer {
    pub fn new() -> Self;
    pub fn with_config(config: MachOAnalysisConfig) -> Self;
    
    /// Parse Mach-O file
    pub async fn analyze<P: AsRef<Path>>(&self, path: P) -> Result<MachOAnalysis>;
    
    /// Parse Mach-O from bytes
    pub fn parse_bytes(&self, data: &[u8]) -> Result<MachOAnalysis>;
    
    /// Parse fat binary
    pub fn parse_fat_binary(&self, data: &[u8]) -> Result<FatBinary>;
    
    /// Validate Mach-O structure
    pub fn validate(&self, data: &[u8]) -> Result<ValidationResult>;
}

pub struct MachOAnalysis {
    /// Mach-O header
    pub mach_header: MachHeader,
    pub load_commands: Vec<LoadCommand>,
    
    /// Segments and sections
    pub segments: Vec<Segment>,
    pub sections: Vec<MachOSection>,
    
    /// Symbol information
    pub symbol_table: Vec<Symbol>,
    pub string_table: Vec<u8>,
    pub dynamic_symbol_table: Vec<DynamicSymbol>,
    
    /// Dynamic information
    pub dylib_dependencies: Vec<DylibDependency>,
    pub dyld_info: Option<DyldInfo>,
    pub code_signature: Option<CodeSignature>,
    pub entitlements: Option<Entitlements>,
    
    /// Analysis results
    pub cpu_type: CpuType,
    pub cpu_subtype: CpuSubtype,
    pub file_type: FileType,
    pub flags: HeaderFlags,
    pub is_fat_binary: bool,
    pub architectures: Vec<Architecture>,
    pub min_os_version: Option<Version>,
    pub sdk_version: Option<Version>,
    pub code_signed: bool,
    pub is_encrypted: bool,
}

impl MachOAnalysis {
    /// Get load command by type
    pub fn get_load_command(&self, cmd_type: LoadCommandType) -> Option<&LoadCommand>;
    
    /// Get segment by name
    pub fn get_segment(&self, name: &str) -> Option<&Segment>;
    
    /// Get section by name
    pub fn get_section(&self, segment: &str, section: &str) -> Option<&MachOSection>;
    
    /// Get symbol by name
    pub fn get_symbol(&self, name: &str) -> Option<&Symbol>;
    
    /// Check code signing
    pub fn verify_code_signature(&self) -> Result<SignatureVerification>;
    
    /// Get entitlements
    pub fn get_entitlements(&self) -> Option<&Entitlements>;
    
    /// Check if library
    pub fn is_dynamic_library(&self) -> bool;
    
    /// Get linked frameworks
    pub fn get_frameworks(&self) -> Vec<&str>;
}
```

## Disassembly APIs

### Disassembler

```rust
use threatflux_binary_analysis::disasm::*;

pub struct Disassembler {
    engine: Box<dyn DisassemblyEngine>,
    config: DisassemblyConfig,
}

impl Disassembler {
    /// Create with Capstone engine
    #[cfg(feature = "disasm-capstone")]
    pub fn new_capstone(arch: Architecture) -> Result<Self>;
    
    /// Create with iced-x86 engine
    #[cfg(feature = "disasm-iced")]
    pub fn new_iced(arch: Architecture) -> Result<Self>;
    
    /// Create with configuration
    pub fn with_config(engine: DisassemblyEngine, config: DisassemblyConfig) -> Result<Self>;
    
    /// Disassemble bytes at address
    pub fn disassemble(&self, data: &[u8], address: u64) -> Result<Vec<Instruction>>;
    
    /// Disassemble single instruction
    pub fn disassemble_one(&self, data: &[u8], address: u64) -> Result<Instruction>;
    
    /// Disassemble function
    pub async fn disassemble_function(
        &self,
        data: &[u8],
        entry_point: u64,
        max_instructions: usize,
    ) -> Result<Vec<Instruction>>;
    
    /// Disassemble with control flow following
    pub async fn disassemble_with_flow(
        &self,
        binary: &BinaryAnalysis,
        entry_point: u64,
        options: FlowOptions,
    ) -> Result<DisassemblyGraph>;
}

pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub size: usize,
    pub groups: Vec<InstructionGroup>,
    pub branch_target: Option<u64>,
    pub operand_details: Vec<Operand>,
    pub is_call: bool,
    pub is_jump: bool,
    pub is_conditional: bool,
    pub is_return: bool,
    pub reads_memory: bool,
    pub writes_memory: bool,
}

impl Instruction {
    /// Get instruction bytes as hex
    pub fn bytes_hex(&self) -> String;
    
    /// Get full instruction text
    pub fn to_string(&self) -> String;
    
    /// Check if instruction is a branch
    pub fn is_branch(&self) -> bool;
    
    /// Get memory operands
    pub fn memory_operands(&self) -> Vec<&MemoryOperand>;
    
    /// Get register operands
    pub fn register_operands(&self) -> Vec<&RegisterOperand>;
    
    /// Get immediate operands
    pub fn immediate_operands(&self) -> Vec<&ImmediateOperand>;
}
```

### Capstone Engine

```rust
#[cfg(feature = "disasm-capstone")]
pub use threatflux_binary_analysis::disasm::capstone::*;

pub struct CapstoneEngine {
    cs: Capstone,
    arch: Architecture,
}

impl CapstoneEngine {
    pub fn new(arch: Architecture) -> Result<Self>;
    
    /// Enable detailed instruction information
    pub fn enable_details(&mut self) -> Result<()>;
    
    /// Set disassembly options
    pub fn set_options(&mut self, options: CapstoneOptions) -> Result<()>;
    
    /// Set AT&T syntax (x86 only)
    pub fn set_att_syntax(&mut self) -> Result<()>;
    
    /// Set Intel syntax (x86 only)  
    pub fn set_intel_syntax(&mut self) -> Result<()>;
}

impl DisassemblyEngine for CapstoneEngine {
    fn disassemble(&self, data: &[u8], address: u64) -> Result<Vec<Instruction>>;
    fn architecture(&self) -> Architecture;
    fn name(&self) -> &'static str { "Capstone" }
}
```

### iced-x86 Engine

```rust
#[cfg(feature = "disasm-iced")]
pub use threatflux_binary_analysis::disasm::iced::*;

pub struct IcedEngine {
    decoder: Decoder,
    arch: Architecture,
}

impl IcedEngine {
    pub fn new(arch: Architecture) -> Result<Self>;
    
    /// Set decoder options
    pub fn set_options(&mut self, options: IcedOptions);
    
    /// Enable instruction info
    pub fn enable_info(&mut self);
}

impl DisassemblyEngine for IcedEngine {
    fn disassemble(&self, data: &[u8], address: u64) -> Result<Vec<Instruction>>;
    fn architecture(&self) -> Architecture;
    fn name(&self) -> &'static str { "iced-x86" }
}
```

## Analysis Modules

### Control Flow Analysis

```rust
use threatflux_binary_analysis::analysis::control_flow::*;

pub struct ControlFlowAnalyzer {
    config: ControlFlowConfig,
}

impl ControlFlowAnalyzer {
    pub fn new() -> Self;
    pub fn with_config(config: ControlFlowConfig) -> Self;
    
    /// Build control flow graph for a function
    pub async fn build_cfg(
        &self,
        binary: &BinaryAnalysis,
        function_address: u64,
    ) -> Result<ControlFlowGraph>;
    
    /// Build call graph for the entire binary
    pub async fn build_call_graph(&self, binary: &BinaryAnalysis) -> Result<CallGraph>;
    
    /// Identify basic blocks
    pub fn identify_basic_blocks(&self, instructions: &[Instruction]) -> Vec<BasicBlock>;
    
    /// Find function boundaries
    pub async fn find_functions(&self, binary: &BinaryAnalysis) -> Result<Vec<Function>>;
    
    /// Analyze function complexity
    pub fn analyze_complexity(&self, cfg: &ControlFlowGraph) -> ComplexityMetrics;
    
    /// Find loops in control flow
    pub fn find_loops(&self, cfg: &ControlFlowGraph) -> Vec<Loop>;
    
    /// Detect tail calls
    pub fn detect_tail_calls(&self, instructions: &[Instruction]) -> Vec<TailCall>;
}

pub struct ControlFlowGraph {
    pub basic_blocks: Vec<BasicBlock>,
    pub edges: Vec<Edge>,
    pub entry_block: BlockId,
    pub exit_blocks: Vec<BlockId>,
    pub function_address: u64,
}

impl ControlFlowGraph {
    /// Get basic block by ID
    pub fn get_block(&self, id: BlockId) -> Option<&BasicBlock>;
    
    /// Get predecessors of a block
    pub fn predecessors(&self, block_id: BlockId) -> Vec<BlockId>;
    
    /// Get successors of a block
    pub fn successors(&self, block_id: BlockId) -> Vec<BlockId>;
    
    /// Check if graph is reducible
    pub fn is_reducible(&self) -> bool;
    
    /// Get dominator tree
    pub fn dominator_tree(&self) -> DominatorTree;
    
    /// Export to DOT format
    #[cfg(feature = "visualization")]
    pub fn to_dot(&self) -> String;
}

pub struct BasicBlock {
    pub id: BlockId,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

impl BasicBlock {
    /// Get block size in bytes
    pub fn size(&self) -> usize;
    
    /// Get instruction count
    pub fn instruction_count(&self) -> usize;
    
    /// Check if block is a loop header
    pub fn is_loop_header(&self) -> bool;
    
    /// Get terminator instruction
    pub fn terminator(&self) -> Option<&Instruction>;
}
```

### Security Analysis

```rust
use threatflux_binary_analysis::analysis::security::*;

pub struct SecurityAnalyzer {
    config: SecurityConfig,
}

impl SecurityAnalyzer {
    pub fn new() -> Self;
    pub fn with_config(config: SecurityConfig) -> Self;
    
    /// Perform comprehensive security analysis
    pub async fn analyze(&self, binary: &BinaryAnalysis) -> Result<SecurityReport>;
    
    /// Check for specific vulnerability types
    pub fn check_vulnerabilities(&self, binary: &BinaryAnalysis) -> Vec<Vulnerability>;
    
    /// Analyze API usage for suspicious patterns
    pub fn analyze_api_usage(&self, binary: &BinaryAnalysis) -> ApiAnalysis;
    
    /// Detect anti-analysis techniques
    pub fn detect_anti_analysis(&self, binary: &BinaryAnalysis) -> Vec<AntiAnalysisTechnique>;
    
    /// Check for code injection indicators
    pub fn detect_code_injection(&self, binary: &BinaryAnalysis) -> Vec<CodeInjectionIndicator>;
    
    /// Analyze privilege escalation potential
    pub fn analyze_privilege_escalation(&self, binary: &BinaryAnalysis) -> PrivilegeReport;
    
    /// Detect persistence mechanisms
    pub fn detect_persistence(&self, binary: &BinaryAnalysis) -> Vec<PersistenceMechanism>;
    
    /// Check for data exfiltration indicators
    pub fn detect_data_exfiltration(&self, binary: &BinaryAnalysis) -> Vec<ExfiltrationIndicator>;
}

pub struct SecurityReport {
    pub security_features: Vec<SecurityFeature>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    pub api_analysis: ApiAnalysis,
    pub anti_analysis: Vec<AntiAnalysisTechnique>,
    pub risk_score: f64,
    pub risk_level: RiskLevel,
    pub recommendations: Vec<SecurityRecommendation>,
}

impl SecurityReport {
    /// Get vulnerabilities by severity
    pub fn vulnerabilities_by_severity(&self, severity: Severity) -> Vec<&Vulnerability>;
    
    /// Check if specific feature is enabled
    pub fn has_security_feature(&self, feature: SecurityFeatureType) -> bool;
    
    /// Get overall security score (0-100)
    pub fn security_score(&self) -> u8;
    
    /// Generate summary report
    pub fn summary(&self) -> SecuritySummary;
    
    /// Export to JSON
    #[cfg(feature = "serde-support")]
    pub fn to_json(&self) -> Result<String>;
}

pub struct Vulnerability {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: VulnerabilityCategory,
    pub cwe_id: Option<u32>,
    pub location: Option<u64>,
    pub evidence: Vec<Evidence>,
    pub mitigation: Option<String>,
}
```

### Entropy Analysis

```rust
use threatflux_binary_analysis::analysis::entropy::*;

pub struct EntropyAnalyzer {
    config: EntropyConfig,
}

impl EntropyAnalyzer {
    pub fn new() -> Self;
    pub fn with_config(config: EntropyConfig) -> Self;
    
    /// Calculate entropy for entire file
    pub fn calculate_file_entropy(&self, binary: &BinaryAnalysis) -> Result<f64>;
    
    /// Calculate entropy for specific data
    pub fn calculate_entropy(&self, data: &[u8]) -> f64;
    
    /// Calculate windowed entropy
    pub fn calculate_windowed_entropy(&self, data: &[u8], window_size: usize) -> Vec<f64>;
    
    /// Analyze entropy patterns
    pub fn analyze_patterns(&self, binary: &BinaryAnalysis) -> Result<EntropyAnalysis>;
    
    /// Find entropy anomalies
    pub fn find_anomalies(&self, binary: &BinaryAnalysis) -> Result<Vec<EntropyAnomaly>>;
    
    /// Detect packed sections
    pub fn detect_packed_sections(&self, binary: &BinaryAnalysis) -> Vec<PackedSection>;
    
    /// Calculate byte frequency distribution
    pub fn byte_frequency(&self, data: &[u8]) -> [f64; 256];
    
    /// Perform chi-square test
    pub fn chi_square_test(&self, data: &[u8]) -> f64;
}

pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub section_entropy: Vec<SectionEntropy>,
    pub windowed_entropy: Vec<f64>,
    pub anomalies: Vec<EntropyAnomaly>,
    pub compression_ratio: f64,
    pub randomness_score: f64,
}

impl EntropyAnalysis {
    /// Get sections with high entropy
    pub fn high_entropy_sections(&self, threshold: f64) -> Vec<&SectionEntropy>;
    
    /// Detect likely packed sections
    pub fn packed_sections(&self) -> Vec<&SectionEntropy>;
    
    /// Get entropy statistics
    pub fn statistics(&self) -> EntropyStatistics;
    
    /// Generate entropy visualization data
    #[cfg(feature = "visualization")]
    pub fn visualization_data(&self) -> EntropyVisualization;
}

pub struct EntropyAnomaly {
    pub offset: u64,
    pub length: usize,
    pub entropy: f64,
    pub expected_entropy: f64,
    pub anomaly_type: AnomalyType,
    pub confidence: f64,
    pub description: String,
}
```

### Packer Detection

```rust
use threatflux_binary_analysis::analysis::packer::*;

pub struct PackerDetector {
    signatures: Vec<PackerSignature>,
    config: PackerDetectionConfig,
}

impl PackerDetector {
    pub fn new() -> Self;
    pub fn with_signatures(signatures: Vec<PackerSignature>) -> Self;
    pub fn with_config(config: PackerDetectionConfig) -> Self;
    
    /// Detect packer using multiple methods
    pub fn detect(&self, binary: &BinaryAnalysis) -> Result<PackerDetectionResult>;
    
    /// Detect using signature matching
    pub fn detect_by_signature(&self, binary: &BinaryAnalysis) -> Option<PackerType>;
    
    /// Detect using entropy analysis
    pub fn detect_by_entropy(&self, binary: &BinaryAnalysis) -> PackerProbability;
    
    /// Detect using import table analysis
    pub fn detect_by_imports(&self, binary: &BinaryAnalysis) -> PackerProbability;
    
    /// Detect using section characteristics
    pub fn detect_by_sections(&self, binary: &BinaryAnalysis) -> PackerProbability;
    
    /// Update signature database
    pub fn update_signatures(&mut self, signatures: Vec<PackerSignature>);
    
    /// Load signatures from file
    pub fn load_signatures<P: AsRef<Path>>(&mut self, path: P) -> Result<()>;
}

pub struct PackerDetectionResult {
    pub is_packed: bool,
    pub detected_packer: Option<PackerType>,
    pub confidence: f64,
    pub evidence: Vec<PackerEvidence>,
    pub methods_used: Vec<DetectionMethod>,
}

impl PackerDetectionResult {
    /// Get confidence as percentage
    pub fn confidence_percentage(&self) -> u8;
    
    /// Check if high confidence detection
    pub fn is_high_confidence(&self) -> bool;
    
    /// Get strongest evidence
    pub fn strongest_evidence(&self) -> Option<&PackerEvidence>;
    
    /// Get detection summary
    pub fn summary(&self) -> String;
}

pub enum PackerType {
    Upx,
    Aspack,
    Fsg,
    Petite,
    Nspack,
    Mpress,
    Themida,
    Vmprotect,
    Unknown(String),
}

pub struct PackerSignature {
    pub name: String,
    pub packer_type: PackerType,
    pub patterns: Vec<BytePattern>,
    pub ep_only: bool,
    pub min_confidence: f64,
}
```

## Utility APIs

### Memory Mapping

```rust
use threatflux_binary_analysis::utils::mmap::*;

pub struct MemoryMap {
    mmap: Mmap,
    path: PathBuf,
}

impl MemoryMap {
    /// Create memory map from file
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self>;
    
    /// Create read-only memory map
    pub fn read_only<P: AsRef<Path>>(path: P) -> Result<Self>;
    
    /// Get file size
    pub fn len(&self) -> usize;
    
    /// Check if empty
    pub fn is_empty(&self) -> bool;
    
    /// Get data at offset
    pub fn get_data(&self, offset: usize, size: usize) -> Option<&[u8]>;
    
    /// Get slice from offset to end
    pub fn get_slice_from(&self, offset: usize) -> Option<&[u8]>;
    
    /// Read exact bytes at offset
    pub fn read_exact(&self, offset: usize, size: usize) -> Result<&[u8]>;
    
    /// Read u32 at offset (little endian)
    pub fn read_u32_le(&self, offset: usize) -> Result<u32>;
    
    /// Read u64 at offset (little endian)
    pub fn read_u64_le(&self, offset: usize) -> Result<u64>;
    
    /// Read null-terminated string
    pub fn read_cstring(&self, offset: usize, max_len: usize) -> Result<String>;
}

impl AsRef<[u8]> for MemoryMap {
    fn as_ref(&self) -> &[u8];
}

impl Deref for MemoryMap {
    type Target = [u8];
    fn deref(&self) -> &[u8];
}
```

### Pattern Matching

```rust
use threatflux_binary_analysis::utils::patterns::*;

pub struct PatternMatcher {
    patterns: Vec<Pattern>,
}

impl PatternMatcher {
    pub fn new() -> Self;
    pub fn with_patterns(patterns: Vec<Pattern>) -> Self;
    
    /// Add pattern to matcher
    pub fn add_pattern(&mut self, pattern: Pattern);
    
    /// Find all pattern matches
    pub fn find_all(&self, data: &[u8]) -> Vec<PatternMatch>;
    
    /// Find first pattern match
    pub fn find_first(&self, data: &[u8]) -> Option<PatternMatch>;
    
    /// Check if any pattern matches
    pub fn matches(&self, data: &[u8]) -> bool;
    
    /// Find matches with context
    pub fn find_with_context(&self, data: &[u8], context_size: usize) -> Vec<ContextualMatch>;
}

pub struct Pattern {
    pub name: String,
    pub pattern: Vec<PatternByte>,
    pub description: String,
    pub category: PatternCategory,
}

impl Pattern {
    /// Create from hex string
    pub fn from_hex(name: &str, hex: &str) -> Result<Self>;
    
    /// Create from bytes with wildcards
    pub fn from_bytes_with_wildcards(name: &str, pattern: &str) -> Result<Self>;
    
    /// Create regex pattern
    pub fn regex(name: &str, regex: &str) -> Result<Self>;
}

pub enum PatternByte {
    Exact(u8),
    Wildcard,
    Range(u8, u8),
}

pub struct PatternMatch {
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
    pub matched_bytes: Vec<u8>,
}
```

### Data Extraction

```rust
use threatflux_binary_analysis::utils::extractor::*;

pub struct DataExtractor;

impl DataExtractor {
    /// Extract strings from binary data
    pub fn extract_strings(
        data: &[u8],
        min_length: usize,
        encodings: &[StringEncoding],
    ) -> Vec<ExtractedString>;
    
    /// Extract ASCII strings
    pub fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString>;
    
    /// Extract Unicode strings
    pub fn extract_unicode_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString>;
    
    /// Extract URLs from strings
    pub fn extract_urls(strings: &[ExtractedString]) -> Vec<Url>;
    
    /// Extract file paths
    pub fn extract_file_paths(strings: &[ExtractedString]) -> Vec<FilePath>;
    
    /// Extract IP addresses
    pub fn extract_ip_addresses(strings: &[ExtractedString]) -> Vec<IpAddr>;
    
    /// Extract email addresses
    pub fn extract_email_addresses(strings: &[ExtractedString]) -> Vec<EmailAddress>;
    
    /// Extract base64 encoded data
    pub fn extract_base64(data: &[u8]) -> Vec<Base64Data>;
    
    /// Extract embedded executables
    pub fn extract_embedded_executables(data: &[u8]) -> Vec<EmbeddedExecutable>;
    
    /// Extract cryptographic constants
    pub fn extract_crypto_constants(data: &[u8]) -> Vec<CryptoConstant>;
}

pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub length: usize,
    pub encoding: StringEncoding,
    pub category: StringCategory,
    pub confidence: f64,
}

impl ExtractedString {
    /// Check if string is suspicious
    pub fn is_suspicious(&self) -> bool;
    
    /// Get entropy of string
    pub fn entropy(&self) -> f64;
    
    /// Check if string is printable
    pub fn is_printable(&self) -> bool;
    
    /// Get character distribution
    pub fn char_distribution(&self) -> CharDistribution;
}
```

## Error Handling

### Error Types

```rust
use threatflux_binary_analysis::error::*;

#[derive(Error, Debug)]
pub enum BinaryAnalysisError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Invalid binary format: {0}")]
    InvalidFormat(String),
    
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
    
    #[error("Parse error at offset {offset}: {message}")]
    ParseError { offset: u64, message: String },
    
    #[error("Analysis timeout after {seconds} seconds")]
    Timeout { seconds: u64 },
    
    #[error("File too large: {size} bytes (limit: {limit})")]
    FileTooLarge { size: u64, limit: u64 },
    
    #[error("Memory allocation failed: {message}")]
    MemoryError { message: String },
    
    #[error("Feature not available: {feature}")]
    FeatureNotAvailable { feature: String },
    
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },
    
    #[error("Disassembly error: {0}")]
    DisassemblyError(String),
    
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

pub type Result<T> = std::result::Result<T, BinaryAnalysisError>;
```

### Error Context

```rust
impl BinaryAnalysisError {
    /// Add context to error
    pub fn with_context(self, context: &str) -> Self;
    
    /// Get error category
    pub fn category(&self) -> ErrorCategory;
    
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool;
    
    /// Get error code
    pub fn error_code(&self) -> u32;
    
    /// Get user-friendly message
    pub fn user_message(&self) -> String;
}

pub enum ErrorCategory {
    Io,
    Format,
    Parse,
    Analysis,
    Configuration,
    Resource,
    Feature,
}
```

## Configuration

### AnalysisConfig

```rust
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    // Parsing options
    pub parse_headers: bool,
    pub parse_sections: bool,
    pub parse_symbols: bool,
    pub parse_imports: bool,
    pub parse_exports: bool,
    pub parse_relocations: bool,
    pub parse_debug_info: bool,
    
    // Analysis options
    pub detect_packers: bool,
    pub analyze_entropy: bool,
    pub extract_strings: bool,
    pub check_signatures: bool,
    pub analyze_control_flow: bool,
    pub detect_vulnerabilities: bool,
    
    // Performance options
    pub use_memory_mapping: bool,
    pub max_file_size: u64,
    pub timeout: Duration,
    pub parallel_processing: bool,
    pub cache_results: bool,
    
    // String extraction options
    pub string_config: StringExtractionConfig,
    
    // Disassembly options
    pub disassembly: Option<DisassemblyConfig>,
    
    // Security analysis options
    pub security: SecurityConfig,
    
    // Format-specific options
    pub pe_config: Option<PeAnalysisConfig>,
    pub elf_config: Option<ElfAnalysisConfig>,
    pub macho_config: Option<MachOAnalysisConfig>,
}

impl AnalysisConfig {
    /// Create minimal configuration for basic analysis
    pub fn minimal() -> Self;
    
    /// Create comprehensive configuration with all features
    pub fn comprehensive() -> Self;
    
    /// Create fast configuration optimized for speed
    pub fn fast() -> Self;
    
    /// Create security-focused configuration
    pub fn security_focused() -> Self;
    
    /// Enable specific feature
    pub fn enable_feature(mut self, feature: AnalysisFeature) -> Self;
    
    /// Disable specific feature
    pub fn disable_feature(mut self, feature: AnalysisFeature) -> Self;
    
    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self;
    
    /// Set max file size
    pub fn with_max_file_size(mut self, size: u64) -> Self;
    
    /// Enable memory mapping
    pub fn with_memory_mapping(mut self, enabled: bool) -> Self;
    
    /// Validate configuration
    pub fn validate(&self) -> Result<()>;
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            parse_headers: true,
            parse_sections: true,
            parse_symbols: false,
            parse_imports: true,
            parse_exports: false,
            parse_relocations: false,
            parse_debug_info: false,
            
            detect_packers: false,
            analyze_entropy: false,
            extract_strings: false,
            check_signatures: false,
            analyze_control_flow: false,
            detect_vulnerabilities: false,
            
            use_memory_mapping: true,
            max_file_size: 100 * 1024 * 1024, // 100MB
            timeout: Duration::from_secs(300), // 5 minutes
            parallel_processing: true,
            cache_results: true,
            
            string_config: StringExtractionConfig::default(),
            disassembly: None,
            security: SecurityConfig::default(),
            pe_config: None,
            elf_config: None,
            macho_config: None,
        }
    }
}
```

This comprehensive API reference covers all major components of the ThreatFlux Binary Analysis library. For more specific usage examples and implementation details, refer to the individual module documentation and example code.

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `elf` | ELF format support | ✅ |
| `pe` | PE format support | ✅ |
| `macho` | Mach-O format support | ✅ |
| `java` | JAR/class file support | ✅ |
| `wasm` | WebAssembly support | ❌ |
| `disasm-capstone` | Capstone disassembly | ✅ |
| `disasm-iced` | iced-x86 disassembly | ❌ |
| `control-flow` | Control flow analysis | ❌ |
| `entropy-analysis` | Entropy calculation | ✅ |
| `symbol-resolution` | Debug symbol support | ✅ |
| `compression` | Compressed section support | ✅ |
| `visualization` | Graph visualization | ✅ |
| `serde-support` | JSON serialization | ✅ |

Enable optional capabilities using Cargo feature flags, for example:

```bash
cargo build --features "wasm,control-flow"
```
