# ThreatFlux Binary Analysis

A comprehensive Rust library for binary analysis with multi-format support, disassembly capabilities, and advanced security analysis features. Designed for security researchers, malware analysts, and reverse engineers.

[![Crates.io](https://img.shields.io/crates/v/threatflux-binary-analysis.svg)](https://crates.io/crates/threatflux-binary-analysis)
[![Documentation](https://docs.rs/threatflux-binary-analysis/badge.svg)](https://docs.rs/threatflux-binary-analysis)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

## 🚀 Features

### Binary Format Support
- **PE (Portable Executable)**: Windows executables, DLLs, drivers
- **ELF (Executable and Linkable Format)**: Linux/Unix executables, shared libraries
- **Mach-O**: macOS executables, dynamic libraries, kernel extensions
- **WASM**: WebAssembly modules (enable with `wasm` feature)
- **Java**: JAR files and class files
- **Raw Binary**: Generic binary file analysis

### Analysis Capabilities
- **🔍 Header Analysis**: Parse and validate file headers
- **📊 Section Analysis**: Enumerate and analyze sections/segments
- **🔗 Symbol Resolution**: Extract and resolve function symbols
- **📈 Control Flow Analysis**: Build control flow graphs with complexity metrics
- **🎯 Disassembly**: Multiple disassembly engines (Capstone, iced-x86)
- **🔒 Security Analysis**: Detect security features and vulnerabilities
- **📐 Entropy Analysis**: Calculate entropy for packed/encrypted sections
- **🏗️ Metadata Extraction**: Compiler detection, build information
- **🔍 String Extraction**: ASCII and Unicode string discovery
- **📱 Mobile Analysis**: Android APK and iOS app analysis
- **🗜️ Compression Support**: Decompress common compressed sections
- **🗺️ Visualization**: Export control flow graphs to DOT format
- **📝 JSON Serialization**: Serialize analysis results to JSON

### Performance Features
- **⚡ Memory-Mapped Files**: Efficient large file handling
- **🔄 Async Support**: Non-blocking analysis operations
- **🧵 Parallel Processing**: Multi-threaded analysis
- **💾 Caching**: Smart caching of analysis results
- **📏 Streaming**: Process large files without loading entirely

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
threatflux-binary-analysis = "0.1.0"
```

### Feature Flags

```toml
[dependencies]
threatflux-binary-analysis = { 
    version = "0.1.0", 
    features = [
        "pe",              # Windows PE format support
        "elf",             # Linux ELF format support  
        "macho",           # macOS Mach-O format support
        "wasm",            # WebAssembly module support
        "disasm-capstone", # Capstone disassembly engine
        "disasm-iced",     # iced-x86 disassembly engine
        "control-flow",    # Control flow analysis
        "entropy-analysis",# Statistical analysis
        "symbol-resolution",# Debug symbol support
        "compression",     # Compressed section support
        "visualization",   # Graph visualization
        "serde-support",   # JSON serialization support
    ]
}
```

#### Available Features

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

*The `disasm-iced` feature enables the [iced-x86](https://github.com/icedland/iced) disassembly engine. Activate it with `--features "disasm-iced"` to use iced-x86 instead of Capstone.*

*Enable WebAssembly module parsing with `--features "wasm"`.*

*Generate control flow graphs with `--features "control-flow"`.*

## 🚀 Quick Start

### Basic Analysis

```rust
use threatflux_binary_analysis::{BinaryAnalyzer, AnalysisConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create analyzer with default configuration
    let analyzer = BinaryAnalyzer::new(AnalysisConfig::default());
    
    // Analyze a binary file
    let analysis = analyzer.analyze_file("./example.exe").await?;
    
    println!("Format: {:?}", analysis.format);
    println!("Architecture: {}", analysis.architecture);
    println!("Entry Point: 0x{:x}", analysis.entry_point);
    println!("Sections: {}", analysis.sections.len());
    
    Ok(())
}
```

### Advanced Configuration

```rust
use threatflux_binary_analysis::{
    BinaryAnalyzer, AnalysisConfig, DisassemblyConfig, SecurityConfig
};

let config = AnalysisConfig {
    // Enable comprehensive analysis
    parse_headers: true,
    parse_sections: true,
    parse_symbols: true,
    parse_imports: true,
    parse_exports: true,
    
    // Security analysis
    detect_packers: true,
    analyze_entropy: true,
    check_signatures: true,
    
    // Performance settings
    use_memory_mapping: true,
    max_file_size: 100 * 1024 * 1024, // 100MB
    timeout: Duration::from_secs(300),
    
    // Disassembly configuration
    disassembly: Some(DisassemblyConfig {
        engine: DisassemblyEngine::Capstone,
        max_instructions: 10000,
        follow_calls: true,
        analyze_control_flow: true,
    }),
    
    // Security configuration
    security: SecurityConfig {
        check_suspicious_sections: true,
        analyze_api_calls: true,
        detect_obfuscation: true,
        check_certificates: true,
    },
};

let analyzer = BinaryAnalyzer::new(config);
```

### Format-Specific Analysis

```rust
use threatflux_binary_analysis::formats::{PeAnalyzer, ElfAnalyzer, MachOAnalyzer};

// PE-specific analysis
let pe_analyzer = PeAnalyzer::new();
let pe_info = pe_analyzer.analyze("./windows.exe").await?;
println!("PE Timestamp: {:?}", pe_info.timestamp);
println!("Subsystem: {:?}", pe_info.subsystem);

// ELF-specific analysis  
let elf_analyzer = ElfAnalyzer::new();
let elf_info = elf_analyzer.analyze("./linux_binary").await?;
println!("ELF Type: {:?}", elf_info.elf_type);
println!("Machine: {:?}", elf_info.machine);

// Mach-O specific analysis
let macho_analyzer = MachOAnalyzer::new();
let macho_info = macho_analyzer.analyze("./macos_binary").await?;
println!("CPU Type: {:?}", macho_info.cpu_type);
println!("File Type: {:?}", macho_info.file_type);
```

### Disassembly

```rust
use threatflux_binary_analysis::disasm::{DisassemblyEngine, Disassembler};

// Create disassembler
let disassembler = Disassembler::new(DisassemblyEngine::Capstone)?;

// Disassemble a function
let instructions = disassembler.disassemble_function(
    &binary_data,
    entry_point,
    architecture,
    100 // max instructions
).await?;

for instruction in instructions {
    println!("0x{:x}: {} {}", 
        instruction.address, 
        instruction.mnemonic, 
        instruction.operands
    );
}
```

### Control Flow Analysis

```rust
use threatflux_binary_analysis::analysis::control_flow;
use threatflux_binary_analysis::BinaryFile;

// Parse binary and build control flow graphs
let binary = BinaryFile::parse(&data)?;
let cfgs = control_flow::analyze_binary(&binary)?;

for cfg in cfgs {
    println!(
        "Function {} has {} basic blocks",
        cfg.function.name,
        cfg.basic_blocks.len()
    );
    println!("Cyclomatic complexity: {}", cfg.complexity.cyclomatic_complexity);
}
```

### Security Analysis

```rust
use threatflux_binary_analysis::analysis::SecurityAnalyzer;

let security_analyzer = SecurityAnalyzer::new();
let security_report = security_analyzer.analyze(&analysis).await?;

println!("Security Features:");
for feature in &security_report.security_features {
    println!("  - {}: {}", feature.name, feature.enabled);
}

println!("Vulnerabilities:");
for vuln in &security_report.vulnerabilities {
    println!("  - {}: {} ({})", vuln.name, vuln.description, vuln.severity);
}

println!("Suspicious Indicators:");
for indicator in &security_report.suspicious_indicators {
    println!("  - {}: {}", indicator.indicator_type, indicator.description);
}
```

### Entropy Analysis

```rust
use threatflux_binary_analysis::analysis::EntropyAnalyzer;

let entropy_analyzer = EntropyAnalyzer::new();

// Analyze entropy for each section
for section in &analysis.sections {
    let entropy = entropy_analyzer.calculate_entropy(&section.data)?;
    println!("Section '{}': entropy = {:.2}", section.name, entropy);
    
    if entropy > 7.0 {
        println!("  ^ High entropy - possibly packed/encrypted");
    }
}

// Find entropy anomalies
let anomalies = entropy_analyzer.find_anomalies(&analysis)?;
for anomaly in anomalies {
    println!("Entropy anomaly at 0x{:x}: {}", anomaly.offset, anomaly.description);
}
```

## 📊 Data Structures

### BinaryAnalysis

```rust
pub struct BinaryAnalysis {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub endianness: Endianness,
    pub entry_point: u64,
    pub base_address: u64,
    pub file_size: u64,
    pub headers: Headers,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub strings: Vec<ExtractedString>,
    pub metadata: BinaryMetadata,
    pub security_features: SecurityFeatures,
}
```

### Section Information

```rust
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub permissions: SectionPermissions,
    pub section_type: SectionType,
    pub entropy: Option<f64>,
    pub data: Vec<u8>,
    pub relocations: Vec<Relocation>,
}
```

### Symbol Information

```rust
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: Option<u64>,
    pub symbol_type: SymbolType,
    pub binding: SymbolBinding,
    pub visibility: SymbolVisibility,
    pub section_index: Option<usize>,
    pub demangled_name: Option<String>,
}
```

### Disassembly Result

```rust
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub size: usize,
    pub groups: Vec<InstructionGroup>,
    pub branch_target: Option<u64>,
    pub is_call: bool,
    pub is_jump: bool,
    pub is_return: bool,
}
```

## 🎯 Examples

### Example 1: PE Malware Analysis

```rust
use threatflux_binary_analysis::{BinaryAnalyzer, AnalysisConfig, formats::pe::PeFeatures};

async fn analyze_malware_sample(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = AnalysisConfig {
        parse_headers: true,
        parse_sections: true,
        parse_imports: true,
        detect_packers: true,
        analyze_entropy: true,
        ..Default::default()
    };
    
    let analyzer = BinaryAnalyzer::new(config);
    let analysis = analyzer.analyze_file(path).await?;
    
    // Check for suspicious imports
    let suspicious_apis = vec![
        "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
        "WriteProcessMemory", "SetWindowsHookEx", "GetProcAddress"
    ];
    
    for import in &analysis.imports {
        if suspicious_apis.contains(&import.name.as_str()) {
            println!("⚠️  Suspicious API: {}", import.name);
        }
    }
    
    // Check for packed sections
    for section in &analysis.sections {
        if let Some(entropy) = section.entropy {
            if entropy > 7.5 {
                println!("📦 Possibly packed section: {} (entropy: {:.2})", 
                    section.name, entropy);
            }
        }
    }
    
    // Check for unusual section names
    let normal_sections = vec![".text", ".data", ".rdata", ".rsrc", ".reloc"];
    for section in &analysis.sections {
        if !normal_sections.contains(&section.name.as_str()) {
            println!("🔍 Unusual section: {}", section.name);
        }
    }
    
    Ok(())
}
```

### Example 2: Binary Diffing

```rust
use threatflux_binary_analysis::{BinaryAnalyzer, AnalysisConfig};
use std::collections::HashMap;

async fn compare_binaries(path1: &str, path2: &str) -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = BinaryAnalyzer::new(AnalysisConfig::default());
    
    let analysis1 = analyzer.analyze_file(path1).await?;
    let analysis2 = analyzer.analyze_file(path2).await?;
    
    println!("=== Binary Comparison ===");
    
    // Compare basic properties
    println!("Format: {} vs {}", analysis1.format, analysis2.format);
    println!("Architecture: {} vs {}", analysis1.architecture, analysis2.architecture);
    println!("Entry Point: 0x{:x} vs 0x{:x}", analysis1.entry_point, analysis2.entry_point);
    
    // Compare sections
    let sections1: HashMap<_, _> = analysis1.sections.iter()
        .map(|s| (s.name.clone(), s)).collect();
    let sections2: HashMap<_, _> = analysis2.sections.iter()
        .map(|s| (s.name.clone(), s)).collect();
    
    for (name, section1) in &sections1 {
        if let Some(section2) = sections2.get(name) {
            if section1.file_size != section2.file_size {
                println!("📏 Section '{}' size changed: {} -> {} bytes", 
                    name, section1.file_size, section2.file_size);
            }
        } else {
            println!("➖ Section '{}' removed", name);
        }
    }
    
    for name in sections2.keys() {
        if !sections1.contains_key(name) {
            println!("➕ Section '{}' added", name);
        }
    }
    
    // Compare imports
    let imports1: Vec<_> = analysis1.imports.iter().map(|i| &i.name).collect();
    let imports2: Vec<_> = analysis2.imports.iter().map(|i| &i.name).collect();
    
    for import in &imports2 {
        if !imports1.contains(import) {
            println!("📥 New import: {}", import);
        }
    }
    
    for import in &imports1 {
        if !imports2.contains(import) {
            println!("📤 Removed import: {}", import);
        }
    }
    
    Ok(())
}
```

### Example 3: Automated Unpacking Detection

```rust
use threatflux_binary_analysis::{
    BinaryAnalyzer, AnalysisConfig,
    analysis::{EntropyAnalyzer, PackerDetector}
};

async fn detect_packing(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = AnalysisConfig {
        analyze_entropy: true,
        detect_packers: true,
        parse_sections: true,
        ..Default::default()
    };
    
    let analyzer = BinaryAnalyzer::new(config);
    let analysis = analyzer.analyze_file(path).await?;
    
    // Use built-in packer detection
    let packer_detector = PackerDetector::new();
    let detection_result = packer_detector.detect(&analysis)?;
    
    if detection_result.is_packed {
        println!("🗜️  File is likely packed!");
        if let Some(packer) = detection_result.detected_packer {
            println!("   Detected packer: {}", packer);
        }
        println!("   Confidence: {:.1}%", detection_result.confidence * 100.0);
    }
    
    // Manual entropy analysis
    let entropy_analyzer = EntropyAnalyzer::new();
    let overall_entropy = entropy_analyzer.calculate_file_entropy(&analysis)?;
    
    println!("📊 Overall file entropy: {:.2}", overall_entropy);
    
    if overall_entropy > 7.0 {
        println!("   High entropy suggests compression or encryption");
    }
    
    // Check for entropy patterns
    for section in &analysis.sections {
        if let Some(entropy) = section.entropy {
            println!("   Section '{}': {:.2}", section.name, entropy);
            
            if entropy > 7.5 && section.permissions.executable {
                println!("     ⚠️  Executable section with very high entropy!");
            }
        }
    }
    
    Ok(())
}
```

### Example 4: Function Analysis

```rust
use threatflux_binary_analysis::{
    BinaryAnalyzer, AnalysisConfig,
    disasm::{Disassembler, DisassemblyEngine},
    analysis::{ControlFlowAnalyzer, FunctionAnalyzer}
};

async fn analyze_functions(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = AnalysisConfig {
        parse_symbols: true,
        disassembly: Some(DisassemblyConfig {
            engine: DisassemblyEngine::Capstone,
            max_instructions: 1000,
            follow_calls: true,
            analyze_control_flow: true,
        }),
        ..Default::default()
    };
    
    let analyzer = BinaryAnalyzer::new(config);
    let analysis = analyzer.analyze_file(path).await?;
    
    let function_analyzer = FunctionAnalyzer::new();
    let functions = function_analyzer.identify_functions(&analysis).await?;
    
    println!("🔍 Found {} functions", functions.len());
    
    for function in &functions {
        println!("\n📍 Function: {} (0x{:x})", function.name, function.address);
        println!("   Size: {} bytes", function.size);
        println!("   Instructions: {}", function.instruction_count);
        println!("   Basic blocks: {}", function.basic_blocks.len());
        
        // Analyze function complexity
        if function.cyclomatic_complexity > 10 {
            println!("   ⚠️  High complexity: {}", function.cyclomatic_complexity);
        }
        
        // Check for suspicious patterns
        if function.has_self_modifying_code {
            println!("   🚨 Self-modifying code detected!");
        }
        
        if function.calls_suspicious_apis {
            println!("   ⚠️  Calls suspicious APIs");
        }
        
        // Print some disassembly
        println!("   First few instructions:");
        for (i, instruction) in function.instructions.iter().take(5).enumerate() {
            println!("     0x{:x}: {} {}", 
                instruction.address, 
                instruction.mnemonic, 
                instruction.operands
            );
        }
        
        if function.instructions.len() > 5 {
            println!("     ... ({} more instructions)", function.instructions.len() - 5);
        }
    }
    
    Ok(())
}
```

## 🔧 Configuration Options

### AnalysisConfig

```rust
pub struct AnalysisConfig {
    // What to parse
    pub parse_headers: bool,           // Parse file headers
    pub parse_sections: bool,          // Parse sections/segments  
    pub parse_symbols: bool,           // Parse symbol tables
    pub parse_imports: bool,           // Parse import tables
    pub parse_exports: bool,           // Parse export tables
    pub parse_relocations: bool,       // Parse relocation tables
    pub parse_debug_info: bool,        // Parse debug information
    
    // Analysis features
    pub detect_packers: bool,          // Run packer detection
    pub analyze_entropy: bool,         // Calculate entropy
    pub extract_strings: bool,         // Extract strings
    pub check_signatures: bool,        // Verify digital signatures
    pub analyze_control_flow: bool,    // Build control flow graphs
    
    // Performance settings
    pub use_memory_mapping: bool,      // Use memory-mapped files
    pub max_file_size: u64,           // Maximum file size (bytes)
    pub timeout: Duration,            // Analysis timeout
    pub parallel_processing: bool,     // Enable parallel processing
    
    // Disassembly settings
    pub disassembly: Option<DisassemblyConfig>,
    
    // Security settings
    pub security: SecurityConfig,
}
```

### DisassemblyConfig

```rust
pub struct DisassemblyConfig {
    pub engine: DisassemblyEngine,     // Capstone or iced-x86
    pub max_instructions: usize,       // Maximum instructions to disassemble
    pub follow_calls: bool,           // Follow function calls
    pub follow_jumps: bool,           // Follow conditional jumps
    pub analyze_control_flow: bool,    // Build control flow graphs
    pub detect_functions: bool,        // Identify function boundaries
    pub resolve_symbols: bool,         // Resolve symbol names
}
```

### SecurityConfig

```rust
pub struct SecurityConfig {
    pub check_suspicious_sections: bool,   // Check for unusual sections
    pub analyze_api_calls: bool,          // Analyze imported APIs
    pub detect_obfuscation: bool,         // Detect code obfuscation
    pub check_certificates: bool,          // Verify code signing certificates
    pub scan_for_shellcode: bool,         // Scan for shellcode patterns
    pub detect_anti_analysis: bool,       // Detect anti-analysis techniques
    pub check_known_malware: bool,        // Check against known malware signatures
}
```

## 🏗️ Architecture

The library is organized into several modules:

- **`formats/`**: Format-specific parsers (PE, ELF, Mach-O, etc.)
- **`disasm/`**: Disassembly engines (Capstone, iced-x86)
- **`analysis/`**: Analysis modules (control flow, security, entropy)
- **`utils/`**: Utility functions (memory mapping, pattern matching)
- **`types.rs`**: Common data structures
- **`error.rs`**: Error handling

### Format Parsers

Each binary format has its own parser module:

```rust
// PE format parser
use threatflux_binary_analysis::formats::pe::PeParser;
let pe_parser = PeParser::new();
let pe_analysis = pe_parser.parse(&file_data)?;

// ELF format parser
use threatflux_binary_analysis::formats::elf::ElfParser;
let elf_parser = ElfParser::new();
let elf_analysis = elf_parser.parse(&file_data)?;
```

### Disassembly Engines

Multiple disassembly engines are supported:

```rust
// Capstone engine (supports many architectures)
use threatflux_binary_analysis::disasm::CapstoneEngine;
let capstone = CapstoneEngine::new(Architecture::X86_64)?;
let instructions = capstone.disassemble(&code, address)?;

// iced-x86 engine (x86/x64 only, but very detailed)
use threatflux_binary_analysis::disasm::IcedEngine;
let iced = IcedEngine::new(Architecture::X86_64)?;
let instructions = iced.disassemble(&code, address)?;
```

## 📈 Performance

The library is designed for high performance:

- **Memory-mapped files**: Efficient handling of large files
- **Lazy parsing**: Only parse what's needed
- **Parallel processing**: Multi-threaded analysis where possible
- **Streaming**: Process files without loading entirely into memory
- **Caching**: Cache analysis results to avoid redundant work

### Benchmarks

Typical performance on modern hardware:

| Operation | Throughput | Notes |
|-----------|------------|-------|
| PE header parsing | ~10,000 files/sec | Basic header info only |
| ELF section parsing | ~5,000 files/sec | Including section contents |
| Disassembly (Capstone) | ~500 MB/sec | x86-64 code |
| Entropy calculation | ~1 GB/sec | Using SIMD optimizations |
| Control flow analysis | ~100 functions/sec | Complex CFG construction |

Run benchmarks:

```bash
cargo bench
```

## 🔒 Security

The library follows secure coding practices:

- **Memory safety**: Rust's ownership model prevents buffer overflows
- **Input validation**: All inputs are validated and bounds-checked
- **Resource limits**: Configurable limits prevent DoS attacks
- **Sandboxing**: Analysis runs with minimal privileges
- **Timeout protection**: Prevents infinite loops in malicious files

### Handling Malicious Files

The library is designed to safely analyze potentially malicious files:

```rust
let config = AnalysisConfig {
    max_file_size: 100 * 1024 * 1024,  // 100MB limit
    timeout: Duration::from_secs(300),  // 5 minute timeout
    use_memory_mapping: true,           // Avoid loading entire file
    ..Default::default()
};
```

## 🧪 Testing

Run the test suite:

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# Test with different features
cargo test --features "disasm-capstone,control-flow"
cargo test --features "wasm"  # Enable WebAssembly support

# Test documentation examples
cargo test --doc
```

Test coverage:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html
```

## 📚 Examples

More examples are available in the [`examples/`](examples/) directory:

- [`basic_analysis.rs`](examples/basic_analysis.rs) - Basic binary analysis
- [`control_flow.rs`](examples/control_flow.rs) - Control flow analysis
- [`disassembly.rs`](examples/disassembly.rs) - Disassembly examples
- [`security_analysis.rs`](examples/security_analysis.rs) - Security analysis

Run an example:

```bash
cargo run --example basic_analysis --features "pe,elf" -- path/to/binary
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/ThreatFlux/threatflux-binary-analysis.git
cd threatflux-binary-analysis

# Install development dependencies
cargo install cargo-watch cargo-tarpaulin

# Run tests in watch mode
cargo watch -x test

# Generate documentation
cargo doc --open --all-features
```

## 📄 License

This project is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## 🔗 Related Projects

- [ThreatFlux Hashing](../threatflux-hashing/) - High-performance file hashing
- [ThreatFlux String Analysis](../threatflux-string-analysis/) - Advanced string analysis
- [ThreatFlux Cache](../threatflux-cache/) - Intelligent caching system
- [File Scanner](../) - Complete file analysis framework

## 📞 Support

- **Documentation**: [docs.rs/threatflux-binary-analysis](https://docs.rs/threatflux-binary-analysis)
- **Issues**: [GitHub Issues](https://github.com/ThreatFlux/threatflux-binary-analysis/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ThreatFlux/threatflux-binary-analysis/discussions)

---

**Security Notice**: This library is designed for security research and analysis. Always analyze suspicious files in a secure, isolated environment.