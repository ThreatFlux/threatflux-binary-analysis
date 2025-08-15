# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building
```bash
# Build with default features (elf, pe, macho, java)
cargo build

# Build with all features including optional ones
cargo build --all-features

# Build with specific features
cargo build --features "disasm-iced,control-flow,wasm"

# Build in release mode for performance
cargo build --release
```

### Testing
```bash
# Run all tests with default features
cargo test

# Run tests with all features
cargo test --all-features

# Run specific test file
cargo test --test integration_test

# Run tests with specific features
cargo test --features "disasm-iced,control-flow"

# Run a single test by name
cargo test test_name_here

# Run tests with output shown
cargo test -- --nocapture
```

### Code Quality
```bash
# Format code
cargo fmt

# Check formatting without changes
cargo fmt -- --check

# Run clippy for linting
cargo clippy

# Run clippy with all features
cargo clippy --all-features
```

### Documentation
```bash
# Generate and open documentation
cargo doc --open --all-features

# Build documentation without opening
cargo doc --all-features
```

### Examples
```bash
# Run basic analysis example
cargo run --example basic_analysis -- path/to/binary

# Run control flow example (requires feature)
cargo run --example control_flow --features "control-flow" -- path/to/binary

# Run disassembly example
cargo run --example disassembly --features "disasm-capstone" -- path/to/binary
```

## Architecture Overview

### Core Module Structure

The library follows a modular architecture with clear separation of concerns:

- **`src/lib.rs`**: Main library entry point, re-exports key types
- **`src/types.rs`**: Core data structures (BinaryAnalysis, Section, Symbol, etc.)
- **`src/error.rs`**: Custom error types and error handling

### Format Parsers (`src/formats/`)

Each binary format has dedicated parser implementing format-specific logic:
- `elf.rs`: Linux/Unix ELF binaries
- `pe.rs`: Windows PE executables  
- `macho.rs`: macOS Mach-O binaries
- `java.rs`: JAR files and Java class files
- `wasm.rs`: WebAssembly modules (feature-gated)
- `raw.rs`: Generic binary analysis fallback

All parsers implement a common trait pattern for consistent API.

### Disassembly Engines (`src/disasm/`)

Multiple disassembly backends with feature flags:
- `capstone_engine.rs`: Multi-architecture via Capstone (default)
- `iced_engine.rs`: x86/x64 specialized via iced-x86 (opt-in)

Engines are abstracted behind common traits for swappable backends.

### Analysis Modules (`src/analysis/`)

Advanced analysis capabilities built on core parsing:
- `control_flow.rs`: CFG construction, complexity metrics (requires petgraph)
- `entropy.rs`: Statistical analysis for packing detection
- `security.rs`: Vulnerability patterns, malware indicators
- `symbols.rs`: Symbol resolution, demangling, cross-references
- `visualization.rs`: DOT graph generation for CFGs

### Utilities (`src/utils/`)

Supporting functionality:
- `mmap.rs`: Memory-mapped file handling for large binaries
- `compression.rs`: Decompression support (flate2)
- `extractor.rs`: String and pattern extraction
- `patterns.rs`: Common binary patterns and signatures
- `serde_utils.rs`: JSON serialization support

## Key Design Patterns

1. **Feature Flags**: Heavy use of Cargo features for optional functionality
2. **Error Handling**: Result-based with custom error types via thiserror
3. **Zero-Copy Parsing**: Uses goblin for efficient binary parsing
4. **Memory Mapping**: Optional mmap for large file handling
5. **Trait Abstraction**: Common traits for format parsers and disassemblers

## Testing Strategy

- Unit tests in each module file
- Integration tests in `tests/` directory
- Format-specific test files (elf_test.rs, pe_test.rs, etc.)
- Feature-gated tests for optional components
- Test utilities: rstest for parametrized tests, proptest for property testing

## Feature Dependencies

When adding code that uses specific libraries, check feature gates:
- Disassembly requires `disasm-capstone` or `disasm-iced`
- Control flow analysis requires `control-flow` feature
- WASM support requires `wasm` feature
- Visualization requires `visualization` feature