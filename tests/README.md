# ThreatFlux Binary Analysis - Test Suite

This directory contains comprehensive test suites for the ThreatFlux Binary Analysis library, designed to achieve 90%+ test coverage across all Phase 1 features.

## Test Organization

### Unit Tests
Individual format parsers and components:

- **`unit_elf_test.rs`** - Comprehensive ELF parser tests
  - Basic header parsing and validation
  - Architecture and endianness detection
  - Section and symbol parsing
  - Program header analysis
  - Error handling and edge cases
  - Performance with large files

- **`unit_pe_test.rs`** - Comprehensive PE parser tests
  - DOS header validation
  - PE/COFF header parsing
  - Section characteristics and permissions
  - Import/export table parsing
  - Debug directory analysis
  - Rich header detection

- **`unit_macho_test.rs`** - Comprehensive Mach-O parser tests
  - Magic number detection (all variants)
  - CPU type and platform detection
  - Load command parsing
  - Segment and section analysis
  - Code signing detection
  - Universal binary support

- **`unit_java_test.rs`** - Comprehensive Java format tests
  - Class file parsing and validation
  - Version detection across Java releases
  - JAR/WAR/EAR/APK archive parsing
  - Constant pool analysis
  - Method and field extraction
  - Android-specific features

- **`unit_compiler_detection_test.rs`** - Advanced compiler detection
  - ELF: GCC, Clang, Rust, Go detection
  - PE: MSVC (2013-2022), MinGW, Intel compiler
  - Mach-O: Xcode, command line tools, Swift
  - Version confidence scoring
  - Cross-compilation detection

- **`unit_debug_info_test.rs`** - Debug information extraction
  - DWARF (v2-v5) section parsing
  - PDB and CodeView detection
  - Stripped binary identification
  - Language detection from debug info
  - Compressed debug sections

- **`unit_enhanced_binary_info_test.rs`** - Enhanced structures
  - New metadata fields validation
  - Serialization/deserialization tests
  - Security features detection
  - Backward compatibility verification
  - Thread safety validation

- **`unit_property_based_test.rs`** - Property-based fuzzing
  - Random input robustness testing
  - Format detection invariants
  - Parser consistency validation
  - Memory usage bounds
  - Error handling quality

### Integration Tests

- **`integration_performance_test.rs`** - Performance benchmarks
  - Parsing speed scaling with file size
  - Concurrent parsing performance
  - Memory usage analysis
  - System binary integration
  - Adversarial input handling

### Common Test Infrastructure

- **`common/`** directory contains shared test utilities:
  - **`fixtures.rs`** - Binary test data creation
  - **`helpers.rs`** - Test utility functions
  - **`mod.rs`** - Module organization

## Coverage Goals

Each test file is designed to achieve **90%+ line coverage** for its corresponding module:

| Module | Target Coverage | Key Test Areas |
|--------|----------------|----------------|
| `formats/elf.rs` | 90%+ | Header parsing, sections, symbols, security |
| `formats/pe.rs` | 90%+ | DOS/PE headers, imports/exports, debug info |
| `formats/macho.rs` | 90%+ | Load commands, segments, code signing |
| `formats/java.rs` | 90%+ | Class files, archives, version detection |
| Compiler Detection | 90%+ | All major toolchains, version mapping |
| Debug Information | 90%+ | DWARF, PDB, stripped detection |
| Enhanced Structures | 90%+ | New fields, serialization, compatibility |

## Running Tests

### All Tests
```bash
cargo test
```

### Specific Test Categories
```bash
# Unit tests only
cargo test unit_

# Integration tests only  
cargo test integration_

# Performance tests only
cargo test performance

# Property-based tests only
cargo test prop_
```

### Coverage Analysis
```bash
# Generate coverage report
cargo install cargo-llvm-cov
cargo llvm-cov --html --output-dir coverage-report

# View coverage by file
cargo llvm-cov --show-missing-lines
```

### Specific Format Tests
```bash
# ELF parser tests
cargo test unit_elf_test

# PE parser tests
cargo test unit_pe_test

# Mach-O parser tests
cargo test unit_macho_test

# Java parser tests
cargo test unit_java_test
```

## Test Features

### Property-Based Testing
Uses `proptest` for robust fuzzing:
- Random binary data generation
- Format detection invariants
- Parser consistency validation
- Memory bounds checking

### Performance Testing
Comprehensive performance analysis:
- Parsing time scaling (4KB → 100MB files)
- Concurrent parsing stress tests
- Memory usage profiling
- System binary integration

### Edge Case Coverage
Extensive edge case testing:
- Corrupted binary data
- Truncated files
- Invalid headers
- Malformed structures
- Large file handling

### Real-World Integration
Tests with actual system binaries:
- `/bin/ls`, `/bin/cat`, `/usr/bin/file`
- Cross-platform compatibility
- Production-ready validation

## Test Data

### Synthetic Test Binaries
The test suite creates realistic binary data for:
- **ELF**: Complete headers, sections, symbols
- **PE**: DOS header, COFF, optional header, sections  
- **Mach-O**: Load commands, segments, code signing
- **Java**: Class files, JAR archives, Android APKs

### Compiler-Specific Binaries
Test data includes compiler signatures for:
- **GCC**: Versions 9-13, comment sections
- **Clang**: Versions 12-16, LLVM metadata
- **MSVC**: Visual Studio 2013-2022, Rich headers
- **Rust**: Cargo metadata, symbol mangling
- **Go**: Build info, runtime sections

### Debug Information Samples
Comprehensive debug format coverage:
- **DWARF v2-v5**: All standard sections
- **PDB**: Debug directories, CodeView
- **Stripped**: Various stripping levels
- **Compressed**: zlib-compressed debug

## Quality Assurance

### Continuous Integration
All tests run in CI with:
- Multiple Rust versions (MSRV to latest)
- Cross-platform testing (Linux, macOS, Windows)
- Feature flag combinations
- Performance regression detection

### Code Quality
Tests follow strict quality standards:
- Comprehensive documentation
- Clear test descriptions
- Proper error message validation
- Memory safety verification
- Thread safety validation

### Maintenance
Regular test maintenance includes:
- Updating compiler version detection
- Adding new binary format variants
- Performance threshold tuning
- Security feature evolution

## Contributing

When adding new tests:

1. **Follow naming conventions**: `test_<feature>_<specific_case>`
2. **Add documentation**: Describe what the test validates
3. **Include edge cases**: Test error conditions and boundary cases
4. **Update coverage goals**: Maintain 90%+ coverage target
5. **Performance considerations**: Ensure tests complete quickly
6. **Cross-platform compatibility**: Test on multiple platforms

### Test Categories

- **Smoke tests**: Basic functionality validation
- **Unit tests**: Individual component testing  
- **Integration tests**: Cross-component interaction
- **Property tests**: Invariant validation with random inputs
- **Performance tests**: Speed and memory usage validation
- **Regression tests**: Previous bug prevention

## Troubleshooting

### Common Issues

**Test failures on specific platforms:**
- Check platform-specific binary formats
- Verify endianness handling
- Validate path separators in test data

**Performance test timeouts:**
- Adjust timeout thresholds for slower systems
- Check memory availability
- Verify test data sizes

**Coverage gaps:**
- Use `cargo llvm-cov` to identify untested lines
- Add specific tests for missed branches
- Verify feature flag combinations

### Debugging Tests

```bash
# Run with output
cargo test -- --nocapture

# Run specific test with debug info
RUST_LOG=debug cargo test test_specific_function

# Run tests in single thread
cargo test -- --test-threads=1
```

This comprehensive test suite ensures the ThreatFlux Binary Analysis library maintains high quality, performance, and reliability across all supported binary formats and use cases.