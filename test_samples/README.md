# ThreatFlux Binary Analysis - Test Samples

This directory contains various test files designed to exercise different aspects of the ThreatFlux binary analysis capabilities. Each file is crafted to test specific analysis features and provide known patterns for validation.

## Files Overview

### 1. `test_program.c` and `test_program` (ELF Binary)

**Source File**: `test_program.c` - Complete C source code
**Binary File**: `test_program` - Compiled ELF executable

**Purpose**: Test binary format analysis, symbol extraction, and static analysis capabilities.

**Key Features**:
- Multiple functions with different complexity levels
- Global and local variables for symbol analysis
- String literals embedded in the binary
- Function calls demonstrating control flow
- Intentionally vulnerable function with buffer overflow potential
- System calls (getpid, system) for API analysis
- Recursive function (Fibonacci) for complexity testing

**Analysis Targets**:
- ELF header parsing
- Symbol table extraction
- String analysis
- Control flow analysis
- Function identification
- Security vulnerability detection
- Compiler metadata

### 2. `analysis_script.py`

**Purpose**: Test script analysis capabilities and Python-specific patterns.

**Key Features**:
- Suspicious import statements (subprocess, base64)
- Hardcoded API endpoints and malware signatures
- Network-related functionality simulation
- Obfuscated payload examples
- File system operations
- Hash calculation routines
- Potential security risks in code patterns

**Analysis Targets**:
- Script language detection
- Suspicious import analysis
- String pattern extraction
- Network indicator identification
- Obfuscation detection
- API usage analysis

### 3. `mixed_content.txt`

**Purpose**: Test text parsing and content analysis capabilities.

**Key Features**:
- Configuration file syntax
- Log entries with timestamps and severity levels
- Network indicators (IPs, domains, URLs)
- Hexadecimal data patterns
- Base64 encoded content
- Windows registry keys
- File system paths
- Cryptocurrency addresses
- Command-line examples
- Email addresses

**Analysis Targets**:
- IOC (Indicator of Compromise) extraction
- Network artifact identification
- Credential pattern detection
- File path analysis
- Encoding detection
- Log parsing capabilities

### 4. `test_binary.bin`

**Purpose**: Test raw binary analysis with known patterns.

**Key Features**:
- Multiple file format signatures (PE, ELF, Java)
- Suspicious API names embedded
- URL patterns
- Mixed endianness data
- Entropy patterns (both repetitive and random)
- Known malware-related strings

**Analysis Targets**:
- Multi-format signature detection
- String extraction from binary data
- Entropy analysis
- API name identification
- URL extraction
- Pattern recognition

### 5. `test_script.sh`

**Purpose**: Test shell script analysis and UNIX-specific patterns.

**Key Features**:
- Complex shell scripting patterns
- System command execution
- File system operations
- Network simulation
- Configuration file generation
- Error handling and logging
- Signal handling
- Conditional logic and loops

**Analysis Targets**:
- Shell script language detection
- Command execution analysis
- File operation patterns
- Network activity simulation
- Configuration parsing
- Security risk assessment

### 6. `create_binary.py`

**Purpose**: Utility script used to generate `test_binary.bin`.

**Key Features**:
- Binary data generation
- Multiple format signature creation
- Pattern embedding
- Reproducible output (seeded random)

## Usage Examples

### Basic File Information
```bash
file test_samples/*
```

### Hash Analysis
```bash
md5sum test_samples/*
sha256sum test_samples/*
```

### String Extraction
```bash
strings test_samples/test_program
strings test_samples/test_binary.bin
```

### Binary Analysis
```bash
objdump -h test_samples/test_program
readelf -a test_samples/test_program
hexdump -C test_samples/test_binary.bin | head
```

### Running the Test Program
```bash
# Basic execution
./test_samples/test_program

# With arguments (tests vulnerable function)
./test_samples/test_program "test input"

# With debug argument
./test_samples/test_program "debug"
```

### Running the Scripts
```bash
# Python analysis script
python3 test_samples/analysis_script.py test_samples/test_program

# Shell script
./test_samples/test_script.sh test_samples/test_binary.bin
```

## Analysis Validation

These test files contain known patterns that should be detected by the ThreatFlux binary analysis system:

### Expected Detections

1. **ELF Binary Analysis**:
   - Function symbols: `main`, `print_banner`, `calculate_fibonacci`, `process_data`, `vulnerable_function`
   - Strings: "ThreatFlux Binary Analysis Test", "Version 1.0.0", etc.
   - Potential vulnerabilities: Buffer overflow in `vulnerable_function`

2. **Script Analysis**:
   - Suspicious imports: `subprocess`, `base64`
   - Network indicators: Various malicious URLs
   - Obfuscated content: Base64 encoded strings

3. **Binary Pattern Detection**:
   - File signatures: PE (4D 5A), ELF (7F 45 4C 46), Java (CA FE BA BE)
   - API names: CreateRemoteThread, VirtualAllocEx, etc.
   - Network artifacts: Embedded URLs

4. **Text Analysis**:
   - IOCs: IP addresses, domains, file paths
   - Credentials: Passwords, API keys
   - System artifacts: Registry keys, file paths

## File Sizes and Characteristics

- `test_program.c`: ~3.2 KB (source code)
- `test_program`: ~17 KB (compiled ELF binary with debug symbols)
- `analysis_script.py`: ~6.8 KB (Python script)
- `mixed_content.txt`: ~4.1 KB (text file)
- `test_binary.bin`: ~723 bytes (binary data)
- `test_script.sh`: ~6.9 KB (shell script)

## Security Notes

⚠️ **Warning**: These files contain intentionally suspicious patterns for testing purposes:
- The C program has a vulnerable function that could cause buffer overflows
- The Python script simulates malicious behavior patterns
- The binary file contains malware-like signatures
- All network references are to example/test domains

These files are safe for analysis but should not be executed in production environments without proper sandboxing.

## Testing Checklist

When using these files to test analysis capabilities, verify:

- [ ] File type detection works correctly
- [ ] Hash calculations are accurate
- [ ] String extraction finds embedded text
- [ ] Binary format parsing succeeds
- [ ] Symbol extraction works for compiled binaries
- [ ] Suspicious pattern detection triggers appropriately
- [ ] Network indicator extraction works
- [ ] Encoding detection (Base64, hex) functions
- [ ] Control flow analysis completes
- [ ] Security vulnerability detection activates