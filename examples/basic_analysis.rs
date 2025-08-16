#![allow(clippy::uninlined_format_args)]
//! Basic binary analysis example
//!
//! This example demonstrates how to use the threatflux-binary-analysis library
//! to perform basic analysis of binary files.

use std::env;
use std::fs;
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer, BinaryFile};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    // Get binary file path from command line arguments
    let args: Vec<String> = env::args().collect();
    
    let data = if args.len() != 2 {
        println!("No binary file provided, using minimal ELF test data for demonstration");
        println!("Usage: {} <binary_file>", args[0]);
        println!();
        
        // Create a minimal valid ELF binary for testing
        create_minimal_elf()
    } else {
        let file_path = &args[1];
        println!("Analyzing binary file: {}", file_path);
        
        // Read the binary file
        fs::read(file_path)?
    };
    println!("File size: {} bytes", data.len());

    // Parse the binary
    let binary = BinaryFile::parse(&data)?;
    println!("Binary format: {:?}", binary.format());
    println!("Architecture: {:?}", binary.architecture());

    // Print basic metadata
    let metadata = binary.metadata();
    println!("\n=== Binary Metadata ===");
    println!("Format: {:?}", metadata.format);
    println!("Architecture: {:?}", metadata.architecture);
    println!("Entry point: {:?}", metadata.entry_point);
    println!("Base address: {:?}", metadata.base_address);
    println!("Endianness: {:?}", metadata.endian);

    if let Some(compiler) = &metadata.compiler_info {
        println!("Compiler: {}", compiler);
    }

    // Print security features
    println!("\n=== Security Features ===");
    let security = &metadata.security_features;
    println!("NX/DEP: {}", security.nx_bit);
    println!("ASLR: {}", security.aslr);
    println!("Stack Canary: {}", security.stack_canary);
    println!("CFI: {}", security.cfi);
    println!("PIE: {}", security.pie);
    println!("RELRO: {}", security.relro);
    println!("Signed: {}", security.signed);

    // Print sections
    println!("\n=== Sections ===");
    for (i, section) in binary.sections().iter().enumerate() {
        println!("Section {}: {}", i, section.name);
        println!("  Address: 0x{:x}", section.address);
        println!("  Size: {} bytes", section.size);
        println!("  Type: {:?}", section.section_type);
        println!(
            "  Permissions: R:{} W:{} X:{}",
            section.permissions.read, section.permissions.write, section.permissions.execute
        );
        println!();
    }

    // Print symbols (limited to first 10)
    println!("=== Symbols (first 10) ===");
    for (i, symbol) in binary.symbols().iter().take(10).enumerate() {
        println!("Symbol {}: {}", i, symbol.name);
        println!("  Address: 0x{:x}", symbol.address);
        println!("  Size: {} bytes", symbol.size);
        println!("  Type: {:?}", symbol.symbol_type);
        println!("  Binding: {:?}", symbol.binding);
        if let Some(demangled) = &symbol.demangled_name {
            println!("  Demangled: {}", demangled);
        }
        println!();
    }

    if binary.symbols().len() > 10 {
        println!("... and {} more symbols", binary.symbols().len() - 10);
    }

    // Print imports (limited to first 10)
    println!("\n=== Imports (first 10) ===");
    for (i, import) in binary.imports().iter().take(10).enumerate() {
        println!("Import {}: {}", i, import.name);
        if let Some(library) = &import.library {
            println!("  Library: {}", library);
        }
        if let Some(address) = import.address {
            println!("  Address: 0x{:x}", address);
        }
        if let Some(ordinal) = import.ordinal {
            println!("  Ordinal: {}", ordinal);
        }
        println!();
    }

    if binary.imports().len() > 10 {
        println!("... and {} more imports", binary.imports().len() - 10);
    }

    // Print exports (limited to first 10)
    println!("\n=== Exports (first 10) ===");
    for (i, export) in binary.exports().iter().take(10).enumerate() {
        println!("Export {}: {}", i, export.name);
        println!("  Address: 0x{:x}", export.address);
        if let Some(ordinal) = export.ordinal {
            println!("  Ordinal: {}", ordinal);
        }
        if let Some(forwarded) = &export.forwarded_name {
            println!("  Forwarded: {}", forwarded);
        }
        println!();
    }

    if binary.exports().len() > 10 {
        println!("... and {} more exports", binary.exports().len() - 10);
    }

    // Perform comprehensive analysis
    println!("\n=== Performing Analysis ===");
    let config = AnalysisConfig {
        enable_disassembly: false, // Disable for basic example
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: threatflux_binary_analysis::DisassemblyEngine::Auto,
        enable_control_flow: false,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 1024 * 1024, // 1MB limit
        architecture_hint: None,
    };

    let analyzer = BinaryAnalyzer::with_config(config);

    match analyzer.analyze(&data) {
        Ok(analysis) => {
            println!("Analysis completed successfully!");
            println!("Format: {:?}", analysis.format);
            println!("Architecture: {:?}", analysis.architecture);
            println!("Entry point: {:?}", analysis.entry_point);
            println!("Sections: {}", analysis.sections.len());
            println!("Symbols: {}", analysis.symbols.len());
            println!("Imports: {}", analysis.imports.len());
            println!("Exports: {}", analysis.exports.len());
        }
        Err(e) => {
            eprintln!("Analysis failed: {}", e);
        }
    }

    Ok(())
}

/// Create a minimal valid ELF binary for testing
fn create_minimal_elf() -> Vec<u8> {
    vec![
        // ELF Header
        0x7f, 0x45, 0x4c, 0x46, // Magic number
        0x02, // 64-bit
        0x01, // Little endian  
        0x01, // Current version
        0x00, // Generic ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // Executable file
        0x3e, 0x00, // x86-64
        0x01, 0x00, 0x00, 0x00, // Version 1
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
        0x00, 0x00, 0x00, 0x00, // Flags
        0x40, 0x00, // ELF header size
        0x38, 0x00, // Program header size
        0x01, 0x00, // Program header count
        0x40, 0x00, // Section header size
        0x00, 0x00, // Section header count
        0x00, 0x00, // Section name index
        // Program Header
        0x01, 0x00, 0x00, 0x00, // Type: LOAD
        0x05, 0x00, 0x00, 0x00, // Flags: R+X
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Offset
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Virtual address
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Physical address
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // File size
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Memory size
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Alignment
        // Code section with simple x86-64 instructions
        0xb8, 0x3c, 0x00, 0x00, 0x00,  // mov eax, 60 (sys_exit)
        0xbf, 0x00, 0x00, 0x00, 0x00,  // mov edi, 0 (exit code)
        0x0f, 0x05,                    // syscall
    ]
}
