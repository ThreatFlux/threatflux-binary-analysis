#![allow(clippy::uninlined_format_args)]
//! Basic binary analysis example
//!
//! This example demonstrates how to use the threatflux-binary-analysis library
//! to perform basic analysis of binary files.

use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer, BinaryFile};

mod util;
use util::{read_binary_from_args, Result};

fn main() -> Result<()> {
    let data = read_binary_from_args()?;
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
