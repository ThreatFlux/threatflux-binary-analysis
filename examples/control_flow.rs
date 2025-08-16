//! Control flow analysis example
//!
//! This example demonstrates how to analyze control flow in binary files,
//! including basic block identification and complexity metrics.

use std::env;
use std::fs;
use threatflux_binary_analysis::{
    analysis::control_flow::{AnalysisConfig, ControlFlowAnalyzer},
    BinaryFile,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    // Get binary file path from command line arguments using iterator
    let mut args_iter = env::args();
    let program_name = args_iter
        .next()
        .unwrap_or_else(|| "control_flow".to_string());
    let file_path = args_iter.next();

    let data = if let Some(file_path) = file_path {
        println!("Analyzing control flow in: {file_path}");

        // Read and parse the binary file
        fs::read(&file_path)?
    } else {
        println!("No binary file provided, using minimal ELF test data for demonstration");
        println!("Usage: {} <binary_file>", program_name);
        println!();

        // Create a minimal valid ELF binary for testing
        create_minimal_elf()
    };
    let binary = BinaryFile::parse(&data)?;

    println!("Binary format: {:?}", binary.format());
    println!("Architecture: {:?}", binary.architecture());

    // Create control flow analyzer
    let config = AnalysisConfig {
        max_instructions: 5000,
        max_depth: 50,
        detect_loops: true,
        calculate_metrics: true,
    };

    let analyzer = ControlFlowAnalyzer::with_config(binary.architecture(), config);

    // Analyze all functions
    println!("\n=== Control Flow Analysis ===");
    match analyzer.analyze_binary(&binary) {
        Ok(cfgs) => {
            println!("Found {} control flow graphs", cfgs.len());

            for (i, cfg) in cfgs.iter().enumerate().take(10) {
                println!("\nFunction {}: {}", i + 1, cfg.function.name);
                println!(
                    "  Address range: 0x{:x} - 0x{:x}",
                    cfg.function.start_address, cfg.function.end_address
                );
                println!("  Size: {} bytes", cfg.function.size);
                println!("  Type: {:?}", cfg.function.function_type);

                if let Some(calling_convention) = &cfg.function.calling_convention {
                    println!("  Calling convention: {calling_convention}");
                }

                // Print basic blocks
                println!("  Basic blocks: {}", cfg.basic_blocks.len());
                for (j, block) in cfg.basic_blocks.iter().enumerate().take(5) {
                    println!(
                        "    Block {}: 0x{:x} - 0x{:x} ({} instructions)",
                        j,
                        block.start_address,
                        block.end_address,
                        block.instructions.len()
                    );

                    println!("      Successors: {:?}", block.successors);
                    println!("      Predecessors: {:?}", block.predecessors);

                    // Show first few instructions
                    for (k, instr) in block.instructions.iter().enumerate().take(3) {
                        println!(
                            "        {}: 0x{:x} {} {}",
                            k, instr.address, instr.mnemonic, instr.operands
                        );
                    }

                    if block.instructions.len() > 3 {
                        println!(
                            "        ... and {} more instructions",
                            block.instructions.len() - 3
                        );
                    }
                }

                if cfg.basic_blocks.len() > 5 {
                    println!("    ... and {} more blocks", cfg.basic_blocks.len() - 5);
                }

                // Print complexity metrics
                let metrics = &cfg.complexity;
                println!("  Complexity metrics:");
                println!(
                    "    Cyclomatic complexity: {}",
                    metrics.cyclomatic_complexity
                );
                println!("    Basic block count: {}", metrics.basic_block_count);
                println!("    Edge count: {}", metrics.edge_count);
                println!("    Nesting depth: {}", metrics.nesting_depth);
                println!("    Loop count: {}", metrics.loop_count);

                // Complexity assessment
                let complexity_level = assess_complexity(metrics.cyclomatic_complexity);
                println!("    Complexity level: {complexity_level}");
            }

            if cfgs.len() > 10 {
                println!("\n... and {} more functions", cfgs.len() - 10);
            }

            // Overall statistics
            println!("\n=== Overall Statistics ===");
            let total_blocks: usize = cfgs.iter().map(|cfg| cfg.basic_blocks.len()).sum();
            let total_complexity: u32 = cfgs
                .iter()
                .map(|cfg| cfg.complexity.cyclomatic_complexity)
                .sum();
            let total_loops: u32 = cfgs.iter().map(|cfg| cfg.complexity.loop_count).sum();

            println!("Total functions analyzed: {}", cfgs.len());
            println!("Total basic blocks: {total_blocks}");
            println!("Total cyclomatic complexity: {total_complexity}");
            println!("Total loops detected: {total_loops}");

            if !cfgs.is_empty() {
                let avg_complexity = total_complexity as f64 / cfgs.len() as f64;
                let avg_blocks = total_blocks as f64 / cfgs.len() as f64;

                println!("Average complexity per function: {avg_complexity:.2}");
                println!("Average blocks per function: {avg_blocks:.2}");
            }

            // Find most complex functions
            let mut sorted_cfgs = cfgs.clone();
            sorted_cfgs.sort_by_key(|cfg| std::cmp::Reverse(cfg.complexity.cyclomatic_complexity));

            println!("\n=== Most Complex Functions ===");
            for (i, cfg) in sorted_cfgs.iter().take(5).enumerate() {
                println!(
                    "{}. {} (complexity: {})",
                    i + 1,
                    cfg.function.name,
                    cfg.complexity.cyclomatic_complexity
                );
            }
        }
        Err(e) => {
            eprintln!("Control flow analysis failed: {e}");
            return Err(e.into());
        }
    }

    Ok(())
}

/// Assess complexity level based on cyclomatic complexity
fn assess_complexity(complexity: u32) -> &'static str {
    match complexity {
        1..=10 => "Low",
        11..=20 => "Moderate",
        21..=50 => "High",
        _ => "Very High",
    }
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
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (sys_exit)
        0xbf, 0x00, 0x00, 0x00, 0x00, // mov edi, 0 (exit code)
        0x0f, 0x05, // syscall
    ]
}
