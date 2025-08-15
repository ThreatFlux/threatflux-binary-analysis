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
    // Get binary file path from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <binary_file>", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
    println!("Analyzing control flow in: {file_path}");

    // Read and parse the binary file
    let data = fs::read(file_path)?;
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
