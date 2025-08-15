//! Disassembly example
//!
//! This example demonstrates how to disassemble binary code using
//! the integrated disassembly engines (Capstone or iced-x86).

use std::env;
use std::fs;
use threatflux_binary_analysis::{
    BinaryFile,
    disasm::{Disassembler, DisassemblyConfig, DisassemblyEngine},
    types::ControlFlow,
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
    println!("Disassembling binary file: {}", file_path);

    // Read and parse the binary file
    let data = fs::read(file_path)?;
    let binary = BinaryFile::parse(&data)?;

    println!("Binary format: {:?}", binary.format());
    println!("Architecture: {:?}", binary.architecture());

    // Create disassembler configuration
    let config = DisassemblyConfig {
        engine: DisassemblyEngine::Auto,
        max_instructions: 100, // Limit for demonstration
        detailed: true,
        analyze_control_flow: true,
        skip_invalid: true,
    };

    // Create disassembler
    let disassembler = Disassembler::with_config(binary.architecture(), config)?;

    println!("\n=== Disassembly Analysis ===");

    // Find executable sections and disassemble them
    let mut total_instructions = 0;

    for section in binary.sections() {
        if section.permissions.execute {
            println!(
                "\nDisassembling section: {} (0x{:x})",
                section.name, section.address
            );
            println!("Section size: {} bytes", section.size);

            if let Some(section_data) = &section.data {
                match disassembler.disassemble(section_data, section.address) {
                    Ok(instructions) => {
                        println!("Found {} instructions", instructions.len());
                        total_instructions += instructions.len();

                        // Display instructions with analysis
                        for (i, instr) in instructions.iter().enumerate().take(20) {
                            print_instruction(i, instr);
                        }

                        if instructions.len() > 20 {
                            println!("... and {} more instructions", instructions.len() - 20);
                        }

                        // Analyze instruction statistics
                        analyze_instruction_stats(&instructions);
                    }
                    Err(e) => {
                        eprintln!("Failed to disassemble section {}: {}", section.name, e);
                    }
                }
            } else {
                println!("Section data not available for disassembly");
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total instructions disassembled: {}", total_instructions);

    // Try to disassemble from entry point if available
    if let Some(entry_point) = binary.entry_point() {
        println!("\n=== Entry Point Analysis ===");
        println!("Entry point: 0x{:x}", entry_point);

        // Find the section containing the entry point
        for section in binary.sections() {
            if entry_point >= section.address && entry_point < section.address + section.size {
                println!("Entry point is in section: {}", section.name);

                if let Some(section_data) = &section.data {
                    let offset = (entry_point - section.address) as usize;
                    if offset < section_data.len() {
                        let entry_data = &section_data[offset..];
                        let limited_data = &entry_data[..entry_data.len().min(100)]; // First 100 bytes

                        match disassembler.disassemble(limited_data, entry_point) {
                            Ok(instructions) => {
                                println!("\nInstructions at entry point:");
                                for (i, instr) in instructions.iter().enumerate().take(10) {
                                    print_instruction(i, instr);
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to disassemble entry point: {}", e);
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    Ok(())
}

/// Print a single instruction with formatting and analysis
fn print_instruction(index: usize, instr: &threatflux_binary_analysis::types::Instruction) {
    // Format instruction bytes
    let bytes_str = instr
        .bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");

    // Format the instruction
    let operands = if instr.operands.is_empty() {
        String::new()
    } else {
        format!(" {}", instr.operands)
    };

    println!(
        "{:3}: 0x{:08x}  {:20} {}{}",
        index, instr.address, bytes_str, instr.mnemonic, operands
    );

    // Add category and flow information
    let category_str = format!("{:?}", instr.category);
    let flow_info = match &instr.flow {
        ControlFlow::Sequential => "sequential".to_string(),
        ControlFlow::Jump(addr) => format!("jmp -> 0x{:x}", addr),
        ControlFlow::ConditionalJump(addr) => format!("branch -> 0x{:x}", addr),
        ControlFlow::Call(addr) => format!("call -> 0x{:x}", addr),
        ControlFlow::Return => "return".to_string(),
        ControlFlow::Interrupt => "interrupt".to_string(),
        ControlFlow::Unknown => "unknown".to_string(),
    };

    println!("      [{}] [{}]", category_str, flow_info);
}

/// Analyze and print instruction statistics
fn analyze_instruction_stats(instructions: &[threatflux_binary_analysis::types::Instruction]) {
    if instructions.is_empty() {
        return;
    }

    println!("\n--- Instruction Statistics ---");

    // Count by category
    let mut category_counts = std::collections::HashMap::new();
    let mut flow_counts = std::collections::HashMap::new();
    let mut mnemonic_counts = std::collections::HashMap::new();

    for instr in instructions {
        *category_counts.entry(instr.category.clone()).or_insert(0) += 1;
        *flow_counts.entry(format!("{:?}", instr.flow)).or_insert(0) += 1;
        *mnemonic_counts.entry(instr.mnemonic.clone()).or_insert(0) += 1;
    }

    // Print category distribution
    println!("Instruction categories:");
    let mut categories: Vec<_> = category_counts.iter().collect();
    categories.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

    for (category, count) in categories.iter().take(5) {
        let percentage = (**count as f64 / instructions.len() as f64) * 100.0;
        println!("  {:?}: {} ({:.1}%)", category, count, percentage);
    }

    // Print control flow distribution
    println!("\nControl flow types:");
    let mut flows: Vec<_> = flow_counts.iter().collect();
    flows.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

    for (flow, count) in flows.iter().take(10) {
        let percentage = (**count as f64 / instructions.len() as f64) * 100.0;
        println!("  {}: {} ({:.1}%)", flow, count, percentage);
    }

    // Print most common mnemonics
    println!("\nMost common instructions:");
    let mut mnemonics: Vec<_> = mnemonic_counts.iter().collect();
    mnemonics.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

    for (mnemonic, count) in mnemonics.iter().take(10) {
        let percentage = (**count as f64 / instructions.len() as f64) * 100.0;
        println!("  {}: {} ({:.1}%)", mnemonic, count, percentage);
    }

    // Calculate average instruction size
    let total_size: usize = instructions.iter().map(|i| i.size).sum();
    let avg_size = total_size as f64 / instructions.len() as f64;
    println!("\nAverage instruction size: {:.2} bytes", avg_size);

    // Find jumps and calls
    let jumps: Vec<_> = instructions
        .iter()
        .filter(|i| {
            matches!(
                i.flow,
                ControlFlow::Jump(_) | ControlFlow::ConditionalJump(_)
            )
        })
        .collect();

    let calls: Vec<_> = instructions
        .iter()
        .filter(|i| matches!(i.flow, ControlFlow::Call(_)))
        .collect();

    println!("Jumps/branches: {}", jumps.len());
    println!("Function calls: {}", calls.len());
}
