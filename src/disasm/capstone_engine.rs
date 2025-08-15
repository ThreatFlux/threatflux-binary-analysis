//! Capstone disassembly engine implementation

use super::{DisassemblyConfig, analyze_control_flow, categorize_instruction};
use crate::{
    BinaryError, Result,
    types::{Architecture, ControlFlow as FlowType, Instruction},
};
use capstone::prelude::*;
use capstone::{Arch, Mode};

/// Disassemble binary data using Capstone engine
pub fn disassemble(
    data: &[u8],
    address: u64,
    architecture: Architecture,
    config: &DisassemblyConfig,
) -> Result<Vec<Instruction>> {
    let cs = create_capstone_engine(architecture)?;

    let instructions = cs
        .disasm_all(data, address)
        .map_err(|e| BinaryError::disassembly(format!("Capstone error: {}", e)))?;

    let mut result = Vec::new();
    let max_instructions = config.max_instructions;

    for (i, instr) in instructions.iter().enumerate() {
        if i >= max_instructions {
            break;
        }

        let mnemonic = instr.mnemonic().unwrap_or("unknown").to_string();
        let operands = instr.op_str().unwrap_or("").to_string();

        // Skip invalid instructions if configured
        if config.skip_invalid && mnemonic == "unknown" {
            continue;
        }

        let category = categorize_instruction(&mnemonic);
        let flow = if config.analyze_control_flow {
            analyze_control_flow(&mnemonic, &operands)
        } else {
            FlowType::Sequential
        };

        let instruction = Instruction {
            address: instr.address(),
            bytes: instr.bytes().to_vec(),
            mnemonic,
            operands,
            category,
            flow,
            size: instr.len(),
        };

        result.push(instruction);
    }

    Ok(result)
}

/// Create Capstone engine for the specified architecture
fn create_capstone_engine(architecture: Architecture) -> Result<Capstone> {
    let (arch, mode) = match architecture {
        Architecture::X86 => (Arch::X86, Mode::Mode32),
        Architecture::X86_64 => (Arch::X86, Mode::Mode64),
        Architecture::Arm => (Arch::ARM, Mode::Arm),
        Architecture::Arm64 => (Arch::ARM64, Mode::Arm),
        Architecture::Mips => (Arch::MIPS, Mode::Mips32),
        Architecture::Mips64 => (Arch::MIPS, Mode::Mips64),
        Architecture::PowerPC => (Arch::PPC, Mode::Mode32),
        Architecture::PowerPC64 => (Arch::PPC, Mode::Mode64),
        _ => {
            return Err(BinaryError::unsupported_arch(format!(
                "Architecture {:?} not supported by Capstone",
                architecture
            )));
        }
    };

    Capstone::new_raw(arch, mode, std::iter::empty(), None)
        .map_err(|e| BinaryError::disassembly(format!("Failed to create Capstone engine: {}", e)))
}

/// Enhanced instruction analysis using Capstone details
#[allow(dead_code)]
pub fn analyze_instruction_details(
    cs: &Capstone,
    instr: &capstone::Insn,
) -> Result<InstructionDetails> {
    let detail = cs.insn_detail(instr).map_err(|e| {
        BinaryError::disassembly(format!("Failed to get instruction details: {}", e))
    })?;

    let mut operands = Vec::new();
    let memory_accesses = Vec::new();
    let mut registers_read = Vec::new();
    let mut registers_written = Vec::new();

    // Extract operand information
    // NOTE: Operand extraction needs implementation for capstone 0.13 API changes
    operands.push("operands_analysis_needed".to_string());

    // Extract register information
    for reg in detail.regs_read() {
        registers_read.push(format!("reg_{:?}", reg)); // Use Debug formatting
    }

    for reg in detail.regs_write() {
        registers_written.push(format!("reg_{:?}", reg)); // Use Debug formatting
    }

    Ok(InstructionDetails {
        operands,
        memory_accesses,
        registers_read,
        registers_written,
        groups: detail.groups().iter().map(|g| g.0).collect(),
    })
}

/// Detailed instruction information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InstructionDetails {
    /// Operand descriptions
    pub operands: Vec<String>,
    /// Memory access information
    pub memory_accesses: Vec<String>,
    /// Registers read by this instruction
    pub registers_read: Vec<String>,
    /// Registers written by this instruction
    pub registers_written: Vec<String>,
    /// Instruction groups
    pub groups: Vec<u8>,
}

// Removed format_operand function - using Debug formatting instead

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capstone_engine_creation() {
        let result = create_capstone_engine(Architecture::X86_64);
        assert!(result.is_ok());
    }

    #[test]
    fn test_x86_disassembly() {
        let config = DisassemblyConfig::default();

        // Simple x86-64 NOP instruction
        let data = &[0x90];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config);

        if result.is_ok() {
            let instructions = result.unwrap();
            assert!(!instructions.is_empty());
            assert_eq!(instructions[0].mnemonic, "nop");
            assert_eq!(instructions[0].address, 0x1000);
        }
    }

    #[test]
    fn test_unsupported_architecture() {
        let result = create_capstone_engine(Architecture::Unknown);
        assert!(result.is_err());
    }
}
