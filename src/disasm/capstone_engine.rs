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
    if config.max_instructions == 0 || data.is_empty() {
        return Ok(Vec::new());
    }

    let cs = create_capstone_engine(architecture)?;

    let instructions = cs
        .disasm_count(data, address, config.max_instructions)
        .map_err(|e| BinaryError::disassembly(format!("Capstone error: {}", e)))?;

    let mut result = Vec::with_capacity(instructions.len());

    for instr in instructions.iter() {
        let mnemonic = instr.mnemonic().unwrap_or("unknown").to_string();
        let raw_operands = instr.op_str().unwrap_or("");

        // Skip invalid instructions if configured
        if config.skip_invalid && mnemonic == "unknown" {
            continue;
        }

        let category = categorize_instruction(&mnemonic);
        let flow = if config.analyze_control_flow {
            analyze_control_flow(&mnemonic, raw_operands)
        } else {
            FlowType::Sequential
        };
        let operands = if config.detailed {
            raw_operands.to_string()
        } else {
            String::new()
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

        if let Ok(instructions) = result {
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

    #[test]
    fn test_complex_instruction_sequence() {
        let config = DisassemblyConfig {
            analyze_control_flow: true,
            ..DisassemblyConfig::default()
        };

        // Function prologue + epilogue: push rbp; mov rbp, rsp; ret
        let data = &[0x55, 0x48, 0x89, 0xe5, 0xc3];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].mnemonic, "push");
        assert_eq!(result[1].mnemonic, "mov");
        assert_eq!(result[2].mnemonic, "ret");
        assert_eq!(result[2].flow, FlowType::Return);
    }

    #[test]
    fn test_instruction_bytes_accuracy() {
        let config = DisassemblyConfig::default();
        let base_addr = 0x1000;

        let test_cases = vec![
            (&[0x90u8][..], 1usize),                  // NOP
            (&[0x89, 0xd8][..], 2),                   // MOV EAX, EBX
            (&[0x0f, 0x10, 0xc1][..], 3),             // MOVUPS XMM0, XMM1
            (&[0xb8, 0x00, 0x10, 0x00, 0x00][..], 5), // MOV EAX, imm32
        ];

        for (data, expected_size) in test_cases {
            let result = disassemble(data, base_addr, Architecture::X86_64, &config).unwrap();
            assert_eq!(result[0].size, expected_size);
            assert_eq!(result[0].bytes.len(), expected_size);
            assert_eq!(result[0].bytes, data);
        }
    }

    #[test]
    fn zero_instruction_limit_returns_without_disassembling() {
        let config = DisassemblyConfig {
            max_instructions: 0,
            ..DisassemblyConfig::default()
        };

        assert!(
            disassemble(&[0x90], 0x1000, Architecture::X86_64, &config)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn compact_output_preserves_flow_analysis() {
        let config = DisassemblyConfig {
            detailed: false,
            analyze_control_flow: true,
            ..DisassemblyConfig::default()
        };
        let instructions =
            disassemble(&[0xe8, 0, 0, 0, 0], 0x1000, Architecture::X86_64, &config).unwrap();

        assert!(instructions[0].operands.is_empty());
        assert_eq!(instructions[0].flow, FlowType::Call(0x1005));
    }
}
