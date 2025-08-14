//! iced-x86 disassembly engine implementation

use super::{analyze_control_flow, categorize_instruction, DisassemblyConfig};
use crate::{
    types::{Architecture, ControlFlow as FlowType, Instruction, InstructionCategory},
    BinaryError, Result,
};
use iced_x86::*;

/// Disassemble binary data using iced-x86 engine
pub fn disassemble(
    data: &[u8],
    address: u64,
    architecture: Architecture,
    config: &DisassemblyConfig,
) -> Result<Vec<Instruction>> {
    // iced-x86 only supports x86/x64
    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X86_64 => 64,
        _ => {
            return Err(BinaryError::unsupported_arch(format!(
                "iced-x86 only supports x86/x64, got {:?}",
                architecture
            )));
        }
    };

    let mut decoder = create_decoder(bitness, data, address)?;
    let mut formatter = create_formatter();
    let mut result = Vec::new();
    let max_instructions = config.max_instructions;

    let mut instr = iced_x86::Instruction::default();
    let mut count = 0;

    while decoder.can_decode() && count < max_instructions {
        decoder.decode_out(&mut instr);

        if config.skip_invalid && instr.code() == Code::INVALID {
            continue;
        }

        let mut output = String::new();
        formatter.format(&instr, &mut output);

        // Parse mnemonic and operands from formatted output
        let (mnemonic, operands) = parse_formatted_instruction(&output);

        let category = categorize_instruction(&mnemonic);
        let flow = if config.analyze_control_flow {
            analyze_iced_control_flow(&instr, &operands)
        } else {
            FlowType::Sequential
        };

        let instruction_bytes = data
            [((instr.ip() - address) as usize)..((instr.ip() - address) as usize + instr.len())]
            .to_vec();

        let instruction = Instruction {
            address: instr.ip(),
            bytes: instruction_bytes,
            mnemonic,
            operands,
            category,
            flow,
            size: instr.len(),
        };

        result.push(instruction);
        count += 1;
    }

    Ok(result)
}

/// Create iced-x86 decoder
fn create_decoder(bitness: u32, data: &[u8], address: u64) -> Result<Decoder> {
    let decoder_options = DecoderOptions::NONE;

    let decoder = match bitness {
        16 => Decoder::with_ip(16, data, address, decoder_options),
        32 => Decoder::with_ip(32, data, address, decoder_options),
        64 => Decoder::with_ip(64, data, address, decoder_options),
        _ => {
            return Err(BinaryError::unsupported_arch(format!(
                "Unsupported bitness: {}",
                bitness
            )));
        }
    };

    Ok(decoder)
}

/// Create iced-x86 formatter
fn create_formatter() -> NasmFormatter {
    NasmFormatter::new()
}

/// Parse formatted instruction into mnemonic and operands
fn parse_formatted_instruction(formatted: &str) -> (String, String) {
    let parts: Vec<&str> = formatted.trim().splitn(2, ' ').collect();

    let mnemonic = parts[0].to_string();
    let operands = if parts.len() > 1 {
        parts[1].to_string()
    } else {
        String::new()
    };

    (mnemonic, operands)
}

/// Analyze control flow using iced-x86 instruction information
fn analyze_iced_control_flow(instr: &iced_x86::Instruction, operands: &str) -> FlowType {
    match instr.flow_control() {
        FlowControl::Next => FlowType::Sequential,
        FlowControl::UnconditionalBranch => {
            if let Some(target) = get_branch_target(instr) {
                FlowType::Jump(target)
            } else {
                FlowType::Unknown
            }
        }
        FlowControl::ConditionalBranch => {
            if let Some(target) = get_branch_target(instr) {
                FlowType::ConditionalJump(target)
            } else {
                FlowType::Unknown
            }
        }
        FlowControl::Call => {
            if let Some(target) = get_branch_target(instr) {
                FlowType::Call(target)
            } else {
                FlowType::Unknown
            }
        }
        FlowControl::Return => FlowType::Return,
        FlowControl::Interrupt => FlowType::Interrupt,
        FlowControl::IndirectBranch | FlowControl::IndirectCall => FlowType::Unknown,
        FlowControl::Exception => FlowType::Interrupt,
        FlowControl::XbeginXabortXend => FlowType::Unknown,
    }
}

/// Get branch target from instruction
fn get_branch_target(instr: &iced_x86::Instruction) -> Option<u64> {
    for i in 0..instr.op_count() {
        match instr.op_kind(i) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                return Some(instr.near_branch_target());
            }
            _ => continue,
        }
    }
    None
}

/// Enhanced instruction analysis using iced-x86 features
pub fn analyze_instruction_details(instr: &iced_x86::Instruction) -> InstructionDetails {
    let mut operands = Vec::new();
    let mut memory_accesses = Vec::new();
    let mut registers_read = Vec::new();
    let mut registers_written = Vec::new();

    // Analyze operands
    for i in 0..instr.op_count() {
        let operand_info = format_operand_info(instr, i);
        operands.push(operand_info);

        // Check for memory access
        if matches!(instr.op_kind(i), OpKind::Memory) {
            memory_accesses.push(format!("mem_access_{}", i));
        }
    }

    // Get registers used (simplified for now - iced-x86 API may have changed)
    // TODO: Fix register analysis with correct iced-x86 1.21 API
    for i in 0..instr.op_count() {
        if let OpKind::Register = instr.op_kind(i) {
            let reg = instr.op_register(i);
            let reg_name = format!("{:?}", reg);
            
            // For now, assume all registers are both read and written
            // This is a simplification until proper API usage is determined
            registers_read.push(reg_name.clone());
            registers_written.push(reg_name);
        }
    }

    InstructionDetails {
        operands,
        memory_accesses,
        registers_read,
        registers_written,
        encoding: format!("{:?}", instr.encoding()),
        cpuid_features: get_cpuid_features(instr),
        stack_pointer_increment: instr.stack_pointer_increment(),
    }
}

/// Detailed instruction information for iced-x86
#[derive(Debug, Clone)]
pub struct InstructionDetails {
    /// Operand descriptions
    pub operands: Vec<String>,
    /// Memory access information
    pub memory_accesses: Vec<String>,
    /// Registers read by this instruction
    pub registers_read: Vec<String>,
    /// Registers written by this instruction
    pub registers_written: Vec<String>,
    /// Instruction encoding
    pub encoding: String,
    /// Required CPU features
    pub cpuid_features: Vec<String>,
    /// Stack pointer increment
    pub stack_pointer_increment: i32,
}

/// Format operand information
fn format_operand_info(instr: &iced_x86::Instruction, operand_index: u32) -> String {
    match instr.op_kind(operand_index) {
        OpKind::Register => {
            format!("reg:{:?}", instr.op_register(operand_index))
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            format!("branch:0x{:x}", instr.near_branch_target())
        }
        OpKind::FarBranch16 | OpKind::FarBranch32 => {
            format!(
                "far_branch:0x{:x}:0x{:x}",
                instr.far_branch_selector(),
                instr.far_branch32()
            )
        }
        OpKind::Immediate8 => {
            format!("imm8:0x{:x}", instr.immediate8())
        }
        OpKind::Immediate16 => {
            format!("imm16:0x{:x}", instr.immediate16())
        }
        OpKind::Immediate32 => {
            format!("imm32:0x{:x}", instr.immediate32())
        }
        OpKind::Immediate64 => {
            format!("imm64:0x{:x}", instr.immediate64())
        }
        OpKind::Immediate8to16 => {
            format!("imm8to16:0x{:x}", instr.immediate8to16())
        }
        OpKind::Immediate8to32 => {
            format!("imm8to32:0x{:x}", instr.immediate8to32())
        }
        OpKind::Immediate8to64 => {
            format!("imm8to64:0x{:x}", instr.immediate8to64())
        }
        OpKind::Immediate32to64 => {
            format!("imm32to64:0x{:x}", instr.immediate32to64())
        }
        OpKind::Memory => {
            format!(
                "mem:[{:?}+{:?}*{}+0x{:x}]",
                instr.memory_base(),
                instr.memory_index(),
                instr.memory_index_scale(),
                instr.memory_displacement64()
            )
        }
        _ => format!("operand_{}", operand_index),
    }
}

/// Get required CPUID features for instruction
fn get_cpuid_features(instr: &iced_x86::Instruction) -> Vec<String> {
    let mut features = Vec::new();

    for feature in instr.cpuid_features() {
        features.push(format!("{:?}", feature));
    }

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iced_engine_x86_64() {
        let config = DisassemblyConfig::default();

        // Simple x86-64 NOP instruction
        let data = &[0x90];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config);

        assert!(result.is_ok());
        let instructions = result.unwrap();
        assert!(!instructions.is_empty());
        assert_eq!(instructions[0].mnemonic, "nop");
        assert_eq!(instructions[0].address, 0x1000);
    }

    #[test]
    fn test_iced_engine_x86() {
        let config = DisassemblyConfig::default();

        // Simple x86 NOP instruction
        let data = &[0x90];
        let result = disassemble(data, 0x1000, Architecture::X86, &config);

        assert!(result.is_ok());
        let instructions = result.unwrap();
        assert!(!instructions.is_empty());
    }

    #[test]
    fn test_unsupported_architecture() {
        let config = DisassemblyConfig::default();
        let data = &[0x90];
        let result = disassemble(data, 0x1000, Architecture::Arm, &config);

        assert!(result.is_err());
    }

    #[test]
    fn test_instruction_parsing() {
        let (mnemonic, operands) = parse_formatted_instruction("mov eax, ebx");
        assert_eq!(mnemonic, "mov");
        assert_eq!(operands, "eax, ebx");

        let (mnemonic, operands) = parse_formatted_instruction("nop");
        assert_eq!(mnemonic, "nop");
        assert_eq!(operands, "");
    }
}
