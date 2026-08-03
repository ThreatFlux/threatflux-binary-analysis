//! iced-x86 disassembly engine implementation

use super::{DisassemblyConfig, categorize_instruction};
use crate::{
    BinaryError, Result,
    types::{Architecture, ControlFlow as FlowType, Instruction},
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
    let mut result = Vec::with_capacity(config.max_instructions.min(data.len()));
    let max_instructions = config.max_instructions;

    let mut instr = iced_x86::Instruction::default();
    let mut decoded_count = 0;

    while decoder.can_decode() && decoded_count < max_instructions {
        let instruction_start = decoder.position();
        decoder.decode_out(&mut instr);
        let instruction_end = decoder.position();
        decoded_count += 1;

        if config.skip_invalid && instr.code() == Code::INVALID {
            continue;
        }

        let mut output = String::new();
        formatter.format(&instr, &mut output);

        // Parse mnemonic and operands from formatted output
        let (mnemonic, raw_operands) = parse_formatted_instruction(&output);

        let category = categorize_instruction(&mnemonic);
        let flow = if config.analyze_control_flow {
            analyze_iced_control_flow(&instr, &raw_operands)
        } else {
            FlowType::Sequential
        };
        let operands = if config.detailed {
            raw_operands
        } else {
            String::new()
        };

        let instruction_bytes = data[instruction_start..instruction_end].to_vec();

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
    }

    Ok(result)
}

/// Create iced-x86 decoder
fn create_decoder(bitness: u32, data: &[u8], address: u64) -> Result<Decoder<'_>> {
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
fn analyze_iced_control_flow(instr: &iced_x86::Instruction, _operands: &str) -> FlowType {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ControlFlow as FlowType, InstructionCategory};

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

    #[test]
    fn test_arithmetic_instructions_x86_64() {
        let config = DisassemblyConfig::default();

        // ADD EAX, EBX (01 d8)
        let data = &[0x01, 0xd8];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Arithmetic);
        assert_eq!(result[0].mnemonic, "add");

        // SUB EAX, EBX (29 d8)
        let data = &[0x29, 0xd8];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Arithmetic);
        assert_eq!(result[0].mnemonic, "sub");

        // INC EAX (ff c0)
        let data = &[0xff, 0xc0];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Arithmetic);
        assert_eq!(result[0].mnemonic, "inc");

        // DEC EAX (ff c8)
        let data = &[0xff, 0xc8];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Arithmetic);
        assert_eq!(result[0].mnemonic, "dec");
    }

    #[test]
    fn test_logic_instructions_x86_64() {
        let config = DisassemblyConfig::default();

        // AND EAX, EBX (21 d8)
        let data = &[0x21, 0xd8];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Logic);
        assert_eq!(result[0].mnemonic, "and");

        // OR EAX, EBX (09 d8)
        let data = &[0x09, 0xd8];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Logic);
        assert_eq!(result[0].mnemonic, "or");

        // XOR EAX, EAX (31 c0)
        let data = &[0x31, 0xc0];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Logic);
        assert_eq!(result[0].mnemonic, "xor");
    }

    #[test]
    fn test_memory_instructions_x86_64() {
        let config = DisassemblyConfig::default();

        // MOV EAX, EBX (89 d8)
        let data = &[0x89, 0xd8];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Memory);
        assert_eq!(result[0].mnemonic, "mov");

        // PUSH EAX (50)
        let data = &[0x50];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Memory);
        assert_eq!(result[0].mnemonic, "push");

        // POP EAX (58)
        let data = &[0x58];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Memory);
        assert_eq!(result[0].mnemonic, "pop");
    }

    #[test]
    fn test_control_instructions_x86_64() {
        let config = DisassemblyConfig {
            analyze_control_flow: true,
            ..DisassemblyConfig::default()
        };

        // JMP short +5 (eb 05)
        let data = &[0xeb, 0x05];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Control);
        assert_eq!(result[0].mnemonic, "jmp");
        if let FlowType::Jump(target) = result[0].flow {
            assert_eq!(target, 0x1007); // 0x1000 + 2 + 5
        } else {
            panic!("Expected Jump flow type");
        }

        // JE short +3 (74 03)
        let data = &[0x74, 0x03];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Control);
        assert_eq!(result[0].mnemonic, "je");
        if let FlowType::ConditionalJump(target) = result[0].flow {
            assert_eq!(target, 0x1005); // 0x1000 + 2 + 3
        } else {
            panic!("Expected ConditionalJump flow type");
        }

        // CALL near (e8 00 00 00 00)
        let data = &[0xe8, 0x00, 0x00, 0x00, 0x00];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Control);
        assert_eq!(result[0].mnemonic, "call");
        if let FlowType::Call(target) = result[0].flow {
            assert_eq!(target, 0x1005); // 0x1000 + 5 + 0
        } else {
            panic!("Expected Call flow type");
        }

        // RET (c3)
        let data = &[0xc3];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Control);
        assert_eq!(result[0].mnemonic, "ret");
        assert_eq!(result[0].flow, FlowType::Return);
    }

    #[test]
    fn test_system_instructions_x86_64() {
        let config = DisassemblyConfig {
            analyze_control_flow: true,
            ..DisassemblyConfig::default()
        };

        // INT 3 (cc)
        let data = &[0xcc];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::System);
        assert_eq!(result[0].mnemonic, "int3");
        assert_eq!(result[0].flow, FlowType::Interrupt);

        // SYSCALL (0f 05) - iced-x86 categorizes this as Unknown flow type
        let data = &[0x0f, 0x05];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::System);
        assert_eq!(result[0].mnemonic, "syscall");
        // iced-x86 categorizes SYSCALL differently than INT3
        assert!(matches!(
            result[0].flow,
            FlowType::Interrupt | FlowType::Unknown
        ));
    }

    #[test]
    fn test_float_instructions_x86_64() {
        let config = DisassemblyConfig::default();

        // FADD ST(0), ST(1) (d8 c1)
        let data = &[0xd8, 0xc1];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Float);
        assert!(result[0].mnemonic.starts_with("fadd"));
    }

    #[test]
    fn test_control_flow_analysis_disabled() {
        let config = DisassemblyConfig {
            analyze_control_flow: false,
            ..DisassemblyConfig::default()
        };

        // JMP short +5 (eb 05)
        let data = &[0xeb, 0x05];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].flow, FlowType::Sequential);
    }

    #[test]
    fn test_skip_invalid_instructions() {
        let config = DisassemblyConfig {
            skip_invalid: true,
            ..DisassemblyConfig::default()
        };

        // Mix valid and invalid bytes
        let data = &[0x90, 0xff, 0xff, 0xff, 0x90]; // NOP, invalid bytes, NOP
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();

        // Should skip invalid instruction and only return valid ones
        assert!(!result.is_empty());
        assert_eq!(result[0].mnemonic, "nop");
    }

    #[test]
    fn test_max_instructions_limit() {
        let config = DisassemblyConfig {
            max_instructions: 2,
            ..DisassemblyConfig::default()
        };

        // Multiple NOPs
        let data = &[0x90, 0x90, 0x90, 0x90, 0x90]; // 5 NOPs
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();

        // Should only return 2 instructions due to limit
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].mnemonic, "nop");
        assert_eq!(result[1].mnemonic, "nop");
    }

    #[test]
    fn test_empty_data() {
        let config = DisassemblyConfig::default();
        let data = &[];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_single_byte_instruction() {
        let config = DisassemblyConfig::default();

        // NOP (0x90)
        let data = &[0x90];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].mnemonic, "nop");
        assert_eq!(result[0].size, 1);
        assert_eq!(result[0].bytes, vec![0x90]);
    }

    #[test]
    fn test_multi_byte_instruction() {
        let config = DisassemblyConfig::default();

        // MOV EAX, immediate (b8 + 4 bytes)
        let data = &[0xb8, 0x00, 0x10, 0x00, 0x00];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].mnemonic, "mov");
        assert_eq!(result[0].size, 5);
        assert_eq!(result[0].bytes, vec![0xb8, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_instruction_addressing() {
        let config = DisassemblyConfig::default();
        let base_addr = 0x401000;

        // Multiple instructions with different addresses
        let data = &[0x90, 0x90, 0x90]; // 3 NOPs
        let result = disassemble(data, base_addr, Architecture::X86_64, &config).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].address, base_addr);
        assert_eq!(result[1].address, base_addr + 1);
        assert_eq!(result[2].address, base_addr + 2);
    }

    #[test]
    fn test_x86_32bit_mode() {
        let config = DisassemblyConfig::default();

        // Test 32-bit specific instruction
        let data = &[0x90]; // NOP
        let result = disassemble(data, 0x1000, Architecture::X86, &config).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].mnemonic, "nop");
    }

    #[test]
    fn test_create_decoder_bitness() {
        // Test 16-bit
        let result = create_decoder(16, &[0x90], 0x1000);
        assert!(result.is_ok());

        // Test 32-bit
        let result = create_decoder(32, &[0x90], 0x1000);
        assert!(result.is_ok());

        // Test 64-bit
        let result = create_decoder(64, &[0x90], 0x1000);
        assert!(result.is_ok());

        // Test invalid bitness
        let result = create_decoder(128, &[0x90], 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_formatter() {
        let formatter = create_formatter();
        // Just verify it creates without panicking
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_parse_formatted_instruction_edge_cases() {
        // Test instruction with multiple operands
        let (mnemonic, operands) = parse_formatted_instruction("add eax, ebx, ecx");
        assert_eq!(mnemonic, "add");
        assert_eq!(operands, "eax, ebx, ecx");

        // Test instruction with whitespace - note: the function trims the input but not the operands
        let (mnemonic, operands) = parse_formatted_instruction("  mov   eax, ebx  ");
        assert_eq!(mnemonic, "mov");
        assert_eq!(operands, "  eax, ebx"); // The trailing spaces of the whole string are trimmed, but internal spaces remain

        // Test empty string
        let (mnemonic, operands) = parse_formatted_instruction("");
        assert_eq!(mnemonic, "");
        assert_eq!(operands, "");

        // Test single word with spaces
        let (mnemonic, operands) = parse_formatted_instruction("  ret  ");
        assert_eq!(mnemonic, "ret");
        assert_eq!(operands, "");
    }

    #[test]
    fn test_analyze_iced_control_flow_variants() {
        use iced_x86::*;

        // Create a simple instruction for testing
        let mut decoder = Decoder::with_ip(64, &[0x90], 0x1000, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);

        // Test with different flow control types by modifying the instruction
        // Note: This is a simplified test as we can't easily create all instruction types
        let flow = analyze_iced_control_flow(&instr, "");
        assert_eq!(flow, FlowType::Sequential); // NOP should be sequential
    }

    #[test]
    fn test_get_branch_target() {
        use iced_x86::*;

        // Test with jump instruction
        let data = &[0xeb, 0x05]; // JMP +5
        let mut decoder = Decoder::with_ip(64, data, 0x1000, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);

        let target = get_branch_target(&instr);
        assert!(target.is_some());
        assert_eq!(target.unwrap(), 0x1007);

        // Test with non-branch instruction
        let data = &[0x90]; // NOP
        let mut decoder = Decoder::with_ip(64, data, 0x1000, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);

        let target = get_branch_target(&instr);
        assert!(target.is_none());
    }

    #[test]
    fn test_complex_instruction_sequence() {
        let config = DisassemblyConfig {
            analyze_control_flow: true,
            ..DisassemblyConfig::default()
        };

        // Complex sequence: PUSH EBP, MOV EBP ESP, RET
        let data = &[0x55, 0x89, 0xe5, 0xc3]; // Function prologue + epilogue
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].mnemonic, "push");
        assert_eq!(result[1].mnemonic, "mov");
        assert_eq!(result[2].mnemonic, "ret");
        assert_eq!(result[2].flow, FlowType::Return);
    }

    #[test]
    fn test_vector_instructions() {
        let config = DisassemblyConfig::default();

        // MOVUPS XMM0, XMM1 (0f 10 c1) - this is categorized as Memory in the current implementation
        // because it's a MOV instruction. The categorization is based on mnemonic prefix, not operand types.
        let data = &[0x0f, 0x10, 0xc1];
        let result = disassemble(data, 0x1000, Architecture::X86_64, &config).unwrap();
        assert_eq!(result[0].category, InstructionCategory::Memory); // Current behavior
        assert_eq!(result[0].mnemonic, "movups");

        // For true vector categorization, we would need AVX instructions with V prefix
        // But let's test what we can with the current categorization logic
        // The categorize_instruction function looks for "xmm", "ymm", "zmm" or starts with "v"
        // So MOVUPS doesn't match the vector pattern in the current implementation
    }

    #[test]
    fn test_instruction_bytes_accuracy() {
        let config = DisassemblyConfig::default();
        let base_addr = 0x1000;

        // Test various instruction lengths
        let test_cases = vec![
            (&[0x90][..], 1),                         // NOP (1 byte)
            (&[0x89, 0xd8][..], 2),                   // MOV EAX, EBX (2 bytes)
            (&[0x0f, 0x10, 0xc1][..], 3),             // MOVUPS (3 bytes)
            (&[0xb8, 0x00, 0x10, 0x00, 0x00][..], 5), // MOV EAX, imm32 (5 bytes)
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

    #[test]
    fn instruction_bytes_do_not_depend_on_wrapping_instruction_pointer_math() {
        let config = DisassemblyConfig::default();
        let instructions =
            disassemble(&[0x90, 0x90], u64::MAX, Architecture::X86_64, &config).unwrap();

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].bytes, vec![0x90]);
        assert_eq!(instructions[1].bytes, vec![0x90]);
    }
}
