//! Disassembly module supporting multiple disassembly engines
//!
//! This module provides disassembly capabilities using both Capstone and iced-x86 engines.
//! The choice of engine can be configured based on requirements and availability.

use crate::{
    types::{Architecture, Instruction, InstructionCategory},
    AnalysisConfig, BinaryError, BinaryFile, Result,
};

#[cfg(feature = "disasm-capstone")]
use crate::types::ControlFlow as FlowType;

#[cfg(feature = "disasm-capstone")]
mod capstone_engine;

#[cfg(feature = "disasm-iced")]
mod iced_engine;

/// Disassembly engine selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisassemblyEngine {
    /// Use Capstone disassembly engine
    #[cfg(feature = "disasm-capstone")]
    Capstone,
    /// Use iced-x86 disassembly engine  
    #[cfg(feature = "disasm-iced")]
    Iced,
    /// Automatic engine selection
    Auto,
}

/// Disassembly configuration
#[derive(Debug, Clone)]
pub struct DisassemblyConfig {
    /// Preferred disassembly engine
    pub engine: DisassemblyEngine,
    /// Maximum number of instructions to disassemble
    pub max_instructions: usize,
    /// Include instruction details (operands, etc.)
    pub detailed: bool,
    /// Enable control flow analysis
    pub analyze_control_flow: bool,
    /// Skip invalid instructions
    pub skip_invalid: bool,
}

impl Default for DisassemblyConfig {
    fn default() -> Self {
        Self {
            engine: DisassemblyEngine::Auto,
            max_instructions: 10000,
            detailed: true,
            analyze_control_flow: true,
            skip_invalid: true,
        }
    }
}

/// Disassembler wrapper supporting multiple engines
pub struct Disassembler {
    config: DisassemblyConfig,
    architecture: Architecture,
}

impl Disassembler {
    /// Create a new disassembler for the specified architecture
    pub fn new(architecture: Architecture) -> Result<Self> {
        Ok(Self {
            config: DisassemblyConfig::default(),
            architecture,
        })
    }

    /// Create disassembler with custom configuration
    pub fn with_config(architecture: Architecture, config: DisassemblyConfig) -> Result<Self> {
        Ok(Self {
            config,
            architecture,
        })
    }

    /// Disassemble binary code
    pub fn disassemble(&self, data: &[u8], address: u64) -> Result<Vec<Instruction>> {
        let engine = self.select_engine()?;

        match engine {
            #[cfg(feature = "disasm-capstone")]
            DisassemblyEngine::Capstone => {
                capstone_engine::disassemble(data, address, self.architecture, &self.config)
            }
            #[cfg(feature = "disasm-iced")]
            DisassemblyEngine::Iced => {
                iced_engine::disassemble(data, address, self.architecture, &self.config)
            }
            DisassemblyEngine::Auto => {
                // Try available engines in order of preference
                #[cfg(feature = "disasm-capstone")]
                {
                    capstone_engine::disassemble(data, address, self.architecture, &self.config)
                }
                #[cfg(all(feature = "disasm-iced", not(feature = "disasm-capstone")))]
                {
                    iced_engine::disassemble(data, address, self.architecture, &self.config)
                }
                #[cfg(not(any(feature = "disasm-capstone", feature = "disasm-iced")))]
                {
                    Err(BinaryError::feature_not_available(
                        "No disassembly engine available. Enable 'disasm-capstone' or 'disasm-iced' feature.",
                    ))
                }
            }
        }
    }

    /// Disassemble a specific section of a binary
    pub fn disassemble_section(
        &self,
        binary: &BinaryFile,
        section_name: &str,
    ) -> Result<Vec<Instruction>> {
        for section in binary.sections() {
            if section.name == section_name {
                if let Some(data) = &section.data {
                    return self.disassemble(data, section.address);
                } else {
                    // Section data not available, would need to read from file
                    return Err(BinaryError::invalid_data(
                        "Section data not available for disassembly",
                    ));
                }
            }
        }

        Err(BinaryError::invalid_data(format!(
            "Section '{}' not found",
            section_name
        )))
    }

    /// Disassemble code at specific address with length
    pub fn disassemble_at(
        &self,
        data: &[u8],
        address: u64,
        length: usize,
    ) -> Result<Vec<Instruction>> {
        if data.len() < length {
            return Err(BinaryError::invalid_data(
                "Insufficient data for disassembly",
            ));
        }

        self.disassemble(&data[..length], address)
    }

    /// Select the appropriate disassembly engine
    fn select_engine(&self) -> Result<DisassemblyEngine> {
        match self.config.engine {
            #[cfg(feature = "disasm-capstone")]
            DisassemblyEngine::Capstone => Ok(DisassemblyEngine::Capstone),
            #[cfg(feature = "disasm-iced")]
            DisassemblyEngine::Iced => Ok(DisassemblyEngine::Iced),
            DisassemblyEngine::Auto => {
                // Select best engine for architecture
                match self.architecture {
                    Architecture::X86 | Architecture::X86_64 => {
                        #[cfg(feature = "disasm-iced")]
                        {
                            Ok(DisassemblyEngine::Iced)
                        }
                        #[cfg(all(feature = "disasm-capstone", not(feature = "disasm-iced")))]
                        {
                            Ok(DisassemblyEngine::Capstone)
                        }
                        #[cfg(not(any(feature = "disasm-capstone", feature = "disasm-iced")))]
                        {
                            Err(BinaryError::feature_not_available(
                                "No disassembly engine available",
                            ))
                        }
                    }
                    _ => {
                        // For non-x86 architectures, prefer Capstone
                        #[cfg(feature = "disasm-capstone")]
                        {
                            Ok(DisassemblyEngine::Capstone)
                        }
                        #[cfg(not(feature = "disasm-capstone"))]
                        {
                            Err(BinaryError::unsupported_arch(format!(
                                "Architecture {:?} requires Capstone engine",
                                self.architecture
                            )))
                        }
                    }
                }
            }
        }
    }
}

/// High-level function to disassemble binary data
pub fn disassemble_binary(
    binary: &BinaryFile,
    config: &AnalysisConfig,
) -> Result<Vec<Instruction>> {
    let disasm_config = DisassemblyConfig {
        engine: config.disassembly_engine,
        max_instructions: config.max_analysis_size / 16, // Estimate ~16 bytes per instruction
        detailed: true,
        analyze_control_flow: true,
        skip_invalid: true,
    };

    let disassembler = Disassembler::with_config(binary.architecture(), disasm_config)?;

    let mut all_instructions = Vec::new();

    // Disassemble executable sections
    for section in binary.sections() {
        if section.permissions.execute {
            if let Some(data) = &section.data {
                match disassembler.disassemble(data, section.address) {
                    Ok(mut instructions) => {
                        all_instructions.append(&mut instructions);
                    }
                    Err(_) => {
                        // Continue with other sections if one fails
                        continue;
                    }
                }
            }
        }
    }

    Ok(all_instructions)
}

/// Determine instruction category from mnemonic
fn categorize_instruction(mnemonic: &str) -> InstructionCategory {
    let mnemonic_lower = mnemonic.to_lowercase();

    if mnemonic_lower.starts_with("add")
        || mnemonic_lower.starts_with("sub")
        || mnemonic_lower.starts_with("mul")
        || mnemonic_lower.starts_with("div")
        || mnemonic_lower.starts_with("inc")
        || mnemonic_lower.starts_with("dec")
    {
        InstructionCategory::Arithmetic
    } else if mnemonic_lower.starts_with("and")
        || mnemonic_lower.starts_with("or")
        || mnemonic_lower.starts_with("xor")
        || mnemonic_lower.starts_with("not")
        || mnemonic_lower.starts_with("shl")
        || mnemonic_lower.starts_with("shr")
    {
        InstructionCategory::Logic
    } else if mnemonic_lower.starts_with("mov")
        || mnemonic_lower.starts_with("lea")
        || mnemonic_lower.starts_with("push")
        || mnemonic_lower.starts_with("pop")
        || mnemonic_lower.starts_with("load")
        || mnemonic_lower.starts_with("store")
    {
        InstructionCategory::Memory
    } else if mnemonic_lower.starts_with("jmp")
        || mnemonic_lower.starts_with("je")
        || mnemonic_lower.starts_with("jne")
        || mnemonic_lower.starts_with("jz")
        || mnemonic_lower.starts_with("jnz")
        || mnemonic_lower.starts_with("call")
        || mnemonic_lower.starts_with("ret")
        || mnemonic_lower.starts_with("br")
        || mnemonic_lower.starts_with("bl")
    {
        InstructionCategory::Control
    } else if mnemonic_lower.starts_with("int")
        || mnemonic_lower.starts_with("syscall")
        || mnemonic_lower.starts_with("sysenter")
        || mnemonic_lower.starts_with("sysexit")
    {
        InstructionCategory::System
    } else if mnemonic_lower.contains("aes")
        || mnemonic_lower.contains("sha")
        || mnemonic_lower.contains("crypto")
    {
        InstructionCategory::Crypto
    } else if mnemonic_lower.starts_with("fadd")
        || mnemonic_lower.starts_with("fsub")
        || mnemonic_lower.starts_with("fmul")
        || mnemonic_lower.starts_with("fdiv")
    {
        InstructionCategory::Float
    } else if mnemonic_lower.contains("xmm")
        || mnemonic_lower.contains("ymm")
        || mnemonic_lower.contains("zmm")
        || mnemonic_lower.starts_with("v")
    {
        InstructionCategory::Vector
    } else {
        InstructionCategory::Unknown
    }
}

/// Determine control flow type from instruction
#[cfg(feature = "disasm-capstone")]
fn analyze_control_flow(mnemonic: &str, operands: &str) -> FlowType {
    let mnemonic_lower = mnemonic.to_lowercase();

    if mnemonic_lower == "ret" || mnemonic_lower == "retn" {
        FlowType::Return
    } else if mnemonic_lower == "call" {
        // Try to extract target address from operands
        if let Some(addr) = extract_address_from_operands(operands) {
            FlowType::Call(addr)
        } else {
            FlowType::Unknown // Indirect call
        }
    } else if mnemonic_lower.starts_with("jmp") {
        if let Some(addr) = extract_address_from_operands(operands) {
            FlowType::Jump(addr)
        } else {
            FlowType::Unknown // Indirect jump
        }
    } else if mnemonic_lower.starts_with('j') && mnemonic_lower.len() > 1 {
        // Conditional jumps
        if let Some(addr) = extract_address_from_operands(operands) {
            FlowType::ConditionalJump(addr)
        } else {
            FlowType::Unknown // Indirect conditional jump
        }
    } else if mnemonic_lower == "int" || mnemonic_lower == "syscall" {
        FlowType::Interrupt
    } else {
        FlowType::Sequential
    }
}

/// Extract address from instruction operands (simplified)
#[cfg(feature = "disasm-capstone")]
fn extract_address_from_operands(operands: &str) -> Option<u64> {
    // This is a simplified implementation
    // Real implementation would need proper operand parsing

    // Look for hex addresses
    if let Some(hex_part) = operands.strip_prefix("0x") {
        if let Ok(addr) = u64::from_str_radix(hex_part, 16) {
            return Some(addr);
        }
    }

    // Look for decimal addresses
    if let Ok(addr) = operands.parse::<u64>() {
        return Some(addr);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_disassembler_creation() {
        let result = Disassembler::new(Architecture::X86_64);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_default() {
        let config = DisassemblyConfig::default();
        assert_eq!(config.engine, DisassemblyEngine::Auto);
        assert_eq!(config.max_instructions, 10000);
        assert!(config.detailed);
        assert!(config.analyze_control_flow);
    }

    #[test]
    fn test_instruction_categorization() {
        assert_eq!(
            categorize_instruction("add"),
            InstructionCategory::Arithmetic
        );
        assert_eq!(categorize_instruction("mov"), InstructionCategory::Memory);
        assert_eq!(categorize_instruction("jmp"), InstructionCategory::Control);
        assert_eq!(categorize_instruction("and"), InstructionCategory::Logic);
        assert_eq!(
            categorize_instruction("syscall"),
            InstructionCategory::System
        );
    }

    #[test]
    #[cfg(feature = "disasm-capstone")]
    fn test_control_flow_analysis() {
        assert_eq!(analyze_control_flow("ret", ""), FlowType::Return);
        assert_eq!(
            analyze_control_flow("call", "0x1000"),
            FlowType::Call(0x1000)
        );
        assert_eq!(
            analyze_control_flow("jmp", "0x2000"),
            FlowType::Jump(0x2000)
        );
        assert_eq!(
            analyze_control_flow("je", "0x3000"),
            FlowType::ConditionalJump(0x3000)
        );
        assert_eq!(
            analyze_control_flow("mov", "eax, ebx"),
            FlowType::Sequential
        );
    }

    #[test]
    #[cfg(feature = "disasm-capstone")]
    fn test_address_extraction() {
        assert_eq!(extract_address_from_operands("0x1000"), Some(0x1000));
        assert_eq!(extract_address_from_operands("4096"), Some(4096));
        assert_eq!(extract_address_from_operands("eax"), None);
    }
}
