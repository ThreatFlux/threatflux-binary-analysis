//! Disassembly module supporting multiple disassembly engines
//!
//! This module provides disassembly capabilities using both Capstone and iced-x86 engines.
//! The choice of engine can be configured based on requirements and availability.

use crate::{
    AnalysisConfig, BinaryError, BinaryFile, Result,
    types::{Architecture, Instruction, InstructionCategory, Section},
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
        let byte_length = u64::try_from(data.len()).map_err(|_| {
            BinaryError::invalid_data("Disassembly byte length does not fit in u64")
        })?;
        address.checked_add(byte_length).ok_or_else(|| {
            BinaryError::invalid_data(format!(
                "Disassembly address range {address:#x} + {} bytes overflows u64",
                data.len()
            ))
        })?;

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
                let data = section_file_data(binary, section, 0, None)?;
                return self.disassemble(data, section.address);
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

/// Resolve a checked file-backed range within a section.
///
/// `Section::data` is only an inline preview for small sections. Analysis must use
/// the owning `BinaryFile` so large sections are not silently skipped.
pub(crate) fn section_file_data<'a>(
    binary: &'a BinaryFile,
    section: &Section,
    relative_offset: u64,
    requested_length: Option<usize>,
) -> Result<&'a [u8]> {
    if relative_offset > section.size || relative_offset > section.file_size {
        return Err(BinaryError::invalid_data(format!(
            "Offset {relative_offset} is outside section '{}'",
            section.name
        )));
    }

    let file_offset = section
        .offset
        .checked_add(relative_offset)
        .ok_or_else(|| BinaryError::invalid_data("Section file offset overflows"))?;
    let start = usize::try_from(file_offset)
        .map_err(|_| BinaryError::invalid_data("Section file offset does not fit in memory"))?;
    let data = binary.data();
    if start > data.len() {
        return Err(BinaryError::invalid_data(format!(
            "Section '{}' starts beyond the end of the file",
            section.name
        )));
    }

    let virtual_remaining = section.size - relative_offset;
    let file_remaining = section.file_size - relative_offset;
    let section_remaining =
        usize::try_from(virtual_remaining.min(file_remaining)).unwrap_or(usize::MAX);
    let available = data.len() - start;
    let length = requested_length
        .unwrap_or(section_remaining)
        .min(section_remaining);
    if length > available {
        return Err(BinaryError::invalid_data(format!(
            "Section '{}' declares {length} file-backed bytes at offset {file_offset}, but only {available} remain",
            section.name
        )));
    }
    let end = start
        .checked_add(length)
        .ok_or_else(|| BinaryError::invalid_data("Section file range overflows"))?;
    data.get(start..end)
        .ok_or_else(|| BinaryError::invalid_data("Section file range is out of bounds"))
}

/// High-level function to disassemble binary data
pub fn disassemble_binary(
    binary: &BinaryFile,
    config: &AnalysisConfig,
) -> Result<Vec<Instruction>> {
    let architecture = config.architecture_hint.unwrap_or(binary.architecture());
    let mut disasm_config = DisassemblyConfig {
        engine: config.disassembly_engine,
        max_instructions: config.max_disassembly_instructions,
        detailed: true,
        analyze_control_flow: true,
        skip_invalid: true,
    };

    let mut all_instructions = Vec::new();
    let mut remaining_bytes = config.max_analysis_size;
    let mut remaining_instructions = disasm_config.max_instructions;
    let mut successful_sections = 0_usize;
    let mut last_error = None;

    let mut executable_sections: Vec<_> = binary
        .sections()
        .iter()
        .filter(|section| section.permissions.execute)
        .collect();
    executable_sections.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.offset.cmp(&right.offset))
            .then_with(|| left.name.cmp(&right.name))
    });

    // Disassemble executable sections
    for section in executable_sections {
        if remaining_bytes == 0 || remaining_instructions == 0 {
            break;
        }

        let data = match section_file_data(binary, section, 0, Some(remaining_bytes)) {
            Ok(data) => data,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        remaining_bytes -= data.len();
        disasm_config.max_instructions = remaining_instructions;
        let disassembler = Disassembler::with_config(architecture, disasm_config.clone())?;

        match disassembler.disassemble(data, section.address) {
            Ok(mut instructions) => {
                successful_sections += 1;
                remaining_instructions = remaining_instructions.saturating_sub(instructions.len());
                all_instructions.append(&mut instructions);
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }

    if let (0, Some(error)) = (successful_sections, last_error) {
        return Err(error);
    }

    all_instructions.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.bytes.cmp(&right.bytes))
            .then_with(|| left.mnemonic.cmp(&right.mnemonic))
            .then_with(|| left.operands.cmp(&right.operands))
    });
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
    } else if is_control_mnemonic(&mnemonic_lower) && !is_interrupt_mnemonic(&mnemonic_lower) {
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

    if is_return_mnemonic(&mnemonic_lower) {
        FlowType::Return
    } else if is_call_mnemonic(&mnemonic_lower) {
        // Try to extract target address from operands
        if let Some(addr) = extract_address_from_operands(operands) {
            FlowType::Call(addr)
        } else {
            FlowType::Unknown // Indirect call
        }
    } else if is_unconditional_branch_mnemonic(&mnemonic_lower) {
        if let Some(addr) = extract_address_from_operands(operands) {
            FlowType::Jump(addr)
        } else {
            FlowType::Unknown // Indirect jump
        }
    } else if is_conditional_branch_mnemonic(&mnemonic_lower) {
        // Conditional jumps
        if let Some(addr) = extract_address_from_operands(operands) {
            FlowType::ConditionalJump(addr)
        } else {
            FlowType::Unknown // Indirect conditional jump
        }
    } else if is_interrupt_mnemonic(&mnemonic_lower) {
        FlowType::Interrupt
    } else {
        FlowType::Sequential
    }
}

/// Extract address from instruction operands (simplified)
#[cfg(feature = "disasm-capstone")]
fn extract_address_from_operands(operands: &str) -> Option<u64> {
    let operand = operands
        .trim()
        .trim_start_matches(['#', '$'])
        .split_whitespace()
        .next()?
        .trim_end_matches(',');

    // Look for hex addresses
    if let Some(addr) = operand
        .strip_prefix("0x")
        .and_then(|hex_part| u64::from_str_radix(hex_part, 16).ok())
    {
        return Some(addr);
    }

    // Look for decimal addresses
    if let Ok(addr) = operand.parse::<u64>() {
        return Some(addr);
    }

    None
}

fn is_call_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "call" | "callq" | "lcall" | "bl" | "blr" | "blx" | "jal" | "jalr" | "bctrl"
    )
}

fn is_return_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "ret" | "retn" | "retf" | "eret")
}

fn is_unconditional_branch_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jmp" | "jmpq" | "ljmp" | "j" | "b" | "br" | "bx" | "jr"
    )
}

fn is_conditional_branch_mnemonic(mnemonic: &str) -> bool {
    (mnemonic.starts_with('j') && !is_unconditional_branch_mnemonic(mnemonic))
        || mnemonic.starts_with("loop")
        || mnemonic.starts_with("b.")
        || matches!(
            mnemonic,
            "beq"
                | "beqz"
                | "bne"
                | "bnez"
                | "bgt"
                | "bgtz"
                | "bge"
                | "bgez"
                | "blt"
                | "bltz"
                | "ble"
                | "blez"
                | "bhi"
                | "bhs"
                | "blo"
                | "bls"
                | "bmi"
                | "bpl"
                | "bvs"
                | "bvc"
                | "cbz"
                | "cbnz"
                | "tbz"
                | "tbnz"
                | "bc"
                | "bdnz"
                | "bdz"
        )
}

fn is_interrupt_mnemonic(mnemonic: &str) -> bool {
    mnemonic.starts_with("int")
        || matches!(
            mnemonic,
            "syscall" | "sysenter" | "sysexit" | "svc" | "swi" | "brk"
        )
}

fn is_control_mnemonic(mnemonic: &str) -> bool {
    is_call_mnemonic(mnemonic)
        || is_return_mnemonic(mnemonic)
        || is_unconditional_branch_mnemonic(mnemonic)
        || is_conditional_branch_mnemonic(mnemonic)
        || is_interrupt_mnemonic(mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[cfg(feature = "disasm-iced")]
    struct TestFormat {
        architecture: Architecture,
        sections: Vec<Section>,
        symbols: Vec<Symbol>,
        entry_point: Option<u64>,
        metadata: BinaryMetadata,
    }

    #[cfg(feature = "disasm-iced")]
    impl BinaryFormatTrait for TestFormat {
        fn format_type(&self) -> BinaryFormat {
            BinaryFormat::Raw
        }

        fn architecture(&self) -> Architecture {
            self.architecture
        }

        fn entry_point(&self) -> Option<u64> {
            self.entry_point
        }

        fn sections(&self) -> &[Section] {
            &self.sections
        }

        fn symbols(&self) -> &[Symbol] {
            &self.symbols
        }

        fn imports(&self) -> &[Import] {
            &[]
        }

        fn exports(&self) -> &[Export] {
            &[]
        }

        fn metadata(&self) -> &BinaryMetadata {
            &self.metadata
        }
    }

    #[cfg(feature = "disasm-iced")]
    fn test_binary(architecture: Architecture, addresses: &[u64]) -> BinaryFile {
        let sections = addresses
            .iter()
            .enumerate()
            .map(|(index, &address)| Section {
                name: format!(".text{index}"),
                address,
                size: 1,
                offset: index as u64,
                file_size: 1,
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                section_type: SectionType::Code,
                data: Some(vec![0x90]),
            })
            .collect();
        let metadata = BinaryMetadata {
            size: addresses.len(),
            format: BinaryFormat::Raw,
            architecture,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };
        BinaryFile {
            data: vec![0x90; addresses.len()],
            parsed: Box::new(TestFormat {
                architecture,
                sections,
                symbols: Vec::new(),
                entry_point: None,
                metadata,
            }),
        }
    }

    #[cfg(all(feature = "disasm-iced", feature = "control-flow"))]
    fn large_test_binary() -> (BinaryFile, u64, u64) {
        const SECTION_OFFSET: usize = 128;
        const SECTION_ADDRESS: u64 = 0x1000;
        const SECTION_SIZE: usize = 2048;
        const CALLER_OFFSET: usize = 1200;
        const CALLEE_OFFSET: usize = 1500;

        let caller = SECTION_ADDRESS + CALLER_OFFSET as u64;
        let callee = SECTION_ADDRESS + CALLEE_OFFSET as u64;
        let displacement = i32::try_from(callee - (caller + 5)).unwrap();
        let mut data = vec![0x90; SECTION_OFFSET + SECTION_SIZE];
        data[SECTION_OFFSET + CALLER_OFFSET] = 0xe8;
        data[SECTION_OFFSET + CALLER_OFFSET + 1..SECTION_OFFSET + CALLER_OFFSET + 5]
            .copy_from_slice(&displacement.to_le_bytes());
        data[SECTION_OFFSET + CALLEE_OFFSET] = 0xc3;

        let sections = vec![Section {
            name: ".text".to_string(),
            address: SECTION_ADDRESS,
            size: SECTION_SIZE as u64,
            offset: SECTION_OFFSET as u64,
            file_size: SECTION_SIZE as u64,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            section_type: SectionType::Code,
            data: None,
        }];
        let symbols = vec![
            Symbol {
                name: "caller".to_string(),
                demangled_name: None,
                address: caller,
                size: 5,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: Some(0),
            },
            Symbol {
                name: "callee".to_string(),
                demangled_name: None,
                address: callee,
                size: 1,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: Some(0),
            },
        ];
        let metadata = BinaryMetadata {
            size: data.len(),
            format: BinaryFormat::Raw,
            architecture: Architecture::X86_64,
            entry_point: Some(caller),
            base_address: Some(SECTION_ADDRESS),
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };
        let binary = BinaryFile {
            data,
            parsed: Box::new(TestFormat {
                architecture: Architecture::X86_64,
                sections,
                symbols,
                entry_point: Some(caller),
                metadata,
            }),
        };
        (binary, caller, callee)
    }

    #[test]
    fn test_disassembler_creation() {
        let result = Disassembler::new(Architecture::X86_64);
        assert!(result.is_ok());
    }

    fn assert_address_range_validation(engine: DisassemblyEngine) {
        let disassembler = Disassembler::with_config(
            Architecture::X86_64,
            DisassemblyConfig {
                engine,
                ..DisassemblyConfig::default()
            },
        )
        .unwrap();

        let error = disassembler.disassemble(&[0x90], u64::MAX).unwrap_err();
        assert!(
            matches!(error, BinaryError::InvalidData(message) if message.contains("address range") && message.contains("overflows u64"))
        );

        let instructions = disassembler
            .disassemble(&[0x90], u64::MAX - 1)
            .expect("the largest representable end-exclusive range must be accepted");
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].address, u64::MAX - 1);
    }

    #[cfg(feature = "disasm-capstone")]
    #[test]
    fn capstone_rejects_wrapping_address_ranges() {
        assert_address_range_validation(DisassemblyEngine::Capstone);
    }

    #[cfg(feature = "disasm-iced")]
    #[test]
    fn iced_rejects_wrapping_address_ranges() {
        assert_address_range_validation(DisassemblyEngine::Iced);
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
        assert_ne!(
            categorize_instruction("blendps"),
            InstructionCategory::Control
        );
        assert_eq!(categorize_instruction("bl"), InstructionCategory::Control);
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
        assert_eq!(
            analyze_control_flow("bl", "#0x4000"),
            FlowType::Call(0x4000)
        );
        assert_eq!(
            analyze_control_flow("b.eq", "#0x5000"),
            FlowType::ConditionalJump(0x5000)
        );
    }

    #[test]
    #[cfg(feature = "disasm-capstone")]
    fn test_address_extraction() {
        assert_eq!(extract_address_from_operands("0x1000"), Some(0x1000));
        assert_eq!(extract_address_from_operands("4096"), Some(4096));
        assert_eq!(extract_address_from_operands("#0x1000"), Some(0x1000));
        assert_eq!(extract_address_from_operands("eax"), None);
    }

    #[cfg(feature = "disasm-iced")]
    #[test]
    fn binary_disassembly_returns_error_when_every_section_fails() {
        let binary = test_binary(Architecture::Arm, &[0x1000]);
        let config = AnalysisConfig {
            disassembly_engine: DisassemblyEngine::Iced,
            max_analysis_size: 16,
            ..AnalysisConfig::default()
        };

        assert!(disassemble_binary(&binary, &config).is_err());
    }

    #[cfg(feature = "disasm-iced")]
    #[test]
    fn binary_disassembly_honors_architecture_hint_and_sorts_output() {
        let binary = test_binary(Architecture::Arm, &[0x2000, 0x1000]);
        let config = AnalysisConfig {
            disassembly_engine: DisassemblyEngine::Iced,
            architecture_hint: Some(Architecture::X86_64),
            max_analysis_size: 16,
            ..AnalysisConfig::default()
        };

        let instructions = disassemble_binary(&binary, &config).unwrap();

        assert_eq!(
            instructions
                .iter()
                .map(|instruction| instruction.address)
                .collect::<Vec<_>>(),
            vec![0x1000, 0x2000]
        );
    }

    #[cfg(feature = "disasm-iced")]
    #[test]
    fn binary_disassembly_honors_global_instruction_limit() {
        let addresses = (0..20).map(|index| 0x1000 + index).collect::<Vec<_>>();
        let binary = test_binary(Architecture::X86_64, &addresses);
        let config = AnalysisConfig {
            disassembly_engine: DisassemblyEngine::Iced,
            max_analysis_size: 1024,
            max_disassembly_instructions: 7,
            ..AnalysisConfig::default()
        };

        assert_eq!(disassemble_binary(&binary, &config).unwrap().len(), 7);
    }

    #[cfg(feature = "disasm-iced")]
    #[test]
    fn section_file_data_rejects_truncated_declared_range() {
        let binary = test_binary(Architecture::X86_64, &[0x1000]);
        let section = Section {
            name: ".truncated".to_string(),
            address: 0x1000,
            size: 2,
            offset: 0,
            file_size: 2,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            section_type: SectionType::Code,
            data: None,
        };

        assert!(section_file_data(&binary, &section, 0, None).is_err());
    }

    #[cfg(all(feature = "disasm-iced", feature = "control-flow"))]
    #[test]
    fn large_sections_use_the_binary_file_instead_of_inline_previews() {
        use crate::analysis::{call_graph::CallGraphAnalyzer, control_flow::ControlFlowAnalyzer};

        let (binary, caller, callee) = large_test_binary();
        let disassembler = Disassembler::with_config(
            Architecture::X86_64,
            DisassemblyConfig {
                engine: DisassemblyEngine::Iced,
                max_instructions: 4096,
                ..DisassemblyConfig::default()
            },
        )
        .unwrap();

        let section_instructions = disassembler.disassemble_section(&binary, ".text").unwrap();
        assert!(section_instructions.iter().any(|instruction| {
            instruction.address == caller && instruction.flow == FlowType::Call(callee)
        }));

        let cfgs = ControlFlowAnalyzer::new(Architecture::X86_64)
            .analyze_binary(&binary)
            .unwrap();
        let caller_cfg = cfgs
            .iter()
            .find(|cfg| cfg.function.start_address == caller)
            .unwrap();
        assert_eq!(caller_cfg.basic_blocks[0].instructions[0].address, caller);

        let call_graph = CallGraphAnalyzer::new_default()
            .analyze_binary(&binary)
            .unwrap();
        assert!(
            call_graph
                .edges
                .iter()
                .any(|edge| edge.caller == caller && edge.callee == Some(callee))
        );
    }
}
