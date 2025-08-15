//! Tests for iced-x86 disassembly support

#[cfg(feature = "disasm-iced")]
use threatflux_binary_analysis::disasm::{Disassembler, DisassemblyConfig, DisassemblyEngine};
#[cfg(feature = "disasm-iced")]
use threatflux_binary_analysis::types::Architecture;

#[cfg(feature = "disasm-iced")]
#[test]
fn test_iced_disassembler_nop() {
    let config = DisassemblyConfig {
        engine: DisassemblyEngine::Iced,
        ..Default::default()
    };
    let disassembler = Disassembler::with_config(Architecture::X86_64, config)
        .expect("failed to create disassembler");
    let data = [0x90u8, 0x90];
    let instructions = disassembler
        .disassemble(&data, 0x1000)
        .expect("disassembly failed");
    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[0].mnemonic, "nop");
    assert_eq!(instructions[0].address, 0x1000);
}
