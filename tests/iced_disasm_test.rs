#![cfg(feature = "disasm-iced")]

use threatflux_binary_analysis::disasm::DisassemblyEngine;
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer};

mod util;
use util::create_test_elf;

#[test]
fn test_iced_disassembly_via_analyzer() {
    let data = create_test_elf();
    let config = AnalysisConfig {
        disassembly_engine: DisassemblyEngine::Iced,
        enable_control_flow: false,
        enable_entropy: false,
        enable_symbols: false,
        ..Default::default()
    };
    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).expect("analysis");
    let disasm = result.disassembly.expect("disassembly");
    assert!(!disasm.is_empty());
    assert_eq!(disasm[0].mnemonic, "mov");
}
