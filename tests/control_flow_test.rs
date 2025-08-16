#![cfg(all(
    feature = "control-flow",
    any(feature = "disasm-capstone", feature = "disasm-iced")
))]

use threatflux_binary_analysis::analysis::control_flow;
use threatflux_binary_analysis::types::ControlFlow as FlowType;
use threatflux_binary_analysis::BinaryFile;

mod util;
use util::create_test_elf;

#[test]
fn test_control_flow_analysis_from_binary() {
    let data = create_test_elf();
    let binary = BinaryFile::parse(&data).expect("parse ELF");
    let cfgs = control_flow::analyze_binary(&binary).expect("analyze");
    assert!(!cfgs.is_empty());
    let cfg = &cfgs[0];
    assert!(!cfg.basic_blocks.is_empty());
    let has_return = cfg.basic_blocks.iter().any(|b| {
        b.instructions
            .iter()
            .any(|i| matches!(i.flow, FlowType::Return))
    });
    assert!(has_return);
}
