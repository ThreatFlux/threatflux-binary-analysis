#![cfg(feature = "wasm")]
//! Tests for WebAssembly binary parsing

use threatflux_binary_analysis::{
    types::{Architecture, BinaryFormat},
    BinaryAnalyzer,
};

#[test]
fn test_analyze_wasm_binary() {
    // Simple WebAssembly module exporting a function `add`
    let wat = r#"(module
        (func (export "add") (param i32 i32) (result i32)
            local.get 0
            local.get 1
            i32.add))"#;
    let wasm = wat::parse_str(wat).expect("valid wasm");

    let analyzer = BinaryAnalyzer::new();
    let analysis = analyzer.analyze(&wasm).expect("analysis succeeds");

    assert_eq!(analysis.format, BinaryFormat::Wasm);
    assert_eq!(analysis.architecture, Architecture::Wasm);
    assert!(analysis.exports.iter().any(|e| e.name == "add"));
    assert!(analysis.sections.iter().any(|s| s.name == "code"));
}
