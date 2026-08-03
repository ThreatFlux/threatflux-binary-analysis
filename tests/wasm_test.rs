#![allow(clippy::uninlined_format_args)]
#![cfg(feature = "wasm")]
//! Tests for WebAssembly binary parsing

use threatflux_binary_analysis::{
    BinaryAnalyzer,
    types::{Architecture, BinaryFormat},
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

#[test]
fn test_rejects_malformed_function_body() {
    let malformed =
        b"\0asm\x01\0\0\0\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x0a\x04\x01\x02\x00\xff";
    let error = BinaryAnalyzer::new()
        .analyze(malformed)
        .expect_err("invalid WebAssembly instructions must fail validation");

    assert!(error.to_string().contains("WASM parse error"));
}
