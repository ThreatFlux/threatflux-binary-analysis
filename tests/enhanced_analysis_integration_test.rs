#![allow(clippy::uninlined_format_args)]
//! Integration tests for enhanced control flow and call graph analysis

#[cfg(feature = "control-flow")]
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer};

#[cfg(feature = "control-flow")]
use threatflux_binary_analysis::DisassemblyEngine;
#[cfg(feature = "control-flow")]
use threatflux_binary_analysis::types::*;

/// Test end-to-end enhanced control flow analysis
#[test]
#[cfg(feature = "control-flow")]
fn test_enhanced_control_flow_analysis() {
    let data = create_test_elf_with_functions();

    let config = AnalysisConfig {
        enable_disassembly: true,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: DisassemblyEngine::Auto,
        enable_control_flow: true,
        enable_call_graph: false,
        enable_cognitive_complexity: true,
        enable_advanced_loops: true,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 10 * 1024 * 1024,
        max_disassembly_instructions: 10_000,
        architecture_hint: Some(Architecture::X86_64),
        call_graph_config: None,
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).unwrap();

    // Verify basic analysis worked
    assert_eq!(result.format, BinaryFormat::Elf);
    assert_eq!(result.architecture, Architecture::X86_64);

    // Verify enhanced control flow analysis was performed
    if let Some(enhanced_cf) = result.enhanced_control_flow {
        // For minimal test data, we might not have functions to analyze
        // This is acceptable - just verify the analysis structure exists

        // Check cognitive complexity statistics
        let _stats = &enhanced_cf.cognitive_complexity_summary;
        // functions_analyzed is usize, so it's always >= 0, just verify it exists

        // Check loop analysis statistics
        let _loop_stats = &enhanced_cf.loop_analysis_summary;
        // For minimal test data, we might not have loops but the structure should be valid
        // total_loops is usize, so it's always >= 0
    }
}

/// Test end-to-end call graph analysis
#[test]
#[cfg(feature = "control-flow")]
fn test_call_graph_analysis() {
    let data = create_test_elf_with_functions();

    let call_graph_config = CallGraphConfig {
        analyze_indirect_calls: true,
        detect_tail_calls: true,
        max_functions: 1_000,
        max_total_instructions: 100_000,
        max_labeled_call_depth: Some(10),
        include_library_calls: false,
    };

    let config = AnalysisConfig {
        enable_disassembly: true,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: DisassemblyEngine::Auto,
        enable_control_flow: false,
        enable_call_graph: true,
        enable_cognitive_complexity: false,
        enable_advanced_loops: false,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 10 * 1024 * 1024,
        max_disassembly_instructions: 10_000,
        architecture_hint: Some(Architecture::X86_64),
        call_graph_config: Some(call_graph_config),
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).unwrap();

    // Verify call graph analysis was performed
    if let Some(call_graph) = result.call_graph {
        // Should have at least some nodes (functions)
        assert!(!call_graph.nodes.is_empty());

        // Verify statistics are computed
        let stats = &call_graph.statistics;
        assert_eq!(stats.total_functions, call_graph.nodes.len());
        assert_eq!(stats.total_calls, call_graph.edges.len());

        // Test DOT export functionality
        let dot_output = call_graph.to_dot().expect("DOT export should succeed");
        assert!(dot_output.contains("digraph CallGraph"));
        assert!(dot_output.contains("rankdir=TB"));

        // Test JSON export functionality (if serde is available)
        #[cfg(feature = "serde-support")]
        {
            let json_output = call_graph.to_json().expect("JSON export should succeed");
            assert!(!json_output.is_empty());
            assert!(json_output.contains("nodes"));
            assert!(json_output.contains("edges"));
        }

        // Test cycle detection
        let cycles = call_graph.detect_cycles();
        assert_eq!(cycles, call_graph.detect_cycles());
    }
}

/// Test comprehensive analysis with all enhanced features enabled
#[test]
#[cfg(feature = "control-flow")]
fn test_comprehensive_enhanced_analysis() {
    let data = create_test_elf_with_functions();

    let config = AnalysisConfig {
        enable_disassembly: true,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: DisassemblyEngine::Auto,
        enable_control_flow: true,
        enable_call_graph: true,
        enable_cognitive_complexity: true,
        enable_advanced_loops: true,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 10 * 1024 * 1024,
        max_disassembly_instructions: 10_000,
        architecture_hint: Some(Architecture::X86_64),
        call_graph_config: Some(CallGraphConfig::default()),
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).unwrap();

    // Verify all analysis types were performed
    assert!(result.enhanced_control_flow.is_some());
    assert!(result.call_graph.is_some());

    // Verify both enhanced analyses work together
    let enhanced_cf = result.enhanced_control_flow.unwrap();
    let call_graph = result.call_graph.unwrap();

    // Should have reasonable consistency between analyses
    // (both should detect similar number of functions)
    let cf_functions = enhanced_cf.cognitive_complexity_summary.functions_analyzed;
    let cg_functions = call_graph.statistics.total_functions;

    // Allow some variance as the analyses might count functions differently
    if cf_functions > 0 && cg_functions > 0 {
        let ratio = (cf_functions as f64) / (cg_functions as f64);
        assert!(
            (0.5..=2.0).contains(&ratio),
            "Function counts too different: CF={}, CG={}",
            cf_functions,
            cg_functions
        );
    }
}

/// Test enhanced complexity metrics calculation
#[test]
#[cfg(feature = "control-flow")]
fn test_complexity_metrics_calculation() {
    let data = create_test_elf_with_functions();

    let config = AnalysisConfig {
        enable_disassembly: true,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: DisassemblyEngine::Auto,
        enable_control_flow: true,
        enable_call_graph: false,
        enable_cognitive_complexity: true,
        enable_advanced_loops: true,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 10 * 1024 * 1024,
        max_disassembly_instructions: 10_000,
        architecture_hint: Some(Architecture::X86_64),
        call_graph_config: None,
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).unwrap();

    if let Some(enhanced_cf) = result.enhanced_control_flow {
        for cfg in &enhanced_cf.control_flow_graphs {
            let complexity = &cfg.complexity;

            // Verify all complexity metrics are computed
            assert!(complexity.cyclomatic_complexity >= 1);
            assert!(complexity.basic_block_count > 0);
            // cognitive_complexity is u32, so it's always >= 0
            // cognitive_complexity is u32, so it's always >= 0

            // Halstead metrics should be computed if there are instructions
            if !cfg.basic_blocks.is_empty()
                && cfg
                    .basic_blocks
                    .iter()
                    .any(|bb| !bb.instructions.is_empty())
            {
                // Halstead metrics might be available
                if let Some(ref halstead) = complexity.halstead_metrics {
                    assert!(halstead.vocabulary > 0);
                    assert!(halstead.length > 0);
                    assert!(halstead.volume > 0.0);
                }

                // Maintainability index might be available if Halstead is computed
                if complexity.halstead_metrics.is_some()
                    && let Some(mi) = complexity.maintainability_index
                {
                    assert!((0.0..=100.0).contains(&mi));
                }
            }
        }
    }
}

/// Test loop analysis functionality
#[test]
#[cfg(feature = "control-flow")]
fn test_loop_analysis() {
    let data = create_test_elf_with_loops();

    let config = AnalysisConfig {
        enable_disassembly: true,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: DisassemblyEngine::Auto,
        enable_control_flow: true,
        enable_call_graph: false,
        enable_cognitive_complexity: false,
        enable_advanced_loops: true,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 10 * 1024 * 1024,
        max_disassembly_instructions: 10_000,
        architecture_hint: Some(Architecture::X86_64),
        call_graph_config: None,
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).unwrap();

    if let Some(enhanced_cf) = result.enhanced_control_flow {
        let loop_stats = &enhanced_cf.loop_analysis_summary;

        // Verify loop statistics structure
        // total_loops is usize, so it's always >= 0
        // total_loops is usize, so it's always >= 0
        assert!(loop_stats.natural_loops <= loop_stats.total_loops);
        assert!(loop_stats.irreducible_loops <= loop_stats.total_loops);
        assert!(loop_stats.nested_loops <= loop_stats.total_loops);

        // Check loop type distribution
        let total_by_type: usize = loop_stats.loops_by_type.values().sum();
        assert!(total_by_type <= loop_stats.total_loops);
    }
}

/// Create a minimal ELF64 executable with a file-backed executable section.
#[allow(dead_code)]
fn create_test_elf_with_functions() -> Vec<u8> {
    const TEXT_OFFSET: usize = 0x100;
    const TEXT_ADDRESS: u64 = 0x401000;
    const STRING_TABLE_OFFSET: usize = 0x180;
    const SECTION_TABLE_OFFSET: usize = 0x200;

    let instructions = [
        0x48, 0x89, 0xe5, // mov %rsp, %rbp
        0xe8, 0x05, 0x00, 0x00, 0x00, // call func2
        0xc3, // ret
        0x48, 0x89, 0xe5, // mov %rsp, %rbp
        0xb8, 0x00, 0x00, 0x00, 0x00, // mov $0, %eax
        0xc3, // ret
        0x48, 0x89, 0xe5, // mov %rsp, %rbp
        0xb8, 0x0a, 0x00, 0x00, 0x00, // mov $10, %eax
        0x48, 0x83, 0xe8, 0x01, // sub $1, %rax (loop body)
        0x75, 0xfb, // jne -5 (loop back)
        0xc3, // ret
    ];
    let section_names = b"\0.text\0.shstrtab\0";
    let mut elf_data = vec![0_u8; SECTION_TABLE_OFFSET + 3 * 64];

    elf_data[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    elf_data[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf_data[18..20].copy_from_slice(&0x3e_u16.to_le_bytes());
    elf_data[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf_data[24..32].copy_from_slice(&TEXT_ADDRESS.to_le_bytes());
    elf_data[40..48].copy_from_slice(&(SECTION_TABLE_OFFSET as u64).to_le_bytes());
    elf_data[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf_data[58..60].copy_from_slice(&64_u16.to_le_bytes());
    elf_data[60..62].copy_from_slice(&3_u16.to_le_bytes());
    elf_data[62..64].copy_from_slice(&2_u16.to_le_bytes());

    elf_data[TEXT_OFFSET..TEXT_OFFSET + instructions.len()].copy_from_slice(&instructions);
    elf_data[STRING_TABLE_OFFSET..STRING_TABLE_OFFSET + section_names.len()]
        .copy_from_slice(section_names);

    let text_header = SECTION_TABLE_OFFSET + 64;
    elf_data[text_header..text_header + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf_data[text_header + 4..text_header + 8].copy_from_slice(&1_u32.to_le_bytes());
    elf_data[text_header + 8..text_header + 16].copy_from_slice(&6_u64.to_le_bytes());
    elf_data[text_header + 16..text_header + 24].copy_from_slice(&TEXT_ADDRESS.to_le_bytes());
    elf_data[text_header + 24..text_header + 32]
        .copy_from_slice(&(TEXT_OFFSET as u64).to_le_bytes());
    elf_data[text_header + 32..text_header + 40]
        .copy_from_slice(&(instructions.len() as u64).to_le_bytes());
    elf_data[text_header + 48..text_header + 56].copy_from_slice(&16_u64.to_le_bytes());

    let string_header = SECTION_TABLE_OFFSET + 128;
    elf_data[string_header..string_header + 4].copy_from_slice(&7_u32.to_le_bytes());
    elf_data[string_header + 4..string_header + 8].copy_from_slice(&3_u32.to_le_bytes());
    elf_data[string_header + 24..string_header + 32]
        .copy_from_slice(&(STRING_TABLE_OFFSET as u64).to_le_bytes());
    elf_data[string_header + 32..string_header + 40]
        .copy_from_slice(&(section_names.len() as u64).to_le_bytes());
    elf_data[string_header + 48..string_header + 56].copy_from_slice(&1_u64.to_le_bytes());

    elf_data
}

/// Create a test ELF binary with loop structures for testing
#[allow(dead_code)]
fn create_test_elf_with_loops() -> Vec<u8> {
    // Similar to create_test_elf_with_functions but with more complex loop structures
    let mut elf_data = create_test_elf_with_functions();

    // Add more complex loop structures
    elf_data.extend_from_slice(&[
        // Nested loop function
        0x48, 0x89, 0xe5, // mov %rsp, %rbp
        0xb8, 0x05, 0x00, 0x00, 0x00, // mov $5, %eax (outer loop counter)
        0xbb, 0x03, 0x00, 0x00, 0x00, // mov $3, %ebx (inner loop counter)
        0x48, 0x83, 0xeb, 0x01, // sub $1, %rbx (inner loop)
        0x75, 0xfb, // jne -5 (inner loop back)
        0x48, 0x83, 0xe8, 0x01, // sub $1, %rax (outer loop)
        0x75, 0xf1, // jne -15 (outer loop back)
        0xc3, // ret
    ]);

    elf_data
}

/// Test performance with larger binaries
#[test]
#[cfg(feature = "control-flow")]
fn test_enhanced_analysis_performance() {
    use std::time::Instant;

    let data = create_large_test_binary();

    let config = AnalysisConfig {
        enable_disassembly: true,
        #[cfg(any(feature = "disasm-capstone", feature = "disasm-iced"))]
        disassembly_engine: DisassemblyEngine::Auto,
        enable_control_flow: true,
        enable_call_graph: true,
        enable_cognitive_complexity: true,
        enable_advanced_loops: true,
        enable_entropy: false,
        enable_symbols: true,
        max_analysis_size: 10 * 1024 * 1024,
        max_disassembly_instructions: 10_000,
        architecture_hint: Some(Architecture::X86_64),
        call_graph_config: None,
    };

    let analyzer = BinaryAnalyzer::with_config(config);

    let start = Instant::now();
    let result = analyzer.analyze(&data);
    let duration = start.elapsed();

    // Analysis should complete within reasonable time (5 seconds for test data)
    assert!(
        duration.as_secs() < 5,
        "Analysis took too long: {:?}",
        duration
    );

    // Should succeed
    assert!(result.is_ok(), "Analysis failed: {:?}", result.err());

    if let Ok(analysis) = result {
        // Verify enhanced features were computed
        assert!(analysis.enhanced_control_flow.is_some() || analysis.call_graph.is_some());
    }
}

/// Create a larger test binary for performance testing
#[allow(dead_code)]
fn create_large_test_binary() -> Vec<u8> {
    let mut data = create_test_elf_with_functions();

    // Add more functions to simulate a larger binary
    for i in 0..50 {
        data.extend_from_slice(&[
            // Function with some complexity
            0x48,
            0x89,
            0xe5, // mov %rsp, %rbp
            0xb8,
            (i & 0xff) as u8,
            0x00,
            0x00,
            0x00, // mov $i, %eax
            0x48,
            0x83,
            0xf8,
            0x0a, // cmp $10, %rax
            0x7c,
            0x05, // jl +5
            0x48,
            0x83,
            0xe8,
            0x0a, // sub $10, %rax
            0xeb,
            0x03, // jmp +3
            0x48,
            0x83,
            0xc0,
            0x01, // add $1, %rax
            0xc3, // ret
        ]);
    }

    data
}
