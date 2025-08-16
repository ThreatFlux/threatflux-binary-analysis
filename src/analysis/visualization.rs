#[cfg(feature = "visualization")]
#[allow(unused_imports)]
use dot_generator as _dot_generator;

use crate::types::ControlFlowGraph;

/// Generate a DOT representation of a control flow graph.
#[cfg(feature = "visualization")]
pub fn cfg_to_dot(cfg: &ControlFlowGraph) -> String {
    let mut dot = String::from("digraph cfg {\n");
    for block in &cfg.basic_blocks {
        dot.push_str(&format!(
            "  bb{} [label=\"0x{:x}\"];\n",
            block.id, block.start_address
        ));
    }
    for block in &cfg.basic_blocks {
        for succ in &block.successors {
            dot.push_str(&format!("  bb{} -> bb{};\n", block.id, succ));
        }
    }
    dot.push_str("}\n");
    dot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BasicBlock, ComplexityMetrics, Function, FunctionType};

    #[cfg(feature = "visualization")]
    #[test]
    fn test_cfg_to_dot() {
        let cfg = ControlFlowGraph {
            function: Function {
                name: "test".into(),
                start_address: 0,
                end_address: 10,
                size: 10,
                function_type: FunctionType::Normal,
                calling_convention: None,
                parameters: vec![],
                return_type: None,
            },
            basic_blocks: vec![
                BasicBlock {
                    id: 0,
                    start_address: 0,
                    end_address: 5,
                    instructions: vec![],
                    successors: vec![1],
                    predecessors: vec![],
                    block_type: crate::types::BlockType::Entry,
                    dominator: None,
                    dominance_frontier: Vec::new(),
                },
                BasicBlock {
                    id: 1,
                    start_address: 5,
                    end_address: 10,
                    instructions: vec![],
                    successors: vec![],
                    predecessors: vec![0],
                    block_type: crate::types::BlockType::Exit,
                    dominator: None,
                    dominance_frontier: Vec::new(),
                },
            ],
            complexity: ComplexityMetrics {
                cyclomatic_complexity: 1,
                basic_block_count: 2,
                edge_count: 1,
                nesting_depth: 0,
                loop_count: 0,
                cognitive_complexity: 1,
                halstead_metrics: None,
                maintainability_index: None,
            },
            loops: vec![],
        };

        let dot = cfg_to_dot(&cfg);
        assert!(dot.contains("bb0 -> bb1"));
        assert!(dot.contains("bb0"));
        assert!(dot.contains("bb1"));
    }
}
