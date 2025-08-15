//! Control flow analysis for binary programs
//!
//! This module provides functionality to analyze control flow in binary programs,
//! including basic block identification, control flow graph construction, and
//! complexity metrics calculation.

use crate::{
    disasm::Disassembler,
    types::{
        Architecture, BasicBlock, ComplexityMetrics, ControlFlow as FlowType, ControlFlowGraph,
        Function, Instruction,
    },
    BinaryError, BinaryFile, Result,
};
use std::cmp;
use std::collections::{HashMap, HashSet};

// Note: petgraph integration planned for future advanced CFG analysis
// #[cfg(feature = "control-flow")]
// use petgraph::{Directed, Graph};

/// Control flow analyzer
pub struct ControlFlowAnalyzer {
    /// Architecture being analyzed
    #[allow(dead_code)]
    architecture: Architecture,
    /// Analysis configuration
    config: AnalysisConfig,
}

/// Configuration for control flow analysis
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Maximum number of instructions to analyze per function
    pub max_instructions: usize,
    /// Maximum depth for recursive analysis
    pub max_depth: usize,
    /// Enable loop detection
    pub detect_loops: bool,
    /// Enable complexity metrics calculation
    pub calculate_metrics: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_instructions: 10000,
            max_depth: 100,
            detect_loops: true,
            calculate_metrics: true,
        }
    }
}

impl ControlFlowAnalyzer {
    /// Create a new control flow analyzer
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            config: AnalysisConfig::default(),
        }
    }

    /// Create analyzer with custom configuration
    pub fn with_config(architecture: Architecture, config: AnalysisConfig) -> Self {
        Self {
            architecture,
            config,
        }
    }

    /// Analyze control flow for all functions in a binary
    pub fn analyze_binary(&self, binary: &BinaryFile) -> Result<Vec<ControlFlowGraph>> {
        let mut cfgs = Vec::new();

        // Get functions from symbols
        let functions = self.extract_functions(binary)?;

        for function in functions {
            if let Ok(cfg) = self.analyze_function(binary, &function) {
                cfgs.push(cfg);
            }
        }

        Ok(cfgs)
    }

    /// Analyze control flow for a specific function
    pub fn analyze_function(
        &self,
        binary: &BinaryFile,
        function: &Function,
    ) -> Result<ControlFlowGraph> {
        // Get instructions for the function
        let instructions = self.get_function_instructions(binary, function)?;

        // Build basic blocks
        let basic_blocks = self.build_basic_blocks(&instructions)?;

        // Calculate complexity metrics
        let complexity = if self.config.calculate_metrics {
            self.calculate_complexity(&basic_blocks)
        } else {
            ComplexityMetrics::default()
        };

        Ok(ControlFlowGraph {
            function: function.clone(),
            basic_blocks,
            complexity,
        })
    }

    /// Extract functions from binary symbols
    fn extract_functions(&self, binary: &BinaryFile) -> Result<Vec<Function>> {
        let mut functions = Vec::new();

        for symbol in binary.symbols() {
            if matches!(symbol.symbol_type, crate::types::SymbolType::Function) {
                let function = Function {
                    name: symbol.name.clone(),
                    start_address: symbol.address,
                    end_address: symbol.address + symbol.size,
                    size: symbol.size,
                    function_type: crate::types::FunctionType::Normal,
                    calling_convention: None,
                    parameters: Vec::new(),
                    return_type: None,
                };
                functions.push(function);
            }
        }

        // If no function symbols, try to find functions from entry point
        if functions.is_empty() {
            if let Some(entry_point) = binary.entry_point() {
                let function = Function {
                    name: "_start".to_string(),
                    start_address: entry_point,
                    end_address: entry_point + 1000, // Estimate
                    size: 1000,
                    function_type: crate::types::FunctionType::Entrypoint,
                    calling_convention: None,
                    parameters: Vec::new(),
                    return_type: None,
                };
                functions.push(function);
            }
        }

        Ok(functions)
    }

    /// Get instructions for a function using the disassembly module
    fn get_function_instructions(
        &self,
        binary: &BinaryFile,
        function: &Function,
    ) -> Result<Vec<Instruction>> {
        // Locate the section containing this function
        for section in binary.sections() {
            let start = section.address;
            let end = start + section.size;

            if function.start_address >= start && function.start_address < end {
                let data = section.data.as_ref().ok_or_else(|| {
                    BinaryError::invalid_data("Section data not available for disassembly")
                })?;

                let offset = (function.start_address - start) as usize;
                if offset >= data.len() {
                    return Ok(Vec::new());
                }

                let available = data.len() - offset;
                let length = cmp::min(function.size as usize, available);
                if length == 0 {
                    return Ok(Vec::new());
                }

                let slice = &data[offset..offset + length];
                let disassembler = Disassembler::new(self.architecture)?;
                return disassembler.disassemble_at(slice, function.start_address, length);
            }
        }

        Err(BinaryError::invalid_data(
            "Function bytes not found in any executable section",
        ))
    }

    /// Build basic blocks from instructions
    fn build_basic_blocks(&self, instructions: &[Instruction]) -> Result<Vec<BasicBlock>> {
        if instructions.is_empty() {
            return Ok(Vec::new());
        }

        let mut basic_blocks = Vec::new();
        let mut block_starts = HashSet::new();

        // First instruction is always a block start
        block_starts.insert(instructions[0].address);

        // Find all block boundaries
        for (i, instr) in instructions.iter().enumerate() {
            match &instr.flow {
                FlowType::Jump(target)
                | FlowType::ConditionalJump(target)
                | FlowType::Call(target) => {
                    // Target of jump/call is a block start
                    block_starts.insert(*target);
                    // Instruction after conditional jump/call is also a block start
                    if i + 1 < instructions.len() {
                        block_starts.insert(instructions[i + 1].address);
                    }
                }
                FlowType::Return | FlowType::Interrupt => {
                    // Instruction after return/interrupt is a block start (if exists)
                    if i + 1 < instructions.len() {
                        block_starts.insert(instructions[i + 1].address);
                    }
                }
                _ => {}
            }
        }

        // Build basic blocks
        let mut current_block_id = 0;
        let mut current_block_start = 0;

        for (i, instr) in instructions.iter().enumerate() {
            if block_starts.contains(&instr.address) && i > current_block_start {
                // End current block
                let block_instructions = instructions[current_block_start..i].to_vec();
                let start_addr = instructions[current_block_start].address;
                let end_addr = instructions[i - 1].address + instructions[i - 1].size as u64;

                basic_blocks.push(BasicBlock {
                    id: current_block_id,
                    start_address: start_addr,
                    end_address: end_addr,
                    instructions: block_instructions,
                    successors: Vec::new(),   // Will be filled later
                    predecessors: Vec::new(), // Will be filled later
                });

                current_block_id += 1;
                current_block_start = i;
            }
        }

        // Add the last block
        if current_block_start < instructions.len() {
            let block_instructions = instructions[current_block_start..].to_vec();
            let start_addr = instructions[current_block_start].address;
            let end_addr =
                instructions.last().unwrap().address + instructions.last().unwrap().size as u64;

            basic_blocks.push(BasicBlock {
                id: current_block_id,
                start_address: start_addr,
                end_address: end_addr,
                instructions: block_instructions,
                successors: Vec::new(),
                predecessors: Vec::new(),
            });
        }

        // Build successor/predecessor relationships
        self.build_cfg_edges(&mut basic_blocks)?;

        Ok(basic_blocks)
    }

    /// Build control flow graph edges between basic blocks
    fn build_cfg_edges(&self, basic_blocks: &mut [BasicBlock]) -> Result<()> {
        let mut addr_to_block: HashMap<u64, usize> = HashMap::new();

        // Build address to block ID mapping
        for (i, block) in basic_blocks.iter().enumerate() {
            addr_to_block.insert(block.start_address, i);
        }

        // Build edges
        for i in 0..basic_blocks.len() {
            let block = &basic_blocks[i];
            if let Some(last_instr) = block.instructions.last() {
                match &last_instr.flow {
                    FlowType::Sequential => {
                        // Fall through to next block
                        if i + 1 < basic_blocks.len() {
                            basic_blocks[i].successors.push(i + 1);
                            basic_blocks[i + 1].predecessors.push(i);
                        }
                    }
                    FlowType::Jump(target) => {
                        // Unconditional jump
                        if let Some(&target_block) = addr_to_block.get(target) {
                            basic_blocks[i].successors.push(target_block);
                            basic_blocks[target_block].predecessors.push(i);
                        }
                    }
                    FlowType::ConditionalJump(target) => {
                        // Conditional jump - two successors
                        if let Some(&target_block) = addr_to_block.get(target) {
                            basic_blocks[i].successors.push(target_block);
                            basic_blocks[target_block].predecessors.push(i);
                        }
                        // Fall through
                        if i + 1 < basic_blocks.len() {
                            basic_blocks[i].successors.push(i + 1);
                            basic_blocks[i + 1].predecessors.push(i);
                        }
                    }
                    FlowType::Call(_target) => {
                        // Function call - continues to next instruction
                        if i + 1 < basic_blocks.len() {
                            basic_blocks[i].successors.push(i + 1);
                            basic_blocks[i + 1].predecessors.push(i);
                        }
                        // Note: Call target is not added as successor for CFG
                    }
                    FlowType::Return | FlowType::Interrupt => {
                        // No successors
                    }
                    FlowType::Unknown => {
                        // Conservatively assume fall through
                        if i + 1 < basic_blocks.len() {
                            basic_blocks[i].successors.push(i + 1);
                            basic_blocks[i + 1].predecessors.push(i);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Calculate complexity metrics for a control flow graph
    fn calculate_complexity(&self, basic_blocks: &[BasicBlock]) -> ComplexityMetrics {
        let basic_block_count = basic_blocks.len() as u32;
        let mut edge_count = 0;

        // Count edges
        for block in basic_blocks {
            edge_count += block.successors.len() as u32;
        }

        // Cyclomatic complexity = E - N + 2P
        // Where E = edges, N = nodes, P = connected components (assume 1)
        let cyclomatic_complexity = if basic_block_count > 0 {
            edge_count.saturating_sub(basic_block_count) + 2
        } else {
            0
        };

        // Detect loops (simplified)
        let loop_count = self.detect_loops(basic_blocks);

        // Calculate nesting depth (simplified)
        let nesting_depth = self.calculate_nesting_depth(basic_blocks);

        ComplexityMetrics {
            cyclomatic_complexity,
            basic_block_count,
            edge_count,
            nesting_depth,
            loop_count,
        }
    }

    /// Detect loops in the control flow graph
    fn detect_loops(&self, basic_blocks: &[BasicBlock]) -> u32 {
        if !self.config.detect_loops {
            return 0;
        }

        let mut loop_count = 0;
        let mut visited = vec![false; basic_blocks.len()];
        let mut in_stack = vec![false; basic_blocks.len()];

        // Use DFS to detect back edges (indicating loops)
        for i in 0..basic_blocks.len() {
            if !visited[i] {
                loop_count += Self::dfs_detect_loops(i, basic_blocks, &mut visited, &mut in_stack);
            }
        }

        loop_count
    }

    /// DFS helper for loop detection
    fn dfs_detect_loops(
        node: usize,
        basic_blocks: &[BasicBlock],
        visited: &mut [bool],
        in_stack: &mut [bool],
    ) -> u32 {
        visited[node] = true;
        in_stack[node] = true;
        let mut loops = 0;

        for &successor in &basic_blocks[node].successors {
            if !visited[successor] {
                loops += Self::dfs_detect_loops(successor, basic_blocks, visited, in_stack);
            } else if in_stack[successor] {
                // Back edge found - indicates a loop
                loops += 1;
            }
        }

        in_stack[node] = false;
        loops
    }

    /// Calculate nesting depth (simplified heuristic)
    fn calculate_nesting_depth(&self, basic_blocks: &[BasicBlock]) -> u32 {
        let mut max_depth = 0;

        // Simple heuristic: depth based on indegree
        for block in basic_blocks {
            let depth = block.predecessors.len() as u32;
            if depth > max_depth {
                max_depth = depth;
            }
        }

        max_depth
    }
}

/// Analyze binary control flow
pub fn analyze_binary(binary: &BinaryFile) -> Result<Vec<ControlFlowGraph>> {
    let analyzer = ControlFlowAnalyzer::new(binary.architecture());
    analyzer.analyze_binary(binary)
}

/// Analyze control flow for a specific function
pub fn analyze_function(binary: &BinaryFile, function: &Function) -> Result<ControlFlowGraph> {
    let analyzer = ControlFlowAnalyzer::new(binary.architecture());
    analyzer.analyze_function(binary, function)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);
        assert_eq!(analyzer.architecture, Architecture::X86_64);
    }

    #[test]
    fn test_config_default() {
        let config = AnalysisConfig::default();
        assert_eq!(config.max_instructions, 10000);
        assert_eq!(config.max_depth, 100);
        assert!(config.detect_loops);
        assert!(config.calculate_metrics);
    }

    #[test]
    fn test_basic_block_creation() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: vec![0x90],
                mnemonic: "nop".to_string(),
                operands: String::new(),
                category: InstructionCategory::Unknown,
                flow: FlowType::Sequential,
                size: 1,
            },
            Instruction {
                address: 0x1001,
                bytes: vec![0xc3],
                mnemonic: "ret".to_string(),
                operands: String::new(),
                category: InstructionCategory::Control,
                flow: FlowType::Return,
                size: 1,
            },
        ];

        let analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);
        let blocks = analyzer.build_basic_blocks(&instructions).unwrap();

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].instructions.len(), 2);
        assert_eq!(blocks[0].start_address, 0x1000);
        assert_eq!(blocks[0].end_address, 0x1002);
    }
}
