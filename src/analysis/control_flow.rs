//! Control flow analysis for binary programs
//!
//! This module provides functionality to analyze control flow in binary programs,
//! including basic block identification, control flow graph construction, and
//! complexity metrics calculation.

use crate::{
    disasm::Disassembler,
    types::{
        Architecture, BasicBlock, CallGraphConfig, ComplexityMetrics, ControlFlow as FlowType,
        ControlFlowGraph, Function, Instruction,
    },
    BinaryError, BinaryFile, Result,
};
use std::cmp;
use std::collections::{HashMap, HashSet};

// Note: petgraph integration planned for future advanced CFG analysis
// #[cfg(feature = "control-flow")]
// use petgraph::{Directed, Graph};

/// Control flow analyzer
#[derive(Clone)]
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
    /// Enable call graph construction
    pub enable_call_graph: bool,
    /// Enable cognitive complexity calculation
    pub enable_cognitive_complexity: bool,
    /// Enable advanced loop analysis
    pub enable_advanced_loops: bool,
    /// Call graph configuration
    pub call_graph_config: Option<CallGraphConfig>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_instructions: 10000,
            max_depth: 100,
            detect_loops: true,
            calculate_metrics: true,
            enable_call_graph: false,
            enable_cognitive_complexity: true,
            enable_advanced_loops: true,
            call_graph_config: None,
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
        let mut basic_blocks = self.build_basic_blocks(&instructions)?;

        // Calculate complexity metrics
        let complexity = if self.config.calculate_metrics {
            self.calculate_complexity(&basic_blocks)
        } else {
            ComplexityMetrics::default()
        };

        // Create a mutable analyzer for enhanced analysis
        let mut analyzer = self.clone();

        // Perform enhanced analysis if enabled
        let loops = if self.config.enable_advanced_loops {
            analyzer
                .analyze_loops(&mut basic_blocks)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Build dominator tree
        if self.config.enable_advanced_loops {
            let _ = analyzer.build_dominator_tree(&mut basic_blocks);
        }

        // Classify block types
        if self.config.enable_advanced_loops {
            let _ = analyzer.classify_block_types(&mut basic_blocks);
        }

        Ok(ControlFlowGraph {
            function: function.clone(),
            basic_blocks,
            complexity,
            loops,
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
                    block_type: crate::types::BlockType::Normal, // Will be classified later
                    dominator: None,          // Will be computed later
                    dominance_frontier: Vec::new(), // Will be computed later
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
                block_type: crate::types::BlockType::Normal, // Will be classified later
                dominator: None,                             // Will be computed later
                dominance_frontier: Vec::new(),              // Will be computed later
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

        // Calculate cognitive complexity
        let cognitive_complexity = self.calculate_cognitive_complexity(basic_blocks);

        // Calculate Halstead metrics if available
        let halstead_metrics = self.calculate_halstead_metrics(basic_blocks);

        // Calculate maintainability index if Halstead metrics are available
        let maintainability_index = if let Some(ref halstead) = halstead_metrics {
            self.calculate_maintainability_index(halstead, cyclomatic_complexity, basic_block_count)
        } else {
            None
        };

        ComplexityMetrics {
            cyclomatic_complexity,
            basic_block_count,
            edge_count,
            nesting_depth,
            loop_count,
            cognitive_complexity,
            halstead_metrics,
            maintainability_index,
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

    /// Calculate cognitive complexity (different from cyclomatic complexity)
    /// Cognitive complexity measures how difficult the code is to understand
    fn calculate_cognitive_complexity(&self, basic_blocks: &[BasicBlock]) -> u32 {
        let mut cognitive_complexity = 0;
        let mut nesting_level = 0;

        for block in basic_blocks {
            for instruction in &block.instructions {
                // Increment for decision structures
                match &instruction.flow {
                    FlowType::ConditionalJump(_) => {
                        cognitive_complexity += 1 + nesting_level;
                    }
                    FlowType::Jump(_) => {
                        // Break/continue statements in loops add complexity
                        if self.is_in_loop_context(block, basic_blocks) {
                            cognitive_complexity += 1;
                        }
                    }
                    _ => {}
                }

                // Analyze instruction patterns for complexity
                match instruction.mnemonic.as_str() {
                    // Conditional instructions
                    "je" | "jne" | "jl" | "jle" | "jg" | "jge" | "jz" | "jnz" | "js" | "jns" => {
                        cognitive_complexity += 1 + nesting_level;
                    }
                    // Loop instructions
                    "loop" | "loope" | "loopne" | "loopz" | "loopnz" => {
                        cognitive_complexity += 1 + nesting_level;
                        nesting_level += 1; // Increase nesting for subsequent instructions
                    }
                    // Exception handling
                    "int" | "syscall" | "sysenter" => {
                        cognitive_complexity += 1;
                    }
                    _ => {}
                }
            }

            // Adjust nesting level based on block structure
            if block.successors.len() > 1 {
                nesting_level += 1;
            }
        }

        cognitive_complexity
    }

    /// Check if a block is in a loop context
    fn is_in_loop_context(&self, _block: &BasicBlock, _basic_blocks: &[BasicBlock]) -> bool {
        // Simplified implementation - in real implementation, this would
        // analyze the control flow to determine if we're inside a loop
        false
    }

    /// Calculate Halstead metrics for software complexity
    fn calculate_halstead_metrics(
        &self,
        basic_blocks: &[BasicBlock],
    ) -> Option<crate::types::HalsteadMetrics> {
        let mut operators = HashMap::new();
        let mut operands = HashMap::new();
        let mut total_operators = 0;
        let mut total_operands = 0;

        for block in basic_blocks {
            for instruction in &block.instructions {
                // Count operators (mnemonics)
                *operators.entry(instruction.mnemonic.clone()).or_insert(0) += 1;
                total_operators += 1;

                // Count operands (simplified - split operands string)
                if !instruction.operands.is_empty() {
                    let ops: Vec<&str> = instruction.operands.split(',').collect();
                    for op in ops {
                        let trimmed = op.trim();
                        if !trimmed.is_empty() {
                            *operands.entry(trimmed.to_string()).or_insert(0) += 1;
                            total_operands += 1;
                        }
                    }
                }
            }
        }

        let n1 = operators.len() as u32; // Distinct operators
        let n2 = operands.len() as u32; // Distinct operands
        let capital_n1 = total_operators; // Total operators
        let capital_n2 = total_operands; // Total operands

        if n1 == 0 && n2 == 0 {
            return None;
        }

        let vocabulary = n1 + n2;
        let length = capital_n1 + capital_n2;
        let calculated_length = (n1 as f64) * (n1 as f64).log2() + (n2 as f64) * (n2 as f64).log2();
        let volume = (length as f64) * (vocabulary as f64).log2();
        let difficulty = if n2 > 0 {
            ((n1 as f64) / 2.0) * ((capital_n2 as f64) / (n2 as f64))
        } else {
            0.0
        };
        let effort = difficulty * volume;
        let time = effort / 18.0; // Assuming 18 mental discriminations per second
        let bugs = volume / 3000.0; // Estimated bugs

        Some(crate::types::HalsteadMetrics {
            n1,
            n2,
            capital_n1,
            capital_n2,
            vocabulary,
            length,
            calculated_length,
            volume,
            difficulty,
            effort,
            time,
            bugs,
        })
    }

    /// Calculate maintainability index
    fn calculate_maintainability_index(
        &self,
        halstead: &crate::types::HalsteadMetrics,
        cyclomatic_complexity: u32,
        lines_of_code: u32,
    ) -> Option<f64> {
        if halstead.volume <= 0.0 || lines_of_code == 0 {
            return None;
        }

        // Maintainability Index = 171 - 5.2 * ln(HV) - 0.23 * CC - 16.2 * ln(LOC)
        // Where HV = Halstead Volume, CC = Cyclomatic Complexity, LOC = Lines of Code
        let mi = 171.0
            - 5.2 * halstead.volume.ln()
            - 0.23 * (cyclomatic_complexity as f64)
            - 16.2 * (lines_of_code as f64).ln();

        // Clamp to 0-100 range
        Some(mi.clamp(0.0, 100.0))
    }

    /// Perform enhanced loop analysis
    pub fn analyze_loops(
        &mut self,
        basic_blocks: &mut [BasicBlock],
    ) -> Result<Vec<crate::types::Loop>> {
        if !self.config.enable_advanced_loops {
            return Ok(Vec::new());
        }

        let mut loops = Vec::new();
        let mut visited = vec![false; basic_blocks.len()];
        let mut in_stack = vec![false; basic_blocks.len()];
        let mut back_edges = Vec::new();

        // Find back edges using DFS
        for i in 0..basic_blocks.len() {
            if !visited[i] {
                self.find_back_edges(
                    i,
                    basic_blocks,
                    &mut visited,
                    &mut in_stack,
                    &mut back_edges,
                );
            }
        }

        // Analyze each back edge to identify loops
        for (tail, head) in back_edges {
            if let Some(loop_info) = self.analyze_natural_loop(head, tail, basic_blocks) {
                loops.push(loop_info);
            }
        }

        // Classify loop types and detect induction variables
        for loop_info in &mut loops {
            self.classify_loop_type(loop_info, basic_blocks);
            self.detect_induction_variables(loop_info, basic_blocks);
        }

        Ok(loops)
    }

    /// Find back edges using DFS
    #[allow(clippy::only_used_in_recursion)]
    fn find_back_edges(
        &self,
        node: usize,
        basic_blocks: &[BasicBlock],
        visited: &mut [bool],
        in_stack: &mut [bool],
        back_edges: &mut Vec<(usize, usize)>,
    ) {
        visited[node] = true;
        in_stack[node] = true;

        for &successor in &basic_blocks[node].successors {
            if !visited[successor] {
                self.find_back_edges(successor, basic_blocks, visited, in_stack, back_edges);
            } else if in_stack[successor] {
                // Found back edge: node -> successor
                back_edges.push((node, successor));
            }
        }

        in_stack[node] = false;
    }

    /// Analyze a natural loop given a back edge
    fn analyze_natural_loop(
        &self,
        header: usize,
        tail: usize,
        basic_blocks: &[BasicBlock],
    ) -> Option<crate::types::Loop> {
        let mut loop_blocks = HashSet::new();
        let mut worklist = Vec::new();

        // Start with the header and tail
        loop_blocks.insert(header);
        loop_blocks.insert(tail);
        worklist.push(tail);

        // Find all blocks in the loop using backwards traversal
        while let Some(current) = worklist.pop() {
            for &pred in &basic_blocks[current].predecessors {
                if !loop_blocks.contains(&pred) {
                    loop_blocks.insert(pred);
                    worklist.push(pred);
                }
            }
        }

        // Find exit blocks
        let mut exit_blocks = Vec::new();
        for &block_id in &loop_blocks {
            for &successor in &basic_blocks[block_id].successors {
                if !loop_blocks.contains(&successor) {
                    exit_blocks.push(successor);
                }
            }
        }

        let body_blocks: Vec<usize> = loop_blocks.into_iter().filter(|&id| id != header).collect();

        Some(crate::types::Loop {
            header_block: header,
            body_blocks,
            exit_blocks,
            loop_type: crate::types::LoopType::Unknown, // Will be classified later
            induction_variables: Vec::new(),            // Will be detected later
            is_natural: true,                           // Natural loops by definition
            nesting_level: 0,                           // Will be calculated later
        })
    }

    /// Classify the type of loop
    fn classify_loop_type(&self, loop_info: &mut crate::types::Loop, basic_blocks: &[BasicBlock]) {
        let header_block = &basic_blocks[loop_info.header_block];

        // Analyze the loop header to determine loop type
        if let Some(last_instruction) = header_block.instructions.last() {
            match last_instruction.mnemonic.as_str() {
                // While loop pattern: test at beginning
                "cmp" | "test" => {
                    loop_info.loop_type = crate::types::LoopType::While;
                }
                // For loop pattern: has induction variable
                "inc" | "dec" | "add" | "sub" => {
                    loop_info.loop_type = crate::types::LoopType::For;
                }
                // Loop instruction
                "loop" | "loope" | "loopne" => {
                    loop_info.loop_type = crate::types::LoopType::For;
                }
                _ => {
                    // Check if it's a do-while (test at end)
                    if !loop_info.exit_blocks.is_empty() {
                        let exit_block = &basic_blocks[loop_info.exit_blocks[0]];
                        if let Some(exit_instruction) = exit_block.instructions.first() {
                            if matches!(exit_instruction.mnemonic.as_str(), "cmp" | "test") {
                                loop_info.loop_type = crate::types::LoopType::DoWhile;
                            }
                        }
                    }

                    // Check for infinite loop (no clear exit)
                    if loop_info.exit_blocks.is_empty() {
                        loop_info.loop_type = crate::types::LoopType::Infinite;
                    }
                }
            }
        }

        // If still unknown, classify as natural or irreducible
        if loop_info.loop_type == crate::types::LoopType::Unknown {
            loop_info.loop_type = if loop_info.is_natural {
                crate::types::LoopType::Natural
            } else {
                crate::types::LoopType::Irreducible
            };
        }
    }

    /// Detect induction variables in a loop
    fn detect_induction_variables(
        &self,
        loop_info: &mut crate::types::Loop,
        basic_blocks: &[BasicBlock],
    ) {
        let mut induction_vars = HashSet::new();

        // Look for variables that are incremented/decremented in the loop
        for &block_id in &loop_info.body_blocks {
            let block = &basic_blocks[block_id];
            for instruction in &block.instructions {
                match instruction.mnemonic.as_str() {
                    "inc" | "dec" | "add" | "sub" => {
                        // Extract operand as potential induction variable
                        if !instruction.operands.is_empty() {
                            let operand =
                                instruction.operands.split(',').next().unwrap_or("").trim();
                            if !operand.is_empty()
                                && !operand.starts_with('#')
                                && !operand.starts_with('$')
                            {
                                induction_vars.insert(operand.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        loop_info.induction_variables = induction_vars.into_iter().collect();
    }

    /// Build dominator tree for enhanced block classification
    pub fn build_dominator_tree(&mut self, basic_blocks: &mut [BasicBlock]) -> Result<()> {
        if basic_blocks.is_empty() {
            return Ok(());
        }

        let n = basic_blocks.len();
        let mut dominators = vec![None; n];
        dominators[0] = Some(0); // Entry block dominates itself

        // Iterative algorithm to compute dominators
        let mut changed = true;
        while changed {
            changed = false;
            for i in 1..n {
                let mut new_dom = None;

                // Find first processed predecessor
                for &pred in &basic_blocks[i].predecessors {
                    if dominators[pred].is_some() {
                        new_dom = Some(pred);
                        break;
                    }
                }

                // Intersect with all other processed predecessors
                if let Some(mut dom) = new_dom {
                    for &pred in &basic_blocks[i].predecessors {
                        if let Some(pred_dom) = dominators[pred] {
                            dom = self.intersect_dominators(dom, pred_dom, &dominators);
                        }
                    }

                    if dominators[i] != Some(dom) {
                        dominators[i] = Some(dom);
                        changed = true;
                    }
                }
            }
        }

        // Set dominator information in basic blocks
        for (i, &dom) in dominators.iter().enumerate() {
            basic_blocks[i].dominator = dom;
        }

        Ok(())
    }

    /// Intersect two dominators to find common dominator
    fn intersect_dominators(
        &self,
        mut b1: usize,
        mut b2: usize,
        dominators: &[Option<usize>],
    ) -> usize {
        while b1 != b2 {
            while b1 > b2 {
                if let Some(dom) = dominators[b1] {
                    b1 = dom;
                } else {
                    break;
                }
            }
            while b2 > b1 {
                if let Some(dom) = dominators[b2] {
                    b2 = dom;
                } else {
                    break;
                }
            }
        }
        b1
    }

    /// Classify basic block types based on their role in control flow
    pub fn classify_block_types(&mut self, basic_blocks: &mut [BasicBlock]) -> Result<()> {
        if basic_blocks.is_empty() {
            return Ok(());
        }

        // Entry block
        basic_blocks[0].block_type = crate::types::BlockType::Entry;

        // Classify other blocks
        #[allow(clippy::needless_range_loop)]
        for i in 1..basic_blocks.len() {
            let block = &basic_blocks[i];

            // Exit blocks (no successors)
            if block.successors.is_empty() {
                basic_blocks[i].block_type = crate::types::BlockType::Exit;
                continue;
            }

            // Return blocks
            if let Some(last_instruction) = block.instructions.last() {
                match last_instruction.flow {
                    FlowType::Return => {
                        basic_blocks[i].block_type = crate::types::BlockType::Return;
                        continue;
                    }
                    FlowType::Call(_) => {
                        basic_blocks[i].block_type = crate::types::BlockType::Call;
                        continue;
                    }
                    FlowType::ConditionalJump(_) => {
                        basic_blocks[i].block_type = crate::types::BlockType::Conditional;
                        continue;
                    }
                    _ => {}
                }
            }

            // Default to normal block
            basic_blocks[i].block_type = crate::types::BlockType::Normal;
        }

        Ok(())
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
