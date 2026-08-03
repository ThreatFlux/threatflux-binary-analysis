//! Control flow analysis for binary programs
//!
//! This module provides functionality to analyze control flow in binary programs,
//! including basic block identification, control flow graph construction, and
//! complexity metrics calculation.

use crate::{
    BinaryError, BinaryFile, Result,
    disasm::{Disassembler, DisassemblyConfig, section_file_data},
    types::{
        Architecture, BasicBlock, ComplexityMetrics, ControlFlow as FlowType, ControlFlowGraph,
        Function, Instruction,
    },
};
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
    /// Maximum number of instructions accepted per function.
    pub max_instructions: usize,
    /// Maximum number of discovered functions accepted for one analysis.
    pub max_functions: usize,
    /// Maximum number of instructions accepted across all discovered functions.
    pub max_total_instructions: usize,
    /// Maximum number of advanced loops retained across one analysis.
    pub max_loops: usize,
    /// Maximum aggregate number of basic-block memberships retained in loops.
    ///
    /// A block that belongs to two loops consumes two memberships.
    pub max_total_loop_body_blocks: usize,
    /// Enable loop detection
    pub detect_loops: bool,
    /// Enable complexity metrics calculation
    pub calculate_metrics: bool,
    /// Enable cognitive complexity calculation
    pub enable_cognitive_complexity: bool,
    /// Enable advanced loop analysis
    pub enable_advanced_loops: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_instructions: 10000,
            max_functions: 10_000,
            max_total_instructions: 1_000_000,
            max_loops: 10_000,
            max_total_loop_body_blocks: 1_000_000,
            detect_loops: true,
            calculate_metrics: true,
            enable_cognitive_complexity: true,
            enable_advanced_loops: true,
        }
    }
}

#[derive(Clone, Copy)]
struct LoopBudget {
    remaining_loops: usize,
    remaining_body_blocks: usize,
    configured_max_loops: usize,
    configured_max_body_blocks: usize,
}

impl LoopBudget {
    fn full(config: &AnalysisConfig) -> Self {
        Self {
            remaining_loops: config.max_loops,
            remaining_body_blocks: config.max_total_loop_body_blocks,
            configured_max_loops: config.max_loops,
            configured_max_body_blocks: config.max_total_loop_body_blocks,
        }
    }
}

enum FunctionAnalysisFailure {
    Recoverable(BinaryError),
    ResourceLimit(BinaryError),
}

impl FunctionAnalysisFailure {
    fn into_error(self) -> BinaryError {
        match self {
            Self::Recoverable(error) | Self::ResourceLimit(error) => error,
        }
    }
}

struct FunctionAnalysis {
    graph: ControlFlowGraph,
    loop_count: usize,
    loop_body_blocks: usize,
}

struct DominatorIndex {
    entry: Vec<usize>,
    exit: Vec<usize>,
    nesting_depth: Vec<u32>,
}

impl DominatorIndex {
    fn dominates(&self, dominator: usize, block: usize) -> bool {
        self.entry.get(dominator).is_some_and(|&dominator_entry| {
            self.entry.get(block).is_some_and(|&block_entry| {
                dominator_entry <= block_entry && self.exit[block] <= self.exit[dominator]
            })
        })
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
        // Get functions from symbols
        let functions = self.extract_functions(binary)?;
        let mut cfgs = Vec::new();
        cfgs.try_reserve(functions.len())
            .map_err(|error| Self::allocation_error("control-flow result graphs", error))?;
        let mut total_instructions = 0_usize;
        let mut total_loops = 0_usize;
        let mut total_loop_body_blocks = 0_usize;
        let mut last_error = None;

        for function in &functions {
            let remaining_instructions = self
                .config
                .max_total_instructions
                .saturating_sub(total_instructions);
            let decode_limit = self
                .config
                .max_instructions
                .saturating_add(1)
                .min(remaining_instructions.saturating_add(1));

            match self.get_function_instructions(binary, function, decode_limit) {
                Ok(instructions) => {
                    total_instructions = self.validate_instruction_count(
                        function,
                        instructions.len(),
                        total_instructions,
                    )?;
                    let loop_budget = LoopBudget {
                        remaining_loops: self.config.max_loops.saturating_sub(total_loops),
                        remaining_body_blocks: self
                            .config
                            .max_total_loop_body_blocks
                            .saturating_sub(total_loop_body_blocks),
                        configured_max_loops: self.config.max_loops,
                        configured_max_body_blocks: self.config.max_total_loop_body_blocks,
                    };
                    match self.analyze_function_instructions(function, &instructions, loop_budget) {
                        Ok(analysis) => {
                            total_loops =
                                total_loops
                                    .checked_add(analysis.loop_count)
                                    .ok_or_else(|| {
                                        BinaryError::control_flow("Loop count overflowed usize")
                                    })?;
                            total_loop_body_blocks = total_loop_body_blocks
                                .checked_add(analysis.loop_body_blocks)
                                .ok_or_else(|| {
                                    BinaryError::control_flow(
                                        "Loop body membership count overflowed usize",
                                    )
                                })?;
                            cfgs.push(analysis.graph);
                        }
                        Err(FunctionAnalysisFailure::Recoverable(error)) => {
                            last_error = Some(error);
                        }
                        Err(FunctionAnalysisFailure::ResourceLimit(error)) => return Err(error),
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }

        if cfgs.is_empty()
            && let Some(error) = last_error
        {
            return Err(error);
        }

        Ok(cfgs)
    }

    /// Analyze control flow for a specific function
    pub fn analyze_function(
        &self,
        binary: &BinaryFile,
        function: &Function,
    ) -> Result<ControlFlowGraph> {
        let decode_limit = self
            .config
            .max_instructions
            .saturating_add(1)
            .min(self.config.max_total_instructions.saturating_add(1));
        let instructions = self.get_function_instructions(binary, function, decode_limit)?;
        self.validate_instruction_count(function, instructions.len(), 0)?;
        self.analyze_function_instructions(function, &instructions, LoopBudget::full(&self.config))
            .map(|analysis| analysis.graph)
            .map_err(FunctionAnalysisFailure::into_error)
    }

    fn analyze_function_instructions(
        &self,
        function: &Function,
        instructions: &[Instruction],
        loop_budget: LoopBudget,
    ) -> std::result::Result<FunctionAnalysis, FunctionAnalysisFailure> {
        // Build basic blocks
        let mut basic_blocks = self
            .build_basic_blocks(instructions)
            .map_err(FunctionAnalysisFailure::Recoverable)?;

        // Dominators are required by loop and nesting analysis.
        let mut analyzer = self.clone();
        let dominator_index = if self.config.enable_advanced_loops || self.config.calculate_metrics
        {
            analyzer
                .build_dominator_tree(&mut basic_blocks)
                .map_err(FunctionAnalysisFailure::Recoverable)?;
            Some(
                Self::build_dominator_index(&basic_blocks)
                    .map_err(FunctionAnalysisFailure::Recoverable)?,
            )
        } else {
            None
        };

        // Calculate complexity metrics
        let complexity = if self.config.calculate_metrics {
            let dominator_index = dominator_index.as_ref().ok_or_else(|| {
                FunctionAnalysisFailure::Recoverable(BinaryError::control_flow(
                    "Dominator index was not built for complexity analysis",
                ))
            })?;
            self.calculate_complexity(&basic_blocks, dominator_index)
        } else {
            ComplexityMetrics::default()
        };

        // Perform enhanced analysis if enabled
        let loops = if self.config.enable_advanced_loops {
            let dominator_index = dominator_index.as_ref().ok_or_else(|| {
                FunctionAnalysisFailure::Recoverable(BinaryError::control_flow(
                    "Dominator index was not built for advanced loop analysis",
                ))
            })?;
            analyzer.analyze_loops_from_dominators(
                &mut basic_blocks,
                dominator_index,
                loop_budget,
            )?
        } else {
            Vec::new()
        };
        let loop_body_blocks = loops.iter().try_fold(0_usize, |total, loop_info| {
            total
                .checked_add(loop_info.body_blocks.len())
                .ok_or_else(|| {
                    FunctionAnalysisFailure::ResourceLimit(BinaryError::control_flow(
                        "Loop body membership count overflowed usize",
                    ))
                })
        })?;
        let loop_count = loops.len();

        // Classify block types
        if self.config.enable_advanced_loops {
            analyzer
                .classify_block_types(&mut basic_blocks)
                .map_err(FunctionAnalysisFailure::Recoverable)?;
        }

        Ok(FunctionAnalysis {
            graph: ControlFlowGraph {
                function: function.clone(),
                basic_blocks,
                complexity,
                loops,
            },
            loop_count,
            loop_body_blocks,
        })
    }

    /// Extract functions from binary symbols
    fn extract_functions(&self, binary: &BinaryFile) -> Result<Vec<Function>> {
        let mut functions = Vec::new();
        let mut seen_addresses = HashSet::new();
        let reservation = binary
            .symbols()
            .len()
            .min(self.config.max_functions.saturating_add(1));
        functions
            .try_reserve(reservation)
            .map_err(|error| Self::allocation_error("discovered functions", error))?;
        seen_addresses
            .try_reserve(reservation)
            .map_err(|error| Self::allocation_error("function address set", error))?;

        for symbol in binary.symbols() {
            if matches!(symbol.symbol_type, crate::types::SymbolType::Function)
                && symbol.size > 0
                && seen_addresses.insert(symbol.address)
            {
                self.ensure_function_limit(functions.len().saturating_add(1))?;
                let function = Function {
                    name: symbol.name.clone(),
                    start_address: symbol.address,
                    end_address: symbol.address.checked_add(symbol.size).ok_or_else(|| {
                        BinaryError::invalid_data(format!(
                            "Function '{}' address range overflows",
                            symbol.name
                        ))
                    })?,
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
        if let (true, Some(entry_point)) = (functions.is_empty(), binary.entry_point()) {
            self.ensure_function_limit(1)?;
            let function = Function {
                name: "_start".to_string(),
                start_address: entry_point,
                end_address: entry_point.checked_add(1000).ok_or_else(|| {
                    BinaryError::invalid_data("Entry-point address range overflows")
                })?, // Estimate when symbols are unavailable
                size: 1000,
                function_type: crate::types::FunctionType::Entrypoint,
                calling_convention: None,
                parameters: Vec::new(),
                return_type: None,
            };
            functions.push(function);
        }

        functions.sort_by(|left, right| {
            left.start_address
                .cmp(&right.start_address)
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(functions)
    }

    /// Get instructions for a function using the disassembly module
    fn get_function_instructions(
        &self,
        binary: &BinaryFile,
        function: &Function,
        max_instructions: usize,
    ) -> Result<Vec<Instruction>> {
        // Locate the section containing this function
        for section in binary.sections() {
            let start = section.address;
            let Some(end) = start.checked_add(section.size) else {
                continue;
            };

            if section.permissions.execute
                && function.start_address >= start
                && function.start_address < end
            {
                let function_size = usize::try_from(function.size).unwrap_or(usize::MAX);
                let data = section_file_data(
                    binary,
                    section,
                    function.start_address - start,
                    Some(function_size),
                )?;
                let length = data.len();
                if length == 0 {
                    return Ok(Vec::new());
                }

                let disassembler = Disassembler::with_config(
                    self.architecture,
                    DisassemblyConfig {
                        max_instructions,
                        ..DisassemblyConfig::default()
                    },
                )?;
                return disassembler.disassemble_at(data, function.start_address, length);
            }
        }

        Err(BinaryError::invalid_data(
            "Function bytes not found in any executable section",
        ))
    }

    fn ensure_function_limit(&self, actual: usize) -> Result<()> {
        if actual > self.config.max_functions {
            return Err(BinaryError::control_flow(format!(
                "Discovered function count {actual} exceeds configured max_functions {}",
                self.config.max_functions
            )));
        }
        Ok(())
    }

    fn validate_instruction_count(
        &self,
        function: &Function,
        function_instructions: usize,
        previous_total: usize,
    ) -> Result<usize> {
        if function_instructions > self.config.max_instructions {
            return Err(BinaryError::control_flow(format!(
                "Function '{}' decoded {function_instructions} instructions, exceeding configured max_instructions {}",
                function.name, self.config.max_instructions
            )));
        }

        let total = previous_total
            .checked_add(function_instructions)
            .ok_or_else(|| BinaryError::control_flow("Total instruction count overflowed usize"))?;
        if total > self.config.max_total_instructions {
            return Err(BinaryError::control_flow(format!(
                "Decoded instruction count {total} exceeds configured max_total_instructions {}",
                self.config.max_total_instructions
            )));
        }
        Ok(total)
    }

    fn allocation_error(context: &str, error: std::collections::TryReserveError) -> BinaryError {
        BinaryError::control_flow(format!("Unable to reserve {context}: {error}"))
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
                FlowType::Jump(target) | FlowType::ConditionalJump(target) => {
                    // A branch target and the instruction following a terminator start blocks.
                    block_starts.insert(*target);
                    if i + 1 < instructions.len() {
                        block_starts.insert(instructions[i + 1].address);
                    }
                }
                FlowType::Return | FlowType::Interrupt if i + 1 < instructions.len() => {
                    // Instruction after return/interrupt is a block start (if exists)
                    block_starts.insert(instructions[i + 1].address);
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
                let end_addr = instructions[i - 1]
                    .address
                    .checked_add(instructions[i - 1].size as u64)
                    .ok_or_else(|| {
                        BinaryError::invalid_data("Instruction address range overflows")
                    })?;

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
            let last_instruction = &instructions[instructions.len() - 1];
            let end_addr = last_instruction
                .address
                .checked_add(last_instruction.size as u64)
                .ok_or_else(|| BinaryError::invalid_data("Instruction address range overflows"))?;

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
                            Self::add_cfg_edge(basic_blocks, i, i + 1);
                        }
                    }
                    FlowType::Jump(target) => {
                        // Unconditional jump
                        if let Some(&target_block) = addr_to_block.get(target) {
                            Self::add_cfg_edge(basic_blocks, i, target_block);
                        }
                    }
                    FlowType::ConditionalJump(target) => {
                        // Conditional jump - two successors
                        if let Some(&target_block) = addr_to_block.get(target) {
                            Self::add_cfg_edge(basic_blocks, i, target_block);
                        }
                        // Fall through
                        if i + 1 < basic_blocks.len() {
                            Self::add_cfg_edge(basic_blocks, i, i + 1);
                        }
                    }
                    FlowType::Call(_target) => {
                        // Function call - continues to next instruction
                        if i + 1 < basic_blocks.len() {
                            Self::add_cfg_edge(basic_blocks, i, i + 1);
                        }
                        // Note: Call target is not added as successor for CFG
                    }
                    FlowType::Return | FlowType::Interrupt => {
                        // No successors
                    }
                    FlowType::Unknown => {
                        // Conservatively assume fall through
                        if i + 1 < basic_blocks.len() {
                            Self::add_cfg_edge(basic_blocks, i, i + 1);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn add_cfg_edge(basic_blocks: &mut [BasicBlock], source: usize, target: usize) {
        if !basic_blocks[source].successors.contains(&target) {
            basic_blocks[source].successors.push(target);
            basic_blocks[target].predecessors.push(source);
        }
    }

    /// Calculate complexity metrics for a control flow graph
    fn calculate_complexity(
        &self,
        basic_blocks: &[BasicBlock],
        dominator_index: &DominatorIndex,
    ) -> ComplexityMetrics {
        let basic_block_count = u32::try_from(basic_blocks.len()).unwrap_or(u32::MAX);
        let edge_count = basic_blocks.iter().fold(0_u32, |count, block| {
            count.saturating_add(u32::try_from(block.successors.len()).unwrap_or(u32::MAX))
        });

        // Cyclomatic complexity = E - N + 2P
        // Where E = edges, N = nodes, and P = weakly connected components.
        let cyclomatic_complexity = if basic_block_count > 0 {
            edge_count
                .saturating_add(self.weak_component_count(basic_blocks).saturating_mul(2))
                .saturating_sub(basic_block_count)
        } else {
            0
        };

        // Detect loops (simplified)
        let loop_count = self.detect_loops(basic_blocks);

        // Calculate nesting depth (simplified)
        let nesting_depth = dominator_index
            .nesting_depth
            .iter()
            .copied()
            .max()
            .unwrap_or(0);

        // Calculate cognitive complexity
        let cognitive_complexity = if self.config.enable_cognitive_complexity {
            self.calculate_cognitive_complexity(basic_blocks, &dominator_index.nesting_depth)
        } else {
            0
        };

        // Calculate Halstead metrics if available
        let halstead_metrics = self.calculate_halstead_metrics(basic_blocks);

        // Calculate maintainability index if Halstead metrics are available
        let maintainability_index = if let Some(ref halstead) = halstead_metrics {
            let instruction_count = basic_blocks.iter().fold(0_u32, |count, block| {
                count.saturating_add(u32::try_from(block.instructions.len()).unwrap_or(u32::MAX))
            });
            self.calculate_maintainability_index(halstead, cyclomatic_complexity, instruction_count)
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

        u32::try_from(Self::collect_back_edges(basic_blocks).len()).unwrap_or(u32::MAX)
    }

    /// Find DFS back edges without using the process call stack.
    fn collect_back_edges(basic_blocks: &[BasicBlock]) -> Vec<(usize, usize)> {
        let mut state = vec![0_u8; basic_blocks.len()];
        let mut back_edges = Vec::new();

        for root in 0..basic_blocks.len() {
            if state[root] != 0 {
                continue;
            }

            state[root] = 1;
            let mut stack = vec![(root, 0_usize)];
            while let Some(&(node, next_successor)) = stack.last() {
                if next_successor == basic_blocks[node].successors.len() {
                    state[node] = 2;
                    stack.pop();
                    continue;
                }

                if let Some(last) = stack.last_mut() {
                    last.1 += 1;
                }
                let successor = basic_blocks[node].successors[next_successor];
                match state[successor] {
                    0 => {
                        state[successor] = 1;
                        stack.push((successor, 0));
                    }
                    1 => back_edges.push((node, successor)),
                    _ => {}
                }
            }
        }

        back_edges
    }

    fn weak_component_count(&self, basic_blocks: &[BasicBlock]) -> u32 {
        let mut visited = vec![false; basic_blocks.len()];
        let mut components = 0_u32;

        for root in 0..basic_blocks.len() {
            if visited[root] {
                continue;
            }
            components = components.saturating_add(1);
            visited[root] = true;
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                for neighbor in basic_blocks[node]
                    .successors
                    .iter()
                    .chain(&basic_blocks[node].predecessors)
                    .copied()
                {
                    if !visited[neighbor] {
                        visited[neighbor] = true;
                        stack.push(neighbor);
                    }
                }
            }
        }

        components
    }

    /// Calculate cognitive complexity (different from cyclomatic complexity)
    /// Cognitive complexity measures how difficult the code is to understand
    fn calculate_cognitive_complexity(
        &self,
        basic_blocks: &[BasicBlock],
        nesting_depths: &[u32],
    ) -> u32 {
        let mut complexity = 0_u32;
        for (index, block) in basic_blocks.iter().enumerate() {
            if matches!(
                block
                    .instructions
                    .last()
                    .map(|instruction| &instruction.flow),
                Some(FlowType::ConditionalJump(_))
            ) {
                complexity = complexity.saturating_add(
                    1_u32.saturating_add(nesting_depths.get(index).copied().unwrap_or(0)),
                );
            }
        }

        complexity.saturating_add(
            u32::try_from(Self::collect_back_edges(basic_blocks).len()).unwrap_or(u32::MAX),
        )
    }

    /// Calculate Halstead metrics for software complexity
    fn calculate_halstead_metrics(
        &self,
        basic_blocks: &[BasicBlock],
    ) -> Option<crate::types::HalsteadMetrics> {
        let mut operators = HashMap::new();
        let mut operands = HashMap::new();
        let mut total_operators = 0_u32;
        let mut total_operands = 0_u32;

        for block in basic_blocks {
            for instruction in &block.instructions {
                // Count operators (mnemonics)
                let operator_count = operators
                    .entry(instruction.mnemonic.clone())
                    .or_insert(0_u32);
                *operator_count = operator_count.saturating_add(1);
                total_operators = total_operators.saturating_add(1);

                // Count operands (simplified - split operands string)
                if !instruction.operands.is_empty() {
                    for op in instruction.operands.split(',') {
                        let trimmed = op.trim();
                        if !trimmed.is_empty() {
                            let operand_count =
                                operands.entry(trimmed.to_string()).or_insert(0_u32);
                            *operand_count = operand_count.saturating_add(1);
                            total_operands = total_operands.saturating_add(1);
                        }
                    }
                }
            }
        }

        let n1 = u32::try_from(operators.len()).unwrap_or(u32::MAX); // Distinct operators
        let n2 = u32::try_from(operands.len()).unwrap_or(u32::MAX); // Distinct operands
        let capital_n1 = total_operators; // Total operators
        let capital_n2 = total_operands; // Total operands

        if n1 == 0 && n2 == 0 {
            return None;
        }

        let vocabulary = n1.saturating_add(n2);
        let length = capital_n1.saturating_add(capital_n2);
        let x_log2_x = |value: u32| {
            if value == 0 {
                0.0
            } else {
                let value = f64::from(value);
                value * value.log2()
            }
        };
        let calculated_length = x_log2_x(n1) + x_log2_x(n2);
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

        self.build_dominator_tree(basic_blocks)?;
        let dominator_index = Self::build_dominator_index(basic_blocks)?;
        self.analyze_loops_from_dominators(
            basic_blocks,
            &dominator_index,
            LoopBudget::full(&self.config),
        )
        .map_err(FunctionAnalysisFailure::into_error)
    }

    fn analyze_loops_from_dominators(
        &mut self,
        basic_blocks: &mut [BasicBlock],
        dominator_index: &DominatorIndex,
        budget: LoopBudget,
    ) -> std::result::Result<Vec<crate::types::Loop>, FunctionAnalysisFailure> {
        let mut loops = Vec::new();
        let mut total_body_blocks = 0_usize;
        let mut back_edges = Self::collect_back_edges(basic_blocks);
        back_edges.sort_unstable_by_key(|&(tail, head)| (head, tail));

        // Back edges are grouped by header so multiple latches can be merged
        // immediately instead of retaining duplicate loop bodies.
        for (tail, head) in back_edges {
            if dominator_index.dominates(head, tail) {
                let extends_existing = loops
                    .last()
                    .is_some_and(|loop_info: &crate::types::Loop| loop_info.header_block == head);
                if !extends_existing && loops.len() >= budget.remaining_loops {
                    return Err(FunctionAnalysisFailure::ResourceLimit(
                        BinaryError::control_flow(format!(
                            "Advanced loop count exceeds configured max_loops {}",
                            budget.configured_max_loops
                        )),
                    ));
                }

                let mut loop_info = self.analyze_natural_loop(
                    head,
                    tail,
                    basic_blocks,
                    dominator_index,
                    budget.configured_max_body_blocks,
                )?;

                if extends_existing {
                    let existing = loops.last_mut().expect("existing loop was checked above");
                    let old_len = existing.body_blocks.len();
                    let merged_len =
                        Self::sorted_union_len(&existing.body_blocks, &loop_info.body_blocks);
                    let added = merged_len.saturating_sub(old_len);
                    let next_total = total_body_blocks.checked_add(added).ok_or_else(|| {
                        FunctionAnalysisFailure::ResourceLimit(BinaryError::control_flow(
                            "Loop body membership count overflowed usize",
                        ))
                    })?;
                    if next_total > budget.remaining_body_blocks {
                        return Err(FunctionAnalysisFailure::ResourceLimit(
                            BinaryError::control_flow(format!(
                                "Advanced loop body membership exceeds configured max_total_loop_body_blocks {}",
                                budget.configured_max_body_blocks
                            )),
                        ));
                    }
                    existing
                        .body_blocks
                        .try_reserve(loop_info.body_blocks.len())
                        .map_err(|error| {
                            FunctionAnalysisFailure::ResourceLimit(Self::allocation_error(
                                "merged loop body blocks",
                                error,
                            ))
                        })?;
                    existing.body_blocks.append(&mut loop_info.body_blocks);
                    existing.body_blocks.sort_unstable();
                    existing.body_blocks.dedup();
                    total_body_blocks = next_total;
                } else {
                    let next_total = total_body_blocks
                        .checked_add(loop_info.body_blocks.len())
                        .ok_or_else(|| {
                            FunctionAnalysisFailure::ResourceLimit(BinaryError::control_flow(
                                "Loop body membership count overflowed usize",
                            ))
                        })?;
                    if next_total > budget.remaining_body_blocks {
                        return Err(FunctionAnalysisFailure::ResourceLimit(
                            BinaryError::control_flow(format!(
                                "Advanced loop body membership exceeds configured max_total_loop_body_blocks {}",
                                budget.configured_max_body_blocks
                            )),
                        ));
                    }
                    loops.try_reserve(1).map_err(|error| {
                        FunctionAnalysisFailure::ResourceLimit(Self::allocation_error(
                            "advanced loops",
                            error,
                        ))
                    })?;
                    loops.push(loop_info);
                    total_body_blocks = next_total;
                }
            }
        }

        // Classify loop types and detect induction variables
        for loop_info in &mut loops {
            Self::refresh_loop_exits(loop_info, basic_blocks)
                .map_err(FunctionAnalysisFailure::ResourceLimit)?;
            self.classify_loop_type(loop_info);
            self.detect_induction_variables(loop_info, basic_blocks);
        }

        let mut containing_loops = Vec::new();
        containing_loops
            .try_reserve_exact(basic_blocks.len())
            .map_err(|error| {
                FunctionAnalysisFailure::ResourceLimit(Self::allocation_error(
                    "loop nesting counters",
                    error,
                ))
            })?;
        containing_loops.resize(basic_blocks.len(), 0_u32);
        for loop_info in &loops {
            containing_loops[loop_info.header_block] =
                containing_loops[loop_info.header_block].saturating_add(1);
            for &block in &loop_info.body_blocks {
                containing_loops[block] = containing_loops[block].saturating_add(1);
            }
        }
        for loop_info in &mut loops {
            loop_info.nesting_level = containing_loops[loop_info.header_block];
        }

        Ok(loops)
    }

    /// Analyze a natural loop given a back edge
    fn analyze_natural_loop(
        &self,
        header: usize,
        tail: usize,
        basic_blocks: &[BasicBlock],
        dominator_index: &DominatorIndex,
        max_body_blocks: usize,
    ) -> std::result::Result<crate::types::Loop, FunctionAnalysisFailure> {
        let mut loop_blocks = HashSet::new();
        let mut worklist = Vec::new();
        let reservation = basic_blocks.len().min(max_body_blocks.saturating_add(1));
        loop_blocks.try_reserve(reservation).map_err(|error| {
            FunctionAnalysisFailure::ResourceLimit(Self::allocation_error(
                "natural loop block set",
                error,
            ))
        })?;
        worklist.try_reserve(reservation).map_err(|error| {
            FunctionAnalysisFailure::ResourceLimit(Self::allocation_error(
                "natural loop worklist",
                error,
            ))
        })?;

        // Start with the header and tail
        loop_blocks.insert(header);
        if tail != header {
            loop_blocks.insert(tail);
            if max_body_blocks == 0 {
                return Err(FunctionAnalysisFailure::ResourceLimit(
                    BinaryError::control_flow(format!(
                        "Advanced loop body membership exceeds configured max_total_loop_body_blocks {max_body_blocks}"
                    )),
                ));
            }
            worklist.push(tail);
        }

        // Find all blocks in the loop using backwards traversal
        while let Some(current) = worklist.pop() {
            for &pred in &basic_blocks[current].predecessors {
                if !loop_blocks.contains(&pred) && dominator_index.dominates(header, pred) {
                    if loop_blocks.len().saturating_sub(1) >= max_body_blocks {
                        return Err(FunctionAnalysisFailure::ResourceLimit(
                            BinaryError::control_flow(format!(
                                "Advanced loop body membership exceeds configured max_total_loop_body_blocks {max_body_blocks}"
                            )),
                        ));
                    }
                    loop_blocks.insert(pred);
                    worklist.push(pred);
                }
            }
        }

        let mut body_blocks: Vec<usize> =
            loop_blocks.into_iter().filter(|&id| id != header).collect();
        body_blocks.sort_unstable();

        Ok(crate::types::Loop {
            header_block: header,
            body_blocks,
            exit_blocks: Vec::new(),
            loop_type: crate::types::LoopType::Unknown, // Will be classified later
            induction_variables: Vec::new(),            // Will be detected later
            is_natural: true,                           // Natural loops by definition
            nesting_level: 0,                           // Will be calculated later
        })
    }

    fn sorted_union_len(left: &[usize], right: &[usize]) -> usize {
        let (mut left_index, mut right_index, mut count) = (0_usize, 0_usize, 0_usize);
        while left_index < left.len() && right_index < right.len() {
            count = count.saturating_add(1);
            match left[left_index].cmp(&right[right_index]) {
                std::cmp::Ordering::Less => left_index += 1,
                std::cmp::Ordering::Greater => right_index += 1,
                std::cmp::Ordering::Equal => {
                    left_index += 1;
                    right_index += 1;
                }
            }
        }
        count
            .saturating_add(left.len().saturating_sub(left_index))
            .saturating_add(right.len().saturating_sub(right_index))
    }

    fn refresh_loop_exits(
        loop_info: &mut crate::types::Loop,
        basic_blocks: &[BasicBlock],
    ) -> Result<()> {
        let mut blocks = HashSet::new();
        blocks
            .try_reserve(loop_info.body_blocks.len().saturating_add(1))
            .map_err(|error| Self::allocation_error("loop exit block set", error))?;
        blocks.insert(loop_info.header_block);
        blocks.extend(loop_info.body_blocks.iter().copied());

        loop_info.exit_blocks.clear();
        for &block in &blocks {
            loop_info
                .exit_blocks
                .try_reserve(basic_blocks[block].successors.len())
                .map_err(|error| Self::allocation_error("loop exit blocks", error))?;
            loop_info.exit_blocks.extend(
                basic_blocks[block]
                    .successors
                    .iter()
                    .copied()
                    .filter(|successor| !blocks.contains(successor)),
            );
        }
        loop_info.exit_blocks.sort_unstable();
        loop_info.exit_blocks.dedup();
        Ok(())
    }

    /// Classify only distinctions that can be established from a CFG alone.
    fn classify_loop_type(&self, loop_info: &mut crate::types::Loop) {
        loop_info.loop_type = if loop_info.exit_blocks.is_empty() {
            crate::types::LoopType::Infinite
        } else if loop_info.is_natural {
            crate::types::LoopType::Natural
        } else {
            crate::types::LoopType::Irreducible
        };
    }

    /// Detect induction variables in a loop
    fn detect_induction_variables(
        &self,
        loop_info: &mut crate::types::Loop,
        basic_blocks: &[BasicBlock],
    ) {
        let mut induction_vars = HashSet::new();

        // Look for variables that are incremented/decremented in the loop
        for block_id in
            std::iter::once(loop_info.header_block).chain(loop_info.body_blocks.iter().copied())
        {
            let block = &basic_blocks[block_id];
            for instruction in &block.instructions {
                match instruction.mnemonic.as_str() {
                    "inc" | "dec" | "add" | "sub" if !instruction.operands.is_empty() => {
                        // Extract operand as potential induction variable
                        let operand = instruction.operands.split(',').next().unwrap_or("").trim();
                        if !operand.is_empty()
                            && !operand.starts_with('#')
                            && !operand.starts_with('$')
                        {
                            induction_vars.insert(operand.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        loop_info.induction_variables = induction_vars.into_iter().collect();
        loop_info.induction_variables.sort_unstable();
    }

    /// Build dominator tree for enhanced block classification
    pub fn build_dominator_tree(&mut self, basic_blocks: &mut [BasicBlock]) -> Result<()> {
        if basic_blocks.is_empty() {
            return Ok(());
        }
        Self::validate_cfg(basic_blocks)?;

        let n = basic_blocks.len();
        let reverse_postorder = Self::reverse_postorder(basic_blocks);
        let mut rpo_index = vec![usize::MAX; n];
        for (index, &block) in reverse_postorder.iter().enumerate() {
            rpo_index[block] = index;
        }
        let mut dominators = vec![None; n];
        dominators[0] = Some(0); // Entry block dominates itself

        // Cooper-Harvey-Kennedy iterative immediate-dominator algorithm.
        let mut changed = true;
        while changed {
            changed = false;
            for &block in reverse_postorder.iter().skip(1) {
                let mut processed_predecessors = basic_blocks[block]
                    .predecessors
                    .iter()
                    .copied()
                    .filter(|&pred| dominators[pred].is_some());
                let Some(mut new_dominator) = processed_predecessors.next() else {
                    continue;
                };

                for predecessor in processed_predecessors {
                    new_dominator = Self::intersect_dominators(
                        new_dominator,
                        predecessor,
                        &dominators,
                        &rpo_index,
                    )
                    .ok_or_else(|| {
                        BinaryError::invalid_data("Malformed dominator predecessor chain")
                    })?;
                }

                if dominators[block] != Some(new_dominator) {
                    dominators[block] = Some(new_dominator);
                    changed = true;
                }
            }
        }

        // Set dominator information in basic blocks
        for (i, &dom) in dominators.iter().enumerate() {
            basic_blocks[i].dominator = dom;
        }

        Ok(())
    }

    /// Index the immediate-dominator forest once for linear-time nesting-depth
    /// calculation and constant-time dominance queries.
    fn build_dominator_index(basic_blocks: &[BasicBlock]) -> Result<DominatorIndex> {
        let block_count = basic_blocks.len();
        let mut first_child = vec![None; block_count];
        let mut next_sibling = vec![None; block_count];
        let mut roots = Vec::new();
        roots
            .try_reserve(block_count)
            .map_err(|error| Self::allocation_error("dominator roots", error))?;

        for (block, basic_block) in basic_blocks.iter().enumerate() {
            match basic_block.dominator {
                None => roots.push(block),
                Some(parent) if parent == block => roots.push(block),
                Some(parent) => {
                    if parent >= block_count {
                        return Err(BinaryError::invalid_data(format!(
                            "Basic block {block} has out-of-range dominator {parent}"
                        )));
                    }
                    next_sibling[block] = first_child[parent];
                    first_child[parent] = Some(block);
                }
            }
        }

        let mut entry = vec![usize::MAX; block_count];
        let mut exit = vec![usize::MAX; block_count];
        let mut nesting_depth = vec![0_u32; block_count];
        let mut stack = Vec::new();
        stack
            .try_reserve(block_count.saturating_mul(2))
            .map_err(|error| Self::allocation_error("dominator traversal", error))?;
        let mut clock = 0_usize;

        for root in roots {
            if entry[root] != usize::MAX {
                continue;
            }
            stack.push((root, false));
            while let Some((block, exiting)) = stack.pop() {
                if exiting {
                    exit[block] = clock;
                    clock = clock.saturating_add(1);
                    continue;
                }
                if entry[block] != usize::MAX {
                    return Err(BinaryError::invalid_data(
                        "Immediate-dominator relation contains a cycle",
                    ));
                }

                entry[block] = clock;
                clock = clock.saturating_add(1);
                if let Some(parent) = basic_blocks[block]
                    .dominator
                    .filter(|&parent| parent != block)
                {
                    nesting_depth[block] = nesting_depth[parent]
                        .saturating_add(u32::from(basic_blocks[parent].successors.len() > 1));
                }

                stack.push((block, true));
                let mut child = first_child[block];
                while let Some(child_block) = child {
                    stack.push((child_block, false));
                    child = next_sibling[child_block];
                }
            }
        }

        if entry.contains(&usize::MAX) {
            return Err(BinaryError::invalid_data(
                "Immediate-dominator relation contains a rootless cycle",
            ));
        }

        Ok(DominatorIndex {
            entry,
            exit,
            nesting_depth,
        })
    }

    /// Intersect two dominators to find common dominator
    fn intersect_dominators(
        mut b1: usize,
        mut b2: usize,
        dominators: &[Option<usize>],
        rpo_index: &[usize],
    ) -> Option<usize> {
        while b1 != b2 {
            while rpo_index[b1] > rpo_index[b2] {
                b1 = dominators[b1]?;
            }
            while rpo_index[b2] > rpo_index[b1] {
                b2 = dominators[b2]?;
            }
        }
        Some(b1)
    }

    fn reverse_postorder(basic_blocks: &[BasicBlock]) -> Vec<usize> {
        let mut visited = vec![false; basic_blocks.len()];
        let mut postorder = Vec::with_capacity(basic_blocks.len());
        visited[0] = true;
        let mut stack = vec![(0_usize, 0_usize)];

        while let Some(&(block, successor_index)) = stack.last() {
            if successor_index == basic_blocks[block].successors.len() {
                postorder.push(block);
                stack.pop();
                continue;
            }

            if let Some(last) = stack.last_mut() {
                last.1 += 1;
            }
            let successor = basic_blocks[block].successors[successor_index];
            if !visited[successor] {
                visited[successor] = true;
                stack.push((successor, 0));
            }
        }

        postorder.reverse();
        postorder
    }

    fn validate_cfg(basic_blocks: &[BasicBlock]) -> Result<()> {
        let mut successor_edges = HashSet::new();
        let mut predecessor_edges = HashSet::new();
        for (source, block) in basic_blocks.iter().enumerate() {
            for &target in &block.successors {
                if basic_blocks.get(target).is_none() {
                    return Err(BinaryError::invalid_data(format!(
                        "Basic block {source} has out-of-range successor {target}"
                    )));
                }
                if !successor_edges.insert((source, target)) {
                    return Err(BinaryError::invalid_data(format!(
                        "CFG contains duplicate successor edge {source} -> {target}"
                    )));
                }
            }
            for &predecessor in &block.predecessors {
                if basic_blocks.get(predecessor).is_none() {
                    return Err(BinaryError::invalid_data(format!(
                        "Basic block {source} has out-of-range predecessor {predecessor}"
                    )));
                }
                if !predecessor_edges.insert((predecessor, source)) {
                    return Err(BinaryError::invalid_data(format!(
                        "CFG contains duplicate predecessor edge {predecessor} -> {source}"
                    )));
                }
            }
        }
        if successor_edges != predecessor_edges {
            return Err(BinaryError::invalid_data(
                "CFG successor and predecessor edge sets are inconsistent",
            ));
        }
        Ok(())
    }

    /// Classify basic block types based on their role in control flow
    pub fn classify_block_types(&mut self, basic_blocks: &mut [BasicBlock]) -> Result<()> {
        if basic_blocks.is_empty() {
            return Ok(());
        }
        Self::validate_cfg(basic_blocks)?;

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

    struct TestFormat {
        sections: Vec<Section>,
        symbols: Vec<Symbol>,
        metadata: BinaryMetadata,
    }

    impl BinaryFormatTrait for TestFormat {
        fn format_type(&self) -> BinaryFormat {
            BinaryFormat::Raw
        }

        fn architecture(&self) -> Architecture {
            Architecture::X86_64
        }

        fn entry_point(&self) -> Option<u64> {
            None
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

    fn function_symbol(name: &str, address: u64) -> Symbol {
        Symbol {
            name: name.to_string(),
            demangled_name: None,
            address,
            size: 1,
            symbol_type: SymbolType::Function,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: None,
        }
    }

    fn function_analysis_binary(include_valid_function: bool) -> BinaryFile {
        let data = vec![0xc3];
        let mut sections = vec![Section {
            name: ".invalid".to_string(),
            address: 0x1000,
            size: 1,
            offset: 2,
            file_size: 1,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            section_type: SectionType::Code,
            data: None,
        }];
        let mut symbols = vec![function_symbol("invalid", 0x1000)];

        if include_valid_function {
            sections.push(Section {
                name: ".valid".to_string(),
                address: 0x2000,
                size: 1,
                offset: 0,
                file_size: 1,
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                section_type: SectionType::Code,
                data: Some(data.clone()),
            });
            symbols.push(function_symbol("valid", 0x2000));
        }

        let metadata = BinaryMetadata {
            size: data.len(),
            format: BinaryFormat::Raw,
            architecture: Architecture::X86_64,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };

        BinaryFile {
            data,
            parsed: Box::new(TestFormat {
                sections,
                symbols,
                metadata,
            }),
        }
    }

    fn looping_functions_binary() -> BinaryFile {
        // Two independent x86 short jumps, each targeting its own address.
        let data = vec![0xeb, 0xfe, 0xeb, 0xfe];
        let sections = vec![Section {
            name: ".text".to_string(),
            address: 0x1000,
            size: data.len() as u64,
            offset: 0,
            file_size: data.len() as u64,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            section_type: SectionType::Code,
            data: Some(data.clone()),
        }];
        let symbols = [0x1000, 0x1002]
            .into_iter()
            .enumerate()
            .map(|(index, address)| {
                let mut symbol = function_symbol(&format!("loop_{index}"), address);
                symbol.size = 2;
                symbol
            })
            .collect();
        let metadata = BinaryMetadata {
            size: data.len(),
            format: BinaryFormat::Raw,
            architecture: Architecture::X86_64,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures::default(),
        };

        BinaryFile {
            data,
            parsed: Box::new(TestFormat {
                sections,
                symbols,
                metadata,
            }),
        }
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);
        assert_eq!(analyzer.architecture, Architecture::X86_64);
    }

    #[test]
    fn test_config_default() {
        let config = AnalysisConfig::default();
        assert_eq!(config.max_instructions, 10000);
        assert_eq!(config.max_functions, 10_000);
        assert_eq!(config.max_total_instructions, 1_000_000);
        assert_eq!(config.max_loops, 10_000);
        assert_eq!(config.max_total_loop_body_blocks, 1_000_000);
        assert!(config.detect_loops);
        assert!(config.calculate_metrics);
    }

    #[test]
    fn analyze_binary_returns_error_when_every_function_fails() {
        let binary = function_analysis_binary(false);
        let analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::InvalidData(message) if message.contains("beyond the end of the file"))
        );
    }

    #[test]
    fn analyze_binary_preserves_partial_function_success() {
        let binary = function_analysis_binary(true);
        let analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_instructions: 1,
                max_functions: 2,
                max_total_instructions: 1,
                ..AnalysisConfig::default()
            },
        );

        let cfgs = analyzer.analyze_binary(&binary).unwrap();

        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].function.name, "valid");
    }

    #[test]
    fn analyze_binary_rejects_function_count_above_configured_cap() {
        let binary = function_analysis_binary(true);
        let analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_functions: 1,
                ..AnalysisConfig::default()
            },
        );

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_functions 1"))
        );
    }

    #[test]
    fn analyze_binary_rejects_total_instructions_above_configured_cap() {
        let binary = function_analysis_binary(true);
        let analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_total_instructions: 0,
                ..AnalysisConfig::default()
            },
        );

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_total_instructions 0"))
        );
    }

    #[test]
    fn analyze_binary_rejects_per_function_instruction_overflow() {
        let binary = function_analysis_binary(true);
        let analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_instructions: 0,
                ..AnalysisConfig::default()
            },
        );

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_instructions 0"))
        );
    }

    #[test]
    fn analyze_binary_rejects_aggregate_loop_count_above_limit() {
        let binary = looping_functions_binary();
        let analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_loops: 1,
                ..AnalysisConfig::default()
            },
        );

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_loops 1"))
        );
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

    fn instruction(address: u64, mnemonic: &str, flow: FlowType) -> Instruction {
        Instruction {
            address,
            bytes: vec![0x90],
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            category: InstructionCategory::Control,
            flow,
            size: 1,
        }
    }

    #[test]
    fn calls_do_not_split_intra_procedural_basic_blocks() {
        let instructions = vec![
            instruction(0x1000, "call", FlowType::Call(0x2000)),
            instruction(0x1001, "nop", FlowType::Sequential),
            instruction(0x1002, "ret", FlowType::Return),
        ];

        let analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);
        let blocks = analyzer.build_basic_blocks(&instructions).unwrap();

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].instructions.len(), 3);
    }

    #[test]
    fn coincident_branch_and_fallthrough_edges_are_not_duplicated() {
        let instructions = vec![
            instruction(0x1000, "je", FlowType::ConditionalJump(0x1001)),
            instruction(0x1001, "ret", FlowType::Return),
        ];

        let analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);
        let blocks = analyzer.build_basic_blocks(&instructions).unwrap();

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].successors, vec![1]);
        assert_eq!(blocks[1].predecessors, vec![0]);
    }

    #[test]
    fn halstead_metrics_remain_finite_without_operands() {
        let instructions = vec![
            instruction(0x1000, "nop", FlowType::Sequential),
            instruction(0x1001, "ret", FlowType::Return),
        ];
        let mut analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);
        let mut blocks = analyzer.build_basic_blocks(&instructions).unwrap();
        analyzer.build_dominator_tree(&mut blocks).unwrap();
        let dominator_index = ControlFlowAnalyzer::build_dominator_index(&blocks).unwrap();
        let metrics = analyzer.calculate_complexity(&blocks, &dominator_index);
        let halstead = metrics.halstead_metrics.unwrap();

        assert!(halstead.calculated_length.is_finite());
        assert!(halstead.volume.is_finite());
    }

    #[test]
    fn public_cfg_algorithms_reject_out_of_range_edges() {
        let mut blocks = vec![BasicBlock {
            id: 0,
            start_address: 0,
            end_address: 1,
            instructions: vec![instruction(0, "jmp", FlowType::Jump(2))],
            successors: vec![1],
            predecessors: Vec::new(),
            block_type: BlockType::Normal,
            dominator: None,
            dominance_frontier: Vec::new(),
        }];
        let mut analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);

        assert!(analyzer.build_dominator_tree(&mut blocks).is_err());
        assert!(analyzer.analyze_loops(&mut blocks).is_err());
    }

    fn block(id: usize, successors: Vec<usize>, predecessors: Vec<usize>) -> BasicBlock {
        BasicBlock {
            id,
            start_address: id as u64,
            end_address: id as u64 + 1,
            instructions: vec![instruction(id as u64, "jmp", FlowType::Jump(0))],
            successors,
            predecessors,
            block_type: BlockType::Normal,
            dominator: None,
            dominance_frontier: Vec::new(),
        }
    }

    #[test]
    fn loop_analysis_merges_latches_and_sets_nesting_level() {
        let mut blocks = vec![
            block(0, vec![1, 2], vec![1, 2]),
            block(1, vec![0], vec![0]),
            block(2, vec![0], vec![0]),
        ];
        let mut analyzer = ControlFlowAnalyzer::new(Architecture::X86_64);

        let loops = analyzer.analyze_loops(&mut blocks).unwrap();

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header_block, 0);
        assert_eq!(loops[0].body_blocks, vec![1, 2]);
        assert_eq!(loops[0].nesting_level, 1);
        assert_eq!(loops[0].loop_type, LoopType::Infinite);
    }

    #[test]
    fn loop_analysis_accepts_exact_aggregate_body_limit() {
        let mut blocks = vec![
            block(0, vec![1, 2], vec![1, 2]),
            block(1, vec![0], vec![0]),
            block(2, vec![0], vec![0]),
        ];
        let mut analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_loops: 1,
                max_total_loop_body_blocks: 2,
                ..AnalysisConfig::default()
            },
        );

        let loops = analyzer.analyze_loops(&mut blocks).unwrap();

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].body_blocks, vec![1, 2]);
    }

    #[test]
    fn loop_analysis_rejects_aggregate_body_membership_above_limit() {
        let mut blocks = vec![
            block(0, vec![1, 2], vec![1, 2]),
            block(1, vec![0], vec![0]),
            block(2, vec![0], vec![0]),
        ];
        let mut analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_total_loop_body_blocks: 1,
                ..AnalysisConfig::default()
            },
        );

        let error = analyzer.analyze_loops(&mut blocks).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_total_loop_body_blocks 1"))
        );
    }

    #[test]
    fn loop_analysis_rejects_loop_count_above_limit() {
        let mut blocks = vec![
            block(0, vec![1], Vec::new()),
            block(1, vec![1, 2], vec![0, 1]),
            block(2, vec![2], vec![1, 2]),
        ];
        let mut analyzer = ControlFlowAnalyzer::with_config(
            Architecture::X86_64,
            AnalysisConfig {
                max_loops: 1,
                ..AnalysisConfig::default()
            },
        );

        let error = analyzer.analyze_loops(&mut blocks).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_loops 1"))
        );
    }

    #[test]
    fn dominator_index_handles_a_long_chain_in_linear_space() {
        const BLOCK_COUNT: usize = 20_000;
        let mut blocks = Vec::new();
        blocks.try_reserve(BLOCK_COUNT).unwrap();
        for id in 0..BLOCK_COUNT {
            let mut basic_block = block(id, Vec::new(), Vec::new());
            basic_block.dominator = Some(id.saturating_sub(1));
            if id + 1 < BLOCK_COUNT {
                // Only the successor count is relevant to nesting depth here.
                basic_block.successors = vec![id + 1, id + 1];
            }
            blocks.push(basic_block);
        }

        let index = ControlFlowAnalyzer::build_dominator_index(&blocks).unwrap();

        assert_eq!(index.nesting_depth[0], 0);
        assert_eq!(index.nesting_depth[BLOCK_COUNT - 1], 19_999);
        assert!(index.dominates(0, BLOCK_COUNT - 1));
        assert!(!index.dominates(BLOCK_COUNT - 1, 0));
    }

    #[test]
    fn adding_high_fan_in_edges_keeps_each_predecessor_unique() {
        const SOURCE_COUNT: usize = 20_000;
        let target = SOURCE_COUNT;
        let mut blocks: Vec<_> = (0..=SOURCE_COUNT)
            .map(|id| block(id, Vec::new(), Vec::new()))
            .collect();

        for source in 0..SOURCE_COUNT {
            ControlFlowAnalyzer::add_cfg_edge(&mut blocks, source, target);
            ControlFlowAnalyzer::add_cfg_edge(&mut blocks, source, target);
        }

        assert_eq!(blocks[target].predecessors.len(), SOURCE_COUNT);
        assert_eq!(blocks[target].predecessors[0], 0);
        assert_eq!(
            blocks[target].predecessors[SOURCE_COUNT - 1],
            SOURCE_COUNT - 1
        );
    }
}
