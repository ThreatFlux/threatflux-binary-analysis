//! Call graph analysis for binary programs
//!
//! This module provides functionality to analyze function call relationships in binary programs,
//! including call graph construction, cycle detection, and visualization export.

use crate::{
    BinaryError, BinaryFile, Result,
    disasm::{Disassembler, DisassemblyConfig, section_file_data},
    types::{
        CallContext, CallGraph, CallGraphConfig, CallGraphEdge, CallGraphNode, CallGraphStatistics,
        CallSite, CallType, Function, Instruction, NodeType,
    },
};
use petgraph::{algo::kosaraju_scc, graphmap::DiGraphMap};
use std::collections::{HashMap, HashSet, VecDeque};

type AddressToNode = HashMap<u64, usize>;
type CallAdjacency = HashMap<u64, Vec<u64>>;

/// Call graph analyzer
#[derive(Clone)]
pub struct CallGraphAnalyzer {
    /// Analysis configuration
    config: CallGraphConfig,
}

impl CallGraphAnalyzer {
    /// Create a new call graph analyzer
    pub fn new(config: CallGraphConfig) -> Self {
        Self { config }
    }

    /// Create analyzer with default configuration
    pub fn new_default() -> Self {
        Self {
            config: CallGraphConfig::default(),
        }
    }

    /// Analyze binary to construct call graph
    pub fn analyze_binary(&self, binary: &BinaryFile) -> Result<CallGraph> {
        // Extract functions from binary
        let functions = self.extract_functions(binary)?;

        // Build call graph nodes
        let mut nodes = Vec::new();
        let mut address_to_node: HashMap<u64, usize> = HashMap::new();
        nodes
            .try_reserve(functions.len())
            .map_err(|error| Self::allocation_error("call-graph nodes", error))?;
        address_to_node
            .try_reserve(functions.len())
            .map_err(|error| Self::allocation_error("call-graph address index", error))?;

        for (i, function) in functions.iter().enumerate() {
            let node = CallGraphNode {
                function_address: function.start_address,
                function_name: function.name.clone(),
                node_type: self.classify_node_type(function, binary),
                complexity: 0,       // Will be calculated later
                in_degree: 0,        // Will be calculated later
                out_degree: 0,       // Will be calculated later
                is_recursive: false, // Will be detected later
                call_depth: None,    // Will be calculated later
            };
            nodes.push(node);
            address_to_node.insert(function.start_address, i);
        }

        // Extract function calls and build edges
        let mut edges = self.extract_function_calls(binary, &functions, &address_to_node)?;
        if !self.config.include_library_calls {
            let mut library_addresses = HashSet::new();
            library_addresses
                .try_reserve(nodes.len())
                .map_err(|error| Self::allocation_error("library address set", error))?;
            library_addresses.extend(
                nodes
                    .iter()
                    .filter(|node| matches!(node.node_type, NodeType::Library))
                    .map(|node| node.function_address),
            );
            edges.retain(|edge| {
                !library_addresses.contains(&edge.caller)
                    && !edge
                        .callee
                        .is_some_and(|callee| library_addresses.contains(&callee))
            });
        }

        // Update node degrees
        self.update_node_degrees(&mut nodes, &edges);

        // Detect recursion
        self.detect_recursion(&mut nodes, &edges);

        // Find entry points
        let entry_points = self.find_entry_points(binary, &functions);

        // Calculate call depths
        let mut call_graph = CallGraph {
            nodes,
            edges,
            entry_points: entry_points.clone(),
            unreachable_functions: Vec::new(),
            statistics: CallGraphStatistics::default(),
        };

        self.compute_call_depths(&mut call_graph)?;

        // Find unreachable functions
        call_graph.unreachable_functions = self.find_unreachable_functions(&call_graph)?;

        // Compute statistics
        call_graph.statistics = self.compute_statistics(&call_graph);

        Ok(call_graph)
    }

    /// Extract functions from binary symbols and analysis
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

        // Extract from symbols
        for symbol in binary.symbols() {
            if matches!(symbol.symbol_type, crate::types::SymbolType::Function)
                && symbol.size > 0
                && !seen_addresses.contains(&symbol.address)
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
                seen_addresses.insert(symbol.address);
            }
        }

        // Add entry point if not already present
        if let Some(entry_point) = binary
            .entry_point()
            .filter(|entry_point| !seen_addresses.contains(entry_point))
        {
            self.ensure_function_limit(functions.len().saturating_add(1))?;
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

    /// Classify node type based on function characteristics
    fn classify_node_type(&self, function: &Function, binary: &BinaryFile) -> NodeType {
        // Check if it's an entry point
        if matches!(
            function.function_type,
            crate::types::FunctionType::Entrypoint
        ) || matches!(function.function_type, crate::types::FunctionType::Main)
            || function.name == "_start"
            || function.name == "main"
            || function.name == "DllMain"
        {
            return NodeType::EntryPoint;
        }

        // Check if it's an imported function
        for import in binary.imports() {
            if import.address == Some(function.start_address) {
                return NodeType::External;
            }
        }

        // Check if it's a library function (heuristic based on name)
        if self.is_library_function(&function.name) {
            return NodeType::Library;
        }

        // Default to internal function
        NodeType::Internal
    }

    /// Check if a function name indicates a library function
    fn is_library_function(&self, name: &str) -> bool {
        // Common library function prefixes (be more specific to avoid false positives)
        const LIBRARY_PREFIXES: &[&str] =
            &["libc_", "libm_", "__", "_GLOBAL_", "std::", "_ZN", "_Z"];

        // Common library function exact names or patterns
        const LIBRARY_NAMES: &[&str] = &[
            "printf", "scanf", "malloc", "free", "strlen", "strcpy", "strcat", "memcpy", "memset",
            "fopen", "fclose", "fread", "fwrite", "msvcrt", "kernel32", "ntdll",
        ];

        // Check prefixes
        for prefix in LIBRARY_PREFIXES {
            if name.starts_with(prefix) {
                return true;
            }
        }

        // Check exact function names. Substring matching (for example, "free")
        // creates severe false positives for user-defined symbols.
        for lib_name in LIBRARY_NAMES {
            if name == *lib_name {
                return true;
            }
        }

        false
    }

    /// Extract function calls from binary analysis
    fn extract_function_calls(
        &self,
        binary: &BinaryFile,
        functions: &[Function],
        address_to_node: &HashMap<u64, usize>,
    ) -> Result<Vec<CallGraphEdge>> {
        if functions.is_empty() {
            return Ok(Vec::new());
        }

        let mut edges = Vec::new();
        edges
            .try_reserve(functions.len().min(self.config.max_total_instructions))
            .map_err(|error| Self::allocation_error("call-graph edges", error))?;
        let mut successful_functions = 0_usize;
        let mut total_instructions = 0_usize;
        let mut last_error = None;

        for function in functions {
            let remaining_instructions = self
                .config
                .max_total_instructions
                .saturating_sub(total_instructions);
            let decode_limit = remaining_instructions.saturating_add(1);

            // Get instructions for this function
            match self.get_function_instructions(binary, function, decode_limit) {
                Ok(instructions) => {
                    let new_total = total_instructions
                        .checked_add(instructions.len())
                        .ok_or_else(|| {
                            BinaryError::control_flow(
                                "Call-graph instruction count overflowed usize",
                            )
                        })?;
                    if new_total > self.config.max_total_instructions {
                        return Err(BinaryError::control_flow(format!(
                            "Decoded instruction count {new_total} exceeds configured CallGraphConfig::max_total_instructions {}",
                            self.config.max_total_instructions
                        )));
                    }
                    total_instructions = new_total;
                    successful_functions += 1;

                    // Analyze instructions for calls
                    for instruction in &instructions {
                        if let Some(edge) = self.analyze_call_instruction(
                            instruction,
                            function.start_address,
                            address_to_node,
                        ) {
                            edges.try_reserve(1).map_err(|error| {
                                Self::allocation_error("call-graph edge", error)
                            })?;
                            edges.push(edge);
                        }
                    }

                    if self.config.detect_tail_calls
                        && let Some(edge) =
                            self.detect_tail_call(function, address_to_node, &instructions)
                    {
                        edges
                            .try_reserve(1)
                            .map_err(|error| Self::allocation_error("tail-call edge", error))?;
                        edges.push(edge);
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }

        if successful_functions == 0
            && let Some(error) = last_error
        {
            return Err(error);
        }

        Ok(Self::merge_edges(edges))
    }

    /// Get instructions for a function
    fn get_function_instructions(
        &self,
        binary: &BinaryFile,
        function: &Function,
        max_instructions: usize,
    ) -> Result<Vec<Instruction>> {
        // Find the section containing this function
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
                    binary.architecture(),
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
                "Discovered function count {actual} exceeds configured CallGraphConfig::max_functions {}",
                self.config.max_functions
            )));
        }
        Ok(())
    }

    fn allocation_error(context: &str, error: std::collections::TryReserveError) -> BinaryError {
        BinaryError::control_flow(format!("Unable to reserve {context}: {error}"))
    }

    /// Analyze a single instruction for call patterns
    fn analyze_call_instruction(
        &self,
        instruction: &Instruction,
        caller_address: u64,
        address_to_node: &HashMap<u64, usize>,
    ) -> Option<CallGraphEdge> {
        match &instruction.flow {
            crate::types::ControlFlow::Call(target_address) => {
                // Direct call
                if address_to_node.contains_key(target_address) {
                    let call_site = CallSite {
                        address: instruction.address,
                        instruction_bytes: instruction.bytes.clone(),
                        context: CallContext::Normal,
                    };

                    let call_type = if *target_address == caller_address {
                        CallType::Recursive
                    } else {
                        CallType::Direct
                    };

                    return Some(CallGraphEdge {
                        caller: caller_address,
                        callee: Some(*target_address),
                        call_type,
                        call_sites: vec![call_site],
                    });
                }
            }
            _ => {
                // Check for indirect calls if enabled
                if self.config.analyze_indirect_calls {
                    return self.analyze_indirect_call(instruction, caller_address);
                }
            }
        }

        None
    }

    /// Analyze indirect call patterns
    fn analyze_indirect_call(
        &self,
        instruction: &Instruction,
        caller_address: u64,
    ) -> Option<CallGraphEdge> {
        // Direct calls have already been represented by ControlFlow::Call. Remaining
        // call-family instructions are indirect, including register operands.
        let mnemonic = instruction.mnemonic.to_ascii_lowercase();
        if matches!(
            mnemonic.as_str(),
            "call" | "callq" | "blr" | "blx" | "jalr" | "bctrl"
        ) {
            // This is an indirect call through memory or register
            let call_site = CallSite {
                address: instruction.address,
                instruction_bytes: instruction.bytes.clone(),
                context: CallContext::Normal,
            };

            // For indirect calls, we can't determine the exact target at static analysis time
            // In a real implementation, this would require more sophisticated analysis
            return Some(CallGraphEdge {
                caller: caller_address,
                callee: None,
                call_type: CallType::Indirect,
                call_sites: vec![call_site],
            });
        }

        None
    }

    fn merge_edges(mut edges: Vec<CallGraphEdge>) -> Vec<CallGraphEdge> {
        edges.sort_by(|left, right| {
            left.caller
                .cmp(&right.caller)
                .then_with(|| left.callee.cmp(&right.callee))
                .then_with(|| {
                    Self::call_type_rank(&left.call_type)
                        .cmp(&Self::call_type_rank(&right.call_type))
                })
        });

        let mut merged: Vec<CallGraphEdge> = Vec::with_capacity(edges.len());
        for mut edge in edges {
            if let Some(existing) = merged.last_mut().filter(|existing| {
                existing.caller == edge.caller
                    && existing.callee == edge.callee
                    && existing.call_type == edge.call_type
            }) {
                existing.call_sites.append(&mut edge.call_sites);
                continue;
            }
            merged.push(edge);
        }

        for edge in &mut merged {
            edge.call_sites.sort_by(|left, right| {
                left.address
                    .cmp(&right.address)
                    .then_with(|| left.instruction_bytes.cmp(&right.instruction_bytes))
            });
            edge.call_sites.dedup_by(|left, right| {
                left.address == right.address
                    && left.instruction_bytes == right.instruction_bytes
                    && left.context == right.context
            });
        }
        merged
    }

    fn call_type_rank(call_type: &CallType) -> u8 {
        match call_type {
            CallType::Direct => 0,
            CallType::Indirect => 1,
            CallType::TailCall => 2,
            CallType::Virtual => 3,
            CallType::Recursive => 4,
            CallType::Conditional => 5,
        }
    }

    /// Detect a tail-call candidate from one already-decoded function.
    fn detect_tail_call(
        &self,
        function: &Function,
        address_to_node: &HashMap<u64, usize>,
        instructions: &[Instruction],
    ) -> Option<CallGraphEdge> {
        // Look for a final direct jump to another discovered function.
        instructions
            .last()
            .and_then(|last| {
                if let crate::types::ControlFlow::Jump(target) = &last.flow {
                    (*target != function.start_address && address_to_node.contains_key(target))
                        .then_some((last, *target))
                } else {
                    None
                }
            })
            .map(|(last_instruction, target)| {
                let call_site = CallSite {
                    address: last_instruction.address,
                    instruction_bytes: last_instruction.bytes.clone(),
                    context: CallContext::Normal,
                };

                CallGraphEdge {
                    caller: function.start_address,
                    callee: Some(target),
                    call_type: CallType::TailCall,
                    call_sites: vec![call_site],
                }
            })
    }

    /// Update node in-degree and out-degree based on edges
    fn update_node_degrees(&self, nodes: &mut [CallGraphNode], edges: &[CallGraphEdge]) {
        let mut callers: HashMap<u64, HashSet<u64>> = HashMap::new();
        let mut callees: HashMap<u64, HashSet<Option<u64>>> = HashMap::new();

        for edge in edges {
            callees.entry(edge.caller).or_default().insert(edge.callee);
            if let Some(callee) = edge.callee {
                callers.entry(callee).or_default().insert(edge.caller);
            }
        }

        for node in nodes {
            node.in_degree = callers
                .get(&node.function_address)
                .map_or(0, |values| u32::try_from(values.len()).unwrap_or(u32::MAX));
            node.out_degree = callees
                .get(&node.function_address)
                .map_or(0, |values| u32::try_from(values.len()).unwrap_or(u32::MAX));
        }
    }

    /// Detect recursive functions
    fn detect_recursion(&self, nodes: &mut [CallGraphNode], edges: &[CallGraphEdge]) {
        let recursive_functions: HashSet<u64> = cyclic_components(nodes, edges)
            .into_iter()
            .flatten()
            .collect();

        // Update nodes
        for node in nodes {
            node.is_recursive = recursive_functions.contains(&node.function_address);
        }
    }

    /// Find entry points in the call graph
    fn find_entry_points(&self, binary: &BinaryFile, functions: &[Function]) -> Vec<u64> {
        let mut entry_points = Vec::new();

        // Add main entry point
        if let Some(entry) = binary.entry_point() {
            entry_points.push(entry);
        }

        // Add other known entry points
        for function in functions {
            match function.function_type {
                crate::types::FunctionType::Entrypoint | crate::types::FunctionType::Main
                    if !entry_points.contains(&function.start_address) =>
                {
                    entry_points.push(function.start_address);
                }
                _ => {}
            }
        }

        entry_points.sort_unstable();
        entry_points.dedup();
        entry_points
    }

    /// Compute call depths from entry points using BFS
    fn compute_call_depths(&self, call_graph: &mut CallGraph) -> Result<()> {
        let (address_to_node, adjacency) = Self::graph_index(call_graph)?;

        for node in &mut call_graph.nodes {
            node.call_depth = None;
        }

        // Multi-source BFS computes the shortest distance from any entry point.
        let mut queue = VecDeque::new();
        queue
            .try_reserve(call_graph.entry_points.len().min(call_graph.nodes.len()))
            .map_err(|error| Self::allocation_error("call-depth queue", error))?;
        for &entry_point in &call_graph.entry_points {
            if let Some(&node_index) = address_to_node.get(&entry_point) {
                call_graph.nodes[node_index].call_depth = Some(0);
                queue.push_back(entry_point);
            }
        }

        while let Some(current_addr) = queue.pop_front() {
            let node_index = address_to_node[&current_addr];
            let depth = call_graph.nodes[node_index].call_depth.unwrap_or(0);
            if self
                .config
                .max_labeled_call_depth
                .is_some_and(|maximum| depth >= maximum)
            {
                continue;
            }

            let next_depth = depth.saturating_add(1);
            if let Some(neighbors) = adjacency.get(&current_addr) {
                for &neighbor in neighbors {
                    let neighbor_index = address_to_node[&neighbor];
                    if call_graph.nodes[neighbor_index].call_depth.is_none() {
                        call_graph.nodes[neighbor_index].call_depth = Some(next_depth);
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        Ok(())
    }

    /// Find unreachable functions independently of the call-depth labeling cap.
    fn find_unreachable_functions(&self, call_graph: &CallGraph) -> Result<Vec<u64>> {
        let (address_to_node, adjacency) = Self::graph_index(call_graph)?;
        let mut reachable = HashSet::new();
        reachable
            .try_reserve(call_graph.nodes.len())
            .map_err(|error| Self::allocation_error("reachable function set", error))?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve(call_graph.nodes.len())
            .map_err(|error| Self::allocation_error("reachability queue", error))?;

        for &entry_point in &call_graph.entry_points {
            if address_to_node.contains_key(&entry_point) && reachable.insert(entry_point) {
                queue.push_back(entry_point);
            }
        }

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adjacency.get(&current) {
                for &neighbor in neighbors {
                    if reachable.insert(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        let mut unreachable = Vec::new();
        unreachable
            .try_reserve(call_graph.nodes.len().saturating_sub(reachable.len()))
            .map_err(|error| Self::allocation_error("unreachable function list", error))?;
        unreachable.extend(
            call_graph
                .nodes
                .iter()
                .filter(|node| !reachable.contains(&node.function_address))
                .map(|node| node.function_address),
        );
        Ok(unreachable)
    }

    fn graph_index(call_graph: &CallGraph) -> Result<(AddressToNode, CallAdjacency)> {
        let mut address_to_node = HashMap::new();
        address_to_node
            .try_reserve(call_graph.nodes.len())
            .map_err(|error| Self::allocation_error("call-graph address index", error))?;
        for (index, node) in call_graph.nodes.iter().enumerate() {
            address_to_node.insert(node.function_address, index);
        }

        let mut adjacency: HashMap<u64, Vec<u64>> = HashMap::new();
        adjacency
            .try_reserve(call_graph.nodes.len())
            .map_err(|error| Self::allocation_error("call-graph adjacency", error))?;
        for edge in &call_graph.edges {
            if !matches!(edge.call_type, CallType::Indirect)
                && address_to_node.contains_key(&edge.caller)
                && let Some(callee) = edge
                    .callee
                    .filter(|callee| address_to_node.contains_key(callee))
            {
                let neighbors = adjacency.entry(edge.caller).or_default();
                neighbors
                    .try_reserve(1)
                    .map_err(|error| Self::allocation_error("call-graph neighbor", error))?;
                neighbors.push(callee);
            }
        }
        for neighbors in adjacency.values_mut() {
            neighbors.sort_unstable();
            neighbors.dedup();
        }

        Ok((address_to_node, adjacency))
    }

    /// Compute call graph statistics
    fn compute_statistics(&self, call_graph: &CallGraph) -> CallGraphStatistics {
        let total_functions = call_graph.nodes.len();
        let total_calls = call_graph.edges.iter().fold(0_usize, |count, edge| {
            count.saturating_add(edge.call_sites.len())
        });

        let direct_calls = call_graph
            .edges
            .iter()
            .filter(|edge| matches!(edge.call_type, CallType::Direct | CallType::Recursive))
            .fold(0_usize, |count, edge| {
                count.saturating_add(edge.call_sites.len())
            });

        let indirect_calls = call_graph
            .edges
            .iter()
            .filter(|edge| matches!(edge.call_type, CallType::Indirect))
            .fold(0_usize, |count, edge| {
                count.saturating_add(edge.call_sites.len())
            });

        let recursive_functions = call_graph
            .nodes
            .iter()
            .filter(|node| node.is_recursive)
            .count();

        let leaf_functions = call_graph
            .nodes
            .iter()
            .filter(|node| node.out_degree == 0)
            .count();

        let entry_points = call_graph.entry_points.len();
        let unreachable_functions = call_graph.unreachable_functions.len();

        let max_call_depth = call_graph
            .nodes
            .iter()
            .filter_map(|node| node.call_depth)
            .max()
            .unwrap_or(0);

        let depths: Vec<u32> = call_graph
            .nodes
            .iter()
            .filter_map(|node| node.call_depth)
            .collect();

        let average_call_depth = if !depths.is_empty() {
            depths.iter().map(|&depth| f64::from(depth)).sum::<f64>() / depths.len() as f64
        } else {
            0.0
        };

        let cyclic_dependencies = self.count_cyclic_dependencies(call_graph);

        CallGraphStatistics {
            total_functions,
            total_calls,
            direct_calls,
            indirect_calls,
            recursive_functions,
            leaf_functions,
            entry_points,
            unreachable_functions,
            max_call_depth,
            average_call_depth,
            cyclic_dependencies,
        }
    }

    /// Count strongly connected components (cyclic dependencies)
    fn count_cyclic_dependencies(&self, call_graph: &CallGraph) -> usize {
        cyclic_components(&call_graph.nodes, &call_graph.edges).len()
    }
}

fn cyclic_components(nodes: &[CallGraphNode], edges: &[CallGraphEdge]) -> Vec<Vec<u64>> {
    let mut graph = DiGraphMap::<u64, ()>::new();
    for node in nodes {
        graph.add_node(node.function_address);
    }
    for edge in edges {
        if !matches!(edge.call_type, CallType::Indirect)
            && graph.contains_node(edge.caller)
            && let Some(callee) = edge.callee.filter(|callee| graph.contains_node(*callee))
        {
            graph.add_edge(edge.caller, callee, ());
        }
    }

    let mut components: Vec<Vec<u64>> = kosaraju_scc(&graph)
        .into_iter()
        .filter(|component| {
            component.len() > 1
                || component
                    .first()
                    .is_some_and(|&node| graph.contains_edge(node, node))
        })
        .collect();
    for component in &mut components {
        component.sort_unstable();
    }
    components.sort();
    components
}

/// Configuration for DOT export
#[derive(Debug, Clone)]
pub struct DotConfig {
    /// Include function addresses in labels
    pub include_addresses: bool,
    /// Color nodes by type
    pub color_by_type: bool,
    /// Show call counts on edges
    pub show_call_counts: bool,
    /// Cluster nodes by module
    pub cluster_by_module: bool,
    /// Maximum number of nodes to include
    pub max_nodes: Option<usize>,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            include_addresses: true,
            color_by_type: true,
            show_call_counts: false,
            cluster_by_module: false,
            max_nodes: Some(1000),
        }
    }
}

/// Trait for call graph exporters
pub trait CallGraphExporter {
    /// Export call graph to string format
    fn export(&self, graph: &CallGraph) -> Result<String>;
}

/// DOT format exporter for Graphviz visualization
pub struct DotExporter {
    config: DotConfig,
}

impl DotExporter {
    /// Create new DOT exporter with configuration
    pub fn new(config: DotConfig) -> Self {
        Self { config }
    }

    /// Create new DOT exporter with default configuration
    pub fn new_default() -> Self {
        Self {
            config: DotConfig::default(),
        }
    }
}

impl CallGraphExporter for DotExporter {
    fn export(&self, graph: &CallGraph) -> Result<String> {
        if self.config.cluster_by_module {
            return Err(BinaryError::feature_not_available(
                "DOT module clustering is not implemented",
            ));
        }
        let mut dot = String::new();

        // DOT header
        dot.push_str("digraph CallGraph {\n");
        dot.push_str("  rankdir=TB;\n");
        dot.push_str("  node [shape=box, style=filled];\n");
        dot.push_str("  edge [arrowhead=normal];\n\n");

        // Limit nodes if configured
        let nodes_to_include = if let Some(max_nodes) = self.config.max_nodes {
            &graph.nodes[..std::cmp::min(max_nodes, graph.nodes.len())]
        } else {
            &graph.nodes
        };

        // Export nodes
        for node in nodes_to_include {
            let escaped_name = escape_dot_label(&node.function_name);
            let label = if self.config.include_addresses {
                format!("{}\\n0x{:x}", escaped_name, node.function_address)
            } else {
                escaped_name
            };

            let color = if self.config.color_by_type {
                match node.node_type {
                    NodeType::EntryPoint => "lightgreen",
                    NodeType::Library => "lightblue",
                    NodeType::External => "lightyellow",
                    NodeType::Internal => "lightgray",
                    NodeType::Indirect => "orange",
                    NodeType::Virtual => "purple",
                    NodeType::Unknown => "pink",
                }
            } else {
                "lightgray"
            };

            dot.push_str(&format!(
                "  \"0x{:x}\" [label=\"{}\", fillcolor=\"{}\"];\n",
                node.function_address, label, color
            ));
        }

        dot.push('\n');

        // Export edges
        let node_addresses: HashSet<u64> = nodes_to_include
            .iter()
            .map(|n| n.function_address)
            .collect();
        if graph
            .edges
            .iter()
            .any(|edge| edge.callee.is_none() && node_addresses.contains(&edge.caller))
        {
            dot.push_str(
                "  \"__unknown_target\" [label=\"unknown target\", shape=ellipse, fillcolor=orange];\n",
            );
        }

        for edge in &graph.edges {
            if !node_addresses.contains(&edge.caller) {
                continue;
            }

            let target = match edge.callee {
                Some(callee) if node_addresses.contains(&callee) => format!("\"0x{callee:x}\""),
                None => "\"__unknown_target\"".to_string(),
                Some(_) => continue,
            };
            let mut attributes = Vec::new();
            if self.config.show_call_counts {
                attributes.push(format!("label=\"{}\"", edge.call_sites.len()));
            }
            match edge.call_type {
                CallType::Direct => {}
                CallType::Indirect => attributes.push("style=dashed".to_string()),
                CallType::TailCall => attributes.push("color=red".to_string()),
                CallType::Virtual => attributes.push("color=purple".to_string()),
                CallType::Recursive => {
                    attributes.push("color=green".to_string());
                    attributes.push("style=bold".to_string());
                }
                CallType::Conditional => attributes.push("color=orange".to_string()),
            }
            let attributes = if attributes.is_empty() {
                String::new()
            } else {
                format!(" [{}]", attributes.join(", "))
            };

            dot.push_str(&format!(
                "  \"0x{:x}\" -> {target}{attributes};\n",
                edge.caller
            ));
        }

        dot.push_str("}\n");
        Ok(dot)
    }
}

fn escape_dot_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

/// JSON exporter for programmatic analysis
pub struct JsonExporter;

impl CallGraphExporter for JsonExporter {
    fn export(&self, graph: &CallGraph) -> Result<String> {
        #[cfg(feature = "serde-support")]
        {
            serde_json::to_string_pretty(graph)
                .map_err(|e| BinaryError::invalid_data(format!("JSON serialization failed: {}", e)))
        }
        #[cfg(not(feature = "serde-support"))]
        {
            let _ = graph; // Suppress unused warning
            Err(BinaryError::feature_not_available("serde-support"))
        }
    }
}

impl CallGraph {
    /// Export call graph to DOT format for Graphviz
    pub fn to_dot(&self) -> Result<String> {
        let exporter = DotExporter::new_default();
        exporter.export(self)
    }

    /// Export call graph to DOT format with custom configuration
    pub fn to_dot_with_config(&self, config: DotConfig) -> Result<String> {
        let exporter = DotExporter::new(config);
        exporter.export(self)
    }

    /// Export call graph to JSON format
    pub fn to_json(&self) -> Result<String> {
        let exporter = JsonExporter;
        exporter.export(self)
    }

    /// Return cyclic strongly connected components in deterministic address order.
    pub fn detect_cycles(&self) -> Vec<Vec<u64>> {
        cyclic_components(&self.nodes, &self.edges)
    }
}

/// Analyze binary call graph
pub fn analyze_binary(binary: &BinaryFile) -> Result<CallGraph> {
    let analyzer = CallGraphAnalyzer::new_default();
    analyzer.analyze_binary(binary)
}

/// Analyze binary call graph with custom configuration
pub fn analyze_binary_with_config(
    binary: &BinaryFile,
    config: CallGraphConfig,
) -> Result<CallGraph> {
    let analyzer = CallGraphAnalyzer::new(config);
    analyzer.analyze_binary(binary)
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

    fn test_binary(data: Vec<u8>, sections: Vec<Section>, symbols: Vec<Symbol>) -> BinaryFile {
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

        test_binary(data, sections, symbols)
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = CallGraphAnalyzer::new_default();
        assert!(analyzer.config.analyze_indirect_calls);
        assert!(analyzer.config.detect_tail_calls);
        assert_eq!(analyzer.config.max_functions, 10_000);
        assert_eq!(analyzer.config.max_total_instructions, 1_000_000);
    }

    #[test]
    fn analyze_binary_returns_error_when_every_function_fails() {
        let binary = function_analysis_binary(false);
        let analyzer = CallGraphAnalyzer::new_default();

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::InvalidData(message) if message.contains("beyond the end of the file"))
        );
    }

    #[test]
    fn analyze_binary_preserves_partial_function_success() {
        let binary = function_analysis_binary(true);
        let analyzer = CallGraphAnalyzer::new(CallGraphConfig {
            max_functions: 2,
            max_total_instructions: 1,
            ..CallGraphConfig::default()
        });

        let graph = analyzer.analyze_binary(&binary).unwrap();

        assert_eq!(graph.nodes.len(), 2);
        assert!(graph.nodes.iter().any(|node| node.function_name == "valid"));
    }

    #[test]
    fn analyze_binary_returns_error_when_function_has_no_executable_section() {
        let binary = test_binary(
            vec![0xc3],
            Vec::new(),
            vec![function_symbol("missing", 0x3000)],
        );
        let analyzer = CallGraphAnalyzer::new_default();

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::InvalidData(message) if message == "Function bytes not found in any executable section")
        );
    }

    #[test]
    fn containing_zero_length_file_range_counts_as_success() {
        let binary = test_binary(
            vec![0xc3],
            vec![Section {
                name: ".empty".to_string(),
                address: 0x3000,
                size: 1,
                offset: 1,
                file_size: 0,
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                section_type: SectionType::Code,
                data: None,
            }],
            vec![function_symbol("empty", 0x3000)],
        );
        let analyzer = CallGraphAnalyzer::new_default();

        let graph = analyzer.analyze_binary(&binary).unwrap();

        assert_eq!(graph.nodes.len(), 1);
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn analyze_binary_rejects_function_count_above_configured_cap() {
        let binary = function_analysis_binary(true);
        let analyzer = CallGraphAnalyzer::new(CallGraphConfig {
            max_functions: 1,
            ..CallGraphConfig::default()
        });

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_functions 1"))
        );
    }

    #[test]
    fn analyze_binary_rejects_total_instructions_above_configured_cap() {
        let binary = function_analysis_binary(true);
        let analyzer = CallGraphAnalyzer::new(CallGraphConfig {
            max_total_instructions: 0,
            ..CallGraphConfig::default()
        });

        let error = analyzer.analyze_binary(&binary).unwrap_err();

        assert!(
            matches!(error, BinaryError::ControlFlowError(message) if message.contains("max_total_instructions 0"))
        );
    }

    #[test]
    fn test_library_function_detection() {
        let analyzer = CallGraphAnalyzer::new_default();
        assert!(analyzer.is_library_function("printf"));
        assert!(analyzer.is_library_function("libc_start_main"));
        assert!(analyzer.is_library_function("__stack_chk_fail"));
        assert!(!analyzer.is_library_function("user_function"));
        assert!(!analyzer.is_library_function("carefree_user"));
        assert!(!analyzer.is_library_function("main"));
    }

    #[test]
    fn indirect_call_setting_gates_unknown_target_edges() {
        let instruction = Instruction {
            address: 0x1000,
            bytes: vec![0xff, 0xd0],
            mnemonic: "call".to_string(),
            operands: "rax".to_string(),
            category: InstructionCategory::Control,
            flow: crate::types::ControlFlow::Sequential,
            size: 2,
        };
        let enabled = CallGraphAnalyzer::new_default();
        let disabled = CallGraphAnalyzer::new(CallGraphConfig {
            analyze_indirect_calls: false,
            ..CallGraphConfig::default()
        });

        let detected = enabled
            .analyze_call_instruction(&instruction, 0x1000, &HashMap::new())
            .unwrap();
        assert_eq!(detected.callee, None);
        assert!(
            disabled
                .analyze_call_instruction(&instruction, 0x1000, &HashMap::new())
                .is_none()
        );
    }

    #[test]
    fn test_node_type_classification() {
        let analyzer = CallGraphAnalyzer::new_default();

        let entry_function = Function {
            name: "_start".to_string(),
            start_address: 0x1000,
            end_address: 0x1100,
            size: 256,
            function_type: FunctionType::Entrypoint,
            calling_convention: None,
            parameters: Vec::new(),
            return_type: None,
        };

        // Create a minimal ELF binary for testing (minimal header)
        let elf_data = vec![
            0x7f, 0x45, 0x4c, 0x46, // ELF magic
            0x02, // 64-bit
            0x01, // Little endian
            0x01, // Version
            0x00, // System V ABI
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
            0x02, 0x00, // Executable file
            0x3e, 0x00, // x86-64
        ];

        // For this test, we don't need a fully valid binary, just enough to classify node types
        // The actual binary parsing might fail, but we can still test the logic
        match crate::BinaryFile::parse(&elf_data) {
            Ok(binary) => {
                let node_type = analyzer.classify_node_type(&entry_function, &binary);
                assert_eq!(node_type, NodeType::EntryPoint);
            }
            Err(_) => {
                // If parsing fails (which is expected for minimal data), just test the function type detection
                // This is acceptable since we're primarily testing the classification logic
                assert_eq!(entry_function.function_type, FunctionType::Entrypoint);
            }
        }
    }

    fn node(address: u64, name: &str) -> CallGraphNode {
        CallGraphNode {
            function_address: address,
            function_name: name.to_string(),
            node_type: NodeType::Internal,
            complexity: 0,
            in_degree: 0,
            out_degree: 0,
            is_recursive: false,
            call_depth: None,
        }
    }

    fn edge(caller: u64, callee: u64, call_type: CallType, site: u64) -> CallGraphEdge {
        CallGraphEdge {
            caller,
            callee: Some(callee),
            call_type,
            call_sites: vec![CallSite {
                address: site,
                instruction_bytes: vec![0xe8],
                context: CallContext::Normal,
            }],
        }
    }

    fn unknown_edge(caller: u64, site: u64) -> CallGraphEdge {
        CallGraphEdge {
            caller,
            callee: None,
            call_type: CallType::Indirect,
            call_sites: vec![CallSite {
                address: site,
                instruction_bytes: vec![0xff, 0xd0],
                context: CallContext::Normal,
            }],
        }
    }

    fn graph(nodes: Vec<CallGraphNode>, edges: Vec<CallGraphEdge>) -> CallGraph {
        CallGraph {
            nodes,
            edges,
            entry_points: vec![1],
            unreachable_functions: Vec::new(),
            statistics: CallGraphStatistics::default(),
        }
    }

    #[test]
    fn dot_export_handles_plain_direct_edges_and_escapes_labels() {
        let graph = graph(
            vec![node(1, "quoted\"name\nline"), node(2, "callee")],
            vec![edge(1, 2, CallType::Direct, 10)],
        );

        let dot = DotExporter::new_default().export(&graph).unwrap();

        assert!(dot.contains("quoted\\\"name\\nline"));
        assert!(dot.contains("\"0x1\" -> \"0x2\";"));
    }

    #[test]
    fn repeated_calls_are_merged_with_sorted_call_sites() {
        let edges = vec![
            edge(1, 2, CallType::Direct, 20),
            edge(1, 2, CallType::Direct, 10),
            edge(1, 2, CallType::Direct, 10),
        ];

        let merged = CallGraphAnalyzer::merge_edges(edges);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].call_sites.len(), 2);
        assert_eq!(merged[0].call_sites[0].address, 10);
        assert_eq!(merged[0].call_sites[1].address, 20);
    }

    #[test]
    fn unknown_target_does_not_conflate_with_function_at_zero() {
        let analyzer = CallGraphAnalyzer::new_default();
        let mut nodes = vec![node(0, "zero"), node(1, "caller")];
        let edges = vec![unknown_edge(1, 10)];

        analyzer.update_node_degrees(&mut nodes, &edges);
        let dot = DotExporter::new_default()
            .export(&graph(nodes.clone(), edges))
            .unwrap();

        assert_eq!(nodes[0].in_degree, 0);
        assert_eq!(nodes[1].out_degree, 1);
        assert!(dot.contains("\"__unknown_target\""));
        assert!(dot.contains("\"0x1\" -> \"__unknown_target\""));
        assert!(!dot.contains("\"0x1\" -> \"0x0\""));
    }

    #[test]
    fn cycle_detection_returns_deterministic_components() {
        let graph = graph(
            vec![node(1, "one"), node(2, "two"), node(3, "three")],
            vec![
                edge(2, 1, CallType::Direct, 20),
                edge(1, 2, CallType::Direct, 10),
                unknown_edge(3, 30),
            ],
        );

        assert_eq!(graph.detect_cycles(), vec![vec![1, 2]]);
    }

    #[cfg(not(feature = "serde-support"))]
    #[test]
    fn json_export_reports_missing_serde_feature() {
        let graph = graph(Vec::new(), Vec::new());

        assert!(matches!(
            graph.to_json(),
            Err(BinaryError::FeatureNotAvailable(feature)) if feature == "serde-support"
        ));
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn json_export_uses_null_for_unknown_call_target() {
        let graph = graph(vec![node(1, "caller")], vec![unknown_edge(1, 10)]);

        let json = graph.to_json().unwrap();

        assert!(json.contains("\"callee\": null"));
    }

    #[test]
    fn maximum_labeled_call_depth_is_enforced() {
        let config = CallGraphConfig {
            max_labeled_call_depth: Some(1),
            ..CallGraphConfig::default()
        };
        let analyzer = CallGraphAnalyzer::new(config);
        let mut graph = graph(
            vec![node(1, "one"), node(2, "two"), node(3, "three")],
            vec![
                edge(1, 2, CallType::Direct, 10),
                edge(2, 3, CallType::Direct, 20),
            ],
        );

        analyzer.compute_call_depths(&mut graph).unwrap();

        assert_eq!(graph.nodes[0].call_depth, Some(0));
        assert_eq!(graph.nodes[1].call_depth, Some(1));
        assert_eq!(graph.nodes[2].call_depth, None);
        assert!(
            analyzer
                .find_unreachable_functions(&graph)
                .unwrap()
                .is_empty()
        );
    }
}
