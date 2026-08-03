# ThreatFlux Binary Analysis API Guide

This guide describes the public API on the upcoming 0.3.0 development line. The
current crates.io release remains 0.2.0 until 0.3.0 is published. See
[Migrating to 0.3](docs/MIGRATING_TO_0.3.md) for intentional API changes.
Generated Rust documentation remains the item-by-item reference:

```console
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --open
```

All primary operations are synchronous. The crate accepts byte slices; file
loading, input allowlists, complete resource isolation, timeouts, and task
scheduling belong to the caller.

## Choose an entry point

| Goal                                                  | API                                                                     | Feature                                                  |
| ----------------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------- |
| Detect and parse structural metadata                  | <code>BinaryFile::parse</code>                                          | Relevant format parser                                   |
| Detect a format without parsing it                    | <code>formats::detect_format</code>                                     | Relevant format parser                                   |
| Parse as an explicitly selected format                | <code>formats::parse_binary</code>                                      | Relevant format parser                                   |
| Collect parser output plus compiled optional analyses | <code>BinaryAnalyzer</code>                                             | Depends on requested analyses                            |
| Disassemble caller-selected bytes                     | <code>disasm::Disassembler</code>                                       | <code>disasm-capstone</code> or <code>disasm-iced</code> |
| Reconstruct control flow or a call graph              | <code>analysis::control_flow</code> / <code>analysis::call_graph</code> | <code>control-flow</code>                                |
| Generate heuristic security findings                  | <code>analysis::security::SecurityAnalyzer</code>                       | Always available                                         |
| Measure entropy and packing indicators                | <code>analysis::entropy</code>                                          | <code>entropy-analysis</code>                            |

## Core parsing API

### BinaryFile

<code>BinaryFile::parse(&[u8]) -> Result&lt;BinaryFile&gt;</code> detects a format,
selects its parser, and retains owned data. The resulting accessors borrow
parsed data:

- <code>format()</code> and <code>architecture()</code>
- <code>entry_point()</code>
- <code>metadata()</code>
- <code>sections()</code>
- <code>symbols()</code>
- <code>imports()</code>
- <code>exports()</code>
- <code>data()</code>

```rust
use threatflux_binary_analysis::{BinaryFile, Result};

fn summarize(bytes: &[u8]) -> Result<()> {
    let binary = BinaryFile::parse(bytes)?;
    println!("{} {}", binary.format(), binary.architecture());

    for section in binary.sections() {
        println!(
            "{} address=0x{:x} virtual_size={} file_size={} r={} w={} x={}",
            section.name,
            section.address,
            section.size,
            section.file_size,
            section.permissions.read,
            section.permissions.write,
            section.permissions.execute,
        );
    }

    Ok(())
}
```

Parsing is not zero-copy: <code>BinaryFile</code> owns a copy of the full input,
and individual format implementations may keep additional owned data.
<code>Section::size</code> is the virtual or in-memory span;
<code>Section::file_size</code> is the number of bytes backed by the file at
<code>Section::offset</code>. ELF, PE, thin Mach-O, and raw parsers populate
<code>Section::data</code> only for eligible file-backed sections no larger than
1 KiB (with format-specific offset checks). Java and WebAssembly sections do
not retain section payloads.

Parser-owned structural output is bounded. ELF, PE, Mach-O, Java/JAR, and
WebAssembly parsing share public hard ceilings of
<code>formats::MAX_PARSED_RECORDS</code> (100,000 structural/output records),
<code>formats::MAX_NAME_BYTES</code> (4 KiB per name), and
<code>formats::MAX_OWNED_NAME_BYTES</code> (32 MiB of copied names per parse).
Inputs above a ceiling return <code>InvalidData</code>. JAR preflight separately
limits the central directory to 50,000 entries before <code>zip</code> builds its
file table.

### Format detection

<code>formats::detect_format</code> uses leading magic values, a checked PE
header offset/signature, and a ZIP scan for class-containing JAR files when the
Java feature is enabled.

- Empty input returns <code>BinaryError::InvalidData</code>.
- Unknown non-empty input becomes <code>BinaryFormat::Raw</code>.
- Valid Java class headers, bounded universal Mach-O headers, and WebAssembly
  magic can be detected without their parser feature; a subsequent parse then
  returns <code>UnsupportedFormat</code>.
- A ZIP is treated as Java only when a <code>.class</code> entry is found.
- JAR inspection rejects archives with more than 50,000 entries.
- An MZ prefix without a valid checked PE signature falls through to raw data.

Use an explicit application allowlist after parsing. Classification as raw data
is a valid parse result, not a rejection.

### Format-specific scope

| Format      | Parsed today                                                                                              | Important omissions                                                                                                           |
| ----------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| ELF         | Sections, static symbols, dynamic imports/exports, entry point, selected hardening/compiler metadata      | Not a full loader, linker, debug-info reader, or signature verifier                                                           |
| PE          | Sections, COFF symbols when present, imports, exports, entry point, selected hardening/compiler metadata  | Authenticode is not verified; stripped images may expose no symbols                                                           |
| Mach-O      | Thin-image sections, nlist symbols when present, imports, exports, entry point when supplied by the image | Fat/universal images unsupported; malformed or unsupported dyld streams fail closed; code-signature presence is not verified  |
| Java class  | Fixed-header validation and a synthetic whole-file section                                                | The validated version is not exposed; no constant-pool, field, method, attribute, or bytecode decoding                        |
| JAR         | Class-entry names and sizes                                                                               | No class extraction/decoding, manifest semantics, or signature verification                                                   |
| WebAssembly | Validated module plus selected sections, imports, and exports                                             | A start-function index is not exposed as the virtual-address entry point; no instruction disassembly or symbol reconstruction |
| Raw         | Synthetic <code>.data</code> section                                                                      | Architecture and entry point unknown                                                                                          |

## Unified analysis

### BinaryAnalyzer

<code>BinaryAnalyzer::new()</code> uses a parser-only
<code>AnalysisConfig::default()</code>: every optional analysis/demangling
switch is false and the input limit is 100 MiB.
<code>BinaryAnalyzer::with_config(config)</code> accepts an explicit
configuration. Analyze raw bytes with <code>analyze</code>, or reuse a parsed
<code>BinaryFile</code> with <code>analyze_binary</code>.

The base fields of <code>AnalysisResult</code> mirror parser output. Optional
fields are populated only when their Cargo feature is compiled and the
corresponding configuration is enabled.

| AnalysisConfig field                      | Implemented behavior                                                                                                                                                                                                           |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| <code>enable_disassembly</code>           | Runs high-level executable-section disassembly when a backend is compiled                                                                                                                                                      |
| <code>disassembly_engine</code>           | Selects Auto, Capstone, or iced when a disassembly backend is compiled                                                                                                                                                         |
| <code>enable_control_flow</code>          | Populates base control-flow graphs with <code>control-flow</code>; it does not implicitly enable cognitive-complexity or advanced-loop output                                                                                  |
| <code>enable_call_graph</code>            | Populates a call graph with <code>control-flow</code>                                                                                                                                                                          |
| <code>enable_cognitive_complexity</code>  | Requests cognitive metrics and enhanced control-flow output with <code>control-flow</code>                                                                                                                                     |
| <code>enable_advanced_loops</code>        | Requests retained loop details and enhanced control-flow output with <code>control-flow</code>                                                                                                                                 |
| <code>enable_entropy</code>               | Populates entropy output with <code>entropy-analysis</code>                                                                                                                                                                    |
| <code>enable_symbols</code>               | Demangles names already returned by a parser with <code>symbol-resolution</code>                                                                                                                                               |
| <code>max_analysis_size</code>            | Rejects oversized input in <code>analyze</code>/<code>analyze_binary</code> with <code>InputTooLarge</code> and supplies the high-level disassembly byte budget; direct <code>BinaryFile::parse</code> has no configured limit |
| <code>max_disassembly_instructions</code> | Caps the total instructions returned by high-level disassembly; defaults to 10,000 and is independent of the input-size limit                                                                                                  |
| <code>architecture_hint</code>            | Overrides the architecture used by high-level disassembly                                                                                                                                                                      |
| <code>call_graph_config</code>            | Supplies call-graph options when call-graph analysis is enabled                                                                                                                                                                |

Feature flags are compile-time capabilities. Configuration cannot enable code
that was not compiled. <code>AnalysisConfig::validate</code> is called
automatically by both analyzer entry points; explicitly requesting a missing
capability returns <code>FeatureNotAvailable</code>. A compiled optional module
still runs only when its runtime switch is true.

<code>BinaryAnalyzer</code> does not currently invoke
<code>SecurityAnalyzer</code>; <code>AnalysisResult::security</code> therefore
remains unset through this path. Call the security module directly when needed.

## Disassembly

Enable one or both engines:

```toml
threatflux-binary-analysis = {
    version = "0.3",
    features = ["disasm-capstone", "disasm-iced"]
}
```

<code>Disassembler</code> provides:

- <code>new(architecture)</code>
- <code>with_config(architecture, config)</code>
- <code>disassemble(data, base_address)</code>
- <code>disassemble_at(data, base_address, length)</code>
- <code>disassemble_section(binary, section_name)</code>

<code>DisassemblyConfig</code> controls engine selection, maximum instruction
count, operand detail, simplified flow classification, and invalid-instruction
skipping. Disassembly rejects a base-address plus byte-length range whose
end-exclusive address cannot be represented by <code>u64</code>.

In Auto mode, x86/x86-64 prefers iced when it is compiled; otherwise it uses
Capstone. Non-x86 input requires Capstone. The current Capstone adapter supports
x86, x86-64, ARM, ARM64, MIPS32/64, and PowerPC32/64. The iced adapter supports
x86 and x86-64.

<code>disassemble_section</code> and the high-level binary helper resolve
checked file-backed section ranges against <code>BinaryFile</code>'s full owned
bytes; <code>Section::data</code> is not used as the analysis source. The
high-level helper visits executable sections until either its byte budget or
independent instruction-count budget is exhausted and can skip a section that
fails range validation.

Instruction category and control-flow target fields are derived from mnemonic
and operand text. They are convenient annotations, not a complete instruction
semantics model.

## Control flow and call graphs

The <code>control-flow</code> feature enables Capstone as well as the two
analysis modules.

<code>ControlFlowAnalyzer</code> discovers functions from parsed function
symbols, falling back to an estimated entry-point function in limited cases. It
then disassembles checked ranges from the full owned bytes, splits basic blocks,
and computes graph and complexity fields. <code>CallGraphAnalyzer</code> uses
similar function discovery and direct-call extraction.

The low-level analyzers reject work above explicit aggregate limits rather than
returning a truncated graph:

| Configuration                                                         |   Default | Meaning                                                                       |
| --------------------------------------------------------------------- | --------: | ----------------------------------------------------------------------------- |
| <code>control_flow::AnalysisConfig::max_instructions</code>           |    10,000 | Per-function decoded-instruction maximum                                      |
| <code>control_flow::AnalysisConfig::max_functions</code>              |    10,000 | Maximum discovered functions                                                  |
| <code>control_flow::AnalysisConfig::max_total_instructions</code>     | 1,000,000 | Aggregate decoded-instruction maximum                                         |
| <code>control_flow::AnalysisConfig::max_loops</code>                  |    10,000 | Aggregate retained advanced-loop maximum                                      |
| <code>control_flow::AnalysisConfig::max_total_loop_body_blocks</code> | 1,000,000 | Aggregate retained loop-body memberships; one block in two loops counts twice |
| <code>CallGraphConfig::max_functions</code>                           |    10,000 | Maximum discovered functions                                                  |
| <code>CallGraphConfig::max_total_instructions</code>                  | 1,000,000 | Aggregate decoded-instruction maximum                                         |

<code>CallGraphConfig::analyze_indirect_calls</code> records recognized indirect
call-family instructions with <code>CallGraphEdge::callee == None</code>; it does
not resolve the target. A real function at address zero is represented as
<code>Some(0)</code>. DOT export uses a distinct unknown-target node, while JSON
serializes the unknown target as <code>null</code>.
<code>detect_tail_calls</code> recognizes direct final jumps,
<code>include_library_calls</code> controls the library-name filter, and
<code>max_labeled_call_depth</code> limits only breadth-first depth labels.
Reachability and edge extraction still examine the bounded reconstructed graph.

These analyses are heuristic:

- stripped binaries can produce few or no functions;
- invalid or non-file-backed section ranges can produce skipped/empty results;
- indirect calls, virtual dispatch, tail calls, and import thunks are not
  exhaustively resolved;
- the synthetic entry-point function uses an estimated size;
- per-function analysis failures may be skipped while other functions continue,
  but an error is returned when every discovered function fails;
- a discovered function outside every executable section is a failure; a
  containing section that legitimately resolves zero file-backed bytes is an
  empty successful disassembly;
- exceeding a function or aggregate instruction cap fails the operation instead
  of returning a silently truncated result;
- exceeding an advanced-loop count or aggregate body-membership cap likewise
  fails instead of omitting loops;
- graph reachability and complexity apply only to the reconstructed graph.

Do not interpret a graph as proof of all executable paths.

When high-level base and enhanced control-flow outputs are requested together,
<code>BinaryAnalyzer</code> decodes and constructs the graphs once, then derives
both result views from that pass. The high-level flags are passed explicitly to
the low-level analyzer, so base control flow alone leaves cognitive complexity
and retained advanced loops disabled.

## Security analysis

<code>SecurityAnalyzer::analyze(&BinaryFile)</code> returns:

- categorized import, section, and symbol indicators;
- parser-derived hardening flags for native ELF, PE, and Mach-O inputs;
- detailed findings with a category and severity;
- a deterministic weighted score from 0 to 100.

The analyzer uses exact import-name lists, selected suspicious-name substrings,
read/write/execute section checks, and parser-provided hardening metadata. The
score is a project heuristic, not CVSS, exploitability, maliciousness, or a
probability.

Each <code>SecurityConfig</code> category boolean independently gates its import
rule set. <code>min_string_length</code> filters import, section-name, and
symbol-name rules. Section-permission checks still run regardless of the
import-category switches. Missing native-hardening findings and score penalties
apply only to ELF, PE, and Mach-O; false flags on Java, WebAssembly, and raw
inputs are treated as unknown or inapplicable.

```rust
use threatflux_binary_analysis::{
    analysis::security::SecurityAnalyzer,
    BinaryFile,
    Result,
};

fn triage(bytes: &[u8]) -> Result<()> {
    let binary = BinaryFile::parse(bytes)?;
    let result = SecurityAnalyzer::new(binary.architecture()).analyze(&binary)?;

    println!("heuristic score: {:.1}", result.risk_score);
    for finding in result.findings {
        println!("{:?}: {}", finding.severity, finding.description);
    }
    Ok(())
}
```

Absence of a finding is not evidence that input is benign. See
[Analysis boundaries](docs/ANALYSIS_BOUNDARIES.md).

## Entropy and symbol helpers

With <code>entropy-analysis</code>,
<code>analysis::entropy::analyze_binary</code> computes Shannon entropy for the
full input and in-bounds file-backed section ranges addressed by parser offsets
and <code>file_size</code> (capped by the virtual <code>size</code>). It
scans fixed-size regions and uses thresholds plus a short list of strings to
produce packing indicators. Those indicators are triage hints, not packer
identification proof.

With <code>symbol-resolution</code>,
<code>analysis::symbols::demangle_symbols</code> fills missing demangled names
for symbols the parser already returned. It does not parse debug information or
recover absent symbols.

## Utilities

### PatternMatcher

<code>utils::patterns::PatternMatcher</code> supports byte, string, magic, and
hex-wildcard searches with a global match-count limit and an aggregate owned
output limit. <code>MatchConfig::max_output_bytes</code> defaults to 16 MiB and
accounts for cloned pattern metadata and matched bytes in both the flat result
and category buckets. Exceeding it returns <code>InvalidData</code> rather than a
partial result. Built-in sets are available for a subset of categories. Regex
and structural pattern variants currently return
<code>BinaryError::FeatureNotAvailable</code>; they are not implemented
regex/structural engines. Pattern names such as malware or packer are signatures
only and do not constitute a verdict.

### Memory mapping

<code>utils::mmap::MappedBinary</code> exposes bounded slices, endian-aware
integer reads, C-string reads, pattern lookup, hexdumps, and borrowed views.
Its <code>new</code>/<code>from_file</code> constructors are unsafe: the caller
must guarantee that no handle or process mutates or truncates the file while the
map is alive.

<code>AdvancedMmap::new</code> is unsafe for the same reason. File-backed huge
pages are rejected. Populate is supported on Linux/Android and rejected
elsewhere; memory locking is supported on Unix and rejected elsewhere. A
requested lock can still fail at runtime due to OS policy or resource limits.
Passing mapped bytes to <code>BinaryFile::parse</code> creates an owned copy.

### Compression

With <code>compression</code>, <code>utils::compression::decompress</code>
accepts gzip (including concatenated members) and valid zlib headers, with a
64 MiB default expanded-output limit.
<code>utils::compression::decompress_with_limit</code> accepts a caller-chosen
ceiling and enforces it while streaming, before appending excess bytes.

### Serde and visualization

With <code>serde-support</code>, public data types gain Serde derives where
implemented, and <code>utils::serde_utils</code> provides pretty JSON
serialization/deserialization helpers.

With <code>visualization</code>,
<code>analysis::visualization::cfg_to_dot</code> exports basic block nodes and
successor edges as DOT. Call-graph DOT and JSON exporters live in
<code>analysis::call_graph</code> under <code>control-flow</code>.

## Errors

The crate-wide <code>Result&lt;T&gt;</code> alias uses the non-exhaustive
<code>BinaryError</code> enum. Variants cover parsing, unsupported formats and
architectures, invalid/oversized data, disassembly/control-flow/symbol/entropy
failures, I/O, memory maps, configuration, unavailable features, and internal
failures. Match with a wildcard so future variants remain source compatible.

Error strings are useful for diagnostics but are not a stable machine-readable
protocol. Match variants when behavior depends on the error category.

## Feature reference

| Feature                        | Public modules or behavior                   |
| ------------------------------ | -------------------------------------------- |
| <code>elf</code>               | <code>formats::elf</code>                    |
| <code>pe</code>                | <code>formats::pe</code>                     |
| <code>macho</code>             | <code>formats::macho</code>                  |
| <code>java</code>              | <code>formats::java</code> and JAR detection |
| <code>wasm</code>              | <code>formats::wasm</code>                   |
| <code>disasm-capstone</code>   | <code>disasm</code> with Capstone            |
| <code>disasm-iced</code>       | <code>disasm</code> with iced-x86            |
| <code>control-flow</code>      | CFG and call-graph modules; implies Capstone |
| <code>entropy-analysis</code>  | Entropy module                               |
| <code>symbol-resolution</code> | Symbol demangling module                     |
| <code>compression</code>       | Compression helper                           |
| <code>visualization</code>     | CFG DOT helper                               |
| <code>serde-support</code>     | Serde derives and JSON helpers               |
