# Migrating from 0.2 to 0.3

Version 0.3.0 is the upcoming development release. Version 0.2.0 remains the
current crates.io release until the tag-driven release workflow publishes
0.3.0.

The 0.3 line tightens untrusted-input behavior and removes placeholder APIs.
Review the changes below before updating a dependency requirement.

## Dependency version

After 0.3.0 is published:

```toml
[dependencies]
threatflux-binary-analysis = "0.3"
```

The minimum supported Rust version remains 1.95.0. The crate now uses Rust 2024
edition internally; downstream crates do not have to change edition merely to
depend on it.

## Optional analyses are explicit

<code>AnalysisConfig::default()</code> is now parser-only. Disassembly,
control-flow, call-graph, cognitive-complexity, advanced-loop, entropy, and
symbol-demangling switches all default to <code>false</code>. The default input
limit remains 100 MiB.

To use an optional analysis, both layers must opt in:

1. compile the corresponding Cargo feature;
2. set the corresponding runtime configuration field.

```toml
[dependencies]
threatflux-binary-analysis = {
    version = "0.3",
    features = ["entropy-analysis"]
}
```

```rust
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer};

let config = AnalysisConfig {
    enable_entropy: true,
    ..Default::default()
};
let analyzer = BinaryAnalyzer::with_config(config);
```

<code>AnalysisConfig::validate()</code> is public and is called automatically by
<code>BinaryAnalyzer::analyze</code> and <code>analyze_binary</code>. Explicitly
requesting analysis code that was not compiled now returns
<code>BinaryError::FeatureNotAvailable</code>. In 0.2, the same request could be
silently ignored and leave its result field empty.

## Input and disassembly limits

<code>BinaryAnalyzer::analyze</code> and <code>analyze_binary</code> now reject
input larger than <code>AnalysisConfig::max_analysis_size</code> with
<code>BinaryError::InputTooLarge { actual, limit }</code>. The value also acts as
the high-level disassembly byte budget. A new, independent
<code>max_disassembly_instructions</code> field caps the total high-level
disassembly result and defaults to 10,000. Add this field to exhaustive
<code>AnalysisConfig</code> literals or use <code>..Default::default()</code>.

<code>BinaryFile::parse</code> is a lower-level parser and does not apply an
<code>AnalysisConfig</code>. Applications that call it directly must enforce
their own pre-read and pre-parse limit.

Direct and high-level disassembly now reject any base-address plus byte-length
range whose end-exclusive address would overflow <code>u64</code>.

The low-level format parsers now also apply non-configurable structural/output
limits: at most 100,000 records, 4 KiB per copied name, and 32 MiB of aggregate
copied names per parse. The constants are exposed as
<code>formats::MAX_PARSED_RECORDS</code>, <code>MAX_NAME_BYTES</code>, and
<code>MAX_OWNED_NAME_BYTES</code>. Inputs that previously produced unusually
large names or record sets can now return <code>InvalidData</code>. JAR archives
retain a separate 50,000 central-directory-entry limit.

## Low-level graph configuration

Low-level control-flow and call-graph analysis now reject inputs above
configurable aggregate budgets. Both configurations add
<code>max_functions</code> (default 10,000) and
<code>max_total_instructions</code> (default 1,000,000).
<code>control_flow::AnalysisConfig::max_instructions</code> remains the
per-function limit and now rejects an over-limit function instead of silently
returning a truncated graph.

Low-level <code>control_flow::AnalysisConfig</code> also adds
<code>max_loops</code> (default 10,000) and
<code>max_total_loop_body_blocks</code> (default 1,000,000). These bound the
number of retained advanced loops and their aggregate body memberships across
one binary analysis. Exceeding either limit returns an error rather than a
partial loop result. Add both fields to exhaustive literals or use
<code>..Default::default()</code>.

At the high level, <code>enable_control_flow</code> no longer accidentally
inherits the low-level defaults for cognitive complexity and advanced loops.
Those remain controlled only by <code>enable_cognitive_complexity</code> and
<code>enable_advanced_loops</code>. Requesting base and enhanced output together
now reuses one control-flow construction pass.

Several public fields were misleading and have been removed or renamed:

- remove <code>max_depth</code>, <code>enable_call_graph</code>, and
  <code>call_graph_config</code> from low-level
  <code>control_flow::AnalysisConfig</code> literals;
- remove <code>resolve_virtual_calls</code> and
  <code>follow_import_thunks</code> from <code>CallGraphConfig</code>; those
  operations were not implemented;
- rename <code>CallGraphConfig::max_call_depth</code> to
  <code>max_labeled_call_depth</code>. It limits depth labels only, not edge
  extraction or reachability.

<code>CallGraphConfig::analyze_indirect_calls</code> remains available because
it gates recording recognized indirect call-family instructions. Their target
is reported as unknown; the analyzer does not resolve function pointers.
Prefer <code>..Default::default()</code> in configuration literals when default
resource budgets are appropriate.

<code>CallGraphEdge::callee</code> changed from <code>u64</code> to
<code>Option&lt;u64&gt;</code>. Unresolved indirect targets are now
<code>None</code> instead of the sentinel address zero; a real address zero is
<code>Some(0)</code>. Update exhaustive edge literals and consumers. JSON emits
<code>null</code> for an unknown target, and DOT output uses a separate
unknown-target node.

## Section file extents

<code>Section</code> now has a public <code>file_size</code> field. Its existing
<code>size</code> field consistently means the virtual or in-memory span;
<code>file_size</code> is the number of bytes backed by the input at
<code>offset</code>. Update exhaustive struct literals and serialized schemas.
Use <code>file_size</code>, capped by <code>size</code>, when reading section bytes.
This prevents BSS/zero-fill ranges and PE alignment padding from consuming data
that belongs elsewhere in the file.

<code>BinaryError</code> is now non-exhaustive. Downstream matches need a
fallback arm:

```rust
use threatflux_binary_analysis::BinaryError;

fn category(error: &BinaryError) -> &'static str {
    match error {
        BinaryError::InputTooLarge { .. } => "limit",
        BinaryError::UnsupportedFormat(_) => "format",
        _ => "analysis",
    }
}
```

## Removed placeholder module

<code>utils::extractor</code>, <code>CodeExtractor</code>, and
<code>TypeAdapter</code> were removed. Their 0.2 implementations returned only
placeholder strings or <code>Unknown</code> values and did not perform
extraction or adaptation. There is no direct replacement; use the parser,
disassembly, and shared-type APIs that implement the needed operation.

## Memory-map constructors are unsafe

The following constructors are now <code>unsafe</code>:

- <code>MappedBinary::new</code>
- <code>MappedBinary::from_file</code>
- <code>AdvancedMmap::new</code>

The caller must guarantee that no handle or process mutates or truncates the
backing file for the mapping lifetime. This pre-existing platform invariant is
now visible at the API boundary.

<code>AdvancedMmap</code> also rejects configuration it cannot honor:
file-backed huge pages are unsupported, populate is Linux/Android-only, and
memory locking is Unix-only.

## Bounded decompression

<code>utils::compression::decompress</code> now limits expanded output to
<code>DEFAULT_MAX_DECOMPRESSED_SIZE</code> (64 MiB) and supports concatenated
gzip members. Use <code>decompress_with_limit(data, max_size)</code> for a
different application budget. Inputs that exceed the selected expanded limit
now return an error rather than growing output without a ceiling.

## Detection and metadata corrections

Behavioral corrections can change results for the same bytes:

- PE detection now requires a checked PE header offset and
  <code>PE\0\0</code> signature; an MZ prefix alone can fall back to raw.
- PE section, symbol, import, and export addresses are now absolute image
  virtual addresses instead of mixing RVAs with absolute addresses.
- JAR inspection rejects more than 50,000 entries and requires a class file.
- Java class detection now requires a plausible fixed header (major version at
  least 45 and a nonzero constant-pool count), and universal Mach-O headers win
  the shared <code>CAFEBABE</code> magic ambiguity.
- Thin Mach-O can now report the entry point/base address and records
  code-signature load-command presence without claiming cryptographic
  verification.
- Thin Mach-O now preflights dyld bind and export streams before Goblin
  materializes them. Unknown/malformed opcodes, invalid indexes, cycles, and
  export tries deeper than 128 levels return an error.
- Thin Mach-O also bounds load-command/section counts and spans, validates
  command-local dylib/rpath strings, nlist and string-table ranges/index
  arithmetic, and raw `LC_MAIN`/`__TEXT` address arithmetic before Goblin parses
  load commands. Malformed, amplifying, or host-sized overflowing inputs now
  return an error, including on 32-bit targets.
- PE COFF and thin Mach-O nlist symbol tables are now exposed when present;
  stripped binaries can still report no symbols.
- WebAssembly start-function indices are no longer reported as virtual-address
  entry points.
- WebAssembly parsing now validates complete modules, including function bodies
  and cross-section semantics, before returning metadata.
- Parser range arithmetic and section-byte extraction use checked bounds.
- Raw binaries report unknown endianness rather than assuming little endian.

<code>Endianness</code> now includes <code>Unknown</code>, and that is also its
default. Add an <code>Unknown</code> or wildcard arm to exhaustive downstream
matches.

If persisted output is compared across versions, treat these as intentional
semantic changes and refresh fixtures.

## Heuristic and pattern behavior

<code>SecurityConfig</code> category switches are now applied independently,
and <code>min_string_length</code> is honored by import/name rules. Indicator
lists are canonicalized to deterministic, deduplicated ordering. Repeated
equivalent import, section, and symbol records no longer duplicate findings or
inflate the score. Missing native-hardening findings and penalties now apply
only to ELF, PE, and Mach-O rather than Java, WebAssembly, or raw inputs.

<code>MatchConfig</code> adds <code>max_output_bytes</code>, with a 16 MiB
default. It limits aggregate cloned pattern metadata and matched bytes across
both result collections. Add the field to exhaustive struct literals or use
<code>..Default::default()</code>. Searches now return <code>InvalidData</code>
instead of allocating beyond that limit or returning a partial result.

Regex and structural <code>PatternMatcher</code> variants now return
<code>FeatureNotAvailable</code> instead of looking like a successful search
with no matches. Pattern type/data mismatches return <code>InvalidData</code>.

These changes make unsupported behavior explicit; they do not turn heuristic
findings into malware or vulnerability verdicts.

## Call-graph exporters return errors

<code>CallGraph::to_dot</code>, <code>to_dot_with_config</code>, and
<code>to_json</code> now return <code>Result&lt;String&gt;</code>. Handle or propagate
the result instead of treating export failure as an empty string. JSON export
without the <code>serde-support</code> feature returns
<code>BinaryError::FeatureNotAvailable</code>.

## Upgrade checklist

- Update the Cargo requirement when 0.3.0 is published.
- Add runtime opt-ins for every optional analysis you intend to run.
- Handle <code>FeatureNotAvailable</code> and <code>InputTooLarge</code>.
- Set <code>max_disassembly_instructions</code> and add it to exhaustive config
  literals.
- Add explicit low-level graph <code>max_functions</code> and
  <code>max_total_instructions</code> budgets, plus control-flow
  <code>max_loops</code> and <code>max_total_loop_body_blocks</code>; update
  removed and renamed graph configuration fields.
- Handle <code>CallGraphEdge::callee</code> as an optional address.
- Add <code>Section::file_size</code> to exhaustive section literals and stored
  schemas.
- Add a wildcard arm to <code>BinaryError</code> matches.
- Handle <code>Endianness::Unknown</code> in exhaustive matches.
- Replace/remove all <code>utils::extractor</code> usage.
- Handle call-graph DOT/JSON exporter results.
- Audit every memory-map call site and document its file-stability invariant.
- Choose an explicit decompression ceiling.
- Refresh expected PE, Mach-O, WebAssembly, raw, security, and pattern outputs.
- Run <code>make ci</code> in this repository or the equivalent downstream
  feature/test matrix.
