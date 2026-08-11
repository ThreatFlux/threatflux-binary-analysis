# ThreatFlux Binary Analysis

[![CI](https://github.com/ThreatFlux/threatflux-binary-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-binary-analysis/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/threatflux-binary-analysis/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-binary-analysis/actions/workflows/security.yml)
[![Crates.io](https://img.shields.io/crates/v/threatflux-binary-analysis.svg)](https://crates.io/crates/threatflux-binary-analysis)
[![docs.rs](https://docs.rs/threatflux-binary-analysis/badge.svg)](https://docs.rs/threatflux-binary-analysis)
[![MSRV](https://img.shields.io/badge/MSRV-1.95.0-blue.svg)](Cargo.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A synchronous Rust library for inspecting the structure of executable and bytecode
formats. The core API detects and parses bytes into a common representation of
metadata, sections, symbols, imports, and exports. Optional Cargo features add
disassembly, control-flow reconstruction, entropy measurements, symbol
demangling, JSON support, and graph output.

Upgrading from 0.2.0? See the [migration guide](docs/MIGRATING_TO_0.3.md).

This is a static-analysis building block, not a malware verdict engine or an
execution sandbox. Its security findings, packing indicators, and control-flow
results are heuristics that can produce false positives, false negatives, or
incomplete output.

## What is implemented

| Input                 | Cargo feature                | Current parser output and limits                                                                                                                                                         |
| --------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ELF                   | <code>elf</code> (default)   | Header metadata, sections, symbols, imports, exports, and selected hardening metadata                                                                                                    |
| PE                    | <code>pe</code> (default)    | Header metadata, sections, COFF symbols when present, imports, exports, and selected hardening metadata; Authenticode is not verified                                                    |
| Thin Mach-O           | <code>macho</code> (default) | Header metadata, sections, nlist symbols when present, imports, exports, entry point when reported by the image, and selected hardening metadata; fat/universal binaries are unsupported |
| Java class            | <code>java</code> (default)  | Fixed-header checks and a synthetic whole-file section; the version is validated for detection but not exposed, and the constant pool, fields, methods, and attributes are not decoded   |
| JAR                   | <code>java</code> (default)  | Identifies ZIP archives containing class entries and exposes class-entry names as symbols; class bodies are not decoded                                                                  |
| WebAssembly           | <code>wasm</code>            | Validated module plus selected section ranges, imports, and exports; the WebAssembly start-function index is not represented as a virtual-address entry point                            |
| Other non-empty bytes | always                       | A raw binary with one synthetic data section                                                                                                                                             |

Valid Java class headers, bounded universal Mach-O headers, and WebAssembly
magic are recognized even when the corresponding parser feature is disabled.
Parsing such input then returns an unsupported-format error. Empty input is
rejected; an unrecognized non-empty input is classified as raw data.

Parser output and optional analyses are separate layers:

1. <code>BinaryFile::parse</code> detects and parses structural data.
2. <code>BinaryAnalyzer</code> copies that structural data and invokes only the
   analysis modules compiled into the crate.
3. <code>Disassembler</code>, control-flow analysis, entropy analysis, and
   <code>SecurityAnalyzer</code> are opt-in tools with independent limitations.

See [Analysis boundaries](docs/ANALYSIS_BOUNDARIES.md) before using the crate on
untrusted input.

## Requirements

- Rust 1.95.0 or newer
- A C toolchain when building the Capstone backend

## Installation

Default parsers (ELF, PE, thin Mach-O, Java class/JAR):

```toml
[dependencies]
threatflux-binary-analysis = "0.3"
```

Select only the formats and analysis backends you need:

```toml
[dependencies]
threatflux-binary-analysis = {
    version = "0.3",
    default-features = false,
    features = ["elf", "disasm-iced", "serde-support"]
}
```

### Feature flags

| Feature                        | Default | Adds                                                        |
| ------------------------------ | :-----: | ----------------------------------------------------------- |
| <code>elf</code>               |   yes   | ELF parser                                                  |
| <code>pe</code>                |   yes   | PE parser                                                   |
| <code>macho</code>             |   yes   | Thin Mach-O parser                                          |
| <code>java</code>              |   yes   | Java class and class-containing JAR parser                  |
| <code>wasm</code>              |   no    | WebAssembly parser                                          |
| <code>disasm-capstone</code>   |   no    | Capstone backend for x86, x86-64, ARM, AArch64, MIPS, PowerPC |
| <code>disasm-iced</code>       |   no    | iced-x86 backend for x86 and x86-64                         |
| <code>control-flow</code>      |   no    | Control-flow and call-graph analysis; also enables Capstone |
| <code>entropy-analysis</code>  |   no    | Shannon entropy and packing heuristics                      |
| <code>symbol-resolution</code> |   no    | Demangling of parsed symbol names                           |
| <code>compression</code>       |   no    | gzip and zlib decompression helper                          |
| <code>visualization</code>     |   no    | DOT export for control-flow graphs                          |
| <code>serde-support</code>     |   no    | Serde derives and JSON helpers                              |

Cargo features are compile-time capabilities. Setting an
<code>AnalysisConfig</code> boolean does not enable a missing feature. Version
0.3 defaults to parser-only analysis: every optional runtime switch is false.
To run an optional analysis, compile its Cargo feature and set its runtime
switch. Requesting a capability that was not compiled returns
<code>BinaryError::FeatureNotAvailable</code>.

## Quick start

Parse a file and inspect its structural metadata:

```rust
use std::fs;
use threatflux_binary_analysis::{BinaryFile, Result};

fn main() -> Result<()> {
    let bytes = fs::read("sample.bin")?;
    let binary = BinaryFile::parse(&bytes)?;

    println!("format: {}", binary.format());
    println!("architecture: {}", binary.architecture());
    println!("sections: {}", binary.sections().len());
    println!("imports: {}", binary.imports().len());

    Ok(())
}
```

Use <code>BinaryAnalyzer</code> when you want the unified
<code>AnalysisResult</code>:

```rust
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer, Result};

fn inspect(bytes: &[u8]) -> Result<()> {
    let config = AnalysisConfig {
        enable_disassembly: false,
        enable_control_flow: false,
        enable_call_graph: false,
        enable_cognitive_complexity: false,
        enable_advanced_loops: false,
        enable_entropy: false,
        ..Default::default()
    };

    let result = BinaryAnalyzer::with_config(config).analyze(bytes)?;
    println!("{} / {}", result.format, result.architecture);
    Ok(())
}
```

The API is synchronous and byte-slice based. <code>BinaryAnalyzer</code>
enforces its configured input limit, but bounding a file before reading it,
scheduling work, and applying wall-time limits remain caller responsibilities.

## Examples

Each example expects a path after <code>--</code>:

```console
cargo run --example basic_analysis -- path/to/file
cargo run --example security_analysis -- path/to/file
cargo run --example disassembly --features disasm-capstone -- path/to/file
cargo run --example control_flow --features control-flow -- path/to/file
```

<code>Section::size</code> is the virtual or in-memory span, while
<code>Section::file_size</code> is the byte count backed by the file at
<code>Section::offset</code>. <code>Section::data</code> is only an inline preview
for eligible file-backed sections no larger than 1 KiB. Built-in disassembly
and graph analysis resolve checked file-backed ranges against
<code>BinaryFile</code>'s full owned bytes. The current disassembly example
prints the preview directly and can therefore be partial; production callers
can use <code>Disassembler::disassemble_section</code> or pass a validated byte
range to <code>disassemble</code>.

## Security and resource boundaries

Treat every parsed file as adversarial:

- Reject oversized input before reading it. <code>BinaryAnalyzer</code> also
  enforces <code>AnalysisConfig::max_analysis_size</code> and returns
  <code>BinaryError::InputTooLarge</code>; direct
  <code>BinaryFile::parse</code> has no configured size policy.
- Set <code>AnalysisConfig::max_disassembly_instructions</code> for the maximum
  high-level disassembly result size. The default is 10,000 instructions.
- Expect copies. <code>BinaryFile::parse</code> owns a copy of the full input,
  and format implementations may retain additional owned data.
- ELF, PE, Mach-O, Java/JAR, and WebAssembly parsing rejects more than 100,000
  structural/output records, names longer than 4 KiB, or more than 32 MiB of
  aggregate owned name bytes per parse. JAR central-directory inspection has
  the tighter 50,000-entry limit described above.
- Run hostile inputs in a separate process with OS-level memory, CPU, and wall
  time limits. The API has no cancellation or timeout mechanism.
- Do not treat a successful parse, a low heuristic score, or absence of a
  finding as proof that a file is safe.
- The default compression helper caps expanded output at 64 MiB.
  <code>decompress_with_limit</code> accepts an application-specific ceiling.
- Pattern searches cap aggregate owned result data at 16 MiB by default;
  configure <code>MatchConfig::max_output_bytes</code> for a different budget.
- Keep files immutable while they are memory mapped.

Memory-map construction is an unsafe API because callers must keep the backing
file stable for the mapping lifetime. Rust's type system reduces many classes of
memory errors, but it is not a sandbox or a guarantee that malformed input
cannot panic, exhaust resources, or trigger a dependency bug.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Documentation

- [Curated API guide](API.md)
- [Analysis boundaries and threat model](docs/ANALYSIS_BOUNDARIES.md)
- [Migrating from 0.2 to 0.3](docs/MIGRATING_TO_0.3.md)
- [Release process](docs/RELEASING.md)
- [Development guide](DEVELOPMENT.md)
- [Testing guide](TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Generated Rust API documentation](https://docs.rs/threatflux-binary-analysis)

Generate API documentation locally with:

```console
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

## Development

The supported local contracts are:

```console
make check
make test
make security
make feature-check
make ci
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for prerequisites and feature-specific
checks. There are currently no Criterion benchmark targets in
<code>Cargo.toml</code>; performance-named integration tests are ordinary test
targets, not a published benchmark suite.

## Contributing

Bug reports, focused fixes, tests, and documentation corrections are welcome.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) first.

## License

Licensed under the [MIT License](LICENSE).
