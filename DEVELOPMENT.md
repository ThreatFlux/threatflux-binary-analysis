# Development Guide

This guide covers local development for ThreatFlux Binary Analysis. For change
submission and review expectations, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Prerequisites

- Rust 1.95.0 or newer; the repository toolchain file pins 1.97.1 with rustfmt
  and Clippy for reproducible local/CI checks
- Git
- A C build environment when compiling the Capstone backend

The Makefile uses these optional Cargo tools:

- <code>cargo-audit</code> for RustSec advisories
- <code>cargo-deny</code> for dependency policy
- <code>cargo-hack</code> for feature combinations
- <code>cargo-llvm-cov</code> for coverage

Install the standard Rust components:

```console
rustup component add rustfmt clippy
```

Install the pinned Cargo tools used by the full local contract with:

```console
make tools
```

This installs Cargo binaries into your normal Cargo bin directory. System
packages remain an explicit platform setup step.

## Build

```console
cargo build
cargo build --all-features
cargo build --no-default-features
```

Default features are <code>elf</code>, <code>pe</code>,
<code>macho</code>, and <code>java</code>. Optional analysis code must remain
correctly gated so that the no-default-features build continues to work.
Runtime <code>AnalysisConfig</code> defaults are parser-only; enabling an
optional runtime switch without its Cargo feature must return
<code>FeatureNotAvailable</code>.

Focused builds are useful while changing a module:

```console
cargo check --no-default-features --features elf
cargo check --no-default-features --features wasm
cargo check --no-default-features --features disasm-iced
cargo check --no-default-features --features control-flow
```

The <code>control-flow</code> feature implies <code>disasm-capstone</code>.

## Validation contracts

Use the Makefile as the supported local interface:

```console
make check
make test
make security
make feature-check
```

<code>make check</code> verifies formatting, all-feature Clippy, rustdoc, and
default/no-default all-target compilation. <code>make test</code> runs the
all-feature suite. <code>make security</code> runs RustSec and dependency policy
checks. <code>make feature-check</code> exercises the Cargo feature power set.

Before opening a pull request, run the complete contract:

```console
make ci
```

This also verifies the crates.io package. All Make targets use
<code>--locked</code> where Cargo supports it, so commit lockfile updates with
intentional dependency changes. Use <code>make help</code> for the concise
target list.

## Repository layout

| Path                       | Responsibility                                                                     |
| -------------------------- | ---------------------------------------------------------------------------------- |
| <code>src/lib.rs</code>    | Top-level parser/analyzer entry points and feature dispatch                        |
| <code>src/types.rs</code>  | Shared public result and graph types                                               |
| <code>src/formats/</code>  | Format detection and individual parsers                                            |
| <code>src/disasm/</code>   | Capstone and iced-x86 adapters                                                     |
| <code>src/analysis/</code> | Control-flow, call-graph, entropy, symbols, visualization, and security heuristics |
| <code>src/utils/</code>    | Memory maps, byte patterns, bounded compression, and JSON                          |
| <code>examples/</code>     | Command-line examples built against public APIs                                    |
| <code>tests/</code>        | Integration, feature, property, and performance-oriented tests                     |
| <code>test_samples/</code> | Manual fixtures and generators; not consumed by the automated Rust tests           |

<code>Cargo.lock</code> is tracked so CI, security checks, and releases validate
the same dependency resolution.

## Design boundaries

Keep the layers explicit:

- Parsers describe implemented file structure. They do not execute, emulate,
  verify signatures, or decide whether a file is malicious.
- Disassemblers decode the exact bytes and architecture supplied to them.
- Graph analyses reconstruct a partial model from symbols, entry points, and
  checked file-backed ranges in the binary's full owned bytes.
- Security and entropy modules produce heuristic triage signals, not verdicts.

When changing behavior, update [API.md](API.md) and
[Analysis boundaries](docs/ANALYSIS_BOUNDARIES.md) in the same pull request.
Avoid using terms such as comprehensive, safe, validated, vulnerability, or
malware detection unless the implementation and tests establish that precise
claim.

## Adding or changing a parser

1. Gate optional format code consistently in module declarations, format
   detection, dispatch, and tests.
2. Implement <code>BinaryFormatParser</code> and
   <code>BinaryFormatTrait</code>.
3. Validate every offset, size, conversion, and addition before slicing.
4. Define how unknown architecture, entry point, unavailable tables, and
   malformed metadata are represented.
5. Add valid, truncated, boundary, and random-input tests.
6. Test the feature alone, with defaults, with all features, and with no
   default features.
7. Document omissions as clearly as supported fields.

Never execute a fixture as part of parser validation. Prefer small,
programmatically generated bytes with documented provenance.

## Optional-analysis changes

For disassembly and graphs, test both direct byte APIs and the
<code>BinaryAnalyzer</code> integration path. Built-in analysis reads checked
ranges from the full <code>BinaryFile</code>; <code>Section::data</code> is
preview-only. Test large sections, invalid ranges, non-file-backed sections, and
budget exhaustion as well as tiny synthetic bytes.

For heuristic security changes:

- document the exact signal and expected false positives/negatives;
- keep scores deterministic;
- avoid labels that imply maliciousness or exploitability;
- test normal software patterns as well as suspicious-looking fixtures.

## Tests and fixtures

See [TESTING.md](TESTING.md) and [tests/README.md](tests/README.md). Automated
tests primarily construct synthetic bytes in memory. The files under
<code>test_samples/</code> are manual fixtures, and some are intentionally
suspicious or unsafe to execute.

Generated outputs do not belong in commits. The ignore rules cover Cargo
targets, coverage output, profiler files, test output, and temporary Rust test
copies. If a regression needs a binary fixture, keep it minimal, document its
source/generator and license, and add it intentionally.

## Documentation

Public items should have accurate rustdoc. Examples must build with the feature
set documented next to them. Markdown snippets should use real type and method
names, and limitations should be adjacent to capability claims.

Validate docs and examples through:

```console
make check
make test
```

## Troubleshooting

### Capstone fails to compile

Confirm that the platform C compiler and build tools are available, then
reproduce with
<code>cargo check --locked --no-default-features --features disasm-capstone</code>.
Include the compiler and target triple in a bug report.

### An optional result is None

Confirm both the Cargo feature and the runtime configuration. Runtime booleans
do not compile optional modules into the crate.

### Disassembly or graphs are empty

Check the detected architecture, selected backend, function symbols/entry
point, checked section file ranges, <code>max_analysis_size</code>, and
<code>max_disassembly_instructions</code>. Graph instruction limits apply per
function.
<code>Section::data</code> is only a preview and is not the built-in analysis
source.

### A Make target reports a missing command

Run <code>make help</code>, inspect the target, and install the named optional
tool. <code>make tools</code> installs the pinned Cargo utilities used by the
full contract.
