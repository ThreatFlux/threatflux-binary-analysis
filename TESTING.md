# Testing Guide

The repository uses Rust unit tests, integration targets under
<code>tests/</code>, property-based tests, doctests, and feature-matrix builds.
No coverage percentage is promised: coverage is diagnostic evidence, not a
substitute for boundary and adversarial tests.

## Supported contracts

Use the Makefile interface:

```console
make check
make test
make security
make feature-check
```

<code>make check</code> covers formatting, all-feature Clippy, rustdoc, and
default/no-default all-target compilation. <code>make test</code> runs the
all-feature suite. <code>make security</code> runs dependency/advisory policy,
and <code>make feature-check</code> exercises the feature power set.

Run the full pre-PR contract with:

```console
make ci
```

CI runs all-feature tests on Linux, Windows, and macOS, validates the 1.95.0
MSRV, and checks the feature power set.

## Test organization

### Library unit tests

Module-local tests live next to code in <code>src/</code>. They exercise error
helpers, format internals, disassembly adapters, analysis algorithms, memory-map
reads, pattern matching, optional utilities, and serialization.

### Integration targets

The files under <code>tests/</code> compile as separate crates. Major groups
include:

| Area                              | Targets                                                                                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Top-level API and shared types    | <code>analyzer_test</code>, <code>types_test</code>, <code>integration_test</code>                                                                           |
| Detection and parser behavior     | <code>format*detection_test</code>, <code>elf_test</code>, <code>macho_test</code>, <code>wasm_test</code>, and the <code>unit*\*\_test</code> parser suites |
| Disassembly and graphs            | <code>iced_disasm_test</code>, <code>control_flow_test</code>, <code>enhanced_analysis_integration_test</code>                                               |
| Robustness                        | <code>unit_property_based_test</code> and its checked-in Proptest regression seeds                                                                           |
| Timing/stress-oriented assertions | <code>integration_performance_test</code>                                                                                                                    |

Feature attributes inside each target decide which tests are active. A target
that reports zero tests under a minimal feature set may be behaving correctly.

<code>integration_performance_test</code> is an ordinary test target with
timing-oriented assertions. The project currently has no enabled Criterion
benchmark targets, so do not describe <code>cargo bench</code> output as a
maintained benchmark suite.

## Focused commands

Run an integration target:

```console
cargo test --locked --test format_detection_test
cargo test --locked --test analyzer_test
cargo test --locked --test unit_property_based_test
```

Run one test and preserve its output:

```console
cargo test --locked --test elf_test test_name -- --nocapture
```

Exercise individual parsers:

```console
cargo test --locked --no-default-features --features elf
cargo test --locked --no-default-features --features pe
cargo test --locked --no-default-features --features macho
cargo test --locked --no-default-features --features java
cargo test --locked --no-default-features --features wasm
```

Exercise optional analysis combinations:

```console
cargo test --locked --no-default-features --features disasm-iced
cargo test --locked --no-default-features --features disasm-capstone
cargo test --locked --no-default-features --features control-flow
cargo test --locked --no-default-features --features entropy-analysis
cargo test --locked --no-default-features --features serde-support
```

The <code>control-flow</code> feature enables Capstone automatically.

For exhaustive pairwise feature validation, install cargo-hack and run the same
command as the Makefile/CI:

```console
make feature-check
```

## What parser tests should establish

For every format or structural field, include:

- a minimal valid input;
- truncated input at each meaningful boundary;
- invalid offsets, sizes, counts, alignments, and enum values;
- overflow-prone offset-plus-length cases;
- both supported widths/endianness where applicable;
- unsupported variants that return a typed error;
- an assertion for every capability or omission documented in the README/API;
- random bytes and structured random mutation where useful.

A test that only checks “does not return Err” is not enough for metadata.
Assert the format, architecture, offsets, sizes, entry point, permissions,
symbols/imports/exports, and relevant error variant.

## Analysis tests

Disassembly tests should state the exact architecture, base address, bytes,
engine feature, instruction budget, and expected instruction sequence.

Control-flow/call-graph tests should distinguish:

- complete expected graphs for deliberately tiny byte sequences;
- partial graphs caused by missing symbols, invalid file ranges, or budgets;
- empty results that are valid under the current discovery model;
- unsupported architecture/backend errors.

Security and entropy tests should include benign counterexamples. Findings and
scores are heuristic, so tests should lock down rule behavior without claiming
that a sample is malicious, vulnerable, packed, or safe.

## Property-based tests

The Proptest target generates arbitrary bytes and magic-prefixed structures to
exercise detection and parser invariants. Keep
<code>tests/unit_property_based_test.proptest-regressions</code> tracked so a
minimized failure remains reproducible.

Useful invariants include:

- public APIs return a value or typed error without reading outside input;
- reported ranges do not overflow and remain within the source where promised;
- limits are respected;
- repeated analysis of the same bytes/configuration is deterministic;
- disabled features continue to compile independently.

Property tests are not a fuzzing service. They complement, rather than replace,
long-running fuzzers and corpus-based testing.

## Fixtures

Most automated tests build synthetic bytes in memory or use helpers in
<code>tests/common/</code>. This makes format intent reviewable and avoids
opaque binary provenance.

<code>test_samples/</code> contains manual fixtures, generators, and scripts.
They are not referenced by the automated Rust test suite. Some source and
scripts intentionally demonstrate unsafe behavior; read
[test_samples/README.md](test_samples/README.md) and do not execute them on a
host you care about.

When adding a binary fixture:

1. Prefer generating it in the test.
2. If a checked-in binary is necessary, minimize it.
3. Document its source, license, generator/toolchain, architecture, and hash.
4. Never include live malware, credentials, personal data, or an unexplained
   compiled artifact.
5. Never execute a fixture in parser tests.

## Coverage

With cargo-llvm-cov installed:

```console
make coverage
```

Coverage output is generated under Cargo's target directory and must remain
untracked.

Review uncovered error paths and format boundaries rather than optimizing only
for a headline percentage.

## Debugging failures

```console
RUST_BACKTRACE=1 cargo test --locked --test integration_test -- --nocapture
cargo test --locked --test unit_property_based_test -- --nocapture
cargo test --locked --all-features -- --test-threads=1
```

When a failure is feature-specific, reproduce it with the smallest feature set
first, then confirm default, all-feature, and no-default configurations before
closing the issue.
