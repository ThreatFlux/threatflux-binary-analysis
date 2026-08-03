# Test Suite Map

This directory contains Cargo integration-test targets and shared test helpers.
Start with the project-wide [Testing Guide](../TESTING.md) for the supported
commands, feature matrix, fixture policy, and coverage instructions.

## Targets

| Target                                             | Primary responsibility                                             |
| -------------------------------------------------- | ------------------------------------------------------------------ |
| <code>analyzer_test.rs</code>                      | <code>BinaryAnalyzer</code> configuration and result behavior      |
| <code>types_test.rs</code>                         | Shared enums, structures, defaults, and optional Serde behavior    |
| <code>format_detection_test.rs</code>              | Magic detection, raw fallback, malformed data, and feature gates   |
| <code>elf_test.rs</code>                           | ELF parser behavior and edge cases                                 |
| <code>macho_test.rs</code>                         | Thin Mach-O parser behavior, unsupported fat input, and edge cases |
| <code>wasm_test.rs</code>                          | Feature-gated WebAssembly parsing                                  |
| <code>integration_test.rs</code>                   | End-to-end parser/analyzer flows across supported formats          |
| <code>control_flow_test.rs</code>                  | Feature-gated control-flow behavior                                |
| <code>iced_disasm_test.rs</code>                   | iced-x86 selection and disassembly                                 |
| <code>enhanced_analysis_integration_test.rs</code> | Control-flow, call-graph, and enhanced-analysis integration        |
| <code>integration_performance_test.rs</code>       | Stress and timing-oriented assertions run as normal tests          |
| <code>unit_elf_test.rs</code>                      | Additional ELF structures and malformed inputs                     |
| <code>unit_pe_test.rs</code>                       | PE structures and malformed inputs                                 |
| <code>unit_macho_test.rs</code>                    | Additional Mach-O structures and malformed inputs                  |
| <code>unit_java_test.rs</code>                     | Java class/JAR behavior and malformed inputs                       |
| <code>unit_compiler_detection_test.rs</code>       | Implemented compiler-metadata heuristics                           |
| <code>unit_debug_info_test.rs</code>               | Debug-related metadata fixtures and current parser behavior        |
| <code>unit_enhanced_binary_info_test.rs</code>     | Extended metadata/result structures                                |
| <code>unit_property_based_test.rs</code>           | Proptest invariants over generated input                           |

<code>common/</code>, <code>mod.rs</code>, and <code>util.rs</code> hold shared
or reusable test support. Cargo also treats top-level Rust files in this
directory as integration targets, so keep helper code warning-free.

## Quick commands

```console
make check
make test
make feature-check
make security
make ci
```

Run one target:

```console
cargo test --locked --test format_detection_test
cargo test --locked --test unit_property_based_test
```

Run one named test:

```console
cargo test --locked --test elf_test test_name -- --nocapture
```

Compile and run a parser by itself:

```console
cargo test --locked --no-default-features --features elf
cargo test --locked --no-default-features --features pe
cargo test --locked --no-default-features --features macho
cargo test --locked --no-default-features --features java
cargo test --locked --no-default-features --features wasm
```

Optional analysis targets require their matching features:

```console
cargo test --locked --no-default-features --features disasm-iced
cargo test --locked --no-default-features --features disasm-capstone
cargo test --locked --no-default-features --features control-flow
```

## Test-data rules

- Prefer compact synthetic inputs built by the test or helpers.
- Assert typed results and exact fields, not just successful return.
- Add truncation, overflow, invalid-range, unsupported-variant, and benign
  counterexample cases.
- Keep
  <code>unit_property_based_test.proptest-regressions</code> under version
  control.
- Do not commit temporary editor/test-runner copies or generated coverage.
- Do not execute analyzed binaries as part of static parser tests.
- Manual files under <code>../test_samples/</code> are not automated fixtures;
  some intentionally contain unsafe patterns.

There is no maintained coverage threshold or enabled Criterion benchmark suite.
Report measured coverage and timing with the command, platform, Rust version,
feature set, and input corpus that produced them.
