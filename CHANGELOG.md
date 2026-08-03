# Changelog

All notable changes are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-03

### Added

- Typed `BinaryError::InputTooLarge { actual, limit }` failures and automatic
  `AnalysisConfig` capability validation.
- Bounded gzip/zlib decompression with a 64 MiB default and a caller-selected
  `decompress_with_limit` API.
- Explicit threat-model, migration, testing, development, and protected release
  documentation.
- CI coverage for the MSRV, stable Rust, all targets, feature combinations,
  crate packaging, dependency policy, and cross-platform tests.

### Changed

- Adopted Rust 2024, Cargo resolver 3, a Rust 1.95.0 MSRV, and a pinned 1.97.1
  contributor/CI toolchain.
- Made `AnalysisConfig::default()` parser-only; every optional analysis now
  requires both its Cargo feature and an explicit runtime opt-in.
- Enforced `max_analysis_size` as the high-level input limit and disassembly
  byte budget, and added an independent 10,000-instruction default through
  `max_disassembly_instructions`.
- Split `Section`'s virtual `size` from its file-backed `file_size`, preventing
  zero-filled or adjacent file data from being analyzed as section contents.
- Added hard parser structural/output ceilings of 100,000 records, 4 KiB per
  name, and 32 MiB of aggregate copied names, with early WebAssembly count
  checks and fallible reservation before owned output growth.
- Made disassembly, control-flow, and call-graph analysis read checked section
  ranges from the owned input instead of relying on 1 KiB section previews.
- Made disassembly and graph output deterministic, honored architecture hints,
  bounded instruction work, and surfaced an error when every attempted section
  or function fails.
- Reject disassembly ranges whose base address plus byte length would overflow
  instead of allowing backend-specific instruction-address wrapping.
- Added rejecting function-count and aggregate-instruction budgets to low-level
  control-flow and call-graph analysis. Removed non-operative graph settings and
  renamed the call-depth option to `max_labeled_call_depth` to match its actual
  scope.
- Bounded retained advanced-loop counts and aggregate loop-body memberships,
  merged multiple latches without retaining duplicate loop bodies, and indexed
  dominator depth/ancestry once per graph to avoid quadratic chain walks.
- Made high-level base control flow honor its cognitive/advanced-loop switches
  and reuse one graph-construction pass when base and enhanced output are both
  requested.
- Represented unresolved indirect call targets as `CallGraphEdge::callee = None`
  instead of conflating them with a real function at address zero, and changed
  tail-call extraction to discard each decoded instruction vector immediately.
- Changed call-graph DOT and JSON convenience exporters to return
  `Result<String>` instead of silently replacing export failures with an empty
  string.
- Corrected PE, ELF, Mach-O, WebAssembly, raw-format, hardening, and compiler
  metadata that previously relied on placeholders or unsafe assumptions.
- Bounded pattern-match owned output to 16 MiB by default, including duplicated
  flat/category results, and made the limit configurable through
  `MatchConfig::max_output_bytes`.
- Deduplicated repeated import, section, and symbol security findings and
  stopped applying native hardening penalties to Java, WebAssembly, and raw
  inputs.
- Disambiguated Java class headers from universal Mach-O's shared
  `CAFEBABE` magic using bounded structural checks.
- Validated complete WebAssembly modules, including function bodies and
  cross-section semantics, before returning structural metadata.
- Added `Endianness::Unknown` and made it the default instead of treating
  unspecified byte order as little-endian.
- Added checked PE COFF and thin Mach-O nlist symbol extraction when those
  tables are present.
- Normalized PE section, symbol, import, and export addresses to absolute image
  virtual addresses so address-based analysis uses one domain.
- Preflight Mach-O dyld bind/export streams with expanded-record, index,
  arithmetic, cycle, and 128-level trie-depth checks before calling Goblin's
  materializing helpers.
- Validated raw thin Mach-O load-command and section counts/spans, command-local
  strings, symbol/string-table ranges, nlist string-index arithmetic, and
  `LC_MAIN`/`__TEXT` address arithmetic before Goblin parses them, preventing
  malformed offsets from panicking, wrapping, or amplifying allocation,
  including on 32-bit hosts.
- Applied security-rule configuration per category and canonicalized heuristic
  indicators. These findings remain best-effort triage signals, not malware or
  vulnerability verdicts.
- Minimized optional dependency features and removed unused runtime and test
  dependencies.
- Replaced inline token arguments with a protected, tag-driven workflow that
  exposes the organization registry credential only to `cargo publish`,
  publishes only after verification, and creates the GitHub release last.

### Fixed

- Removed self-referential Goblin parser state and the unsound lifetime
  `transmute` used by the ELF, PE, and Mach-O implementations.
- Added checked conversions, additions, and range access for attacker-controlled
  offsets, sizes, addresses, memory-map reads, and analysis calculations.
- Preflighted JAR central-directory metadata before allocation, capped archives
  at 50,000 entries, rejected ZIP64/multi-disk inputs, and stopped claiming
  generic ZIP files as Java archives.
- Prevented empty patterns, non-ASCII case folding, mismatched pattern data, and
  malformed hexadecimal wildcards from producing panics or false success.
- Made unsupported regex and structural matching return
  `FeatureNotAvailable` instead of empty successful results.
- Made memory-map safety requirements explicit and rejected configuration the
  implementation cannot honor.

### Removed

- The public `utils::extractor` placeholder module, whose methods returned only
  comments or `Unknown` values.
- Generated coverage HTML, compiled sample binaries, temporary test copies,
  root debug probes, and obsolete generated development scripts.

## [0.2.0] - 2025-08-17

### Added

- Call-graph and enhanced control-flow analysis, cognitive-complexity and loop
  metrics, Java and WebAssembly parsing, optional disassembly backends, and
  expanded format/property/integration tests.

### Changed

- Expanded the shared binary model and optional feature surface used by
  downstream ThreatFlux tools.

## [0.1.9] - 2025-08-15

### Changed

- Maintenance release with dependency, automation, and test corrections.

## [0.1.8] - 2025-08-15

### Changed

- Maintenance release for the initial multi-format parser line.

## [0.1.7] - 2025-08-15

### Fixed

- Example and Clippy compatibility issues in the initial release series.

[Unreleased]: https://github.com/ThreatFlux/threatflux-binary-analysis/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ThreatFlux/threatflux-binary-analysis/compare/0.2.0...v0.3.0
[0.2.0]: https://github.com/ThreatFlux/threatflux-binary-analysis/compare/0.1.9...0.2.0
[0.1.9]: https://github.com/ThreatFlux/threatflux-binary-analysis/compare/0.1.8...0.1.9
[0.1.8]: https://github.com/ThreatFlux/threatflux-binary-analysis/compare/0.1.7...0.1.8
[0.1.7]: https://github.com/ThreatFlux/threatflux-binary-analysis/releases/tag/0.1.7
