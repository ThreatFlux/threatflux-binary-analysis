# Contributing

Thank you for helping improve ThreatFlux Binary Analysis. Focused bug fixes,
format-boundary tests, documentation corrections, and carefully scoped parser
or analysis improvements are welcome.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Suspected vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.

## Before you start

- Search existing issues and pull requests for related work.
- Open an issue before a large API, dependency, format, or architecture change
  so the scope and compatibility impact can be discussed.
- Do not attach a confidential, proprietary, or live-malware sample to a public
  issue. Prefer a minimal synthetic reproducer.
- Read [API.md](API.md) and
  [Analysis boundaries](docs/ANALYSIS_BOUNDARIES.md). Capability claims in a
  change must match the implementation.
- For changes relative to the published 0.2.x line, read
  [Migrating to 0.3](docs/MIGRATING_TO_0.3.md).

## Development setup

The crate requires Rust 1.95.0 or newer. Clone your fork and create a focused
branch:

```console
git clone https://github.com/YOUR-ACCOUNT/threatflux-binary-analysis.git
cd threatflux-binary-analysis
git remote add upstream https://github.com/ThreatFlux/threatflux-binary-analysis.git
git switch -c fix/short-description
```

Install rustfmt and Clippy:

```console
rustup component add rustfmt clippy
```

The all-features build may need Capstone development files and
<code>pkg-config</code>. See [DEVELOPMENT.md](DEVELOPMENT.md) for platform
prerequisites and optional tooling.

## Make a change

Keep each pull request narrow and reviewable:

1. Reproduce the problem with a test where practical.
2. Implement the smallest coherent change.
3. Add valid, malformed, boundary, and feature-gating coverage appropriate to
   the code.
4. Update rustdoc and Markdown in the same change.
5. Run the validation matrix.
6. Review the final diff for unrelated formatting, generated files, binary
   artifacts, credentials, and sample provenance.

Avoid drive-by dependency updates or broad refactors in a bug-fix pull request.
Call out any public API or output change explicitly.

## Validation

Run the supported checks individually while iterating:

```console
make check
make test
make security
make feature-check
```

Before opening the pull request, run the complete contract:

```console
make ci
```

If you cannot run a check, state which one and why in the pull request. Do not
describe unrun checks as passing.

For a single optional feature:

```console
cargo test --locked --no-default-features --features wasm
cargo test --locked --no-default-features --features disasm-iced
cargo test --locked --no-default-features --features control-flow
```

The <code>control-flow</code> feature implies Capstone. See
[TESTING.md](TESTING.md) for the full matrix.

## Parser contributions

A parser change should define both support and limits:

- accepted magic/container variants;
- architecture and endianness mapping;
- offset/size/count validation;
- behavior for truncated and internally inconsistent data;
- which sections, symbols, imports, exports, entry points, and hardening fields
  are actually populated;
- behavior when the Cargo feature is disabled.

Use checked arithmetic before constructing ranges. Never execute a fixture.
Where a binary fixture is unavoidable, document how it was generated, its
license/provenance, architecture, size, and cryptographic hash.

Do not label a format fully supported when only a subset is decoded. For
example, current Java class parsing validates the fixed header and version but
does not expose the version or decode the constant pool, members, attributes,
or bytecode.

## Disassembly and analysis contributions

State whether a change operates on:

- caller-supplied bytes;
- checked file-backed ranges in <code>BinaryFile</code>'s full owned bytes;
- the preview-only <code>Section::data</code> field;
- parsed symbols or entry-point fallbacks;
- heuristic string/name/import rules.

Tests should cover invalid/non-file-backed section ranges, stripped binaries,
unsupported architectures, instruction limits, and partial analysis. Graph and heuristic
outputs must be described as best effort unless completeness is demonstrably
established.

For security rules, include benign counterexamples and document expected false
positives/negatives. The project score is not CVSS or a malware probability.

## Rust and API style

- Use the crate's <code>Result</code> and specific <code>BinaryError</code>
  variants at public boundaries.
- Keep optional dependencies behind their Cargo feature.
- Avoid panics for ordinary invalid input; return a typed error.
- Document errors and any panic conditions on public APIs.
- Prefer checked conversions and checked/saturating arithmetic where loss or
  overflow is possible.
- Keep public names and result semantics consistent across format parsers.
- Add unsafe code only when a safe implementation is impractical, and document
  the invariant immediately next to the unsafe block.

Formatting is owned by rustfmt. Clippy warnings are denied in CI.

## Documentation style

- Use current public type and method names.
- Put the required feature beside every feature-gated example.
- Distinguish compile-time Cargo features from runtime configuration.
- Put limitations next to the corresponding capability.
- Avoid performance, safety, coverage, or format-completeness claims without
  reproducible evidence.
- Keep examples synchronous unless the application itself supplies an async
  wrapper.

## Pull request description

Include:

- the problem and user-visible impact;
- the chosen approach and alternatives that materially affected it;
- tests added or changed;
- exact validation commands and results;
- feature combinations exercised;
- API, compatibility, performance, or security implications;
- fixture provenance, if applicable;
- follow-up work deliberately left out of scope.

Respond to review with additional commits while discussion is active. Maintainers
may squash commits when merging.

## Reporting issues

A useful public bug report contains the crate version, Rust version, OS/target,
enabled features, expected behavior, actual error/result, and a minimal
non-sensitive reproducer. Remove paths, symbols, strings, and metadata that
identify people or proprietary software.

For private security reports, use the process in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the
repository's [MIT License](LICENSE).
