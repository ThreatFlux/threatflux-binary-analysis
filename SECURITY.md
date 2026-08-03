# Security Policy

ThreatFlux Binary Analysis processes attacker-controlled file structures and
instruction bytes. Security defects in parsing, resource enforcement,
disassembly, or unsafe invariants are in scope for private reporting.

## Supported versions

| Line            | Status                                       |
| --------------- | -------------------------------------------- |
| 0.3.x           | Upcoming development line; not yet published |
| 0.2.x           | Current published line                       |
| 0.1.x and older | No longer supported                          |

Security fixes normally target the active development line and, where
practical, the current published line. An advisory will identify the exact
affected and fixed versions.

## Report a vulnerability privately

Preferred: open a
[private GitHub security advisory](https://github.com/ThreatFlux/threatflux-binary-analysis/security/advisories/new).

If GitHub private reporting is unavailable, email
<security@threatflux.ai>. Use a subject that identifies this repository and do
not send a live-malware sample until a maintainer confirms a safe transfer
method.

Do not:

- open a public issue or pull request for an undisclosed vulnerability;
- post exploit details, crash artifacts, or sensitive samples publicly;
- test against systems or data you do not own or have permission to assess.

Include, when available:

- affected crate version/commit and enabled Cargo features;
- Rust version, target triple, operating system, and relevant system libraries;
- affected API and expected versus observed behavior;
- a minimal synthetic reproducer or crash input;
- impact, preconditions, and whether the issue is reliably reproducible;
- sanitizer, backtrace, fuzzing, or resource measurements;
- any disclosure deadline or coordination constraints.

We will acknowledge the report as soon as practical, validate it, coordinate a
fix and disclosure with the reporter, and credit the reporter if requested.
Response and release timing depends on impact, reproducibility, and release
coordination; this policy does not promise a fixed service-level deadline.

## Security findings versus library vulnerabilities

<code>analysis::security::SecurityAnalyzer</code> reports heuristic traits of
the file being inspected. False positives and false negatives are expected. Its
score is not CVSS, a malware probability, or proof of exploitability.

A security vulnerability in this crate is different: examples include
memory-safety invariant violations, attacker-controlled panics, resource-limit
bypasses, path/file races in crate-owned behavior, or materially incorrect
security guarantees.

## Untrusted-input model

The crate is a static-analysis library, not a sandbox.

- APIs are synchronous and have no built-in wall-time cancellation.
- <code>BinaryFile::parse</code> copies the full input and does not apply an
  input-size policy on its own.
- <code>BinaryAnalyzer</code> enforces
  <code>AnalysisConfig::max_analysis_size</code> and returns
  <code>BinaryError::InputTooLarge</code> when the input exceeds it.
- Calling <code>analyze_binary</code> enforces the same limit, but a
  pre-existing <code>BinaryFile</code> has already been parsed and copied.
- Format parsers reject more than 100,000 structural/output records, names over
  4 KiB, or more than 32 MiB of aggregate copied names per parse. JAR metadata
  has a separate 50,000-entry ceiling.
- Unknown non-empty input is accepted as <code>Raw</code>.
- Optional graph and heuristic stages can perform attacker-influenced work.
- Archive/compression handling and memory mapping have additional constraints.
- Memory-map construction is unsafe because callers must keep the backing file
  stable for the mapping lifetime.

The high-level size limit is an important guard, but it is not a complete CPU,
memory, allocation-count, recursion, archive-entry, or wall-time budget.

## Recommended deployment controls

For hostile or multi-tenant samples:

1. Enforce an upload/read limit before allocating the complete input.
2. Set <code>AnalysisConfig::max_analysis_size</code> to the same or a lower
   application limit.
3. Set <code>AnalysisConfig::max_disassembly_instructions</code> to the maximum
   result size your application can retain.
4. Allowlist expected parsed formats and reject <code>Raw</code> unless it is
   intentional.
5. Run analysis in a disposable, low-privilege process with no network access,
   a read-only filesystem, and OS-enforced CPU, memory, process, file, and wall
   time limits.
6. Disable parser and analysis features you do not need.
7. Treat crashes, timeouts, and limit violations as analysis failures, not as a
   property of the sample.
8. Keep samples, error text, symbols, paths, and generated reports out of
   client-visible responses and ordinary logs unless they are explicitly
   sanitized.

Example application-side limit:

```rust
use std::{fs, io, path::Path};
use threatflux_binary_analysis::{AnalysisConfig, BinaryAnalyzer, AnalysisResult};

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

fn analyze_path(path: &Path) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "input too large").into());
    }

    let bytes = fs::read(path)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "input too large").into());
    }

    let config = AnalysisConfig {
        max_analysis_size: MAX_INPUT_BYTES as usize,
        max_disassembly_instructions: 10_000,
        ..Default::default()
    };
    Ok(BinaryAnalyzer::with_config(config).analyze(&bytes)?)
}
```

This reduces oversized-input risk but does not replace worker isolation.

When invoking the low-level graph analyzers directly, set their
<code>max_functions</code> and <code>max_total_instructions</code> fields to an
application budget. <code>control_flow::AnalysisConfig::max_instructions</code>
also rejects oversized per-function instruction results. When advanced loop
analysis is enabled, set <code>max_loops</code> and
<code>max_total_loop_body_blocks</code> as well. The graph defaults are 10,000
functions, 1,000,000 total instructions, 10,000 retained loops, and 1,000,000
aggregate loop-body memberships; they are safeguards, not a complete CPU or
process-memory limit.

## Memory maps

<code>MappedBinary</code> and <code>AdvancedMmap</code> use read-only memory
maps internally. Keep the mapped file immutable and prevent an untrusted party
from replacing, truncating, or mutating it while the mapping exists.

Passing a mapped slice to <code>BinaryFile::parse</code> still creates an owned
copy. <code>AdvancedMmap</code> rejects file-backed huge pages; populate is
Linux/Android-only and memory locking is Unix-only. Unsupported requests return
configuration errors, and an allowed memory-lock request can still fail under
OS policy.

## Archives and compression

Java archive detection opens ZIP metadata, iterates entries, and rejects
archives with more than 50,000 entries. Apply the tighter limits required by
your application even though class bodies are not decoded.

For gzip/zlib data, <code>decompress</code> has a 64 MiB expanded-output limit;
prefer <code>decompress_with_limit</code> when the application needs a smaller
budget. Also validate the returned length. Do not rely on compressed input size
as a bound on expanded output.

## Format and heuristic limitations

- Parsing does not verify Authenticode, Mach-O code signatures, or JAR
  signatures.
- Hardening flags are parser-derived observations and may be incomplete.
- Thin Mach-O is supported; fat/universal Mach-O is not.
- Java class parsing does not decode methods, constant pools, or bytecode.
- WebAssembly parsing does not provide instruction semantics.
- Disassembly and graph results can be partial because of function discovery,
  checked file-range failures, unsupported instructions, and analysis budgets.
- Security rules rely primarily on exact imports, selected names, section
  permissions, and hardening metadata.

Absence of an error or finding is not evidence that a sample is safe.

## Dependency and supply-chain checks

The repository uses Cargo feature gates to reduce optional attack surface.
Useful local checks include:

```console
cargo audit
cargo deny check
cargo tree --all-features
```

Pin and review dependencies according to your own threat model, monitor RustSec
advisories, and rebuild promptly after a relevant parser or disassembler
advisory.

## Disclosure and releases

We aim to coordinate disclosure after a fix is available. Significant issues
may receive a GitHub advisory and CVE where appropriate. Release notes and the
advisory will identify affected configurations, mitigations, and fixed
versions.
