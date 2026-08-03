# Manual Test Samples

These files are small, synthetic inputs for manually exploring file-inspection
tools. They are not consumed by the automated Rust test suite and they do not
establish parser correctness, security coverage, or malware-detection quality.

## Safety

Read the source before executing anything in this directory.

- <code>test_program.c</code> intentionally contains an unsafe
  <code>strcpy</code> path and a call to <code>system</code>. Any locally built
  executable must not be run with untrusted arguments.
- <code>test_script.sh</code> writes a log under <code>/tmp</code> and creates
  configuration under <code>$HOME/.threatflux</code>. Its network-looking
  commands are printed simulations, but the filesystem side effects are real.
- <code>analysis_script.py</code> reads a supplied file and prints synthetic
  suspicious-looking strings. In no-argument mode it prints simulated network
  and command activity.
- None of these files is live malware. Their suspicious strings are deliberately
  inert fixtures.

Static analysis does not require executing a sample. Prefer inspecting bytes
with the Rust examples:

```console
cargo run --example security_analysis -- test_samples/test_binary.bin
```

## Inventory

| File                            | Purpose                                                                                                                        |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| <code>test_program.c</code>     | C source with functions, strings, recursion, globals, and an intentionally unsafe path; compile locally only when needed       |
| <code>create_binary.py</code>   | Deterministically creates <code>test_binary.bin</code>                                                                         |
| <code>test_binary.bin</code>    | Synthetic MZ-prefixed bytes containing additional magic values, API names, URLs, repeated data, and seeded pseudo-random bytes |
| <code>analysis_script.py</code> | Standalone Python demonstration data, not part of the Rust library                                                             |
| <code>test_script.sh</code>     | Standalone shell demonstration data with documented side effects                                                               |
| <code>mixed_content.txt</code>  | Text fixture containing mixed source/configuration-like content                                                                |

<code>test_binary.bin</code> is not a valid PE image: it lacks a checked PE
header/signature and is expected to parse through the raw fallback. It remains
useful for direct pattern matching.

The current checked-in generated fixture hash is:

```text
e161935990a8a24283f5b17b007b38364c6b84fef0c8cf5a472e913318535666  test_binary.bin
```

Recalculate them after an intentional regeneration:

```console
sha256sum test_samples/test_binary.bin
```

## Regeneration

Regenerate the deterministic byte-pattern fixture from the repository root:

```console
(cd test_samples && python3 create_binary.py)
```

The C executable is platform and toolchain dependent, generated locally, and
ignored by Git. Build it only in an isolated development environment when a
manual executable is needed:

```console
cc -O0 -g -o test_samples/test_program test_samples/test_program.c
file test_samples/test_program
sha256sum test_samples/test_program
```

Generated executables do not belong in the repository.

## Adding a sample

Prefer generated in-memory fixtures in <code>tests/</code>. Add a manual binary
only when it covers a case that cannot be expressed clearly in code, and include:

- source or a deterministic generator;
- license/provenance;
- architecture and file type;
- exact generation command/toolchain;
- size and SHA-256;
- the test or manual procedure that needs it.

Never commit credentials, private data, proprietary files, or live malware.
