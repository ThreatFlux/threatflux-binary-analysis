# Contributing to ThreatFlux Binary Analysis

Thank you for your interest in contributing to ThreatFlux Binary Analysis! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Code Style and Standards](#code-style-and-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)
- [License](#license)

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for all contributors.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/threatflux-binary-analysis.git
   cd threatflux-binary-analysis
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/threatflux/threatflux-binary-analysis.git
   ```
4. **Keep your fork up to date**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

## Development Setup

### Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)
- Git
- Make (optional but recommended)

### Building the Project

```bash
# Build with default features
cargo build

# Build with all features
cargo build --all-features

# Build in release mode
cargo build --release
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with all features
cargo test --all-features

# Run a specific test
cargo test test_name_here

# Run tests with output
cargo test -- --nocapture
```

### Using Make

The project includes a comprehensive Makefile for common tasks:

```bash
# Run all checks (format, lint, audit, test, etc.)
make all

# Individual commands
make fmt          # Format code
make lint         # Run clippy
make test         # Run tests
make audit        # Security audit
make doc          # Generate documentation
make check-features  # Verify feature combinations
```

## How to Contribute

### Reporting Issues

- **Check existing issues** to avoid duplicates
- **Use issue templates** when available
- **Provide detailed information**:
  - Clear description of the problem
  - Steps to reproduce
  - Expected vs actual behavior
  - System information (OS, Rust version, etc.)
  - Relevant code samples or error messages

### Suggesting Features

- **Open a discussion** first for major features
- **Provide use cases** and examples
- **Consider backwards compatibility**
- **Be open to feedback** and alternative approaches

### Submitting Pull Requests

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Write clean, readable code
   - Follow existing patterns and conventions
   - Add tests for new functionality
   - Update documentation as needed

3. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: Add new feature description"
   ```
   
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `style:` Formatting, missing semicolons, etc.
   - `refactor:` Code restructuring without changing functionality
   - `test:` Adding or modifying tests
   - `chore:` Maintenance tasks

4. **Run checks locally**:
   ```bash
   make all  # Runs all checks
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**:
   - Use a clear, descriptive title
   - Reference any related issues
   - Describe what changes were made and why
   - Include test instructions if applicable

## Development Workflow

### Pre-commit Hook

The project includes a pre-commit hook that runs `make all` automatically. To install it:

```bash
make install-hooks
```

### Feature Flags

The project uses Cargo features for optional functionality:

- `disasm-capstone`: Capstone disassembly engine (default)
- `disasm-iced`: Iced-x86 disassembly engine
- `control-flow`: Control flow analysis
- `visualization`: Graph visualization
- `wasm`: WebAssembly support
- `serde-support`: JSON serialization
- `symbol-resolution`: Symbol demangling
- `compression`: Compressed file support
- `mmap`: Memory-mapped file support

When adding features that depend on external crates, use feature flags appropriately.

### Architecture Support

When adding support for new architectures:

1. Update the `Architecture` enum in `src/types.rs`
2. Add parsing logic in the relevant format parser
3. Add disassembly support if applicable
4. Add comprehensive tests
5. Update documentation

## Code Style and Standards

### Rust Guidelines

- Follow standard Rust naming conventions
- Use `rustfmt` for formatting (run `cargo fmt`)
- Use `clippy` for linting (run `cargo clippy`)
- Write idiomatic Rust code
- Prefer explicit error handling over panics
- Use descriptive variable and function names

### Documentation

- Add doc comments for all public APIs
- Include examples in doc comments when helpful
- Keep comments concise and relevant
- Update README.md for significant changes

### Error Handling

- Use the custom `BinaryError` type for library errors
- Provide meaningful error messages
- Chain errors appropriately with `thiserror`
- Never panic in library code (except for programmer errors)

## Testing Guidelines

### Test Organization

- Unit tests in the same file as the code (`#[cfg(test)]` module)
- Integration tests in `tests/` directory
- Feature-specific tests behind appropriate feature flags

### Test Coverage

- Test both success and failure cases
- Test edge cases and boundary conditions
- Use property-based testing where appropriate (`proptest`)
- Aim for high code coverage but prioritize meaningful tests

### Test Naming

Use descriptive test names that explain what is being tested:

```rust
#[test]
fn test_parse_elf_64bit_header() { ... }

#[test]
fn test_disassemble_x86_instructions() { ... }
```

## Documentation

### Code Documentation

- Document all public APIs
- Include examples for complex functionality
- Explain non-obvious implementation details
- Keep documentation up to date with code changes

### Project Documentation

- Update README.md for user-facing changes
- Update CLAUDE.md for AI assistant guidance
- Maintain accurate feature documentation
- Document breaking changes in CHANGELOG.md

## Security

### Security Guidelines

- Never commit sensitive information (keys, passwords, etc.)
- Validate all inputs, especially when parsing binary data
- Use safe Rust patterns (avoid `unsafe` unless necessary)
- Consider security implications of new features
- Report security vulnerabilities privately

### Binary Analysis Safety

- Handle malformed binaries gracefully
- Implement resource limits for analysis operations
- Validate file sizes and formats before processing
- Use bounded operations to prevent DoS

## License

By contributing to ThreatFlux Binary Analysis, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to:
- Open an issue for questions
- Start a discussion for broader topics
- Reach out to maintainers

Thank you for contributing to ThreatFlux Binary Analysis!