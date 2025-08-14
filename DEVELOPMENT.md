# ThreatFlux Development Guide

This document explains how to set up your development environment to run the same quality checks locally that are performed in CI/CD.

## Quick Setup

1. **Run the setup script:**
   ```bash
   ./setup-dev-tools.sh
   ```

2. **That's it!** The script will install all necessary tools and set up pre-commit hooks.

## What Gets Installed

### Rust Components
- **rustfmt** - Code formatting
- **clippy** - Rust linter with security-focused rules

### Cargo Tools
- **cargo-audit** - Security vulnerability scanning
- **cargo-deny** - License and dependency policy enforcement
- **cargo-semver-checks** - Semantic versioning validation (optional)
- **cargo-outdated** - Dependency update checking (optional)

### System Dependencies
- **libcapstone** - Disassembly engine (needed for binary-analysis)
- **pkg-config** - Build system helper

## Pre-commit Hooks

The setup script installs a comprehensive pre-commit hook that runs:

### 1. Code Quality Checks
- ✅ **Format Check** - `cargo fmt --check`
- ✅ **Linting** - `cargo clippy` with security-focused rules
- ✅ **Build Test** - `cargo build --all-features`
- ✅ **Unit Tests** - `cargo test --all-features`
- ✅ **Documentation** - `cargo doc --all-features`

### 2. Security Checks
- ✅ **Vulnerability Scan** - `cargo audit`
- ✅ **Dependency Policy** - `cargo deny check`
- ✅ **Secret Detection** - Basic pattern matching for secrets
- ✅ **TODO/FIXME Check** - Prevents uncommitted TODO comments

### 3. Repository Health
- ✅ **Large File Detection** - Prevents committing files >10MB
- ✅ **License Validation** - Ensures all dependencies use approved licenses

## Manual Commands

You can run these checks manually at any time:

```bash
# Format your code
cargo fmt

# Run security-focused linting
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test --all-features

# Check for security vulnerabilities
cargo audit

# Validate dependencies and licenses
cargo deny check

# Build with all features
cargo build --all-features

# Generate documentation
cargo doc --all-features --no-deps
```

## Bypassing Pre-commit Hooks

In rare cases, you may need to bypass the pre-commit hooks:

```bash
# Skip pre-commit hooks for a single commit
git commit --no-verify -m "emergency fix"

# Temporarily disable pre-commit hook
chmod -x .git/hooks/pre-commit

# Re-enable pre-commit hook
chmod +x .git/hooks/pre-commit
```

## Repository-Specific Notes

### Binary Analysis Repository
Requires system dependencies for disassembly:
- **macOS**: `brew install capstone pkg-config`
- **Ubuntu/Debian**: `sudo apt-get install libcapstone-dev pkg-config`
- **CentOS/RHEL**: `sudo yum install capstone-devel pkg-config`

### Package Security Repositories
May require additional network access for vulnerability database updates.

## Troubleshooting

### "command not found: cargo-audit"
```bash
cargo install cargo-audit
```

### "command not found: cargo-deny"
```bash
cargo install cargo-deny
```

### "libcapstone not found" (Binary Analysis)
**macOS:**
```bash
brew install capstone
```

**Linux:**
```bash
sudo apt-get install libcapstone-dev pkg-config
```

### Pre-commit Hook Not Running
Check that the hook is executable:
```bash
ls -la .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Slow Pre-commit Checks
The first run may be slow due to dependency compilation. Subsequent runs use cached builds and are much faster.

You can also run individual checks:
```bash
# Just format and lint (fastest)
cargo fmt --check && cargo clippy

# Skip tests in pre-commit by editing .git/hooks/pre-commit
# Comment out the test section if needed for rapid iteration
```

## CI/CD Parity

The pre-commit hooks are designed to run the same checks as CI/CD:

| Check | Local Command | CI/CD Workflow |
|-------|---------------|----------------|
| Format | `cargo fmt --check` | `cargo fmt --all -- --check` |
| Lint | `cargo clippy` | Security-focused clippy rules |
| Test | `cargo test` | `cargo test --all-features` |
| Audit | `cargo audit` | Security audit workflow |
| Deny | `cargo deny check` | Dependency validation |
| Build | `cargo build` | Multi-target builds |

## Updating Tools

Keep your tools up to date:

```bash
# Update Rust toolchain
rustup update

# Update cargo tools
cargo install cargo-audit --force
cargo install cargo-deny --force
cargo install cargo-semver-checks --force --locked
cargo install cargo-outdated --force

# Update advisory database
cargo audit --update
```

## Configuration Files

### `.clippy.toml` (if present)
Repository-specific clippy configuration.

### `deny.toml`
Dependency and license policy configuration. See individual repositories for specific policies.

### `.rustfmt.toml` (if present)
Code formatting configuration.

## Getting Help

- **Pre-commit issues**: Check this guide and repository issues
- **Rust toolchain**: https://rustup.rs/
- **Cargo tools**: Individual tool documentation
- **CI/CD workflows**: See `.github/workflows/` in each repository

## Contributing

When contributing:

1. ✅ Ensure all pre-commit checks pass
2. ✅ Add tests for new functionality  
3. ✅ Update documentation as needed
4. ✅ Follow existing code style and patterns
5. ✅ Keep commits focused and atomic

The pre-commit hooks help ensure code quality and consistency across all ThreatFlux repositories.