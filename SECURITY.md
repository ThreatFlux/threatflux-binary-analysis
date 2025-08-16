# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take the security of ThreatFlux Binary Analysis seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT:
- Open a public GitHub issue for security vulnerabilities
- Post about the vulnerability on social media or forums
- Exploit the vulnerability for malicious purposes

### Please DO:
- Email us at: security@threatflux.io (if available) or open a private security advisory on GitHub
- Provide detailed steps to reproduce the vulnerability
- Include the impact and potential exploit scenarios
- Allow reasonable time for us to address the issue before public disclosure

## What to Include in Your Report

To help us better understand and resolve the issue, please include:

1. **Type of vulnerability** (e.g., buffer overflow, arbitrary code execution, privilege escalation)
2. **Component affected** (module, function, file)
3. **Steps to reproduce** with sample code or files if possible
4. **Impact assessment** - what can an attacker achieve?
5. **Environment details**:
   - Operating System and version
   - Rust version
   - Library version
   - Feature flags enabled
6. **Proof of concept** code (if available)

## Response Timeline

- **Initial Response**: Within 48 hours, we will acknowledge receipt of your report
- **Assessment**: Within 7 days, we will assess the vulnerability and provide an initial severity rating
- **Fix Timeline**: Depending on severity:
  - Critical: Fix within 7-14 days
  - High: Fix within 30 days
  - Medium: Fix within 60 days
  - Low: Fix in the next regular release

## Security Considerations for Binary Analysis

### Input Validation

The library handles potentially malicious binary files. Key security measures include:

- **Size limits**: Configurable maximum file sizes to prevent resource exhaustion
- **Parsing boundaries**: Strict boundary checking when parsing binary formats
- **Memory safety**: Leveraging Rust's memory safety guarantees
- **Resource limits**: Configurable limits for analysis operations

### Safe Defaults

- Analysis operations have reasonable default limits
- Memory-mapped file access is opt-in via feature flag
- Decompression has size limits to prevent zip bombs
- Recursive operations have depth limits

### Known Security Considerations

1. **Malformed binaries**: The library is designed to handle malformed inputs gracefully without panicking
2. **Resource consumption**: Large or specially crafted files may consume significant resources
3. **Decompression bombs**: ZIP/compression support includes safeguards against decompression bombs
4. **Path traversal**: File operations validate paths to prevent directory traversal attacks

## Security Best Practices for Users

When using this library in production:

### 1. Resource Limits
```rust
use threatflux_binary_analysis::AnalysisConfig;

let config = AnalysisConfig {
    max_analysis_size: 100 * 1024 * 1024, // 100MB limit
    enable_control_flow: false, // Disable expensive operations if not needed
    ..Default::default()
};
```

### 2. Sandboxing
Consider running analysis in a sandboxed environment:
- Use containers or VMs for untrusted binaries
- Apply OS-level resource limits (ulimit, cgroups)
- Run with minimal privileges

### 3. Input Validation
Always validate inputs before analysis:
```rust
// Check file size before analysis
let metadata = std::fs::metadata(&path)?;
if metadata.len() > MAX_FILE_SIZE {
    return Err("File too large");
}

// Verify file type if expecting specific formats
let data = std::fs::read(&path)?;
let format = threatflux_binary_analysis::detect_format(&data)?;
if !allowed_formats.contains(&format) {
    return Err("Unsupported format");
}
```

### 4. Error Handling
Never expose detailed error messages to untrusted users:
```rust
match analyzer.analyze(&data) {
    Ok(result) => process_result(result),
    Err(e) => {
        // Log detailed error internally
        log::error!("Analysis failed: {:?}", e);
        // Return generic error to user
        return Err("Analysis failed");
    }
}
```

## Security Features

### Built-in Protections

- **Memory safety**: Rust's ownership system prevents common vulnerabilities
- **Bounds checking**: All array/buffer accesses are bounds-checked
- **Integer overflow protection**: Debug builds panic on overflow, release builds wrap
- **No unsafe code in core paths**: Unsafe code is minimized and well-audited
- **Dependency auditing**: Regular audits using `cargo audit`

### Feature Flags for Security

Certain features can be disabled to reduce attack surface:

```toml
[dependencies]
threatflux-binary-analysis = { 
    version = "0.1", 
    default-features = false,
    features = ["elf", "pe"]  # Only enable needed formats
}
```

## Vulnerability Disclosure

We follow responsible disclosure practices:

1. Security vulnerabilities are embargoed until a fix is available
2. We will coordinate disclosure with reporters
3. Credit will be given to reporters (unless they prefer to remain anonymous)
4. CVEs will be requested for significant vulnerabilities

## Security Updates

Stay informed about security updates:

- Watch the GitHub repository for security advisories
- Monitor the CHANGELOG for security-related updates
- Consider using tools like `cargo audit` in your CI/CD pipeline

## Contact

For security concerns, please contact:
- GitHub Security Advisory (preferred): [Create private advisory](https://github.com/threatflux/threatflux-binary-analysis/security/advisories/new)
- Email: security@threatflux.io (if available)

## Acknowledgments

We thank the security researchers and users who responsibly disclose vulnerabilities and help improve the security of this project.

## References

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)