# Pull Request

## Description
<!-- Provide a brief description of the changes -->

## Type of Change
<!-- Mark the relevant option with an "x" -->
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🧪 Test improvement
- [ ] 🔒 Security improvement

## Binary Format Impact
<!-- Mark the relevant formats affected by this change -->
- [ ] ELF (Linux/Unix binaries)
- [ ] PE (Windows executables)
- [ ] Mach-O (macOS binaries)  
- [ ] WebAssembly
- [ ] Java/Archive files
- [ ] Raw binary data
- [ ] Not applicable

## Feature Categories
<!-- Mark the relevant feature areas affected -->
- [ ] Binary parsing
- [ ] Disassembly engines (Capstone/iced-x86)
- [ ] Control flow analysis
- [ ] Security analysis
- [ ] Symbol resolution
- [ ] Entropy analysis
- [ ] API changes
- [ ] Performance
- [ ] Documentation

## Changes Made
<!-- Provide a detailed list of changes -->
- 
- 
- 

## Testing
<!-- Describe the testing you've performed -->
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Performance testing performed (if applicable)
- [ ] Cross-platform testing (specify platforms)

### Test Results
<!-- Include relevant test output or screenshots -->
```
cargo test --all-features
```

## Documentation
- [ ] README updated (if applicable)
- [ ] API documentation updated
- [ ] Examples updated/added (if applicable)
- [ ] CHANGELOG updated

## Performance Impact
<!-- If this change affects performance, describe the impact -->
- [ ] No performance impact expected
- [ ] Performance improvement (describe below)
- [ ] Performance regression possible (describe mitigation)

**Performance details:**
<!-- Benchmark results or performance analysis -->

## Breaking Changes
<!-- List any breaking changes and migration path -->
- None
- 

## Dependencies
<!-- List any new dependencies or dependency changes -->
- [ ] No new dependencies
- [ ] New dependencies added (list below)
- [ ] Existing dependencies updated

**New/Updated Dependencies:**
- 
- 

## Security Considerations
<!-- Address any security implications -->
- [ ] No security implications
- [ ] Security improvement (describe below)
- [ ] Potential security considerations (describe below)

## Checklist
<!-- Ensure all items are checked before submitting -->
- [ ] Code follows the project's style guidelines
- [ ] Self-review of code has been performed
- [ ] Code is properly documented
- [ ] Tests pass locally with my changes
- [ ] Any dependent changes have been merged and published
- [ ] Cargo clippy passes without warnings
- [ ] Cargo fmt has been run
- [ ] No unsafe code added without proper documentation
- [ ] All features work with `--no-default-features`
- [ ] All features work with `--all-features`

## Examples
<!-- If adding new functionality, provide usage examples -->
```rust
// Example usage of new functionality
```

## Additional Notes
<!-- Any additional information, screenshots, or context -->

## Related Issues
<!-- Link related issues -->
- Fixes #
- Closes #
- Related to #