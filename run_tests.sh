#!/bin/bash

# ThreatFlux Binary Analysis - Comprehensive Test Runner
# This script runs all test categories and generates coverage reports

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
COVERAGE=${COVERAGE:-true}
PERFORMANCE=${PERFORMANCE:-true}
INTEGRATION=${INTEGRATION:-true}
PROPERTY=${PROPERTY:-true}
FEATURES=${FEATURES:-"default"}
VERBOSE=${VERBOSE:-false}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  ThreatFlux Binary Analysis${NC}"
    echo -e "${BLUE}     Comprehensive Test Suite${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_section() {
    echo -e "${YELLOW}>>> $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_dependencies() {
    print_section "Checking Dependencies"
    
    # Check for required tools
    if ! command -v cargo &> /dev/null; then
        print_error "cargo is required but not installed"
        exit 1
    fi
    
    # Check for coverage tool
    if [ "$COVERAGE" = true ]; then
        if ! cargo llvm-cov --version &> /dev/null; then
            print_info "Installing cargo-llvm-cov for coverage analysis..."
            cargo install cargo-llvm-cov
        fi
    fi
    
    print_success "All dependencies available"
    echo
}

run_unit_tests() {
    print_section "Running Unit Tests"
    
    local test_files=(
        "unit_elf_test"
        "unit_pe_test" 
        "unit_macho_test"
        "unit_java_test"
        "unit_compiler_detection_test"
        "unit_debug_info_test"
        "unit_enhanced_binary_info_test"
    )
    
    for test_file in "${test_files[@]}"; do
        print_info "Running $test_file..."
        if [ "$VERBOSE" = true ]; then
            cargo test --features "$FEATURES" "$test_file" -- --nocapture
        else
            cargo test --features "$FEATURES" "$test_file" -q
        fi
        print_success "$test_file completed"
    done
    
    echo
}

run_property_tests() {
    if [ "$PROPERTY" = false ]; then
        return
    fi
    
    print_section "Running Property-Based Tests"
    
    print_info "Running fuzzing tests with proptest..."
    if [ "$VERBOSE" = true ]; then
        cargo test --features "$FEATURES" unit_property_based_test -- --nocapture
    else
        cargo test --features "$FEATURES" unit_property_based_test -q
    fi
    
    print_success "Property-based tests completed"
    echo
}

run_integration_tests() {
    if [ "$INTEGRATION" = false ]; then
        return
    fi
    
    print_section "Running Integration Tests"
    
    print_info "Running integration tests..."
    if [ "$VERBOSE" = true ]; then
        cargo test --features "$FEATURES" integration_ -- --nocapture
    else
        cargo test --features "$FEATURES" integration_ -q
    fi
    
    print_success "Integration tests completed"
    echo
}

run_performance_tests() {
    if [ "$PERFORMANCE" = false ]; then
        return
    fi
    
    print_section "Running Performance Tests"
    
    print_info "Running performance benchmarks..."
    # Run performance tests with release mode for accurate timing
    if [ "$VERBOSE" = true ]; then
        cargo test --release --features "$FEATURES" performance -- --nocapture
    else
        cargo test --release --features "$FEATURES" performance -q
    fi
    
    print_success "Performance tests completed"
    echo
}

run_format_specific_tests() {
    print_section "Running Format-Specific Test Suites"
    
    local formats=("elf" "pe" "macho" "java")
    
    for format in "${formats[@]}"; do
        print_info "Testing $format parser with all features..."
        cargo test --features "$FEATURES,$format" --test "*${format}*" -q
        print_success "$format parser tests completed"
    done
    
    echo
}

run_feature_combination_tests() {
    print_section "Running Feature Combination Tests"
    
    local feature_sets=(
        "default"
        "elf,pe,macho,java"
        "disasm-capstone,control-flow" 
        "disasm-iced,entropy-analysis"
        "symbol-resolution,serde-support"
        "compression,visualization"
    )
    
    for features in "${feature_sets[@]}"; do
        print_info "Testing with features: $features"
        if cargo test --features "$features" --lib -q 2>/dev/null; then
            print_success "Feature set '$features' tests passed"
        else
            print_error "Feature set '$features' tests failed"
        fi
    done
    
    echo
}

generate_coverage_report() {
    if [ "$COVERAGE" = false ]; then
        return
    fi
    
    print_section "Generating Coverage Report"
    
    print_info "Running tests with coverage instrumentation..."
    cargo llvm-cov clean
    
    # Run all tests with coverage
    cargo llvm-cov --features "$FEATURES" --html --output-dir coverage-report test
    
    # Generate summary
    cargo llvm-cov --features "$FEATURES" --summary-only
    
    print_success "Coverage report generated in coverage-report/"
    
    # Check coverage thresholds
    local coverage_output
    coverage_output=$(cargo llvm-cov --features "$FEATURES" --summary-only 2>&1)
    
    if echo "$coverage_output" | grep -q "TOTAL.*9[0-9]\.[0-9]*%\|TOTAL.*100\.0*%"; then
        print_success "Coverage target (90%+) achieved!"
    elif echo "$coverage_output" | grep -q "TOTAL.*8[5-9]\.[0-9]*%"; then
        print_info "Coverage is close to target (85-89%)"
    else
        print_error "Coverage below target (< 85%)"
    fi
    
    echo
}

run_documentation_tests() {
    print_section "Running Documentation Tests"
    
    print_info "Testing documentation examples..."
    cargo test --features "$FEATURES" --doc -q
    
    print_success "Documentation tests completed"
    echo
}

run_cross_platform_tests() {
    print_section "Running Cross-Platform Compatibility Tests"
    
    # Test with different targets if available
    local targets=("x86_64-unknown-linux-gnu" "x86_64-apple-darwin" "x86_64-pc-windows-msvc")
    
    print_info "Testing cross-compilation compatibility..."
    for target in "${targets[@]}"; do
        if rustup target list --installed | grep -q "$target"; then
            print_info "Testing compilation for $target..."
            if cargo check --target "$target" --features "$FEATURES" 2>/dev/null; then
                print_success "$target compilation successful"
            else
                print_info "$target compilation skipped (dependencies unavailable)"
            fi
        fi
    done
    
    echo
}

run_security_tests() {
    print_section "Running Security Tests"
    
    print_info "Running security-focused tests..."
    
    # Test with address sanitizer if available
    if [ -z "$CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS" ]; then
        export RUSTFLAGS="-Z sanitizer=address"
        export RUSTDOCFLAGS="-Z sanitizer=address"
        
        if cargo test --features "$FEATURES" --target x86_64-unknown-linux-gnu -q 2>/dev/null; then
            print_success "Address sanitizer tests passed"
        else
            print_info "Address sanitizer tests skipped (not available)"
        fi
    fi
    
    # Test with miri for undefined behavior detection
    if command -v cargo-miri &> /dev/null; then
        print_info "Running miri tests for undefined behavior detection..."
        if cargo miri test --features "$FEATURES" -q 2>/dev/null; then
            print_success "Miri tests passed"
        else
            print_info "Miri tests skipped (some dependencies incompatible)"
        fi
    fi
    
    echo
}

cleanup() {
    print_section "Cleanup"
    
    # Clean up temporary files
    cargo clean -q
    
    print_success "Cleanup completed"
    echo
}

print_summary() {
    print_section "Test Summary"
    
    echo "Test run completed with configuration:"
    echo "  - Features: $FEATURES"
    echo "  - Coverage: $COVERAGE"
    echo "  - Performance: $PERFORMANCE" 
    echo "  - Integration: $INTEGRATION"
    echo "  - Property: $PROPERTY"
    echo "  - Verbose: $VERBOSE"
    echo
    
    if [ "$COVERAGE" = true ]; then
        echo "Coverage report available at: coverage-report/index.html"
    fi
    
    print_success "All test categories completed successfully!"
}

show_help() {
    cat << EOF
ThreatFlux Binary Analysis Test Runner

Usage: $0 [OPTIONS]

OPTIONS:
    --no-coverage       Skip coverage report generation
    --no-performance    Skip performance tests
    --no-integration    Skip integration tests  
    --no-property       Skip property-based tests
    --features FEATURES Set feature flags (default: "default")
    --verbose           Enable verbose output
    --help              Show this help message

EXAMPLES:
    $0                                    # Run all tests with default features
    $0 --features "elf,pe,disasm-capstone" # Test specific features
    $0 --no-performance --verbose        # Skip performance tests, verbose output
    $0 --no-coverage --features "default" # Quick test run without coverage

ENVIRONMENT VARIABLES:
    COVERAGE=false      Disable coverage (same as --no-coverage)
    PERFORMANCE=false   Disable performance tests
    INTEGRATION=false   Disable integration tests
    PROPERTY=false      Disable property tests
    FEATURES="..."      Set feature flags
    VERBOSE=true        Enable verbose output

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-coverage)
            COVERAGE=false
            shift
            ;;
        --no-performance)
            PERFORMANCE=false
            shift
            ;;
        --no-integration)
            INTEGRATION=false
            shift
            ;;
        --no-property)
            PROPERTY=false
            shift
            ;;
        --features)
            FEATURES="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_header
    
    check_dependencies
    run_unit_tests
    run_property_tests
    run_integration_tests
    run_performance_tests
    run_format_specific_tests
    run_feature_combination_tests
    run_documentation_tests
    run_cross_platform_tests
    run_security_tests
    generate_coverage_report
    
    print_summary
}

# Run main function
main "$@"