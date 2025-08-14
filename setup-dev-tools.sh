#!/bin/bash
#
# Development Tools Setup Script for ThreatFlux repositories
# This script installs all the tools needed for local CI/CD checks
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Rust is installed
check_rust() {
    print_status "Checking Rust installation..."
    if ! command_exists cargo; then
        print_error "Rust/Cargo not found. Please install Rust first:"
        print_error "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    
    local rust_version=$(rustc --version)
    print_success "Found Rust: $rust_version"
}

# Install Rust components
install_rust_components() {
    print_status "Installing Rust components..."
    
    if ! command_exists cargo-fmt; then
        print_status "Installing rustfmt..."
        rustup component add rustfmt
        print_success "rustfmt installed"
    else
        print_success "rustfmt already installed"
    fi
    
    if ! command_exists cargo-clippy; then
        print_status "Installing clippy..."
        rustup component add clippy
        print_success "clippy installed"
    else
        print_success "clippy already installed"
    fi
}

# Install cargo tools
install_cargo_tools() {
    print_status "Installing cargo security tools..."
    
    if ! command_exists cargo-audit; then
        print_status "Installing cargo-audit..."
        cargo install cargo-audit
        print_success "cargo-audit installed"
    else
        print_success "cargo-audit already installed"
    fi
    
    if ! command_exists cargo-deny; then
        print_status "Installing cargo-deny..."
        cargo install cargo-deny
        print_success "cargo-deny installed"
    else
        print_success "cargo-deny already installed"
    fi
    
    if ! command_exists cargo-outdated; then
        print_status "Installing cargo-outdated (optional)..."
        cargo install cargo-outdated
        print_success "cargo-outdated installed"
    else
        print_success "cargo-outdated already installed"
    fi
    
    if ! command_exists cargo-semver-checks; then
        print_status "Installing cargo-semver-checks (optional)..."
        cargo install cargo-semver-checks --locked
        print_success "cargo-semver-checks installed"
    else
        print_success "cargo-semver-checks already installed"
    fi
}

# Install system dependencies
install_system_deps() {
    print_status "Checking system dependencies..."
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command_exists brew; then
            # Check for libcapstone (needed for binary-analysis)
            if ! brew list capstone &>/dev/null; then
                print_status "Installing capstone via Homebrew..."
                brew install capstone
                print_success "capstone installed"
            else
                print_success "capstone already installed"
            fi
            
            # Check for pkg-config
            if ! brew list pkg-config &>/dev/null; then
                print_status "Installing pkg-config via Homebrew..."
                brew install pkg-config
                print_success "pkg-config installed"
            else
                print_success "pkg-config already installed"
            fi
        else
            print_warning "Homebrew not found. Please install manually if needed:"
            print_warning "  - capstone: for binary analysis features"
            print_warning "  - pkg-config: for build dependencies"
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists apt-get; then
            print_status "Installing system dependencies via apt..."
            sudo apt-get update
            sudo apt-get install -y libcapstone-dev pkg-config
            print_success "System dependencies installed"
        elif command_exists yum; then
            print_status "Installing system dependencies via yum..."
            sudo yum install -y capstone-devel pkg-config
            print_success "System dependencies installed"
        elif command_exists pacman; then
            print_status "Installing system dependencies via pacman..."
            sudo pacman -S capstone pkg-config
            print_success "System dependencies installed"
        else
            print_warning "Package manager not recognized. Please install manually:"
            print_warning "  - capstone development libraries"
            print_warning "  - pkg-config"
        fi
    else
        print_warning "Operating system not recognized. You may need to install:"
        print_warning "  - capstone development libraries"
        print_warning "  - pkg-config"
    fi
}

# Set up pre-commit hooks
setup_precommit_hooks() {
    print_status "Setting up pre-commit hooks..."
    
    if [[ -f ".git/hooks/pre-commit" ]]; then
        print_warning "Pre-commit hook already exists. Backing up..."
        cp .git/hooks/pre-commit .git/hooks/pre-commit.backup.$(date +%s)
    fi
    
    if [[ -f "pre-commit-template" ]]; then
        cp pre-commit-template .git/hooks/pre-commit
        chmod +x .git/hooks/pre-commit
        print_success "Pre-commit hook installed"
    else
        print_warning "pre-commit-template not found in current directory"
        print_warning "You can manually copy the pre-commit hook later"
    fi
}

# Test installation
test_tools() {
    print_status "Testing installed tools..."
    
    local failed_tests=()
    
    if ! cargo fmt --version >/dev/null 2>&1; then
        failed_tests+=("cargo fmt")
    fi
    
    if ! cargo clippy --version >/dev/null 2>&1; then
        failed_tests+=("cargo clippy")
    fi
    
    if ! cargo audit --version >/dev/null 2>&1; then
        failed_tests+=("cargo audit")
    fi
    
    if ! cargo deny --version >/dev/null 2>&1; then
        failed_tests+=("cargo deny")
    fi
    
    if [[ ${#failed_tests[@]} -eq 0 ]]; then
        print_success "All tools working correctly!"
    else
        print_error "Some tools failed: ${failed_tests[*]}"
        exit 1
    fi
}

# Display usage information
display_usage() {
    echo "ThreatFlux Development Tools Setup"
    echo ""
    echo "This script installs all tools required for local CI/CD checks:"
    echo "  - Rust components (rustfmt, clippy)"
    echo "  - Cargo security tools (audit, deny, semver-checks)"
    echo "  - System dependencies (capstone, pkg-config)"
    echo "  - Pre-commit hooks"
    echo ""
    echo "Usage: ./setup-dev-tools.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --skip-system-deps    Skip system dependency installation"
    echo "  --skip-precommit      Skip pre-commit hook setup"
    echo "  --help               Show this help message"
    echo ""
}

# Parse command line arguments
SKIP_SYSTEM_DEPS=false
SKIP_PRECOMMIT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-system-deps)
            SKIP_SYSTEM_DEPS=true
            shift
            ;;
        --skip-precommit)
            SKIP_PRECOMMIT=true
            shift
            ;;
        --help)
            display_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            display_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo "🔧 ThreatFlux Development Tools Setup"
    echo "======================================"
    echo ""
    
    check_rust
    install_rust_components
    install_cargo_tools
    
    if [[ "$SKIP_SYSTEM_DEPS" != true ]]; then
        install_system_deps
    else
        print_warning "Skipping system dependencies installation"
    fi
    
    if [[ "$SKIP_PRECOMMIT" != true ]]; then
        setup_precommit_hooks
    else
        print_warning "Skipping pre-commit hook setup"
    fi
    
    test_tools
    
    echo ""
    echo "🎉 Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Run 'cargo test' to verify your project builds and tests pass"
    echo "  2. Run 'cargo clippy' to check for linting issues"
    echo "  3. Run 'cargo audit' to check for security vulnerabilities"
    echo "  4. Run 'cargo deny check' to validate dependencies"
    echo ""
    echo "Pre-commit hooks will now run these checks automatically before each commit."
    echo "To bypass pre-commit hooks temporarily, use: git commit --no-verify"
}

# Run main function
main