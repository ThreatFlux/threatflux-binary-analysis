# ThreatFlux Binary Analysis - Makefile
# Comprehensive build and test automation

# Docker configuration
DOCKER_IMAGE = threatflux-binary-analysis
DOCKER_TAG = latest
DOCKER_FULL_NAME = $(DOCKER_IMAGE):$(DOCKER_TAG)

# Rust configuration
CARGO_FEATURES_DEFAULT = 
CARGO_FEATURES_ALL = --all-features
CARGO_FEATURES_NONE = --no-default-features

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
WHITE = \033[0;37m
NC = \033[0m # No Color

.PHONY: help all all-coverage all-docker all-docker-coverage clean docker-build docker-clean
.PHONY: fmt fmt-check fmt-docker lint lint-docker audit audit-docker deny deny-docker
.PHONY: test test-docker test-doc test-doc-docker build build-docker build-all build-all-docker
.PHONY: docs docs-docker examples examples-docker bench bench-docker
.PHONY: coverage coverage-open coverage-lcov coverage-html coverage-summary coverage-json coverage-docker
.PHONY: install-tools ci-local ci-local-coverage setup-dev

# Default target
all: fmt-check lint audit deny test docs build examples ## Run all checks and builds locally

# Extended target with coverage
all-coverage: fmt-check lint audit deny test coverage docs build examples ## Run all checks including coverage locally

# Docker all-in-one target
all-docker: docker-build ## Run all checks and builds in Docker container
	@echo "$(CYAN)Running all checks in Docker container...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) sh -c " \
		echo '$(BLUE)=== Formatting Check ===$(NC)' && \
		cargo fmt --all -- --check && \
		echo '$(BLUE)=== Linting ===$(NC)' && \
		cargo clippy --all-targets --all-features -- -D warnings && \
		echo '$(BLUE)=== Security Audit ===$(NC)' && \
		cargo audit && \
		echo '$(BLUE)=== Dependency Check ===$(NC)' && \
		cargo deny check && \
		echo '$(BLUE)=== Tests ===$(NC)' && \
		cargo test --all-features && \
		echo '$(BLUE)=== Documentation ===$(NC)' && \
		cargo doc --all-features --no-deps && \
		echo '$(BLUE)=== Build ===$(NC)' && \
		cargo build --all-features && \
		echo '$(BLUE)=== Examples ===$(NC)' && \
		cargo build --examples --all-features && \
		echo '$(GREEN)✅ All checks passed!$(NC)' \
	"

# Docker all-in-one target with coverage
all-docker-coverage: docker-build ## Run all checks including coverage in Docker container
	@echo "$(CYAN)Running all checks with coverage in Docker container...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) sh -c " \
		echo '$(BLUE)=== Formatting Check ===$(NC)' && \
		cargo fmt --all -- --check && \
		echo '$(BLUE)=== Linting ===$(NC)' && \
		cargo clippy --all-targets --all-features -- -D warnings && \
		echo '$(BLUE)=== Security Audit ===$(NC)' && \
		cargo audit && \
		echo '$(BLUE)=== Dependency Check ===$(NC)' && \
		cargo deny check && \
		echo '$(BLUE)=== Tests with Coverage ===$(NC)' && \
		cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info && \
		cargo llvm-cov --all-features --workspace --html && \
		echo '$(BLUE)=== Documentation ===$(NC)' && \
		cargo doc --all-features --no-deps && \
		echo '$(BLUE)=== Build ===$(NC)' && \
		cargo build --all-features && \
		echo '$(BLUE)=== Examples ===$(NC)' && \
		cargo build --examples --all-features && \
		echo '$(GREEN)✅ All checks with coverage passed!$(NC)' \
	"

help: ## Show this help message
	@echo "$(CYAN)ThreatFlux Binary Analysis - Available Commands$(NC)"
	@echo ""
	@echo "$(YELLOW)Main Commands:$(NC)"
	@awk 'BEGIN {FS = ":.*##"; printf "  %-20s %s\n", "Target", "Description"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST) | grep -E "(all|help|setup|clean)"
	@echo ""
	@echo "$(YELLOW)Local Development:$(NC)"
	@awk 'BEGIN {FS = ":.*##"; printf "  %-20s %s\n", "Target", "Description"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST) | grep -E "^  [a-zA-Z_-]+[^-docker]" | grep -v -E "(all|help|setup|clean|docker)"
	@echo ""
	@echo "$(YELLOW)Docker Commands:$(NC)"
	@awk 'BEGIN {FS = ":.*##"; printf "  %-20s %s\n", "Target", "Description"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST) | grep -E "(docker|all-docker)"

# =============================================================================
# Setup and Installation
# =============================================================================

setup-dev: install-tools ## Set up development environment
	@echo "$(CYAN)Setting up development environment...$(NC)"
	@rustup component add rustfmt clippy
	@echo "$(GREEN)✅ Development environment ready!$(NC)"

install-tools: ## Install required development tools
	@echo "$(CYAN)Installing development tools...$(NC)"
	@command -v cargo-audit > /dev/null || cargo install cargo-audit
	@command -v cargo-deny > /dev/null || cargo install cargo-deny
	@command -v cargo-llvm-cov > /dev/null || cargo install cargo-llvm-cov
	@echo "$(GREEN)✅ Tools installed!$(NC)"

# =============================================================================
# Docker Commands
# =============================================================================

docker-build: ## Build Docker image for consistent environment
	@echo "$(CYAN)Building Docker image...$(NC)"
	@echo 'FROM rust:1.89-alpine\n\
RUN apk add --no-cache pkgconfig capstone-dev musl-dev\n\
RUN rustup component add rustfmt clippy\n\
RUN cargo install cargo-audit cargo-deny cargo-llvm-cov\n\
WORKDIR /workspace\n\
ENV CARGO_TERM_COLOR=always\n\
ENV RUST_BACKTRACE=1\n\
CMD ["cargo", "build"]' | docker build -t $(DOCKER_FULL_NAME) -

docker-clean: ## Clean Docker images and containers
	@echo "$(CYAN)Cleaning Docker resources...$(NC)"
	@docker rmi $(DOCKER_FULL_NAME) 2>/dev/null || true
	@docker system prune -f

# =============================================================================
# Formatting Commands
# =============================================================================

fmt: ## Format code using rustfmt
	@echo "$(CYAN)Formatting code...$(NC)"
	@cargo fmt --all

fmt-check: ## Check code formatting without modifying files
	@echo "$(CYAN)Checking code formatting...$(NC)"
	@cargo fmt --all -- --check

fmt-docker: docker-build ## Format code using Docker
	@echo "$(CYAN)Formatting code in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) cargo fmt --all

# =============================================================================
# Linting Commands
# =============================================================================

lint: ## Run clippy linting
	@echo "$(CYAN)Running clippy linting...$(NC)"
	@cargo clippy --all-targets --all-features -- -D warnings

lint-docker: docker-build ## Run clippy linting in Docker
	@echo "$(CYAN)Running clippy linting in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		cargo clippy --all-targets --all-features -- -D warnings

# =============================================================================
# Security and Dependency Commands
# =============================================================================

audit: ## Run security audit
	@echo "$(CYAN)Running security audit...$(NC)"
	@cargo audit

audit-docker: docker-build ## Run security audit in Docker
	@echo "$(CYAN)Running security audit in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) cargo audit

deny: ## Run dependency validation
	@echo "$(CYAN)Running dependency validation...$(NC)"
	@cargo deny check

deny-docker: docker-build ## Run dependency validation in Docker
	@echo "$(CYAN)Running dependency validation in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) cargo deny check

# =============================================================================
# Testing Commands
# =============================================================================

test: ## Run all tests
	@echo "$(CYAN)Running tests...$(NC)"
	@cargo test --all-features

test-docker: docker-build ## Run all tests in Docker
	@echo "$(CYAN)Running tests in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		cargo test --all-features

test-doc: ## Run documentation tests
	@echo "$(CYAN)Running documentation tests...$(NC)"
	@cargo test --doc --all-features

test-doc-docker: docker-build ## Run documentation tests in Docker
	@echo "$(CYAN)Running documentation tests in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		cargo test --doc --all-features

# =============================================================================
# Build Commands
# =============================================================================

build: ## Build the project
	@echo "$(CYAN)Building project...$(NC)"
	@cargo build

build-docker: docker-build ## Build the project in Docker
	@echo "$(CYAN)Building project in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) cargo build

build-all: ## Build with all features
	@echo "$(CYAN)Building project with all features...$(NC)"
	@cargo build --all-features

build-all-docker: docker-build ## Build with all features in Docker
	@echo "$(CYAN)Building project with all features in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		cargo build --all-features

build-release: ## Build optimized release
	@echo "$(CYAN)Building release...$(NC)"
	@cargo build --release --all-features

build-release-docker: docker-build ## Build optimized release in Docker
	@echo "$(CYAN)Building release in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		cargo build --release --all-features

# =============================================================================
# Documentation Commands
# =============================================================================

docs: ## Generate documentation
	@echo "$(CYAN)Generating documentation...$(NC)"
	@RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

docs-docker: docker-build ## Generate documentation in Docker
	@echo "$(CYAN)Generating documentation in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		sh -c "RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps"

docs-open: docs ## Generate and open documentation
	@echo "$(CYAN)Opening documentation...$(NC)"
	@cargo doc --all-features --no-deps --open

# =============================================================================
# Examples and Benchmarks
# =============================================================================

examples: ## Build all examples
	@echo "$(CYAN)Building examples...$(NC)"
	@cargo build --examples --all-features

examples-docker: docker-build ## Build all examples in Docker
	@echo "$(CYAN)Building examples in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		cargo build --examples --all-features

bench: ## Run benchmarks
	@echo "$(CYAN)Running benchmarks...$(NC)"
	@cargo bench --all-features

bench-docker: docker-build ## Run benchmarks in Docker
	@echo "$(CYAN)Running benchmarks in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		cargo bench --all-features

# =============================================================================
# Coverage and Profiling
# =============================================================================

coverage: ## Generate test coverage report (HTML + LCOV)
	@echo "$(CYAN)Generating coverage report...$(NC)"
	@cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	@cargo llvm-cov --all-features --workspace --html
	@echo "$(GREEN)✅ Coverage report generated in target/llvm-cov/html/index.html$(NC)"

coverage-open: coverage ## Generate and open HTML coverage report
	@echo "$(CYAN)Opening coverage report...$(NC)"
	@open target/llvm-cov/html/index.html 2>/dev/null || \
	 xdg-open target/llvm-cov/html/index.html 2>/dev/null || \
	 echo "$(YELLOW)Please open target/llvm-cov/html/index.html manually$(NC)"

coverage-lcov: ## Generate LCOV coverage report only
	@echo "$(CYAN)Generating LCOV coverage report...$(NC)"
	@cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	@echo "$(GREEN)✅ LCOV report generated at lcov.info$(NC)"

coverage-html: ## Generate HTML coverage report only
	@echo "$(CYAN)Generating HTML coverage report...$(NC)"
	@cargo llvm-cov --all-features --workspace --html
	@echo "$(GREEN)✅ HTML report generated in target/llvm-cov/html/index.html$(NC)"

coverage-summary: ## Show coverage summary
	@echo "$(CYAN)Generating coverage summary...$(NC)"
	@cargo llvm-cov --all-features --workspace --summary-only

coverage-json: ## Generate JSON coverage report
	@echo "$(CYAN)Generating JSON coverage report...$(NC)"
	@cargo llvm-cov --all-features --workspace --json --output-path coverage.json
	@echo "$(GREEN)✅ JSON report generated at coverage.json$(NC)"

coverage-docker: docker-build ## Generate test coverage report in Docker
	@echo "$(CYAN)Generating coverage report in Docker...$(NC)"
	@docker run --rm -v "$(PWD):/workspace" $(DOCKER_FULL_NAME) \
		sh -c "cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info && \
		       cargo llvm-cov --all-features --workspace --html"

# =============================================================================
# CI/Local Integration
# =============================================================================

ci-local: ## Run CI-like checks locally
	@echo "$(CYAN)Running CI checks locally...$(NC)"
	@echo "$(BLUE)=== Formatting ===$(NC)"
	@$(MAKE) fmt-check
	@echo "$(BLUE)=== Linting ===$(NC)"
	@$(MAKE) lint
	@echo "$(BLUE)=== Security Audit ===$(NC)"
	@$(MAKE) audit
	@echo "$(BLUE)=== Dependency Check ===$(NC)"
	@$(MAKE) deny
	@echo "$(BLUE)=== Tests ===$(NC)"
	@$(MAKE) test
	@echo "$(BLUE)=== Documentation ===$(NC)"
	@$(MAKE) docs
	@echo "$(BLUE)=== Build ===$(NC)"
	@$(MAKE) build-all
	@echo "$(GREEN)✅ All CI checks passed locally!$(NC)"

ci-local-coverage: ## Run CI-like checks locally with coverage
	@echo "$(CYAN)Running CI checks with coverage locally...$(NC)"
	@echo "$(BLUE)=== Formatting ===$(NC)"
	@$(MAKE) fmt-check
	@echo "$(BLUE)=== Linting ===$(NC)"
	@$(MAKE) lint
	@echo "$(BLUE)=== Security Audit ===$(NC)"
	@$(MAKE) audit
	@echo "$(BLUE)=== Dependency Check ===$(NC)"
	@$(MAKE) deny
	@echo "$(BLUE)=== Tests with Coverage ===$(NC)"
	@$(MAKE) coverage-summary
	@echo "$(BLUE)=== Documentation ===$(NC)"
	@$(MAKE) docs
	@echo "$(BLUE)=== Build ===$(NC)"
	@$(MAKE) build-all
	@echo "$(GREEN)✅ All CI checks with coverage passed locally!$(NC)"

# =============================================================================
# Utility Commands
# =============================================================================

clean: ## Clean build artifacts and coverage reports
	@echo "$(CYAN)Cleaning build artifacts...$(NC)"
	@cargo clean
	@rm -rf target/
	@rm -f lcov.info coverage.json
	@echo "$(GREEN)✅ Clean complete!$(NC)"

watch: ## Watch for changes and run tests
	@echo "$(CYAN)Watching for changes...$(NC)"
	@cargo watch -x "test --all-features"

update: ## Update dependencies
	@echo "$(CYAN)Updating dependencies...$(NC)"
	@cargo update

check-deps: ## Check dependency tree
	@echo "$(CYAN)Checking dependency tree...$(NC)"
	@cargo tree --all-features

# =============================================================================
# Development Workflows
# =============================================================================

dev: ## Quick development check (format + lint + test)
	@echo "$(CYAN)Running quick development checks...$(NC)"
	@$(MAKE) fmt
	@$(MAKE) lint
	@$(MAKE) test

dev-docker: ## Quick development check in Docker
	@echo "$(CYAN)Running quick development checks in Docker...$(NC)"
	@$(MAKE) fmt-docker
	@$(MAKE) lint-docker
	@$(MAKE) test-docker

pre-commit: ## Run pre-commit checks
	@echo "$(CYAN)Running pre-commit checks...$(NC)"
	@$(MAKE) fmt-check
	@$(MAKE) lint
	@$(MAKE) test
	@echo "$(GREEN)✅ Pre-commit checks passed!$(NC)"

# Show variables for debugging
debug-vars: ## Show Makefile variables
	@echo "$(CYAN)Makefile Variables:$(NC)"
	@echo "DOCKER_IMAGE: $(DOCKER_IMAGE)"
	@echo "DOCKER_TAG: $(DOCKER_TAG)"
	@echo "DOCKER_FULL_NAME: $(DOCKER_FULL_NAME)"